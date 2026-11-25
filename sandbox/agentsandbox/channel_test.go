package agentsandbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// testPKI is a certificate authority made for one test, standing in for an operator's
// in-cluster issuer; every key stays in memory or the test's temporary directory.
type testPKI struct {
	ca     *x509.Certificate
	key    *ecdsa.PrivateKey
	caPEM  []byte
	serial atomic.Int64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "plimsoll test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	k := &testPKI{ca: ca, key: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	k.serial.Store(1)
	return k
}

// leaf is what a serving certificate names, and until when it is valid (zero: an hour
// from now).
type leaf struct {
	dns      []string
	uris     []string
	ips      []net.IP
	notAfter time.Time
}

// cert is a serving certificate for l, signed by the CA. It may be called from a
// server's goroutine, so it reports a failure with Error, never Fatal.
func (k *testPKI) cert(t *testing.T, l leaf) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
		return tls.Certificate{}
	}
	if l.notAfter.IsZero() {
		l.notAfter = time.Now().Add(time.Hour)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(k.serial.Add(1)), DNSNames: l.dns, IPAddresses: l.ips,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: l.notAfter}
	for _, s := range l.uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Error(err)
			return tls.Certificate{}
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, k.ca, &key.PublicKey, k.key)
	if err != nil {
		t.Error(err)
		return tls.Certificate{}
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// podCert is the certificate the issuer signs for a pod: the one DNS name and the one URI,
// the pod's identity, as the driver requests it (measured 2026-11-24).
func (k *testPKI) podCert(t *testing.T, name, identity string) tls.Certificate {
	return k.cert(t, leaf{dns: []string{name}, uris: []string{identity}})
}

// caFile writes the CA certificate where SandboxdCAFile can name it.
func (k *testPKI) caFile(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "sandboxd-ca.crt")
	if err := os.WriteFile(f, k.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// The pod the channel tests dial, and the identity its certificate must carry.
const (
	fakePodName = "sb-plimsoll-0000000000000000"
	fakePodUID  = "0f8b2c1e-8f6f-4a5e-9d2a-3b7c9e1a5d40"
)

var fakeIdentity = podIdentity(fakeTrustDomain, "default", fakePodName, fakePodUID)

// tlsSandboxd serves the fake sandboxd behind a front serving cert at every address, and
// returns the count of requests that reached it.
func tlsSandboxd(t *testing.T, cert tls.Certificate, protos ...string) (*fakeSandboxd, *atomic.Int64) {
	t.Helper()
	sd := newFakeSandboxdWith(t, &cert, protos...)
	return sd, &sd.reached
}

// pinnedProvider is a provider over the fake API whose channel pins pki, checks name
// (empty: the default) and dials addr for every pod.
func pinnedProvider(t *testing.T, pki *testPKI, name, addr string) *Provider {
	t.Helper()
	p, _, _ := testProviderWith(t, func(c *Config) {
		c.SandboxdCAFile, c.SandboxdServerName = pki.caFile(t), name
	})
	p.dialAddr = func(string) string { return addr }
	return p
}

// fakeChannel is the channel to the channel tests' pod.
func fakeChannel(p *Provider) *podChannel { return p.channelTo(fakePodIP, fakePodName, fakePodUID) }

func startSomething(p *Provider) error {
	_, err := p.exec(context.Background(), fakeChannel(p), []string{"true"}, nil, 1024, 1024)
	return err
}

// (a) The pinned CA, the configured name and the pod's identity connect, and a command runs.
func TestChannelConnectsWithThePinnedCANameAndIdentity(t *testing.T) {
	pki := newTestPKI(t)
	sd, reached := tlsSandboxd(t, pki.podCert(t, "sandboxd.example.test", fakeIdentity))
	p := pinnedProvider(t, pki, "sandboxd.example.test", sd.addr(fakePodIP))
	sd.run = func([]string, []byte) (string, string, int32) { return "ok", "", 0 }
	out, err := p.exec(context.Background(), fakeChannel(p), []string{"true"}, nil, 1024, 1024)
	if err != nil || string(out.stdout) != "ok" || reached.Load() == 0 {
		t.Fatalf("out %q, err %v, %d requests reached sandboxd", out.stdout, err, reached.Load())
	}
}

// (b) Every certificate but the one for this pod is refused inside the handshake: marked
// not dispatched (environment), naming the CA file, the name and the pod, with no byte of
// a request past the front. Among them the ones a valid pod of the deployment holds:
// another pod's identity, the same name with another UID (a pod made again under its
// name), the same pod in another namespace or trust domain. Deleting checkIdentity's
// URI comparison passes those four (measured 2026-11-24, the build's note).
func TestChannelRefusesEveryCertificateButThePodsOwnBeforeDispatch(t *testing.T) {
	pki, other := newTestPKI(t), newTestPKI(t)
	name := DefaultServerName
	for what, l := range map[string]leaf{
		"another CA":                         {dns: []string{name}, uris: []string{fakeIdentity}},
		"another name":                       {dns: []string{"other.plimsoll.invalid"}, uris: []string{fakeIdentity}},
		"another pod":                        {dns: []string{name}, uris: []string{podIdentity(fakeTrustDomain, "default", "sb-plimsoll-1111111111111111", "a1b2c3d4-0000-4000-8000-000000000001")}},
		"the same name, another UID":         {dns: []string{name}, uris: []string{podIdentity(fakeTrustDomain, "default", fakePodName, "a1b2c3d4-0000-4000-8000-000000000002")}},
		"another namespace":                  {dns: []string{name}, uris: []string{podIdentity(fakeTrustDomain, "other", fakePodName, fakePodUID)}},
		"another trust domain":               {dns: []string{name}, uris: []string{podIdentity("other.test", "default", fakePodName, fakePodUID)}},
		"no URI name":                        {dns: []string{name}},
		"two URI names":                      {dns: []string{name}, uris: []string{fakeIdentity, "spiffe://" + fakeTrustDomain + "/x"}},
		"another DNS name beside it":         {dns: []string{name, "sandboxd.example.test"}, uris: []string{fakeIdentity}},
		"an IP address beside it":            {dns: []string{name}, uris: []string{fakeIdentity}, ips: []net.IP{net.ParseIP(fakePodIP)}},
		"expired":                            {dns: []string{name}, uris: []string{fakeIdentity}, notAfter: time.Now().Add(-time.Hour)},
		"the identity with a trailing slash": {dns: []string{name}, uris: []string{fakeIdentity + "/"}},
	} {
		t.Run(what, func(t *testing.T) {
			issuer := pki
			if what == "another CA" {
				issuer = other
			}
			sd, reached := tlsSandboxd(t, issuer.cert(t, l))
			p := pinnedProvider(t, pki, "", sd.addr(fakePodIP))
			err := startSomething(p)
			reason, marked := sandbox.NotDispatchedReason(err)
			if !marked || reason != sandbox.RefusalEnvironment {
				t.Fatalf("err %v: marked %t (%s), want not dispatched for the environment", err, marked, reason)
			}
			for _, s := range []string{DefaultServerName, "sandboxd-ca.crt", fakePodName, fakeIdentity} {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("the refusal does not name %s: %v", s, err)
				}
			}
			if fr := sd.front(fakePodIP); reached.Load() != 0 || fr.bytes.Load() != 0 || fr.handshakes.Load() != 0 {
				t.Fatalf("%d requests reached sandboxd, %d bytes passed the front, %d handshakes completed", reached.Load(), fr.bytes.Load(), fr.handshakes.Load())
			}
		})
	}
}

// (d) There is no cleartext path: against a cleartext HTTP/2 listener the first bytes the
// client sends are a TLS ClientHello, never the HTTP/2 preface, and the call fails; a TLS
// server that does not speak h2 is refused by the channel check; and the transport is
// HTTP/2 over TLS alone, on the pinned pool, with verification on.
func TestChannelHasNoPlaintextPath(t *testing.T) {
	pki := newTestPKI(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	first := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			first <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 64)
		n, _ := io.ReadAtLeast(c, b, 3)
		first <- b[:n]
	}()
	p := pinnedProvider(t, pki, "", ln.Addr().String())
	if err := startSomething(p); err == nil {
		t.Fatal("a call to a cleartext listener succeeded")
	}
	got := <-first
	if len(got) < 3 || got[0] != 0x16 || got[1] != 0x03 || bytes.HasPrefix(got, []byte("PRI")) {
		t.Fatalf("the client's first bytes were %q, not a TLS handshake record", got)
	}

	// A TLS server offering HTTP/1.1 alone: the transport, or the channel check, refuses.
	sd, reached := tlsSandboxd(t, pki.podCert(t, DefaultServerName, fakeIdentity), "http/1.1")
	p = pinnedProvider(t, pki, "", sd.addr(fakePodIP))
	if err := startSomething(p); err == nil || reached.Load() != 0 {
		t.Fatalf("an HTTP/1.1-only server: err %v, %d requests reached it", err, reached.Load())
	}

	ch := fakeChannel(p)
	tr, ok := ch.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the channel's transport is %T", ch.client.Transport)
	}
	switch c := tr.TLSClientConfig; {
	case tr.Protocols == nil || tr.Protocols.HTTP1() || tr.Protocols.UnencryptedHTTP2() || !tr.Protocols.HTTP2():
		t.Errorf("protocols %v, want HTTP/2 over TLS alone", tr.Protocols)
	case c == nil || c.InsecureSkipVerify || c.RootCAs == nil || c.VerifyConnection == nil || c.MinVersion != tls.VersionTLS13:
		t.Errorf("TLS config %+v: want the pinned pool, verification, the channel check and TLS 1.3", c)
	case c.ServerName != DefaultServerName:
		t.Errorf("server name %q", c.ServerName)
	case tr.Proxy != nil:
		t.Error("the channel goes through a proxy")
	}
	if !poolIsExactly(tr.TLSClientConfig.RootCAs, pki) {
		t.Error("the pool is not exactly the pinned CA")
	}
}

func poolIsExactly(pool *x509.CertPool, pki *testPKI) bool {
	want := x509.NewCertPool()
	want.AddCert(pki.ca)
	return pool.Equal(want)
}

// The channel check refuses a connection with no verified chain, so a later edit that
// skipped verification would still be refused, and marked.
func TestChannelCheckRefusesAnUnverifiedConnection(t *testing.T) {
	pki := newTestPKI(t)
	check := channelTLS(nil, DefaultServerName, fakeIdentity).VerifyConnection
	good := pki.podCert(t, DefaultServerName, fakeIdentity)
	leafCert, err := x509.ParseCertificate(good.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	chains := [][]*x509.Certificate{{leafCert, pki.ca}}
	if err := check(tls.ConnectionState{NegotiatedProtocol: "h2", PeerCertificates: []*x509.Certificate{leafCert}}); !errors.Is(err, errChannel) {
		t.Fatalf("no verified chain: %v", err)
	}
	if err := check(tls.ConnectionState{NegotiatedProtocol: "", VerifiedChains: chains, PeerCertificates: []*x509.Certificate{leafCert}}); !errors.Is(err, errChannel) {
		t.Fatalf("no h2: %v", err)
	}
	if err := check(tls.ConnectionState{NegotiatedProtocol: "h2", VerifiedChains: chains}); !errors.Is(err, errChannel) {
		t.Fatalf("no peer certificate: %v", err)
	}
	if err := check(tls.ConnectionState{NegotiatedProtocol: "h2", VerifiedChains: chains, PeerCertificates: []*x509.Certificate{leafCert}}); err != nil {
		t.Fatalf("a verified h2 connection to the pod: %v", err)
	}
	// A channel built with no identity refuses every certificate.
	if err := channelTLS(nil, DefaultServerName, "").VerifyConnection(tls.ConnectionState{NegotiatedProtocol: "h2", VerifiedChains: chains, PeerCertificates: []*x509.Certificate{leafCert}}); !errors.Is(err, errChannel) {
		t.Fatalf("no identity to check: %v", err)
	}
	ch := &podChannel{caFile: "ca.pem"}
	if _, marked := sandbox.NotDispatchedReason(ch.refusal(connect.NewError(connect.CodeUnavailable, check(tls.ConnectionState{})))); !marked {
		t.Error("the channel check's refusal is not marked not dispatched")
	}
	if _, marked := sandbox.NotDispatchedReason(ch.refusal(connect.NewError(connect.CodeUnavailable, io.ErrUnexpectedEOF))); marked {
		t.Error("an error outside the handshake was marked not dispatched")
	}
}

// The CA file must hold certificates and only certificates; an empty pool would trust
// nothing and a nil one the system roots, so neither is ever built.
func TestCAFileMustHoldOnlyCertificates(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	if pool, err := readCAPool(write("good", pki.caPEM)); err != nil || pool == nil {
		t.Fatalf("a CA file refused: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(pki.key)
	for name, b := range map[string][]byte{
		"empty":            nil,
		"blank":            []byte("\n\n"),
		"garbage":          []byte("not a certificate"),
		"a key":            pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		"a key beside it":  append(slicesClone(pki.caPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...),
		"trailing garbage": append(slicesClone(pki.caPEM), []byte("junk")...),
		"a bad DER":        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
	} {
		if _, err := readCAPool(write(strings.ReplaceAll(name, " ", "-"), b)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := readCAPool(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file was accepted")
	}
}

func slicesClone(b []byte) []byte { return append([]byte(nil), b...) }

// The server name is a DNS name, never an address.
func TestServerNameIsADNSName(t *testing.T) {
	for _, s := range []string{DefaultServerName, "sandboxd", "sandboxd.plimsoll.svc.cluster.local"} {
		if !validServerName(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", "10.0.0.1", "::1", "Sandboxd.example", "a..b", "-a.b", "a_b.c", strings.Repeat("a", 64) + ".b", "*.example"} {
		if validServerName(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

// subCA is a certificate the test CA signs with cert-sign usage, carrying names when a
// pod's certificate is what an issuer wrongly made a CA (dns and uris set), or none when
// it is an ordinary intermediate authority; and a leaf for identity that it signs.
func (k *testPKI) subCA(t *testing.T, dns, uris []string, identity string) tls.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(k.serial.Add(1)), Subject: pkix.Name{CommonName: "intermediate"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: dns,
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(time.Hour)}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, k.ca, &caKey.PublicKey, k.key)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(k.serial.Add(1)), DNSNames: []string{DefaultServerName}, URIs: []*url.URL{u},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, sub, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
}

// A pod whose certificate an issuer made a CA signs the victim pod's identity with its own
// key and serves its certificate as the intermediate: refused before anything is sent
// (finding release-108 measured the run executing there, 2 requests reaching sandboxd). An
// intermediate authority that names no server still serves a pod's certificate.
func TestChannelRefusesAPodCertificateActingAsIntermediate(t *testing.T) {
	pki := newTestPKI(t)
	other := podIdentity(fakeTrustDomain, "default", "sb-plimsoll-1111111111111111", "a1b2c3d4-0000-4000-8000-000000000001")
	sd, reached := tlsSandboxd(t, pki.subCA(t, []string{DefaultServerName}, []string{other}, fakeIdentity))
	err := startSomething(pinnedProvider(t, pki, "", sd.addr(fakePodIP)))
	if reason, marked := sandbox.NotDispatchedReason(err); !marked || reason != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "intermediate that names a server") {
		t.Fatalf("err %v: marked %t (%s), want not dispatched for the intermediate", err, marked, reason)
	}
	if reached.Load() != 0 {
		t.Fatalf("%d requests reached sandboxd", reached.Load())
	}

	// The fake answers this exec with a stream error after it is reached; what matters is
	// that the handshake passed and the request got there.
	plain, reached2 := tlsSandboxd(t, pki.subCA(t, nil, nil, fakeIdentity))
	err = startSomething(pinnedProvider(t, pki, "", plain.addr(fakePodIP)))
	if err != nil && strings.Contains(err.Error(), errChannel.Error()) {
		t.Fatalf("a pod certificate under an intermediate that names no server was refused: %v", err)
	}
	if reached2.Load() == 0 {
		t.Fatalf("no request reached sandboxd through the ordinary intermediate (err %v)", err)
	}
}

// A pod's own certificate that is a CA is refused, though its names are right.
func TestCheckIdentityRefusesACALeaf(t *testing.T) {
	u, _ := url.Parse(fakeIdentity)
	leaf := &x509.Certificate{DNSNames: []string{DefaultServerName}, URIs: []*url.URL{u}, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	if err := checkIdentity(leaf, DefaultServerName, fakeIdentity); err == nil || !strings.Contains(err.Error(), "certificate authority") {
		t.Fatalf("a CA leaf: %v", err)
	}
	leaf.IsCA, leaf.KeyUsage = false, x509.KeyUsageDigitalSignature
	if err := checkIdentity(leaf, DefaultServerName, fakeIdentity); err != nil {
		t.Fatalf("an ordinary leaf: %v", err)
	}
}
