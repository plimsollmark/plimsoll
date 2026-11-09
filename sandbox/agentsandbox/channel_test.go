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
// deployment CA; every key stays in memory or the test's temporary directory.
type testPKI struct {
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
	caPEM []byte
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
	return &testPKI{ca: ca, key: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// serverCert is a serving certificate for names, signed by the CA.
func (k *testPKI) serverCert(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, k.ca, &key.PublicKey, k.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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

// tlsSandboxd serves the fake sandboxd over TLS with cert, as a pod's terminator would,
// and returns the count of requests that reached it.
func tlsSandboxd(t *testing.T, cert tls.Certificate, protos ...string) (*fakeSandboxd, *atomic.Int64) {
	t.Helper()
	sd := newFakeSandboxdWith(t, cert, protos...)
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

func startSomething(p *Provider) error {
	_, err := p.exec(context.Background(), fakePodIP, []string{"true"}, nil, 1024, 1024)
	return err
}

// (a) The pinned CA and the configured name connect, and a command runs.
func TestChannelConnectsWithThePinnedCAAndName(t *testing.T) {
	pki := newTestPKI(t)
	sd, reached := tlsSandboxd(t, pki.serverCert(t, "sandboxd.example.test"))
	p := pinnedProvider(t, pki, "sandboxd.example.test", sd.srv.Listener.Addr().String())
	sd.run = func([]string, []byte) (string, string, int32) { return "ok", "", 0 }
	out, err := p.exec(context.Background(), fakePodIP, []string{"true"}, nil, 1024, 1024)
	if err != nil || string(out.stdout) != "ok" || reached.Load() == 0 {
		t.Fatalf("out %q, err %v, %d requests reached sandboxd", out.stdout, err, reached.Load())
	}
}

// (b) A certificate from another CA, and (c) one from the pinned CA for another name, are
// refused inside the handshake: marked not dispatched (environment), naming the CA file
// and the name, and no request reached sandboxd.
func TestChannelRefusesAnotherCAOrNameBeforeDispatch(t *testing.T) {
	pki, other := newTestPKI(t), newTestPKI(t)
	for name, cert := range map[string]tls.Certificate{
		"another CA":   other.serverCert(t, DefaultServerName),
		"another name": pki.serverCert(t, "other.plimsoll.invalid"),
	} {
		t.Run(name, func(t *testing.T) {
			sd, reached := tlsSandboxd(t, cert)
			p := pinnedProvider(t, pki, "", sd.srv.Listener.Addr().String())
			err := startSomething(p)
			reason, marked := sandbox.NotDispatchedReason(err)
			if !marked || reason != sandbox.RefusalEnvironment {
				t.Fatalf("err %v: marked %t (%s), want not dispatched for the environment", err, marked, reason)
			}
			if !strings.Contains(err.Error(), DefaultServerName) || !strings.Contains(err.Error(), "sandboxd-ca.crt") {
				t.Errorf("the refusal names neither the server name nor the CA file: %v", err)
			}
			if reached.Load() != 0 {
				t.Fatalf("%d requests reached sandboxd", reached.Load())
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
	sd, reached := tlsSandboxd(t, pki.serverCert(t, DefaultServerName), "http/1.1")
	p = pinnedProvider(t, pki, "", sd.srv.Listener.Addr().String())
	if err := startSomething(p); err == nil || reached.Load() != 0 {
		t.Fatalf("an HTTP/1.1-only server: err %v, %d requests reached it", err, reached.Load())
	}

	tr, ok := p.sandboxd.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the channel's transport is %T", p.sandboxd.Transport)
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
	check := channelTLS(nil, DefaultServerName).VerifyConnection
	if err := check(tls.ConnectionState{NegotiatedProtocol: "h2"}); !errors.Is(err, errChannel) {
		t.Fatalf("no verified chain: %v", err)
	}
	if err := check(tls.ConnectionState{NegotiatedProtocol: "", VerifiedChains: [][]*x509.Certificate{{pki.ca}}}); !errors.Is(err, errChannel) {
		t.Fatalf("no h2: %v", err)
	}
	if err := check(tls.ConnectionState{NegotiatedProtocol: "h2", VerifiedChains: [][]*x509.Certificate{{pki.ca}}}); err != nil {
		t.Fatalf("a verified h2 connection: %v", err)
	}
	p := &Provider{cfg: Config{SandboxdCAFile: "ca.pem"}}
	if _, marked := sandbox.NotDispatchedReason(p.channelRefusal(connect.NewError(connect.CodeUnavailable, check(tls.ConnectionState{})))); !marked {
		t.Error("the channel check's refusal is not marked not dispatched")
	}
	if _, marked := sandbox.NotDispatchedReason(p.channelRefusal(connect.NewError(connect.CodeUnavailable, io.ErrUnexpectedEOF))); marked {
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
