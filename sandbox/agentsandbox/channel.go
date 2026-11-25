package agentsandbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The channel to sandboxd. sandboxd serves no TLS (agent-sandbox v1.0.7's user guide:
// "sandboxd does not terminate TLS"), and everything a run needs crosses this one
// connection: sandboxd's token, the code and files, each project's plan with the runner's
// report key, and every byte of output. So the image runs sandboxd on loopback behind
// plimsoll's own terminator (docker/sandboxdtls), which serves TLS 1.3 on the pod's
// address, and plimsolld speaks HTTP/2 over TLS alone: it trusts only the certificate
// authority the operator names, never the system roots. There is no cleartext path.
//
// Each pod serves a certificate of its own, which an issuer in the cluster signed for that
// pod alone: one fixed DNS name, so the standard library verifies the chain and the name
// as it does for any server, and exactly one URI name, the pod's identity, built from the
// namespace, name and UID the API server gave the pod (podIdentity). plimsolld reads the
// pod before it dials, and the handshake's last check (channelTLS) requires the identity
// of the pod it read, so a connection redirected to another pod of the deployment, which
// holds a valid certificate of its own, fails the handshake and nothing is sent. A pod
// deleted and made again under the same name has a new UID, so it fails too. The key is
// made on the node and mounted into the pod (the read-back's keyVolume).
const (
	// frontPort is where the terminator listens in every pod, the port the template's
	// network policy admits plimsolld to; sandboxdPort is sandboxd's own gRPC port on
	// loopback behind it. Both are fixed in the terminator, which refuses any other.
	frontPort    = 9090
	sandboxdPort = 9091
	loopbackHost = "127.0.0.1"
	// frontPath is the container's command: the terminator, which starts sandboxd.
	frontPath = "/usr/local/bin/plimsoll-sandboxd-tls"
	// tlsMountPath is where the template mounts the pod's key volume (files tls.crt and
	// tls.key), inside tlsGuardDir, which the image makes root's, mode 0700.
	tlsMountPath = "/etc/plimsoll/sandboxd-tls"
	tlsGuardDir  = "/etc/plimsoll"
	tlsKeyPath   = tlsMountPath + "/tls.key"
	// DefaultServerName is the DNS name every pod's certificate must carry when the
	// operator sets none. .invalid is reserved (RFC 6761) and never resolves, so the name
	// can only be checked, never dialed: plimsolld dials each pod's address.
	DefaultServerName = "sandboxd.plimsoll.invalid"
	// channelBudget bounds a connection's dial and its handshake, each.
	channelBudget = 10 * time.Second
	// channelIdle closes a connection left idle. Each claim has a client of its own,
	// whose every connection is closed when the claim is released, so this is a backstop.
	channelIdle = 30 * time.Second
)

var dnsNameRE = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// validServerName accepts a DNS name, never an address: the certificate is checked
// against the name, and the address dialed is each pod's. A trust domain takes the same
// form.
func validServerName(s string) bool {
	return len(s) <= 253 && dnsNameRE.MatchString(s) && net.ParseIP(s) == nil
}

// readCAPool reads the deployment CA: PEM certificates and nothing else. The pool is
// never empty, since an empty one would trust nothing, and never nil, since a nil one
// means the system roots.
func readCAPool(file string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("agentsandbox: sandboxd's CA: %w", err)
	}
	pool, n := x509.NewCertPool(), 0
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return nil, fmt.Errorf("agentsandbox: sandboxd's CA file %s holds something other than PEM certificates", file)
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("agentsandbox: sandboxd's CA file %s holds a %q block, not only certificates", file, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("agentsandbox: sandboxd's CA file %s: %w", file, err)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("agentsandbox: sandboxd's CA file %s holds no certificate", file)
	}
	return pool, nil
}

// errChannel is the channel check's own refusal, raised inside the handshake.
var errChannel = errors.New("the connection to sandboxd is not the pinned channel")

// podIdentity is the URI a pod's certificate must carry as its one URI name: a SPIFFE ID
// (the form in-cluster issuers write) in the operator's trust domain, with the pod's
// namespace, name and UID as the API server reported them. The UID binds: a name is
// reused when a pod is made again (the warm pool refills under the same names), a UID
// never is.
func podIdentity(trustDomain, namespace, name, uid string) string {
	return "spiffe://" + trustDomain + "/ns/" + namespace + "/pod/" + name + "/" + uid
}

// identityTemplate is podIdentity as the pod's key volume asks the issuer for it, with
// the variables filled from the pod being mounted.
func identityTemplate(trustDomain string) string {
	return podIdentity(trustDomain, "${POD_NAMESPACE}", "${POD_NAME}", "${POD_UID}")
}

// channelTLS is the client's TLS for one pod: the pinned pool, the fixed name, TLS 1.3,
// and a final check that a chain was verified, HTTP/2 negotiated, and the certificate
// names exactly the fixed DNS name and exactly one URI, identity, and nothing else (no IP
// address, no email address). So a certificate of another pod, valid in every other way,
// is refused inside the handshake, and a later edit that skipped verification, or a
// transport that dropped ALPN, refuses instead of passing quietly.
func channelTLS(pool *x509.CertPool, name, identity string) *tls.Config {
	return &tls.Config{
		RootCAs:    pool,
		ServerName: name,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("%w: no verified certificate chain", errChannel)
			}
			if cs.NegotiatedProtocol != "h2" {
				return fmt.Errorf("%w: negotiated %q, not h2", errChannel, cs.NegotiatedProtocol)
			}
			for _, chain := range cs.VerifiedChains {
				if err := checkIntermediates(chain); err != nil {
					return err
				}
			}
			return checkIdentity(cs.PeerCertificates[0], name, identity)
		},
	}
}

// checkIntermediates refuses a chain in which a certificate between the leaf and the
// pinned CA names a server: an intermediate authority names none, and a pod's own
// certificate always carries the pod's URI and the fixed DNS name. So a pod whose
// certificate an issuer made a CA cannot sign another pod's identity and serve it with its
// own certificate as the intermediate (finding release-108: such a chain was accepted and
// the run executed there).
func checkIntermediates(chain []*x509.Certificate) error {
	for i := 1; i < len(chain)-1; i++ {
		c := chain[i]
		if len(c.URIs) != 0 || len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 || len(c.EmailAddresses) != 0 {
			return fmt.Errorf("%w: the certificate is signed by an intermediate that names a server (%q), as another pod's certificate does", errChannel, truncate(fmt.Sprint(c.URIs, c.DNSNames), 200))
		}
	}
	return nil
}

// checkIdentity holds the serving certificate to the one DNS name and the one URI.
func checkIdentity(leaf *x509.Certificate, name, identity string) error {
	switch {
	case identity == "":
		return fmt.Errorf("%w: no pod identity to check", errChannel)
	case len(leaf.URIs) != 1:
		return fmt.Errorf("%w: the certificate carries %d URI names, want exactly one, %s", errChannel, len(leaf.URIs), identity)
	case leaf.URIs[0].String() != identity:
		return fmt.Errorf("%w: the certificate is another pod's: it names %q, not %s", errChannel, truncate(leaf.URIs[0].String(), 200), identity)
	case len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name:
		return fmt.Errorf("%w: the certificate carries the DNS names %q, want %q alone", errChannel, leaf.DNSNames, name)
	case len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0:
		return fmt.Errorf("%w: the certificate carries an IP address or email name beside the pod's identity", errChannel)
	case leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0:
		return fmt.Errorf("%w: the pod's certificate is a certificate authority, which could sign another pod's identity", errChannel)
	}
	return nil
}

// podChannel is the client for one claimed pod. It has a transport of its own, so a
// connection made and checked for this pod never carries a request for another: a pod's
// address is reused once it is deleted, and a pooled connection is checked only at its
// handshake. The claim's release closes it: every connection it made, busy or idle, and
// any dial after.
type podChannel struct {
	client   *http.Client
	addr     string // the host:port dialed
	pod      string // the pod's name, for errors
	identity string // the URI its certificate must carry
	name     string // the DNS name its certificate must carry
	caFile   string

	mu     sync.Mutex
	conns  map[net.Conn]bool
	closed bool
}

// errReleased refuses a dial on a channel whose claim was released.
var errReleased = errors.New("agentsandbox: the pod's channel was closed when its claim was released")

// channelTo is the channel to the pod at ip, named podName with UID uid in the provider's
// namespace, as the read-back read it.
func (p *Provider) channelTo(ip, podName, uid string) *podChannel {
	addr := net.JoinHostPort(ip, strconv.Itoa(frontPort))
	if p.dialAddr != nil {
		addr = p.dialAddr(ip)
	}
	name := p.cfg.serverName()
	identity := podIdentity(p.cfg.SandboxdTrustDomain, p.cfg.Namespace, podName, uid)
	c := &podChannel{addr: addr, pod: podName, identity: identity, name: name, caFile: p.cfg.SandboxdCAFile, conns: map[net.Conn]bool{}}
	c.client = channelClient(p.pool, name, identity, c.dial)
	return c
}

// dial makes one connection for the channel and tracks it until it closes.
func (c *podChannel) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, errReleased
	}
	conn, err := (&net.Dialer{Timeout: channelBudget}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = conn.Close()
		return nil, errReleased
	}
	c.conns[conn] = true
	return &trackedConn{Conn: conn, ch: c}, nil
}

// trackedConn is a channel's connection, which forgets itself when closed.
type trackedConn struct {
	net.Conn
	ch   *podChannel
	once sync.Once
}

func (t *trackedConn) Close() error {
	t.once.Do(func() {
		t.ch.mu.Lock()
		delete(t.ch.conns, t.Conn)
		t.ch.mu.Unlock()
	})
	return t.Conn.Close()
}

// close closes every connection the channel made and refuses any later dial. The run
// that held the claim is over by then, so a connection still busy carries nothing of
// another's.
func (c *podChannel) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	conns := make([]net.Conn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	c.client.CloseIdleConnections()
}

// channelClient is the HTTP client for one pod's sandboxd: HTTP/2 over TLS only (no
// HTTP/1.1 and no cleartext HTTP/2), no proxy, no redirect, dialing through dial.
func channelClient(pool *x509.CertPool, name, identity string, dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	return &http.Client{
		Transport: &http.Transport{
			Protocols:           protocols,
			TLSClientConfig:     channelTLS(pool, name, identity),
			Proxy:               nil,
			DialContext:         dial,
			TLSHandshakeTimeout: channelBudget,
			IdleConnTimeout:     channelIdle,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// refusal marks a call that failed inside the TLS handshake as not dispatched: Go's
// client completes the handshake before it writes a request and sends no early data, so
// neither the token nor any code left. Only a certificate that failed verification and
// the channel check's own refusal are marked, since both arise only in the handshake; any
// other error keeps the conservative reading (execution may have occurred).
func (c *podChannel) refusal(err error) error {
	var verify *tls.CertificateVerificationError
	if errors.As(err, &verify) || errors.Is(err, errChannel) {
		return sandbox.NotDispatched(sandbox.RefusalEnvironment, fmt.Errorf(
			"agentsandbox: sandboxd's TLS terminator did not prove itself as pod %s (%s) with a certificate for %q from the CA in %s, so nothing was sent: %w",
			c.pod, c.identity, c.name, c.caFile, err))
	}
	return err
}
