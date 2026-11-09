package agentsandbox

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The channel to sandboxd. sandboxd serves no TLS (agent-sandbox v1.0.7's user guide:
// "sandboxd does not terminate TLS"), and everything a run needs crosses this one
// connection: sandboxd's token, the code and files, each project's plan with the runner's
// report key, and every byte of output. So the image runs sandboxd on loopback behind
// plimsoll's own terminator (docker/sandboxdtls), which serves TLS 1.3 on the pod's
// address with the deployment's certificate, and plimsolld speaks HTTP/2 over TLS alone:
// it trusts only the certificate authority the operator names, never the system roots,
// and only a certificate for the configured name. There is no cleartext path.
const (
	// frontPort is where the terminator listens in every pod, the port the template's
	// network policy admits plimsolld to; sandboxdPort is sandboxd's own gRPC port on
	// loopback behind it. Both are fixed in the terminator, which refuses any other.
	frontPort    = 9090
	sandboxdPort = 9091
	loopbackHost = "127.0.0.1"
	// frontPath is the container's command: the terminator, which starts sandboxd.
	frontPath = "/usr/local/bin/plimsoll-sandboxd-tls"
	// tlsMountPath is where the template mounts the TLS Secret (keys tls.crt and
	// tls.key), inside tlsGuardDir, which the image makes root's, mode 0700.
	tlsMountPath = "/etc/plimsoll/sandboxd-tls"
	tlsGuardDir  = "/etc/plimsoll"
	tlsKeyPath   = tlsMountPath + "/tls.key"
	// DefaultServerName is the name sandboxd's certificate must carry when the operator
	// sets none. .invalid is reserved (RFC 6761) and never resolves, so the name can only
	// be checked, never dialed: plimsolld dials each pod's address.
	DefaultServerName = "sandboxd.plimsoll.invalid"
	// channelBudget bounds a connection's dial and its handshake, each.
	channelBudget = 10 * time.Second
	// channelIdle closes a connection left idle: each run claims a fresh pod, so a
	// connection is seldom reused, and a pod's address is reused once it is deleted.
	channelIdle = 30 * time.Second
)

var dnsNameRE = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// validServerName accepts a DNS name, never an address: the certificate is checked
// against the name, and the address dialed is each pod's.
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

// channelTLS is the client's TLS: the pinned pool, the name, TLS 1.3, and a final check
// that a chain was verified and HTTP/2 negotiated, so a later edit that skipped
// verification, or a transport that dropped ALPN, refuses instead of passing quietly.
func channelTLS(pool *x509.CertPool, name string) *tls.Config {
	return &tls.Config{
		RootCAs:    pool,
		ServerName: name,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 {
				return fmt.Errorf("%w: no verified certificate chain", errChannel)
			}
			if cs.NegotiatedProtocol != "h2" {
				return fmt.Errorf("%w: negotiated %q, not h2", errChannel, cs.NegotiatedProtocol)
			}
			return nil
		},
	}
}

// channelClient is the HTTP client for sandboxd: HTTP/2 over TLS only (no HTTP/1.1 and no
// cleartext HTTP/2), no proxy, no redirect.
func channelClient(pool *x509.CertPool, name string) *http.Client {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	return &http.Client{
		Transport: &http.Transport{
			Protocols:           protocols,
			TLSClientConfig:     channelTLS(pool, name),
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: channelBudget}).DialContext,
			TLSHandshakeTimeout: channelBudget,
			IdleConnTimeout:     channelIdle,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// channelRefusal marks a call that failed inside the TLS handshake as not dispatched:
// Go's client completes the handshake before it writes a request and sends no early
// data, so neither the token nor any code left. Only a certificate that failed
// verification and the channel check's own refusal are marked, since both arise only in
// the handshake; any other error keeps the conservative reading (execution may have
// occurred).
func (p *Provider) channelRefusal(err error) error {
	var verify *tls.CertificateVerificationError
	if errors.As(err, &verify) || errors.Is(err, errChannel) {
		return sandbox.NotDispatched(sandbox.RefusalEnvironment, fmt.Errorf(
			"agentsandbox: sandboxd's TLS terminator did not prove itself with a certificate for %q from the CA in %s, so nothing was sent: %w",
			p.cfg.serverName(), p.cfg.SandboxdCAFile, err))
	}
	return err
}
