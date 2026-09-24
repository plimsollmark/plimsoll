package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
	"sync"
	"time"
)

// guardEndpoint is a validated public egress-guard URL: where a guest's brokered
// host.* calls go when the provider's network can only reach one host.
type guardEndpoint struct {
	URL  string
	Host string // hostname only
	Path string
}

// parseGuardURL validates an egress-guard URL. envName names the setting in errors;
// defaultPath is used when the URL has no path. The rules are the VM providers'
// shared ones: absolute HTTPS on port 443 (both providers' network rules name a
// host on 443), no userinfo, query or fragment, not loopback, and a canonical
// unencoded path, so the guest's literal target and the daemon's route are
// byte-identical. An empty value means "no guard".
func parseGuardURL(raw, envName, defaultPath string) (*guardEndpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("%s must be an absolute HTTPS URL without credentials, query, or fragment", envName)
	}
	if port := u.Port(); port != "" && port != "443" {
		return nil, fmt.Errorf("%s must use HTTPS port 443; the sandbox network rule names the host on 443", envName)
	}
	host := strings.ToLower(u.Hostname())
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(host, ".localhost") {
		return nil, fmt.Errorf("%s must not point to a loopback hostname", envName)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil, fmt.Errorf("%s must not point to a loopback address", envName)
	}
	p := u.EscapedPath()
	if p == "" || p == "/" {
		p = defaultPath
	}
	if !strings.HasPrefix(p, "/") || pathpkg.Clean(p) != p || strings.ContainsAny(p, `\\%`) {
		return nil, fmt.Errorf("%s path must be an absolute, canonical, unencoded path", envName)
	}
	u.Path, u.RawPath = p, ""
	return &guardEndpoint{URL: u.String(), Host: host, Path: p}, nil
}

// newGuardToken mints a per-run guard credential.
func newGuardToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("mint guard token: %w", err)
	}
	return "crg_" + fmt.Sprintf("%x", raw[:]), nil
}

// guardRegistry maps live per-run guard credentials (by SHA-256, so the map never
// holds a token) to the run's frozen broker session. It is process-local: a guard
// credential only exists in the process that opened the run, which is why the public
// guard URL must reach that same process. Both VM providers use it; they differ only
// in how the credential reaches the guard (E2B injects it outside the guest,
// dockercloud's guest sends it).
type guardRegistry struct {
	mu       sync.Mutex
	sessions map[[32]byte]*brokerSession
}

// open freezes the grant into a broker session and registers a fresh credential for
// it. cleanup unregisters and closes the session exactly once; call it when the run
// ends on every path.
func (g *guardRegistry) open(ctx context.Context, grant *HostAPIGrant, timeout time.Duration) (token string, core *brokerSession, cleanup func(), err error) {
	if grant == nil {
		return "", nil, func() {}, errors.New("open guard: nil grant")
	}
	core, err = brokerSessionForGrant(ctx, grant, timeout)
	if err != nil {
		return "", nil, func() {}, err
	}
	token, err = newGuardToken()
	if err != nil {
		core.Close()
		return "", nil, func() {}, err
	}
	digest := sha256.Sum256([]byte(token))
	g.mu.Lock()
	if g.sessions == nil {
		g.sessions = make(map[[32]byte]*brokerSession)
	}
	g.sessions[digest] = core
	g.mu.Unlock()
	var once sync.Once
	cleanup = func() {
		once.Do(func() {
			g.mu.Lock()
			delete(g.sessions, digest)
			g.mu.Unlock()
			core.Close()
		})
	}
	return token, core, cleanup, nil
}

func (g *guardRegistry) lookup(token string) *brokerSession {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	digest := sha256.Sum256([]byte(token))
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sessions[digest]
}

// call is EgressGuardCall for any provider that uses the registry.
func (g *guardRegistry) call(ctx context.Context, token, method, rawTarget string, body []byte) EgressGuardResponse {
	if strings.TrimSpace(token) == "" {
		return EgressGuardResponse{Status: http.StatusUnauthorized, ContentType: "application/json", Body: []byte(`{"error":"missing egress guard credential"}`)}
	}
	core := g.lookup(token)
	if core == nil {
		return EgressGuardResponse{Status: http.StatusUnauthorized, ContentType: "application/json", Body: []byte(`{"error":"unknown or expired egress guard credential"}`)}
	}
	resp := core.Call(ctx, brokerCall{Method: method, RawTarget: rawTarget, Body: bytes.NewReader(body)})
	return EgressGuardResponse{Status: resp.Status, ContentType: resp.ContentType, Body: resp.Body}
}
