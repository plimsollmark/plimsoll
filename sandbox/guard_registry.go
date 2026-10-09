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

// grantSlot serves the grant of the call in progress, or none: a run's slot holds its
// grant for the run, a session's is lent one call's grant at a time.
type grantSlot struct {
	mu   sync.Mutex
	core *brokerSession
}

func (s *grantSlot) current() *brokerSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core
}

func (s *grantSlot) set(core *brokerSession) {
	s.mu.Lock()
	s.core = core
	s.mu.Unlock()
}

// lend serves core's grant until the returned release, which stops serving it and
// ends it: a request still in flight is cut off upstream, one still arriving is
// refused, and the release waits for them, so the call's trace is read complete
// after it. Release is idempotent: a call releases before reading its trace and
// again, deferred, on its error paths.
func (s *grantSlot) lend(core *brokerSession) (release func()) {
	s.set(core)
	var once sync.Once
	return func() {
		once.Do(func() {
			s.set(nil)
			core.Close()
		})
	}
}

// guardRegistry maps live guard credentials (by SHA-256, so the map never holds a
// token) to the slot whose grant they reach. It is process-local: a guard credential
// only exists in the process that opened the run or session, which is why the public
// guard URL must reach that same process. Both VM providers use it; they differ only
// in how the credential reaches the guard (E2B injects it outside the guest,
// dockercloud's guest sends it).
type guardRegistry struct {
	mu    sync.Mutex
	slots map[[32]byte]*grantSlot
}

// open freezes the grant into a broker session and registers a fresh credential for
// it. cleanup unregisters and closes the session exactly once; call it when the run
// ends on every path.
func (g *guardRegistry) open(ctx context.Context, grant *HostAPIGrant, timeout time.Duration, routes *RouteBudget) (token string, core *brokerSession, cleanup func(), err error) {
	if grant == nil {
		return "", nil, func() {}, errors.New("open guard: nil grant")
	}
	core, err = brokerSessionForGrant(ctx, grant, timeout, routes)
	if err != nil {
		return "", nil, func() {}, err
	}
	token, slot, unregister, err := g.register()
	if err != nil {
		core.Close()
		return "", nil, func() {}, err
	}
	release := slot.lend(core)
	return token, core, func() { unregister(); release() }, nil
}

// register adds a fresh credential with an empty slot, for a session to lend one
// call's grant at a time. unregister removes it and is idempotent; ending a lent
// grant is the lender's release.
func (g *guardRegistry) register() (token string, slot *grantSlot, unregister func(), err error) {
	token, err = newGuardToken()
	if err != nil {
		return "", nil, func() {}, err
	}
	digest := sha256.Sum256([]byte(token))
	slot = &grantSlot{}
	g.mu.Lock()
	if g.slots == nil {
		g.slots = make(map[[32]byte]*grantSlot)
	}
	g.slots[digest] = slot
	g.mu.Unlock()
	var once sync.Once
	return token, slot, func() {
		once.Do(func() {
			g.mu.Lock()
			delete(g.slots, digest)
			g.mu.Unlock()
		})
	}, nil
}

// lookup is the grant a credential reaches now: nil for an unknown credential, and
// for a session's between its calls.
func (g *guardRegistry) lookup(token string) *brokerSession {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	digest := sha256.Sum256([]byte(token))
	g.mu.Lock()
	slot := g.slots[digest]
	g.mu.Unlock()
	if slot == nil {
		return nil
	}
	return slot.current()
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
