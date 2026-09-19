package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// HostRoute is one (method, path) the granted sandbox may reach through the host
// API bridge. Path is matched segment-by-segment against the request; a "*"
// segment matches exactly one non-empty path segment, so "/v1/lights/*/on"
// matches "/v1/lights/abc/on" but not "/v1/lights/on" or "/v1/lights/a/b/on".
type HostRoute struct {
	Method string // GET, PUT, POST, DELETE, PATCH (case-insensitive)
	Path   string // exact path, with optional "*" wildcard segments
}

// HostAPIGrant is an opt-in, per-run capability: attach it to a Request/
// ProjectRequest and that run can reach an HTTP host API (BaseURL) through an
// injected, generic client. It is OFF BY DEFAULT in two independent senses:
//
//   - a nil grant means the run is fully isolated (no network at all); and
//   - a grant with an empty Allow list reaches nothing — the embedder must inject
//     the exact routes it wants to expose. There are no implicit/default routes.
//
// The credential the run presents is produced per run by Minter (see TokenMinter),
// not stored on the grant: prefer a short-lived, route-scoped token so an
// exfiltrated credential is useless almost immediately. A nil Minter means the host
// API is reached with no Authorization header.
//
// The bridge is domain-agnostic: it knows nothing about any particular API.
// Embedders inject their own Allow list and, if they want domain ergonomics on top
// of the generic client, an optional Preamble of extra JS (e.g. a thin SDK that
// wraps host.get/host.put).
//
// Provider support:
//   - Docker keeps the container on --network none and brokers calls over a
//     bind-mounted unix socket; the broker enforces Allow and injects the token,
//     so the credential never enters the sandbox. Both snippet and project grants
//     are supported: a project preloads the same client module into every step
//     process (node --import) so project files get the identical host.* global.
//   - WASM calls the same broker core through a quota-bounded wazero host function;
//     the credential remains in Go and never enters QuickJS linear memory or its
//     JavaScript heap. Only snippet grants are supported.
//   - E2B can use the configured Plimsoll egress guard: E2B's network policy
//     permits only that guard host and injects a per-run guard header outside the
//     VM; the guard delegates to the same broker core, so the customer credential
//     still never enters the hostile VM. E2B grants remain disabled when no guard
//     URL is configured.
//
// In every case the blast radius is bounded by the credential's scopes, so a grant
// must be minimally scoped: Validate rejects a grant whose declared Scopes include
// code:run or "*".
type HostAPIGrant struct {
	BaseURL  string
	Allow    []HostRoute // routes the sandbox may reach; empty = deny everything
	Minter   TokenMinter // mints the per-run credential; nil = no Authorization header
	Scopes   []string    // declared scopes of the credential; must exclude code:run / "*"
	Global   string      // JS global exposing the client; "" defaults to "host"
	Preamble string      // optional extra JS appended after the client (domain SDK)

	// HealthCheck, when set, names a concrete GET route the per-run broker probes to
	// decide whether the host API is degraded. It is broker-operated backpressure, not
	// part of the guest-callable Allow surface: after an upstream 429/503 trips the
	// run's circuit breaker, the broker sheds further calls and (if this route is set)
	// probes it host-side with the run's credential, closing the breaker early when the
	// probe returns 2xx. Must be a concrete GET path (no wildcard), since the broker
	// sends an exact URL. Nil means reactive shedding only, with no recovery probe.
	HealthCheck *HostRoute
	// MaxCalls is the run's brokered-call budget, allowed and denied attempts
	// combined; 0 means DefaultMaxHostCalls. A profile raises it knowingly for a
	// workload that is a loop by design (a controller stepping a plant behind the
	// broker, one call per tick), never above MaxHostCallsCeiling, so a run can
	// still not make an unbounded number of upstream requests.
	MaxCalls int
}

// DefaultMaxHostCalls is a run's brokered-call budget when its grant sets none.
// MaxHostCallsCeiling is the most a grant may ask for.
const (
	DefaultMaxHostCalls = 256
	MaxHostCallsCeiling = 100_000
)

// CallBudget is the budget the broker enforces for this grant.
func (g *HostAPIGrant) CallBudget() int {
	if g == nil || g.MaxCalls <= 0 {
		return DefaultMaxHostCalls
	}
	return g.MaxCalls
}

// Clone returns an independent deep copy of the grant (nil-safe). Registry-style
// holders hand out clones instead of shared pointers so nothing downstream — a
// provider, a decorator, hostile-input handling — can mutate the loaded
// configuration for every later run. The Minter is shared by reference: it is an
// interface whose implementations must be stateless/concurrency-safe anyway.
func (g *HostAPIGrant) Clone() *HostAPIGrant {
	if g == nil {
		return nil
	}
	c := *g
	c.Allow = append([]HostRoute(nil), g.Allow...)
	c.Scopes = append([]string(nil), g.Scopes...)
	if g.HealthCheck != nil {
		hc := *g.HealthCheck
		c.HealthCheck = &hc
	}
	return &c
}

// TokenMinter issues the credential a granted run presents to the host API.
// plimsoll calls Mint once per run with that run's scope; the returned value is
// injected by Docker's host-side broker. Implementations should issue short-lived
// tokens scoped to exactly MintScope so theft is self-limiting.
type TokenMinter interface {
	Mint(ctx context.Context, scope MintScope) (MintedToken, error)
}

// SubjectBoundMinter is an optional interface a TokenMinter implements when the
// credential it issues embeds the caller identity (MintScope.Subject) — a
// per-session token. Such a minter MUST NOT run without an authenticated subject,
// or every unauthenticated caller collapses into one shared identity against the
// host API (defeating per-caller rate limiting, tenancy, and audit). The RPC layer
// checks HostAPIGrant.RequiresSubject before attaching a grant and refuses the run
// when no authenticated principal is present.
type SubjectBoundMinter interface {
	RequiresSubject() bool
}

// RequiresSubject reports whether this grant's minter issues subject-bound
// credentials and so needs an authenticated caller. Static tokens (which carry no
// caller identity) do not; a per-session JWT minter does.
func (g *HostAPIGrant) RequiresSubject() bool {
	if g == nil || g.Minter == nil {
		return false
	}
	m, ok := g.Minter.(SubjectBoundMinter)
	return ok && m.RequiresSubject()
}

// MintScope is what a run is permitted to do, handed to the minter so it can issue
// a credential scoped to exactly that and no wider — including WHO the run is for
// (Subject), so a minter can issue per-session/per-caller tokens.
type MintScope struct {
	BaseURL string
	Allow   []HostRoute
	Scopes  []string      // the grant's declared scopes, for the minter to embed
	TTL     time.Duration // desired lifetime ~ the run's wall-clock budget
	Subject string        // the calling principal's identity ("" = anonymous)
}

type subjectKey struct{}

// WithSubject stamps the calling principal's identity onto ctx so a TokenMinter can
// mint a credential scoped to that specific caller (per-session tokens). The RPC
// layer sets it from the authenticated principal; "" means anonymous.
func WithSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, subjectKey{}, subject)
}

func subjectFromContext(ctx context.Context) string {
	s, _ := ctx.Value(subjectKey{}).(string)
	return s
}

// MintedToken is a credential from a TokenMinter. ExpiresAt is informational
// (zero = no expiry, e.g. a static token).
type MintedToken struct {
	Value     string
	ExpiresAt time.Time
}

// StaticToken returns a TokenMinter that always issues value unchanged. Use it only
// for host APIs that cannot mint per-run credentials; a static token cannot be
// time-boxed, so a real minter is strongly preferred. Declare what the token
// carries via HostAPIGrant.Scopes so Validate can reject a forbidden one.
func StaticToken(value string) TokenMinter { return staticMinter{value: value} }

type staticMinter struct{ value string }

func (m staticMinter) Mint(context.Context, MintScope) (MintedToken, error) {
	return MintedToken{Value: m.value}, nil
}

// forbiddenGrantScopes must never appear on a host-API credential: code:run would
// let sandboxed code re-enter plimsoll, "*" would reach everything.
var forbiddenGrantScopes = map[string]bool{"code:run": true, "*": true}

// Validate reports whether the grant is well-formed and safely scoped. It is called
// when a profile is loaded and again defensively before each run.
func (g *HostAPIGrant) Validate() error {
	if !utf8.ValidString(g.BaseURL) || strings.TrimSpace(g.BaseURL) == "" {
		return errors.New("host-api grant: BaseURL is required")
	}
	if !utf8.ValidString(g.Global) || !utf8.ValidString(g.Preamble) {
		return errors.New("host-api grant: Global and Preamble must be valid UTF-8")
	}
	if g.MaxCalls < 0 || g.MaxCalls > MaxHostCallsCeiling {
		return fmt.Errorf("host-api grant: MaxCalls must be 0 (the default, %d) or between 1 and %d", DefaultMaxHostCalls, MaxHostCallsCeiling)
	}
	u, err := url.Parse(g.BaseURL)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("host-api grant: BaseURL %q is not a valid URL with a host", g.BaseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("host-api grant: BaseURL scheme must be http or https")
	}
	if u.Scheme == "http" && !strings.EqualFold(u.Hostname(), "localhost") {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("host-api grant: non-loopback BaseURL must use https")
		}
	}
	// Providers join the guest path to BaseURL through different HTTP stacks.
	// Keeping BaseURL origin-only guarantees they all authorize and send the same
	// path; userinfo, a prefix path, query, or fragment would make that ambiguous.
	if u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return fmt.Errorf("host-api grant: BaseURL must be an origin only (scheme and host, with optional port)")
	}
	for _, s := range g.Scopes {
		// Each entry is one OAuth-style scope token. The JWT minter serializes this
		// slice by joining entries with spaces, so permitting whitespace inside one
		// entry would let a declaration such as "safe code:run" smuggle a second,
		// forbidden scope into the minted credential.
		if !utf8.ValidString(s) || s == "" || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
			return fmt.Errorf("host-api grant: scope %q must be one non-empty token without whitespace", s)
		}
		if forbiddenGrantScopes[s] {
			return fmt.Errorf("host-api grant: forbidden scope %q (a capability token must never carry code:run or %q)", s, "*")
		}
	}
	seenRoutes := make(map[string]struct{}, len(g.Allow))
	for _, route := range g.Allow {
		if !utf8.ValidString(route.Method) || !utf8.ValidString(route.Path) {
			return errors.New("host-api grant: route method and path must be valid UTF-8")
		}
		method := strings.ToUpper(route.Method)
		if route.Method != strings.TrimSpace(route.Method) {
			return fmt.Errorf("host-api grant: route method %q has surrounding whitespace", route.Method)
		}
		switch method {
		case "GET", "PUT", "POST", "DELETE", "PATCH":
		default:
			return fmt.Errorf("host-api grant: route method %q is not one of GET, PUT, POST, DELETE, PATCH", route.Method)
		}
		if err := validateRoutePattern(route.Path); err != nil {
			return fmt.Errorf("host-api grant: route %s %q: %w", method, route.Path, err)
		}
		key := method + " " + route.Path
		if _, exists := seenRoutes[key]; exists {
			return fmt.Errorf("host-api grant: duplicate route %s", key)
		}
		seenRoutes[key] = struct{}{}
	}
	if hc := g.HealthCheck; hc != nil {
		// A broker-operated probe must be a safe, idempotent read the broker can send as
		// an EXACT URL: GET only, and a concrete path (a wildcard has no single URL to
		// probe). It is authority the broker uses, not a route the guest may call.
		if !utf8.ValidString(hc.Method) || !utf8.ValidString(hc.Path) {
			return errors.New("host-api grant: health_check method and path must be valid UTF-8")
		}
		if hc.Method != strings.TrimSpace(hc.Method) {
			return fmt.Errorf("host-api grant: health_check method %q has surrounding whitespace", hc.Method)
		}
		if strings.ToUpper(hc.Method) != "GET" {
			return fmt.Errorf("host-api grant: health_check must be a GET route, got %q", hc.Method)
		}
		if strings.Contains(hc.Path, "*") {
			return errors.New("host-api grant: health_check path must be concrete (no wildcard); the broker probes an exact URL")
		}
		if err := validateRoutePattern(hc.Path); err != nil {
			return fmt.Errorf("host-api grant: health_check %q: %w", hc.Path, err)
		}
	}
	return nil
}

func validateRoutePattern(pattern string) error {
	if pattern == "" || !strings.HasPrefix(pattern, "/") {
		return errors.New("path must be absolute")
	}
	if strings.Contains(pattern, "\\") || strings.ContainsAny(pattern, "?#") || strings.IndexFunc(pattern, unicode.IsControl) >= 0 {
		return errors.New("path contains a backslash, control character, query, or fragment")
	}
	decoded, err := url.PathUnescape(pattern)
	if err != nil || decoded != pattern {
		return errors.New("path must be decoded and canonical")
	}
	if path.Clean(pattern) != pattern {
		return errors.New("path must not contain empty, dot, or traversal segments")
	}
	// Profiles must not load routes that an HTTP client would percent-encode on
	// the wire. Replace wildcards with a representative safe segment before the
	// check; the wildcard marker itself is policy syntax, not a request byte.
	wireExample := strings.ReplaceAll(pattern, "*", "x")
	if (&url.URL{Path: wireExample}).EscapedPath() != wireExample {
		return errors.New("path contains bytes that require wire encoding")
	}
	for _, segment := range strings.Split(pattern, "/") {
		if strings.Contains(segment, "*") && segment != "*" {
			return errors.New("wildcard must occupy a complete path segment")
		}
	}
	return nil
}

// baseHost returns the host (no port) of BaseURL, or "" if it cannot be parsed.
// Providers that can restrict egress (e2b) allow exactly this host.
func (g *HostAPIGrant) baseHost() string {
	u, err := url.Parse(g.BaseURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// credential mints the per-run token for a run with the given wall-clock budget.
// It returns "" when the grant has no minter (an unauthenticated host API).
func (g *HostAPIGrant) credential(ctx context.Context, budget time.Duration) (string, error) {
	if g == nil || g.Minter == nil {
		return "", nil
	}
	subject := subjectFromContext(ctx)
	if g.RequiresSubject() && (!utf8.ValidString(subject) || subject == "" || subject == "*" ||
		subject != strings.TrimSpace(subject) || strings.IndexFunc(subject, unicode.IsControl) >= 0) {
		return "", errors.New("host-api grant: subject-bound minter requires a stable authenticated subject")
	}
	tok, err := g.Minter.Mint(ctx, MintScope{
		BaseURL: g.BaseURL,
		Allow:   append([]HostRoute(nil), g.Allow...),
		Scopes:  append([]string(nil), g.Scopes...),
		TTL:     budget,
		Subject: subject,
	})
	if err != nil {
		return "", err
	}
	if tok.Value == "" || strings.IndexFunc(tok.Value, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return "", errors.New("host-api grant: minter returned an empty or invalid bearer token")
	}
	if !tok.ExpiresAt.IsZero() && !tok.ExpiresAt.After(time.Now()) {
		return "", errors.New("host-api grant: minter returned an expired bearer token")
	}
	return tok.Value, nil
}

func (g *HostAPIGrant) globalName() string {
	if g.Global == "" {
		return "host"
	}
	return g.Global
}

// routeAllowed reports whether method+path is permitted by the grant's allowlist.
// It first rejects any path containing a traversal segment, then requires an
// explicit HostRoute match — so an empty Allow list denies everything.
//
// The path MUST already be in decoded, canonical form: a guest could otherwise
// percent-encode the structural characters to smuggle traversal past this check
// while the upstream (or the docker reverse-proxy) decodes them on the wire — e.g.
// "%2f" -> "/" (an extra segment the "*" wildcard never bound) or "%2e%2e" -> ".."
// (traversal). We match on the decoded path and reject anything whose decoded form
// differs from the raw path, so the string we approve is byte-for-byte the string
// that is actually sent. Any decode error is also a denial.
func (g *HostAPIGrant) routeAllowed(method, requestPath string) bool {
	_, ok := g.matchRoute(method, requestPath)
	return ok
}

// matchRoute returns the allowlist HostRoute that permits method+requestPath, if
// any, applying the same guards as routeAllowed. The returned route's Path is the
// grant's TEMPLATE (with "*" wildcard segments), never the raw requestPath — this
// is the redaction point for telemetry: the broker records route.Path, so a
// concrete id or query value from the request can never enter a CallTrace.
func (g *HostAPIGrant) matchRoute(method, requestPath string) (HostRoute, bool) {
	decoded, err := url.PathUnescape(requestPath)
	if err != nil || decoded != requestPath {
		return HostRoute{}, false
	}
	// A query or fragment would be matched here as part of a path segment, but
	// net/http strips it at "?"/"#" when building the request — so the route we
	// approve would differ from the one actually hit (e.g. "/p/x?/s" matches the
	// allowlisted "/p/*/s" but reaches "/p/x" on the wire). Reject both, keeping the
	// same approve==wire invariant as the percent-encoding check above.
	if requestPath == "" || !strings.HasPrefix(requestPath, "/") || strings.Contains(requestPath, "\\") ||
		strings.ContainsAny(requestPath, "?#") || strings.IndexFunc(requestPath, unicode.IsControl) >= 0 ||
		path.Clean(requestPath) != requestPath || (&url.URL{Path: requestPath}).EscapedPath() != requestPath {
		return HostRoute{}, false
	}
	segs := strings.Split(requestPath, "/")
	for _, s := range segs {
		if s == "." || s == ".." {
			return HostRoute{}, false
		}
	}
	for _, r := range g.Allow {
		if strings.EqualFold(r.Method, method) && pathMatches(r.Path, segs) {
			return r, true
		}
	}
	return HostRoute{}, false
}

// pathMatches matches a route pattern (with "*" wildcard segments) against the
// already-split request path.
func pathMatches(pattern string, segs []string) bool {
	ps := strings.Split(pattern, "/")
	if len(ps) != len(segs) {
		return false
	}
	for i := range ps {
		if ps[i] == "*" {
			if segs[i] == "" { // a wildcard must bind a non-empty segment
				return false
			}
			continue
		}
		if ps[i] != segs[i] {
			return false
		}
	}
	return true
}

// withHostSDK prepends the Docker unix-socket client (and any embedder Preamble)
// when a grant is set. E2B uses the separate guard client because its transport is
// an E2B-controlled HTTPS egress path rather than a host-mounted Unix socket.
func withHostSDK(code string, grant *HostAPIGrant) string {
	if grant == nil {
		return code
	}
	preamble := hostNetPreamble(grant.globalName(), grant.Allow)
	if grant.Preamble != "" {
		preamble += "\n" + grant.Preamble
	}
	return preamble + "\n" + code
}

// hostSDKModule returns the standalone Docker host-API client as a preloadable ES
// module: it defines globalThis[grant.globalName()] and, when present, layers the
// grant's domain Preamble on top. Unlike withHostSDK it carries no user code, so the
// project runner can preload it into every step process (node --import) and give
// project files the SAME global host.* contract as a snippet. The template is an IIFE
// with no load-time side effects (it only defines the global; the socket + bearer stay
// host-side), so preloading it can never fail or perturb a step. Returns "" for a nil
// grant.
func hostSDKModule(grant *HostAPIGrant) string {
	if grant == nil {
		return ""
	}
	preamble := hostNetPreamble(grant.globalName(), grant.Allow)
	if grant.Preamble != "" {
		preamble += "\n" + grant.Preamble
	}
	return preamble
}

// withWasmHostSDK prepends the in-process QuickJS client. The private native
// primitive only moves a bounded JSON envelope across WASM linear memory; the Go
// broker session still owns the grant, credential, quotas, and upstream HTTP.
func withWasmHostSDK(code string, grant *HostAPIGrant) string {
	if grant == nil {
		return code
	}
	preamble := hostWasmPreamble(grant.globalName(), grant.Allow)
	if grant.Preamble != "" {
		preamble += "\n" + grant.Preamble
	}
	return preamble + "\n" + code
}

// allowJSON serializes the allowlist for the injected JS client's own gate. Uses
// short keys to keep the preamble compact. A nil/empty list marshals to "[]", which
// makes the client reach nothing — matching the Go-side "empty Allow denies all".
func allowJSON(allow []HostRoute) string {
	type r struct {
		M string `json:"m"`
		P string `json:"p"`
	}
	out := make([]r, 0, len(allow))
	for _, a := range allow {
		out = append(out, r{M: a.Method, P: a.Path})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// hostNetPreamble builds the generic JS client for Docker. It reaches the host API
// only over a brokered unix socket; the broker enforces routes and adds the bearer,
// so neither the credential nor an unrestricted network transport enters the guest.
// It exposes a generic client at globalThis[global]: call(method, path, body) plus
// get/put/post/del helpers. It is intentionally domain-agnostic.
//
// The allowlist is baked into the client so it only OFFERS Allow-ed calls. The
// shared broker core remains the authoritative gate; the client-side check is
// defense in depth and a clearer error for cooperative code.
func hostNetPreamble(global string, allow []HostRoute) string {
	globalJSON, err := json.Marshal(global)
	if err != nil {
		globalJSON = []byte(`"host"`)
	}
	s := strings.ReplaceAll(hostNetClientTmpl, "__HOST_JSON__", string(globalJSON))
	return strings.ReplaceAll(s, "__ALLOW_JSON__", allowJSON(allow))
}

// withE2BHostSDK prepends the remote E2B guard client. The guard URL is an
// operator-controlled endpoint, never a caller-supplied origin. E2B's network
// policy allows only its host and injects the per-run authentication header
// outside the guest; the guest therefore has no bearer or guard secret to steal.
func withE2BHostSDK(code string, grant *HostAPIGrant, guardURL string) string {
	if grant == nil {
		return code
	}
	globalJSON, err := json.Marshal(grant.globalName())
	if err != nil {
		globalJSON = []byte(`"host"`)
	}
	guardJSON, err := json.Marshal(guardURL)
	if err != nil {
		guardJSON = []byte(`""`)
	}
	preamble := strings.ReplaceAll(hostE2BClientTmpl, "__HOST_JSON__", string(globalJSON))
	preamble = strings.ReplaceAll(preamble, "__GUARD_URL_JSON__", string(guardJSON))
	preamble = strings.ReplaceAll(preamble, "__ALLOW_JSON__", allowJSON(grant.Allow))
	if grant.Preamble != "" {
		preamble += "\n" + grant.Preamble
	}
	return preamble + "\n" + code
}

// hostE2BSDKModule is the project equivalent of withE2BHostSDK: it carries only
// the preinjected global, not user code or a credential. E2B preloads it into every
// Node step through NODE_OPTIONS so snippets and projects share one host.* surface.
func hostE2BSDKModule(grant *HostAPIGrant, guardURL string) string {
	if grant == nil {
		return ""
	}
	return withE2BHostSDK("", grant, guardURL)
}

// hostWasmPreamble exposes the same domain-agnostic Promise API as Docker, but
// calls the synchronous QuickJS native primitive implemented by
// coderunner-hostcall.c. The Promise wrapper keeps host SDKs portable between the
// Node and QuickJS providers.
func hostWasmPreamble(global string, allow []HostRoute) string {
	globalJSON, err := json.Marshal(global)
	if err != nil {
		globalJSON = []byte(`"host"`)
	}
	s := strings.ReplaceAll(hostWasmClientTmpl, "__HOST_JSON__", string(globalJSON))
	return strings.ReplaceAll(s, "__ALLOW_JSON__", allowJSON(allow))
}

const hostNetClientTmpl = `
globalThis[__HOST_JSON__] = (function () {
  const socket = process.env.HOST_API_SOCKET;
  // Allowlist baked in host-side; the client offers only Allow-ed calls. Mirrors the
  // Go routeAllowed check (decoded==raw, no query/fragment, no . / .. segments,
  // segment-wise "*" match) so the client and the docker broker agree on what a grant
  // permits. The host-side shared broker remains the authoritative boundary.
  const __allow = __ALLOW_JSON__;
  function __segMatch(pattern, segs) {
    const ps = pattern.split("/");
    if (ps.length !== segs.length) return false;
    for (let i = 0; i < ps.length; i++) {
      if (ps[i] === "*") { if (segs[i] === "") return false; continue; }
      if (ps[i] !== segs[i]) return false;
    }
    return true;
  }
  function __allowed(method, path) {
    try { if (decodeURIComponent(path) !== path) return false; } catch { return false; }
    if (encodeURI(path) !== path) return false;
    if (!path.startsWith("/") || path.indexOf("\\") >= 0 || path.indexOf("?") >= 0 || path.indexOf("#") >= 0 || /[\u0000-\u001f\u007f]/.test(path)) return false;
    const segs = path.split("/");
    for (const s of segs) { if (s === "." || s === "..") return false; }
    const m = String(method).toUpperCase();
    for (const r of __allow) { if (String(r.m).toUpperCase() === m && __segMatch(r.p, segs)) return true; }
    return false;
  }
  function headers(payload) {
    return {
      "content-type": "application/json",
      ...(payload ? { "content-length": Buffer.byteLength(payload) } : {}),
    };
  }
  async function viaSocket(method, path, body) {
	if (!socket) throw new Error("host api broker unavailable");
    const http = (await import("node:http")).default;
    const payload = body !== undefined ? JSON.stringify(body) : undefined;
    return new Promise((resolve, reject) => {
      const req = http.request({ socketPath: socket, path, method, headers: headers(payload) }, (res) => {
        let text = ""; res.setEncoding("utf8");
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          let data; try { data = JSON.parse(text); } catch { data = text; }
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(data);
          else reject(new Error("host api " + res.statusCode + ": " + text));
        });
      });
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }
  function call(method, path, body) {
    if (!__allowed(method, path)) {
      return Promise.reject(new Error("host api call not permitted by sandbox capability: " + method + " " + path));
    }
    return viaSocket(method, path, body);
  }
  return {
    call,
    get: (p) => call("GET", p),
    put: (p, b) => call("PUT", p, b),
    post: (p, b) => call("POST", p, b),
    patch: (p, b) => call("PATCH", p, b),
    del: (p) => call("DELETE", p),
  };
})();
`

const hostE2BClientTmpl = `
globalThis[__HOST_JSON__] = (function () {
  const __guardURL = __GUARD_URL_JSON__;
  const __allow = __ALLOW_JSON__;
  function __segMatch(pattern, segs) {
    const ps = pattern.split("/");
    if (ps.length !== segs.length) return false;
    for (let i = 0; i < ps.length; i++) {
      if (ps[i] === "*") { if (segs[i] === "") return false; continue; }
      if (ps[i] !== segs[i]) return false;
    }
    return true;
  }
  function __allowed(method, path) {
    try { if (decodeURIComponent(path) !== path) return false; } catch { return false; }
    if (encodeURI(path) !== path) return false;
    if (!path.startsWith("/") || path.indexOf("\\") >= 0 || path.indexOf("?") >= 0 || path.indexOf("#") >= 0 || /[\u0000-\u001f\u007f]/.test(path)) return false;
    const segs = path.split("/");
    for (const s of segs) { if (s === "." || s === "..") return false; }
    const m = String(method).toUpperCase();
    for (const r of __allow) { if (String(r.m).toUpperCase() === m && __segMatch(r.p, segs)) return true; }
    return false;
  }
  async function viaGuard(method, path, body) {
    if (!__guardURL) throw new Error("host api guard unavailable");
    const payload = { method: String(method).toUpperCase(), path: path };
    if (body !== undefined) payload.body = body;
    const response = await fetch(__guardURL, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const text = await response.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    if (response.status >= 200 && response.status < 300) return data;
    throw new Error("host api " + response.status + ": " + text);
  }
  function call(method, path, body) {
    method = String(method).toUpperCase();
    path = String(path);
    if (!__allowed(method, path)) {
      return Promise.reject(new Error("host api call not permitted by sandbox capability: " + method + " " + path));
    }
    return viaGuard(method, path, body);
  }
  return {
    call,
    get: (p) => call("GET", p),
    put: (p, b) => call("PUT", p, b),
    post: (p, b) => call("POST", p, b),
    patch: (p, b) => call("PATCH", p, b),
    del: (p) => call("DELETE", p),
  };
})();
`

const hostWasmClientTmpl = `
globalThis[__HOST_JSON__] = (function () {
  const __allow = __ALLOW_JSON__;
  function __segMatch(pattern, segs) {
    const ps = pattern.split("/");
    if (ps.length !== segs.length) return false;
    for (let i = 0; i < ps.length; i++) {
      if (ps[i] === "*") { if (segs[i] === "") return false; continue; }
      if (ps[i] !== segs[i]) return false;
    }
    return true;
  }
  function __allowed(method, path) {
    try { if (decodeURIComponent(path) !== path) return false; } catch { return false; }
    if (encodeURI(path) !== path) return false;
    if (!path.startsWith("/") || path.indexOf("\\") >= 0 || path.indexOf("?") >= 0 || path.indexOf("#") >= 0 || /[\u0000-\u001f\u007f]/.test(path)) return false;
    const segs = path.split("/");
    for (const s of segs) { if (s === "." || s === "..") return false; }
    const m = String(method).toUpperCase();
    for (const r of __allow) { if (String(r.m).toUpperCase() === m && __segMatch(r.p, segs)) return true; }
    return false;
  }
  function call(method, path, body) {
    method = String(method).toUpperCase();
    path = String(path);
    if (!__allowed(method, path)) {
      return Promise.reject(new Error("host api call not permitted by sandbox capability: " + method + " " + path));
    }
    let envelope;
    try {
      const request = { method: method, path: path };
      if (body !== undefined) request.body = body;
      envelope = JSON.stringify(request);
    } catch (e) {
      return Promise.reject(e);
    }
    let response;
    try {
      response = globalThis.__coderunner_host_call(envelope);
    } catch (e) {
      return Promise.reject(e);
    }
    let data;
    try { data = JSON.parse(response.body); } catch { data = response.body; }
    if (response.status >= 200 && response.status < 300) return Promise.resolve(data);
    return Promise.reject(new Error("host api " + response.status + ": " + response.body));
  }
  return {
    call,
    get: (p) => call("GET", p),
    put: (p, b) => call("PUT", p, b),
    post: (p, b) => call("POST", p, b),
    patch: (p, b) => call("PATCH", p, b),
    del: (p) => call("DELETE", p),
  };
})();
`
