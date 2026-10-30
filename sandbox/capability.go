package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"mime"
	"net"
	"net/url"
	"path"
	"slices"
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
	// RouteMaxCalls caps the calls one run may make to a route of Allow, keyed by the
	// entry itself, for a route whose call spends (one that starts a paid GPU job, say).
	// MaxCalls bounds all routes together, so without it a run allowed to poll a job's
	// status a hundred times could start a hundred jobs. A route it does not name is
	// bounded by MaxCalls alone. A call counts against every capped entry its path
	// matches, so overlapping entries and their order cannot route a call around a cap.
	// Validate refuses an entry of the same method that matches a capped entry's calls
	// with a "*" in place of one of its fixed segments: an upstream may serve "ep1.json",
	// "0123" or "ep1." as the capped "ep1" or "123", a spelling only it knows, so a call
	// matched by the wildcard alone would reach the capped route uncounted.
	RouteMaxCalls map[HostRoute]int
	// AllowInSessions permits the grant on a call inside a session. It is off by
	// default because a grant is a per-call permission and a session keeps code alive
	// between calls: while the call runs, anything an earlier call of the session left
	// running can use the grant too. A session refuses a granted call without it before
	// anything runs (CheckSessionGrant).
	AllowInSessions bool
	// PassHeaders names the request headers the broker copies from the guest's request
	// to the upstream one, first value only, checked as a field value (visible ASCII,
	// space and tab, at most maxPassHeaderValueBytes). Every other guest header is
	// dropped, as it always was. It exists for the headers an API requires that a
	// standard client sends itself (the Claude API's anthropic-version, the optional
	// anthropic-beta and OpenAI-Beta). Validate refuses a name the broker owns or that
	// shapes the connection (Authorization, Host, Content-Type, Content-Length,
	// Transfer-Encoding, the X-Plimsoll-* family) and one an API reads an API key from
	// (x-api-key, api-key and the rest of providerKeyHeaders): see passHeaderRefused.
	PassHeaders []string
	// SetHeaders are request headers the broker sets on every upstream request with the
	// grant's own value, whatever the guest sent: for a header that picks where the
	// run's credential acts (anthropic-workspace-id, OpenAI-Organization, OpenAI-Project)
	// or one the operator pins rather than trusting the guest's (anthropic-version). A
	// header has one owner: a name is the grant's to set or the guest's to pass, never
	// both. Validate refuses every name PassHeaders refuses, an API key header among
	// them, since a credential is the Minter's and never a value in a grants file, and a
	// value that is empty, longer than maxPassHeaderValueBytes, outside visible ASCII,
	// space and tab, or padded with either.
	SetHeaders map[string]string
	// SDKEnv is the environment a granted guest process gets so that a standard client
	// library finds the broker without any plimsoll-specific code: each entry is a
	// variable name and a literal value, in which "{origin}" stands for the loopback
	// origin the provider serves the broker on inside the sandbox
	// ({"OPENAI_BASE_URL": "{origin}/v1", "OPENAI_API_KEY": "plimsoll-grant"}). The
	// client libraries refuse to start without a key, so a profile names a dummy one;
	// the broker never forwards it. Validate refuses a name plimsoll or the dynamic
	// loader reads (sdkEnvNameRefused) and a value with a control character.
	SDKEnv map[string]string
	// RouteMaxRequestBytes sets the request body limit for an allow entry (keyed by the
	// entry as written in Allow), for a route that takes an upload; an entry it does not
	// name keeps the default (maxHostRequestBytes, 1 MiB). A raised limit changes how the
	// body moves: it is passed through to the API as it arrives instead of buffered. A
	// body over the route's limit is refused with 413 before anything is sent when its
	// length is declared, and cut at the limit when it is not. Validate keeps each limit
	// between 1 and MaxRouteRequestBytes and under the run's MaxRequestBytes.
	RouteMaxRequestBytes map[HostRoute]int64
	// RouteContentTypes names the media types the broker takes from the guest's
	// Content-Type on an allow entry and sends to the API ("multipart/form-data"), with
	// the boundary and charset parameters alone, checked. Every route takes
	// application/json. On a route that lists types, a body of another type is refused
	// with 415; on a route that lists none the body is sent as application/json, as it
	// always was, whatever the guest's header said.
	RouteContentTypes map[HostRoute][]string
	// MaxRequestBytes is the run's request body bytes across all its brokered calls,
	// what the grant lets a run send to the API in all; 0 means DefaultMaxRequestBytes,
	// and Validate refuses more than MaxRequestBytesCeiling. A call whose body would
	// take the total past it is refused with 413 before anything is sent.
	MaxRequestBytes int64
}

// Request body budgets. maxHostRequestBytes (broker.go) is every call's limit unless
// the profile raises it for a route; the run's total is the number the operator chose
// for what a run may send, not an accident of the call budget times the body limit.
const (
	// MaxRouteRequestBytes is the most a profile may let one call send on a route: 512
	// MiB, so the Claude Files API's 500 MB request limit fits under it (the plan's D4).
	MaxRouteRequestBytes = 512 << 20
	// DefaultMaxRequestBytes is a run's total when the profile sets none: what the
	// default call budget (DefaultMaxHostCalls) could send at the default body limit.
	DefaultMaxRequestBytes = 256 << 20
	// MaxRequestBytesCeiling is the most a profile may let a run send in all: 1 GiB.
	MaxRequestBytesCeiling = 1 << 30
)

// requestLimit is the request body limit for a call matched to route: the profile's
// for the entry, or the default.
func (g *HostAPIGrant) requestLimit(route HostRoute) int64 {
	if g != nil {
		if n := g.RouteMaxRequestBytes[route]; n > 0 {
			return n
		}
	}
	return maxHostRequestBytes
}

// requestBudget is the run's total request body bytes.
func (g *HostAPIGrant) requestBudget() int64 {
	if g != nil && g.MaxRequestBytes > 0 {
		return g.MaxRequestBytes
	}
	return DefaultMaxRequestBytes
}

// requestContentType is the Content-Type the broker sends for a body on route, given
// the guest's header: application/json when the guest sent none, or JSON, or the
// route lists no type; the guest's media type when the route lists it, rebuilt from
// the type and its boundary and charset parameters alone, each checked (RFC 2046
// boundary characters, at most 70; a charset of token characters), so a parameter
// cannot carry a line break or a second header into the request. The second result is
// false when the body's type is refused.
func (g *HostAPIGrant) requestContentType(route HostRoute, guest string) (string, bool) {
	types := g.RouteContentTypes[route]
	if len(types) == 0 || strings.TrimSpace(guest) == "" {
		return "application/json", true
	}
	mediaType, params, err := mime.ParseMediaType(guest)
	if err != nil {
		return "", false
	}
	if mediaType == "application/json" {
		return "application/json", true
	}
	if !slices.Contains(types, mediaType) {
		return "", false
	}
	kept := make(map[string]string, 2)
	if v, ok := params["boundary"]; ok {
		if !validBoundary(v) {
			return "", false
		}
		kept["boundary"] = v
	}
	if v, ok := params["charset"]; ok {
		if v == "" || len(v) > 40 || !isToken(v) {
			return "", false
		}
		kept["charset"] = v
	}
	return mime.FormatMediaType(mediaType, kept), true
}

// validBoundary reports whether v is a multipart boundary as RFC 2046 section 5.1.1
// defines one: 1 to 70 characters from its bchars set, not ending in a space.
func validBoundary(v string) bool {
	if v == "" || len(v) > 70 || strings.HasSuffix(v, " ") {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("'()+_,-./:=? ", r):
		default:
			return false
		}
	}
	return true
}

// isToken reports whether v is an RFC 9110 token: visible ASCII with no separator.
func isToken(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune(`"(),/:;<=>?@[\]{}`, r) {
			return false
		}
	}
	return true
}

// validRequestMediaType reports whether t may be a RouteContentTypes entry: a
// lowercase type and subtype, each a token, no wildcard, and not a type that is
// application/json (every route takes it already), multipart/byteranges or a
// message/* type (an HTTP message inside the body is the one shape an upstream may
// read as a second request).
func validRequestMediaType(t string) bool {
	kind, sub, ok := strings.Cut(t, "/")
	if !ok || !isToken(kind) || !isToken(sub) || strings.ToLower(t) != t || strings.Contains(t, "*") {
		return false
	}
	return t != "application/json" && t != "multipart/byteranges" && kind != "message"
}

// maxPassHeaderValueBytes bounds one passed header value; the API headers this is for
// are short tokens (a date, a comma-separated list of feature names).
const maxPassHeaderValueBytes = 1024

// maxSDKEnvValueBytes bounds one SDKEnv value: a URL or a dummy key.
const maxSDKEnvValueBytes = 1024

// sdkEnvOriginToken is the placeholder in an SDKEnv value for the broker's loopback
// origin inside the sandbox.
const sdkEnvOriginToken = "{origin}"

// passHeaderRefused reports whether name may not be a PassHeaders entry: the broker
// sets it itself (the credential, the body's type and length), the transport owns it
// (connection and framing headers, which a forwarded value could use to desynchronize
// the upstream), it names the guest's own origin (Host), it carries a proxy's or
// plimsoll's own trust (Forwarded, X-Forwarded-*, X-Plimsoll-*), an API reads it as
// an API key (providerKeyHeaders), or it is not a valid field name at all.
func passHeaderRefused(name string) bool {
	if !validFieldName(name) {
		return true
	}
	lower := strings.ToLower(name)
	switch lower {
	case "authorization", "proxy-authorization", "cookie", "host", "content-length", "content-type",
		"transfer-encoding", "connection", "upgrade", "te", "trailer", "keep-alive", "expect",
		"forwarded", "via", "accept-encoding":
		return true
	}
	if slices.Contains(providerKeyHeaders, lower) {
		return true
	}
	return strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-plimsoll-") || strings.HasPrefix(lower, "proxy-")
}

// providerKeyHeaders are the headers model APIs read an API key from besides
// Authorization. HTTP standardizes no other credential field (RFC 9110 has Authorization
// and Proxy-Authorization), so the list is what the APIs document, and it is the list an
// AI gateway strips from its clients by default (LiteLLM, from v1.82.0: x-api-key,
// x-goog-api-key and api-key, with ocp-apim-subscription-key among the provider key
// headers it forwards only when told to). The Claude API still accepts its key in
// x-api-key beside Authorization (platform.claude.com, authentication, read 2026-10-29),
// the Gemini API reads x-goog-api-key, Azure OpenAI api-key, and Azure API Management
// ocp-apim-subscription-key. Passing one would let the guest's own key ride beside the
// broker's credential, and which of two keys an API honors is documented nowhere: the
// guest, not the profile, could choose the account the upstream acts for, and through an
// upload route put data into an account of its own.
var providerKeyHeaders = []string{"x-api-key", "x-goog-api-key", "api-key", "ocp-apim-subscription-key"}

// validFieldName reports whether name is an RFC 9110 token: one or more of the
// characters allowed in a header field name.
func validFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// validFieldValue reports whether v may be forwarded as a header value: visible ASCII,
// space and horizontal tab only, bounded. A CR, LF or NUL, or a byte past 0x7e, is
// refused whole rather than cleaned, so no value reaches the upstream in a form the
// guest did not send.
func validFieldValue(v string) bool {
	if len(v) > maxPassHeaderValueBytes {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\t' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

// passedHeaders returns the guest headers the grant lets through, from the raw guest
// request headers: for each PassHeaders name, the first value, when it is a valid field
// value. Names are matched without regard to case. A nil guest header set (the JSON
// envelope clients, which send none) passes nothing.
func (g *HostAPIGrant) passedHeaders(guest map[string][]string) map[string]string {
	if g == nil || len(g.PassHeaders) == 0 || len(guest) == 0 {
		return nil
	}
	var out map[string]string
	for _, name := range g.PassHeaders {
		for k, vs := range guest {
			if !strings.EqualFold(k, name) || len(vs) == 0 || !validFieldValue(vs[0]) {
				continue
			}
			if out == nil {
				out = make(map[string]string, len(g.PassHeaders))
			}
			out[name] = vs[0]
			break
		}
	}
	return out
}

// sdkEnvNameRefused reports whether name may not be an SDKEnv variable: not a plain
// uppercase identifier, or one plimsoll or the dynamic loader reads at startup (the
// loader names are the ones Preflight refuses on an image, checkLoaderEnv).
func sdkEnvNameRefused(name string) bool {
	if name == "" || (name[0] >= '0' && name[0] <= '9') {
		return true
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return true
		}
	}
	switch name {
	case "PATH", "HOME", "HOSTNAME", "NODE_OPTIONS", "GLIBC_TUNABLES", "LOCPATH", "NLSPATH", "GCONV_PATH", HostAPISocketEnv, HostAPIListenEnv:
		// The last two are plimsoll's own entries in the guest environment; a profile's
		// entry of the same name would come later and win, moving or breaking the
		// broker's socket or the forwarder (release review, 2026-10-28).
		return true
	}
	return strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "PLIMSOLL_") || strings.HasPrefix(name, "NODE_")
}

// sdkEnv renders the grant's SDKEnv as NAME=value entries for origin, sorted by name
// so every provider hands the guest the same list. Nil for a grant without any.
func (g *HostAPIGrant) sdkEnv(origin string) []string {
	if g == nil || len(g.SDKEnv) == 0 {
		return nil
	}
	names := slices.Sorted(maps.Keys(g.SDKEnv))
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, name+"="+strings.ReplaceAll(g.SDKEnv[name], sdkEnvOriginToken, origin))
	}
	return out
}

// ErrGrantNotForSessions is a granted call inside a session whose grant does not set
// AllowInSessions. It is refused before anything runs.
var ErrGrantNotForSessions = errors.New("sandbox: the grant does not allow calls in a session")

// CheckSessionGrant is the check every session provider makes before a call that may
// carry a grant: nil without a grant or when the grant allows sessions, otherwise a
// refusal marked not dispatched, reason permission.
func CheckSessionGrant(g *HostAPIGrant) error {
	if g == nil {
		return nil
	}
	if g.WantsLoopback() {
		// A session's container runs under one seccomp profile for its life, and a later
		// call cannot relax it; the loopback forwarder, its profile variant and its
		// lifetime in a kept sandbox are not designed. Stated, not half-served.
		return NotDispatched(RefusalUnsupported, fmt.Errorf("%w: a grant with sdk_env (the local address for standard client libraries) is not available in a session; make the call as a run", ErrUnsupported))
	}
	if g.AllowInSessions {
		return nil
	}
	return NotDispatched(RefusalPermission, fmt.Errorf("%w: code an earlier call of the session left running could use it while this call runs; allow_in_sessions on the grant's profile accepts that, or make the call outside a session", ErrGrantNotForSessions))
}

// WantsLoopback reports whether the grant asks for the local address a standard
// client library reaches the broker through: its profile set sdk_env. Only such a run
// gets the loopback forwarder, the environment, and the seccomp profile variant that
// allows IPv4 TCP sockets; every other granted run keeps the injected client alone.
func (g *HostAPIGrant) WantsLoopback() bool { return g != nil && len(g.SDKEnv) > 0 }

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
	c.RouteMaxCalls = maps.Clone(g.RouteMaxCalls)
	c.PassHeaders = append([]string(nil), g.PassHeaders...)
	c.SetHeaders = maps.Clone(g.SetHeaders)
	c.SDKEnv = maps.Clone(g.SDKEnv)
	c.RouteMaxRequestBytes = maps.Clone(g.RouteMaxRequestBytes)
	if g.RouteContentTypes != nil {
		c.RouteContentTypes = make(map[HostRoute][]string, len(g.RouteContentTypes))
		for route, types := range g.RouteContentTypes {
			c.RouteContentTypes[route] = append([]string(nil), types...)
		}
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
	for route, n := range g.RouteMaxCalls {
		if !slices.Contains(g.Allow, route) {
			return fmt.Errorf("host-api grant: RouteMaxCalls names %s %q, which is not an entry of Allow", route.Method, route.Path)
		}
		if n < 1 || n > MaxHostCallsCeiling {
			return fmt.Errorf("host-api grant: RouteMaxCalls for %s %q must be between 1 and %d", route.Method, route.Path, MaxHostCallsCeiling)
		}
		for _, w := range g.Allow {
			if widensFixedSegment(w, route) {
				return fmt.Errorf("host-api grant: RouteMaxCalls caps %s %q, but %s %q matches its calls with a \"*\" in place of a fixed segment, "+
					"so a call spelled for the wildcard alone (\"ep1.json\" for \"ep1\") can reach the capped route uncounted; "+
					"move the cap to the wider route, or list the routes it should reach instead of the \"*\"", route.Method, route.Path, w.Method, w.Path)
			}
		}
	}
	if g.MaxRequestBytes < 0 || g.MaxRequestBytes > MaxRequestBytesCeiling {
		return fmt.Errorf("host-api grant: MaxRequestBytes must be 0 (the default, %d) or between 1 and %d", DefaultMaxRequestBytes, MaxRequestBytesCeiling)
	}
	for route, n := range g.RouteMaxRequestBytes {
		if !slices.Contains(g.Allow, route) {
			return fmt.Errorf("host-api grant: RouteMaxRequestBytes names %s %q, which is not an entry of Allow", route.Method, route.Path)
		}
		if n < 1 || n > MaxRouteRequestBytes {
			return fmt.Errorf("host-api grant: RouteMaxRequestBytes for %s %q must be between 1 and %d", route.Method, route.Path, MaxRouteRequestBytes)
		}
		if n > g.requestBudget() {
			return fmt.Errorf("host-api grant: RouteMaxRequestBytes for %s %q (%d) is above the run's MaxRequestBytes (%d), so no call could send that much", route.Method, route.Path, n, g.requestBudget())
		}
	}
	for route, types := range g.RouteContentTypes {
		if !slices.Contains(g.Allow, route) {
			return fmt.Errorf("host-api grant: RouteContentTypes names %s %q, which is not an entry of Allow", route.Method, route.Path)
		}
		if len(types) == 0 {
			return fmt.Errorf("host-api grant: RouteContentTypes for %s %q lists no type", route.Method, route.Path)
		}
		for i, t := range types {
			if !utf8.ValidString(t) || !validRequestMediaType(t) {
				return fmt.Errorf("host-api grant: RouteContentTypes for %s %q: %q is not a media type the broker forwards (a lowercase type/subtype, no wildcard, not application/json, multipart/byteranges or message/*)", route.Method, route.Path, t)
			}
			if slices.Contains(types[:i], t) {
				return fmt.Errorf("host-api grant: RouteContentTypes for %s %q lists %q twice", route.Method, route.Path, t)
			}
		}
	}
	seenHeaders := make(map[string]struct{}, len(g.PassHeaders))
	for _, name := range g.PassHeaders {
		if !utf8.ValidString(name) || passHeaderRefused(name) {
			return fmt.Errorf("host-api grant: PassHeaders entry %q is not a header the broker forwards (not a field name, one the broker or the transport owns, or one an API reads an API key from)", name)
		}
		lower := strings.ToLower(name)
		if _, dup := seenHeaders[lower]; dup {
			return fmt.Errorf("host-api grant: PassHeaders names %q twice", name)
		}
		seenHeaders[lower] = struct{}{}
	}
	seenSet := make(map[string]struct{}, len(g.SetHeaders))
	for name, value := range g.SetHeaders {
		if !utf8.ValidString(name) || passHeaderRefused(name) {
			return fmt.Errorf("host-api grant: SetHeaders entry %q is not a header a grant may set (not a field name, one the broker or the transport owns, or one an API reads an API key from: the credential is the token's, never a value in the profile)", name)
		}
		if value == "" || !validFieldValue(value) || strings.Trim(value, " \t") != value {
			return fmt.Errorf("host-api grant: SetHeaders value for %q must be a header value of 1 to %d bytes of visible ASCII, space and tab, with no space or tab at either end", name, maxPassHeaderValueBytes)
		}
		lower := strings.ToLower(name)
		if _, passed := seenHeaders[lower]; passed {
			return fmt.Errorf("host-api grant: %q is both passed from the guest and set by the grant; a header has one owner", name)
		}
		if _, dup := seenSet[lower]; dup {
			return fmt.Errorf("host-api grant: SetHeaders names %q twice", name)
		}
		seenSet[lower] = struct{}{}
	}
	for name, value := range g.SDKEnv {
		if !utf8.ValidString(name) || sdkEnvNameRefused(name) {
			return fmt.Errorf("host-api grant: SDKEnv name %q must be an uppercase identifier and not one plimsoll or the loader reads", name)
		}
		if !utf8.ValidString(value) || len(value) > maxSDKEnvValueBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("host-api grant: SDKEnv value for %q must be at most %d bytes with no control character", name, maxSDKEnvValueBytes)
		}
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

// ValidateHostRoute checks one route as a grant's Validate does: one of the five
// verbs a grant enforces, and a path the broker would accept as a pattern (absolute,
// decoded, canonical, no dot, traversal or ";" segments, whole-segment wildcards). A
// tool that produces routes (the spec generator, a profile's catalog) checks with it,
// so a route the broker would refuse is refused where it is made.
func ValidateHostRoute(route HostRoute) error {
	switch route.Method {
	case "GET", "PUT", "POST", "DELETE", "PATCH":
	default:
		return fmt.Errorf("route method %q is not one of GET, PUT, POST, DELETE, PATCH", route.Method)
	}
	if !utf8.ValidString(route.Path) {
		return errors.New("route path must be valid UTF-8")
	}
	if err := validateRoutePattern(route.Path); err != nil {
		return fmt.Errorf("route %s %q: %w", route.Method, route.Path, err)
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
	if path.Clean(pattern) != pattern || !upstreamNeutralSegments(strings.Split(pattern, "/")) {
		return errors.New("path must not contain empty, dot, traversal, or \";\" segments")
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
	if !upstreamNeutralSegments(segs) {
		return HostRoute{}, false
	}
	for _, r := range g.Allow {
		if strings.EqualFold(r.Method, method) && pathMatches(r.Path, segs) {
			return r, true
		}
	}
	return HostRoute{}, false
}

// cappedRoutesMatching returns every RouteMaxCalls entry that method and requestPath
// match, in no particular order. requestPath must already have passed matchRoute.
// Literal segments are compared without regard to case: with an uncapped "/v2/EP1/run"
// beside a capped "/v2/ep1/run", a call to the first matches only it as written, and
// an upstream that routes without regard to case serves it as ep1. Charging a cap a
// call may reach is safe; missing it is the bypass. Other spellings an upstream may
// read as the capped route are known only to it, so Validate refuses the wildcard
// entry that would let one through (widensFixedSegment).
func (g *HostAPIGrant) cappedRoutesMatching(method, requestPath string) []HostRoute {
	if len(g.RouteMaxCalls) == 0 {
		return nil
	}
	segs := strings.Split(strings.ToLower(requestPath), "/")
	var out []HostRoute
	for r := range g.RouteMaxCalls {
		if strings.EqualFold(r.Method, method) && pathMatches(strings.ToLower(r.Path), segs) {
			out = append(out, r)
		}
	}
	return out
}

// upstreamNeutralSegments reports whether no segment carries syntax an upstream
// server may interpret after the broker has matched it. approve==wire guarantees
// the bytes sent are the bytes approved; this guarantees the upstream reads them
// as the same route. A ";" starts a path parameter on Tomcat, Jetty and Spring, so
// "/orgs/..;/repos/x" passes a "/orgs/*/repos/*" grant byte for byte and then
// normalizes to "/repos/x" upstream. A segment made only of dots is traversal or,
// on servers that trim trailing dots, an empty segment. Neither appears in a real
// route template, so both are refused everywhere rather than per framework.
func upstreamNeutralSegments(segs []string) bool {
	for _, s := range segs {
		if strings.Contains(s, ";") || (s != "" && strings.Trim(s, ".") == "") {
			return false
		}
	}
	return true
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
			// A wildcard binds a non-empty segment of RFC 3986's unreserved characters
			// and nothing else. Upstreams give other characters meanings that make the
			// segment another operation than the route grants: "items/a:verb" is a
			// custom method on APIs that follow Google's AIP-136 and on gRPC-JSON
			// transcoders, and "$batch" or "$each" is an OData system segment that runs
			// other requests or acts on every entity of a set. A list of characters to
			// refuse grew one framework at a time (";", then ":", then "$" from the
			// 9 October scan), so the wildcard takes an allowlist instead; a route that
			// needs another character grants that segment as a literal.
			if !unreservedSegment(segs[i]) {
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

// unreservedChars are RFC 3986's unreserved characters, the only ones a "*" binds.
const unreservedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// unreservedSegment reports whether s is non-empty and made only of unreservedChars.
func unreservedSegment(s string) bool {
	return s != "" && strings.Trim(s, unreservedChars) == ""
}

// widensFixedSegment reports whether route w matches calls that capped matches too
// with a "*" where capped has a fixed segment: the same method, the same number of
// segments, every pair of fixed segments equal without regard to case, and at least
// one fixed segment of capped under a "*" of w. Such a w matches "ep1.json", "0123"
// or "ep1." in that position, which an upstream may serve as capped's "ep1" or
// "123", and the cap, compared as written, never sees the call.
func widensFixedSegment(w, capped HostRoute) bool {
	if !strings.EqualFold(w.Method, capped.Method) {
		return false
	}
	ws, cs := strings.Split(w.Path, "/"), strings.Split(capped.Path, "/")
	if len(ws) != len(cs) {
		return false
	}
	wider := false
	for i := range ws {
		switch {
		case ws[i] == "*" && cs[i] != "*":
			wider = true
		case ws[i] != "*" && cs[i] != "*" && !strings.EqualFold(ws[i], cs[i]):
			return false
		}
	}
	return wider
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

// withGuardHostSDK prepends the remote guard client used by the VM providers. The
// guard URL is an operator-controlled endpoint, never a caller-supplied origin.
// guardToken is empty on E2B, whose network policy injects the per-run credential
// outside the guest, so an E2B guest has no guard secret to steal. On dockercloud
// the client sends it as EgressGuardHeader: Docker's proxy cannot inject a
// credential for plimsoll's guard, so the guest holds its own run's credential (per
// run, valid only at the guard, only for this run's grant, dead when the run ends).
func withGuardHostSDK(code string, grant *HostAPIGrant, guardURL, guardToken string) string {
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
	headers := map[string]string{}
	if guardToken != "" {
		headers[EgressGuardHeader] = guardToken
	}
	headersJSON, err := json.Marshal(headers)
	if err != nil {
		headersJSON = []byte(`{}`)
	}
	preamble := strings.ReplaceAll(hostE2BClientTmpl, "__HOST_JSON__", string(globalJSON))
	preamble = strings.ReplaceAll(preamble, "__GUARD_URL_JSON__", string(guardJSON))
	preamble = strings.ReplaceAll(preamble, "__GUARD_HEADERS_JSON__", string(headersJSON))
	preamble = strings.ReplaceAll(preamble, "__ALLOW_JSON__", allowJSON(grant.Allow))
	if grant.Preamble != "" {
		preamble += "\n" + grant.Preamble
	}
	return preamble + "\n" + code
}

// hostGuardSDKModule is the project equivalent of withGuardHostSDK: it carries only
// the preinjected global (and, on dockercloud, the run's guard credential), never
// user code. The VM providers preload it into every Node step through NODE_OPTIONS
// so snippets and projects share one host.* surface.
func hostGuardSDKModule(grant *HostAPIGrant, guardURL, guardToken string) string {
	if grant == nil {
		return ""
	}
	return withGuardHostSDK("", grant, guardURL, guardToken)
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
  // An answer outside 2xx rejects with an Error whose message keeps the long-standing
  // "host api STATUS: BODY" form, and which carries the status as a number and the
  // body (parsed JSON when it parses), so code can branch on e.status.
  function hostError(status, text, data) {
    const e = new Error("host api " + status + ": " + text);
    e.status = status; e.body = data;
    return e;
  }
  const socket = process.env.HOST_API_SOCKET;
  // A run with sdk_env also has the loopback forwarder (HOST_API_LISTEN), a process of
  // plimsoll's that listens before this one starts (hostForwarderWrapperJS); this
  // client needs nothing of it and keeps the socket.
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
          else reject(hostError(res.statusCode, text, data));
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
  // An answer outside 2xx rejects with an Error whose message keeps the long-standing
  // "host api STATUS: BODY" form, and which carries the status as a number and the
  // body (parsed JSON when it parses), so code can branch on e.status.
  function hostError(status, text, data) {
    const e = new Error("host api " + status + ": " + text);
    e.status = status; e.body = data;
    return e;
  }
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
      headers: Object.assign({ "content-type": "application/json" }, __GUARD_HEADERS_JSON__),
      body: JSON.stringify(payload),
    });
    const text = await response.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    if (response.status >= 200 && response.status < 300) return data;
    throw hostError(response.status, text, data);
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
    // raw names the guard's raw route for a standard HTTP client: the base URL a
    // client library takes, and the headers it must add (none on E2B, whose network
    // rule adds the guard credential outside the guest; the run's guard credential on
    // dockercloud, which this client already holds).
    raw: { url: __guardURL ? __guardURL + "/raw" : "", headers: __GUARD_HEADERS_JSON__ },
  };
})();
`

const hostWasmClientTmpl = `
globalThis[__HOST_JSON__] = (function () {
  // An answer outside 2xx rejects with an Error whose message keeps the long-standing
  // "host api STATUS: BODY" form, and which carries the status as a number and the
  // body (parsed JSON when it parses), so code can branch on e.status.
  function hostError(status, text, data) {
    const e = new Error("host api " + status + ": " + text);
    e.status = status; e.body = data;
    return e;
  }
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
    return Promise.reject(hostError(response.status, response.body, data));
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
