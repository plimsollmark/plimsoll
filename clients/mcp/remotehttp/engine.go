package remotehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/semaphore"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
	"github.com/plimsollmark/plimsoll/internal/unreadbody"
)

type bucket struct {
	tokens float64
	at     time.Time
}

func (b *bucket) refill(now time.Time, capacity, perSecond float64) {
	if b.at.IsZero() {
		b.tokens = capacity
	} else {
		b.tokens += now.Sub(b.at).Seconds() * perSecond
		if b.tokens > capacity {
			b.tokens = capacity
		}
	}
	b.at = now
}

func (b *bucket) allow(now time.Time, capacity, perSecond float64) bool {
	b.refill(now, capacity, perSecond)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// grantRate meters one grant: its tool calls, and its refreshes apart from them,
// so a busy connection cannot starve its own token rotation.
type grantRate struct{ calls, refresh bucket }

// Engine owns authorization state, the one shared tool server, and its dedicated
// HTTP surface. It never proxies the daemon's routes or serves local files.
//
// No unauthenticated route draws on a shared rate budget an anonymous client can
// empty: metadata and 401 challenges are static, token requests are charged to the
// grant their credential names once a read-only lookup finds it, and approvals
// allocate nothing until a passkey verifies. Anonymous work is bounded by its own
// concurrency slots, separate from tool calls, and by body and read limits.
type Engine struct {
	cfg           Config
	state         *store
	keys          *webauthn.WebAuthn
	tools         *server.Server
	mcp           http.Handler
	clients       *clientResolver
	audit         *auditLog
	seals         sealer
	marks         marks
	mu            sync.Mutex
	authenticated bucket
	refusals      bucket
	suppressed    int
	grantLimits   map[string]*grantRate
	appCalls      map[string]int   // tool calls in flight per approved app (client digest)
	appBody       map[string]int64 // body memory held per approved app, at most half of mcpBodyBudget
	visitors      map[string]int   // anonymous requests in flight per lane and visitor
	lanesInUse    map[string]int   // and per lane
	closed        bool
	bodyBudget    *semaphore.Weighted
	requests      chan struct{} // tool calls
	public        chan struct{} // unauthenticated OAuth and owner routes
	control       net.Listener
	closeOnce     sync.Once
	closeDone     chan struct{}
	closeErr      error
	runtimeCalls  sync.WaitGroup
	httpCalls     sync.WaitGroup
	runtimeCancel context.CancelFunc
}

func New(cfg Config) (*Engine, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s, err := openStore(cfg.StateDir, cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Engine, error) { _ = s.close(); return nil, err }
	if !cfg.Enrollment && len(s.data.Credentials) == 0 {
		return fail(errors.New("no owner passkey enrolled; use the local enroll command first"))
	}
	u, _ := url.Parse(cfg.PublicURL)
	keys, err := webauthn.New(&webauthn.Config{RPID: u.Hostname(), RPDisplayName: "plimsoll owner", RPOrigins: []string{cfg.PublicURL}, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}, AttestationPreference: protocol.PreferNoAttestation})
	if err != nil {
		return fail(err)
	}
	audit, err := openAudit(cfg.StateDir)
	if err != nil {
		return fail(err)
	}
	e := newEngine(cfg, s)
	e.keys, e.clients, e.audit = keys, newResolver(), audit
	if !cfg.Enrollment {
		cfg.Daemon.RequireGrant = true
		cfg.Daemon.Logger = slog.New(auditHandler{audit: audit})
		cfg.Daemon.RecordObserver = func(grant, digest string) { audit.event("checked_record", grant, digest) }
		e.tools, err = server.New(cfg.Daemon)
		if err != nil {
			_ = audit.close()
			return fail(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err = e.checkDaemon(ctx); err != nil {
			_ = e.tools.Close(ctx)
			_ = audit.close()
			return fail(err)
		}
		e.mcp = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return e.tools.MCP() }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, DisableLocalhostProtection: true, PropagateRequestCancellation: true, MaxRequestBodyBytes: mcpBodyLimit, Logger: slog.New(slog.DiscardHandler)})
	}
	return e, nil
}

func newEngine(cfg Config, s *store) *Engine {
	return &Engine{cfg: cfg, state: s, seals: newSealer(), marks: marks{entries: map[string]time.Time{}}, grantLimits: map[string]*grantRate{}, appCalls: map[string]int{}, appBody: map[string]int64{}, visitors: map[string]int{}, lanesInUse: map[string]int{}, bodyBudget: semaphore.NewWeighted(mcpBodyBudget), requests: make(chan struct{}, 16), public: make(chan struct{}, 8), closeDone: make(chan struct{})}
}

func (e *Engine) checkDaemon(ctx context.Context) error {
	opts := []client.Option{client.WithToken(e.cfg.Daemon.Token)}
	if e.cfg.Daemon.HTTPClient != nil {
		opts = append(opts, client.WithHTTPClient(e.cfg.Daemon.HTTPClient))
	}
	c, err := client.New(e.cfg.Daemon.URL, opts...)
	if err != nil {
		return err
	}
	i, err := c.Describe(ctx)
	if err != nil {
		return errors.New("authenticated daemon Describe failed")
	}
	if !i.Isolation.Meets(e.cfg.Daemon.MinimumIsolation) {
		return errors.New("daemon is below the required isolation floor")
	}
	anonOpts := []client.Option{}
	if e.cfg.Daemon.HTTPClient != nil {
		anonOpts = append(anonOpts, client.WithHTTPClient(e.cfg.Daemon.HTTPClient))
	}
	anonymous, err := client.New(e.cfg.Daemon.URL, anonOpts...)
	if err != nil {
		return err
	}
	_, err = anonymous.Describe(ctx)
	if connect.CodeOf(err) != connect.CodeUnauthenticated && connect.CodeOf(err) != connect.CodePermissionDenied {
		return errors.New("daemon did not prove anonymous caller refusal")
	}
	return nil
}

func (e *Engine) generation() uint64 {
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	return e.state.data.Generation
}

func (e *Engine) resource() string { return e.cfg.PublicURL + "/mcp" }
func (e *Engine) active() bool {
	return e.healthy() && e.enabled()
}

// healthy is false while a fault on this side (the audit log, the state store)
// refuses all authorization until an operator restarts the process.
func (e *Engine) healthy() bool {
	if !e.audit.healthy() {
		return false
	}
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	return !e.state.failed
}

// enabled is the owner's durable decision: an enrolled passkey and no disable.
func (e *Engine) enabled() bool {
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	return !e.state.data.Disabled && len(e.state.data.Credentials) > 0
}

// refused audits an anonymous failure. Past the refusal budget the event is
// counted instead, and the count rides on the next one written, so a flood of
// bad attempts cannot rotate the earlier audit history away.
func (e *Engine) refused(kind string) {
	e.mu.Lock()
	if !e.refusals.allow(time.Now(), 30, .5) {
		e.suppressed++
		e.mu.Unlock()
		return
	}
	n := e.suppressed
	e.suppressed = 0
	e.mu.Unlock()
	detail := ""
	if n > 0 {
		detail = "suppressed=" + strconv.Itoa(n)
	}
	e.audit.event(kind, "", detail)
}

func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	// Chromium sends Origin: null for a form POST under no-referrer. Keep the
	// exact Origin check usable while disclosing no path or query as a referrer.
	h.Set("Referrer-Policy", "strict-origin")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
}
func jsonReply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func oauthError(w http.ResponseWriter, status int, kind string) {
	jsonReply(w, status, map[string]string{"error": kind})
}
func reject(w http.ResponseWriter, status int) { http.Error(w, http.StatusText(status), status) }

func originAllowed(origin string) bool {
	return origin == "https://claude.ai" || origin == "https://claude.com" || origin == "https://chatgpt.com" || origin == "https://chat.openai.com"
}
func oneHeader(r *http.Request, name string) (string, bool) {
	v := r.Header.Values(name)
	if len(v) > 1 {
		return "", false
	}
	if len(v) == 0 {
		return "", true
	}
	return v[0], !strings.ContainsAny(v[0], "\r\n,")
}
func (e *Engine) browserProof(r *http.Request, tx *approval) bool {
	origin, ok := oneHeader(r, "Origin")
	if !ok || origin != e.cfg.PublicURL {
		return false
	}
	cookie, err := r.Cookie(approvalCookie(tx.Nonce))
	return err == nil && constantEqual(digest(cookie.Value), tx.CookieHash)
}

// maxMeters bounds grant meters. Only an owner-approved grant gets one, and the
// store holds at most maxGrants active, so dropping the least recently used
// meter when full only forgets a grant that expired or was retired.
const maxMeters = 4 * maxGrants

// grantRateLocked returns a grant's meters. It never takes the state lock, which
// a durable write holds through its fsync, so Engine.mu is never held across one.
func (e *Engine) grantRateLocked(grant string) *grantRate {
	g := e.grantLimits[grant]
	if g != nil {
		return g
	}
	if len(e.grantLimits) >= maxMeters {
		var oldest string
		var at time.Time
		for id, m := range e.grantLimits {
			last := m.calls.at
			if m.refresh.at.After(last) {
				last = m.refresh.at
			}
			if oldest == "" || last.Before(at) {
				oldest, at = id, last
			}
		}
		delete(e.grantLimits, oldest)
	}
	g = &grantRate{}
	e.grantLimits[grant] = g
	return g
}

// takeCall charges a tool call to the shared meter and the grant's together, or to
// neither: a request refused by its own grant's meter must not drain the allowance every
// other connector shares. refund gives both back, for a call a later admission refuses.
func (e *Engine) takeCall(grant string) (refund func(), ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	shared, own := &e.authenticated, &e.grantRateLocked(grant).calls
	shared.refill(now, 64, 2)
	own.refill(now, 16, 1)
	if shared.tokens < 1 || own.tokens < 1 {
		return nil, false
	}
	shared.tokens--
	own.tokens--
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		shared.tokens = min(shared.tokens+1, 64)
		if g := e.grantLimits[grant]; g != nil {
			g.calls.tokens = min(g.calls.tokens+1, 16)
		}
	}, true
}

// takeAppSlot holds one of an approved app's tool-call places: one app, however many
// grants it holds, has at most half of the tool-call slots, so its calls never take
// every slot from another app's.
func (e *Engine) takeAppSlot(app string) (func(), bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.appCalls[app] >= cap(e.requests)/2 {
		return nil, false
	}
	e.appCalls[app]++
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.appCalls[app]--; e.appCalls[app] <= 0 {
			delete(e.appCalls, app)
		}
	}, true
}

// takeRefresh meters a grant's refreshes: a client rotates once per access
// lifetime, so four at once and one per 10 seconds leave room for retries.
func (e *Engine) takeRefresh(grant string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.grantRateLocked(grant).refresh.allow(time.Now(), 4, .1)
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	u, _ := url.Parse(e.cfg.PublicURL)
	// The public authority and the explicitly configured backend are the only
	// accepted Host values. Forwarded headers never establish identity or origin.
	if r.Host != u.Host && r.Host != e.cfg.Listen {
		reject(w, 403)
		return
	}
	if r.URL.IsAbs() || r.URL.RawPath != "" || strings.Contains(r.RequestURI, "\\") || r.Header.Get("X-HTTP-Method-Override") != "" {
		reject(w, 404)
		return
	}
	if !e.enter() {
		reject(w, 503)
		return
	}
	defer e.httpCalls.Done()
	path := r.URL.Path
	metadata := path == "/.well-known/oauth-protected-resource" || path == "/.well-known/oauth-protected-resource/mcp" || path == "/.well-known/oauth-authorization-server" || path == "/.well-known/openid-configuration"
	if metadata && !e.cfg.Enrollment {
		if r.Method != "GET" && r.Method != "OPTIONS" {
			reject(w, 405)
			return
		}
		// Static, and needed by a client recovering from an expired token, so
		// it draws on no budget an anonymous client could empty.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		e.metadata(w, path)
		return
	}
	allowed := false
	switch path {
	case "/mcp":
		allowed = !e.cfg.Enrollment && (r.Method == "POST" || r.Method == "GET" || r.Method == "DELETE" || r.Method == "OPTIONS")
	case "/oauth/authorize":
		allowed = !e.cfg.Enrollment && (r.Method == "GET" || r.Method == "POST")
	case "/oauth/token", "/oauth/revoke", "/oauth/register":
		allowed = !e.cfg.Enrollment && r.Method == "POST"
	case "/owner/enroll":
		allowed = r.Method == "GET"
	case "/owner/enroll/options", "/owner/enroll/finish":
		allowed = r.Method == "POST"
	case "/owner/login/options", "/owner/login/finish":
		allowed = !e.cfg.Enrollment && r.Method == "POST"
	}
	if !allowed {
		reject(w, 404)
		return
	}
	release, admitted := e.admit(r, path)
	if !admitted {
		e.refused("visitor_busy")
		w.Header().Set("Retry-After", "1")
		reject(w, 429)
		return
	}
	defer release()
	origin, ok := oneHeader(r, "Origin")
	if !ok || origin != "" && origin != e.cfg.PublicURL && !originAllowed(origin) {
		reject(w, 403)
		return
	}
	if path != "/oauth/authorize" && r.URL.RawQuery != "" {
		reject(w, 400)
		return
	}
	if path == "/mcp" {
		e.serveMCP(w, r, origin)
		return
	}
	limit := int64(8192)
	if strings.HasPrefix(path, "/owner/") || path == "/oauth/authorize" {
		// An approval form carries the sealed approval, up to maxSealBytes.
		limit = 64 << 10
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if r.Method == "POST" {
		if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			reject(w, 500)
			return
		}
		// Read the bounded body before taking a slot, so a slow sender holds
		// only its own connection, never a slot another request needs.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			reject(w, 400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	select {
	case e.public <- struct{}{}:
		defer func() { <-e.public }()
	default:
		w.Header().Set("Retry-After", "1")
		reject(w, 429)
		return
	}
	switch path {
	case "/oauth/authorize":
		if r.Method == "GET" {
			e.authorize(w, r)
		} else {
			e.consent(w, r)
		}
	case "/oauth/token":
		e.token(w, r)
	case "/oauth/revoke":
		e.revoke(w, r)
	case "/oauth/register":
		e.register(w, r)
	case "/owner/enroll":
		e.enrollmentPage(w, r)
	case "/owner/enroll/options":
		e.beginEnrollment(w, r)
	case "/owner/enroll/finish":
		e.finishCeremony(w, r, true)
	case "/owner/login/options":
		e.beginLogin(w, r)
	case "/owner/login/finish":
		e.finishCeremony(w, r, false)
	}
}

func (e *Engine) metadata(w http.ResponseWriter, path string) {
	if strings.HasPrefix(path, "/.well-known/oauth-protected-resource") {
		jsonReply(w, 200, map[string]any{"resource": e.resource(), "authorization_servers": []string{e.cfg.PublicURL}, "scopes_supported": []string{"code:run"}, "bearer_methods_supported": []string{"header"}})
		return
	}
	jsonReply(w, 200, map[string]any{"issuer": e.cfg.PublicURL, "authorization_endpoint": e.cfg.PublicURL + "/oauth/authorize", "token_endpoint": e.cfg.PublicURL + "/oauth/token", "revocation_endpoint": e.cfg.PublicURL + "/oauth/revoke", "registration_endpoint": e.cfg.PublicURL + "/oauth/register", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_methods_supported": []string{"none"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"code:run", "offline_access"}, "client_id_metadata_document_supported": false, "authorization_response_iss_parameter_supported": true})
}

func (e *Engine) serveMCP(w http.ResponseWriter, r *http.Request, origin string) {
	if !e.audit.healthy() {
		reject(w, 503)
		return
	}
	w.Header().Add("Vary", "Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate, MCP-Protocol-Version, Mcp-Session-Id")
	}
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Session-Id, Mcp-Method, Mcp-Name")
		w.WriteHeader(204)
		return
	}
	authorization, ok := oneHeader(r, "Authorization")
	parts := strings.Split(authorization, " ")
	if !ok || len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		e.challenge(w)
		return
	}
	g, err := e.state.access(parts[1], e.resource())
	if err != nil {
		e.challenge(w)
		return
	}
	if !strings.Contains(" "+g.Scope+" ", " code:run ") {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="code:run"`)
		reject(w, 403)
		return
	}
	if !e.cfg.ExecutionEnabled {
		reject(w, 503)
		return
	}
	refund, ok := e.takeCall(g.ID)
	if !ok {
		w.Header().Set("Retry-After", "1")
		reject(w, 429)
		return
	}
	release, ok := e.takeAppSlot(digest(g.Client))
	if !ok {
		refund()
		w.Header().Set("Retry-After", "1")
		reject(w, 429)
		return
	}
	defer release()
	select {
	case e.requests <- struct{}{}:
		defer func() { <-e.requests }()
	default:
		refund()
		reject(w, 429)
		return
	}
	if err = e.tools.RegisterGrant(g.ID, digest(g.Client)); err != nil {
		reject(w, 403)
		return
	}
	ctx, err := e.tools.GrantContext(r.Context(), g.ID)
	if err != nil {
		e.challenge(w)
		return
	}
	// A request that read the grant just before its revocation can register it
	// after the revocation's cleanup. Check the grant again now it is registered.
	if !e.state.grantActive(g.ID) {
		e.cancelGrant(r.Context(), g.ID)
		e.challenge(w)
		return
	}
	if r.ContentLength > mcpBodyLimit {
		reject(w, 413)
		return
	}
	body, releaseBody, err := e.readBudgeted(w, r, digest(g.Client))
	defer releaseBody()
	if err != nil {
		if errors.Is(err, errBodyBudget) {
			w.Header().Set("Retry-After", "1")
			reject(w, 429)
		} else {
			reject(w, 413)
		}
		return
	}
	// A JSON-RPC batch (an array, which the SDK still takes under the 2025-03-26
	// revision) is many calls in one request: each would be dispatched and its answer
	// held until all finish, past the one call this request was charged for. Refused.
	if trimmed := bytes.TrimLeft(body, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '[' {
		reject(w, 400)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	e.audit.event("tool_admission", g.ID, "")
	if !e.audit.healthy() {
		reject(w, 503)
		return
	}
	e.mcp.ServeHTTP(w, r.WithContext(ctx))
}

var errBodyBudget = errors.New("body memory budget exhausted")

// mcpBodyBudget is the memory the bodies of every tool request in flight may hold
// together. One approved app holds at most half of it, one body at mcpBodyLimit, so its
// requests never take the rest from another app's, as takeAppSlot does for call slots.
const mcpBodyBudget int64 = 64 << 20

// readBudgeted reads a tool request's body, taking budget as bytes arrive, so a
// request without a declared length holds only what it sends. The budget stays
// held for the call (the decoded input lives as long as the call does) and is given
// back by the returned function, which the caller runs once whatever the error.
func (e *Engine) readBudgeted(w http.ResponseWriter, r *http.Request, app string) ([]byte, func(), error) {
	const step = 1 << 20
	var held int64
	release := func() {
		if held == 0 {
			return
		}
		e.bodyBudget.Release(held)
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.appBody[app] -= held; e.appBody[app] <= 0 {
			delete(e.appBody, app)
		}
	}
	var buf bytes.Buffer
	body := http.MaxBytesReader(w, r.Body, mcpBodyLimit)
	chunk := make([]byte, 64<<10)
	for {
		n, err := body.Read(chunk)
		if int64(buf.Len()+n) > held {
			if !e.takeBody(app, step) {
				return nil, release, errBodyBudget
			}
			held += step
		}
		buf.Write(chunk[:n])
		if err == io.EOF {
			return buf.Bytes(), release, nil
		}
		if err != nil {
			return nil, release, err
		}
	}
}

// takeBody holds n bytes of the body budget for app, within its half.
func (e *Engine) takeBody(app string, n int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.appBody[app]+n > mcpBodyBudget/2 || !e.bodyBudget.TryAcquire(n) {
		return false
	}
	e.appBody[app] += n
	return true
}

// challenge is static, and is what tells a client its access token expired, so
// it is never rate limited into a 429 the client would not refresh on.
func (e *Engine) challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+e.cfg.PublicURL+`/.well-known/oauth-protected-resource", scope="code:run"`)
	reject(w, 401)
}

func (e *Engine) enter() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	e.httpCalls.Add(1)
	return true
}

// HTTPServer supplies bounded network behavior around the handler. The listener
// itself is additionally capped by Serve; TLS is the trusted reverse proxy's job.
// Requests in flight to the OAuth and owner routes, the only ones whose bodies are
// read before a credential is checked, counted from the moment their headers arrive,
// so through the time a slow body takes too. They wait in three lanes, so a flood of
// one kind cannot take the places another needs: token requests, a connected app
// renewing its access ("recovery"); the owner's approval page and passkey steps
// ("owner"); and registration and revocation ("other"). /mcp is in none: it reads no
// body before its access token checks out, so an anonymous request there gets its
// static 401 at once and its connection closes (unreadbody), while signed-in calls are
// bounded by the tool-call slots and per-grant meters. The listener holds four times
// maxAnonymous connections, so anonymous bodies can never hold them all.
type lane struct{ places, perVisitor int }

var lanes = map[string]lane{"recovery": {8, 2}, "owner": {16, 4}, "other": {8, 2}}

const (
	maxAnonymous   = 32 // the lanes' places together
	maxConnections = 4 * maxAnonymous
)

func laneOf(path string) string {
	switch {
	case path == "/oauth/token":
		return "recovery"
	case path == "/oauth/authorize" || strings.HasPrefix(path, "/owner/"):
		return "owner"
	default:
		return "other"
	}
}

// admit takes a place in a request's lane, refusing it at once when the lane is full
// or its visitor holds the lane's share. Requests to /mcp take none.
func (e *Engine) admit(r *http.Request, path string) (func(), bool) {
	if path == "/mcp" {
		return func() {}, true
	}
	name := laneOf(path)
	l := lanes[name]
	key := ""
	if v := e.visitor(r); v != "" {
		key = name + " " + v
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lanesInUse[name] >= l.places || key != "" && e.visitors[key] >= l.perVisitor {
		return nil, false
	}
	e.lanesInUse[name]++
	if key != "" {
		e.visitors[key]++
	}
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.lanesInUse[name]--; e.lanesInUse[name] <= 0 {
			delete(e.lanesInUse, name)
		}
		if key != "" {
			if e.visitors[key]--; e.visitors[key] <= 0 {
				delete(e.visitors, key)
			}
		}
	}, true
}

// visitor names who sent a request, for the per-visitor limit: the last address in
// the header the local reverse proxy sets (PLIMSOLL_MCP_VISITOR_HEADER), which a
// proxy that overwrites the header (Tailscale Funnel's) or appends to it both make
// the address it saw. The listener is loopback only, so every connection is from a
// process on this machine. An IPv6 address counts by its /64, the block one home
// connection gets. "" when no header is configured: every visitor then shares the
// anonymous total alone. A missing or unreadable address counts as one visitor.
func (e *Engine) visitor(r *http.Request) string {
	if e.cfg.VisitorHeader == "" {
		return ""
	}
	values := r.Header.Values(e.cfg.VisitorHeader)
	if len(values) == 0 {
		return "unknown"
	}
	last := values[len(values)-1]
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	a, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil {
		return "unknown"
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
}

// HTTPServer answers a request it refuses before reading its body by closing the
// connection (unreadbody), so a slow body cannot hold a connection past a refusal.
func (e *Engine) HTTPServer() *http.Server {
	return &http.Server{Addr: e.cfg.Listen, Handler: unreadbody.Handler(e), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: e.cfg.Daemon.CallTimeout + 20*time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
}

func (e *Engine) Close(ctx context.Context) error {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		if e.runtimeCancel != nil {
			e.runtimeCancel()
		}
		e.mu.Unlock()
		if e.control != nil {
			_ = e.control.Close()
		}
		go func() {
			var err error
			if e.tools != nil {
				e.tools.Shutdown()
				err = e.tools.Close(context.Background())
			}
			e.httpCalls.Wait()
			e.runtimeCalls.Wait()
			e.closeErr = errors.Join(err, e.audit.close(), e.state.close())
			close(e.closeDone)
		}()
	})
	select {
	case <-e.closeDone:
		return e.closeErr
	case <-ctx.Done():
		return errors.New("remote server cleanup is still pending")
	}
}
