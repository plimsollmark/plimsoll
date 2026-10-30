package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Per-run host-API budgets. A grant bounds WHICH routes a run may call; these
// bound HOW MUCH, so a hostile run cannot turn its capability into an API flood
// or bulk-exfiltration channel. The two body sizes are judgments, not measurements:
// each holds an ordinary JSON API body, and a larger one is refused, never cut short
// (an over-cap response is a 502 to the guest).
const (
	maxHostRequestBytes  = 1 << 20 // one JSON request body
	maxHostResponseBytes = 4 << 20 // one response body
	maxHostConcurrent    = 16
)

// hostCallTimeout bounds one upstream call, headers and body. Without it a hung
// upstream holds one of the run's 16 call slots (and, on E2B and Docker Cloud, a
// shared guard slot) until the run's own deadline; a JSON API call that has not
// finished in a minute is treated as failed, and the run's deadline still bounds the
// run. A streamed answer keeps this limit for its headers and then moves to
// hostStreamIdleTimeout. A variable so a test can shorten it.
var hostCallTimeout = 60 * time.Second

// hostStreamIdleTimeout bounds the gap between two pieces of a streamed answer: a
// stream that sends nothing for this long is cut. The single call limit becomes a
// per-gap limit for a stream, since a chat answer can take minutes to finish while
// never pausing this long (the Claude API sends ping events while it works). The
// run's own deadline still bounds the whole. A variable so a test can shorten it.
var hostStreamIdleTimeout = 60 * time.Second

// streamPiece is how much of a streamed answer the broker moves at a time; memory per
// streamed call is this, never the answer.
const streamPiece = 32 << 10

// Per-run backpressure. When the upstream signals overload (HTTP 429/503), the broker's
// circuit breaker opens and SHEDS further calls (fails fast) rather than piling more
// load onto a struggling API. Shedding, not artificial delay, is deliberate: a delay
// would hold the run's concurrency slot and lengthen the client-side queue against the
// same overloaded upstream. A grant's optional HealthCheck route lets the breaker probe
// for recovery and close early.
const (
	breakerDefaultCooldown = 1 * time.Second  // backoff when the upstream gave no Retry-After
	breakerMaxCooldown     = 30 * time.Second // cap on any honored Retry-After
	breakerProbeInterval   = 1 * time.Second  // at most one health probe per second while shedding
	breakerProbeTimeout    = 2 * time.Second  // a hung health endpoint must not stall the run
)

// brokerCall is the complete guest-controlled input to one host-API call. The
// target is deliberately raw: a transport must not URL-decode or clean it before
// the shared core checks approve==wire. A guest-selected origin is not part of the
// protocol. Headers are the guest's request headers as they arrived, when the
// transport carries them (the socket and the guard's raw route; the JSON envelope
// clients send none): the core forwards only the names the grant's PassHeaders lists
// and drops the rest, so a standard client's telemetry, user agent and dummy
// credential never reach the API.
type brokerCall struct {
	Method    string
	RawTarget string
	Headers   map[string][]string
	Body      io.Reader
	// ContentLength is the body's declared length: 0 for no body, -1 when the guest
	// declared none (a chunked request). On a route whose request limit the profile
	// raised, a declared length over the limit or over the run's remaining total is
	// refused before a byte is read, and the length is what the API is told.
	ContentLength int64
	// Stream, when set, receives a text/event-stream answer piece by piece as it
	// arrives (stream); every other answer is buffered and capped as always, and a nil
	// Stream buffers always.
	Stream StreamSink
}

// brokerResponse is the bounded reply a provider adapter returns to its guest.
// Headers are intentionally not generic: only Content-Type is exposed, so an
// upstream cannot smuggle cookies, redirects, or transport metadata into a guest.
// FromBroker marks an answer the broker made itself (a refusal, a shed, an upstream
// it could not reach) as against one the upstream gave; adapters tell a standard
// client not to retry it (brokerNoRetryHeader), since the budget counts each attempt.
type brokerResponse struct {
	Status      int
	ContentType string
	Body        []byte
	FromBroker  bool
	// Streamed marks an answer that already went to the call's Stream piece by
	// piece; Body is empty and the adapter writes nothing more.
	Streamed bool
}

// brokerNoRetryHeader, with the value "false", is the header the OpenAI and
// Anthropic client libraries read to skip their retry loop (two retries by default on
// 408, 409, 429 and 5xx). Every adapter sets it on an answer the broker made itself,
// so a client does not retry a budget refusal twice, spending the budget each time,
// or a shed against a breaker whose cooldown has not ended. An upstream's own answer
// never carries it: the client's retry policy toward the API is the client's.
const brokerNoRetryHeader = "X-Should-Retry"

// brokerSession is the provider-neutral, per-run enforcement core. The grant,
// credential, budgets, upstream transport, and metadata-only trace are private to
// one run; provider adapters only translate their framing to/from brokerCall.
type brokerSession struct {
	grant     *HostAPIGrant
	token     string
	origin    *url.URL
	transport http.RoundTripper
	requests  chan struct{}
	callsMade atomic.Int64
	// sent is the request body bytes the run has sent, or holds reserved while a body
	// is in flight, against the grant's MaxRequestBytes (reserveRequestBytes).
	sent atomic.Int64
	// routes counts the calls charged to each route the grant's RouteMaxCalls caps:
	// the run's own, or the session's, shared by all its granted calls.
	routes  *RouteBudget
	trace   *callTrace
	health  *HostRoute // optional concrete GET route the breaker probes for recovery
	breaker breaker

	// life ends with the run, or with a session's call: End cancels it, which cuts off
	// an upstream request in flight and refuses a call that arrives later. A session's
	// broker socket outlives its calls, so without it a request a leftover process
	// began during a call could reach the API with that call's credential after the
	// call ended, and land in no trace.
	life     context.Context
	end      context.CancelFunc
	mu       sync.Mutex
	ended    bool
	inflight sync.WaitGroup
}

// breaker is the per-run circuit breaker that implements host-API backpressure. It is
// closed until an upstream 429/503 opens it for a cooldown; while open the broker sheds
// calls. When a HealthCheck route is set AND the trip was an availability failure, one
// elected caller per breakerProbeInterval probes it and closes the breaker early on
// recovery.
type breaker struct {
	mu        sync.Mutex
	openUntil time.Time // zero = closed
	lastProbe time.Time // last elected health probe, to rate-limit probes while open
	// quotaTrip records that the current window was opened by an upstream 429. A health
	// route reports whether the SERVICE is available; it cannot report whether this
	// caller's rate limit or quota has reset, so a 2xx from it is not evidence that a 429
	// has cleared. Probing such a window would let a healthy-looking service reopen the
	// gate and put the run's traffic straight back into the limiter it just tripped —
	// defeating the backoff the 429 asked for. A quota window is therefore waited out.
	quotaTrip bool
	// gen counts the decisions that opened or extended the breaker. A probe's verdict
	// applies only to the generation it was elected under: a 429 that opens a quota
	// window while a probe is out is a newer decision the probe never examined, and an
	// old probe's 200 used to clear it (review, 2026-10-23).
	gen uint64
}

// gate reports the breaker's decision for a call arriving at now. shedding is true when
// the breaker is open; electedToProbe is true for the single caller (per
// breakerProbeInterval) that should probe the health route before shedding, and gen is
// the generation that probe examines (resetIf).
func (br *breaker) gate(now time.Time, haveHealth bool) (shedding, electedToProbe bool, gen uint64) {
	br.mu.Lock()
	defer br.mu.Unlock()
	if br.openUntil.IsZero() || !now.Before(br.openUntil) {
		br.clearLocked() // the window lapsed; the next trip starts from a clean state
		return false, false, br.gen
	}
	if haveHealth && !br.quotaTrip && (br.lastProbe.IsZero() || now.Sub(br.lastProbe) >= breakerProbeInterval) {
		br.lastProbe = now
		return true, true, br.gen
	}
	return true, false, br.gen
}

// open trips the breaker for cooldown from now, extending (never shortening) an existing
// window. quota marks a 429 trip, which suppresses health probing for the whole window
// (see breaker.quotaTrip); a window that carried a quota trip keeps that property even if
// a later availability failure extends it, since the rate limit has not been shown to
// have cleared either.
func (br *breaker) open(now time.Time, cooldown time.Duration, quota bool) {
	br.mu.Lock()
	defer br.mu.Unlock()
	if !br.openUntil.IsZero() && !now.Before(br.openUntil) {
		br.clearLocked() // a previous window already lapsed; this is a fresh trip
	}
	if quota {
		br.quotaTrip = true
	}
	if deadline := now.Add(cooldown); deadline.After(br.openUntil) {
		br.openUntil = deadline
	}
	br.gen++
}

// resetIf clears the breaker after a health probe elected under gen confirms recovery,
// so the next trip may probe again immediately, and reports whether it did. A breaker
// opened again since then holds a decision the probe did not examine, and stays open.
func (br *breaker) resetIf(gen uint64) bool {
	br.mu.Lock()
	defer br.mu.Unlock()
	if br.gen != gen {
		return false
	}
	br.clearLocked()
	return true
}

func (br *breaker) clearLocked() {
	br.openUntil = time.Time{}
	br.lastProbe = time.Time{}
	br.quotaTrip = false
}

// retryAfterCooldown derives the breaker cooldown from an upstream Retry-After header,
// clamped to [breakerDefaultCooldown, breakerMaxCooldown]. An absent or unparseable
// header yields the default; both delta-seconds and HTTP-date forms are honored.
func retryAfterCooldown(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return breakerDefaultCooldown
	}
	if secs, err := strconv.Atoi(header); err == nil {
		// Clamp before multiplying: a value past about 9.2e9 seconds would wrap the
		// Duration negative and land on the floor instead of the cap.
		if secs > int(breakerMaxCooldown/time.Second) {
			return breakerMaxCooldown
		}
		return clampCooldown(time.Duration(secs) * time.Second)
	}
	if t, err := http.ParseTime(header); err == nil {
		return clampCooldown(time.Until(t))
	}
	return breakerDefaultCooldown
}

func clampCooldown(d time.Duration) time.Duration {
	if d < breakerDefaultCooldown {
		return breakerDefaultCooldown
	}
	if d > breakerMaxCooldown {
		return breakerMaxCooldown
	}
	return d
}

// newBrokerSession validates a grant and binds an already-minted token to one
// run. Providers mint immediately before calling this so the requested TTL tracks
// their actual execution budget. A nil transport uses a direct, proxy-free clone
// of Go's default transport: ambient HTTP_PROXY settings must not become an
// undeclared credential-bearing hop.
func newBrokerSession(grant *HostAPIGrant, token string, transport http.RoundTripper) (*brokerSession, error) {
	if grant == nil {
		return nil, errors.New("host api broker: grant is nil")
	}
	// Freeze the per-run authority. Registry grants are already clones, but direct
	// embedders must not be able to widen a live session by mutating their input.
	grant = grant.Clone()
	if err := grant.Validate(); err != nil {
		return nil, err
	}
	if token != "" && strings.IndexFunc(token, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return nil, errors.New("host api broker: credential is not a valid bearer token")
	}
	origin, err := url.Parse(grant.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("host api broker: parse origin: %w", err)
	}
	if transport == nil {
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("host api broker: default HTTP transport has an unsupported type")
		}
		tr := defaultTransport.Clone()
		tr.Proxy = nil
		tr.ResponseHeaderTimeout = hostCallTimeout
		transport = tr
	}
	life, end := context.WithCancel(context.Background())
	return &brokerSession{
		grant:     grant,
		token:     token,
		origin:    origin,
		transport: transport,
		requests:  make(chan struct{}, maxHostConcurrent),
		routes:    NewRouteBudget(),
		trace:     newCallTrace(),
		health:    grant.HealthCheck, // frozen concrete GET route, or nil
		life:      life,
		end:       end,
	}, nil
}

// brokerSessionForGrant validates and mints a per-run credential before creating
// the shared core. The downstream token is retained only by the Go session and is
// never returned to a provider adapter or guest SDK.
//
// Every provider calls it before any of the run's code is dispatched, so its errors
// are marked not dispatched here, at the source: reason permission (the run's
// authority could not be issued), or capacity when the run's context ended first.
// routes is the session's route budget for a call in a session, nil for a run, which
// gets a fresh one.
func brokerSessionForGrant(ctx context.Context, grant *HostAPIGrant, timeout time.Duration, routes *RouteBudget) (*brokerSession, error) {
	if grant == nil {
		return nil, nil
	}
	refuse := func(err error) error {
		if ctx.Err() != nil {
			return NotDispatched(RefusalCapacity, err)
		}
		return NotDispatched(RefusalPermission, err)
	}
	grant = grant.Clone()
	if err := grant.Validate(); err != nil {
		return nil, refuse(err)
	}
	token, err := grant.credential(ctx, timeout)
	if err != nil {
		return nil, refuse(err)
	}
	core, err := newBrokerSession(grant, token, nil)
	if err != nil {
		return nil, refuse(err)
	}
	if routes != nil {
		core.routes = routes
	}
	return core, nil
}

func (b *brokerSession) traceSnapshot() *CallTrace {
	if b == nil {
		return nil
	}
	return b.trace.snapshot()
}

// brokerEndWait bounds how long End waits for calls in flight. A call already
// upstream is cancelled and returns at once; a call still reading its request body
// can take up to the server's read timeout, and is refused when it finishes.
const brokerEndWait = 2 * time.Second

// End revokes the run's authority: a call in flight loses its upstream request, a
// call that arrives later is refused, and End waits (up to brokerEndWait) for the
// calls in flight, so a trace read after it holds every call that reached the API.
// Nil-safe and idempotent.
func (b *brokerSession) End() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.ended = true
	b.mu.Unlock()
	b.end()
	done := make(chan struct{})
	go func() {
		b.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(brokerEndWait):
	}
}

// enter counts a call in flight, or reports that the run's authority has ended.
func (b *brokerSession) enter() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ended {
		return false
	}
	b.inflight.Add(1)
	return true
}

// Close ends the run's authority and releases its idle upstream connections. It is
// nil-safe.
func (b *brokerSession) Close() {
	if b == nil {
		return
	}
	b.End()
	if c, ok := b.transport.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func brokerError(status int, msg string) brokerResponse {
	return brokerResponse{
		Status:      status,
		ContentType: "text/plain; charset=utf-8",
		Body:        []byte(msg + "\n"),
		FromBroker:  true,
	}
}

// Call enforces the complete grant contract and performs one upstream request.
// Every transport uses this exact path; no adapter is authoritative for policy.
func (b *brokerSession) Call(ctx context.Context, call brokerCall) brokerResponse {
	if b == nil {
		return brokerError(http.StatusServiceUnavailable, "host api broker unavailable")
	}
	if !b.enter() {
		b.trace.recordDenied()
		return brokerError(http.StatusServiceUnavailable, "host api grant has ended")
	}
	defer b.inflight.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(b.life, cancel)()
	select {
	case b.requests <- struct{}{}:
		defer func() { <-b.requests }()
	default:
		b.trace.recordDenied()
		return brokerError(http.StatusTooManyRequests, "host api broker is at capacity")
	}

	// Count before any validation so denied probes spend the same finite budget as
	// allowed calls. The budget is the grant's (DefaultMaxHostCalls unless the
	// profile raised it, never past MaxHostCallsCeiling).
	if b.callsMade.Add(1) > int64(b.grant.CallBudget()) {
		b.trace.recordDenied()
		return brokerError(http.StatusTooManyRequests, "host api call budget for this run is exhausted")
	}

	method := strings.ToUpper(call.Method)
	route, ok := b.matchRawTarget(method, call.RawTarget)
	if !ok {
		b.trace.recordDenied()
		return brokerError(http.StatusForbidden, "forbidden by sandbox capability allowlist")
	}
	// Backpressure gate. An upstream 429/503 opens the per-run breaker; while open the
	// broker sheds this permitted call instead of adding to the overload. A declared
	// health route lets one elected caller probe for recovery and proceed if the API
	// has come back — for an availability trip only, never a 429 (see breaker.quotaTrip).
	// The route was already authorized above, so a shed is distinct from a policy denial
	// (recorded as Shed, not Denied).
	if shedding, elected, gen := b.breaker.gate(time.Now(), b.health != nil); shedding {
		recovered := false
		if elected {
			if healthy, cooldown := b.probeHealth(ctx); healthy {
				recovered = b.breaker.resetIf(gen)
			} else {
				b.breaker.open(time.Now(), cooldown, false)
			}
		}
		if !recovered {
			b.trace.recordShed()
			return brokerError(http.StatusServiceUnavailable, "host api is shedding load: upstream reported degraded")
		}
	}

	// The body. Its type is the route's rule (requestContentType), its limit the
	// route's (the default, or the one the profile raised for an upload route), and its
	// bytes are charged to the run's total before anything is sent. Within the default
	// limit the body is buffered as it always was. Above it the body is passed through
	// to the API as it arrives, behind a reader that cuts it at the limit, so memory per
	// call stays at the piece size and a body over the limit never finishes at the API;
	// a declared length over the limit is refused before a byte is read.
	contentType := "application/json"
	if call.ContentLength != 0 { // a body, declared or not; a request without one has no type to check
		var ok bool
		if contentType, ok = b.grant.requestContentType(route, headerFirst(call.Headers, "Content-Type")); !ok {
			b.trace.recordDenied()
			return brokerError(http.StatusUnsupportedMediaType, "host api request content type is not allowed on this route")
		}
	}
	limit := b.grant.requestLimit(route)
	if call.ContentLength > limit {
		b.trace.recordDenied()
		return brokerError(http.StatusRequestEntityTooLarge, "host api request body exceeds the route's limit")
	}
	var (
		body     []byte
		upload   *capReader
		reserved int64
	)
	if limit <= maxHostRequestBytes {
		var err error
		if body, err = readBrokerBody(call.Body, limit); err != nil {
			b.trace.recordDenied()
			return brokerError(http.StatusRequestEntityTooLarge, "host api request body exceeds the route's limit")
		}
		reserved = int64(len(body))
	} else if call.Body != nil && call.ContentLength != 0 {
		reserved = call.ContentLength
		if reserved < 0 {
			reserved = limit // undeclared: the route's whole limit is held until the call settles
		}
		held := reserved
		upload = &capReader{r: call.Body, remaining: reserved, settle: func(sent int64) {
			b.sent.Add(sent - held) // what was held less what went
		}}
	}
	if !b.reserveRequestBytes(reserved) {
		b.trace.recordDenied()
		return brokerError(http.StatusRequestEntityTooLarge, "host api request bytes for this run are exhausted")
	}
	if upload != nil {
		defer upload.Close() // settles the hold; the transport is handed nothing after it
	}
	sentBytes := func() int {
		if upload != nil {
			return int(upload.progress())
		}
		return len(body)
	}

	requestURL := *b.origin
	requestURL.Path = call.RawTarget
	requestURL.RawPath = ""
	// This is the second half of approve==wire. matchRawTarget rejected every
	// encoded or non-canonical raw target; verify Go will not encode it differently
	// when producing the actual request line.
	if requestURL.EscapedPath() != call.RawTarget {
		b.trace.recordDenied()
		return brokerError(http.StatusForbidden, "forbidden by sandbox capability allowlist")
	}
	// A route's cap bounds the calls that reach the API (docs/capability-grants.md), so
	// it is charged last, once nothing else can refuse the call: a shed call, an
	// over-size body or a non-canonical path used to spend it too, and backpressure
	// alone could eat a run's whole allowance on a paid route (review, 2026-10-26). The
	// per-run call budget above is different: every attempt spends it, denied ones
	// included, so a guest cannot probe for free.
	if !b.chargeRouteCaps(method, call.RawTarget) {
		b.trace.recordDenied()
		return brokerError(http.StatusTooManyRequests, "host api call budget for this route is exhausted")
	}

	// The call's deadline. A buffered answer has hostCallTimeout for headers and body
	// together, read under the same context. A streamed answer keeps that limit for its
	// headers (the transport's ResponseHeaderTimeout is the same value) and then moves
	// to a per-gap limit, so the timer is one the stream path stops and replaces.
	ctx, cancelCall := context.WithCancel(ctx)
	defer cancelCall()
	callTimer := time.AfterFunc(hostCallTimeout, cancelCall)
	defer callTimer.Stop()
	var requestBody io.Reader
	switch {
	case upload != nil:
		requestBody = upload
	case len(body) > 0:
		requestBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), requestBody)
	if err != nil || req.URL.RequestURI() != call.RawTarget {
		b.trace.recordDenied()
		return brokerError(http.StatusForbidden, "forbidden by sandbox capability allowlist")
	}
	if upload != nil {
		req.ContentLength = call.ContentLength // the declared length, or -1: sent chunked
	}
	// The upstream request's headers are the broker's, never the guest's: a default
	// Accept, then the few names the grant lets through from the guest (first value,
	// checked; Validate refused every name the broker or the transport owns), then the
	// names the grant sets with its own values (never also passed), then the body's type
	// and the credential, set last so nothing passed or set can stand in for them.
	req.Header = make(http.Header)
	req.Header.Set("Accept", "application/json")
	for name, value := range b.grant.passedHeaders(call.Headers) {
		req.Header.Set(name, value)
	}
	for name, value := range b.grant.SetHeaders {
		req.Header.Set(name, value)
	}
	if requestBody != nil {
		req.Header.Set("Content-Type", contentType)
	}
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}

	// SEAM(forensic-logging): this is the only shared point where an authorized
	// call's request and response bytes are both in scope. Any future opt-in sink
	// attaches here; CallRow remains metadata-only by construction.
	// The body can take until the server's read timeout to arrive, long enough for the
	// call that lent this grant to end: check that it has not, as late as possible.
	if b.life.Err() != nil {
		b.trace.recordDenied()
		return brokerError(http.StatusServiceUnavailable, "host api grant has ended")
	}
	started := time.Now()
	resp, err := b.transport.RoundTrip(req) // RoundTrip never follows redirects.
	// The three failure records below leave Delivered false: the guest receives a
	// broker error in place of the upstream response, whatever status the upstream
	// sent, and the row keeps that status so the trace still says what happened.
	if err != nil || resp == nil || resp.Body == nil {
		b.trace.record(CallRow{
			Method:   strings.ToUpper(route.Method),
			Route:    route.Path,
			ReqBytes: sentBytes(),
			Latency:  time.Since(started),
		})
		if upload != nil && upload.over() {
			// The guest's body ran past the route's limit: the upstream request was
			// broken off at the limit, so the API never got a complete body.
			return brokerError(http.StatusRequestEntityTooLarge, "host api request body exceeds the route's limit")
		}
		return brokerError(http.StatusBadGateway, "host api unavailable")
	}
	defer resp.Body.Close()
	if call.Stream != nil && resp.StatusCode >= 100 && resp.StatusCode <= 599 && isEventStream(resp.Header.Get("Content-Type")) {
		return b.stream(call.Stream, resp, route, sentBytes(), started, cancelCall, callTimer)
	}
	if resp.ContentLength > maxHostResponseBytes {
		b.trace.record(CallRow{
			Method:   strings.ToUpper(route.Method),
			Route:    route.Path,
			Status:   resp.StatusCode,
			ReqBytes: sentBytes(),
			Latency:  time.Since(started),
		})
		return brokerError(http.StatusBadGateway, "host api unavailable")
	}

	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxHostResponseBytes+1))
	latency := time.Since(started)
	if readErr != nil || len(responseBody) > maxHostResponseBytes || resp.StatusCode < 100 || resp.StatusCode > 599 {
		b.trace.record(CallRow{
			Method:   strings.ToUpper(route.Method),
			Route:    route.Path,
			Status:   resp.StatusCode,
			ReqBytes: sentBytes(),
			Latency:  latency,
		})
		return brokerError(http.StatusBadGateway, "host api unavailable")
	}

	b.trace.record(CallRow{
		Method:    strings.ToUpper(route.Method),
		Route:     route.Path,
		Status:    resp.StatusCode,
		Delivered: true,
		ReqBytes:  sentBytes(),
		RespBytes: len(responseBody),
		Latency:   latency,
	})
	// The upstream itself signaling overload is the backpressure signal: open the
	// breaker so subsequent calls in this run shed instead of piling on. The guest still
	// receives this response; only later calls are affected. The two statuses mean
	// different things — 503 is "the service is struggling" (probeable), 429 is "you have
	// spent your allowance" (not) — so the trip carries which one it was.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		b.breaker.open(time.Now(), retryAfterCooldown(resp.Header.Get("Retry-After")), resp.StatusCode == http.StatusTooManyRequests)
	}
	answerType := resp.Header.Get("Content-Type")
	if answerType == "" || strings.IndexFunc(answerType, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		answerType = "application/octet-stream"
	}
	return brokerResponse{Status: resp.StatusCode, ContentType: answerType, Body: responseBody}
}

// stream passes resp's body to sink piece by piece: at most maxHostResponseBytes in
// all, never a gap longer than hostStreamIdleTimeout between pieces, and never past
// the run's own deadline (the request's context). The status and content type go out
// first, so a cut cannot become a 502: the stream ends early, and a client sees an
// answer without its final event ([DONE], message_stop) and raises. Memory is one
// piece, never the answer. The row records the bytes delivered; Delivered is true only
// when the upstream ended the stream itself within the caps. The breaker reads the
// status as for a buffered answer.
func (b *brokerSession) stream(sink StreamSink, resp *http.Response, route HostRoute, reqBytes int, started time.Time, cancel context.CancelFunc, callTimer *time.Timer) brokerResponse {
	callTimer.Stop()
	idle := time.AfterFunc(hostStreamIdleTimeout, cancel)
	defer idle.Stop()
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		b.breaker.open(time.Now(), retryAfterCooldown(resp.Header.Get("Retry-After")), resp.StatusCode == http.StatusTooManyRequests)
	}
	contentType := resp.Header.Get("Content-Type")
	w := sink.Begin(resp.StatusCode, contentType)
	buf := make([]byte, streamPiece)
	written := 0
	delivered := false
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if written+n > maxHostResponseBytes {
				n = maxHostResponseBytes - written
			}
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					break // the guest stopped reading
				}
				written += n
			}
			if written >= maxHostResponseBytes {
				cancel() // the cap: cut, and let the upstream know
				break
			}
			idle.Reset(hostStreamIdleTimeout)
		}
		if err == io.EOF {
			delivered = true
			break
		}
		if err != nil {
			break // an idle cut, the run's deadline, or the upstream broke off
		}
	}
	b.trace.record(CallRow{
		Method:    strings.ToUpper(route.Method),
		Route:     route.Path,
		Status:    resp.StatusCode,
		Delivered: delivered,
		ReqBytes:  reqBytes,
		RespBytes: written,
		Latency:   time.Since(started),
	})
	return brokerResponse{Status: resp.StatusCode, ContentType: contentType, Streamed: true}
}

// isEventStream reports whether a Content-Type names server-sent events.
func isEventStream(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "text/event-stream"
}

// matchRawTarget rejects any target that an HTTP stack would decode, clean, or
// encode differently. Only after that exact-wire check does it ask the grant for
// a route-template match.
func (b *brokerSession) matchRawTarget(method, rawTarget string) (HostRoute, bool) {
	if rawTarget == "" || strings.ContainsAny(rawTarget, "%?#") {
		return HostRoute{}, false
	}
	u := &url.URL{Path: rawTarget}
	if u.EscapedPath() != rawTarget {
		return HostRoute{}, false
	}
	return b.grant.matchRoute(method, rawTarget)
}

// chargeRouteCaps admits a call against every capped allow entry its path matches,
// not only the entry that matched it first. A cap on "POST /v2/ep1/run" would
// otherwise hold or not depending on whether "POST /v2/*/run" is written before it.
// The count is the run's, or for a call in a session the session's (RouteBudget).
// target has already passed matchRawTarget.
func (b *brokerSession) chargeRouteCaps(method, target string) bool {
	return b.routes.charge(b.origin.Scheme+"://"+b.origin.Host, b.grant.cappedRoutesMatching(method, target), b.grant.RouteMaxCalls)
}

// probeHealth sends the grant's declared health_check route host-side (with the run's
// credential) to decide whether the upstream has recovered. It is broker overhead, not
// guest behavior, so it is NEITHER recorded in the CallTrace NOR charged against the
// run's call budget. A 2xx means healthy; any other status, a transport error, or a
// timeout means still-degraded, and the returned cooldown (from a fresh Retry-After when
// the probe carries one) refreshes the breaker window. The path was validated concrete
// at load, so this builds an exact URL with no wildcard to expand.
//
// What a 2xx here is evidence OF is narrow, and the caller enforces the limit: the route
// answers "is this service able to serve", which speaks to a 503 and says nothing about a
// 429's rate limit or quota. The breaker only elects a prober for an availability trip.
func (b *brokerSession) probeHealth(ctx context.Context) (healthy bool, cooldown time.Duration) {
	if b.health == nil {
		return false, breakerDefaultCooldown
	}
	probeURL := *b.origin
	probeURL.Path = b.health.Path
	probeURL.RawPath = ""
	if probeURL.EscapedPath() != b.health.Path { // defensive: the path is validated concrete at load
		return false, breakerDefaultCooldown
	}
	pctx, cancel := context.WithTimeout(ctx, breakerProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return false, breakerDefaultCooldown
	}
	req.Header = make(http.Header)
	req.Header.Set("Accept", "application/json")
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	resp, err := b.transport.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return false, breakerDefaultCooldown
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHostResponseBytes+1)) // drain to reuse the connection
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, 0
	}
	return false, retryAfterCooldown(resp.Header.Get("Retry-After"))
}

// readBrokerBody buffers a body of at most limit bytes; one byte more is an error.
func readBrokerBody(r io.Reader, limit int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("host api request body exceeds limit")
	}
	return body, nil
}

// headerFirst is the first value of name among the guest's headers, matched without
// regard to case, or "" when the guest sent none.
func headerFirst(h map[string][]string, name string) string {
	for k, vals := range h {
		if strings.EqualFold(k, name) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// reserveRequestBytes charges n request body bytes to the run's total (the grant's
// MaxRequestBytes), or reports false when they would take it past the budget, so a
// body that cannot fit is refused before anything is sent and two bodies in flight
// cannot both fit the same remainder.
func (b *brokerSession) reserveRequestBytes(n int64) bool {
	budget := b.grant.requestBudget()
	for {
		cur := b.sent.Load()
		if cur+n > budget {
			return false
		}
		if b.sent.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// errRequestOverCap is the error a passed-through upload fails with past its limit; the
// transport then breaks the upstream request off, which the API sees as incomplete.
var errRequestOverCap = errors.New("host api request body exceeds the route's limit")

// errUploadClosed is what a passed-through upload's reader answers once it is closed.
var errUploadClosed = errors.New("host api request body was closed")

// capReader is the request body of a passed-through upload: it hands the transport at
// most remaining bytes and, if the guest's body has more, fails the request with
// errRequestOverCap, so a body over its limit never finishes at the API. A body of
// exactly the limit ends normally: the reader looks one byte past the limit before it
// decides.
//
// The transport reads it on a goroutine of its own and may go on reading after
// RoundTrip has returned (an API may answer before the body is in). So the bytes held
// from the run's total are settled on Close, which Call makes as it returns (the
// transport may make it first), and from then on the reader hands the transport
// nothing: a read that was waiting on the guest has its bytes dropped. The bytes the
// API can receive are therefore exactly the bytes charged. Settling at the call's
// return while the reader stayed open let a second upload start on the refund while
// the first was still being read, so the bytes sent could pass the run's total
// (release review, 2026-10-29).
type capReader struct {
	r      io.Reader
	settle func(sent int64) // called once, by the first Close, with the bytes handed over

	mu        sync.Mutex
	remaining int64
	sent      int64
	pastCap   bool
	closed    bool
}

func (c *capReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	closed, remaining := c.closed, c.remaining
	c.mu.Unlock()
	if closed {
		return 0, errUploadClosed
	}
	var n int
	var err error
	if remaining <= 0 {
		err = c.pastLimit()
	} else {
		if int64(len(p)) > remaining {
			p = p[:remaining]
		}
		n, err = c.r.Read(p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed { // closed while this read waited on the guest: these bytes never go
		return 0, errUploadClosed
	}
	c.remaining -= int64(n)
	c.sent += int64(n)
	if err == errRequestOverCap {
		c.pastCap = true
	}
	return n, err
}

// pastLimit reads one byte past the limit: the body's own end (io.EOF) if it stops
// there, errRequestOverCap if it goes on.
func (c *capReader) pastLimit() error {
	var one [1]byte
	for attempt := 0; attempt < 8; attempt++ {
		n, err := c.r.Read(one[:])
		if n > 0 {
			return errRequestOverCap
		}
		if err != nil {
			return err
		}
	}
	return io.ErrNoProgress
}

// Close ends the body and settles the hold; only the first call does anything.
func (c *capReader) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.settle(c.sent)
	}
	return nil
}

// progress is the bytes the transport has been handed so far.
func (c *capReader) progress() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

// over reports whether the guest's body ran past the limit.
func (c *capReader) over() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pastCap
}
