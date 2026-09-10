package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
// or bulk-exfiltration channel.
const (
	maxHostRequestBytes  = 1 << 20 // one JSON request body
	maxHostResponseBytes = 4 << 20 // one response body
	maxHostCallsPerRun   = 256     // allowed and denied attempts combined
	maxHostConcurrent    = 16
)

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
// the shared core checks approve==wire. Guest headers and a guest-selected origin
// are not part of the protocol.
type brokerCall struct {
	Method    string
	RawTarget string
	Body      io.Reader
}

// brokerResponse is the bounded reply a provider adapter returns to its guest.
// Headers are intentionally not generic: only Content-Type is exposed, so an
// upstream cannot smuggle cookies, redirects, or transport metadata into a guest.
type brokerResponse struct {
	Status      int
	ContentType string
	Body        []byte
}

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
	trace     *callTrace
	health    *HostRoute // optional concrete GET route the breaker probes for recovery
	breaker   breaker
}

// breaker is the per-run circuit breaker that implements host-API backpressure. It is
// closed until an upstream 429/503 opens it for a cooldown; while open the broker sheds
// calls. When a HealthCheck route is set, one elected caller per breakerProbeInterval
// probes it and closes the breaker early on recovery.
type breaker struct {
	mu        sync.Mutex
	openUntil time.Time // zero = closed
	lastProbe time.Time // last elected health probe, to rate-limit probes while open
}

// gate reports the breaker's decision for a call arriving at now. shedding is true when
// the breaker is open; electedToProbe is true for the single caller (per
// breakerProbeInterval) that should probe the health route before shedding.
func (br *breaker) gate(now time.Time, haveHealth bool) (shedding, electedToProbe bool) {
	br.mu.Lock()
	defer br.mu.Unlock()
	if br.openUntil.IsZero() || !now.Before(br.openUntil) {
		return false, false
	}
	if haveHealth && (br.lastProbe.IsZero() || now.Sub(br.lastProbe) >= breakerProbeInterval) {
		br.lastProbe = now
		return true, true
	}
	return true, false
}

// open trips the breaker until at least deadline, extending (never shortening) an
// existing window.
func (br *breaker) open(deadline time.Time) {
	br.mu.Lock()
	defer br.mu.Unlock()
	if deadline.After(br.openUntil) {
		br.openUntil = deadline
	}
}

// reset clears the breaker after a health probe confirms recovery, so the next trip may
// probe again immediately.
func (br *breaker) reset() {
	br.mu.Lock()
	defer br.mu.Unlock()
	br.openUntil = time.Time{}
	br.lastProbe = time.Time{}
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
		transport = tr
	}
	return &brokerSession{
		grant:     grant,
		token:     token,
		origin:    origin,
		transport: transport,
		requests:  make(chan struct{}, maxHostConcurrent),
		trace:     newCallTrace(),
		health:    grant.HealthCheck, // frozen concrete GET route, or nil
	}, nil
}

// brokerSessionForGrant validates and mints a per-run credential before creating
// the shared core. The downstream token is retained only by the Go session and is
// never returned to a provider adapter or guest SDK.
func brokerSessionForGrant(ctx context.Context, grant *HostAPIGrant, timeout time.Duration) (*brokerSession, error) {
	if grant == nil {
		return nil, nil
	}
	grant = grant.Clone()
	if err := grant.Validate(); err != nil {
		return nil, err
	}
	token, err := grant.credential(ctx, timeout)
	if err != nil {
		return nil, err
	}
	return newBrokerSession(grant, token, nil)
}

func (b *brokerSession) traceSnapshot() *CallTrace {
	if b == nil {
		return nil
	}
	return b.trace.snapshot()
}

// Close releases idle upstream connections owned by this run. It is nil-safe.
func (b *brokerSession) Close() {
	if b == nil {
		return
	}
	if c, ok := b.transport.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func brokerError(status int, msg string) brokerResponse {
	return brokerResponse{
		Status:      status,
		ContentType: "text/plain; charset=utf-8",
		Body:        []byte(msg + "\n"),
	}
}

// Call enforces the complete grant contract and performs one upstream request.
// Every transport uses this exact path; no adapter is authoritative for policy.
func (b *brokerSession) Call(ctx context.Context, call brokerCall) brokerResponse {
	if b == nil {
		return brokerError(http.StatusServiceUnavailable, "host api broker unavailable")
	}
	select {
	case b.requests <- struct{}{}:
		defer func() { <-b.requests }()
	default:
		b.trace.recordDenied()
		return brokerError(http.StatusTooManyRequests, "host api broker is at capacity")
	}

	// Count before any validation so denied probes spend the same finite budget as
	// allowed calls.
	if b.callsMade.Add(1) > maxHostCallsPerRun {
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
	// has come back. The route was already authorized above, so a shed is distinct from
	// a policy denial (recorded as Shed, not Denied).
	if shedding, elected := b.breaker.gate(time.Now(), b.health != nil); shedding {
		recovered := false
		if elected {
			if healthy, cooldown := b.probeHealth(ctx); healthy {
				b.breaker.reset()
				recovered = true
			} else {
				b.breaker.open(time.Now().Add(cooldown))
			}
		}
		if !recovered {
			b.trace.recordShed()
			return brokerError(http.StatusServiceUnavailable, "host api is shedding load: upstream reported degraded")
		}
	}

	body, err := readBrokerBody(call.Body)
	if err != nil {
		b.trace.recordDenied()
		return brokerError(http.StatusRequestEntityTooLarge, "host api request body too large")
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

	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
	if err != nil || req.URL.RequestURI() != call.RawTarget {
		b.trace.recordDenied()
		return brokerError(http.StatusForbidden, "forbidden by sandbox capability allowlist")
	}
	req.Header = make(http.Header)
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}

	// SEAM(forensic-logging): this is the only shared point where an authorized
	// call's request and response bytes are both in scope. Any future opt-in sink
	// attaches here; CallRow remains metadata-only by construction.
	started := time.Now()
	resp, err := b.transport.RoundTrip(req) // RoundTrip never follows redirects.
	if err != nil || resp == nil || resp.Body == nil {
		b.trace.record(CallRow{
			Method:   strings.ToUpper(route.Method),
			Route:    route.Path,
			ReqBytes: len(body),
			Latency:  time.Since(started),
		})
		return brokerError(http.StatusBadGateway, "host api unavailable")
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxHostResponseBytes {
		b.trace.record(CallRow{
			Method:   strings.ToUpper(route.Method),
			Route:    route.Path,
			Status:   resp.StatusCode,
			ReqBytes: len(body),
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
			ReqBytes: len(body),
			Latency:  latency,
		})
		return brokerError(http.StatusBadGateway, "host api unavailable")
	}

	b.trace.record(CallRow{
		Method:    strings.ToUpper(route.Method),
		Route:     route.Path,
		Status:    resp.StatusCode,
		ReqBytes:  len(body),
		RespBytes: len(responseBody),
		Latency:   latency,
	})
	// The upstream itself signaling overload is the backpressure signal: open the
	// breaker so subsequent calls in this run shed instead of piling on. The guest still
	// receives this response; only later calls are affected.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		b.breaker.open(time.Now().Add(retryAfterCooldown(resp.Header.Get("Retry-After"))))
	}
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" || strings.IndexFunc(contentType, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		contentType = "application/octet-stream"
	}
	return brokerResponse{Status: resp.StatusCode, ContentType: contentType, Body: responseBody}
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

// probeHealth sends the grant's declared health_check route host-side (with the run's
// credential) to decide whether the upstream has recovered. It is broker overhead, not
// guest behavior, so it is NEITHER recorded in the CallTrace NOR charged against the
// run's call budget. A 2xx means healthy; any other status, a transport error, or a
// timeout means still-degraded, and the returned cooldown (from a fresh Retry-After when
// the probe carries one) refreshes the breaker window. The path was validated concrete
// at load, so this builds an exact URL with no wildcard to expand.
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

func readBrokerBody(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r, maxHostRequestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxHostRequestBytes {
		return nil, errors.New("host api request body exceeds limit")
	}
	return body, nil
}
