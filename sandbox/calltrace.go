package sandbox

import (
	"sync"
	"time"
)

// CallRow is one brokered host.* call, recorded as METADATA ONLY. It names the
// matched route TEMPLATE (the grant's HostRoute.Path pattern, e.g. "/items/*"),
// never the raw request path, so a concrete id or query value can never enter the
// trace. It carries no request or response body and no credential — only the
// method, byte sizes (already bounded by the broker's per-call caps), the upstream
// status, the broker round-trip latency, and a 1-based sequence number within the
// run. This preserves plimsoll's invariant that telemetry records metadata and
// never code or secrets.
//
// Delivered is the broker's own outcome for the call, kept separately from the
// upstream status. The broker records a row for every call it forwarded, including
// one whose response it then refused to deliver (no upstream answer, an oversized or
// unreadable body, a malformed status), and such a row keeps the upstream status it
// saw. A 2xx Status with Delivered false is therefore a call the guest never got an
// answer to, and zero RespBytes cannot stand in for that distinction, because an
// empty successful response is valid. A consumer asking "did the guest get a
// successful response" must check both.
type CallRow struct {
	Seq       int           // 1-based sequence among a run's recorded calls
	Method    string        // route method (GET/PUT/POST/DELETE/PATCH), from the Allow list
	Route     string        // matched HostRoute.Path TEMPLATE, never the raw path
	Status    int           // upstream HTTP status; 0 if the upstream never responded
	Delivered bool          // the upstream response reached the guest (false: the broker returned its own error instead)
	ReqBytes  int           // request body bytes the broker read (<= maxHostRequestBytes)
	RespBytes int           // response body bytes returned to the guest (<= maxHostResponseBytes)
	Latency   time.Duration // broker -> upstream -> guest round trip for this call
}

// SEAM(forensic-logging): CallRow is metadata-only BY CONSTRUCTION. It has no
// field for a path, query, body, or credential, so none can enter it. If a
// deployment ever needs full-call forensic capture (the "log every tool call"
// posture some agent platforms ship), that is a SEPARATE, opt-in sink, never a
// widening of this type. Its provider-neutral tap point is brokerSession.Call in
// broker.go, where request and response bytes are both in scope. It must default
// off, be gated by explicit config, and leave the default metadata-only path
// byte-identical when unset. Privacy-by-construction stays the default; forensic
// capture is the exception a customer turns on. See docs/seams.md.

// CallTrace is the bounded, metadata-only record of the host.* calls one run's
// broker served. It is EVIDENCE attached to a Result, never authoritative: its
// presence or absence never changes ExitCode, output, or isolation — a run is
// byte-identical with or without it. It holds route templates, methods, sizes,
// timings, and counts, never bodies or credentials. It is naturally bounded by the
// broker's per-run call budget; Dropped counts any allowed call past the trace cap
// (the retained prefix is never annotated in-band, mirroring output truncation),
// Denied counts calls the broker refused for policy (budget, route, or size; no path
// is recorded, since a denied call matched no template), and Shed counts calls the
// broker refused because the upstream signaled overload (HTTP 429/503) and the per-run
// circuit breaker was open — backpressure, distinct from a policy denial.
type CallTrace struct {
	Calls   []CallRow
	Dropped int
	Denied  int
	Shed    int
}

// Len reports the number of recorded calls. Nil-safe: a nil trace has length 0, so
// audit and summary sites need no separate guard.
func (t *CallTrace) Len() int {
	if t == nil {
		return 0
	}
	return len(t.Calls)
}

// maxTraceRows caps a run's recorded calls, and deliberately does NOT follow a grant
// that raises its call budget: a profile may allow 100,000 brokered calls (a controller
// stepping a plant once per tick), and holding 100,000 rows per run would make the
// trace a ledger rather than bounded evidence. Beyond the cap a call is counted in
// CallTrace.Dropped instead of stored, which is the signal the detectors already read
// to report a count as "at least".
const maxTraceRows = DefaultMaxHostCalls

// callTrace accumulates CallRows for one run. Broker handlers run concurrently, so
// every mutation takes the mutex. Construct with newCallTrace; a nil *callTrace is
// safe to call and records nothing (the no-grant case).
type callTrace struct {
	mu      sync.Mutex
	rows    []CallRow
	dropped int
	denied  int
	shed    int
}

func newCallTrace() *callTrace { return &callTrace{} }

// record appends one allowed call. The caller passes metadata already reduced to a
// template (Route) plus numbers; record assigns the sequence number and enforces
// the row cap. Beyond the cap the call is counted in dropped, not stored.
func (t *callTrace) record(row CallRow) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.rows) >= maxTraceRows {
		t.dropped++
		return
	}
	row.Seq = len(t.rows) + 1
	t.rows = append(t.rows, row)
}

// recordDenied counts a call the broker refused (budget, query, route, or size). No
// path is ever stored for a denial, since a denied call matched no template.
func (t *callTrace) recordDenied() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.denied++
}

// recordShed counts a call the broker refused because the per-run circuit breaker was
// open (the upstream signaled overload). Like a denial it stores no path; unlike a
// denial the route was permitted — only the upstream's health blocked it.
func (t *callTrace) recordShed() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.shed++
}

// snapshot returns an immutable copy for attaching to a Result, or nil when the run
// brokered nothing (no grant, or a grant that made no calls). Returning nil keeps a
// grant-free run's Result byte-identical to its pre-telemetry shape.
func (t *callTrace) snapshot() *CallTrace {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.rows) == 0 && t.dropped == 0 && t.denied == 0 && t.shed == 0 {
		return nil
	}
	return &CallTrace{
		Calls:   append([]CallRow(nil), t.rows...),
		Dropped: t.dropped,
		Denied:  t.denied,
		Shed:    t.shed,
	}
}
