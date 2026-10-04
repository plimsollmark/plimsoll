// Package insights derives deterministic, metadata-only efficiency findings from a
// run's brokered host.* call trace (Prospector Phase 1). It reads a bounded
// sandbox.CallTrace — route TEMPLATES, methods, statuses, whether the broker
// delivered each response, byte sizes, upstream latencies, and sequence numbers,
// never a raw path, body, or credential — and reports where the agent's call
// pattern was wasteful.
//
// Two detectors remain after the 2026-09-16 evidence audit: fan-out (many successful
// calls to one per-item route) and repeated-read (the same fixed-route request made
// repeatedly with same-size responses). Each reports one finding per (method, route)
// group over disjoint evidence, so a run's findings never describe the same call
// twice and their costs sum without double counting. The sequential and
// aggregate-in-code detectors were deleted: the trace holds no call start times, so
// it cannot tell serial calls from concurrent ones, and it holds no guest content, so
// it cannot tell a client-side reduce from any other loop. The aggregate idea survives
// only as a conditional alternative in the API-design prompt for a read fan-out (see
// Prompt).
//
// Two invariants carry over from the trace and must never be broken here:
//
//   - Metadata only. A Finding is templated from trusted inputs alone: the profile's
//     route templates (from the grant's Allow list), one of five HTTP verbs, and
//     numeric counts/timings. It never echoes a guest-controlled string, so a finding
//     can neither leak an id/body/token nor become a prompt-injection channel.
//   - Non-authoritative. A Finding is evidence, exactly like the isolation tier. The
//     detectors run post-dispatch over an immutable trace; producing them never
//     changes a run's ExitCode, output, or isolation.
package insights

import "time"

// PatternID names the detector that produced a Finding. The string form is stable
// (it is the wire/audit label), so treat these as an API. The retired ids
// aggregate_in_code and sequential_calls may still appear in an operator's historical
// audit stream; the report renders them, the daemon never emits them again.
type PatternID string

const (
	// PatternFanOut is many successful calls to one per-item (wildcard) route template
	// in a run — the classic "512 GET /items/:id" N+1. Fix class: batch.
	PatternFanOut PatternID = "fan_out"
	// PatternRepeatedRead is one fixed (no-wildcard) read route requested repeatedly
	// with same-size successful responses. The fixed route is what makes "the same
	// request" established rather than guessed; the unchanged size is evidence, not
	// proof, that the data did not change (the trace holds sizes, not content).
	// Wildcard routes are never flagged here, since equal size cannot tell one item
	// fetched N times from N same-size items. Fix class: cache.
	PatternRepeatedRead PatternID = "repeated_read"
)

// RemedyClass is the kind of fix a Finding points at. Like PatternID it is a stable
// wire/audit label. The retired classes aggregate, filter and parallel may appear in
// historical audit records; Prompt refuses them rather than rendering a template that
// no longer exists.
type RemedyClass string

const (
	RemedyBatch RemedyClass = "batch" // one request replaces many per-item calls
	RemedyCache RemedyClass = "cache" // reuse the response to a request already made
)

// Severity ranks a Finding for advisory display only; it never gates a run. Ordered
// so a larger value is more severe, which the Analyze sort relies on.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}

// Cost is what a Finding can say about the price of its pattern. The inputs are
// measured (the broker counted the calls, timed each round trip, and summed the
// bytes); the "ideal" they are compared against is never measured, and it is always
// the same assumption: one call's worth. Only calls the broker delivered with a 2xx
// status are counted; failed calls are named in the finding's sentence instead. Read
// each field with that in mind, and never present the two derived ones as savings.
type Cost struct {
	// ExtraCalls is the measured successful call count minus one. As rigorous as the
	// operator's declaration when the profile declares and grants a batch route (a
	// fan-out with Suggested set: one call would do if that route returns the same
	// items, which is what the declaration asserts); an assumption otherwise, since
	// the replacement's shape is unknown.
	ExtraCalls int
	// AddedLatency is the summed measured round-trip time minus one call's (the
	// slowest for fan-out, the average for repeated reads). It is a model, "time
	// spent beyond one call", not a measurement of wall time lost: it assumes the
	// replacement call would take about as long as one of the existing ones, and it
	// sums calls that may have overlapped.
	AddedLatency time.Duration
	// BytesMoved is the measured request+response bytes across the counted calls,
	// already bounded by the broker's per-call caps. It is the gross total the
	// pattern moved, not a saving: the replacement call moves bytes too.
	BytesMoved int
}

// Route is a (method, template) pair, never a raw path. Used for the batch route a
// Finding names.
type Route struct {
	Method string
	Path   string
}

// Finding is one efficiency observation about a run's brokered host.* calls. Every
// string field is trusted (a route template, an HTTP verb, or a sentence templated
// from those plus numbers); none is guest-controlled.
//
// At most one of Suggested, GrantRoute and Candidate is set, and only on a read fan-out.
// What separates them is the basis for naming the route: an operator's declaration in
// the profile's batch_of (Suggested, GrantRoute) or the route's path alone (Candidate).
// A path cannot say whether the route pages, returns fewer fields, or covers a different
// scope, so only a declared route ever reaches the caller.
type Finding struct {
	Pattern  PatternID
	Severity Severity
	Method   string // route method the finding concerns (GET/PUT/POST/DELETE/PATCH)
	Route    string // matched route TEMPLATE, never a raw path
	Remedy   RemedyClass
	Cost     Cost
	// Suggested is the batch route the profile declares for this route (batch_of) and
	// grants (Allow): the agent can switch to it now. It is the one route a finding
	// hands the caller, and its presence is what makes a finding agent-fixable.
	Suggested *Route
	// GrantRoute is the batch route the profile declares for this route but does not
	// grant: the operator action is to add it to the Allow list. OPERATOR-ONLY: the agent
	// cannot call an ungranted route.
	GrantRoute *Route
	// Candidate is a route the path alone suggests: the per-item route's collection
	// (/items for /items/*), granted or listed in the profile's catalog, with no batch_of
	// declaration. OPERATOR-ONLY: plimsoll does not know it returns the same items, so the
	// operator checks it and, if it does, declares it.
	Candidate *Route
	// Detail is one plain sentence for a human or an agent, templated from trusted
	// metadata only (route template, method, counts, timings). It states the remedy
	// as a condition, names calls that did not succeed, and says "at least" when the
	// trace hit its row cap.
	Detail string
}
