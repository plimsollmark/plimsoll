// Package insights derives deterministic, metadata-only efficiency findings from a
// run's brokered host.* call trace (Prospector Phase 1). It reads a bounded
// sandbox.CallTrace — route TEMPLATES, methods, byte sizes, upstream latencies, and
// sequence numbers, never a raw path, body, or credential — and reports where the
// agent's call pattern was wasteful.
//
// Two invariants carry over from the trace and must never be broken here:
//
//   - Metadata only. A Finding is templated from trusted inputs alone: the profile's
//     route templates (from the grant's Allow list), one of four HTTP verbs, and
//     numeric counts/timings. It never echoes a guest-controlled string, so a finding
//     can neither leak an id/body/token nor become a prompt-injection channel.
//   - Non-authoritative. A Finding is evidence, exactly like the isolation tier. The
//     detectors run post-dispatch over an immutable trace; producing them never
//     changes a run's ExitCode, output, or isolation.
package insights

import "time"

// PatternID names the detector that produced a Finding. The string form is stable
// (it is the wire/audit label in later phases), so treat these as an API.
type PatternID string

const (
	// PatternFanOut is many calls to one per-item (wildcard) route template in a run
	// — the classic "512 GET /items/:id" N+1. Fix class: batch.
	PatternFanOut PatternID = "fan_out"
	// PatternAggregateInCode is a burst of reads with no writes after, i.e. the client
	// pulled rows to reduce them locally (a client-side sum). Fix class: aggregate.
	PatternAggregateInCode PatternID = "aggregate_in_code"
	// PatternRepeatedRead is the same read repeated with an identical response shape —
	// cacheable. Heuristic: the trace holds no id, so identical response SIZE is the
	// arg-shape proxy. Fix class: cache.
	PatternRepeatedRead PatternID = "repeated_read"
	// PatternSequential is a run whose summed upstream latency spans several routes and
	// dominates the wall clock — issuing the independent calls concurrently would cut
	// the wait. Lowest confidence: the trace cannot prove the calls were serialized or
	// independent. Fix class: parallel.
	PatternSequential PatternID = "sequential_calls"
)

// RemedyClass is the kind of fix a Finding points at. The first four match the
// roadmap's vocabulary; RemedyParallel is added for the sequential detector, whose
// fix is concurrency rather than a different endpoint.
type RemedyClass string

const (
	RemedyBatch     RemedyClass = "batch"     // one request replaces many per-item calls
	RemedyAggregate RemedyClass = "aggregate" // compute the reduction server-side
	RemedyFilter    RemedyClass = "filter"    // push a selection server-side (reserved)
	RemedyCache     RemedyClass = "cache"     // reuse a prior identical response
	RemedyParallel  RemedyClass = "parallel"  // issue independent calls concurrently
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
// the same assumption: one call's worth. Read each field with that in mind, and
// never present the two derived ones as savings.
type Cost struct {
	// ExtraCalls is the measured call count minus one. Rigorous when a granted
	// batch route exists (a fan-out with Suggested set: one call really would do);
	// an assumption when the finding says the API needs a new endpoint, since that
	// endpoint's shape is unknown. Zero for latency-only findings.
	ExtraCalls int
	// AddedLatency is the summed measured round-trip time minus one call's (the
	// slowest for fan-out, aggregate and sequential; the average for repeated
	// reads). It is a model, "time spent beyond one call", not a measurement of
	// wall time lost: it assumes the replacement call would take about as long as
	// one of the existing ones, and it sums calls that may have overlapped.
	AddedLatency time.Duration
	// BytesMoved is the measured request+response bytes across the flagged calls,
	// already bounded by the broker's per-call caps. It is the gross total the
	// pattern moved, not a saving: the replacement call moves bytes too.
	BytesMoved int
}

// Route is a (method, template) pair, never a raw path. Used for a Finding's
// router-suggested better endpoint.
type Route struct {
	Method string
	Path   string
}

// Finding is one efficiency observation about a run's brokered host.* calls. Every
// string field is trusted (a route template, an HTTP verb, or a sentence templated
// from those plus numbers); none is guest-controlled.
type Finding struct {
	Pattern  PatternID
	Severity Severity
	Method   string // route method the finding concerns (GET/PUT/POST/DELETE/PATCH)
	Route    string // matched route TEMPLATE, never a raw path
	Remedy   RemedyClass
	Cost     Cost
	// Suggested is a better route the profile already exposes (from the Allow list),
	// set by the router when one exists — e.g. a fan-out on /items/* whose profile
	// also grants /items. Nil when Analyze got no Allow list or found no sibling.
	// Its presence is what later phases use to split agent-fixable from API-change.
	Suggested *Route
	// CatalogMatch is a better route the host API EXPOSES (per the profile's endpoint
	// catalog, e.g. generated from its OpenAPI spec) but the profile does NOT grant — so
	// the fix is an operator action: widen the Allow list to enable the batch. It is set
	// only when Suggested is not (a granted sibling always wins), and is OPERATOR-ONLY:
	// it never reaches the caller, since the agent cannot call an ungranted route. Nil
	// when Analyze got no catalog or the API exposes no such endpoint.
	CatalogMatch *Route
	// Detail is one plain sentence for a human or an agent, templated from trusted
	// metadata only (route template, method, counts, timings).
	Detail string
}
