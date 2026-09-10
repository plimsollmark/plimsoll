package rpc

import (
	"sort"
	"sync"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// latencyBucketCount is the number of finite upstream-latency histogram buckets.
const latencyBucketCount = 12

// latencyBucketsSec are the finite upper bounds (seconds) of the upstream-latency
// histogram, ascending. They straddle a fast local JSON API (sub-10ms) through a
// slow or paginating upstream (multi-second), matching the run's wall-clock budget.
// Observations above the last bound fall only into the implicit +Inf bucket.
var latencyBucketsSec = [latencyBucketCount]float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// HostCallLatencyBounds returns the finite histogram bucket bounds (seconds) so the
// /metrics renderer and tests share one definition.
func HostCallLatencyBounds() []float64 {
	return append([]float64(nil), latencyBucketsSec[:]...)
}

// hostCallKey labels one metric series. All three dimensions are operator-bounded:
// profile and route come from configured grants (route is always a template, never
// a raw path), and method is one of four verbs — so the series set is cardinality-
// safe and can never be inflated by guest-controlled input.
type hostCallKey struct {
	profile string
	method  string
	route   string
}

// hostCallSeries aggregates one key: a call count (also the histogram's _count and
// its +Inf bucket) and a latency histogram. buckets[i] is the NON-cumulative count
// of observations that fell in latencyBucketsSec[i]; the snapshot renders them
// cumulatively.
type hostCallSeries struct {
	count   uint64
	sumSec  float64
	buckets [latencyBucketCount]uint64
}

// hostCallStats folds per-run CallTraces into labeled Prometheus series (a call
// counter and an upstream-latency histogram). The zero value is ready to use; the
// series map is created on first observe. All access is mutex-guarded.
type hostCallStats struct {
	mu     sync.Mutex
	series map[hostCallKey]*hostCallSeries
}

// observe folds one run's CallTrace into the series under profile. No-op for a
// nil/empty trace, so a run with no grant costs nothing. Only recorded (allowed)
// calls carry a route template; denials are not route-labeled here.
func (h *hostCallStats) observe(profile string, t *sandbox.CallTrace) {
	if t == nil || len(t.Calls) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.series == nil {
		h.series = make(map[hostCallKey]*hostCallSeries)
	}
	for _, c := range t.Calls {
		key := hostCallKey{profile: profile, method: c.Method, route: c.Route}
		s := h.series[key]
		if s == nil {
			s = &hostCallSeries{}
			h.series[key] = s
		}
		s.count++
		sec := c.Latency.Seconds()
		s.sumSec += sec
		for i, ub := range latencyBucketsSec {
			if sec <= ub {
				s.buckets[i]++
				break
			}
		}
	}
}

// HostCallSeriesSnapshot is one metric series for /metrics rendering: the label
// values plus histogram data. CumulativeBuckets is aligned to HostCallLatencyBounds
// and is cumulative; the implicit +Inf bucket equals Count.
type HostCallSeriesSnapshot struct {
	Profile           string
	Method            string
	Route             string
	Count             uint64
	SumSec            float64
	CumulativeBuckets []uint64
}

// HostCallStats returns a snapshot of the host-call metric series, sorted by
// (profile, method, route) so the exposition output is stable across scrapes.
func (s *SandboxService) HostCallStats() []HostCallSeriesSnapshot {
	h := &s.hostCalls
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HostCallSeriesSnapshot, 0, len(h.series))
	for k, v := range h.series {
		cum := make([]uint64, latencyBucketCount)
		var running uint64
		for i := 0; i < latencyBucketCount; i++ {
			running += v.buckets[i]
			cum[i] = running
		}
		out = append(out, HostCallSeriesSnapshot{
			Profile:           k.profile,
			Method:            k.method,
			Route:             k.route,
			Count:             v.count,
			SumSec:            v.sumSec,
			CumulativeBuckets: cum,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Profile != out[j].Profile {
			return out[i].Profile < out[j].Profile
		}
		if out[i].Method != out[j].Method {
			return out[i].Method < out[j].Method
		}
		return out[i].Route < out[j].Route
	})
	return out
}
