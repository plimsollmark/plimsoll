package rpc

import (
	"sort"
	"sync"

	"github.com/plimsollmark/plimsoll/internal/insights"
)

// Prospector Phase 4 advice metrics. This folds a run's efficiency findings into
// labeled Prometheus series so a Grafana dashboard can chart pattern waste alongside
// the raw host-call latency the hostCallStats already exposes. Like every Prospector
// surface it is metadata only: the labels are a grant profile and a fixed detector
// vocabulary (pattern/severity/remedy) plus the router's agent-fixable bool, and the
// values are counts, an attributed-latency sum, and byte totals the trace already
// held — never a path, body, or credential.

// adviceKey labels one advice metric series. Every dimension is operator-bounded and
// cardinality-safe: profile comes from configured grants, pattern and remedy from the
// four/five-value detector vocabulary, severity is one of four ranks, and agentFixable
// is a bool — so no guest-controlled input can inflate the series set. The matched
// route TEMPLATE is deliberately NOT a label here: it already labels the host-call
// series, and adding it would multiply this family's cardinality without adding an
// aggregation the dashboard needs (waste rolls up by profile and pattern).
type adviceKey struct {
	profile      string
	pattern      string
	severity     string
	remedy       string
	agentFixable bool
}

// adviceSeries accumulates one key: how many findings shared it and the waste they
// attributed (extra calls, upstream latency in seconds, and bytes moved). The latency
// sum is what the bottleneck-attribution panel weighs against raw upstream latency.
type adviceSeries struct {
	count           uint64
	extraCalls      uint64
	addedLatencySec float64
	bytesMoved      uint64
}

// adviceStats folds per-run findings into labeled series. The zero value is ready to
// use; the map is created on first observe. All access is mutex-guarded.
type adviceStats struct {
	mu     sync.Mutex
	series map[adviceKey]*adviceSeries
}

// observe folds one run's findings into the series under profile. No-op for an empty
// finding set, so a run that produced no advice — including every run under a profile
// with advice off, which computes none — costs nothing.
func (a *adviceStats) observe(profile string, findings []insights.Finding) {
	if len(findings) == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.series == nil {
		a.series = make(map[adviceKey]*adviceSeries)
	}
	for _, f := range findings {
		key := adviceKey{
			profile:      profile,
			pattern:      string(f.Pattern),
			severity:     f.Severity.String(),
			remedy:       string(f.Remedy),
			agentFixable: f.Suggested != nil,
		}
		s := a.series[key]
		if s == nil {
			s = &adviceSeries{}
			a.series[key] = s
		}
		s.count++
		if f.Cost.ExtraCalls > 0 {
			s.extraCalls += uint64(f.Cost.ExtraCalls)
		}
		s.addedLatencySec += f.Cost.AddedLatency.Seconds()
		if f.Cost.BytesMoved > 0 {
			s.bytesMoved += uint64(f.Cost.BytesMoved)
		}
	}
}

// AdviceSeriesSnapshot is one advice metric series for /metrics rendering: the label
// values plus the accumulated count and waste.
type AdviceSeriesSnapshot struct {
	Profile         string
	Pattern         string
	Severity        string
	Remedy          string
	AgentFixable    bool
	Count           uint64
	ExtraCalls      uint64
	AddedLatencySec float64
	BytesMoved      uint64
}

// AdviceStats returns a snapshot of the advice metric series, sorted by
// (profile, pattern, severity, remedy, agent_fixable) so the exposition output is
// stable across scrapes.
func (s *SandboxService) AdviceStats() []AdviceSeriesSnapshot {
	a := &s.adviceStats
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AdviceSeriesSnapshot, 0, len(a.series))
	for k, v := range a.series {
		out = append(out, AdviceSeriesSnapshot{
			Profile:         k.profile,
			Pattern:         k.pattern,
			Severity:        k.severity,
			Remedy:          k.remedy,
			AgentFixable:    k.agentFixable,
			Count:           v.count,
			ExtraCalls:      v.extraCalls,
			AddedLatencySec: v.addedLatencySec,
			BytesMoved:      v.bytesMoved,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Profile != out[j].Profile {
			return out[i].Profile < out[j].Profile
		}
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		if out[i].Severity != out[j].Severity {
			return out[i].Severity < out[j].Severity
		}
		if out[i].Remedy != out[j].Remedy {
			return out[i].Remedy < out[j].Remedy
		}
		return boolLess(out[i].AgentFixable, out[j].AgentFixable)
	})
	return out
}

// boolLess orders false before true so the series sort is total and deterministic.
func boolLess(a, b bool) bool { return !a && b }
