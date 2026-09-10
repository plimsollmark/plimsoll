package rpc

import (
	"log/slog"
	"time"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/insights"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Prospector Phase 2 advisory channel. Everything here is post-dispatch analysis
// over a run's immutable, metadata-only CallTrace: it reads route templates, verbs,
// sizes, and timings the broker already recorded, and never touches the run's
// result. A run with advice is byte-identical in execution to one without — the
// non-blocking guarantee the roadmap requires.

// adviceFor resolves a run's grant_profile to its efficiency-advice opt-in. grantFor
// has already authorized the profile for this caller, so this is a plain lookup; an
// empty or unknown profile advises nothing (off by default).
func (s *SandboxService) adviceFor(profile string) grants.AdviceMode {
	if profile == "" {
		return grants.AdviceOff
	}
	p, ok := s.Grants.Get(profile)
	if !ok {
		return grants.AdviceOff
	}
	return p.Advice()
}

// adviceRetentionFor resolves a run's grant_profile to its advisory-telemetry retention
// level. Like adviceFor, an empty or unknown profile retains nothing (off by default).
func (s *SandboxService) adviceRetentionFor(profile string) grants.AdviceRetention {
	if profile == "" {
		return grants.RetentionNone
	}
	p, ok := s.Grants.Get(profile)
	if !ok {
		return grants.RetentionNone
	}
	return p.AdviceRetention()
}

// catalogFor resolves a run's grant_profile to its known host-API endpoints (a superset
// of the grant's Allow), which Prospector uses to name an ungranted route worth adding.
// An empty or unknown profile knows no catalog.
func (s *SandboxService) catalogFor(profile string) []sandbox.HostRoute {
	if profile == "" {
		return nil
	}
	p, ok := s.Grants.Get(profile)
	if !ok {
		return nil
	}
	return p.Catalog()
}

// computeAdvice runs the Prospector detectors over a run's CallTrace and splits the
// findings by audience, per the profile's advice mode:
//
//   - all: every finding, for the operator surface (audit/logs/dashboards). Computed
//     for both operator and caller modes.
//   - caller: the agent-fixable subset — findings whose remedy is a better route the
//     profile already exposes (Finding.Suggested set). Populated only in caller mode;
//     API-change findings (no suggested route) never leave the operator surface.
//
// catalog, when set (the profile's known API endpoints, e.g. from its OpenAPI spec via
// plimsoll-specgen), lets a finding name the concrete ungranted route the operator
// should add (Finding.CatalogMatch) instead of a vague "the API needs a change." That
// annotation is operator-only: it is never in the caller subset, since the agent cannot
// call an ungranted route.
//
// It reads only the metadata the broker recorded and never mutates the trace, so it
// cannot change ExitCode, output, or isolation.
func computeAdvice(mode grants.AdviceMode, trace *sandbox.CallTrace, allow, catalog []sandbox.HostRoute) (all, caller []insights.Finding) {
	if mode == grants.AdviceOff {
		return nil, nil
	}
	all = insights.AnalyzeWithCatalog(trace, allow, catalog)
	if mode != grants.AdviceCaller {
		return all, nil
	}
	for _, f := range all {
		if f.Suggested != nil { // a better route exists -> the agent can fix it now
			caller = append(caller, f)
		}
	}
	return all, caller
}

// adviceWire maps agent-fixable findings to their wire form for the run result.
// Every field is trusted metadata (a route template, an HTTP verb, a number, or a
// sentence templated from those); no guest-controlled string is ever copied through,
// so the response cannot leak an id/body/token or carry a prompt-injection payload.
func adviceWire(findings []insights.Finding) []*plimsollv1.AdviceFinding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]*plimsollv1.AdviceFinding, 0, len(findings))
	for _, f := range findings {
		af := &plimsollv1.AdviceFinding{
			Pattern:        string(f.Pattern),
			Severity:       f.Severity.String(),
			Remedy:         string(f.Remedy),
			Method:         f.Method,
			Route:          f.Route,
			Detail:         f.Detail,
			ExtraCalls:     int32(f.Cost.ExtraCalls),
			AddedLatencyMs: f.Cost.AddedLatency.Milliseconds(),
			BytesMoved:     int64(f.Cost.BytesMoved),
		}
		if f.Suggested != nil {
			af.SuggestedMethod = f.Suggested.Method
			af.SuggestedRoute = f.Suggested.Path
		}
		out = append(out, af)
	}
	return out
}

// findingSummary is one finding's audit-line record: the Prospector per-run pattern
// summary the roadmap's Phase 4 asks for (findings + costs). Every field is trusted
// metadata — a route TEMPLATE, an HTTP verb, a pattern/severity/remedy label, a
// sentence templated from those plus numbers, or a count/timing/size — so a summary
// can neither leak a path/body/credential nor carry a prompt-injection payload. The
// json tags are the wire contract the HTML report parser (internal/report) reads, so
// treat them as an API. AgentFixable is the router's split (a better route exists);
// SuggestedMethod/Route name it when it does.
type findingSummary struct {
	Pattern         string `json:"pattern"`
	Severity        string `json:"severity"`
	Remedy          string `json:"remedy"`
	Method          string `json:"method"`
	Route           string `json:"route"`
	Detail          string `json:"detail,omitempty"`
	AgentFixable    bool   `json:"agent_fixable"`
	SuggestedMethod string `json:"suggested_method,omitempty"`
	SuggestedRoute  string `json:"suggested_route,omitempty"`
	// GrantRouteMethod/Route name a route the API exposes but the profile does not grant
	// (from the endpoint catalog): the operator action is to add it to the allow list.
	// Operator-only; never sent to the caller.
	GrantRouteMethod string `json:"grant_route_method,omitempty"`
	GrantRoute       string `json:"grant_route,omitempty"`
	ExtraCalls       int    `json:"extra_calls,omitempty"`
	AddedLatencyMs   int64  `json:"added_latency_ms,omitempty"`
	BytesMoved       int    `json:"bytes_moved,omitempty"`
}

// adviceAuditAttrs summarizes the operator-surface findings for the audit line, gated
// by the profile's retention level (roadmap Phase 5). Every attribute is trusted
// labels and numbers — never a path, body, or credential:
//
//   - RetentionNone (default): nothing. The run's findings never reach the durable
//     audit log; the caller wire hint and the bounded /metrics aggregates are emitted
//     elsewhere and are unaffected.
//   - RetentionAggregate: the mode, finding count, and total estimated waste, so a log
//     reader can glance the run's cost without a per-route record of it.
//   - RetentionDetailed: additionally advice_finding_details, one record per finding —
//     the per-route breakdown the exported-audit HTML report renders.
//
// Empty when the run produced no findings or retention is none.
func adviceAuditAttrs(mode grants.AdviceMode, retention grants.AdviceRetention, all []insights.Finding) []slog.Attr {
	if len(all) == 0 || retention == grants.RetentionNone {
		return nil
	}
	var agentFixable, ungranted, extraCalls, bytesMoved int
	var addedLatency time.Duration
	var details []findingSummary
	if retention == grants.RetentionDetailed {
		details = make([]findingSummary, 0, len(all))
	}
	for _, f := range all {
		if f.Suggested != nil {
			agentFixable++
		}
		if f.CatalogMatch != nil {
			ungranted++
		}
		extraCalls += f.Cost.ExtraCalls
		addedLatency += f.Cost.AddedLatency
		bytesMoved += f.Cost.BytesMoved
		if retention != grants.RetentionDetailed {
			continue
		}
		fs := findingSummary{
			Pattern:        string(f.Pattern),
			Severity:       f.Severity.String(),
			Remedy:         string(f.Remedy),
			Method:         f.Method,
			Route:          f.Route,
			Detail:         f.Detail,
			AgentFixable:   f.Suggested != nil,
			ExtraCalls:     f.Cost.ExtraCalls,
			AddedLatencyMs: f.Cost.AddedLatency.Milliseconds(),
			BytesMoved:     f.Cost.BytesMoved,
		}
		if f.Suggested != nil {
			fs.SuggestedMethod = f.Suggested.Method
			fs.SuggestedRoute = f.Suggested.Path
		}
		if f.CatalogMatch != nil {
			fs.GrantRouteMethod = f.CatalogMatch.Method
			fs.GrantRoute = f.CatalogMatch.Path
		}
		details = append(details, fs)
	}
	attrs := []slog.Attr{
		slog.String("advice", mode.String()),
		slog.String("advice_retention", retention.String()),
		slog.Int("advice_findings", len(all)),
		slog.Int("advice_agent_fixable", agentFixable),
		slog.Int("advice_ungranted_routes", ungranted),
		slog.Int("advice_extra_calls", extraCalls),
		slog.Int64("advice_added_latency_ms", addedLatency.Milliseconds()),
		slog.Int("advice_bytes_moved", bytesMoved),
	}
	if retention == grants.RetentionDetailed {
		attrs = append(attrs, slog.Any("advice_finding_details", details))
	}
	return attrs
}
