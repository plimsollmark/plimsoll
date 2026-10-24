// Package report renders plimsoll's exported audit stream into a single
// self-contained, dependency-free HTML report (Prospector Phase 4). It is the
// no-Grafana companion to the dashboard: a customer points it at a file of the
// daemon's JSON run audit lines (internal/auditline) and gets a static page — no build step, no
// external CSS or JS, no network — summarizing the run's brokered host-API calls and
// the efficiency findings plimsoll derived.
//
// The invariant the rest of Prospector carries holds here too: the audit stream is
// metadata only (route TEMPLATES, verbs, labels, counts, timings), so nothing this
// package reads or renders can be a raw path, body, or credential. All string fields
// are still escaped through html/template as defense in depth.
package report

import (
	"io"
	"strconv"
	"time"

	"github.com/plimsollmark/plimsoll/internal/auditline"
)

// Finding is one efficiency observation as it appears in the report. It mirrors the
// advice_finding_details records on the audit line plus an optional DesignPrompt the
// caller may attach for findings that need a new endpoint (Phase 3 surfacing).
type Finding struct {
	Pattern         string `json:"pattern"`
	Severity        string `json:"severity"`
	Remedy          string `json:"remedy"`
	Method          string `json:"method"`
	Route           string `json:"route"`
	Detail          string `json:"detail"`
	AgentFixable    bool   `json:"agent_fixable"`
	SuggestedMethod string `json:"suggested_method"`
	SuggestedRoute  string `json:"suggested_route"`
	// GrantRouteMethod/GrantRoute name the batch route the profile declares (batch_of)
	// but does not grant: the operator adds one line to the allow list.
	GrantRouteMethod string `json:"grant_route_method"`
	GrantRoute       string `json:"grant_route"`
	// CandidateMethod/CandidateRoute name a route found from the path alone (the
	// per-item route's collection, granted or catalogued) with no declaration: the
	// operator checks whether it returns the same items before declaring it.
	CandidateMethod string `json:"candidate_method"`
	CandidateRoute  string `json:"candidate_route"`
	ExtraCalls      int    `json:"extra_calls"`
	AddedLatencyMs  int64  `json:"added_latency_ms"`
	BytesMoved      int    `json:"bytes_moved"`
	// DesignPrompt is an optional design prompt for an operator to paste into their own
	// AI. It is filled in by the caller (which holds the profile's route list); the
	// audit stream never carries it. Rendered only when set.
	DesignPrompt string `json:"-"`
}

// Class is what the report can say about a finding's fix. The first two rest on the
// operator's batch_of declaration: the declared route is granted (the agent can switch
// to it now) or not (the operator adds one allow line). A candidate rests on the path
// alone, which cannot say whether the route pages, returns fewer fields or covers
// another scope, so the operator checks it first. Knowing none of these is not the same
// as knowing the API must change: the profile may declare no catalog, or the API may
// expose an equivalent endpoint under a name this run never touched.
type Class string

const (
	ClassAgentFixable Class = "agent-fixable" // a declared batch route is granted
	ClassGrantRoute   Class = "grant-route"   // a declared batch route is not granted
	ClassCandidate    Class = "candidate"     // the path suggests a route; nothing declares it
	ClassNoKnownRoute Class = "no-known-route"
)

// Class classifies one finding for display and counting.
func (f Finding) Class() Class {
	switch {
	case f.AgentFixable:
		return ClassAgentFixable
	case f.GrantRoute != "":
		return ClassGrantRoute
	case f.CandidateRoute != "":
		return ClassCandidate
	default:
		return ClassNoKnownRoute
	}
}

// Record is one run's audit line (snippet, cell, project or module) reduced to the
// fields the report renders.
type Record struct {
	Time   time.Time
	Caller string
	// TraceID is the caller's opaque correlation id, echoed by the daemon so this
	// metadata-only record can be JOINED to the caller's own log of the same
	// request. Empty when the caller did not correlate. It is rendered as an
	// identifier and never parsed — the report knows nothing about its meaning,
	// which is the property that makes it safe to carry here.
	TraceID   string
	Profile   string
	Sandbox   string
	Isolation string
	Op        string // javascript, project, module or cell
	// Exit is what ended the run as the report shows it: the exit code of the snippet,
	// the cell or the project's last reported step, else the outcome (a module run, or a
	// project stopped before any step reported); never a 0 nothing reported.
	Exit            string
	TimedOut        bool
	DurationMs      int64
	HostCalls       int
	HostCallsDenied int
	Advice          string
	FindingCount    int
	AgentFixable    int
	ExtraCalls      int
	AddedLatencyMs  int64
	BytesMoved      int
	Findings        []Finding
}

// Parse reads a newline-delimited JSON audit stream and returns every run's record in
// stream order: snippets, cells, projects and modules (auditline.Parse). Lines that are
// blank, not valid JSON, or not a run's are skipped rather than failing the whole
// report, so a mixed operational log (other RPCs, errors, warnings) can be piped in
// directly. It returns an error only if the underlying reader fails.
func Parse(r io.Reader) ([]Record, error) {
	runs, err := auditline.Parse(r)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(runs))
	for _, run := range runs {
		exit := run.Outcome
		if run.ExitCode != nil {
			exit = strconv.Itoa(*run.ExitCode)
		}
		findings := make([]Finding, 0, len(run.Findings))
		for _, f := range run.Findings {
			findings = append(findings, Finding{Pattern: f.Pattern, Severity: f.Severity, Remedy: f.Remedy,
				Method: f.Method, Route: f.Route, Detail: f.Detail, AgentFixable: f.AgentFixable,
				SuggestedMethod: f.SuggestedMethod, SuggestedRoute: f.SuggestedRoute,
				GrantRouteMethod: f.GrantRouteMethod, GrantRoute: f.GrantRoute,
				CandidateMethod: f.CandidateMethod, CandidateRoute: f.CandidateRoute,
				ExtraCalls: f.ExtraCalls, AddedLatencyMs: f.AddedLatencyMs, BytesMoved: int(f.BytesMoved)})
		}
		out = append(out, Record{
			Time:            run.Time,
			Caller:          run.Caller,
			TraceID:         run.TraceID,
			Profile:         run.Profile,
			Sandbox:         run.Sandbox,
			Isolation:       run.Isolation,
			Op:              run.Op,
			Exit:            exit,
			TimedOut:        run.TimedOut,
			DurationMs:      run.DurationMs,
			HostCalls:       run.HostCalls,
			HostCallsDenied: run.HostCallsDenied,
			Advice:          run.Advice,
			FindingCount:    run.FindingCount,
			AgentFixable:    run.AgentFixable,
			ExtraCalls:      run.ExtraCalls,
			AddedLatencyMs:  run.AddedLatencyMs,
			BytesMoved:      run.BytesMoved,
			Findings:        findings,
		})
	}
	return out, nil
}

// Options tune the rendered report.
type Options struct {
	// Title heads the report; defaults to a Prospector title when empty.
	Title string
	// Source is a short provenance note (e.g. the audit file name) shown in the header.
	Source string
	// Generated stamps the report; the zero value uses the current time.
	Generated time.Time
}
