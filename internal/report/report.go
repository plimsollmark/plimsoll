// Package report renders plimsoll's exported audit stream into a single
// self-contained, dependency-free HTML report (Prospector Phase 4). It is the
// no-Grafana companion to the dashboard: a customer points it at a file of the
// daemon's JSON "code run" audit lines and gets a static page — no build step, no
// external CSS or JS, no network — summarizing the run's brokered host-API calls and
// the efficiency findings plimsoll derived.
//
// The invariant the rest of Prospector carries holds here too: the audit stream is
// metadata only (route TEMPLATES, verbs, labels, counts, timings), so nothing this
// package reads or renders can be a raw path, body, or credential. All string fields
// are still escaped through html/template as defense in depth.
package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Finding is one efficiency observation as it appears in the report. It mirrors the
// advice_finding_details records on the audit line plus an optional DesignPrompt the
// caller may attach for API-change findings (Phase 3 surfacing).
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
	ExtraCalls      int    `json:"extra_calls"`
	AddedLatencyMs  int64  `json:"added_latency_ms"`
	BytesMoved      int    `json:"bytes_moved"`
	// DesignPrompt is an optional API-change design prompt for an operator to paste
	// into their own AI. It is filled in by the caller (which holds the profile's
	// route list); the audit stream never carries it. Rendered only when set.
	DesignPrompt string `json:"-"`
}

// Record is one "code run" audit line reduced to the fields the report renders.
type Record struct {
	Time   time.Time
	Caller string
	// TraceID is the caller's opaque correlation id, echoed by the daemon so this
	// metadata-only record can be JOINED to the caller's own log of the same
	// request. Empty when the caller did not correlate. It is rendered as an
	// identifier and never parsed — the report knows nothing about its meaning,
	// which is the property that makes it safe to carry here.
	TraceID         string
	Profile         string
	Sandbox         string
	Isolation       string
	ExitCode        int
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

// auditLine is the JSON shape of a daemon "code run" audit line. Only the fields the
// report consumes are declared; unknown fields (and non-"code run" lines) are ignored.
type auditLine struct {
	Msg             string    `json:"msg"`
	Time            time.Time `json:"time"`
	Caller          string    `json:"caller"`
	TraceID         string    `json:"trace_id"`
	Profile         string    `json:"grant_profile"`
	Sandbox         string    `json:"sandbox"`
	Isolation       string    `json:"isolation"`
	ExitCode        int       `json:"exit_code"`
	TimedOut        bool      `json:"timed_out"`
	DurationMs      int64     `json:"duration_ms"`
	HostCalls       int       `json:"host_calls"`
	HostCallsDenied int       `json:"host_calls_denied"`
	Advice          string    `json:"advice"`
	FindingCount    int       `json:"advice_findings"`
	AgentFixable    int       `json:"advice_agent_fixable"`
	ExtraCalls      int       `json:"advice_extra_calls"`
	AddedLatencyMs  int64     `json:"advice_added_latency_ms"`
	BytesMoved      int       `json:"advice_bytes_moved"`
	Findings        []Finding `json:"advice_finding_details"`
}

// maxLineBytes bounds a single audit line the parser will accept. It sits above the
// daemon's 8 MiB request ceiling so a legitimate line (bounded findings, no bodies)
// always fits, while a pathological line cannot exhaust memory.
const maxLineBytes = 16 << 20

// Parse reads a newline-delimited JSON audit stream and returns the "code run"
// records in stream order. Lines that are blank, not valid JSON, or not a "code run"
// entry are skipped rather than failing the whole report, so a mixed operational log
// (other RPCs, errors, warnings) can be piped in directly. It returns an error only
// if the underlying reader fails.
func Parse(r io.Reader) ([]Record, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	var out []Record
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var al auditLine
		if err := json.Unmarshal([]byte(line), &al); err != nil {
			continue // tolerate a corrupt or foreign line
		}
		if al.Msg != "code run" {
			continue
		}
		out = append(out, Record{
			Time:            al.Time,
			Caller:          al.Caller,
			TraceID:         al.TraceID,
			Profile:         al.Profile,
			Sandbox:         al.Sandbox,
			Isolation:       al.Isolation,
			ExitCode:        al.ExitCode,
			TimedOut:        al.TimedOut,
			DurationMs:      al.DurationMs,
			HostCalls:       al.HostCalls,
			HostCallsDenied: al.HostCallsDenied,
			Advice:          al.Advice,
			FindingCount:    al.FindingCount,
			AgentFixable:    al.AgentFixable,
			ExtraCalls:      al.ExtraCalls,
			AddedLatencyMs:  al.AddedLatencyMs,
			BytesMoved:      al.BytesMoved,
			Findings:        al.Findings,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read audit stream: %w", err)
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
