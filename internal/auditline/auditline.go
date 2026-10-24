// Package auditline is the daemon's per-run audit line as data: the messages that mark
// one, and the fields its readers use, in one type. The daemon writes the line through
// slog (internal/rpc); a test there decodes every kind of run line with Decode, so the
// writer and this type cannot drift apart. Every reader (internal/report, the advisor and
// adapter examples) decodes through here instead of declaring a shape of its own: three
// readers once each found "the run line" differently, and the report kept only snippet
// runs, dropping every project and module run (review, 2026-10-23).
//
// The line is metadata only: route templates, verbs, labels, counts and timings, never a
// raw path, body or credential.
package auditline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// The messages of a run's audit line. A snippet and a session cell are both "code run";
// Op tells them apart.
const (
	Code    = "code run"
	Project = "project run"
	Module  = "module run"
)

// IsRun reports whether msg marks one dispatched run's audit line.
func IsRun(msg string) bool { return msg == Code || msg == Project || msg == Module }

// Run is a run's audit line.
type Run struct {
	Msg       string    `json:"msg"`
	Time      time.Time `json:"time"`
	Op        string    `json:"op"` // javascript, project, module or cell
	Caller    string    `json:"caller"`
	TraceID   string    `json:"trace_id"`
	Profile   string    `json:"grant_profile"`
	Sandbox   string    `json:"sandbox"`
	Isolation string    `json:"isolation"`
	// Outcome is a project's or module's (ProjectOutcome.String); empty for a snippet or
	// a cell, whose line states its exit code and timeout alone.
	Outcome string `json:"outcome"`
	// ExitCode is the exit code of the snippet, the cell, or the project's last reported
	// step; nil when none was reported (a project stopped before any step reported, a
	// module run), which is not an exit code of 0.
	ExitCode *int `json:"exit_code"`
	// TimedOut: the run, or its last reported step, ran out of time.
	TimedOut        bool      `json:"timed_out"`
	DurationMs      int64     `json:"duration_ms"`
	HostCalls       int       `json:"host_calls"`
	HostCallsDenied int       `json:"host_calls_denied"`
	HostCallsShed   int       `json:"host_calls_shed"`
	Advice          string    `json:"advice"`
	FindingCount    int       `json:"advice_findings"`
	AgentFixable    int       `json:"advice_agent_fixable"`
	ExtraCalls      int       `json:"advice_extra_calls"`
	AddedLatencyMs  int64     `json:"advice_added_latency_ms"`
	BytesMoved      int       `json:"advice_bytes_moved"`
	Findings        []Finding `json:"advice_finding_details"`
}

// Finding is one efficiency finding on a run's line (advice_finding_details).
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
	BytesMoved      int64  `json:"bytes_moved"`
}

// Decode reads one line and reports whether it is a run's audit line. Anything else (a
// blank, a foreign or corrupt line, another RPC's line) is false, never an error, so a
// mixed operational log can be read directly.
func Decode(line []byte) (Run, bool) {
	s := strings.TrimSpace(string(line))
	if s == "" || s[0] != '{' {
		return Run{}, false
	}
	var r Run
	if err := json.Unmarshal([]byte(s), &r); err != nil || !IsRun(r.Msg) {
		return Run{}, false
	}
	return r, true
}

// maxLineBytes bounds one line the reader accepts. It sits above the daemon's 8 MiB
// request ceiling so a legitimate line (bounded findings, no bodies) always fits, while a
// pathological line cannot exhaust memory.
const maxLineBytes = 16 << 20

// Parse reads a newline-delimited audit stream and returns every run's line in stream
// order. It fails only when the reader does.
func Parse(r io.Reader) ([]Run, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	var out []Run
	for sc.Scan() {
		if run, ok := Decode(sc.Bytes()); ok {
			out = append(out, run)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read audit stream: %w", err)
	}
	return out, nil
}
