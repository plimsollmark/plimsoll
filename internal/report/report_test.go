package report

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

// fixedTime is a stable stamp so rendered output is deterministic across runs.
var fixedTime = time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)

func loadSample(t *testing.T) []Record {
	t.Helper()
	f, err := os.Open("testdata/sample-audit.jsonl")
	if err != nil {
		t.Fatalf("open sample: %v", err)
	}
	defer f.Close()
	recs, err := Parse(f)
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	return recs
}

// TestParseSkipsNonCodeRun proves the parser keeps only "code run" lines and tolerates
// a foreign/corrupt line and a "code run failed" error line without failing.
func TestParseSkipsNonCodeRun(t *testing.T) {
	recs := loadSample(t)
	if len(recs) != 5 {
		t.Fatalf("expected 5 code-run records, got %d", len(recs))
	}
	if recs[0].Profile != "hue" || len(recs[0].Findings) != 2 {
		t.Errorf("record 0 = %+v, want hue with 2 findings", recs[0])
	}
	if recs[0].Findings[0].SuggestedRoute != "/v1/lights" {
		t.Errorf("record 0 finding 0 lost its suggested route: %+v", recs[0].Findings[0])
	}
	if len(recs[3].Findings) != 0 || recs[3].Profile != "readonly" {
		t.Errorf("record 3 (advice-off run) = %+v, want readonly with no findings", recs[3])
	}
}

// TestParseCarriesTraceID proves the join key survives the audit stream into the
// report. Without it the report is a dead end for "which request was this?" — the
// question plimsoll's metadata-only record deliberately defers to the caller's
// own log rather than answering with a second copy of the payload. A run whose
// caller did not correlate parses to an empty id rather than failing the line.
func TestParseCarriesTraceID(t *testing.T) {
	recs := loadSample(t)
	if recs[0].TraceID != "9af31c02" {
		t.Errorf("record 0 trace id = %q, want 9af31c02", recs[0].TraceID)
	}
	if recs[1].TraceID != "3f1b7c0e-9a41-4d8e-8f0a-5b2c1d3e4f50" {
		t.Errorf("record 1 trace id = %q, want the uuid form", recs[1].TraceID)
	}
	if recs[2].TraceID != "" {
		t.Errorf("record 2 trace id = %q, want empty for an uncorrelated run", recs[2].TraceID)
	}
}

// TestRenderShowsTraceID proves the id reaches the rendered page: a join key that
// stops at the parser helps nobody holding the report.
func TestRenderShowsTraceID(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, loadSample(t), Options{Source: "sample-audit.jsonl", Generated: fixedTime}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "9af31c02") {
		t.Error("rendered report does not show the run's trace id")
	}
}

// TestRenderFromSample is the roadmap's check: the HTML report renders from a sample
// audit file, is self-contained (no external references), and reflects the aggregates.
func TestRenderFromSample(t *testing.T) {
	recs := loadSample(t)
	var buf bytes.Buffer
	if err := Render(&buf, recs, Options{Source: "sample-audit.jsonl", Generated: fixedTime}); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	// Well-formed, self-contained document.
	if !strings.HasPrefix(strings.TrimSpace(out), "<!doctype html>") {
		t.Error("output is not an HTML document")
	}
	// No external resource may be referenced: the report must render offline.
	for _, bad := range []string{"://", "src=", "<link", "@import"} {
		if strings.Contains(out, bad) {
			t.Errorf("report references something external (%q); it must be self-contained", bad)
		}
	}

	// Aggregates: 5 findings total (2+1+1+1), 238 host calls (24+140+30+3+41),
	// 2 agent-fixable, 1 route to grant, 2 with no known route.
	wants := []string{
		"sample-audit.jsonl",
		"2026-07-18 12:00:00 UTC",
		">238<", // total host calls tile
		">5<",   // total findings tile
		"Fan-out",
		"Aggregate in code",
		"/v1/lights/*",
		"Better route already granted",
		"a batch endpoint would collapse them into one request.",
		// The three fix classes the report distinguishes, each on a real record.
		"agent-fixable",
		"grant a route",
		"<code>GET /api/suppliers</code> but this profile does not grant it",
		"no known route",
		"work in progress", // the advisor's own status, on the artifact itself
		"metadata only",    // footer guarantee
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("report missing %q", w)
		}
	}

	// The profile aggregation names each grant profile that ran.
	for _, p := range []string{"hue", "inventory", "readonly"} {
		if !strings.Contains(out, ">"+p+"<") {
			t.Errorf("report does not mention profile %q", p)
		}
	}
}

// TestRenderDeterministic confirms two renders of the same input are byte-identical,
// so the report is stable to commit or diff.
func TestRenderDeterministic(t *testing.T) {
	recs := loadSample(t)
	var a, b bytes.Buffer
	opts := Options{Generated: fixedTime}
	if err := Render(&a, recs, opts); err != nil {
		t.Fatal(err)
	}
	if err := Render(&b, recs, opts); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("render is not deterministic")
	}
}

// TestRenderDesignPrompt proves an attached API-change prompt is surfaced in the
// report (the Phase 3 operator-surface hook the CLI fills in).
func TestRenderDesignPrompt(t *testing.T) {
	rec := Record{
		Profile:      "hue",
		Sandbox:      "docker",
		FindingCount: 1,
		Findings: []Finding{{
			Pattern:      "aggregate_in_code",
			Severity:     "medium",
			Remedy:       "aggregate",
			Method:       "GET",
			Route:        "/api/orders/*",
			Detail:       "reduced rows in code",
			AgentFixable: false,
			DesignPrompt: "You are an API designer. PLEASE_DESIGN_THIS_ENDPOINT.",
		}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, []Record{rec}, Options{Generated: fixedTime}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "API-design prompt for this finding") {
		t.Error("design prompt section missing")
	}
	if !strings.Contains(out, "PLEASE_DESIGN_THIS_ENDPOINT") {
		t.Error("design prompt body missing")
	}
}

// TestRenderHistoricalPatternLabels: the sequential and aggregate-in-code detectors
// were deleted on 2026-09-16, but an operator's retained audit stream may still carry
// their records. The report keeps rendering them under their old labels rather than
// failing or relabelling history; the daemon simply never emits them again. (The
// sample fixture's aggregate_in_code record is the same case in file form.)
func TestRenderHistoricalPatternLabels(t *testing.T) {
	rec := Record{Profile: "hue", Sandbox: "docker", FindingCount: 2, Findings: []Finding{
		{Pattern: "sequential_calls", Severity: "low", Remedy: "parallel", Method: "GET", Route: "/a", Detail: "historical"},
		{Pattern: "aggregate_in_code", Severity: "low", Remedy: "aggregate", Method: "GET", Route: "/items/*", Detail: "historical"},
	}}
	var buf bytes.Buffer
	if err := Render(&buf, []Record{rec}, Options{Generated: fixedTime}); err != nil {
		t.Fatalf("render historical stream: %v", err)
	}
	for _, want := range []string{"Sequential calls", "Aggregate in code"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("historical pattern label %q missing from the rendered report", want)
		}
	}
}

// TestRenderEmpty renders an empty stream without error and shows the empty state.
func TestRenderEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, nil, Options{Generated: fixedTime}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No") {
		t.Error("empty report should show an empty-state message")
	}
}

// TestParseCarriesGrantRoute proves the report reads the grant_route fields the daemon
// writes. Dropping them at this boundary is what turned "add one line to the allow list"
// into "the API needs a change" in the rendered page, even though the audit line named
// the exact route to grant.
func TestParseCarriesGrantRoute(t *testing.T) {
	line := `{"msg":"code run","grant_profile":"inventory","advice_findings":1,"advice_finding_details":[{"pattern":"fan_out","severity":"medium","remedy":"batch","method":"GET","route":"/api/orders/*","agent_fixable":false,"grant_route_method":"GET","grant_route":"/api/orders"}]}`
	recs, err := Parse(strings.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || len(recs[0].Findings) != 1 {
		t.Fatalf("parsed %+v, want one record with one finding", recs)
	}
	f := recs[0].Findings[0]
	if f.GrantRouteMethod != "GET" || f.GrantRoute != "/api/orders" {
		t.Fatalf("grant route = %q %q, want GET /api/orders", f.GrantRouteMethod, f.GrantRoute)
	}
	if f.Class() != ClassGrantRoute {
		t.Fatalf("class = %q, want %q", f.Class(), ClassGrantRoute)
	}
}

// TestRenderClassifiesByWhatIsKnown checks the three classes read differently on the
// page. The distinction is the point: a granted route is the agent's to use, a catalogued
// one is an operator's allow-list line, and neither being known is not evidence that the
// API must change — the profile may simply declare no catalog.
func TestRenderClassifiesByWhatIsKnown(t *testing.T) {
	rec := Record{Profile: "inventory", Sandbox: "docker", FindingCount: 3, Findings: []Finding{
		{Pattern: "fan_out", Severity: "high", Remedy: "batch", Method: "GET", Route: "/a/*", Detail: "granted sibling", AgentFixable: true, SuggestedMethod: "GET", SuggestedRoute: "/a"},
		{Pattern: "fan_out", Severity: "medium", Remedy: "batch", Method: "GET", Route: "/b/*", Detail: "catalogued sibling", GrantRouteMethod: "GET", GrantRoute: "/b"},
		{Pattern: "fan_out", Severity: "low", Remedy: "batch", Method: "GET", Route: "/c/*", Detail: "nothing known"},
	}}
	var buf bytes.Buffer
	if err := Render(&buf, []Record{rec}, Options{Generated: fixedTime}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"agent-fixable",
		"grant a route",
		"<code>GET /b</code> but this profile does not grant it",
		"no known route",
		"the profile declares no catalog to check",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report is missing %q", want)
		}
	}
	// The old binary label claimed more than the data supports; it must be gone.
	if strings.Contains(out, ">API change<") {
		t.Error("report still labels an unresolved finding as an API change")
	}
	// The report says the advisor is a work in progress, like the example page does.
	if !strings.Contains(out, "work in progress") {
		t.Error("rendered report carries no work-in-progress notice")
	}
}
