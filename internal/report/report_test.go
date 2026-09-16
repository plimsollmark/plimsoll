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
	if len(recs) != 4 {
		t.Fatalf("expected 4 code-run records, got %d", len(recs))
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

	// Aggregates: 4 findings total (2+1+1), 197 host calls (24+140+30+3), 2 agent-fixable,
	// 2 API-change.
	wants := []string{
		"sample-audit.jsonl",
		"2026-07-18 12:00:00 UTC",
		">197<", // total host calls tile
		">4<",   // total findings tile
		"Fan-out",
		"Aggregate in code",
		"/v1/lights/*",
		"Better route already granted",
		"a batch endpoint would collapse them into one request.",
		"metadata only", // footer guarantee
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
