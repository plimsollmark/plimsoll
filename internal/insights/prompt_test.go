package insights

import (
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// promptFor runs Analyze on rows, finds the pattern, and generates its remediation
// prompt. It fails the test if the pattern was not detected or Prompt refused it.
func promptFor(t *testing.T, tr *sandbox.CallTrace, allow []sandbox.HostRoute, p PatternID) (Finding, string) {
	t.Helper()
	f, ok := find(Analyze(tr, allow), p)
	if !ok {
		t.Fatalf("%s not detected", p)
	}
	prompt, ok := Prompt(f, allow)
	if !ok {
		t.Fatalf("Prompt refused a %s finding (remedy %s)", p, f.Remedy)
	}
	return f, prompt
}

func TestPromptGroundedInMetadata(t *testing.T) {
	// A fan-out with NO collection sibling in the grant: the router leaves Suggested
	// nil, so this is the API-change case Phase 3 exists for.
	allow := []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}}
	f, prompt := promptFor(t, trace(fanoutRows("/items/*", 512, 3*time.Millisecond)...), allow, PatternFanOut)

	if f.Suggested != nil {
		t.Fatalf("test setup: fan-out should have no suggested route, got %+v", *f.Suggested)
	}
	for _, want := range []string{
		"GET /items/*", // the declared route, template form
		"511 more calls",
		"batch endpoint",
		"OpenAPI 3.1",
		"rationale",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestPromptOneTemplatePerRemedyClass(t *testing.T) {
	// Each remedy class must yield a distinct, non-empty, endpoint/behavior-shaped
	// prompt. Build a bare finding per class (Prompt reads only fields it interpolates).
	cases := []struct {
		remedy   RemedyClass
		wantTask string
	}{
		{RemedyBatch, "batch endpoint"},
		{RemedyAggregate, "aggregate"},
		{RemedyFilter, "filter or selection parameter"},
		{RemedyCache, "Cache-Control"},
		{RemedyParallel, "compound endpoint"},
	}
	seen := make(map[string]RemedyClass)
	for _, tc := range cases {
		f := Finding{
			Pattern: PatternFanOut, // pattern is not read by Prompt; remedy selects the template
			Method:  "GET",
			Route:   "/items/*",
			Remedy:  tc.remedy,
			Detail:  "one-sentence trusted summary.",
		}
		prompt, ok := Prompt(f, nil)
		if !ok {
			t.Fatalf("remedy %s produced no prompt", tc.remedy)
		}
		if !strings.Contains(prompt, tc.wantTask) {
			t.Errorf("remedy %s prompt missing task marker %q:\n%s", tc.remedy, tc.wantTask, prompt)
		}
		if prior, dup := seen[prompt]; dup {
			t.Errorf("remedy %s produced the same prompt as %s (templates not distinct)", tc.remedy, prior)
		}
		seen[prompt] = tc.remedy
		// The cache remedy is a headers change, not a new operation; the others are.
		if tc.remedy == RemedyCache {
			if !strings.Contains(prompt, "304 Not Modified") {
				t.Errorf("cache prompt should describe conditional requests:\n%s", prompt)
			}
		} else if !strings.Contains(prompt, "OpenAPI 3.1") {
			t.Errorf("remedy %s prompt should ask for an OpenAPI stub:\n%s", tc.remedy, prompt)
		}
	}
}

func TestPromptUnknownRemedyRefused(t *testing.T) {
	f := Finding{Method: "GET", Route: "/items/*", Remedy: RemedyClass("bogus"), Detail: "x"}
	if got, ok := Prompt(f, nil); ok || got != "" {
		t.Errorf("unknown remedy class must yield (\"\", false), got (%q, %v)", got, ok)
	}
}

// TestPromptNeverLeaksNonTemplateData is the redaction proof at the Phase 3 boundary:
// even when a hostile guest tries to smuggle a concrete id, body, or token, none can
// reach the prompt because none is present in the inputs Prompt reads. The trace holds
// only templates, and the Allow list is operator config.
func TestPromptNeverLeaksNonTemplateData(t *testing.T) {
	const (
		secretID   = "hunter2-4242"
		secretBody = "{\"ssn\":\"078-05-1120\"}"
		token      = "Bearer eyJhbGci"
	)
	// Aggregate-in-code: many distinct-row reads, no writes, a granted per-item route.
	allow := []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}}
	rows := fanoutRows("/items/*", 40, 20*time.Millisecond)
	_, prompt := promptFor(t, trace(rows...), allow, PatternAggregateInCode)

	for _, leak := range []string{secretID, secretBody, token, "078-05-1120", "eyJhbGci"} {
		if strings.Contains(prompt, leak) {
			t.Errorf("prompt leaked non-template data %q:\n%s", leak, prompt)
		}
	}
	// Positive: it names only the template and its verb, never a raw path.
	if !strings.Contains(prompt, "GET /items/*") {
		t.Errorf("prompt should ground itself in the route template:\n%s", prompt)
	}
	if strings.ContainsAny(prompt, "?#") {
		t.Errorf("prompt contains a query/fragment marker, so a raw path may have leaked:\n%s", prompt)
	}
}

func TestPromptListsAllDeclaredRoutesSorted(t *testing.T) {
	// The prompt grounds the AI in the full declared surface, deduped and sorted, so it
	// can design a change that does not collide with an existing route (the roadmap
	// example lists both the per-item and the collection route).
	allow := []sandbox.HostRoute{
		{Method: "get", Path: "/items"},   // lowercase verb -> normalized
		{Method: "GET", Path: "/items/*"}, //
		{Method: "GET", Path: "/items"},   // duplicate of the first -> collapsed
		{Method: "POST", Path: "/orders"}, //
	}
	f := Finding{Method: "GET", Route: "/items/*", Remedy: RemedyBatch, Detail: "x."}
	prompt, ok := Prompt(f, allow)
	if !ok {
		t.Fatal("Prompt refused a batch finding")
	}
	block := prompt[strings.Index(prompt, "  - "):]
	block = block[:strings.Index(block, "\n\nTask:")]
	want := "  - GET /items\n  - GET /items/*\n  - POST /orders"
	if block != want {
		t.Errorf("routes block =\n%q\nwant\n%q", block, want)
	}
}

func TestPromptDeterministic(t *testing.T) {
	allow := []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}, {Method: "GET", Path: "/rooms"}}
	build := func() Finding {
		f, _ := find(Analyze(trace(fanoutRows("/items/*", 60, time.Millisecond)...), allow), PatternFanOut)
		return f
	}
	a, _ := Prompt(build(), allow)
	b, _ := Prompt(build(), allow)
	if a != b {
		t.Errorf("Prompt is not deterministic:\n%q\nvs\n%q", a, b)
	}
}

func TestPromptFallsBackToFindingRouteWithoutAllowList(t *testing.T) {
	// Called with no Allow list, the routes block still names the finding's own
	// template so the AI has something concrete to design against.
	f := Finding{Method: "PUT", Route: "/v1/lights/*/on", Remedy: RemedyFilter, Detail: "x."}
	prompt, ok := Prompt(f, nil)
	if !ok {
		t.Fatal("Prompt refused a filter finding")
	}
	if !strings.Contains(prompt, "  - PUT /v1/lights/*/on") {
		t.Errorf("prompt should fall back to the finding's own route:\n%s", prompt)
	}
}
