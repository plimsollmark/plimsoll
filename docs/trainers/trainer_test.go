package trainers

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

var trainerPages = []string{
	"plain-english.html",
	"concepts.html",
	"architecture.html",
	"providers.html",
	"capabilities.html",
	"operations.html",
	"dependencies.html",
	"integrations.html",
	"agent-products.html",
	"discoverability.html",
	"customer-examples.html",
	"brokering.html",
	"private-api.html",
	"advisor.html",
	"capacity-endpoint.html",
	"two-entry-points.html",
}

var trainerDataPattern = regexp.MustCompile(`(?s)<script id="trainerData" type="application/json">\s*(.*?)\s*</script>`)

type trainerDocument struct {
	ID       string           `json:"id"`
	Title    string           `json:"title"`
	Tagline  string           `json:"tagline"`
	Mode     string           `json:"mode"`
	Chapters []trainerChapter `json:"chapters"`
}

type trainerChapter struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	Lede      string `json:"lede"`
	Explainer struct {
		Try  string `json:"try"`
		Idea string `json:"idea"`
	} `json:"explainer"`
}

func TestTrainerDocuments(t *testing.T) {
	supported := map[string]bool{
		"scenario": true, "quiz": true, "pipeline": true, "matrix": true,
		"budget": true, "checklist": true, "sim": true,
	}
	seenTrainerIDs := map[string]bool{}
	for _, name := range trainerPages {
		t.Run(name, func(t *testing.T) {
			raw := readFile(t, name)
			matches := trainerDataPattern.FindStringSubmatch(raw)
			if len(matches) != 2 {
				t.Fatal("missing exactly one embedded trainerData document")
			}
			var doc trainerDocument
			if err := json.Unmarshal([]byte(matches[1]), &doc); err != nil {
				t.Fatalf("parse trainerData: %v", err)
			}
			if doc.ID == "" || doc.Title == "" || doc.Tagline == "" {
				t.Fatalf("incomplete trainer identity: %+v", doc)
			}
			if seenTrainerIDs[doc.ID] {
				t.Fatalf("duplicate trainer id %q", doc.ID)
			}
			seenTrainerIDs[doc.ID] = true
			if doc.Mode == "experience" {
				if !strings.Contains(raw, `id="experienceApp"`) || !strings.Contains(raw, `id="processGraph"`) || !strings.Contains(raw, `id="traceTimeline"`) {
					t.Fatal("experience trainer is missing its process graph shell")
				}
				return
			}
			for _, id := range []string{"trainerTitle", "trainerTagline", "chapters", "stage", "lessonControls", "explainer", "prevChapter", "nextChapter", "progressDots"} {
				if !strings.Contains(raw, `id="`+id+`"`) {
					t.Fatalf("missing shell element %q", id)
				}
			}
			// A floor, not an exact count. This asserted `== 6` until 2026-09-10, which
			// caught a stub trainer (the thing worth catching) but also made the course
			// unable to learn anything new: a lesson could only gain a chapter by losing
			// one, so the test was deciding editorial questions it has no view on.
			// Every trainer still holds at least six, so nothing has been weakened.
			if len(doc.Chapters) < 6 {
				t.Fatalf("chapter count = %d, want at least 6 (a trainer this short is a stub)", len(doc.Chapters))
			}
			seenChapters := map[string]bool{}
			for i, chapter := range doc.Chapters {
				if chapter.ID == "" || chapter.Label == "" || chapter.Title == "" || chapter.Lede == "" || chapter.Explainer.Try == "" || chapter.Explainer.Idea == "" {
					t.Fatalf("chapter %d is missing required teaching copy: %+v", i, chapter)
				}
				if !supported[chapter.Kind] {
					t.Fatalf("chapter %q has unsupported kind %q", chapter.ID, chapter.Kind)
				}
				if seenChapters[chapter.ID] {
					t.Fatalf("duplicate chapter id %q", chapter.ID)
				}
				seenChapters[chapter.ID] = true
			}
		})
	}
}

func TestPrivateAPIFlightRecorderNamesTheRealBoundary(t *testing.T) {
	raw := readFile(t, "private-api.html") + readFile(t, "private-api.js")
	for _, fact := range []string{
		"LLM model", "MCP client / host", "Stockroom gateway", "Stockroom dataplane",
		"plimsoll / plimsolld", "Guest JavaScript", "Gateway REST route", "WMS / ERP",
		"POST /mcp", "tools/list", "tools/call", "run_javascript", "inventory.warehouses.list()",
		"stockroom://sandbox-api.d.ts", "GET /v1/warehouses", "Connect/gRPC", "vendor HTTP(S)", "CodegenService", "StockService",
		"RunJavaScriptV2",
		// The lesson teaches a real boundary through an invented company, so the
		// sentence that says so is load-bearing: without it the page reads as a
		// walkthrough of somebody's actual production system.
		"Stockroom is a worked example, not a product.",
		"the isolated process that runs the model-authored JavaScript", "themeToggle", "Light mode",
		"process-workbench", "ownership-legend", "Protocol decoder", "MCP over HTTP", "MCP over stdio",
		"StdioServerTransport", "application/grpc+proto", "host-api.sock", "Learn more:", "Further reading",
		"EXTERNAL · official docs ↗", "INTERNAL · trainer site →", "Hono",
		"https://modelcontextprotocol.io/specification", "https://www.jsonrpc.org/specification",
		"https://ts.sdk.modelcontextprotocol.io/server", "https://connectrpc.com/",
		"https://grpc.io/docs/what-is-grpc", "https://protobuf.dev/overview/",
	} {
		if !strings.Contains(raw, fact) {
			t.Errorf("private API flight recorder lost process-graph fact %q", fact)
		}
	}
	for _, forbidden := range []string{
		// "../../../" is any link that escapes docs/ entirely, which is how the
		// earlier version of this page sent readers into a sibling repository's
		// source tree. Matching the shape rather than one path also keeps a private
		// directory name out of a test that ships publicly (2026-09-10 review).
		"Open the defining source file", "../../../", "../../sandbox/", "source-section", "source-grid",
	} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("private API flight recorder still exposes repository source navigation %q", forbidden)
		}
	}
}

func TestPrivateAPIFlightRecorderKeepsTheLessonEvidenceBounded(t *testing.T) {
	html := readFile(t, "private-api.html")
	css := readFile(t, "private-api.css")
	js := readFile(t, "private-api.js")
	raw := html + css + js

	for _, fact := range []string{
		"static lesson · no live telemetry",
		"contract-check", "Which of these is the MCP tool?", "data-contract-answer=\"correct\"",
		"data-runtime-choice", "data-provider-choice", "probe-controls",
		"prefers-reduced-motion", "event.target.closest",
	} {
		if !strings.Contains(raw, fact) {
			t.Errorf("private API trainer lost bounded lesson contract %q", fact)
		}
	}
	if got := strings.Count(html, `data-contract-answer="correct"`); got != 1 {
		t.Errorf("contract check has %d correct answers, want exactly 1", got)
	}
	for _, forbidden := range []string{
		"flight recorder · last run", "t+000ms", "t+004ms", "tapeReadout", "rollTape",
		"hopTally", "20 round trips", "orbit-caption", "recorderBadge",
	} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("private API trainer still contains unsupported or duplicate interaction %q", forbidden)
		}
	}
	if !strings.Contains(css, ".flight-recorder { width: min(1440px, 100%); margin: 0 auto; padding: 0 38px 46px; overflow: visible; }") {
		t.Error("flight recorder still clips content at its outer container")
	}
	if strings.Contains(css, ".tape-readout") {
		t.Error("flight recorder still has a competing fixed tape panel")
	}
}

func TestCatalogLinksEveryTrainer(t *testing.T) {
	catalog := readFile(t, "index.html")
	for _, page := range trainerPages {
		if !strings.Contains(catalog, `href="`+page+`"`) {
			t.Errorf("catalog does not link %s", page)
		}
	}
}

func TestTrainerSecurityClaimsStayFailClosed(t *testing.T) {
	providers := readFile(t, "providers.html")
	for _, claim := range []string{
		"runc shares the host kernel and reports container tier",
		"Docker supports both operations, WASM supports snippets, and E2B requires its configured guard for both.",
	} {
		if !strings.Contains(providers, claim) {
			t.Errorf("providers trainer lost security claim %q", claim)
		}
	}
	operations := readFile(t, "operations.html")
	if !strings.Contains(operations, "Docker or WASM JavaScript grant profile") {
		t.Error("operations trainer lost provider-neutral grant smoke-test guidance")
	}
	advisor := readFile(t, "advisor.html")
	for _, claim := range []string{`"status","value":"shipped"`, "128 tiny calls", "route template + timing"} {
		if !strings.Contains(advisor, claim) {
			t.Errorf("advisor trainer lost shipped/bounded claim %q", claim)
		}
	}
	capacity := readFile(t, "capacity-endpoint.html")
	for _, claim := range []string{`"status","value":"shipped"`, "one elected caller per second", "x-plimsoll-health-check"} {
		if !strings.Contains(capacity, claim) {
			t.Errorf("capacity trainer lost backpressure/specgen claim %q", claim)
		}
	}
}

func TestSharedAssetsAreLocal(t *testing.T) {
	for _, page := range trainerPages {
		raw := readFile(t, page)
		if page == "private-api.html" {
			if !strings.Contains(raw, `href="trainer.css"`) || !strings.Contains(raw, `href="private-api.css"`) || !strings.Contains(raw, `src="private-api.js"`) {
				t.Errorf("%s does not use its local experience assets", page)
			}
			continue
		}
		if !strings.Contains(raw, `href="trainer.css"`) || !strings.Contains(raw, `src="trainer.js"`) {
			t.Errorf("%s does not use local shared assets", page)
		}
	}
	for _, asset := range []string{"trainer.css", "trainer.js"} {
		if info, err := os.Stat(asset); err != nil || info.Size() == 0 {
			t.Errorf("asset %s is missing or empty: %v", asset, err)
		}
	}
}

func TestReferenceLinksLabelTheirDestination(t *testing.T) {
	shared := readFile(t, "trainer.js") + readFile(t, "trainer.css")
	for _, marker := range []string{
		"Definitions and references", "INTERNAL · trainer site →", "EXTERNAL · official docs ↗",
		"https://hono.dev/docs", "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports",
		"https://www.jsonrpc.org/specification", "https://connectrpc.com/", "https://gvisor.dev/docs/",
	} {
		if !strings.Contains(shared, marker) {
			t.Errorf("shared trainer reference shelf lost %q", marker)
		}
	}
	for _, page := range []string{"demo.html", "quick-start.html"} {
		// demo.html drives the commercial hosted demo and is excluded from the public
		// export (see docs/public-export-plan.md), so it is checked wherever it exists
		// and skipped where it does not. quick-start.html ships everywhere, so a
		// missing one is a real failure rather than a different repository.
		raw, err := os.ReadFile(page)
		if os.IsNotExist(err) && page == "demo.html" {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{"customer-reference-shelf", "INTERNAL · trainer site →", "EXTERNAL · official docs ↗", "https://hono.dev/docs"} {
			if !strings.Contains(string(raw), marker) {
				t.Errorf("%s lost labeled reference link %q", page, marker)
			}
		}
	}
	private := readFile(t, "private-api.html") + readFile(t, "private-api.js")
	for _, marker := range []string{"external-reference", "Hono", "https://hono.dev/docs"} {
		if !strings.Contains(private, marker) {
			t.Errorf("private API trainer lost Hono reference %q", marker)
		}
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
