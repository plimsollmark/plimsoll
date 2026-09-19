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
	"dependencies.html",
	"integrations.html",
	"agent-products.html",
	"discoverability.html",
	"customer-examples.html",
	"brokering.html",
	"private-api.html",
	"advisor.html",
	"capacity-endpoint.html",
}

// The shape a catalog page is built in. Shape decides which structural checks apply,
// so a page that is deliberately different is one row of data here rather than an
// `if page == "..."` inside every test that walks the catalog.
//
//	plain       the default: one scrolling document on plain.css, with its own markup,
//	            its own <style> for what makes it itself, and its own script if it
//	            needs one
//	explorer    trainerData in "path-explorer" mode plus a page-local map, driven by
//	            architecture.mjs
//
// The chapter renderer (trainer.js) was the default until 2026-09-19; no catalog
// page uses it now. It still drives the private positioning page outside this
// directory, which is why it is not deleted.
var pageShape = map[string]string{
	"architecture.html": "explorer",
}

func shapeOf(page string) string {
	if shape, ok := pageShape[page]; ok {
		return shape
	}
	return "plain"
}

var trainerDataPattern = regexp.MustCompile(`(?s)<script id="trainerData" type="application/json">\s*(.*?)\s*</script>`)

type trainerDocument struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Tagline string `json:"tagline"`
	Mode    string `json:"mode"`
}

func TestTrainerDocuments(t *testing.T) {
	for _, name := range trainerPages {
		t.Run(name, func(t *testing.T) {
			raw := readFile(t, name)
			if shapeOf(name) == "plain" {
				checkPlainPage(t, name, raw)
				return
			}
			matches := trainerDataPattern.FindStringSubmatch(raw)
			if len(matches) != 2 {
				t.Fatal("missing exactly one embedded trainerData document")
			}
			var doc trainerDocument
			if err := json.Unmarshal([]byte(matches[1]), &doc); err != nil {
				t.Fatalf("parse trainerData: %v", err)
			}
			if doc.Mode != "path-explorer" {
				t.Fatalf("page is declared explorer in pageShape but its document mode is %q", doc.Mode)
			}
			if doc.ID == "" || doc.Title == "" || doc.Tagline == "" {
				t.Fatalf("incomplete trainer identity: %+v", doc)
			}
			for _, id := range []string{"architectureExplorer", "architectureMap", "pathCategories", "pathSelect", "providerSelect", "stepInspector", "nodeInspector", "stepTimeline"} {
				if !strings.Contains(raw, `id="`+id+`"`) {
					t.Fatalf("path explorer is missing shell element %q", id)
				}
			}
		})
	}
}

// checkPlainPage holds a "plain" page to what that shape promises: it stands on the
// shared plain base rather than the lesson renderer, and it does not quietly grow back
// into a chapter lesson. The two shapes that break a phone (a fixed rail, a
// viewport-width box that overflows once a scrollbar exists) are refused in the page's
// own markup and styles; the base's mobile-first promise is checked once, in
// TestPlainBaseIsMobileFirst.
func checkPlainPage(t *testing.T, name, raw string) {
	t.Helper()
	if strings.Contains(raw, "trainerData") || strings.Contains(raw, `src="trainer.js"`) {
		t.Error("a plain page carries no trainerData and loads no renderer; " +
			"if this page is a lesson again, move it out of pageShape")
	}
	if !strings.Contains(raw, `content="width=device-width, initial-scale=1"`) {
		t.Error("missing the responsive viewport declaration")
	}
	if !strings.Contains(raw, `href="index.html"`) {
		t.Error("no way back to the catalog")
	}
	if got := strings.Count(raw, "<h1"); got != 1 {
		t.Errorf("found %d <h1> elements, want exactly 1", got)
	}
	for _, phoneHostile := range []string{"position: fixed", "position:fixed", "100vw"} {
		if strings.Contains(raw, phoneHostile) {
			t.Errorf("uses %q, which is what makes a page awkward on a phone", phoneHostile)
		}
	}
}

// TestPlainBaseIsMobileFirst checks the one stylesheet every plain page shares. The
// narrow layout has to be the base and the wide one the enhancement, so a min-width
// media query is required and a max-width one is refused; nothing in it may pin an
// element to the viewport.
func TestPlainBaseIsMobileFirst(t *testing.T) {
	css := readFile(t, "plain.css")
	if !strings.Contains(css, "@media (min-width:") {
		t.Error("plain.css has no min-width media query, so the wide layout is not an enhancement")
	}
	if strings.Contains(css, "@media (max-width:") {
		t.Error("plain.css has a max-width media query, which makes the wide layout the base")
	}
	if strings.Contains(css, "prefers-color-scheme") {
		t.Error("plain.css reacts to the system colour scheme; the pages are light only")
	}
	for _, phoneHostile := range []string{"position: fixed", "position:fixed", "100vw"} {
		if strings.Contains(css, phoneHostile) {
			t.Errorf("plain.css uses %q, which is what makes a page awkward on a phone", phoneHostile)
		}
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

// countWords carries only the numbers a plausible catalog can hold; an unlisted
// count fails the test rather than letting the prose and the cards drift apart.
var countWords = map[int]string{
	12: "Twelve", 13: "Thirteen", 14: "Fourteen", 15: "Fifteen", 16: "Sixteen",
	17: "Seventeen", 18: "Eighteen", 19: "Nineteen", 20: "Twenty",
}

// The catalog and the site home both state the trainer count in words. A trainer
// added without touching that sentence leaves a number a reader can count and
// find wrong, which is what this test is for.
func TestStatedTrainerCountMatchesTheCards(t *testing.T) {
	catalog := readFile(t, "index.html")
	if cards := strings.Count(catalog, `class="catalog-card"`); cards != len(trainerPages) {
		t.Errorf("catalog shows %d cards for %d trainers", cards, len(trainerPages))
	}
	word, ok := countWords[len(trainerPages)]
	if !ok {
		t.Fatalf("no English word listed for %d trainers", len(trainerPages))
	}
	if !strings.Contains(catalog, word+" compact trainers") {
		t.Errorf("the catalog does not state the trainer count as %q", word+" compact trainers")
	}
	// The site home states the count too, but only the private one: the public landing
	// page is written by scripts/export-public.sh and states no count at all, so this
	// checks the sentence where it exists rather than demanding it exist.
	if home := readFile(t, "../index.html"); strings.Contains(home, "compact trainers") &&
		!strings.Contains(home, word+" compact trainers") {
		t.Errorf("the site home states a trainer count other than %q", word+" compact trainers")
	}
	// The README counts them too, in the words it uses on the front page. It said
	// "eighteen" over sixteen pages until 2026-09-18, which is the drift this catches.
	if readme := readFile(t, "../../README.md"); strings.Contains(readme, "interactive lessons") &&
		!strings.Contains(readme, word+" interactive lessons") {
		t.Errorf("the README states a lesson count other than %q", word+" interactive lessons")
	}
}

// The catalog promotes the physics-oracle run report above the lessons: it is
// evidence from a real run, not a trainer, so it is linked rather than listed as
// a card. The target is checked on disk, so a moved page fails here.
func TestCatalogPromotesTheOracleRunReport(t *testing.T) {
	const href = "../examples/oracle/index.html"
	catalog := readFile(t, "index.html")
	if !strings.Contains(catalog, `href="`+href+`"`) {
		t.Fatalf("catalog does not link the oracle run report at %s", href)
	}
	if strings.Index(catalog, href) > strings.Index(catalog, `href="plain-english.html"`) {
		t.Error("the oracle run report is linked below the first trainer card, not near the top")
	}
	if _, err := os.Stat(href); err != nil {
		t.Errorf("the linked oracle run report is missing: %v", err)
	}
	if !strings.Contains(readFile(t, "../index.html"), `href="examples/oracle/index.html"`) {
		t.Error("the site home does not link the oracle run report")
	}
}

func TestSharedAssetsAreLocal(t *testing.T) {
	for _, page := range trainerPages {
		raw := readFile(t, page)
		switch shapeOf(page) {
		case "explorer":
			for _, asset := range []string{"architecture.css", "architecture.mjs", "architecture-model.mjs"} {
				if info, err := os.Stat(asset); err != nil || info.Size() == 0 {
					t.Errorf("path explorer asset %s is missing or empty: %v", asset, err)
				}
			}
			if !strings.Contains(raw, `href="architecture.css"`) || !strings.Contains(raw, `src="architecture.mjs"`) {
				t.Error("architecture explorer does not load its local assets")
			}
		case "plain":
			// A plain page stands on plain.css, the base the plain pages share, and
			// must not reach for the lesson stylesheet: inheriting the lesson shell is
			// exactly what the shape exists not to do.
			if strings.Contains(raw, `href="trainer.css"`) {
				t.Errorf("%s is declared plain but loads the shared lesson stylesheet", page)
			}
			if !strings.Contains(raw, `href="plain.css"`) {
				t.Errorf("%s is declared plain but does not load plain.css", page)
			}
		}
	}
	// trainer.css and trainer.js still serve the catalog, the quick start, the demo
	// page and the private positioning page.
	for _, asset := range []string{"trainer.css", "trainer.js", "plain.css"} {
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
		// export (see private/public-export-plan.md), so it is checked wherever it exists
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
	// The Flight Recorder names Hono, the example gateway's HTTP framework, and a
	// reader who has never heard of it needs the link to say where it goes.
	private := readFile(t, "private-api.html")
	for _, marker := range []string{"Hono", "https://hono.dev/docs", "External · official docs ↗"} {
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
