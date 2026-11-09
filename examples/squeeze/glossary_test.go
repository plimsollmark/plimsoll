package main

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var anyDfnRE = regexp.MustCompile(`<dfn[\s>][^>]*>?`)

// Every underlined term in a template names a glossary entry that exists, so the render can give
// it a definition. This reads the templates, which is where a new term is first written.
func TestEveryDfnNamesAGlossaryEntry(t *testing.T) {
	defs, err := loadGlossary()
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"page.html": pageTemplate, "staged.html": stagedTemplate, "method.html": methodTemplate} {
		for _, tag := range anyDfnRE.FindAllString(text, -1) {
			m := regexp.MustCompile(`data-gloss="([a-z0-9-]+)"`).FindStringSubmatch(tag)
			if m == nil {
				t.Errorf("%s: %s names no glossary entry", name, tag)
				continue
			}
			if defs[m[1]] == "" {
				t.Errorf("%s: <dfn data-gloss=%q> has no entry in %s; add the term to docs/trainers/terms.json and run go test ./docs/trainers -run TestGeneratedBlocks -update", name, m[1], glossaryRelPath)
			}
		}
	}
}

// The published pages carry each term's definition from the glossary, word for word.
func TestPublishedDfnsCarryTheirDefinition(t *testing.T) {
	defs, err := loadGlossary()
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"../../docs/examples/squeeze", "../../docs/examples/squeeze-recipe"} {
		raw, err := os.ReadFile(filepath.Join(dir, "index.html"))
		if err != nil {
			t.Fatal(err)
		}
		page := string(raw)
		tags := anyDfnRE.FindAllString(page, -1)
		if len(tags) == 0 {
			t.Fatalf("%s has no underlined terms; this test would pass vacuously", dir)
		}
		for _, tag := range tags {
			id := regexp.MustCompile(`data-gloss="([a-z0-9-]+)"`).FindStringSubmatch(tag)
			def := regexp.MustCompile(`data-def="([^"]*)"`).FindStringSubmatch(tag)
			href := regexp.MustCompile(`data-href="([^"]*)"`).FindStringSubmatch(tag)
			if id == nil || def == nil || href == nil {
				t.Errorf("%s: %s lacks its definition; run the render command in the failure message of TestPublishedFilesVerify or TestStagedPagePublishedVerifies", dir, tag)
				continue
			}
			if got := html.UnescapeString(def[1]); got != defs[id[1]] {
				t.Errorf("%s: %q says %q, the glossary says %q", dir, id[1], got, defs[id[1]])
			}
			if href[1] != "../../trainers/glossary.html#"+id[1] {
				t.Errorf("%s: %q links to %q", dir, id[1], href[1])
			}
		}
		if !strings.Contains(page, `id="gloss-pop"`) {
			t.Errorf("%s has underlined terms and no popup", dir)
		}
	}
}

// A render refuses an underlined term with no definition behind it.
func TestRenderRefusesADfnWithoutDefinition(t *testing.T) {
	defs := map[string]string{"seed": "One number that decides a random choice."}
	ok, err := applyGlossaryWith([]byte(`<body><dfn data-gloss="seed">seed</dfn></body>`), defs)
	if err != nil || !strings.Contains(string(ok), `data-def="One number that decides a random choice."`) {
		t.Fatalf("a defined term: %v\n%s", err, ok)
	}
	for name, page := range map[string]string{
		"unnamed":  `<body><dfn>seed</dfn></body>`,
		"missing":  `<body><dfn data-gloss="resampling">resampling</dfn></body>`,
		"mixed in": `<body><dfn data-gloss="seed">a</dfn><dfn>b</dfn></body>`,
	} {
		if _, err := applyGlossaryWith([]byte(page), defs); err == nil {
			t.Errorf("%s: rendered anyway", name)
		}
	}
}
