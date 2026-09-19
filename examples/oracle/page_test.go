package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The page is written from page.html by a run that needs docker, but the artifact
// people read is the committed docs/examples/oracle/index.html. Editing the prose in
// one and not the other is the drift this test exists to catch: every literal run of
// the template must appear in the committed page, in the template's order. It says
// nothing about the numbers, which only a real run can produce.
func TestCommittedPageCarriesEveryLineOfItsTemplate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "oracle", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	page, at := string(raw), 0
	for _, run := range templateLiterals(pageTemplate) {
		i := strings.Index(page[at:], run)
		if i < 0 {
			t.Fatalf("the committed page does not carry this template text "+
				"(edit both, or regenerate with `go run ./examples/oracle`):\n%s", excerpt(firstMissingLine(run, page)))
		}
		at += i + len(run)
	}
}

// templateLiterals returns the parts of the template that Execute copies through
// untouched: the text between {{actions}}, which must survive verbatim into the page.
func templateLiterals(tmpl string) []string {
	var literals []string
	for i, part := range strings.Split(tmpl, "{{") {
		if i > 0 {
			end := strings.Index(part, "}}")
			if end < 0 {
				continue // an unterminated action; Parse would have failed first
			}
			part = part[end+2:]
		}
		if strings.TrimSpace(part) != "" {
			literals = append(literals, part)
		}
	}
	return literals
}

// firstMissingLine narrows a missing literal run to the first of its lines the page
// does not contain anywhere, so the failure names the edited sentence rather than the
// whole block it sits in. It falls back to the run itself when every line is present
// individually, which means the order changed rather than the text.
func firstMissingLine(run, page string) string {
	for _, line := range strings.Split(run, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.Contains(page, line) {
			return line
		}
	}
	return run
}

func excerpt(run string) string {
	line := strings.TrimSpace(strings.ReplaceAll(run, "\n", " "))
	if len(line) > 160 {
		line = line[:160] + "…"
	}
	return line
}
