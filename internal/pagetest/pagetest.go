// Package pagetest checks an example's committed page against the template its run
// writes it from. The page is written by a run that needs docker, but the artifact
// people read is the committed docs/examples/<name>/index.html, so prose edited in one
// and not the other is drift: every literal run of the template (the text between its
// {{actions}}, which Execute copies through untouched) must appear in the committed
// page, in the template's order. It says nothing about the numbers, which only a real
// run can produce. Only tests import it.
package pagetest

import (
	"os"
	"strings"
	"testing"
)

// CarriesTemplate fails t unless the committed page at path carries every literal run
// of tmpl, in the template's order; regenerate is the command that rewrites the page,
// which the failure names beside the text the page lacks.
func CarriesTemplate(t testing.TB, tmpl, path, regenerate string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if missing, ok := Missing(tmpl, string(raw)); !ok {
		t.Fatalf("the committed page does not carry this template text "+
			"(edit both, or regenerate with `%s`):\n%s", regenerate, missing)
	}
}

// Missing reports whether page carries every literal run of tmpl in order (ok), and
// when it does not, the text to show for the first run it lacks: the first line of
// that run the page holds nowhere, so the failure names the edited sentence rather
// than the whole block it sits in, or the run itself when every line is present on
// its own, which means the order changed rather than the text. That text is put on
// one line and cut at 160 characters.
func Missing(tmpl, page string) (excerpt string, ok bool) {
	at := 0
	for _, run := range Literals(tmpl) {
		i := strings.Index(page[at:], run)
		if i < 0 {
			return shorten(firstMissingLine(run, page)), false
		}
		at += i + len(run)
	}
	return "", true
}

// Literals returns the parts of the template that Execute copies through untouched:
// the text between {{actions}}, each part that is not only white space.
func Literals(tmpl string) []string {
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

func firstMissingLine(run, page string) string {
	for _, line := range strings.Split(run, "\n") {
		if strings.TrimSpace(line) != "" && !strings.Contains(page, line) {
			return line
		}
	}
	return run
}

func shorten(run string) string {
	line := strings.TrimSpace(strings.ReplaceAll(run, "\n", " "))
	if len(line) > 160 {
		line = line[:160] + "…"
	}
	return line
}
