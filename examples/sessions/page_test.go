package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The committed page is written by a run that needs an OpenShell gateway; this
// test catches the drift that needs none: every fixed sentence of the template
// must appear in the committed page, in order, and the bundle and key it points
// to must be beside it.
func TestCommittedPageCarriesItsTemplateText(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "examples", "sessions")
	raw, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	page, at := string(raw), 0
	for _, s := range []string{
		"<h1>One sandbox, five calls: an OpenShell session with a signed chain of records</h1>",
		"<h2>The calls</h2>",
		"<h2>The chain</h2>",
		"<h2>The verifier</h2>",
		"<h2>What happens around each call</h2>",
		"<h2>What this does not show</h2>",
		"go run ./examples/sessions",
	} {
		i := strings.Index(page[at:], s)
		if i < 0 {
			t.Fatalf("the committed page does not carry %q (edit both, or regenerate with go run ./examples/sessions)", s)
		}
		at += i + len(s)
	}
	for _, f := range []string{"bundle.jsonl", "harness.pub"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("the page links %s: %v", f, err)
		}
	}
}
