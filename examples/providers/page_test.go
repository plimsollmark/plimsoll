package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The committed page is written by a run that needs docker and live providers; this
// test catches the drift that needs neither: every fixed sentence of the template
// must appear in the committed page, in order. The numbers only a real run produces.
func TestCommittedPageCarriesItsTemplateText(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "providers", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	page, at := string(raw), 0
	for _, s := range []string{
		"<h1>Same run, different sandboxes: one fingerprint on every provider</h1>",
		"Switching is one setting, <code>SANDBOX_PROVIDER</code>",
		"<h3>Why the numbers agree</h3>",
		"<h2>What this does not show</h2>",
		"A reported isolation tier is configuration plus behavioral tests, never hardware attestation.",
		"go run ./examples/providers",
	} {
		i := strings.Index(page[at:], s)
		if i < 0 {
			t.Fatalf("the committed page does not carry %q (edit both, or regenerate with go run ./examples/providers)", s)
		}
		at += i + len(s)
	}
	if !strings.Contains(page, publishedFingerprint) {
		t.Fatal("the committed page does not name the oracle's published fingerprint")
	}
}
