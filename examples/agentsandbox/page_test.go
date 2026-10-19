package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	published = "../../docs/examples/agentsandbox"
	sbomPages = "../../docs/examples/sbom"
)

// The page is rendered from the files beside it, with no cluster, so the committed page
// must be exactly what this program writes from them.
func TestPublishedPageIsWhatTheFilesSay(t *testing.T) {
	got, err := render(published, sbomPages)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(published, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/examples/agentsandbox/index.html is not what the published files render; run go run ./examples/agentsandbox")
	}
	for _, s := range []string{"same results", "provider isolation container is below requested minimum kernel", "not gVisor&#39;s", "Linux version 6.6"} {
		if !strings.Contains(string(got), s) {
			t.Errorf("the page does not say %q", s)
		}
	}
}

// flipAfter changes the base64 character n places after the first marker.
func flipAfter(marker string, n int) func([]byte) []byte {
	return func(b []byte) []byte {
		out := bytes.Clone(b)
		i := bytes.Index(out, []byte(marker))
		if i < 0 {
			return out
		}
		at := i + len(marker) + n
		if out[at] == 'A' {
			out[at] = 'B'
		} else {
			out[at] = 'A'
		}
		return out
	}
}

// A bundle whose bytes changed, or a transcript file with a field the page does not
// know, is refused rather than rendered.
func TestRenderRefusesAlteredEvidence(t *testing.T) {
	for _, c := range []struct {
		name, file string
		edit       func([]byte) []byte
	}{
		{"one character of a stored response changed", "bundle.jsonl", flipAfter(`"response":"`, 40)},
		{"one character of the pre-fix response changed", "before-the-fix.jsonl", flipAfter(`"response":"`, 40)},
		{"an unknown field in the transcripts", "refusals.json", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"recorded"`), []byte(`"signed": true, "recorded"`), 1)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range []string{"bundle.jsonl", "harness.pub", "before-the-fix.jsonl", "refusals.json", "run-e25b11e37738.cdx.json", "run-4077fd7745e8.cdx.json"} {
				b, err := os.ReadFile(filepath.Join(published, f))
				if err != nil {
					t.Fatal(err)
				}
				if f == c.file {
					edited := c.edit(b)
					if bytes.Equal(edited, b) {
						t.Fatalf("the edit changed nothing in %s", f)
					}
					b = edited
				}
				if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := render(dir, sbomPages); err == nil {
				t.Fatal("rendered")
			}
		})
	}
}
