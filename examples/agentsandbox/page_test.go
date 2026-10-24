package main

import (
	"bytes"
	"io/fs"
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
	for _, s := range []string{"same results", "Same request, 4 rooms", "provider isolation container is below requested minimum kernel", "not gVisor&#39;s", "Linux version 6.6",
		`id="kata"`, "<code>kata-clh-runtime-rs</code>", "two kernels", "Linux version 6.18.35", "nested virtualization on a laptop", "never runtime attestation"} {
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

// replace changes the first old to new.
func replace(old, new string) func([]byte) []byte {
	return func(b []byte) []byte { return bytes.Replace(b, []byte(old), []byte(new), 1) }
}

// A bundle whose bytes changed, a transcript file with a field the page does not know, or a
// room list that disagrees with the signed runs is refused rather than rendered.
func TestRenderRefusesAlteredEvidence(t *testing.T) {
	for _, c := range []struct {
		name, file string
		edit       func([]byte) []byte
	}{
		{"one character of a stored response changed", "bundle.jsonl", flipAfter(`"response":"`, 40)},
		{"one character of a Kata room response changed", "kata/bundle.jsonl", flipAfter(`"response":"`, 40)},
		{"one character of the pod check's response changed", "kata/kernel.jsonl", flipAfter(`"response":"`, 40)},
		{"one character of the pre-fix transcript changed", "before-the-fix.jsonl", flipAfter(`"response":"`, 40)},
		{"an unknown field in the transcripts", "refusals.json", replace(`"recorded"`, `"signed": true, "recorded"`)},
		{"an unknown field in the room list", "rooms.json", replace(`"rooms"`, `"signed": true, "rooms"`)},
		{"the node's boot ID made the guest's", "rooms.json", replace("2c96a215-a66a-4657-9304-92279b9201e3", "d8776183-1e63-42c1-b396-fed1f8f370db")},
		{"the Kata room said to be the kernel tier", "rooms.json", replace(`"tier": "vm",
      "bundle": "kata/bundle.jsonl"`, `"tier": "kernel",
      "bundle": "kata/bundle.jsonl"`)},
		{"a room of the CycloneDX example left out", "rooms.json", replace(`,
    {
      "id": "dockercloud",
      "label": "a Docker Cloud microVM",
      "tier": "vm",
      "provider": "dockercloud"
    }`, "")},
		{"a room's bundle outside the page", "rooms.json", replace(`"bundle": "kata/bundle.jsonl"`, `"bundle": "../sbom/bundle.jsonl"`)},
		{"a recorded room naming a provider", "rooms.json", replace(`"handler": "kata-clh-runtime-rs",`, `"handler": "kata-clh-runtime-rs", "provider": "docker",`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			edited := false
			err := filepath.WalkDir(published, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() || d.Name() == "index.html" {
					return err
				}
				rel, err := filepath.Rel(published, p)
				if err != nil {
					return err
				}
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				if filepath.ToSlash(rel) == c.file {
					changed := c.edit(b)
					if bytes.Equal(changed, b) {
						t.Fatalf("the edit changed nothing in %s", c.file)
					}
					b, edited = changed, true
				}
				if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(rel)), 0o755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(dir, rel), b, 0o644)
			})
			if err != nil {
				t.Fatal(err)
			}
			if !edited {
				t.Fatalf("no published file %s", c.file)
			}
			if _, err := render(dir, sbomPages); err == nil {
				t.Fatal("rendered")
			} else {
				t.Log(err)
			}
		})
	}
}
