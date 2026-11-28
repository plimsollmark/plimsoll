package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func sha256Hex(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}

// A set written by hand, as an operator does it with sha256sum: the harness file's digest
// as written (it ends in a newline, as nearly every text file does), and three seeds, one
// hashed as the scan hashes a value, one with echo (whose newline is part of the digest),
// one in capitals. The file entry finds the file shipped byte for byte (it found nothing
// before the scan matched digests as written); check lists the two seeds no call can ever
// match and the file entry taken as written, and passes a set the builder wrote from the
// same material.
func TestCheckListsHandEntriesThatNeverMatch(t *testing.T) {
	dir := t.TempDir()
	sim := "import numpy as np\n\ndef step(state, u, dt):  \n    return state + dt * (u - 0.3 * state)\n"
	write(t, filepath.Join(dir, "harness", "sim.py"), sim)
	write(t, filepath.Join(dir, "seeds.txt"), "731904\n552018\nKESTREL-42\n")
	hand := map[string]any{"version": 2, "mode": "refuse", "entries": []map[string]any{
		{"kind": "file", "sha256": sha256Hex(sim), "label": "harness/sim.py"},
		{"kind": "value", "sha256": sha256Hex("731904"), "length": 6, "label": "seeds.txt:1"},
		{"kind": "value", "sha256": sha256Hex("552018\n"), "length": 7, "label": "seeds.txt:2"},
		{"kind": "value", "sha256": sha256Hex("KESTREL-42"), "length": 10, "label": "seeds.txt:3"},
	}}
	raw, err := json.Marshal(hand)
	if err != nil {
		t.Fatal(err)
	}
	handPath := filepath.Join(dir, "hand.json")
	write(t, handPath, string(raw))

	task := filepath.Join(dir, "task")
	write(t, filepath.Join(task, "helpers", "model.py"), sim)
	var out bytes.Buffer
	if code, err := run([]string{"scan", "-set", handPath, task}, &out, io.Discard); err != nil || code != 1 || !strings.Contains(out.String(), "harness/sim.py (refuse)") {
		t.Fatalf("scan of the harness file shipped byte for byte against its sha256sum entry: %d, %v, %q", code, err, out.String())
	}

	out.Reset()
	code, err := run([]string{"check", "-set", handPath, filepath.Join(dir, "harness"), filepath.Join(dir, "seeds.txt")}, &out, io.Discard)
	if err != nil || code != 1 {
		t.Fatalf("check of a hand set with two dead entries: %d, %v, %q", code, err, out.String())
	}
	for _, want := range []string{"never found: seeds.txt:2 (refuse)", "never found: seeds.txt:3 (refuse)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("check output lacks %q: %q", want, out.String())
		}
	}
	for _, alive := range []string{"harness/sim.py", "seeds.txt:1"} {
		if strings.Contains(out.String(), "never found: "+alive+" ") {
			t.Errorf("check lists %s as never found, which matches: %q", alive, out.String())
		}
	}
	// The file entry finds its file, but as written only (TestCheckNamesAFileEntryHashedAsWritten).
	if !strings.Contains(out.String(), "as written: harness/sim.py (refuse)") {
		t.Errorf("check does not name the file entry taken as written: %q", out.String())
	}

	var built bytes.Buffer
	if code, err := run([]string{"build", "-mode", "refuse", "-file", filepath.Join(dir, "harness"), "-values", filepath.Join(dir, "seeds.txt")}, &built, io.Discard); err != nil || code != 0 {
		t.Fatalf("build: %d, %v", code, err)
	}
	builtPath := filepath.Join(dir, "built.json")
	write(t, builtPath, built.String())
	out.Reset()
	if code, err := run([]string{"check", "-set", builtPath, filepath.Join(dir, "harness"), filepath.Join(dir, "seeds.txt")}, &out, io.Discard); err != nil || code != 0 ||
		!strings.HasPrefix(out.String(), "every entry found: 4 entries in 2 files") {
		t.Fatalf("check of the builder's set: %d, %v, %q", code, err, out.String())
	}
	if code, err := run([]string{"check", "-set", builtPath}, io.Discard, io.Discard); err == nil || code != 2 {
		t.Errorf("check with no PATH: %d, %v", code, err)
	}
}

// A file entry taken with sha256sum finds only the copy it was taken of: the same file
// with Windows line endings, trailing whitespace or no final newline passes it, where the
// builder's entry finds all of them. The daemon cannot tell the two kinds apart (a digest
// says nothing of what was hashed), so check, which has the file, names such an entry and
// fails; the builder's entry for the same file passes.
func TestCheckNamesAFileEntryHashedAsWritten(t *testing.T) {
	dir := t.TempDir()
	sim := "import numpy as np\n\ndef step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n"
	write(t, filepath.Join(dir, "harness", "sim.py"), sim)
	raw, err := json.Marshal(map[string]any{"version": 2, "mode": "refuse", "entries": []map[string]any{
		{"kind": "file", "sha256": sha256Hex(sim), "label": "harness/sim.py"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	handPath := filepath.Join(dir, "hand.json")
	write(t, handPath, string(raw))
	var out bytes.Buffer
	code, err := run([]string{"check", "-set", handPath, filepath.Join(dir, "harness")}, &out, io.Discard)
	if err != nil || code != 1 || !strings.Contains(out.String(), "as written: harness/sim.py (refuse)") {
		t.Fatalf("check of a file entry taken with sha256sum: %d, %v, %q; want it named, exit 1", code, err, out.String())
	}
	if strings.Contains(out.String(), "never found:") {
		t.Errorf("check calls an entry that finds its own file never found: %q", out.String())
	}

	var built bytes.Buffer
	if code, err := run([]string{"build", "-mode", "refuse", "-file", filepath.Join(dir, "harness")}, &built, io.Discard); err != nil || code != 0 {
		t.Fatalf("build: %d, %v", code, err)
	}
	builtPath := filepath.Join(dir, "built.json")
	write(t, builtPath, built.String())
	out.Reset()
	if code, err := run([]string{"check", "-set", builtPath, filepath.Join(dir, "harness")}, &out, io.Discard); err != nil || code != 0 {
		t.Fatalf("check of the builder's entry for the same file: %d, %v, %q", code, err, out.String())
	}
}
