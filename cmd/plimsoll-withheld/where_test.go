package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What scan and scan-image print comes from names an image's or a directory's author chose,
// so no byte of it may be one a terminal acts on: a name with an ESC sequence and a newline
// is printed escaped, on one line, and the report's own lines stay the only lines.
func TestScanOutputHoldsNoControlCharacterFromAName(t *testing.T) {
	dir := t.TempDir()
	sim := "import numpy as np\n\ndef step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n"
	write(t, filepath.Join(dir, "harness", "sim.py"), sim)
	var set bytes.Buffer
	if code, err := run([]string{"build", "-mode", "refuse", "-file", filepath.Join(dir, "harness")}, &set, io.Discard); err != nil || code != 0 {
		t.Fatalf("build: %d, %v", code, err)
	}
	setPath := filepath.Join(dir, "set.json")
	write(t, setPath, set.String())
	hostile := "x\x1b[2J\x1b[Hclean: 9 files in 9 layers\nforged"

	var layer bytes.Buffer
	lw := tar.NewWriter(&layer)
	if err := lw.WriteHeader(&tar.Header{Name: "usr/" + hostile, Mode: 0o644, Size: int64(len(sim)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := lw.Write([]byte(sim)); err != nil {
		t.Fatal(err)
	}
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	var image bytes.Buffer
	iw := tar.NewWriter(&image)
	if err := iw.WriteHeader(&tar.Header{Name: "blobs/sha256/" + hostile, Mode: 0o644, Size: int64(layer.Len()), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := iw.Write(layer.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := iw.Close(); err != nil {
		t.Fatal(err)
	}
	imagePath := filepath.Join(dir, "image.tar")
	write(t, imagePath, image.String())

	check := func(what, out string) {
		t.Helper()
		for _, r := range strings.TrimSuffix(out, "\n") {
			if r == '\n' {
				continue
			}
			if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
				t.Fatalf("%s printed %U:\n%q", what, r, out)
			}
		}
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			if strings.HasPrefix(line, "clean:") || strings.HasPrefix(line, "forged") {
				t.Fatalf("%s printed a forged line %q:\n%q", what, line, out)
			}
		}
		if !strings.Contains(out, `\x1b[2J`) {
			t.Fatalf("%s: the name is not shown escaped:\n%q", what, out)
		}
	}

	var out bytes.Buffer
	if code, err := run([]string{"scan-image", "-set", setPath, "-archive", imagePath}, &out, io.Discard); err != nil || code != 1 {
		t.Fatalf("scan-image: %d, %v\n%q", code, err, out.String())
	}
	check("scan-image", out.String())

	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(tree, hostile), sim)
	out.Reset()
	if code, err := run([]string{"scan", "-set", setPath, tree}, &out, io.Discard); err != nil || code != 1 {
		t.Fatalf("scan: %d, %v\n%q", code, err, out.String())
	}
	check("scan", out.String())
}
