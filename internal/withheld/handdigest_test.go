package withheld

import (
	"archive/zip"
	"encoding/base64"
	"math/rand/v2"
	"testing"
)

// The no-leak demo of 2026-11-26: an operator who writes a file entry by hand, with a plain
// sha256sum of the harness file, gets the digest of its bytes as written. That file ends in
// a newline (almost every text file does) and here also carries trailing whitespace and
// Windows line endings, so the digest differs from the builder's normalized one. The scan
// used to look for the normalized digest alone, so the set loaded without a word and the
// very file it names, shipped byte for byte, passed as clean.
func TestHandWrittenRawDigestIsFound(t *testing.T) {
	raw := []byte("import numpy as np  \r\n\r\ndef step(state, u, dt):\t\r\n    return state + dt * (u - 0.3 * state)\r\n")
	set := setOf(t, ModeRefuse, nil, map[string]any{"kind": "file", "sha256": hexOf(raw), "label": "harness/sim.py"})
	for _, tc := range []struct {
		name  string
		parts []Part
	}{
		{"a call's file", []Part{{Where: "files[0].content", Data: raw, Whole: true}}},
		{"a snippet's code", []Part{{Where: "code", Data: raw, Whole: true}}},
		{"inside base64", []Part{{Where: "files[0].content", Data: []byte(base64.StdEncoding.EncodeToString(raw)), Whole: true}}},
		{"a tar member", []Part{{Where: "files[0].content", Data: tarOf(member{"sim.py", string(raw)}), Whole: true}}},
		{"a gzip member", []Part{{Where: "files[0].content", Data: gzipOf(raw), Whole: true}}},
		{"a stored zip member", []Part{{Where: "files[0].content", Data: zipOf(zip.Store, member{"sim.py", string(raw)}), Whole: true}}},
		{"a deflated zip member", []Part{{Where: "files[0].content", Data: zipOf(zip.Deflate, member{"sim.py", string(raw)}), Whole: true}}},
	} {
		found := foundIn(set, tc.parts)
		if len(found) != 1 || found[0].Label != "harness/sim.py" {
			t.Errorf("%s: found %+v, want harness/sim.py: a hand-written digest of the file's own bytes must find that file", tc.name, found)
		}
	}
	// A hand-written digest finds the copy it was taken of and no other: the builder's
	// normalized digest is what finds a copy with other line endings.
	lf := []byte("import numpy as np\n\ndef step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n")
	if found := foundIn(set, []Part{{Where: "files[0].content", Data: lf, Whole: true}}); len(found) != 0 {
		t.Errorf("a raw digest found another copy: %+v", found)
	}
}

// Matching the bytes as written as well as the normalized form adds no find to an entry the
// builder wrote: a file's raw digest equals a normalized digest only when the file is that
// normalized form, which Normalize leaves as it is, so the normalized digest found it already.
func TestRawMatchAddsNothingToBuilderEntries(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	alphabet := []byte("ab \t\r\n")
	gen := func() []byte {
		b := make([]byte, 1+rng.IntN(12))
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return b
	}
	for range 5000 {
		a, b := gen(), gen()
		if n := Normalize(a); string(Normalize(n)) != string(n) {
			t.Fatalf("Normalize is not idempotent on %q: %q then %q", a, n, Normalize(n))
		}
		if len(Normalize(a)) == 0 {
			continue // the builder writes no entry for blank content, and Parse refuses one
		}
		set := setOf(t, ModeAudit, nil, file(string(a), "a", ""))
		rawHit := hexOf(b) == fileHex(a)
		normHit := fileHex(b) == fileHex(a)
		if rawHit && !normHit {
			t.Fatalf("%q's raw digest matches %q's entry but its normalized one does not", b, a)
		}
		if found := len(foundIn(set, []Part{{Where: "f", Data: b, Whole: true}})) == 1; found != normHit {
			t.Fatalf("builder entry of %q against %q: found %v, the normalized digest says %v", a, b, found, normHit)
		}
	}
}

// A digest of whitespace alone, written by hand as sha256sum gives it, would match every
// blank file a caller ships (an __init__.py of one newline); Parse refuses it as it refuses
// the normalized digest of empty content.
func TestParseRefusesARawDigestOfBlankContent(t *testing.T) {
	for _, blank := range []string{"\n", "\r\n", "\n\n", " \n", "\t", "\r\n\r\n", "    "} {
		raw := `{"version":2,"mode":"refuse","entries":[{"kind":"file","sha256":"` + hexOf([]byte(blank)) + `","label":"blank"}]}`
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("Parse accepted a file entry of %q as written", blank)
		}
	}
}

// The cost of the second match, per megabyte of ordinary source ending in a newline (the
// case that takes both hashes): BenchmarkFileEntry against BenchmarkFileDigest, the
// normalized match alone. docs/ship-scan.md's archive bound states the two.
func benchSource() []byte {
	line := []byte("    return state + dt * (u - 0.3 * state)  # one line of a simulator\n")
	b := make([]byte, 0, 1<<20+len(line))
	for len(b) < 1<<20 {
		b = append(b, line...)
	}
	return b
}

func BenchmarkFileDigest(b *testing.B) {
	data := benchSource()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		FileDigest(data)
	}
}

func BenchmarkFileEntry(b *testing.B) {
	data := benchSource()
	set := setOf(b, ModeAudit, nil, file("withheld file\n", "f", ""))
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if _, ok, n := set.fileEntry(data); ok || n != 2 {
			b.Fatalf("ok %v, %d hashes", ok, n)
		}
	}
}
