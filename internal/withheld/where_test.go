package withheld

import (
	"slices"
	"strings"
	"testing"
)

// A name in an image is the image author's text: it reaches every Where, so a Where must hold
// no control character, whatever the name carries (an ESC sequence that clears a terminal, a
// forged line after a newline, CR, U+2028 and U+2029, a byte that is not UTF-8).
func TestScanImageNeutralizesNamesInWhere(t *testing.T) {
	hostile := "evil\x1b[2J\x1b[H\nclean: 0 files\r  \xff.py"
	s := setOf(t, ModeRefuse, nil, file(harnessSource, "harness/sim.py", ""))
	zstd := string([]byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0})
	big := strings.Repeat("\x00", MaxImageFileBytes+1)
	layer := string(layerTarOf(t, [2]string{"usr/" + hostile, harnessSource}, [2]string{"data/" + hostile + ".bin", big}))
	res := scanImage(t, s, layerTarOf(t,
		[2]string{"blobs/sha256/" + hostile, zstd},
		[2]string{"blobs/sha256/l\x1b]0;x\a ", layer},
		[2]string{hostile, "plain"}))
	var wheres []string
	for _, f := range res.Found {
		wheres = append(wheres, f.Where...)
	}
	for _, in := range res.Incomplete {
		wheres = append(wheres, in.Where)
	}
	if len(res.Found) != 1 || len(res.Incomplete) < 2 {
		t.Fatalf("found %+v, incomplete %+v; want the harness found and the zstd layer and the big file incomplete", res.Found, res.Incomplete)
	}
	for _, w := range wheres {
		for _, r := range w {
			if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 || r == 0xfffd {
				t.Fatalf("a Where holds %U: %q", r, w)
			}
		}
	}
	if !slices.Contains(wheres, `blobs/sha256/evil\x1b[2J\x1b[H\x0aclean: 0 files\x0d  \xff.py`) {
		t.Fatalf("the escaped member name is missing from %q", wheres)
	}
}

func TestCleanWhere(t *testing.T) {
	for in, want := range map[string]string{
		"blobs/sha256/ab:usr/src/x.py (path)": "blobs/sha256/ab:usr/src/x.py (path)",
		"héllo/日本語":                           "héllo/日本語",
		"a\x1bb":                              `a\x1bb`,
		"a\nb\rc":                             `a\x0ab\x0dc`,
		"a\u2028b\u2029c":                     `a\u2028b\u2029c`,
		"a\x7fb\u0085c":                       `a\x7fb\x85c`,
		"a\xc3\x28b":                          `a\xc3(b`,
	} {
		got := CleanWhere(in)
		if got != want {
			t.Errorf("CleanWhere(%q) = %q, want %q", in, got, want)
		}
		if CleanWhere(got) != got {
			t.Errorf("CleanWhere is not idempotent on %q", in)
		}
	}
}
