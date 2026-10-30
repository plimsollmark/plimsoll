package withheld

import (
	"bytes"
	"crypto/sha256"
)

// Source entries (docs/ship-scan.md, "Source entries"). A file entry matches a file
// whole, so a harness file shipped edited (a function renamed, a line added, the code
// reformatted) or bundled into a larger file is not found by it. A source entry holds
// the digests of its file's distinctive lines instead, and a shipped file holding at
// least the entry's min_lines of them is a find. The builder's min_lines is
// DefaultMinLines.

const (
	// MinSourceLines is the fewest distinctive lines a source entry holds, and the
	// fewest a find needs: under it, a few lines two files of one codebase share (an
	// import block, a helper's signature) would be a find.
	MinSourceLines = 8
	// MinSourceLineBytes is the shortest distinctive line, after SourceLine: shorter
	// lines (a closing brace, "returnx", an import of one module) are in every
	// codebase.
	MinSourceLineBytes = 24
)

// DefaultMinLines is the builder's min_lines for an entry of n lines: a third of them,
// and never fewer than MinSourceLines. An edited copy keeps most of a file's lines and
// a bundled one all of them. Files of one codebase share more than one might think:
// across this module's own code the closest pair (two session providers written to
// one pattern) shared 83 of one's 362 lines, 23 percent: at a quarter that pair held 91
// percent of what a find needs, at a third 69 percent (measured 2026-10-28,
// TestSourceEntriesInOrdinaryCode).
func DefaultMinLines(n int) int { return max(MinSourceLines, (n+2)/3) }

// sourceEntry is a source entry as the scan uses it: the entry it reports, and the
// lines a find needs.
type sourceEntry struct {
	report   int
	minLines int
}

// SourceLine appends to dst line as source entries compare it: every space, tab,
// carriage return, newline, form feed and vertical tab removed, so a copy reindented or
// reformatted still matches; then, at its end, commas, then quotes, then one \n escape,
// and at its start quotes: what wraps a line of code quoted as a string, as a
// notebook's JSON and a list of lines do.
func SourceLine(dst, line []byte) []byte {
	start := len(dst)
	for _, c := range line {
		switch c {
		case ' ', '\t', '\r', '\n', '\f', '\v':
		default:
			dst = append(dst, c)
		}
	}
	n := bytes.TrimRight(dst[start:], ",")
	n = bytes.TrimRight(n, `"'`)
	n = bytes.TrimSuffix(n, []byte(`\n`))
	n = bytes.TrimLeft(n, `"'`)
	return append(dst[:start], n...)
}

// commentMarkers start the lines Distinctive drops: a comment is where files share text
// they do not share code (a license header, a generated banner).
var commentMarkers = [][]byte{[]byte("#"), []byte("//"), []byte("/*"), []byte("*"), []byte("--"), []byte(";")}

// Distinctive reports whether n, a line after SourceLine, is one source entries hold:
// MinSourceLineBytes or longer, and not a comment.
func Distinctive(n []byte) bool {
	if len(n) < MinSourceLineBytes {
		return false
	}
	for _, m := range commentMarkers {
		if bytes.HasPrefix(n, m) {
			return false
		}
	}
	return true
}

// SourceDigests is what a source entry holds for content: the digest of each of its
// distinctive lines as written, each once, in the order they first appear.
func SourceDigests(content []byte) [][sha256.Size]byte {
	var out [][sha256.Size]byte
	seen := map[[sha256.Size]byte]bool{}
	var buf []byte
	for line := range bytes.Lines(content) {
		if buf = SourceLine(buf[:0], line); !Distinctive(buf) {
			continue
		}
		if d := sha256.Sum256(buf); !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// source checks content, a whole file, against the source entries: each distinctive
// line it holds, as written and with its escapes decoded (a file embedded in a string),
// counted once, and an entry found when its count reaches the entry's min_lines. It
// costs one pass over the content (two with escapes) and one SHA-256 per distinctive
// line.
func (sc *scanner) source(content []byte) {
	s := sc.set
	if len(s.sources) == 0 {
		return
	}
	if sc.lineSeen == nil {
		sc.lineSeen = make([]int, len(s.lineEntries))
		sc.srcCount = make([]int, len(s.sources))
		sc.srcStamp = make([]int, len(s.sources))
	}
	sc.stamp++ // counts of an earlier content are stale from here
	each := func(data []byte) {
		for line := range bytes.Lines(data) {
			if sc.norm = SourceLine(sc.norm[:0], line); !Distinctive(sc.norm) {
				continue
			}
			at, ok := s.sourceLines[sha256.Sum256(sc.norm)]
			if !ok || sc.lineSeen[at] == sc.stamp {
				continue
			}
			sc.lineSeen[at] = sc.stamp
			for _, e := range s.lineEntries[at] {
				if sc.srcStamp[e] != sc.stamp {
					sc.srcStamp[e], sc.srcCount[e] = sc.stamp, 0
				}
				if sc.srcCount[e]++; sc.srcCount[e] == s.sources[e].minLines {
					sc.found(s.sources[e].report)
				}
			}
		}
	}
	each(content)
	if u, _, ok := unescape(content); ok {
		each(u)
	}
}
