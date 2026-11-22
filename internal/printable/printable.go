// Package printable makes text that came from outside a program (a daemon's answer, a
// bundle, a file's name or content, a request) safe to show on a terminal or in a log
// line: every character that can rewrite a screen, forge a line or display text in
// another order than it reads is written as a visible escape. It holds the one set of
// such characters plimsoll uses: record.ValidQualification refuses the same set, and the
// Python and TypeScript clients get it from the table internal/wiretables writes.
package printable

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// forbidden holds the code points Text escapes, as inclusive ranges, in the order
// docs/run-records.md lists them for a qualification.
var forbidden = [...][2]rune{
	{0x00, 0x1f}, {0x7f, 0x9f}, // control characters: C0 (CR, LF, ESC among them), DEL and C1
	{0x061c, 0x061c}, {0x200e, 0x200e}, {0x200f, 0x200f}, // bidirectional marks
	{0x2028, 0x2028}, {0x2029, 0x2029}, // line and paragraph separators
	{0x202a, 0x202e}, {0x2066, 0x2069}, // bidirectional embeddings, overrides and isolates
}

// Ranges returns the inclusive code point ranges Text escapes.
func Ranges() [][2]rune { return append([][2]rune(nil), forbidden[:]...) }

// Escaped reports whether Text writes r as an escape.
func Escaped(r rune) bool {
	for _, f := range forbidden {
		if r >= f[0] && r <= f[1] {
			return true
		}
	}
	return false
}

// Text returns s with each character of the set (Ranges) written as an escape, \x1b for
// one below U+0100 and \u202e above, and each byte that is not UTF-8 as \x escape. Text
// that holds none comes back unchanged, and the escapes hold none, so cleaning twice
// changes nothing. A backslash is left as it is: the result is for a reader, and a name
// that must stay unambiguous (two inputs, two outputs) needs an escaping of its own
// (withheld.KnownPath).
func Text(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, Escaped) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case !Escaped(r):
			b.WriteString(s[i : i+n])
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
		i += n
	}
	return b.String()
}

// JSON returns the JSON text j (as an encoder writes it) with each character of the set
// inside a string written as a JSON escape (\u009b, \u202e), and each byte that is not
// UTF-8 inside a string as \ufffd, which is what a JSON reader takes it for. Outside
// strings it changes nothing, so the indentation and the line breaks between values stay
// as they were. The value a JSON reader reads is unchanged; only what a terminal shows
// is. An encoder already escapes the characters below U+0020; DEL, C1, the separators and
// the bidirectional characters it writes as they are.
func JSON(j []byte) []byte {
	var b []byte // nil until the first change
	inString, escape := false, false
	for i := 0; i < len(j); {
		c := j[i]
		switch {
		case !inString:
			if c == '"' {
				inString = true
			}
		case escape:
			escape = false
		case c == '\\':
			escape = true
		case c == '"':
			inString = false
		default:
			r, n := utf8.DecodeRune(j[i:])
			bad := r == utf8.RuneError && n == 1
			if bad || Escaped(r) {
				if b == nil {
					b = append(make([]byte, 0, len(j)+16), j[:i]...)
				}
				if bad {
					r = utf8.RuneError
				}
				b = fmt.Appendf(b, `\u%04x`, r)
				i += n
				continue
			}
			if b != nil {
				b = append(b, j[i:i+n]...)
			}
			i += n
			continue
		}
		if b != nil {
			b = append(b, c)
		}
		i++
	}
	if b == nil {
		return j
	}
	return b
}
