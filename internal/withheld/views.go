package withheld

import (
	"unicode/utf16"
	"unicode/utf8"
)

// A part is scanned in up to three views, each by the same run rule (scanValues), so
// a value is found where an encoding put it (docs/ship-scan.md, "Encoded values"):
//
//   - as written;
//   - with its escapes decoded once (unescape), when it holds any: a seed after an
//     escaped character (seed%3D731904, "\n731904") is otherwise glued to the
//     escape's letters and digits, and a value with escaped characters inside it is
//     otherwise a different string;
//   - each base64 blob in it decoded (base64Blobs): the value's base64 sits inside a
//     blob's long run of letters and digits, never on run boundaries, and once decoded
//     it is found at any of the three alignments.
//
// One level each: an encoding inside another (base64 inside base64, an escape inside
// base64, %253D) is not decoded.

// MinBase64Chars is the shortest run of base64 characters decoded: 6 characters hold
// 4 bytes, the shortest value.
const MinBase64Chars = 6

// unescape decodes, once, the percent escapes (%HH) and the backslash escapes of JSON,
// JavaScript and Python strings in data. ok is false when data holds none, so the
// caller skips a view the same as the written one. escaped marks the bytes of out that
// an escape produced: an archive in out whose first bytes no escape produced is the
// same archive the written view holds (archive.go).
func unescape(data []byte) (out []byte, escaped bitset, ok bool) {
	for i := 0; i < len(data); i++ {
		if c := data[i]; c != '%' && c != '\\' {
			continue
		}
		if _, n := appendEscape(nil, data, i); n == 0 {
			continue
		}
		out = append(make([]byte, 0, len(data)), data[:i]...)
		escaped = newBitset(len(data))
		for i < len(data) {
			at := len(out)
			var n int
			if out, n = appendEscape(out, data, i); n > 0 {
				for j := at; j < len(out); j++ {
					escaped.set(j)
				}
				i += n
				continue
			}
			out = append(out, data[i])
			i++
		}
		return out, escaped, true
	}
	return nil, nil, false
}

// bitset is a set of byte positions.
type bitset []uint64

// newBitset holds positions 0 to n.
func newBitset(n int) bitset    { return make(bitset, n/64+1) }
func (b bitset) set(i int)      { b[i/64] |= 1 << (i % 64) }
func (b bitset) has(i int) bool { return b[i/64]&(1<<(i%64)) != 0 }

// anyIn reports whether any position from lo to hi (not included) is in the set, a word
// at a time: a tar header's 512 positions are eight words.
func (b bitset) anyIn(lo, hi int) bool {
	for i := lo; i < hi; {
		n := min(64-i%64, hi-i)
		w := b[i/64] >> (i % 64)
		if n < 64 {
			w &= 1<<n - 1
		}
		if w != 0 {
			return true
		}
		i += n
	}
	return false
}

// appendEscape decodes the escape at data[i] onto dst and returns the bytes it
// consumed, or 0 (dst unchanged) when none starts there. The escapes: %HH; \" \\ \/
// \' \b \f \n \r \t \v; \xHH as one byte; \uHHHH as UTF-8, a surrogate pair as one
// character and a lone surrogate as U+FFFD, as Go's JSON decoder reads them. A
// backslash before anything else is a backslash (a Windows path, a regular expression).
func appendEscape(dst, data []byte, i int) ([]byte, int) {
	rest := data[i:]
	if len(rest) < 2 {
		return dst, 0
	}
	if rest[0] == '%' {
		if len(rest) >= 3 {
			if b, ok := hexByte(rest[1], rest[2]); ok {
				return append(dst, b), 3
			}
		}
		return dst, 0
	}
	if rest[0] != '\\' {
		return dst, 0
	}
	switch c := rest[1]; c {
	case '"', '\\', '/', '\'':
		return append(dst, c), 2
	case 'b':
		return append(dst, '\b'), 2
	case 'f':
		return append(dst, '\f'), 2
	case 'n':
		return append(dst, '\n'), 2
	case 'r':
		return append(dst, '\r'), 2
	case 't':
		return append(dst, '\t'), 2
	case 'v':
		return append(dst, '\v'), 2
	case 'x':
		if len(rest) >= 4 {
			if b, ok := hexByte(rest[2], rest[3]); ok {
				return append(dst, b), 4
			}
		}
	case 'u':
		r, ok := hexRune(rest[2:])
		if !ok {
			return dst, 0
		}
		if utf16.IsSurrogate(r) {
			if r < 0xdc00 && len(rest) >= 12 && rest[6] == '\\' && rest[7] == 'u' {
				if r2, ok := hexRune(rest[8:]); ok && r2 >= 0xdc00 && r2 <= 0xdfff {
					return utf8.AppendRune(dst, utf16.DecodeRune(r, r2)), 12
				}
			}
			r = utf8.RuneError
		}
		return utf8.AppendRune(dst, r), 6
	}
	return dst, 0
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func hexByte(a, b byte) (byte, bool) {
	hi, ok1 := hexVal(a)
	lo, ok2 := hexVal(b)
	return hi<<4 | lo, ok1 && ok2
}

// hexRune reads the four hex digits of a \u escape.
func hexRune(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		v, ok := hexVal(c)
		if !ok {
			return 0, false
		}
		r = r<<4 | rune(v)
	}
	return r, true
}

// The two base64 alphabets differ only in the characters for 62 and 63: + and / in the
// standard one, - and _ in the URL-safe one. A table entry is the character's value,
// or -1 for none.
var b64Std, b64URL [256]int8

func init() {
	for i := range b64Std {
		b64Std[i], b64URL[i] = -1, -1
	}
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for v, c := range []byte(letters) {
		b64Std[c], b64URL[c] = int8(v), int8(v)
	}
	b64Std['+'], b64Std['/'] = 62, 63
	b64URL['-'], b64URL['_'] = 62, 63
}

// base64Blobs calls fn with each base64 blob in data decoded: every run of at least
// MinBase64Chars characters of either alphabet, decoded from its first character. In a
// standard run, %2B and %2F (base64 in a URL) and \/ (in a JSON string) are + and /.
// A line break (a real one or a \n escape, either after a \r) after a whole number of
// 4-character groups, and any spaces or tabs after it, continues the run, so wrapped
// base64 (76 columns from the base64 command, 64 in PEM) is one blob. A URL-safe run
// that is the same span as a standard run decodes the same and is not decoded again.
// fn's slice is reused after it returns.
func base64Blobs(data []byte, fn func(blob []byte)) {
	if len(data) < MinBase64Chars {
		return
	}
	var vals, blob []byte
	// The standard runs' starts and ends, as bit sets over data, for the URL-safe pass.
	starts := make([]uint64, len(data)/64+1)
	ends := make([]uint64, len(data)/64+2)
	has := func(set []uint64, i int) bool { return set[i/64]&(1<<(i%64)) != 0 }
	mark := func(set []uint64, i int) { set[i/64] |= 1 << (i % 64) }
	for pass, alphabet := range []*[256]int8{&b64Std, &b64URL} {
		std := pass == 0
		for i := 0; i < len(data); {
			if _, n := b64At(data, i, alphabet, std); n == 0 {
				i++
				continue
			}
			start, line, plain := i, 0, true
			vals = vals[:0]
			for {
				if v, n := b64At(data, i, alphabet, std); n > 0 {
					if n > 1 || !word(data[i]) {
						plain = false
					}
					vals = append(vals, v)
					line++
					i += n
					continue
				}
				if line%4 == 0 {
					if j := lineBreak(data, i); j > i {
						if _, n := b64At(data, j, alphabet, std); n > 0 {
							i, line = j, 0
							continue
						}
					}
				}
				break
			}
			if len(vals) < MinBase64Chars {
				continue
			}
			if std {
				mark(starts, start)
				mark(ends, i)
			} else if plain && has(starts, start) && has(ends, i) {
				// Letters and digits only (and line breaks, which both passes take
				// alike), and a standard run starts here and one ends there: they are
				// the same run, since no standard run ends inside letters and digits.
				continue
			}
			blob = decodeBase64(blob[:0], vals)
			fn(blob)
		}
	}
}

// b64At reads the base64 character at data[i] in alphabet and returns its value and
// the bytes it took, or 0 bytes when there is none. std adds the escaped forms of +
// and / that the standard alphabet's text carries in URLs and JSON.
func b64At(data []byte, i int, alphabet *[256]int8, std bool) (byte, int) {
	if i >= len(data) {
		return 0, 0
	}
	if v := alphabet[data[i]]; v >= 0 {
		return byte(v), 1
	}
	if !std {
		return 0, 0
	}
	rest := data[i:]
	switch {
	case len(rest) >= 3 && rest[0] == '%' && rest[1] == '2' && (rest[2]|0x20 == 'b'):
		return 62, 3
	case len(rest) >= 3 && rest[0] == '%' && rest[1] == '2' && (rest[2]|0x20 == 'f'):
		return 63, 3
	case len(rest) >= 2 && rest[0] == '\\' && rest[1] == '/':
		return 63, 2
	}
	return 0, 0
}

// lineBreak returns the index after the line break at data[i] (\n, \r\n, or their
// escapes \n and \r\n) and the spaces and tabs after it, or i when none is there.
func lineBreak(data []byte, i int) int {
	j := i
	for _, nl := range []string{"\r\n", "\n", `\r\n`, `\n`} {
		if len(data)-i >= len(nl) && string(data[i:i+len(nl)]) == nl {
			j = i + len(nl)
			break
		}
	}
	if j == i {
		return i
	}
	for j < len(data) && (data[j] == ' ' || data[j] == '\t') {
		j++
	}
	return j
}

// decodeBase64 appends the bytes of vals (6-bit values) onto dst: 3 bytes per 4
// values; 2 or 3 values left over give 1 or 2 bytes, 1 gives none.
func decodeBase64(dst, vals []byte) []byte {
	for len(vals) >= 4 {
		n := uint32(vals[0])<<18 | uint32(vals[1])<<12 | uint32(vals[2])<<6 | uint32(vals[3])
		dst = append(dst, byte(n>>16), byte(n>>8), byte(n))
		vals = vals[4:]
	}
	switch len(vals) {
	case 2:
		dst = append(dst, vals[0]<<2|vals[1]>>4)
	case 3:
		n := uint32(vals[0])<<18 | uint32(vals[1])<<12 | uint32(vals[2])<<6
		dst = append(dst, byte(n>>16), byte(n>>8))
	}
	return dst
}
