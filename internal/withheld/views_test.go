package withheld

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// encodedSet withholds one value of each shape the encodings treat differently.
func encodedSet(t *testing.T) *Set {
	return setOf(t, ModeAudit, nil,
		value("731904", "seed", ""),          // digits: no encoding changes it, so only its context can hide it
		value("12:30:45", "time", ""),        // : is escaped by strict URL encoders
		value("Kestrel-42", "word", ""),      // letters: case
		value("café-42", "accented", ""),     // non-ASCII: \u00e9, %C3%A9
		value("x<3&y>4", "html", ""),         // Go's json.Marshal escapes < > &
		value("cases/hidden/07", "path", ""), // / is \/ in PHP's JSON
		value("a😀b-42", "astral", ""),        // a surrogate pair in a \u escape
		value("fly north 7", "spaced", ""),
		value("fly+north+7", "spaced", ""), // the builder's form for a space; one entry with the value
		file("import numpy as np\n\ndef step(s, u):\n    return s + u\n", "harness/sim.py", ""))
}

func b64(s string) string        { return base64.StdEncoding.EncodeToString([]byte(s)) }
func b64URLText(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// wrap breaks s into lines of n characters joined by sep, as the base64 command (76
// columns) and PEM (64) write it.
func wrap(s string, n int, sep string) string {
	var lines []string
	for len(s) > n {
		lines, s = append(lines, s[:n]), s[n:]
	}
	return strings.Join(append(lines, s), sep)
}

// Each encoding a harness or an agent's output plausibly puts a withheld value in, and
// the one level the scan decodes: the value is found in each.
func TestEncodedValuesAreFound(t *testing.T) {
	set := encodedSet(t)
	// Three bytes that encode as ++++ and three as ////, and as ---- and ____ in the URL-safe
	// alphabet: blobs that carry the characters the alphabets differ in.
	const plusses, slashes = "\xfb\xef\xbe", "\xff\xff\xff"
	sim := "import numpy as np\n\ndef step(s, u):\n    return s + u\n"
	for _, tc := range []struct {
		name, text string
		want       []string
	}{
		// The value's neighbor escaped: the seed is unchanged, but %3D or \n is glued to it.
		{"URL, escaped neighbor", "next=viewer.html%3Fseed%3D731904%26case%3D2", []string{"seed"}},
		{"URL, lower-case hex", "next=viewer.html%3fseed%3d731904%26case%3d2", []string{"seed"}},
		{"JSON, newline before", `{"seeds": "100001\n731904\n"}`, []string{"seed"}},
		{"JSON, Go's HTML escapes", `"\u003cb\u003e731904\u003c/b\u003e"`, []string{"seed"}},
		{"Python bytes, hex escape", `b'\x0a731904'`, []string{"seed"}},
		// The value's own characters escaped.
		{"URL, strict", "t=12%3A30%3A45&z=1", []string{"time"}},
		{"URL, strict, lower-case hex", "t=12%3a30%3a45", []string{"time"}},
		{"URL, UTF-8", "w=caf%C3%A9-42", []string{"accented"}},
		{"URL, form plus", "q=fly+north+7&p=1", []string{"spaced"}},
		{"URL, %20", "q=fly%20north%207", []string{"spaced"}},
		{"JSON, Go's HTML escapes inside", `"x\u003c3\u0026y\u003e4"`, []string{"html"}},
		{"JSON, Python's ASCII escapes", `"caf\u00e9-42"`, []string{"accented"}},
		{"JSON, PHP's escaped slash", `"cases\/hidden\/07"`, []string{"path"}},
		{"JSON, surrogate pair", `"a\ud83d\ude00b-42"`, []string{"astral"}},
		// Case.
		{"upper case", "KESTREL-42", []string{"word"}},
		{"lower case", "id kestrel-42.", []string{"word"}},
		{"mixed case", "kEsTrEl-42", []string{"word"}},
		// Base64: the value alone, and inside a longer blob at each of the three alignments
		// (a prefix of 0, 1 or 2 bytes modulo 3 before it).
		{"base64 alone, padded", "v=" + b64("Kestrel-42"), []string{"word"}},
		{"base64 alone, unpadded", "v=" + strings.TrimRight(b64("Kestrel-42"), "="), []string{"word"}},
		{"base64 blob, alignment 0", "data:application/json;base64," + b64(`{"a":731904}`), []string{"seed"}},
		{"base64 blob, alignment 1", "data:application/json;base64," + b64(`{"ab":731904}`), []string{"seed"}},
		{"base64 blob, alignment 2", "data:application/json;base64," + b64(`{"abc":731904}`), []string{"seed"}},
		{"base64 blob, upper-case value", `"` + b64("name=KESTREL-42;") + `"`, []string{"word"}},
		{"base64 with + and /", `"` + b64(plusses+slashes+"seed=731904") + `"`, []string{"seed"}},
		{"base64 in a URL, + and / escaped", "blob=" + strings.NewReplacer("+", "%2B", "/", "%2F", "=", "%3D").Replace(b64(plusses+slashes+"seed=731904")), []string{"seed"}},
		{"base64 in JSON, / escaped", `{"b":"` + strings.ReplaceAll(b64(slashes+"seed=731904"), "/", `\/`) + `"}`, []string{"seed"}},
		{"URL-safe base64 after a path", "/v1/blob/" + b64URLText(plusses+slashes+"seed=731904"), []string{"seed"}},
		// Wrapped base64, the value across a line break: the 52-byte prefix puts its
		// bytes at characters 70 to 78 of a 76-column wrap.
		{"base64 wrapped at 76", wrap(b64(strings.Repeat("p", 52)+" 731904 "+strings.Repeat("q", 40)), 76, "\n"), []string{"seed"}},
		{"base64 wrapped, CRLF and indented", "key: |\n  " + wrap(b64(strings.Repeat("p", 52)+" 731904 "+strings.Repeat("q", 40)), 76, "\r\n  "), []string{"seed"}},
		{"base64 wrapped in a JSON string", `"` + wrap(b64(strings.Repeat("p", 43)+" 731904 "+strings.Repeat("q", 40)), 64, `\n`) + `"`, []string{"seed"}},
		// A whole file inlined as a data URI is found by its file entry.
		{"file as a data URI", `<script src="data:text/x-python;base64,` + b64(sim) + `">`, []string{"harness/sim.py"}},
		{"file as a data URI, CRLF", `src="data:;base64,` + b64(strings.ReplaceAll(sim, "\n", "\r\n")) + `"`, []string{"harness/sim.py"}},
	} {
		got := labels(foundIn(set, []Part{{Where: "files[0].content", Data: []byte(tc.text), Whole: true}}))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: found %v, want %v\n%s", tc.name, got, tc.want, tc.text)
		}
	}
}

// What the views do not decode, stated in docs/ship-scan.md: one level of each, and a
// blob is decoded from its run's first character. These pin the documented limits, so
// a change that lifts one updates the page.
func TestEncodedValuesTheScanDoesNotFind(t *testing.T) {
	set := encodedSet(t)
	for _, tc := range []struct{ name, text string }{
		{"double URL encoding", "next%3Dview%253Fseed%253D731904%2526x"},
		{"base64 inside base64", b64(b64(`{"a":731904}`))},
		{"an escape inside base64", b64(`"seeds": "1\n731904"`)},
		{"a blob glued to a letter before it", "x" + b64(`{"a":731904}`)},
		{"hex", fmt.Sprintf("%x", " 731904 ")},
		{"split", `"7319" + "04"`},
		{"inside a longer run, as before", "seed731904"},
	} {
		if got := labels(foundIn(set, []Part{{Where: "code", Data: []byte(tc.text)}})); len(got) != 0 {
			t.Errorf("%s: found %v; the docs say it is not\n%s", tc.name, got, tc.text)
		}
	}
}

func TestUnescape(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`a%3Db%3d`, "a=b="},
		{`50%`, ""},   // nothing to decode: the caller skips the view
		{`50%zz`, ""}, // not hex
		{`C:\Users\x`, ""},
		{`\n\t\r\b\f\v\"\\\/\'`, "\n\t\r\b\f\v\"\\/'"},
		{`\\n`, `\n`}, // an escaped backslash, then a plain n
		{`\x41\x4`, `A\x4`},
		{`\u00e9\u20ac`, "é€"},
		{`\ud83d\ude00`, "😀"},
		{`\ud83dx`, "\uFFFDx"},
		{`\ude00`, "\uFFFD"},
		{`\u12`, ""},
		{`%C3%A9 and \u00e9`, "é and é"}, // one pass decodes both kinds
		{`%255C`, "%5C"},                 // one level
	} {
		got, _, ok := unescape([]byte(tc.in))
		if tc.want == "" {
			if ok {
				t.Errorf("unescape(%q) = %q, want no view", tc.in, got)
			}
			continue
		}
		if !ok || string(got) != tc.want {
			t.Errorf("unescape(%q) = %q, %v; want %q", tc.in, got, ok, tc.want)
		}
	}
}

func blobs(text string) []string {
	var out []string
	base64Blobs([]byte(text), func(b []byte) { out = append(out, string(b)) })
	return out
}

func TestBase64Blobs(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       []string
	}{
		{"one blob", "x " + b64("hello world"), []string{"hello world"}},
		// Under 6 characters a run holds less than the shortest value.
		{"short runs are not decoded", "a bcde fg", nil},
		// Letters and digits only: the same span in both alphabets, decoded once.
		{"decoded once", "(" + b64("hello!") + ")", []string{"hello!"}},
		// The standard pass reads "/x/" plus the blob; the URL-safe pass reads the blob alone.
		{"both alphabets", "/x/" + b64("hello!"), []string{"\xff\x1f\xda\x19[\x1b\x1b\xc8", "hello!"}},
		// The standard run goes on past the blob; the URL-safe run ends with it.
		{"a standard run longer than the URL-safe one", "(" + b64("hello!") + "/x", []string{"hello!\xff", "hello!"}},
		{"a 1-character tail is dropped", "QUJDREVGRw", []string{"ABCDEFG"}},
		{"padding ends the run", "QUJD=REVG", nil},
		{"joined across a wrap", "QUJD\nREVG", []string{"ABCDEF"}},
		{"not joined after a partial group", "QUJDRE\nVGRw", []string{"ABCD"}},
		{"not joined across a blank line", "QUJDREVG\n\nSElK", []string{"ABCDEF"}},
	} {
		if got := blobs(tc.text); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: blobs %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The views are found by the same run rule as the written text: a value glued to a
// letter or digit in the decoded bytes is another string there too.
func TestViewsKeepTheRunRule(t *testing.T) {
	set := encodedSet(t)
	for _, text := range []string{
		"next%3D1731904",           // decoded: =1731904
		`"seed\u003d731904a"`,      // decoded: seed=731904a
		b64(`{"a":7319041}`),       // decoded: {"a":7319041}
		"kestrel-42" + "0",         // as before
		"q=fly+north+77",           // the + form, glued to a 7
		"t=12%3A30%3A456",          // decoded: 12:30:456
		`"cases\/hidden\/07\/x07"`, // decoded: cases/hidden/07/x07 holds the value, then /x07: found
	} {
		got := labels(foundIn(set, []Part{{Where: "code", Data: []byte(text)}}))
		want := []string(nil)
		if strings.Contains(text, "x07") {
			want = []string{"path"}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: found %v, want %v", text, got, want)
		}
	}
}

// corpus is ordinary text: the module's own Go source and documents, as written.
func corpus(t testing.TB) [][]byte {
	t.Helper()
	var out [][]byte
	for _, pattern := range []string{"../../*.md", "../../docs/*.md", "../../sandbox/*.go", "../../internal/*/*.go", "../../cmd/*/*.go", "../../docs/trainers/*.html"} {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, b)
		}
	}
	if len(out) < 50 {
		t.Fatalf("the corpus has %d files; run from the package directory", len(out))
	}
	return out
}

// randomValues draws n values of the shapes a withheld set holds: 6-digit seeds,
// 8-digit hex keys, UUIDs, 10-character mixed-case tokens and word-number answers.
func randomValues(r *rand.Rand, n int) []string {
	const hexDigits, alnum = "0123456789abcdef", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	pick := func(from string, k int) string {
		b := make([]byte, k)
		for i := range b {
			b[i] = from[r.IntN(len(from))]
		}
		return string(b)
	}
	words := []string{"kestrel", "harrier", "osprey", "merlin", "falcon", "condor"}
	out := make([]string, n)
	for i := range out {
		switch i % 5 {
		case 0:
			out[i] = fmt.Sprintf("%06d", 100000+r.IntN(900000))
		case 1:
			out[i] = pick(hexDigits, 8)
		case 2:
			out[i] = pick(hexDigits, 8) + "-" + pick(hexDigits, 4) + "-" + pick(hexDigits, 4) + "-" + pick(hexDigits, 4) + "-" + pick(hexDigits, 12)
		case 3:
			out[i] = pick(alnum, 10)
		case 4:
			out[i] = fmt.Sprintf("%s-%d", words[r.IntN(len(words))], r.IntN(100))
		}
	}
	return out
}

// The views add no false finds on ordinary text: random values of the usual shapes,
// scanned over the module's own source and documents, are found by the decoded views
// only where the written view finds them too. The written view's own rate (a random
// 6-digit seed is a whole number in unrelated text about once in 900,000 numbers) is
// the existing rule and is not counted here.
func TestViewsAddNoFindsOnOrdinaryText(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	values := randomValues(r, 2000)
	var entries []map[string]any
	seen := map[string]bool{}
	for i, v := range values {
		if k := strings.ToLower(v); !seen[k] {
			seen[k] = true
			entries = append(entries, value(v, fmt.Sprintf("v%d", i), ""))
		}
	}
	set := setOf(t, ModeAudit, nil, entries...)
	var size, extra int
	for _, doc := range corpus(t) {
		size += len(doc)
		written := map[int]bool{}
		set.scanValues(doc, func(i int) { written[i] = true })
		var viewed []int
		if u, _, ok := unescape(doc); ok {
			set.scanValues(u, func(i int) { viewed = append(viewed, i) })
		}
		base64Blobs(doc, func(b []byte) { set.scanValues(b, func(i int) { viewed = append(viewed, i) }) })
		for _, i := range viewed {
			if !written[i] {
				extra++
				t.Errorf("%s found only in a decoded view", set.entries[i].label)
			}
		}
	}
	t.Logf("%d values over %d bytes of ordinary text: %d finds in the decoded views alone", len(entries), size, extra)
}

// The work stays bounded per run in every view: at most MaxValueRuns hashes for each
// run of letters and digits in the written, decoded and base64 views, and one per blob
// for file entries. Each input here is built to make one view as costly as it can be.
func TestScanViewsWorkIsBoundedPerRun(t *testing.T) {
	var entries []map[string]any
	for n := MinValueBytes; n <= MaxValueBytes; n++ {
		entries = append(entries, value(strings.Repeat("q", n), fmt.Sprintf("q%d", n), ""))
	}
	entries = append(entries, file("withheld file\n", "f", ""))
	s := setOf(t, ModeAudit, nil, entries...)
	for name, data := range worstCases(1 << 16) {
		runs := Runs(data)
		blobCount := 0
		if u, _, ok := unescape(data); ok {
			runs += Runs(u)
		}
		base64Blobs(data, func(b []byte) { runs += Runs(b); blobCount++ })
		hashes := s.scanViews(data, func(int) { t.Fatalf("%s: nothing here is withheld", name) }, nil)
		if limit := MaxValueRuns*runs + blobCount; hashes > limit {
			t.Errorf("%s: %d hashes, over the bound %d", name, hashes, limit)
		}
		if hashes > 14*len(data) {
			t.Errorf("%s: %d hashes for %d bytes, over 14 per byte", name, hashes, len(data))
		}
		t.Logf("%s: %d bytes, %d hashes (%.2f per byte)", name, len(data), hashes, float64(hashes)/float64(len(data)))
	}
}

// worstCases are inputs of about n bytes built to maximize one view's work: the most
// runs in the written view, in the decoded view, in a base64 blob, and both written and
// base64 at once.
func worstCases(n int) map[string][]byte {
	blob := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a."), n*3/8))
	return map[string][]byte{
		"written: a.a.":            bytes.Repeat([]byte("a."), n/2),
		"decoded: a\\na\\n":        bytes.Repeat([]byte(`a\n`), n/3),
		"decoded: a.a%2E":          bytes.Repeat([]byte("a.a%2E"), n/6),
		"base64 of a.a.":           []byte(blob)[:n],
		"written and base64: a/a/": bytes.Repeat([]byte("a/"), n/2),
		"ordinary text":            ordinaryText(n),
	}
}

// ordinaryText is n bytes of this package's own source, repeated.
func ordinaryText(n int) []byte {
	src, err := os.ReadFile("withheld.go")
	if err != nil {
		panic(err)
	}
	return bytes.Repeat(src, n/len(src)+1)[:n]
}

// The scan's cost on the most a call carries (about 4.4 MiB: sandbox.MaxProjectBytes of
// files, MaxProjectSteps steps of MaxProjectStepBytes, MaxProjectArtifacts artifact
// paths of MaxProjectPathBytes), for each worst case, against a set declaring every
// value length. docs/ship-scan.md quotes the slowest.
func BenchmarkScanViews(b *testing.B) {
	var es []map[string]any
	for n := MinValueBytes; n <= MaxValueBytes; n++ {
		es = append(es, value(strings.Repeat("q", n), fmt.Sprintf("q%d", n), ""))
	}
	es = append(es, file("withheld file\n", "f", ""))
	s := setOf(b, ModeAudit, nil, es...)
	const most = 4<<20 + 20*16<<10 + 100*1<<10
	cases := worstCases(most)
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		data := cases[name]
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				foundIn(s, []Part{{Where: "files[0].content", Data: data, Whole: true}})
			}
		})
	}
}

// The scan's cost on ordinary text of the most a call carries, against a set of the
// usual size and shapes (200 values: seeds, keys, UUIDs, tokens, answers; one file),
// beside the worst cases above, which declare every value length.
func BenchmarkScanOrdinary(b *testing.B) {
	var es []map[string]any
	seen := map[string]bool{}
	for i, v := range randomValues(rand.New(rand.NewPCG(5, 6)), 200) {
		if k := strings.ToLower(v); !seen[k] {
			seen[k] = true
			es = append(es, value(v, fmt.Sprintf("v%d", i), ""))
		}
	}
	es = append(es, file("withheld file\n", "f", ""))
	s := setOf(b, ModeAudit, nil, es...)
	data := ordinaryText(4<<20 + 20*16<<10 + 100*1<<10)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		foundIn(s, []Part{{Where: "files[0].content", Data: data, Whole: true}})
	}
}

// Any input: the views never panic, and the work stays within the per-run bound.
func FuzzScanViews(f *testing.F) {
	for _, seed := range []string{"next=%3Fseed%3D731904", `"a<😀\x41\n"`, "QUJD\r\n  REVG%2B%2f\\/x",
		"/v1/" + b64URLText("\xfb\xef\xbe731904"), "%", `\`, `\u`, `\ud83d\u`} {
		f.Add([]byte(seed))
	}
	for _, data := range worstCases(64) {
		f.Add(data)
	}
	var entries []map[string]any
	for n := MinValueBytes; n <= 24; n++ {
		entries = append(entries, value(strings.Repeat("q", n), fmt.Sprintf("q%d", n), ""))
	}
	entries = append(entries, value("731904", "seed", ""), file("withheld file\n", "f", ""))
	s := setOf(f, ModeAudit, nil, entries...)
	f.Fuzz(func(t *testing.T, data []byte) {
		runs, blobCount := Runs(data), 0
		if u, _, ok := unescape(data); ok {
			runs += Runs(u)
		}
		base64Blobs(data, func(b []byte) { runs += Runs(b); blobCount++ })
		if hashes := s.scanViews(data, func(int) {}, nil); hashes > MaxValueRuns*runs+blobCount {
			t.Fatalf("%d hashes for %d runs and %d blobs", hashes, runs, blobCount)
		}
		foundIn(s, []Part{{Where: "code", Data: data, Whole: true}})
	})
}

// anyIn, a word at a time, says what asking each position would.
func TestBitsetAnyIn(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		n := r.IntN(300)
		b := newBitset(n)
		for range r.IntN(4) {
			b.set(r.IntN(n + 1))
		}
		lo := r.IntN(n + 1)
		hi := lo + r.IntN(n+2-lo)
		want := false
		for i := lo; i < hi; i++ {
			want = want || b.has(i)
		}
		if got := b.anyIn(lo, hi); got != want {
			t.Fatalf("anyIn(%d, %d) over %d = %v, want %v", lo, hi, n, got, want)
		}
	}
}
