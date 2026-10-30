package withheld

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
)

func hexOf(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func valueHex(v string) string {
	d := ValueDigest([]byte(v))
	return hex.EncodeToString(d[:])
}

func fileHex(b []byte) string {
	d := FileDigest(b)
	return hex.EncodeToString(d[:])
}

// setOf builds a set file from entries given as maps, so a test states only what it
// is about.
func setOf(t testing.TB, mode Mode, exempt []string, entries ...map[string]any) *Set {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"version": Version, "mode": mode, "exempt_callers": exempt, "entries": entries})
	if err != nil {
		t.Fatal(err)
	}
	s, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, raw)
	}
	return s
}

func value(v, label string, mode Mode) map[string]any {
	m := map[string]any{"kind": "value", "sha256": valueHex(v), "length": len(v), "label": label}
	if mode != "" {
		m["mode"] = mode
	}
	return m
}

func file(content, label string, mode Mode) map[string]any {
	m := map[string]any{"kind": "file", "sha256": fileHex([]byte(content)), "label": label}
	if mode != "" {
		m["mode"] = mode
	}
	return m
}

func labels(found []Finding) []string {
	var out []string
	for _, f := range found {
		out = append(out, f.Label)
	}
	return out
}

// foundIn scans parts and returns what was found; a test whose scan stops or is
// incomplete fails.
func foundIn(s *Set, parts []Part) []Finding {
	res, err := s.Scan(context.Background(), parts)
	if err != nil || len(res.Incomplete) > 0 {
		panic(fmt.Sprintf("scan: %v, incomplete %v", err, res.Incomplete))
	}
	return res.Found
}

// The hackathon's two leaks, replayed: the simulator's source shipped into the sandbox
// under another name, and a practice seed in an example URL inside a viewer file.
func TestScanFindsTheHackathonLeaks(t *testing.T) {
	sim := "import numpy as np\n\ndef step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n"
	set := setOf(t, ModeRefuse, nil,
		file(sim, "harness/sim.py", ""),
		value("731904", "practice-seeds.txt:3", ModeAudit))
	viewer := []byte(`<a href="viewer.html?seed=731904&case=2">example flight</a>`)
	shipped := strings.ReplaceAll(sim, "\n", "\r\n") + "  \n\n"
	found := foundIn(set, []Part{
		{Where: "files[0].path", Data: []byte("helpers/model.py")},
		{Where: "files[0].content", Data: []byte(shipped), Whole: true},
		{Where: "files[1].path", Data: []byte("viewer.html")},
		{Where: "files[1].content", Data: viewer, Whole: true},
	})
	want := []Finding{
		{Label: "harness/sim.py", Mode: ModeRefuse, Where: []string{"files[0].content"}},
		{Label: "practice-seeds.txt:3", Mode: ModeAudit, Where: []string{"files[1].content"}},
	}
	if !reflect.DeepEqual(found, want) {
		t.Fatalf("found %+v, want %+v", found, want)
	}
}

func TestValueIsFoundOnlyAsWholeRuns(t *testing.T) {
	set := setOf(t, ModeAudit, nil,
		value("48213", "seed", ""),
		value("0.7321", "answer", ""),
		value("8c1f0e2a-4b7d-4f1e-9a3c-5d6e7f809a1b", "uuid", ""))
	for _, tc := range []struct {
		text string
		want []string
	}{
		{"viewer.html?seed=48213&x=1", []string{"seed"}},
		{"seed_48213", []string{"seed"}},
		{"48213", []string{"seed"}},
		{"(48213)", []string{"seed"}},
		{"148213", nil},
		{"48213a", nil},
		{"4821 3", nil},
		{`{"answer": 0.7321}`, []string{"answer"}},
		{"x=0.7321.", []string{"answer"}},
		{"10.7321", nil},
		{"0.73210", nil},
		{"id: 8c1f0e2a-4b7d-4f1e-9a3c-5d6e7f809a1b\n", []string{"uuid"}},
		{"id: 8C1F0E2A-4b7d-4f1e-9a3c-5d6e7f809a1b\n", []string{"uuid"}}, // any letter case
		{"48213 and 0.7321", []string{"seed", "answer"}},
	} {
		got := labels(foundIn(set, []Part{{Where: "code", Data: []byte(tc.text)}}))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: found %v, want %v", tc.text, got, tc.want)
		}
	}
}

func TestFileIsFoundUnderNormalization(t *testing.T) {
	src := "line one\nline two\n"
	set := setOf(t, ModeRefuse, nil, file(src, "src", ""))
	for _, tc := range []struct {
		name  string
		data  string
		whole bool
		want  bool
	}{
		{"as written", src, true, true},
		{"CRLF", "line one\r\nline two\r\n", true, true},
		{"trailing whitespace", "line one \t\nline two\n\n\n", true, true},
		{"no final newline", "line one\nline two", true, true},
		{"one byte changed", "line one\nline twO\n", true, false},
		{"leading whitespace kept", " line one\nline two\n", true, false},
		{"not a whole part", src, false, false},
	} {
		found := foundIn(set, []Part{{Where: "files[0].content", Data: []byte(tc.data), Whole: tc.whole}})
		if (len(found) == 1) != tc.want {
			t.Errorf("%s: found %v, want %v", tc.name, found, tc.want)
		}
	}
	if !bytes.Equal(Normalize([]byte("a \r\n\r\nb\t\r\n\n")), []byte("a\n\nb")) {
		t.Errorf("Normalize = %q", Normalize([]byte("a \r\n\r\nb\t\r\n\n")))
	}
}

func TestScanStatesEveryPlaceOnceInOrder(t *testing.T) {
	set := setOf(t, ModeAudit, nil, value("seed731904", "s", ""))
	found := foundIn(set, []Part{
		{Where: "steps[0]", Data: []byte("run --seed seed731904 --again seed731904")},
		{Where: "files[0].path", Data: []byte("cases/seed731904.json")},
		{Where: "files[0].content", Data: []byte("nothing"), Whole: true},
		{Where: "artifacts[0]", Data: []byte("out/seed731904")},
	})
	if len(found) != 1 || !reflect.DeepEqual(found[0].Where, []string{"steps[0]", "files[0].path", "artifacts[0]"}) {
		t.Fatalf("found %+v", found)
	}
}

func TestModesAndExemption(t *testing.T) {
	set := setOf(t, ModeRefuse, []string{"judge"}, value("abcdef12", "a", ""), value("abcdef34", "b", ModeAudit))
	found := foundIn(set, []Part{{Where: "code", Data: []byte("abcdef12 abcdef34")}})
	if len(found) != 2 || found[0].Mode != ModeRefuse || found[1].Mode != ModeAudit {
		t.Fatalf("modes: %+v", found)
	}
	if !set.Exempt("judge") || set.Exempt("") || set.Exempt("agent") || set.Exempt("*") {
		t.Error("exemption: only the listed, authenticated caller is exempt")
	}
	if set.Len() != 2 || set.ExemptCount() != 1 {
		t.Errorf("Len %d, ExemptCount %d", set.Len(), set.ExemptCount())
	}
}

func TestParseRefusesWhatItDoesNotUnderstand(t *testing.T) {
	good := value("abcdef12", "a", "")
	encode := func(m map[string]any) string { b, _ := json.Marshal(m); return string(b) }
	set := func(mutate func(m map[string]any)) string {
		m := map[string]any{"version": Version, "mode": "refuse", "entries": []any{good}}
		mutate(m)
		return encode(m)
	}
	entry := func(mutate func(e map[string]any)) string {
		e := value("abcdef12", "a", "")
		mutate(e)
		return set(func(m map[string]any) { m["entries"] = []any{e} })
	}
	for _, tc := range []struct{ name, raw string }{
		{"version", set(func(m map[string]any) { m["version"] = 1 })},
		{"version 3", set(func(m map[string]any) { m["version"] = 3 })},
		{"no mode", set(func(m map[string]any) { delete(m, "mode") })},
		{"bad mode", set(func(m map[string]any) { m["mode"] = "block" })},
		// warn waits for the response to state the scan; until then it would be audit.
		{"warn", set(func(m map[string]any) { m["mode"] = "warn" })},
		{"no entries", set(func(m map[string]any) { m["entries"] = []any{} })},
		{"unknown field", set(func(m map[string]any) { m["exempt"] = []string{"judge"} })},
		{"trailing data", set(func(map[string]any) {}) + "{}"},
		{"exempt star", set(func(m map[string]any) { m["exempt_callers"] = []string{"*"} })},
		{"exempt empty", set(func(m map[string]any) { m["exempt_callers"] = []string{""} })},
		{"exempt padded", set(func(m map[string]any) { m["exempt_callers"] = []string{" judge"} })},
		{"exempt twice", set(func(m map[string]any) { m["exempt_callers"] = []string{"judge", "judge"} })},
		{"duplicate digest", set(func(m map[string]any) { m["entries"] = []any{good, value("abcdef12", "b", "")} })},
		{"uppercase digest", entry(func(e map[string]any) { e["sha256"] = strings.ToUpper(e["sha256"].(string)) })},
		{"short digest", entry(func(e map[string]any) { e["sha256"] = "abcd" })},
		{"not hex", entry(func(e map[string]any) { e["sha256"] = strings.Repeat("zz", 32) })},
		{"value too short", entry(func(e map[string]any) { e["length"] = 3 })},
		{"value too long", entry(func(e map[string]any) { e["length"] = 257 })},
		{"value without length", entry(func(e map[string]any) { delete(e, "length") })},
		{"file with length", entry(func(e map[string]any) { e["kind"] = "file" })},
		// It would match every empty file a caller ships (__init__.py, .gitkeep).
		{"empty file", set(func(m map[string]any) { m["entries"] = []any{file("\n \n", "empty", "")} })},
		{"unknown kind", entry(func(e map[string]any) { e["kind"] = "source" })},
		{"bad entry mode", entry(func(e map[string]any) { e["mode"] = "silent" })},
		{"label with a space", entry(func(e map[string]any) { e["label"] = "seed 3" })},
		{"empty label", entry(func(e map[string]any) { e["label"] = "" })},
		{"long label", entry(func(e map[string]any) { e["label"] = strings.Repeat("a", 129) })},
	} {
		if _, err := Parse([]byte(tc.raw)); err == nil {
			t.Errorf("%s: Parse accepted %s", tc.name, tc.raw)
		}
	}
	s, err := Parse([]byte(set(func(map[string]any) {})))
	if err != nil {
		t.Fatal(err)
	}
	if s.Digest() != hexOf([]byte(set(func(map[string]any) {}))) {
		t.Error("the set's digest is the SHA-256 of the file as loaded")
	}
}

func TestCheckValue(t *testing.T) {
	for _, tc := range []struct {
		v   string
		min int
		ok  bool
	}{
		{"731904", 6, true},
		{"73190", 6, false},
		{"7319", 4, true},
		{"731", 3, false}, // below the floor the daemon accepts
		{"-0.5e3", 4, false},
		{"0.5e3.", 4, false},
		{"0.5e3", 4, true},
		{"a-b-c-d-e-f-g-h", 6, true},
		{"a-b-c-d-e-f-g-h-i", 6, false},
		{strings.Repeat("9", 256), 6, true},
		{strings.Repeat("9", 257), 6, false},
	} {
		if err := CheckValue([]byte(tc.v), tc.min); (err == nil) != tc.ok {
			t.Errorf("CheckValue(%q, %d) = %v, want ok %v", tc.v, tc.min, err, tc.ok)
		}
	}
}

// naiveValues is the definition scanValues implements, written the slow way: every
// span that starts a run, ends a run and covers at most MaxValueRuns of them.
func naiveValues(s *Set, data []byte) []int {
	var found []int
	for i := range data {
		if !word(data[i]) || (i > 0 && word(data[i-1])) {
			continue
		}
		for j := i + 1; j <= len(data); j++ {
			if !word(data[j-1]) || (j < len(data) && word(data[j])) {
				continue
			}
			if Runs(data[i:j]) > MaxValueRuns || j-i > MaxValueBytes || !s.lengths[j-i] {
				continue
			}
			if e, ok := s.values[ValueDigest(data[i:j])]; ok {
				found = append(found, e)
			}
		}
	}
	return found
}

func TestScanValuesMatchesItsDefinition(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	alphabet := []byte("ab1.- _")
	for range 300 {
		data := make([]byte, 40+r.IntN(80))
		for i := range data {
			data[i] = alphabet[r.IntN(len(alphabet))]
		}
		// Withhold a few spans of the data itself, so finds happen.
		var entries []map[string]any
		seen := map[string]bool{}
		for range 4 {
			i, n := r.IntN(len(data)-12), 4+r.IntN(8)
			v := string(data[i : i+n])
			if CheckValue([]byte(v), MinValueBytes) != nil || seen[v] {
				continue
			}
			seen[v] = true
			entries = append(entries, value(v, fmt.Sprintf("v%d", len(entries)), ""))
		}
		if len(entries) == 0 {
			continue
		}
		s := setOf(t, ModeAudit, nil, entries...)
		var fast []int
		s.scanValues(data, func(e int) { fast = append(fast, e) })
		count := func(es []int) map[int]int {
			m := map[int]int{}
			for _, e := range es {
				m[e]++
			}
			return m
		}
		if slow := naiveValues(s, data); !reflect.DeepEqual(count(fast), count(slow)) {
			t.Fatalf("data %q: scan found %v, definition %v", data, fast, slow)
		}
	}
}

// The scan's work is at most MaxValueRuns hashes per run, whatever the set declares:
// the worst request the daemon accepts costs a bounded amount of one core. Runs of
// one letter between dots, with every length declared, are that worst case: every
// span of runs long enough has a declared length.
func TestScanWorkIsBoundedPerRun(t *testing.T) {
	var entries []map[string]any
	for n := MinValueBytes; n <= MaxValueBytes; n++ {
		entries = append(entries, value(strings.Repeat("q", n), fmt.Sprintf("q%d", n), ""))
	}
	s := setOf(t, ModeAudit, nil, entries...)
	data := bytes.Repeat([]byte("a."), 1<<16)
	runs := Runs(data)
	hashes := s.scanValues(data, func(int) { t.Fatal("nothing here is withheld") })
	if hashes > MaxValueRuns*runs {
		t.Fatalf("%d hashes for %d runs", hashes, runs)
	}
	// Spans of 3 to 8 runs are at least MinValueBytes long; the first runs end fewer.
	if want := 6*runs - (2 + 3 + 4 + 5 + 6 + 7); hashes != want {
		t.Fatalf("%d hashes for %d runs, want %d", hashes, runs, want)
	}
}

func BenchmarkScanWorstCase(b *testing.B) {
	var es []any
	for n := MinValueBytes; n <= MaxValueBytes; n++ {
		v := strings.Repeat("q", n)
		es = append(es, map[string]any{"kind": "value", "sha256": valueHex(v), "length": n, "label": fmt.Sprintf("q%d", n)})
	}
	raw, _ := json.Marshal(map[string]any{"version": Version, "mode": "audit", "entries": es})
	s, err := Parse(raw)
	if err != nil {
		b.Fatal(err)
	}
	// The most a call carries: a project's files (sandbox.MaxProjectBytes, 4 MiB), its
	// steps (MaxProjectSteps of MaxProjectStepBytes, 20 of 16 KiB) and its artifact paths
	// (MaxProjectArtifacts of MaxProjectPathBytes, 100 of 1 KiB). A cell carries less.
	const most = 4<<20 + 20*16<<10 + 100*1<<10
	data := bytes.Repeat([]byte("a."), most/2)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		foundIn(s, []Part{{Where: "files[0].content", Data: data, Whole: true}})
	}
}
