package printable

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestText(t *testing.T) {
	for in, want := range map[string]string{
		"docker":                       "docker",
		"tab\there":                    `tab\x09here`,
		"\x1b[2K\rran\nok":             `\x1b[2K\x0dran\x0aok`,
		"del\x7f c1\u009b":             `del\x7f c1\x9b`,
		"rtl\u202eetc":                 `rtl\u202eetc`,
		"mark\u200e\u200f\u061c":       `mark\u200e\u200f\u061c`,
		"isolate\u2066x\u2069":         `isolate\u2066x\u2069`,
		"lines\u2028\u2029":            `lines\u2028\u2029`,
		"bad\xffutf8":                  `bad\xffutf8`,
		"accent é and … stay":          "accent é and … stay",
		`a backslash \x1b stays as is`: `a backslash \x1b stays as is`,
	} {
		got := Text(in)
		if got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
		if Text(got) != got {
			t.Errorf("Text is not idempotent on %q", got)
		}
		if strings.ContainsFunc(got, Escaped) {
			t.Errorf("Text(%q) still holds a character of the set: %q", in, got)
		}
	}
}

// Every code point of the set is escaped and none outside it, at each range's edges.
func TestEscapedIsTheSet(t *testing.T) {
	for _, r := range Ranges() {
		for _, c := range []rune{r[0], r[1]} {
			if !Escaped(c) || Text(string(c)) == string(c) {
				t.Errorf("U+%04X is in the set but not escaped", c)
			}
		}
		for _, c := range []rune{r[0] - 1, r[1] + 1} {
			if c >= 0 && !inSet(c) && Escaped(c) {
				t.Errorf("U+%04X is outside the set but escaped", c)
			}
		}
	}
}

func inSet(c rune) bool {
	for _, r := range Ranges() {
		if c >= r[0] && c <= r[1] {
			return true
		}
	}
	return false
}

// JSON escapes the set's characters inside strings only, as JSON escapes: the value a
// reader decodes is the same, the structure's own line breaks and indentation stay, and
// what a terminal is shown holds none of the set.
func TestJSON(t *testing.T) {
	value := map[string]any{
		"name\u202e":   "docker\u009b2K\u2028x",
		"plain":        "nothing to do",
		"quote":        `a "quoted" \ and \u202e as text`,
		"list":         []string{"del\x7f", "ok"},
		"number":       3,
		"nested":       map[string]string{"bidi": "\u2066x\u2069"},
		"html is fine": "<b>",
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got := JSON(data)
	if strings.ContainsFunc(string(got), func(r rune) bool { return Escaped(r) && r != '\n' }) {
		t.Fatalf("JSON left a character of the set: %q", got)
	}
	if strings.Count(string(got), "\n") != strings.Count(string(data), "\n") {
		t.Errorf("JSON changed the line breaks between values:\n%s", got)
	}
	var before, after any
	if err := json.Unmarshal(data, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &after); err != nil {
		t.Fatalf("JSON's output is not JSON: %v\n%s", err, got)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("JSON changed the value: %v, want %v", after, before)
	}
	if !strings.Contains(string(got), `"docker\u009b2K\u2028x"`) || !strings.Contains(string(got), `"name\u202e"`) {
		t.Errorf("JSON did not write the escapes: %s", got)
	}
	plain := []byte(`{"a": "b"}`)
	if out := JSON(plain); &out[0] != &plain[0] {
		t.Errorf("JSON copied text that needs no change")
	}
	// A byte that is not UTF-8 inside a string is what a JSON reader takes it for.
	if got := string(JSON([]byte("[\"a\xffb\"]"))); got != `["a\ufffdb"]` {
		t.Errorf("JSON of invalid UTF-8: %q", got)
	}
}
