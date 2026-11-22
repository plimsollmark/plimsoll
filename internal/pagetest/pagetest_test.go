package pagetest

import (
	"reflect"
	"strings"
	"testing"
)

const tmpl = "<h1>{{.Title}}</h1>\n<p>The first sentence.</p>\n<p>The second sentence.</p>\n{{range .Rows}}<td>{{.}}</td>{{end}}\n<footer>The end.</footer>\n"

func TestLiteralsAreTheTextBetweenActions(t *testing.T) {
	got := Literals(tmpl)
	want := []string{"<h1>", "</h1>\n<p>The first sentence.</p>\n<p>The second sentence.</p>\n", "<td>", "</td>", "\n<footer>The end.</footer>\n"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Literals = %q, want %q", got, want)
	}
	if got := Literals("{{.A}} {{.B}}"); got != nil {
		t.Fatalf("white space between actions is not a literal run: %q", got)
	}
	if got := Literals("<p>{{.A</p>"); !reflect.DeepEqual(got, []string{"<p>"}) {
		t.Fatalf("the text after an unterminated action is dropped: %q", got)
	}
}

func TestMissing(t *testing.T) {
	page := "<h1>A page</h1>\n<p>The first sentence.</p>\n<p>The second sentence.</p>\n<td>1</td><td>2</td>\n<footer>The end.</footer>\n"
	if missing, ok := Missing(tmpl, page); !ok {
		t.Fatalf("a page written from the template lacks %q", missing)
	}
	edited := strings.Replace(page, "The second sentence.", "The second sentence, edited.", 1)
	if missing, ok := Missing(tmpl, edited); ok || missing != "<p>The second sentence.</p>" {
		t.Fatalf("an edited sentence: Missing = %q, %t; want the template's line and false", missing, ok)
	}
	swapped := strings.Replace(page, "<p>The first sentence.</p>\n<p>The second sentence.</p>", "<p>The second sentence.</p>\n<p>The first sentence.</p>", 1)
	if missing, ok := Missing(tmpl, swapped); ok || missing != "</h1> <p>The first sentence.</p> <p>The second sentence.</p>" {
		t.Fatalf("two lines swapped: Missing = %q, %t; want the whole run on one line and false", missing, ok)
	}
	moved := "<footer>The end.</footer>\n" + strings.Replace(page, "\n<footer>The end.</footer>\n", "\n", 1)
	if missing, ok := Missing(tmpl, moved); ok || missing != "<footer>The end.</footer>" {
		t.Fatalf("the last run moved first: Missing = %q, %t; want that run and false", missing, ok)
	}
	if missing, ok := Missing("<p>one</p>{{.X}}<p>two</p>", "<p>two</p> x <p>one</p>"); ok || missing != "<p>two</p>" {
		t.Fatalf("two runs, each present, in the wrong order: Missing = %q, %t; want the later run and false", missing, ok)
	}
	long := "<p>" + strings.Repeat("x", 200) + "</p>"
	if missing, ok := Missing(long, ""); ok || missing != long[:160]+"…" {
		t.Fatalf("a long line: Missing = %q, %t; want it cut at 160 characters", missing, ok)
	}
}
