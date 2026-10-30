package trainers

// A link an example page builds in its browser from data it carries (the Nemotron page's
// batch squares hold each session's transcript, receipts and public key in a data-c
// attribute, and the page's script writes the links when a square is clicked) is a link
// no static check reads: the export's link check follows href and src as written, and
// skips a value that is JavaScript joining strings. This test reads those paths from the
// data itself and requires each to be a file beside the page.

import (
	"encoding/json"
	"html"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	dataAttr = regexp.MustCompile(`\sdata-[a-z0-9-]+=(?:'([^']*)'|"([^"]*)")`)
	// A relative file path as a page's data writes one: no scheme, no spaces, no quotes.
	dataPath  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]*$`)
	linkedExt = map[string]bool{".json": true, ".jsonl": true, ".pub": true, ".gz": true, ".html": true, ".png": true, ".svg": true, ".csv": true, ".txt": true}
)

func TestExamplePageDataLinksResolve(t *testing.T) {
	var checked int
	err := filepath.WalkDir(filepath.Join("..", "examples"), func(page string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(page) != ".html" {
			return err
		}
		body, err := os.ReadFile(page)
		if err != nil {
			return err
		}
		for _, m := range dataAttr.FindAllStringSubmatch(string(body), -1) {
			value := html.UnescapeString(m[1] + m[2])
			if !strings.HasPrefix(value, "{") && !strings.HasPrefix(value, "[") {
				continue
			}
			var data any
			if json.Unmarshal([]byte(value), &data) != nil {
				continue
			}
			for _, s := range dataStrings(data) {
				if !dataPath.MatchString(s) || !linkedExt[path.Ext(s)] || strings.Contains(s, "..") {
					continue
				}
				checked++
				if _, err := os.Stat(filepath.Join(filepath.Dir(page), filepath.FromSlash(s))); err != nil {
					t.Errorf("%s: its data links %s, which is not a file beside the page", page, s)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The Nemotron page alone carries three such links for each of its 120 batch sessions.
	if checked < 300 {
		t.Fatalf("checked %d data links in docs/examples, want at least 300; the scan is not reading the pages' data", checked)
	}
}

// dataStrings is every string in a decoded JSON value.
func dataStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, dataStrings(e)...)
		}
		return out
	case map[string]any:
		var out []string
		for _, e := range x {
			out = append(out, dataStrings(e)...)
		}
		return out
	}
	return nil
}
