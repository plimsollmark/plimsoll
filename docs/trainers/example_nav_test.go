package trainers

// Every published example page links back to the site's home page. The pages are
// written by several generators (three Go templates, the advisor report, and the
// environment report and index scripts), and a reader who arrives on one from a
// shared link otherwise has no way to the rest of the site. Checking the rendered
// pages rather than the generators catches a generator that loses the bar.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const siteHome = `href="https://plimsollmark.github.io/plimsoll/"`

func TestEveryExamplePageLinksHome(t *testing.T) {
	var pages int
	err := filepath.WalkDir(filepath.Join("..", "examples"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".html" {
			return err
		}
		pages++
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(body), siteHome) {
			t.Errorf("%s has no link to the site home (%s)", path, siteHome)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if pages < 13 {
		t.Fatalf("found %d example pages, want at least 13; the walk is not reading docs/examples", pages)
	}
}
