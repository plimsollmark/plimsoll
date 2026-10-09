package trainers

// Every published example, measurement and integration page links back to the site's home
// page. The pages are written by several generators (three Go templates, the advisor report,
// the environment report and index scripts, and the integration pages' build), and a reader who arrives on one from a
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
	// The example pages, the measurement pages written the same way, and the integration
	// pages (one per framework plus their index).
	for dir, want := range map[string]int{"examples": 13, "measurements": 2, "integrations": 7} {
		var pages int
		err := filepath.WalkDir(filepath.Join("..", dir), func(path string, d fs.DirEntry, err error) error {
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
		if pages < want {
			t.Fatalf("found %d pages in docs/%s, want at least %d; the walk is not reading it", pages, dir, want)
		}
	}
}
