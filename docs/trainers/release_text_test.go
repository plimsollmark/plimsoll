package trainers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The two client READMEs are also the package pages PyPI and npm show, where a link
// relative to this repository resolves to nothing. A link there names its full URL.
func TestPackageReadmesLinkAbsolutely(t *testing.T) {
	link := regexp.MustCompile(`\]\(([^)\s]+)|(?:href|src)="([^"]+)"`)
	for _, f := range []string{"clients/python/README.md", "clients/typescript/README.md"} {
		raw, err := os.ReadFile(filepath.Join(repoRoot, f))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range link.FindAllStringSubmatch(string(raw), -1) {
			target := m[1] + m[2]
			if strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "http://") ||
				strings.HasPrefix(target, "#") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			t.Errorf("%s links to %q, which resolves to nothing on its package page; use the full https://github.com/plimsollmark/plimsoll/blob/main/... URL", f, target)
		}
	}
}

// A sentence saying something is "not yet released" goes false the day it ships, and
// nothing then flags it (three did, in the 0.20.0 release review). A document names the
// version a thing ships in instead.
func TestNoUnversionedReleaseStatus(t *testing.T) {
	stale := regexp.MustCompile(`(?i)not (yet )?(been )?released|until a release contains it|is in the source checkout|not yet (on|published to) (pypi|npm)`)
	var docs []string
	for _, pattern := range []string{"*.md", "docs/*.md", "docs/*/*.md", "clients/*/README.md", "examples/*/README.md", "e2b/README.md"} {
		matches, err := filepath.Glob(filepath.Join(repoRoot, pattern))
		if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, matches...)
	}
	if len(docs) < 10 {
		t.Fatalf("found only %d documents to check; the globs no longer match the tree", len(docs))
	}
	for _, d := range docs {
		raw, err := os.ReadFile(d)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if m := stale.FindString(line); m != "" {
				rel, _ := filepath.Rel(repoRoot, d)
				t.Errorf("%s:%d says %q; name the version it ships in instead", rel, i+1, m)
			}
		}
	}
}
