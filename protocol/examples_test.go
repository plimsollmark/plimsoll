package protocol

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// requestProtocol matches the protocol field of a request or answer written out as JSON,
// the form a reader copies from an example ({"protocol": 8, ...}).
var requestProtocol = regexp.MustCompile(`"protocol":\s*([0-9]+)`)

// readerCopies says whether path (relative to the module root) is text a reader copies a
// request from: the published documents (docs/*.md), the trainers' pages, every README
// outside private/, and the comments of non-test Go files. Rendered example pages
// (docs/examples/) show runs recorded under the release that made them, tests send old
// numbers on purpose, and private scripts are finding release-18's.
func readerCopies(path string) bool {
	path = filepath.ToSlash(path)
	switch {
	case strings.HasPrefix(path, "private/"), strings.Contains(path, "/testdata/"), strings.HasPrefix(path, "docs/examples/"):
		return false
	case strings.HasPrefix(path, "docs/") && !strings.Contains(strings.TrimPrefix(path, "docs/"), "/") && strings.HasSuffix(path, ".md"):
		return true
	case strings.HasPrefix(path, "docs/trainers/") && strings.HasSuffix(path, ".html"):
		return true
	case filepath.Base(path) == "README.md":
		return true
	case strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go"):
		return true
	}
	return false
}

// TestExamplesSendTheCurrentProtocol: every request or answer written out where a reader
// copies it (readerCopies) carries Number, so a request copied from an example is not
// refused for an old protocol. Two published examples still sent protocol 7 after the bump
// to 8, and the quick-start trainer's curl line protocol 2 (found 2026-11-24 while the
// release notes were drafted).
func TestExamplesSendTheCurrentProtocol(t *testing.T) {
	skipDirs := map[string]bool{".git": true, ".claude": true, "node_modules": true, "tmp": true, "gen": true, "dist": true}
	checked := 0
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel("..", path)
		if d.IsDir() {
			if skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".venv") {
				return filepath.SkipDir
			}
			return nil
		}
		if !readerCopies(rel) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range requestProtocol.FindAllSubmatchIndex(b, -1) {
			checked++
			n, _ := strconv.Atoi(string(b[m[2]:m[3]]))
			if uint32(n) != Number {
				line := 1 + strings.Count(string(b[:m[0]]), "\n")
				t.Errorf("%s:%d says protocol %d; this module speaks %d", rel, line, n, Number)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no protocol field found where a reader copies one; the walk no longer reaches the documents")
	}
}
