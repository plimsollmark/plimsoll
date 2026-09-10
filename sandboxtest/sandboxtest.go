// Package sandboxtest provides shared test helpers for projects that embed the
// plimsoll sandbox, so the cross-cutting guarantees are asserted by ONE
// implementation here instead of being copy-pasted into every consumer's tests.
//
// The host-isolation guarantee (a snippet cannot reach the host filesystem, env,
// or network) is a property of the plimsoll engine and is tested once in
// plimsoll/sandbox — consumers do not need to re-test it. What each consumer
// DOES need, because each is a separate Go module, is a per-module check that it
// never reintroduces the banned qjs dependency; RequireNoQJS is that check, so the
// scan logic lives here and each consumer calls it in a one-line test.
package sandboxtest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// BannedQJS must never be imported: its MemoryLimit is a no-op, so it cannot bound
// memory. Use plimsoll/sandbox (wazero, with a real per-run cap) instead.
const BannedQJS = "github.com/fastschema/qjs"

// RequireNoQJS fails t if the module under test imports BannedQJS. Call it from a
// one-line test in each consumer:
//
//	func TestNoBannedQJSDependency(t *testing.T) { sandboxtest.RequireNoQJS(t) }
func RequireNoQJS(t testing.TB) { RequireNoImport(t, BannedQJS) }

// RequireNoImport fails t if modulePath (or a subpackage of it) is imported by the
// module under test. It locates the calling module via `go env GOMOD` and checks
// it two ways: an AST import scan of every .go file (build-tag- and _test.go-
// agnostic, ignores comments/strings, needs no toolchain — the load-bearing check)
// and a best-effort `go list -test -deps` for transitive deps.
func RequireNoImport(t testing.TB, modulePath string) {
	t.Helper()
	root := moduleRoot(t)

	var hits []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if perr != nil {
			return nil
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == modulePath || strings.HasPrefix(path, modulePath+"/") {
				hits = append(hits, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("source scan failed: %v", err)
	}
	if len(hits) > 0 {
		t.Fatalf("%s is imported (banned — use plimsoll/sandbox) in:\n  %s", modulePath, strings.Join(hits, "\n  "))
	}

	cmd := exec.Command("go", "list", "-mod=mod", "-test", "-deps", "./...")
	cmd.Dir = root
	out, lerr := cmd.Output()
	if strings.Contains(string(out), modulePath) {
		t.Fatalf("%s is in the transitive dependency graph — banned", modulePath)
	}
	if lerr != nil {
		t.Logf("note: transitive `go list` check did not run (%v); the AST scan still enforced the ban", lerr)
	}
}

func moduleRoot(t testing.TB) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Skipf("cannot locate module root: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		t.Skip("not in a module; skipping dependency ban check")
	}
	return filepath.Dir(gomod)
}
