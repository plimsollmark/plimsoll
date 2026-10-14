package rpc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Same-day budget tests start at noon. Midnight tests add explicit offsets.
func fixedSpendTestTime() time.Time { return time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC) }

// Follow local clock seeds and aliases as well as a direct time.Now assignment.
// This is a source guard, not a general-purpose interprocedural Go analyzer.
func wallClockAssignments(f *ast.File) []token.Pos {
	timeNames := map[string]bool{}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if path == "time" {
			name := "time"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			timeNames[name] = true
		}
	}
	var bad []token.Pos
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		tainted := map[string]bool{}
		usesWall := func(n ast.Node) bool {
			found := false
			ast.Inspect(n, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && tainted[id.Name] {
					found = true
				}
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Now" {
					if id, ok := sel.X.(*ast.Ident); ok && timeNames[id.Name] {
						found = true
					}
				}
				return true
			})
			return found
		}
		// Fixed point handles clock variables assigned after installing a closure.
		for changed := true; changed; {
			changed = false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				seed := func(id *ast.Ident, rhs ast.Node) {
					if !tainted[id.Name] && usesWall(rhs) {
						tainted[id.Name], changed = true, true
					}
				}
				switch x := n.(type) {
				case *ast.AssignStmt:
					for i, lhs := range x.Lhs {
						if id, ok := lhs.(*ast.Ident); ok && i < len(x.Rhs) {
							seed(id, x.Rhs[i])
						}
					}
				case *ast.ValueSpec:
					for i, id := range x.Names {
						if i < len(x.Values) {
							seed(id, x.Values[i])
						}
					}
				}
				return true
			})
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if a, ok := n.(*ast.AssignStmt); ok {
				for i, lhs := range a.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "now" || i >= len(a.Rhs) {
						continue
					}
					isSpend := false
					switch receiver := sel.X.(type) {
					case *ast.Ident:
						isSpend = receiver.Name == "c"
					case *ast.SelectorExpr:
						isSpend = receiver.Sel.Name == "Spend"
					}
					if isSpend && usesWall(a.Rhs[i]) {
						bad = append(bad, lhs.Pos())
					}
				}
			}
			return true
		})
	}
	return bad
}

func TestSpendTestClocksNeverUseWallTime(t *testing.T) {
	paths, err := filepath.Glob("*_test.go")
	if err != nil || len(paths) == 0 {
		t.Fatalf("test sources: %v, %v", paths, err)
	}
	fs := token.NewFileSet()
	for _, path := range paths {
		f, err := parser.ParseFile(fs, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, pos := range wallClockAssignments(f) {
			t.Errorf("%s: spend clock uses wall time; seed it from fixedSpendTestTime", fs.Position(pos))
		}
	}
}

func TestSpendClockGuardFollowsSeedsAndAliases(t *testing.T) {
	for _, body := range []string{
		"c.now = time.Now", "svc.Spend.now = func() time.Time { return time.Now() }",
		"clock := time.Now(); c.now = func() time.Time { return clock }",
		"seed := time.Now; clock := seed(); svc.Spend.now = func() time.Time { return clock }",
		"var clock = time.Now(); c.now = func() time.Time { return clock }",
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", "package rpc; import \"time\"; func f() {"+body+"}", 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(wallClockAssignments(f)) != 1 {
			t.Fatalf("guard missed %s", body)
		}
	}
	f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", "package rpc; import \"time\"; func f() { clock := fixedSpendTestTime(); c.now = func() time.Time { return clock }; deadline := time.Now() }", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wallClockAssignments(f)) != 0 {
		t.Fatal("guard confused a polling deadline with a spend clock")
	}
}
