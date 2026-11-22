package rpc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryDocCommentNamesItsFunction: a function's doc comment starts with the
// function's own name (Go's convention, and what go doc shows under it). Two comments in
// sandbox_service.go sat on the wrong functions, wireString's on publicEndDetail and
// runRecord's on recordEnd, so go doc showed each under another name (finding
// release-44).
func TestEveryDocCommentNamesItsFunction(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Doc == nil {
				continue
			}
			text := fn.Doc.Text()
			if !strings.HasPrefix(text, fn.Name.Name+" ") && !strings.HasPrefix(text, fn.Name.Name+":") {
				line, _, _ := strings.Cut(text, "\n")
				t.Errorf("%s: the doc comment of %s starts %q, not with its name", fset.Position(fn.Pos()), fn.Name.Name, line)
			}
		}
	}
}
