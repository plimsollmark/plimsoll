package server_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
)

// A receipts directory that fails for real (made read-only under an open sandbox) shows
// in the answers as what failed, never as the directory's path: over serve-http the model
// reading them is a vendor's, and the path names the owner's home and user name. A
// session file's reason once carried the operating system's error as text, path and all
// (hunt-security-24).
func TestNoAnswerShowsTheReceiptsDirectorysPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, dir := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	var answers []string
	call := func(name string, args map[string]any) {
		answers = append(answers, text(c.call(name, args)))
	}
	call("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	call("run_code", map[string]any{"code": "x", "sandbox": h})
	call("close_sandbox", map[string]any{"sandbox": h})
	call("run_code", map[string]any{"code": "print(1)"})
	call("open_sandbox", nil)
	if !strings.Contains(answers[1], "could not be created") {
		t.Fatalf("the second sandbox call does not say its session's receipt file could not be created: %s", answers[1])
	}
	for _, root := range []string{dir, filepath.Dir(dir)} {
		for i, a := range answers {
			if strings.Contains(a, root) {
				t.Errorf("answer %d names %s: %s", i, root, a)
			}
		}
	}
}

// No reason is built by formatting an error as text (%v or %s of a variable named err or
// ending in err), which keeps the path an operating system's error names out of the reach
// of shown: an error is wrapped with %w, or passed through shown or reasonOf. A panic's
// message is a programming error, never an answer, and is not held to it.
func TestNoErrorIsFormattedIntoText(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "panic" {
				return false
			}
			// Where each formatting function's format is: fmt's, and refused's, which
			// formats a refusal's summary.
			at := -1
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if pkg, ok := fn.X.(*ast.Ident); ok && pkg.Name == "fmt" && (fn.Sel.Name == "Sprintf" || fn.Sel.Name == "Errorf") {
					at = 0
				}
			case *ast.Ident:
				if fn.Name == "refused" {
					at = 1
				}
			}
			if at < 0 || len(call.Args) <= at {
				return true
			}
			lit, ok := call.Args[at].(*ast.BasicLit)
			if !ok {
				return true
			}
			format, _ := strconv.Unquote(lit.Value)
			for i, verb := range verbs(format) {
				if at+i+1 >= len(call.Args) || verb == 'w' {
					continue
				}
				if id, ok := call.Args[at+i+1].(*ast.Ident); ok && strings.HasSuffix(strings.ToLower(id.Name), "err") {
					t.Errorf("%s: %%%c of %s formats an error into text; wrap it with %%w or pass it through shown", fset.Position(call.Pos()), verb, id.Name)
				}
			}
			return true
		})
	}
}

// verbs is format's verbs in order, %% left out.
func verbs(format string) []rune {
	var out []rune
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		for i < len(format) && strings.ContainsRune("+-# 0123456789.*[]", rune(format[i])) {
			i++
		}
		if i < len(format) && format[i] != '%' {
			out = append(out, rune(format[i]))
		}
	}
	return out
}
