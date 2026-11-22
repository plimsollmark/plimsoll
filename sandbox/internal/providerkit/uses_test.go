package providerkit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ownCopies are the places allowed to keep a rule of their own, each with why it is not
// the shared one. A new entry needs a reason a reviewer can check.
var ownCopies = map[string]string{
	// The guest-side agent keeps a run-wide output budget shared by every stream of every
	// step and ends a flood; a Capture bounds one stream only.
	"lambdamicrovm/agent/run.go:capWriter": "a run-wide budget and flood stop, not one stream's cap",
}

// digestLiterals are the functions allowed to name the bare literal "sha256:", each with
// why it checks no digest. Anything else that names it is a digest rule of its own (a
// prefix test, a prefix cut before a hex decode), which ValidDigest is.
var digestLiterals = map[string]string{
	// Cuts an image ID to its first 12 digits for a message; the ID was checked by
	// ValidDigest when it was read (parseImageIDAndVolumes).
	"docker_preflight.go:shortImageID": "shortens a checked ID for a message",
}

// TestEveryProviderUsesTheKit fails when a provider under sandbox/ writes one of the kit's
// rules again instead of calling it: a regular expression or a literal for an image digest
// (PinnedDigest, ValidDigest, ReportedDigest; the literals "@sha256:" and "sha256:", the
// second outside digestLiterals: the docker preflight tested a manifest digest by
// HasPrefix "sha256:" and a hex decode, which accepts upper case, until finding
// release-43), random bytes hex-encoded by hand (RandHex),
// a timeout clamped by hand (ClampTimeout), or a capped output buffer of its own (Capture).
// Before 2026-11-18 the digest rule was written four times with two answers.
func TestEveryProviderUsesTheKit(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == "testdata" || rel == "internal/providerkit" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, problem := range kitBypasses(f, rel) {
			t.Errorf("sandbox/%s: %s", rel, problem)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// kitBypasses lists where f writes a kit rule of its own.
func kitBypasses(f *ast.File, rel string) []string {
	var problems []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && isPkg(sel.X, "regexp") && strings.HasPrefix(sel.Sel.Name, "MustCompile") || ok && isPkg(sel.X, "regexp") && sel.Sel.Name == "Compile" {
				for _, a := range n.Args {
					if s, ok := stringLit(a); ok && strings.Contains(s, "sha256") {
						problems = append(problems, "a regular expression for an image digest; use providerkit.PinnedDigest, ValidDigest or ReportedDigest")
					}
				}
			}
		case *ast.BasicLit:
			if s, ok := stringLit(n); ok && s == "@sha256:" {
				problems = append(problems, `the literal "@sha256:"; use providerkit.PinnedDigest`)
			}
		case *ast.FuncDecl:
			if n.Body != nil {
				problems = append(problems, funcBypasses(n.Body, returnsDuration(n.Type))...)
				if _, ok := digestLiterals[rel+":"+n.Name.Name]; !ok && namesDigestPrefix(n.Body) {
					problems = append(problems, n.Name.Name+` names the literal "sha256:", a digest rule of its own; use providerkit.ValidDigest`)
				}
			}
		case *ast.FuncLit:
			problems = append(problems, funcBypasses(n.Body, returnsDuration(n.Type))...)
		case *ast.TypeSpec:
			if st, ok := n.Type.(*ast.StructType); ok && isCapturer(st) {
				if _, ok := ownCopies[rel+":"+n.Name.Name]; !ok {
					problems = append(problems, "type "+n.Name.Name+" keeps a capped buffer of its own; use providerkit.Capture")
				}
			}
		}
		return true
	})
	return problems
}

// funcBypasses finds, in one function body, random bytes hex-encoded by hand and a
// timeout clamped by hand (a variable given a default under "if v <= 0" and later cut to
// a ceiling, by min or by "if v > ..."), in a function returning a time.Duration or on a
// variable whose name says it is a timeout.
func funcBypasses(body *ast.BlockStmt, duration bool) []string {
	var problems []string
	calls := map[string]bool{}
	defaulted := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false // checked on its own
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok {
					calls[id.Name+"."+sel.Sel.Name] = true
				}
			}
			if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "min" {
				for _, a := range n.Args {
					if v, ok := a.(*ast.Ident); ok && defaulted[v.Name] && (duration || timeoutName(v.Name)) {
						problems = append(problems, "a timeout clamped by hand ("+v.Name+"); use providerkit.ClampTimeout")
					}
				}
			}
		case *ast.IfStmt:
			v, op := comparedIdent(n.Cond)
			switch {
			case op == token.LEQ && assigns(n.Body, v):
				defaulted[v] = true
			case op == token.GTR && defaulted[v] && assigns(n.Body, v) && (duration || timeoutName(v)):
				problems = append(problems, "a timeout clamped by hand ("+v+"); use providerkit.ClampTimeout")
			}
		}
		return true
	})
	if calls["rand.Read"] && calls["hex.EncodeToString"] {
		problems = append(problems, "random bytes hex-encoded by hand; use providerkit.RandHex")
	}
	return problems
}

// namesDigestPrefix reports whether node holds the bare string literal "sha256:".
func namesDigestPrefix(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if s, ok := stringLit(asExpr(n)); ok && s == "sha256:" {
			found = true
		}
		return !found
	})
	return found
}

func asExpr(n ast.Node) ast.Expr {
	e, _ := n.(ast.Expr)
	return e
}

// TestTheGuardSeesADigestPrefixTest: the form the docker preflight used is found, and an
// allowed function is not.
func TestTheGuardSeesADigestPrefixTest(t *testing.T) {
	src := `package p
import "strings"
func ok(id string) bool { return strings.HasPrefix(id, "sha256:") && len(id) == 71 }
func shortImageID(id string) string { return "sha256:" + strings.TrimPrefix(id, "sha256:")[:12] }
`
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := kitBypasses(f, "docker_preflight.go")
	if len(got) != 1 || !strings.Contains(got[0], "ok names the literal") {
		t.Fatalf("problems %q; want one, for ok and not for the allowed shortImageID", got)
	}
}

func timeoutName(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "timeout") || name == "req" || name == "requested"
}

func returnsDuration(ft *ast.FuncType) bool {
	if ft.Results == nil || len(ft.Results.List) != 1 {
		return false
	}
	sel, ok := ft.Results.List[0].Type.(*ast.SelectorExpr)
	return ok && isPkg(sel.X, "time") && sel.Sel.Name == "Duration"
}

// comparedIdent is v and the operator of a condition "v <op> x".
func comparedIdent(cond ast.Expr) (string, token.Token) {
	b, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return "", token.ILLEGAL
	}
	id, ok := b.X.(*ast.Ident)
	if !ok {
		return "", token.ILLEGAL
	}
	return id.Name, b.Op
}

// assigns reports whether block assigns v directly.
func assigns(block *ast.BlockStmt, v string) bool {
	for _, st := range block.List {
		if as, ok := st.(*ast.AssignStmt); ok {
			for _, lhs := range as.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == v {
					return true
				}
			}
		}
	}
	return false
}

// isCapturer reports a struct with a size limit and a flag saying bytes were dropped:
// the shape of a capped output buffer.
func isCapturer(st *ast.StructType) bool {
	var limit, flag bool
	for _, field := range st.Fields.List {
		typ, ok := field.Type.(*ast.Ident)
		if !ok {
			continue
		}
		for _, name := range field.Names {
			n := strings.ToLower(name.Name)
			switch {
			case typ.Name == "int" && (n == "limit" || n == "max" || n == "cap"):
				limit = true
			case typ.Name == "bool" && (strings.Contains(n, "dropped") || strings.Contains(n, "truncated")):
				flag = true
			}
		}
	}
	return limit && flag
}

func isPkg(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}
