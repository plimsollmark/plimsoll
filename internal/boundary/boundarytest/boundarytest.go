// Package boundarytest holds a provider's smoke code to its boundary declaration without
// running it: every record the code makes (Proof.Proved, Proof.Check, Proof.Skipped)
// names the function it is written in as its step and a claim the declaration answers
// that way, and every step the declaration names for a claim has a record of it there.
// It needs no sandbox, so it holds the providers whose smoke test only a live service
// runs as firmly as the ones a test can run; Proof.Done holds the path the smoke test
// took at run time.
package boundarytest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/boundary"
)

const importPath = "github.com/plimsollmark/plimsoll/internal/boundary"

// record is one call that records a claim, where it is written.
type record struct {
	method string // Proved, Check or Skipped
	claim  boundary.Claim
	step   string // the step argument; for Skipped, the enclosing function
	fn     string // the function the call is written in
	at     string
}

// Problems lists every way the smoke test's file disagrees with d. root is the module
// root, which d.Source is relative to. Every record of a provider's proof is written in
// that one file, so two providers of one package (docker and e2b in package sandbox)
// never read as one.
func Problems(d *boundary.Declaration, root string) ([]string, error) {
	consts, err := claimConstants()
	if err != nil {
		return nil, err
	}
	file := filepath.Join(root, filepath.FromSlash(d.Source))
	records, err := records(file, consts)
	if err != nil {
		return nil, err
	}
	var problems []string
	type pair struct {
		claim boundary.Claim
		step  string
	}
	recorded := map[pair]bool{}
	skipped := map[boundary.Claim]bool{}
	for _, r := range records {
		e, ok := d.Entries[r.claim]
		switch {
		case !ok || !e.Checked():
			problems = append(problems, fmt.Sprintf("%s: %s records %s, which the declaration says the smoke test does not check", r.at, r.method, r.claim))
		case r.method == "Skipped":
			if e.When == "" {
				problems = append(problems, fmt.Sprintf("%s: Skipped(%s), which the declaration does not make conditional", r.at, r.claim))
			}
			skipped[r.claim] = true
		case r.step != r.fn:
			problems = append(problems, fmt.Sprintf("%s: %s(%s, %q) is written in %s: a step is the function that makes the check", r.at, r.method, r.claim, r.step, r.fn))
		case !slices.Contains(e.Steps, r.step):
			problems = append(problems, fmt.Sprintf("%s: %s(%s) in step %s, which the declaration does not name for it (%s)", r.at, r.method, r.claim, r.step, strings.Join(e.Steps, ", ")))
		default:
			recorded[pair{r.claim, r.step}] = true
		}
	}
	for _, info := range boundary.Claims() {
		e := d.Entries[info.Claim]
		for _, s := range e.Steps {
			if !recorded[pair{info.Claim, s}] {
				problems = append(problems, fmt.Sprintf("%s: declared proved by %s, which records no proof of it in %s", info.Claim, s, d.Source))
			}
		}
		if e.When != "" && !skipped[info.Claim] {
			problems = append(problems, fmt.Sprintf("%s: declared conditional (%s), and no code records it skipped when the condition does not hold", info.Claim, e.When))
		}
	}
	sort.Strings(problems)
	return problems, nil
}

// claimConstants maps each claim constant's name in package boundary to its value.
func claimConstants() (map[string]boundary.Claim, error) {
	_, self, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(self), "..", "boundary.go")
	f, err := parser.ParseFile(token.NewFileSet(), src, nil, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]boundary.Claim{}
	for _, decl := range f.Decls {
		g, ok := decl.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, spec := range g.Specs {
			v := spec.(*ast.ValueSpec)
			if id, ok := v.Type.(*ast.Ident); !ok || id.Name != "Claim" {
				continue
			}
			for i, name := range v.Names {
				lit, ok := v.Values[i].(*ast.BasicLit)
				if !ok {
					return nil, fmt.Errorf("claim constant %s is not a string literal", name.Name)
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return nil, err
				}
				out[name.Name] = boundary.Claim(s)
			}
		}
	}
	if len(out) != len(boundary.Claims()) {
		return nil, fmt.Errorf("read %d claim constants from %s, but the closed list has %d", len(out), src, len(boundary.Claims()))
	}
	return out, nil
}

// records reads every record call in file.
func records(file string, consts map[string]boundary.Claim) ([]record, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		return nil, err
	}
	local := ""
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == importPath {
			local = "boundary"
			if imp.Name != nil {
				local = imp.Name.Name
			}
		}
	}
	var out []record
	if local == "" {
		return nil, nil
	}
	{
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var problem error
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "Proved" && sel.Sel.Name != "Check" && sel.Sel.Name != "Skipped") || len(call.Args) == 0 {
					return true
				}
				arg, ok := call.Args[0].(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if x, ok := arg.X.(*ast.Ident); !ok || x.Name != local {
					return true
				}
				claim, ok := consts[arg.Sel.Name]
				if !ok {
					return true
				}
				r := record{method: sel.Sel.Name, claim: claim, fn: fn.Name.Name, at: fset.Position(call.Pos()).String()}
				if r.method == "Skipped" {
					r.step = r.fn
				} else {
					lit, ok := call.Args[1].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						problem = fmt.Errorf("%s: %s(%s) names its step with something other than a string literal", r.at, r.method, claim)
						return false
					}
					r.step, _ = strconv.Unquote(lit.Value)
				}
				out = append(out, r)
				return true
			})
			if problem != nil {
				return nil, problem
			}
		}
	}
	return out, nil
}
