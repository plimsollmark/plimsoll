package outsidefacts

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The shapes the scan knows. Each is a way code comes to rest on a fact it does not own;
// rules.md beside this file states each rule in one line, and Scan is the rule itself.
const (
	// ShapeErrorText: an error's text (x.Error()) tested for words.
	ShapeErrorText = "error-text"
	// ShapeOutputText: another program's standard output or standard error tested for words.
	ShapeOutputText = "output-text"
	// ShapeExitCode: an exit code compared with a number other than 0.
	ShapeExitCode = "exit-code"
	// ShapeVersionParse: a version string taken apart or tested.
	ShapeVersionParse = "version-parse"
	// ShapeProviderName: a provider named by a literal outside the tables that list providers.
	ShapeProviderName = "provider-name"
	// ShapePlatformCase: the operating system or machine named by a literal (runtime.GOOS,
	// runtime.GOARCH): code that does one thing here and another, or nothing, there.
	ShapePlatformCase = "platform-case"
	// ShapeFixedWait: in a test, a fixed sleep or timer outside any loop that nothing fails on.
	ShapeFixedWait = "fixed-wait"
)

// Shapes is every shape, in the order the rules state them.
var Shapes = []string{ShapeErrorText, ShapeOutputText, ShapeExitCode, ShapeVersionParse, ShapeProviderName, ShapePlatformCase, ShapeFixedWait}

// ProductRoots are the directories the product is built from: the daemon, the providers, the
// Go client, the record and attest libraries, the programs that run inside a sandbox image,
// and the MCP server. Examples and timing programs are demonstrations and are not scanned.
var ProductRoots = []string{"attest", "client", "clients/mcp", "cmd", "docker", "internal", "placement", "protocol", "record", "sandbox"}

// SkipDirs are directories under ProductRoots that hold no product code, each with why.
var SkipDirs = map[string]string{
	"clients/mcp/examples": "demonstration programs, like the examples at the root",
	"internal/answertest":  "test support: only tests import it",
	"internal/clientcases": "test support: the judge of the clients' test runs",
	"internal/clientsuite": "test support: the client suites' named test daemons",
	"internal/pagetest":    "test support: checks an example's committed page",
	"internal/refusedport": "test support: only tests import it",
	"sandbox/drivertest":   "a conformance suite: test code in a package tests import",
	"sandbox/projecttest":  "a conformance suite: test code in a package tests import",
	"sandbox/sessiontest":  "a conformance suite: test code in a package tests import",
}

// TestRoots are the directories whose test files the fixed-wait rule reads.
var TestRoots = []string{"attest", "client", "clients", "cmd", "docker", "docs", "examples", "internal", "measurements", "placement", "protocol", "record", "sandbox", "sandboxtest"}

// ProviderTables are the files that list providers: a provider's name there is the table
// itself, so the provider-name rule does not read them.
var ProviderTables = map[string]bool{
	"sandbox/factory.go":            true,
	"cmd/plimsolld/providers.go":    true,
	"cmd/plimsolld/config.go":       true,
	"internal/settings/registry.go": true,
}

// ProviderNames are the names the provider-name rule looks for: SANDBOX_PROVIDER's values.
var ProviderNames = map[string]bool{
	"wasm": true, "docker": true, "e2b": true, "dockercloud": true,
	"openshell": true, "agentsandbox": true, "wslc": true, "lambdamicrovm": true,
}

// WaitMarker is the comment that answers the fixed-wait rule: "fixed-wait: " and the reason
// the wait is safe, on the wait's own line or the line above it.
const WaitMarker = "fixed-wait:"

// A Site is one place the scan found: a file, the top-level declaration it is in, and the shape.
type Site struct {
	File   string // repository-relative, forward slashes
	Symbol string // the enclosing top-level declaration: Func, Type.Method, or a var or const name
	Shape  string
	Line   int    // for a person reading the failure; a row never names a line
	Text   string // the expression, shortened
}

// Key is what a row answers: one row covers every site with its key.
func (s Site) Key() string { return s.File + "\x00" + s.Symbol + "\x00" + s.Shape }

var (
	outputSubject  = regexp.MustCompile(`(?i)stderr|stdout|output`)
	versionSubject = regexp.MustCompile(`(?i)version`)
	exitSubject    = regexp.MustCompile(`(?i)exit`)
)

// wordTests are the functions of strings and bytes that test text for words. Splitting and
// trimming are not here: taking text apart by a separator reads a format, not words.
var wordTests = map[string]bool{
	"Contains": true, "ContainsAny": true, "HasPrefix": true, "HasSuffix": true, "Index": true,
	"LastIndex": true, "EqualFold": true, "Cut": true, "CutPrefix": true, "CutSuffix": true,
}

// regexpTests are the methods of a compiled pattern that read text.
var regexpTests = map[string]bool{
	"Match": true, "MatchString": true, "FindString": true, "FindStringSubmatch": true, "FindSubmatch": true,
	"Find": true, "FindAllString": true, "FindAllStringSubmatch": true, "FindStringIndex": true, "FindIndex": true,
	"FindAllSubmatch": true, "FindAll": true,
}

// numberParsers are the calls that turn text into a number.
var numberParsers = map[string]bool{"Atoi": true, "ParseInt": true, "ParseUint": true, "ParseFloat": true}

// Scan reads the product code under root (the repository's top directory) and returns every
// site of the six product shapes, in file order.
func Scan(root string) ([]Site, error) {
	var sites []Site
	for _, dir := range ProductRoots {
		err := walkGo(root, dir, false, func(rel string, src []byte) error {
			found, err := ScanSource(rel, src)
			sites = append(sites, found...)
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	sortSites(sites)
	return sites, nil
}

// ScanTests reads the test files under root and returns every fixed wait that carries no
// marker, in file order.
func ScanTests(root string) ([]Site, error) {
	var sites []Site
	for _, dir := range TestRoots {
		err := walkGo(root, dir, true, func(rel string, src []byte) error {
			found, err := ScanTestSource(rel, src)
			sites = append(sites, found...)
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	sortSites(sites)
	return sites, nil
}

func sortSites(sites []Site) {
	sort.SliceStable(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
}

// walkGo calls visit for each Go file under root/dir: test files when tests is set, the others
// when it is not. Directories named testdata, hidden directories, node_modules and SkipDirs
// (for product files) are not entered; a root that is absent is skipped.
func walkGo(root, dir string, tests bool, visit func(rel string, src []byte) error) error {
	start := filepath.Join(root, filepath.FromSlash(dir))
	if _, err := os.Stat(start); err != nil {
		return nil
	}
	return filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			name := d.Name()
			if name == "testdata" || name == "node_modules" || (strings.HasPrefix(name, ".") && path != start) {
				return filepath.SkipDir
			}
			if _, skip := SkipDirs[rel]; skip && !tests {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") != tests {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return visit(rel, src)
	})
}

// ScanSource is Scan for one file's source: rel is its repository-relative name.
func ScanSource(rel string, src []byte) ([]Site, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, 0)
	if err != nil {
		return nil, err
	}
	var sites []Site
	for _, decl := range f.Decls {
		for _, part := range declParts(decl) {
			sym := part.name
			add := func(shape string, n ast.Node) {
				sites = append(sites, Site{File: rel, Symbol: sym, Shape: shape, Line: fset.Position(n.Pos()).Line, Text: text(fset, n)})
			}
			versionFunc := versionSubject.MatchString(sym)
			ast.Inspect(part.node, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					sel, ok := n.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkg, _ := sel.X.(*ast.Ident)
					switch {
					case pkg != nil && (pkg.Name == "strings" || pkg.Name == "bytes") && wordTests[sel.Sel.Name] && len(n.Args) >= 1:
						if shape := subjectShape(fset, n.Args[0]); shape != "" {
							add(shape, n)
						}
					case regexpTests[sel.Sel.Name] && len(n.Args) >= 1:
						if shape := subjectShape(fset, n.Args[0]); shape != "" {
							add(shape, n)
						} else if versionFunc {
							add(ShapeVersionParse, n)
						}
					case pkg != nil && pkg.Name == "strconv" && numberParsers[sel.Sel.Name] && versionFunc:
						add(ShapeVersionParse, n)
					case pkg != nil && pkg.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Sscan") && versionFunc:
						add(ShapeVersionParse, n)
					case pkg != nil && pkg.Name == "semver":
						add(ShapeVersionParse, n)
					}
				case *ast.BinaryExpr:
					switch n.Op {
					case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ:
					default:
						return true
					}
					literal := false
					for i, side := range []ast.Expr{n.X, n.Y} {
						other := n.Y
						if i == 1 {
							other = n.X
						}
						lit, ok := side.(*ast.BasicLit)
						if !ok {
							continue
						}
						literal = true
						if shape := literalShape(fset, rel, lit, other, n.Op); shape != "" {
							add(shape, n)
						}
					}
					// Two errors compared by their text, with no literal on either side.
					if !literal && (n.Op == token.EQL || n.Op == token.NEQ) &&
						(strings.Contains(text(fset, n.X), ".Error()") || strings.Contains(text(fset, n.Y), ".Error()")) {
						add(ShapeErrorText, n)
					}
				case *ast.SwitchStmt:
					if n.Tag == nil {
						return true
					}
					for _, st := range n.Body.List {
						cc, ok := st.(*ast.CaseClause)
						if !ok {
							continue
						}
						for _, e := range cc.List {
							lit, ok := e.(*ast.BasicLit)
							if !ok {
								continue
							}
							if shape := literalShape(fset, rel, lit, n.Tag, token.EQL); shape != "" {
								add(shape, e)
							}
						}
					}
				}
				return true
			})
		}
	}
	return sites, nil
}

// subjectShape is the shape of a word test on subject: error-text for an error's text,
// output-text for something named for a program's output, version-parse for something named
// for a version, "" for anything else.
func subjectShape(fset *token.FileSet, subject ast.Expr) string {
	s := text(fset, subject)
	switch {
	case strings.Contains(s, ".Error()"):
		return ShapeErrorText
	case outputSubject.MatchString(s):
		return ShapeOutputText
	case versionSubject.MatchString(s):
		return ShapeVersionParse
	}
	return ""
}

// literalShape is the shape of comparing other with the literal lit, "" for none.
func literalShape(fset *token.FileSet, rel string, lit *ast.BasicLit, other ast.Expr, op token.Token) string {
	o := text(fset, other)
	switch lit.Kind {
	case token.INT:
		if lit.Value != "0" && exitSubject.MatchString(o) {
			return ShapeExitCode
		}
	case token.STRING:
		if op != token.EQL && op != token.NEQ {
			return ""
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			return ""
		}
		if o == "runtime.GOOS" || o == "runtime.GOARCH" {
			return ShapePlatformCase
		}
		if ProviderNames[v] && !ProviderTables[rel] {
			return ShapeProviderName
		}
		if v == "" {
			return "" // "printed nothing" is not a test for words
		}
		return subjectShape(fset, other)
	}
	return ""
}

// ScanTestSource is ScanTests for one test file's source.
func ScanTestSource(rel string, src []byte) ([]Site, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	marked := map[int]bool{} // lines a marker answers: its own and the one after its comment group
	for _, group := range f.Comments {
		for _, c := range group.List {
			i := strings.Index(c.Text, WaitMarker)
			if i < 0 || strings.Trim(c.Text[i+len(WaitMarker):], " \t*/") == "" {
				continue
			}
			marked[fset.Position(c.Pos()).Line] = true
			marked[fset.Position(group.End()).Line+1] = true
		}
	}
	var sites []Site
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		sym := funcName(fset, fd)
		var stack []ast.Node
		ast.Inspect(fd, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "time" || (sel.Sel.Name != "Sleep" && sel.Sel.Name != "After") {
				return true
			}
			line := fset.Position(n.Pos()).Line
			if marked[line] {
				return true
			}
			if sel.Sel.Name == "After" {
				// Only a timer that is read where it is made: one kept in a variable is read
				// somewhere the scan does not follow.
				recv, ok := stack[len(stack)-2].(*ast.UnaryExpr)
				if len(stack) < 2 || !ok || recv.Op != token.ARROW {
					return true
				}
			}
			for i := len(stack) - 1; i >= 0; i-- {
				switch s := stack[i].(type) {
				case *ast.ForStmt, *ast.RangeStmt:
					return true // a wait inside a loop is a poll's pause
				case *ast.CommClause:
					inComm := s.Comm != nil && s.Comm.Pos() <= n.Pos() && n.End() <= s.Comm.End()
					if sel.Sel.Name == "After" && inComm && clauseFails(s) {
						return true // the timer is a limit: the test fails or leaves when it fires
					}
				}
			}
			sites = append(sites, Site{File: rel, Symbol: sym, Shape: ShapeFixedWait, Line: line, Text: text(fset, n)})
			return true
		})
	}
	return sites, nil
}

// clauseFails reports whether a select case's body fails the test, panics or returns: then its
// timer is a limit on waiting, not a stand-in for something having happened.
func clauseFails(cc *ast.CommClause) bool {
	fails := false
	for _, st := range cc.Body {
		ast.Inspect(st, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.ReturnStmt:
				fails = true
			case *ast.CallExpr:
				switch fun := n.Fun.(type) {
				case *ast.SelectorExpr:
					switch fun.Sel.Name {
					case "Fatal", "Fatalf", "Error", "Errorf", "FailNow", "Fail", "Skip", "Skipf":
						fails = true
					}
				case *ast.Ident:
					if fun.Name == "panic" {
						fails = true
					}
				}
			}
			return true
		})
	}
	return fails
}

type declPart struct {
	name string
	node ast.Node
}

// declParts names what a top-level declaration declares: a function by its name (a method as
// Type.Method), and each var, const or type spec by its first name.
func declParts(decl ast.Decl) []declPart {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return []declPart{{funcName(nil, d), d}}
	case *ast.GenDecl:
		var parts []declPart
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.ValueSpec:
				if len(s.Names) > 0 {
					parts = append(parts, declPart{s.Names[0].Name, s})
				}
			case *ast.TypeSpec:
				parts = append(parts, declPart{s.Name.Name, s})
			}
		}
		return parts
	}
	return nil
}

// funcName is Func, or Type.Method for a method (a pointer receiver and type parameters dropped).
func funcName(_ *token.FileSet, fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
			continue
		case *ast.IndexExpr:
			t = x.X
			continue
		case *ast.IndexListExpr:
			t = x.X
			continue
		case *ast.ParenExpr:
			t = x.X
			continue
		}
		break
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// Symbols are the top-level names a Go file declares, as rows name them.
func Symbols(rel string, src []byte) (map[string]bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			names[funcName(nil, d)] = true
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.ValueSpec:
					for _, n := range s.Names {
						names[n.Name] = true
					}
				case *ast.TypeSpec:
					names[s.Name.Name] = true
				}
			}
		}
	}
	return names, nil
}

func text(fset *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, n)
	s := strings.Join(strings.Fields(b.String()), " ")
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}
