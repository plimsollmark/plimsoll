package printable

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// command is a program whose output a person reads, with the writers it prints to by
// name: terminal ones, whose every print is checked, and the others, each with why not.
type command struct {
	dir       string
	terminal  []string
	elsewhere map[string]string
	// trusted are expressions printed as they are, each with why no outside text is in it.
	trusted map[string]string
}

var commands = []command{
	{
		dir:      "cmd/plimsoll-attest",
		terminal: []string{"stdout", "os.Stdout", "os.Stderr"},
		elsewhere: map[string]string{
			"f":    "a key, a bundle or a statement file the command writes",
			"hash": "the SHA-256 of the artifact verify-receipt checks",
		},
	},
	{
		dir:      "cmd/plimsoll-clients",
		terminal: []string{"output", "diagnostic", "os.Stdout", "os.Stderr", "w"}, // w: the table's tabwriter over output
		trusted: map[string]string{
			`token + "\n"`: "a token this command generated (64 hex digits) or read and checked as visible ASCII",
			"paid":         "the allowance in seconds, from strconv.FormatInt, or \"none\"",
		},
	},
	{
		dir:      "cmd/plimsoll-withheld",
		terminal: []string{"stdout", "stderr", "os.Stdout", "os.Stderr"},
		elsewhere: map[string]string{
			"f": "the known-unreadable list file the command writes",
		},
	},
	{
		dir:      "cmd/plimsolld",
		terminal: []string{"os.Stdout", "os.Stderr"},
		elsewhere: map[string]string{
			"w": "an HTTP response (the metrics exposition, whose label values escapeLabelValue escapes, or a health answer)",
		},
		trusted: map[string]string{
			"helpText()": "the help text, written from the settings registry compiled into the daemon",
		},
	},
}

// The commands' output to a person goes through printable.Text or printable.JSON (or
// withheld.CleanWhere, which is printable.Text): every value a print gives a terminal
// writer is a literal, a constant, a number, a call to one of them, or a function that
// returns only such values. The security scan of 2026-11-20 (F8, F11) found a daemon's
// sandbox and isolation strings printed raw by plimsoll-attest run; this finds every such
// print by reading the code, so a new one fails here. What it does not see: a print
// inside another package given one of these writers, a writer passed under a name the
// table does not list to a method other than the fmt and io functions, a value made
// clean by any other means, and the daemon's log lines, which its handler cleans
// (cmd/plimsolld logging.go, tested there).
func TestEveryPrintOfOutsideTextIsEscaped(t *testing.T) {
	for _, c := range commands {
		findings, err := scanCommand(filepath.Join("..", "..", c.dir), c)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			t.Errorf("%s/%s", c.dir, f)
		}
	}
}

// The scan finds what it is for: each print below is one it must refuse.
func TestTheScanRefusesARawPrint(t *testing.T) {
	src := `package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io"
	"os"
)

const fixed = "fixed"

func clean() string { return printable.Text(x) + fixed }

func f(stdout io.Writer, resp R, err error, other io.Writer) {
	fmt.Fprintf(stdout, "ran on %s (%s): exit %d\n", resp.GetSandbox(), resp.GetIsolation(), resp.Code)
	fmt.Fprintln(os.Stderr, "plimsoll-attest:", err)
	fmt.Fprint(stdout, fmt.Sprintf("%v", resp))
	stdout.Write(raw)
	json.NewEncoder(stdout).Encode(resp)
	io.Copy(stdout, resp.Body)
	fmt.Fprintf(other, "%d", 1)
	fmt.Fprintf(stdout, format, 1)

	fmt.Fprintf(stdout, "%q %d %x\n", resp.GetSandbox(), resp.Code, resp.Digest)
	fmt.Fprintln(stdout, printable.Text(resp.GetSandbox()), fixed, clean(), len(raw))
	stdout.Write(printable.JSON(raw))
	fmt.Fprintf(&b, "%s", resp.GetSandbox())
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := scanCommand(dir, command{terminal: []string{"stdout", "os.Stderr"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"resp.GetSandbox() printed with %s",
		"resp.GetIsolation() printed with %s",
		"err printed with %v",
		`fmt.Sprintf("%v", resp) printed with %v`,
		"raw written to stdout",
		"a JSON encoder writes to stdout",
		"io.Copy to stdout",
		"other: a writer the table does not name",
		"format: a format that is not a literal",
	} {
		if !slices.ContainsFunc(findings, func(f string) bool { return strings.Contains(f, want) }) {
			t.Errorf("the scan does not refuse %q; it found:\n%s", want, strings.Join(findings, "\n"))
		}
	}
	if len(findings) != 9 {
		t.Errorf("the scan found %d prints, want 9 (the clean ones refused too?):\n%s", len(findings), strings.Join(findings, "\n"))
	}
}

// scanCommand reads the non-test Go files in dir and returns each print to a terminal
// writer that may carry outside text, as "file:line: what".
func scanCommand(dir string, c command) ([]string, error) {
	fset := token.NewFileSet()
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s holds no Go file", dir)
	}
	s := &scan{fset: fset, c: c, consts: map[string]bool{}, funcs: map[string]*ast.FuncDecl{}, safeFunc: map[string]int{}}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.GenDecl:
				if d.Tok == token.CONST {
					for _, spec := range d.Specs {
						for _, id := range spec.(*ast.ValueSpec).Names {
							s.consts[id.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil {
					s.funcs[d.Name.Name] = d
				}
			}
			return true
		})
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				s.call(call)
			}
			return true
		})
	}
	return s.findings, nil
}

type scan struct {
	fset     *token.FileSet
	c        command
	consts   map[string]bool
	funcs    map[string]*ast.FuncDecl
	safeFunc map[string]int // 1 safe, 2 not, 3 being decided
	findings []string
}

func (s *scan) src(e ast.Expr) string {
	var b strings.Builder
	if err := formatNode(&b, s.fset, e); err != nil {
		return "?"
	}
	return b.String()
}

func (s *scan) report(n ast.Node, format string, args ...any) {
	p := s.fset.Position(n.Pos())
	s.findings = append(s.findings, fmt.Sprintf("%s:%d: %s", filepath.Base(p.Filename), p.Line, fmt.Sprintf(format, args...)))
}

// writer classifies a print's writer: true when a person reads it; false when it is
// elsewhere or a buffer in memory (&b), whose text is checked where it is printed. A
// writer the table does not name is reported.
func (s *scan) writer(e ast.Expr) bool {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		return false
	}
	name := s.src(e)
	if name == "io.Discard" {
		return false
	}
	if slices.Contains(s.c.terminal, name) {
		return true
	}
	if _, ok := s.c.elsewhere[name]; !ok {
		s.report(e, "%s: a writer the table does not name (list it as a terminal, or elsewhere with why)", name)
	}
	return false
}

func (s *scan) call(call *ast.CallExpr) {
	pkg, fn := callee(call)
	switch {
	case pkg == "fmt" && (fn == "Fprintf" || fn == "Fprint" || fn == "Fprintln") && len(call.Args) > 0:
		if s.writer(call.Args[0]) {
			s.args(call, fn[1:], call.Args[1:])
		}
	case (pkg == "fmt" || pkg == "log") && (fn == "Printf" || fn == "Print" || fn == "Println" ||
		pkg == "log" && (fn == "Fatalf" || fn == "Fatal" || fn == "Fatalln" || fn == "Panicf" || fn == "Panic" || fn == "Panicln")):
		s.args(call, strings.TrimPrefix(strings.TrimPrefix(fn, "Fatal"), "Panic"), call.Args)
	case pkg == "io" && fn == "WriteString" && len(call.Args) == 2:
		if s.writer(call.Args[0]) && !s.safe(call.Args[1]) {
			s.report(call, "%s written to %s", s.src(call.Args[1]), s.src(call.Args[0]))
		}
	case pkg == "io" && (fn == "Copy" || fn == "CopyN" || fn == "CopyBuffer") && len(call.Args) > 0:
		if s.writer(call.Args[0]) {
			s.report(call, "io.%s to %s: bytes from elsewhere reach the terminal as they are", fn, s.src(call.Args[0]))
		}
	case pkg == "json" && fn == "NewEncoder" && len(call.Args) == 1:
		if s.writer(call.Args[0]) {
			s.report(call, "a JSON encoder writes to %s: marshal, then write printable.JSON of it", s.src(call.Args[0]))
		}
	default:
		// A Write or WriteString method on a terminal writer.
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Write" && sel.Sel.Name != "WriteString") || len(call.Args) != 1 {
			return
		}
		if slices.Contains(s.c.terminal, s.src(sel.X)) && !s.safe(call.Args[0]) {
			s.report(call, "%s written to %s", s.src(call.Args[0]), s.src(sel.X))
		}
	}
}

// args checks a print's values: with a format (kind "printf"), each value by its verb;
// without (Print, Println), each as %v.
func (s *scan) args(call *ast.CallExpr, kind string, args []ast.Expr) {
	verbs := make([]string, len(args))
	for i := range verbs {
		verbs[i] = "v"
	}
	if strings.HasSuffix(kind, "f") {
		if len(args) == 0 {
			return
		}
		format, ok := s.literal(args[0])
		if !ok {
			s.report(call, "%s: a format that is not a literal", s.src(args[0]))
			return
		}
		args = args[1:]
		vs, ok := verbsOf(format)
		if !ok || len(vs) != len(args) {
			s.report(call, "a format this scan cannot read, or one whose verbs do not match its values")
			return
		}
		verbs = vs
	}
	for i, a := range args {
		if strings.ContainsRune("dxXqtboOeEfFgGpTU", rune(verbs[i][0])) || s.safe(a) {
			continue
		}
		s.report(a, "%s printed with %%%s, not through printable.Text", s.src(a), verbs[i])
	}
}

// safe reports whether e can hold no outside text as it is.
func (s *scan) safe(e ast.Expr) bool {
	if why, ok := s.c.trusted[s.src(e)]; ok && why != "" {
		return true
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return s.consts[e.Name] || e.Name == "true" || e.Name == "false"
	case *ast.ParenExpr:
		return s.safe(e.X)
	case *ast.BinaryExpr:
		return e.Op == token.ADD && s.safe(e.X) && s.safe(e.Y)
	case *ast.CallExpr:
		pkg, fn := callee(e)
		switch {
		case pkg == "printable" && (fn == "Text" || fn == "JSON"), pkg == "withheld" && fn == "CleanWhere":
			return true
		case pkg == "" && (fn == "len" || fn == "cap"):
			return true
		case pkg == "strconv" && (fn == "Itoa" || fn == "FormatInt" || fn == "FormatUint" || fn == "Quote" || fn == "QuoteToASCII"):
			return true
		case pkg == "fmt" && (fn == "Sprintf" || fn == "Sprint" || fn == "Sprintln"):
			before := len(s.findings)
			s.args(e, strings.TrimPrefix(fn, "S"), e.Args)
			clean := len(s.findings) == before
			s.findings = s.findings[:before]
			return clean
		}
		if at, ok := e.Fun.(*ast.ArrayType); ok && at.Len == nil && len(e.Args) == 1 {
			return s.safe(e.Args[0]) // []byte("...")
		}
		if id, ok := e.Fun.(*ast.Ident); ok {
			return s.safeFunction(id.Name)
		}
	}
	return false
}

// safeFunction reports whether the package's function name returns only safe values.
func (s *scan) safeFunction(name string) bool {
	switch s.safeFunc[name] {
	case 1:
		return true
	case 2, 3:
		return false
	}
	d, ok := s.funcs[name]
	if !ok || d.Body == nil || d.Type.Results == nil || len(d.Type.Results.List) != 1 {
		s.safeFunc[name] = 2
		return false
	}
	s.safeFunc[name] = 3
	safe := true
	ast.Inspect(d.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(n.Results) != 1 || !s.safe(n.Results[0]) {
				safe = false
			}
		}
		return safe
	})
	if safe {
		s.safeFunc[name] = 1
	} else {
		s.safeFunc[name] = 2
	}
	return safe
}

// literal is the string a format expression spells, when it is a literal or a sum of them.
func (s *scan) literal(e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		v, err := unquote(e.Value)
		return v, err == nil
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		x, ok := s.literal(e.X)
		if !ok {
			return "", false
		}
		y, ok := s.literal(e.Y)
		return x + y, ok
	case *ast.ParenExpr:
		return s.literal(e.X)
	}
	return "", false
}

// verbsOf returns the verb of each value a format takes, in order; false for a format
// this scan does not read (an explicit argument index, a * width).
func verbsOf(format string) ([]string, bool) {
	var verbs []string
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		for i < len(format) && strings.IndexByte("+-# 0123456789.", format[i]) >= 0 {
			i++
		}
		if i >= len(format) || format[i] == '[' || format[i] == '*' {
			return nil, false
		}
		if format[i] == '%' {
			continue
		}
		verbs = append(verbs, string(format[i]))
	}
	return verbs, true
}

// callee is a call's package (or receiver) name and function name: ("fmt", "Fprintf"),
// ("", "len").
func callee(call *ast.CallExpr) (string, string) {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return "", f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name, f.Sel.Name
		}
	}
	return "", ""
}

func formatNode(w io.Writer, fset *token.FileSet, n ast.Node) error { return format.Node(w, fset, n) }

func unquote(s string) (string, error) { return strconv.Unquote(s) }
