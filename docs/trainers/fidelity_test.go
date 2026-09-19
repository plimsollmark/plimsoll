package trainers

// Fidelity guards: every checkable claim a trainer makes about plimsoll is checked
// against plimsoll's own source, not against a list somebody has to remember to
// update.
//
// Why this file exists. On 2026-09-10 a review found that five trainer pages still
// said Docker project grants and E2B grants were rejected, months after both
// shipped, and that one chapter still called the E2B egress path a "proposal" while
// describing, correctly, the design that had already landed. Nothing failed. A
// trainer is prose until something reads it, and the only reader was a person.
//
// The guards below are deliberately GENERATIVE rather than a fact list: they extract
// every env var, metric, error identifier and procedure name the trainers mention
// and require the source to back it. A new page gets checked the day it is added,
// with nobody editing this file. Where a claim genuinely cannot be derived (a
// numeric limit rendered as "256 KiB"), the pairing is stated once, next to the
// constant it comes from.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// trainerProse is every page a reader can reach, including the two that live
// outside this directory. Missing files are skipped: the public export does not
// contain the private ones, and failing its build for a file it never had would be
// a false alarm, not a finding.
func trainerProse(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	names := append([]string{}, trainerPages...)
	names = append(names, "index.html", "quick-start.html", "trainer.js",
		"demo.html", "../../private/positioning/docker-agent-boundaries.html")
	for _, name := range names {
		raw, err := os.ReadFile(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		out[name] = string(raw)
	}
	if len(out) < len(trainerPages) {
		t.Fatalf("read %d pages, want at least the %d trainer pages", len(out), len(trainerPages))
	}
	return out
}

// plimsollSource is the shipping (non-test) Go source of the component. Test files
// are excluded on purpose: a trainer should describe what the daemon does, and a
// name that appears only in a fixture is not that.
func plimsollSource(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, dir := range []string{"../../sandbox", "../../internal", "../../cmd", "../../client"} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			b.Write(raw)
			b.WriteString("\n")
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if b.Len() == 0 {
		t.Fatal("read no plimsoll source; the guards below would pass vacuously")
	}
	return b.String()
}

// envVarsNotOwnedByPlimsoll are names a trainer may print that the daemon does not
// read, because they belong to the caller rather than to plimsoll. Each needs a
// reason; "the test was failing" is not one.
var envVarsNotOwnedByPlimsoll = map[string]string{
	// A consumer's own switch between embedding the sandbox package and calling a
	// remote plimsolld. plimsoll never reads it: the Private API Lab shows it inside
	// the example gateway's dataplane, which is where it belongs.
	"PLIMSOLL_URL": "read by a consumer, not by plimsolld",
}

func TestTrainerEnvVarsAreReadByTheDaemon(t *testing.T) {
	src := plimsollSource(t)
	pattern := regexp.MustCompile(`\b(?:PLIMSOLL|SANDBOX|E2B|CODERUNNER)_[A-Z0-9_]+`)
	seen := map[string]string{}
	for name, prose := range trainerProse(t) {
		for _, v := range pattern.FindAllString(prose, -1) {
			if _, ok := seen[v]; !ok {
				seen[v] = name
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no env vars in the trainers; the pattern is probably wrong")
	}
	for v, page := range seen {
		if strings.HasPrefix(v, "CODERUNNER_") {
			t.Errorf("%s names %s, a pre-rename variable that no longer exists", page, v)
			continue
		}
		if _, ok := envVarsNotOwnedByPlimsoll[v]; ok {
			continue
		}
		if !strings.Contains(src, `"`+v+`"`) {
			t.Errorf("%s names env var %s, which no shipping source file reads", page, v)
		}
	}
}

func TestTrainerMetricNamesAreExposed(t *testing.T) {
	src := plimsollSource(t)
	pattern := regexp.MustCompile(`\b(?:plimsoll|coderunner)_[a-z0-9_]+`)
	seen := map[string]string{}
	for name, prose := range trainerProse(t) {
		for _, m := range pattern.FindAllString(prose, -1) {
			if _, ok := seen[m]; !ok {
				seen[m] = name
			}
		}
	}
	// The guard used to be "some trainer must name a metric", which failed the day the
	// only page that named them was deleted, for a reason that had nothing to do with
	// fidelity. What the guard is actually for is proving the pattern still recognises a
	// metric name, so it asks the daemon's own source instead: no trainer has to mention
	// metrics, but one that does gets checked.
	if len(pattern.FindAllString(src, 1)) == 0 {
		t.Fatal("the pattern matches no metric name in the daemon's source; it is probably wrong")
	}
	for m, page := range seen {
		if strings.HasPrefix(m, "coderunner_") {
			t.Errorf("%s names %s, a pre-rename metric that is no longer exposed", page, m)
			continue
		}
		if !strings.Contains(src, m) {
			t.Errorf("%s names metric %s, which the daemon does not expose", page, m)
		}
	}
}

func TestTrainerErrorIdentifiersExist(t *testing.T) {
	src := plimsollSource(t)
	// Err followed by an upper-case word: the exported sentinel shape. Anchored on a
	// word boundary so "Error" and "Errorf" in sample code are not swept up.
	pattern := regexp.MustCompile(`\bErr[A-Z][A-Za-z]+\b`)
	seen := map[string]string{}
	for name, prose := range trainerProse(t) {
		for _, e := range pattern.FindAllString(prose, -1) {
			if _, ok := seen[e]; !ok {
				seen[e] = name
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no error identifiers in the trainers; the pattern is probably wrong")
	}
	for e, page := range seen {
		if !regexp.MustCompile(`\b` + e + `\b`).MatchString(src) {
			t.Errorf("%s names %s, which does not exist in the source", page, e)
		}
	}
}

type parsedGoFile struct {
	file *ast.File
}

func shippingGoFiles(t *testing.T, dirs ...string) []parsedGoFile {
	t.Helper()
	fset := token.NewFileSet()
	var files []parsedGoFile
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			files = append(files, parsedGoFile{file: file})
			return nil
		})
		if err != nil {
			t.Fatalf("parse shipping Go in %s: %v", dir, err)
		}
	}
	if len(files) == 0 {
		t.Fatal("parsed no shipping Go; source-derived fidelity checks would pass vacuously")
	}
	return files
}

func receiverType(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.StarExpr:
		return receiverType(expr.X)
	case *ast.IndexExpr:
		return receiverType(expr.X)
	case *ast.IndexListExpr:
		return receiverType(expr.X)
	default:
		return ""
	}
}

type goAPIIndex struct {
	packages map[string]map[string]bool
	types    map[string]map[string]bool
	exported map[string]bool
}

func goAPIFromSource(t *testing.T) goAPIIndex {
	t.Helper()
	index := goAPIIndex{
		packages: map[string]map[string]bool{},
		types:    map[string]map[string]bool{},
		exported: map[string]bool{},
	}
	files := shippingGoFiles(t, "../../sandbox", "../../internal", "../../cmd", "../../client")
	for _, parsed := range files {
		pkg := parsed.file.Name.Name
		if index.packages[pkg] == nil {
			index.packages[pkg] = map[string]bool{}
		}
		for _, decl := range parsed.file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if !ast.IsExported(decl.Name.Name) {
					continue
				}
				index.exported[decl.Name.Name] = true
				if decl.Recv == nil {
					index.packages[pkg][decl.Name.Name] = true
					continue
				}
				receiver := receiverType(decl.Recv.List[0].Type)
				if index.types[receiver] == nil {
					index.types[receiver] = map[string]bool{}
				}
				index.types[receiver][decl.Name.Name] = true
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if !ast.IsExported(spec.Name.Name) {
							continue
						}
						index.exported[spec.Name.Name] = true
						index.packages[pkg][spec.Name.Name] = true
						if index.types[spec.Name.Name] == nil {
							index.types[spec.Name.Name] = map[string]bool{}
						}
						var fields *ast.FieldList
						switch typ := spec.Type.(type) {
						case *ast.StructType:
							fields = typ.Fields
						case *ast.InterfaceType:
							fields = typ.Methods
						}
						if fields != nil {
							for _, field := range fields.List {
								for _, name := range field.Names {
									if ast.IsExported(name.Name) {
										index.types[spec.Name.Name][name.Name] = true
										index.exported[name.Name] = true
									}
								}
							}
						}
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if ast.IsExported(name.Name) {
								index.exported[name.Name] = true
								index.packages[pkg][name.Name] = true
							}
						}
					}
				}
			}
		}
	}
	return index
}

var (
	packageAPIReference = regexp.MustCompile(`\b([a-z][A-Za-z0-9_]*)\.([A-Z][A-Za-z0-9_]*)\b`)
	typeAPIReference    = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*)\.([A-Z][A-Za-z0-9_]*)\b`)
	codeCallReference   = regexp.MustCompile(`<code>\s*([A-Z][A-Za-z0-9_]*)\s*\(`)
)

// TestTrainerExportedGoIdentifiersExist treats package-qualified references,
// Type.Member references, and standalone exported calls in code markup as Go API
// claims. Package names, types, fields, methods, functions, variables, and constants
// all come from the shipping AST. A removed API therefore fails every trainer that
// still teaches it, without recording the removed name in this test.
func TestTrainerExportedGoIdentifiersExist(t *testing.T) {
	api := goAPIFromSource(t)
	for page, prose := range trainerProse(t) {
		seen := map[string]bool{}
		for _, match := range packageAPIReference.FindAllStringSubmatch(prose, -1) {
			pkg, identifier := match[1], match[2]
			if api.packages[pkg] == nil || api.packages[pkg][identifier] {
				continue
			}
			claim := pkg + "." + identifier
			if !seen[claim] {
				t.Errorf("%s names exported Go API %s, which does not exist in package %s", page, claim, pkg)
				seen[claim] = true
			}
		}
		for _, match := range typeAPIReference.FindAllStringSubmatch(prose, -1) {
			typeName, member := match[1], match[2]
			if api.types[typeName] == nil || api.types[typeName][member] {
				continue
			}
			claim := typeName + "." + member
			if !seen[claim] {
				t.Errorf("%s names exported Go API %s, but %s has no exported member %s", page, claim, typeName, member)
				seen[claim] = true
			}
		}
		for _, match := range codeCallReference.FindAllStringSubmatch(prose, -1) {
			identifier := match[1]
			if api.exported[identifier] || seen[identifier] {
				continue
			}
			t.Errorf("%s names exported Go call %s, which does not exist in shipping source", page, identifier)
			seen[identifier] = true
		}
	}
}

// TestTrainerShippedFeaturesAreNotDescribedAsProposals guards the second drift class
// found on 2026-09-10: a chapter that describes, accurately, a design that has
// already landed, while still labelling it a plan. That reads as vapourware to a
// customer and as an open question to a contributor, and both are wrong.
func TestTrainerShippedFeaturesAreNotDescribedAsProposals(t *testing.T) {
	shipped := []string{
		`"value":"proposal"`,
		`"value": "proposal"`,
		"Proposed plan.",
		"the proposed E2B path",
		"envd-mailbox interim",
		"the advisor would learn to spot",
	}
	for name, prose := range trainerProse(t) {
		for _, phrase := range shipped {
			if strings.Contains(prose, phrase) {
				t.Errorf("%s describes a shipped capability as unbuilt: %q", name, phrase)
			}
		}
	}
	// There used to be a positive half here demanding a `"status","value":"shipped"`
	// stat in three lesson documents. That pinned a rendering detail, not a fact, and
	// the pages are no longer lesson documents; the phrases above are the check.
}

// TestTrainerNumericLimitsMatchTheConstants pairs each human-readable ceiling with
// the constant it is a rendering of. This is the one place a fact list is
// unavoidable: "256 KiB" cannot be derived from `MaxCodeBytes = 256 << 10` without
// re-implementing the rendering, so the pairing is stated once, here, beside it.
//
// It checks in one direction only. A page that renders one of these numbers is held
// to the constant; a page that does not render it owes nothing. Until 2026-09-19 it
// also demanded that *some* trainer render every number, which is the test deciding
// what a lesson should teach, the same overreach as the chapter-count rule, and it
// put an "8 MiB" sentence into the integrations lesson for no reader's benefit
// (Carroll, 2026-09-19: no guards on what a trainer chooses to say).
func TestTrainerNumericLimitsMatchTheConstants(t *testing.T) {
	space := regexp.MustCompile(`\s+`)
	flat := space.ReplaceAllString(plimsollSource(t), " ")
	prose := trainerProse(t)
	for _, c := range []struct {
		decl, rendered, why string
	}{
		{"MaxCodeBytes = 256 << 10", "256 KiB", "snippet source ceiling"},
		{"MaxProjectBytes = 4 << 20", "4 MiB", "project total ceiling"},
		{"MaxProjectFiles = 200", "200 files", "project file count"},
		{"MaxProjectSteps = 20", "20 steps", "project step count"},
		{"MaxProjectArtifacts = 100", "100 artifact paths", "project artifact count"},
		{"maxRequestBytes = 8 << 20", "8 MiB", "raw HTTP body cap"},
		{"maxRunTimeout = 5 * time.Minute", "5 min", "RPC wall ceiling"},
		{"DefaultMaxHostCalls = 256", "256 calls", "default per-run host call budget"},
		{"breakerMaxCooldown = 30 * time.Second", "30s", "circuit-breaker cooldown cap"},
	} {
		// Not strings.Contains: "128 MiB" contains "8 MiB", so a substring match let a
		// different number satisfy the pairing. Found 2026-09-19, when deleting the only
		// page that appeared to render the raw body cap turned out to change nothing.
		rendered := regexp.MustCompile(`(^|[^0-9.])` + regexp.QuoteMeta(c.rendered))
		var pages []string
		for name, text := range prose {
			if rendered.MatchString(text) {
				pages = append(pages, name)
			}
		}
		sort.Strings(pages)
		if strings.Contains(flat, c.decl) {
			continue
		}
		if len(pages) == 0 {
			// Nothing renders it, so no reader is misled; the pairing itself is stale.
			t.Errorf("the %s pairing names %q, which is no longer in the source; update or delete the pairing", c.why, c.decl)
			continue
		}
		t.Errorf("%s renders the %s as %q, but %q is no longer in the source; the page or the pairing is wrong",
			strings.Join(pages, ", "), c.why, c.rendered, c.decl)
	}
}
