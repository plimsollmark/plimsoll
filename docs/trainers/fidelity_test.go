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
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
		"private-api.html", "private-api.js",
		"demo.html", "../positioning/docker-agent-boundaries.html")
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
	if len(seen) == 0 {
		t.Fatal("found no metric names in the trainers; the pattern is probably wrong")
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

type providerGrantCapabilities map[string]map[string]bool

func providerCapabilitiesFromSource(t *testing.T) providerGrantCapabilities {
	t.Helper()
	files := shippingGoFiles(t, "../../sandbox")
	typeNames := map[string]string{}
	for _, parsed := range files {
		for _, decl := range parsed.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "Name" || fn.Body == nil || len(fn.Recv.List) != 1 {
				continue
			}
			receiver := receiverType(fn.Recv.List[0].Type)
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				ret, ok := node.(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 1 {
					return true
				}
				lit, ok := ret.Results[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				name, err := strconv.Unquote(lit.Value)
				if err == nil {
					typeNames[receiver] = strings.ToLower(name)
				}
				return false
			})
		}
	}

	capabilities := providerGrantCapabilities{}
	for _, parsed := range files {
		for _, decl := range parsed.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || len(fn.Recv.List) != 1 {
				continue
			}
			kind := ""
			switch fn.Name.Name {
			case "SupportsJavaScriptGrants":
				kind = "javascript"
			case "SupportsProjectGrants":
				kind = "project"
			default:
				continue
			}
			provider := typeNames[receiverType(fn.Recv.List[0].Type)]
			if provider == "" {
				continue
			}
			live := false
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				ret, ok := node.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, result := range ret.Results {
					if ident, ok := result.(*ast.Ident); !ok || ident.Name != "false" {
						live = true
					}
				}
				return true
			})
			if capabilities[provider] == nil {
				capabilities[provider] = map[string]bool{}
			}
			capabilities[provider][kind] = live
		}
	}
	if len(capabilities) == 0 {
		t.Fatal("derived no provider grant capabilities from source")
	}
	return capabilities
}

type fidelityCell struct {
	Text string `json:"text"`
	Note string `json:"note"`
}

type fidelityRow struct {
	Label string         `json:"label"`
	Cells []fidelityCell `json:"cells"`
}

type fidelityChapter struct {
	ID      string        `json:"id"`
	Kind    string        `json:"kind"`
	Title   string        `json:"title"`
	Lede    string        `json:"lede"`
	Prompt  string        `json:"prompt"`
	Columns []string      `json:"columns"`
	Rows    []fidelityRow `json:"rows"`
}

type fidelityDocument struct {
	Chapters []fidelityChapter `json:"chapters"`
}

func trainerDocumentsForFidelity(t *testing.T) map[string]fidelityDocument {
	t.Helper()
	documents := map[string]fidelityDocument{}
	for _, name := range trainerPages {
		raw := readFile(t, name)
		matches := trainerDataPattern.FindStringSubmatch(raw)
		if len(matches) != 2 {
			t.Fatalf("%s: missing exactly one trainerData document", name)
		}
		var doc fidelityDocument
		if err := json.Unmarshal([]byte(matches[1]), &doc); err != nil {
			t.Fatalf("%s: parse trainerData: %v", name, err)
		}
		documents[name] = doc
	}
	return documents
}

var staleCapabilityStatus = regexp.MustCompile(`(?i)\bplanned\b|\brejected\b|\bjs\s+only\b`)

func providerInLabel(label string, capabilities providerGrantCapabilities) string {
	lower := strings.ToLower(label)
	for provider := range capabilities {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(provider) + `\b`).MatchString(lower) {
			return provider
		}
	}
	return ""
}

func capabilityKindsForCell(chapter fidelityChapter, row fidelityRow, column, cellText string) []string {
	columnAndRow := strings.ToLower(column + " " + row.Label)
	chapterText := strings.ToLower(chapter.Title + " " + chapter.Lede + " " + chapter.Prompt)
	isCapability := strings.Contains(columnAndRow, "grant") ||
		strings.Contains(columnAndRow, "capabil") ||
		(strings.Contains(chapterText, "permission slip") &&
			(strings.Contains(strings.ToLower(column), "today") || strings.Contains(strings.ToLower(column), "status")))
	if !isCapability {
		return nil
	}
	if regexp.MustCompile(`(?i)\bjs\s+only\b`).MatchString(cellText) {
		return []string{"project"}
	}
	hasProject := strings.Contains(columnAndRow, "project")
	hasJavaScript := strings.Contains(columnAndRow, "javascript") ||
		regexp.MustCompile(`\bjs\b`).MatchString(columnAndRow) || strings.Contains(columnAndRow, "snippet")
	switch {
	case hasProject && !hasJavaScript:
		return []string{"project"}
	case hasJavaScript && !hasProject:
		return []string{"javascript"}
	default:
		return []string{"javascript", "project"}
	}
}

// TestTrainerGrantMatrixCellsMatchSource parses the JSON matrix structure itself.
// It derives provider names and operation-specific grant support from Name and
// Supports*Grants methods, then rejects stale status words only when the referenced
// capability is live. A legitimate WASM project-grant "rejected" cell therefore
// remains valid, while the same cell for Docker fails without adding a phrase to a
// denylist.
func TestTrainerGrantMatrixCellsMatchSource(t *testing.T) {
	capabilities := providerCapabilitiesFromSource(t)
	for page, document := range trainerDocumentsForFidelity(t) {
		for _, chapter := range document.Chapters {
			if chapter.Kind != "matrix" {
				continue
			}
			for _, row := range chapter.Rows {
				provider := providerInLabel(row.Label, capabilities)
				if provider == "" {
					continue
				}
				for i, cell := range row.Cells {
					if i >= len(chapter.Columns) {
						t.Errorf("%s chapter %q row %q has a cell without a column", page, chapter.ID, row.Label)
						continue
					}
					cellText := cell.Text + " " + cell.Note
					status := staleCapabilityStatus.FindString(cellText)
					if status == "" {
						continue
					}
					for _, kind := range capabilityKindsForCell(chapter, row, chapter.Columns[i], cellText) {
						if capabilities[provider][kind] {
							t.Errorf("%s chapter %q capability cell %q/%q says %q, but %s %s grants are live in source",
								page, chapter.ID, row.Label, chapter.Columns[i], status, provider, kind)
						}
					}
				}
			}
		}
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
	// The positive half: the two pages that carry a status stat must say shipped.
	for _, page := range []string{"advisor.html", "capacity-endpoint.html", "brokering.html"} {
		if !strings.Contains(readFile(t, page), `"status","value":"shipped"`) {
			t.Errorf("%s lost its shipped status stat", page)
		}
	}
}

// TestTrainerNumericLimitsMatchTheConstants pairs each human-readable ceiling with
// the constant it is a rendering of. This is the one place a fact list is
// unavoidable: "256 KiB" cannot be derived from `MaxCodeBytes = 256 << 10` without
// re-implementing the rendering, so the pairing is stated once, here, beside it.
func TestTrainerNumericLimitsMatchTheConstants(t *testing.T) {
	space := regexp.MustCompile(`\s+`)
	flat := space.ReplaceAllString(plimsollSource(t), " ")
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
		{"maxHostCallsPerRun = 256", "256 calls", "per-run host call budget"},
		{"breakerMaxCooldown = 30 * time.Second", "30s", "circuit-breaker cooldown cap"},
	} {
		if !strings.Contains(flat, c.decl) {
			t.Errorf("the %s constant changed or moved: %q is no longer in the source, so "+
				"the trainers' %q may now be wrong", c.why, c.decl, c.rendered)
			continue
		}
		found := false
		for _, prose := range trainerProse(t) {
			if strings.Contains(prose, c.rendered) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no trainer renders the %s as %q; if the wording changed, change it here too",
				c.why, c.rendered)
		}
	}
}
