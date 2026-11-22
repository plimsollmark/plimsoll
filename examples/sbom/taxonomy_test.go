package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"google.golang.org/protobuf/proto"
)

// The plimsoll property taxonomy (docs/cyclonedx-properties.md) is registered with
// CycloneDX, so readers outside this repository rely on it. These tests hold it to the
// emitter: every name the emitter can write is documented at the element it is written
// on, every documented name is one the emitter writes, and each property in the published
// BOMs appears as often and in the format the document states.

const taxonomyPath = "../../docs/cyclonedx-properties.md"

type taxonomyRow struct {
	placement string // the walker's path for the element, "$" for the BOM's own properties
	text      string // the row's description
}

type taxonomy struct {
	placements map[string]map[string]bool // walker path to the plimsoll names placed there
	rows       map[string][]taxonomyRow   // name to its property rows, one per placement
	evidence   map[string]bool            // names used as an evidence entry's propertyName
}

var backticked = regexp.MustCompile("`([^`]+)`")

// walkerPath turns a JSON path as the document writes it into the walker's form.
func walkerPath(p string) string {
	if p == "$.properties" {
		return "$"
	}
	return p
}

func cells(line string) []string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func readTaxonomy(t *testing.T) taxonomy {
	t.Helper()
	b, err := os.ReadFile(taxonomyPath)
	if err != nil {
		t.Fatal(err)
	}
	tx := taxonomy{placements: map[string]map[string]bool{}, rows: map[string][]taxonomyRow{}, evidence: map[string]bool{}}
	section, heading := "", ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimPrefix(line, "## ")
			heading = ""
			for _, m := range backticked.FindAllStringSubmatch(section, -1) {
				if strings.HasPrefix(m[1], "$") {
					heading = walkerPath(m[1])
				}
			}
			continue
		}
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "|---") {
			continue
		}
		c := cells(line)
		switch {
		case section == "Where the properties go" && len(c) == 3 && strings.HasPrefix(c[0], "`$"):
			path := walkerPath(backticked.FindStringSubmatch(c[0])[1])
			if strings.HasSuffix(path, ".propertyName") {
				for _, m := range backticked.FindAllStringSubmatch(c[2], -1) {
					tx.evidence["plimsoll:"+m[1]] = true
				}
				continue
			}
			names := map[string]bool{}
			for _, m := range backticked.FindAllStringSubmatch(c[2], -1) {
				names["plimsoll:"+m[1]] = true
			}
			tx.placements[path] = names
		case section == "Evidence property names" && len(c) == 2 && strings.HasPrefix(c[0], "`plimsoll:"):
			if !tx.evidence[backticked.FindStringSubmatch(c[0])[1]] {
				t.Errorf("evidence name %s has a row but is not in the placement table", c[0])
			}
		case heading != "" && len(c) == 2 && strings.HasPrefix(c[0], "`plimsoll:"):
			name := backticked.FindStringSubmatch(c[0])[1]
			tx.rows[name] = append(tx.rows[name], taxonomyRow{heading, c[1]})
		}
	}
	if len(tx.placements) == 0 || len(tx.rows) == 0 || len(tx.evidence) == 0 {
		t.Fatalf("read %d placements, %d property rows, %d evidence names from %s: the document's layout changed", len(tx.placements), len(tx.rows), len(tx.evidence), taxonomyPath)
	}
	return tx
}

// emittedNames reads the emitter's source for every name passed to cdxutil.Props (each
// even argument) and every evidence propertyName, so a name only some runs carry (policy,
// instance) is held to the document too.
func emittedNames(t *testing.T) (props, evidence map[string]bool) {
	t.Helper()
	props, evidence = map[string]bool{}, map[string]bool{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Props" {
					return true
				}
				for i := 0; i < len(n.Args); i += 2 {
					lit, ok := n.Args[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Errorf("%s: a Props name is not a string literal, so this test cannot see it", fset.Position(n.Args[i].Pos()))
						continue
					}
					s, _ := strconv.Unquote(lit.Value)
					props["plimsoll:"+s] = true
				}
			case *ast.KeyValueExpr:
				if k, ok := n.Key.(*ast.BasicLit); ok && k.Value == `"propertyName"` {
					v, ok := n.Value.(*ast.BasicLit)
					if !ok || v.Kind != token.STRING {
						t.Errorf("%s: a propertyName is not a string literal, so this test cannot see it", fset.Position(n.Value.Pos()))
						return true
					}
					s, _ := strconv.Unquote(v.Value)
					evidence[s] = true
				}
			}
			return true
		})
	}
	return props, evidence
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestTaxonomyNamesMatchTheEmitter(t *testing.T) {
	tx := readTaxonomy(t)
	props, evidence := emittedNames(t)
	documented := map[string]bool{}
	for path, names := range tx.placements {
		for n := range names {
			documented[n] = true
			found := false
			for _, r := range tx.rows[n] {
				found = found || r.placement == path
			}
			if !found {
				t.Errorf("%s is placed on %s but has no property row under that element", n, path)
			}
		}
	}
	for n, rs := range tx.rows {
		for _, r := range rs {
			if !tx.placements[r.placement][n] {
				t.Errorf("%s has a row under %s but the placement table does not put it there", n, r.placement)
			}
		}
	}
	if got, want := sortedKeys(props), sortedKeys(documented); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("the emitter writes %v; the taxonomy documents %v", got, want)
	}
	if got, want := sortedKeys(evidence), sortedKeys(tx.evidence); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("the emitter's evidence names are %v; the taxonomy documents %v", got, want)
	}
	for n := range documented {
		if n != "plimsoll:emitter" && propertySource(n) == "Emitter mapping constant." {
			t.Errorf("the example page would call %s an emitter constant; give it its source in propertySource", n)
		}
	}
}

func TestPublishedBOMsFollowTheTaxonomy(t *testing.T) {
	tx := readTaxonomy(t)
	files, err := filepath.Glob("../../docs/examples/sbom/run-*.cdx.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no published run BOMs: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		followsTaxonomy(t, tx, filepath.Base(f), b)
	}
}

// TestFreshBOMsFollowTheTaxonomy builds BOMs from the fixture runs with the record's
// optional fields set and the request's optional fields cleared, so a property only some
// runs carry is held to its placement, count and format too, not only the ones the
// published runs happen to have.
func TestFreshBOMsFollowTheTaxonomy(t *testing.T) {
	tx := readTaxonomy(t)
	runs, _, _ := fixtures(t)
	guestGuard := " " + sandbox.GuestGuardPolicyPrefix + strings.Repeat("b", 64)
	policies := []string{"seccomp:sha256:" + strings.Repeat("a", 64), "seccomp:docker-default", "seccomp:unconfined", "seccomp:skipped:runsc",
		"seccomp:sha256:" + strings.Repeat("a", 64) + guestGuard, "seccomp:docker-default" + guestGuard, "seccomp:unconfined" + guestGuard, "seccomp:skipped:runsc" + guestGuard}
	for i, run := range runs {
		with := run
		with.Record.Policy = policies[i%len(policies)]
		with.Record.Instance = "k8s-pod-uid:6f1c3a52-0d1e-4c4b-9a8e-2f7b9c1d0e11"
		bom := decodeBOM(t, emitted(t, with))
		followsTaxonomy(t, tx, "with policy and instance", emitted(t, with))
		w := bom["formulation"].([]any)[0].(map[string]any)["workflows"].([]any)[0].(map[string]any)
		if got := propertyValues(w)["plimsoll:policy"]; len(got) != 1 || got[0] != with.Record.Policy {
			t.Errorf("policy on the workflow is %v, want [%s]", got, with.Record.Policy)
		}
		if got := propertyValues(w)["plimsoll:instance"]; len(got) != 1 || got[0] != with.Record.Instance {
			t.Errorf("instance on the workflow is %v, want [%s]", got, with.Record.Instance)
		}

		without := run
		req := proto.Clone(run.Request).(*plimsollv1.RunRequest)
		req.TraceId = ""
		req.MinimumIsolation = ""
		without.Request = req
		raw := emitted(t, without)
		followsTaxonomy(t, tx, "without a trace id", raw)
		program := decodeBOM(t, raw)["metadata"].(map[string]any)["component"].(map[string]any)
		if got := propertyValues(program)["plimsoll:trace_id"]; len(got) != 0 {
			t.Errorf("a request with no trace id gave plimsoll:trace_id %v; the taxonomy says it is then absent", got)
		}
		w = decodeBOM(t, raw)["formulation"].([]any)[0].(map[string]any)["workflows"].([]any)[0].(map[string]any)
		if got := propertyValues(w)["plimsoll:minimum_isolation"]; len(got) != 1 || got[0] != "" {
			t.Errorf("a request with no floor gave plimsoll:minimum_isolation %v; the taxonomy says it is then written once, empty", got)
		}
	}
}

// TestRunsTheTaxonomyCannotDescribeAreRefused holds the taxonomy's scope: its provider
// list is the providers whose records name the image they ran in. A run from any other
// provider must be refused, not written. WSL runs left this list in taxonomy version 2,
// once their records carry the sentence beside the tier (wslc_test.go).
func TestRunsTheTaxonomyCannotDescribeAreRefused(t *testing.T) {
	runs, _, _ := fixtures(t)
	for _, c := range []struct{ provider, environment string }{
		{"e2b", "e2b-template:" + strings.Repeat("c", 20)},
		{"openshell", "openshell-image:sha256:" + strings.Repeat("d", 64)},
		{"wasm", "quickjs-wasm:sha256:" + strings.Repeat("e", 64)},
	} {
		s := runs[0]
		s.Record.Provider, s.Record.Isolation, s.Record.Environment, s.Record.SoftwareIdentity = c.provider, "vm", c.environment, ""
		o := defaults()
		if _, err := buildBOM(s, o); err == nil || !strings.Contains(err.Error(), "states no image identity this emitter can map") {
			t.Errorf("a %s run gave %v; want it refused for naming no image the emitter can map, since the taxonomy's provider list does not include it", c.provider, err)
		}
	}
}

// TestTaxonomyFollowsTheCanonicalDocs ties the taxonomy's claims to the documents and
// code that define them: the outcome list to the protocol's enumeration, the two values
// the record's digests leave out to the run records page, and the policy forms to it.
func TestTaxonomyFollowsTheCanonicalDocs(t *testing.T) {
	tx := readTaxonomy(t)
	outcomes := map[string]bool{}
	for _, n := range plimsollv1.ProjectOutcome_name {
		if v := strings.ToLower(strings.TrimPrefix(n, "PROJECT_OUTCOME_")); v != "unspecified" {
			outcomes[v] = true
		}
	}
	if got, want := sortedKeys(enumeration(rowText(tx, "plimsoll:outcome", "$.formulation[].workflows[]"))), sortedKeys(outcomes); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("the taxonomy lists outcomes %v; the protocol defines %v", got, want)
	}

	b, err := os.ReadFile("../../docs/run-records.md")
	if err != nil {
		t.Fatal(err)
	}
	records := string(b)
	_, rest, ok := strings.Cut(records, "Left out on purpose:")
	if !ok {
		t.Fatal("docs/run-records.md no longer says which fields the digests leave out")
	}
	rest, _, _ = strings.Cut(rest, "\n\n")
	leftOut := map[string]bool{}
	for _, m := range regexp.MustCompile(`\*\*`+"`?"+`([^*`+"`"+`]+)`+"`?"+`\*\*`).FindAllStringSubmatch(rest, -1) {
		leftOut[m[1]] = true
	}
	for term, c := range map[string]struct{ name, path string }{
		"trace id":  {"plimsoll:trace_id", "$.metadata.component"},
		"durations": {"plimsoll:duration_ms", "$.formulation[].workflows[].tasks[].steps[].commands[]"},
	} {
		if !leftOut[term] {
			t.Errorf("docs/run-records.md no longer leaves %q out of the digests; the taxonomy's %s row says it does", term, c.name)
		}
		if !strings.Contains(rowText(tx, c.name, c.path), "Not covered by the run record's digests") {
			t.Errorf("the %s row does not say the record's digests leave it out", c.name)
		}
	}

	row := ""
	for _, line := range strings.Split(records, "\n") {
		if strings.HasPrefix(line, "| `policy` |") {
			row = line
		}
	}
	policy := strings.ReplaceAll(rowText(tx, "plimsoll:policy", "$.formulation[].workflows[]"), "<digest>", "...")
	forms := regexp.MustCompile("`(seccomp:[^`]+)`").FindAllStringSubmatch(row, -1)
	if len(forms) < 4 {
		t.Fatalf("read %d seccomp forms from the run records page's policy row, want at least 4", len(forms))
	}
	for _, m := range forms {
		if !strings.Contains(policy, "`"+m[1]+"`") {
			t.Errorf("the run records page lists policy %s; the taxonomy's policy row does not", m[1])
		}
	}

	// The guest guard's word: both pages name it as the docker provider writes it, after a
	// seccomp form, and the format check accepts each seccomp form alone and followed by one
	// space and the word, and nothing else.
	word := sandbox.GuestGuardPolicyPrefix + "..."
	for page, text := range map[string]string{"run records page's policy row": row, "taxonomy's policy row": policy} {
		if !regexp.MustCompile("`seccomp:[^` ]+ " + regexp.QuoteMeta(word) + "`").MatchString(text) {
			t.Errorf("the %s does not name the guest guard's word %s after a seccomp form", page, word)
		}
	}
	hex := func(form string) string { return strings.ReplaceAll(form, "...", strings.Repeat("c", 64)) }
	for _, m := range forms {
		seccomp, _, _ := strings.Cut(m[1], " ")
		for _, v := range []string{hex(seccomp), hex(seccomp + " " + word)} {
			if !policyValue.MatchString(v) {
				t.Errorf("the format check refuses %q, a policy the pages allow", v)
			}
		}
		for _, v := range []string{hex(seccomp + " " + word + " " + word), hex(word), hex(seccomp + "  " + word), hex(seccomp + " guard:sha256:...")} {
			if policyValue.MatchString(v) {
				t.Errorf("the format check accepts %q, a policy the pages do not allow", v)
			}
		}
	}
}

var (
	digestValue  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	unsigned     = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	signedValue  = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
	typedValue   = regexp.MustCompile(`^[a-z0-9-]+:.+$`)
	policyValue  = regexp.MustCompile(`^(seccomp:sha256:[0-9a-f]{64}|seccomp:docker-default|seccomp:unconfined|seccomp:skipped:runsc)( ` + regexp.QuoteMeta(sandbox.GuestGuardPolicyPrefix) + `[0-9a-f]{64})?$`)
	traceIDValue = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

func decodeBOM(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func propertyValues(el map[string]any) map[string][]string {
	out := map[string][]string{}
	ps, _ := el["properties"].([]any)
	for _, p := range ps {
		p := p.(map[string]any)
		out[p["name"].(string)] = append(out[p["name"].(string)], p["value"].(string))
	}
	return out
}

// followsTaxonomy checks one BOM against the document: every plimsoll property is on an
// element the document allows, as often and in the format its row states, and the
// evidence entries are the documented ones, each as often as its row states.
func followsTaxonomy(t *testing.T, tx taxonomy, name string, raw []byte) {
	t.Helper()
	tiers := map[string]bool{}
	for _, r := range tx.rows["plimsoll:isolation"] {
		for v := range enumeration(r.text) {
			tiers[v] = true
		}
	}
	if len(tiers) != 4 {
		t.Fatalf("read tiers %v from the isolation row, want four", sortedKeys(tiers))
	}
	elements := map[string][]map[string]any{}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch v := v.(type) {
		case map[string]any:
			elements[path] = append(elements[path], v)
			for k, x := range v {
				if k != "properties" {
					walk(x, path+"."+k)
				}
			}
		case []any:
			for _, x := range v {
				walk(x, path+"[]")
			}
		}
	}
	walk(decodeBOM(t, raw), "$")
	evidence := map[string]int{}
	for _, el := range elements["$.declarations.evidence[]"] {
		n, _ := el["propertyName"].(string)
		if !tx.evidence[n] {
			t.Errorf("%s: evidence propertyName %q is not in the taxonomy", name, n)
		}
		evidence[n]++
	}
	if evidence["plimsoll:run_record"] != 1 || evidence["plimsoll:qualification"] > 1 {
		t.Errorf("%s: evidence entries %v, want plimsoll:run_record exactly once and plimsoll:qualification at most once", name, evidence)
	}
	for path, els := range elements {
		for _, el := range els {
			values := propertyValues(el)
			if path == "$.components[]" && el["bom-ref"] != "image" {
				for n := range values {
					if strings.HasPrefix(n, "plimsoll:") {
						t.Errorf("%s: %s is on component %v; the taxonomy puts it on the image component only", name, n, el["bom-ref"])
					}
				}
				continue
			}
			for n, vs := range values {
				if !strings.HasPrefix(n, "plimsoll:") {
					continue
				}
				if !tx.placements[path][n] {
					t.Errorf("%s: %s is written on %s, which the taxonomy does not allow", name, n, path)
					continue
				}
				text := rowText(tx, n, path)
				for _, v := range vs {
					bad := false
					switch {
					case strings.Contains(text, "_Digest_"):
						bad = !digestValue.MatchString(v)
					case strings.Contains(text, "_Boolean_"):
						bad = v != "true" && v != "false"
					case strings.Contains(text, "_Integer_") && strings.Contains(text, "negative"):
						bad = !signedValue.MatchString(v)
					case strings.Contains(text, "_Integer_"):
						bad = !unsigned.MatchString(v)
					case strings.Contains(text, "_Text_"):
						bad = v == "" || !record.ValidQualification(v)
					case strings.Contains(text, "_Typed reference_"):
						bad = v != "" && !typedValue.MatchString(v)
					}
					switch n {
					case "plimsoll:minimum_isolation":
						bad = bad || v != "" && !tiers[v]
					case "plimsoll:policy":
						bad = bad || !policyValue.MatchString(v)
					case "plimsoll:bundle_line":
						bad = bad || v == "0"
					}
					if bad {
						t.Errorf("%s: %s = %q does not have the format its row states", name, n, v)
					}
					if e := enumeration(text); len(e) > 0 && !e[v] {
						t.Errorf("%s: %s = %q is not one of %v", name, n, v, sortedKeys(e))
					}
					if n == "plimsoll:trace_id" && !traceIDValue.MatchString(v) {
						t.Logf("%s: trace_id %q does not conform; the taxonomy allows that, as the caller sent it", name, v)
					}
				}
			}
			for n := range tx.placements[path] {
				text := rowText(tx, n, path)
				switch {
				case strings.Contains(text, "MUST appear exactly once") && len(values[n]) != 1:
					t.Errorf("%s: %s appears %d times on an element at %s, want exactly once", name, n, len(values[n]), path)
				case strings.Contains(text, "MAY appear at most once") && len(values[n]) > 1,
					strings.Contains(text, "MUST appear exactly when the run record states one") && len(values[n]) > 1:
					t.Errorf("%s: %s appears %d times on an element at %s, want at most once", name, n, len(values[n]), path)
				}
			}
			if path == "$" && (len(values["plimsoll:qualification_sha256"]) == 1) != (evidence["plimsoll:qualification"] == 1) {
				t.Errorf("%s: plimsoll:qualification_sha256 and the qualification evidence must come together", name)
			}
		}
	}
}

func rowText(tx taxonomy, name, path string) string {
	for _, r := range tx.rows[name] {
		if r.placement == path {
			return r.text
		}
	}
	return ""
}

// enumeration reads the values a row lists after "_Enumeration_:" as "`value` (meaning)".
// A row whose list refers to another property's values, rather than naming its own, has none.
func enumeration(text string) map[string]bool {
	_, list, ok := strings.Cut(text, "_Enumeration_:")
	if !ok {
		return nil
	}
	out := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z0-9_]+)` \\(").FindAllStringSubmatch(list, -1) {
		out[m[1]] = true
	}
	return out
}

// TestTaxonomyClaimsNoMoreThanTheRecord pins the wording of the rows an independent review
// found promising more than the run record measures (findings cyclonedx-2, -5, -6 and -9 in
// private/findings/cyclonedx.json): a reader of the taxonomy alone must not take provider
// configuration as a measurement, a caller's value as a checked one, or a requested limit as
// the limit in force, and the provider list must be the providers the emitter maps.
func TestTaxonomyClaimsNoMoreThanTheRecord(t *testing.T) {
	tx := readTaxonomy(t)
	b, err := os.ReadFile(taxonomyPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, banned := range []string{"had no network", "has no network", "Only `plimsoll:exit_code` can be negative", "policy the provider verified for the run, as a typed digest"} {
		if strings.Contains(doc, banned) {
			t.Errorf("the taxonomy says %q, which the run record does not support", banned)
		}
	}
	workflow := "$.formulation[].workflows[]"
	for _, c := range []struct{ name, path, want string }{
		{"plimsoll:grant", workflow, "provider's configuration, not something the run record measures"},
		{"plimsoll:trace_id", "$.metadata.component", "exactly as the caller sent it"},
		{"plimsoll:timeout_ms", workflow, "the limit actually in force is not in the run record"},
		{"plimsoll:timeout_ms", workflow, "MAY be negative"},
		{"plimsoll:isolation", workflow, "not a hardware attestation"},
	} {
		if !strings.Contains(rowText(tx, c.name, c.path), c.want) {
			t.Errorf("the %s row no longer says %q", c.name, c.want)
		}
	}
	if got := sortedKeys(enumeration(rowText(tx, "plimsoll:provider", workflow))); strings.Join(got, " ") != "agentsandbox docker dockercloud wslc" {
		t.Errorf("the provider list is %v; the emitter maps runs on agentsandbox, docker, dockercloud and wslc only (cdxutil.ImageDigest)", got)
	}
	// A WSL run's image is an image ID, never called a pin or a registry manifest digest
	// (finding cyclonedx-13).
	if row := rowText(tx, "plimsoll:environment", walkerPath("$.components[]")); !strings.Contains(row, "the digest is the image ID") ||
		!strings.Contains(row, "It is not a registry manifest digest, and no registry pin is stated") {
		t.Errorf("the environment row does not say a wslc-image digest is an image ID and no pin: %q", row)
	}
}

// TestExamplePageLinksTheTaxonomy: the registry maintainer found property names on the
// example page and no definitions behind them (finding cyclonedx-10), so the page links the
// taxonomy beside every run's field table.
func TestExamplePageLinksTheTaxonomy(t *testing.T) {
	b, err := os.ReadFile("../../docs/examples/sbom/index.html")
	if err != nil {
		t.Fatal(err)
	}
	runs, _ := filepath.Glob("../../docs/examples/sbom/run-*.cdx.json")
	link := `href="https://github.com/plimsollmark/plimsoll/blob/main/docs/cyclonedx-properties.md"`
	if got := strings.Count(string(b), link); got != len(runs) || got == 0 {
		t.Errorf("the example page links the taxonomy %d times, want once beside each of its %d runs' field tables", got, len(runs))
	}
}
