package sandbox_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// guestScriptTests names, for every Node program a provider embeds in its Go source and
// sends into a sandbox, the docker-suite test that runs it. A provider whose sandboxes
// are remote (OpenShell, agent-sandbox, E2B) is proven live only against its service, so
// an edit that breaks one of its scripts passed every offline gate: a rename of .write to
// .Write in Go source also changed process.stdout.write in OpenShell's scripts on
// 2026-10-17, and nothing ran them until a gateway did. Each test here runs its script in
// a locked-down docker container, where node is the same, and checks the report parses.
//
// Keys are the file, relative to sandbox/, and the constant's name.
var guestScriptTests = map[string]string{
	"agentsandbox/smoke.go:boundaryScript": "TestDockerRunsTheAgentSandboxBoundaryScript",
	"agentsandbox/smoke.go:runnerScript":   "TestDockerRunsTheAgentSandboxRunnerScript",
	"openshell/smoke.go:mainJS":            "TestDockerRunsTheOpenShellSmokeProject",
	"openshell/smoke.go:smokeProbeScript":  "TestDockerRunsTheOpenShellSmokeScript",
	"openshell/grant.go:relayScript":       "TestDockerRunsTheOpenShellGrantRelay",
	"e2b.go:vmSmokeProbe":                  "TestDockerRunsTheE2BSmokeScript",
	"e2b.go:e2bSessionNodeScript":          "TestE2BSessionDockerSmokeTest",
}

// targetGuestScripts are the Node programs of a provider whose sandboxes no docker-suite run
// can start (wslc: WSL containers on Windows), keyed like guestScriptTests, each with the
// test that runs it in a docker container through a stand-in for the provider's own
// program, and the Makefile target that runs that test, which make audit runs with DOCKER=1.
var targetGuestScripts = map[string]privateGuestScript{
	"wslc/smoke.go:probeScript": {test: "TestLiveSmokeTestEvidence", target: "wslc-docker-check"},
}

// privateGuestScripts are the Node programs of providers that exist only in a working copy
// and never ship, keyed like guestScriptTests, each with the test that runs it in a
// locked-down docker container and the make target (in that copy's local.mk, appended to
// make audit) that runs the test when DOCKER=1. A file of that copy's own fills it; it is
// empty wherever no such provider exists.
var privateGuestScripts = map[string]privateGuestScript{}

type privateGuestScript struct{ test, target string }

// nodeScript reports whether a string literal is a Node program: what such a program
// calls that no other string in the tree does.
func nodeScript(s string) bool {
	return strings.Contains(s, `require("`) || strings.Contains(s, "process.stdout.") || strings.Contains(s, "process.argv")
}

// TestEveryGuestScriptRunsInTheDockerSuite fails when a Node program is embedded in a
// provider's source without a docker-suite test that runs it, when such a test is
// missing, or when the docker suite would not select it. Offline; it reads the source.
func TestEveryGuestScriptRunsInTheDockerSuite(t *testing.T) {
	found := map[string]bool{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == "internal" && path == "internal") {
			// sandbox/internal holds what the docker provider itself runs (sessionkit's
			// programs, the runner wire), proven by the docker suite through docker.
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, name := range spec.Names {
				if i < len(spec.Values) && nodeScript(literalText(spec.Values[i])) {
					found[filepath.ToSlash(path)+":"+name.Name] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) < len(guestScriptTests) {
		t.Fatalf("found %d Node programs, fewer than the table names; is the scan reading the source?", len(found))
	}
	suite := dockerSuite(t)
	for key := range found {
		if dockerOwn(key) {
			continue // the docker provider's own programs run in every docker-suite run
		}
		if p, ok := targetGuestScripts[key]; ok {
			checkTargetGuestScript(t, key, p, "../Makefile")
			continue
		}
		if p, ok := privateGuestScripts[key]; ok {
			checkTargetGuestScript(t, key, p, "../local.mk")
			continue
		}
		name, ok := guestScriptTests[key]
		if !ok {
			t.Errorf("%s is a Node program sent into a sandbox with no docker-suite test that runs it; add one and name it in guestScriptTests", key)
			continue
		}
		dir := filepath.Dir(strings.SplitN(key, ":", 2)[0])
		if !testDefined(t, dir, name) {
			t.Errorf("%s names %s, which no test file in sandbox/%s defines", key, name, dir)
		}
		if !suite.run.MatchString(name) || suite.skip.MatchString(name) {
			t.Errorf("%s is not selected by the docker suite's -run %q -skip %q", name, suite.run, suite.skip)
		}
		if !slices.Contains(suite.packages, pkgPath(dir)) {
			t.Errorf("%s is in %s, which the docker suite does not test (it tests %v)", name, pkgPath(dir), suite.packages)
		}
	}
	for key := range guestScriptTests {
		if !found[key] {
			t.Errorf("guestScriptTests names %s, which is no longer a Node program in the source", key)
		}
	}
	for key := range targetGuestScripts {
		if !found[key] {
			t.Errorf("targetGuestScripts names %s, which is no longer a Node program in the source", key)
		}
	}
	for key := range privateGuestScripts {
		if !found[key] {
			t.Errorf("privateGuestScripts names %s, which is no longer a Node program in the source", key)
		}
	}
}

// checkTargetGuestScript holds a program to the same rule through its own make target, in
// the Makefile (a published provider's) or in a working copy's local.mk (a private one's):
// the test exists, the target's go test line selects it in its package under DOCKER=1 and
// does not skip it, and make audit runs the target (the Makefile's audit recipe with
// DOCKER=1, or local.mk's EXTRA_AUDIT).
func checkTargetGuestScript(t *testing.T, key string, p privateGuestScript, makefile string) {
	t.Helper()
	dir := filepath.Dir(strings.SplitN(key, ":", 2)[0])
	if !testDefined(t, dir, p.test) {
		t.Errorf("%s names %s, which no test file in sandbox/%s defines", key, p.test, dir)
	}
	b, err := os.ReadFile(makefile)
	if err != nil {
		t.Errorf("%s names the target %s, but this tree has no %s to run it: %v", key, p.target, makefile, err)
		return
	}
	mk := string(b)
	recipe := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(p.target) + `:\n\t(.+)$`).FindStringSubmatch(mk)
	if recipe == nil {
		t.Errorf("%s names the target %s, which %s does not define", key, p.target, makefile)
		return
	}
	line := regexp.MustCompile(`DOCKER\)" = "1" \]; then .*\$\(SUITE_TEST\) ` + regexp.QuoteMeta(pkgPath(dir)) + ` -run '([^']+)'(?: -skip '([^']+)')?`).FindStringSubmatch(recipe[1])
	if line == nil || !regexp.MustCompile(line[1]).MatchString(p.test) || line[2] != "" && regexp.MustCompile(line[2]).MatchString(p.test) {
		t.Errorf("%s's target %s does not run %s in %s under DOCKER=1", key, p.target, p.test, pkgPath(dir))
	}
	audited := regexp.MustCompile(`(?m)^EXTRA_AUDIT \+=.*\b` + regexp.QuoteMeta(p.target) + `\b`)
	if filepath.Base(makefile) == "Makefile" {
		audited = regexp.MustCompile(`(?m)^\t@if \[ "\$\(DOCKER\)" = "1" \]; then \$\(MAKE\) ` + regexp.QuoteMeta(p.target) + `;`)
	}
	if !audited.MatchString(mk) {
		t.Errorf("%s's target %s is not run by make audit", key, p.target)
	}
}

// dockerOwn is a file of the docker provider itself (docker.go, docker_*.go and the
// session smoke test it runs), whose programs the docker suite runs through docker. Every
// other provider's programs, a new provider's included, need a test in the table.
func dockerOwn(key string) bool {
	file := strings.SplitN(key, ":", 2)[0]
	return !strings.Contains(file, "/") && !strings.HasPrefix(file, "dockercloud") &&
		(file == "docker.go" || strings.HasPrefix(file, "docker_") || file == "session_smoke.go")
}

// literalText joins the string literals of a constant expression, skipping the rest.
func literalText(e ast.Expr) string {
	var b strings.Builder
	ast.Inspect(e, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				b.WriteString(s)
			}
		}
		return true
	})
	return b.String()
}

func testDefined(t *testing.T, dir, name string) bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "func "+name+"(t *testing.T)") {
			return true
		}
	}
	return false
}

func pkgPath(dir string) string {
	if dir == "." {
		return "./sandbox"
	}
	return "./sandbox/" + filepath.ToSlash(dir)
}

type dockerSuiteSelection struct {
	run, skip *regexp.Regexp
	packages  []string
}

// dockerSuite reads what make docker-suite selects from the Makefile: the DOCKER_TESTS
// pattern, the -skip pattern and the packages of its go test line.
func dockerSuite(t *testing.T) dockerSuiteSelection {
	t.Helper()
	b, err := os.ReadFile("../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	mk := string(b)
	m := regexp.MustCompile(`(?m)^DOCKER_TESTS := (.+)$`).FindStringSubmatch(mk)
	if m == nil {
		t.Fatal("no DOCKER_TESTS in the Makefile")
	}
	var sel dockerSuiteSelection
	sel.run = regexp.MustCompile(strings.TrimSpace(m[1]))
	// The suite's go test runs through the results reader, and its -skip is DOCKER_GO_SKIP:
	// the live tests' pattern, then, under a named runtime other than runc, the tests whose
	// containers never run under it. The default pass's skip is the part before that.
	line := regexp.MustCompile(`(?m)^\s+\$\(NO_PAID_KEYS\) \$\(SUITE_TEST\) -race (.+) -run '\$\(DOCKER_TESTS\)' -skip '\$\(DOCKER_GO_SKIP\)'`).FindStringSubmatch(mk)
	if line == nil {
		t.Fatal("no docker-suite go test line in the Makefile")
	}
	skip := regexp.MustCompile(`(?m)^DOCKER_GO_SKIP = (.*?)\$\(if `).FindStringSubmatch(mk)
	if skip == nil || skip[1] == "" {
		t.Fatal("no DOCKER_GO_SKIP with a default pass's pattern in the Makefile")
	}
	sel.packages = strings.Fields(line[1])
	sel.skip = regexp.MustCompile(strings.ReplaceAll(skip[1], "$$", "$"))
	return sel
}
