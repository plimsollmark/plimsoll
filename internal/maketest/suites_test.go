// Package maketest tests the Makefile itself: that every target whose help line says it
// FAILS (a suite that is a request for proof) runs its commands through the one required
// mode, SUITE_BEGIN and SUITE_END, that the two do what the Makefile says, and that a
// dry run of each such suite runs nothing.
package maketest

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// root is the repository root, two levels above this package.
var root = filepath.Join("..", "..")

// makefiles returns the Makefile and, in a working copy that has one, local.mk, which the
// Makefile includes and which adds targets of its own, by name.
func makefiles(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, name := range []string{"Makefile", "local.mk"} {
		b, err := os.ReadFile(filepath.Join(root, name))
		if os.IsNotExist(err) && name != "Makefile" {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(b)
	}
	return files
}

var (
	helpLine = regexp.MustCompile(`(?m)^## ([A-Za-z0-9_.-]+): (.*)$`)
	// A rule's first line: a target, a colon and prerequisites, not a variable (:=, ::=, ?=, =)
	// and not a target-specific variable (target: NAME = value).
	ruleLine = regexp.MustCompile(`^([A-Za-z0-9_.-]+):(?:[^=]*)$`)
)

// recipes returns each target's recipe in mk, by target: its tab-indented lines, each
// backslash-continued line joined into one, as make reads them.
func recipes(mk string) map[string][]string {
	out := map[string][]string{}
	lines := strings.Split(mk, "\n")
	for i := 0; i < len(lines); i++ {
		m := ruleLine.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		var recipe []string
		for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "\t") {
			i++
			logical := lines[i]
			for strings.HasSuffix(logical, `\`) && i+1 < len(lines) {
				i++
				logical = strings.TrimSuffix(logical, `\`) + " " + strings.TrimSpace(lines[i])
			}
			recipe = append(recipe, logical)
		}
		if len(recipe) > 0 {
			out[m[1]] = append(out[m[1]], recipe...)
		}
	}
	return out
}

// requiredSuites returns every target whose help line, in either file, says FAILS.
func requiredSuites(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, mk := range makefiles(t) {
		for _, m := range helpLine.FindAllStringSubmatch(mk, -1) {
			if strings.Contains(m[2], "FAILS") {
				names = append(names, m[1])
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("no help line says FAILS")
	}
	return names
}

// TestEveryRequiredSuiteRunsThroughTheRunner: a target whose help line says FAILS wraps its
// commands in SUITE_BEGIN and SUITE_END, on one recipe line, and a target that does says
// so in its help; no other recipe copies the pattern (a tee into tmp/ or a scan for
// skipped tests), which drifted in the eleven copies it replaced (review item 3,
// 2026-11-18): a suite with no scan at all passed when its coverage was skipped.
func TestEveryRequiredSuiteRunsThroughTheRunner(t *testing.T) {
	for name, mk := range makefiles(t) {
		help := map[string]string{}
		for _, m := range helpLine.FindAllStringSubmatch(mk, -1) {
			help[m[1]] = m[2]
		}
		for target, recipe := range recipes(mk) {
			uses := false
			for _, line := range recipe {
				begin, end := strings.Index(line, "$(SUITE_BEGIN)"), strings.Index(line, "$(SUITE_END)")
				if begin >= 0 != (end >= 0) || end >= 0 && end < begin {
					t.Errorf("%s: %s has a recipe line with one half of the runner, or the halves reversed: %s", name, target, line)
				}
				uses = uses || begin >= 0 && end > begin
				if strings.Contains(line, "--- SKIP") || regexp.MustCompile(`\| *tee (-a )?tmp/`).MatchString(line) {
					t.Errorf("%s: %s copies the runner's pattern instead of using SUITE_BEGIN and SUITE_END: %s", name, target, line)
				}
			}
			text, documented := help[target]
			switch {
			case strings.Contains(text, "FAILS") && !uses:
				t.Errorf("%s: %s says it FAILS, and does not run through SUITE_BEGIN and SUITE_END", name, target)
			case uses && !documented:
				t.Errorf("%s: %s runs through the runner and has no help line saying it FAILS", name, target)
			case uses && !strings.Contains(text, "FAILS"):
				t.Errorf("%s: %s runs through the runner, and its help line does not say a skipped test FAILS it: %q", name, target, text)
			}
		}
	}
}

// TestTheRunner runs a scratch target through SUITE_BEGIN and SUITE_END, in a directory of
// its own holding a small Go module with real tests: a passing test passes and its output
// is in tmp/<target>.log; a test that skips fails the target and is named, read from go
// test's structured results (so it fails the same without -v, and with go test's words
// changed); a go test that does not run through the reader fails the target, pass or skip,
// since it leaves no result; a selection that matches no test fails; a failing command's
// status is the target's; a command that leaves no status fails; and a tmp/ that cannot be
// written fails before anything runs.
func TestTheRunner(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	makefile, err := filepath.Abs(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	module := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		files := map[string]string{
			"go.mod": "module scratch\n\ngo 1.24\n",
			"scratch_test.go": `package scratch

import "testing"

func TestPasses(t *testing.T) { t.Log("it ran") }

func TestSkips(t *testing.T) { t.Skip("this one needs something that is not here") }

func TestSkipsInside(t *testing.T) {
	t.Run("case", func(t *testing.T) { t.Skip("a case that did not run") })
}

func TestFails(t *testing.T) { t.Fatal("broken on purpose") }
`,
		}
		for name, text := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	run := func(t *testing.T, dir, command string) (string, error) {
		t.Helper()
		scratch := filepath.Join(t.TempDir(), "scratch.mk")
		if err := os.WriteFile(scratch, []byte("scratch-suite:\n\t@$(SUITE_BEGIN) "+command+"; $(SUITE_END)\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("make", "--no-print-directory", "-C", dir, "-f", makefile, "-f", scratch, "scratch-suite")
		// Not the flags of the make this test runs under: a SUITE_TAG there (the landing gate
		// tags each stage's suite files) would rename the files this test reads.
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off", "MAKEFLAGS=", "MFLAGS=", "SUITE_TAG=")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	t.Run("pass", func(t *testing.T) {
		dir := module(t)
		out, err := run(t, dir, `$(SUITE_TEST) -run '^TestPasses$$' -count=1 ./...`)
		if err != nil || !strings.Contains(out, "scratch-suite: OK") {
			t.Fatalf("a passing test: %v\n%s", err, out)
		}
		if log, _ := os.ReadFile(filepath.Join(dir, "tmp", "scratch-suite.log")); !strings.Contains(string(log), "--- PASS: TestPasses") || !strings.Contains(string(log), "it ran") {
			t.Fatalf("the log does not hold what go test -v would print: %q", log)
		}
		var res struct{ Package, Test, Action string }
		b, _ := os.ReadFile(filepath.Join(dir, "tmp", "scratch-suite.results"))
		if err := json.Unmarshal([]byte(strings.SplitN(string(b), "\n", 2)[0]), &res); err != nil || res.Test != "TestPasses" || res.Action != "pass" || res.Package != "scratch" {
			t.Fatalf("the results file's first line is not TestPasses passing: %v %q", err, b)
		}
	})
	for name, pattern := range map[string]string{"skip": "^(TestPasses|TestSkips)$$", "skip in a subtest": "^(TestPasses|TestSkipsInside)$$"} {
		t.Run(name, func(t *testing.T) {
			out, err := run(t, module(t), `$(SUITE_TEST) -run '`+pattern+`' -count=1 ./...`)
			if err == nil || !strings.Contains(out, "required coverage was skipped:") || !strings.Contains(out, "--- SKIP: scratch TestSkips") || strings.Contains(out, "scratch-suite: OK") {
				t.Fatalf("a skipped test beside a passing one, go test exiting 0: %v\n%s", err, out)
			}
			if !strings.Contains(out, "did not run") && !strings.Contains(out, "is not here") {
				t.Fatalf("the skipped test's own reason is not in the refusal:\n%s", out)
			}
		})
	}
	t.Run("go test past the reader", func(t *testing.T) {
		for _, command := range []string{
			`go test -run '^TestPasses$$' -count=1 -v ./...`,
			`go test -run '^(TestPasses|TestSkips)$$' -count=1 ./...`, // no -v: the old scan saw nothing here
		} {
			out, err := run(t, module(t), command)
			if err == nil || !strings.Contains(out, "no test result was recorded") || strings.Contains(out, "scratch-suite: OK") {
				t.Fatalf("%s, which leaves no structured result: %v\n%s", command, err, out)
			}
		}
	})
	t.Run("nothing selected", func(t *testing.T) {
		out, err := run(t, module(t), `$(SUITE_TEST) -run '^TestNoSuchTest$$' -count=1 ./...`)
		if err == nil || !strings.Contains(out, "ran no test") || strings.Contains(out, "scratch-suite: OK") {
			t.Fatalf("a selection that matches no test: %v\n%s", err, out)
		}
	})
	t.Run("fail", func(t *testing.T) {
		out, err := run(t, module(t), `$(SUITE_TEST) -run '^(TestPasses|TestFails)$$' -count=1 ./...`)
		if err == nil || !strings.Contains(out, "broken on purpose") || !strings.Contains(out, "Error 1") || strings.Contains(out, "scratch-suite: OK") {
			t.Fatalf("a failing test: %v\n%s", err, out)
		}
		out, err = run(t, module(t), `$(SUITE_TEST) -run '^TestPasses$$' -count=1 ./... && (exit 3)`)
		if err == nil || !strings.Contains(out, "Error 3") || strings.Contains(out, "scratch-suite: OK") {
			t.Fatalf("a command that exits 3 after a passing test: %v\n%s", err, out)
		}
	})
	t.Run("no status", func(t *testing.T) {
		out, err := run(t, module(t), `$(SUITE_TEST) -run '^TestPasses$$' -count=1 ./... && exit 0`)
		if err == nil || strings.Contains(out, "scratch-suite: OK") {
			t.Fatalf("a command that ends the shell before its status is written: %v\n%s", err, out)
		}
	})
	t.Run("a test program's own output", func(t *testing.T) {
		// A suite that runs compiled test programs itself hands their output to the reader's stream.
		dir := module(t)
		build := exec.Command("go", "test", "-c", "-o", "scratch.test", ".")
		build.Dir = dir
		build.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
		if b, err := build.CombinedOutput(); err != nil {
			t.Fatalf("go test -c: %v\n%s", err, b)
		}
		out, err := run(t, dir, `./scratch.test -test.run '^TestPasses$$' -test.v=test2json | $(SUITE_READER) stream . -run TestPasses`)
		if err != nil || !strings.Contains(out, "scratch-suite: OK") {
			t.Fatalf("a passing test program through stream: %v\n%s", err, out)
		}
		out, err = run(t, dir, `./scratch.test -test.run '^(TestPasses|TestSkips)$$' -test.v=test2json | $(SUITE_READER) stream . -run TestPasses`)
		if err == nil || !strings.Contains(out, "required coverage was skipped:") || !strings.Contains(out, "TestSkips") {
			t.Fatalf("a skipped test in a test program's output: %v\n%s", err, out)
		}
		out, err = run(t, dir, `./scratch.test -test.run '^(TestPasses|TestFails)$$' -test.v=test2json | $(SUITE_READER) stream . -run TestPasses`)
		if err == nil || strings.Contains(out, "scratch-suite: OK") {
			t.Fatalf("a failed test in a test program's output: %v\n%s", err, out)
		}
	})
	t.Run("tmp not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes a read-only directory")
		}
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "tmp"), 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "tmp"), 0o755) })
		out, err := run(t, dir, `echo ran`)
		if err == nil || !strings.Contains(out, "scratch-suite: tmp/ is not writable") || strings.Contains(out, "ran") {
			t.Fatalf("an unwritable tmp/: %v\n%s", err, out)
		}
	})
}

// TestDockerSuiteParts: the docker suite's parts, as make docker-suite-parts prints them for
// CI's matrix, are each a required suite, name only framework environments that have a lock,
// and are what make docker-suite runs (every part's go test in its dry run, nothing run); and
// the docker workflow reads that list and runs each entry's target, called once for runc and
// once for runsc. A part CI did not run would be coverage dropped without a word.
func TestDockerSuiteParts(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	out, err := exec.Command("make", "-s", "--no-print-directory", "-C", root, "docker-suite-parts").Output()
	if err != nil {
		t.Fatalf("make docker-suite-parts: %v", err)
	}
	var parts []struct{ Part, Frameworks, Python, Node string }
	if err := json.Unmarshal(out, &parts); err != nil || len(parts) == 0 {
		t.Fatalf("make docker-suite-parts printed no list of parts: %v\n%s", err, out)
	}
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	nodeVersion := regexp.MustCompile(`(?m)^NODE_VERSION := (\S+)$`).FindSubmatch(makefile)
	if nodeVersion == nil {
		t.Fatal("the Makefile declares no NODE_VERSION")
	}
	required := map[string]bool{}
	for _, name := range requiredSuites(t) {
		required[name] = true
	}
	bin := t.TempDir()
	for _, name := range []string{"go", "npm", "docker"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("make", "-n", "--no-print-directory", "-C", root, "docker-suite", "DOCKER=1")
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dry, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n docker-suite: %v\n%s", err, dry)
	}
	for _, p := range parts {
		if !required[p.Part] {
			t.Errorf("part %s is not a required suite (its help line must say a skipped test FAILS it)", p.Part)
		}
		if p.Python == "" {
			t.Errorf("part %s carries no Python version", p.Part)
		}
		for _, fw := range strings.Fields(p.Frameworks) {
			if _, err := os.Stat(filepath.Join(root, "clients", "python", "frameworks", fw, "requirements.txt")); err != nil {
				t.Errorf("part %s names framework environment %s, which has no lock: %v", p.Part, fw, err)
			}
		}
		// Each part's recipe, as the dry run of docker-suite prints it, holds its go test.
		dryPart := exec.Command("make", "-n", "--no-print-directory", "-C", root, p.Part, "DOCKER=1")
		dryPart.Env = cmd.Env
		own, err := dryPart.CombinedOutput()
		if err != nil {
			t.Fatalf("make -n %s: %v\n%s", p.Part, err, own)
		}
		if !strings.Contains(string(own), ".reader test ") || !strings.Contains(string(dry), string(own)) {
			t.Errorf("make -n docker-suite does not print part %s's commands:\n%s", p.Part, own)
		}
		// A part that runs the example programs runs node (the TypeScript client's granted
		// example), so CI must install the node the Makefile names for it.
		if strings.Contains(string(own), "TestPythonExamplesDocker") && p.Node != string(nodeVersion[1]) {
			t.Errorf("part %s runs the example programs, which need node, and names node %q, not NODE_VERSION %s", p.Part, p.Node, nodeVersion[1])
		}
	}
	workflow := func(name string) string {
		b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	suite := workflow("docker-suite.yml")
	for _, want := range []string{"make -s --no-print-directory docker-suite-parts", "include: ${{ fromJSON(needs.parts.outputs.parts) }}", `make "$PART"`,
		"if: matrix.node != ''", "node-version: ${{ matrix.node }}"} {
		if !strings.Contains(suite, want) {
			t.Errorf("docker-suite.yml does not hold %q: CI would not run the Makefile's parts as the Makefile states them", want)
		}
	}
	// The clients job pins node by hand; it is the same node the parts get.
	if !strings.Contains(workflow("audit.yml"), "node-version: '"+string(nodeVersion[1])+"'") {
		t.Errorf("audit.yml's clients job does not pin node %s, the Makefile's NODE_VERSION", nodeVersion[1])
	}
	call := regexp.MustCompile(`(?m)^    uses: \./\.github/workflows/docker-suite\.yml\n    with:\n      runtime: (\S+)$`)
	for file, runtime := range map[string]string{"audit.yml": "runc", "gvisor.yml": "runsc"} {
		m := call.FindStringSubmatch(workflow(file))
		if m == nil || m[1] != runtime {
			t.Errorf("%s does not call docker-suite.yml with runtime %s", file, runtime)
		}
	}
}

// TestFrameworksCacheKey: make py-frameworks-key, the key CI restores tmp/py-frameworks under,
// changes when any input of an environment does (a lock's content, the list of names, the
// locks' Python, the py-frameworks recipe) and refuses a name with no lock, in a scratch tree
// of two stand-in locks. A key that missed an input would restore an environment built from
// another lock, and only the stamps would then stand between CI and a stale environment.
func TestFrameworksCacheKey(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	src, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(rel, text string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("Makefile", string(src))
	write("clients/python/frameworks/a/requirements.txt", "a==1\n")
	write("clients/python/frameworks/b/requirements.txt", "b==1\n")
	key := func(args ...string) (string, error) {
		t.Helper()
		out, err := exec.Command("make", append([]string{"-s", "--no-print-directory", "-C", dir, "py-frameworks-key"}, args...)...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	base, err := key()
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(base) {
		t.Fatalf("make py-frameworks-key: %v %q", err, base)
	}
	if again, _ := key(); again != base {
		t.Fatalf("the key is not stable: %s then %s", base, again)
	}
	changed := map[string]func() (string, error){
		"the list":   func() (string, error) { return key("PY_FRAMEWORKS=a") },
		"the Python": func() (string, error) { return key("PY_FRAMEWORKS_PYTHON=3.13") },
		"a lock": func() (string, error) {
			write("clients/python/frameworks/b/requirements.txt", "b==2\n")
			defer write("clients/python/frameworks/b/requirements.txt", "b==1\n")
			return key()
		},
		"the recipe": func() (string, error) {
			write("Makefile", strings.Replace(string(src), "--require-hashes --no-deps", "--require-hashes --no-deps --no-compile", 1))
			defer write("Makefile", string(src))
			return key()
		},
	}
	for what, k := range changed {
		got, err := k()
		if err != nil || got == base {
			t.Errorf("the key did not change with %s: %v %q", what, err, got)
		}
	}
	if out, err := key("PY_FRAMEWORKS=a nonesuch"); err == nil || !strings.Contains(out, "no lock for nonesuch") {
		t.Errorf("a name with no lock is not refused: %v %q", err, out)
	}
}

// TestFrameworkLocksNameOnePython: the Python the Makefile declares for the framework locks
// (make py-frameworks-python, which CI's jobs install) is the one every lock was compiled
// with, by its pip-compile header, and no workflow that sets up Python for them names a
// version of its own: one declared value, so a new lock or a new job cannot disagree with it.
func TestFrameworkLocksNameOnePython(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	out, err := exec.Command("make", "-s", "--no-print-directory", "-C", root, "py-frameworks-python").Output()
	if err != nil {
		t.Fatalf("make py-frameworks-python: %v", err)
	}
	want := strings.TrimSpace(string(out))
	locks, err := filepath.Glob(filepath.Join(root, "clients", "python", "frameworks", "*", "requirements.txt"))
	if err != nil || len(locks) == 0 {
		t.Fatalf("no framework locks: %v", err)
	}
	header := regexp.MustCompile(`(?m)^# This file is autogenerated by pip-compile with Python (\S+)$`)
	for _, lock := range locks {
		b, err := os.ReadFile(lock)
		if err != nil {
			t.Fatal(err)
		}
		if m := header.FindSubmatch(b); m == nil || string(m[1]) != want {
			t.Errorf("%s was not compiled for Python %s (make py-frameworks-python): header %q", lock, want, m)
		}
	}
	for _, name := range []string{"audit.yml", "docker-suite.yml"} {
		b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range regexp.MustCompile(`(?m)^\s+python-version: (.+)$`).FindAllStringSubmatch(string(b), -1) {
			if !strings.HasPrefix(m[1], "${{ ") {
				t.Errorf("%s sets up Python %s by hand; it reads the version from make py-frameworks-python", name, m[1])
			}
		}
	}
}

// TestSuiteDryRunsRunNoTest: make -n of each required suite prints its commands, its go test
// among them, and runs none. GNU make runs a recipe line holding $(MAKE) even under -n, so a
// line that both built the environments and ran go test ran the docker-backed checks for real
// (review finding release-36): a suite keeps such a line on its own. Stand-ins for go, npm
// and docker first on PATH record any call.
func TestSuiteDryRunsRunNoTest(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	bin, calls := t.TempDir(), filepath.Join(t.TempDir(), "calls")
	for _, name := range []string{"go", "npm", "docker"} {
		script := "#!/bin/sh\necho \"" + name + " $*\" >> '" + calls + "'\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The go test each suite's dry run must print, through the results reader ($(SUITE_TEST)):
	// the two suites that build environments with $(MAKE) first name the one after that line,
	// so the dry run is seen to reach it.
	printed := map[string]string{
		"docker-py-suite": ".reader test ./clients/python -run",
		"clients-suite":   ".reader test ./clients/python/ ./clients/typescript/",
	}
	for _, suite := range requiredSuites(t) {
		cmd := exec.Command("make", "-n", "--no-print-directory", "-C", root, suite, "DOCKER=1")
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make -n %s: %v\n%s", suite, err, out)
		}
		want, ok := printed[suite]
		if !ok {
			want = ".reader " // the reader's test, or its stream for a suite that runs test programs itself
		}
		if !strings.Contains(string(out), want) {
			t.Errorf("make -n %s printed no %q:\n%s", suite, want, out)
		}
		if b, err := os.ReadFile(calls); err == nil {
			t.Fatalf("make -n %s ran commands:\n%s", suite, b)
		}
	}
}

// TestRuntimeBlindTests: the tests docker-go-suite leaves out of a pass under a named runtime
// (DOCKER_RUNTIME_BLIND) are tests whose containers never run under that runtime, so the pass
// they are left out of would only repeat the default pass. Every test of the selection the
// pattern names is in a file that never reads the runtime setting and never passes docker a
// runtime; the pattern names tests (a pattern that matched nothing would hold trivially); and
// the suite's dry run carries the pattern in its -skip under runsc and not under the default
// runtime or runc named outright, where these tests are proven.
func TestRuntimeBlindTests(t *testing.T) {
	mk := makefiles(t)["Makefile"]
	value := func(name string) string {
		m := regexp.MustCompile(`(?m)^` + name + ` := (.*)$`).FindStringSubmatch(mk)
		if m == nil {
			t.Fatalf("the Makefile sets no %s", name)
		}
		return m[1]
	}
	selected, blind := regexp.MustCompile(value("DOCKER_TESTS")), regexp.MustCompile(value("DOCKER_RUNTIME_BLIND"))
	testFunc := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	readsRuntime := regexp.MustCompile(`SANDBOX_DOCKER_RUNTIME|\btestDocker\(|\bsessionDocker\(|\bpythonSessionDocker\(|\bdockertest\.|\.Runtime\b|"--runtime"`)
	named := 0
	for _, dir := range []string{"sandbox", "sandbox/openshell", "sandbox/agentsandbox", "docker"} {
		files, err := filepath.Glob(filepath.Join(root, dir, "*_test.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no test files in %s: %v", dir, err)
		}
		for _, file := range files {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range testFunc.FindAllStringSubmatch(string(b), -1) {
				if !selected.MatchString(m[1]) || !blind.MatchString(m[1]) {
					continue
				}
				named++
				if hit := readsRuntime.FindString(string(b)); hit != "" {
					t.Errorf("%s is left out of a pass under a named runtime (DOCKER_RUNTIME_BLIND), but its file %s reads the runtime (%s): under another runtime it may prove something the default pass does not", m[1], filepath.Base(file), hit)
				}
			}
		}
	}
	if named < 10 {
		t.Errorf("DOCKER_RUNTIME_BLIND names %d tests of the docker suite's selection; the stand-in for E2B's service has 14", named)
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	for runtime, left := range map[string]bool{"": false, "runc": false, "runsc": true} {
		cmd := exec.Command("make", "-n", "--no-print-directory", "-C", root, "docker-go-suite")
		cmd.Env = append(os.Environ(), "SANDBOX_DOCKER_RUNTIME="+runtime)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("make -n docker-go-suite under %q: %v", runtime, err)
		}
		skip := regexp.MustCompile(`-skip '([^']*)'`).FindStringSubmatch(string(out))
		if skip == nil {
			t.Fatalf("make -n docker-go-suite under %q printed no -skip:\n%s", runtime, out)
		}
		if got := strings.Contains(skip[1], blind.String()); got != left {
			t.Errorf("under SANDBOX_DOCKER_RUNTIME=%q the suite's -skip is %q; the runtime-blind tests are left out there: %v, want %v", runtime, skip[1], got, left)
		}
		if !strings.HasPrefix(skip[1], "Live$") {
			t.Errorf("under SANDBOX_DOCKER_RUNTIME=%q the suite's -skip %q no longer starts with the live tests' Live$", runtime, skip[1])
		}
	}
}

// TestShortPassReadsEveryByHandList: the short pass's check of skipped tests (make race,
// suiterun unselected) is handed the published list of tests run by hand, and every list a
// working copy's local.mk adds to BY_HAND_TESTS. On 2026-11-20 the Makefile's own
// assignment replaced the working copy's, and the first gate through it failed the short
// pass on twelve tests that were listed.
func TestShortPassReadsEveryByHandList(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	out, err := exec.Command("make", "-n", "--no-print-directory", "-C", root, "race").Output()
	if err != nil {
		t.Fatalf("make -n race: %v", err)
	}
	var check string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, " unselected ") {
			check = line
		}
	}
	if check == "" {
		t.Fatalf("make -n race prints no check of skipped tests (suiterun unselected):\n%s", out)
	}
	lists := []string{"internal/suiterun/by-hand-tests.txt"}
	for _, mk := range makefiles(t) {
		for _, m := range regexp.MustCompile(`(?m)^BY_HAND_TESTS \+= (\S+)$`).FindAllStringSubmatch(mk, -1) {
			lists = append(lists, m[1])
		}
	}
	for _, list := range lists {
		if !strings.Contains(check+" ", " "+list+" ") {
			t.Errorf("the short pass's check is not handed %s: %s", list, check)
		}
		if _, err := os.Stat(filepath.Join(root, list)); err != nil {
			t.Errorf("BY_HAND_TESTS names %s: %v", list, err)
		}
	}
}

// TestAgentSandboxSuiteDockerRun: on a kind cluster (AGENTSANDBOX_NETWORK set) the agent-sandbox
// suite runs its test programs in a container, and the docker run it starts is read as docker
// reads it: every argument before the image is a flag or a flag's value, the image is alpine:3,
// and each file setting and the test programs' folder are mounted read-only with -v. Commit
// a4b65b589 dropped the two -v flags with go test's, so docker took a mount for the image name
// and stopped with "invalid reference format" before any test (finding release-99). The recipe
// runs for real with go and docker stand-ins first on PATH and the runner's two halves replaced,
// so nothing is built, nothing runs in docker and no suite file under tmp/ is touched.
func TestAgentSandboxSuiteDockerRun(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	bin, calls := t.TempDir(), filepath.Join(t.TempDir(), "calls")
	for name, script := range map[string]string{
		"go":     "#!/bin/sh\nexit 0\n",
		"docker": "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '" + calls + "'\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{}
	dir := t.TempDir()
	for _, v := range []string{"SANDBOX_AGENTSANDBOX_CA_FILE", "SANDBOX_AGENTSANDBOX_TOKEN_FILE",
		"SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE", "SANDBOX_AGENTSANDBOX_SANDBOXD_CA_FILE"} {
		files[v] = filepath.Join(dir, strings.ToLower(v))
	}
	cmd := exec.Command("make", "--no-print-directory", "-C", root, "agentsandbox-suite",
		"AGENTSANDBOX_NETWORK=kind", "AGENTSANDBOX_POD_ROUTE=10.244.0.0/16 via 172.24.0.2",
		"SUITE_BEGIN={", "SUITE_END=}", "SUITE_READER=:")
	// Not the flags of the make this test runs under, and none of the suite's settings from
	// the environment this test was started in.
	cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	for v, f := range files {
		cmd.Env = append(cmd.Env, v+"="+f)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make agentsandbox-suite with stand-ins: %v\n%s", err, out)
	}
	b, err := os.ReadFile(calls)
	if err != nil {
		t.Fatalf("the suite started no docker: %v", err)
	}
	args := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if args[0] != "run" {
		t.Fatalf("the suite's docker call is not a run: %q", args)
	}
	// The flags this docker run may carry: those that take a value, and --rm, which does not.
	valued := map[string]bool{"--network": true, "--cap-add": true, "-e": true, "-v": true}
	image, mounts := "", map[string]bool{}
	for i := 1; i < len(args) && image == ""; i++ {
		switch a := args[i]; {
		case a == "--rm":
		case valued[a] && i+1 < len(args):
			i++
			if a == "-v" {
				mounts[args[i]] = true
			}
		case strings.HasPrefix(a, "-"):
			t.Fatalf("the suite's docker run carries a flag this test does not know, %q: %q", a, args)
		default:
			image = a
		}
	}
	if image != "alpine:3" {
		t.Fatalf("docker reads %q as the image, not alpine:3 (a mount without its -v?): %q", image, args)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(abs, "tmp", "agentsandbox-suite") + ":/suite:ro"}
	for _, f := range files {
		want = append(want, f+":"+f+":ro")
	}
	for _, m := range want {
		if !mounts[m] {
			t.Errorf("the suite's docker run does not mount %q with -v: %q", m, args)
		}
	}
}
