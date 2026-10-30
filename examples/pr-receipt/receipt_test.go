package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/protocol"
)

func receiptScratch(t *testing.T) string {
	t.Helper()
	if err := os.MkdirAll("../../tmp", 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("../../tmp", "receipt-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func receiptCommand(t *testing.T, env []string, program string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(program, args...)
	// A gate may use a temporary index to inspect new files. Fixture git calls
	// must still use their own repository, not inherit that gate's index/objects.
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GIT_") && !strings.HasPrefix(e, "TEST_COMMAND=") && !strings.HasPrefix(e, "PR_BASE_SHA=") && !strings.HasPrefix(e, "PR_HEAD_SHA=") && !strings.HasPrefix(e, "PR_NUMBER=") && !strings.HasPrefix(e, "PR_REPOSITORY=") && !strings.HasPrefix(e, "PLIMSOLL_HARNESS_KEY=") && !strings.HasPrefix(e, "PLIMSOLL_MIN_TESTS=") && !strings.HasPrefix(e, "JUNIT_PATH=") && !strings.HasPrefix(e, "COVERAGE_PATH=") && !strings.HasPrefix(e, "SESSION_TRAILER=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, env...)
	return cmd.CombinedOutput()
}

func TestReceiptPreparationTreatsCommandAsDataAndIncludesChangedFiles(t *testing.T) {
	dir := receiptScratch(t)
	project := filepath.Join(dir, "project")
	if err := os.Mkdir(project, 0755); err != nil {
		t.Fatal(err)
	}
	if out, err := receiptCommand(t, nil, "git", "init", "--quiet", project); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	if err := os.WriteFile(filepath.Join(project, "test.mjs"), []byte("console.log('ok');\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := receiptCommand(t, nil, "git", "-C", project, "add", "test.mjs"); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	command := "touch " + filepath.Join(dir, "must-not-exist")
	env := []string{"TEST_COMMAND=" + command, "PR_NUMBER=42", "PR_REPOSITORY=example/project"}
	if out, err := receiptCommand(t, env, "python3", "prepare.py", project, filepath.Join(dir, "uncommitted")); err == nil {
		t.Fatalf("a project with no commit was prepared: %s", out)
	}
	commit := receiptCommit(t, project)
	// The number must be given, and spelled one way: no default, no leading zero.
	for _, number := range []string{"", "042"} {
		bad := []string{"TEST_COMMAND=" + command, "PR_REPOSITORY=example/project"}
		if number != "" {
			bad = append(bad, "PR_NUMBER="+number)
		}
		if out, err := receiptCommand(t, bad, "python3", "prepare.py", project, filepath.Join(dir, "bad-number")); err == nil || !strings.Contains(string(out), "PR_NUMBER") {
			t.Fatalf("PR_NUMBER %q was accepted: %s", number, out)
		}
	}
	output := filepath.Join(dir, "output")
	if out, err := receiptCommand(t, env, "python3", "prepare.py", project, output); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "must-not-exist")); !os.IsNotExist(err) {
		t.Fatalf("command was run on the host: %v", err)
	}
	request, err := os.ReadFile(filepath.Join(output, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var q struct {
		Protocol         int
		MinimumIsolation string
		Project          struct {
			Files []struct{ Path, Content string }
			Steps []string
		}
	}
	if err := json.Unmarshal(request, &q); err != nil {
		t.Fatal(err)
	}
	if q.Protocol != int(protocol.Number) || q.MinimumIsolation != "kernel" || len(q.Project.Files) != 2 || q.Project.Files[0].Path != "test.mjs" || len(q.Project.Steps) != 1 || q.Project.Steps[0] != command {
		t.Fatalf("wrong request: %s", request)
	}
	// The subject names what was tested inside the signed request.
	if f := q.Project.Files[1]; f.Path != ".pr-receipt/subject.json" || f.Content != "{\n  \"commit\": \""+commit+"\",\n  \"pull_request\": \"42\",\n  \"repository\": \"example/project\"\n}\n" {
		t.Fatalf("wrong subject: %+v", f)
	}
	git := func(args ...string) {
		t.Helper()
		if out, err := receiptCommand(t, nil, "git", append([]string{"-C", project}, args...)...); err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(project, name)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// The files are the commit's own: an edit to a tracked file and a file staged but not
	// committed are not what runs, and the subject still names the commit.
	write("test.mjs", "console.log('changed');\n")
	write("staged.mjs", "console.log('staged');\n")
	git("add", "staged.mjs")
	dirty := filepath.Join(dir, "dirty")
	if out, err := receiptCommand(t, env, "python3", "prepare.py", project, dirty); err != nil {
		t.Fatalf("a working tree with uncommitted changes: %s: %v", out, err)
	}
	if again, err := os.ReadFile(filepath.Join(dirty, "request.json")); err != nil || string(again) != string(request) {
		t.Fatalf("uncommitted changes reached the request (%v):\n%s", err, again)
	}
	git("rm", "-q", "--cached", "staged.mjs")
	git("checkout", "--", "test.mjs")
	if err := os.Remove(filepath.Join(project, "staged.mjs")); err != nil {
		t.Fatal(err)
	}
	// In order: each setup leaves the project as the next one expects.
	for _, c := range []struct {
		name, want string
		setup      func() []string
	}{
		{"no repository", "PR_REPOSITORY", func() []string { return env[:2] }},
		{"a repository with a space", "PR_REPOSITORY", func() []string { return append(env[:2:2], "PR_REPOSITORY=example project") }},
		{"a tracked file under .pr-receipt/", "collide", func() []string {
			write(".pr-receipt/subject.json", "{}\n")
			git("add", ".pr-receipt")
			receiptCommit(t, project)
			return env
		}},
		{"a tracked link", "regular file", func() []string {
			git("rm", "-q", "-r", ".pr-receipt")
			if err := os.Remove(filepath.Join(project, "test.mjs")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(dir, "outside"), filepath.Join(project, "test.mjs")); err != nil {
				t.Fatal(err)
			}
			git("add", "test.mjs")
			receiptCommit(t, project)
			return env
		}},
		{"a submodule", "submodule", func() []string {
			git("rm", "-q", "test.mjs")
			write("test.mjs", "console.log('ok');\n")
			git("add", "test.mjs")
			git("update-index", "--add", "--cacheinfo", "160000,"+commit+",vendor/lib")
			receiptCommit(t, project)
			return env
		}},
	} {
		out, err := receiptCommand(t, c.setup(), "python3", "prepare.py", project, filepath.Join(dir, "refused"))
		if err == nil || !strings.Contains(string(out), c.want) {
			t.Fatalf("%s: want a refusal naming %q, got %v: %s", c.name, c.want, err, out)
		}
	}
}

// receiptCommit commits what is staged and returns the commit.
func receiptCommit(t *testing.T, project string) string {
	t.Helper()
	if out, err := receiptCommand(t, nil, "git", "-C", project, "-c", "user.name=Receipt Test", "-c", "user.email=receipt@example.invalid",
		"-c", "commit.gpgsign=false", "commit", "-q", "-m", "test"); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	out, err := receiptCommand(t, nil, "git", "-C", project, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	return strings.TrimSpace(string(out))
}

func TestReceiptShellSyntax(t *testing.T) {
	if out, err := receiptCommand(t, nil, "bash", "-n", "receipt.sh"); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
}

// An operator key is refused before anything is built or run when it is not a .key file,
// lacks its .pub, or sits inside the project, whose tracked files go into the sandbox.
func TestReceiptOperatorKeyRefusals(t *testing.T) {
	dir := receiptScratch(t)
	project := filepath.Join(dir, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inside.key", "inside.pub", "../outside.key"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct{ key, want string }{
		{filepath.Join(dir, "operator.pem"), "must name a .key file"},
		{filepath.Join(dir, "outside.key"), "needs the .key file and the .pub beside it"},
		{filepath.Join(project, "inside.key"), "must be outside the project"},
	} {
		out, err := receiptCommand(t, []string{"PLIMSOLL_HARNESS_KEY=" + c.key}, "bash", "receipt.sh", project, filepath.Join(dir, "out"))
		if err == nil || !strings.Contains(string(out), c.want) {
			t.Errorf("key %s: got %v, %q; want a refusal saying %q", c.key, err, out, c.want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Errorf("a refused key left an output directory (%v)", err)
	}
}

// A minimum test count is refused before anything is built or run when it is not a whole
// number of 1 or more, or when no test report is asked for, since then nothing is counted.
func TestReceiptMinimumTestsRefusals(t *testing.T) {
	dir := receiptScratch(t)
	project := filepath.Join(dir, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		env  []string
		want string
	}{
		{[]string{"PLIMSOLL_MIN_TESTS=0", "JUNIT_PATH=reports.xml"}, "must be a whole number from 1"},
		{[]string{"PLIMSOLL_MIN_TESTS=02", "JUNIT_PATH=reports.xml"}, "must be a whole number from 1"},
		{[]string{"PLIMSOLL_MIN_TESTS=many", "JUNIT_PATH=reports.xml"}, "must be a whole number from 1"},
		{[]string{"PLIMSOLL_MIN_TESTS=2"}, "needs JUNIT_PATH"},
	} {
		out, err := receiptCommand(t, c.env, "bash", "receipt.sh", project, filepath.Join(dir, "out"))
		if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 2 || !strings.Contains(string(out), c.want) {
			t.Errorf("%v: got %v, %q; want a refusal saying %q", c.env, err, out, c.want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Errorf("a refused minimum left an output directory (%v)", err)
	}
}

// TestReceiptScriptEndToEnd runs receipt.sh as published: a real run under gVisor, the
// bundle verified, the BOM written and checked against the run's key, and nothing in the
// output naming a directory of the machine that made it. It needs docker with runsc and
// the containerd image store, so only make receipt-suite runs it (RECEIPT_SUITE=1), and
// that target fails on a skip.
func TestReceiptScriptEndToEnd(t *testing.T) {
	if os.Getenv("RECEIPT_SUITE") != "1" {
		t.Skip("make receipt-suite runs this: docker, runsc and the containerd image store")
	}
	runtimes, err := exec.Command("docker", "info", "-f", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}").CombinedOutput()
	if err != nil || !strings.Contains(" "+string(runtimes), " runsc ") {
		t.Fatalf("receipt.sh runs under runsc; docker reports runtimes %q (%v)", runtimes, err)
	}
	store, err := exec.Command("docker", "info", "-f", "{{json .DriverStatus}}").CombinedOutput()
	if err != nil || !strings.Contains(string(store), "io.containerd.snapshotter") {
		t.Fatalf("the receipt's BOM needs the containerd image store; docker reports %q (%v)", store, err)
	}
	dir := receiptScratch(t)
	project := filepath.Join(dir, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"package.json", "sum.mjs", "test.mjs"} {
		b, err := os.ReadFile(filepath.Join("fixture", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}} {
		if out, err := receiptCommand(t, nil, "git", append([]string{"-C", project}, args...)...); err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
	}
	commit := receiptCommit(t, project)
	out := filepath.Join(dir, "out")
	log, err := receiptCommand(t, []string{"TEST_COMMAND=npm test", "PR_NUMBER=0", "PR_REPOSITORY=example/pr-receipt-fixture"}, "bash", "receipt.sh", project, out)
	if err != nil {
		t.Fatalf("receipt.sh: %v\n%s", err, log)
	}
	// Its states: a key made for the run reads as self-consistent only, and with no test
	// report how many tests ran is unknown, so the verdict is incomplete though the job passed.
	wantStates(t, "default key", receiptStates(t, out), map[string]string{"verdict": "incomplete", "signer": "self_consistent",
		"covers": "known", "candidate": "current", "run": "completed", "steps": "passed", "tests": "unknown", "evidence": "complete"})
	if !strings.Contains(string(log), "### plimsoll receipt: incomplete\n") || !strings.Contains(string(log), "- **Signer:** `self_consistent`.") {
		t.Errorf("receipt.sh printed no summary of its states:\n%s", log)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := read("status.txt"); got != "PASS\n" {
		t.Errorf("status.txt = %q, want PASS", got)
	}
	if got := read("run.log"); !strings.Contains(got, " signed into bundle.jsonl; ") {
		t.Errorf("run.log does not name the bundle by its relative name:\n%s", got)
	}
	if got := read("check.log"); !strings.Contains(got, "PASS: attached key matches independently trusted key.") {
		t.Errorf("check.log has no trusted-key pass:\n%s", got)
	}
	if got := read("request.json"); !strings.Contains(got, `\"commit\": \"`+commit+`\"`) {
		t.Errorf("the request does not name commit %s:\n%s", commit, got)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		body := read(e.Name())
		for _, local := range []string{dir, root, home} {
			if len(local) > 1 && strings.Contains(body, local) {
				t.Errorf("%s names the local directory %s", e.Name(), local)
			}
		}
	}

	// The verifier accepts the receipt for the commit it tested, with its junit.xml and its
	// signed in-toto test-result statement.
	sbom := filepath.Join(dir, "sbom")
	if log, err := exec.Command("go", "-C", "../sbom", "build", "-o", sbom, ".").CombinedOutput(); err != nil {
		t.Fatalf("build the checker: %v\n%s", err, log)
	}
	attestBin := filepath.Join(dir, "plimsoll-attest")
	if log, err := exec.Command("go", "build", "-o", attestBin, "../../cmd/plimsoll-attest").CombinedOutput(); err != nil {
		t.Fatalf("build plimsoll-attest: %v\n%s", err, log)
	}
	verify := func(out string, extra ...string) {
		t.Helper()
		args := append([]string{"-I", "verify.py", "--sbom", sbom, "--receipt", glob1(t, filepath.Join(out, "run-*.cdx.json")),
			"--trusted-pub", filepath.Join(out, "harness.pub"), "--repo", project, "--repository", "example/pr-receipt-fixture",
			"--head", commit, "--pr", "0", "--junit", filepath.Join(out, "junit.xml"),
			"--attest", attestBin, "--test-result", filepath.Join(out, "test-result.intoto.json")}, extra...)
		if log, err := receiptCommand(t, nil, "python3", args...); err != nil || !strings.Contains(string(log), `"verified": true`) {
			t.Errorf("verify.py %v: %v\n%s", extra, err, log)
		}
	}
	verify(out, "--command", "npm test")

	// Signed with an operator key instead: the run's public key is the operator's, and the
	// private key is still where the operator keeps it. This run asks node's test runner for
	// its JUnit report and its lcov coverage, which come back inside the signed result byte
	// for byte; the coverage is converted to Cobertura.
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if log, err := receiptCommand(t, nil, "go", "run", "../../cmd/plimsoll-attest", "keygen", "-out", filepath.Join(keys, "operator")); err != nil {
		t.Fatalf("keygen: %v\n%s", err, log)
	}
	signed := filepath.Join(dir, "signed")
	junitCommand := "node --test --experimental-test-coverage --test-reporter=junit --test-reporter-destination=reports.xml" +
		" --test-reporter=lcov --test-reporter-destination=lcov.info test.mjs"
	if log, err := receiptCommand(t, []string{"TEST_COMMAND=" + junitCommand, "JUNIT_PATH=reports.xml", "COVERAGE_PATH=lcov.info", "PR_NUMBER=0", "PR_REPOSITORY=example/pr-receipt-fixture", "PLIMSOLL_HARNESS_KEY=" + filepath.Join(keys, "operator.key")}, "bash", "receipt.sh", project, signed); err != nil {
		t.Fatalf("receipt.sh with an operator key: %v\n%s", err, log)
	}
	want, err := os.ReadFile(filepath.Join(keys, "operator.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(signed, "harness.pub")); err != nil || string(got) != string(want) {
		t.Errorf("harness.pub is not the operator's public key (%v)", err)
	}
	if _, err := os.Stat(filepath.Join(keys, "operator.key")); err != nil {
		t.Errorf("the operator key was not left in place: %v", err)
	}
	if report, err := os.ReadFile(filepath.Join(signed, "junit.xml")); err != nil || !strings.Contains(string(report), "<testsuites") || strings.Contains(string(report), "plimsoll.junit_source") {
		t.Errorf("junit.xml is not node's own report (%v):\n%s", err, report)
	}
	if report, err := os.ReadFile(filepath.Join(signed, "coverage.cobertura.xml")); err != nil || !strings.Contains(string(report), `filename="sum.mjs"`) {
		t.Errorf("coverage.cobertura.xml does not cover sum.mjs (%v):\n%s", err, report)
	}
	opened, err := exec.Command(attestBin, "open-statement", "-pub", filepath.Join(signed, "harness.pub"),
		"-type", "https://in-toto.io/attestation/test-result/v0.1", filepath.Join(signed, "test-result.intoto.json")).CombinedOutput()
	if err != nil || !strings.Contains(string(opened), `"result":"PASSED"`) || !strings.Contains(string(opened), `"isolation":"kernel"`) ||
		!strings.Contains(string(opened), `"gitCommit":"`+commit+`"`) {
		t.Errorf("the test-result statement does not open as PASSED at the kernel tier for commit %s (%v):\n%s", commit, err, opened)
	}
	verify(signed, "--command", junitCommand, "--junit-path", "reports.xml", "--coverage-path", "lcov.info",
		"--coverage", filepath.Join(signed, "coverage.cobertura.xml"))
	// Everything established: the operator's key, the head, the framework's report, nothing cut.
	wantStates(t, "operator key", receiptStates(t, signed), map[string]string{"verdict": "passed", "signer": "trusted_key",
		"candidate": "current", "run": "completed", "steps": "passed", "tests": "discovered", "evidence": "complete"})

	// The test report decides too, whenever one is asked for: a report that lists no test, one
	// that lists a failure, and one with fewer tests than PLIMSOLL_MIN_TESTS each fail the job
	// though every step exited 0. Each still gets its signed receipt.
	ran, _ := receiptStates(t, signed).States["tests"]["passed"].(float64)
	if ran < 1 {
		t.Fatalf("the operator-key run's report lists %v tests that ran", ran)
	}
	for _, c := range []struct {
		name, command, minimum, tests, detail string
	}{
		{"zero tests", `printf '<testsuites tests="0"></testsuites>\n' > reports.xml`, "", "zero", "lists 0 tests that ran; the gate requires at least 1 test"},
		{"a listed failure", `printf '<testsuites><testcase name="adds"><failure/></testcase></testsuites>\n' > reports.xml`, "", "discovered", "lists failures or errors"},
		{"below the minimum", junitCommand, fmt.Sprint(int(ran) + 1), "discovered", fmt.Sprintf("requires at least %d tests", int(ran)+1)},
	} {
		out := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "-"))
		env := []string{"TEST_COMMAND=" + c.command, "JUNIT_PATH=reports.xml", "PR_NUMBER=0", "PR_REPOSITORY=example/pr-receipt-fixture",
			"PLIMSOLL_HARNESS_KEY=" + filepath.Join(keys, "operator.key")}
		if c.minimum != "" {
			env = append(env, "PLIMSOLL_MIN_TESTS="+c.minimum)
		}
		log, err := receiptCommand(t, env, "bash", "receipt.sh", project, out)
		if err == nil {
			t.Errorf("%s: the job passed:\n%s", c.name, log)
		}
		r := receiptStates(t, out)
		wantStates(t, c.name, r, map[string]string{"verdict": "failed", "signer": "trusted_key", "run": "completed", "steps": "passed", "tests": c.tests})
		passed, detail := false, ""
		for _, k := range r.Checks {
			if k.Check == "tests" {
				passed, detail = k.Passed != nil && *k.Passed, k.Detail
			}
		}
		if passed || !strings.Contains(detail, c.detail) {
			t.Errorf("%s: tests check passed %v, %q; want a refusal saying %q", c.name, passed, detail, c.detail)
		}
		if got, err := os.ReadFile(filepath.Join(out, "status.txt")); err != nil || string(got) != "FAIL\n" ||
			!strings.Contains(string(log), "### plimsoll receipt: failed\n") || !strings.Contains(string(log), "its own check refused it at: tests\n  tests: ") {
			t.Errorf("%s: status %q (%v)\n%s", c.name, got, err, log)
		}
	}

	// A run that did not complete: the recipe's 30-second limit ends it. The receipt is made,
	// the job fails, and the states say why.
	slow := filepath.Join(dir, "slow")
	log, err = receiptCommand(t, []string{"TEST_COMMAND=sleep 45", "PR_NUMBER=0", "PR_REPOSITORY=example/pr-receipt-fixture"}, "bash", "receipt.sh", project, slow)
	if err == nil {
		t.Fatalf("a timed-out run passed:\n%s", log)
	}
	wantStates(t, "timed out", receiptStates(t, slow), map[string]string{"verdict": "failed", "signer": "self_consistent", "run": "timed_out", "steps": "failed"})
	if got, err := os.ReadFile(filepath.Join(slow, "status.txt")); err != nil || string(got) != "FAIL\n" || !strings.Contains(string(log), "### plimsoll receipt: failed\n") {
		t.Errorf("timed out: status %q (%v)\n%s", got, err, log)
	}

	// A head other than the commit that ran (the checkout is a commit behind the event's
	// head): the receipt is stale, and the job fails although the tests passed.
	if err := os.WriteFile(filepath.Join(project, "README.md"), []byte("# sum\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := receiptCommand(t, nil, "git", "-C", project, "add", "README.md"); err != nil {
		t.Fatalf("git add: %s: %v", out, err)
	}
	later := receiptCommit(t, project)
	if out, err := receiptCommand(t, nil, "git", "-C", project, "checkout", "-q", "--detach", commit); err != nil {
		t.Fatalf("git checkout: %s: %v", out, err)
	}
	stale := filepath.Join(dir, "stale")
	log, err = receiptCommand(t, []string{"TEST_COMMAND=npm test", "PR_NUMBER=0", "PR_REPOSITORY=example/pr-receipt-fixture", "PR_HEAD_SHA=" + later}, "bash", "receipt.sh", project, stale)
	if err == nil {
		t.Fatalf("a receipt for the commit behind the head passed:\n%s", log)
	}
	wantStates(t, "stale", receiptStates(t, stale), map[string]string{"verdict": "refused", "candidate": "stale", "steps": "passed"})
	if got, err := os.ReadFile(filepath.Join(stale, "status.txt")); err != nil || string(got) != "FAIL\n" || !strings.Contains(string(log), "its own check refused it at: head") {
		t.Errorf("stale: status %q (%v)\n%s", got, err, log)
	}
}

// receiptDaemonSockets lists every Unix socket the daemon makes in its TMPDIR, each as the
// name prefix of the private directory os.MkdirTemp makes for it there and the socket's
// file name. It is read from the sources, so a new socket fails the test below until it is
// counted here and in receipt.sh's socket_room.
func receiptDaemonSockets(t *testing.T) [][2]string {
	t.Helper()
	sockets := [][2]string{
		{"plimsoll-docker-config-", "alive.sock"}, // docker_cli.go: the docker CLI's private config and its liveness socket
		{"crsbx-broker", "host-api.sock"},         // docker_broker.go: a run's capability broker
		{"crsbx-session-broker", "host-api.sock"}, // docker_session.go, through startUnixBroker: a session's broker
		{"crsbx-smoke-sock", "host-api.sock"},     // docker_smoke.go: the startup smoke test's socket
	}
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// The reaper's list names every private directory the provider makes in TMPDIR.
	m := regexp.MustCompile(`dockerHostDirPrefixes = \[\]string\{([^}]*)\}`).FindStringSubmatch(read("../../sandbox/docker_hostdirs.go"))
	if m == nil {
		t.Fatal("sandbox/docker_hostdirs.go no longer lists dockerHostDirPrefixes")
	}
	var prefixes []string
	for _, q := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(m[1], -1) {
		prefixes = append(prefixes, q[1])
	}
	var counted []string
	for _, s := range sockets {
		counted = append(counted, s[0])
	}
	slices.Sort(prefixes)
	slices.Sort(counted)
	if !slices.Equal(prefixes, counted) {
		t.Errorf("the provider's private directories are %v; this test counts %v", prefixes, counted)
	}
	// Every Unix listener in what plimsolld runs is one of those: three call sites. The two
	// fakes are programs that run inside a test's sandbox, never in plimsolld.
	listen := regexp.MustCompile(`Listen\w*\(\s*"unix|ListenUnix`)
	found := map[string]int{}
	for _, root := range []string{"../../sandbox", "../../cmd", "../../internal"} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			if n := len(listen.FindAllString(read(path), -1)); n > 0 {
				found[filepath.ToSlash(strings.TrimPrefix(path, "../../"))] = n
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]int{"sandbox/docker_cli.go": 1, "sandbox/docker_broker.go": 1, "sandbox/docker_smoke.go": 1,
		"sandbox/internal/e2bfake/envd/main.go": 1}
	// The Docker Cloud session fake is withheld from the public export with the session code
	// it stands in for, so its listener is counted only where the file is (the export's dry
	// run found the public tree failing here, 2026-10-29).
	if _, err := os.Stat("../../sandbox/internal/dcfake/agent/main.go"); err == nil {
		want["sandbox/internal/dcfake/agent/main.go"] = 1
	}
	if fmt.Sprint(found) != fmt.Sprint(want) {
		t.Errorf("Unix listeners %v; this test counts %v", found, want)
	}
	for file, names := range map[string][]string{
		"docker_cli.go":     {`os.MkdirTemp("", "plimsoll-docker-config-")`, `dockerAliveSocket = "alive.sock"`},
		"docker_broker.go":  {`os.MkdirTemp("", prefix)`, `"host-api.sock"`, `startUnixBroker("crsbx-broker"`},
		"docker_session.go": {`startUnixBroker("crsbx-session-broker"`},
		"docker_smoke.go":   {`os.MkdirTemp("", "crsbx-smoke-sock")`, `"host-api.sock"`},
	} {
		body := read("../../sandbox/" + file)
		for _, s := range names {
			if !strings.Contains(body, s) {
				t.Errorf("sandbox/%s no longer holds %s", file, s)
			}
		}
	}
	return sockets
}

// The daemon's sockets fit Linux's limit wherever the checkout is. A socket path is at most
// 107 bytes (sun_path's 108, less the terminating zero), and the docker provider makes its
// sockets in the daemon's TMPDIR, each in a directory os.MkdirTemp names with up to 10 random
// digits. On a GitHub runner the tools sit under $GITHUB_WORKSPACE/tools/plimsoll, and the
// workspace is /home/runner/work/<repository>/<repository>, so a TMPDIR under the checkout
// grows with the repository's name. This runs receipt.sh from a checkout of that shape for a
// 100-character name (under this test's scratch directory, so longer still) with a stand-in
// daemon that makes every counted socket at its longest and says whether it could listen.
func TestReceiptDaemonSocketsFitALongCheckout(t *testing.T) {
	sockets := receiptDaemonSockets(t)
	longest := 0
	for _, s := range sockets {
		longest = max(longest, len(s[0])+10+1+len(s[1]))
	}
	script, err := os.ReadFile("receipt.sh")
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`(?m)^socket_room=(\d+)$`).FindSubmatch(script); m == nil || string(m[1]) != fmt.Sprint(longest) {
		t.Fatalf("receipt.sh's socket_room is %q; the longest socket name the daemon makes in its TMPDIR is %d bytes", m, longest)
	}

	dir := receiptScratch(t)
	repo := strings.Repeat("r", 100)
	workspace := filepath.Join(dir, "home", "runner", "work", repo, repo)
	source := filepath.Join(workspace, "tools", "plimsoll")
	var table strings.Builder
	for _, s := range sockets {
		fmt.Fprintf(&table, "\t\t{%q, %q},\n", s[0], s[1])
	}
	fake := map[string]string{
		"go.mod":                      "module example.invalid/fake\n\ngo 1.22\n",
		"examples/sbom/main.go":       "package main\n\nfunc main() {}\n",
		"cmd/plimsoll-attest/main.go": "package main\n\nfunc main() {}\n",
		// The stand-in daemon: every counted socket at its longest, then exit, so receipt.sh
		// stops at readiness and prints this log.
		"cmd/plimsolld/main.go": `package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

func main() {
	tmp := os.TempDir()
	fmt.Printf("TMPDIR %s\n", tmp)
	for _, s := range [][2]string{
` + table.String() + `	} {
		dir := filepath.Join(tmp, s[0]+"4294967295")
		if err := os.Mkdir(dir, 0o700); err != nil {
			fmt.Printf("no directory %s: %v\n", dir, err)
			continue
		}
		path := filepath.Join(dir, s[1])
		l, err := net.Listen("unix", path)
		if err != nil {
			fmt.Printf("refused %d %s: %v\n", len(path), path, err)
			continue
		}
		_ = l.Close()
		fmt.Printf("listened %d %s\n", len(path), path)
	}
	os.Exit(1)
}
`,
	}
	for name, body := range fake {
		path := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	project := filepath.Join(dir, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	// A RUNNER_TEMP as short as a hosted runner's (/home/runner/work/_temp, 23 bytes): this
	// test's own, under the system temporary directory, since the scratch path is longer.
	short, err := os.MkdirTemp("", "rt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	longTemp := filepath.Join(workspace, "_temp")
	if err := os.MkdirAll(longTemp, 0o700); err != nil {
		t.Fatal(err)
	}
	shortParent := short
	if len(short)+len("/plimsoll.XXXXXX")+1+longest > 107 { // a long system TMPDIR: receipt.sh falls back
		shortParent = "/tmp"
	}
	line := regexp.MustCompile(`(?m)^(TMPDIR|listened|refused|no directory) (.*)$`)
	template := 0 // the length of the name receipt.sh gives the daemon's directory
	for _, c := range []struct {
		name, runnerTemp, parent string
	}{
		{"no RUNNER_TEMP", "", "/tmp"},
		{"a short RUNNER_TEMP", short, shortParent},
		{"a RUNNER_TEMP too long for the sockets", longTemp, "/tmp"},
	} {
		cmd := exec.Command("bash", "receipt.sh", project, filepath.Join(dir, "out-"+strings.ReplaceAll(c.name, " ", "-")))
		for _, e := range os.Environ() {
			keep := true
			for _, p := range []string{"GIT_", "PLIMSOLL_", "PR_", "TEST_COMMAND=", "JUNIT_PATH=", "COVERAGE_PATH=", "SESSION_TRAILER=", "RUNNER_TEMP=", "GOFLAGS=", "GOWORK="} {
				keep = keep && !strings.HasPrefix(e, p)
			}
			if keep {
				cmd.Env = append(cmd.Env, e)
			}
		}
		cmd.Env = append(cmd.Env, "PLIMSOLL_SOURCE="+source, "GOWORK=off")
		if c.runnerTemp != "" {
			cmd.Env = append(cmd.Env, "RUNNER_TEMP="+c.runnerTemp)
		}
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("%s: receipt.sh passed with a daemon that exits:\n%s", c.name, out)
		}
		tmpdir, listened := "", 0
		for _, m := range line.FindAllStringSubmatch(string(out), -1) {
			switch m[1] {
			case "TMPDIR":
				tmpdir = m[2]
			case "listened":
				listened++
				var n int
				if _, err := fmt.Sscanf(m[2], "%d", &n); err != nil || n > 107 {
					t.Errorf("%s: a socket path of %d bytes (%v): %s", c.name, n, err, m[2])
				}
			default:
				t.Errorf("%s: %s %s", c.name, m[1], m[2])
			}
		}
		if tmpdir == "" || listened != len(sockets) {
			t.Fatalf("%s: the stand-in daemon listened on %d of %d sockets (TMPDIR %q):\n%s", c.name, listened, len(sockets), tmpdir, out)
		}
		if filepath.Dir(tmpdir) != c.parent || strings.HasPrefix(tmpdir, source) {
			t.Errorf("%s: the daemon's TMPDIR is %s; want a directory of its own in %s", c.name, tmpdir, c.parent)
		}
		if _, err := os.Stat(tmpdir); !os.IsNotExist(err) {
			t.Errorf("%s: the daemon's TMPDIR %s outlived the script (%v)", c.name, tmpdir, err)
		}
		template = len(filepath.Base(tmpdir))
		t.Logf("%s: TMPDIR %s, longest socket path %d bytes", c.name, tmpdir, len(tmpdir)+1+longest)
	}
	// On a hosted runner, RUNNER_TEMP is /home/runner/work/_temp whatever the repository's
	// name; the checkout's tmp/, where TMPDIR was before, gave 103 + twice the name's length.
	if n := len("/home/runner/work/_temp") + 1 + template + 1 + longest; n > 107 {
		t.Errorf("on a hosted runner the longest socket path would be %d bytes", n)
	}
}

func glob1(t *testing.T, pattern string) string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil || len(m) != 1 {
		t.Fatalf("%s: want one match, got %v (%v)", pattern, m, err)
	}
	return m[0]
}

// prepare.py states the protocol number in the request it writes; it must be the one this
// module's daemon serves, or every receipt is refused before anything runs.
func TestPrepareStatesTheCurrentProtocol(t *testing.T) {
	b, err := os.ReadFile("prepare.py")
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("'protocol': %d,", protocol.Number); !strings.Contains(string(b), want) {
		t.Errorf("prepare.py does not state %s", want)
	}
}
