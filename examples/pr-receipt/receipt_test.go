package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
		if !strings.HasPrefix(e, "GIT_") && !strings.HasPrefix(e, "TEST_COMMAND=") && !strings.HasPrefix(e, "PR_BASE_SHA=") && !strings.HasPrefix(e, "PR_NUMBER=") && !strings.HasPrefix(e, "PR_REPOSITORY=") && !strings.HasPrefix(e, "PLIMSOLL_HARNESS_KEY=") {
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
	if q.Protocol != 3 || q.MinimumIsolation != "kernel" || len(q.Project.Files) != 2 || q.Project.Files[0].Path != "test.mjs" || len(q.Project.Steps) != 1 || q.Project.Steps[0] != command {
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
	// In order: each setup leaves the project as the next one expects.
	for _, c := range []struct {
		name, want string
		setup      func() []string
	}{
		{"no repository", "PR_REPOSITORY", func() []string { return env[:2] }},
		{"a repository with a space", "PR_REPOSITORY", func() []string { return append(env[:2:2], "PR_REPOSITORY=example project") }},
		{"a change not committed", "differ from the commit", func() []string { write("test.mjs", "console.log('changed');\n"); return env }},
		{"a tracked file under .pr-receipt/", "collide", func() []string {
			git("checkout", "--", "test.mjs")
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
	if log, err := receiptCommand(t, []string{"TEST_COMMAND=npm test", "PR_NUMBER=0", "PR_REPOSITORY=example/pr-receipt-fixture"}, "bash", "receipt.sh", project, out); err != nil {
		t.Fatalf("receipt.sh: %v\n%s", err, log)
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

	// Signed with an operator key instead: the run's public key is the operator's, and the
	// private key is still where the operator keeps it.
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if log, err := receiptCommand(t, nil, "go", "run", "../../cmd/plimsoll-attest", "keygen", "-out", filepath.Join(keys, "operator")); err != nil {
		t.Fatalf("keygen: %v\n%s", err, log)
	}
	signed := filepath.Join(dir, "signed")
	if log, err := receiptCommand(t, []string{"TEST_COMMAND=npm test", "PR_NUMBER=0", "PR_REPOSITORY=example/pr-receipt-fixture", "PLIMSOLL_HARNESS_KEY=" + filepath.Join(keys, "operator.key")}, "bash", "receipt.sh", project, signed); err != nil {
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
}
