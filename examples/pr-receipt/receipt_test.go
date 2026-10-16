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
		if !strings.HasPrefix(e, "GIT_") && !strings.HasPrefix(e, "TEST_COMMAND=") && !strings.HasPrefix(e, "PR_BASE_SHA=") && !strings.HasPrefix(e, "PR_NUMBER=") {
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
	output := filepath.Join(dir, "output")
	if out, err := receiptCommand(t, []string{"TEST_COMMAND=" + command, "PR_NUMBER=42"}, "python3", "prepare.py", project, output); err != nil {
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
	if q.Protocol != 3 || q.MinimumIsolation != "kernel" || len(q.Project.Files) != 1 || q.Project.Files[0].Path != "test.mjs" || len(q.Project.Steps) != 1 || q.Project.Steps[0] != command {
		t.Fatalf("wrong request: %s", request)
	}
	context, err := os.ReadFile(filepath.Join(output, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(context), `"test.mjs"`) {
		t.Fatalf("changed file missing: %s", context)
	}
	if err := os.Remove(filepath.Join(project, "test.mjs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "outside"), filepath.Join(project, "test.mjs")); err != nil {
		t.Fatal(err)
	}
	if out, err := receiptCommand(t, nil, "python3", "prepare.py", project, filepath.Join(dir, "unsafe")); err == nil {
		t.Fatalf("linked file accepted: %s", out)
	}
}

func TestReceiptShellSyntax(t *testing.T) {
	if out, err := receiptCommand(t, nil, "bash", "-n", "receipt.sh"); err != nil {
		t.Fatalf("%s: %v", out, err)
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
	out := filepath.Join(dir, "out")
	if log, err := receiptCommand(t, []string{"TEST_COMMAND=npm test", "PR_NUMBER=0"}, "bash", "receipt.sh", project, out); err != nil {
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
}
