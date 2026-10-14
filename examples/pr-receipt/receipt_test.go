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
