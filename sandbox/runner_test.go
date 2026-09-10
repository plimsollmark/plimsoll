package sandbox

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectRunnerAlwaysEmitsCompleteBoundedJSON(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	work := t.TempDir()
	plan := map[string]any{
		"steps":     []string{`node -e 'const fs=require("fs"); process.stdout.write("\0".repeat(900000)); process.stderr.write("\0".repeat(900000)); fs.writeFileSync("artifact.bin", Buffer.alloc(8 << 20))'`},
		"artifacts": []string{"artifact.bin"},
	}
	input, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, filepath.Join("..", "docker", "runner.mjs"))
	cmd.Env = append(cmd.Environ(), "PLIMSOLL_WORK="+work)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("runner failed: %v", err)
	}
	if len(out) >= projectStdoutCap {
		t.Fatalf("runner emitted %d bytes, host cap is %d", len(out), projectStdoutCap)
	}
	idx := bytes.LastIndex(out, []byte(runnerSentinel))
	if idx < 0 {
		t.Fatal("runner result sentinel missing")
	}
	var result map[string]any
	if err := json.Unmarshal(out[idx+len(runnerSentinel):], &result); err != nil {
		t.Fatalf("runner emitted truncated/invalid JSON: %v", err)
	}
	if steps, _ := result["steps"].([]any); len(steps) != 1 {
		t.Fatalf("steps = %v, want one structured result", result["steps"])
	}
	if strings.Contains(string(out), "could not parse") {
		t.Fatal("runner emitted a parse failure")
	}
}

// TestProjectRunnerReportsTruncationFlags drives the real runner protocol: a
// step whose stdout exceeds the per-step cap must be flagged stdoutTruncated,
// and requested artifacts that overflow the aggregate artifact budget must set
// artifactsTruncated — machine-readable signals, not in-band markers.
func TestProjectRunnerReportsTruncationFlags(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	work := t.TempDir()
	plan := map[string]any{
		"steps": []string{
			`node -e 'const fs=require("fs"); fs.writeFileSync("a.bin", Buffer.alloc(5<<20)); fs.writeFileSync("b.bin", Buffer.alloc(5<<20))'`,
			`node -e 'process.stdout.write("x".repeat(2*1024*1024))'`, // > 1 MiB per-step cap
		},
		"artifacts": []string{"a.bin", "b.bin"}, // 10 MiB > 8 MiB aggregate budget
	}
	input, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, filepath.Join("..", "docker", "runner.mjs"))
	cmd.Env = append(cmd.Environ(), "PLIMSOLL_WORK="+work)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("runner failed: %v", err)
	}
	idx := bytes.LastIndex(out, []byte(runnerSentinel))
	if idx < 0 {
		t.Fatal("runner result sentinel missing")
	}
	var result struct {
		Steps []struct {
			Stdout          string `json:"stdout"`
			StdoutTruncated bool   `json:"stdoutTruncated"`
		} `json:"steps"`
		Artifacts []struct {
			Path string `json:"path"`
		} `json:"artifacts"`
		ArtifactsTruncated bool `json:"artifactsTruncated"`
	}
	if err := json.Unmarshal(out[idx+len(runnerSentinel):], &result); err != nil {
		t.Fatalf("runner emitted invalid JSON: %v", err)
	}
	if len(result.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(result.Steps))
	}
	if result.Steps[0].StdoutTruncated {
		t.Fatal("quiet step falsely flagged truncated")
	}
	if !result.Steps[1].StdoutTruncated {
		t.Fatal("over-cap stdout not flagged truncated")
	}
	if strings.Contains(result.Steps[1].Stdout, "[output truncated]") {
		t.Fatal("in-band truncation marker leaked into step output")
	}
	if len(result.Artifacts) != 1 || result.Artifacts[0].Path != "a.bin" {
		t.Fatalf("artifacts = %+v, want only a.bin (b.bin over budget)", result.Artifacts)
	}
	if !result.ArtifactsTruncated {
		t.Fatal("dropped artifact not flagged via artifactsTruncated")
	}
}
