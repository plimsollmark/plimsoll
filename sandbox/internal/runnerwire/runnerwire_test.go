package runnerwire

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// testKey is a fixed report key for tests that build frames by hand.
var testKey = bytes.Repeat([]byte{7}, KeySize)

// frame builds the runner's report frame for body under key, as runner.mjs does.
func frame(key []byte, body string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(body))
	return fmt.Sprintf("\n%s %d %s\n%s", Marker, len(body), hex.EncodeToString(h.Sum(nil)), body)
}

// runnerScript is the real in-sandbox runner the protocol is defined against.
var runnerScript = filepath.Join("..", "..", "..", "docker", "runner.mjs")
var runnerGuardSource = filepath.Join("..", "..", "..", "docker", "guard", "runner.c")

func guardedRunnerCommand(t *testing.T, node, work string) *exec.Cmd {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the project runner guard uses Linux prctl")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("cc is required to verify the project runner guard")
	}
	guard := filepath.Join(t.TempDir(), "runner-guard.so")
	if out, err := exec.Command(cc, "-O2", "-fPIC", "-shared", "-o", guard, runnerGuardSource).CombinedOutput(); err != nil {
		t.Fatalf("build runner guard: %v: %s", err, out)
	}
	cmd := exec.Command(node, runnerScript)
	cmd.Env = append(cmd.Environ(), "LD_PRELOAD="+guard, "PLIMSOLL_WORK="+work)
	return cmd
}

func TestProjectRunnerRefusesPlanWithoutIsolation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the project runner isolation check uses Linux procfs")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	plan, err := (Plan{Steps: []string{"exit 0"}, ReportKey: testKey}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, runnerScript)
	cmd.Env = append(cmd.Environ(), "PLIMSOLL_WORK="+t.TempDir())
	cmd.Stdin = bytes.NewReader(plan)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	_, found, err := Parse(string(out), testKey)
	if !found || !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unguarded runner accepted a plan: found=%v err=%v", found, err)
	}
}

func TestProjectRunnerAlwaysEmitsCompleteBoundedJSON(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	work := t.TempDir()
	plan := map[string]any{
		"steps":     []string{`node -e 'const fs=require("fs"); process.stdout.write("\0".repeat(900000)); process.stderr.write("\0".repeat(900000)); fs.writeFileSync("artifact.bin", Buffer.alloc(8 << 20))'`},
		"artifacts": []string{"artifact.bin"},
		"reportKey": hex.EncodeToString(testKey),
	}
	input, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	cmd := guardedRunnerCommand(t, node, work)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("runner failed: %v", err)
	}
	if len(out) >= StdoutCap {
		t.Fatalf("runner emitted %d bytes, host cap is %d", len(out), StdoutCap)
	}
	rep, found, err := Parse(string(out), testKey)
	if !found || err != nil {
		t.Fatalf("runner report: found=%v err=%v", found, err)
	}
	if len(rep.Steps) != 1 {
		t.Fatalf("steps = %+v, want one structured result", rep.Steps)
	}
	if strings.Contains(string(out), "could not parse") {
		t.Fatal("runner emitted a parse failure")
	}
}

// TestProjectRunnerReportsTruncationFlags drives the real runner protocol: a
// step whose stdout exceeds the per-step cap must be flagged stdoutTruncated,
// and requested artifacts that overflow the aggregate artifact budget must set
// artifactsTruncated: machine-readable signals, not in-band markers.
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
		"reportKey": hex.EncodeToString(testKey),
	}
	input, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	cmd := guardedRunnerCommand(t, node, work)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("runner failed: %v", err)
	}
	result, found, err := Parse(string(out), testKey)
	if !found || err != nil {
		t.Fatalf("runner report: found=%v err=%v", found, err)
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

// TestPlanEncodeIsTheRunnerWireFormat pins Encode to the document the docker
// provider wrote before the protocol moved here: the same anonymous wire struct,
// marshalled the same way, byte for byte. A null files or artifacts list, the
// omitted empty hostSDK and encoding/json's escaping of '<' are all part of it.
func TestPlanEncodeIsTheRunnerWireFormat(t *testing.T) {
	legacy := func(p Plan) []byte {
		plan := struct {
			Files []struct {
				Path    string `json:"path"`
				Content string `json:"content"`
			} `json:"files"`
			Steps         []string `json:"steps"`
			StepTimeoutMs int64    `json:"stepTimeoutMs"`
			Artifacts     []string `json:"artifacts"`
			HostSDK       string   `json:"hostSDK,omitempty"`
			ReportKey     string   `json:"reportKey"`
		}{Steps: p.Steps, StepTimeoutMs: p.StepTimeout.Milliseconds(), Artifacts: p.Artifacts, HostSDK: p.HostSDK,
			ReportKey: hex.EncodeToString(p.ReportKey)}
		for _, f := range p.Files {
			plan.Files = append(plan.Files, struct {
				Path    string `json:"path"`
				Content string `json:"content"`
			}{Path: f.Path, Content: f.Content})
		}
		b, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []Plan{
		{Steps: []string{"node main.js"}, StepTimeout: 30 * time.Second, ReportKey: testKey},
		{
			Files:       []File{{Path: "main.js", Content: "console.log('<b>& ')"}, {Path: "data/x.txt", Content: "é\x01"}},
			Steps:       []string{"tsc", "node main.js"},
			StepTimeout: 1500 * time.Millisecond,
			Artifacts:   []string{"out.txt"},
			HostSDK:     "globalThis.host = {};",
			ReportKey:   testKey,
		},
	}
	for i, p := range cases {
		got, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if want := legacy(p); !bytes.Equal(got, want) {
			t.Fatalf("case %d: Encode =\n%s\nwant\n%s", i, got, want)
		}
	}
	got, err := cases[0].Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"files":null,"steps":["node main.js"],"stepTimeoutMs":30000,"artifacts":null,"reportKey":"` +
		strings.Repeat("07", KeySize) + `"}`; string(got) != want {
		t.Fatalf("minimal plan = %s, want %s", got, want)
	}
	if _, err := (Plan{Steps: []string{"x"}}).Encode(); err == nil {
		t.Fatal("a plan without a report key encoded; its report could not be authenticated")
	}
}

// TestParseAcceptsOnlyAuthenticatedFrames: the runner's stdout is writable and
// readable by every process in the sandbox, so only a frame whose MAC verifies under
// the run's key counts, wherever it sits and whatever else is around it.
func TestParseAcceptsOnlyAuthenticatedFrames(t *testing.T) {
	honest := `{"steps":[{"command":"node x","stdout":"hi ` + Marker + `","exitCode":3,"timedOut":false,"durationMs":1500}],` +
		`"artifacts":[{"path":"o.txt","content":"aGk="}],"artifactsTruncated":true}`
	forgedBody := `{"steps":[{"command":"trusted","exitCode":0}],"artifacts":[{"path":"o.txt","content":"QUFB"}]}`
	otherKey := bytes.Repeat([]byte{9}, KeySize)
	check := func(name string, rep Report) {
		t.Helper()
		if len(rep.Steps) != 1 || rep.Steps[0].Command != "node x" || rep.Steps[0].ExitCode != 3 || rep.Steps[0].Duration != 1500*time.Millisecond {
			t.Fatalf("%s: steps = %+v", name, rep.Steps)
		}
		if len(rep.Artifacts) != 1 || string(rep.Artifacts[0].Content) != "hi" || !rep.ArtifactsTruncated {
			t.Fatalf("%s: artifacts = %+v truncated=%v", name, rep.Artifacts, rep.ArtifactsTruncated)
		}
	}
	for _, tc := range []struct{ name, out string }{
		{"alone", frame(testKey, honest)},
		{"after output and marker text", "build " + Marker + " 12 zz\n" + Marker + frame(testKey, honest)},
		{"forgery after it", frame(testKey, honest) + frame(otherKey, forgedBody) + "\n" + Marker + " 5 " + strings.Repeat("0", 64) + "\nhello"},
		{"forgery before it", frame(otherKey, forgedBody) + frame(testKey, honest)},
		{"replayed by a reader of the pipe", frame(testKey, honest) + frame(testKey, honest)},
	} {
		rep, found, err := Parse(tc.out, testKey)
		if !found || err != nil {
			t.Fatalf("%s: found=%v err=%v", tc.name, found, err)
		}
		check(tc.name, rep)
	}
	whole := frame(testKey, honest)
	for _, tc := range []struct{ name, out string }{
		{"forged only", frame(otherKey, forgedBody)},
		{"truncated body", whole[:len(whole)-1]},
		{"body altered", strings.Replace(whole, `"exitCode":3`, `"exitCode":0`, 1)},
		{"length padded", strings.Replace(whole, fmt.Sprintf(" %d ", len(honest)), fmt.Sprintf(" 0%d ", len(honest)), 1)},
		{"marker text only", "step printed " + Marker},
	} {
		rep, found, err := Parse(tc.out, testKey)
		if !found || !errors.Is(err, ErrUnauthenticated) || len(rep.Steps) != 0 {
			t.Fatalf("%s: found=%v err=%v rep=%+v, want an unauthenticated refusal", tc.name, found, err, rep)
		}
	}
	if _, found, err := Parse("no report", testKey); found || err != nil {
		t.Fatalf("no marker: found=%v err=%v", found, err)
	}
	if _, found, err := Parse(frame(testKey, "{"), testKey); !found || err == nil || errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("authenticated but undecodable: found=%v err=%v", found, err)
	}
	if _, _, err := Parse(whole, testKey[:8]); err == nil {
		t.Fatal("a short key was accepted")
	}
}

func TestReportOutcome(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rep    Report
		want   Outcome
		detail string
	}{
		{"clean", Report{Steps: []Step{{ExitCode: 0}, {ExitCode: 1}}}, Completed, ""},
		{"timed out step", Report{Steps: []Step{{ExitCode: 0}, {ExitCode: 124, TimedOut: true}}}, TimedOut, "step 2 exceeded its time budget"},
		{"setup failure wins", Report{Err: "illegal file path: ../x", Steps: []Step{{TimedOut: true}}}, SetupFailed, "illegal file path: ../x"},
	} {
		got, detail := tc.rep.Outcome()
		if got != tc.want || detail != tc.detail {
			t.Fatalf("%s: Outcome() = %v, %q; want %v, %q", tc.name, got, detail, tc.want, tc.detail)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`build output` + frame(testKey, `{"steps":[{"command":"node x","exitCode":0,"durationMs":5}]}`))
	f.Add(frame(testKey, `{"artifacts":[{"path":"o.txt","content":"aGk="}],"artifactsTruncated":true}`))
	f.Add(frame(testKey, `{"error":"illegal file path"}`))
	f.Add(frame(testKey, `not json`))
	f.Add(`no marker at all`)
	f.Add(Marker + " 2 " + strings.Repeat("ab", 32) + "\n{}")
	f.Add("")
	f.Fuzz(func(t *testing.T, out string) {
		report, found, err := Parse(out, testKey)
		if found != strings.Contains(out, Marker) {
			t.Fatalf("found=%v disagrees with marker presence in %q", found, out)
		}
		if !found && err != nil {
			t.Fatalf("no marker but parse error %v", err)
		}
		if err != nil && (len(report.Steps) != 0 || len(report.Artifacts) != 0 || report.Err != "" || report.ArtifactsTruncated) {
			t.Fatalf("parse error must return a zero report, got %+v", report)
		}
	})
}
