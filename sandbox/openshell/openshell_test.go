package openshell

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1/openshellv1connect"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/sandboxv1"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// echoScript is a `node -` stand-in: stdout is the code it received, exit 0.
func echoScript(e *fakeExec) error {
	code := e.readAll()
	if err := e.stdout(code); err != nil {
		return err
	}
	return e.exit(0)
}

func TestConfigValidate(t *testing.T) {
	good := Config{GatewayURL: "https://127.0.0.1:17670", CAFile: "ca", CertFile: "c", KeyFile: "k", Image: "plimsoll/sandbox:latest"}
	if err := good.validate(); err != nil {
		t.Fatalf("good config: %v", err)
	}
	pinned := good
	pinned.RequirePinnedImage, pinned.Image = true, "plimsoll/sandbox@sha256:"+strings.Repeat("ab", 32)
	if err := pinned.validate(); err != nil {
		t.Fatalf("pinned config: %v", err)
	}
	for _, tc := range []struct {
		name   string
		adjust func(*Config)
		want   string
	}{
		{"cleartext", func(c *Config) { c.GatewayURL = "http://127.0.0.1:17670" }, "https"},
		{"path", func(c *Config) { c.GatewayURL = "https://gw.example/api" }, "no path"},
		{"credentials", func(c *Config) { c.GatewayURL = "https://u:p@gw.example" }, "credentials"},
		{"no host", func(c *Config) { c.GatewayURL = "https:///x" }, "host"},
		{"missing key", func(c *Config) { c.KeyFile = "" }, "mutual TLS"},
		{"no image", func(c *Config) { c.Image = "" }, "image is required"},
		{"image whitespace", func(c *Config) { c.Image = "plimsoll/sandbox:latest\n" }, "whitespace"},
		{"unpinned", func(c *Config) { c.RequirePinnedImage = true }, "not pinned"},
		{"tiny memory", func(c *Config) { c.MemoryMB = 4 }, "at least 6 MiB"},
		{"negative memory", func(c *Config) { c.MemoryMB = -1 }, "memory"},
		{"NaN CPU", func(c *Config) { c.CPUs = math.NaN() }, "CPU"},
		{"tiny CPU", func(c *Config) { c.CPUs = 0.001 }, "CPU"},
		{"pids", func(c *Config) { c.PidsLimit = 64 }, "SANDBOX_PIDS"},
		{"negative disk", func(c *Config) { c.DiskMB = -1 }, "disk limit"},
		{"huge disk", func(c *Config) { c.DiskMB = maxDiskMB + 1 }, "disk limit"},
	} {
		c := good
		tc.adjust(&c)
		if err := c.validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: validate() = %v, want an error mentioning %q", tc.name, err, tc.want)
		}
		if _, err := New(c); err == nil {
			t.Errorf("%s: New accepted the config", tc.name)
		}
	}
}

// TestPolicyHashMatchesTheGateway pins policyHash to hashes the v0.1.2 gateway itself
// reported in GetSandboxConfig on 2026-09-28, for four policies: the run policy, the
// gateway's own default, and two design probes (one with a process section). A
// protobuf encoding change that broke the equality would fail every run closed; this
// catches it first.
func TestPolicyHashMatchesTheGateway(t *testing.T) {
	sys := []string{"/bin", "/usr", "/lib", "/proc", "/dev/urandom", "/etc"}
	for _, tc := range []struct {
		name   string
		policy *sandboxv1.SandboxPolicy
		want   string
	}{
		{"run policy", runPolicy(), "d1c56801c3fcf0b1d8473339f3b625b1cbf43d5401c1268026551dd28a39d871"},
		{"gateway default", &sandboxv1.SandboxPolicy{
			Version:    1,
			Filesystem: &sandboxv1.FilesystemPolicy{IncludeWorkdir: true, ReadOnly: append(append([]string{}, sys...), "/var/log"), ReadWrite: []string{"/tmp", "/dev/null"}},
			Landlock:   &sandboxv1.LandlockPolicy{Compatibility: "best_effort"},
		}, "a45a8ff3564f00ae26cbd66f1131f37eedd8b54a66fbfec103d65a204c19c6e8"},
		{"probe, /sandbox/work", &sandboxv1.SandboxPolicy{
			Version:    1,
			Filesystem: &sandboxv1.FilesystemPolicy{ReadOnly: append(append([]string{}, sys...), "/runner.mjs"), ReadWrite: []string{"/sandbox/work", "/tmp", "/dev/null"}},
			Landlock:   &sandboxv1.LandlockPolicy{Compatibility: "best_effort"},
		}, "cb87d045a485ed8bbbd10c0580ef19f61a72312572b48664000d6c68014653bc"},
		{"probe, process identity", &sandboxv1.SandboxPolicy{
			Version:    1,
			Filesystem: &sandboxv1.FilesystemPolicy{ReadOnly: append(append([]string{}, sys...), "/runner.mjs", "/sys/fs/cgroup"), ReadWrite: []string{"/sandbox/work", "/tmp", "/dev/null"}},
			Landlock:   &sandboxv1.LandlockPolicy{Compatibility: "best_effort"},
			Process:    &sandboxv1.ProcessPolicy{RunAsUser: "1000", RunAsGroup: "1000"},
		}, "a407726e71fc08e1452222192dafdfffe9676ce9c3c6ff3f6e7ae1d1ffd24917"},
	} {
		got, err := policyHash(tc.policy)
		if err != nil || got != tc.want {
			t.Errorf("%s: policyHash = %s, %v; the gateway reported %s", tc.name, got, err, tc.want)
		}
	}
	withRule := runPolicy()
	withRule.NetworkPolicies = map[string]*sandboxv1.NetworkPolicyRule{"x": {Name: "x"}}
	if _, err := policyHash(withRule); err == nil {
		t.Error("policyHash accepted a policy with a network rule")
	}
}

func TestResourceLimits(t *testing.T) {
	for _, tc := range []struct {
		mem  int
		cpus float64
		want string
	}{
		{256, 1, `{"limits":{"cpu":"1","memory":"256Mi"}}`},
		{192, 0.5, `{"limits":{"cpu":"0.5","memory":"192Mi"}}`},
	} {
		s, err := resourceLimits(tc.mem, tc.cpus)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := json.Marshal(s.AsMap())
		if string(got) != tc.want {
			t.Errorf("resourceLimits(%d, %v) = %s, want %s", tc.mem, tc.cpus, got, tc.want)
		}
	}
}

func TestCapture(t *testing.T) {
	c := capture{limit: 5}
	c.write([]byte("abc"))
	c.write([]byte("de"))
	if string(c.buf) != "abcde" || c.dropped {
		t.Fatalf("exact fill: %q dropped=%v", c.buf, c.dropped)
	}
	c.write([]byte("f"))
	if string(c.buf) != "abcde" || !c.dropped {
		t.Fatalf("overflow: %q dropped=%v", c.buf, c.dropped)
	}
	c = capture{limit: 4}
	c.write([]byte("abcdef"))
	if string(c.buf) != "abcd" || !c.dropped {
		t.Fatalf("split write: %q dropped=%v", c.buf, c.dropped)
	}
}

func TestRunJavaScript(t *testing.T) {
	f, p := newFake(t)
	f.run = echoScript
	if p.IsolationClass() != sandbox.IsolationUnknown {
		t.Fatalf("tier before any check = %v, want unknown", p.IsolationClass())
	}
	code := `console.log("hello")`
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: code})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.Stdout != code || res.ExitCode != 0 || res.TimedOut || res.Isolation != sandbox.IsolationContainer || res.Sandbox != Name {
		t.Fatalf("got %+v", res)
	}
	e := f.lastExec()
	if got := e.start.GetCommand(); len(got) != 2 || got[0] != "node" || got[1] != "-" || !e.start.GetNoLoginShell() || e.start.GetExecutionTimeout() == nil {
		t.Fatalf("exec start = %v", e.start)
	}
	if !strings.HasPrefix(e.start.GetSandbox(), namePrefix) || len(e.start.GetSandbox()) > 19 {
		t.Fatalf("sandbox name %q", e.start.GetSandbox())
	}
	if err := p.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if live := f.live(); len(live) != 0 {
		t.Fatalf("sandboxes left after the run: %v", live)
	}
	if n := f.called("DeleteSandbox"); n != 1 {
		t.Fatalf("DeleteSandbox called %d times", n)
	}
}

// TestCreateRequest checks what a run asks the gateway for: this instance's label, the
// run label and the lifetime (the run's own budget, a snippet's default 5 s here), the
// image, the limits and the run policy, in the default workspace.
func TestCreateRequest(t *testing.T) {
	f, p := newFake(t)
	var spec *openshellv1.Sandbox
	f.run = func(e *fakeExec) error {
		f.mu.Lock()
		spec = proto.Clone(f.boxes[e.start.GetSandbox()].sb).(*openshellv1.Sandbox)
		f.mu.Unlock()
		return echoScript(e)
	}
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	if l := spec.GetMetadata().GetLabels(); l[instanceLabel] != p.instance || len(p.instance) != 16 ||
		l[runLabel] != "1" || l[lifetimeLabel] != "5" || len(l) != 3 {
		t.Fatalf("labels %v, instance %q", l, p.instance)
	}
	tmpl := spec.GetSpec().GetTemplate()
	limits := tmpl.GetResources().AsMap()["limits"].(map[string]any)
	if tmpl.GetImage() != "plimsoll/sandbox:test" || limits["memory"] != "256Mi" || limits["cpu"] != "1" {
		t.Fatalf("template %v", tmpl)
	}
	pol := spec.GetSpec().GetPolicy()
	if !proto.Equal(pol, runPolicy()) || len(pol.GetNetworkPolicies()) != 0 || pol.GetFilesystem().GetIncludeWorkdir() ||
		pol.GetLandlock().GetCompatibility() != "hard_requirement" {
		t.Fatalf("policy %v", pol)
	}
	if got := pol.GetFilesystem().GetReadWrite(); len(got) != 2 || got[0] != "/tmp" || got[1] != "/dev/null" {
		t.Fatalf("read_write %v, want only /tmp and /dev/null", got)
	}
}

func TestRunJavaScriptCapsOutput(t *testing.T) {
	f, p := newFake(t)
	f.run = func(e *fakeExec) error {
		e.readAll()
		chunk := bytes.Repeat([]byte("a"), 4096)
		for i := 0; i < 25; i++ { // 100 KiB, past the 64 KiB cap
			if err := e.stdout(chunk); err != nil {
				return err
			}
		}
		if err := e.stderr([]byte("warn")); err != nil {
			return err
		}
		return e.exit(0)
	}
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "flood"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != maxOutputBytes || !res.StdoutTruncated || res.Stderr != "warn" || res.StderrTruncated || res.ExitCode != 0 {
		t.Fatalf("stdout %d bytes truncated=%v, stderr %q truncated=%v, exit %d", len(res.Stdout), res.StdoutTruncated, res.Stderr, res.StderrTruncated, res.ExitCode)
	}
}

// TestRunJavaScriptTimeout requires the deadline to cancel the exec stream (on the
// docker driver, the kill) and the run to report a timeout with the output so far.
func TestRunJavaScriptTimeout(t *testing.T) {
	f, p := newFake(t)
	f.run = func(e *fakeExec) error {
		e.readAll()
		if err := e.stdout([]byte("started\n")); err != nil {
			return err
		}
		return e.hang()
	}
	start := time.Now()
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "for(;;){}", Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if !res.TimedOut || res.ExitCode != 124 || res.Stdout != "started\n" {
		t.Fatalf("got %+v", res)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("a 300ms budget took %v", took)
	}
	e := f.lastExec()
	deadline := time.Now().Add(2 * time.Second)
	for !e.wasCancelled() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !e.wasCancelled() {
		t.Fatal("the gateway never saw the exec stream cancelled")
	}
}

// TestCallerCancellation is not a timeout: the caller's own cancellation is an error.
func TestCallerCancellation(t *testing.T) {
	f, p := newFake(t)
	started := make(chan struct{})
	f.run = func(e *fakeExec) error {
		e.readAll()
		close(started)
		return e.hang()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	if _, err := p.RunJavaScript(ctx, sandbox.Request{Code: "x"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// TestExitStatusBeatsSendFailure: a command that exits without reading its stdin makes
// the send side fail, and the exit status still decides the result.
func TestExitStatusBeatsSendFailure(t *testing.T) {
	f, p := newFake(t)
	f.run = func(e *fakeExec) error {
		if err := e.stderr([]byte("bye")); err != nil {
			return err
		}
		return e.exit(7)
	}
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: strings.Repeat("x", sandbox.MaxCodeBytes)})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.ExitCode != 7 || res.Stderr != "bye" {
		t.Fatalf("got %+v", res)
	}
	// 16 MiB is far more than HTTP/2 flow control lets through to a gateway that never
	// reads, so the send side cannot finish: it fails when the stream ends.
	ctx := context.Background()
	b, err := p.create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer p.deleteLater(b)
	out, err := p.exec(ctx, b, []string{"node", "-"}, nil, make([]byte, 16<<20), 64, 64)
	if err != nil || !out.exited || out.exitCode != 7 || string(out.stderr) != "bye" {
		t.Fatalf("exec = %+v, %v; want exit 7", out, err)
	}
}

func TestStreamWithoutExitIsAnError(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(e *fakeExec) error
	}{
		{"ends cleanly", func(e *fakeExec) error { e.readAll(); return e.stdout([]byte("partial")) }},
		{"fails", func(e *fakeExec) error {
			e.readAll()
			return connect.NewError(connect.CodeUnavailable, errors.New("supervisor relay failed"))
		}},
	} {
		f, p := newFake(t)
		f.run = tc.run
		if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x"}); err == nil {
			t.Errorf("%s: a stream with no exit status gave a result", tc.name)
		}
	}
}

// stdinBytes sends n bytes of stdin and requires the fake to receive them all, in
// frames no larger than the gateway's per-message limit allows.
func TestStdinFramesAndHalfClose(t *testing.T) {
	f, p := newFake(t)
	var got []byte
	f.run = func(e *fakeExec) error {
		got = e.readAll() // returns only at the client's half-close
		if err := e.stdout([]byte(fmt.Sprint(len(got)))); err != nil {
			return err
		}
		return e.exit(0)
	}
	code := strings.Repeat("0123456789abcdef", sandbox.MaxCodeBytes/16)
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != fmt.Sprint(len(code)) || string(got) != code {
		t.Fatalf("the gateway received %d of %d bytes", len(got), len(code))
	}
}

// wirePlan is the runner's stdin as the fake decodes it.
type wirePlan struct {
	Files []struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	} `json:"files"`
	Steps         []string `json:"steps"`
	StepTimeoutMs int64    `json:"stepTimeoutMs"`
	Artifacts     []string `json:"artifacts"`
	ReportKey     string   `json:"reportKey"`
}

// frameWith frames a runner report under key the way runner.mjs does.
func frameWith(key []byte, body string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(body))
	return fmt.Sprintf("\n%s %d %x\n%s", runnerwire.Marker, len(body), h.Sum(nil), body)
}

// signed frames a runner report under the key the plan carried, as the real runner
// signs it.
func signed(t *testing.T, plan wirePlan, body string) string {
	t.Helper()
	key, err := hex.DecodeString(plan.ReportKey)
	if err != nil || len(key) != runnerwire.KeySize {
		t.Fatalf("plan carries no usable report key: %q", plan.ReportKey)
	}
	return frameWith(key, body)
}

// fakeRunner is a /runner.mjs stand-in: it decodes the plan and writes whatever
// report returns to stdout, then exits.
func fakeRunner(t *testing.T, report func(wirePlan) (stdout, stderr string, exit int32)) func(e *fakeExec) error {
	return func(e *fakeExec) error {
		var plan wirePlan
		if err := json.Unmarshal(e.readAll(), &plan); err != nil {
			t.Errorf("runner stdin is not a plan: %v", err)
		}
		stdout, stderr, exit := report(plan)
		if stdout != "" {
			if err := e.stdout([]byte(stdout)); err != nil {
				return err
			}
		}
		if stderr != "" {
			if err := e.stderr([]byte(stderr)); err != nil {
				return err
			}
		}
		return e.exit(exit)
	}
}

func TestRunProject(t *testing.T) {
	f, p := newFake(t)
	var seen wirePlan
	f.run = fakeRunner(t, func(plan wirePlan) (string, string, int32) {
		seen = plan
		return "incidental\n" + signed(t, plan, `{"steps":[{"command":"node main.js","stdout":"hi\n","exitCode":0,"durationMs":12},`+
			`{"command":"exit 2","stderr":"boom","stderrTruncated":true,"exitCode":2,"durationMs":1}],`+
			`"artifacts":[{"path":"out.txt","content":"aGk="}],"artifactsTruncated":true}`), "", 0
	})
	req := sandbox.ProjectRequest{
		Files:     []sandbox.File{{Path: "main.js", Content: "console.log('hi')"}, {Path: "lib/a.js", Content: "<x>"}},
		Steps:     []string{"node main.js", "exit 2", "echo never"},
		Artifacts: []string{"out.txt"},
		Timeout:   7 * time.Second,
	}
	res, err := p.RunProject(context.Background(), req)
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	e := f.lastExec()
	if cmd := e.start.GetCommand(); strings.Join(cmd, "\x00") != strings.Join(runnerCommand, "\x00") || e.start.GetEnvironment()["PLIMSOLL_WORK"] != workDir {
		t.Fatalf("runner exec %q env %v", cmd, e.start.GetEnvironment())
	}
	if len(seen.Files) != 2 || seen.Files[1].Content != "<x>" || len(seen.Steps) != 3 || seen.StepTimeoutMs != 7000 || seen.Artifacts[0] != "out.txt" {
		t.Fatalf("plan %+v", seen)
	}
	want := sandbox.ProjectResult{
		Sandbox: Name, Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted,
		Steps: []sandbox.StepResult{
			{Command: "node main.js", Stdout: "hi\n", Duration: 12 * time.Millisecond},
			{Command: "exit 2", Stderr: "boom", StderrTruncated: true, ExitCode: 2, Duration: time.Millisecond},
		},
		Artifacts:          []sandbox.Artifact{{Path: "out.txt", Content: []byte("hi")}},
		ArtifactsTruncated: true,
	}
	if fmt.Sprintf("%+v", res) != fmt.Sprintf("%+v", want) {
		t.Fatalf("got  %+v\nwant %+v", res, want)
	}
}

func TestRunProjectOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		stdout      string
		stderr      string
		exit        int32
		outcome     sandbox.ProjectOutcome
		detailMatch string
	}{
		// The runner's stderr is writable by every process in the sandbox, so it never
		// becomes the detail; the exit code does.
		{"runner killed", "", "Killed by a guest-written line\n", 137, sandbox.ProjectOutcomeProtocolError, "the runner did not report (it exited 137)"},
		{"silent runner", "", "", 1, sandbox.ProjectOutcomeProtocolError, "(it exited 1)"},
		{"broken report", "REPORT:{", "", 0, sandbox.ProjectOutcomeProtocolError, "could not parse"},
		{"setup failure", `REPORT:{"error":"illegal file path: ../x"}`, "", 0, sandbox.ProjectOutcomeSetupFailed, "illegal file path"},
		{"hung step", `REPORT:{"steps":[{"command":"a","exitCode":0},{"command":"b","exitCode":124,"timedOut":true}]}`, "", 0, sandbox.ProjectOutcomeTimedOut, "step 2 exceeded"},
		// A process in the sandbox can write the runner's stdout but has no key.
		{"forged report", frameWith(bytes.Repeat([]byte{9}, runnerwire.KeySize), `{"steps":[{"command":"a","exitCode":0}]}`), "", 0, sandbox.ProjectOutcomeProtocolError, "no authenticated runner report"},
	} {
		f, p := newFake(t)
		f.run = fakeRunner(t, func(plan wirePlan) (string, string, int32) {
			out := tc.stdout
			if body, ok := strings.CutPrefix(out, "REPORT:"); ok {
				out = signed(t, plan, body)
			}
			return out, tc.stderr, tc.exit
		})
		res, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"a", "b"}})
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if res.Outcome != tc.outcome || !strings.Contains(res.Detail, tc.detailMatch) {
			t.Errorf("%s: outcome %v detail %q, want %v containing %q", tc.name, res.Outcome, res.Detail, tc.outcome, tc.detailMatch)
		}
		if strings.Contains(res.Detail, "guest-written") {
			t.Errorf("%s: the runner's stderr reached the detail: %q", tc.name, res.Detail)
		}
	}
}

// TestRunProjectDeadline: when the run's outer deadline ends a runner that never
// reports, the outcome is timed_out.
func TestRunProjectDeadline(t *testing.T) {
	f, p := newFake(t)
	f.run = func(e *fakeExec) error { e.readAll(); return e.hang() }
	// The budget covers creating the sandbox and the ready poll as well as the hanging
	// exec, so it is generous: at 400 ms a loaded machine spent it before the exec
	// started, and the run failed instead of timing out (seen in the export's run of
	// the whole suite).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := p.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"sleep 60"}})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != sandbox.ProjectOutcomeTimedOut || res.Detail != "run exceeded the time budget" {
		t.Fatalf("got %+v", res)
	}
}

// TestReadBackRefusals: any difference between what a run asked for and what the
// gateway reads back refuses the run before any code executes, and the sandbox is
// deleted.
func TestReadBackRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bend   func(f *fakeGateway)
		expect string
	}{
		{"spec policy", func(f *fakeGateway) {
			f.mutateSpec = func(sb *openshellv1.Sandbox) {
				sb.Spec.Policy.Filesystem.ReadWrite = append(sb.Spec.Policy.Filesystem.ReadWrite, "/")
			}
		}, "spec's policy differs"},
		{"effective policy", func(f *fakeGateway) {
			f.mutateConfig = func(c *sandboxv1.GetSandboxConfigResponse) {
				c.Policy.NetworkPolicies = map[string]*sandboxv1.NetworkPolicyRule{"any": {Name: "any"}}
			}
		}, "differs from the policy sent"},
		{"hash", func(f *fakeGateway) {
			f.mutateConfig = func(c *sandboxv1.GetSandboxConfigResponse) { c.PolicyHash = strings.Repeat("0", 64) }
		}, "hash"},
		{"global policy", func(f *fakeGateway) {
			f.mutateConfig = func(c *sandboxv1.GetSandboxConfigResponse) {
				c.PolicySource = sandboxv1.PolicySource_POLICY_SOURCE_GLOBAL
			}
		}, "gateway-wide"},
		{"not admitted", func(f *fakeGateway) {
			f.mutateConfig = func(c *sandboxv1.GetSandboxConfigResponse) {
				c.ConfigurationAdmitted, c.ConfigurationError = false, "provider missing"
			}
		}, "not admitted"},
		{"agent proposals", func(f *fakeGateway) {
			f.mutateConfig = func(c *sandboxv1.GetSandboxConfigResponse) {
				c.Settings[agentProposalsSetting] = &sandboxv1.EffectiveSetting{Value: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_BoolValue{BoolValue: true}}}
			}
		}, agentProposalsSetting},
		// External review of v0.10.0, finding 6 (2026-09-28): an absent key read as off.
		{"agent proposals not reported", func(f *fakeGateway) {
			f.mutateConfig = func(c *sandboxv1.GetSandboxConfigResponse) { delete(c.Settings, agentProposalsSetting) }
		}, "did not report " + agentProposalsSetting},
		{"agent proposals not a boolean", func(f *fakeGateway) {
			f.mutateConfig = func(c *sandboxv1.GetSandboxConfigResponse) {
				c.Settings[agentProposalsSetting] = &sandboxv1.EffectiveSetting{Value: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_StringValue{StringValue: "yes"}}}
			}
		}, agentProposalsSetting},
		{"image", func(f *fakeGateway) {
			f.mutateSpec = func(sb *openshellv1.Sandbox) { sb.Spec.Template.Image = "other:latest" }
		}, "image reads back"},
		{"resources", func(f *fakeGateway) {
			f.mutateSpec = func(sb *openshellv1.Sandbox) {
				sb.Spec.Template.Resources, _ = structpb.NewStruct(map[string]any{})
			}
		}, "resources"},
		{"label", func(f *fakeGateway) {
			f.mutateSpec = func(sb *openshellv1.Sandbox) { sb.Metadata.Labels[instanceLabel] = "someone-else" }
		}, "label"},
		{"lifetime label", func(f *fakeGateway) {
			f.mutateSpec = func(sb *openshellv1.Sandbox) { sb.Metadata.Labels[lifetimeLabel] = "99999" }
		}, "label plimsoll.lifetime"},
		{"driver config not sent", func(f *fakeGateway) {
			f.mutateSpec = func(sb *openshellv1.Sandbox) {
				sb.Spec.Template.DriverConfig, _ = structpb.NewStruct(map[string]any{"docker": map[string]any{"privileged": true}})
			}
		}, "driver config"},
		{"providers", func(f *fakeGateway) {
			f.mutateSpec = func(sb *openshellv1.Sandbox) { sb.Spec.Providers = []string{"github"} }
		}, "credential providers"},
		{"error phase", func(f *fakeGateway) { f.failPhase = openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR }, "ImagePullFailed"},
	} {
		f, p := newFake(t)
		f.run = echoScript
		tc.bend(f)
		_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x"})
		if err == nil || !strings.Contains(err.Error(), tc.expect) {
			t.Errorf("%s: err = %v, want a refusal mentioning %q", tc.name, err, tc.expect)
		}
		if n := f.called("ExecSandboxInteractive"); n != 0 {
			t.Errorf("%s: %d execs ran on a refused sandbox", tc.name, n)
		}
		if err := p.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		if live := f.live(); len(live) != 0 {
			t.Errorf("%s: refused sandbox not deleted: %v", tc.name, live)
		}
	}
}

func TestDriverEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		info   func() (*openshellv1.GetGatewayInfoResponse, error)
		expect string
	}{
		{"vm driver", func() (*openshellv1.GetGatewayInfoResponse, error) {
			r, _ := dockerInfo()
			r.ComputeDrivers[0].Name, r.ComputeDrivers[0].Capabilities.DriverName = "vm", "vm"
			return r, nil
		}, `"vm"`},
		{"renamed driver", func() (*openshellv1.GetGatewayInfoResponse, error) {
			r, _ := dockerInfo()
			r.ComputeDrivers[0].Capabilities.DriverName = "podman"
			return r, nil
		}, "podman"},
		{"two drivers", func() (*openshellv1.GetGatewayInfoResponse, error) {
			r, _ := dockerInfo()
			r.ComputeDrivers = append(r.ComputeDrivers, r.ComputeDrivers[0])
			return r, nil
		}, "2 compute drivers"},
		{"no limits", func() (*openshellv1.GetGatewayInfoResponse, error) {
			r, _ := dockerInfo()
			r.ComputeDrivers[0].Capabilities.ResourceCapabilities = nil
			return r, nil
		}, "limit support"},
		{"denied", func() (*openshellv1.GetGatewayInfoResponse, error) {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("requires platform_admin"))
		}, "platform_admin"},
	} {
		f, p := newFake(t)
		f.run = echoScript
		if err := p.Preflight(context.Background()); err != nil {
			t.Fatalf("%s: docker preflight: %v", tc.name, err)
		}
		if p.IsolationClass() != sandbox.IsolationContainer {
			t.Fatalf("%s: tier after a docker check = %v", tc.name, p.IsolationClass())
		}
		f.info = tc.info
		if err := p.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), tc.expect) {
			t.Errorf("%s: Preflight = %v, want an error mentioning %s", tc.name, err, tc.expect)
		}
		if p.IsolationClass() != sandbox.IsolationUnknown {
			t.Errorf("%s: tier after a failed check = %v, want unknown", tc.name, p.IsolationClass())
		}
		if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x"}); err == nil {
			t.Errorf("%s: a run was served", tc.name)
		}
		if n := f.called("CreateSandbox"); n != 0 {
			t.Errorf("%s: %d sandboxes created without driver evidence", tc.name, n)
		}
	}
}

// TestRefusalsBeforeDispatch: refusals that run nothing are marked as not dispatched
// and cost no sandbox.
func TestRefusalsBeforeDispatch(t *testing.T) {
	f, p := newFake(t)
	f.run = echoScript
	// Cleartext off loopback: the grant itself is invalid, so it is refused before
	// dispatch. Valid grants run (grant_test.go).
	grant := &sandbox.HostAPIGrant{BaseURL: "http://api.example.com"}
	ctx := context.Background()
	check := func(name string, err error, want error, reason sandbox.Refusal) {
		t.Helper()
		got, marked := sandbox.NotDispatchedReason(err)
		if !errors.Is(err, want) || !marked || got != reason {
			t.Errorf("%s: err = %v (marked=%v reason=%v), want %v marked %v", name, err, marked, got, want, reason)
		}
	}
	_, err := p.RunJavaScript(ctx, sandbox.Request{Code: "x", Grant: grant})
	check("invalid snippet grant", err, sandbox.ErrInvalidRequest, sandbox.RefusalRequest)
	_, err = p.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"true"}, Grant: grant})
	check("invalid project grant", err, sandbox.ErrInvalidRequest, sandbox.RefusalRequest)
	_, err = p.RunModule(ctx, sandbox.ModuleRequest{Model: "VanDerPol", Rows: [][]float64{{1}}, EndTime: 1, Step: 0.1})
	check("module", err, sandbox.ErrUnsupported, sandbox.RefusalUnsupported)
	_, err = p.RunJavaScript(ctx, sandbox.Request{Code: "x", MinimumIsolation: sandbox.IsolationKernel})
	check("kernel floor", err, sandbox.ErrInsufficientIsolation, sandbox.RefusalIsolation)
	_, err = p.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"true"}, MinimumIsolation: sandbox.IsolationVM})
	check("vm floor", err, sandbox.ErrInsufficientIsolation, sandbox.RefusalIsolation)
	_, err = p.RunJavaScript(ctx, sandbox.Request{})
	check("empty code", err, sandbox.ErrInvalidRequest, sandbox.RefusalRequest)
	if n := f.called("CreateSandbox") + f.called("GetGatewayInfo"); n != 0 {
		t.Fatalf("%d gateway calls for refused requests", n)
	}
	// A container floor is met by the docker driver's evidence.
	if _, err := p.RunJavaScript(ctx, sandbox.Request{Code: "x", MinimumIsolation: sandbox.IsolationContainer}); err != nil {
		t.Fatalf("container floor: %v", err)
	}
	if !p.SupportsProjects() || p.SupportsModules() || !p.SupportsJavaScriptGrants() || !p.SupportsProjectGrants() {
		t.Fatal("capability flags")
	}
}

// TestReconcileOrphans: this instance's untracked sandboxes go at once; another
// instance's go only after its declared lifetime plus staleMargin, measured from the
// gateway's creation time; nothing in flight, already deleting, undeclared or
// unlabelled is touched.
func TestReconcileOrphans(t *testing.T) {
	f, p := newFake(t)
	p.noteSkew(0) // the reaper has measured the gateway's clock, as any create does
	run := func(instance, lifetime string) map[string]string {
		l := map[string]string{instanceLabel: instance, runLabel: "1"}
		if lifetime != "" {
			l[lifetimeLabel] = lifetime
		}
		return l
	}
	ready, now := openshellv1.SandboxPhase_SANDBOX_PHASE_READY, time.Now()
	ago := func(d time.Duration) *timestamppb.Timestamp { return timestamppb.New(now.Add(-d)) }
	// Reaped.
	f.add("plp-orphan", run(p.instance, "5"), ready)
	f.addAt("plp-expired", run("crashed", "60"), ready, ago(60*time.Second+staleMargin+time.Minute))
	// Kept.
	f.add("plp-inflight", run(p.instance, "5"), openshellv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING)
	f.add("plp-going", run(p.instance, "5"), openshellv1.SandboxPhase_SANDBOX_PHASE_DELETING)
	f.addAt("plp-within", run("alive", "60"), ready, ago(60*time.Second+staleMargin-time.Minute))
	f.addAt("plp-undeclared", run("crashed", ""), ready, ago(24*time.Hour))
	for i, bad := range []string{"0", "-5", "+5", "abc", "99999999999"} {
		f.addAt(fmt.Sprintf("plp-bad%d", i), run("crashed", bad), ready, ago(24*time.Hour))
	}
	f.addAt("plp-no-created", run("crashed", "60"), ready, nil)
	f.addAt("plp-no-run-label", map[string]string{instanceLabel: "crashed", lifetimeLabel: "60"}, ready, ago(24*time.Hour))
	f.add("unlabelled", nil, ready)
	p.track("plp-inflight")
	defer p.untrack("plp-inflight")

	n, err := p.ReconcileOrphans(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("ReconcileOrphans = %d, %v; want 2", n, err)
	}
	live := map[string]bool{}
	for _, name := range f.live() {
		live[name] = true
	}
	for _, name := range []string{"plp-orphan", "plp-expired"} {
		if live[name] {
			t.Errorf("%s survived", name)
		}
	}
	for _, name := range []string{"plp-inflight", "plp-going", "plp-within", "plp-undeclared", "plp-bad0", "plp-bad1",
		"plp-bad2", "plp-bad3", "plp-bad4", "plp-no-created", "plp-no-run-label", "unlabelled"} {
		if !live[name] {
			t.Errorf("%s was deleted", name)
		}
	}
}

// TestPreflightIsCached: the daemon serves /readyz without authentication, so a call
// during an in-flight check answers at once (not ready, before any check has
// finished), and a burst of calls afterwards costs one gateway call.
func TestPreflightIsCached(t *testing.T) {
	f, p := newFake(t)
	p.pfTTL = preflightTTL
	entered, release := make(chan struct{}), make(chan struct{})
	f.info = func() (*openshellv1.GetGatewayInfoResponse, error) {
		close(entered)
		<-release
		return dockerInfo()
	}
	first := make(chan error, 1)
	go func() { first <- p.Preflight(context.Background()) }()
	<-entered
	if err := p.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "no gateway check has completed") {
		t.Fatalf("Preflight during the first check = %v, want not ready", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	for range 50 {
		if err := p.Preflight(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.called("GetGatewayInfo"); n != 1 {
		t.Fatalf("GetGatewayInfo called %d times for 52 Preflight calls, want 1", n)
	}
}

// TestTierLossIsLogged: a driver check that fails after one passed logs once, further
// failures stay quiet, and the next pass logs the recovery.
func TestTierLossIsLogged(t *testing.T) {
	f, p := newFake(t)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	ctx := context.Background()
	if err := p.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	f.info = func() (*openshellv1.GetGatewayInfoResponse, error) {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("gateway down"))
	}
	for range 3 {
		if err := p.Preflight(ctx); err == nil {
			t.Fatal("preflight passed with the gateway down")
		}
	}
	if tier := p.IsolationClass(); tier != sandbox.IsolationUnknown {
		t.Fatalf("tier %v with the gateway down, want unknown", tier)
	}
	f.info = dockerInfo
	if err := p.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if lost, back := strings.Count(out, "isolation tier is unknown"), strings.Count(out, "tier is restored"); lost != 1 || back != 1 {
		t.Fatalf("logged the loss %d times and the recovery %d times, want once each:\n%s", lost, back, out)
	}
}

// TestDeleteWaitsUntilGone: an accepted deletion is watched until the record is gone,
// and the name stays tracked (so Drain waits) until then.
func TestDeleteWaitsUntilGone(t *testing.T) {
	f, p := newFake(t)
	f.run = echoScript
	f.deletePolls = 5
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, b := range f.boxes {
		if !b.deleted || b.pollsAfterGone > 0 {
			t.Fatalf("%s: drained before the gateway stopped reporting it", name)
		}
	}
}

// TestDeleteGivesUp: a delete that keeps failing is retried, logged and untracked, so
// Drain returns and ReconcileOrphans owns the sandbox.
func TestDeleteGivesUp(t *testing.T) {
	f, p := newFake(t)
	f.run = echoScript
	f.deleteErr = connect.NewError(connect.CodeUnavailable, errors.New("gateway busy"))
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.called("DeleteSandbox"); n != 3 {
		t.Fatalf("DeleteSandbox called %d times, want 3 attempts", n)
	}
	f.mu.Lock()
	f.deleteErr = nil
	f.mu.Unlock()
	if n, err := p.ReconcileOrphans(ctx); err != nil || n != 1 {
		t.Fatalf("ReconcileOrphans = %d, %v; want the undeleted sandbox", n, err)
	}
}

func TestEnvironments(t *testing.T) {
	_, p := newFake(t)
	env := p.Environments()
	if env.JavaScript.Identity != "" || env.JavaScript.MaxTimeout != snippetMax || env.Project.MaxTimeout != projectMax || !reflect.DeepEqual(env.Module, sandbox.PayloadEnvironment{}) {
		t.Fatalf("tag image: %+v", env)
	}
	digest := strings.Repeat("Ab", 32)
	p.cfg.Image = "plimsoll/sandbox@sha256:" + digest
	if env := p.Environments(); env.Project.Identity != "openshell-image:sha256:"+strings.ToLower(digest) {
		t.Fatalf("pinned image: %+v", env)
	}
}

func TestSmokeChecks(t *testing.T) {
	if err := checkWritable(500, []string{"/tmp", "/tmp/x"}, nil); err != nil {
		t.Errorf("only /tmp: %v", err)
	}
	for _, tc := range []struct {
		swept        int
		dirs, files  []string
		expectSubstr string
	}{
		{500, []string{"/tmp", "/sandbox"}, nil, "/sandbox"},
		{500, []string{"/tmp"}, []string{"/.openshell/channel/x"}, "/.openshell"},
		{500, []string{"/tmpfoo"}, nil, "/tmpfoo"},
		{500, nil, nil, "/tmp does not accept writes"},
		{3, []string{"/tmp"}, nil, "too few"},
	} {
		if err := checkWritable(tc.swept, tc.dirs, tc.files); err == nil || !strings.Contains(err.Error(), tc.expectSubstr) {
			t.Errorf("checkWritable(%d, %v, %v) = %v, want %q", tc.swept, tc.dirs, tc.files, err, tc.expectSubstr)
		}
	}
	if err := checkEgress(map[string]string{"a": "EACCES", "b": "timeout"}); err != nil {
		t.Errorf("denied egress: %v", err)
	}
	if err := checkEgress(map[string]string{"a": "EACCES", "b": "open"}); err == nil {
		t.Error("open egress passed")
	}
	if err := checkEgress(nil); err == nil {
		t.Error("no egress attempts passed")
	}
	if err := checkLimits("268435456", "100000 100000", 256, 1); err != nil {
		t.Errorf("exact limits: %v", err)
	}
	if err := checkLimits("201326592", "50000 100000", 192, 0.5); err != nil {
		t.Errorf("fractional CPU: %v", err)
	}
	for _, tc := range [][2]string{{"max", "100000 100000"}, {"268435456", "max 100000"}, {"268435456", "200000 100000"}, {"unreadable: EACCES", "100000 100000"}} {
		if err := checkLimits(tc[0], tc[1], 256, 1); err == nil {
			t.Errorf("checkLimits(%q, %q) passed", tc[0], tc[1])
		}
	}
}

// smokeFake scripts the fake to play the sandbox the smoke test probes: a probe
// report, a runner that really hashes the plan's blob, and a hung command whose
// processes the counting exec sees until the stream is cancelled.
type smokeFake struct {
	report      map[string]any
	surviveKill bool

	mu    sync.Mutex
	alive int // processes of the hung command the counter reports
}

func (s *smokeFake) setAlive(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alive = n
}

func (s *smokeFake) run(t *testing.T) func(e *fakeExec) error {
	return func(e *fakeExec) error {
		cmd := e.start.GetCommand()
		switch {
		case strings.Contains(strings.Join(cmd, " "), "plimsoll-hang-"):
			e.readAll()
			s.setAlive(2)
			err := e.hang()
			if !s.surviveKill {
				s.setAlive(0)
			}
			return err
		case len(cmd) == 3 && strings.Contains(cmd[2], `print("python")`):
			e.readAll()
			if err := e.stdout([]byte("javascript\n")); err != nil {
				return err
			}
			return e.exit(0)
		case strings.Join(cmd, "\x00") == strings.Join(runnerCommand, "\x00"):
			var plan wirePlan
			if err := json.Unmarshal(e.readAll(), &plan); err != nil {
				t.Errorf("smoke plan: %v", err)
			}
			blob := ""
			for _, f := range plan.Files {
				if f.Path == "data/blob.txt" {
					blob = f.Content
				}
			}
			out := fmt.Sprintf("%d %x", len(blob), sha256.Sum256([]byte(blob)))
			report := signed(t, plan, `{"steps":[{"command":"node main.js","exitCode":0}],"artifacts":[{"path":"out.txt","content":"`+
				base64.StdEncoding.EncodeToString([]byte(out))+`"}]}`)
			if err := e.stdout([]byte(report)); err != nil {
				return err
			}
			return e.exit(0)
		default: // `node -`: the probe or the process counter
			script := string(e.readAll())
			var out []byte
			if strings.Contains(script, "/cmdline") {
				s.mu.Lock()
				out = []byte(fmt.Sprint(s.alive))
				s.mu.Unlock()
			} else {
				out, _ = json.Marshal(s.report)
			}
			if err := e.stdout(out); err != nil {
				return err
			}
			return e.exit(0)
		}
	}
}

func goodProbeReport() map[string]any {
	return map[string]any{
		"node": "v22.23.3", "swept": 5424, "writable": []string{"/tmp"}, "writableFiles": []string{},
		"egress":    map[string]string{"tcp 1.1.1.1:443": "EACCES", "https://example.com": "EACCES"},
		"dns":       "198.18.0.2",
		"memoryMax": "268435456", "cpuMax": "100000 100000", "pidsMax": "2048", "interfaces": []string{"lo"},
	}
}

func TestSmokeTestAgainstFake(t *testing.T) {
	for _, tc := range []struct {
		name   string
		adjust func(*smokeFake)
		expect string
	}{
		{"passes", func(*smokeFake) {}, ""},
		{"home writable", func(s *smokeFake) { s.report["writable"] = []string{"/tmp", "/sandbox"} }, "outside /tmp"},
		{"egress open", func(s *smokeFake) { s.report["egress"] = map[string]string{"tcp 1.1.1.1:443": "open"} }, "OPEN"},
		{"no memory limit", func(s *smokeFake) { s.report["memoryMax"] = "max" }, "memory.max"},
		{"external interface", func(s *smokeFake) { s.report["interfaces"] = []string{"lo", "eth0"} }, "not loopback alone"},
		{"no interfaces reported", func(s *smokeFake) { delete(s.report, "interfaces") }, "not loopback alone"},
		{"survives the cancel", func(s *smokeFake) { s.surviveKill = true }, "left 2 of its processes"},
	} {
		f, p := newFake(t)
		p.killWait = 500 * time.Millisecond
		s := &smokeFake{report: goodProbeReport()}
		tc.adjust(s)
		f.run = s.run(t)
		err := p.SmokeTest(context.Background())
		if tc.expect == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
				continue
			}
			ev := p.lastSmoke()
			if ev.PolicyHash != p.policyHash || ev.PlanBytes < 5<<20 || ev.HungProcesses != 2 || ev.GatewayVersion != "0.1.2-fake" {
				t.Errorf("%s: evidence %+v", tc.name, ev)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.expect) {
			t.Errorf("%s: SmokeTest = %v, want an error mentioning %q", tc.name, err, tc.expect)
		}
	}
}

// TestNewSpeaksMutualTLS builds a provider from PEM files with New and requires it to
// reach a gateway that verifies client certificates, and a certificate from another
// authority to be refused.
func TestNewSpeaksMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := newCA(t, "gateway CA")
	serverCert := issue(t, ca, caKey, "gateway", x509.ExtKeyUsageServerAuth)
	clientPEM, clientKeyPEM := issuePEM(t, ca, caKey, "client", x509.ExtKeyUsageClientAuth)
	other, otherKey := newCA(t, "someone else")
	strangerPEM, strangerKeyPEM := issuePEM(t, other, otherKey, "stranger", x509.ExtKeyUsageClientAuth)
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caFile := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))

	f := &fakeGateway{boxes: map[string]*fakeBox{}, info: dockerInfo}
	path, handler := openshellv1connect.NewOpenShellHandler(f)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	cfg := Config{GatewayURL: srv.URL, CAFile: caFile, CertFile: write("client.pem", clientPEM), KeyFile: write("client.key", clientKeyPEM), Image: "plimsoll/sandbox:latest"}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight over mutual TLS: %v", err)
	}

	stranger := cfg
	stranger.CertFile, stranger.KeyFile = write("stranger.pem", strangerPEM), write("stranger.key", strangerKeyPEM)
	ps, err := New(stranger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := ps.Preflight(context.Background()); err == nil {
		t.Fatal("a client certificate from another authority was accepted")
	}

	for name, bad := range map[string]Config{
		"missing CA":   func() Config { c := cfg; c.CAFile = filepath.Join(dir, "absent.pem"); return c }(),
		"CA not PEM":   func() Config { c := cfg; c.CAFile = write("junk.pem", []byte("junk")); return c }(),
		"key mismatch": func() Config { c := cfg; c.KeyFile = stranger.KeyFile; return c }(),
	} {
		if _, err := New(bad); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}

func newCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func issuePEM(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	certPEM, keyPEM := issuePEM(t, ca, caKey, name, usage)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestReadBackAcceptsProposalsProvablyOff: the two states that prove the setting off
// both pass: reported with no value (the gateway's default, what a v0.1.2 gateway
// sends when nothing set it) and an explicit boolean false.
func TestReadBackAcceptsProposalsProvablyOff(t *testing.T) {
	for name, value := range map[string]*sandboxv1.SettingValue{
		"unset": nil,
		"false": {Value: &sandboxv1.SettingValue_BoolValue{BoolValue: false}},
	} {
		f, p := newFake(t)
		f.run = echoScript
		f.mutateConfig = func(c *sandboxv1.GetSandboxConfigResponse) {
			c.Settings[agentProposalsSetting] = &sandboxv1.EffectiveSetting{Value: value}
		}
		if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x"}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestReconcileReadsAgesOnTheGatewaysClock: another instance's sandbox is aged on the
// gateway's clock, measured at each create, so a local clock running fast does not
// reap a live sandbox, and a reaper that has measured nothing reaps no other
// instance's sandbox (external review of v0.10.0, documentation item 4, 2026-09-28).
func TestReconcileReadsAgesOnTheGatewaysClock(t *testing.T) {
	f, p := newFake(t)
	labels := map[string]string{instanceLabel: "other", runLabel: "1", lifetimeLabel: "60"}
	ready, now := openshellv1.SandboxPhase_SANDBOX_PHASE_READY, time.Now()
	// On the gateway's clock, six minutes behind this one, the sandbox is a second old.
	f.addAt("plp-live-elsewhere", labels, ready, timestamppb.New(now.Add(-6*time.Minute-time.Second)))
	f.mu.Lock()
	sb := f.boxes["plp-live-elsewhere"].sb
	f.mu.Unlock()
	if p.orphaned(sb, now) {
		t.Fatal("a reaper with no clock measurement would reap another instance's sandbox")
	}
	p.noteSkew(-6 * time.Minute)
	if p.orphaned(sb, now) {
		t.Fatal("a sandbox a second old on the gateway's clock was taken for abandoned")
	}
	if !p.orphaned(sb, now.Add(7*time.Minute)) {
		t.Fatal("the sandbox was not reaped once past its lifetime and margin on the gateway's clock")
	}
}

func TestClockSkew(t *testing.T) {
	issued := time.Unix(1790000000, 0)
	ready := issued.Add(2 * time.Second)
	for name, tc := range map[string]struct {
		created time.Time
		want    time.Duration
	}{
		"inside the window":          {issued.Add(time.Second), 0},
		"whole seconds, just before": {issued.Add(-500 * time.Millisecond), 0},
		"gateway behind":             {issued.Add(-3 * time.Minute), -3 * time.Minute},
		"gateway ahead":              {ready.Add(4 * time.Minute), 4 * time.Minute},
	} {
		got, ok := clockSkew(issued, ready, timestamppb.New(tc.created))
		if !ok || got != tc.want {
			t.Errorf("%s: skew %v (%v), want %v", name, got, ok, tc.want)
		}
	}
	if _, ok := clockSkew(issued, ready, nil); ok {
		t.Error("a missing creation time measured a skew")
	}
}

// lateTimer is a context whose deadline has passed but whose timer has not fired.
type lateTimer struct {
	context.Context
	deadline time.Time
}

func (c lateTimer) Deadline() (time.Time, bool) { return c.deadline, true }
func (c lateTimer) Err() error                  { return nil }

// TestDeadlineAwareDoesNotWaitForTheTimer: a create that ends on the deadline before
// the context's timer runs is still reported as the deadline, not as a transport
// error (the rule is deadline.Expired, tested there).
func TestDeadlineAwareDoesNotWaitForTheTimer(t *testing.T) {
	if err := deadlineAware(lateTimer{context.Background(), time.Now().Add(-time.Millisecond)}, errors.New("stream reset")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadlineAware in the late-timer window: %v, want it to wrap DeadlineExceeded", err)
	}
}
