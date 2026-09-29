package openshell

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The live suite runs against a real OpenShell gateway. It is free (a local gateway
// and local docker) but needs one, so it is opt-in: it skips unless OPENSHELL_LIVE=1,
// and with OPENSHELL_LIVE=1 missing configuration fails instead of skipping, so a
// green deliberate run means the gateway was exercised.
//
//	OPENSHELL_LIVE=1
//	SANDBOX_OPENSHELL_GATEWAY_URL   e.g. https://127.0.0.1:17670
//	SANDBOX_OPENSHELL_CA_FILE       the gateway CA (PEM)
//	SANDBOX_OPENSHELL_CERT_FILE     the client certificate (PEM)
//	SANDBOX_OPENSHELL_KEY_FILE      the client key (PEM)
//	SANDBOX_OPENSHELL_IMAGE         e.g. plimsoll/sandbox:latest
//
// Each test uses its own provider instance and, on cleanup, waits for its background
// deletes and requires the gateway to list none of its sandboxes.
func liveProvider(t *testing.T, adjust func(*Config)) *Provider {
	t.Helper()
	if os.Getenv("OPENSHELL_LIVE") != "1" {
		t.Skip("the live OpenShell suite runs with OPENSHELL_LIVE=1 and a gateway")
	}
	cfg := Config{}
	var missing []string
	for _, v := range []struct {
		name  string
		field *string
	}{
		{"SANDBOX_OPENSHELL_GATEWAY_URL", &cfg.GatewayURL},
		{"SANDBOX_OPENSHELL_CA_FILE", &cfg.CAFile},
		{"SANDBOX_OPENSHELL_CERT_FILE", &cfg.CertFile},
		{"SANDBOX_OPENSHELL_KEY_FILE", &cfg.KeyFile},
		{"SANDBOX_OPENSHELL_IMAGE", &cfg.Image},
	} {
		if *v.field = os.Getenv(v.name); *v.field == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("OPENSHELL_LIVE=1 but %s not set", strings.Join(missing, ", "))
	}
	if adjust != nil {
		adjust(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		start := time.Now()
		if err := p.Drain(ctx); err != nil {
			t.Errorf("drain: %v", err)
		}
		resp, err := p.client.ListSandboxes(ctx, connect.NewRequest(&openshellv1.ListSandboxesRequest{
			WorkspaceScope: ws(), LabelSelector: instanceLabel + "=" + p.instance,
		}))
		if err != nil {
			t.Errorf("list sandboxes after drain: %v", err)
		} else if n := len(resp.Msg.GetSandboxes()); n != 0 {
			t.Errorf("%d sandboxes of this instance left after drain", n)
		}
		t.Logf("drained and verified empty in %v", time.Since(start).Round(time.Millisecond))
	})
	return p
}

func TestOpenShellSmokeLive(t *testing.T) {
	p := liveProvider(t, nil)
	start := time.Now()
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	ev := p.lastSmoke()
	t.Logf("smoke passed in %v on gateway %s, tier %s", time.Since(start).Round(time.Millisecond), ev.GatewayVersion, p.IsolationClass())
	t.Logf("policy hash %s (read back equal on sandbox %s)", ev.PolicyHash, ev.Sandbox)
	t.Logf("write sweep: %d paths tried; directories accepting writes %v; files %v", ev.Swept, ev.Writable, ev.WritableFiles)
	t.Logf("egress %v; example.com resolved to %s; interfaces %v", ev.Egress, ev.DNS, ev.Interfaces)
	t.Logf("cgroup: memory.max %s, cpu.max %q, pids.max %s", ev.MemoryMax, ev.CPUMax, ev.PidsMax)
	t.Logf("runner round trip: %d-byte plan (%.2f MiB) in %v", ev.PlanBytes, float64(ev.PlanBytes)/(1<<20), ev.RoundTrip.Round(time.Millisecond))
	t.Logf("kill: %d processes of the hung command alive; none left %v after the cancel", ev.HungProcesses, ev.KillConfirmed.Round(time.Millisecond))
	if p.IsolationClass() != sandbox.IsolationContainer {
		t.Fatalf("tier %v after smoke, want container", p.IsolationClass())
	}
}

// TestOpenShellSmokeEnvelopeLive proves a non-default envelope, a fractional CPU
// limit included, reaches the sandbox's cgroup.
func TestOpenShellSmokeEnvelopeLive(t *testing.T) {
	p := liveProvider(t, func(c *Config) { c.MemoryMB, c.CPUs = 192, 0.5 })
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	ev := p.lastSmoke()
	t.Logf("cgroup: memory.max %s, cpu.max %q", ev.MemoryMax, ev.CPUMax)
}

func TestOpenShellRunJavaScriptLive(t *testing.T) {
	p := liveProvider(t, nil)
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log("openshell", 6*7); console.error("to stderr"); process.exitCode = 3`})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.ExitCode != 3 || res.Stdout != "openshell 42\n" || res.Stderr != "to stderr\n" || res.TimedOut || res.Isolation != sandbox.IsolationContainer || res.Sandbox != Name {
		t.Fatalf("got %+v", res)
	}
	t.Logf("snippet ran in %v", res.Duration.Round(time.Millisecond))
}

func TestOpenShellRunJavaScriptTimeoutLive(t *testing.T) {
	p := liveProvider(t, nil)
	start := time.Now()
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log("started"); for (;;) {}`, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if !res.TimedOut || res.ExitCode != 124 {
		t.Fatalf("got %+v, want a timed-out run", res)
	}
	t.Logf("timed out after %v (budget 2s, sandbox create included); stdout %q", time.Since(start).Round(time.Millisecond), res.Stdout)
}

func TestOpenShellOutputCapLive(t *testing.T) {
	p := liveProvider(t, nil)
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: `process.stdout.write("a".repeat(1 << 20)); process.stderr.write("b".repeat(100))`})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.ExitCode != 0 || !res.StdoutTruncated || len(res.Stdout) != maxOutputBytes || strings.Trim(res.Stdout, "a") != "" || res.StderrTruncated || len(res.Stderr) != 100 {
		t.Fatalf("exit %d, stdout %d bytes truncated=%v, stderr %d bytes truncated=%v", res.ExitCode, len(res.Stdout), res.StdoutTruncated, len(res.Stderr), res.StderrTruncated)
	}
}

func TestOpenShellRunProjectLive(t *testing.T) {
	p := liveProvider(t, nil)
	ctx := context.Background()
	res, err := p.RunProject(ctx, sandbox.ProjectRequest{
		Files: []sandbox.File{
			{Path: "lib/util.mjs", Content: "export const add = (a, b) => a + b;\n"},
			{Path: "main.mjs", Content: "import { add } from './lib/util.mjs';\nimport { writeFileSync } from 'node:fs';\nwriteFileSync('out.txt', String(add(2, 3)));\nconsole.log('sum', add(2, 3), process.cwd());\n"},
		},
		Steps:     []string{"node main.mjs", "exit 7", "echo never"},
		Artifacts: []string{"out.txt", "absent.txt"},
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 2 || res.Steps[0].ExitCode != 0 ||
		res.Steps[0].Stdout != "sum 5 "+workDir+"\n" || res.Steps[1].ExitCode != 7 || res.Isolation != sandbox.IsolationContainer {
		t.Fatalf("got %+v", res)
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Path != "out.txt" || string(res.Artifacts[0].Content) != "5" {
		t.Fatalf("artifacts = %+v", res.Artifacts)
	}

	// No files at all: the work directory must exist before the first step runs.
	res, err = p.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"pwd && echo hi > f.txt"}, Artifacts: []string{"f.txt"}})
	if err != nil {
		t.Fatalf("RunProject without files: %v", err)
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].Stdout != workDir+"\n" ||
		len(res.Artifacts) != 1 || string(res.Artifacts[0].Content) != "hi\n" {
		t.Fatalf("got %+v", res)
	}
}

func TestOpenShellRunProjectStepTimeoutLive(t *testing.T) {
	p := liveProvider(t, nil)
	res, err := p.RunProject(context.Background(), sandbox.ProjectRequest{
		Steps:   []string{"echo before", "sleep 60", "echo never"},
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != sandbox.ProjectOutcomeTimedOut || len(res.Steps) != 2 || !res.Steps[1].TimedOut || res.Steps[1].ExitCode != 124 {
		t.Fatalf("got %+v", res)
	}
	t.Logf("outcome %v: %s", res.Outcome, res.Detail)
}

// TestOpenShellLargePlanLive sends the largest plan a valid project can produce: 4 MiB
// of content that encoding/json escapes to six bytes a character.
func TestOpenShellLargePlanLive(t *testing.T) {
	p := liveProvider(t, nil)
	const mainJS = `const fs=require("fs"),c=require("crypto");const b=fs.readFileSync("blob.txt");fs.writeFileSync("out.txt",b.length+" "+c.createHash("sha256").update(b).digest("hex"));`
	blob := strings.Repeat("<", sandbox.MaxProjectBytes-len(mainJS))
	start := time.Now()
	res, err := p.RunProject(context.Background(), sandbox.ProjectRequest{
		Files:     []sandbox.File{{Path: "main.js", Content: mainJS}, {Path: "blob.txt", Content: blob}},
		Steps:     []string{"node main.js"},
		Artifacts: []string{"out.txt"},
		Timeout:   60 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	want := fmt.Sprintf("%d %x", len(blob), sha256.Sum256([]byte(blob)))
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Artifacts) != 1 || string(res.Artifacts[0].Content) != want {
		t.Fatalf("got outcome %v detail %q steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	t.Logf("a %d-byte project (a plan of about %d MiB) round-tripped in %v", sandbox.MaxProjectBytes, 6*len(blob)>>20, time.Since(start).Round(time.Millisecond))
}

// TestOpenShellReconcileLive leaves a sandbox untracked, as a lost create or a failed
// delete would, and requires ReconcileOrphans to delete it and nothing else.
func TestOpenShellReconcileLive(t *testing.T) {
	p := liveProvider(t, nil)
	ctx := context.Background()
	if _, err := p.checkDriver(ctx); err != nil {
		t.Fatal(err)
	}
	orphan, err := p.create(ctx)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	inflight, err := p.create(ctx)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	p.untrack(orphan.name)
	n, err := p.ReconcileOrphans(ctx)
	if err != nil || n != 1 {
		t.Fatalf("ReconcileOrphans = %d, %v; want 1", n, err)
	}
	gone := false
	for i := 0; i < 300 && !gone; i++ {
		_, err := p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: orphan.name}))
		gone = connect.CodeOf(err) == connect.CodeNotFound
		time.Sleep(100 * time.Millisecond)
	}
	if !gone {
		t.Fatalf("orphan %s still present", orphan.name)
	}
	if _, err := p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: inflight.name})); err != nil {
		t.Fatalf("the tracked sandbox was touched: %v", err)
	}
	p.deleteLater(inflight)
}

// TestOpenShellReconcileOtherInstanceLive: a sandbox another instance left behind (its
// process died, so nothing tracks or deletes it) is reaped by this one only once its
// declared lifetime plus the margin has passed, measured from the gateway's own
// creation time. The margin is shortened from five minutes to three seconds here.
func TestOpenShellReconcileOtherInstanceLive(t *testing.T) {
	crashed := liveProvider(t, nil)
	reaper := liveProvider(t, nil)
	reaper.staleAfter = 3 * time.Second
	// The reaper ages another instance's sandbox on the gateway's clock, which its own
	// creates measure; a reaper that has created nothing reaps nothing of another's.
	own, err := reaper.create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reaper.deleteLater(own)
	if _, known := reaper.gatewaySkew(); !known {
		t.Fatal("a create measured no clock skew")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	b, err := crashed.create(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	crashed.untrack(b.name)
	if n, err := reaper.ReconcileOrphans(context.Background()); err != nil || n != 0 {
		t.Fatalf("ReconcileOrphans within the declared lifetime = %d, %v; want nothing reaped", n, err)
	}
	time.Sleep(6 * time.Second) // past the 2 s lifetime plus the 3 s margin
	if n, err := reaper.ReconcileOrphans(context.Background()); err != nil || n != 1 {
		t.Fatalf("ReconcileOrphans after the lifetime = %d, %v; want the abandoned sandbox", n, err)
	}
	// The crashed instance's cleanup requires the gateway to list none of its
	// sandboxes, so wait for this one to be gone, not merely deleting.
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, err := reaper.client.GetSandbox(context.Background(), connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: b.name}))
		if connect.CodeOf(err) == connect.CodeNotFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %s still present 60 s after it was reaped (last error %v)", b.name, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Logf("another instance's sandbox %s: kept within its 2 s lifetime, reaped after it plus the margin", b.name)
}
