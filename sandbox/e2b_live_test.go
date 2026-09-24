package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests hit the real E2B API and only run when E2B_API_KEY is set.
func e2bClient(t *testing.T) *E2B {
	t.Helper()
	key := os.Getenv("E2B_API_KEY")
	if key == "" {
		t.Skip("E2B_API_KEY not set")
	}
	return &E2B{APIKey: key, DefaultTimeout: 60 * time.Second, MaxTimeout: 90 * time.Second}
}

func TestE2BRunJavaScriptLive(t *testing.T) {
	e := e2bClient(t)
	res, err := e.RunJavaScript(context.Background(), Request{Code: `console.log("e2b", 6*7)`})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "e2b 42") {
		t.Fatalf("got exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	t.Logf("ok in %v: %q", res.Duration, strings.TrimSpace(res.Stdout))
}

func TestE2BRunProjectLive(t *testing.T) {
	e := e2bClient(t)
	res, err := e.RunProject(context.Background(), ProjectRequest{
		Files: []File{
			{Path: "util.mjs", Content: "export const add = (a, b) => a + b;\n"},
			{Path: "main.mjs", Content: "import { add } from './util.mjs';\nconsole.log('sum', add(2, 3));\n"},
		},
		Steps: []string{"node main.mjs"},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("outcome = %s (%s), want completed", res.Outcome, res.Detail)
	}
	if len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 || !strings.Contains(res.Steps[0].Stdout, "sum 5") {
		t.Fatalf("got %+v", res.Steps)
	}
	t.Logf("ok: %q", strings.TrimSpace(res.Steps[0].Stdout))
}

// TestE2BSecuredAccessLive proves secured access is actually in force: the same
// envd endpoint that serves an authenticated request must REJECT one without the
// per-sandbox access token. Without this, anyone who learns a sandbox ID during
// its lifetime could drive its data plane over the public envd URL.
func TestE2BSecuredAccessLive(t *testing.T) {
	e := e2bClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	vm, err := e.create(ctx, 60*time.Second)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer e.kill(vm.id)
	if vm.accessToken == "" {
		t.Fatal("secure create returned no envd access token")
	}
	if vm.trafficAccessToken == "" {
		t.Fatal("restricted-public-traffic create returned no traffic token")
	}

	// Authenticated write works.
	if err := e.writeFile(ctx, vm, "/home/user/probe.txt", "ok"); err != nil {
		t.Fatalf("authenticated writeFile: %v", err)
	}
	// The same call with no token must be rejected.
	if err := e.writeFile(ctx, e2bVM{id: vm.id, trafficAccessToken: vm.trafficAccessToken}, "/home/user/anon.txt", "nope"); err == nil {
		t.Fatal("unauthenticated envd request succeeded — secured access is NOT in force")
	} else {
		t.Logf("unauthenticated envd request rejected as expected: %v", err)
	}
}

// TestE2BEgressDeniedLive proves the deny-all egress rule is actually in force
// inside the microVM: outbound connections to both a raw IP and a DNS name must
// fail. Unit tests only assert the create request carries denyOut; this asserts
// the live network actually drops the traffic.
func TestE2BEgressDeniedLive(t *testing.T) {
	e := e2bClient(t)
	res, err := e.RunJavaScript(context.Background(), Request{Code: `
(async () => {
  let open = false;
  for (const target of ["https://1.1.1.1", "https://example.com"]) {
    try {
      await fetch(target, { signal: AbortSignal.timeout(5000) });
      console.log("EGRESS-OPEN", target);
      open = true;
    } catch (err) {
      console.log("EGRESS-BLOCKED", target, err.cause?.code || err.code || err.name);
    }
  }
  process.exit(open ? 0 : 42);
})();
`})
	if err != nil {
		t.Fatalf("infrastructure error: %v", err)
	}
	if strings.Contains(res.Stdout, "EGRESS-OPEN") || res.ExitCode != 42 {
		t.Fatalf("egress is NOT denied: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	t.Logf("egress denied as expected: %q", strings.TrimSpace(res.Stdout))
}

// TestE2BOverCapRejectedLive proves verifyResources rejects a live microVM whose
// template allocation exceeds the requested per-run maximum (no real template has
// a 1 MiB allocation). The run must fail before any code executes; the deferred
// kill reaps the oversized VM.
func TestE2BOverCapRejectedLive(t *testing.T) {
	e := e2bClient(t)
	e.MaxMemoryMB = 1
	_, err := e.RunJavaScript(context.Background(), Request{Code: `console.log("must not run")`})
	if err == nil {
		t.Fatal("run succeeded despite a 1 MiB memory cap — over-cap rejection is NOT in force")
	}
	if !strings.Contains(err.Error(), "exceeds memory cap") {
		t.Fatalf("expected an over-cap rejection, got: %v", err)
	}
	t.Logf("over-cap VM rejected as expected: %v", err)
}

// TestE2BResourceMetadataLive proves the live control plane populates the
// memoryMB/cpuCount/diskSizeMB fields verifyResources depends on. With all three
// caps set generously, a successful run means none of the fields were zero or
// missing (a missing diskSizeMB fails closed with an explicit error).
func TestE2BResourceMetadataLive(t *testing.T) {
	e := e2bClient(t)
	e.MaxMemoryMB = 1 << 16
	e.MaxVCPU = 128
	e.MaxDiskMB = 1 << 20
	res, err := e.RunJavaScript(context.Background(), Request{Code: `console.log("metadata ok")`})
	if err != nil {
		t.Fatalf("run with generous caps failed — control plane resource metadata is missing or zero: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "metadata ok") {
		t.Fatalf("got exit=%d stdout=%q", res.ExitCode, res.Stdout)
	}
	t.Log("live control plane reports memoryMB, cpuCount, and diskSizeMB")
}

func TestE2BRunProjectArtifactsLive(t *testing.T) {
	e := e2bClient(t)
	res, err := e.RunProject(context.Background(), ProjectRequest{
		Files:     []File{{Path: "gen.mjs", Content: "import {writeFileSync} from 'node:fs';\nwriteFileSync('out.txt','e2b-artifact');\n"}},
		Steps:     []string{"node gen.mjs"},
		Artifacts: []string{"out.txt", "missing.txt"},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("outcome = %s (%s), want completed", res.Outcome, res.Detail)
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Path != "out.txt" || string(res.Artifacts[0].Content) != "e2b-artifact" {
		t.Fatalf("artifacts = %+v, want one out.txt='e2b-artifact'", res.Artifacts)
	}
	t.Logf("ok: captured %s = %q", res.Artifacts[0].Path, res.Artifacts[0].Content)
}

// TestE2BSmokeLive proves the startup template smoke passes against the real
// control plane and the default template: secured create, multipart staging,
// a probe run through the project-step path (sh → node), verified cwd, and
// live-denied egress. This is exactly what the daemon runs at startup, so a
// pass here means EnsureReady would admit this configuration.
func TestE2BSmokeLive(t *testing.T) {
	e := e2bClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := e.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	t.Log("template smoke passed: toolchain present, step cwd honored, egress denied")
}

// TestE2BOrphanListingLive verifies the reconciliation contract against the real
// control plane: a created sandbox is discoverable by this instance's metadata
// stamp via GET /sandboxes, a tracked/young sandbox is never reaped, and after
// untracking it is exactly the reconciler's candidate set (the kill decision
// itself is unit-tested; the 60s create grace makes killing here too slow).
func TestE2BOrphanListingLive(t *testing.T) {
	e := e2bClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	vm, err := e.create(ctx, 60*time.Second)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer e.kill(vm.id)

	listed, err := e.listInstanceSandboxes(ctx)
	if err != nil {
		t.Fatalf("list by instance stamp: %v", err)
	}
	found := false
	for _, sb := range listed {
		if sb.id == vm.id {
			found = true
			if sb.startedAt.IsZero() {
				t.Error("live listing has no parseable startedAt; the reconciler grace would never let this be reaped")
			}
		}
	}
	if !found {
		t.Fatalf("created sandbox %s not returned by the instance-stamped listing: %+v", vm.id, listed)
	}

	// Tracked: reconciliation must not touch it.
	if n, err := e.ReconcileOrphans(ctx); err != nil || n != 0 {
		t.Fatalf("reconcile with a tracked live sandbox: killed=%d err=%v, want 0/nil", n, err)
	}
	// Untracked but younger than the grace window: still spared.
	e.untrackVM(vm.id)
	if n, err := e.ReconcileOrphans(ctx); err != nil || n != 0 {
		t.Fatalf("reconcile inside the grace window: killed=%d err=%v, want 0/nil", n, err)
	}
	e.trackVM(vm.id) // restore so the deferred kill's untrack stays consistent
	t.Logf("ok: sandbox %s discoverable by instance stamp and correctly spared", vm.id)
}

// TestE2BRunProjectMultiStepLive runs a project of three steps, each reading what
// the one before wrote. Until 2026-09-24 every step was staged at one script path
// and envd refused to reopen it, so every project of more than one step failed
// with "could not stage step"; the one-step tests above never saw it.
func TestE2BRunProjectMultiStepLive(t *testing.T) {
	e := e2bClient(t)
	res, err := e.RunProject(context.Background(), ProjectRequest{
		Files: []File{{Path: "seed.txt", Content: "1\n"}},
		Steps: []string{"echo 2 >> seed.txt", "echo 3 >> seed.txt", "cat seed.txt"},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 3 || res.Steps[2].Stdout != "1\n2\n3\n" {
		t.Fatalf("outcome=%s steps=%+v", res.Outcome, res.Steps)
	}
}
