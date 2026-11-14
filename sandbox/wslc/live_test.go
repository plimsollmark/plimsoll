package wslc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The live suite runs against a real wslc.exe on a Windows host with WSL 3.0.5 or later,
// from a WSL distribution, by hand: `make wslc-suite`, which sets WSLC_LIVE=1
// and fails on any skipped test. Configuration: SANDBOX_WSLC_IMAGE (the sandbox image,
// already loaded into the session with `wslc image load` or pulled), and SANDBOX_WSLC_PATH
// when wslc.exe is not at DefaultPath. It spends nothing: WSLC runs on the machine itself.

func liveRequested() bool { return os.Getenv("WSLC_LIVE") == "1" }

// sharedEnv is this process's environment with the shared mode chosen explicitly: the
// default mode is per-run, and these tests mean the shared one.
func sharedEnv(k string) string {
	if k == "SANDBOX_WSLC_MODE" {
		return "shared"
	}
	return os.Getenv(k)
}

// liveProvider is the shared-mode provider from this process's environment with its startup checks
// passed; without WSLC_LIVE=1 the test is skipped, and with it a missing configuration
// fails.
func liveProvider(t *testing.T) *Provider {
	t.Helper()
	if !liveRequested() {
		t.Skip("set WSLC_LIVE=1 (make wslc-suite) on a host with wslc.exe")
	}
	if os.Getenv("SANDBOX_WSLC_IMAGE") == "" {
		t.Fatal("WSLC_LIVE=1 needs SANDBOX_WSLC_IMAGE")
	}
	prov, err := FromEnv(sharedEnv)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := prov.EnsureReady(ctx); err != nil {
		t.Fatal(err)
	}
	return prov.Sandbox.(*Provider)
}

func TestLiveSmokeTestEvidence(t *testing.T) {
	p := liveProvider(t)
	ev, ok := p.Evidence()
	if !ok {
		t.Fatal("no evidence after EnsureReady")
	}
	t.Logf("wsl %s, kernel %s, %s, seccomp %s (%s filters), no_new_privs %s, pids.max %s, nproc %d, session %s boot %s, walked %d entries (%d unlistable), image %s %v",
		ev.WSLVersion, ev.KernelRelease, ev.Moby, ev.Seccomp, ev.SeccompFilters, ev.NoNewPrivs, ev.PidsMax, ev.NprocLimit, ev.Session, ev.BootID,
		ev.WalkedEntries, ev.Unlistable, ev.ImageID, ev.RepoDigests)
	// Which default session the shared mode lands in depends on the
	// caller's elevation, so the evidence must name it.
	if !strings.HasPrefix(ev.Session, "wslc-cli-") {
		t.Errorf("the evidence does not name the session the smoke test landed in: %q", ev.Session)
	}
}

// No variable of this process reaches a step, a canary and a WSLENV asking interop to
// translate it included. WSLENV names the canary with no flag, the
// form that crosses into a Windows process ("/u" is "only included when running WSL from
// Win32", learn.microsoft.com/en-us/windows/wsl/filesystems, so a "/u" canary never reaches
// wslc.exe and its absence proves nothing). The control first shows that, with this
// process's environment, interop does hand the canary to a Windows process.
func TestLiveEnvironmentCanary(t *testing.T) {
	// The control below starts cmd.exe through interop, so the skip comes first: an ordinary
	// test run must not touch Windows (under load the interop call timed out and failed
	// `make audit`, 2026-11-13).
	if !liveRequested() {
		t.Skip("set WSLC_LIVE=1 (make wslc-suite) on a host with wslc.exe")
	}
	t.Setenv("PLIMSOLL_LIVE_CANARY", "canary-4e1d")
	t.Setenv("WSLENV", "PLIMSOLL_LIVE_CANARY:PATH/l")
	ctl := exec.Command("/mnt/c/Windows/System32/cmd.exe", "/d", "/c", "set", "PLIMSOLL_LIVE_CANARY")
	ctl.Dir = "/mnt/c"
	if b, err := ctl.CombinedOutput(); err != nil || !strings.Contains(string(b), "canary-4e1d") {
		t.Fatalf("control: interop did not hand the canary to cmd.exe (err %v, output %q); the check below would prove nothing", err, b)
	}
	p := liveProvider(t)
	res, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"env"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 {
		t.Fatalf("result: %+v", res)
	}
	out := res.Steps[0].Stdout + res.Steps[0].Stderr
	if strings.Contains(out, "canary-4e1d") || strings.Contains(out, "WSLENV") {
		t.Fatalf("a variable of plimsolld's reached the container:\n%s", out)
	}
	t.Logf("a step's environment:\n%s", out)

	// The environment the container starts with, which the runner's `env -i` hides from
	// every step but which the dynamic loader of plimsoll's first process reads: the
	// provider's own argv, cut at the image so /usr/bin/env gets no arguments and prints
	// it. --env is the control: a check that cannot print a variable proves nothing by not
	// printing the canary.
	ev, _ := p.Evidence()
	argv := p.runArgv(containerName(), ev.ImageID)
	at := slices.Index(argv, ev.ImageID)
	if at < 0 {
		t.Fatalf("image ID %q not in the run argv", ev.ImageID)
	}
	argv = append(slices.Clone(argv[:at]), "--env", "PLIMSOLL_LIVE_POSITIVE=positive-9b2c", ev.ImageID)
	b, err := hostCommand(context.Background(), p.cfg.Path, argv...).Output()
	first := string(b)
	if err != nil || !strings.Contains(first, "PATH=") || !strings.Contains(first, "PLIMSOLL_LIVE_POSITIVE=positive-9b2c") {
		t.Fatalf("control: the variable passed with --env was not printed (err %v):\n%s", err, first)
	}
	if strings.Contains(first, "canary-4e1d") || strings.Contains(first, "WSLENV") {
		t.Fatalf("a variable of plimsolld's reached the container's first process:\n%s", first)
	}
	t.Logf("the environment the container starts with:\n%s", first)
}

// Bytes cross interop unchanged both ways: a file sent in the plan on stdin hashes the
// same inside, and an artifact of random bytes comes back with the hash the container
// printed.
func TestLiveBytesCrossInteropUnchanged(t *testing.T) {
	p := liveProvider(t)
	raw := make([]byte, 384<<10)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	content := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(content))
	res, err := p.RunProject(context.Background(), sandbox.ProjectRequest{
		Files:     []sandbox.File{{Path: "in.txt", Content: content}},
		Steps:     []string{"sha256sum in.txt", `node -e 'const c=require("crypto"),b=c.randomBytes(1<<20);require("fs").writeFileSync("out.bin",b);console.log(c.createHash("sha256").update(b).digest("hex"))'`},
		Artifacts: []string{"out.bin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 2 || len(res.Artifacts) != 1 {
		t.Fatalf("result: %+v", res)
	}
	if got := strings.Fields(res.Steps[0].Stdout); len(got) == 0 || got[0] != hex.EncodeToString(sum[:]) {
		t.Fatalf("the file's hash inside is %q, want %x", res.Steps[0].Stdout, sum)
	}
	back := sha256.Sum256(res.Artifacts[0].Content)
	if strings.TrimSpace(res.Steps[1].Stdout) != hex.EncodeToString(back[:]) {
		t.Fatalf("the artifact came back changed: inside %q, here %x", res.Steps[1].Stdout, back)
	}
}

// A snippet that never ends is stopped by its budget.
func TestLiveTimeout(t *testing.T) {
	p := liveProvider(t)
	start := time.Now()
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "for(;;);", Timeout: 2 * time.Second})
	if err != nil || !res.TimedOut {
		t.Fatalf("a snippet that never ends: %+v, %v", res, err)
	}
	t.Logf("stopped after %v", time.Since(start))
}
