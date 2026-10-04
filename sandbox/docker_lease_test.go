package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Every container the provider starts declares its lifetime, rounded up to the second.
func TestDockerRunContainersDeclareTheirLifetime(t *testing.T) {
	d := testDocker()
	at := time.Unix(1_000_000, 500_000_000)
	args := strings.Join(d.lockdownArgs("c", at, false, d.Runtime), " ")
	if !strings.Contains(args, "--label "+dockerExpiresLabel+"=1000001 ") {
		t.Fatalf("lockdown args %q do not declare the lifetime 1000001", args)
	}
	ctx, cancel := context.WithDeadline(context.Background(), at)
	defer cancel()
	if got := d.containerExpiry(ctx); !got.Equal(at) {
		t.Fatalf("expiry under a deadline %v; want %v", got, at)
	}
}

// A run's container that outlived its CLI and every removal attempt is reaped once
// its declared lifetime plus the margin has passed; one still inside it is not
// (review F2).
func TestDockerReconcileReapsAnExpiredRunContainer(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := d.RunJavaScript(ctx, Request{Code: `1`}); err != nil { // preflights
		t.Fatal(err)
	}
	start := func(name string, expires time.Time) {
		t.Helper()
		_ = exec.Command("docker", "rm", "-f", name).Run()
		if out, err := exec.Command("docker", "run", "-d", "--name", name, "--network", "none",
			"--label", dockerExpiresLabel+"="+strconv.FormatInt(expires.Unix(), 10),
			"--entrypoint", "sleep", d.Image, "600").CombinedOutput(); err != nil {
			t.Fatalf("docker run: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	}
	expired, live := "crsbx-lease-expired-"+randID(), "crsbx-lease-live-"+randID()
	start(expired, time.Now().Add(-dockerReapMargin-time.Minute))
	start(live, time.Now().Add(time.Minute))
	if _, err := d.ReconcileOrphans(ctx); err != nil {
		t.Fatal(err)
	}
	if exec.Command("docker", "inspect", expired).Run() == nil {
		t.Error("the expired run container is still there")
	}
	if exec.Command("docker", "inspect", live).Run() != nil {
		t.Error("a run container inside its lifetime was removed")
	}
}

// A run whose docker CLI dies while the run's context is still alive leaves no
// container behind (review F2): before, only a context's end removed it, and a
// container whose CLI failed ran on with nothing to stop it.
func TestDockerRunWhoseCLIDiesLeavesNoContainer(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := d.RunJavaScript(ctx, Request{Code: `setInterval(() => {}, 1000)`, Timeout: 90 * time.Second})
		done <- err
	}()
	var pid int
	var name string
	for deadline := time.Now().Add(30 * time.Second); name == ""; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no running docker run CLI of this test found")
		}
		pid, name = runCLIChild()
		if name != "" {
			out, _ := exec.Command("docker", "inspect", "--format", "{{.State.Running}}", name).Output()
			if strings.TrimSpace(string(out)) != "true" {
				name = "" // not started yet
			}
		}
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(dockerRemoveBudget + 10*time.Second):
		t.Fatal("the run did not return after its CLI died")
	}
	if ctx.Err() != nil {
		t.Fatal("the run's context ended; the test needs it alive to show the CLI's failure alone removes the container")
	}
	if exec.Command("docker", "inspect", name).Run() == nil {
		t.Fatalf("container %s outlived its CLI", name)
	}
}

// runCLIChild finds a docker run CLI this test process started for a run (not a
// smoke probe) and returns its PID and the container's name.
func runCLIChild() (int, string) {
	self := strconv.Itoa(os.Getpid())
	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	for _, stat := range stats {
		raw, err := os.ReadFile(stat)
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...: comm may hold spaces, so read after the last ')'.
		fields := strings.Fields(string(raw[bytes.LastIndexByte(raw, ')')+1:]))
		if len(fields) < 2 || fields[1] != self {
			continue
		}
		dir := filepath.Dir(stat)
		cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(string(cmdline), "\x00")
		for i, a := range args {
			if a == "--name" && i+1 < len(args) && strings.HasPrefix(args[i+1], "crsbx-") && !strings.HasPrefix(args[i+1], "crsbx-smoke") {
				pid, _ := strconv.Atoi(filepath.Base(dir))
				return pid, args[i+1]
			}
		}
	}
	return 0, ""
}

// Once the smoke test has proven the images, runs launch only those: an image a tag
// names afterwards is refused, not dispatched, reason environment, until it is proven
// (review F1). Before a smoke test has run there is no proof to keep.
func TestDockerRefusesAnImageTheSmokeTestDidNotProve(t *testing.T) {
	d := DefaultDocker("")
	d.ready, d.daemonHost, d.verifiedRuntime, d.verifiedGuestUID = true, "unix:///var/run/docker.sock", d.Runtime, d.guestUID()
	d.verifiedImageIDs = map[string]string{d.Image: "sha256:snippet", d.ProjectImage: "sha256:project"}
	if _, err := d.executionState(); err != nil {
		t.Fatalf("before any smoke test: %v", err)
	}
	d.provenImageIDs = map[string]string{d.Image: "sha256:snippet", d.ProjectImage: "sha256:project"}
	if _, err := d.executionState(); err != nil {
		t.Fatalf("the proven images: %v", err)
	}
	d.verifiedImageIDs[d.ProjectImage] = "sha256:rebuilt"
	_, err := d.executionState()
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment || !strings.Contains(err.Error(), "sha256:rebuilt") {
		t.Fatalf("a re-pointed project tag: %v; want not dispatched, environment, naming the new image", err)
	}
	if _, err := d.verifiedState(); err != nil {
		t.Fatalf("the verified state, which the smoke test and the reaper read: %v", err)
	}
}

// A tag re-pointed after the smoke test is refused by runs and by Preflight, so by
// readiness, until a smoke test proves the new content (review F1). Before, a rebuilt
// tag was launched within Preflight's 5 s cache, its lockdown and runner guard unproven.
func TestDockerRepointedTagIsRefusedUntilProven(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	tag := "plimsoll-test/proof:" + randID()
	retag := func(src string) {
		t.Helper()
		if out, err := exec.Command("docker", "tag", src, tag).CombinedOutput(); err != nil {
			t.Fatalf("docker tag %s: %v: %s", src, err, out)
		}
	}
	retag(d.Image)
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", tag).Run() })
	d.Image = tag
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := d.SmokeTest(ctx); err != nil {
		t.Fatal(err)
	}
	if res, err := d.RunJavaScript(ctx, Request{Code: `console.log("proven")`}); err != nil || strings.TrimSpace(res.Stdout) != "proven" {
		t.Fatalf("a run on the proven image: %+v, %v", res, err)
	}
	retag(d.ProjectImage) // someone rebuilds the tag
	d.stateMu.Lock()
	d.lastVerified = time.Time{} // past Preflight's 5 s cache
	d.stateMu.Unlock()
	_, err := d.RunJavaScript(ctx, Request{Code: `console.log("unproven")`})
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment {
		t.Fatalf("a run on the re-pointed tag: %v; want not dispatched, environment", err)
	}
	if err := d.Preflight(ctx); err == nil {
		t.Fatal("Preflight, which readiness runs, passed with an unproven image")
	}
	if err := d.SmokeTest(ctx); err != nil {
		t.Fatalf("proving the new content: %v", err)
	}
	if err := d.Preflight(ctx); err != nil {
		t.Fatalf("Preflight once the new content is proven: %v", err)
	}
}
