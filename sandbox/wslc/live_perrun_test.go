package wslc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
)

// The per-run mode's live tests, run by `make wslc-suite` with the others (live_test.go
// says how). Each session is a VM of about 0.9 GB of Windows memory, so the provider is
// capped at two.

// livePerRunProvider is a per-run provider from this process's environment, not yet started
// (no smoke test, so no startup sweep).
func livePerRunProvider(t *testing.T) *Provider {
	t.Helper()
	return livePerRunProviderFrom(t, perRunEnv)
}

// livePerRunProviderFrom is livePerRunProvider over the environment given.
func livePerRunProviderFrom(t *testing.T, getenv func(string) string) *Provider {
	t.Helper()
	if !liveRequested() {
		t.Skip("set WSLC_LIVE=1 (make wslc-suite) on a host with wslc.exe")
	}
	if os.Getenv("SANDBOX_WSLC_IMAGE") == "" {
		t.Fatal("WSLC_LIVE=1 needs SANDBOX_WSLC_IMAGE")
	}
	prov, err := FromEnv(getenv)
	if err != nil {
		t.Fatal(err)
	}
	return prov.Sandbox.(*Provider)
}

// perRunEnv is this process's environment with the per-run mode, two sessions at most, and
// the default tier (container): SANDBOX_WSLC_ACCEPT_VM_TIER is unset here whatever this
// process has, so an operator's own setting cannot change what these tests check.
func perRunEnv(k string) string {
	switch k {
	case "SANDBOX_WSLC_MODE":
		return "per-run"
	case "SANDBOX_WSLC_MAX_SESSIONS":
		return "2"
	case "SANDBOX_WSLC_ACCEPT_VM_TIER":
		return ""
	}
	return os.Getenv(k)
}

// acceptedEnv is perRunEnv with SANDBOX_WSLC_ACCEPT_VM_TIER=1: the operator accepts
// Microsoft's statement, and the per-run mode reports vm.
func acceptedEnv(k string) string {
	if k == "SANDBOX_WSLC_ACCEPT_VM_TIER" {
		return "1"
	}
	return perRunEnv(k)
}

// livePerRun is a per-run provider from this process's environment, its smoke test passed.
func livePerRun(t *testing.T) *Provider {
	t.Helper()
	return livePerRunReady(t, livePerRunProvider(t))
}

// livePerRunReady runs p's startup checks (Preflight and the smoke test) and returns it.
func livePerRunReady(t *testing.T, p *Provider) *Provider {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := p.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.SmokeTest(ctx); err != nil {
		t.Fatal(err)
	}
	return p
}

// liveLeft is every listed session with the provider's prefix and every entry of its run
// root but the template.
func liveLeft(t *testing.T, p *Provider) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	names, err := p.listSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, n := range names {
		if strings.HasPrefix(n, SessionPrefix) {
			left = append(left, "session "+n)
		}
	}
	entries, err := os.ReadDir(p.pr.root.linux)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != templateDirName {
			left = append(left, "dir "+e.Name())
		}
	}
	return left
}

// The per-run mode on the real WSLC: the smoke test's two sessions are two VMs (boot IDs
// that differ from each other, from the default session's and from this distribution's),
// a run reports the container tier (the operator has not set SANDBOX_WSLC_ACCEPT_VM_TIER=1)
// and runs the guest's code, and once the teardowns are done no session with the prefix is
// listed and no directory is left.
func TestLivePerRunSmokeAndRun(t *testing.T) {
	p := livePerRun(t)
	ev, ok := p.Evidence()
	if !ok || ev.Mode != ModePerRun || len(ev.RunSessions) != 2 || ev.VMTierAccepted {
		t.Fatalf("evidence: %+v", ev)
	}
	a, b := ev.RunSessions[0], ev.RunSessions[1]
	if a.BootID == b.BootID || a.BootID == ev.DefaultSessionBootID || a.BootID == ev.DistroBootID || b.BootID == ev.DefaultSessionBootID || b.BootID == ev.DistroBootID {
		t.Fatalf("boot IDs are not distinct: %+v", ev)
	}
	t.Logf("template %d bytes built in %v; session 1 %s boot %s result %v teardown %v; session 2 %s boot %s result %v teardown %v; gpu in VM %q, in container %q; Windows mounts %q",
		ev.TemplateBytes, ev.TemplateBuild, a.Name, a.BootID, a.Result, a.Teardown, b.Name, b.BootID, b.Result, b.Teardown, ev.GPUInSessionVM, ev.GPUInContainer, ev.SessionVMWindowsMounts)
	if p.IsolationClass() != sandbox.IsolationContainer || p.Qualification() != PerRunQualification {
		t.Fatalf("tier %v, qualification %q", p.IsolationClass(), p.Qualification())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	res, err := p.RunJavaScript(ctx, sandbox.Request{Code: "console.log('per-run ok ' + process.getuid())", MinimumIsolation: sandbox.IsolationContainer})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("a run took %v to its result", time.Since(start))
	if res.ExitCode != 0 || strings.TrimSpace(string(res.Stdout)) != "per-run ok 61000" || res.Isolation != sandbox.IsolationContainer {
		t.Fatalf("result: %+v", res)
	}
	// The record's environment names the image ID the run was started by: the ID image
	// inspect read at startup, and the only image the run's own VM store lists (the
	// template build refuses a store that lists any other), as a bill of materials
	// restates it (record version 5, finding cyclonedx-13's fourth measurement).
	if want := imageIdentity(ev.ImageID); res.EnvironmentIdentity != want || !providerkit.ValidDigest(ev.ImageID) {
		t.Fatalf("the run states environment %q, want %q", res.EnvironmentIdentity, want)
	}
	t.Logf("the run's environment %s is the image ID image inspect read; repository digests %v", res.EnvironmentIdentity, ev.RepoDigests)
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if left := liveLeft(t, p); len(left) != 0 {
		t.Fatalf("left after the teardowns: %v", left)
	}
}

// With SANDBOX_WSLC_ACCEPT_VM_TIER=1 on the real WSLC, the per-run mode reports vm with the
// accepted sentence, a vm floor runs, and the run's result states vm.
func TestLivePerRunAcceptedTierIsVM(t *testing.T) {
	p := livePerRunReady(t, livePerRunProviderFrom(t, acceptedEnv))
	ev, ok := p.Evidence()
	if !ok || !ev.VMTierAccepted {
		t.Fatalf("evidence: %+v", ev)
	}
	if p.IsolationClass() != sandbox.IsolationVM || p.Qualification() != PerRunAcceptedQualification {
		t.Fatalf("tier %v, qualification %q", p.IsolationClass(), p.Qualification())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := p.RunJavaScript(ctx, sandbox.Request{Code: "console.log('accepted ' + process.getuid())", MinimumIsolation: sandbox.IsolationVM})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("a vm-floor run with the setting: exit %d, stdout %q, tier %s", res.ExitCode, res.Stdout, res.Isolation)
	if res.ExitCode != 0 || strings.TrimSpace(string(res.Stdout)) != "accepted 61000" || res.Isolation != sandbox.IsolationVM {
		t.Fatalf("result: %+v", res)
	}
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if left := liveLeft(t, p); len(left) != 0 {
		t.Fatalf("left after the teardowns: %v", left)
	}
}

// On the real WSLC with the default configuration, a vm floor and a kernel floor are each
// refused before dispatch, for the isolation reason, on a snippet and on a project, and
// `wslc system session list` shows no session made for them.
func TestLivePerRunVMFloorRefused(t *testing.T) {
	p := livePerRun(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := p.listSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, floor := range []sandbox.IsolationClass{sandbox.IsolationVM, sandbox.IsolationKernel} {
		_, err := p.RunJavaScript(ctx, sandbox.Request{Code: "console.log('must not run')", MinimumIsolation: floor})
		reason, marked := sandbox.NotDispatchedReason(err)
		if !errors.Is(err, sandbox.ErrInsufficientIsolation) || !marked || reason != sandbox.RefusalIsolation {
			t.Fatalf("snippet at %s: %v (marked %v, reason %v)", floor, err, marked, reason)
		}
		t.Logf("snippet at %s refused: %v", floor, err)
		_, err = p.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"node -e 'console.log(1)'"}, MinimumIsolation: floor})
		reason, marked = sandbox.NotDispatchedReason(err)
		if !errors.Is(err, sandbox.ErrInsufficientIsolation) || !marked || reason != sandbox.RefusalIsolation {
			t.Fatalf("project at %s: %v (marked %v, reason %v)", floor, err, marked, reason)
		}
	}
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := p.listSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var made []string
	for _, n := range after {
		if !slices.Contains(before, n) {
			made = append(made, n)
		}
	}
	t.Logf("sessions listed before %q, after %q", before, after)
	if len(made) != 0 {
		t.Fatalf("refused runs made sessions: %q", made)
	}
	if left := liveLeft(t, p); len(left) != 0 {
		t.Fatalf("left: %v", left)
	}
}

// Live, the simulated half of the orphan check: plimsolld dies mid-run. Its teardown never runs
// (abandon) and the holder's Windows process is killed by hand, as measured on a real
// WSLC session (a killed holder leaves the session listed); a control shows the orphan is there. A new
// provider's startup then ends the session and deletes its directory. This proves the
// sweep removes an orphan of that exact shape. It does NOT prove what a dead daemon
// leaves behind: the daemon here is alive, and nothing closes the holder's pipe or
// orphans its interop process. TestLivePerRunRealKillLeavesNothingAfterRestart is that.
func TestLivePerRunKilledDaemonLeavesNothingAfterRestart(t *testing.T) {
	first := livePerRun(t)
	first.pr.mu.Lock()
	first.pr.abandon = true
	first.pr.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		_, err := first.RunJavaScript(ctx, sandbox.Request{Code: "setTimeout(() => {}, 20000)", Timeout: 30 * time.Second})
		done <- err
	}()
	// Wait for the run's holder, give its VM time to boot and the container to start, then
	// kill the holder as a dying daemon's process group would.
	var victim *holder
	deadline := time.Now().Add(60 * time.Second)
	for victim == nil && time.Now().Before(deadline) {
		first.pr.mu.Lock()
		for _, h := range first.pr.live {
			if h.cmd != nil && h.cmd.Process != nil {
				victim = h
			}
		}
		first.pr.mu.Unlock()
		time.Sleep(200 * time.Millisecond)
	}
	if victim == nil {
		t.Fatal("no run's holder appeared")
	}
	// fixed-wait: 5 s stands for "the run is under way in its own session" before its holder is killed; not shown safe on a slow host
	time.Sleep(5 * time.Second)
	if err := victim.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	victim.waitExited(15 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	names, err := first.listSessions(ctx)
	if err != nil || !slices.Contains(names, victim.name) {
		t.Fatalf("control: the killed holder's session %s is not listed (%v, %v): the check below would prove nothing", victim.name, names, err)
	}
	if _, err := os.Stat(victim.dir); err != nil {
		t.Fatalf("control: the orphan's directory: %v", err)
	}
	<-done // the run's own result is not what this test is about
	second := livePerRun(t)
	if left := liveLeft(t, second); len(left) != 0 {
		t.Fatalf("left after a restart: %v", left)
	}
	names, err = second.listSessions(ctx)
	if err != nil || slices.Contains(names, victim.name) {
		t.Fatalf("the orphan %s is still listed after the restart (%v, %v)", victim.name, names, err)
	}
}

// killHelperEnv makes this test binary act as the smallest real process that holds per-run
// sessions the way plimsolld does (TestMain runs killHelperMain instead of the tests).
const killHelperEnv = "PLIMSOLL_WSLC_KILL_HELPER"

// killHelperMain is that process: the provider plimsolld builds (FromEnv, in the per-run
// mode), its startup checks (Preflight and the smoke test, which sweep and build the
// template), and one run of a snippet that outlasts the test, started through the same
// RunJavaScript the RPC layer calls. It prints READY when startup is done, and MIDRUN with
// the run's session name and directory once the run's session is listed and its container
// exists in it, then waits to be killed.
func killHelperMain() int {
	prov, err := FromEnv(perRunEnv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		return 2
	}
	p := prov.Sandbox.(*Provider)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := p.Preflight(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		return 2
	}
	if err := p.SmokeTest(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		return 2
	}
	p.drain()
	fmt.Println("READY")
	go func() {
		_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "setTimeout(() => {}, 100000)", Timeout: 100 * time.Second})
		fmt.Fprintln(os.Stderr, "helper: the run ended on its own:", err)
	}()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		var h *holder
		p.pr.mu.Lock()
		for _, c := range p.pr.live {
			if c.cmd != nil && c.cmd.Process != nil {
				h = c
			}
		}
		p.pr.mu.Unlock()
		if h == nil {
			continue
		}
		qctx, qcancel := context.WithTimeout(ctx, 30*time.Second)
		out, err := p.output(qctx, "--session", h.name, "container", "list", "--all", "--quiet")
		qcancel()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			fmt.Printf("MIDRUN %s %s\n", h.name, h.dir)
			select {}
		}
	}
	fmt.Fprintln(os.Stderr, "helper: no run's container appeared within two minutes")
	return 3
}

// Live, the real half of the orphan check: a real process holding a per-run session is killed
// with SIGKILL while its run is in progress (the way an OOM kill or a crash ends plimsolld,
// the process alone, not its children), and a fresh provider's startup sweep then leaves no
// listed session with the provider's prefix and nothing in the run root but the template.
//
// What the helper is: this test binary started again as a process whose whole job is to be
// plimsolld's provider (killHelperMain: FromEnv, Preflight, SmokeTest, RunJavaScript), not
// the plimsolld binary itself, which would add an RPC client and nothing about sessions.
//
// What each check proves. The state read right after the kill is only logged: whether a
// dead parent leaves its session (the holder's pipe closes when the parent dies, which might
// end the session politely) is exactly what is not known, so it is observed, never
// assumed. The assertions after the restart are the finding's: the restart's own sweep
// (not the test) removed every session and directory, including the killed run's. The
// cleanup runs even when an assertion fails: it kills the helper if it is still alive and
// sweeps what it left.
func TestLivePerRunRealKillLeavesNothingAfterRestart(t *testing.T) {
	// The cleanup's provider is built before anything starts; it holds no session and, with
	// no smoke test, runs no startup sweep of its own.
	cleaner := livePerRunProvider(t)

	var helper *exec.Cmd
	var helperErr bytes.Buffer
	var helperMu sync.Mutex
	exited := make(chan struct{})
	t.Cleanup(func() {
		if helper != nil && helper.Process != nil {
			_ = helper.Process.Kill()
			<-exited
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := cleaner.resolveRoot(ctx); err != nil {
			t.Errorf("cleanup: %v", err)
			return
		}
		// Spares the template, ends every session with the prefix, deletes every directory
		// and archive of this provider's (nothing here is live).
		if _, err := cleaner.sweep(false); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	// The helper is the daemon before the restart: it takes the run root's lock, which ends
	// with it when it is killed. This process may hold that root from an earlier test.
	releaseRootLocks()
	helper = exec.Command(os.Args[0])
	helper.Env = append(os.Environ(), killHelperEnv+"=1")
	helper.Stderr = writerFunc(func(b []byte) (int, error) {
		helperMu.Lock()
		defer helperMu.Unlock()
		return helperErr.Write(b)
	})
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		_ = helper.Wait()
		close(exited)
		close(lines)
	}()
	helperLog := func() string {
		helperMu.Lock()
		defer helperMu.Unlock()
		return helperErr.String()
	}

	var session, dir string
	timeout := time.After(12 * time.Minute)
wait:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("the helper ended before its run began:\n%s", helperLog())
			}
			if fields := strings.Fields(line); len(fields) == 3 && fields[0] == "MIDRUN" {
				session, dir = fields[1], fields[2]
				break wait
			}
		case <-timeout:
			t.Fatalf("the helper's run never began:\n%s", helperLog())
		}
	}
	if !strings.HasPrefix(session, SessionPrefix) {
		t.Fatalf("the helper named a session %q without the provider's prefix", session)
	}
	if err := helper.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(30 * time.Second):
		t.Fatal("the helper did not die after SIGKILL")
	}

	// What the dead process left, observed and logged, not asserted.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := cleaner.resolveRoot(ctx); err != nil {
		t.Fatal(err)
	}
	names, err := cleaner.listSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, statErr := os.Stat(dir)
	t.Logf("after the kill, before the restart: session %s listed: %v; directory present: %v", session, slices.Contains(names, session), statErr == nil)

	// The restart: a fresh provider's startup (its smoke test sweeps).
	second := livePerRun(t)
	if left := liveLeft(t, second); len(left) != 0 {
		t.Fatalf("left after a restart: %v", left)
	}
	names, err = second.listSessions(ctx)
	if err != nil || slices.Contains(names, session) {
		t.Fatalf("the killed run's session %s is still listed after the restart (%v, %v)", session, names, err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the killed run's directory %s is still there after the restart (%v)", dir, err)
	}
	if err := second.Drain(ctx); err != nil {
		t.Fatal(err)
	}
}

// writerFunc is an io.Writer from a function.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
