package sandbox

import (
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A docker session's process 1 (finding guest-guard-10, decision 10 B): the guest guard in its
// process-1 mode (program/guard.c, "--pid1"), in place of docker's --init. It puts its filter on
// itself, starts the main process as its child, collects every process that ends in the
// container, passes no signal on, and ends the container when the main process ends or on a
// signal recorded as from outside it (docker stop's). Code of the session can still end or stall
// its own session through process 1 (findings guest-guard-34 to 36, in the guard's header
// comment); no test here says otherwise. Each test here runs under docker's ordinary runtime with
// the profile SANDBOX_DOCKER_SECCOMP names and under gVisor (SANDBOX_DOCKER_RUNTIME=runsc).

// pid1Session opens a session of the docker provider the suite selects, with image as its
// project image ("" for the default), closed when the test ends.
func pid1Session(t *testing.T, image string) (*DockerSandbox, Session, context.Context) {
	t.Helper()
	d := testDocker()
	if image != "" {
		d.ProjectImage = image
	}
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	if err := d.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 3 * time.Minute, DiskBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	// Close and wait for the removal: run alone, a test binary that ended right after Close left
	// its container behind (2026-11-20).
	t.Cleanup(func() {
		_ = s.Close(context.Background())
		select {
		case <-s.Done():
		case <-time.After(DockerRemoveBudget + 5*time.Second):
			t.Errorf("session %s was not removed within the removal budget", s.(*dockerSession).name)
		}
	})
	return d, s, ctx
}

// processOneJS prints process 1's command line and Seccomp line as the session's code reads them.
const processOneJS = `const fs = require("fs");
const cmd = fs.readFileSync("/proc/1/cmdline", "latin1").split("\0").filter(Boolean);
const m = /^Seccomp:\s*(\S+)/m.exec(fs.readFileSync("/proc/1/status", "latin1"));
console.log(JSON.stringify({cmd, seccomp: m ? m[1] : "none"}));`

// TestDockerSessionProcessOneIsTheGuard: process 1 of a session is the guest guard in its
// process-1 mode, and under gVisor its Seccomp line reads 2, a filter in force (gVisor applies
// no host profile, so a 2 there is the guard's own filter; with docker's --init it read 0).
// Under docker's ordinary runtime the Seccomp line reads 2 with or without the guard (the host
// profile), so there only the command line tells the guard from docker's init.
func TestDockerSessionProcessOneIsTheGuard(t *testing.T) {
	t.Parallel()
	d, s, ctx := pid1Session(t, "")
	r, err := s.RunJavaScript(ctx, Request{Code: processOneJS, Timeout: 30 * time.Second})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("reading process 1: %+v, %v", r, err)
	}
	var got struct {
		Cmd     []string `json:"cmd"`
		Seccomp string   `json:"seccomp"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.Stdout)), &got); err != nil {
		t.Fatalf("process 1's lines: %q: %v", r.Stdout, err)
	}
	t.Logf("runtime %q: process 1 is %q, Seccomp %s", d.Runtime, got.Cmd, got.Seccomp)
	want, err := dockerSessionMain("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Cmd) < 3+len(want) || got.Cmd[0] != guestGuardTarget || got.Cmd[1] != guestGuardPID1 || got.Cmd[2] != "--" || got.Cmd[3] != want[0] {
		t.Errorf("process 1 of the session is %q; want %s %s -- %s ...", got.Cmd, guestGuardTarget, guestGuardPID1, want[0])
	}
	if d.Runtime == "runsc" && got.Seccomp != "2" {
		t.Errorf("under gVisor process 1's Seccomp line reads %q; want 2, the guard's filter", got.Seccomp)
	}
	// Finding guest-guard-39: docker took the run's --init=false and recorded Init as false, not
	// unset, so the daemon's own init setting, which applies only while Init is unset (moby's
	// daemon/oci_linux.go, withCommonOptions), cannot put docker's init in as process 1.
	insp, err := s.(*dockerSession).inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if insp.hostConfig.Init == nil || *insp.hostConfig.Init {
		t.Errorf("the session's container has HostConfig.Init %v; want false, written by the run's %s", insp.hostConfig.Init, dockerNoInit)
	}
}

// TestDockerSessionRefusesAnotherProcessOne (finding guest-guard-38): a session whose process 1
// is not the guard in its process-1 mode exactly as plimsoll started it is refused at open, by
// the open's comparison of process 1's command line (recordBaseline's call of processOneIs).
// guardFirstSeam hands the session's main process /usr/bin/./env in place of /usr/bin/env: the
// same program, so the container starts and the main process writes its marker, but process 1's
// command line differs by two bytes from the one plimsoll wrote, as docker's init, an image's own
// first program or any other would. Not parallel: the seam is the package's one. The refusal
// leaves no container, and the next open works.
func TestDockerSessionRefusesAnotherProcessOne(t *testing.T) {
	d := testDocker()
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	var fired atomic.Bool
	seam := func(argv []string) string {
		if len(argv) > 0 && argv[0] == "/usr/bin/env" && slices.ContainsFunc(argv, func(a string) bool { return strings.HasPrefix(a, "plimsoll-session-main:") }) && fired.CompareAndSwap(false, true) {
			return "/usr/bin/./env"
		}
		return ""
	}
	guardFirstSeam.Store(&seam)
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 2 * time.Minute})
	guardFirstSeam.Store(nil)
	if err == nil {
		// Wait for the removal: a test binary that ends right after Close leaves the container.
		_ = s.Close(context.Background())
		select {
		case <-s.Done():
		// fixed-wait: a limit on waiting for the removal before the failure below; the test fails either way
		case <-time.After(DockerRemoveBudget + 5*time.Second):
		}
		t.Fatal("a session whose process 1 is not the guard as plimsoll started it opened")
	}
	if !fired.Load() {
		t.Fatal("no command carried the main process's marker behind /usr/bin/env, so process 1 was never changed")
	}
	if !strings.Contains(err.Error(), "not the guest guard as plimsoll started it") {
		t.Fatalf("the open: %v; want the refusal of process 1's command line", err)
	}
	out, lerr := exec.Command("docker", "ps", "-a", "-q", "--filter", "label="+dockerInstanceLabel+"="+d.instance()).Output()
	if lerr != nil {
		t.Fatal(lerr)
	}
	if left := strings.TrimSpace(string(out)); left != "" {
		t.Fatalf("the refused open left containers behind: %s", left)
	}
	s, err = d.OpenSession(ctx, SessionOptions{Lifetime: 2 * time.Minute})
	if err != nil {
		t.Fatalf("an open after it: %v", err)
	}
	defer func() {
		_ = s.Close(context.Background())
		select {
		case <-s.Done():
		case <-time.After(DockerRemoveBudget + 5*time.Second):
			t.Errorf("the next session was not removed within the removal budget")
		}
	}()
	r, err := s.RunJavaScript(ctx, Request{Code: `console.log("ran")`, Timeout: 20 * time.Second})
	if err != nil || strings.TrimSpace(r.Stdout) != "ran" {
		t.Fatalf("a call in the next session: %q, %v", r.Stdout, err)
	}
}

// orphansJS makes 300 short-lived orphans one after another (each a sleep whose parent, a
// subshell, has already exited, so it is handed to process 1), then waits for every one of them
// to end and counts the zombies process 1 still holds. 300 is past the session's process limit
// (256): a process 1 that did not collect them would leave the loop unable to start more.
const orphansJS = `const fs = require("fs");
const {spawnSync} = require("child_process");
const r = spawnSync("/bin/sh", ["-c", "i=0; while [ $i -lt 300 ]; do (sleep 0.01 &) || exit 7; i=$((i+1)); done"], {encoding: "utf8"});
function left() {
  let zombies = 0, alive = 0;
  for (const p of fs.readdirSync("/proc")) {
    if (!/^[0-9]+$/.test(p)) continue;
    let s; try { s = fs.readFileSync("/proc/" + p + "/stat", "latin1"); } catch { continue; }
    const f = s.slice(s.lastIndexOf(")") + 2).split(" ");
    if (f[1] !== "1") continue;
    if (f[0] === "Z") zombies++; else if (s.includes("(sleep)")) alive++;
  }
  return {zombies, alive};
}
const deadline = Date.now() + 5000;
(function wait() {
  const n = left();
  if ((n.zombies === 0 && n.alive <= 1) || Date.now() > deadline) {
    console.log(JSON.stringify({status: r.status, stderr: r.stderr, zombies: n.zombies, alive: n.alive}));
    return;
  }
  setTimeout(wait, 100);
})();`

// TestDockerSessionCollectsOrphans: process 1 collects every orphan that ends, promptly, and the
// session goes on working (its sweep and the next call) after 300 of them.
func TestDockerSessionCollectsOrphans(t *testing.T) {
	t.Parallel()
	_, s, ctx := pid1Session(t, "")
	r, err := s.RunJavaScript(ctx, Request{Code: orphansJS, Timeout: time.Minute})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("the orphans call: %+v, %v", r, err)
	}
	var got struct {
		Status  *int   `json:"status"`
		Stderr  string `json:"stderr"`
		Zombies int    `json:"zombies"`
		Alive   int    `json:"alive"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.Stdout)), &got); err != nil {
		t.Fatalf("the orphans call printed %q: %v", r.Stdout, err)
	}
	status := "none (ended by a signal)"
	if got.Status != nil {
		status = strconv.Itoa(*got.Status)
	}
	t.Logf("after 300 orphans: loop status %s, %d zombies of process 1 left, %d still running", status, got.Zombies, got.Alive)
	if got.Status == nil || *got.Status != 0 {
		t.Errorf("the loop that makes 300 orphans ended %s (%q); want 0, every one started", status, got.Stderr)
	}
	if got.Zombies != 0 {
		t.Errorf("%d zombies of process 1 left after the orphans ended; want none", got.Zombies)
	}
	if r, err := s.RunJavaScript(ctx, Request{Code: `console.log("next")`}); err != nil || strings.TrimSpace(r.Stdout) != "next" || s.Err() != nil {
		t.Fatalf("the call after the orphans: %+v, %v, %v; want the session open", r, err, s.Err())
	}
}

// forgedSignalsPy sends process 1 a SIGTERM through rt_sigqueueinfo with a sender of its own
// making: no sender (si_pid 0), which is what a signal from outside the container carries, with
// the code of kill (SI_USER, 0), of the kernel (SI_KERNEL, 0x80) and of sigqueue (SI_QUEUE, -1).
// The kernel lets a process send another only a negative code that way, so the first two must be
// refused and the third, though delivered, is not a code process 1 acts on. It prints one line
// per code: the code, the call's result and errno.
const forgedSignalsPy = `import ctypes, signal
libc = ctypes.CDLL(None, use_errno=True)
for code in (0, 0x80, -1):
    info = (ctypes.c_int * 32)()
    info[0], info[1], info[2] = signal.SIGTERM, 0, code
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(NR), ctypes.c_long(1), ctypes.c_long(signal.SIGTERM), info)
    print(code, r, ctypes.get_errno(), flush=True)
`

// TestDockerSessionPassesOnNoKillFromInside: SIGTERM, SIGINT, SIGHUP and SIGUSR1 that code of
// the session sends process 1 with kill, and a SIGTERM it queues with a made-up sender of "none"
// and sigqueue's code, end nothing: process 1 passes none of them on, so the session stays open.
// A made-up sender of "none" with kill's or the kernel's code, the record of a signal from
// outside, is refused by the kernel itself, under both runtimes. (With docker's --init, the same
// SIGTERM from inside ended the session: docker's init passed it on to the main process.) It
// shows no more than that: other signals code of the session can cause or send end or stop
// process 1 (findings guest-guard-34 and 35).
func TestDockerSessionPassesOnNoKillFromInside(t *testing.T) {
	t.Parallel()
	_, s, ctx := pid1Session(t, pythonProjectImage)
	r, err := s.RunJavaScript(ctx, Request{Code: `for (const sig of ["SIGTERM", "SIGINT", "SIGHUP", "SIGUSR1"]) { try { process.kill(1, sig); } catch (e) { console.log(sig, e.code); } }
setTimeout(() => console.log("sent"), 500);`, Timeout: 30 * time.Second})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("the signalling call: %+v, %v", r, err)
	}
	t.Logf("the signalling call printed %q", r.Stdout)
	nr := map[string]int{"amd64": 129, "arm64": 138}[runtime.GOARCH]
	r, err = s.RunJavaScript(ctx, Request{Code: pythonFromNode(strings.Replace(forgedSignalsPy, "NR", strconv.Itoa(nr), 1)), Timeout: 30 * time.Second})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("the forged signals: %+v, %v", r, err)
	}
	t.Logf("the forged signals (code, result, errno): %q", r.Stdout)
	if want := "0 -1 1\n128 -1 1\n-1 0 0\n"; r.Stdout != want {
		t.Errorf("rt_sigqueueinfo to process 1 answered %q; want %q: the codes of kill and of the kernel refused (EPERM), sigqueue's delivered", r.Stdout, want)
	}
	// fixed-wait: 500 ms for a signal's effect on process 1 to show before the next call proves the session is open; nothing can signal that a thing did not happen, so this is a bounded look: a late one would be missed, and a slow machine cannot fail it
	time.Sleep(500 * time.Millisecond)
	if r, err := s.RunJavaScript(ctx, Request{Code: `console.log("next")`}); err != nil || strings.TrimSpace(r.Stdout) != "next" || s.Err() != nil {
		t.Fatalf("the call after signalling process 1 from inside: %+v, %v, %v; want the session open", r, err, s.Err())
	}
}

// TestDockerSessionCloseTime: closing a session ends its container as fast as before (docker
// rm -f, measured to Done), and a docker stop, which sends the stop signal and waits up to its
// timeout before killing, ends it on the signal, well within that wait, when no code in it keeps
// sending process 1 a SIGTERM of its own (finding guest-guard-36). Both times are logged.
func TestDockerSessionCloseTime(t *testing.T) {
	t.Parallel()
	_, s, ctx := pid1Session(t, "")
	if _, err := s.RunJavaScript(ctx, Request{Code: `console.log(1)`}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(DockerRemoveBudget + 5*time.Second):
		t.Fatal("Done was not closed within the removal budget")
	}
	closed := time.Since(start)

	_, s2, ctx2 := pid1Session(t, "")
	if _, err := s2.RunJavaScript(ctx2, Request{Code: `console.log(1)`}); err != nil {
		t.Fatal(err)
	}
	name := s2.(*dockerSession).name
	start = time.Now()
	out, err := exec.Command("docker", "stop", "-t", "10", name).CombinedOutput()
	stopped := time.Since(start)
	if err != nil {
		t.Fatalf("docker stop: %v: %s", err, out)
	}
	code, _ := exec.Command("docker", "inspect", "-f", "{{.State.ExitCode}}", name).Output()
	t.Logf("close to Done: %v; docker stop -t 10: %v, exit %s", closed.Round(time.Millisecond), stopped.Round(time.Millisecond), strings.TrimSpace(string(code)))
	if closed > 5*time.Second {
		t.Errorf("close took %v; want under 5 s", closed)
	}
	if stopped > 5*time.Second {
		t.Errorf("docker stop took %v; want under 5 s, the stop signal ending the container, not docker's kill after 10 s", stopped)
	}
}
