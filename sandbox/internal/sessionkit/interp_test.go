package sessionkit

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The launcher's identity line: gVisor can report a negative start time for a
// process started right after its sandbox booted (measured 2026-10-01), which a
// first version of the pattern refused, failing one Python launch in thirty.
func TestIdentityPattern(t *testing.T) {
	for _, ok := range []string{"16:1234:707974686f6e33", "16:-146:707974686f6e33", "1:0:00"} {
		if !identityPattern.MatchString(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "16::70", "16:12:", "x:1:70", "16:1:70\n", "16:1:7G", "16:--1:70"} {
		if identityPattern.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The identity the launcher prints, which the sweep keeps, is the process it
// started, whatever another process of the session writes into the ready file while
// it waits. Here the other process writes a decoy's PID there as soon as the
// launcher makes its directory, and the interpreter writes its own only after that,
// so a launcher that reads the PID from the file reports the decoy. The launcher
// runs on this host with the host's sh and setsid, as in a sandbox.
func TestLaunchIdentityIsTheProcessItStarted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the launcher reads /proc")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "interp")
	ready := filepath.Join(dir, "ready")
	marker := "plimsoll-launch-test-" + strconv.Itoa(os.Getpid())

	decoy := exec.Command("sleep", "60")
	if err := decoy.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = decoy.Process.Kill(); _ = decoy.Wait() })
	decoyPID := strconv.Itoa(decoy.Process.Pid)

	spoofed := make(chan bool, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-stop:
				spoofed <- false
				return
			default:
			}
			if _, err := os.Stat(dir); err == nil {
				if _, err := os.Stat(ready); os.IsNotExist(err) && os.WriteFile(ready, []byte(decoyPID), 0o600) == nil {
					spoofed <- true
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
		spoofed <- false
	}()

	// The interpreter stands in for a kernel: it waits for the decoy's PID to be in
	// the file, writes its own, and stays.
	interp := `while [ ! -s "$1/ready" ]; do sleep 0.01; done; printf %s "$$" > "$1/ready"; while :; do sleep 1; done`
	cmd := exec.Command("sh", "-c", launchScript, "sh", "sh", "-c", interp, marker)
	cmd.Env = append(os.Environ(), "PLIMSOLL_INTERP_DIR="+dir, "PLIMSOLL_WORK="+filepath.Join(root, "work"))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if !<-spoofed {
		t.Fatal("the decoy's PID was never written into the ready file")
	}
	if err != nil {
		t.Fatalf("launch: %v: %s", err, stderr.String())
	}
	id := string(out)
	if !identityPattern.MatchString(id) {
		t.Fatalf("launcher printed %q", id)
	}
	pid, _ := strconv.Atoi(strings.SplitN(id, ":", 2)[0])
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
	if strconv.Itoa(pid) == decoyPID {
		t.Fatalf("the launcher reported the decoy %s, the PID another process wrote into its ready file", decoyPID)
	}
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || !strings.Contains(string(cmdline), marker) {
		t.Fatalf("the reported process %d is not the interpreter (command line %q, %v)", pid, cmdline, err)
	}
	if want := hex.EncodeToString(cmdline); !strings.HasSuffix(id, ":"+want) {
		t.Fatalf("the identity %q does not carry the interpreter's command line", id)
	}
}

// procIdentity is pid:starttime:cmdline-hex of a live process, as a launcher reports it.
// exec.Cmd.Start returns once the exec has begun, which can be before the kernel has
// set the new program's arguments: the command line reads empty for that moment (the
// test failed about 1 run in 20 on it), so it is read until it is not. A launcher reads
// it only after its interpreter says it is ready, so it never sees that moment.
func procIdentity(t *testing.T, pid int) string {
	t.Helper()
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(stat)
	f := strings.Fields(s[strings.LastIndex(s, ")")+2:])
	var cmd []byte
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		if cmd, err = os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline"); err != nil {
			t.Fatal(err)
		}
		if len(cmd) > 0 || time.Now().After(deadline) {
			break
		}
	}
	return strconv.Itoa(pid) + ":" + f[19] + ":" + hex.EncodeToString(cmd)
}

// The check confirms an interpreter only when it is the one live process with its
// command line, and a relay only when its parent is 0, which no process this test can
// start has (docker exec gives one; the docker suite proves that side).
func TestCheckScriptConfirmsOnlyTheProcessReported(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the check reads /proc")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	check := func(ids ...string) int {
		argv := CheckArgv(ids)
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
		if err == nil {
			return 0
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Logf("check %v: exit %d: %s", ids, ee.ExitCode(), out)
			return ee.ExitCode()
		}
		t.Fatal(err)
		return -1
	}
	// A command line no other process has: this test's PID and the time.
	arg := "4" + strconv.Itoa(os.Getpid()) + strconv.FormatInt(time.Now().UnixNano()%1e9, 10)
	start := func() *exec.Cmd {
		c := exec.Command("sleep", arg)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		return c
	}
	one := start()
	id := procIdentity(t, one.Process.Pid)
	if got := check("interp:" + id); got != 0 {
		t.Fatalf("the only process with its command line: exit %d, want 0", got)
	}
	parts := strings.SplitN(id, ":", 3)
	if got := check("interp:" + parts[0] + ":1" + parts[1] + ":" + parts[2]); got != 1 {
		t.Fatalf("another start time: exit %d, want 1", got)
	}
	if got := check("relay:" + id); got != 1 {
		t.Fatalf("a relay whose parent is not 0: exit %d, want 1", got)
	}
	// relay@N requires parent N: this test started the process, so it is the parent.
	if got := check("relay@" + strconv.Itoa(os.Getpid()) + ":" + id); got != 0 {
		t.Fatalf("a relay whose parent is the one named: exit %d, want 0", got)
	}
	if got := check("relay@1:" + id); got != 1 {
		t.Fatalf("a relay whose parent is not the one named: exit %d, want 1", got)
	}
	if got := check("relay@:" + id); got != 1 {
		t.Fatalf("a relay kind that names no parent: exit %d, want 1", got)
	}
	if got := check("other:" + id); got != 1 {
		t.Fatalf("an unknown kind: exit %d, want 1", got)
	}
	if got := check(); got != 1 {
		t.Fatalf("nothing to check: exit %d, want 1", got)
	}
	start() // a look-alike: the same command line
	if got := check("interp:" + id); got != 1 {
		t.Fatalf("an interpreter with a look-alike: exit %d, want 1", got)
	}
}

// A cell's request can reach the JavaScript kernel in several chunks; a chunk that
// arrives after the request's newline must not run the cell again.
func TestKernelJSRunsACellOnceWhateverTheChunks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("unix sockets")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	dir := t.TempDir()
	k := exec.Command("node", "-e", kernelJS, dir)
	k.Stdout, k.Stderr = io.Discard, io.Discard
	if err := k.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k.Process.Kill(); _ = k.Wait() })
	// node starts in well under a second on an idle machine and took over 5 s under
	// the export's full parallel test run, which failed this at a 5 s bound; 30 s only
	// bounds a kernel that never starts.
	for deadline := time.Now().Add(30 * time.Second); ; {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the kernel never became ready")
		}
		time.Sleep(25 * time.Millisecond)
	}
	send := func(chunks ...string) string {
		c, err := net.Dial("unix", filepath.Join(dir, "ctl.sock"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for i, ch := range chunks {
			// The first chunk carries the request; the kernel may have answered and
			// closed before the later ones, which then have nowhere to go.
			if _, err := io.WriteString(c, ch); err != nil && i == 0 {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		reply, _ := io.ReadAll(c)
		return string(reply)
	}
	send(`{"nonce":"a","code":"globalThis.runs = (globalThis.runs || 0) + 1"}`+"\n", "a later chunk\n", "and another")
	if reply := send(`{"nonce":"b","code":"require('fs').writeFileSync(process.argv[1] + '/runs', String(runs))"}` + "\n"); !strings.Contains(reply, `"ok"`) {
		t.Fatalf("reading the count: %q", reply)
	}
	got, err := os.ReadFile(filepath.Join(dir, "runs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1" {
		t.Fatalf("the cell ran %s times", got)
	}
}

// A FIFO in place of the ready file, which any process of the session can put there,
// fails the launch at once (exit 3, before the cell's code is sent). A launcher that
// opened it for reading blocked until the cell's deadline, so one line of a cell's code
// cost every later cell that started an interpreter its whole budget.
func TestLaunchRefusesAReadyFileThatIsNotARegularFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the launcher reads /proc")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "interp")
	interp := `mkfifo "$1/ready"; while :; do sleep 1; done`
	cmd := exec.Command("sh", "-c", launchScript, "sh", "sh", "-c", interp, "plimsoll-fifo-test")
	cmd.Env = append(os.Environ(), "PLIMSOLL_INTERP_DIR="+dir, "PLIMSOLL_WORK="+filepath.Join(root, "work"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { killInterpreterIn(dir) })
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 {
			t.Fatalf("launcher: %v (%s), want exit 3", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		t.Fatal("the launcher still waited 5 seconds after a FIFO took the ready file's place")
	}
}

// killInterpreterIn kills the process session of the interpreter a launcher started
// with dir as its last argument (setsid makes it the session's leader).
func killInterpreterIn(dir string) {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err == nil && strings.HasSuffix(string(cmdline), "\x00"+dir+"\x00") {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	}
}

// The lister reports each process's real uid and leaves out the kernel's own threads,
// which a virtual machine's /proc shows (they ignore SIGKILL, so a sweep that counted
// them would never finish). This machine's /proc shows kernel threads when it is not a
// container; either way no listed process may carry the PF_KTHREAD flag.
func TestListScriptReportsUIDsAndSkipsKernelThreads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the lister reads /proc")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	argv := ListArgv()
	out, err := exec.Command(argv[0], argv[1:]...).Output()
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseListing(out)
	if err != nil {
		t.Fatal(err)
	}
	me := os.Getuid()
	sawSelf := false
	for _, p := range l.Procs {
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(p.PID) + "/stat")
		if err != nil {
			continue // gone since the listing
		}
		f := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+2:]))
		flags, _ := strconv.ParseUint(f[6], 10, 64)
		if flags&0x200000 != 0 {
			t.Errorf("pid %d %q is a kernel thread and was listed", p.PID, p.Cmd)
		}
		if p.PID == os.Getpid() {
			sawSelf = true // an ancestor of the lister: never listed
		}
		if p.UID < 0 {
			t.Errorf("pid %d %q: uid not read", p.PID, p.Cmd)
		}
	}
	if sawSelf {
		t.Error("the lister listed its own ancestor, this test")
	}
	// This test's own child must be listed with this test's uid.
	c := exec.Command("sleep", "30")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Process.Kill(); _ = c.Wait() }()
	out, err = exec.Command(argv[0], argv[1:]...).Output()
	if err != nil {
		t.Fatal(err)
	}
	if l, err = ParseListing(out); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range l.Procs {
		if p.PID == c.Process.Pid {
			found = true
			if p.UID != me {
				t.Errorf("the child's uid: got %d, want %d", p.UID, me)
			}
		}
	}
	if !found {
		t.Error("the lister did not list this test's child")
	}
}

func TestBaselineAllKeepsEveryProcessButRefusesTheGuestUID(t *testing.T) {
	listing := func(procs ...Process) []byte {
		b, err := json.Marshal(Listing{Ptrace: "1", Procs: procs})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	initP := Process{PID: 1, Start: "1", UID: 0, CmdHex: "2f696e6974"}
	envd := Process{PID: 300, PPID: 1, Start: "90", UID: 0, CmdHex: "656e7664"}
	chrony := Process{PID: 410, PPID: 1, Start: "95", UID: 104, CmdHex: "6368726f6e7964"}
	keep, err := BaselineAll(listing(initP, envd, chrony), 61000)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{initP.Identity(), envd.Identity(), chrony.Identity()}
	if strings.Join(keep, ",") != strings.Join(want, ",") {
		t.Fatalf("keep = %v, want %v", keep, want)
	}
	if _, err := BaselineAll(listing(envd, chrony), 61000); err == nil {
		t.Error("a listing without PID 1 was accepted")
	}
	guestOwned := Process{PID: 500, PPID: 1, Start: "99", UID: 61000, CmdHex: "78"}
	if _, err := BaselineAll(listing(initP, guestOwned), 61000); err == nil {
		t.Error("a process already running as the guest uid was accepted")
	}
	unread := Process{PID: 501, PPID: 1, Start: "99", UID: -1, CmdHex: "78"}
	if _, err := BaselineAll(listing(initP, unread), 61000); err == nil {
		t.Error("a process whose uid could not be read was accepted")
	}
	if _, err := BaselineAll([]byte("not json"), 61000); err == nil {
		t.Error("output that is not a listing was accepted")
	}
}

// This machine's /proc may show no kernel thread (WSL2 and containers show none), so
// the flag test is checked here on stat lines: a kworker's (flags 0x04208060, as Linux
// 6.x reports one) and an ordinary process's (0x00400100).
func TestKernelThreadFlag(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	script := `const fs=require("node:fs");` + clearFn + `
for (const st of process.argv.slice(1)) {
  const f = st.slice(st.lastIndexOf(")") + 2).split(" ");
  process.stdout.write(kthread(f) ? "k" : "u");
}`
	worker := "57 (kworker/u8:3-events_unbound) I 2 0 0 0 -1 69238880 0 0 0 0 0 7 0 0 20 0 1 0 1200 0 0"
	user := "812 (node) S 1 812 812 0 -1 4194560 120 0 0 0 4 1 0 0 20 0 11 0 5000 0 0"
	out, err := exec.Command("node", "-e", script, worker, user).Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "ku" {
		t.Fatalf("kthread verdicts = %q, want %q (kworker, then a user process)", out, "ku")
	}
}

// The liveness test answers "running" for a process it cannot read, so the kill loop
// signals it instead of calling the round clean: a thread list that cannot be read, or
// a thread that ends while it is read, proves nothing (round-5 review, 2026-10-08).
// Only a process whose every readable thread is dead reads dead.
func TestLivenessTreatsAnUnreadableProcessAsRunning(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the liveness test reads Linux procfs")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	// live() is read out of the shipped program, so this is the code the sandbox runs.
	script := `const fs=require("node:fs");` + clearFn + `
let statReadable = true;
try { fs.readFileSync("/proc/999999/stat") } catch { statReadable = false }
const answers = {
  self: live(String(process.pid)),
  init: live("1"),
  goneStatReadable: statReadable,
  unreadable: live("self/../proc-does-not-exist"),
};
process.stdout.write(JSON.stringify(answers));`
	out, err := exec.Command(node, "-e", script).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var got struct {
		Self, Init, GoneStatReadable, Unreadable bool
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("answers %q: %v", out, err)
	}
	if !got.Self || !got.Init {
		t.Fatalf("a running process reads dead: self %v, init %v", got.Self, got.Init)
	}
	if !got.Unreadable {
		t.Fatal("a process whose threads cannot be listed reads dead; it must read as running, so it is killed")
	}
	// What keeps the loop converging is the step before the liveness test: a process
	// that is gone has no stat to read, so the scan passes over it and never asks.
	if got.GoneStatReadable {
		t.Fatal("a PID that does not exist has a readable stat, so the scan could not pass over it")
	}
	// The kill loop itself is not run here: it kills every process that is not in its
	// keep list, so it belongs inside a container of its own (sandbox/docker_sweep_test.go).
}
