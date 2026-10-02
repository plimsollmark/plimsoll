package sessionkit

import (
	"encoding/hex"
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
func procIdentity(t *testing.T, pid int) string {
	t.Helper()
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(stat)
	f := strings.Fields(s[strings.LastIndex(s, ")")+2:])
	cmd, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		t.Fatal(err)
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
	for i := 0; ; i++ {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			break
		}
		if i > 200 {
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
