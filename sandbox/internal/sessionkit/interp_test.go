package sessionkit

import (
	"encoding/hex"
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
