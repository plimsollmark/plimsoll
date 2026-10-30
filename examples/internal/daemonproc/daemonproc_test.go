package daemonproc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A daemon that exits before it is ready is reported at once, with the exit, not after
// the whole wait: copied starters in four examples never noticed, so a daemon that died
// at startup cost minutes (review B9, 2026-10-23).
func TestADaemonThatExitsAtStartupIsReportedAtOnce(t *testing.T) {
	sh, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no false(1) on this machine")
	}
	start := time.Now()
	_, err = Start(context.Background(), sh, Options{Ready: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "exited before it was ready") {
		t.Fatalf("Start: %v; want the daemon's early exit", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("reported after %v of a 1 minute wait", took)
	}
}

// fakeDaemonReport is where the stand-in daemon writes what it saw: its environment,
// its process group and each signal, one per line.
const fakeDaemonReport = "DAEMONPROC_FAKE_REPORT"

// TestMain runs this test binary as a stand-in plimsolld when the starter under test
// starts it: it serves /readyz on PLIMSOLL_ADDR and, on SIGINT or SIGTERM, records the
// signal and exits 0 after a short drain, as plimsolld does on the first signal.
func TestMain(m *testing.M) {
	if report := os.Getenv(fakeDaemonReport); report != "" {
		fakeDaemon(report)
		return
	}
	os.Exit(m.Run())
}

func fakeDaemon(report string) {
	f, err := os.OpenFile(report, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		os.Exit(3)
	}
	for _, kv := range os.Environ() {
		fmt.Fprintf(f, "env %s\n", kv)
	}
	fmt.Fprintf(f, "pgrp %d\n", syscall.Getpgrp())
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	l, err := net.Listen("tcp", os.Getenv("PLIMSOLL_ADDR"))
	if err != nil {
		os.Exit(4)
	}
	go func() { _ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})) }()
	fmt.Fprintf(f, "signal %v\n", <-signals)
	time.Sleep(200 * time.Millisecond) // the drain, during which a second signal would force-quit plimsolld
	select {
	case s := <-signals:
		fmt.Fprintf(f, "signal %v\n", s)
	default:
	}
	fmt.Fprintln(f, "drained")
	f.Close()
	os.Exit(0)
}

// TestADaemonIsStoppedOnceWithSIGTERMAndGetsOnlyItsOwnSettings: an example's context
// ending (its signal.NotifyContext on Ctrl-C) stops the daemon with one SIGTERM, so it
// drains and deletes its sandboxes; exec's default had been SIGKILL. The daemon is in a
// process group of its own, so a terminal's Ctrl-C does not reach it as a second signal,
// and it gets Options.Env and passedEnv, never a setting of this shell's (release
// release review, 2026-10-29, findings 1 and 3).
func TestADaemonIsStoppedOnceWithSIGTERMAndGetsOnlyItsOwnSettings(t *testing.T) {
	report := filepath.Join(t.TempDir(), "report")
	t.Setenv("SANDBOX_DOCKER_RUNTIME", "runsc")
	t.Setenv("PLIMSOLL_HARDENED", "1")
	ctx, cancel := context.WithCancel(context.Background())
	d, err := Start(ctx, os.Args[0], Options{Env: []string{fakeDaemonReport + "=" + report, "SANDBOX_PROVIDER=docker"}, Ready: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := d.Stop(30 * time.Second); err != nil {
		t.Fatalf("Stop after the context ended: %v", err)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var signals []string
	env := map[string]bool{}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "signal "):
			signals = append(signals, strings.TrimPrefix(l, "signal "))
		case strings.HasPrefix(l, "env "):
			env[strings.SplitN(strings.TrimPrefix(l, "env "), "=", 2)[0]] = true
		case strings.HasPrefix(l, "pgrp "):
			if l == fmt.Sprintf("pgrp %d", syscall.Getpgrp()) {
				t.Error("the daemon is in this process's group, where a terminal's Ctrl-C reaches it too")
			}
		}
	}
	if len(signals) != 1 || signals[0] != syscall.SIGTERM.String() || lines[len(lines)-1] != "drained" {
		t.Errorf("signals %v, last line %q; want one SIGTERM and a drain", signals, lines[len(lines)-1])
	}
	for _, name := range []string{"SANDBOX_DOCKER_RUNTIME", "PLIMSOLL_HARDENED"} {
		if env[name] {
			t.Errorf("the daemon got %s from this process's environment", name)
		}
	}
	for _, name := range []string{"SANDBOX_PROVIDER", "PLIMSOLL_ADDR", "PATH"} {
		if !env[name] {
			t.Errorf("the daemon did not get %s", name)
		}
	}
	for name := range env {
		if !slices.Contains(passedEnv, name) && !slices.Contains([]string{fakeDaemonReport, "SANDBOX_PROVIDER", "PLIMSOLL_ADDR", "PLIMSOLL_METRICS_ADDR"}, name) {
			t.Errorf("the daemon got %s, which neither Options.Env nor passedEnv names", name)
		}
	}
}
