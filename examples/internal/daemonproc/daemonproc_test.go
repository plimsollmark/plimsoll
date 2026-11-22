package daemonproc

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
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
	// fixed-wait: the fake daemon's drain time, which the test's second signal must land inside; the fake's own behavior, not a wait for anything
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

// The daemon Build makes states daemon_version "(devel)": its build information names plimsoll's module at
// version (devel) with no version control stamp, which is what the daemon reads (internal/rpc's moduleVersion).
func TestBuildLeavesOutTheVersionControlStamp(t *testing.T) {
	t.Chdir(filepath.Join("..", "..", ".."))
	binary, err := Build(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bi, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if bi.Main.Path != "github.com/plimsollmark/plimsoll" || bi.Main.Version != "(devel)" {
		t.Fatalf("the daemon's build names %s %s, want github.com/plimsollmark/plimsoll (devel)", bi.Main.Path, bi.Main.Version)
	}
	for _, s := range bi.Settings {
		if strings.HasPrefix(s.Key, "vcs") {
			t.Errorf("the build information keeps the version control setting %s=%s", s.Key, s.Value)
		}
	}
}

// No example or measurement builds plimsolld with the version control stamp: each go build of ./cmd/plimsolld in
// their Go and shell sources passes -buildvcs=false, or goes through BuildArgs. A new build site without it fails here.
func TestEveryExampleBuildOfPlimsolldLeavesOutTheStamp(t *testing.T) {
	goBuild := regexp.MustCompile(`"build".*"\./cmd/plimsolld"|go( -C \S+)? build .*\./cmd/plimsolld`)
	n := 0
	for _, root := range []string{filepath.Join("..", ".."), filepath.Join("..", "..", "..", "measurements")} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !(strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".sh")) || strings.HasSuffix(path, "_test.go") {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(b), "\n") {
				code := strings.TrimSpace(line)
				if strings.HasPrefix(code, "//") || strings.HasPrefix(code, "#") || !goBuild.MatchString(code) {
					continue
				}
				n++
				// The pull-request recipe alone asks buildvcs.sh: at a clean release tag the stamp is the true release, so a
				// user's receipt names it; everywhere else that script answers false (its own test holds it to that).
				if strings.HasSuffix(filepath.ToSlash(path), "pr-receipt/receipt.sh") && code == recipeBuild {
					if err := recipeSetsBuildvcsOnce(string(b)); err != nil {
						t.Errorf("%s: %v", path, err)
					}
					continue
				}
				if !strings.Contains(code, "-buildvcs=false") {
					t.Errorf("%s:%d builds plimsolld with the version control stamp: %s", path, i+1, code)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if n < 2 {
		t.Fatalf("found %d builds of plimsolld; the scan no longer sees the example and measurement build sites", n)
	}
}

// The pull-request recipe's one build of plimsolld that may keep the stamp, and the one line that sets what it passes.
const (
	recipeAssign = `buildvcs="$(env "${no_git_env[@]}" bash "$script_dir/buildvcs.sh" "$source_dir")"`
	recipeBuild  = `env "${no_git_env[@]}" go -C "$source_dir" build -buildvcs="$buildvcs" -o "$work_dir/plimsolld" ./cmd/plimsolld`
)

// recipeSetsBuildvcsOnce: in receipt.sh the variable buildvcs is set only by the line that asks buildvcs.sh and read
// only by the build above. Any other mention outside a comment (a second assignment, a read, a declare, an export, a
// -buildvcs=true) could change what that build stamps, so it fails.
func recipeSetsBuildvcsOnce(src string) error {
	assigned, built := 0, 0
	for i, line := range strings.Split(src, "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") {
			continue
		}
		switch code {
		case recipeAssign:
			assigned++
			code = strings.TrimPrefix(code, "buildvcs=")
		case recipeBuild:
			built++
			code = strings.Replace(code, `-buildvcs="$buildvcs"`, "", 1)
		}
		code = strings.NewReplacer("buildvcs.sh", "", "-buildvcs=false", "").Replace(code)
		if strings.Contains(code, "buildvcs") {
			return fmt.Errorf("line %d mentions buildvcs outside the one assignment and the one build: %s", i+1, strings.TrimSpace(line))
		}
	}
	if assigned != 1 || built != 1 {
		return fmt.Errorf("%d lines assign buildvcs as %s and %d build with it; want one of each", assigned, recipeAssign, built)
	}
	return nil
}

// The recipe's exemption refuses anything else that sets the variable its build passes.
func TestTheRecipeSetsBuildvcsOnlyFromTheScript(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "pr-receipt", "receipt.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if err := recipeSetsBuildvcsOnce(src); err != nil {
		t.Fatalf("receipt.sh as committed: %v", err)
	}
	at := strings.Index(src, recipeBuild)
	if at < 0 {
		t.Fatal("receipt.sh has no line building plimsolld as the recipe's exemption names it")
	}
	for _, added := range []string{"buildvcs=true", "export buildvcs=true", "read -r buildvcs < /dev/null", `: "${buildvcs:=true}"`,
		"declare buildvcs=true", "GOFLAGS=-buildvcs=true go version", recipeAssign} {
		if err := recipeSetsBuildvcsOnce(src[:at] + added + "\n" + src[at:]); err == nil {
			t.Errorf("a line %q before the build passes", added)
		}
	}
}
