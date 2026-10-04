package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// dockerRequired reports whether the caller asked for docker coverage to be
// proven rather than attempted. `make docker-suite` sets
// SANDBOX_TEST_REQUIRE_DOCKER=1, and under it every infrastructure skip below is a
// failure: a daemon that is not there, an image that was never built, a throwaway
// image that could not be tagged. Without it (an ordinary `go test ./...` on a
// laptop without docker) the same conditions skip, as they always have.
//
// The distinction exists because a skip inside a deliberately requested suite reads
// exactly like a pass: the run is green, the isolation claims were never exercised,
// and nothing says so. CI runs the suite in required mode for that reason.
func dockerRequired() bool {
	return os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1"
}

// infraSkip skips the test for a missing piece of docker infrastructure, or fails
// it when that infrastructure was required (see dockerRequired).
func infraSkip(t *testing.T, format string, args ...any) {
	t.Helper()
	if dockerRequired() {
		t.Fatalf("docker coverage was required (SANDBOX_TEST_REQUIRE_DOCKER=1) but its infrastructure is missing: "+format, args...)
	}
	t.Skipf(format, args...)
}

func requireDocker(t *testing.T) {
	t.Helper()
	if testing.Short() {
		infraSkip(t, "skipping docker sandbox test in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		infraSkip(t, "docker not available")
	}
}

// testDocker builds a DockerSandbox for tests, honoring SANDBOX_DOCKER_RUNTIME so
// the whole docker suite can be exercised under gVisor:
//
//	SANDBOX_DOCKER_RUNTIME=runsc go test ./sandbox -run 'Docker|RunProject'
func testDocker() *DockerSandbox {
	d := DefaultDocker("")
	d.Runtime = os.Getenv("SANDBOX_DOCKER_RUNTIME")
	d.Seccomp = os.Getenv("SANDBOX_DOCKER_SECCOMP") // exercise the whole suite under a profile
	return d
}

// TestDockerLockdownAppliesSeccomp verifies a configured seccomp profile is pinned on
// runc runs and skipped under gVisor (which filters syscalls itself). No daemon
// needed — inspects the generated flags.
func TestDockerLockdownAppliesSeccomp(t *testing.T) {
	d := DefaultDocker("")
	d.Seccomp = "/etc/crsbx/seccomp.json"
	if !strings.Contains(strings.Join(d.lockdownArgs("c", time.Now(), false, d.Runtime), " "), "--security-opt seccomp=/etc/crsbx/seccomp.json") {
		t.Error("configured seccomp profile not applied under runc")
	}
	d.Runtime = "runsc"
	if strings.Contains(strings.Join(d.lockdownArgs("c", time.Now(), false, d.Runtime), " "), "seccomp=") {
		t.Error("gVisor run should not also apply a host seccomp profile")
	}
}

func TestDockerLockdownDisablesDaemonLogStorage(t *testing.T) {
	d := DefaultDocker("")
	args := strings.Join(d.lockdownArgs("c", time.Now(), false, d.Runtime), " ")
	if !strings.Contains(args, "--log-driver none") {
		t.Fatalf("lockdown args do not disable daemon-side storage of hostile output: %s", args)
	}
}

// TestShippedSeccompProfileIsSaneAndTight validates the audited default profile
// (docker/seccomp.json) at the policy level, without a daemon: it must be well-formed
// JSON, deny-by-default (SCMP_ACT_ERRNO), allow the syscalls the node runtime + TS
// toolchain actually need, and — the whole point of shipping it over docker's builtin
// default — NOT allow the non-cap-gated kernel-attack-surface syscalls the workload
// never uses. cap-drop ALL already removes the cap-gated ones; these are the extras a
// same-uid attacker could otherwise reach.
func TestShippedSeccompProfileIsSaneAndTight(t *testing.T) {
	raw, err := os.ReadFile("../docker/seccomp.json")
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	var prof struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
			Args   []struct {
				Index    int    `json:"index"`
				Value    uint64 `json:"value"`
				ValueTwo uint64 `json:"valueTwo"`
				Op       string `json:"op"`
			} `json:"args"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(raw, &prof); err != nil {
		t.Fatalf("profile is not valid JSON: %v", err)
	}
	if prof.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatalf("defaultAction = %q, want SCMP_ACT_ERRNO (deny-by-default)", prof.DefaultAction)
	}
	allowed := map[string]bool{}
	unixSocketOnly := map[string]bool{}
	for _, s := range prof.Syscalls {
		if s.Action != "SCMP_ACT_ALLOW" {
			continue
		}
		for _, n := range s.Names {
			allowed[n] = true
			if n == "socket" || n == "socketpair" {
				if len(s.Args) == 1 && s.Args[0].Index == 0 && s.Args[0].Value == 1 && s.Args[0].Op == "SCMP_CMP_EQ" {
					unixSocketOnly[n] = true
				} else {
					t.Errorf("%s has an unfiltered allow rule; only AF_UNIX may be allowed", n)
				}
			}
		}
	}
	for _, n := range []string{"socket", "socketpair"} {
		if !unixSocketOnly[n] {
			t.Errorf("%s is not restricted to AF_UNIX", n)
		}
	}
	// Essentials: if these regress out, the workload breaks (verified live elsewhere,
	// asserted here so an edit can't silently drop them).
	for _, n := range []string{
		"read", "write", "openat", "close", "mmap", "mprotect", "futex",
		"clone", "execve", "wait4", "epoll_pwait", "getrandom",
		"set_tid_address", "set_robust_list", "socket", "connect",
		"kill", // a judge stops its own controller (docker/sim/oracle); see docs/seccomp.md
		// Older forms of utimensat, which the kernel implements the same way; older C
		// libraries still issue them (docs/seccomp.md, TestDockerLegacyTimestampSyscalls).
		"utime", "utimes", "futimesat", "utimensat",
	} {
		if !allowed[n] {
			t.Errorf("essential syscall %q is not allowed — the profile would break the workload", n)
		}
	}
	// Tightening: the denial table in docs/seccomp.md is the list, so the document and
	// this test cannot drift apart. Every syscall its first column names must be
	// withheld; its two rows that are not plain names are checked for what they claim;
	// a row this loop cannot read fails.
	names, cloneRow, socketRow := seccompDenialTable(t)
	// 43 names on 2026-09-29. A shorter table means a row was dropped: loosen the
	// profile on purpose, then lower this.
	if len(names) < 43 {
		t.Fatalf("the denial table names %d syscalls, fewer than the 43 it had; was a row dropped?", len(names))
	}
	for _, n := range names {
		if allowed[n] {
			t.Errorf("syscall %q is in the denial table of docs/seccomp.md but the profile allows it", n)
		}
	}
	if !socketRow {
		t.Error("the denial table lost its socket(AF_ALG, ...) row, which the AF_UNIX-only check above stands behind")
	}
	if !cloneRow {
		t.Fatal("the denial table lost its CLONE_NEW* row")
	}
	// clone may create no namespace: every allow rule for it must carry the one
	// argument filter (flags & mask) == 0, with the mask covering each CLONE_NEW* flag
	// clone can take. CLONE_NEWTIME is clone3-only, and clone3 is withheld above.
	const cloneNewFlags = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000 // NS CGROUP UTS IPC USER PID NET
	cloneRules := 0
	for _, s := range prof.Syscalls {
		if s.Action != "SCMP_ACT_ALLOW" || !slices.Contains(s.Names, "clone") {
			continue
		}
		cloneRules++
		if len(s.Args) != 1 || s.Args[0].Index != 0 || s.Args[0].Op != "SCMP_CMP_MASKED_EQ" ||
			s.Args[0].ValueTwo != 0 || s.Args[0].Value&cloneNewFlags != cloneNewFlags {
			t.Errorf("an allow rule for clone does not refuse every CLONE_NEW* flag: %+v", s.Args)
		}
	}
	if cloneRules == 0 {
		t.Error("no allow rule for clone; the workload cannot start a thread")
	}
	// mknod and mknodat only for FIFOs: every allow rule carries the one filter
	// (mode & S_IFMT) == S_IFIFO on the mode argument (docs/seccomp.md).
	for _, s := range prof.Syscalls {
		if s.Action != "SCMP_ACT_ALLOW" {
			continue
		}
		for _, n := range s.Names {
			want := map[string]int{"mknod": 1, "mknodat": 2}
			idx, ok := want[n]
			if !ok {
				continue
			}
			if len(s.Names) != 1 || len(s.Args) != 1 || s.Args[0].Index != idx || s.Args[0].Op != "SCMP_CMP_MASKED_EQ" ||
				s.Args[0].Value != 0o170000 || s.Args[0].ValueTwo != 0o010000 {
				t.Errorf("an allow rule for %s is not limited to FIFOs: %+v", n, s.Args)
			}
		}
	}
}

// seccompDenialTable reads the first column of the denial table in docs/seccomp.md:
// the syscall names, and whether its CLONE_NEW* and socket(AF_ALG) rows are present.
func seccompDenialTable(t *testing.T) (names []string, cloneRow, socketRow bool) {
	t.Helper()
	raw, err := os.ReadFile("../docs/seccomp.md")
	if err != nil {
		t.Fatalf("read docs/seccomp.md: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	start := slices.Index(lines, "| Syscall(s) | Why denied |")
	if start < 0 || start+2 >= len(lines) {
		t.Fatal("docs/seccomp.md has no denial table (header \"| Syscall(s) | Why denied |\")")
	}
	token := regexp.MustCompile("`([^`]+)`")
	name := regexp.MustCompile(`^[a-z0-9_]+$`)
	for _, line := range lines[start+2:] {
		if !strings.HasPrefix(line, "|") {
			break
		}
		cell := strings.SplitN(line, "|", 3)[1]
		found := token.FindAllStringSubmatch(cell, -1)
		if len(found) == 0 {
			t.Fatalf("a denial table row names nothing this test can check: %q", line)
		}
		for _, m := range found {
			switch tok := m[1]; {
			case name.MatchString(tok):
				names = append(names, tok)
			case tok == "CLONE_NEW*":
				cloneRow = true
			case strings.HasPrefix(tok, "socket(AF_ALG"):
				socketRow = true
			default:
				t.Fatalf("denial table entry %q is neither a syscall name nor a row this test knows", tok)
			}
		}
	}
	return names, cloneRow, socketRow
}

func TestIsDigestPinned(t *testing.T) {
	pinned := "node@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		img  string
		want bool
	}{
		{pinned, true},
		{"node:22-alpine", false},
		{"plimsoll/sandbox:latest", false},
		{"node@sha256:short", false},
		{"@sha256:" + strings.Repeat("a", 40), false}, // no repository before the digest
		{"node@sha256:" + strings.Repeat("z", 64), false},
		{pinned + "suffix", false},
	} {
		if got := isDigestPinned(tc.img); got != tc.want {
			t.Errorf("isDigestPinned(%q) = %v, want %v", tc.img, got, tc.want)
		}
	}
}

func TestDockerRequirePinnedImagesPreflight(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		infraSkip(t, "docker not on PATH")
	}
	d := DefaultDocker("") // mutable tags
	d.RequirePinnedImages = true
	if err := d.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "not pinned") {
		t.Fatalf("err = %v, want a not-pinned rejection", err)
	}
}

func TestDockerHostIsRemote(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"", false},
		{"unix:///var/run/docker.sock", false},
		{"/var/run/docker.sock", false},
		{"named-daemon", true},
		{"tcp://10.0.0.5:2375", true},
		{"ssh://user@host", true},
		{"https://dockerd:2376", true},
	} {
		if got := dockerHostIsRemote(tc.host); got != tc.want {
			t.Errorf("dockerHostIsRemote(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestDockerRejectsRemoteActiveContext(t *testing.T) {
	bin := t.TempDir()
	docker := filepath.Join(bin, "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\n[ \"$1\" = --config ] && shift 2\necho tcp://10.0.0.9:2375\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "remote")
	if err := DefaultDocker("").Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "remote daemon") {
		t.Fatalf("err = %v, want remote active-context rejection", err)
	}
}

func TestDockerPreflightVerifiesRegisteredRuntime(t *testing.T) {
	bin := t.TempDir()
	docker := filepath.Join(bin, "docker")
	script := "#!/bin/sh\n[ \"$1\" = --config ] && shift 2\nif [ \"$1\" = context ]; then echo unix:///var/run/docker.sock; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = info ]; then echo '{\"runc\":{\"path\":\"runc\"}}'; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = image ]; then echo '{\"Id\":\"sha256:d0cafe\",\"Config\":{}}'; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(docker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	d := DefaultDocker("")
	d.Runtime = "runsc"
	if err := d.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("err = %v, want unregistered-runtime rejection", err)
	}
	d.Runtime = "runc"
	if err := d.Preflight(context.Background()); err != nil {
		t.Fatalf("registered runtime rejected: %v", err)
	}
	state, err := d.executionState()
	if err != nil {
		t.Fatal(err)
	}
	args, err := dockerArgs(state.host, "run", "image")
	if err != nil || len(args) < 3 || args[0] != "--host" || args[1] != "unix:///var/run/docker.sock" {
		t.Fatalf("pinned docker args = %v, err=%v", args, err)
	}

	// A runtime key named runsc is not enough: it must resolve to a runsc
	// executable, or the kernel-isolation claim is just trusting a label.
	badRunsc := "#!/bin/sh\n[ \"$1\" = --config ] && shift 2\nif [ \"$1\" = context ]; then echo unix:///var/run/docker.sock; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = info ]; then echo '{\"runsc\":{\"path\":\"runc\"}}'; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = image ]; then echo '{\"Id\":\"sha256:d0cafe\",\"Config\":{}}'; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(docker, []byte(badRunsc), 0o755); err != nil {
		t.Fatal(err)
	}
	d2 := DefaultDocker("")
	d2.Runtime = "runsc"
	if err := d2.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "not a runsc executable") {
		t.Fatalf("err = %v, want mislabeled-runsc rejection", err)
	}
	if got := d2.IsolationClass(); got != IsolationContainer {
		t.Fatalf("unverified runsc isolation = %v, want conservative container", got)
	}

	goodRunsc := "#!/bin/sh\n[ \"$1\" = --config ] && shift 2\nif [ \"$1\" = context ]; then echo unix:///var/run/docker.sock; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = info ]; then echo '{\"runsc\":{\"path\":\"/usr/local/bin/runsc\"}}'; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = image ]; then echo '{\"Id\":\"sha256:d0cafe\",\"Config\":{}}'; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(docker, []byte(goodRunsc), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := d2.Preflight(context.Background()); err != nil {
		t.Fatalf("real runsc registration rejected: %v", err)
	}
	if got := d2.IsolationClass(); got != IsolationKernel {
		t.Fatalf("verified runsc isolation = %v, want kernel", got)
	}
}

func TestDockerPreflightKeepsPinnedEndpointAndFailsClosed(t *testing.T) {
	bin := t.TempDir()
	docker := filepath.Join(bin, "docker")
	contextFile := filepath.Join(bin, "context")
	failFile := filepath.Join(bin, "fail")
	logFile := filepath.Join(bin, "hosts")
	// The paths are written into the script: the docker CLI gets PATH and nothing
	// else from plimsoll (docker_cli.go), so a variable set here would not reach it.
	script := "#!/bin/sh\n[ \"$1\" = --config ] && shift 2\n" +
		"if [ \"$1\" = context ]; then IFS= read -r endpoint < '" + contextFile + "'; echo \"$endpoint\"; exit 0; fi\n" +
		"if [ \"$1\" = --host ] && [ \"$3\" = info ]; then echo \"$2\" >> '" + logFile + "'; if [ -f '" + failFile + "' ]; then exit 1; fi; echo '{\"runsc\":{\"path\":\"runsc\"}}'; exit 0; fi\n" +
		"if [ \"$1\" = --host ] && [ \"$3\" = image ]; then echo '{\"Id\":\"sha256:d0cafe\",\"Config\":{}}'; exit 0; fi\n" +
		"exit 1\n"
	if err := os.WriteFile(docker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contextFile, []byte("unix:///run/docker-a.sock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")

	d := DefaultDocker("")
	d.Runtime = "runsc"
	now := time.Unix(1_700_000_000, 0)
	d.preflightNow = func() time.Time { return now }
	if err := d.Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := d.executionState()
	if err != nil || first.host != "unix:///run/docker-a.sock" || first.isolation != IsolationKernel {
		t.Fatalf("first state = %+v, err=%v", first, err)
	}

	// Changing the active context must not redirect later runs or cleanup. Within
	// the bounded readiness cache, a probe is served from the verified state.
	if err := os.WriteFile(contextFile, []byte("unix:///run/docker-b.sock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(raw)); len(got) != 1 || got[0] != first.host {
		t.Fatalf("cached readiness unexpectedly probed Docker: %q", raw)
	}

	// At the cache boundary readiness must refresh, and it must probe the pinned A
	// endpoint rather than following the now-active B context. Exercise the run
	// path helper: it must not bypass the cache TTL merely because stale state is
	// still marked ready.
	now = now.Add(dockerPreflightCacheTTL)
	if err := d.ensurePreflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := d.executionState()
	if err != nil || second.host != first.host {
		t.Fatalf("endpoint drifted: first=%+v second=%+v err=%v", first, second, err)
	}

	// A failed readiness refresh invalidates admission until the same pinned
	// endpoint verifies again; ensurePreflight must not skip merely because a host
	// string remains stored.
	if err := os.WriteFile(failFile, []byte("fail"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.Preflight(context.Background()); err != nil {
		t.Fatalf("recent verified readiness was not cached: %v", err)
	}
	now = now.Add(dockerPreflightCacheTTL)
	if err := d.Preflight(context.Background()); err == nil {
		t.Fatal("expired readiness cache hid a failed daemon probe")
	}
	if _, err := d.executionState(); err == nil {
		t.Fatal("failed readiness probe left provider admissible")
	}
	if err := os.Remove(failFile); err != nil {
		t.Fatal(err)
	}
	if err := d.ensurePreflight(context.Background()); err != nil {
		t.Fatalf("provider did not recover on pinned endpoint: %v", err)
	}
	recovered, err := d.executionState()
	if err != nil || recovered.host != first.host {
		t.Fatalf("recovered state = %+v, err=%v", recovered, err)
	}
	raw, err = os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "docker-b") {
		t.Fatalf("readiness followed mutable context B: %s", raw)
	}
}

// TestDockerPreflightBoundsConcurrentCallers: a caller that loses the preflight
// race waits for the in-flight probe, but only for a bound. The property the old
// fail-fast protected is unbounded queueing behind one daemon probe, and a
// bounded wait keeps it: callers poll rather than block on the mutex and give up
// on a deadline.
func TestDockerPreflightBoundsConcurrentCallers(t *testing.T) {
	d := DefaultDocker("")
	d.preflightWait = 150 * time.Millisecond
	d.preflightMu.Lock()
	defer d.preflightMu.Unlock()

	started := time.Now()
	err := d.Preflight(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("err = %v, want an in-progress readiness error", err)
	}
	elapsed := time.Since(started)
	if elapsed < 100*time.Millisecond {
		t.Fatalf("gave up after %v without waiting for the in-flight probe", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("concurrent Preflight queued for %v instead of bounding its wait", elapsed)
	}
}

// TestDockerPreflightWaitsForInFlightProbe is the behaviour the bounded wait
// exists for: the holder publishes a fresh ready state, and the waiting caller
// succeeds instead of being told to retry. Measured without it, a concurrent
// consumer lost 47 of 48 runs at every cache-TTL expiry.
func TestDockerPreflightWaitsForInFlightProbe(t *testing.T) {
	d := DefaultDocker("")
	now := time.Unix(1_700_000_000, 0)
	d.preflightNow = func() time.Time { return now }
	d.preflightWait = 3 * time.Second

	d.preflightMu.Lock()
	go func() {
		time.Sleep(80 * time.Millisecond)
		// Publish BEFORE releasing, exactly as a real probe does, so the waiter
		// sees a ready provider without ever taking the lock.
		d.stateMu.Lock()
		d.ready = true
		d.daemonHost = "unix:///run/docker.sock"
		d.verifiedRuntime = d.Runtime
		d.verifiedGuestUID = d.guestUID()
		d.lastVerified = now
		d.stateMu.Unlock()
		d.preflightMu.Unlock()
	}()

	started := time.Now()
	if err := d.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight = %v, want nil once the in-flight probe published a ready state", err)
	}
	if elapsed := time.Since(started); elapsed < 50*time.Millisecond {
		t.Fatalf("returned in %v, so it cannot have waited for the probe", elapsed)
	}
}

// TestDockerPreflightWaitRespectsCallerDeadline: the wait never outlives the
// caller's own budget, which is what keeps it safe for a short-timeout run.
func TestDockerPreflightWaitRespectsCallerDeadline(t *testing.T) {
	d := DefaultDocker("")
	d.preflightWait = 30 * time.Second
	d.preflightMu.Lock()
	defer d.preflightMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := d.Preflight(ctx); err == nil {
		t.Fatal("want an error when the caller's deadline expires during the wait")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("waited %v past the caller's 120ms deadline", elapsed)
	}
}

func TestDockerConcurrentPreflightRejectsExpiredEvidence(t *testing.T) {
	d := DefaultDocker("")
	now := time.Unix(1_700_000_000, 0)
	d.preflightNow = func() time.Time { return now }
	d.stateMu.Lock()
	d.ready = true
	d.daemonHost = "unix:///run/docker.sock"
	d.verifiedRuntime = d.Runtime
	d.verifiedGuestUID = d.guestUID()
	d.lastVerified = now.Add(-dockerPreflightCacheTTL)
	d.stateMu.Unlock()
	d.preflightWait = 100 * time.Millisecond // bound the wait; this test is about expiry, not latency

	d.preflightMu.Lock()
	defer d.preflightMu.Unlock()
	if err := d.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("expired concurrent Preflight error = %v, want fail-closed in-progress error", err)
	}
}

func TestDockerDirectRunsEnforceSnapshottedMinimumIsolation(t *testing.T) {
	d := DefaultDocker("")
	now := time.Unix(1_700_000_000, 0)
	d.preflightNow = func() time.Time { return now }
	d.stateMu.Lock()
	d.ready = true
	d.daemonHost = "unix:///run/docker.sock"
	d.verifiedRuntime = ""
	d.verifiedGuestUID = d.guestUID()
	d.verifiedImageIDs = map[string]string{
		d.Image:        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		d.ProjectImage: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
	}
	d.lastVerified = now
	d.stateMu.Unlock()

	res, err := d.RunJavaScript(context.Background(), Request{
		Code:             "1",
		MinimumIsolation: IsolationKernel,
	})
	if !errors.Is(err, ErrInsufficientIsolation) || res.Isolation != IsolationContainer {
		t.Fatalf("RunJavaScript result=%+v err=%v, want container isolation rejection", res, err)
	}
	project, err := d.RunProject(context.Background(), ProjectRequest{
		Steps:            []string{"true"},
		MinimumIsolation: IsolationKernel,
	})
	if !errors.Is(err, ErrInsufficientIsolation) || project.Isolation != IsolationContainer {
		t.Fatalf("RunProject result=%+v err=%v, want container isolation rejection", project, err)
	}
}

func TestDockerRejectsRemoteDaemonAtPreflight(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		infraSkip(t, "docker not on PATH")
	}
	t.Setenv("DOCKER_HOST", "tcp://10.0.0.5:2375")
	d := DefaultDocker("")
	if err := d.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "remote daemon") {
		t.Fatalf("err = %v, want a remote-daemon rejection", err)
	}
}

// afterMarker finds the start marker wherever it is in stderr: after a warning the
// docker CLI printed first, which is dropped with it, and before guest output that
// repeats it, which is kept. No marker, no start.
func TestAfterMarker(t *testing.T) {
	const m = "plimsoll-started:ab12\n"
	for _, c := range []struct {
		in, want string
		ran      bool
	}{
		{m + "guest\n", "guest\n", true},
		{"WARNING: Your kernel does not support swap limit capabilities.\n" + m + "guest", "guest", true},
		{m + "guest wrote " + m, "guest wrote " + m, true},
		{"docker: Error response from daemon: x\n", "docker: Error response from daemon: x\n", false},
		{"", "", false},
	} {
		if got, ran := afterMarker(c.in, m); got != c.want || ran != c.ran {
			t.Errorf("afterMarker(%q) = %q, %v; want %q, %v", c.in, got, ran, c.want, c.ran)
		}
	}
}

func TestDockerRunCapturesStdoutAndExitZero(t *testing.T) {

	d := testDocker()
	requireSnippetImage(t, d)
	res, err := d.RunJavaScript(context.Background(), Request{Code: `console.log("hi", 1 + 2)`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "hi 3") {
		t.Fatalf("stdout = %q, want it to contain %q", res.Stdout, "hi 3")
	}
	if res.Sandbox != "docker" {
		t.Fatalf("sandbox = %q, want docker", res.Sandbox)
	}
}

func TestDockerNonZeroExitIsResultNotError(t *testing.T) {

	d := testDocker()
	requireSnippetImage(t, d)
	res, err := d.RunJavaScript(context.Background(), Request{Code: `console.error("boom"); process.exit(3)`})
	if err != nil {
		t.Fatalf("non-zero exit should be a result, got error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", res.ExitCode)
	}
	if !strings.Contains(res.Stderr, "boom") {
		t.Fatalf("stderr = %q, want it to contain %q", res.Stderr, "boom")
	}
}

func TestDockerTimeout(t *testing.T) {

	d := testDocker()
	requireSnippetImage(t, d)
	// Long enough for the container to start even under runsc on a loaded host: a run
	// whose deadline passes before the guest starts is docker's failure, not a timeout.
	d.DefaultTimeout = 3 * time.Second
	res, err := d.RunJavaScript(context.Background(), Request{Code: `setTimeout(() => {}, 60000)`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.TimedOut {
		t.Fatalf("expected TimedOut=true, got %+v", res)
	}
}

func TestDisabledRefusesToRun(t *testing.T) {
	_, err := Disabled{}.RunJavaScript(context.Background(), Request{Code: "console.log(1)"})
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("err = %v, want ErrDisabled", err)
	}
	if _, err := (Disabled{}).RunProject(context.Background(), ProjectRequest{Steps: []string{"true"}}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("RunProject err = %v, want ErrDisabled", err)
	}
}

func TestHostSDKModuleIsPreloadable(t *testing.T) {
	// nil grant → empty module (a no-grant project run carries no hostSDK).
	if got := hostSDKModule(nil); got != "" {
		t.Fatalf("hostSDKModule(nil) = %q, want empty", got)
	}

	grant := &HostAPIGrant{
		BaseURL:  "https://host.internal",
		Allow:    []HostRoute{{Method: "GET", Path: "/items/*"}},
		Global:   "acme",
		Minter:   StaticToken("unused-in-module"),
		Preamble: "globalThis.acmeSdk = { items: (id) => acme.get('/items/' + id) };",
	}
	mod := hostSDKModule(grant)
	// It must define the grant's global (the same contract a snippet gets) and layer
	// the domain preamble on top, so a project step's node --import gives host.* + SDK.
	if !strings.Contains(mod, `globalThis["acme"]`) {
		t.Errorf("module does not define the grant global; got:\n%s", mod)
	}
	if !strings.Contains(mod, "acmeSdk") {
		t.Errorf("module does not include the domain preamble; got:\n%s", mod)
	}
	// The allowlist is baked in for the client-side mirror; the socket is read at call
	// time from the env, so no credential can appear in the preloaded text.
	if !strings.Contains(mod, "/items/*") {
		t.Errorf("module does not bake in the allowlist route; got:\n%s", mod)
	}
	if strings.Contains(mod, "unused-in-module") {
		t.Errorf("module leaked the bearer token; got:\n%s", mod)
	}
}

func TestDockerRejectsImageOptionInjection(t *testing.T) {
	for _, image := range []string{"--runtime=runc", "-network=host", ""} {
		if err := validateDockerImage(image); err == nil {
			t.Errorf("validateDockerImage(%q) succeeded, want rejection", image)
		}
	}
	if err := validateDockerImage("registry.example/team/node:22"); err != nil {
		t.Fatalf("valid image rejected: %v", err)
	}
}

func TestDockerZeroValueTimeoutFallbacks(t *testing.T) {
	d := &DockerSandbox{}
	if got := d.snippetTimeout(0); got != dockerDefaultTimeout {
		t.Errorf("snippet default = %v, want %v", got, dockerDefaultTimeout)
	}
	if got := d.snippetTimeout(time.Hour); got != dockerMaxTimeout {
		t.Errorf("snippet max = %v, want %v", got, dockerMaxTimeout)
	}
	if got := d.projectTimeout(0); got != dockerProjectTimeout {
		t.Errorf("project default = %v, want %v", got, dockerProjectTimeout)
	}
	if got := d.projectTimeout(time.Hour); got != dockerMaxProjectTime {
		t.Errorf("project max = %v, want %v", got, dockerMaxProjectTime)
	}
	if got := d.maxOutput(); got != dockerDefaultOutputBytes {
		t.Errorf("output cap = %d, want %d", got, dockerDefaultOutputBytes)
	}
}

func requireProjectImage(t *testing.T, d *DockerSandbox) {
	t.Helper()
	requireDocker(t)
	if err := exec.Command("docker", "image", "inspect", d.ProjectImage).Run(); err != nil {
		infraSkip(t, "project image %s not built (run `make docker-images`)", d.ProjectImage)
	}
}

// requireSnippetImage is requireProjectImage's missing counterpart for the snippet
// image. It checks every image the sandbox is configured with, not only the snippet
// image, because Preflight requires all of them before any run: with node:22-alpine
// present and the project image absent, a snippet test would otherwise fail on the
// missing project image. requireDocker proves only that the docker binary is on PATH; a machine can
// have docker installed and a daemon running without ever having pulled
// node:22-alpine, and then every snippet test fails reporting "image is not
// inspectable on the pinned daemon" — an infrastructure condition dressed up as a
// test failure, saying nothing about the code under test.
//
// That machine is not hypothetical: it is every hosted CI runner, and it is any
// contributor who installed docker and went straight to `go test ./...`. The
// project image already skipped correctly; this one did not, which is how the first
// CI run of .github/workflows/audit.yml failed (2026-09-10).
func requireSnippetImage(t *testing.T, d *DockerSandbox) {
	t.Helper()
	requireDocker(t)
	for _, img := range d.configuredImages() {
		if err := exec.Command("docker", "image", "inspect", img).Run(); err != nil {
			infraSkip(t, "image %s, which Preflight requires, is not present (run `make docker-images`)", img)
		}
	}
}

func TestRunProjectMultiFileTypeScript(t *testing.T) {
	d := testDocker()
	requireProjectImage(t, d)
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{
			{Path: "tsconfig.json", Content: `{"compilerOptions":{"strict":true,"noEmit":true,"module":"esnext","moduleResolution":"bundler","target":"es2022"}}`},
			{Path: "util.ts", Content: "export const add = (a: number, b: number): number => a + b;\n"},
			{Path: "main.ts", Content: "import { add } from './util';\nconsole.log('sum', add(2, 3));\n"},
		},
		Steps: []string{"tsc --noEmit", "tsx main.ts"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("outcome = %s (%s), want completed", res.Outcome, res.Detail)
	}
	if len(res.Steps) != 2 {
		t.Fatalf("ran %d steps, want 2: %+v", len(res.Steps), res.Steps)
	}
	if res.Steps[0].ExitCode != 0 {
		t.Fatalf("tsc exit = %d, stderr=%q", res.Steps[0].ExitCode, res.Steps[0].Stderr)
	}
	if !strings.Contains(res.Steps[1].Stdout, "sum 5") {
		t.Fatalf("run stdout = %q, want it to contain %q", res.Steps[1].Stdout, "sum 5")
	}
}

func TestRunProjectCapturesArtifacts(t *testing.T) {
	d := testDocker()
	requireProjectImage(t, d)
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{{Path: "gen.mjs", Content: "import {writeFileSync} from 'node:fs';\nwriteFileSync('out.txt','hello-artifact');\nwriteFileSync('bin.dat', Buffer.from([0,1,2,255]));\n"}},
		Steps: []string{"node gen.mjs"},
		// includes a missing path, which must be silently skipped
		Artifacts: []string{"out.txt", "bin.dat", "missing.txt"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("run failed: outcome=%s detail=%q steps=%+v", res.Outcome, res.Detail, res.Steps)
	}
	got := map[string][]byte{}
	for _, a := range res.Artifacts {
		got[a.Path] = a.Content
	}
	if len(res.Artifacts) != 2 {
		t.Fatalf("captured %d artifacts, want 2 (missing.txt skipped): %v", len(res.Artifacts), got)
	}
	if string(got["out.txt"]) != "hello-artifact" {
		t.Errorf("out.txt = %q, want hello-artifact", got["out.txt"])
	}
	if want := []byte{0, 1, 2, 255}; string(got["bin.dat"]) != string(want) {
		t.Errorf("bin.dat = %v, want %v (binary must survive)", got["bin.dat"], want)
	}
}

func TestRunProjectStopsChainOnFailure(t *testing.T) {
	d := testDocker()
	requireProjectImage(t, d)
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{{Path: "bad.ts", Content: "const x: number = \"nope\";\n"}},
		Steps: []string{"tsc --noEmit --strict bad.ts", "echo SHOULD_NOT_RUN"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Steps) != 1 {
		t.Fatalf("ran %d steps, want 1 (chain should stop on failure)", len(res.Steps))
	}
	if res.Steps[0].ExitCode == 0 {
		t.Fatalf("expected non-zero tsc exit on a type error")
	}
}

func TestRunProjectRejectsTraversalBeforeContainerStart(t *testing.T) {
	d := testDocker()
	_, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{{Path: "../escape.ts", Content: "x"}},
		Steps: []string{"true"},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("err = %v, want ErrInvalidRequest", err)
	}
}

// A caller that gives up on a Preflight (an unauthenticated /readyz poll that hangs
// up) must not take the kernel tier away: the probe runs detached from the caller's
// cancellation, so only a real failure invalidates the evidence (v0.15.0 review, M1).
func TestDockerPreflightIgnoresTheCallersCancellation(t *testing.T) {
	bin := t.TempDir()
	docker := filepath.Join(bin, "docker")
	slow := filepath.Join(bin, "slow")
	script := "#!/bin/sh\n[ \"$1\" = --config ] && shift 2\nif [ \"$1\" = context ]; then echo unix:///var/run/docker.sock; exit 0; fi\n" +
		"if [ \"$1\" = --host ] && [ \"$3\" = info ]; then if [ -f '" + slow + "' ]; then /bin/sleep 1; fi; echo '{\"runsc\":{\"path\":\"/usr/local/bin/runsc\"}}'; exit 0; fi\n" +
		"if [ \"$1\" = --host ] && [ \"$3\" = image ]; then echo '{\"Id\":\"sha256:d0cafe\",\"Config\":{}}'; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(docker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	d := DefaultDocker("")
	d.Runtime = "runsc"
	now := time.Unix(1_700_000_000, 0)
	d.preflightNow = func() time.Time { return now }
	if err := d.Preflight(context.Background()); err != nil || d.IsolationClass() != IsolationKernel {
		t.Fatalf("Preflight = %v, isolation %v; want kernel", err, d.IsolationClass())
	}
	now = now.Add(time.Minute) // past the readiness cache
	if err := os.WriteFile(slow, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	perr := d.Preflight(ctx)
	if got := d.IsolationClass(); got != IsolationKernel {
		t.Fatalf("a caller's cancellation dropped the tier to %v (Preflight: %v); want kernel", got, perr)
	}
}

// Guest code cannot pass its own exit for docker's: a snippet that prints docker's
// diagnostic and exits 125, 126 or 127 ran, so it is a result with that exit code,
// not an infrastructure error, and its stderr is exactly what it wrote (v0.15.0
// review, L7).
func TestDockerGuestCannotFakeAnInfrastructureExit(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	for _, code := range []int{125, 126, 127} {
		res, err := d.RunJavaScript(context.Background(), Request{Code: fmt.Sprintf(`process.stderr.write("docker: Error response from daemon: OCI runtime create failed\n"); process.exit(%d)`, code)})
		if err != nil {
			t.Fatalf("exit %d: an infrastructure error from guest code: %v", code, err)
		}
		if res.ExitCode != code || res.Stderr != "docker: Error response from daemon: OCI runtime create failed\n" {
			t.Fatalf("exit %d: result %+v", code, res)
		}
	}
}

// containerGone tells forceRemove it may stop retrying, so it says "gone" only for a
// name docker has no container under: never for a live container, and a name that is
// only a prefix of a live one's is a different name. Checked against the daemon.
func TestDockerContainerGoneByExactName(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := d.ensurePreflight(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := d.verifiedState()
	if err != nil {
		t.Fatal(err)
	}
	name := "crsbx-gonetest-" + randID()
	args, err := dockerArgs(state.host, "run", "-d", "--rm", "--name", name, "--entrypoint", "sleep", state.imageID, "60")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dockerOutput(ctx, args...); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.forceRemove(state.host, name) })
	if containerGone(state.host, name) {
		t.Fatal("a running container reads as gone")
	}
	if !containerGone(state.host, name[:len(name)-1]) {
		t.Fatal("a name that is only a prefix of a live container's reads as present")
	}
	d.forceRemove(state.host, name)
	if !containerGone(state.host, name) {
		t.Fatal("a removed container reads as present")
	}
}

// Every guest process runs as the guest uid and gid, a uid no host account uses, in a
// run's snippet and project step alike.
func TestDockerGuestRunsAsTheGuestUID(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	ctx := context.Background()
	want := fmt.Sprintf("%d %d", defaultGuestUID, defaultGuestUID)
	res, err := d.RunJavaScript(ctx, Request{Code: `console.log(process.getuid(), process.getgid())`})
	if err != nil || strings.TrimSpace(res.Stdout) != want {
		t.Fatalf("snippet: %+v, %v; want %q", res, err, want)
	}
	pres, err := d.RunProject(ctx, ProjectRequest{Steps: []string{`node -e 'console.log(process.getuid(), process.getgid())'`}})
	if err != nil || len(pres.Steps) != 1 || strings.TrimSpace(pres.Steps[0].Stdout) != want {
		t.Fatalf("project step: %+v, %v; want %q", pres, err, want)
	}

	// A uid the image names gets its passwd home, as docker gives it: the start
	// script's lookup, read from the kernel's /proc/self/status. Here uid 1000, node
	// in the image; this host's accounts are taken out of the check.
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prev, prevGroup := hostPasswdPath, hostGroupPath
	hostPasswdPath, hostGroupPath = empty, empty
	defer func() { hostPasswdPath, hostGroupPath = prev, prevGroup }()
	named := testDocker()
	named.GuestUID = 1000
	res, err = named.RunJavaScript(ctx, Request{Code: `console.log(process.getuid(), process.env.HOME)`})
	if err != nil || strings.TrimSpace(res.Stdout) != "1000 /home/node" {
		t.Fatalf("a uid the image names: %+v, %v; want 1000 /home/node", res, err)
	}
}
