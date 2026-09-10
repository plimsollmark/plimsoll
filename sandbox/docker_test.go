package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireDocker(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping docker sandbox test in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
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
	if !strings.Contains(strings.Join(d.lockdownArgs("c", false, d.Runtime), " "), "--security-opt seccomp=/etc/crsbx/seccomp.json") {
		t.Error("configured seccomp profile not applied under runc")
	}
	d.Runtime = "runsc"
	if strings.Contains(strings.Join(d.lockdownArgs("c", false, d.Runtime), " "), "seccomp=") {
		t.Error("gVisor run should not also apply a host seccomp profile")
	}
}

func TestDockerLockdownDisablesDaemonLogStorage(t *testing.T) {
	d := DefaultDocker("")
	args := strings.Join(d.lockdownArgs("c", false, d.Runtime), " ")
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
				Index int    `json:"index"`
				Value uint64 `json:"value"`
				Op    string `json:"op"`
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
	} {
		if !allowed[n] {
			t.Errorf("essential syscall %q is not allowed — the profile would break the workload", n)
		}
	}
	// Tightening: these are NOT cap-gated (cap-drop ALL does not stop them) and the
	// workload never uses them, so a hardened profile must withhold them. ptrace and
	// process_vm_* read other same-uid processes; io_uring/userfaultfd are prime
	// exploit primitives; keyctl/add_key touch the kernel keyring; the rest are
	// namespace/module/kexec/mount escape surface.
	for _, n := range []string{
		"ptrace", "process_vm_readv", "process_vm_writev",
		"io_uring_setup", "io_uring_enter", "io_uring_register",
		"userfaultfd", "perf_event_open", "bpf",
		"keyctl", "add_key", "request_key",
		"unshare", "setns", "mount", "umount2", "pivot_root", "chroot",
		"kexec_load", "init_module", "finit_module", "reboot", "swapon",
		"modify_ldt", "name_to_handle_at", "open_by_handle_at", "clone3",
	} {
		if allowed[n] {
			t.Errorf("syscall %q is allowed but should be denied by the hardened profile", n)
		}
	}
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
		t.Skip("docker not on PATH")
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
	if err := os.WriteFile(docker, []byte("#!/bin/sh\necho tcp://10.0.0.9:2375\n"), 0o755); err != nil {
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
	script := "#!/bin/sh\nif [ \"$1\" = context ]; then echo unix:///var/run/docker.sock; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = info ]; then echo '{\"runc\":{\"path\":\"runc\"}}'; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = image ]; then echo '{\"Id\":\"sha256:d0cafe\",\"Config\":{}}'; exit 0; fi\nexit 1\n"
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
	badRunsc := "#!/bin/sh\nif [ \"$1\" = context ]; then echo unix:///var/run/docker.sock; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = info ]; then echo '{\"runsc\":{\"path\":\"runc\"}}'; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = image ]; then echo '{\"Id\":\"sha256:d0cafe\",\"Config\":{}}'; exit 0; fi\nexit 1\n"
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

	goodRunsc := "#!/bin/sh\nif [ \"$1\" = context ]; then echo unix:///var/run/docker.sock; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = info ]; then echo '{\"runsc\":{\"path\":\"/usr/local/bin/runsc\"}}'; exit 0; fi\nif [ \"$1\" = --host ] && [ \"$3\" = image ]; then echo '{\"Id\":\"sha256:d0cafe\",\"Config\":{}}'; exit 0; fi\nexit 1\n"
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
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = context ]; then IFS= read -r endpoint < \"$CR_CONTEXT_FILE\"; echo \"$endpoint\"; exit 0; fi\n" +
		"if [ \"$1\" = --host ] && [ \"$3\" = info ]; then echo \"$2\" >> \"$CR_HOST_LOG\"; if [ -f \"$CR_FAIL_FILE\" ]; then exit 1; fi; echo '{\"runsc\":{\"path\":\"runsc\"}}'; exit 0; fi\n" +
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
	t.Setenv("CR_CONTEXT_FILE", contextFile)
	t.Setenv("CR_FAIL_FILE", failFile)
	t.Setenv("CR_HOST_LOG", logFile)

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

func TestDockerPreflightDoesNotQueueConcurrentCallers(t *testing.T) {
	d := DefaultDocker("")
	d.preflightMu.Lock()
	defer d.preflightMu.Unlock()

	started := time.Now()
	err := d.Preflight(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("err = %v, want an in-progress readiness error", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("concurrent Preflight queued for %v instead of failing quickly", elapsed)
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
	d.lastVerified = now.Add(-dockerPreflightCacheTTL)
	d.stateMu.Unlock()

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
		t.Skip("docker not on PATH")
	}
	t.Setenv("DOCKER_HOST", "tcp://10.0.0.5:2375")
	d := DefaultDocker("")
	if err := d.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "remote daemon") {
		t.Fatalf("err = %v, want a remote-daemon rejection", err)
	}
}

func TestDockerInfraExitClassification(t *testing.T) {
	for _, tc := range []struct {
		code   int
		stderr string
		want   bool
	}{
		{125, "docker: Error response from daemon: no such image", true},
		{126, "OCI runtime create failed: exec: not executable", true},
		{127, "docker: executable file not found in $PATH", true},
		{127, "MyError: process.exit(127) from user code", false}, // guest exit, no docker marker
		{1, "docker: Error response from daemon", false},          // ordinary non-zero code
		{125, "", false}, // 125 but no docker diagnostic
	} {
		if got := dockerInfraExit(tc.code, tc.stderr); got != tc.want {
			t.Errorf("dockerInfraExit(%d, %q) = %v, want %v", tc.code, tc.stderr, got, tc.want)
		}
	}
}

func TestDockerRunCapturesStdoutAndExitZero(t *testing.T) {
	requireDocker(t)
	d := testDocker()
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
	requireDocker(t)
	d := testDocker()
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
	requireDocker(t)
	d := testDocker()
	d.DefaultTimeout = 1 * time.Second
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
	if err != ErrDisabled {
		t.Fatalf("err = %v, want ErrDisabled", err)
	}
	if _, err := (Disabled{}).RunProject(context.Background(), ProjectRequest{Steps: []string{"true"}}); err != ErrDisabled {
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
		t.Skipf("project image %s not built (run `docker build -t %s docker/`)", d.ProjectImage, d.ProjectImage)
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
