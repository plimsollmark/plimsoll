package python

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// fakeSessionsURL serves a daemon on the in-memory session provider with sessions on,
// for a suite that opens and closes sessions without running anything in them (the
// framework adapters that serve a shell over a session).
func fakeSessionsURL(t *testing.T) string {
	t.Helper()
	svc := quiet(rpc.NewSandboxService(&sandboxtest.Sessions{}))
	svc.Sessions = rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Minute}
	return serve(t, svc, nil, nil)
}

// TestPythonWorkspaceDocker runs tests/docker_workspace_check.py, the agent
// workspace's fixed scripts on a real docker session, against a daemon served here
// on the docker provider with sessions on: the shell's directory and exports
// persisting across calls, files, search, edit, persist into another session, and a
// background process not outliving its call. The check is not a test_*.py, so the
// discover run of TestPythonClient never sees it. Skips in -short mode and without
// docker or its images; fails instead under SANDBOX_TEST_REQUIRE_DOCKER=1, which
// `make docker-suite` sets.
func TestPythonWorkspaceDocker(t *testing.T) {
	skip := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker coverage was required (SANDBOX_TEST_REQUIRE_DOCKER=1) but its infrastructure is missing: "+format, args...)
		}
		t.Skipf(format, args...)
	}
	if testing.Short() {
		skip("skipping the docker workspace check in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skip("docker not available")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		skip("python3 is not installed")
	}
	if out, err := exec.Command(python, "-c", "import sys; sys.exit(sys.version_info < (3, 10))").CombinedOutput(); err != nil {
		skip("python3 is older than 3.10: %v %s", err, out)
	}
	d := sandbox.DefaultDocker("")
	d.Runtime = os.Getenv("SANDBOX_DOCKER_RUNTIME")
	d.Seccomp = os.Getenv("SANDBOX_DOCKER_SECCOMP")
	for _, img := range []string{d.Image, d.ProjectImage} {
		if err := exec.Command("docker", "image", "inspect", img).Run(); err != nil {
			skip("image %s is not present (run `make docker-images`)", img)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := (sandbox.Provider{Sandbox: d}).EnsureReady(ctx); err != nil {
		t.Fatalf("docker provider not ready: %v", err)
	}
	svc := quiet(rpc.NewSandboxService(d))
	svc.Sessions = rpc.SessionConfig{MaxSessions: 4, Lifetime: 10 * time.Minute, IdleTimeout: 2 * time.Minute}
	url := serve(t, svc, nil, nil)

	cmd := exec.Command(python, "-B", "-m", "unittest", "tests.docker_workspace_check", "-v")
	cmd.Env = append(os.Environ(),
		"PLIMSOLL_DOCKER_SESSIONS_URL="+url,
		"PLIMSOLL_DOCKER_REQUIRED=1",
		"PYTHONPATH=src",
		"PYTHONDONTWRITEBYTECODE=1",
	)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("python3 -m unittest tests.docker_workspace_check: %v", err)
	}
	if pythonSkip.Match(out) {
		t.Fatal("the docker workspace check skipped a case; under this test every case must run")
	}
}
