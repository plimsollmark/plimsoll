package python

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestADKEnvironmentDocker runs frameworks/adk/docker_adk_check.py with the ADK framework
// environment against a daemon served here on the docker provider, sessions on, with the
// default project image (the environment needs no Python in the sandbox): Google ADK's real
// tools, toolset and Runner over PlimsollEnvironment on a real session, the same command
// script on ADK's LocalEnvironment, and a scripted agent whose files persist between calls.
// Skips in -short mode and without docker, its images or the environment; fails instead
// under SANDBOX_TEST_REQUIRE_DOCKER=1, which `make docker-suite` sets.
func TestADKEnvironmentDocker(t *testing.T) {
	t.Parallel()
	skip := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker coverage was required (SANDBOX_TEST_REQUIRE_DOCKER=1) but its infrastructure is missing: "+format, args...)
		}
		t.Skipf(format, args...)
	}
	if testing.Short() {
		skip("skipping the ADK environment's docker check in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skip("docker not available")
	}
	python, err := filepath.Abs(filepath.Join("..", "..", "tmp", "py-frameworks", "adk", "bin", "python"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(python); err != nil {
		skip("no adk environment at %s: run make py-frameworks PY_FRAMEWORKS=adk", python)
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
	// The environment's default floor is kernel; docker under runc is the container tier.
	floor := "container"
	if d.IsolationClass() == sandbox.IsolationKernel {
		floor = "kernel"
	}
	svc := clientsuite.Quiet(rpc.NewSandboxService(d))
	svc.Sessions = rpc.SessionConfig{MaxSessions: 4, Lifetime: 10 * time.Minute, IdleTimeout: 5 * time.Minute}
	url := clientsuite.Serve(t, svc, nil, nil)

	cmd := exec.Command(python, "-B", "-m", "unittest", "frameworks.adk.docker_adk_check", "-v")
	cmd.Env = append(withoutTracing(os.Environ()),
		"PLIMSOLL_DOCKER_SESSIONS_URL="+url,
		"PLIMSOLL_DOCKER_FLOOR="+floor,
		"PLIMSOLL_DOCKER_REQUIRED=1",
		"PYTHONPATH=src",
		"PYTHONDONTWRITEBYTECODE=1",
	)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("python -m unittest frameworks.adk.docker_adk_check: %v", err)
	}
	if pythonSkip.Match(out) {
		t.Fatal("the ADK environment's docker check skipped a case; under this test every case must run")
	}
}
