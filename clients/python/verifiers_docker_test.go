package python

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestVerifiersRuntimeDocker runs frameworks/verifiers/docker_check.py, the verifiers
// runtime plugin on real docker sessions: the plimsoll-sum environment through
// verifiers' own vf-validate (setup, the gold answer, an untouched task graded in a fresh
// sandbox) with every call's record logged and the log rechecked. It needs the docker
// images and the verifiers environment that make py-frameworks builds
// (tmp/py-frameworks/verifiers; make docker-suite builds it). Skips in -short mode and
// without either; fails instead under SANDBOX_TEST_REQUIRE_DOCKER=1, as docker-suite runs
// it. clients-suite excludes it, as it does TestPythonWorkspaceDocker: its CI job has no
// images. The check is not a test_*.py, so the framework suite's discover run never sees it.
func TestVerifiersRuntimeDocker(t *testing.T) {
	skip := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker coverage was required (SANDBOX_TEST_REQUIRE_DOCKER=1) but the verifiers check's infrastructure is missing: "+format, args...)
		}
		t.Skipf(format, args...)
	}
	if testing.Short() {
		skip("skipping the verifiers docker check in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skip("docker not available")
	}
	python, err := filepath.Abs(filepath.Join("..", "..", "tmp", "py-frameworks", "verifiers", "bin", "python"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(python); err != nil {
		skip("no verifiers environment at %s: run make py-frameworks PY_FRAMEWORKS=verifiers", python)
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
	floor := "container"
	if d.Runtime == "runsc" {
		floor = "kernel"
	}

	cmd := exec.Command(python, "-B", "-m", "unittest", "frameworks.verifiers.docker_check", "-v")
	cmd.Env = append(os.Environ(),
		"PLIMSOLL_DOCKER_SESSIONS_URL="+url,
		"PLIMSOLL_DOCKER_FLOOR="+floor,
		"PLIMSOLL_VERIFIERS_OUT="+t.TempDir(),
		"PLIMSOLL_DOCKER_REQUIRED=1",
		"PYTHONPATH=src",
		"PYTHONDONTWRITEBYTECODE=1",
	)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("python -m unittest frameworks.verifiers.docker_check: %v", err)
	}
	if pythonSkip.Match(out) {
		t.Fatal("the verifiers docker check skipped a case; under this test every case must run")
	}
}
