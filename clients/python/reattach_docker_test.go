package python

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestPythonReattachDocker runs tests/docker_reattach_check.py, session reattach across
// processes on a real docker session (step R6 of the sessions builds plan), against a
// daemon served here on the docker provider with sessions on, its callers from a callers
// file and its audit log written to a file the check reads: one process opens a session
// and exits without closing it, another takes it over by its key and reads the file the
// first wrote, a third from the first's old checkpoint is refused as stale, a worker that
// still holds a session another process took over is refused before its call runs (the
// audit log shows no such call), and open development mode refuses the takeover. Skips in
// -short mode and without docker or its images; fails instead under
// SANDBOX_TEST_REQUIRE_DOCKER=1, which `make docker-suite` sets.
func TestPythonReattachDocker(t *testing.T) {
	t.Parallel()
	skip := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker coverage was required (SANDBOX_TEST_REQUIRE_DOCKER=1) but its infrastructure is missing: "+format, args...)
		}
		t.Skipf(format, args...)
	}
	if testing.Short() {
		skip("skipping the docker reattach check in -short mode")
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
	d.ProjectImage = "plimsoll/sandbox-python:latest" // the cells are Python
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
	// Registered before the daemons are served, so it runs after they close: whatever
	// session a case left open, pass or fail, is closed and its container removed. A
	// session left open goes idle, the daemon pauses its container, and a paused container
	// outlived this test with the docker exec attached to it until 2026-11-20 (the check's
	// first case never closed its session); the docker suites now fail on such a container
	// (suiterun leftovers).
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
		defer dcancel()
		if err := d.Drain(dctx); err != nil {
			t.Errorf("draining the docker sandbox: %v", err)
		}
	})
	dir := t.TempDir()

	// The callers file plimsolld reads (PLIMSOLL_CLIENTS_FILE): one caller, by its
	// token's SHA-256.
	const token = "docker-reattach-check-token"
	sum := sha256.Sum256([]byte(token))
	callers, err := json.Marshal(map[string]any{"clients": []map[string]any{{"id": "docker-check", "token_sha256": hex.EncodeToString(sum[:]), "scopes": []string{rpc.ScopeCodeRun}}}})
	if err != nil {
		t.Fatal(err)
	}
	callersPath := filepath.Join(dir, "callers.json")
	if err := os.WriteFile(callersPath, callers, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := rpc.LoadClients(callersPath)
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")
	audit, err := os.Create(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = audit.Close() })
	svc := rpc.NewSandboxService(d)
	svc.Logger = slog.New(slog.NewJSONHandler(audit, nil))
	svc.Sessions = rpc.SessionConfig{MaxSessions: 8, Lifetime: 10 * time.Minute, IdleTimeout: 2 * time.Minute}
	url := clientsuite.Serve(t, svc, verifier, nil)

	// Open development mode: no callers file and no token.
	dev := clientsuite.Quiet(rpc.NewSandboxService(d))
	dev.Sessions = rpc.SessionConfig{MaxSessions: 2, Lifetime: 10 * time.Minute, IdleTimeout: 2 * time.Minute}
	mux := http.NewServeMux()
	path, handler := rpc.NewHandler(dev, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, handler)
	devSrv := httptest.NewServer(mux)
	t.Cleanup(devSrv.Close)

	cmd := exec.Command(python, "-B", "-m", "unittest", "tests.docker_reattach_check", "-v")
	cmd.Env = append(os.Environ(),
		"PLIMSOLL_DOCKER_REATTACH_URL="+url,
		"PLIMSOLL_DOCKER_REATTACH_TOKEN="+token,
		"PLIMSOLL_DOCKER_DEVMODE_URL="+devSrv.URL,
		"PLIMSOLL_DOCKER_AUDIT_LOG="+auditPath,
		"PLIMSOLL_DOCKER_REATTACH_DIR="+dir,
		"PLIMSOLL_DOCKER_REQUIRED=1",
		"PYTHONPATH=src",
		"PYTHONDONTWRITEBYTECODE=1",
	)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("python3 -m unittest tests.docker_reattach_check: %v", err)
	}
	if pythonSkip.Match(out) {
		t.Fatal("the docker reattach check skipped a case; under this test every case must run")
	}
}
