package python

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// frameworkDocker serves a daemon on the docker provider, sessions on, for a framework's
// check on real docker sessions, run with the framework's environment tmp/py-frameworks/<name>
// (make py-frameworks), with projectImage as the daemon's project image. It returns the
// environment's python, the daemon's URL and the tier the docker runtime gives: container
// under runc, kernel under runsc.
//
// make docker-suite runs these checks, under runc and, in the gvisor workflow, under runsc,
// with SANDBOX_TEST_REQUIRE_DOCKER=1: there a missing docker, image or environment fails the
// test instead of skipping it, and the suite fails on any skipped Go test. make clients-suite
// excludes them by name (DOCKER_PY_TESTS in the Makefile), since CI's clients job builds no
// images. Elsewhere they skip in -short mode and without docker, its images or the
// environment.
func frameworkDocker(t *testing.T, name, projectImage string) (python, url, floor string) {
	t.Helper()
	return frameworkDockerAs(t, name, projectImage, "")
}

// frameworkDockerToken is the one token frameworkDockerAs's daemon accepts when it is given
// one: a takeover of a session needs an authenticated caller.
type frameworkDockerToken string

func (v frameworkDockerToken) VerifyToken(_ context.Context, token string) (rpc.Principal, bool, error) {
	if token != string(v) {
		return rpc.Principal{}, false, nil
	}
	return rpc.Principal{UserID: "framework-docker", Scopes: []string{rpc.ScopeCodeRun}}, true, nil
}

// frameworkDockerAs is frameworkDocker behind token, or with no authentication at all
// (open development mode) when token is empty.
func frameworkDockerAs(t *testing.T, name, projectImage, token string) (python, url, floor string) {
	t.Helper()
	skip := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker coverage was required (SANDBOX_TEST_REQUIRE_DOCKER=1) but its infrastructure is missing: "+format, args...)
		}
		t.Skipf(format, args...)
	}
	if testing.Short() {
		skip("skipping the %s docker check in -short mode", name)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skip("docker not available")
	}
	python, err := filepath.Abs(filepath.Join("..", "..", "tmp", "py-frameworks", name, "bin", "python"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(python); err != nil {
		skip("no %s environment at %s: run make py-frameworks PY_FRAMEWORKS=%s", name, python, name)
	}
	d := sandbox.DefaultDocker("")
	d.ProjectImage = projectImage
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
	floor = "container"
	if d.IsolationClass() == sandbox.IsolationKernel {
		floor = "kernel"
	}
	svc := clientsuite.Quiet(rpc.NewSandboxService(d))
	svc.Sessions = rpc.SessionConfig{MaxSessions: 4, Lifetime: 20 * time.Minute, IdleTimeout: 5 * time.Minute}
	var verifier rpc.TokenVerifier
	if token != "" {
		verifier = frameworkDockerToken(token)
	}
	return python, clientsuite.Serve(t, svc, verifier, nil), floor
}

// frameworkDockerCheck runs a framework's unittest docker check (module, under
// frameworks/<name>/) with python against url, and fails unless exactly cases ran and every
// one passed.
func frameworkDockerCheck(t *testing.T, python, url, floor, module string, cases int) {
	t.Helper()
	cmd := exec.Command(python, "-B", "-m", "unittest", "-v", module)
	cmd.Env = frameworkDockerEnv(url, floor)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("python -m unittest %s: %v", module, err)
	}
	if unittestNotRun.Match(out) {
		t.Fatalf("%s skipped a case or marked one an expected failure; under this test every case must run and pass", module)
	}
	if !regexp.MustCompile(`(?m)^Ran ` + strconv.Itoa(cases) + ` tests? in `).Match(out) {
		t.Fatalf("%s: expected %d cases to run", module, cases)
	}
}

// frameworkDockerEnv is the environment a framework's docker check runs in: this process's,
// less the tracing settings withoutTracing drops (as the ADK and example checks run), so no
// check can send its runs to a tracing service, then the daemon's URL and the floor.
func frameworkDockerEnv(url, floor string) []string {
	return append(withoutTracing(os.Environ()),
		"PLIMSOLL_DOCKER_SESSIONS_URL="+url,
		"PLIMSOLL_DOCKER_FLOOR="+floor,
		"PYTHONPATH=src",
		"PYTHONDONTWRITEBYTECODE=1",
	)
}

// TestFrameworkDockerEnvDropsTracing: the docker checks' environment carries no tracing setting
// of the caller's (review finding release-35), and does carry the daemon's URL and the floor.
func TestFrameworkDockerEnvDropsTracing(t *testing.T) {
	t.Setenv("LANGSMITH_TRACING", "true")
	t.Setenv("LANGCHAIN_API_KEY", "lsv2-not-a-key")
	t.Setenv("OPENAI_AGENTS_DISABLE_TRACING", "0")
	env := strings.Join(frameworkDockerEnv("http://127.0.0.1:9", "kernel"), "\n")
	for _, name := range []string{"LANGSMITH_TRACING=", "LANGCHAIN_API_KEY=", "OPENAI_AGENTS_DISABLE_TRACING="} {
		if strings.Contains(env, name) {
			t.Errorf("the docker checks' environment carries %s", name)
		}
	}
	for _, want := range []string{"PLIMSOLL_DOCKER_SESSIONS_URL=http://127.0.0.1:9", "PLIMSOLL_DOCKER_FLOOR=kernel"} {
		if !strings.Contains(env, want) {
			t.Errorf("the docker checks' environment lacks %s", want)
		}
	}
}

// TestPythonDocsNameTheSuiteOfEachDockerCheck: no sentence in the Python client's guide or in a
// check on a real docker session says one of the Makefile's DOCKER_PY_TESTS runs in make
// clients-suite, which excludes them (review finding release-26: the guide and the OpenAI check
// did, so a contributor running clients-suite would believe a path was tested that was not run).
// A sentence that says clients-suite excludes them is the one allowed form.
func TestPythonDocsNameTheSuiteOfEachDockerCheck(t *testing.T) {
	makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^DOCKER_PY_TESTS := (.+)$`).FindSubmatch(makefile)
	if m == nil {
		t.Fatal("no DOCKER_PY_TESTS in the Makefile")
	}
	names := strings.Split(strings.TrimSpace(string(m[1])), "|")
	files := []string{"README.md"}
	for _, pattern := range []string{"*_docker_test.go", filepath.Join("frameworks", "*", "docker_*_check.py"), filepath.Join("tests", "docker_*check.py")} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, found...)
	}
	sentence := regexp.MustCompile(`[^.!?:;]+`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(b)), " ")
		for _, s := range sentence.FindAllString(text, -1) {
			if !strings.Contains(s, "clients-suite") || strings.Contains(s, "exclud") {
				continue
			}
			for _, name := range names {
				if strings.Contains(s, name) {
					t.Errorf("%s says %s runs in clients-suite, which excludes it (it is docker-suite's): %q", f, name, strings.TrimSpace(s))
				}
			}
		}
	}
}

var unittestNotRun = regexp.MustCompile(`(?m)\.\.\. (skipped|expected failure|unexpected success)|(skipped|expected failures|unexpected successes)=[0-9]+`)

// TestAgentFrameworkDocker runs frameworks/agent_framework/docker_agent_framework_check.py
// on each of plimsoll's two project images: the Agent Framework harness's
// ShellEnvironmentProvider probes BusyBox sh through PlimsollShellTool and builds its snapshot
// (the probes' output is in this test's log, and the CLIs it finds differ by image), a
// scripted harness agent's two commands share a file, the agent's file tools over
// PlimsollFileStore and its shell see one tree, each of the store's refusals holds against
// links, a sparse file and the workspace's state made in BusyBox, a folder swapped for a link
// out by the session's kept interpreter is never read through, and a recursive search of 5,000
// files and a listing and search of 60,000 names end inside the framework's 10-second bound.
func TestAgentFrameworkDocker(t *testing.T) {
	t.Parallel()
	for _, image := range []string{"plimsoll/sandbox:latest", "plimsoll/sandbox-python:latest"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			python, url, floor := frameworkDocker(t, "agent_framework", image)
			frameworkDockerCheck(t, python, url, floor, "frameworks.agent_framework.docker_agent_framework_check", 7)
		})
	}
}
