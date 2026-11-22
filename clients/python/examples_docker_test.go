package python

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestPythonExamplesDocker runs each example program in examples/ (one per agent kit),
// as a newcomer would run it, with that kit's framework environment, against a daemon
// served here on the docker provider: sessions on, plimsoll/sandbox-python as the project
// image. Every example drives its kit with a scripted stand-in for the model, so nothing
// calls a model service, and each must print the line its one piece of code printed in
// the sandbox. The CrewAI example writes CrewAI's settings under HOME, so each run gets a
// HOME of its own. make docker-suite runs it (DOCKER_PY_TESTS in the Makefile), under runc
// and, in the gvisor workflow, under runsc; clients-suite excludes it, since CI's clients job
// builds no images. Skips in -short mode and without docker, its images or an environment;
// fails instead under SANDBOX_TEST_REQUIRE_DOCKER=1.
func TestPythonExamplesDocker(t *testing.T) {
	t.Parallel()
	skip := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker coverage was required (SANDBOX_TEST_REQUIRE_DOCKER=1) but its infrastructure is missing: "+format, args...)
		}
		t.Skipf(format, args...)
	}
	if testing.Short() {
		skip("skipping the example programs' docker check in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skip("docker not available")
	}
	examples := []struct {
		file, env string // the program, and the framework environment (tmp/py-frameworks/<env>) it runs in
		path      []string
		want      []string // what its output must hold
	}{
		// The LangChain example needs langchain's create_agent, which the deepagents
		// environment has (the langchain one holds langchain-core alone).
		{file: "langchain_tool.py", env: "deepagents", want: []string{`"ran": true`, "6 x 7 = 42", `"record_sha256"`}},
		// LangGraph's retry policy under plimsoll's rule: a capacity refusal is retried and the
		// second try runs, an answer lost after sending is not (LangGraph's own rule would), and
		// the daemon's real isolation refusal is not; then the labels a traced tool call puts on
		// its LangSmith run, kept in memory, never sent.
		{file: "langchain_retry_guard.py", env: "deepagents", want: []string{
			"capacity refusal (stand-in): retry_on says True",
			"capacity refusal (stand-in): the node ran 2 time(s): 6 x 7 = 42",
			"answer lost after sending (stand-in): retry_on says False, LangGraph's default rule says True",
			"answer lost after sending (stand-in): the node ran 1 time(s): raised TransportError (not_dispatched=None)",
			"tier (real): retry_on says False",
			"tier (real): the node ran 1 time(s): raised InsufficientIsolationError (not_dispatched=isolation)",
			"the tool answered the model: 6 x 7 = 42",
			`"plimsoll_dispatched": "yes"`, `"plimsoll_outcome": "completed"`, `"plimsoll_record_sha256": "`,
		}},
		{file: "agno_tool.py", env: "agno", want: []string{`"ran": true`, "6 x 7 = 42", `"record_sha256"`}},
		{file: "crewai_tool.py", env: "crewai", path: []string{filepath.Join("crewai-plimsoll", "src")},
			want: []string{`"ran": true`, "6 x 7 = 42", `"record_sha256"`}},
		{file: "adk_executor.py", env: "adk", want: []string{"OUTCOME_OK", "6 x 7 = 42"}},
		{file: "adk_environment.py", env: "adk", want: []string{"6 x 7 = 42", "7 x 6 = 42", "plimsoll: execute ran behind", "record "}},
		{file: "openai_agents_sandbox.py", env: "openai_agents", want: []string{"Process exited with code 0", "6 x 7 = 42"}},
		// The second command reads the file the first wrote, and the record's digest reached
		// the application beside the model's text.
		{file: "agent_framework_shell.py", env: "agent_framework",
			want: []string{`'exit code: 0\n6 x 7 = 42'`, `'plimsoll_dispatched': 'yes'`, `'plimsoll_outcome': 'completed'`, `'plimsoll_record_sha256': '`}},
		// The second step reads the variable the first set, in the session's one interpreter, and
		// each cell's record reached the application, ending where the session's chain ends.
		{file: "smolagents_executor.py", env: "smolagents",
			want: []string{"6 x 7 = 42 in Python 3.", "the agent said: 42", ", completed, record sha256 ", "the last record ends the session's chain: True"}},
		// PydanticAI's FileSystem writes the script and plimsoll's shell tool runs it in the same session; the
		// record's digest reached the application in the tool return's metadata.
		{file: "pydantic_ai_workspace.py", env: "pydantic_ai",
			want: []string{`'exit code: 0\n6 x 7 = 42'`, `'plimsoll_dispatched': 'yes'`, `'plimsoll_outcome': 'completed'`, `'plimsoll_record_sha256': '`}},
	}
	pythons := map[string]string{}
	for _, ex := range examples {
		python, err := filepath.Abs(filepath.Join("..", "..", "tmp", "py-frameworks", ex.env, "bin", "python"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(python); err != nil {
			skip("no %s environment at %s: run make py-frameworks", ex.env, python)
		}
		pythons[ex.file] = python
	}
	d := sandbox.DefaultDocker("")
	d.ProjectImage = "plimsoll/sandbox-python:latest"
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
	// The examples default to the kernel floor; docker under runc is the container tier.
	floor := "container"
	if d.IsolationClass() == sandbox.IsolationKernel {
		floor = "kernel"
	}
	svc := clientsuite.Quiet(rpc.NewSandboxService(d))
	// Ten: the nine examples that open a session and the OpenAI Agents SDK check below run
	// at once, one session each at a time at most (langchain_retry_guard.py opens none).
	svc.Sessions = rpc.SessionConfig{MaxSessions: 10, Lifetime: 10 * time.Minute, IdleTimeout: 5 * time.Minute}
	url := clientsuite.Serve(t, svc, nil, nil)

	// The granted examples, on a daemon of their own (examples_granted_docker_test.go).
	t.Run("granted", func(t *testing.T) {
		t.Parallel()
		runGrantedExamples(t, d, floor)
	})

	for _, ex := range examples {
		t.Run(strings.TrimSuffix(ex.file, ".py"), func(t *testing.T) {
			t.Parallel()
			cmd := exec.Command(pythons[ex.file], "-B", filepath.Join("examples", ex.file))
			cmd.Env = append(os.Environ(),
				"PLIMSOLL_URL="+url,
				"PLIMSOLL_MIN_ISOLATION="+floor,
				"PYTHONPATH="+strings.Join(append([]string{"src"}, ex.path...), string(os.PathListSeparator)),
				"PYTHONDONTWRITEBYTECODE=1",
				"HOME="+t.TempDir(),
			)
			out, err := cmd.CombinedOutput()
			t.Logf("%s", out)
			if err != nil {
				t.Fatalf("python examples/%s: %v", ex.file, err)
			}
			for _, w := range ex.want {
				if !strings.Contains(string(out), w) {
					t.Errorf("examples/%s printed no %q", ex.file, w)
				}
			}
		})
	}

	// The OpenAI Agents SDK provider's own checks on the same daemon, the ones OpenAI's
	// provider guide asks for on a real sandbox ("Mock tests cannot establish those
	// properties"): the SDK's Runner with its ScriptedModel through the shell, apply_patch
	// and view_image tools, each command's labels and record in the SDK's events and spans,
	// its file helpers, no network, a read-only system, no background process outliving a
	// command, a timeout, a command cut in flight, and a stop and resume
	// (frameworks/openai_agents/docker_openai_check.py).
	t.Run("openai_agents_check", func(t *testing.T) {
		t.Parallel()
		cmd := exec.Command(pythons["openai_agents_sandbox.py"], "-B", "-m", "unittest", "frameworks.openai_agents.docker_openai_check", "-v")
		cmd.Env = append(withoutTracing(os.Environ()),
			"PLIMSOLL_DOCKER_SESSIONS_URL="+url,
			"PLIMSOLL_DOCKER_FLOOR="+floor,
			"PYTHONPATH=src",
			"PYTHONDONTWRITEBYTECODE=1",
		)
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		if err != nil {
			t.Fatalf("python -m unittest frameworks.openai_agents.docker_openai_check: %v", err)
		}
		if pythonSkip.Match(out) {
			t.Fatal("the OpenAI Agents SDK docker check skipped a case; under this test every case must run")
		}
	})
}
