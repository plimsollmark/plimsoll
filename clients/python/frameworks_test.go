package python

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// TestPythonFrameworks runs each framework adapter's suite, frameworks/<name>/, with
// that framework installed: a virtual environment per framework at
// tmp/py-frameworks/<name> (make clients-suite builds it from the directory's
// requirements.txt), since the client itself has no dependencies and the frameworks'
// own conflict. A framework is a directory, so adding one needs no change here.
//
// The suites call each tool through the framework's own tool-call path, with no model,
// against two daemons behind the real RPC handler:
//
//   - echo: a container-tier provider that runs nothing and answers each project
//     with what it was asked to run, or with the failure a marker in the code names;
//     its handler can hold a Describe or a Run until a test releases it (holds);
//   - wasm: the real wasm provider, which runs no projects.
func TestPythonFrameworks(t *testing.T) {
	dirs, err := filepath.Glob("frameworks/*/requirements.txt")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no framework suites under frameworks/: %v", err)
	}
	env := append(os.Environ(),
		"PLIMSOLL_ECHO_URL="+serve(t, echoService{quiet(rpc.NewSandboxService(projectEcho{}))}, nil, func(mux *http.ServeMux) {
			// How many projects the echo provider was handed: a test that says a call
			// was not retried counts dispatches instead of trusting a note.
			mux.HandleFunc("GET /test/project-runs", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(strconv.FormatInt(echoRuns.Load(), 10)))
			})
			// Every Describe from now on waits until /test/release.
			mux.HandleFunc("POST /test/hold-describe", func(http.ResponseWriter, *http.Request) { echoHolds.holdDescribe() })
			mux.HandleFunc("POST /test/release", func(http.ResponseWriter, *http.Request) { echoHolds.releaseAll() })
			mux.HandleFunc("GET /test/holds", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(echoHolds.state())
			})
		}),
		"PLIMSOLL_WASM_URL="+serve(t, quiet(rpc.NewSandboxService(sandboxtest.Wasm())), nil, nil),
		"PLIMSOLL_INTEGRATION_REQUIRED=1",
		"PYTHONPATH=src",
		"PYTHONDONTWRITEBYTECODE=1",
	)
	for _, req := range dirs {
		dir := filepath.Dir(req)
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			python, err := filepath.Abs(filepath.Join("..", "..", "tmp", "py-frameworks", name, "bin", "python"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(python); err != nil {
				clientSkipOrFail(t, "no environment for %s at %s: run make clients-suite", name, python)
			}
			cmd := exec.Command(python, "-B", "-m", "unittest", "discover", "-s", dir, "-t", ".", "-v")
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			t.Logf("%s", out)
			if err != nil {
				t.Fatalf("%s: python -m unittest: %v", name, err)
			}
			if pythonSkip.Match(out) {
				t.Fatalf("the %s suite skipped a case; under this test every case must run", name)
			}
		})
	}
}

// echoService is the echo daemon's handler: the real one, with Describe held while a
// test holds it and every Run request counted as it arrives, before any check.
type echoService struct{ *rpc.SandboxService }

func (s echoService) Describe(ctx context.Context, req *connect.Request[plimsollv1.DescribeRequest]) (*connect.Response[plimsollv1.DescribeResponse], error) {
	if echoHolds.describing() {
		echoHolds.wait(ctx, "describe")
	}
	return s.SandboxService.Describe(ctx, req)
}

func (s echoService) Run(ctx context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	echoHolds.runRequests.Add(1)
	return s.SandboxService.Run(ctx, req)
}

// holds keeps calls on the echo daemon waiting until a test releases them, and counts
// the waits that ended because the call's context did: for a Run, the context the
// handler passes the provider, which ends when the client hangs up.
type holds struct {
	runRequests atomic.Int64 // Run requests the handler received

	mu       sync.Mutex
	describe bool          // Describe waits
	release  chan struct{} // closed by releaseAll
	waiting  map[string]int
	canceled map[string]int
}

var echoHolds = &holds{release: make(chan struct{}), waiting: map[string]int{}, canceled: map[string]int{}}

func (h *holds) holdDescribe() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.describe = true
}

func (h *holds) describing() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.describe
}

func (h *holds) releaseAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	close(h.release)
	h.release, h.describe = make(chan struct{}), false
}

// wait blocks until releaseAll or until ctx ends, which it counts.
func (h *holds) wait(ctx context.Context, kind string) {
	h.mu.Lock()
	release := h.release
	h.waiting[kind]++
	h.mu.Unlock()
	select {
	case <-release:
		h.mu.Lock()
	case <-ctx.Done():
		h.mu.Lock()
		h.canceled[kind]++
	}
	h.waiting[kind]--
	h.mu.Unlock()
}

func (h *holds) state() map[string]int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return map[string]int64{
		"describe_waiting": int64(h.waiting["describe"]), "run_waiting": int64(h.waiting["run"]),
		"describe_canceled": int64(h.canceled["describe"]), "run_canceled": int64(h.canceled["run"]),
		"run_requests": h.runRequests.Load(),
	}
}

// projectEcho answers a project with a JSON account of what it was asked to run (the
// files and their contents, the steps) as the step's stdout, unless the code the
// framework tool sent holds one of these markers:
//
//	ECHO:HOLD       the run waits until /test/release or until its context ends
//	ECHO:EXIT       the step exits 3 with "boom" on stderr, a failing guest
//	ECHO:TIMEOUT    the step and the run time out
//	ECHO:SETUP      setup_failed with no step's report (the code may or may not have run)
//	ECHO:PROTOCOL   protocol_error with no step's report: the sandbox answered nothing readable
//	ECHO:LOUD       20,000 characters on stdout, past a tool's cut
//	ECHO:LOST       an error with no not-dispatched mark: the code may have run
//	ECHO:WARN       the step exits 0 with "RESULT 42" on stdout and a warning on stderr
type projectEcho struct{}

var _ sandbox.Sandbox = projectEcho{}

// echoRuns counts the projects projectEcho has been handed, across every test.
var echoRuns atomic.Int64

func (projectEcho) Name() string                           { return "project-echo" }
func (projectEcho) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationContainer }
func (projectEcho) SupportsProjects() bool                 { return true }
func (projectEcho) Environments() sandbox.Environments {
	langs := []sandbox.Language{sandbox.LanguagePython, sandbox.LanguageJavaScript}
	return sandbox.Environments{Project: sandbox.PayloadEnvironment{Identity: "echo-image:sha256:0002", MaxTimeout: 5 * time.Minute, Languages: langs}}
}
func (projectEcho) RunJavaScript(context.Context, sandbox.Request) (sandbox.Result, error) {
	return sandbox.Result{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}
func (projectEcho) RunModule(context.Context, sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	return sandbox.ModuleResult{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}

func (projectEcho) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	echoRuns.Add(1)
	out := sandbox.ProjectResult{Sandbox: "project-echo", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted,
		EnvironmentIdentity: "echo-image:sha256:0002"}
	plan := struct {
		Files   map[string]string `json:"files"`
		Steps   []string          `json:"steps"`
		Timeout float64           `json:"timeout_s"`
	}{Files: map[string]string{}, Steps: req.Steps, Timeout: req.Timeout.Seconds()}
	all := ""
	for _, f := range req.Files {
		plan.Files[f.Path] = f.Content
		all += f.Content
	}
	step := sandbox.StepResult{Command: strings.Join(req.Steps, " && "), Duration: time.Millisecond}
	switch {
	case strings.Contains(all, "ECHO:HOLD"):
		echoHolds.wait(ctx, "run")
		if err := ctx.Err(); err != nil {
			return sandbox.ProjectResult{}, err
		}
	case strings.Contains(all, "ECHO:LOST"):
		return sandbox.ProjectResult{}, errors.New("the attach stream broke after the step started")
	case strings.Contains(all, "ECHO:PROTOCOL"):
		out.Outcome, out.Detail = sandbox.ProjectOutcomeProtocolError, "the runner's report was cut"
		return out, nil
	case strings.Contains(all, "ECHO:SETUP"):
		out.Outcome, out.Detail = sandbox.ProjectOutcomeSetupFailed, "a file could not be written"
		return out, nil
	case strings.Contains(all, "ECHO:TIMEOUT"):
		out.Outcome = sandbox.ProjectOutcomeTimedOut
		step.TimedOut, step.ExitCode = true, 124
	case strings.Contains(all, "ECHO:EXIT"):
		step.ExitCode, step.Stderr = 3, "boom"
	case strings.Contains(all, "ECHO:WARN"):
		step.Stdout, step.Stderr = "RESULT 42\n", "DeprecationWarning: this call is old\n"
	case strings.Contains(all, "ECHO:LOUD"):
		step.Stdout = strings.Repeat("x", 20_000)
	default:
		b, _ := json.Marshal(plan)
		step.Stdout = string(b)
	}
	out.Steps = []sandbox.StepResult{step}
	return out, nil
}
