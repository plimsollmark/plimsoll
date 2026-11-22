package clientsuite

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
)

// The tool-echo daemon is what a framework adapter's code tool is tested against with no
// sandbox (clients/python/frameworks): a container-tier provider that runs nothing and
// answers each project with what it was asked to run, or with the failure a marker in
// the code names; its handler can hold a Describe or a Run until a test releases it.
// Until 2026-11-18 (P7b of the refactor plan) the framework suites' Go driver served it
// itself under PLIMSOLL_ECHO_URL, the name the table's echo daemon, a different one, has.

// serveToolEcho serves one tool-echo daemon with its test routes:
//
//	GET  /test/project-runs    how many projects the provider was handed
//	POST /test/hold-describe   every Describe from now on waits until /test/release
//	POST /test/release         releases every held call
//	GET  /test/holds           the calls waiting and the waits their callers ended
//	GET  /test/last-trace-id   the trace ID of the last Run request, as received
func serveToolEcho(t *testing.T) []string {
	e := &toolEcho{holds: newHolds()}
	svc := toolEchoService{Quiet(rpc.NewSandboxService(e)), e}
	return []string{Serve(t, svc, nil, func(mux *http.ServeMux) {
		// A test that says a call was not retried counts dispatches instead of trusting a note.
		mux.HandleFunc("GET /test/project-runs", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strconv.FormatInt(e.runs.Load(), 10)))
		})
		mux.HandleFunc("POST /test/hold-describe", func(http.ResponseWriter, *http.Request) { e.holds.holdDescribe() })
		mux.HandleFunc("POST /test/release", func(http.ResponseWriter, *http.Request) { e.holds.releaseAll() })
		mux.HandleFunc("GET /test/holds", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(e.holds.state())
		})
		mux.HandleFunc("GET /test/last-trace-id", func(w http.ResponseWriter, _ *http.Request) {
			tid, _ := e.traceID.Load().(string)
			_, _ = w.Write([]byte(tid))
		})
	})}
}

// toolEchoService is the tool-echo daemon's handler: the real one, with Describe held
// while a test holds it and every Run request counted and its trace ID kept as it
// arrives, before any check.
type toolEchoService struct {
	*rpc.SandboxService
	e *toolEcho
}

func (s toolEchoService) Describe(ctx context.Context, req *connect.Request[plimsollv1.DescribeRequest]) (*connect.Response[plimsollv1.DescribeResponse], error) {
	if s.e.holds.describing() {
		s.e.holds.wait(ctx, "describe")
	}
	return s.SandboxService.Describe(ctx, req)
}

func (s toolEchoService) Run(ctx context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	s.e.holds.runRequests.Add(1)
	s.e.traceID.Store(req.Msg.GetTraceId())
	return s.SandboxService.Run(ctx, req)
}

// holds keeps calls on the tool-echo daemon waiting until a test releases them, and
// counts the waits that ended because the call's context did: for a Run, the context the
// handler passes the provider, which ends when the client hangs up.
type holds struct {
	runRequests atomic.Int64 // Run requests the handler received

	mu       sync.Mutex
	describe bool          // Describe waits
	release  chan struct{} // closed by releaseAll
	waiting  map[string]int
	canceled map[string]int
}

func newHolds() *holds {
	return &holds{release: make(chan struct{}), waiting: map[string]int{}, canceled: map[string]int{}}
}

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

// toolEcho answers a project with a JSON account of what it was asked to run (the files
// and their contents, the steps, the budget) as the step's stdout, unless the code the
// framework tool sent holds one of these markers:
//
//	ECHO:HOLD       the run waits until /test/release or until its context ends
//	ECHO:EXIT       the step exits 3 with "boom" on stderr, a failing guest
//	ECHO:TIMEOUT    the step and the run time out
//	ECHO:SETUP      setup_failed with no step's report: no step began, so the code did not run
//	ECHO:PROTOCOL   protocol_error with no step's report: the sandbox answered nothing readable
//	ECHO:LOUD       20,000 characters on stdout, past a tool's cut
//	ECHO:LOST       an error with no not-dispatched mark: the code may have run
//	ECHO:WARN       the step exits 0 with "RESULT 42" on stdout and a warning on stderr
type toolEcho struct {
	holds   *holds
	runs    atomic.Int64 // the projects it was handed
	traceID atomic.Value // the trace ID of the last Run request, a string
}

var _ sandbox.Sandbox = (*toolEcho)(nil)

func (*toolEcho) Name() string                           { return "project-echo" }
func (*toolEcho) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationContainer }
func (*toolEcho) SupportsProjects() bool                 { return true }
func (*toolEcho) Environments() sandbox.Environments {
	langs := []sandbox.Language{sandbox.LanguagePython, sandbox.LanguageJavaScript}
	return sandbox.Environments{Project: sandbox.PayloadEnvironment{Identity: "echo-image:sha256:0002", MaxTimeout: 5 * time.Minute, Languages: langs}}
}
func (*toolEcho) RunJavaScript(context.Context, sandbox.Request) (sandbox.Result, error) {
	return sandbox.Result{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}
func (*toolEcho) RunModule(context.Context, sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	return sandbox.ModuleResult{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}

func (e *toolEcho) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	e.runs.Add(1)
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
		e.holds.wait(ctx, "run")
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
