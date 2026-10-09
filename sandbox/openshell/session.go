package openshell

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// Sessions keep one sandbox alive across calls (sandbox.SessionProvider). The
// boundary between calls is the shared sweep (sandbox/internal/sessionkit, which
// says what makes its verdict trustworthy). What is particular to OpenShell:
//
//   - The sweep's verdict stands only where code in the sandbox cannot attach to it,
//     so OpenSession refuses a host whose Yama ptrace_scope would allow that.
//   - When the sweep does not prove the boundary, a stop and start (the platform
//     killing every process) is the recovery, and when that fails the session ends.
//   - The main process is sleep, not the gateway's default login shell: a spared shell
//     reading a stream is a place leftover code could inject commands, and sleep
//     leaves on SIGTERM, so a stop takes a fraction of a second instead of the stop
//     timeout the shell waits out.
//   - Anyone who can call the gateway can change a sandbox between calls, so the
//     sandbox and its effective configuration are read back before every call.

var (
	// sessionCommand is a session sandbox's main process: 2^31-1 seconds, which every
	// sleep accepts, and far beyond any lifetime.
	sessionCommand = []string{"sleep", "2147483647"}
	// sessionDirs are what a session's files may occupy: /tmp is the sandbox's only
	// writable directory.
	sessionDirs = []string{"/tmp"}
	// sessionSnippetCommand runs a session's snippet from stdin in the work directory.
	sessionSnippetCommand = []string{"sh", "-c", `mkdir -p "$PLIMSOLL_WORK" && cd "$PLIMSOLL_WORK" && exec node -`}
)

const (
	// sessionLabel marks a session's sandbox (informational; the reaper treats it as
	// any plimsoll sandbox, by its declared lifetime).
	sessionLabel = "plimsoll.session"
	// stopBudget bounds a stop and its wait for the stopped phase.
	stopBudget = 60 * time.Second
	// startBudget bounds a start, its wait for the ready phase and the process list
	// after it: the same as a stop, since both wait on the gateway's driver.
	startBudget = 60 * time.Second
)

// SupportsSessions is true: sessions need nothing beyond what runs need.
func (*Provider) SupportsSessions() bool { return true }

// SessionEnvironments is the runs' environments: one image runs every payload kind.
func (p *Provider) SessionEnvironments() sandbox.Environments { return p.Environments() }

// session is one open session.
type session struct {
	p      *Provider
	routes *sandbox.RouteBudget // route caps span the session's granted calls
	b      box
	labels map[string]string
	tier   sandbox.IsolationClass
	// life is the lifecycle every provider's sessions share: the turn, the lifetime,
	// suspend and the sweep after every call (sessionkit.Life), with the session's
	// interpreters, which a stop kills.
	life *sessionkit.Life
}

// errDraining is a sandbox creation (a run's, an open's, the smoke test's) refused
// because Drain has begun.
var errDraining = fmt.Errorf("%w: the openshell provider is shutting down", sandbox.ErrAtCapacity)

var _ sandbox.Session = (*session)(nil)

// OpenSession creates a session's sandbox (the run policy, sleep as the main process,
// the session's lifetime declared on it), verifies it as a run's sandbox is verified,
// checks that the host's ptrace_scope lets the sweep's verdict stand, and records the
// sandbox's own processes, which every sweep spares.
func (p *Provider) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	if opts.Lifetime <= 0 {
		return nil, sandbox.NotDispatched(sandbox.RefusalRequest, fmt.Errorf("%w: a session needs a positive lifetime", sandbox.ErrInvalidRequest))
	}
	tier, err := p.ready(ctx, nil, opts.MinimumIsolation)
	if err != nil {
		return nil, err
	}
	// OpenShell has no pool, so a language hint changes nothing here; it is still
	// checked, so a hint is refused alike on every provider.
	if _, err := sandbox.SessionLanguages(opts.Languages, p.SessionEnvironments().Project.Languages); err != nil {
		return nil, err
	}
	// The lifetime runs from the open's start, as on docker: the sandbox declares it
	// from its create, so the reaper never finds a live session past its declaration.
	expires := time.Now().Add(opts.Lifetime)
	// No sized /tmp, whatever DiskMB says: docker discards a tmpfs when its container
	// stops, and a session is stopped to suspend it and to recover from a failed sweep,
	// so its files would vanish (measured on v0.1.2, 2026-09-29). Its disk budget is
	// measured after each call instead.
	b, labels, err := p.createBox(ctx, opts.Lifetime, sessionCommand, map[string]string{sessionLabel: "1"}, nil)
	if err != nil {
		return nil, deadlineAware(ctx, err)
	}
	s := &session{p: p, b: b, labels: labels, tier: tier, routes: sandbox.NewRouteBudget()}
	s.life = sessionkit.NewLife(b.name, s.hooks())
	if err := s.recordBaseline(ctx); err != nil {
		s.life.Abandon()
		p.deleteLater(ctx, b)
		return nil, deadlineAware(ctx, err)
	}
	// Once Drain has begun the session is refused and its sandbox deleted, which Drain
	// waits for (the sandbox stays tracked until then).
	if !s.life.Activate(&p.sessions, expires, opts.DiskBytes) {
		s.life.Abandon()
		p.deleteLater(ctx, b)
		return nil, sandbox.NotDispatched(sandbox.RefusalCapacity, errDraining)
	}
	return s, nil
}

// hooks are what the session's lifecycle does to its sandbox.
func (s *session) hooks() sessionkit.Hooks {
	return sessionkit.Hooks{
		Provider: Name, Unit: "sandbox",
		Refuse: sessionkit.Refusals{Ended: sandbox.RefuseEndedSession, GaveUp: sandbox.RefuseGaveUp, Unreadable: sandbox.RefuseUnreadable},
		// A stopped container holds no memory or CPU and keeps its files; the next call
		// starts it again.
		Suspend: func(ctx context.Context) error {
			if err := s.stop(ctx); err != nil {
				return fmt.Errorf("the sandbox could not be stopped: %w", err)
			}
			return nil
		},
		Resume: func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, startBudget)
			defer cancel()
			if err := s.start(ctx); err != nil {
				return fmt.Errorf("the sandbox could not be started again: %w", err)
			}
			return nil
		},
		ReadBack: s.readBack,
		Sweep: func(ctx context.Context, argv []string) (sessionkit.ExecResult, error) {
			return s.control(ctx, nil, argv, nil, 4096, 4096)
		},
		Measure:  sessionkit.MeasureWalk,
		Dirs:     sessionDirs,
		Unproven: s.recover,
		Teardown: func() { s.p.destroy(s.b) },
	}
}

func (s *session) Isolation() sandbox.IsolationClass { return s.tier }

// Environments is the provider's: an OpenShell sandbox runs the configured image,
// which states no software identity.
func (s *session) Environments() sandbox.Environments { return s.p.Environments() }
func (s *session) ExpiresAt() time.Time               { return s.life.ExpiresAt() }
func (s *session) Done() <-chan struct{}              { return s.life.Done() }
func (s *session) Err() error                         { return s.life.Err() }

// Close ends the session and deletes its sandbox. It does not wait for a call in
// flight: the call is stopped.
func (s *session) Close(context.Context) error {
	s.life.Close()
	return nil
}

// Suspend stops the sandbox: a stopped container holds no memory or CPU and keeps its
// files; the next call starts it again.
func (s *session) Suspend(ctx context.Context) (bool, error) { return s.life.Suspend(ctx) }

func (s *session) stop(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopBudget)
	defer cancel()
	if _, err := s.p.client.StopSandbox(ctx, connect.NewRequest(&openshellv1.StopSandboxRequest{WorkspaceScope: ws(), Name: s.b.name})); err != nil {
		return fmt.Errorf("openshell stop sandbox: %w", err)
	}
	for {
		resp, err := s.p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: s.b.name}))
		if err != nil {
			return fmt.Errorf("openshell get sandbox: %w", err)
		}
		switch ph := resp.Msg.GetSandbox().GetStatus().GetPhase(); ph {
		case openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPED:
			s.life.Interps.Clear()
			return nil
		case openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPING, openshellv1.SandboxPhase_SANDBOX_PHASE_READY:
		default:
			return fmt.Errorf("openshell stop sandbox: phase %v while stopping", ph)
		}
		if err := sleepCtx(ctx, readyPoll); err != nil {
			return err
		}
	}
}

// start starts a stopped sandbox, waits until it is ready and records its processes
// again: the main process is a new one after a start.
func (s *session) start(ctx context.Context) error {
	if _, err := s.p.client.StartSandbox(ctx, connect.NewRequest(&openshellv1.StartSandboxRequest{WorkspaceScope: ws(), Name: s.b.name})); err != nil {
		return fmt.Errorf("openshell start sandbox: %w", err)
	}
	for ready := false; !ready; {
		resp, err := s.p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: s.b.name}))
		if err != nil {
			return fmt.Errorf("openshell get sandbox: %w", err)
		}
		switch ph := resp.Msg.GetSandbox().GetStatus().GetPhase(); ph {
		case openshellv1.SandboxPhase_SANDBOX_PHASE_READY:
			ready = true
			continue
		case openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPED, openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPING,
			openshellv1.SandboxPhase_SANDBOX_PHASE_STARTING, openshellv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING,
			openshellv1.SandboxPhase_SANDBOX_PHASE_UNKNOWN, openshellv1.SandboxPhase_SANDBOX_PHASE_UNSPECIFIED:
		default:
			return fmt.Errorf("openshell start sandbox: phase %v instead of ready: %s", ph, conditionSummary(resp.Msg.GetSandbox()))
		}
		if err := sleepCtx(ctx, readyPoll); err != nil {
			return err
		}
	}
	return s.recordBaseline(ctx)
}

// recordBaseline lists the processes of a sandbox no call has touched (just created,
// or just started) and keeps them as the sandbox's own. It refuses anything but PID 1
// and one main process running the session command, and a host whose ptrace_scope is
// missing or 0.
func (s *session) recordBaseline(ctx context.Context) error {
	out, err := s.control(ctx, nil, sessionkit.ListArgv(), nil, 1<<20, maxOutputBytes)
	if err != nil {
		return fmt.Errorf("openshell session: list processes: %w", err)
	}
	if out.ExitCode != 0 {
		return fmt.Errorf("openshell session: the process list exited %d: %q", out.ExitCode, out.Stderr)
	}
	keep, err := sessionkit.Baseline([]byte(out.Stdout), sessionCommand, true)
	if err != nil {
		return fmt.Errorf("openshell session: %w", err)
	}
	s.life.SetBaseline(keep)
	return nil
}

// admit is the checks a call shares before it takes its turn: no grant, the call's
// floor against the evidence measured at open, and the driver check a run makes.
func (s *session) admit(ctx context.Context, grant *sandbox.HostAPIGrant, floor sandbox.IsolationClass) error {
	if err := sandbox.CheckMinimumIsolation(s.tier, floor); err != nil {
		return err
	}
	if _, err := s.p.ready(ctx, grant, floor); err != nil {
		return err
	}
	return sandbox.CheckSessionGrant(grant)
}

// readBack reads the sandbox and its configuration back before a call and says how
// the session ends on any difference. A read the gateway does not answer refuses the
// call and keeps the session, as on docker (review F4).
func (s *session) readBack(ctx context.Context) error {
	resp, err := s.p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: s.b.name}))
	if connect.CodeOf(err) == connect.CodeNotFound {
		return &sandbox.SessionEndedError{Reason: sandbox.SessionSandboxChanged, Detail: "the sandbox no longer exists"}
	}
	if err != nil {
		return fmt.Errorf("openshell get sandbox: %w", err)
	}
	sb := resp.Msg.GetSandbox()
	switch ph := sb.GetStatus().GetPhase(); ph {
	case openshellv1.SandboxPhase_SANDBOX_PHASE_READY:
	case openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR, openshellv1.SandboxPhase_SANDBOX_PHASE_COMPLETED:
		return &sandbox.SessionEndedError{Reason: sandbox.SessionMainProcessEnded, Detail: conditionSummary(sb)}
	default:
		return &sandbox.SessionEndedError{Reason: sandbox.SessionSandboxChanged, Detail: fmt.Sprintf("the sandbox is in phase %v, not ready", ph)}
	}
	if err := s.p.verifySandbox(sb, s.labels, sessionCommand, nil); err != nil {
		return &sandbox.SessionEndedError{Reason: sandbox.SessionSandboxChanged, Detail: err.Error()}
	}
	cfg, err := s.p.readConfig(ctx, s.b.name)
	if err != nil {
		return err
	}
	if err := s.p.checkConfig(cfg); err != nil {
		return &sandbox.SessionEndedError{Reason: sandbox.SessionSandboxChanged, Detail: err.Error()}
	}
	return nil
}

// recover runs after a sweep that did not prove the call boundary: when the sandbox's
// main process ended (code in the sandbox can kill it), which a restart would hide
// rather than repair, the session ends; otherwise a stop and start (the platform
// killing every process) gives the next call a clean sandbox, and when that fails the
// session ends.
func (s *session) recover(ctx context.Context, sweep string) *sandbox.SessionEndedError {
	ctx, cancel := context.WithTimeout(ctx, stopBudget+projectMax)
	defer cancel()
	resp, err := s.p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: s.b.name}))
	if err == nil {
		switch resp.Msg.GetSandbox().GetStatus().GetPhase() {
		case openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR, openshellv1.SandboxPhase_SANDBOX_PHASE_COMPLETED:
			return &sandbox.SessionEndedError{Reason: sandbox.SessionMainProcessEnded, Detail: conditionSummary(resp.Msg.GetSandbox())}
		}
	}
	slog.Warn("openshell: session sweep did not prove the call boundary; restarting the sandbox", "sandbox", s.b.name, "detail", sweep)
	if err := s.stop(ctx); err != nil {
		return &sandbox.SessionEndedError{Reason: sandbox.SessionBoundaryFailed, Detail: sweep + "; the recovery stop failed: " + err.Error()}
	}
	if err := s.start(ctx); err != nil {
		return &sandbox.SessionEndedError{Reason: sandbox.SessionBoundaryFailed, Detail: sweep + "; the recovery start failed: " + err.Error()}
	}
	return nil
}

// RunJavaScript runs req.Code with `node -` in the session's sandbox.
func (s *session) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	fail := sandbox.Result{Sandbox: Name, Isolation: s.tier}
	if err := sandbox.ValidateRequest(req); err != nil {
		return fail, err
	}
	if err := req.Software.Check(""); err != nil {
		return fail, err
	}
	timeout := clampTimeout(req.Timeout, snippetDefault, snippetMax)
	if err := s.admit(ctx, req.Grant, req.MinimumIsolation); err != nil {
		return fail, err
	}
	runCtx, done, err := s.life.Call(ctx, timeout)
	if err != nil {
		return fail, err
	}
	defer done()
	code, env := req.Code, map[string]string(nil)
	var g *grantRun
	if req.Grant != nil {
		// A call's grant lives for the call: its relay is one of the call's processes,
		// and the sweep after the call ends it like any other.
		var err error
		if g, err = s.p.startGrant(runCtx, s.b, req.Grant, timeout, s.routes); err != nil {
			return fail, s.grantError(runCtx, err)
		}
		defer g.Close()
		code, env = sandbox.HostClientSnippet(req.Code, req.Grant), g.env()
	}
	// A session's snippet runs in the work directory its projects write, so the
	// next call finds a project's files where the project left them.
	if env == nil {
		env = map[string]string{}
	}
	env["PLIMSOLL_WORK"] = workDir
	start := time.Now()
	out, err := s.p.exec(runCtx, s.b, sessionSnippetCommand, env, []byte(code), maxOutputBytes, maxOutputBytes)
	res := sandbox.Result{
		Stdout:          string(out.stdout),
		Stderr:          string(out.stderr),
		StdoutTruncated: out.stdoutTruncated,
		StderrTruncated: out.stderrTruncated,
		ExitCode:        out.exitCode,
		Duration:        time.Since(start),
		Sandbox:         Name,
		Isolation:       s.tier,
	}
	if g != nil {
		g.broker.End()
		res.CallTrace = g.broker.Trace()
	}
	if out.exited {
		return res, nil
	}
	if deadline.Expired(runCtx) == context.DeadlineExceeded && s.Err() == nil {
		// The call's own deadline: its process group is killed, and the sweep that
		// follows kills anything that detached.
		res.TimedOut, res.ExitCode = true, 124
		return res, nil
	}
	// The brokered calls happened whatever became of the exec stream.
	fail.CallTrace = res.CallTrace
	return fail, s.life.CallError(runCtx, err)
}

// RunProject writes the files and runs the steps through /runner.mjs in the session's
// sandbox. The work directory is under /tmp, so files persist to the next call.
func (s *session) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	fail := sandbox.ProjectResult{Sandbox: Name, Isolation: s.tier}
	if err := sandbox.ValidateProjectRequest(req); err != nil {
		return fail, err
	}
	if err := req.Software.Check(""); err != nil {
		return fail, err
	}
	timeout := clampTimeout(req.Timeout, projectDefault, projectMax)
	key, err := runnerwire.NewKey()
	if err != nil {
		return fail, err
	}
	plan := runnerwire.Plan{Steps: req.Steps, StepTimeout: timeout, Artifacts: req.Artifacts, HostSDK: sandbox.HostClientModule(req.Grant), ReportKey: key}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, runnerwire.File(f))
	}
	planJSON, err := plan.Encode()
	if err != nil {
		return fail, err
	}
	if err := s.admit(ctx, req.Grant, req.MinimumIsolation); err != nil {
		return fail, err
	}
	runCtx, done, err := s.life.Call(ctx, timeout+runnerGrace)
	if err != nil {
		return fail, err
	}
	defer done()
	var g *grantRun
	if req.Grant != nil {
		if g, err = s.p.startGrant(runCtx, s.b, req.Grant, timeout+runnerGrace, s.routes); err != nil {
			return fail, s.grantError(runCtx, err)
		}
		defer g.Close()
	}
	res, err := s.p.runPlan(runCtx, s.b, s.tier, planJSON, key, g)
	if g != nil {
		g.broker.End()
		res.CallTrace = g.broker.Trace()
	}
	// The brokered calls happened whatever became of the run.
	fail.CallTrace = res.CallTrace
	if err != nil {
		return fail, s.life.CallError(runCtx, err)
	}
	if res.Outcome == sandbox.ProjectOutcomeTimedOut && s.Err() != nil {
		// The session ended under the call, not the call's own budget.
		return fail, s.Err()
	}
	return res, nil
}

// grantError is what a call returns when its grant could not be set up. A refusal
// marked not dispatched (the credential could not be minted, before anything of the
// call ran) stays as it is, as on docker, whatever became of the session meanwhile;
// anything else, a relay that did not start, is a call error.
func (s *session) grantError(runCtx context.Context, err error) error {
	if _, marked := sandbox.NotDispatchedReason(err); marked {
		return err
	}
	return s.life.CallError(runCtx, err)
}

// control runs argv, one of plimsoll's own programs (the process lister, the sweep),
// under sessionkit.ControlArgv, with env as its only variables besides PATH: nothing
// the gateway's exec hands a command reaches it. A v0.1.2 gateway hands every exec a
// fixed set, never the image's environment (measured 2026-10-03); this keeps a
// variable that loads code (NODE_OPTIONS) out of plimsoll's programs on a gateway
// that starts passing the image's.
func (s *session) control(ctx context.Context, env map[string]string, argv []string, stdin []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
	argv, err := sessionkit.ControlArgv(env, argv...)
	if err != nil {
		return sessionkit.ExecResult{}, err
	}
	return s.execFunc(ctx, argv, nil, stdin, outCap, errCap)
}

// execFunc is exec in the form the shared interpreter driver calls. What it runs is
// the interpreter launcher, a shell whose child is the guest's interpreter, so it
// starts with the gateway's environment, which the interpreter inherits; no
// non-interactive shell loads code from a variable but bash's BASH_ENV, and the
// gateway's own shell is busybox.
func (s *session) execFunc(ctx context.Context, argv []string, env map[string]string, stdin []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
	out, err := s.p.exec(ctx, s.b, argv, env, stdin, outCap, errCap)
	return sessionkit.ExecResult{
		Stdout: string(out.stdout), Stderr: string(out.stderr),
		StdoutTruncated: out.stdoutTruncated, StderrTruncated: out.stderrTruncated,
		ExitCode: out.exitCode, Exited: out.exited,
	}, err
}

// RunCell runs code in the session's interpreter for req.Language, starting one
// when none is alive (sandbox/internal/sessionkit), through a relay the session keeps
// attached by one exec stream held open, so a warm cell starts no process. A suspend
// stops the sandbox and with it every interpreter and relay, so the cell after a
// suspend starts a fresh one. A cell's budget is a project's.
func (s *session) RunCell(ctx context.Context, req sandbox.CellRequest) (sandbox.CellResult, error) {
	fail := sandbox.CellResult{Sandbox: Name, Isolation: s.tier}
	if err := sandbox.ValidateCellRequest(req); err != nil {
		return fail, err
	}
	if err := req.Software.Check(""); err != nil {
		return fail, err
	}
	timeout := clampTimeout(req.Timeout, projectDefault, projectMax)
	if err := s.admit(ctx, nil, req.MinimumIsolation); err != nil {
		return fail, err
	}
	runCtx, done, err := s.life.Call(ctx, timeout)
	if err != nil {
		return fail, err
	}
	defer done()
	files := make([]sessionkit.File, 0, len(req.Files))
	for _, f := range req.Files {
		files = append(files, sessionkit.File{Path: f.Path, Content: f.Content})
	}
	start := time.Now()
	out, err := s.life.Interps.RunRelayed(runCtx, s.execFunc, s.attach, sessionkit.Cell{
		Language: string(req.Language), Code: req.Code, Files: files,
		Work: workDir, OutCap: maxOutputBytes, ErrCap: maxOutputBytes,
	})
	return sandbox.SessionCellResult(runCtx, fail, out, err, time.Since(start), "", "", s.Err,
		func() error { return nil }, func(err error) error { return s.life.CallError(runCtx, err) })
}

// streamAttached is an exec stream held open for the session: an interpreter's relay.
// Its stdin goes out as stdin frames; its stdout arrives through a pipe a goroutine
// fills from the stream's events.
type streamAttached struct {
	cancel context.CancelFunc
	stream *connect.BidiStreamForClient[openshellv1.ExecSandboxInput, openshellv1.ExecSandboxEvent]
	mu     sync.Mutex // Send is not safe for concurrent use
	out    *io.PipeReader
}

func (a *streamAttached) Stdin() io.Writer  { return a }
func (a *streamAttached) Stdout() io.Reader { return a.out }

func (a *streamAttached) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for off := 0; off < len(p); off += stdinFrame {
		frame := p[off:min(off+stdinFrame, len(p))]
		if err := a.stream.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Stdin{Stdin: frame}}); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

// Close cancels the stream, which ends the relay's process group.
func (a *streamAttached) Close() {
	a.cancel()
	_ = a.out.Close()
}

// attach starts argv in the sandbox on a stream that lives as long as the session or
// until Close. Unlike docker's, the relay is not made non-dumpable: OpenShell's
// supervisor then refuses its connection to the interpreter's socket with EACCES
// (measured on v0.1.2, 2026-10-01), presumably because it can no longer identify
// the process. What keeps the session's code from opening the relay's pipes is the
// gateway walling each exec's processes off from the others' (measured on v0.1.2,
// 2026-10-01), which sandbox.SessionSmokeTest checks at startup, refusing sessions on
// a gateway where a call can open a running relay's pipes; the sweep's verdict stays
// protected by the ptrace_scope check OpenSession makes.
//
// A relay is one of plimsoll's own programs: its frames carry every cell's result. It
// starts under sessionkit.ControlArgv, with env as its only variables (control).
func (s *session) attach(argv []string, env map[string]string) (sessionkit.Attached, error) {
	argv, err := sessionkit.ControlArgv(env, argv...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(s.life.Context())
	stream := s.p.client.ExecSandboxInteractive(ctx)
	start := &openshellv1.ExecSandboxRequest{
		WorkspaceScope: ws(),
		Sandbox:        s.b.name,
		Command:        argv,
		NoLoginShell:   true,
	}
	if err := stream.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Start{Start: start}}); err != nil {
		cancel()
		return nil, fmt.Errorf("openshell attach: %w", err)
	}
	pr, pw := io.Pipe()
	go func() {
		defer func() { _ = stream.CloseResponse() }()
		for {
			ev, err := stream.Receive()
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			switch pl := ev.GetPayload().(type) {
			case *openshellv1.ExecSandboxEvent_Stdout:
				if _, err := pw.Write(pl.Stdout.GetData()); err != nil {
					cancel()
					return
				}
			case *openshellv1.ExecSandboxEvent_Exit:
				_ = pw.CloseWithError(io.EOF)
				cancel()
				return
			}
		}
	}()
	return &streamAttached{cancel: cancel, stream: stream, out: pr}, nil
}
