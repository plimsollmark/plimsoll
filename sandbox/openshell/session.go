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
	// sweepBudget bounds one sweep exec: normally a node start and one /tmp walk.
	sweepBudget = 20 * time.Second
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
	p       *Provider
	b       box
	labels  map[string]string
	tier    sandbox.IsolationClass
	expires time.Time
	disk    int64

	ctx    context.Context // cancelled when the session ends, which stops a call in flight
	cancel context.CancelFunc
	turn   chan struct{} // one slot: holding it is the right to call, suspend or resume
	done   chan struct{}

	mu       sync.Mutex
	end      *sandbox.SessionEndedError
	stopped  bool
	baseline []string // pid:starttime:cmdline-hex of the sandbox's own processes
	life     *time.Timer

	// interps are the session's live interpreters; a stop kills them.
	interps sessionkit.Interpreters
}

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
	// No sized /tmp, whatever DiskMB says: docker discards a tmpfs when its container
	// stops, and a session is stopped to suspend it and to recover from a failed sweep,
	// so its files would vanish (measured on v0.1.2, 2026-09-29). Its disk budget is
	// measured after each call instead.
	b, labels, err := p.createBox(ctx, opts.Lifetime, sessionCommand, map[string]string{sessionLabel: "1"}, nil)
	if err != nil {
		return nil, deadlineAware(ctx, err)
	}
	sctx, cancel := context.WithCancel(context.Background())
	s := &session{
		p: p, b: b, labels: labels, tier: tier,
		expires: time.Now().Add(opts.Lifetime),
		disk:    opts.DiskBytes,
		ctx:     sctx, cancel: cancel,
		turn: make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	if err := s.recordBaseline(ctx); err != nil {
		cancel()
		p.deleteLater(b)
		return nil, deadlineAware(ctx, err)
	}
	p.mu.Lock()
	p.sessions[s] = struct{}{}
	p.mu.Unlock()
	s.mu.Lock()
	s.life = time.AfterFunc(time.Until(s.expires), func() { s.finish(sandbox.SessionExpired, "") })
	s.mu.Unlock()
	return s, nil
}

func (p *Provider) openSessions() []*session {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*session, 0, len(p.sessions))
	for s := range p.sessions {
		out = append(out, s)
	}
	return out
}

func (s *session) Isolation() sandbox.IsolationClass { return s.tier }
func (s *session) ExpiresAt() time.Time              { return s.expires }
func (s *session) Done() <-chan struct{}             { return s.done }

func (s *session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.end == nil {
		return nil
	}
	return s.end
}

// finish ends the session once, for the first reason given: it stops a call in
// flight, and deletes the sandbox off the caller's path.
func (s *session) finish(reason sandbox.SessionEnd, detail string) {
	s.mu.Lock()
	if s.end != nil {
		s.mu.Unlock()
		return
	}
	s.end = &sandbox.SessionEndedError{Reason: reason, Detail: detail}
	if s.life != nil {
		s.life.Stop()
	}
	s.mu.Unlock()
	s.cancel()
	s.interps.Close()
	close(s.done)
	s.p.mu.Lock()
	delete(s.p.sessions, s)
	s.p.mu.Unlock()
	if reason != sandbox.SessionClosed && reason != sandbox.SessionShutdown {
		slog.Info("openshell: session ended", "sandbox", s.b.name, "reason", reason.String(), "detail", detail)
	}
	s.p.deleteLater(s.b)
}

// acquire takes the session's turn, bounded by ctx. A session that ended, or ends
// while waiting, refuses: nothing ran.
func (s *session) acquire(ctx context.Context) error {
	if err := s.Err(); err != nil {
		return sandbox.RefuseEndedSession(err)
	}
	select {
	case s.turn <- struct{}{}:
	case <-s.done:
		return sandbox.RefuseEndedSession(s.Err())
	case <-ctx.Done():
		return sandbox.RefuseGaveUp(ctx)
	}
	if err := s.Err(); err != nil {
		<-s.turn
		return sandbox.RefuseEndedSession(err)
	}
	return nil
}

func (s *session) release() { <-s.turn }

// Close ends the session and deletes its sandbox. It does not wait for a call in
// flight: the call is stopped.
func (s *session) Close(context.Context) error {
	s.finish(sandbox.SessionClosed, "")
	return nil
}

// Suspend stops the sandbox: a stopped container holds no memory or CPU and keeps its
// files; the next call starts it again.
func (s *session) Suspend(ctx context.Context) (bool, error) {
	if err := s.acquire(ctx); err != nil {
		return false, err
	}
	defer s.release()
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		return false, nil
	}
	if err := s.stop(ctx); err != nil {
		s.finish(sandbox.SessionBoundaryFailed, "the sandbox could not be stopped: "+err.Error())
		return false, s.Err()
	}
	return false, nil
}

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
			s.mu.Lock()
			s.stopped = true
			s.mu.Unlock()
			s.interps.Clear()
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
	s.mu.Lock()
	s.stopped = false
	s.mu.Unlock()
	return s.recordBaseline(ctx)
}

// recordBaseline lists the processes of a sandbox no call has touched (just created,
// or just started) and keeps them as the sandbox's own. It refuses anything but PID 1
// and one main process running the session command, and a host whose ptrace_scope is
// missing or 0.
func (s *session) recordBaseline(ctx context.Context) error {
	out, err := s.p.exec(ctx, s.b, sessionkit.ListArgv(), nil, nil, 1<<20, maxOutputBytes)
	if err != nil {
		return fmt.Errorf("openshell session: list processes: %w", err)
	}
	if out.exitCode != 0 {
		return fmt.Errorf("openshell session: the process list exited %d: %q", out.exitCode, out.stderr)
	}
	keep, err := sessionkit.Baseline(out.stdout, sessionCommand, true)
	if err != nil {
		return fmt.Errorf("openshell session: %w", err)
	}
	s.mu.Lock()
	s.baseline = keep
	s.mu.Unlock()
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

// prepare runs with the turn held, before a call: it starts a stopped sandbox, then
// reads the sandbox and its configuration back and ends the session on any
// difference. Nothing has run when it fails.
func (s *session) prepare(ctx context.Context) error {
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		// The caller cannot cut the start short, only its budget can, as with the stop:
		// a start cancelled after the gateway took it would leave the sandbox running
		// while this session thinks it stopped.
		startCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), startBudget)
		err := s.start(startCtx)
		cancel()
		if err != nil {
			s.finish(sandbox.SessionBoundaryFailed, "the sandbox could not be started again: "+err.Error())
			return sandbox.RefuseEndedSession(s.Err())
		}
	}
	resp, err := s.p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: s.b.name}))
	if err != nil {
		if ctx.Err() != nil {
			return sandbox.RefuseGaveUp(ctx)
		}
		if connect.CodeOf(err) == connect.CodeNotFound {
			s.finish(sandbox.SessionSandboxChanged, "the sandbox no longer exists")
			return sandbox.RefuseEndedSession(s.Err())
		}
		return fmt.Errorf("openshell get sandbox: %w", err)
	}
	sb := resp.Msg.GetSandbox()
	switch ph := sb.GetStatus().GetPhase(); ph {
	case openshellv1.SandboxPhase_SANDBOX_PHASE_READY:
	case openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR, openshellv1.SandboxPhase_SANDBOX_PHASE_COMPLETED:
		s.finish(sandbox.SessionMainProcessEnded, conditionSummary(sb))
		return sandbox.RefuseEndedSession(s.Err())
	default:
		s.finish(sandbox.SessionSandboxChanged, fmt.Sprintf("the sandbox is in phase %v, not ready", ph))
		return sandbox.RefuseEndedSession(s.Err())
	}
	if err := s.p.verifySandbox(sb, s.labels, sessionCommand, nil); err != nil {
		s.finish(sandbox.SessionSandboxChanged, err.Error())
		return sandbox.RefuseEndedSession(s.Err())
	}
	if err := s.p.verifyConfig(ctx, s.b.name); err != nil {
		if ctx.Err() != nil {
			return sandbox.RefuseGaveUp(ctx)
		}
		s.finish(sandbox.SessionSandboxChanged, err.Error())
		return sandbox.RefuseEndedSession(s.Err())
	}
	return nil
}

// boundary runs after every call, with the turn still held and whatever happened to
// the caller's context: the sweep, then, when it did not prove the boundary, a stop
// and start, and when that fails the end of the session. A session over its disk
// budget ends here too. It reports nothing: the session's state says what happened.
func (s *session) boundary() {
	if s.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, sweepBudget)
	s.mu.Lock()
	args := sessionkit.SweepArgv(s.disk, sessionDirs, s.interps.Keep(s.baseline))
	s.mu.Unlock()
	out, err := s.p.exec(ctx, s.b, args, nil, nil, 4096, 4096)
	cancel()
	if s.Err() != nil {
		return
	}
	switch {
	case err == nil && out.exited && out.exitCode == sessionkit.SweepClean:
		return
	case err == nil && out.exited && out.exitCode == sessionkit.SweepOverBudget:
		s.finish(sandbox.SessionDiskExceeded, fmt.Sprintf("the session's files under /tmp exceed %d bytes or %d entries", s.disk, sessionkit.MaxDiskEntries))
		return
	case err == nil && out.exited && out.exitCode == sessionkit.SweepUnmeasurable:
		s.finish(sandbox.SessionDiskExceeded, "a directory under /tmp could not be read, so the session's disk use cannot be measured")
		return
	}
	sweepErr := fmt.Sprintf("the sweep exited %d (err %v)", out.exitCode, err)
	// The sandbox's main process may have ended (code in the sandbox can kill it),
	// which a restart would hide rather than repair.
	rctx, rcancel := context.WithTimeout(s.ctx, stopBudget+projectMax)
	defer rcancel()
	resp, gerr := s.p.client.GetSandbox(rctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: s.b.name}))
	if gerr == nil {
		switch resp.Msg.GetSandbox().GetStatus().GetPhase() {
		case openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR, openshellv1.SandboxPhase_SANDBOX_PHASE_COMPLETED:
			s.finish(sandbox.SessionMainProcessEnded, conditionSummary(resp.Msg.GetSandbox()))
			return
		}
	}
	slog.Warn("openshell: session sweep did not prove the call boundary; restarting the sandbox", "sandbox", s.b.name, "detail", sweepErr)
	if err := s.stop(rctx); err != nil {
		s.finish(sandbox.SessionBoundaryFailed, sweepErr+"; the recovery stop failed: "+err.Error())
		return
	}
	if err := s.start(rctx); err != nil {
		s.finish(sandbox.SessionBoundaryFailed, sweepErr+"; the recovery start failed: "+err.Error())
	}
}

// begin takes the session's turn and prepares the sandbox for one call. The returned
// end runs the boundary (the sweep, and its recovery) and gives the turn back off the
// caller's path: the answer goes back first, and the next call, a suspend or a close
// waits for it. A session the boundary ends is therefore reported to the next call.
func (s *session) begin(ctx context.Context) (end func(), err error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	if err := s.prepare(ctx); err != nil {
		s.release()
		return nil, err
	}
	return func() {
		go func() {
			s.boundary()
			s.release()
		}()
	}, nil
}

// callError is what a call returns when its exec did not deliver an exit status: a
// session that ended during the call (its lifetime passed, or it was closed) is
// reported as that end. Execution may have happened, so it is not marked
// not-dispatched.
func (s *session) callError(runCtx context.Context, err error) error {
	if end := s.Err(); end != nil {
		return end
	}
	if ctxErr := deadline.Expired(runCtx); ctxErr != nil {
		return ctxErr
	}
	return err
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
	end, err := s.begin(ctx)
	if err != nil {
		return fail, err
	}
	defer end()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	code, env := req.Code, map[string]string(nil)
	var g *grantRun
	if req.Grant != nil {
		// A call's grant lives for the call: its relay is one of the call's processes,
		// and the sweep after the call ends it like any other.
		var err error
		if g, err = s.p.startGrant(runCtx, s.b, req.Grant, timeout); err != nil {
			return fail, s.callError(runCtx, err)
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
	return fail, s.callError(runCtx, err)
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
	end, err := s.begin(ctx)
	if err != nil {
		return fail, err
	}
	defer end()
	runCtx, cancel := context.WithTimeout(ctx, timeout+runnerGrace)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	var g *grantRun
	if req.Grant != nil {
		if g, err = s.p.startGrant(runCtx, s.b, req.Grant, timeout+runnerGrace); err != nil {
			return fail, s.callError(runCtx, err)
		}
		defer g.Close()
	}
	res, err := s.p.runPlan(runCtx, s.b, s.tier, planJSON, key, g)
	if g != nil {
		res.CallTrace = g.broker.Trace()
	}
	// The brokered calls happened whatever became of the run.
	fail.CallTrace = res.CallTrace
	if err != nil {
		return fail, s.callError(runCtx, err)
	}
	if res.Outcome == sandbox.ProjectOutcomeTimedOut && s.Err() != nil {
		// The session ended under the call, not the call's own budget.
		return fail, s.Err()
	}
	return res, nil
}

// execFunc is exec in the form the shared interpreter driver calls.
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
	end, err := s.begin(ctx)
	if err != nil {
		return fail, err
	}
	defer end()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	files := make([]sessionkit.File, 0, len(req.Files))
	for _, f := range req.Files {
		files = append(files, sessionkit.File{Path: f.Path, Content: f.Content})
	}
	start := time.Now()
	out, err := s.interps.RunRelayed(runCtx, s.execFunc, s.attach, sessionkit.Cell{
		Language: string(req.Language), Code: req.Code, Files: files,
		Work: workDir, OutCap: maxOutputBytes, ErrCap: maxOutputBytes,
	})
	if refusal, ok := sandbox.RefuseCell(err, s.Err()); ok {
		return fail, refusal
	}
	if err != nil {
		return fail, s.callError(runCtx, err)
	}
	res := sandbox.CellResult{
		Stdout:             out.Stdout,
		Stderr:             out.Stderr,
		StdoutTruncated:    out.StdoutTruncated,
		StderrTruncated:    out.StderrTruncated,
		TimedOut:           out.TimedOut,
		InterpreterStarted: out.Started,
		InterpreterEnded:   out.Ended,
		Duration:           time.Since(start),
		Sandbox:            Name,
		Isolation:          s.tier,
	}
	switch {
	case out.TimedOut:
		res.ExitCode = 124
	case out.Raised:
		res.ExitCode = 1
	}
	return res, nil
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
// the process. Code of the session could open the relay's pipes and forge its own
// cells' output, as it could forge the per-cell client's before; the sweep's verdict
// stays protected by the ptrace_scope check OpenSession makes.
func (s *session) attach(argv []string, env map[string]string) (sessionkit.Attached, error) {
	ctx, cancel := context.WithCancel(s.ctx)
	stream := s.p.client.ExecSandboxInteractive(ctx)
	start := &openshellv1.ExecSandboxRequest{
		WorkspaceScope: ws(),
		Sandbox:        s.b.name,
		Command:        argv,
		Environment:    env,
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
