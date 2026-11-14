package wslc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// Paths in plimsoll's sandbox image, the same the other providers that run the runner use.
const (
	runnerPath      = "/runner.mjs"
	runnerGuardPath = "/usr/local/lib/plimsoll-runner-guard.so"
	workDir         = "/work"
	// controlPath is the PATH the runner starts with (the image's own PATH reaches the
	// steps through the plan).
	controlPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// A snippet is one staged file and one node step through the runner, so a snippet takes
// the path the smoke test proves.
const (
	snippetFile = "snippet.js"
	snippetStep = "node " + snippetFile
)

// containerName is a fresh name for one run's container: a prefix and 24 random hex
// digits, so the forced removal after a run that did not end cleanly names only it.
func containerName() string { return "plimsoll-wslc-" + randHex(12) }

// runArgv is the whole argument list of one run's `wslc container run`: every control
// WSLC has, the image by the ID the smoke test read, and the runner started under
// /usr/bin/env -i. Every element is a fixed flag or a checked ID (exec.go); nothing a
// caller sent is in it.
func (p *Provider) runArgv(name, imageID string) []string {
	mb := func(n int) string { return strconv.Itoa(n) + "m" }
	user := strconv.Itoa(GuestUID) + ":" + strconv.Itoa(GuestUID)
	nproc := strconv.Itoa(p.cfg.Nproc)
	return []string{
		"container", "run",
		"--rm",          // removed when the runner exits
		"--interactive", // stdin carries the plan
		"--name", name,
		"--pull", "never", // the image is the one the smoke test inspected, never fetched
		"--network", "none",
		// The session VM's resolver settings would otherwise be copied in (the docker
		// provider's guestResolvConf explains why); the smoke test reads what is left.
		"--dns", "127.0.0.1",
		"--dns-search", ".",
		"--cap-drop", "ALL",
		"--user", user,
		"--memory", strconv.Itoa(p.cfg.MemoryMB * 1024 * 1024),
		"--cpus", cpusArg(p.cfg.CPUs),
		"--ulimit", "nproc=" + nproc + ":" + nproc,
		"--ulimit", "nofile=" + strconv.Itoa(nofileLimit) + ":" + strconv.Itoa(nofileLimit),
		"--ulimit", "core=0:0",
		// Every place the image leaves writable is covered by a bounded tmpfs that
		// cannot hold a program: /tmp and /var/tmp are world-writable in the image.
		// Every mode is stated, never left to the engine: WSLC 3.0.5's dockerd (25.0.3)
		// mounts a /dev/shm tmpfs with no mode as 755 root, which the guest uid cannot
		// write (measured 2026-11-11), while /tmp came up 1777.
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=" + mb(smallTmpfsMB) + ",mode=1777",
		"--tmpfs", "/var/tmp:rw,noexec,nosuid,nodev,size=" + mb(smallTmpfsMB) + ",mode=1777",
		"--tmpfs", "/dev/shm:rw,noexec,nosuid,nodev,size=" + mb(smallTmpfsMB) + ",mode=1777",
		"--tmpfs", workDir + ":rw,noexec,nosuid,nodev,size=" + mb(p.cfg.workMB()) + ",mode=1777",
		"--workdir", workDir,
		// An image's HEALTHCHECK would make dockerd run the image's command in the
		// container on an interval, beside guest code.
		"--no-healthcheck",
		"--stop-timeout", "1",
		"--entrypoint", "/usr/bin/env",
		imageID,
		// /usr/bin/env's arguments: a clean environment, the guard that makes the runner
		// unreadable to its own steps, and the runner. The image's environment reaches
		// the steps through the plan, never this process.
		"-i", "PATH=" + controlPath, "HOME=/", "LD_PRELOAD=" + runnerGuardPath, "node", runnerPath,
	}
}

// planRun is one run's outcome as the transport saw it.
type planRun struct {
	stdout   []byte
	exit     int  // wslc's exit code; -1 when it did not exit on its own
	reported bool // an authenticated report was found
	result   sandbox.ProjectResult
	ended    error // the backstop's context error, when it fired
}

// runPlan starts one container for plan and returns what came back: in the shared mode in
// the default session, in the per-run mode in a session of its own, opened for it and
// torn down after (in the background: the result does not wait for the teardown). A nil
// error with reported false means wslc ran but no authenticated report came back; the
// caller says what that means for its payload. An error is never marked not dispatched
// once wslc starts a container, which may have run guest code.
func (p *Provider) runPlan(ctx context.Context, s *verified, files []runnerwire.File, steps, artifacts []string, budget time.Duration) (planRun, error) {
	if p.pr == nil {
		release, err := p.takeTurn(ctx, budget)
		if err != nil {
			return planRun{}, err
		}
		defer release()
		return p.runIn(ctx, s, "", files, steps, artifacts, budget)
	}
	release, err := p.admitRun()
	if err != nil {
		return planRun{}, err
	}
	defer release()
	h, _, err := p.openRunSession(ctx)
	if err != nil {
		return planRun{}, err
	}
	out, err := p.runIn(ctx, s, h.name, files, steps, artifacts, budget)
	// A run that ended abnormally, or whose holder died under it, takes the give-up path.
	p.endSessionLater(h, err == nil && out.ended == nil && !h.dead())
	return out, err
}

// takeTurn is the shared mode's cap of one run at a time. A run that
// finds the place taken waits for it, no longer than its own budget and no longer than
// its caller's context; a run that gives up waiting was refused before anything started,
// marked not dispatched with reason capacity. release gives the place back, after the
// run's container has been removed.
func (p *Provider) takeTurn(ctx context.Context, budget time.Duration) (release func(), err error) {
	wctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	select {
	case p.turn <- struct{}{}:
		return func() { <-p.turn }, nil
	case <-wctx.Done():
		return nil, sandbox.NotDispatched(sandbox.RefusalCapacity,
			fmt.Errorf("wslc: another run holds the shared session (one run at a time, because --ulimit nproc counts across the session VM) and this one's wait ended: %w", wctx.Err()))
	}
}

// runPolicy is the Policy every dispatched run's result carries: PolicyGVisor when gVisor
// is on (a run is refused before it starts unless its VM's default runtime read back as
// runsc), "" otherwise.
func (p *Provider) runPolicy() string {
	if p.cfg.GVisor {
		return PolicyGVisor
	}
	return ""
}

// runIn starts one container for plan in session ("" is the default session).
func (p *Provider) runIn(ctx context.Context, s *verified, session string, files []runnerwire.File, steps, artifacts []string, budget time.Duration) (planRun, error) {
	return p.runInNamed(ctx, s, session, containerName(), files, steps, artifacts, budget)
}

// runInNamed is runIn with the container's name chosen by the caller (the gVisor smoke
// test reads the container from the VM's side by that name while the boundary test runs).
func (p *Provider) runInNamed(ctx context.Context, s *verified, session, name string, files []runnerwire.File, steps, artifacts []string, budget time.Duration) (planRun, error) {
	key, err := runnerwire.NewKey()
	if err != nil {
		return planRun{}, sandbox.NotDispatched(sandbox.RefusalEnvironment, err)
	}
	// The steps get the image's environment; the runner itself starts with none of it.
	plan := runnerwire.Plan{Files: files, Steps: steps, Budget: budget, Artifacts: artifacts,
		Env: append([]string(nil), s.imageEnv...), ReportKey: key}
	planJSON, err := plan.Encode()
	if err != nil {
		return planRun{}, sandbox.NotDispatched(sandbox.RefusalRequest, err)
	}
	argv := p.runArgv(name, s.imageID)
	if session != "" {
		argv = append([]string{"--session", session}, argv...)
	}
	if err := checkArgs(argv); err != nil {
		return planRun{}, sandbox.NotDispatched(sandbox.RefusalEnvironment, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, budget+p.cfg.StartAllowance)
	defer cancel()
	cmd := hostCommand(runCtx, p.cfg.Path, argv...)
	cmd.Stdin = bytes.NewReader(planJSON)
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = runnerwire.StdoutCap, errorCap
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// WaitDelay bounds the wait for the streams after the Linux side of interop is
	// killed: a Windows process that outlives it must not hold this call open.
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		// wslc.exe could not be started at all (a missing file, an unsafe argument, a
		// caller that already gave up): exec reports that before a process exists, so
		// nothing ran.
		reason := sandbox.RefusalEnvironment
		if ctx.Err() != nil {
			reason = sandbox.RefusalCapacity
		}
		return planRun{}, sandbox.NotDispatched(reason, fmt.Errorf("wslc: could not start %s: %w", p.cfg.Path, err))
	}
	runErr := cmd.Wait()
	ended := runCtx.Err()

	out := planRun{stdout: stdout.Bytes(), exit: -1, ended: ended}
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		out.exit = 0
	case errors.As(runErr, &exitErr) && exitErr.Exited():
		out.exit = exitErr.ExitCode()
	}
	if (runErr != nil || ended != nil) && session == "" {
		// A client that did not exit 0, or was killed, may have left its container
		// running in the session VM. (A run's own session is torn down whole instead.)
		p.forceRemove(name)
	}
	base := sandbox.ProjectResult{Sandbox: Name, Isolation: p.IsolationClass(), EnvironmentIdentity: imageIdentity(s.imageID), Policy: p.runPolicy()}
	out.result, out.reported = sandbox.RunnerReport(base, stdout.String(), key)
	return out, nil
}

// forceRemove removes a container by name, a few times, each try bounded on its own:
// the run's context may be the one that ended. A removal that keeps failing is logged;
// the container then ends when its runner's own budget does, since --rm removes it on
// exit.
func (p *Provider) forceRemove(name string) {
	var err error
	for try := 0; try < p.removeTries; try++ {
		if try > 0 {
			time.Sleep(p.removePause)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err = p.output(ctx, "container", "remove", "--force", name)
		cancel()
		if err == nil {
			return
		}
	}
	slog.Error("wslc: could not remove a run's container", "container", name, "err", err)
}

// noReport is the result of a run whose runner wrote no authenticated report. Nothing
// shows whether the runner started (there is no start marker in this provider: the marker
// the docker provider writes needs a shell script in argv), so it is never marked not
// dispatched, and its detail is plimsoll's own words, never the container's stderr.
func (p *Provider) noReport(out planRun) (sandbox.ProjectResult, error) {
	tier := p.IsolationClass()
	if out.ended == context.DeadlineExceeded {
		return sandbox.ProjectResult{Sandbox: Name, Isolation: tier, Policy: p.runPolicy(),
			Outcome: sandbox.ProjectOutcomeTimedOut, Detail: "run exceeded the time budget"}, nil
	}
	if out.ended != nil {
		return sandbox.ProjectResult{Sandbox: Name, Isolation: tier, Policy: p.runPolicy()}, out.ended
	}
	return sandbox.ProjectResult{Sandbox: Name, Isolation: tier, Policy: p.runPolicy()},
		fmt.Errorf("wslc: the run ended (wslc exit %d) with no authenticated runner report; it may have run", out.exit)
}

// RunProject writes the files and runs the steps in order in a fresh container.
func (p *Provider) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	res := sandbox.ProjectResult{Sandbox: Name, Isolation: p.IsolationClass()}
	if err := sandbox.ValidateProjectRequest(req); err != nil {
		return res, err
	}
	s, err := p.admit(req.MinimumIsolation, req.Software, req.Grant)
	if err != nil {
		return res, err
	}
	files := make([]runnerwire.File, len(req.Files))
	for i, f := range req.Files {
		files[i] = runnerwire.File(f)
	}
	out, err := p.runPlan(ctx, s, files, req.Steps, req.Artifacts, p.clamp(req.Timeout))
	if err != nil {
		return res, err
	}
	if !out.reported {
		return p.noReport(out)
	}
	return out.result, nil
}

// RunJavaScript runs the snippet as a one-file project with one node step.
func (p *Provider) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	res := sandbox.Result{Sandbox: Name, Isolation: p.IsolationClass()}
	if err := sandbox.ValidateRequest(req); err != nil {
		return res, err
	}
	s, err := p.admit(req.MinimumIsolation, req.Software, req.Grant)
	if err != nil {
		return res, err
	}
	out, err := p.runPlan(ctx, s, []runnerwire.File{{Path: snippetFile, Content: req.Code}}, []string{snippetStep}, nil, p.clamp(req.Timeout))
	if err != nil {
		return res, err
	}
	res.EnvironmentIdentity = imageIdentity(s.imageID)
	res.Policy = p.runPolicy()
	if !out.reported {
		pr, err := p.noReport(out)
		if err != nil {
			return res, err
		}
		res.TimedOut, res.ExitCode = pr.Outcome == sandbox.ProjectOutcomeTimedOut, 124
		return res, nil
	}
	r := out.result
	switch {
	case r.Outcome == sandbox.ProjectOutcomeSetupFailed && len(r.Steps) == 0:
		// The runner stages the file before it starts any step, so nothing ran.
		return res, sandbox.NotDispatched(sandbox.RefusalEnvironment, errors.New("wslc: the runner could not stage the snippet"))
	case len(r.Steps) != 1 || (r.Outcome != sandbox.ProjectOutcomeCompleted && r.Outcome != sandbox.ProjectOutcomeTimedOut):
		return res, fmt.Errorf("wslc: the runner ended the snippet as %s with %d steps", r.Outcome, len(r.Steps))
	}
	st := r.Steps[0]
	res.Stdout, res.Stderr = st.Stdout, st.Stderr
	res.StdoutTruncated, res.StderrTruncated = st.StdoutTruncated, st.StderrTruncated
	res.ExitCode, res.TimedOut, res.Duration = st.ExitCode, st.TimedOut || r.Outcome == sandbox.ProjectOutcomeTimedOut, st.Duration
	return res, nil
}
