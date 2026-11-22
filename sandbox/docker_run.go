package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

func (d *DockerSandbox) RunJavaScript(ctx context.Context, req Request) (Result, error) {
	if err := ValidateRequest(req); err != nil {
		return Result{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	execState, isolation, err := d.admit(ctx, dockerSnippet, req.MinimumIsolation, req.Software)
	if err != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, err
	}
	return d.runSnippet(ctx, execState, req)
}

// dockerPayload is which configured image a call launches.
type dockerPayload int

const (
	dockerSnippet dockerPayload = iota
	dockerProject
	dockerModule
)

// admit is every check before a docker call dispatches, in one order for every payload
// kind (review R4): the kind's image is configured, Preflight has verified the daemon
// and images, the execution state is the one the smoke test proved, the run's tier
// meets the caller's floor, and the image's selected manifest meets the caller's
// software rule. It returns that state, and the isolation evidence a refusal reports:
// the provider's before the state is known, the state's after.
func (d *DockerSandbox) admit(ctx context.Context, kind dockerPayload, floor IsolationClass, rule SoftwareRule) (dockerExecutionState, IsolationClass, error) {
	switch kind {
	case dockerSnippet:
		if err := validateDockerImage(d.Image); err != nil {
			return dockerExecutionState{}, 0, notReady(ctx, err)
		}
	case dockerProject:
		if err := validateDockerImage(d.ProjectImage); err != nil {
			return dockerExecutionState{}, 0, notReady(ctx, err)
		}
	case dockerModule:
		if d.ModuleImage == "" {
			return dockerExecutionState{}, d.IsolationClass(),
				refused(fmt.Errorf("%w: no module image is configured (SANDBOX_DOCKER_MODULE_IMAGE)", ErrUnsupported))
		}
	}
	if err := d.ensurePreflight(ctx); err != nil {
		return dockerExecutionState{}, d.IsolationClass(), notReady(ctx, err)
	}
	state, err := d.executionState()
	if err != nil {
		return dockerExecutionState{}, d.IsolationClass(), notReady(ctx, err)
	}
	if err := CheckMinimumIsolation(state.isolation, floor); err != nil {
		return dockerExecutionState{}, state.isolation, err
	}
	manifest := map[dockerPayload]string{dockerSnippet: state.imageManifest, dockerProject: state.projectManifest, dockerModule: state.moduleManifest}[kind]
	if err := rule.Check(manifest); err != nil {
		return dockerExecutionState{}, state.isolation, err
	}
	return state, state.isolation, nil
}

// runSnippet runs req in the snippet image under execState, once every check before
// dispatch has passed: the launch that RunJavaScript and the startup smoke test share.
func (d *DockerSandbox) runSnippet(ctx context.Context, execState dockerExecutionState, req Request) (Result, error) {
	isolation := execState.isolation
	timeout := d.snippetTimeout(req.Timeout)

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Name the container so we can force-remove it. On timeout, CommandContext
	// kills the `docker run` *client*, but the container keeps running until its
	// work finishes (an infinite loop would never stop). Force-removing by name
	// guarantees the workload is torn down even when the client was killed.
	name := "crsbx-" + providerkit.RandHex(8)

	// The seccomp profile this run applies, selected from its grant (a run whose grant
	// asks for the local address gets the sdk_env variant), and refused before anything
	// starts when the configuration has none for it.
	seccomp, policy, err := execState.seccomp.seccompFor(req.Grant, execState.runtime)
	if err != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, err
	}
	policy = execState.withGuard(policy)
	broker, mountArgs, grantEnv, err := d.brokerForRun(runCtx, req.Grant, timeout)
	if err != nil {
		return Result{Sandbox: d.Name()}, err
	}
	defer broker.Close()
	args := append(d.lockdownArgs(name, d.containerExpiry(runCtx), false, execState.runtime, seccomp), mountArgs...)
	if execState.platform != "" {
		args = append(args, "--platform", execState.platform)
	}
	// Launch the Preflight-verified content ID, not the mutable tag. startScript writes
	// started to stderr before node exists; node then reads the script from stdin with
	// the image's environment. What the guest's code prints comes after the marker, so
	// it cannot pass its own exit for docker's, and of what the image declares only the
	// loader variables could act before it, which Preflight refuses (checkLoaderEnv).
	// The marker comes before node is started, so the startup smoke test runs a snippet
	// this way (smokeSnippet): an image whose PATH lacks node fails there, not as every
	// guest's exit 127.
	started := startMarker()
	// A snippet whose grant asks for the local address starts behind the forwarder,
	// which listens before `node -` reads the code; every other snippet is `node -`.
	var argv []string
	if req.Grant.WantsLoopback() {
		argv, err = dockerForwardingSnippetArgv(started, d.hostAPIListenAddr(), execState.guestEnv(execState.imageID, grantEnv...))
	} else {
		argv, err = guestArgv(started, execState.guestEnv(execState.imageID, grantEnv...), sessionkit.GuestNodeArgv("-")...)
	}
	if err != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, err
	}
	tail, err := launch(execState.guard, execState.imageID, argv)
	if err != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, err
	}
	args = append(args, tail...)
	args, err = dockerArgs(execState.host, args...)
	if err != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, err
	}

	cmd := dockerCommand(runCtx, args...)
	if refused := refusedCommand(cmd); refused != nil {
		// The refusing point refused the command: docker never started, so nothing ran.
		return Result{Sandbox: d.Name(), Isolation: isolation}, NotDispatched(RefusalEnvironment, refused)
	}
	cmd.Stdin = bytes.NewReader([]byte(withHostSDK(req.Code, req.Grant)))
	var stdout, stderr providerkit.Capture
	stdout.Limit = d.maxOutput()
	stderr.Limit = d.maxOutput() + len(started) // the marker is not the guest's output
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err = cmd.Run()
	duration := time.Since(start)
	// What ended the run is read now, before the cleanup below, which has a budget of
	// its own and can outlast the run's deadline: read after it, a docker failure that
	// took milliseconds, or a guest that exited in time, came back as a timed-out run
	// (R6 review, 2026-10-03).
	ended := deadline.Expired(runCtx)
	// The run is over once the CLI returns, so its grant ends here, before the cleanup:
	// a container the CLI left behind keeps running until its removal, which can
	// take more than half a minute, and its processes must not spend that time making
	// granted calls. The trace is complete from here and goes on every result below.
	trace := broker.finalTrace()
	if err != nil || ended != nil {
		// A CLI that did not exit 0 may have failed itself (a broken attach stream, a
		// daemon restart under live-restore) and left the container running with
		// nothing to stop it (review F2); one --rm already removed costs a docker rm
		// that finds nothing.
		d.removeOrHold(ctx, execState.host, name)
	}

	// The marker is in stderr exactly when the start script ran, which writes it before
	// node starts; it is never the guest's.
	guestStderr, guestStarted := afterMarker(stderr.String(), started)
	res := Result{
		Stdout:              stdout.String(),
		Stderr:              guestStderr,
		StdoutTruncated:     stdout.Truncated(),
		StderrTruncated:     stderr.Truncated(),
		Duration:            duration,
		Sandbox:             d.Name(),
		Isolation:           isolation,
		SoftwareIdentity:    execState.imageManifest,
		EnvironmentIdentity: dockerImageIdentity(execState.imageID),
		Policy:              policy,
		// Metadata-only evidence of the run's brokered host.* calls. Nil unless the
		// run carried a grant that made calls; it never affects execution below.
		CallTrace: trace,
	}

	if ended != nil && !guestStarted {
		// The run ended with no start marker: nothing shows the guest's code started, so
		// it is not reported as the guest's timeout. Unmarked, as below.
		return Result{Sandbox: d.Name(), Isolation: isolation, CallTrace: trace}, fmt.Errorf("docker did not start the container's command before the run ended: %w", ended)
	}
	if ended == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = 124
		return res, nil
	}
	if ended != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation, CallTrace: trace}, ended
	}

	if !guestStarted {
		// No start marker, whatever docker exited with: an infrastructure error, not "your
		// code exited non-zero", and never marked (unstartedRun), the guest guard's refusal
		// included.
		return Result{Sandbox: d.Name(), CallTrace: trace}, unstartedRun("container's command", err, stderr.String())
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || !exitErr.Exited() {
			// The docker CLI itself failed or was killed by a signal: what the guest
			// exited with never reached this process.
			return Result{Sandbox: d.Name(), Isolation: isolation, CallTrace: trace}, fmt.Errorf("the docker CLI failed during the run: %w", err)
		}
		// The guest's own exit, relayed by the CLI: a normal result, not an error.
		res.ExitCode = exitErr.ExitCode()
	}
	return res, nil
}

// unstartedRun is the error of a fresh run (a snippet, a project, a module run) whose
// container's standard error does not hold the run's start marker: what names the command,
// runErr is what the docker CLI returned, stderr is that standard error. It is never marked not
// dispatched, because no mark means the run may have executed and that must stay true here.
//
// Almost always docker failed before the container's command started (a bad image, a rejected
// flag, a daemon error), but a broken attach stream can lose the marker of a run that ran. The
// guest guard's refusal is no exception, though nothing of the run started when it is real: what
// shows it is the guard's line as the last line of this standard error and the exit code of the
// step it names, with no marker before them. A snippet's node is the container's command, so the
// run's own code writes this standard error and picks this exit code; and under runc it can open
// the same stream again for reading through /proc/self/fd/2 (measured 2026-11-20: 40 of 40 fresh
// snippets whose first statement did so got the descriptor and read nothing, docker having taken
// the marker first). So the marker's absence would rest on docker reading it before the run's
// code does, and a mark could tell a caller that a run that ran did not, inviting a retry that
// runs it again. A project's steps hold no descriptor of this stream while the runner guard
// holds, and cannot make the runner exit with a code of the guard's, but a project and a module
// run are held to the same rule rather than to that chain of facts. It is the rule a held
// session's call follows (dockerSession.callRefusal). An end in the guard's shape gets
// plimsoll's own words for the step and errno it names, never the line itself, and says that
// whether the run's code ran is not known. The only mark a fresh run takes at its launch is the
// refusing point's (refusedCommand): there docker never started.
func unstartedRun(what string, runErr error, stderr string) error {
	code := exitCodeOf(runErr)
	if step, errno, ok := guestGuardShape(code, stderr); ok {
		return fmt.Errorf("the run's %s ended as the guest guard ends when it refuses (step %s, errno %d, exit %d) and its start marker was not read; code of the run can write that line and exit with that code, so whether the run's code ran is not known", what, step, errno, code)
	}
	return fmt.Errorf("docker did not run the %s (%v): %s", what, runErr, truncateForError(strings.TrimSpace(stderr)))
}

// runnerSteps and runnerArtifacts copy the runner's decoded report into this
// package's result types (the runner package cannot import this one).
func (d *DockerSandbox) RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error) {
	if err := ValidateProjectRequest(req); err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	execState, isolation, err := d.admit(ctx, dockerProject, req.MinimumIsolation, req.Software)
	if err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, err
	}
	return d.runPlan(ctx, execState, execState.projectImageID, req)
}

// runPlan launches one runner container from a Preflight-verified image ID with
// req as its plan and classifies what came back. RunProject and RunModule share
// it: a module run is a project run whose one step is the worker, so every
// lockdown, timeout, output cap and outcome rule is written once.
func (d *DockerSandbox) runPlan(ctx context.Context, execState dockerExecutionState, imageID string, req ProjectRequest) (out ProjectResult, errOut error) {
	selected := execState.projectManifest
	if imageID == execState.moduleImageID && execState.moduleImageID != "" {
		selected = execState.moduleManifest
	}
	defer func() {
		out.SoftwareIdentity = selected
		out.EnvironmentIdentity = dockerImageIdentity(imageID)
	}()
	isolation := execState.isolation
	timeout := d.projectTimeout(req.Timeout)

	// The runner gives the steps one deadline (the plan's budget); the outer context is a hard backstop
	// with a small grace so the runner reports cleanly before docker is killed.
	runCtx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()

	// The seccomp profile this run applies, selected from its grant as in runSnippet.
	seccomp, policy, err := execState.seccomp.seccompFor(req.Grant, execState.runtime)
	if err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, err
	}
	policy = execState.withGuard(policy)
	// A grant mounts the same per-run broker socket the snippet path uses; the runner
	// preloads hostSDKModule(grant) into every step so project files reach host.* over
	// the shared brokerSession. Nil grant → nil broker, no socket, empty HostSDK.
	broker, mountArgs, grantEnv, err := d.brokerForRun(runCtx, req.Grant, timeout)
	if err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, err
	}
	defer broker.Close()

	// The report key authenticates the runner's report: every process in the
	// container can write the runner's stdout, so an unsigned report could be forged
	// (internal/runnerwire). It travels only in the plan on stdin.
	reportKey, err := runnerwire.NewKey()
	if err != nil {
		return ProjectResult{Sandbox: d.Name()}, err
	}
	// The steps start with the image's environment and the grant's socket; the runner
	// itself starts with neither (runnerArgv).
	plan := runnerwire.Plan{Steps: req.Steps, Budget: timeout, Artifacts: req.Artifacts, HostSDK: hostSDKModule(req.Grant),
		Env: execState.guestEnv(imageID, grantEnv...), ReportKey: reportKey}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, runnerwire.File(f))
	}
	planJSON, err := plan.Encode()
	if err != nil {
		return ProjectResult{Sandbox: d.Name()}, err
	}
	started := startMarker()
	// A run whose grant asks for the local address (sdk_env) starts its runner behind
	// the loopback forwarder, so a step's standard HTTP client reaches the broker at
	// the base URL the profile's sdk_env names; every other run, granted or not, keeps
	// the bare runner.
	var runner []string
	if req.Grant.WantsLoopback() {
		runner, err = d.forwardingRunnerArgv(started, d.hostAPIListenAddr())
	} else {
		runner, err = d.runnerArgv(started)
	}
	if err != nil {
		return ProjectResult{Sandbox: d.Name()}, err
	}

	name := "crsbx-" + providerkit.RandHex(8)

	// The runner reads the plan from stdin. Launch the Preflight-verified content ID,
	// not the mutable tag. mountArgs (the broker socket bind) are docker options, so
	// they precede the image; they are empty for a no-grant run.
	args := d.lockdownArgs(name, d.containerExpiry(runCtx), true, execState.runtime, seccomp)
	args = append(args, mountArgs...)
	if execState.platform != "" {
		args = append(args, "--platform", execState.platform)
	}
	tail, err := launch(execState.guard, imageID, runner)
	if err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, err
	}
	args = append(args, tail...)
	args, err = dockerArgs(execState.host, args...)
	if err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, err
	}
	cmd := dockerCommand(runCtx, args...)
	if refused := refusedCommand(cmd); refused != nil {
		// As in runSnippet: docker never started, so nothing ran.
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, NotDispatched(RefusalEnvironment, refused)
	}
	cmd.Stdin = bytes.NewReader(planJSON)
	var stdout, stderr providerkit.Capture
	stdout.Limit = runnerwire.StdoutCap
	stderr.Limit = d.maxOutput() + len(started)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	// Read before the cleanup, as in runSnippet: the cleanup can outlast the deadline.
	ended := deadline.Expired(runCtx)
	// As in RunJavaScript: the grant ends before the cleanup, and the complete trace goes
	// on every result below, failures included (a hung agent calling an API until the
	// deadline is the case the trace exists for).
	trace := broker.finalTrace()
	if runErr != nil || ended != nil {
		// As in RunJavaScript: a CLI that did not exit 0 may have left its container
		// running (review F2).
		d.removeOrHold(ctx, execState.host, name)
	}

	// An authenticated report is the result whatever the backstop says: the runner
	// writes it after its steps ended, each step carries its own TimedOut, and the
	// backstop (the budget plus a short grace, counted from before the container
	// started) can fire while a report is already in stdout, which used to be thrown
	// away as timed out with no steps (review, 2026-10-26).
	res, reported := RunnerReport(ProjectResult{Sandbox: d.Name(), Isolation: isolation, Policy: policy}, stdout.String(), reportKey)
	if !reported && ended != nil {
		if _, ran := afterMarker(stderr.String(), started); !ran {
			// Nothing shows the runner, so any step, started: not reported as a timeout.
			// Unmarked, as below.
			return ProjectResult{Sandbox: d.Name(), Isolation: isolation, CallTrace: trace},
				fmt.Errorf("docker did not start the project container's command before the run ended: %w", ended)
		}
		if ended == context.DeadlineExceeded {
			return ProjectResult{Sandbox: d.Name(), Isolation: isolation, Outcome: ProjectOutcomeTimedOut, Detail: "run exceeded the time budget", CallTrace: trace}, nil
		}
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation, CallTrace: trace}, ended
	}
	if !reported {
		// The runner never reported. Distinguish two very different causes:
		//   - no start marker: almost always docker never started the container's
		//     command, so the sandbox boundary never launched. That is an
		//     INFRASTRUCTURE error (a returned error → CodeInternal at the RPC edge), not
		//     a typed run outcome, and unmarked, since a broken stream can lose a marker.
		//   - the runner started but vanished (OOM-killed inside the sandbox, say):
		//     execution state unknown → ProtocolError.
		var exitErr *exec.ExitError
		if _, ran := afterMarker(stderr.String(), started); !ran {
			// As in runSnippet: never marked, the guest guard's refusal included.
			return ProjectResult{Sandbox: d.Name(), Isolation: isolation, CallTrace: trace},
				unstartedRun("project container's command", runErr, stderr.String())
		}
		// Detail is plimsoll's own words: it reaches the audit line, and the
		// container's stderr is writable by every process in the sandbox. The exit
		// code survives (137 is the kernel's kill, for instance an OOM).
		detail := "the runner did not report"
		if errors.As(runErr, &exitErr) {
			detail = fmt.Sprintf("the runner did not report (container exit %d)", exitErr.ExitCode())
		}
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation, Outcome: ProjectOutcomeProtocolError, Detail: detail, CallTrace: trace}, nil
	}
	// Metadata-only evidence of the run's brokered host.* calls; nil unless the run
	// carried a grant that made calls. Never affects the outcome.
	res.CallTrace = trace
	return res, nil
}

// moduleResultsArtifact is the path, under /work, the worker writes its record to
// and the run captures as its one artifact.
const moduleResultsArtifact = "results.bin"

// RunModule runs a simulator baked into ModuleImage once per row through the same
// runner and lockdown as a project: the parameter table is written into /work as
// text (shortest round-trip decimals, so every value reaches the worker exactly),
// one step runs the worker in table mode with the result budget on its command
// line, and the results come back as one artifact decoded here. The worker
// refuses a table whose results could exceed the budget before it runs a row
// (ValidateModuleRequest applied the width-1 necessary condition already), so
// results are never truncated: that refusal is ErrInvalidRequest, and a worker
// that accepted the table and still overran the artifact budget is a protocol
// error, never a shorter answer.
func (d *DockerSandbox) RunModule(ctx context.Context, req ModuleRequest) (ModuleResult, error) {
	if err := ValidateModuleRequest(req); err != nil {
		return ModuleResult{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	execState, isolation, err := d.admit(ctx, dockerModule, req.MinimumIsolation, req.Software)
	if err != nil {
		return ModuleResult{Sandbox: d.Name(), Isolation: isolation}, err
	}

	var table strings.Builder
	for _, row := range req.Rows {
		for j, v := range row {
			if j > 0 {
				table.WriteByte(' ')
			}
			table.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
		}
		table.WriteByte('\n')
	}
	step := fmt.Sprintf("sim-worker --table /models/%s.so params.txt %s %s %s %d",
		req.Model, moduleResultsArtifact,
		strconv.FormatFloat(req.EndTime, 'g', -1, 64), strconv.FormatFloat(req.Step, 'g', -1, 64),
		MaxModuleResultBytes)
	started := time.Now()
	pr, err := d.runPlan(ctx, execState, execState.moduleImageID, ProjectRequest{
		Files:     []File{{Path: "params.txt", Content: table.String()}},
		Steps:     []string{step},
		Timeout:   req.Timeout,
		Artifacts: []string{moduleResultsArtifact},
	})
	res := ModuleResult{Sandbox: d.Name(), Isolation: isolation, SoftwareIdentity: execState.moduleManifest,
		EnvironmentIdentity: dockerImageIdentity(execState.moduleImageID), Duration: time.Since(started), Policy: pr.Policy}
	if err != nil {
		return res, err
	}
	return interpretModuleRun(res, pr, req)
}

// interpretModuleRun turns the runner's report of the one worker step into a
// ModuleResult. The worker's exit codes are its contract (docker/sim/worker.c):
// 0 done; 1 the module failed to load or validate; 2 usage; 3 the table was
// malformed; 4 the results could exceed the byte budget, refused before any row
// ran; 5 the output was unwritable. 1 to 3 are request-attributable, so
// setup_failed with the worker's diagnostic; 4 is ErrInvalidRequest; anything
// else, including a signal, is a protocol error.
func interpretModuleRun(res ModuleResult, pr ProjectResult, req ModuleRequest) (ModuleResult, error) {
	res.Outcome, res.Detail = pr.Outcome, pr.Detail
	// runPlan classifies a timed-out step, so that case arrives here already
	// typed. Carry the worker's output through the early return anyway, and say
	// it in the module operation's own vocabulary.
	if len(pr.Steps) == 1 {
		res.Stdout, res.Stderr = pr.Steps[0].Stdout, pr.Steps[0].Stderr
		if pr.Steps[0].TimedOut {
			res.Detail = "the worker exceeded the time budget"
		}
	}
	if pr.Outcome != ProjectOutcomeCompleted {
		return res, nil
	}
	if len(pr.Steps) != 1 {
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, fmt.Sprintf("runner reported %d steps for the one worker step", len(pr.Steps))
		return res, nil
	}
	st := pr.Steps[0]
	diag := strings.TrimSpace(st.Stderr)
	switch st.ExitCode {
	case 0:
	case 4:
		return res, fmt.Errorf("%w: %s", ErrInvalidRequest, diag)
	case 1, 2, 3:
		res.Outcome, res.Detail = ProjectOutcomeSetupFailed, "the worker refused the request: "+diag
		return res, nil
	default:
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, fmt.Sprintf("the worker exited %d: %s", st.ExitCode, diag)
		return res, nil
	}
	if pr.ArtifactsTruncated {
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, "the worker accepted the table but its results exceeded the artifact budget"
		return res, nil
	}
	var rec []byte
	found := false
	for _, a := range pr.Artifacts {
		if a.Path == moduleResultsArtifact {
			rec, found = a.Content, true
		}
	}
	if !found {
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, "the worker exited 0 without writing its results"
		return res, nil
	}
	runs, width, err := DecodeModuleResults(rec, len(req.Rows), req.RowWidth())
	if err != nil {
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, "undecodable worker results: "+err.Error()
		return res, nil
	}
	res.Runs, res.Width = runs, width
	return res, nil
}

// Removal's bounds: removeAttempts tries of removeAttemptBudget each, a pause of one
// second after the first and two after the second. dockerRemoveBudget is the sum and is
// one deadline over all of it: each attempt's removal and its absence check share the
// attempt's budget, which the whole deadline also bounds, so forceRemove never takes
// longer. Before, each absence check had a fresh budget of its own, so a stalled daemon
// could hold a removal for about 63 s against the 33 s stated (review, 2026-10-23).
const (
	removeAttempts      = 3
	removeAttemptBudget = 10 * time.Second
	dockerRemoveBudget  = removeAttempts*removeAttemptBudget + (removeAttempts-1)*removeAttempts/2*time.Second
)

// removeContainer removes the container name and returns nil once it is confirmed gone:
// `docker rm -f` up to removeAttempts times, each after unpauseForRemoval and followed when
// it fails by an exact-name listing (containerGone), all inside ctx. Killing `docker run`
// does not guarantee its container stops, so a removal that cannot be confirmed is an
// error, never a silent success. It is the one way every container of the provider is
// removed: a run's, a session's at its end (close, lifetime, drain), a failed open's, a
// pool member's, and the orphan pass's.
func removeContainer(ctx context.Context, host, name string) error {
	args, err := dockerArgs(host, "rm", "-f", name)
	if err != nil {
		return fmt.Errorf("cannot remove a container without a pinned daemon endpoint: %w", err)
	}
	for attempt := 1; ; attempt++ {
		actx, cancel := context.WithTimeout(ctx, removeAttemptBudget)
		unpauseForRemoval(actx, host, name)
		_, err := dockerOutput(actx, args...)
		gone := err == nil || containerGone(actx, host, name)
		cancel()
		if gone {
			return nil
		}
		if err == nil {
			err = errors.New("the container is still listed")
		}
		if attempt == removeAttempts || providerkit.Sleep(ctx, time.Duration(attempt)*time.Second) != nil {
			return fmt.Errorf("container %s not confirmed gone after %d attempts: %w", name, attempt, err)
		}
	}
}

// unpauseForRemoval unpauses name when it is paused (a suspended session's container) and
// its runtime is not runc, so the `docker rm -f` right after it kills a running sandbox
// (hunt-quality-106). Measured 2026-11-20 on Docker Engine 29.1.3 and gVisor
// release-20260907.0, cgroup v2, with a scratch script's containers (a relay-shaped
// docker exec attached, then docker pause):
//
//   - gVisor: rm -f of the paused container took 10.2 s, and so did docker kill: docker's
//     kill does not take ("container ... is zombie and can not be killed", seen when a kill
//     ran beside an unpause), so docker waits its 10 s for the container to stop and then
//     ends it directly. Each removal try has 10 s (removeAttemptBudget), so the first try
//     was always killed and the second confirmed it, about 11 s after the end began. With
//     unpause first, the rm -f took 147 ms (170 ms in all).
//   - runc: rm -f of the paused container took 138 ms and docker kill 59 ms, and the
//     guest's code ran not at all (a loop counting in a bind-mounted file did not move): the
//     kill reaches the frozen processes. So runc is not unpaused.
//
// No way of removing a paused gVisor container fast without letting it run again was
// found: rm -f and kill both wait the 10 s, and a kill sent before the unpause held the
// rm -f after it too, while the unpaused guest ran for 6.6 s of it. So under gVisor the guest's code runs again
// between the unpause and the kill of the rm -f after it: measured at about 22 ms of the
// counting loop's run time (1,736 iterations at 77,000 a second). In that moment it can do
// only what it could do while the session ran, and less: every way out of the container
// was shut before the removal began (a session's teardown closes its relays, then its
// broker's socket, then removes the container; a failed open and a pool member close the
// broker first; a dead daemon's broker sockets and relays died with it), it has no
// network (--network none), its root file system is read-only and its writable places are
// tmpfs mounts the removal destroys, and the limits on memory, processes and CPU and the
// seccomp profile still apply. It cannot keep the kill from ending it. A container that is
// not paused, already gone, or whose state cannot be read is left to the rm -f as before:
// one docker inspect more per try, about 10 ms.
func unpauseForRemoval(ctx context.Context, host, name string) {
	args, err := dockerArgs(host, "inspect", "--type", "container", "--format", "{{.State.Paused}} {{.HostConfig.Runtime}}", name)
	if err != nil {
		return
	}
	state, err := dockerOutput(ctx, args...)
	if err != nil {
		return
	}
	paused, rt, _ := strings.Cut(strings.TrimSpace(string(state)), " ")
	if paused != "true" || rt == "runc" {
		return
	}
	if args, err := dockerArgs(host, "unpause", name); err == nil {
		_, _ = dockerOutput(ctx, args...)
	}
}

// forceRemove is removeContainer under dockerRemoveBudget, on its own context so it
// runs after the run's has ended. It logs and returns a removal it could not confirm.
func (d *DockerSandbox) forceRemove(host, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dockerRemoveBudget)
	defer cancel()
	err := removeContainer(ctx, host, name)
	if err != nil {
		slog.Error("docker: failed to remove a sandbox container", "container", name, "error", err)
	}
	return err
}

// removeOrHold is a run's teardown: forceRemove, and when the container cannot be
// confirmed gone, it is quarantined (providerkit.Quarantine): the capacity admitted for
// the call ctx belongs to stays held, and ReconcileOrphans retries the removal on every
// pass until it is confirmed gone. Call it before the call returns.
func (d *DockerSandbox) removeOrHold(ctx context.Context, host, name string) {
	if err := d.quarantine.Destroy(name, HoldCapacity(ctx), func() error { return d.forceRemove(host, name) }); err != nil {
		slog.Error("docker: container quarantined; its capacity stays held until ReconcileOrphans confirms it gone", "container", name)
	}
}

// containerGone reports whether no container named name exists, by an exact-name
// listing: never by reading docker's error wording ("No such container"), which a
// docker version may change, nor by its exit code, which differs between versions
// (docker 29's rm -f exits 0 for a missing container). An unreadable listing is
// "not known to be gone".
func containerGone(ctx context.Context, host, name string) bool {
	args, err := dockerArgs(host, "ps", "-a", "-q", "--no-trunc", "--filter", "name=^"+regexp.QuoteMeta(name)+"$")
	if err != nil {
		return false
	}
	out, err := dockerOutput(ctx, args...)
	return err == nil && strings.TrimSpace(string(out)) == ""
}
