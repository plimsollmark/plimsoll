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
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
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
	name := "crsbx-" + randID()

	broker, mountArgs, grantEnv, err := d.brokerForRun(runCtx, req.Grant, timeout)
	if err != nil {
		return Result{Sandbox: d.Name()}, err
	}
	defer broker.Close()
	args := append(d.lockdownArgs(name, d.containerExpiry(runCtx), false, execState.runtime), mountArgs...)
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
	argv, err := guestArgv(started, execState.guestEnv(execState.imageID, grantEnv...), "node", "-")
	if err != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, err
	}
	args = append(args, launch(execState.imageID, argv)...)
	args, err = dockerArgs(execState.host, args...)
	if err != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, err
	}

	cmd := dockerCommand(runCtx, args...)
	cmd.Stdin = bytes.NewReader([]byte(withHostSDK(req.Code, req.Grant)))
	var stdout, stderr cappedBuffer
	stdout.limit = d.maxOutput()
	stderr.limit = d.maxOutput() + len(started) // the marker is not the guest's output
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
	if err != nil || ended != nil {
		// A CLI that did not exit 0 may have failed itself (a broken attach stream, a
		// daemon restart under live-restore) and left the container running with
		// nothing to stop it (review F2); one --rm already removed costs a docker rm
		// that finds nothing.
		d.forceRemove(execState.host, name)
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
		// Metadata-only evidence of the run's brokered host.* calls. Nil unless the
		// run carried a grant that made calls; it never affects execution below.
		CallTrace: broker.finalTrace(),
	}

	if ended != nil && !guestStarted {
		// The run ended with no start marker: nothing shows the guest's code started, so
		// it is not reported as the guest's timeout. Unmarked, as below.
		return Result{Sandbox: d.Name(), Isolation: isolation}, fmt.Errorf("docker did not start the container's command before the run ended: %w", ended)
	}
	if ended == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = 124
		return res, nil
	}
	if ended != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, ended
	}

	if !guestStarted {
		// No start marker, whatever docker exited with: almost always docker failed before
		// the container's command started (a bad image, a rejected flag, a daemon error),
		// so it is an infrastructure error, not "your code exited non-zero". Unmarked: a
		// broken attach stream could lose the marker of a run that ran.
		return Result{Sandbox: d.Name()}, fmt.Errorf("docker did not run the container's command (%v): %s", err, truncateForError(strings.TrimSpace(stderr.String())))
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || !exitErr.Exited() {
			// The docker CLI itself failed or was killed by a signal: what the guest
			// exited with never reached this process.
			return Result{Sandbox: d.Name(), Isolation: isolation}, fmt.Errorf("the docker CLI failed during the run: %w", err)
		}
		// The guest's own exit, relayed by the CLI: a normal result, not an error.
		res.ExitCode = exitErr.ExitCode()
	}
	return res, nil
}

// runnerSteps and runnerArtifacts copy the runner's decoded report into this
// package's result types (the runner package cannot import this one).
func runnerSteps(steps []runnerwire.Step) []StepResult {
	var out []StepResult
	for _, s := range steps {
		out = append(out, StepResult(s))
	}
	return out
}

func runnerArtifacts(artifacts []runnerwire.Artifact) []Artifact {
	var out []Artifact
	for _, a := range artifacts {
		out = append(out, Artifact(a))
	}
	return out
}

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

	// The runner enforces a per-step timeout; the outer context is a hard backstop
	// with a small grace so the runner reports cleanly before docker is killed.
	runCtx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()

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
	// itself starts with neither (dockerRunnerArgv).
	plan := runnerwire.Plan{Steps: req.Steps, StepTimeout: timeout, Artifacts: req.Artifacts, HostSDK: hostSDKModule(req.Grant),
		Env: execState.guestEnv(imageID, grantEnv...), ReportKey: reportKey}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, runnerwire.File(f))
	}
	planJSON, err := plan.Encode()
	if err != nil {
		return ProjectResult{Sandbox: d.Name()}, err
	}
	started := startMarker()
	runner, err := dockerRunnerArgv(started)
	if err != nil {
		return ProjectResult{Sandbox: d.Name()}, err
	}

	name := "crsbx-" + randID()

	// The runner reads the plan from stdin. Launch the Preflight-verified content ID,
	// not the mutable tag. mountArgs (the broker socket bind) are docker options, so
	// they precede the image; they are empty for a no-grant run.
	args := d.lockdownArgs(name, d.containerExpiry(runCtx), true, execState.runtime)
	args = append(args, mountArgs...)
	if execState.platform != "" {
		args = append(args, "--platform", execState.platform)
	}
	args = append(args, launch(imageID, runner)...)
	args, err = dockerArgs(execState.host, args...)
	if err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, err
	}
	cmd := dockerCommand(runCtx, args...)
	cmd.Stdin = bytes.NewReader(planJSON)
	var stdout, stderr cappedBuffer
	stdout.limit = runnerwire.StdoutCap
	stderr.limit = d.maxOutput() + len(started)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	// Read before the cleanup, as in runSnippet: the cleanup can outlast the deadline.
	ended := deadline.Expired(runCtx)
	if runErr != nil || ended != nil {
		// As in RunJavaScript: a CLI that did not exit 0 may have left its container
		// running (review F2).
		d.forceRemove(execState.host, name)
	}

	if ended != nil {
		if _, ran := afterMarker(stderr.String(), started); !ran {
			// Nothing shows the runner, so any step, started: not reported as a timeout.
			// Unmarked, as below.
			return ProjectResult{Sandbox: d.Name(), Isolation: isolation},
				fmt.Errorf("docker did not start the project container's command before the run ended: %w", ended)
		}
		if ended == context.DeadlineExceeded {
			return ProjectResult{Sandbox: d.Name(), Isolation: isolation, Outcome: ProjectOutcomeTimedOut, Detail: "run exceeded the time budget"}, nil
		}
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, ended
	}

	report, found, parseErr := runnerwire.Parse(stdout.String(), reportKey)
	if !found {
		// The runner never reported. Distinguish two very different causes:
		//   - no start marker: almost always docker never started the container's
		//     command, so the sandbox boundary never launched. That is an
		//     INFRASTRUCTURE error (a returned error → CodeInternal at the RPC edge), not
		//     a typed run outcome, and unmarked, since a broken stream can lose a marker.
		//   - the runner started but vanished (OOM-killed inside the sandbox, say):
		//     execution state unknown → ProtocolError.
		var exitErr *exec.ExitError
		if _, ran := afterMarker(stderr.String(), started); !ran {
			return ProjectResult{Sandbox: d.Name(), Isolation: isolation},
				fmt.Errorf("docker did not run the project container's command (%v): %s", runErr, truncateForError(strings.TrimSpace(stderr.String())))
		}
		// Detail is plimsoll's own words: it reaches the audit line, and the
		// container's stderr is writable by every process in the sandbox. The exit
		// code survives (137 is the kernel's kill, for instance an OOM).
		detail := "the runner did not report"
		if errors.As(runErr, &exitErr) {
			detail = fmt.Sprintf("the runner did not report (container exit %d)", exitErr.ExitCode())
		}
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation, Outcome: ProjectOutcomeProtocolError, Detail: detail}, nil
	}
	if errors.Is(parseErr, runnerwire.ErrUnauthenticated) {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation, Outcome: ProjectOutcomeProtocolError, Detail: "no authenticated runner report"}, nil
	}
	if parseErr != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation, Outcome: ProjectOutcomeProtocolError, Detail: "could not parse sandbox result"}, nil
	}

	// Metadata-only evidence of the run's brokered host.* calls; nil unless the run
	// carried a grant that made calls. Never affects the outcome.
	return projectResultFromReport(d.Name(), isolation, report, broker.finalTrace()), nil
}

// projectResultFromReport is a project result from the runner's authenticated
// report, for a run's container and a session's alike.
func projectResultFromReport(provider string, isolation IsolationClass, report runnerwire.Report, trace *CallTrace) ProjectResult {
	res := ProjectResult{
		Sandbox:            provider,
		Isolation:          isolation,
		Steps:              runnerSteps(report.Steps),
		Artifacts:          runnerArtifacts(report.Artifacts),
		ArtifactsTruncated: report.ArtifactsTruncated,
		CallTrace:          trace,
	}
	// A runner-reported failure around step execution (illegal file path,
	// unwritable file, over-budget result) is request-attributable: setup_failed.
	// A step killed by its own time budget is a timed-out run, not a completed one;
	// RunModule classifies the same event as timed_out, and the two operations must
	// not disagree about what happened.
	outcome, detail := report.Outcome()
	res.Outcome, res.Detail = ProjectOutcomeCompleted, detail
	switch outcome {
	case runnerwire.SetupFailed:
		res.Outcome = ProjectOutcomeSetupFailed
	case runnerwire.TimedOut:
		res.Outcome = ProjectOutcomeTimedOut
	}
	return res
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
		EnvironmentIdentity: dockerImageIdentity(execState.moduleImageID), Duration: time.Since(started)}
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

// forceRemove's bounds: removeAttempts tries of removeAttemptBudget each, a pause of
// one second after the first and two after the second. dockerRemoveBudget is the sum,
// the longest forceRemove takes, which is how long a session's Done can trail its end.
const (
	removeAttempts      = 3
	removeAttemptBudget = 10 * time.Second
	dockerRemoveBudget  = removeAttempts*removeAttemptBudget + (removeAttempts-1)*removeAttempts/2*time.Second
)

// forceRemove is the hard teardown after the docker CLI is killed by a context.
// Killing `docker run` does not guarantee the container stops, so retry and log
// instead of silently leaving hostile code alive indefinitely.
func (d *DockerSandbox) forceRemove(host, name string) {
	var lastErr error
	for attempt := 1; attempt <= removeAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), removeAttemptBudget)
		args, argErr := dockerArgs(host, "rm", "-f", name)
		if argErr != nil {
			cancel()
			slog.Error("docker: cannot force-remove container without a pinned daemon endpoint", "container", name, "error", argErr)
			return
		}
		_, err := dockerOutput(ctx, args...)
		cancel()
		if err == nil || containerGone(host, name) {
			return
		}
		lastErr = err
		if attempt < removeAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	slog.Error("docker: failed to force-remove timed-out sandbox container",
		"container", name, "attempts", removeAttempts, "error", lastErr)
}

// containerGone reports whether no container named name exists, by an exact-name
// listing: never by reading docker's error wording ("No such container"), which a
// docker version may change, nor by its exit code, which differs between versions
// (docker 29's rm -f exits 0 for a missing container). An unreadable listing is
// "not known to be gone".
func containerGone(host, name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), removeAttemptBudget)
	defer cancel()
	args, err := dockerArgs(host, "ps", "-a", "-q", "--no-trunc", "--filter", "name=^"+regexp.QuoteMeta(name)+"$")
	if err != nil {
		return false
	}
	out, err := dockerOutput(ctx, args...)
	return err == nil && strings.TrimSpace(string(out)) == ""
}
