package sandbox

import (
	"context"
	"errors"
	"fmt"
	pathpkg "path"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
)

// RunJavaScript runs one snippet with node from a staged CommonJS file.
func (d *DockerCloud) RunJavaScript(ctx context.Context, req Request) (res Result, err error) {
	fail := Result{Sandbox: d.Name(), Isolation: IsolationVM}
	if err := ValidateRequest(req); err != nil {
		return fail, err
	}
	if err := d.admit(req.MinimumIsolation, req.Software); err != nil {
		return fail, err
	}
	timeout := clampRunTimeout(req.Timeout, d.DefaultTimeout, d.MaxTimeout)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	guard, closeGuard, err := d.openGuard(runCtx, req.Grant, timeout)
	if err != nil {
		return fail, err
	}
	defer closeGuard()

	vm, err := d.create(runCtx, remainingBudget(runCtx, timeout))
	if err != nil {
		return fail, d.deadlineAware(runCtx, err)
	}
	defer d.destroy(ctx, vm) // every exit path, including cancellation and panics
	// Runs before the destroy: the grant ends with the run's code, not with a
	// teardown during which a process the guest detached could keep calling the API,
	// unseen by the trace already returned.
	// Every return carries the run's trace, an error's included: the calls the grant
	// served before a failure happened, and the daemon counts them (review F11).
	defer func() {
		if trace := endDCGuard(guard); res.CallTrace == nil {
			res.CallTrace = trace
		}
	}()
	if err := d.sealNetwork(runCtx, vm, guard); err != nil {
		return fail, d.deadlineAware(runCtx, err)
	}
	code := req.Code
	if guard != nil {
		code = withGuardHostSDK(code, req.Grant, guard.endpoint.URL, guard.token)
	}

	// Staged as a file, not a `node -e` argument: one argv element is limited to
	// about 128 KiB and an accepted snippet may be larger.
	const snippetPath = "/tmp/plimsoll-snippet.cjs"
	if err := d.upload(runCtx, vm, []File{{Path: snippetPath, Content: code}}); err != nil {
		if deadline.Expired(runCtx) == context.DeadlineExceeded {
			return Result{Sandbox: d.Name(), Isolation: IsolationVM, ExitCode: 124, TimedOut: true}, nil
		}
		return fail, fmt.Errorf("dockercloud write snippet: %w", err)
	}
	start := time.Now()
	out, err := d.execGuarded(runCtx, vm, []string{"node", snippetPath}, "")
	res = Result{
		Stdout:          out.stdout,
		Stderr:          out.stderr,
		StdoutTruncated: out.stdoutTruncated,
		StderrTruncated: out.stderrTruncated,
		ExitCode:        out.exitCode,
		TimedOut:        out.timedOut,
		Duration:        time.Since(start),
		Sandbox:         d.Name(),
		Isolation:       IsolationVM,
	}
	res.CallTrace = endDCGuard(guard)
	if err != nil {
		if deadline.Expired(runCtx) == context.DeadlineExceeded {
			res.TimedOut, res.ExitCode = true, 124
			return res, nil
		}
		return fail, err
	}
	return res, nil
}

// RunModule is unsupported: the module worker image is a docker recipe.
func (d *DockerCloud) RunModule(_ context.Context, req ModuleRequest) (ModuleResult, error) {
	fail := ModuleResult{Sandbox: d.Name(), Isolation: IsolationVM}
	if err := ValidateModuleRequest(req); err != nil {
		return fail, err
	}
	if err := CheckMinimumIsolation(IsolationVM, req.MinimumIsolation); err != nil {
		return fail, err
	}
	return fail, refused(ErrUnsupported)
}

// RunProject writes the files, then runs each step in order, stopping on the first
// failure, and finally captures the requested artifacts that exist.
func (d *DockerCloud) RunProject(ctx context.Context, req ProjectRequest) (res ProjectResult, err error) {
	fail := ProjectResult{Sandbox: d.Name(), Isolation: IsolationVM}
	if err := ValidateProjectRequest(req); err != nil {
		return fail, err
	}
	if err := d.admit(req.MinimumIsolation, req.Software); err != nil {
		return fail, err
	}
	timeout := clampRunTimeout(req.Timeout, d.DefaultTimeout, d.MaxTimeout)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	guard, closeGuard, err := d.openGuard(runCtx, req.Grant, timeout)
	if err != nil {
		return fail, err
	}
	defer closeGuard()

	dir := d.projectDir()
	staged := make([]File, 0, len(req.Files)+len(req.Steps))
	dirs := map[string]struct{}{dir: {}}
	for _, f := range req.Files {
		// Defense in depth: validation already refuses escaping paths, but never
		// write outside the project dir even inside the disposable microVM.
		dest := pathpkg.Join(dir, f.Path)
		if dest == dir || !strings.HasPrefix(dest, dir+"/") {
			return ProjectResult{Sandbox: d.Name(), Isolation: IsolationVM, Outcome: ProjectOutcomeSetupFailed, Detail: "illegal file path: " + f.Path}, nil
		}
		staged = append(staged, File{Path: dest, Content: f.Content})
		dirs[pathpkg.Dir(dest)] = struct{}{}
	}
	// Every step script is staged in the same upload, one file per step, so a run
	// costs one upload however many steps it has.
	stepPaths := make([]string, len(req.Steps))
	for i, step := range req.Steps {
		stepPaths[i] = fmt.Sprintf("/tmp/plimsoll-step-%d.sh", i)
		staged = append(staged, File{Path: stepPaths[i], Content: step})
	}

	// A grant preloads the guard client into every Node step, as on E2B: the same
	// host.* global for snippets and projects.
	var stepPrefix []string
	if guard != nil {
		staged = append(staged, File{Path: dcHostModulePath, Content: hostGuardSDKModule(req.Grant, guard.endpoint.URL, guard.token)})
		stepPrefix = []string{"env", "NODE_OPTIONS=--import " + dcHostModulePath}
	}

	vm, err := d.create(runCtx, remainingBudget(runCtx, timeout))
	if err != nil {
		return fail, d.deadlineAware(runCtx, err)
	}
	defer d.destroy(ctx, vm)
	// Runs before the destroy: the grant ends with the run's code, not with a
	// teardown during which a process the guest detached could keep calling the API,
	// unseen by the trace already returned.
	// Every return carries the run's trace, an error's included: the calls the grant
	// served before a failure happened, and the daemon counts them (review F11).
	defer func() {
		if trace := endDCGuard(guard); res.CallTrace == nil {
			res.CallTrace = trace
		}
	}()
	if err := d.sealNetwork(runCtx, vm, guard); err != nil {
		return fail, d.deadlineAware(runCtx, err)
	}

	timedOut := func() ProjectResult {
		return ProjectResult{Sandbox: d.Name(), Isolation: IsolationVM, Outcome: ProjectOutcomeTimedOut, Detail: "run exceeded the time budget before its steps ran"}
	}
	if err := d.mkdirs(runCtx, vm, dirs); err != nil {
		if deadline.Expired(runCtx) == context.DeadlineExceeded {
			return timedOut(), nil
		}
		return fail, fmt.Errorf("could not create project directories: %w", err)
	}
	if err := d.upload(runCtx, vm, staged); err != nil {
		if deadline.Expired(runCtx) == context.DeadlineExceeded {
			return timedOut(), nil
		}
		return fail, fmt.Errorf("could not write project files: %w", err)
	}

	res = ProjectResult{Sandbox: d.Name(), Isolation: IsolationVM, Outcome: ProjectOutcomeCompleted}
	for i, step := range req.Steps {
		start := time.Now()
		out, err := d.execGuarded(runCtx, vm, append(append([]string(nil), stepPrefix...), "sh", stepPaths[i]), dir)
		if err != nil {
			if deadline.Expired(runCtx) == context.DeadlineExceeded {
				res.Steps = append(res.Steps, StepResult{Command: step, ExitCode: 124, TimedOut: true, Duration: time.Since(start)})
				res.Outcome, res.Detail = ProjectOutcomeTimedOut, "run exceeded the time budget"
				res.CallTrace = endDCGuard(guard)
				return res, nil
			}
			return fail, err
		}
		res.Steps = append(res.Steps, StepResult{
			Command:         step,
			Stdout:          out.stdout,
			Stderr:          out.stderr,
			StdoutTruncated: out.stdoutTruncated,
			StderrTruncated: out.stderrTruncated,
			ExitCode:        out.exitCode,
			TimedOut:        out.timedOut,
			Duration:        time.Since(start),
		})
		if out.timedOut {
			res.Outcome, res.Detail = ProjectOutcomeTimedOut, "step exceeded the time budget"
			res.CallTrace = endDCGuard(guard)
			return res, nil
		}
		if out.exitCode != 0 {
			break
		}
	}
	// The steps are done: the grant ends before its trace is read.
	res.CallTrace = endDCGuard(guard)

	// Capture requested artifacts (those that exist), even after a failed step.
	var wanted []string
	for _, p := range req.Artifacts {
		dest := pathpkg.Join(dir, p)
		if dest != dir && strings.HasPrefix(dest, dir+"/") {
			wanted = append(wanted, dest)
		}
	}
	if len(wanted) > 0 {
		arts, truncated, err := d.download(runCtx, vm, wanted)
		if err != nil {
			if deadline.Expired(runCtx) == context.DeadlineExceeded {
				res.Outcome, res.Detail = ProjectOutcomeTimedOut, "run exceeded the time budget while reading artifacts"
				return res, nil
			}
			return fail, fmt.Errorf("read artifacts: %w", err)
		}
		for _, a := range arts {
			res.Artifacts = append(res.Artifacts, Artifact{Path: strings.TrimPrefix(a.Path, dir+"/"), Content: a.Content})
		}
		res.ArtifactsTruncated = truncated
	}
	return res, nil
}

// deadlineAware keeps the caller's own deadline recognizable: a create that ran out
// of time is reported as context.DeadlineExceeded rather than as whatever transport
// error the cancelled request produced.
func (d *DockerCloud) deadlineAware(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("%w: %v", ctxErr, err)
	}
	return err
}

// runCeiling is the longest one E2B or Docker Cloud run may take: the configured
// maximum, or 120 seconds when none is set.
func runCeiling(max time.Duration) time.Duration {
	if max <= 0 {
		return 120 * time.Second
	}
	return max
}

// clampRunTimeout applies a provider's default and ceiling to a requested budget.
func clampRunTimeout(req, def, max time.Duration) time.Duration {
	if req <= 0 {
		req = def
		if req <= 0 {
			req = 30 * time.Second
		}
	}
	if max = runCeiling(max); req > max {
		req = max
	}
	return req
}
