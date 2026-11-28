package openshell

import (
	"context"
	"fmt"
	"strings"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// OpenShell sessions take file calls in the sandbox scope alone (docs/openshell.md, "File
// calls: the sandbox scope only"). The native helper refuses the work scope where the work
// folder is not a mount of its own, since a folder it holds open could then be moved out of
// the work folder under it, and a session's workDir is a plain folder of the container's
// writable layer, which the guest cannot make a mount of (both measured on v0.1.2 with the
// docker driver, 2026-11-27). OpenShell's Landlock policy does not close that either: it
// grants the reparenting right on /tmp, so a rename out of the work folder is allowed
// (measured the same day). The one mount the gateway would make at create, a tmpfs in the
// driver settings, is discarded at the stop a suspend and a recovery make. So a session
// states FilesScopesSandboxOnly, refuses a work-scope call before anything starts, and
// every record names the scope its call used: none claims the work scope's confinement.

var _ sandbox.FileRunner = (*session)(nil)

// WorkDir is the session's work folder: where its snippets, projects and cells run, and
// what a caller that names paths relative to it joins them to.
func (*session) WorkDir() string { return workDir }

// FileScopes is the sandbox scope alone (the package comment above says why).
func (*session) FileScopes() []sandbox.FilesScope { return sandbox.FilesScopesSandboxOnly() }

// fileStart makes the work folder if no call has yet, changes into it and execs the helper:
// the helper starts in the work folder, as on docker, and a caller's first call (a stat of
// the work folder) finds it there. Neither step can stop the helper: the sandbox scope
// resolves absolute paths and needs no working folder, so a work folder the session's code
// replaced with a file or a link (which would make mkdir or cd fail) still gets the helper's
// own answer, never a shell's exit code read as the helper's. It runs as the guest, like
// everything a gateway exec starts, so it can do nothing the guest's own shell cannot.
const fileStart = `mkdir -p "$1" 2>/dev/null; cd "$1" 2>/dev/null || cd /; shift; exec "$@"`

// RunFiles carries out one file call in the session's sandbox: the image's native helper,
// the build this plimsolld carries as far as the guest can tell (the startup smoke test
// checked the file at nativehelper.InContainer as the guest, nativehelper.FileReport.CheckBuilt:
// its type, owner, mode, size and identity line; the guest cannot read its bytes, so their
// SHA-256 is not checked here, and the check saw the sandbox the smoke test made, from the
// image as it was then), started by the gateway's exec as the sandbox's
// user, the guest's, under sessionkit.ControlArgv: an empty environment and a fixed PATH,
// never the gateway's variables, since the helper is one of plimsoll's own programs. A
// call in the work scope is refused, not dispatched, reason unsupported.
//
// The sweep follows a call that can grow the sandbox's disk (a write, a make_dir) and any
// call the helper did not answer (sandbox.SessionFiles says which). A session's /tmp here is
// not sized at all, so the session's disk budget is held by the measurement the sweep makes
// alone, and a run of writes that skipped it would be bounded by nothing. A stat, read, list,
// read_many, remove or rename the helper answered adds nothing to measure and leaves no
// process (the helper is the one process the call starts, and it has exited), so none
// follows it.
func (s *session) RunFiles(ctx context.Context, req sandbox.FilesRequest) (sandbox.FilesResult, error) {
	fail := sandbox.FilesResult{Sandbox: Name, Isolation: s.tier, EnvironmentIdentity: s.p.imageIdentity()}
	if err := sandbox.ValidateFilesRequest(req); err != nil {
		return fail, err
	}
	if err := sandbox.CheckFilesScope(req.Scope, s.FileScopes(), Name); err != nil {
		return fail, err
	}
	if err := req.Software.Check(""); err != nil {
		return fail, err
	}
	timeout := providerkit.ClampTimeout(req.Timeout, projectDefault, projectMax)
	if err := s.admit(ctx, nil, req.MinimumIsolation); err != nil {
		return fail, err
	}
	runCtx, done, err := s.life.CallSweepIf(ctx, timeout)
	if err != nil {
		return fail, err
	}
	sweep := true
	defer func() { done(sweep) }()
	var res sandbox.FilesResult
	res, sweep, err = sandbox.SessionFiles(runCtx, req, fail, s.fileExec, s.Err, s.Err,
		func(err error) error { return s.life.CallError(runCtx, err) })
	return res, err
}

// fileExec starts argv, the driver's command line for the helper (nativehelper.InContainer,
// "files", the scope, "-"), with stdin as its input, through fileStart.
func (s *session) fileExec(ctx context.Context, argv []string, stdin []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
	if len(argv) < 2 || argv[0] != nativehelper.InContainer {
		return sessionkit.ExecResult{}, fmt.Errorf("openshell session: %q is not the native helper's command line", strings.Join(argv, " "))
	}
	return s.control(ctx, nil, append([]string{"sh", "-c", fileStart, "sh", workDir}, argv...), stdin, outCap, errCap)
}
