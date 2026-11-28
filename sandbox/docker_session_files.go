package sandbox

import (
	"context"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

var _ FileRunner = (*dockerSession)(nil)

// WorkDir is the session's work folder, which a WORK path resolves from.
func (s *dockerSession) WorkDir() string { return dockerSessionWork }

// FileScopes are both where the kernel holds the work scope (the work folder is a tmpfs of its
// own), else the sandbox scope alone (DockerSandbox.sessionFileScopes).
func (s *dockerSession) FileScopes() []FilesScope { return s.d.sessionFileScopes() }

// RunFiles carries out one file call in the session's container: the project image's native
// helper, the build this plimsolld carries (the startup check verified it at
// NativeHelperPath by its SHA-256), started by docker exec as the container's user, the
// guest's, in the work folder, behind the guest guard (execAs), under
// sessionkit.ControlArgv: an empty environment and a fixed PATH, never the image's, since the
// helper is one of plimsoll's own programs.
//
// The helper makes itself non-dumpable as its first act; it is static, so the runner guard's
// LD_PRELOAD, which makes a dynamic program non-dumpable, would never load into it. There is no
// quiesce before it, as there is before the runner: the runner holds a key a process of the
// session must not read, and the helper holds nothing a process of the session lacks (it has
// the guest's permissions and no more), so the most such a process can do, in the moment
// before the helper is non-dumpable, is shape the answer as it could shape the files
// themselves. A quiesce would also kill the session's interpreters on every file call.
//
// The sweep follows an answered write or make_dir, which is what holds the session to its disk
// bound (SessionOptions.DiskBytes; the work tmpfs is sized from the operator's disk budget,
// which may be larger), and any call the helper did not answer, since a docker exec client that
// goes away does not stop its process (sandbox.SessionFiles says which). A read, stat, listing,
// readmany, removal or rename the helper answered is followed by none.
func (s *dockerSession) RunFiles(ctx context.Context, req FilesRequest) (FilesResult, error) {
	fail := FilesResult{Sandbox: s.d.Name(), Isolation: s.tier, Policy: s.policy,
		SoftwareIdentity: s.manifest, EnvironmentIdentity: dockerImageIdentity(s.imageID)}
	if err := ValidateFilesRequest(req); err != nil {
		return fail, err
	}
	if err := CheckFilesScope(req.Scope, s.FileScopes(), s.d.Name()); err != nil {
		return fail, err
	}
	if err := s.admit(req.MinimumIsolation, req.Software); err != nil {
		return fail, err
	}
	runCtx, done, err := s.life.CallSweepIf(ctx, s.d.projectTimeout(req.Timeout))
	if err != nil {
		return fail, err
	}
	sweep := true
	defer func() { done(sweep) }()
	exec := func(ctx context.Context, argv []string, stdin []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
		argv, err := sessionkit.ControlArgv(nil, argv...)
		if err != nil {
			return sessionkit.ExecResult{}, err
		}
		out, err := s.exec(ctx, argv, nil, stdin, outCap, errCap)
		if out.refused {
			// The refusing point refused the exec: docker never started, so nothing of the
			// call ran (callRefusal says why only this refusal is marked).
			return sessionkit.ExecResult{}, NotDispatched(RefusalEnvironment, s.Err())
		}
		return out.kit(), err
	}
	var res FilesResult
	res, sweep, err = SessionFiles(runCtx, req, fail, exec, s.Err, func() error {
		if s.stoppedWithin(runCtx, dockerEndGrace) {
			return s.Err()
		}
		return nil
	}, func(err error) error { return s.life.CallError(runCtx, err) })
	return res, err
}
