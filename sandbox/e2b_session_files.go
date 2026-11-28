package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// E2B sessions take file calls (FileRunner) through plimsoll's native helper, which E2B's
// templates do not carry: each session's open puts the build this plimsolld carries into the
// machine before any of the session's code runs, and each file call starts
// it as the guest. What the open does, and why (session-files-11):
//
//   - The helper's place is e2bHelperPath, in a folder of the root's (mode 0755) that the
//     open makes when it is missing and refuses when it is a link, is not the root's, is
//     writable by its group or every user, or has anything on the way to it the guest could
//     change. Not under /usr/local, which E2B's template build leaves writable by every user:
//     the open closes it, but plimsoll's own programs never rest on that closing alone.
//   - Whatever is at the path before the open is the template's. A link, a folder, a device,
//     or a file that is not the root's, that its group or every user may write, or that is
//     setuid, refuses the session: the open never writes through or over what it did not put
//     there. A regular file of the root's is the operator's baked copy: its bytes are read
//     back through envd and checked here, and a copy that is not this build refuses the
//     session (e2bSessionHelperRefused); one that is skips the upload.
//   - Nothing there: the daemon uploads the helper through envd into the root-only staging
//     folder under a fresh name, and the open's install (e2b_session.js, installHelper)
//     copies it into a file of its own in the helper's folder (O_EXCL, O_NOFOLLOW, synced,
//     the root's, mode 0711) and publishes it with a hard link, which refuses a name already
//     there; then it checks the type, owner, mode and size, and the daemon reads the bytes
//     back and checks their SHA-256 itself, never with a program inside the machine.
//   - Each file call starts the helper as root through envd and drops to the guest with the
//     pinned setpriv (every uid and gid the guest's, no supplementary group, no-new-privs),
//     as every guest process of an E2B session starts; the helper then runs under
//     sessionkit.ControlArgvClosed (an empty environment, a fixed PATH) in the work folder,
//     which the open made a mount of its own, as the helper's work scope requires.

// e2bHelperPath is where an E2B session's open puts the native helper, and where an
// operator's template may hold it already (e2b/README.md).
const e2bHelperPath = "/usr/lib/plimsoll/plimsoll-helper"

// e2bHelperArch is the only machine type an E2B session's helper is built for, as node names
// it (process.arch): plimsoll builds the helper for amd64 alone.
const e2bHelperArch = "x64"

// e2bFileStdin, run by the pinned sh as root, takes its standard input from the file its
// first argument names (a call's input, in the root-only staging folder), removes that file,
// and execs the rest (setpriv's drop to the guest, then the helper), so the input reaches the
// helper as its stdin and never lies where the guest can read it. Exit 125 is this script's,
// never the helper's: the driver reads it as no answer.
const e2bFileStdin = `[ -f "$1" ] && [ ! -h "$1" ] || exit 125; exec 0<"$1"; rm -f -- "$1" || exit 125; shift; exec "$@"`

// ErrE2BHelper is the refusal of a session whose machine could not be given the native helper
// this plimsolld carries.
var ErrE2BHelper = errors.New("the session's machine does not hold the native helper this plimsolld carries")

// e2bSessionHelperRefused is the refusal of a session whose open found, or left, something
// other than this build of the native helper at e2bHelperPath: nothing of the caller's has run.
// The machine is the template's, so the reason is environment, as for the open's other
// refusals of a template, with the way out.
func e2bSessionHelperRefused(why string) error {
	return NotDispatched(RefusalEnvironment, fmt.Errorf("%w: an E2B session cannot open on this template: %w (%s). "+
		"A template that holds the helper at %s must hold the build of this plimsolld's release (e2b/README.md in plimsoll's repository); one that holds nothing there gets it at each open",
		ErrUnsupported, ErrE2BHelper, why, e2bHelperPath))
}

// installHelper gives the machine the native helper, as the open found its path (state, from
// e2b_session.js helperAt: "absent" or "present"), and checks the bytes at the path against
// this build's SHA-256. Every refusal is the template's (e2bSessionHelperRefused, or the
// install's own words through e2bSessionOpenRefused); an error of envd's is the open's.
func (s *e2bSession) installHelper(ctx context.Context, state, arch string) error {
	if arch != e2bHelperArch {
		return e2bSessionHelperRefused("the machine is " + truncateForError(arch) + ", and the helper is built for x64 alone")
	}
	want, err := nativehelper.Program("amd64")
	if err != nil {
		return err
	}
	switch state {
	case "present":
	case "absent":
		staged := e2bSessionStage + "/" + providerkit.RandHex(8) + ".helper"
		if err := s.e.writeFilesAs(ctx, s.machine(), e2bRootUser, []File{{Path: staged, Content: string(want)}}); err != nil {
			return fmt.Errorf("e2b session: upload the native helper: %w", err)
		}
		argv, err := s.control(nil, sessionkit.NodeArgv("-e", e2bSessionJS, "install", staged, e2bHelperPath, strconv.Itoa(len(want)))...)
		if err != nil {
			return err
		}
		out, err := s.root(ctx, argv, 4096, 4096)
		if err != nil {
			return fmt.Errorf("e2b session: install the native helper: %w", err)
		}
		if out.Exited && out.ExitCode == e2bOpenRefusedExit {
			return e2bSessionOpenRefused(out.Stderr)
		}
		if !out.Exited || out.ExitCode != 0 {
			return fmt.Errorf("e2b session: installing the native helper exited %d: %s", out.ExitCode, truncateForError(strings.TrimSpace(out.Stderr)))
		}
	default:
		return fmt.Errorf("e2b session: the machine's preparation said %q of the native helper's path", truncateForError(state))
	}
	got, found, err := s.e.readFileAs(ctx, s.machine(), e2bRootUser, e2bHelperPath, int64(len(want)))
	if err != nil {
		return fmt.Errorf("e2b session: read the native helper back: %w", err)
	}
	if !found {
		return e2bSessionHelperRefused("nothing is at its path when read back")
	}
	if !bytes.Equal(got, want) {
		sum := sha256.Sum256(got)
		wantSum := sha256.Sum256(want)
		return e2bSessionHelperRefused(fmt.Sprintf("the file at its path has sha256 %s, this build %s", hex.EncodeToString(sum[:]), hex.EncodeToString(wantSum[:])))
	}
	return nil
}

var _ FileRunner = (*e2bSession)(nil)

// WorkDir is the session's work folder, which a WORK path resolves from.
func (*e2bSession) WorkDir() string { return e2bSessionWork }

// FileScopes are both: the open bind-mounts the work folder on itself.
func (*e2bSession) FileScopes() []FilesScope { return FilesScopesBoth() }

// RunFiles carries out one file call in the session's machine: the native helper the open put
// there and checked (installHelper), started as the guest in the work folder (fileExec).
// The sweep follows an answered write or make_dir, which is what holds the session to its disk
// bound (SessionOptions.DiskBytes), and any call the helper did not answer, since a process envd
// started may outlive the stream that started it (sandbox.SessionFiles says which). A read,
// stat, listing, readmany, removal or rename the helper answered is followed by none.
func (s *e2bSession) RunFiles(ctx context.Context, req FilesRequest) (FilesResult, error) {
	fail := FilesResult{Sandbox: s.e.Name(), Isolation: s.tier}
	if err := ValidateFilesRequest(req); err != nil {
		return fail, err
	}
	if err := CheckFilesScope(req.Scope, s.FileScopes(), s.e.Name()); err != nil {
		return fail, err
	}
	if err := s.admit(nil, req.MinimumIsolation, req.Software); err != nil {
		return fail, err
	}
	timeout := clampRunTimeout(req.Timeout, s.e.DefaultTimeout, s.e.MaxTimeout)
	runCtx, done, err := s.life.CallSweepIf(ctx, timeout)
	if err != nil {
		return fail, err
	}
	sweep := true
	defer func() { done(sweep) }()
	var res FilesResult
	res, sweep, err = SessionFiles(runCtx, req, fail, s.fileExec, s.Err, s.Err,
		func(err error) error { return s.life.CallError(runCtx, err) })
	return res, err
}

// fileExec starts argv, the driver's command line for the helper (nativehelper.Files, then
// the scope and "-"), with stdin as its input: the input goes up through envd into the
// root-only staging folder under a fresh name, and the pinned sh, as root, opens it as its
// standard input, removes it and execs setpriv's drop to the guest, then the pinned sh as the
// guest changes into the work folder and execs the helper at e2bHelperPath under
// sessionkit.ControlArgvClosed. A failed upload is marked not dispatched (nothing started).
// A process envd ended at the call's deadline is the deadline's error, so the call is
// timed_out; any other end without an exit status is no answer.
func (s *e2bSession) fileExec(ctx context.Context, argv []string, stdin []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
	if len(argv) < 2 || argv[0] != nativehelper.InContainer {
		return sessionkit.ExecResult{}, fmt.Errorf("e2b session: %q is not the native helper's command line", truncateForError(strings.Join(argv, " ")))
	}
	helper, err := sessionkit.ControlArgvClosed(nil, append([]string{e2bHelperPath}, argv[1:]...)...)
	if err != nil {
		return sessionkit.ExecResult{}, err
	}
	sh, err := s.pinned("sh")
	if err != nil {
		return sessionkit.ExecResult{}, err
	}
	dropped, err := s.asGuest(append([]string{sh, "-c", e2bGuestStart, "sh", e2bSessionWork}, helper...))
	if err != nil {
		return sessionkit.ExecResult{}, err
	}
	in := e2bSessionStage + "/" + providerkit.RandHex(8) + ".in"
	full, err := s.control(nil, append([]string{"sh", "-c", e2bFileStdin, "sh", in}, dropped...)...)
	if err != nil {
		return sessionkit.ExecResult{}, err
	}
	if err := s.e.writeFilesAs(ctx, s.machine(), e2bRootUser, []File{{Path: in, Content: string(stdin)}}); err != nil {
		return sessionkit.ExecResult{}, s.unsent(ctx, fmt.Errorf("e2b session: stage the file call's input: %w", err))
	}
	out, err := s.e.envdRun(ctx, s.machine(), envdProcess{user: e2bRootUser, cmd: full[0], args: full[1:], cwd: e2bControlDir}, outCap, errCap)
	res := sessionkit.ExecResult{
		Stdout: out.stdout, Stderr: out.stderr,
		StdoutTruncated: out.stdoutTruncated, StderrTruncated: out.stderrTruncated,
		ExitCode: out.exitCode, Exited: err == nil && out.exited,
	}
	if err == nil && !out.exited && deadline.Expired(ctx) == context.DeadlineExceeded {
		return res, context.DeadlineExceeded
	}
	return res, err
}
