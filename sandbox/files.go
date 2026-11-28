package sandbox

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// A file call is one operation on a session's files (stat, read, write, list, read_many,
// make_dir, remove, rename), carried out inside the session's sandbox by plimsoll's native
// helper as the guest's own user (docs/session-files.md is the helper's contract; the shared
// driver is sandbox/internal/sessionkit/files.go). It is a session call like any other: one
// at a time, in the chain, with a record. A provider whose sessions carry file calls
// implements FileRunner on its Session, states the scopes it takes them in
// (PayloadEnvironment.FileScopes in its SessionEnvironments, FileRunner.FileScopes on the
// session), and passes sandbox/sessiontest's file cases for those scopes.

// The parts of a file call, named after the wire's; they are sessionkit's, where the driver
// that builds the helper's command and reads its answer lives.
type (
	FilesScope     = sessionkit.FileScope
	FilesOp        = sessionkit.FileOp
	FilesWriteMode = sessionkit.FileWriteMode
	FilesError     = sessionkit.FileError
	FilesEntryType = sessionkit.FileType
	FilesEntry     = sessionkit.FileEntry
	FilesItem      = sessionkit.FileItem
	// FilesCall is the operation and its fields (which fields each operation reads is
	// sessionkit.FileCall's comment).
	FilesCall = sessionkit.FileCall
	// FilesAnswer is the helper's answer: an error, or the operation's answer.
	FilesAnswer = sessionkit.FileAnswer
)

const (
	FilesScopeWork    = sessionkit.FileScopeWork
	FilesScopeSandbox = sessionkit.FileScopeSandbox

	FilesStat     = sessionkit.FileStat
	FilesRead     = sessionkit.FileRead
	FilesWrite    = sessionkit.FileWrite
	FilesList     = sessionkit.FileList
	FilesReadMany = sessionkit.FileReadMany
	FilesMakeDir  = sessionkit.FileMakeDir
	FilesRemove   = sessionkit.FileRemove
	FilesRename   = sessionkit.FileRename

	FilesWriteReplace    = sessionkit.FileWriteReplace
	FilesWriteCreateOnly = sessionkit.FileWriteCreateOnly
	FilesWriteAppend     = sessionkit.FileWriteAppend

	FilesErrorNone             = sessionkit.FileErrorNone
	FilesErrorNotFound         = sessionkit.FileErrorNotFound
	FilesErrorIsDir            = sessionkit.FileErrorIsDir
	FilesErrorNotDir           = sessionkit.FileErrorNotDir
	FilesErrorExists           = sessionkit.FileErrorExists
	FilesErrorSymlink          = sessionkit.FileErrorSymlink
	FilesErrorNotRegular       = sessionkit.FileErrorNotRegular
	FilesErrorPermissionDenied = sessionkit.FileErrorPermissionDenied
	FilesErrorTooLarge         = sessionkit.FileErrorTooLarge
	FilesErrorNoSpace          = sessionkit.FileErrorNoSpace
	FilesErrorReadOnly         = sessionkit.FileErrorReadOnly
	FilesErrorNotEmpty         = sessionkit.FileErrorNotEmpty
	FilesErrorScanLimit        = sessionkit.FileErrorScanLimit
	FilesErrorOther            = sessionkit.FileErrorOther

	FilesTypeFile  = sessionkit.FileTypeFile
	FilesTypeDir   = sessionkit.FileTypeDir
	FilesTypeLink  = sessionkit.FileTypeLink
	FilesTypeOther = sessionkit.FileTypeOther
	// FilesTypeUnreadable is a folder a recursive listing could not enter.
	FilesTypeUnreadable = sessionkit.FileTypeUnreadable
)

// FilesOps are every file operation.
var FilesOps = sessionkit.FileOps

// FilesRequest is one file call.
type FilesRequest struct {
	FilesCall
	Timeout          time.Duration
	MinimumIsolation IsolationClass
	Software         SoftwareRule
}

// FilesResult is a file call's outcome. Outcome is completed when the helper answered (then
// the answer's Error says whether the operation succeeded), timed_out when the call's
// deadline passed, protocol_error when its answer could not be read, runner_failed when it
// ended without one. The answer carries nothing the helper wrote but its frames: no text
// from inside the sandbox.
type FilesResult struct {
	Outcome ProjectOutcome
	FilesAnswer
	Duration            time.Duration
	Sandbox             string
	Isolation           IsolationClass
	SoftwareIdentity    string
	EnvironmentIdentity string
	// Instance is the sandbox instance that ran it, as a typed reference
	// (sandbox.ValidInstance), or "" when the provider names none.
	Instance string
	Policy   string
	// Record is the daemon's statement of this call (see RunRecord), set by an RPC client
	// that checked it. Direct providers leave it nil.
	Record *RunRecord
}

// FileRunner is the file half of a Session that carries file calls. WorkDir is the absolute
// path of the session's work folder, which a WORK path resolves from. FileScopes are the
// scopes the session takes file calls in, never empty, in the wire's order; RunFiles refuses
// a call in any other scope before anything starts (CheckFilesScope).
type FileRunner interface {
	RunFiles(ctx context.Context, req FilesRequest) (FilesResult, error)
	WorkDir() string
	FileScopes() []FilesScope
}

// FilesScopesBoth is what a session states that takes file calls in both scopes: the work
// scope's confinement holds there because its work folder is a mount of its own (docker's
// tmpfs, an E2B session's bind mount; docs/session-files.md, "Scopes"). A new slice each
// call, so no caller can change another's statement.
func FilesScopesBoth() []FilesScope { return []FilesScope{FilesScopeWork, FilesScopeSandbox} }

// FilesScopesSandboxOnly is what a session states whose work folder is not a mount of its
// own (OpenShell's), or whose kernel lacks what the work scope needs (a docker host before
// Linux 5.8), so the helper refuses the work scope there.
func FilesScopesSandboxOnly() []FilesScope { return []FilesScope{FilesScopeSandbox} }

// CheckFilesScope refuses a file call in a scope the session does not take, marked not
// dispatched, reason unsupported: nothing has started. provider names the provider in the
// error. A scope that is neither work nor sandbox is ValidateFilesRequest's to refuse (as
// malformed, reason request), so it passes here.
func CheckFilesScope(scope FilesScope, scopes []FilesScope, provider string) error {
	var word string
	switch scope {
	case FilesScopeWork:
		word = "work"
	case FilesScopeSandbox:
		word = "sandbox"
	default:
		return nil
	}
	if slices.Contains(scopes, scope) {
		return nil
	}
	return NotDispatched(RefusalUnsupported, fmt.Errorf("%w: provider %s's sessions take no file calls in the %s scope", ErrUnsupported, provider, word))
}

// ValidateFilesRequest refuses a file call that must not run: what the helper would refuse as
// malformed, and a floor out of range. Its error is marked NotDispatched, reason request:
// validation runs before anything starts.
func ValidateFilesRequest(req FilesRequest) error {
	if err := validateMinimumIsolation(req.MinimumIsolation); err != nil {
		return refused(err)
	}
	if err := req.Check(); err != nil {
		return refused(fmt.Errorf("%w: %v", ErrInvalidRequest, err))
	}
	return nil
}

// SessionFiles runs req's helper through exec, the provider's way to start an argv as the
// guest in the session's work folder, and turns how it ended into the call's result. ctx is
// the call's context (deadline included); fail is the result's evidence (provider, tier,
// policy, software). It returns sweep, whether the session's lifecycle must sweep after the
// call (sessionkit.Life.CallSweepIf): false only when the helper answered a call that cannot add
// to the disk (filesGrowDisk), since the helper is the one process a file call starts and it
// has exited. After an answered write or make_dir the sweep runs all the same: it is what
// measures the session's disk against SessionOptions.DiskBytes, so a session of writes alone
// ends when it leaves more than that, as a session of project calls does (review finding
// session-files-17; on docker the work tmpfs is sized from the operator's disk budget, which
// may be larger).
//
//   - The helper answered (any error of the contract included): completed.
//   - It exited with an answer the driver could not read, or refused a command the daemon's
//     own check passed: protocol_error.
//   - It exited with no answer and no code of the contract: runner_failed, unless the
//     sandbox stopped (stopped returns the session's end), which is the call's error.
//   - The call's own deadline passed on a session still open: timed_out.
//   - Anything else that delivered no exit status: callError(err), unmarked, since the
//     helper may have run (a write may have happened).
//
// A refusal exec itself marks (nothing started) is returned as it is.
func SessionFiles(ctx context.Context, req FilesRequest, fail FilesResult, exec sessionkit.FileExec,
	ended, stopped func() error, callError func(error) error) (res FilesResult, sweep bool, err error) {
	start := time.Now()
	ans, end, _, err := sessionkit.RunFile(ctx, exec, req.FilesCall)
	took := time.Since(start)
	if err != nil {
		if _, marked := NotDispatchedReason(err); marked {
			return fail, true, err
		}
		if deadline.Expired(ctx) == context.DeadlineExceeded && ended() == nil {
			res = fail
			res.Outcome, res.Duration = ProjectOutcomeTimedOut, took
			return res, true, nil
		}
		return fail, true, callError(err)
	}
	res = fail
	res.Duration = took
	switch end {
	case sessionkit.FileAnswered:
		res.Outcome, res.FilesAnswer = ProjectOutcomeCompleted, ans
		return res, filesGrowDisk(req.Op), nil
	case sessionkit.FileUnreadable:
		res.Outcome = ProjectOutcomeProtocolError
		return res, true, nil
	}
	if e := stopped(); e != nil {
		return fail, true, e
	}
	res.Outcome = ProjectOutcomeRunnerFailed
	return res, true, nil
}

// filesGrowDisk reports whether an answered call of op can add to what the sandbox's disk
// holds: a write, answered done or not (an append cut short, folders PARENTS made), and a
// make_dir. A read, stat, listing, readmany, removal or rename adds nothing.
func filesGrowDisk(op FilesOp) bool {
	return op == FilesWrite || op == FilesMakeDir
}
