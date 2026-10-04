package sandbox

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// SessionProvider is the optional interface of a provider that can keep one
// sandbox alive across calls: files a call writes persist for the next call, and
// no process a call starts outlives it, except the interpreters RunCell keeps. Like
// Drainer, it is optional; a provider that does not implement it has no sessions.
type SessionProvider interface {
	// SupportsSessions reports whether OpenSession can work as configured.
	SupportsSessions() bool
	// SessionEnvironments is where a session's calls run, stated before any session
	// opens: the session layer checks a session's software rule against it, and a
	// call's response states it. One sandbox runs every call of a session, so a
	// provider whose runs use a different image per payload kind (docker) states the
	// session's one image for every kind.
	SessionEnvironments() Environments
	// OpenSession creates the session's sandbox and returns once it is ready and
	// verified. The session belongs to whoever holds the returned value; an RPC
	// layer binds it to one principal.
	OpenSession(ctx context.Context, opts SessionOptions) (Session, error)
}

// SessionPool is a SessionProvider that can keep sandboxes ready for OpenSession:
// never-used, with their interpreters already running, each handed to one session and
// removed when it closes, never reused. StartSessionPool keeps size of them, for
// sessions given a lifetime of at most lifetime, and fails when it cannot make the
// first; Drain stops it.
type SessionPool interface {
	StartSessionPool(ctx context.Context, size int, lifetime time.Duration) error
}

// SessionOptions is what a session is opened with.
type SessionOptions struct {
	// MinimumIsolation is checked at open, against the evidence the provider
	// measures then; each call's own floor is checked again against it.
	MinimumIsolation IsolationClass
	// Lifetime is the session's absolute lifetime from open. The provider ends the
	// session when it passes, whatever the session is doing, and declares it on the
	// sandbox so a crashed daemon's session is reaped too. Required.
	Lifetime time.Duration
	// DiskBytes bounds what the session's calls may leave behind: after a call that
	// leaves more, the session ends. 0 means no bound beyond the provider's own.
	DiskBytes int64
	// Languages are the languages the caller expects its cells to use: a hint, checked
	// by SessionLanguages. It changes latency, never behavior: a provider with a pool
	// hands over a sandbox whose interpreters for them are already running, and a cell
	// in any stated language runs whatever the hint said. Empty means no hint.
	Languages []Language
}

// SessionLanguages checks a session's language hint and returns the languages in it
// that its environment states, without repeats, in the stated order. A language
// plimsoll keeps no interpreter for is refused as a malformed request. One it knows
// but the environment does not state is dropped, not refused: a hint changes latency,
// never behavior, and a cell in that language is refused when it is sent, as without
// the hint. When the environment states no languages (its smoke test has not run),
// the hint keeps its own order.
func SessionLanguages(hint, stated []Language) ([]Language, error) {
	for _, l := range hint {
		if !l.Known() {
			return nil, NotDispatched(RefusalRequest, fmt.Errorf("%w: the language hint names %q, which plimsoll keeps no interpreter for", ErrInvalidRequest, l))
		}
	}
	var out []Language
	if len(stated) == 0 {
		for _, l := range hint {
			if !slices.Contains(out, l) {
				out = append(out, l)
			}
		}
		return out, nil
	}
	for _, l := range stated {
		if slices.Contains(hint, l) {
			out = append(out, l)
		}
	}
	return out, nil
}

// Session is one open session. Calls are serialized: a call waits (bounded by
// its context) until the previous one has finished and the boundary between
// them has been established.
type Session interface {
	// Isolation is the tier the provider measured when the session opened.
	Isolation() IsolationClass
	// Environments is what this session runs: its snippet and project environments,
	// identities included, as of the artifact the sandbox was created from. A session
	// layer checks a software rule against it after the open (review F10): what the
	// provider stated before the open can name an earlier artifact.
	Environments() Environments
	// ExpiresAt is when the session's lifetime ends.
	ExpiresAt() time.Time
	RunJavaScript(ctx context.Context, req Request) (Result, error)
	RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error)
	// RunCell runs code in the session's interpreter for its language, starting one
	// when none is alive. The interpreter is the one process a session keeps between
	// calls; every other process a call starts, the interpreter's children included,
	// still dies with the call.
	CellRunner
	// Suspend releases the session's CPU and keeps its files; the next call resumes
	// it first. A session layer calls it when the session has been idle. It waits
	// for a call in progress to finish. It reports whether the suspended sandbox still
	// holds its memory: a stopped container does not, a paused one does (with its
	// files in memory and its live interpreters), and a session layer that accounts
	// for memory keeps the session's share while it does.
	Suspend(ctx context.Context) (holdsMemory bool, err error)
	// Close ends the session and deletes its sandbox (off the caller's path). It is
	// idempotent, and a no-op on a session that already ended.
	Close(ctx context.Context) error
	// Done is closed once the session has ended, by Close or by itself, and its
	// sandbox is deleted (or the delete gave up): what a session holds, its memory
	// included, is released by then, so a session layer gives back the session's
	// capacity on Done. It can trail the end by the provider's delete time. Whether the
	// session has ended is Err, which is set at once.
	Done() <-chan struct{}
	// Err is nil while the session is open and a *SessionEndedError from the moment it
	// ends.
	Err() error
}

// SessionEnd says why a session ended. The lifecycle every provider's sessions share
// lives in sandbox/internal/sessionkit (Life), which defines it.
type SessionEnd = sessionkit.End

const (
	SessionOpen = sessionkit.Open
	// SessionClosed: its holder closed it.
	SessionClosed = sessionkit.Closed
	// SessionExpired: its lifetime passed.
	SessionExpired = sessionkit.Expired
	// SessionDiskExceeded: a call left more on disk than the session's budget.
	SessionDiskExceeded = sessionkit.DiskExceeded
	// SessionMainProcessEnded: the sandbox's main process ended (code in the
	// sandbox can kill it), so the sandbox can run nothing more.
	SessionMainProcessEnded = sessionkit.MainProcessEnded
	// SessionBoundaryFailed: the provider could not give the next call a clean
	// sandbox: it could not prove that no process of a call outlived it and a
	// restart failed too, or the sandbox could not be stopped or started. It ended
	// the session rather than run the next call beside a leftover process.
	SessionBoundaryFailed = sessionkit.BoundaryFailed
	// SessionSandboxChanged: the sandbox no longer reads back as it was verified
	// (its policy, settings or spec changed, or it disappeared).
	SessionSandboxChanged = sessionkit.SandboxChanged
	// SessionShutdown: the provider was drained.
	SessionShutdown = sessionkit.Shutdown
)

// ErrSessionEnded matches every *SessionEndedError.
var ErrSessionEnded = sessionkit.ErrEnded

// SessionEndedError is a session's end, with its reason (Reason) and any detail
// (Detail).
type SessionEndedError = sessionkit.EndedError

// SessionEndReason reads the reason from an error, SessionOpen when err is not a
// session's end.
func SessionEndReason(err error) SessionEnd {
	var se *SessionEndedError
	if errors.As(err, &se) {
		return se.Reason
	}
	return SessionOpen
}

// RefuseEndedSession is the error a call on an ended session returns: the end,
// marked as refused before dispatch, since nothing ran.
func RefuseEndedSession(end error) error {
	return NotDispatched(RefusalRequest, end)
}

// RefuseUnreadable is the error a session call returns when the session's sandbox
// could not be read back before it: nothing ran, the sandbox could not be shown to be
// the one opened, and the session goes on (reason environment; review F4).
func RefuseUnreadable(err error) error {
	return NotDispatched(RefusalEnvironment, err)
}

// sessionRefusals are the refusals a session's lifecycle (sessionkit.Life) returns.
func sessionRefusals() sessionkit.Refusals {
	return sessionkit.Refusals{Ended: RefuseEndedSession, GaveUp: RefuseGaveUp, Unreadable: RefuseUnreadable}
}

// RefuseGaveUp is the error a session call returns when its context ends before any
// of it ran: while it waited for the session's turn (held by a call in flight, or by
// the sweep after the previous one), or while the sandbox was made ready for it. It
// is marked as refused before dispatch, reason capacity: the session was busy.
func RefuseGaveUp(ctx context.Context) error {
	return NotDispatched(RefusalCapacity, ctx.Err())
}

// RefuseCell is the refusal for a cell none of whose code ran, from the error the
// session's interpreters returned (end is the session's Err); ok is false for any
// other error, which means the code may have run.
//   - An interpreter that could not start (sessionkit.ErrLaunch): on a session that
//     has ended the end is why, and is what the caller is told; when ctx, the call's
//     context, has ended, the caller gave up; otherwise the image cannot run the
//     language.
//   - Files that could not be written (sessionkit.ErrFiles): a request this session's
//     work directory cannot take. The interpreter and the session go on.
//   - A deadline before the code was sent (sessionkit.ErrUnsent): DeadlineExceeded,
//     marked; the next cell starts a fresh interpreter and says so.
func RefuseCell(ctx context.Context, err, end error) (refusal error, ok bool) {
	switch {
	case errors.Is(err, sessionkit.ErrLaunch) && end != nil:
		return RefuseEndedSession(end), true
	case errors.Is(err, sessionkit.ErrLaunch) && ctx.Err() != nil:
		return RefuseGaveUp(ctx), true
	case errors.Is(err, sessionkit.ErrLaunch):
		return NotDispatched(RefusalEnvironment, fmt.Errorf("%w: %v", ErrUnsupported, err)), true
	case errors.Is(err, sessionkit.ErrFiles):
		return NotDispatched(RefusalRequest, fmt.Errorf("%w: %v", ErrInvalidRequest, err)), true
	case errors.Is(err, sessionkit.ErrUnsent):
		// DeadlineExceeded, so the caller reads it as its timeout; the mark says no
		// code of the cell ran.
		return NotDispatched(RefusalCapacity, fmt.Errorf("%w: %v", context.DeadlineExceeded, err)), true
	}
	return nil, false
}

// SessionCellResult turns the interpreter driver's outcome into a session cell's
// result, for every provider; ctx is the call's context. An interpreter that could not start ran none of the
// cell's code: that refusal is marked not dispatched (RefuseCell, asking ended whether
// the session's end caused it). A cell whose interpreter ended on a session that has
// ended returns that end, unmarked, through callError: the teardown closing the relay
// can reach the cell before the cancelled context does, so the interpreter's end is the
// session's, not the cell's, and the code may have run. Otherwise a cell whose
// interpreter ended is checked against the sandbox (stopped; nil where a provider has
// no such check), since a sandbox that stopped ends the session and its exit status is
// not the cell's.
func SessionCellResult(ctx context.Context, fail CellResult, out sessionkit.CellOutcome, err error, took time.Duration, software, environment string,
	ended, stopped func() error, callError func(error) error) (CellResult, error) {
	if refusal, ok := RefuseCell(ctx, err, ended()); ok {
		return fail, refusal
	}
	if err != nil {
		return fail, callError(err)
	}
	if out.Ended && !out.TimedOut {
		if end := ended(); end != nil {
			return fail, callError(end)
		}
		if end := stopped(); end != nil {
			return fail, end
		}
	}
	res := CellResult{
		Stdout:              out.Stdout,
		Stderr:              out.Stderr,
		StdoutTruncated:     out.StdoutTruncated,
		StderrTruncated:     out.StderrTruncated,
		TimedOut:            out.TimedOut,
		InterpreterStarted:  out.Started,
		InterpreterEnded:    out.Ended,
		Duration:            took,
		Sandbox:             fail.Sandbox,
		Isolation:           fail.Isolation,
		SoftwareIdentity:    software,
		EnvironmentIdentity: environment,
	}
	switch {
	case out.TimedOut:
		res.ExitCode = 124
	case out.Raised:
		res.ExitCode = 1
	}
	return res, nil
}
