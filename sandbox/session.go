package sandbox

import (
	"context"
	"errors"
	"fmt"
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
}

// Session is one open session. Calls are serialized: a call waits (bounded by
// its context) until the previous one has finished and the boundary between
// them has been established.
type Session interface {
	// Isolation is the tier the provider measured when the session opened.
	Isolation() IsolationClass
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
	// Done is closed when the session has ended, by Close or by itself.
	Done() <-chan struct{}
	// Err is nil while the session is open and a *SessionEndedError afterwards.
	Err() error
}

// SessionEnd says why a session ended.
type SessionEnd int

const (
	SessionOpen SessionEnd = iota
	// SessionClosed: its holder closed it.
	SessionClosed
	// SessionExpired: its lifetime passed.
	SessionExpired
	// SessionDiskExceeded: a call left more on disk than the session's budget.
	SessionDiskExceeded
	// SessionMainProcessEnded: the sandbox's main process ended (code in the
	// sandbox can kill it), so the sandbox can run nothing more.
	SessionMainProcessEnded
	// SessionBoundaryFailed: the provider could not give the next call a clean
	// sandbox: it could not prove that no process of a call outlived it and a
	// restart failed too, or the sandbox could not be stopped or started. It ended
	// the session rather than run the next call beside a leftover process.
	SessionBoundaryFailed
	// SessionSandboxChanged: the sandbox no longer reads back as it was verified
	// (its policy, settings or spec changed, or it disappeared).
	SessionSandboxChanged
	// SessionShutdown: the provider was drained.
	SessionShutdown
)

var sessionEndNames = map[SessionEnd]string{
	SessionOpen:             "open",
	SessionClosed:           "closed",
	SessionExpired:          "expired",
	SessionDiskExceeded:     "disk_exceeded",
	SessionMainProcessEnded: "main_process_ended",
	SessionBoundaryFailed:   "boundary_failed",
	SessionSandboxChanged:   "sandbox_changed",
	SessionShutdown:         "shutdown",
}

func (e SessionEnd) String() string {
	if s, ok := sessionEndNames[e]; ok {
		return s
	}
	return fmt.Sprintf("session_end(%d)", int(e))
}

// ErrSessionEnded matches every *SessionEndedError.
var ErrSessionEnded = errors.New("sandbox: the session has ended")

// SessionEndedError is a session's end, with its reason and any detail.
type SessionEndedError struct {
	Reason SessionEnd
	Detail string
}

func (e *SessionEndedError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("sandbox: the session has ended (%s)", e.Reason)
	}
	return fmt.Sprintf("sandbox: the session has ended (%s): %s", e.Reason, e.Detail)
}

func (e *SessionEndedError) Is(target error) bool { return target == ErrSessionEnded }

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
//     has ended the end is why, and is what the caller is told; otherwise the image
//     cannot run the language.
//   - Files that could not be written (sessionkit.ErrFiles): a request this session's
//     work directory cannot take. The interpreter and the session go on.
//   - A deadline before the code was sent (sessionkit.ErrUnsent): DeadlineExceeded,
//     marked; the next cell starts a fresh interpreter and says so.
func RefuseCell(err, end error) (refusal error, ok bool) {
	switch {
	case errors.Is(err, sessionkit.ErrLaunch) && end != nil:
		return RefuseEndedSession(end), true
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
