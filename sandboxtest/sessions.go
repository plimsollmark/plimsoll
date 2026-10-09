package sandboxtest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Sessions is an in-memory sandbox.SessionProvider for tests of code that drives
// sessions (a daemon, a client, a harness): it keeps no sandbox and runs no code.
// Each session answers its nth snippet with n "x" characters on stdout, and
// completes every project. It reports the container tier.
type Sessions struct {
	// BeforeOpen, when set, runs at the start of every OpenSession, which returns
	// its error: a test holds an open inside the provider, or makes one fail.
	BeforeOpen func() error
	// SuspendHoldsMemory is what every session's Suspend reports: true acts like a
	// paused container, false (the default) like a stopped one.
	SuspendHoldsMemory bool
	// FailedSuspends is how many of each session's first Suspend calls fail without
	// ending it, as one that gave up waiting for a busy turn does.
	FailedSuspends int
	// HoldDeletes, when set, leaves an ended session's Done open until its
	// FinishDelete, as a real provider's Done waits for its sandbox's delete; unset,
	// Done closes as the session ends (the fake has no sandbox to delete).
	HoldDeletes bool
	// OpenedEnvironments, when set, is what every opened session's Environments
	// reports instead of SessionEnvironments: a provider whose image changed during
	// the open.
	OpenedEnvironments *sandbox.Environments

	mu     sync.Mutex
	opened []*FakeSession
}

var _ sandbox.SessionProvider = (*Sessions)(nil)
var _ sandbox.Sandbox = (*Sessions)(nil)

// Name is "fake-sessions".
func (*Sessions) Name() string { return "fake-sessions" }

// IsolationClass is container.
func (*Sessions) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationContainer }

// RunJavaScript, RunProject and RunModule are unsupported: only sessions run here.
func (*Sessions) RunJavaScript(context.Context, sandbox.Request) (sandbox.Result, error) {
	return sandbox.Result{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}

func (*Sessions) RunProject(context.Context, sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	return sandbox.ProjectResult{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}

func (*Sessions) RunModule(context.Context, sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	return sandbox.ModuleResult{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}

// SupportsSessions is true.
func (*Sessions) SupportsSessions() bool { return true }

// SessionEnvironments states nothing: the fake runs no image.
func (*Sessions) SessionEnvironments() sandbox.Environments { return sandbox.Environments{} }

// OpenSession opens a fake session with opts.
func (p *Sessions) OpenSession(_ context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	if p.BeforeOpen != nil {
		if err := p.BeforeOpen(); err != nil {
			return nil, err
		}
	}
	s := &FakeSession{Options: opts, expires: time.Now().Add(opts.Lifetime), done: make(chan struct{}), holdsMemory: p.SuspendHoldsMemory,
		failSuspends: p.FailedSuspends, holdDelete: p.HoldDeletes, environments: p.SessionEnvironments()}
	if p.OpenedEnvironments != nil {
		s.environments = *p.OpenedEnvironments
	}
	p.mu.Lock()
	p.opened = append(p.opened, s)
	p.mu.Unlock()
	return s, nil
}

// Opened returns the sessions opened so far, in order.
func (p *Sessions) Opened() []*FakeSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*FakeSession(nil), p.opened...)
}

// WaitEnded waits until every session opened so far has ended and its Done has closed,
// or ctx ends: a test of something the daemon ends by itself waits for it this way
// rather than for a guessed time.
func (p *Sessions) WaitEnded(ctx context.Context) error {
	for _, s := range p.Opened() {
		select {
		case <-s.Done():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// FakeSession is one session of Sessions.
type FakeSession struct {
	Options      sandbox.SessionOptions
	expires      time.Time
	done         chan struct{}
	holdsMemory  bool
	failSuspends int
	environments sandbox.Environments
	holdDelete   bool
	deleted      sync.Once

	mu          sync.Mutex
	calls       int
	cells       map[sandbox.Language]int
	suspended   int
	lastTimeout time.Duration
	end         *sandbox.SessionEndedError
}

var _ sandbox.Session = (*FakeSession)(nil)

func (s *FakeSession) Isolation() sandbox.IsolationClass { return sandbox.IsolationContainer }

// Environments is what the provider's SessionEnvironments said when the session
// opened, or Sessions.OpenedEnvironments when that is set.
func (s *FakeSession) Environments() sandbox.Environments { return s.environments }
func (s *FakeSession) ExpiresAt() time.Time               { return s.expires }
func (s *FakeSession) Done() <-chan struct{}              { return s.done }

// Err is the session's end, or nil.
func (s *FakeSession) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.end == nil {
		return nil
	}
	return s.end
}

// End ends the session for reason, as a provider does when a lifetime passes or a
// budget is exceeded. Done closes with it unless the provider holds deletes.
func (s *FakeSession) End(reason sandbox.SessionEnd) {
	s.mu.Lock()
	ended := s.end == nil
	if ended {
		s.end = &sandbox.SessionEndedError{Reason: reason}
	}
	s.mu.Unlock()
	if ended && !s.holdDelete {
		s.FinishDelete()
	}
}

// FinishDelete closes Done, as a provider does once an ended session's sandbox is
// deleted. It does nothing before the session ends, or a second time.
func (s *FakeSession) FinishDelete() {
	if s.Err() == nil {
		return
	}
	s.deleted.Do(func() { close(s.done) })
}

// Suspends counts the Suspend calls the session received.
func (s *FakeSession) Suspends() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.suspended
}

// Calls counts the snippet and project calls the session ran.
func (s *FakeSession) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// LastTimeout is the timeout the last snippet call carried, as the caller set it.
func (s *FakeSession) LastTimeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastTimeout
}

// RunJavaScript answers the nth call with n "x" characters.
func (s *FakeSession) RunJavaScript(_ context.Context, req sandbox.Request) (sandbox.Result, error) {
	if err := s.Err(); err != nil {
		return sandbox.Result{}, sandbox.RefuseEndedSession(err)
	}
	if err := sandbox.CheckSessionGrant(req.Grant); err != nil {
		return sandbox.Result{}, err
	}
	s.mu.Lock()
	s.calls++
	n := s.calls
	s.lastTimeout = req.Timeout
	s.mu.Unlock()
	return sandbox.Result{Stdout: strings.Repeat("x", n), Sandbox: "fake-sessions", Isolation: sandbox.IsolationContainer}, nil
}

// RunProject completes every project with no steps.
func (s *FakeSession) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	if err := s.Err(); err != nil {
		return sandbox.ProjectResult{}, sandbox.RefuseEndedSession(err)
	}
	if err := sandbox.CheckSessionGrant(req.Grant); err != nil {
		return sandbox.ProjectResult{}, err
	}
	return sandbox.ProjectResult{Sandbox: "fake-sessions", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted}, nil
}

// RunCell answers with the language, the number of cells that language's fake
// interpreter has run (1 for the first, which reports InterpreterStarted), and the
// code, as "python 2: x = 1". A cell's files are listed on stderr, one path a line.
// CellPastDeadline and CellEndsSession end the interpreter and the session.
func (s *FakeSession) RunCell(_ context.Context, req sandbox.CellRequest) (sandbox.CellResult, error) {
	if err := sandbox.ValidateCellRequest(req); err != nil {
		return sandbox.CellResult{}, err
	}
	if err := s.Err(); err != nil {
		return sandbox.CellResult{}, sandbox.RefuseEndedSession(err)
	}
	s.mu.Lock()
	s.calls++
	if s.cells == nil {
		s.cells = map[sandbox.Language]int{}
	}
	s.cells[req.Language]++
	n := s.cells[req.Language]
	if req.Code == CellPastDeadline {
		s.cells[req.Language] = 0
	}
	s.lastTimeout = req.Timeout
	s.mu.Unlock()
	var paths []string
	for _, f := range req.Files {
		paths = append(paths, f.Path+"\n")
	}
	res := sandbox.CellResult{
		Stdout:             fmt.Sprintf("%s %d: %s", req.Language, n, req.Code),
		Stderr:             strings.Join(paths, ""),
		InterpreterStarted: n == 1,
		Sandbox:            "fake-sessions",
		Isolation:          sandbox.IsolationContainer,
	}
	switch req.Code {
	case CellPastDeadline:
		res.ExitCode, res.TimedOut, res.InterpreterEnded = 124, true, true
	case CellEndsSession:
		s.End(sandbox.SessionDiskExceeded)
	}
	return res, nil
}

// Cells the fake answers as a provider answers code it cannot run here.
const (
	// CellPastDeadline runs past its deadline: it times out (exit 124) and ends its
	// interpreter, so the language's next cell starts a fresh one.
	CellPastDeadline = "plimsoll-fake:past-deadline"
	// CellEndsSession answers, and then the session ends, as one does when a call
	// leaves more on disk than the session's budget.
	CellEndsSession = "plimsoll-fake:ends-session"
)

// Suspend counts itself and reports the provider's SuspendHoldsMemory, or fails
// without ending the session while it has had no more than FailedSuspends calls.
func (s *FakeSession) Suspend(context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.suspended++
	if s.suspended <= s.failSuspends {
		return false, sandbox.NotDispatched(sandbox.RefusalCapacity, errors.New("sandboxtest: gave up waiting for the session's turn"))
	}
	return s.holdsMemory, nil
}

// Close ends the session as closed.
func (s *FakeSession) Close(context.Context) error {
	s.End(sandbox.SessionClosed)
	return nil
}
