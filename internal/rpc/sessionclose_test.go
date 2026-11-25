package rpc

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// suspendBudgetAtStart is the daemon's suspend budget as the package sets it, read before
// any test puts a short one in its place.
var suspendBudgetAtStart = sessionSuspendBudget

// The daemon's budget for an idle suspend sits above the bound every provider holds its
// own stop or pause under (sandbox.SuspendBound), by the stated margin, so a slow stop is
// the provider's to report and never the daemon's failed suspend, which closes the
// session. The budget is computed from the bound; this fails when a number typed in its
// place parts from it (hunt-quality-58).
func TestTheSuspendBudgetSitsAboveTheProvidersBound(t *testing.T) {
	if sessionSuspendMargin <= 0 || suspendBudgetAtStart != sandbox.SuspendBound+sessionSuspendMargin {
		t.Fatalf("the suspend budget is %s; want the providers' bound %s plus the margin %s", suspendBudgetAtStart, sandbox.SuspendBound, sessionSuspendMargin)
	}
}

// waitLog waits for want in log.
func waitLog(t *testing.T, log *lockedLog, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(log.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in the log:\n%s", want, log.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// hangPauseSessions is the metered fake whose sessions' pauses hang for the whole budget
// they are given, as a provider's stop that is never answered does, and whose closes
// honor the context they get, as a provider's API call does: one given a spent context
// fails at once. The first closeFails closes on a live context fail too, with the
// provider's answer. With gate set, every close after the first waits for gate to be
// closed (or its context to end), so a test reads the state between the first try and
// the next without racing the retry's timer.
type hangPauseSessions struct {
	meteredSessions
	closeFails int
	gate       chan struct{}
}

func (p *hangPauseSessions) OpenSession(ctx context.Context, o sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.meteredSessions.OpenSession(ctx, o)
	if err != nil {
		return nil, err
	}
	return &hangPauseSession{Session: s, fails: p.closeFails, gate: p.gate}, nil
}

type hangPauseSession struct {
	sandbox.Session
	gate          chan struct{}
	mu            sync.Mutex
	fails         int
	closes, spent int
}

func (s *hangPauseSession) Suspend(ctx context.Context) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

func (s *hangPauseSession) Close(ctx context.Context) error {
	s.mu.Lock()
	later := s.closes > 0
	s.mu.Unlock()
	if later && s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes++
	if ctx.Err() != nil {
		s.spent++
		return ctx.Err()
	}
	if s.fails > 0 {
		s.fails--
		return errors.New("the delete was not answered")
	}
	return s.Session.Close(ctx)
}

func (s *hangPauseSession) counts() (closes, spent int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes, s.spent
}

// The reviewer's case for hunt-quality-1: a paid session's idle pause hangs for its whole
// budget, and the caller's allowance cannot cover another idle period. The close gets a
// budget of its own (never the pause's spent one), a close the provider fails is tried
// again until it takes, the log never says closed while the provider still holds the
// session, a call meanwhile is refused with nothing run, and the meter holds the time the
// session may still bill (past the allowance, since those seconds bill anyway) until it
// is gone, then settles to what ran.
func TestAPauseThatHangsThenCannotPayIsClosedOnItsOwnBudgetAndTriedAgain(t *testing.T) {
	oldPause := sessionSuspendBudget
	sessionSuspendBudget = 50 * time.Millisecond
	t.Cleanup(func() { sessionSuspendBudget = oldPause })
	svc, inner, ctx := meteredSessionService(190)
	svc.closeRetry = closeRetry{first: 10 * time.Millisecond, attempts: 4}
	gate := make(chan struct{})
	svc.Sandbox = &hangPauseSessions{meteredSessions: meteredSessions{inner}, closeFails: 2, gate: gate}
	var log lockedLog
	svc.Logger = slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: slog.LevelInfo}))
	clock := fixedSpendTestTime()
	svc.Spend.now = func() time.Time { return clock }
	open, err := svc.OpenSession(ctx, openReq()) // reserves 2 min + 1 min + 10 s = 190 s
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	claimSession(t, svc, ctx, id)
	e, _ := svc.sessions.get(id, "alice")
	clock = clock.Add(150 * time.Second) // 150 s ran: another 70 s does not fit in 190
	e.mu.Lock()
	gen := e.idleGen
	e.mu.Unlock()
	svc.suspend(e, gen)

	fake := inner.Opened()[0]
	if fake.Err() != nil {
		t.Fatal("the first close took; the test needs it to fail")
	}
	if strings.Contains(log.String(), "session closed") || !strings.Contains(log.String(), `"why":"unpaid"`) {
		t.Fatalf("after a failed close: want a failed close named unpaid, and no line saying closed:\n%s", log.String())
	}
	spent, _ := svc.Spend.spent("alice")
	if !e.paid.running() || spent < 190+500 {
		t.Fatalf("after a failed close: meter running %v, %.0f s spent; want it running and holding the session's remaining lifetime (about 600 s) past the 190 s allowance", e.paid.running(), spent)
	}
	_, err = headRun(svc, ctx, callReq(id, "1"))
	if _, marked := notDispatchedOf(err); !marked || fake.Calls() != 0 {
		t.Fatalf("a call while the close is tried again: %v, %d ran; want refused, not dispatched, nothing run", err, fake.Calls())
	}

	close(gate) // the tries after the first go ahead: one more fails, the next takes
	waitGone(t, e, "the session whose close was tried again")
	closes, spentCtx := e.sess.(*hangPauseSession).counts()
	if closes != 3 || spentCtx != 0 {
		t.Fatalf("%d closes, %d of them with a spent context; want 3 (two failed, one took), none spent", closes, spentCtx)
	}
	// The line is written by the retrying goroutine after it removes the session, so it can
	// land a moment after waitGone returns: under a loaded machine the bare check failed a
	// landing gate once (2026-11-20). Wait for it, bounded.
	for deadline := time.Now().Add(2 * time.Second); !strings.Contains(log.String(), "session closed after a failed close"); {
		if time.Now().After(deadline) {
			t.Fatalf("no line saying the retried close took:\n%s", log.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if after, _ := svc.Spend.spent("alice"); e.paid.running() || after > 151 {
		t.Fatalf("after the end: meter running %v, %.0f s spent; want it stopped, charged the 150 s that ran", e.paid.running(), after)
	}
	if failed, gaveUp := svc.SessionCloseCounts(); failed != 2 || gaveUp != 0 {
		t.Fatalf("close counts %d failed, %d gave up; want 2 and 0", failed, gaveUp)
	}
}

// alwaysCloseFails is the metered fake whose sessions never close.
type alwaysCloseFails struct{ meteredSessions }

func (p *alwaysCloseFails) OpenSession(ctx context.Context, o sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.meteredSessions.OpenSession(ctx, o)
	if err != nil {
		return nil, err
	}
	return &closeFailingSession{Session: s}, nil
}

// A close of the daemon's own that fails every try gives up with an error line and a
// count, never a line saying closed, and the meter keeps holding the session's time,
// since its sandbox may bill until the provider's lifetime for it ends.
func TestAFailedOwnCloseGivesUpAndKeepsTheMeterHeld(t *testing.T) {
	svc, inner, ctx := meteredSessionService(1000)
	svc.closeRetry = closeRetry{first: 5 * time.Millisecond, attempts: 3}
	svc.Sandbox = &alwaysCloseFails{meteredSessions{inner}}
	var log lockedLog
	svc.Logger = slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: slog.LevelInfo}))
	clock := fixedSpendTestTime()
	svc.Spend.now = func() time.Time { return clock }
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(open.Msg.GetSessionId(), "alice")
	e.mu.Lock()
	gen := e.idleGen
	e.mu.Unlock()
	svc.suspend(e, gen) // unclaimed: closed instead of paused
	waitLog(t, &log, "session close gave up")
	if strings.Contains(log.String(), "session closed") {
		t.Fatalf("a close that never took was logged as closed:\n%s", log.String())
	}
	if failed, gaveUp := svc.SessionCloseCounts(); failed != 3 || gaveUp != 1 {
		t.Fatalf("close counts %d failed, %d gave up; want 3 and 1", failed, gaveUp)
	}
	if spent, _ := svc.Spend.spent("alice"); !e.paid.running() || spent < 500 {
		t.Fatalf("after the give-up: meter running %v, %.0f s spent; want the session's remaining 10-minute lifetime held", e.paid.running(), spent)
	}
}

// panickingRuns is a provider whose every snippet panics, with a value made from what a
// run returned, as a provider's bug could.
type panickingRuns struct{ fakeSandbox }

func (*panickingRuns) RunJavaScript(context.Context, sandbox.Request) (sandbox.Result, error) {
	panic("output was guest-secret-7f3a")
}

// The reviewer's case for hunt-quality-3: a provider that panics in a single run. The run
// gets its failed audit line, marked as a panic with the panic's type and stack and
// never its value, runs_failed counts it, the caller gets an unmarked internal error with
// an ID, and the run's slot comes back.
func TestAProviderPanicInARunIsAuditedAndCounted(t *testing.T) {
	svc := NewSandboxService(&panickingRuns{})
	svc.Limiter = NewCodeLimiter(1, 1, 0, 0)
	var log lockedLog
	svc.Logger = slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := authenticatedContext("alice")
	for i := 0; i < 2; i++ { // the second finds the one slot free again
		_, err := svc.Run(ctx, jsReq("1"))
		if connect.CodeOf(err) != connect.CodeInternal || !strings.Contains(err.Error(), "internal error ") {
			t.Fatalf("run %d: %v; want internal error <id>", i, err)
		}
		if _, marked := notDispatchedOf(err); marked {
			t.Fatalf("run %d: marked not dispatched; the code may have run", i)
		}
	}
	if total, failed := svc.RunCounts(); total != 2 || failed != 2 {
		t.Fatalf("runs %d, failed %d; want both counted as failed", total, failed)
	}
	lines := log.String()
	if strings.Count(lines, `"msg":"code run failed"`) != 2 || !strings.Contains(lines, `"provider_panicked":true`) ||
		!strings.Contains(lines, `"panic_type":"string"`) || !strings.Contains(lines, "panickingRuns") {
		t.Fatalf("want two failed audit lines marked as panics, with the type and the stack:\n%s", lines)
	}
	if strings.Contains(lines, "guest-secret") {
		t.Fatalf("the panic's value reached the log:\n%s", lines)
	}
}

// kernelStated is a session provider that states the kernel tier while its sessions
// measure container.
type kernelStated struct{ meteredSessions }

func (kernelStated) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationKernel }

// The reviewer's case for hunt-quality-4: an open whose session comes back below the
// request's floor is refused with the isolation refusal, not dispatched (an open carries
// no code), and the session is closed, its place, its slot and its paid time given back.
// The floor is the request's, or the daemon's own (SandboxService.Floor) for a request
// that names none.
func TestAnOpenBelowTheFloorIsRefusedAndClosed(t *testing.T) {
	t.Run("request", func(t *testing.T) { testAnOpenBelowTheFloor(t, false) })
	t.Run("daemon", func(t *testing.T) { testAnOpenBelowTheFloor(t, true) })
}

func testAnOpenBelowTheFloor(t *testing.T, daemonFloor bool) {
	svc, inner, ctx := meteredSessionService(1000)
	svc.Sandbox = kernelStated{meteredSessions{inner}}
	svc.Sessions.MaxSessions = 1
	svc.Limiter = NewCodeLimiter(1, 1, 0, 0)
	clock := fixedSpendTestTime()
	svc.Spend.now = func() time.Time { return clock }
	req := openReq()
	if daemonFloor {
		svc.Floor = sandbox.IsolationKernel
	} else {
		req.Msg.MinimumIsolation = "kernel"
	}
	_, err := svc.OpenSession(ctx, req)
	if reason, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodeFailedPrecondition || !marked ||
		reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION {
		t.Fatalf("an open whose session measures container under a kernel floor: %v; want failed precondition, not dispatched, isolation", err)
	}
	if !errors.Is(err, sandbox.ErrInsufficientIsolation) {
		t.Fatalf("%v; want ErrInsufficientIsolation", err)
	}
	fake := inner.Opened()[0]
	select {
	case <-fake.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the session below the floor was not closed")
	}
	// The meter settles once the sandbox is gone, on the goroutine that waits for it.
	deadline := time.Now().Add(5 * time.Second)
	for spent, _ := svc.Spend.spent("alice"); spent > 1; spent, _ = svc.Spend.spent("alice") {
		if time.Now().After(deadline) {
			t.Fatalf("%.0f s spent; want the open's reservation given back", spent)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The place and the slot came back: the only place, and the only slot, take a new open
	// (one the floor lets through).
	svc.Floor = sandbox.IsolationUnknown
	for {
		if _, err = svc.OpenSession(ctx, openReq()); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("an open after the refused one: %v; want its place and slot free", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// givenUpSessions opens sessions its caller has given up on by the time they open, and
// whose closes honor their context (hangPauseSession's Close).
type givenUpSessions struct {
	meteredSessions
	cancelCaller context.CancelFunc
}

func (p *givenUpSessions) OpenSession(ctx context.Context, o sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.meteredSessions.OpenSession(ctx, o)
	if err != nil {
		return nil, err
	}
	p.cancelCaller()
	return &hangPauseSession{Session: s}, nil
}

// An open whose caller gave up while its sandbox opened closes the session on a context
// of its own, not the caller's canceled one, so a provider whose close honors its
// context closes it at the first try.
func TestAnOpenItsCallerGaveUpOnIsClosedOnALiveContext(t *testing.T) {
	svc, inner, base := meteredSessionService(1000)
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	svc.Sandbox = &givenUpSessions{meteredSessions: meteredSessions{inner}, cancelCaller: cancel}
	if _, err := svc.OpenSession(ctx, openReq()); err == nil {
		t.Fatal("an open its caller gave up on answered")
	}
	fake := inner.Opened()[0]
	if fake.Err() == nil {
		t.Fatal("the session its caller gave up on is still open after the open returned")
	}
	if failed, _ := svc.SessionCloseCounts(); failed != 0 {
		t.Fatalf("%d failed closes; want the first to take", failed)
	}
}
