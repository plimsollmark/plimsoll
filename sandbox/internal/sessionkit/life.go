package sessionkit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
)

// A session's lifecycle is the same on every provider: one call at a time, the
// sandbox made ready before each call and swept after it, a lifetime, a suspend, an
// end that is reported at once while the sandbox's removal finishes off the caller's
// path. Life is that lifecycle; a provider supplies only what touches its sandbox
// (Hooks). Package sandbox names End and EndedError SessionEnd and SessionEndedError
// and documents each end there.

// End says why a session ended.
type End int

const (
	Open End = iota
	Closed
	Expired
	DiskExceeded
	MainProcessEnded
	BoundaryFailed
	SandboxChanged
	Shutdown
)

var endNames = map[End]string{
	Open:             "open",
	Closed:           "closed",
	Expired:          "expired",
	DiskExceeded:     "disk_exceeded",
	MainProcessEnded: "main_process_ended",
	BoundaryFailed:   "boundary_failed",
	SandboxChanged:   "sandbox_changed",
	Shutdown:         "shutdown",
}

func (e End) String() string {
	if s, ok := endNames[e]; ok {
		return s
	}
	return fmt.Sprintf("session_end(%d)", int(e))
}

// ErrEnded matches every *EndedError.
var ErrEnded = errors.New("sandbox: the session has ended")

// EndedError is a session's end, with its reason and any detail.
type EndedError struct {
	Reason End
	Detail string
}

func (e *EndedError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("sandbox: the session has ended (%s)", e.Reason)
	}
	return fmt.Sprintf("sandbox: the session has ended (%s): %s", e.Reason, e.Detail)
}

func (e *EndedError) Is(target error) bool { return target == ErrEnded }

// SweepBudget bounds one sweep: normally an exec, a node start and a scan of /proc
// (and, on a provider that measures by walking, one walk of the session's files).
const SweepBudget = 20 * time.Second

// Refusals are the errors a session's own refusals take, package sandbox's
// not-dispatched marks (which sessionkit cannot import): nothing of the call ran.
type Refusals struct {
	// Ended is a call on a session that has ended, or ended while it waited.
	Ended func(end error) error
	// GaveUp is a call whose context ended before any of it ran.
	GaveUp func(ctx context.Context) error
	// Unreadable is a call whose sandbox could not be read back before it; the
	// session goes on.
	Unreadable func(err error) error
}

// Hooks are what a provider's session does to its sandbox. Life calls each with the
// session's turn held, except Teardown, which runs once the session has ended.
type Hooks struct {
	// Provider and Unit name the provider and what it calls its sandbox, for the log
	// line an end other than Closed or Shutdown writes ("docker", "container").
	Provider, Unit string
	Refuse         Refusals

	// Suspend releases the sandbox's CPU and keeps its files. Its context cannot be
	// cut short by the caller, only by the hook's own budget: a suspend cancelled after
	// the platform took it would leave the sandbox suspended while the session thinks it
	// runs. An error ends the session (BoundaryFailed, with the error as the detail).
	Suspend func(ctx context.Context) error
	// SuspendHoldsMemory: a suspended sandbox still holds its memory (a paused
	// container does, a stopped one does not).
	SuspendHoldsMemory bool
	// Resume makes a suspended sandbox run again before a call, under the same
	// context rule as Suspend. An error ends the session (BoundaryFailed).
	Resume func(ctx context.Context) error
	// ReadBack checks before every call that the sandbox is the one opened. It returns
	// nil; an *EndedError, which ends the session (the sandbox changed, is gone, or
	// its main process ended); or any other error when the sandbox could not be read,
	// which refuses the call and keeps the session.
	ReadBack func(ctx context.Context) error

	// Sweep runs argv (SweepArgv) in the sandbox as one of plimsoll's own programs and
	// returns what it exited with. Its exit status is the boundary between calls.
	Sweep func(ctx context.Context, argv []string) (ExecResult, error)
	// Measure and Dirs are how the sweep measures the session's files against its disk
	// budget.
	Measure Measure
	Dirs    []string
	// Unproven runs after a sweep that did not prove the boundary (sweep says how) and
	// returns the session's end, or nil when the provider gave the next call a clean
	// sandbox another way (a restart).
	Unproven func(ctx context.Context, sweep string) *EndedError

	// Teardown removes the sandbox once the session has ended, after its interpreters
	// are closed; Done closes when it returns.
	Teardown func()
}

// Life is one session's lifecycle. Its zero value is not usable; see NewLife.
type Life struct {
	// Name is the sandbox's name, for the log and the provider's registry.
	Name string
	// Interps are the session's live interpreters, which the sweep keeps.
	Interps Interpreters

	h      Hooks
	ctx    context.Context // cancelled when the session ends, which stops a call in flight
	cancel context.CancelFunc
	turn   chan struct{} // one slot: holding it is the right to call, suspend or resume
	done   chan struct{} // closed once the session has ended and Teardown has returned

	mu        sync.Mutex
	end       *EndedError
	reg       *Registry
	timer     *time.Timer
	expires   time.Time
	disk      int64
	suspended bool
	baseline  []string // the sandbox's own processes, which every sweep keeps
}

// NewLife is a session's lifecycle before anyone holds the session: Activate hands it
// over, Abandon gives it up.
func NewLife(name string, h Hooks) *Life {
	l := &Life{Name: name, h: h, turn: make(chan struct{}, 1), done: make(chan struct{})}
	l.ctx, l.cancel = context.WithCancel(context.Background())
	return l
}

// Context is cancelled when the session ends.
func (l *Life) Context() context.Context { return l.ctx }

// SetBaseline records the sandbox's own processes (Baseline), which every sweep keeps.
func (l *Life) SetBaseline(keep []string) {
	l.mu.Lock()
	l.baseline = keep
	l.mu.Unlock()
}

// Keep is what every sweep spares: the sandbox's own processes and the live
// interpreters.
func (l *Life) Keep() []string {
	l.mu.Lock()
	baseline := append([]string(nil), l.baseline...)
	l.mu.Unlock()
	return l.Interps.Keep(baseline)
}

// Activate hands the session to a caller: registered in reg, its lifetime ending at
// expires, its disk budget disk (0: none). It returns false, and changes nothing,
// once reg's Drain has begun; the caller then abandons the session.
func (l *Life) Activate(reg *Registry, expires time.Time, disk int64) bool {
	l.mu.Lock()
	l.expires, l.disk, l.reg = expires, disk, reg
	l.mu.Unlock()
	if !reg.register(l) {
		return false
	}
	l.mu.Lock()
	if l.end == nil {
		l.timer = time.AfterFunc(time.Until(expires), func() { l.Finish(Expired, "") })
	}
	l.mu.Unlock()
	return true
}

// Abandon gives up a session no caller holds (one that failed to open, a pool
// member): it stops anything started for it and closes its interpreters. The provider
// removes the sandbox. It records an end, as Finish does, so a call that still reached
// the session is refused with that end instead of a nil one (a nil cause reads as
// success, and the call would go on without its turn).
func (l *Life) Abandon() {
	l.mu.Lock()
	if l.end == nil {
		l.end = &EndedError{Reason: Closed, Detail: "abandoned before a caller held it"}
	}
	if l.timer != nil {
		l.timer.Stop()
	}
	l.mu.Unlock()
	l.cancel()
	l.Interps.Close()
}

// ExpiresAt is when the session's lifetime ends.
func (l *Life) ExpiresAt() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.expires
}

// Done is closed once the session has ended and its sandbox is removed (or the
// removal gave up).
func (l *Life) Done() <-chan struct{} { return l.done }

// Err is nil while the session is open and its *EndedError from the moment it ends.
func (l *Life) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.end == nil {
		return nil
	}
	return l.end
}

// Finish ends the session once, for the first reason given: it stops a call in
// flight and removes the sandbox off the caller's path. Done closes only once the
// removal has returned: a session layer gives back the session's capacity on Done,
// and until then the sandbox still holds its memory (review F9).
func (l *Life) Finish(reason End, detail string) {
	l.mu.Lock()
	if l.end != nil {
		l.mu.Unlock()
		return
	}
	l.end = &EndedError{Reason: reason, Detail: detail}
	if l.timer != nil {
		l.timer.Stop()
	}
	reg := l.reg
	l.mu.Unlock()
	l.cancel()
	gone := func() {}
	if reg != nil {
		gone = reg.unregister(l)
	}
	if reason != Closed && reason != Shutdown {
		slog.Info(l.h.Provider+": session ended", l.h.Unit, l.Name, "reason", reason.String(), "detail", detail)
	}
	go func() {
		defer gone()
		l.Interps.Close()
		l.h.Teardown()
		close(l.done)
	}()
}

// Close ends the session and removes its sandbox. It does not wait for a call in
// flight: the call is stopped.
func (l *Life) Close() { l.Finish(Closed, "") }

// Hold takes the session's turn, bounded by ctx, as a call does, without making the
// sandbox ready: what a call refuses with, Hold refuses with. release gives it back.
func (l *Life) Hold(ctx context.Context) (release func(), err error) {
	if err := l.acquire(ctx); err != nil {
		return nil, err
	}
	return l.release, nil
}

// acquire takes the session's turn, bounded by ctx. A session that ended, or ends
// while waiting, refuses: nothing ran. So does a ctx that is done, even when a free
// turn was there to take (select picks at random among ready cases): a caller that has
// gone would otherwise resume a suspended sandbox for nothing.
func (l *Life) acquire(ctx context.Context) error {
	if err := l.Err(); err != nil {
		return l.h.Refuse.Ended(err)
	}
	select {
	case l.turn <- struct{}{}:
	case <-l.ctx.Done(): // cancelled as the session ends, before its removal
		return l.h.Refuse.Ended(l.Err())
	case <-ctx.Done():
		return l.h.Refuse.GaveUp(ctx)
	}
	if err := l.Err(); err != nil {
		<-l.turn
		return l.h.Refuse.Ended(err)
	}
	if ctx.Err() != nil {
		<-l.turn
		return l.h.Refuse.GaveUp(ctx)
	}
	return nil
}

func (l *Life) release() { <-l.turn }

// Suspend suspends the sandbox (Hooks.Suspend), waiting for a call in flight to
// finish, and reports whether the suspended sandbox still holds its memory.
func (l *Life) Suspend(ctx context.Context) (holdsMemory bool, err error) {
	if err := l.acquire(ctx); err != nil {
		return false, err
	}
	defer l.release()
	l.mu.Lock()
	suspended := l.suspended
	l.mu.Unlock()
	if suspended {
		return l.h.SuspendHoldsMemory, nil
	}
	if err := l.h.Suspend(context.WithoutCancel(ctx)); err != nil {
		l.Finish(BoundaryFailed, err.Error())
		return false, l.Err()
	}
	l.mu.Lock()
	l.suspended = true
	l.mu.Unlock()
	return l.h.SuspendHoldsMemory, nil
}

// Call takes the session's turn for one call and makes the sandbox ready for it
// (resumed if suspended, then read back). It returns the call's context, ctx bounded
// by timeout and cancelled when the session ends, and done, which the call runs when
// it has its answer: done runs the sweep and gives the turn back off the caller's
// path, so the answer goes back first, and the next call (or a suspend, or a close)
// waits for the sweep, which an agent's own thinking time between tool calls usually
// hides. A session the sweep ends is therefore reported to the next call. Nothing has
// run when Call fails.
func (l *Life) Call(ctx context.Context, timeout time.Duration) (runCtx context.Context, done func(), err error) {
	if err := l.acquire(ctx); err != nil {
		return nil, nil, err
	}
	if err := l.prepare(ctx); err != nil {
		l.release()
		return nil, nil, err
	}
	// A session that ended while prepare ran (its lifetime, a drain) refuses the call:
	// nothing has run yet. One that ends from here on cancels runCtx, at once if it
	// already has (AfterFunc would cancel it from another goroutine, after the call
	// could have started).
	if err := l.Err(); err != nil {
		l.release()
		return nil, nil, l.h.Refuse.Ended(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	stop := context.AfterFunc(l.ctx, cancel)
	if l.ctx.Err() != nil {
		cancel()
	}
	return runCtx, func() {
		stop()
		cancel()
		go func() {
			l.boundary()
			l.release()
		}()
	}, nil
}

// prepare runs with the turn held, before a call: it resumes a suspended sandbox,
// then reads it back.
func (l *Life) prepare(ctx context.Context) error {
	l.mu.Lock()
	suspended := l.suspended
	l.mu.Unlock()
	if suspended {
		if err := l.h.Resume(context.WithoutCancel(ctx)); err != nil {
			l.Finish(BoundaryFailed, err.Error())
			return l.h.Refuse.Ended(l.Err())
		}
		l.mu.Lock()
		l.suspended = false
		l.mu.Unlock()
	}
	err := l.h.ReadBack(ctx)
	var end *EndedError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &end):
		l.Finish(end.Reason, end.Detail)
		return l.h.Refuse.Ended(l.Err())
	case ctx.Err() != nil:
		return l.h.Refuse.GaveUp(ctx)
	}
	// Nothing ran, and the sandbox could not be shown to be the one opened. The
	// session goes on: the next call reads it back again (review F4).
	return l.h.Refuse.Unreadable(err)
}

// boundary runs after every call, with the turn held and whatever happened to the
// caller's context: the sweep, and when it does not prove the boundary,
// Hooks.Unproven. A session over its disk budget ends here too.
func (l *Life) boundary() {
	if l.Err() != nil {
		return
	}
	l.mu.Lock()
	disk := l.disk
	l.mu.Unlock()
	ctx, cancel := context.WithTimeout(l.ctx, SweepBudget)
	out, err := l.h.Sweep(ctx, SweepArgv(disk, l.h.Measure, l.h.Dirs, l.Keep()))
	cancel()
	if l.Err() != nil {
		return
	}
	if err == nil && out.Exited {
		switch out.ExitCode {
		case SweepClean:
			return
		case SweepOverBudget:
			l.Finish(DiskExceeded, l.overBudget(disk))
			return
		case SweepUnmeasurable:
			l.Finish(DiskExceeded, l.unmeasurable())
			return
		}
	}
	if end := l.h.Unproven(l.ctx, fmt.Sprintf("the sweep exited %d (err %v)", out.ExitCode, err)); end != nil {
		l.Finish(end.Reason, end.Detail)
	}
}

func (l *Life) overBudget(disk int64) string {
	if l.h.Measure == MeasureWalk {
		return fmt.Sprintf("the session's files under %s exceed %d bytes or %d entries", strings.Join(l.h.Dirs, ", "), disk, MaxDiskEntries)
	}
	return fmt.Sprintf("the session's writable filesystems hold more than %d bytes", disk)
}

func (l *Life) unmeasurable() string {
	if l.h.Measure == MeasureWalk {
		return fmt.Sprintf("a directory under %s could not be read, so the session's disk use cannot be measured", strings.Join(l.h.Dirs, ", "))
	}
	return "the session's disk use could not be read"
}

// CallError is what a call returns when its command did not deliver an exit status:
// a session that ended during the call (its lifetime passed, or it was closed) is
// reported as that end, then the call's own deadline. Execution may have happened, so
// it is not marked not-dispatched.
func (l *Life) CallError(runCtx context.Context, err error) error {
	if end := l.Err(); end != nil {
		return end
	}
	if ctxErr := deadline.Expired(runCtx); ctxErr != nil {
		return ctxErr
	}
	return err
}

// Registry is a provider's open sessions, the opens still in flight, the sandbox
// removals still running, and whether Drain has begun, after which no session is
// handed over. Its zero value is ready.
type Registry struct {
	mu       sync.Mutex
	open     map[*Life]struct{}
	opening  sync.WaitGroup // added to only under mu while not draining
	removals sync.WaitGroup // added to only under mu
	draining bool
}

// Enter counts an operation in flight that Drain must wait for (an open; on OpenShell,
// any creation of a sandbox until its name is tracked), which Opened waits for; leave
// ends it. ok is false once Drain has begun.
func (r *Registry) Enter() (leave func(), ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.draining {
		return nil, false
	}
	r.opening.Add(1)
	return r.opening.Done, true
}

// Unless runs f under the registry's lock unless Drain has begun, and reports
// whether it ran: a Drain either comes after f and sees what it did, or came first.
func (r *Registry) Unless(f func()) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.draining {
		return false
	}
	f()
	return true
}

func (r *Registry) register(l *Life) bool {
	ran := r.Unless(func() {
		if r.open == nil {
			r.open = map[*Life]struct{}{}
		}
		r.open[l] = struct{}{}
	})
	return ran
}

// unregister removes l and counts its removal, which the returned func ends. Both
// happen under one lock, so a Drain that no longer finds l open waits for its
// removal.
func (r *Registry) unregister(l *Life) (gone func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.open, l)
	r.removals.Add(1)
	return r.removals.Done
}

// Removal counts a sandbox removal outside a session's end (a pool member's), which
// the returned func ends; WaitRemovals waits for it.
func (r *Registry) Removal() (gone func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removals.Add(1)
	return r.removals.Done
}

// Drain refuses every open and every Activate from now on.
func (r *Registry) Drain() {
	r.mu.Lock()
	r.draining = true
	r.mu.Unlock()
}

// Opened is closed once no open counted by Enter is in flight.
func (r *Registry) Opened() <-chan struct{} {
	c := make(chan struct{})
	go func() {
		r.opening.Wait()
		close(c)
	}()
	return c
}

// Open is the sessions open now.
func (r *Registry) Open() []*Life {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Life, 0, len(r.open))
	for l := range r.open {
		out = append(out, l)
	}
	return out
}

// EndAll ends every session open now (reason) and returns wait, which waits within
// ctx until each of them has been torn down. That includes a session another
// goroutine (its lifetime timer, a client's Close) had begun to end: EndAll's Finish
// returns at once for it, and its removal may not be counted yet when EndAll returns,
// so WaitRemovals alone would miss it.
func (r *Registry) EndAll(reason End) (wait func(ctx context.Context) error) {
	open := r.Open()
	for _, l := range open {
		l.Finish(reason, "")
	}
	return func(ctx context.Context) error {
		for _, l := range open {
			select {
			case <-l.Done():
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
}

// WaitRemovals waits, within ctx, for every removal counted so far. Call it only once
// no more can be counted: after Drain, with the opens in flight done and every other
// counter stopped.
func (r *Registry) WaitRemovals(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		r.removals.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
