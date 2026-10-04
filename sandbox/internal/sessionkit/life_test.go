package sessionkit

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// refused marks a refusal as package sandbox's not-dispatched marks do, by kind.
type refused struct {
	kind string
	err  error
}

func (r *refused) Error() string { return r.kind + ": " + r.err.Error() }
func (r *refused) Unwrap() error { return r.err }

func refusalKind(err error) string {
	var r *refused
	if errors.As(err, &r) {
		return r.kind
	}
	return ""
}

var testRefusals = Refusals{
	Ended:      func(end error) error { return &refused{"ended", end} },
	GaveUp:     func(ctx context.Context) error { return &refused{"gave_up", ctx.Err()} },
	Unreadable: func(err error) error { return &refused{"unreadable", err} },
}

// fakeSandbox scripts the hooks and records what Life asked of it.
type fakeSandbox struct {
	mu       sync.Mutex
	readBack error
	sweep    ExecResult
	sweepErr error
	unproven *EndedError
	suspends int
	resumes  int
	swept    [][]string
	torn     chan struct{} // closed when Teardown may return
}

func (f *fakeSandbox) hooks() Hooks {
	return Hooks{
		Provider: "test", Unit: "sandbox",
		Refuse: testRefusals,
		Suspend: func(context.Context) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.suspends++
			return nil
		},
		Resume: func(context.Context) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.resumes++
			return nil
		},
		ReadBack: func(context.Context) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.readBack
		},
		Sweep: func(_ context.Context, argv []string) (ExecResult, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.swept = append(f.swept, argv)
			return f.sweep, f.sweepErr
		},
		Measure: MeasureWalk,
		Dirs:    []string{"/tmp"},
		Unproven: func(context.Context, string) *EndedError {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.unproven
		},
		Teardown: func() {
			if f.torn != nil {
				<-f.torn
			}
		},
	}
}

func (f *fakeSandbox) set(change func(f *fakeSandbox)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func openLife(t *testing.T, f *fakeSandbox, reg *Registry) *Life {
	t.Helper()
	l := NewLife("box", f.hooks())
	l.SetBaseline([]string{"1:1:00", "7:2:00"})
	if !l.Activate(reg, time.Now().Add(time.Hour), 4096) {
		t.Fatal("Activate refused before Drain")
	}
	t.Cleanup(l.Close)
	return l
}

// call runs one call and waits for its sweep, as the next call would.
func call(t *testing.T, l *Life) error {
	t.Helper()
	_, done, err := l.Call(context.Background(), time.Second)
	if err != nil {
		return err
	}
	done()
	if release, err := l.Hold(context.Background()); err == nil {
		release()
	}
	return nil
}

// The read-back decides each call: nil runs it; an end ends the session; any other
// error refuses the call and keeps the session; a caller who gave up gave up.
func TestReadBackDecidesTheCall(t *testing.T) {
	f := &fakeSandbox{}
	l := openLife(t, f, &Registry{})
	if err := call(t, l); err != nil {
		t.Fatalf("a call on a sandbox that reads back: %v", err)
	}
	f.set(func(f *fakeSandbox) { f.readBack = errors.New("no answer") })
	if err := call(t, l); refusalKind(err) != "unreadable" || l.Err() != nil {
		t.Fatalf("an unreadable sandbox: %v (session %v); want the call refused and the session open", err, l.Err())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := l.Call(ctx, time.Second); refusalKind(err) != "gave_up" {
		t.Fatalf("a caller that gave up: %v", err)
	}
	f.set(func(f *fakeSandbox) { f.readBack = &EndedError{Reason: SandboxChanged, Detail: "changed"} })
	err := call(t, l)
	var end *EndedError
	if refusalKind(err) != "ended" || !errors.As(err, &end) || end.Reason != SandboxChanged {
		t.Fatalf("a changed sandbox: %v; want the session's end, refused", err)
	}
}

// The sweep's exit status is the boundary: clean goes on, over budget and
// unmeasurable end the session, and anything else is for Unproven to decide.
func TestSweepDecidesTheBoundary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sweep    ExecResult
		sweepErr error
		unproven *EndedError
		want     End
		detail   string
	}{
		{"clean", ExecResult{Exited: true, ExitCode: SweepClean}, nil, nil, Open, ""},
		{"over budget", ExecResult{Exited: true, ExitCode: SweepOverBudget}, nil, nil, DiskExceeded, "under /tmp exceed 4096 bytes"},
		{"unmeasurable", ExecResult{Exited: true, ExitCode: SweepUnmeasurable}, nil, nil, DiskExceeded, "could not be read"},
		{"unproven, restarted", ExecResult{Exited: true, ExitCode: 1}, nil, nil, Open, ""},
		{"unproven, ended", ExecResult{}, errors.New("stream broke"), &EndedError{Reason: BoundaryFailed, Detail: "no"}, BoundaryFailed, "no"},
		{"over budget, no status", ExecResult{ExitCode: SweepOverBudget}, nil, &EndedError{Reason: BoundaryFailed}, BoundaryFailed, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSandbox{sweep: tc.sweep, sweepErr: tc.sweepErr, unproven: tc.unproven}
			l := openLife(t, f, &Registry{})
			if err := call(t, l); err != nil {
				t.Fatal(err)
			}
			if got := SessionEnd(l.Err()); got != tc.want {
				t.Fatalf("ended %v; want %v", got, tc.want)
			}
			if tc.detail != "" && !strings.Contains(l.Err().Error(), tc.detail) {
				t.Fatalf("end %q; want it to say %q", l.Err(), tc.detail)
			}
			argv := f.swept[0]
			if !slices.Equal(argv[3:6], []string{"4096", "200000", "walk"}) || !slices.Equal(argv[7:], []string{"1:1:00", "7:2:00"}) {
				t.Fatalf("sweep argv %q", argv[3:])
			}
		})
	}
}

// SessionEnd is the reason of a session's end, Open when it is open.
func SessionEnd(err error) End {
	var end *EndedError
	if errors.As(err, &end) {
		return end.Reason
	}
	return Open
}

// A suspended sandbox is suspended once and resumed by the next call.
func TestSuspendThenCallResumes(t *testing.T) {
	f := &fakeSandbox{}
	l := openLife(t, f, &Registry{})
	for range 2 {
		if _, err := l.Suspend(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err := call(t, l); err != nil {
		t.Fatal(err)
	}
	if f.suspends != 1 || f.resumes != 1 {
		t.Fatalf("suspends %d, resumes %d; want 1 and 1", f.suspends, f.resumes)
	}
}

// Once Drain has begun nothing is handed over, and Enter refuses.
func TestDrainRefusesActivateAndEnter(t *testing.T) {
	var reg Registry
	reg.Drain()
	l := NewLife("box", (&fakeSandbox{}).hooks())
	if l.Activate(&reg, time.Now().Add(time.Hour), 0) {
		t.Fatal("Activate after Drain")
	}
	if len(reg.Open()) != 0 {
		t.Fatal("a session refused by Drain is registered")
	}
	if _, ok := reg.Enter(); ok {
		t.Fatal("Enter after Drain")
	}
}

// EndAll waits for a session another goroutine (its lifetime timer, a Close) had
// begun to end and not yet unregistered: its Finish from EndAll returns at once, and
// its removal is not counted yet, so only its own Done says when it is gone. This is
// what docker's Drain relied on waiting for each session it found open.
func TestEndAllWaitsForASessionAnotherGoroutineIsEnding(t *testing.T) {
	var reg Registry
	f := &fakeSandbox{torn: make(chan struct{})}
	l := NewLife("box", f.hooks())
	if !l.Activate(&reg, time.Now().Add(time.Hour), 0) {
		t.Fatal("Activate refused")
	}
	// Another goroutine's Finish has claimed the end and not yet reached the registry.
	l.mu.Lock()
	l.end = &EndedError{Reason: Expired}
	l.timer.Stop()
	l.mu.Unlock()
	wait := reg.EndAll(Shutdown)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := wait(ctx); err == nil {
		t.Fatal("EndAll's wait returned while a session it found open was still being ended")
	}
	if err := reg.WaitRemovals(context.Background()); err != nil {
		t.Fatal(err) // nothing counted yet: what made waiting on removals alone wrong
	}
}

// Finish is reported at once, and Done closes only after Teardown.
func TestDoneWaitsForTeardown(t *testing.T) {
	var reg Registry
	f := &fakeSandbox{torn: make(chan struct{})}
	l := openLife(t, f, &reg)
	l.Finish(Expired, "")
	if SessionEnd(l.Err()) != Expired {
		t.Fatalf("Err after Finish: %v", l.Err())
	}
	select {
	case <-l.Done():
		t.Fatal("Done before the sandbox was removed")
	case <-time.After(20 * time.Millisecond):
	}
	if len(reg.Open()) != 0 {
		t.Fatal("an ended session is still registered")
	}
	close(f.torn)
	<-l.Done()
	if err := reg.WaitRemovals(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestControlArgv(t *testing.T) {
	argv, err := ControlArgv(map[string]string{"PLIMSOLL_WORK": "/work"}, "node", "-")
	if err != nil || !slices.Equal(argv, []string{"/usr/bin/env", "-i", "PATH=" + ControlPath, "PLIMSOLL_WORK=/work", "node", "-"}) {
		t.Fatalf("ControlArgv: %q, %v", argv, err)
	}
	if _, err := ControlArgv(map[string]string{"A B": "x"}); err == nil {
		t.Error("ControlArgv accepted an invalid name")
	}
}

// A call whose context is already done is refused before it does anything: it could
// otherwise take a free turn (select picks at random among ready cases) and resume a
// suspended sandbox, which on OpenShell is a StartSandbox and a baseline, for a request
// then refused as gave_up.
func TestACallThatGaveUpResumesNothing(t *testing.T) {
	resumed := 0
	for range 200 {
		f := &fakeSandbox{}
		l := NewLife("box", f.hooks())
		l.SetBaseline([]string{"1:1:00"})
		if !l.Activate(&Registry{}, time.Now().Add(time.Hour), 0) {
			t.Fatal("Activate refused")
		}
		if _, err := l.Suspend(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// A fake read-back answers even on a done context; a real one fails, so the
		// call is refused gave_up after the resume either way.
		f.set(func(f *fakeSandbox) { f.readBack = ctx.Err() })
		_, _, err := l.Call(ctx, time.Second)
		if refusalKind(err) != "gave_up" {
			t.Fatalf("refusal %v", err)
		}
		f.mu.Lock()
		resumed += f.resumes
		f.mu.Unlock()
		l.Close()
	}
	t.Logf("a call with a done context resumed the suspended sandbox %d times in 200", resumed)
	if resumed > 0 {
		t.Errorf("a call whose context was already done resumed the sandbox %d times in 200", resumed)
	}
}

// A session that ends while prepare runs (its Resume, here; equally its read-back)
// refuses the call, not dispatched, instead of handing it a run context: the provider
// would otherwise dispatch on an ended session.
func TestASessionThatEndsDuringPrepareRefusesTheCall(t *testing.T) {
	f := &fakeSandbox{}
	gate := make(chan struct{})
	entered := make(chan struct{})
	h := f.hooks()
	h.Resume = func(context.Context) error {
		close(entered)
		<-gate
		return nil
	}
	l := NewLife("box", h)
	if !l.Activate(&Registry{}, time.Now().Add(time.Hour), 0) {
		t.Fatal("Activate refused")
	}
	if _, err := l.Suspend(context.Background()); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		runCtx context.Context
		done   func()
		err    error
	}
	got := make(chan answer, 1)
	go func() {
		runCtx, done, err := l.Call(context.Background(), time.Minute)
		got <- answer{runCtx, done, err}
	}()
	<-entered
	l.Finish(Expired, "")
	close(gate)
	a := <-got
	if a.err != nil {
		if refusalKind(a.err) != "ended" {
			t.Errorf("refused as %q (%v); want ended", refusalKind(a.err), a.err)
		}
		return
	}
	defer a.done()
	t.Errorf("Call returned no error on a session that ended before dispatch (Err %v); the run context is done: %v", l.Err(), a.runCtx.Err())
}

// A call that reaches an abandoned session is refused with the session's end, every
// time: before, the abandoned context could win the turn's select with no end
// recorded, and a provider's refusal of a nil cause reads as success.
func TestACallOnAnAbandonedSessionIsRefused(t *testing.T) {
	l := NewLife("box", (&fakeSandbox{}).hooks())
	l.Abandon()
	for i := 0; i < 50; i++ {
		_, done, err := l.Call(context.Background(), time.Second)
		if err == nil {
			done()
			t.Fatalf("call %d on an abandoned session ran", i)
		}
		var end *EndedError
		if refusalKind(err) != "ended" || !errors.As(err, &end) {
			t.Fatalf("call %d on an abandoned session: %v; want refused with the session's end", i, err)
		}
	}
}
