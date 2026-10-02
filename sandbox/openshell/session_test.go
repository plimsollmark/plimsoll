package openshell

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/sandboxv1"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// freshListing is what the process lister prints in an untouched session sandbox.
const freshListing = `{"ptrace":"1","procs":[{"pid":1,"ppid":0,"state":"S","start":"100","cmd":"/.openshell/runtime/openshell-sandbox","cmdHex":"2f2e6f70656e7368656c6c2f72756e74696d652f6f70656e7368656c6c2d73616e64626f7800"},{"pid":7,"ppid":1,"state":"S","start":"101","cmd":"sleep 2147483647","cmdHex":"736c656570003231343734383336343700"}]}`

// settled waits until the boundary after the last call has finished, as the next
// call would: the boundary runs after a call has answered.
func settled(t *testing.T, s *session) {
	t.Helper()
	select {
	case s.turn <- struct{}{}:
		<-s.turn
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the boundary after the call did not finish")
	}
}

// sessionScript answers a session's execs: the lister gets listing(), the sweep
// exits with sweep(), and anything else is a payload that prints "ok". It records
// every exec's argv[1] ("-e" for the two scripts) in order.
type sessionScript struct {
	mu      sync.Mutex
	listing func() string
	sweep   func() int32
	payload func(e *fakeExec) error
	kinds   []string
	sweeps  [][]string
}

func (s *sessionScript) run(e *fakeExec) error {
	e.readAll()
	cmd := e.start.GetCommand()
	s.mu.Lock()
	switch {
	case len(cmd) >= 3 && cmd[0] == "node" && cmd[1] == "-e" && cmd[2] == sessionkit.ListScript:
		s.kinds = append(s.kinds, "list")
		l := freshListing
		if s.listing != nil {
			l = s.listing()
		}
		s.mu.Unlock()
		if err := e.stdout([]byte(l)); err != nil {
			return err
		}
		return e.exit(0)
	case len(cmd) >= 3 && cmd[0] == "node" && cmd[1] == "-e" && cmd[2] == sessionkit.SweepScript:
		s.kinds = append(s.kinds, "sweep")
		s.sweeps = append(s.sweeps, cmd[3:])
		code := int32(sessionkit.SweepClean)
		if s.sweep != nil {
			code = s.sweep()
		}
		s.mu.Unlock()
		return e.exit(code)
	}
	s.kinds = append(s.kinds, "payload")
	s.mu.Unlock()
	if s.payload != nil {
		return s.payload(e)
	}
	if err := e.stdout([]byte("ok\n")); err != nil {
		return err
	}
	return e.exit(0)
}

func (s *sessionScript) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.kinds...)
}

func openFake(t *testing.T, opts sandbox.SessionOptions) (*fakeGateway, *Provider, *session, *sessionScript) {
	t.Helper()
	f, p := newFake(t)
	sc := &sessionScript{}
	f.run = sc.run
	if opts.Lifetime == 0 {
		opts.Lifetime = time.Minute
	}
	s, err := p.OpenSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return f, p, s.(*session), sc
}

func TestOpenSessionCreatesAVerifiedSleepingSandbox(t *testing.T) {
	f, p, s, sc := openFake(t, sandbox.SessionOptions{Lifetime: 90 * time.Second})
	names := f.live()
	if len(names) != 1 || names[0] != s.b.name {
		t.Fatalf("live sandboxes %v", names)
	}
	sb := f.boxes[s.b.name].sb
	if !slices.Equal(sb.GetSpec().GetCommand(), sessionCommand) {
		t.Fatalf("main process %q", sb.GetSpec().GetCommand())
	}
	labels := sb.GetMetadata().GetLabels()
	if labels[lifetimeLabel] != "90" || labels[sessionLabel] != "1" || labels[instanceLabel] != p.instance || labels[runLabel] != "1" {
		t.Fatalf("labels %v", labels)
	}
	if got := sc.seen(); !slices.Equal(got, []string{"list"}) {
		t.Fatalf("execs at open: %v", got)
	}
	if !slices.Equal(s.baseline, []string{"1:100:2f2e6f70656e7368656c6c2f72756e74696d652f6f70656e7368656c6c2d73616e64626f7800", "7:101:736c656570003231343734383336343700"}) {
		t.Fatalf("baseline %v", s.baseline)
	}
	if !p.isTracked(s.b.name) {
		t.Fatal("an open session's sandbox is not tracked, so the reaper could take it")
	}
	if s.Isolation() != sandbox.IsolationContainer {
		t.Fatalf("tier %v", s.Isolation())
	}
}

func TestOpenSessionRefusesAnUnprovableHost(t *testing.T) {
	for name, listing := range map[string]string{
		"ptrace scope 0":        strings.Replace(freshListing, `"ptrace":"1"`, `"ptrace":"0"`, 1),
		"no Yama":               strings.Replace(freshListing, `"ptrace":"1"`, `"ptrace":""`, 1),
		"an extra process":      strings.Replace(freshListing, `]}`, `,{"pid":9,"ppid":1,"state":"S","start":"102","cmd":"sh"}]}`, 1),
		"the login shell":       strings.Replace(freshListing, "sleep 2147483647", "/bin/sh -l", 1),
		"no main process":       `{"ptrace":"1","procs":[{"pid":1,"ppid":0,"state":"S","start":"100","cmd":"x"}]}`,
		"a listing that is not": `not json`,
	} {
		t.Run(name, func(t *testing.T) {
			f, p := newFake(t)
			sc := &sessionScript{listing: func() string { return listing }}
			f.run = sc.run
			if _, err := p.OpenSession(context.Background(), sandbox.SessionOptions{Lifetime: time.Minute}); err == nil {
				t.Fatal("the session opened")
			}
			waitGone(t, f)
		})
	}
}

// waitGone waits for the provider's background deletes.
func waitGone(t *testing.T, f *fakeGateway) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(f.live()) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("sandboxes left: %v", f.live())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSessionCallVerifiesRunsAndSweeps(t *testing.T) {
	f, _, s, sc := openFake(t, sandbox.SessionOptions{DiskBytes: 5 << 20})
	before := f.called("GetSandboxConfig")
	res, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "console.log('ok')"})
	if err != nil || res.Stdout != "ok\n" || res.Sandbox != Name || res.Isolation != sandbox.IsolationContainer {
		t.Fatalf("call: %+v, %v", res, err)
	}
	settled(t, s)
	if f.called("GetSandboxConfig") != before+1 {
		t.Fatal("the configuration was not read back before the call")
	}
	if got := sc.seen(); !slices.Equal(got, []string{"list", "payload", "sweep"}) {
		t.Fatalf("execs: %v", got)
	}
	// Each kept process is named by PID, start time and command line, so one that lands
	// on a spared PID in the same clock tick is not spared unless it is the same
	// program (external review of v0.10.0, documentation item 5, 2026-09-28).
	if want := []string{"5242880", "200000", "/tmp", "1:100:2f2e6f70656e7368656c6c2f72756e74696d652f6f70656e7368656c6c2d73616e64626f7800", "7:101:736c656570003231343734383336343700"}; !slices.Equal(sc.sweeps[0], want) {
		t.Fatalf("sweep arguments %v, want %v", sc.sweeps[0], want)
	}
	// A project call gets the same verification and sweep.
	pr, err := s.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	settled(t, s)
	if pr.Outcome != sandbox.ProjectOutcomeProtocolError {
		t.Fatalf("the fake runner does not report, so the outcome is a protocol error: %+v", pr)
	}
	if got := sc.seen(); !slices.Equal(got, []string{"list", "payload", "sweep", "payload", "sweep"}) {
		t.Fatalf("execs: %v", got)
	}
}

func TestSessionSweepFailureRestartsTheSandbox(t *testing.T) {
	f, _, s, sc := openFake(t, sandbox.SessionOptions{})
	codes := []int32{1, sessionkit.SweepClean}
	sc.sweep = func() int32 { c := codes[0]; codes = codes[1:]; return c }
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	settled(t, s)
	if f.called("StopSandbox") != 1 || f.called("StartSandbox") != 1 {
		t.Fatalf("stop %d, start %d", f.called("StopSandbox"), f.called("StartSandbox"))
	}
	// The processes were listed again after the start: the main process is new.
	if got := sc.seen(); !slices.Equal(got, []string{"list", "payload", "sweep", "list"}) {
		t.Fatalf("execs: %v", got)
	}
	if s.Err() != nil {
		t.Fatalf("a recovered session ended: %v", s.Err())
	}
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "2"}); err != nil {
		t.Fatalf("the call after a recovery: %v", err)
	}
	settled(t, s)
}

func TestSessionEndsWhenTheRestartFails(t *testing.T) {
	f, p, s, sc := openFake(t, sandbox.SessionOptions{})
	sc.sweep = func() int32 { return 1 }
	// After the stop, the fresh listing shows a process the sandbox should not have.
	sc.listing = func() string {
		return strings.Replace(freshListing, `]}`, `,{"pid":9,"ppid":1,"state":"S","start":"102","cmd":"sleep 99"}]}`, 1)
	}
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatalf("the call's own result must still come back: %v", err)
	}
	settled(t, s)
	if sandbox.SessionEndReason(s.Err()) != sandbox.SessionBoundaryFailed {
		t.Fatalf("session: %v", s.Err())
	}
	waitGone(t, f)
	if p.isTracked(s.b.name) {
		t.Fatal("the ended session's sandbox is still tracked")
	}
	_, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "2"})
	if !errors.Is(err, sandbox.ErrSessionEnded) {
		t.Fatalf("a call after the end: %v", err)
	}
	settled(t, s)
	if r, ok := sandbox.NotDispatchedReason(err); !ok || r != sandbox.RefusalRequest {
		t.Fatalf("not marked as not dispatched: %v", err)
	}
}

func TestSessionEndsOverItsDiskBudget(t *testing.T) {
	f, _, s, sc := openFake(t, sandbox.SessionOptions{DiskBytes: 1 << 20})
	sc.sweep = func() int32 { return sessionkit.SweepOverBudget }
	res, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if err != nil || res.Stdout != "ok\n" {
		t.Fatalf("the call that filled the disk still returns its result: %+v, %v", res, err)
	}
	settled(t, s)
	if sandbox.SessionEndReason(s.Err()) != sandbox.SessionDiskExceeded {
		t.Fatalf("session: %v", s.Err())
	}
	waitGone(t, f)
}

func TestSessionEndsWhenTheMainProcessDies(t *testing.T) {
	f, _, s, sc := openFake(t, sandbox.SessionOptions{})
	sc.payload = func(e *fakeExec) error {
		f.setPhase(s.b.name, openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR)
		return e.exit(0)
	}
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "kill the main process"}); err != nil {
		t.Fatal(err)
	}
	settled(t, s)
	if sandbox.SessionEndReason(s.Err()) != sandbox.SessionMainProcessEnded {
		t.Fatalf("session: %v", s.Err())
	}
	if f.called("StartSandbox") != 0 {
		t.Fatal("a sandbox whose main process ended was restarted, hiding the end")
	}
}

// The gateway can mark the sandbox after the killing call's sweep has found it clean
// (seen live twice); the next call's read-back then ends the session and refuses the
// call before its payload runs.
func TestSessionNoticesALateMainProcessEndAtTheNextCall(t *testing.T) {
	f, _, s, sc := openFake(t, sandbox.SessionOptions{})
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "kill the main process"}); err != nil {
		t.Fatal(err)
	}
	if s.Err() != nil {
		t.Fatalf("ended before the gateway marked the sandbox: %v", s.Err())
	}
	f.setPhase(s.b.name, openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR)
	_, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "the next call"})
	if _, ok := sandbox.NotDispatchedReason(err); !ok || sandbox.SessionEndReason(err) != sandbox.SessionMainProcessEnded {
		t.Fatalf("the next call: %v", err)
	}
	payloads := 0
	for _, k := range sc.seen() {
		if k == "payload" {
			payloads++
		}
	}
	if payloads != 1 {
		t.Fatalf("%d payloads ran, want only the killing call's", payloads)
	}
}

func TestSessionRefusesACallAfterAnOutOfBandChange(t *testing.T) {
	f, _, s, sc := openFake(t, sandbox.SessionOptions{})
	f.mutateConfig = func(c *sandboxv1.GetSandboxConfigResponse) {
		c.Settings[agentProposalsSetting] = &sandboxv1.EffectiveSetting{Value: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_BoolValue{BoolValue: true}}}
	}
	_, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if _, ok := sandbox.NotDispatchedReason(err); !ok || sandbox.SessionEndReason(err) != sandbox.SessionSandboxChanged {
		t.Fatalf("a call after the setting changed: %v", err)
	}
	if slices.Contains(sc.seen(), "payload") {
		t.Fatal("the payload ran on a changed sandbox")
	}
}

func TestSessionSuspendStopsAndTheNextCallStarts(t *testing.T) {
	f, _, s, sc := openFake(t, sandbox.SessionOptions{})
	if _, err := s.Suspend(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.called("StopSandbox") != 1 || !f.boxes[s.b.name].stopped {
		t.Fatal("Suspend did not stop the sandbox")
	}
	if _, err := s.Suspend(context.Background()); err != nil || f.called("StopSandbox") != 1 {
		t.Fatalf("a second Suspend: %v, stops %d", err, f.called("StopSandbox"))
	}
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	settled(t, s)
	if f.called("StartSandbox") != 1 {
		t.Fatal("the call did not start the sandbox")
	}
	if got := sc.seen(); !slices.Equal(got, []string{"list", "list", "payload", "sweep"}) {
		t.Fatalf("execs: %v", got)
	}
}

func TestSessionLifetimeDeletesTheSandbox(t *testing.T) {
	f, _, s, sc := openFake(t, sandbox.SessionOptions{Lifetime: 300 * time.Millisecond})
	hung := make(chan struct{})
	sc.payload = func(e *fakeExec) error { close(hung); return e.hang() }
	done := make(chan error, 1)
	go func() {
		_, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "for(;;){}", Timeout: 20 * time.Second})
		done <- err
	}()
	<-hung
	select {
	case err := <-done:
		if sandbox.SessionEndReason(err) != sandbox.SessionExpired {
			t.Fatalf("a call cut by the lifetime: %v", err)
		}
		if _, marked := sandbox.NotDispatchedReason(err); marked {
			t.Fatal("a call that was running is marked as not dispatched")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lifetime did not stop the call")
	}
	waitGone(t, f)
}

func TestSessionFloorAndInvalidGrantAreRefusedBeforeTheTurn(t *testing.T) {
	_, _, s, sc := openFake(t, sandbox.SessionOptions{})
	_, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM})
	if !errors.Is(err, sandbox.ErrInsufficientIsolation) {
		t.Fatalf("floor: %v", err)
	}
	_, err = s.RunJavaScript(context.Background(), sandbox.Request{Code: "1", Grant: &sandbox.HostAPIGrant{}})
	if !errors.Is(err, sandbox.ErrInvalidRequest) {
		t.Fatalf("an invalid grant: %v", err)
	}
	if got := sc.seen(); !slices.Equal(got, []string{"list"}) {
		t.Fatalf("execs after two refusals: %v", got)
	}
}

func TestDrainEndsOpenSessions(t *testing.T) {
	f, p, s, _ := openFake(t, sandbox.SessionOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if sandbox.SessionEndReason(s.Err()) != sandbox.SessionShutdown {
		t.Fatalf("session after drain: %v", s.Err())
	}
	if len(f.live()) != 0 {
		t.Fatalf("sandboxes left after drain: %v", f.live())
	}
}

func TestCallsInOneSessionAreSerialized(t *testing.T) {
	_, _, s, sc := openFake(t, sandbox.SessionOptions{})
	var mu sync.Mutex
	running, most := 0, 0
	sc.payload = func(e *fakeExec) error {
		mu.Lock()
		running++
		most = max(most, running)
		mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		mu.Lock()
		running--
		mu.Unlock()
		return e.exit(0)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if most != 1 {
		t.Fatalf("%d calls ran at once", most)
	}
	// Every payload was followed by its own sweep before the next payload.
	kinds := sc.seen()[1:]
	for i := 0; i+1 < len(kinds); i += 2 {
		if kinds[i] != "payload" || kinds[i+1] != "sweep" {
			t.Fatalf("execs %v", kinds)
		}
	}
}

// A call that gives up waiting for the turn, held here as the previous call's sweep
// holds it, ran nothing: it is marked so, as the daemon's own busy refusal is.
func TestSessionGivingUpOnTheTurnIsNotDispatched(t *testing.T) {
	_, _, s, _ := openFake(t, sandbox.SessionOptions{})
	s.turn <- struct{}{}
	defer func() { <-s.turn }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := s.RunJavaScript(ctx, sandbox.Request{Code: "1", Timeout: time.Second})
	if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalCapacity || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a call behind a held turn: %v (reason %v, marked %v); want the deadline, not dispatched, capacity", err, reason, ok)
	}
}
