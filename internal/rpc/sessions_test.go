package rpc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

func sessionService() (*SandboxService, *sandboxtest.Sessions) {
	p := &sandboxtest.Sessions{}
	svc := NewSandboxService(p)
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	return svc, p
}

type softwareSessions struct{ *sandboxtest.Sessions }

func (*softwareSessions) Environments() sandbox.Environments {
	e := sandbox.PayloadEnvironment{Identity: "outer:test", SoftwareIdentity: "oci-manifest:linux/amd64@sha256:aaaa"}
	return sandbox.Environments{JavaScript: e, Project: e}
}

func (s *softwareSessions) SessionEnvironments() sandbox.Environments { return s.Environments() }

// Both modes: an approved rule with one identity is merged to exact on every call,
// and must still match the rule the session was opened with.
func TestSessionSoftwareRuleCannotBeDropped(t *testing.T) {
	for _, mode := range []string{"exact", "approved"} {
		t.Run(mode, func(t *testing.T) { testSessionSoftwareRuleCannotBeDropped(t, mode) })
	}
}

func testSessionSoftwareRuleCannotBeDropped(t *testing.T, mode string) {
	svc, p := sessionService()
	svc.Sandbox = &softwareSessions{p}
	described := svc.Sandbox.(sandbox.Describer).Environments()
	p.OpenedEnvironments = &described
	ctx := authenticatedContext("alice")
	id := svc.Sandbox.(sandbox.Describer).Environments().JavaScript.SoftwareIdentity
	wrong := openReq()
	wrong.Msg.SoftwareRule = &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{id + "-other"}}
	_, err := svc.OpenSession(ctx, wrong)
	if !errors.Is(err, sandbox.ErrSoftwareMismatch) || len(p.Opened()) != 0 {
		t.Fatalf("mismatched OpenSession reached the provider: %v", err)
	}
	if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalEnvironment {
		t.Fatalf("mismatched OpenSession has no environment refusal: %v, %v", reason, ok)
	}
	openRequest := openReq()
	openRequest.Msg.SoftwareRule = &plimsollv1.SoftwareRule{Mode: mode, Identities: []string{id}}
	opened, err := svc.OpenSession(ctx, openRequest)
	if err != nil || opened.Msg.GetSoftwareIdentity() != id {
		t.Fatalf("open: %+v, %v", opened, err)
	}
	call := callReq(opened.Msg.GetSessionId(), "1")
	_, err = svc.SessionRun(ctx, call)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("rule omitted from a call: %v", err)
	}
	call.Msg.SoftwareRule = openRequest.Msg.SoftwareRule
	response, err := svc.SessionRun(ctx, call)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Msg.GetRun().GetJavascript().GetStdout()) != "x" || len(p.Opened()) != 1 {
		t.Fatalf("refused call reached provider: %+v", response.Msg)
	}
	rec, err := record.CheckSessionCall(call.Msg, response.Msg.GetRun(), opened.Msg.GetSession(), 0, "")
	if err != nil || rec.SoftwareIdentity != id || rec.SoftwareRuleID != "exact:"+id {
		t.Fatalf("record: %+v, %v", rec, err)
	}
}

func openReq() *connect.Request[plimsollv1.OpenSessionRequest] {
	return connect.NewRequest(&plimsollv1.OpenSessionRequest{Protocol: protocol.Number})
}

func callReq(id, code string) *connect.Request[plimsollv1.SessionRunRequest] {
	return connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: id,
		Payload: &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: code}}})
}

func closeReq(id string) *connect.Request[plimsollv1.CloseSessionRequest] {
	return connect.NewRequest(&plimsollv1.CloseSessionRequest{Protocol: protocol.Number, SessionId: id})
}

// claimSession names the session in a call the daemon refuses before anything runs (it
// has no payload): that claims it, so its first idle timeout suspends it rather than
// closing it as unclaimed, and spends no rate, slot or idle time.
func claimSession(t *testing.T, svc *SandboxService, ctx context.Context, id string) {
	t.Helper()
	_, err := svc.SessionRun(ctx, connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: id}))
	if _, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodeInvalidArgument || !marked {
		t.Fatalf("a call with no payload: %v; want InvalidArgument, not dispatched", err)
	}
}

func TestSessionCallsChainTheirRecords(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	if len(id) != 32 || open.Msg.GetSession() != record.SessionFingerprint(id) || open.Msg.GetIsolation() != "container" {
		t.Fatalf("open: %+v", open.Msg)
	}
	if got := p.Opened()[0].Options; got.Lifetime != time.Minute || got.DiskBytes != 1<<20 {
		t.Fatalf("the provider was asked for %+v", got)
	}
	prev := ""
	for i := uint64(1); i <= 3; i++ {
		req := callReq(id, "console.log(1)")
		resp, err := svc.SessionRun(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := record.CheckSessionCall(req.Msg, resp.Msg.GetRun(), open.Msg.GetSession(), i-1, prev)
		if err != nil || rec == nil {
			t.Fatalf("call %d: %v, %v", i, rec, err)
		}
		prev = rec.SHA256
	}
	closed, err := svc.CloseSession(ctx, closeReq(id))
	if err != nil {
		t.Fatal(err)
	}
	if closed.Msg.GetCalls() != 3 || closed.Msg.GetLastRecordSha256() != prev || closed.Msg.GetEnded() != plimsollv1.SessionEnd_SESSION_END_CLOSED {
		t.Fatalf("close: %+v", closed.Msg)
	}
	if _, err := svc.SessionRun(ctx, callReq(id, "1")); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a call after close: %v", err)
	}
}

func TestSessionBelongsToItsPrincipal(t *testing.T) {
	svc, _ := sessionService()
	open, err := svc.OpenSession(authenticatedContext("alice"), openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	_, foreign := svc.SessionRun(authenticatedContext("bob"), callReq(id, "1"))
	_, unknown := svc.SessionRun(authenticatedContext("bob"), callReq(strings.Repeat("0", 32), "1"))
	if connect.CodeOf(foreign) != connect.CodeNotFound || foreign.Error() != unknown.Error() {
		t.Fatalf("another principal's ID and an unknown ID must be the same miss: %v / %v", foreign, unknown)
	}
	if _, err := svc.CloseSession(authenticatedContext("bob"), closeReq(id)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("another principal closed the session: %v", err)
	}
	if _, err := svc.SessionRun(authenticatedContext("alice"), callReq(id, "1")); err != nil {
		t.Fatalf("the owner's call: %v", err)
	}
}

func TestAnEndedSessionRefusesWithItsReason(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	if _, err := svc.SessionRun(ctx, callReq(id, "1")); err != nil {
		t.Fatal(err)
	}
	p.Opened()[0].End(sandbox.SessionExpired)
	_, err = svc.SessionRun(ctx, callReq(id, "1"))
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeFailedPrecondition {
		t.Fatalf("a call on an expired session: %v", err)
	}
	var sawEnd, sawMark bool
	for _, d := range ce.Details() {
		switch v, _ := d.Value(); v := v.(type) {
		case *plimsollv1.SessionEnded:
			sawEnd = v.GetReason() == plimsollv1.SessionEnd_SESSION_END_EXPIRED
		case *plimsollv1.NotDispatched:
			sawMark = true
		}
	}
	if !sawEnd || !sawMark {
		t.Fatalf("details: end %v, not dispatched %v", sawEnd, sawMark)
	}
	// The owner still collects the chain's end after the session ended by itself.
	closed, err := svc.CloseSession(ctx, closeReq(id))
	if err != nil || closed.Msg.GetCalls() != 1 || closed.Msg.GetEnded() != plimsollv1.SessionEnd_SESSION_END_EXPIRED {
		t.Fatalf("close after expiry: %+v, %v", closed, err)
	}
}

func TestSessionsAreOffUnlessEnabled(t *testing.T) {
	svc, _ := sessionService()
	svc.Sessions.MaxSessions = 0
	_, err := svc.OpenSession(authenticatedContext("alice"), openReq())
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("sessions off: %v", err)
	}
	wantNotDispatched(t, "sessions off", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSUPPORTED)
	d, _ := svc.Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{}))
	if d.Msg.GetSupportsSessions() || d.Msg.GetSessionLifetimeMs() != 0 {
		t.Fatalf("describe with sessions off: %+v", d.Msg)
	}
	svc.Sessions.MaxSessions = 4
	d, _ = svc.Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{}))
	if !d.Msg.GetSupportsSessions() || d.Msg.GetSessionLifetimeMs() != 60000 || d.Msg.GetSessionIdleTimeoutMs() != 60000 {
		t.Fatalf("describe with sessions on: %+v", d.Msg)
	}
	// A provider without sessions has none, whatever the operator set.
	plain := NewSandboxService(&fakeSandbox{})
	plain.Sessions = svc.Sessions
	if _, err := plain.OpenSession(authenticatedContext("alice"), openReq()); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("a provider without sessions: %v", err)
	}
}

func TestSessionRequestsStateTheProtocol(t *testing.T) {
	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	for _, n := range []uint32{0, protocol.Number + 1} {
		want := connect.CodeUnimplemented
		if n == 0 {
			want = connect.CodeInvalidArgument
		}
		o := openReq()
		o.Msg.Protocol = n
		if _, err := svc.OpenSession(ctx, o); connect.CodeOf(err) != want {
			t.Errorf("open on protocol %d: %v", n, err)
		}
		c := callReq(strings.Repeat("0", 32), "1")
		c.Msg.Protocol = n
		if _, err := svc.SessionRun(ctx, c); connect.CodeOf(err) != want {
			t.Errorf("call on protocol %d: %v", n, err)
		}
		cl := closeReq(strings.Repeat("0", 32))
		cl.Msg.Protocol = n
		if _, err := svc.CloseSession(ctx, cl); connect.CodeOf(err) != want {
			t.Errorf("close on protocol %d: %v", n, err)
		}
	}
}

// A session holds a concurrency slot while its sandbox runs, gives it back when idle
// suspends it, and takes one again for the next call.
func TestSessionSlotsFollowSuspend(t *testing.T) {
	svc, p := sessionService()
	svc.Limiter = NewCodeLimiter(1, 0, 0, 0)
	svc.Sessions.IdleTimeout = 50 * time.Millisecond
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	claimSession(t, svc, ctx, open.Msg.GetSessionId())
	if _, err := svc.Run(ctx, jsReq("1")); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a run while the session holds the only slot: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for svc.Limiter.Stats().InFlight != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the idle session never gave its slot back")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if p.Opened()[0].Suspends() == 0 {
		t.Fatal("the slot came back without a suspend")
	}
	if _, err := svc.SessionRun(ctx, callReq(open.Msg.GetSessionId(), "1")); err != nil {
		t.Fatalf("the call after a suspend: %v", err)
	}
	if svc.Limiter.Stats().InFlight != 1 {
		t.Fatal("the resumed session holds no slot")
	}
}

// A session whose suspended sandbox still holds its memory (a paused container)
// keeps its slot through the suspend: the slot is its share of the memory budget.
func TestPausedSessionKeepsItsSlot(t *testing.T) {
	svc, p := sessionService()
	p.SuspendHoldsMemory = true
	svc.Limiter = NewCodeLimiter(1, 0, 0, 0)
	svc.Sessions.IdleTimeout = 50 * time.Millisecond
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	claimSession(t, svc, ctx, open.Msg.GetSessionId())
	deadline := time.Now().Add(3 * time.Second)
	for p.Opened()[0].Suspends() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the idle session was never suspended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := svc.Limiter.Stats().InFlight; got != 1 {
		t.Fatalf("a paused session holds %d slots, want 1", got)
	}
	if _, err := svc.Run(ctx, jsReq("1")); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a run while a paused session holds the only slot: %v", err)
	}
	if _, err := svc.SessionRun(ctx, callReq(open.Msg.GetSessionId(), "1")); err != nil {
		t.Fatalf("the call after a pause: %v", err)
	}
	if got := svc.Limiter.Stats().InFlight; got != 1 {
		t.Fatalf("the resumed session holds %d slots, want 1", got)
	}
}

func TestSessionCountIsBounded(t *testing.T) {
	svc, _ := sessionService()
	svc.Sessions.MaxSessions = 1
	ctx := authenticatedContext("alice")
	if _, err := svc.OpenSession(ctx, openReq()); err != nil {
		t.Fatal(err)
	}
	_, err := svc.OpenSession(ctx, openReq())
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a second session over the bound: %v", err)
	}
	wantNotDispatched(t, "over the bound", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY)
}

// The bound holds for opens that arrive together: a second open while the first is
// still creating its sandbox is refused before it reaches the provider, and an open
// that fails gives its place back.
func TestSessionCapHoldsForSimultaneousOpens(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.MaxSessions = 1
	entered := make(chan struct{}, 2)
	proceed := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(proceed) }) })
	p.BeforeOpen = func() error {
		entered <- struct{}{}
		<-proceed
		return nil
	}
	ctx := authenticatedContext("alice")
	first := make(chan error, 1)
	go func() { _, err := svc.OpenSession(ctx, openReq()); first <- err }()
	<-entered
	second := make(chan error, 1)
	go func() { _, err := svc.OpenSession(ctx, openReq()); second <- err }()
	select {
	case err := <-second:
		if connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("a second open during the first: %v", err)
		}
		wantNotDispatched(t, "a second open during the first", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY)
	case <-entered:
		t.Fatal("a second open reached the provider while the first was opening, past a bound of one")
	case <-time.After(10 * time.Second):
		t.Fatal("the second open did not return")
	}
	once.Do(func() { close(proceed) })
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if n := len(p.Opened()); n != 1 {
		t.Fatalf("%d sessions opened, the bound is 1", n)
	}

	failing, fp := sessionService()
	failing.Sessions.MaxSessions = 1
	fp.BeforeOpen = func() error { return errors.New("the gateway is down") }
	if _, err := failing.OpenSession(ctx, openReq()); err == nil {
		t.Fatal("a failing provider opened a session")
	}
	fp.BeforeOpen = nil
	if _, err := failing.OpenSession(ctx, openReq()); err != nil {
		t.Fatalf("a failed open kept its place: %v", err)
	}
}

// A caller that gives up while its sandbox opens never gets the session's ID, so
// the session is closed at once and its place given back, not held until it expires.
func TestSessionOpenedAfterTheCallerGaveUpIsClosed(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.MaxSessions = 1
	ctx, cancel := context.WithCancel(authenticatedContext("alice"))
	p.BeforeOpen = func() error { cancel(); return nil }
	_, err := svc.OpenSession(ctx, openReq())
	if err == nil {
		t.Fatal("an open whose caller gave up answered with a session")
	}
	opened := p.Opened()
	if len(opened) != 1 || opened[0].Err() == nil {
		t.Fatalf("the abandoned session is still open (%d opened)", len(opened))
	}
	p.BeforeOpen = nil
	if _, err := svc.OpenSession(authenticatedContext("alice"), openReq()); err != nil {
		t.Fatalf("the abandoned session kept its place: %v", err)
	}
}

func TestSessionAuditLinesCarryTheFingerprintNeverTheID(t *testing.T) {
	svc, _ := sessionService()
	var buf bytes.Buffer
	svc.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	if _, err := svc.SessionRun(ctx, callReq(id, "1")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CloseSession(ctx, closeReq(id)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, id) {
		t.Fatalf("the session ID reached the log:\n%s", out)
	}
	for _, want := range []string{`"msg":"session opened"`, `"msg":"code run"`, `"session_call":1`, `"msg":"session closed"`, `"session":"` + open.Msg.GetSession() + `"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %s:\n%s", want, out)
		}
	}
}

func TestSessionCallFloorIsCheckedAgainstTheSessionsTier(t *testing.T) {
	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	req := callReq(open.Msg.GetSessionId(), "1")
	req.Msg.MinimumIsolation = "vm"
	_, err = svc.SessionRun(ctx, req)
	wantNotDispatched(t, "a floor above the session's tier", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION)
	empty := callReq(open.Msg.GetSessionId(), "")
	empty.Msg.Payload = nil
	if _, err := svc.SessionRun(ctx, empty); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no payload: %v", err)
	}
}

// With no auth configured every caller is the same principal ("anon"), so a session's
// ID is the only thing that keeps it apart: exactly the dev mode the daemon already
// warns about, and the reason docs/sessions.md says so rather than implying that
// ownership protects a session there.
func TestWithoutAuthEveryCallerOwnsEverySession(t *testing.T) {
	svc, _ := sessionService()
	open, err := svc.OpenSession(context.Background(), openReq())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SessionRun(context.Background(), callReq(open.Msg.GetSessionId(), "1")); err != nil {
		t.Fatalf("an unauthenticated caller and its own session: %v", err)
	}
	// An authenticated principal is still separate from the anonymous one.
	if _, err := svc.SessionRun(authenticatedContext("alice"), callReq(open.Msg.GetSessionId(), "1")); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a named principal reached the anonymous session: %v", err)
	}
}

// Every session call gets the daemon's own five-minute ceiling, like a run: a call
// asking for longer is cut to it, so a session cannot hold a slot indefinitely.
func TestSessionCallsGetTheDaemonCeiling(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	req := callReq(open.Msg.GetSessionId(), "1")
	req.Msg.TimeoutMs = int32((24 * time.Hour).Milliseconds())
	if _, err := svc.SessionRun(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got := p.Opened()[0].LastTimeout(); got != maxRunTimeout {
		t.Fatalf("the call's timeout was %v, want the daemon's ceiling %v", got, maxRunTimeout)
	}
}

// TestARateRefusedCallGivesBackTheSlotItTook: a call on a suspended session takes a
// slot, then is refused by the caller's rate; the session was not resumed, so the
// slot must come back at once rather than at the next idle suspend (external review
// of v0.10.0, finding 3, 2026-09-28).
func TestARateRefusedCallGivesBackTheSlotItTook(t *testing.T) {
	svc, p := sessionService()
	svc.Limiter = NewCodeLimiter(1, 0, 1, 1) // the open spends the only run this minute
	svc.Sessions.IdleTimeout = 50 * time.Millisecond
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	claimSession(t, svc, ctx, open.Msg.GetSessionId())
	deadline := time.Now().Add(3 * time.Second)
	for p.Opened()[0].Suspends() == 0 || svc.Limiter.Stats().InFlight != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the idle session was never suspended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := svc.SessionRun(ctx, callReq(open.Msg.GetSessionId(), "1")); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a call past the caller's rate: %v", err)
	}
	if n := svc.Limiter.Stats().InFlight; n != 0 {
		t.Fatalf("the refused call left %d slot(s) held", n)
	}
}

// slowCloseProvider opens sessions whose Close returns at once but whose end comes
// only when the test ends them, a timing the session contract allows.
type slowCloseProvider struct{ *sandboxtest.Sessions }

type slowCloseSession struct{ *sandboxtest.FakeSession }

func (slowCloseSession) Close(context.Context) error { return nil }

func (p slowCloseProvider) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return slowCloseSession{s.(*sandboxtest.FakeSession)}, nil
}

// TestCloseSessionHonoursItsContext: CloseSession's wait for the session to end is
// bounded by the caller's context, and a later close collects the session once it
// has ended (external review of v0.10.0, finding 11, 2026-09-28).
func TestCloseSessionHonoursItsContext(t *testing.T) {
	p := slowCloseProvider{&sandboxtest.Sessions{}}
	svc := NewSandboxService(p)
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	fake := p.Opened()[0]
	t.Cleanup(func() { fake.End(sandbox.SessionClosed) })
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := svc.CloseSession(short, closeReq(open.Msg.GetSessionId()))
		done <- err
	}()
	select {
	case err := <-done:
		if connect.CodeOf(err) != connect.CodeDeadlineExceeded {
			t.Fatalf("CloseSession past its deadline: %v", err)
		}
		if _, marked := sandbox.NotDispatchedReason(err); marked {
			t.Fatal("a close that has begun was marked not dispatched")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CloseSession ignored its context while the session was still ending")
	}
	fake.End(sandbox.SessionClosed)
	closed, err := svc.CloseSession(ctx, closeReq(open.Msg.GetSessionId()))
	if err != nil || closed.Msg.GetSession() == "" {
		t.Fatalf("closing again once the session ended: %v", err)
	}
}

// A cell runs in the session's interpreter and comes back as a cell result with a
// record; on Run it is refused before dispatch, since a cell has no Run of its own.
func TestCellRunsOnlyInASession(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	cell := &plimsollv1.CellRun{Language: "python", Code: "1 + 1", Files: []*plimsollv1.ProjectFile{{Path: "a.txt", Content: "a"}}}
	_, err := svc.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, Payload: &plimsollv1.RunRequest_Cell{Cell: cell}}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("Run with a cell: %v", err)
	}
	wantNotDispatched(t, "Run with a cell", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST)
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.SessionRun(ctx, connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number,
		SessionId: open.Msg.GetSessionId(), Payload: &plimsollv1.SessionRunRequest_Cell{Cell: cell}}))
	if err != nil {
		t.Fatal(err)
	}
	got := resp.Msg.GetRun().GetCell()
	if string(got.GetStdout()) != "python 1: 1 + 1" || string(got.GetStderr()) != "a.txt\n" || !got.GetInterpreterStarted() {
		t.Fatalf("cell result: %+v", got)
	}
	if resp.Msg.GetRun().GetRecord().GetSequence() != 1 || len(p.Opened()) != 1 {
		t.Fatalf("record: %+v", resp.Msg.GetRun().GetRecord())
	}
	bad := &plimsollv1.CellRun{Language: "cobol", Code: "1"}
	_, err = svc.SessionRun(ctx, connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number,
		SessionId: open.Msg.GetSessionId(), Payload: &plimsollv1.SessionRunRequest_Cell{Cell: bad}}))
	wantNotDispatched(t, "an unknown language", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST)
}

// A call re-arms the idle timer before it gives the session's turn back, so a short
// idle timeout can fire while the turn is still held. That suspend must try again,
// or the session holds its slot until its next call.
func TestIdleSuspendFindingTheTurnBusyTriesAgain(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.IdleTimeout = time.Hour // nothing fires by itself
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	claimSession(t, svc, ctx, open.Msg.GetSessionId())
	e, ok := svc.sessions.get(open.Msg.GetSessionId(), auditCaller(ctx))
	if !ok {
		t.Fatal("the session is not registered")
	}
	e.mu.Lock()
	e.idleTimeout = 20 * time.Millisecond
	e.mu.Unlock()
	e.mu.Lock()
	gen := e.idleGen // the current timer's
	e.mu.Unlock()
	e.turn <- struct{}{} // a call holds the turn
	svc.suspend(e, gen)  // the idle timer fires now
	<-e.turn             // the call gives the turn back
	deadline := time.Now().Add(3 * time.Second)
	for p.Opened()[0].Suspends() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("an idle suspend that found the turn busy never tried again")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An idle timer that fired, then waited while a call took the turn, ran and armed a
// fresh timer, does nothing: the session was just used (round-3 review: a stale
// callback suspended it at once, which on e2b ends the interpreters a cell just used).
func TestStaleIdleTimerDoesNotSuspend(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.IdleTimeout = time.Hour // nothing fires by itself
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, ok := svc.sessions.get(open.Msg.GetSessionId(), auditCaller(ctx))
	if !ok {
		t.Fatal("the session is not registered")
	}
	e.mu.Lock()
	stale := e.idleGen // the timer that fires, before the call below
	e.mu.Unlock()
	if _, err := svc.SessionRun(ctx, callReq(open.Msg.GetSessionId(), "1")); err != nil {
		t.Fatal(err)
	}
	svc.suspend(e, stale) // its callback runs only now
	if n := p.Opened()[0].Suspends(); n != 0 {
		t.Fatalf("a stale idle callback suspended a session used since: %d suspends", n)
	}
	e.mu.Lock()
	current := e.idleGen
	e.mu.Unlock()
	svc.suspend(e, current) // the current timer still suspends
	if n := p.Opened()[0].Suspends(); n != 1 {
		t.Fatalf("the current idle timer: %d suspends, want 1", n)
	}
}

// hangingCloseSessions opens sessions that its caller has given up on by the time
// they open, and whose Close hangs until its context ends, reporting whether that
// context had a deadline.
type hangingCloseSessions struct {
	*sandboxtest.Sessions
	cancelCaller context.CancelFunc
	closed       chan bool
}

func (p *hangingCloseSessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	p.cancelCaller()
	return &hangingClose{Session: s, closed: p.closed}, nil
}

type hangingClose struct {
	sandbox.Session
	closed chan bool
}

func (s *hangingClose) Close(ctx context.Context) error {
	_, bounded := ctx.Deadline()
	<-ctx.Done()
	s.closed <- bounded
	return ctx.Err()
}

// A session that finishes opening after its caller gave up is closed, and a close
// that hangs must not hold the handler (and its slot and place) without end.
func TestOrphanSessionCloseIsBounded(t *testing.T) {
	old := sessionOrphanCloseBudget
	sessionOrphanCloseBudget = 50 * time.Millisecond
	t.Cleanup(func() { sessionOrphanCloseBudget = old })
	ctx, cancel := context.WithCancel(authenticatedContext("alice"))
	defer cancel()
	p := &hangingCloseSessions{Sessions: &sandboxtest.Sessions{}, cancelCaller: cancel, closed: make(chan bool, 1)}
	svc := NewSandboxService(p)
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	done := make(chan error, 1)
	go func() {
		_, err := svc.OpenSession(ctx, openReq())
		done <- err
	}()
	select {
	case err := <-done:
		if _, marked := sandbox.NotDispatchedReason(err); !marked {
			t.Fatalf("the open its caller gave up on: %v; want a marked refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a hanging close held the open's handler")
	}
	if bounded := <-p.closed; !bounded {
		t.Fatal("the close had no deadline")
	}
}

// One caller holds at most MaxPerCaller sessions, suspended ones included, so a
// caller with a short idle timeout cannot take every place; another caller still
// gets one, and a close gives the place back.
func TestSessionsPerCallerCap(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.MaxPerCaller = 2
	svc.Sessions.IdleTimeout = 20 * time.Millisecond
	alice, bob := authenticatedContext("alice"), authenticatedContext("bob")
	var ids []string
	for i := 0; i < 2; i++ {
		o, err := svc.OpenSession(alice, openReq())
		if err != nil {
			t.Fatal(err)
		}
		claimSession(t, svc, alice, o.Msg.GetSessionId())
		ids = append(ids, o.Msg.GetSessionId())
	}
	deadline := time.Now().Add(3 * time.Second)
	for p.Opened()[0].Suspends() == 0 || p.Opened()[1].Suspends() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the sessions never suspended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, err := svc.OpenSession(alice, openReq())
	if reason, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodeResourceExhausted || !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY {
		t.Fatalf("a third session for one caller: %v; want ResourceExhausted, marked capacity", err)
	}
	if _, err := svc.OpenSession(bob, openReq()); err != nil {
		t.Fatalf("another caller's first session: %v", err)
	}
	if _, err := svc.CloseSession(alice, connect.NewRequest(&plimsollv1.CloseSessionRequest{Protocol: protocol.Number, SessionId: ids[0]})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.OpenSession(alice, openReq()); err != nil {
		t.Fatalf("a session after closing one: %v", err)
	}
}

// failingSessions opens fake sessions whose failCall-th snippet call runs (the fake
// counts it) and then returns an unmarked error, as an exec stream that broke after
// the code ran does.
type failingSessions struct {
	*sandboxtest.Sessions
	failCall int
}

func (p *failingSessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &failingSession{Session: s, failCall: p.failCall}, nil
}

type failingSession struct {
	sandbox.Session
	failCall, n int
}

func (s *failingSession) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	res, err := s.Session.RunJavaScript(ctx, req)
	if s.n++; s.n == s.failCall {
		return res, errors.New("the exec stream broke after the code ran")
	}
	return res, err
}

// A session call that may have run but ended in an error gets a record in the
// chain, carried on the error: the next call chains after it, and the close counts
// it, so a verified chain cannot hide a call that ran.
func TestUnansweredSessionCallIsInTheChain(t *testing.T) {
	inner := &sandboxtest.Sessions{}
	svc := NewSandboxService(&failingSessions{Sessions: inner, failCall: 2})
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	fp := record.SessionFingerprint(id)
	first, err := svc.SessionRun(ctx, callReq(id, "1"))
	if err != nil {
		t.Fatal(err)
	}
	r1 := first.Msg.GetRun().GetRecord()
	second := callReq(id, "2")
	_, err = svc.SessionRun(ctx, second)
	if _, marked := sandbox.NotDispatchedReason(err); err == nil || marked {
		t.Fatalf("the call that broke after running: %v; want an unmarked error", err)
	}
	var unanswered *plimsollv1.RunRecord
	var ce *connect.Error
	if errors.As(err, &ce) {
		for _, d := range ce.Details() {
			if v, derr := d.Value(); derr == nil {
				if u, ok := v.(*plimsollv1.UnansweredCall); ok {
					unanswered = u.GetRecord()
				}
			}
		}
	}
	r2, cerr := record.CheckUnanswered(second.Msg, unanswered, fp, 1, r1.GetRecordSha256())
	if cerr != nil {
		t.Fatalf("the unanswered call's record: %v", cerr)
	}
	third, err := svc.SessionRun(ctx, callReq(id, "3"))
	if err != nil {
		t.Fatal(err)
	}
	if r3 := third.Msg.GetRun().GetRecord(); r3.GetSequence() != 3 || r3.GetPreviousSha256() != r2.SHA256 {
		t.Fatalf("the call after: sequence %d after %q; want 3 after the unanswered record", r3.GetSequence(), r3.GetPreviousSha256())
	}
	sum, err := svc.CloseSession(ctx, closeReq(id))
	if err != nil {
		t.Fatal(err)
	}
	if ran := inner.Opened()[0].Calls(); sum.Msg.GetCalls() != uint64(ran) {
		t.Fatalf("the close counts %d calls, the session ran %d", sum.Msg.GetCalls(), ran)
	}
}

// A session holds one call waiting for its turn; any more are refused at once, not
// dispatched, instead of parking requests on the session (v0.15.0 review, M4).
func TestOnlyOneCallWaitsForASessionsTurn(t *testing.T) {
	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	e, _ := svc.sessions.get(id, auditCaller(ctx))
	e.turn <- struct{}{} // a long call holds the turn
	waitCtx, cancel := context.WithCancel(ctx)
	waited := make(chan error, 1)
	go func() { _, err := svc.SessionRun(waitCtx, callReq(id, "1")); waited <- err }()
	deadline := time.Now().Add(3 * time.Second)
	for len(e.waiting) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first waiter never queued")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, err = svc.SessionRun(ctx, callReq(id, "2"))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a second waiter: %v; want ResourceExhausted", err)
	}
	wantNotDispatched(t, "a second waiter", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY)
	if _, err := svc.CloseSession(ctx, closeReq(id)); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a close behind a waiter: %v; want ResourceExhausted", err)
	}
	cancel()
	<-waited
	<-e.turn
	if _, err := svc.SessionRun(ctx, callReq(id, "3")); err != nil {
		t.Fatalf("a call once the turn is free: %v", err)
	}
}

// A caller may not ask for an idle timeout below a second: an idle suspend that finds
// a call running tries again one idle timeout later (v0.15.0 review, L2).
func TestRequestedIdleTimeoutHasAFloor(t *testing.T) {
	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, connect.NewRequest(&plimsollv1.OpenSessionRequest{Protocol: protocol.Number, IdleTimeoutMs: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if got := open.Msg.GetIdleTimeoutMs(); got != 1000 {
		t.Fatalf("idle timeout %d ms, want the 1000 ms floor", got)
	}
}

// Describe states where a session runs, from the provider's SessionEnvironments, and
// nothing when sessions are off (v0.15.0 review, L19).
func TestDescribeStatesTheSessionEnvironment(t *testing.T) {
	svc, p := sessionService()
	svc.Sandbox = &softwareSessions{p}
	d, err := svc.Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Msg.GetSessionEnvironment(); got.GetIdentity() != "outer:test" || got.GetSoftwareIdentity() != "oci-manifest:linux/amd64@sha256:aaaa" {
		t.Fatalf("session environment %+v", got)
	}
	svc.Sessions.MaxSessions = 0
	if d, _ := svc.Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{})); d.Msg.GetSessionEnvironment() != nil {
		t.Fatalf("sessions off, but Describe states a session environment: %+v", d.Msg.GetSessionEnvironment())
	}
}

type panickingSessions struct{ *sandboxtest.Sessions }

func (p *panickingSessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &panickingSession{Session: s}, nil
}

type panickingSession struct{ sandbox.Session }

func (s *panickingSession) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	if _, err := s.Session.RunJavaScript(ctx, req); err != nil {
		return sandbox.Result{}, err
	}
	panic("the provider broke after the code ran")
}

// A provider that panics during a session call may have run it: the call is chained
// as unanswered, so the next call follows it and the close counts it, and the turn is
// free again (v0.15.0 review, L4).
func TestAPanickingSessionCallIsInTheChain(t *testing.T) {
	svc := NewSandboxService(&panickingSessions{Sessions: &sandboxtest.Sessions{}})
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	svc.Logger = slog.New(slog.DiscardHandler)
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	_, err = svc.SessionRun(ctx, callReq(id, "1"))
	var ce *connect.Error
	found := false
	if errors.As(err, &ce) {
		for _, d := range ce.Details() {
			if v, derr := d.Value(); derr == nil {
				if _, ok := v.(*plimsollv1.UnansweredCall); ok {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("a panicking call: %v; want an error carrying its unanswered record", err)
	}
	sum, err := svc.CloseSession(ctx, closeReq(id))
	if err != nil || sum.Msg.GetCalls() != 1 {
		t.Fatalf("close: %+v, %v; want the panicked call counted", sum, err)
	}
}

type languageSessions struct {
	*sandboxtest.Sessions
	stated []sandbox.Language
}

func (s *languageSessions) SessionEnvironments() sandbox.Environments {
	return sandbox.Environments{Project: sandbox.PayloadEnvironment{Languages: s.stated}}
}

// A language hint reaches the provider in the environment's order without repeats,
// less any language the environment does not run, and a hint naming a language
// plimsoll does not know is refused before the provider is asked.
func TestSessionLanguageHint(t *testing.T) {
	svc, p := sessionService()
	lp := &languageSessions{Sessions: p, stated: []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython}}
	svc.Sandbox = lp
	ctx := authenticatedContext("alice")
	for i, c := range []struct {
		stated []sandbox.Language
		want   []sandbox.Language
	}{
		{lp.stated, lp.stated},
		{[]sandbox.Language{sandbox.LanguageJavaScript}, []sandbox.Language{sandbox.LanguageJavaScript}},
	} {
		lp.stated = c.stated
		req := openReq()
		req.Msg.Languages = []string{"python", "javascript", "python"}
		if _, err := svc.OpenSession(ctx, req); err != nil {
			t.Fatal(err)
		}
		if got := p.Opened()[i].Options.Languages; !slices.Equal(got, c.want) {
			t.Fatalf("stating %v, the provider was asked for languages %v; want %v", c.stated, got, c.want)
		}
	}
	req := openReq()
	req.Msg.Languages = []string{"cobol"}
	_, err := svc.OpenSession(ctx, req)
	if reason, ok := sandbox.NotDispatchedReason(err); connect.CodeOf(err) != connect.CodeInvalidArgument || !ok || reason != sandbox.RefusalRequest {
		t.Fatalf("an unknown language: %v (reason %v, %v); want InvalidArgument, request", err, reason, ok)
	}
	if len(p.Opened()) != 2 {
		t.Fatal("a hint naming an unknown language reached the provider")
	}
}

// A call that ends its session says so in its own answer, though the sandbox's delete
// is still running, and the session keeps its concurrency slot until the delete is
// through (Done), not merely until it ended (review F9).
func TestEndedSessionKeepsItsSlotUntilItsSandboxIsGone(t *testing.T) {
	svc, p := sessionService()
	p.HoldDeletes = true
	svc.Limiter = NewCodeLimiter(1, 0, 0, 0)
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.SessionRun(ctx, connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number,
		SessionId: open.Msg.GetSessionId(), Payload: &plimsollv1.SessionRunRequest_Cell{
			Cell: &plimsollv1.CellRun{Language: "python", Code: sandboxtest.CellEndsSession}}}))
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Msg.GetEnded(); got != plimsollv1.SessionEnd_SESSION_END_DISK_EXCEEDED {
		t.Fatalf("the call that ended the session answers ended = %v", got)
	}
	if _, err := svc.Run(ctx, jsReq("1")); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a run while the ended session's sandbox is still being deleted: %v", err)
	}
	p.Opened()[0].FinishDelete()
	deadline := time.Now().Add(3 * time.Second)
	for svc.Limiter.Stats().InFlight != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the slot was not given back once the sandbox was gone")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Admitted: the fake keeps no one-shot runs, so it refuses the run past admission.
	if _, err := svc.Run(ctx, jsReq("1")); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("a run once the sandbox is gone: %v", err)
	}
}

// The software rule is checked again against what the opened session runs (review
// F10): a provider that refreshed its image during the open would otherwise be bound
// to a session stating the earlier image. The refusal is not dispatched, the session
// is closed, and an accepted open states the opened session's identity.
func TestSessionSoftwareRuleIsCheckedAgainstTheOpenedSession(t *testing.T) {
	svc, p := sessionService()
	svc.Sandbox = &softwareSessions{p}
	stated := svc.Sandbox.(sandbox.Describer).Environments()
	rebuilt := stated
	rebuilt.JavaScript.SoftwareIdentity = "oci-manifest:linux/amd64@sha256:bbbb"
	rebuilt.Project.SoftwareIdentity = rebuilt.JavaScript.SoftwareIdentity
	p.OpenedEnvironments = &rebuilt
	ctx := authenticatedContext("alice")
	req := openReq()
	req.Msg.SoftwareRule = &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{stated.JavaScript.SoftwareIdentity}}
	_, err := svc.OpenSession(ctx, req)
	if !errors.Is(err, sandbox.ErrSoftwareMismatch) {
		t.Fatalf("an open whose session runs another image: %v", err)
	}
	if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalEnvironment {
		t.Fatalf("the refusal is not marked not dispatched, environment: %v, %v", reason, ok)
	}
	if opened := p.Opened(); len(opened) != 1 || opened[0].Err() == nil {
		t.Fatal("the refused session was not closed")
	}
	req = openReq()
	req.Msg.SoftwareRule = &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{rebuilt.JavaScript.SoftwareIdentity}}
	_, err = svc.OpenSession(ctx, req)
	if !errors.Is(err, sandbox.ErrSoftwareMismatch) {
		t.Fatalf("a rule naming the opened image is refused before the open, by what the provider states: %v", err)
	}
	resp, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Msg.GetSoftwareIdentity(); got != rebuilt.JavaScript.SoftwareIdentity {
		t.Fatalf("the open states %q; want the opened session's %q", got, rebuilt.JavaScript.SoftwareIdentity)
	}
}

// An idle suspend that fails without ending the session (it gave up waiting for a turn
// the session's recovery held) is tried again after another idle period: otherwise an
// abandoned session would keep its concurrency slot for its whole lifetime.
func TestAFailedIdleSuspendIsTriedAgain(t *testing.T) {
	svc, p := sessionService()
	p.FailedSuspends = 1
	svc.Limiter = NewCodeLimiter(1, 0, 0, 0)
	svc.Sessions.IdleTimeout = 50 * time.Millisecond
	open, err := svc.OpenSession(authenticatedContext("alice"), openReq())
	if err != nil {
		t.Fatal(err)
	}
	claimSession(t, svc, authenticatedContext("alice"), open.Msg.GetSessionId())
	deadline := time.Now().Add(3 * time.Second)
	for svc.Limiter.Stats().InFlight != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("after a failed suspend the idle session never gave its slot back (%d suspends)", p.Opened()[0].Suspends())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := p.Opened()[0].Suspends(); n < 2 {
		t.Fatalf("%d suspends; want the failed one and another", n)
	}
}

// A provider that panics while opening a session gives back the session's place and
// its concurrency slot, as a failed open does: before, the panic unwound past both, and
// they stayed taken until a restart.
func TestAPanickingOpenGivesItsPlaceBack(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.MaxSessions = 1
	svc.Limiter = NewCodeLimiter(1, 0, 0, 0)
	svc.Logger = slog.New(slog.DiscardHandler)
	p.BeforeOpen = func() error { panic("the provider broke while opening") }
	ctx := authenticatedContext("alice")
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("OpenSession let the provider's panic through: %v", r)
			}
		}()
		if _, err := svc.OpenSession(ctx, openReq()); err == nil {
			t.Error("a panicking open succeeded")
		}
	}()
	p.BeforeOpen = nil
	if _, err := svc.OpenSession(ctx, openReq()); err != nil {
		t.Fatalf("the open after a panicking one: %v; the place or the slot was not given back", err)
	}
}

func ownerOpen(owner string) *connect.Request[plimsollv1.OpenSessionRequest] {
	r := openReq()
	r.Msg.Owner = owner
	return r
}

// endedAs reads the SessionEnded detail of a refused session call.
func endedAs(err error) (plimsollv1.SessionEnd, bool) {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return 0, false
	}
	for _, d := range ce.Details() {
		if v, derr := d.Value(); derr == nil {
			if se, ok := v.(*plimsollv1.SessionEnded); ok {
				return se.GetReason(), true
			}
		}
	}
	return 0, false
}

// An owner at its cap gets a new session by the daemon closing that owner's least
// recently used one, whose later calls are refused, not dispatched, as replaced. The
// cap counts one owner of one caller: another owner, and the same owner name under
// another caller, are untouched.
func TestSessionsPerOwnerCapReplacesTheLeastRecentlyUsed(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.MaxSessions = 8
	svc.Sessions.MaxPerOwner = 2
	alice, bob := authenticatedContext("alice"), authenticatedContext("bob")
	open := func(ctx context.Context, owner string) string {
		t.Helper()
		o, err := svc.OpenSession(ctx, ownerOpen(owner))
		if err != nil {
			t.Fatal(err)
		}
		return o.Msg.GetSessionId()
	}
	first, second := open(alice, "u1"), open(alice, "u1")
	other, bobs := open(alice, "u2"), open(bob, "u1")
	// first is used after second opened, so second is the least recently used.
	if _, err := svc.SessionRun(alice, callReq(first, "1")); err != nil {
		t.Fatal(err)
	}
	third := open(alice, "u1")
	if p.Opened()[1].Err() == nil {
		t.Fatal("the least recently used session of the owner was not closed")
	}
	for i, s := range p.Opened() {
		if i != 1 && s.Err() != nil {
			t.Fatalf("session %d ended: %v", i, s.Err())
		}
	}
	_, err := svc.SessionRun(alice, callReq(second, "2"))
	if reason, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodeFailedPrecondition || !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST {
		t.Fatalf("a call on the replaced session: %v; want FailedPrecondition, marked request", err)
	}
	if end, ok := endedAs(err); !ok || end != plimsollv1.SessionEnd_SESSION_END_REPLACED {
		t.Fatalf("the replaced session's end: %v %v; want REPLACED", end, ok)
	}
	c, err := svc.CloseSession(alice, closeReq(second))
	if err != nil || c.Msg.GetEnded() != plimsollv1.SessionEnd_SESSION_END_REPLACED {
		t.Fatalf("closing the replaced session: %v %v; want REPLACED", c, err)
	}
	for _, id := range []string{first, third, other} {
		if _, err := svc.SessionRun(alice, callReq(id, "3")); err != nil {
			t.Fatalf("a session the cap left alone: %v", err)
		}
	}
	if _, err := svc.SessionRun(bob, callReq(bobs, "3")); err != nil {
		t.Fatalf("another caller's session of the same owner name: %v", err)
	}
}

// When every session of an owner at its cap is running a call, the open is refused,
// not dispatched, reason capacity, and nothing is closed.
func TestSessionsPerOwnerCapRefusesWhenEveryOneIsBusy(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.MaxPerOwner = 1
	alice := authenticatedContext("alice")
	o, err := svc.OpenSession(alice, ownerOpen("u1"))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
	e.turn <- struct{}{} // a call in progress
	_, err = svc.OpenSession(alice, ownerOpen("u1"))
	if reason, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodeResourceExhausted || !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY {
		t.Fatalf("an open while the owner's one session runs a call: %v; want ResourceExhausted, marked capacity", err)
	}
	if p.Opened()[0].Err() != nil || len(p.Opened()) != 1 {
		t.Fatal("a refused open closed or opened a session")
	}
	<-e.turn
	if _, err := svc.OpenSession(alice, ownerOpen("u1")); err != nil {
		t.Fatalf("an open once the call ended: %v", err)
	}
	if p.Opened()[0].Err() == nil {
		t.Fatal("the idle session was not replaced")
	}
}

// A replaced session's place passes to the open, so a full daemon still gives an
// owner at its cap a new session; another caller is refused as before. The open
// waits for the replaced sandbox's delete, which gives back its concurrency slot,
// within the request's bound.
func TestSessionsPerOwnerReplacedPlacePassesToTheOpen(t *testing.T) {
	svc, p := sessionService()
	p.HoldDeletes = true
	svc.Limiter = NewCodeLimiter(2, 2, 0, 0)
	svc.Sessions.MaxSessions = 2
	svc.Sessions.MaxPerOwner = 2
	alice, bob := authenticatedContext("alice"), authenticatedContext("bob")
	var ids []string
	for i := 0; i < 2; i++ {
		o, err := svc.OpenSession(alice, ownerOpen("u1"))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, o.Msg.GetSessionId())
	}
	if _, err := svc.OpenSession(bob, ownerOpen("u1")); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("another caller on a full daemon: %v", err)
	}
	gaveUp, cancel := context.WithTimeout(alice, 50*time.Millisecond)
	defer cancel()
	_, err := svc.OpenSession(gaveUp, ownerOpen("u1"))
	if _, marked := notDispatchedOf(err); !marked {
		t.Fatalf("an open whose caller gave up waiting for the delete: %v; want a marked refusal", err)
	}
	if p.Opened()[0].Err() == nil {
		t.Fatal("the least recently used session was not closed")
	}
	p.Opened()[0].FinishDelete()
	// The slot the open had taken over comes back once that sandbox is gone.
	for deadline := time.Now().Add(5 * time.Second); svc.Limiter.Stats().InFlight != 1; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the slot never came back: %d in flight", svc.Limiter.Stats().InFlight)
		}
	}
	// The owner now holds one session, so this open replaces none.
	if _, err := svc.OpenSession(alice, ownerOpen("u1")); err != nil {
		t.Fatalf("an open with room once the delete gave the slot back: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := svc.OpenSession(alice, ownerOpen("u1"))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the open did not wait for the delete: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	p.Opened()[1].FinishDelete()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the open after the delete: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the open never finished")
	}
}

// An owner is checked like a trace ID, but refused, never dropped: dropping it would
// lift the cap without a word. Sessions with no owner count against none.
func TestSessionOwnerIsCheckedAndOptional(t *testing.T) {
	svc, _ := sessionService()
	svc.Sessions.MaxPerOwner = 1
	alice := authenticatedContext("alice")
	for _, bad := range []string{"a/b", "a b", strings.Repeat("a", 65)} {
		_, err := svc.OpenSession(alice, ownerOpen(bad))
		if reason, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodeInvalidArgument || !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST {
			t.Fatalf("owner %q: %v; want InvalidArgument, marked request", bad, err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.OpenSession(alice, openReq()); err != nil {
			t.Fatalf("session %d with no owner: %v", i, err)
		}
	}
}

// An open the daemon refuses after choosing its victim closes nothing: a caller
// already gone, a spent rate, no free slot. The owner keeps the session it had.
func TestSessionsPerOwnerARefusedOpenClosesNothing(t *testing.T) {
	cases := map[string]func(*SandboxService, *sandboxtest.Sessions) context.Context{
		"caller gone": func(*SandboxService, *sandboxtest.Sessions) context.Context {
			gone, cancel := context.WithCancel(authenticatedContext("alice"))
			cancel()
			return gone
		},
		"rate spent": func(svc *SandboxService, _ *sandboxtest.Sessions) context.Context {
			svc.Limiter = NewCodeLimiter(4, 4, 1, 1) // the first open spends the one start a minute
			return authenticatedContext("alice")
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			svc, p := sessionService()
			svc.Sessions.MaxPerOwner = 1
			ctx := setup(svc, p)
			if _, err := svc.OpenSession(authenticatedContext("alice"), ownerOpen("u1")); err != nil {
				t.Fatal(err)
			}
			_, err := svc.OpenSession(ctx, ownerOpen("u1"))
			if _, marked := notDispatchedOf(err); err == nil || !marked {
				t.Fatalf("the refused open: %v; want a not-dispatched refusal", err)
			}
			if p.Opened()[0].Err() != nil || len(p.Opened()) != 1 {
				t.Fatalf("a refused open closed the owner's session (%v) or opened one (%d)", p.Opened()[0].Err(), len(p.Opened()))
			}
		})
	}
	t.Run("no slot", func(t *testing.T) {
		svc, p := sessionService()
		svc.Sessions.MaxSessions = 8
		svc.Sessions.MaxPerOwner = 1
		svc.Limiter = NewCodeLimiter(2, 2, 0, 0)
		alice, bob := authenticatedContext("alice"), authenticatedContext("bob")
		a, err := svc.OpenSession(alice, ownerOpen("u1"))
		if err != nil {
			t.Fatal(err)
		}
		claimSession(t, svc, alice, a.Msg.GetSessionId())
		e, _ := svc.sessions.get(a.Msg.GetSessionId(), "alice")
		e.mu.Lock()
		gen := e.idleGen
		e.mu.Unlock()
		svc.suspend(e, gen) // a stopped sandbox gives its slot back
		for i := 0; i < 2; i++ {
			if _, err := svc.OpenSession(bob, openReq()); err != nil {
				t.Fatal(err)
			}
		}
		_, err = svc.OpenSession(alice, ownerOpen("u1"))
		if reason, marked := notDispatchedOf(err); !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY {
			t.Fatalf("an open with no slot: %v; want refused, capacity", err)
		}
		if p.Opened()[0].Err() != nil {
			t.Fatal("an open refused for want of a slot closed the owner's suspended session")
		}
	})
}

// closeFailing opens fake sessions whose Close fails and leaves them open, as a provider
// whose delete the docker daemon did not answer does.
type closeFailing struct{ *sandboxtest.Sessions }

func (p *closeFailing) OpenSession(ctx context.Context, o sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, o)
	if err != nil {
		return nil, err
	}
	return &closeFailingSession{Session: s}, nil
}

type closeFailingSession struct{ sandbox.Session }

func (*closeFailingSession) Close(context.Context) error {
	return errors.New("the delete was not answered")
}

// A victim whose close fails stays the owner's, open, counted and holding its slot, and
// the open is refused: before, it was left out of every cap
// and refused other callers' opens for a slot nobody counted.
func TestSessionsPerOwnerAFailedCloseKeepsTheVictim(t *testing.T) {
	svc, p := sessionService()
	svc.Sandbox = &closeFailing{p}
	svc.Sessions.MaxSessions = 4
	svc.Sessions.MaxPerOwner = 1
	svc.Limiter = NewCodeLimiter(2, 2, 0, 0)
	alice, bob := authenticatedContext("alice"), authenticatedContext("bob")
	a, err := svc.OpenSession(alice, ownerOpen("u1"))
	if err != nil {
		t.Fatal(err)
	}
	// Bounded, so an open that waits for a victim that never goes fails here, not by hanging.
	bounded, cancel := context.WithTimeout(alice, 5*time.Second)
	defer cancel()
	_, err = svc.OpenSession(bounded, ownerOpen("u1"))
	if reason, marked := notDispatchedOf(err); !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY {
		t.Fatalf("an open whose victim would not close: %v; want refused, capacity", err)
	}
	e, _ := svc.sessions.get(a.Msg.GetSessionId(), "alice")
	e.mu.Lock()
	replaced, slot := e.replaced, e.release != nil
	e.mu.Unlock()
	if replaced || !slot {
		t.Fatalf("the victim: replaced=%v, holds its slot=%v; want it the owner's again", replaced, slot)
	}
	if _, err := svc.SessionRun(alice, callReq(a.Msg.GetSessionId(), "1")); err != nil {
		t.Fatalf("a call on the session that stayed open: %v", err)
	}
	if _, err := svc.OpenSession(bob, openReq()); err != nil {
		t.Fatalf("another caller with a slot free: %v", err)
	}
	if svc.Limiter.Stats().InFlight != 2 {
		t.Fatalf("slots in flight: %d; want the two sessions'", svc.Limiter.Stats().InFlight)
	}
}

// A victim the provider had ended by itself reports that end, not a replacement, and is no victim at all once ended.
func TestSessionsPerOwnerAnEndedSessionIsNoVictim(t *testing.T) {
	svc, p := sessionService()
	p.HoldDeletes = true
	svc.Sessions.MaxPerOwner = 1
	alice := authenticatedContext("alice")
	a, err := svc.OpenSession(alice, ownerOpen("u1"))
	if err != nil {
		t.Fatal(err)
	}
	p.Opened()[0].End(sandbox.SessionExpired) // its delete still pending, so not yet marked ended
	if _, err := svc.OpenSession(alice, ownerOpen("u1")); err != nil {
		t.Fatal(err)
	}
	_, err = svc.SessionRun(alice, callReq(a.Msg.GetSessionId(), "1"))
	if end, ok := endedAs(err); !ok || end != plimsollv1.SessionEnd_SESSION_END_EXPIRED {
		t.Fatalf("a call on the expired session: %v %v; want EXPIRED", end, ok)
	}
	p.Opened()[0].FinishDelete()
	c, err := svc.CloseSession(alice, closeReq(a.Msg.GetSessionId()))
	if err != nil || c.Msg.GetEnded() != plimsollv1.SessionEnd_SESSION_END_EXPIRED {
		t.Fatalf("closing it: %v %v; want EXPIRED", c, err)
	}
}

// An unknown session ID (a restart forgot it, or it is another caller's) is refused,
// not dispatched, with a session end, so a client stops using it and opens a new one.
func TestAnUnknownSessionIsRefusedAsEnded(t *testing.T) {
	svc, _ := sessionService()
	_, err := svc.SessionRun(authenticatedContext("alice"), callReq("00000000000000000000000000000000", "1"))
	if reason, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodeNotFound || !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST {
		t.Fatalf("a call on an unknown session: %v; want NotFound, marked request", err)
	}
	if end, ok := endedAs(err); !ok || end != plimsollv1.SessionEnd_SESSION_END_NOT_FOUND {
		t.Fatalf("its end: %v %v; want NOT_FOUND", end, ok)
	}
}

// meteredSessions is the fake session provider billed by the second.
type meteredSessions struct{ *sandboxtest.Sessions }

func (meteredSessions) BillingTeardown() time.Duration { return 10 * time.Second }

func meteredSessionService(allowance int64) (*SandboxService, *sandboxtest.Sessions, context.Context) {
	p := &sandboxtest.Sessions{}
	svc := NewSandboxService(meteredSessions{p})
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: 10 * time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	svc.Spend = NewSpendCap(0)
	ctx := context.WithValue(context.Background(), principalKey{}, Principal{UserID: "alice", Scopes: []string{ScopeCodeRun}, PaidSecondsPerDay: allowance})
	return svc, p, ctx
}

func timedCall(id string, ms int32) *connect.Request[plimsollv1.SessionRunRequest] {
	r := callReq(id, "1")
	r.Msg.TimeoutMs = ms
	return r
}

// On a provider billed by the second, an open reserves its own time, the idle time
// and the teardown (2 min + 1 min + 10 s) before anything is made, and is refused
// without making anything when the allowance cannot cover it; a suspend stops the
// charge, the call that resumes the session starts it again, and the end settles it.
func TestMeteredSessionsDrawOnTheAllowance(t *testing.T) {
	svc, p, ctx := meteredSessionService(100)
	if _, err := svc.OpenSession(ctx, openReq()); !refusedCapacity(err) || len(p.Opened()) != 0 {
		t.Fatalf("an open its allowance cannot cover: %v, %d opened; want refused, capacity, nothing made", err, len(p.Opened()))
	}
	svc, p, ctx = meteredSessionService(1000)
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	if a, _ := svc.Spend.spent("alice"); a != 190 {
		t.Fatalf("held after the open: %v, want 190", a)
	}
	if _, err := svc.SessionRun(ctx, timedCall(id, 5000)); err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(id, "alice")
	e.mu.Lock()
	gen := e.idleGen
	e.mu.Unlock()
	svc.suspend(e, gen)
	if a, _ := svc.Spend.spent("alice"); a > 1 || e.paid.running() {
		t.Fatalf("after the suspend: %v spent, running %v; want the open's fraction of a second, stopped", a, e.paid.running())
	}
	if _, err := svc.SessionRun(ctx, timedCall(id, 5000)); err != nil {
		t.Fatal(err)
	}
	if a, _ := svc.Spend.spent("alice"); a < 75 || a > 76 || !e.paid.running() {
		t.Fatalf("after the call that resumed it: %v, running %v; want its 75 s (5 s, the idle minute, 10 s) held", a, e.paid.running())
	}
	if _, err := svc.CloseSession(ctx, closeReq(id)); err != nil {
		t.Fatal(err)
	}
	<-e.gone
	if a, _ := svc.Spend.spent("alice"); a > 1 {
		t.Fatalf("after the end: %v spent; want what ran, a fraction of a second", a)
	}
	_ = p
}

// A call the allowance cannot cover is refused, not dispatched, and the session goes
// on: a call within what it holds still runs.
func TestMeteredSessionCallRefusedKeepsTheSession(t *testing.T) {
	svc, _, ctx := meteredSessionService(190)
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	if _, err := svc.SessionRun(ctx, timedCall(id, 125000)); !refusedCapacity(err) { // 195 s of 190
		t.Fatalf("a call past the allowance: %v; want refused, capacity", err)
	}
	if _, err := svc.SessionRun(ctx, timedCall(id, 5000)); err != nil {
		t.Fatalf("a call within what is held after the refusal: %v", err)
	}
}

// A suspend that fails leaves the sandbox running: another idle period is reserved,
// and when the allowance cannot cover it the session is closed rather than run unpaid.
func TestMeteredSessionThatCannotSuspendOrPayIsClosed(t *testing.T) {
	svc, p, ctx := meteredSessionService(190)
	p.FailedSuspends = 1
	clock := time.Now()
	svc.Spend.now = func() time.Time { return clock }
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	claimSession(t, svc, ctx, open.Msg.GetSessionId())
	e, _ := svc.sessions.get(open.Msg.GetSessionId(), "alice")
	clock = clock.Add(150 * time.Second) // 150 s ran: another 70 s does not fit in 190
	e.mu.Lock()
	gen := e.idleGen
	e.mu.Unlock()
	svc.suspend(e, gen)
	select {
	case <-e.gone:
	case <-time.After(5 * time.Second):
		t.Fatal("the session that could neither suspend nor pay is still open")
	}
	if n := p.Opened()[0].Suspends(); n != 1 {
		t.Fatalf("%d suspends; want the one that failed (an unclaimed session is closed without one)", n)
	}
}

// A session on a provider billed by the second must be able to stop billing.
func TestMeteredSessionNeedsAnIdleTimeout(t *testing.T) {
	svc, p, ctx := meteredSessionService(1000)
	svc.Sessions.IdleTimeout = 0
	_, err := svc.OpenSession(ctx, openReq())
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || len(p.Opened()) != 0 {
		t.Fatalf("a metered session with no idle timeout: %v, %d opened; want failed precondition, nothing made", err, len(p.Opened()))
	}
}

// leakySessions is the metered fake whose sessions' sandboxes outlive their deletes:
// each reports, after its end, billing until until (sandbox.BillsUntiler). With
// failOpen, every open fails having reported its delete given up until until.
type leakySessions struct {
	meteredSessions
	until    time.Time
	failOpen bool
}

type leakySession struct {
	sandbox.Session
	until time.Time
}

func (s leakySession) BillsUntil() time.Time { return s.until }

func (p leakySessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	if p.failOpen {
		sandbox.TeardownGaveUpUntil(ctx, p.until)
		return nil, errors.New("the open failed and its sandbox's delete gave up")
	}
	s, err := p.meteredSessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return leakySession{Session: s, until: p.until}, nil
}

// A session whose sandbox outlives its delete is charged, after its end, until the
// provider's own lifetime for the sandbox ends, and so is a failed open whose delete
// gave up (round-3 review: neither reached the meter, so the sandbox billed on unseen).
func TestLeakedSessionSandboxesAreCharged(t *testing.T) {
	for _, failOpen := range []bool{false, true} {
		svc, _, ctx := meteredSessionService(100000)
		until := time.Now().Add(20 * time.Minute)
		svc.Sandbox = leakySessions{meteredSessions: svc.Sandbox.(meteredSessions), until: until, failOpen: failOpen}
		open, err := svc.OpenSession(ctx, openReq())
		if failOpen {
			if err == nil {
				t.Fatal("the failing open succeeded")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			id := open.Msg.GetSessionId()
			e, _ := svc.sessions.get(id, "alice")
			if _, err := svc.CloseSession(ctx, closeReq(id)); err != nil {
				t.Fatal(err)
			}
			<-e.gone
		}
		if a, _ := svc.Spend.spent("alice"); a < 20*60-5 || a > 20*60+5 {
			t.Fatalf("failOpen=%v: %v seconds charged; want the 1,200 the leaked sandbox bills", failOpen, a)
		}
	}
}

// A call refused before dispatch is not use: the session suspends when it would have
// without it. A fresh idle period after each refusal let a caller keep a session billed
// by the second running past its allowance, by sending calls the allowance refuses
// (round-7 review, 2026-10-08). A call that runs still starts a fresh idle period.
func TestRefusedSessionCallKeepsTheSuspendDeadline(t *testing.T) {
	svc, _, ctx := meteredSessionService(190)
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	e, _ := svc.sessions.get(id, "alice")
	idleAt := func() time.Time {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.idleAt
	}
	before := idleAt()
	if before.IsZero() {
		t.Fatal("the open armed no idle timer")
	}
	time.Sleep(20 * time.Millisecond)
	for range 3 {
		if _, err := svc.SessionRun(ctx, timedCall(id, 125000)); !refusedCapacity(err) {
			t.Fatalf("a call past the allowance: %v; want refused, capacity", err)
		}
	}
	if after := idleAt(); !after.Equal(before) {
		t.Fatalf("three refused calls moved the suspend from %v to %v; want it where it was", before, after)
	}
	if _, err := svc.SessionRun(ctx, timedCall(id, 5000)); err != nil {
		t.Fatalf("a call within what is held: %v", err)
	}
	if after := idleAt(); !after.After(before) {
		t.Fatalf("a call that ran left the suspend at %v; want a fresh idle period after it", after)
	}
}

// lockedLog is a log destination a timer's goroutine can write while a test reads it.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(b)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func waitGone(t *testing.T, e *sessionEntry, what string) {
	t.Helper()
	select {
	case <-e.gone:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s is still open", what)
	}
}

// A session no request named by its first idle timeout is closed, not suspended: one
// whose open answer never reached its client looks exactly like that, and nobody can use
// or close it (failure-injection review, finding 7). Its slot and place come back, a late
// call is refused, not dispatched, with the end unclaimed, and a close collects that end.
func TestAnUnclaimedSessionIsClosedAtItsFirstIdleTimeout(t *testing.T) {
	svc, p := sessionService()
	var log lockedLog
	svc.Logger = slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc.Limiter = NewCodeLimiter(1, 0, 0, 0)
	svc.Sessions.MaxPerCaller = 1
	svc.Sessions.IdleTimeout = time.Second // the shortest the daemon takes (minSessionIdle)
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	e, _ := svc.sessions.get(id, "alice")
	waitGone(t, e, "the unclaimed session")
	if n := p.Opened()[0].Suspends(); n != 0 {
		t.Fatalf("%d suspends; want the session closed without one", n)
	}
	if n := svc.Limiter.Stats().InFlight; n != 0 {
		t.Fatalf("%d slots held after the close; want 0", n)
	}
	_, err = svc.SessionRun(ctx, callReq(id, "1"))
	if end, ok := endedAs(err); !ok || end != plimsollv1.SessionEnd_SESSION_END_UNCLAIMED {
		t.Fatalf("a call after the close: %v; want the end unclaimed", err)
	}
	if _, marked := notDispatchedOf(err); !marked || connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a call after the close: %v; want FailedPrecondition, not dispatched", err)
	}
	if p.Opened()[0].Calls() != 0 {
		t.Fatal("a call reached the closed session's provider")
	}
	closed, err := svc.CloseSession(ctx, closeReq(id))
	if err != nil || closed.Msg.GetEnded() != plimsollv1.SessionEnd_SESSION_END_UNCLAIMED || closed.Msg.GetCalls() != 0 {
		t.Fatalf("the close: %v, %v; want the end unclaimed and no calls", closed, err)
	}
	// The caller's one place came back.
	if _, err := svc.OpenSession(ctx, openReq()); err != nil {
		t.Fatalf("an open after the unclaimed session closed: %v", err)
	}
	out := log.String()
	if !strings.Contains(out, `"msg":"session closed unclaimed`) || !strings.Contains(out, `"session":"`+open.Msg.GetSession()+`"`) {
		t.Errorf("no log line names the unclaimed session by its fingerprint:\n%s", out)
	}
	if strings.Contains(out, id) {
		t.Errorf("the session ID reached the log:\n%s", out)
	}
}

// A call refused before it ran still claims the session, since its client holds the ID:
// the first idle timeout suspends it, and nothing ends it as unclaimed.
func TestACallRefusedBeforeItRanClaimsTheSession(t *testing.T) {
	svc, p := sessionService()
	svc.Limiter = NewCodeLimiter(1, 0, 1, 1) // the open spends the only run this minute
	svc.Sessions.IdleTimeout = time.Second   // the shortest the daemon takes (minSessionIdle)
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SessionRun(ctx, callReq(open.Msg.GetSessionId(), "1")); !refusedCapacity(err) {
		t.Fatalf("a call past the caller's rate: %v; want refused, capacity", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for p.Opened()[0].Suspends() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the claimed session was never suspended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := p.Opened()[0].Err(); err != nil {
		t.Fatalf("the claimed session ended: %v", err)
	}
}

// A session that never suspends (idle timeout 0) is closed unclaimed after
// sessionClaimWindow; once claimed it has no timer at all, whether the claiming call
// ran or was refused.
func TestASessionThatNeverSuspendsHasAClaimWindow(t *testing.T) {
	old := sessionClaimWindow
	sessionClaimWindow = 50 * time.Millisecond
	t.Cleanup(func() { sessionClaimWindow = old })
	svc, p := sessionService()
	svc.Sessions.IdleTimeout = 0
	ctx := authenticatedContext("alice")
	var entries []*sessionEntry
	for i := 0; i < 3; i++ {
		o, err := svc.OpenSession(ctx, openReq())
		if err != nil {
			t.Fatal(err)
		}
		e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
		entries = append(entries, e)
	}
	claimSession(t, svc, ctx, entries[1].id) // refused before it ran
	if _, err := svc.SessionRun(ctx, callReq(entries[2].id, "1")); err != nil {
		t.Fatal(err)
	}
	waitGone(t, entries[0], "the unclaimed session that never suspends")
	if _, err := svc.SessionRun(ctx, callReq(entries[0].id, "1")); func() bool {
		end, ok := endedAs(err)
		return !ok || end != plimsollv1.SessionEnd_SESSION_END_UNCLAIMED
	}() {
		t.Fatalf("a call on it: %v; want the end unclaimed", err)
	}
	time.Sleep(4 * sessionClaimWindow)
	for i, s := range p.Opened()[1:] {
		if s.Err() != nil || s.Suspends() != 0 {
			t.Fatalf("claimed session %d: ended %v, %d suspends; want it open and never suspended", i+1, s.Err(), s.Suspends())
		}
	}
}

// A close that fails without ending the unclaimed session keeps it, claimable, and is
// tried again after another period, since nobody else will close it.
func TestAFailedUnclaimedCloseIsTriedAgain(t *testing.T) {
	svc, p := sessionService()
	var log lockedLog
	svc.Logger = slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc.Sandbox = &closeFailing{p}
	svc.Sessions.IdleTimeout = time.Hour // nothing fires by itself
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(open.Msg.GetSessionId(), "alice")
	e.mu.Lock()
	e.idleTimeout = 20 * time.Millisecond // below the floor an open applies, so retries come quickly
	gen := e.idleGen
	e.mu.Unlock()
	svc.suspend(e, gen) // the first idle timeout
	deadline := time.Now().Add(10 * time.Second)
	for strings.Count(log.String(), "unclaimed session close failed") < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("a failed close of an unclaimed session was not tried again:\n%s", log.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := svc.SessionRun(ctx, callReq(open.Msg.GetSessionId(), "1")); err != nil {
		t.Fatalf("a call on the session whose close failed: %v", err)
	}
	if strings.Contains(log.String(), "session closed unclaimed") {
		t.Fatalf("a close that failed was logged as done:\n%s", log.String())
	}
}

// On a provider billed by the second, an unclaimed session's close stops its paid time:
// the caller is charged what ran, not the open's reservation.
func TestAnUnclaimedMeteredSessionStopsBilling(t *testing.T) {
	svc, _, ctx := meteredSessionService(1000)
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(open.Msg.GetSessionId(), "alice")
	e.mu.Lock()
	gen := e.idleGen
	e.mu.Unlock()
	svc.suspend(e, gen) // the first idle timeout
	waitGone(t, e, "the unclaimed metered session")
	if a, _ := svc.Spend.spent("alice"); a > 1 || e.paid.running() {
		t.Fatalf("after the close: %v spent, running %v; want a fraction of a second, stopped", a, e.paid.running())
	}
}
