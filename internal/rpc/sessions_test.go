package rpc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
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
