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
	e, ok := svc.sessions.get(open.Msg.GetSessionId(), auditCaller(ctx))
	if !ok {
		t.Fatal("the session is not registered")
	}
	e.mu.Lock()
	e.idleTimeout = 20 * time.Millisecond
	e.mu.Unlock()
	e.turn <- struct{}{} // a call holds the turn
	svc.suspend(e)       // the idle timer fires now
	<-e.turn             // the call gives the turn back
	deadline := time.Now().Add(3 * time.Second)
	for p.Opened()[0].Suspends() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("an idle suspend that found the turn busy never tried again")
		}
		time.Sleep(10 * time.Millisecond)
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
