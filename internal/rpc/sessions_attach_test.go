package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/wireenum"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
	"google.golang.org/protobuf/proto"
)

func attachReq(fingerprint string, generation, calls uint64, last string) *connect.Request[plimsollv1.AttachSessionRequest] {
	return connect.NewRequest(&plimsollv1.AttachSessionRequest{Protocol: protocol.Number, Session: fingerprint,
		Checkpoint: &plimsollv1.SessionCheckpoint{Generation: generation, Calls: calls, LastRecordSha256: last}})
}

func requireAttachRefusal(t *testing.T, err error, code connect.Code, reason sandbox.Refusal) {
	t.Helper()
	got, marked := notDispatchedOf(err)
	if connect.CodeOf(err) != code || !marked || got != wireenum.RefusalToWire(reason) {
		t.Fatalf("refusal: %v (%v, %v), want %v/%v", err, got, marked, code, reason)
	}
}

func TestAttachPreservesChainPolicyAndAccounting(t *testing.T) {
	svc, p := sessionService()
	var log bytes.Buffer
	svc.Logger = slog.New(slog.NewJSONHandler(&log, nil))
	ctx := authenticatedContext("alice")
	req := openReq()
	req.Msg.MinimumIsolation = "container"
	opened, err := svc.OpenSession(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	id, fp := opened.Msg.GetSessionId(), opened.Msg.GetSession()
	e, _ := svc.sessions.get(id, "alice")
	e.mu.Lock()
	idleAt, idleGen, used, release := e.idleAt, e.idleGen, e.used, e.release != nil
	e.mu.Unlock()
	a := attachReq(fp, 1, 0, "")
	a.Msg.TraceId = "job:1"
	attached, err := svc.AttachSession(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	info := proto.Clone(opened.Msg).(*plimsollv1.OpenSessionResponse)
	info.Generation = 2
	if !proto.Equal(attached.Msg.GetSessionInfo(), info) {
		t.Fatal("attach changed policy or identity")
	}
	e.mu.Lock()
	unchanged := e.idleAt == idleAt && e.idleGen == idleGen && e.used == used && (e.release != nil) == release && e.calls == 0 && e.last == "" && e.claimed
	e.mu.Unlock()
	if !unchanged || len(p.Opened()) != 1 {
		t.Fatal("attach changed idle time, usage, capacity, chain, or provider sessions")
	}
	_, err = svc.SessionRun(ctx, callReq(id, "stale"))
	requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalPermission)
	_, err = svc.CloseSession(ctx, closeReq(id))
	requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalPermission)
	run := callReq(id, "1")
	run.Msg.Generation = 2
	_, err = svc.SessionRun(ctx, run)
	requireAttachRefusal(t, err, connect.CodeInvalidArgument, sandbox.RefusalRequest)
	run.Msg.MinimumIsolation = "container"
	out, err := svc.SessionRun(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := record.CheckSessionCall(run.Msg, out.Msg.GetRun(), fp, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.AttachSession(ctx, attachReq(fp, 2, 0, ""))
	requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalRequest)
	next, err := svc.AttachSession(ctx, attachReq(fp, 2, 1, rec.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	if next.Msg.GetCheckpoint().GetGeneration() != 3 || next.Msg.GetCheckpoint().GetLastRecordSha256() != rec.SHA256 {
		t.Fatal("attach lost chain")
	}
	close := closeReq(id)
	close.Msg.Generation = 3
	summary, err := svc.CloseSession(ctx, close)
	if err != nil || summary.Msg.GetCalls() != 1 {
		t.Fatalf("close: %v", err)
	}
	if _, ok := svc.sessions.lookupFingerprint(fp, "alice"); ok {
		t.Fatal("closed fingerprint retained")
	}
	if strings.Contains(log.String(), id) || strings.Contains(log.String(), rec.SHA256) || !strings.Contains(log.String(), `"trace_id":"job:1"`) {
		t.Fatal("attach audit omitted trace or disclosed secret/checkpoint")
	}
}

func TestAttachRejectsInvalidOrForeignState(t *testing.T) {
	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	opened, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	fp := opened.Msg.GetSession()
	tests := []struct {
		name   string
		change func(*plimsollv1.AttachSessionRequest)
	}{
		{"missing", func(r *plimsollv1.AttachSessionRequest) { r.Checkpoint = nil }},
		{"zero generation", func(r *plimsollv1.AttachSessionRequest) { r.Checkpoint.Generation = 0 }},
		{"digest without calls", func(r *plimsollv1.AttachSessionRequest) { r.Checkpoint.LastRecordSha256 = strings.Repeat("a", 64) }},
		{"calls without digest", func(r *plimsollv1.AttachSessionRequest) { r.Checkpoint.Calls = 1 }},
		{"uppercase digest", func(r *plimsollv1.AttachSessionRequest) {
			r.Checkpoint.Calls = 1
			r.Checkpoint.LastRecordSha256 = strings.Repeat("A", 64)
		}},
		{"bad fingerprint", func(r *plimsollv1.AttachSessionRequest) { r.Session = "secret/" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := attachReq(fp, 1, 0, "")
			tt.change(req.Msg)
			_, err := svc.AttachSession(ctx, req)
			requireAttachRefusal(t, err, connect.CodeInvalidArgument, sandbox.RefusalRequest)
		})
	}
	_, err = svc.AttachSession(context.Background(), attachReq(fp, 1, 0, ""))
	requireAttachRefusal(t, err, connect.CodeUnauthenticated, sandbox.RefusalPermission)
	noScope := context.WithValue(context.Background(), principalKey{}, Principal{UserID: "alice"})
	_, err = svc.AttachSession(noScope, attachReq(fp, 1, 0, ""))
	requireAttachRefusal(t, err, connect.CodePermissionDenied, sandbox.RefusalPermission)
	_, foreign := svc.AttachSession(authenticatedContext("bob"), attachReq(fp, 1, 0, ""))
	_, unknown := svc.AttachSession(authenticatedContext("bob"), attachReq(strings.Repeat("0", 64), 1, 0, ""))
	if foreign.Error() != unknown.Error() {
		t.Fatal("foreign lookup disclosed existence")
	}
	requireAttachRefusal(t, foreign, connect.CodeNotFound, sandbox.RefusalRequest)
	dev, err := svc.OpenSession(context.Background(), openReq())
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.AttachSession(authenticatedContext("anon"), attachReq(dev.Msg.GetSession(), 1, 0, ""))
	requireAttachRefusal(t, err, connect.CodeNotFound, sandbox.RefusalRequest)
	good, err := svc.AttachSession(ctx, attachReq(fp, 1, 0, ""))
	if err != nil || good.Msg.GetCheckpoint().GetGeneration() != 2 {
		t.Fatalf("refusals changed generation: %v", err)
	}
}

func TestTwoAttachesCannotBothOwnSession(t *testing.T) {
	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.AttachSession(ctx, attachReq(o.Msg.GetSession(), 1, 0, ""))
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else {
			requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalPermission)
		}
	}
	if success != 1 {
		t.Fatalf("%d transfers succeeded", success)
	}
}

func TestAttachCancellationExpiryAndOverflow(t *testing.T) {
	for _, state := range []string{"canceled", "expired", "ended", "overflow"} {
		t.Run(state, func(t *testing.T) {
			svc, p := sessionService()
			ctx := authenticatedContext("alice")
			o, err := svc.OpenSession(ctx, openReq())
			if err != nil {
				t.Fatal(err)
			}
			e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
			req := attachReq(o.Msg.GetSession(), 1, 0, "")
			switch state {
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired":
				e.expires = time.Now().Add(-time.Second)
			case "ended":
				p.Opened()[0].End(sandbox.SessionExpired)
			case "overflow":
				e.mu.Lock()
				e.generation = math.MaxUint64
				e.mu.Unlock()
				req.Msg.Checkpoint.Generation = math.MaxUint64
			}
			_, err = svc.AttachSession(ctx, req)
			if err == nil {
				t.Fatal("invalid attach succeeded")
			}
			if _, marked := notDispatchedOf(err); !marked {
				t.Fatal("refusal unmarked")
			}
			e.mu.Lock()
			g := e.generation
			e.mu.Unlock()
			if g != req.Msg.Checkpoint.Generation {
				t.Fatal("refusal advanced generation")
			}
		})
	}
}

func TestAttachRateRefusalDoesNotClaimOrTransfer(t *testing.T) {
	svc, _ := sessionService()
	svc.Limiter = NewCodeLimiter(1, 1, 1, 1)
	ctx := authenticatedContext("static")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(o.Msg.GetSessionId(), "static")
	_, err = svc.AttachSession(ctx, attachReq(o.Msg.GetSession(), 1, 0, ""))
	requireAttachRefusal(t, err, connect.CodeResourceExhausted, sandbox.RefusalCapacity)
	e.mu.Lock()
	unchanged := e.generation == 1 && !e.claimed
	e.mu.Unlock()
	if !unchanged {
		t.Fatal("rate refusal transferred or claimed session")
	}
	// Replenish only the rate bucket; the session still holds the sole slot.
	svc.Limiter.mu.Lock()
	svc.Limiter.buckets["static"].tokens = 1
	svc.Limiter.mu.Unlock()
	_, err = svc.AttachSession(ctx, attachReq(o.Msg.GetSession(), 1, 0, ""))
	if err != nil {
		t.Fatal(err)
	}
}

type attachHeldSession struct {
	sandbox.Session
	entered chan struct{}
	proceed chan struct{}
}

func (h *attachHeldSession) RunJavaScript(ctx context.Context, r sandbox.Request) (sandbox.Result, error) {
	close(h.entered)
	select {
	case <-h.proceed:
	case <-ctx.Done():
		return sandbox.Result{}, ctx.Err()
	}
	return h.Session.RunJavaScript(ctx, r)
}

// The queue's occupied token proves that the competing request reached the turn.
// The timer is only a deadlock guard, not the evidence for the interleaving.
func waitAttachQueue(t *testing.T, e *sessionEntry) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for len(e.waiting) != 1 {
		select {
		case <-deadline.C:
			t.Fatal("request did not reach the turn")
		default:
			runtime.Gosched()
		}
	}
}

type attachHeldProvider struct {
	*sandboxtest.Sessions
	entered chan struct{}
	proceed chan struct{}
}

func (p *attachHeldProvider) OpenSession(ctx context.Context, o sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, o)
	if err != nil {
		return nil, err
	}
	return &attachHeldSession{Session: s, entered: p.entered, proceed: p.proceed}, nil
}

func TestAttachWaitsForInflightRecordAndRefusesOldCheckpoint(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	held := &attachHeldProvider{Sessions: p, entered: make(chan struct{}), proceed: make(chan struct{})}
	svc.Sandbox = held
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
	runErr := make(chan error, 1)
	go func() { _, err := svc.SessionRun(ctx, callReq(e.id, "1")); runErr <- err }()
	<-held.entered
	attachErr := make(chan error, 1)
	go func() { _, err := svc.AttachSession(ctx, attachReq(e.fingerprint, 1, 0, "")); attachErr <- err }()
	waitAttachQueue(t, e)
	close(held.proceed)
	if err := <-runErr; err != nil {
		t.Fatal(err)
	}
	requireAttachRefusal(t, <-attachErr, connect.CodeFailedPrecondition, sandbox.RefusalRequest)
	e.mu.Lock()
	calls, last, generation := e.calls, e.last, e.generation
	e.mu.Unlock()
	if calls != 1 || last == "" || generation != 1 {
		t.Fatal("in-flight record or generation lost")
	}
}

// gatedSession holds an attach inside the session's turn: once armed, the first Err
// call, which an attach makes right after it takes the turn and before it compares the
// checkpoint, closes reached and waits for proceed. Nothing else asks the session for
// its end in these tests while it is armed (no call is in flight, and the idle timer
// is a minute away). Each Suspend is announced on suspended.
type gatedSession struct {
	sandbox.Session
	armed     atomic.Bool
	reached   chan struct{}
	proceed   chan struct{}
	suspended chan struct{}
}

func (g *gatedSession) Err() error {
	if g.armed.CompareAndSwap(true, false) {
		close(g.reached)
		<-g.proceed
	}
	return g.Session.Err()
}

func (g *gatedSession) Suspend(ctx context.Context) (bool, error) {
	holds, err := g.Session.Suspend(ctx)
	g.suspended <- struct{}{}
	return holds, err
}

type gatedProvider struct {
	*sandboxtest.Sessions
	mu   sync.Mutex
	last *gatedSession
}

func (p *gatedProvider) OpenSession(ctx context.Context, o sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, o)
	if err != nil {
		return nil, err
	}
	g := &gatedSession{Session: s, reached: make(chan struct{}), proceed: make(chan struct{}), suspended: make(chan struct{}, 4)}
	p.mu.Lock()
	p.last = g
	p.mu.Unlock()
	return g, nil
}

func gatedService(t *testing.T) (*SandboxService, *sandboxtest.Sessions, *sessionEntry, *gatedSession) {
	t.Helper()
	svc, p := sessionService()
	gp := &gatedProvider{Sessions: p}
	svc.Sandbox = gp
	o, err := svc.OpenSession(authenticatedContext("alice"), openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
	gp.mu.Lock()
	defer gp.mu.Unlock()
	return svc, p, e, gp.last
}

// waitFor is a deadlock guard on a channel the code under test signals.
func waitFor(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not happen", what)
	}
}

// A run and a close that passed their first generation check and queued behind a real
// attach find, once the attach gives the turn back, that another worker owns the
// session: refused before anything reaches the provider, the session left open.
func TestQueuedRunAndCloseAreStaleAfterARealAttach(t *testing.T) {
	for _, op := range []string{"run", "close"} {
		t.Run(op, func(t *testing.T) {
			svc, p, e, g := gatedService(t)
			ctx := authenticatedContext("alice")
			g.armed.Store(true)
			attached := make(chan error, 1)
			go func() { _, err := svc.AttachSession(ctx, attachReq(e.fingerprint, 1, 0, "")); attached <- err }()
			waitFor(t, g.reached, "the attach taking the turn")
			errs := make(chan error, 1)
			go func() {
				var err error
				if op == "run" {
					_, err = svc.SessionRun(ctx, callReq(e.id, "1"))
				} else {
					_, err = svc.CloseSession(ctx, closeReq(e.id))
				}
				errs <- err
			}()
			waitAttachQueue(t, e)
			close(g.proceed)
			if err := <-attached; err != nil {
				t.Fatal(err)
			}
			requireAttachRefusal(t, <-errs, connect.CodeFailedPrecondition, sandbox.RefusalPermission)
			if p.Opened()[0].Calls() != 0 || p.Opened()[0].Err() != nil {
				t.Fatal("stale worker touched provider")
			}
			e.mu.Lock()
			generation := e.generation
			e.mu.Unlock()
			if generation != 2 {
				t.Fatalf("generation %d after one attach", generation)
			}
		})
	}
}

// The idle timer fires while an attach holds the turn: the suspend it owes waits for
// the turn and runs when the attach gives it back, once, with no fresh idle period.
func TestIdleTimerDueDuringAttachSuspendsAtRelease(t *testing.T) {
	svc, p := sessionService()
	svc.Limiter = NewCodeLimiter(1, 1, 0, 0) // the session holds a slot, which a suspend gives back
	gp := &gatedProvider{Sessions: p}
	svc.Sandbox = gp
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
	gp.mu.Lock()
	g := gp.last
	gp.mu.Unlock()
	e.mu.Lock()
	gen, idleAt := e.idleGen, e.idleAt
	e.mu.Unlock()
	g.armed.Store(true)
	attached := make(chan error, 1)
	go func() { _, err := svc.AttachSession(ctx, attachReq(e.fingerprint, 1, 0, "")); attached <- err }()
	waitFor(t, g.reached, "the attach taking the turn")
	svc.suspend(e, gen) // the idle timer's callback, as time.AfterFunc would run it
	e.mu.Lock()
	due := e.idleDue != nil
	unchanged := e.idleGen == gen && e.idleAt == idleAt
	e.mu.Unlock()
	if !due || !unchanged || p.Opened()[0].Suspends() != 0 {
		t.Fatal("the suspend did not wait for the attach, or the attach moved the idle deadline")
	}
	close(g.proceed)
	if err := <-attached; err != nil {
		t.Fatal(err)
	}
	waitFor(t, g.suspended, "the suspend after the attach gave the turn back")
	// The suspend holds the turn until it is done; taking it proves it finished.
	give, err := e.takeTurn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	suspended, pending := e.release == nil, e.idleDue != nil
	e.mu.Unlock()
	give()
	if !suspended || pending || p.Opened()[0].Suspends() != 1 || p.Opened()[0].Err() != nil {
		t.Fatalf("after release: suspended %v, another due %v, %d suspends", suspended, pending, p.Opened()[0].Suspends())
	}
	select {
	case <-g.suspended:
		t.Fatal("suspended twice")
	default:
	}
}

func TestQueuedAttachCancellationLeavesOwnership(t *testing.T) {
	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
	give, err := e.takeTurn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer give()
	canceled, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 1)
	go func() { _, err := svc.AttachSession(canceled, attachReq(e.fingerprint, 1, 0, "")); errs <- err }()
	waitAttachQueue(t, e)
	_, err = svc.AttachSession(ctx, attachReq(e.fingerprint, 1, 0, ""))
	requireAttachRefusal(t, err, connect.CodeResourceExhausted, sandbox.RefusalCapacity)
	cancel()
	requireAttachRefusal(t, <-errs, connect.CodeCanceled, sandbox.RefusalCapacity)
	e.mu.Lock()
	unchanged := e.generation == 1 && !e.claimed
	e.mu.Unlock()
	if !unchanged {
		t.Fatal("canceled attach changed owner")
	}
}

func TestAttachThroughAuthenticatedHTTP(t *testing.T) {
	svc, _ := sessionService()
	mux := http.NewServeMux()
	path, handler := NewHandler(svc, connect.WithInterceptors(AuthInterceptor(fakeVerifier{token: "shared-token", scopes: []string{ScopeCodeRun}})))
	mux.Handle(path, handler)
	server := httptest.NewServer(BindAnswers(mux))
	defer server.Close()
	client := plimsollv1connect.NewSandboxServiceClient(server.Client(), server.URL)
	open := openReq()
	open.Header().Set("Authorization", "Bearer shared-token")
	open.Header().Set(protocol.RequestIDHeader, testRequestID)
	o, err := client.OpenSession(context.Background(), open)
	if err != nil {
		t.Fatal(err)
	}
	a := attachReq(o.Msg.GetSession(), 1, 0, "")
	a.Header().Set(protocol.RequestIDHeader, testRequestID)
	_, err = client.AttachSession(context.Background(), a)
	requireAttachRefusal(t, err, connect.CodeUnauthenticated, sandbox.RefusalPermission)
	a.Header().Set("Authorization", "Bearer shared-token")
	a.Msg.Protocol = protocol.Number - 1
	_, err = client.AttachSession(context.Background(), a)
	requireAttachRefusal(t, err, connect.CodeUnimplemented, sandbox.RefusalProtocol)
	a.Msg.Protocol = protocol.Number
	out, err := client.AttachSession(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if out.Header().Get(protocol.RequestIDHeader) != testRequestID || out.Msg.GetCheckpoint().GetGeneration() != 2 {
		t.Fatal("attach not bound to request or not transferred")
	}
}

func TestAttachCannotSkipAnUnansweredRecord(t *testing.T) {
	svc, p := sessionService()
	svc.Sandbox = &failingSessions{Sessions: p, failCall: 1}
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	call := callReq(o.Msg.GetSessionId(), "1")
	_, err = svc.SessionRun(ctx, call)
	if err == nil {
		t.Fatal("expected lost result")
	}
	var ce *connect.Error
	var unanswered *plimsollv1.RunRecord
	if errors.As(err, &ce) {
		for _, d := range ce.Details() {
			v, _ := d.Value()
			if u, ok := v.(*plimsollv1.UnansweredCall); ok {
				unanswered = u.GetRecord()
			}
		}
	}
	rec, err := record.CheckUnanswered(call.Msg, unanswered, o.Msg.GetSession(), 0, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.AttachSession(ctx, attachReq(o.Msg.GetSession(), 1, 0, ""))
	requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalRequest)
	_, err = svc.AttachSession(ctx, attachReq(o.Msg.GetSession(), 1, 1, rec.SHA256))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAttachDoesNotResumeSuspendedSession(t *testing.T) {
	svc, p := sessionService()
	svc.Limiter = NewCodeLimiter(1, 1, 0, 0)
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
	e.claim()
	e.mu.Lock()
	gen := e.idleGen
	e.mu.Unlock()
	svc.suspend(e, gen)
	e.mu.Lock()
	suspended := e.release == nil
	idleAt, idleGen := e.idleAt, e.idleGen
	e.mu.Unlock()
	if !suspended || p.Opened()[0].Suspends() != 1 {
		t.Fatal("fixture did not suspend")
	}
	_, err = svc.AttachSession(ctx, attachReq(e.fingerprint, 1, 0, ""))
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	unchanged := e.release == nil && e.idleAt == idleAt && e.idleGen == idleGen
	e.mu.Unlock()
	if !unchanged || p.Opened()[0].Calls() != 0 || p.Opened()[0].Suspends() != 1 {
		t.Fatal("attach resumed or changed suspended session")
	}
}

// attachServer serves svc over HTTP behind the auth interceptor, as plimsolld does.
func attachServer(t *testing.T, svc *SandboxService, verifier TokenVerifier) plimsollv1connect.SandboxServiceClient {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := NewHandler(svc, connect.WithInterceptors(AuthInterceptor(verifier)))
	mux.Handle(path, handler)
	server := httptest.NewServer(BindAnswers(mux))
	t.Cleanup(server.Close)
	return plimsollv1connect.NewSandboxServiceClient(server.Client(), server.URL)
}

func bound[T any](m *T, token string) *connect.Request[T] {
	r := connect.NewRequest(m)
	r.Header().Set(protocol.RequestIDHeader, testRequestID)
	if token != "" {
		r.Header().Set("Authorization", "Bearer "+token)
	}
	return r
}

// Open development mode stamps a principal with no user, which may run and open but
// never attach: a dev-mode session has no owner a credential could prove.
func TestAttachRefusedInOpenDevMode(t *testing.T) {
	svc, p := sessionService()
	client := attachServer(t, svc, nil)
	o, err := client.OpenSession(context.Background(), bound(&plimsollv1.OpenSessionRequest{Protocol: protocol.Number}, ""))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(o.Msg.GetSessionId(), "anon")
	_, err = client.AttachSession(context.Background(), bound(&plimsollv1.AttachSessionRequest{Protocol: protocol.Number,
		Session: o.Msg.GetSession(), Checkpoint: &plimsollv1.SessionCheckpoint{Generation: 1}}, ""))
	requireAttachRefusal(t, err, connect.CodeUnauthenticated, sandbox.RefusalPermission)
	e.mu.Lock()
	unchanged := e.generation == 1 && !e.claimed
	e.mu.Unlock()
	if !unchanged || p.Opened()[0].Calls() != 0 || p.Opened()[0].Err() != nil {
		t.Fatal("a refused dev-mode attach changed the session")
	}
}

// A dev-mode session is logged as caller "anon"; a real principal of that name is
// another caller and finds nothing, exactly as for an unknown fingerprint.
func TestDevModeSessionNotAttachableByARealPrincipalNamedAnon(t *testing.T) {
	svc, _ := sessionService()
	dev, err := svc.OpenSession(context.Background(), openReq())
	if err != nil {
		t.Fatal(err)
	}
	anon := authenticatedContext("anon")
	_, err = svc.AttachSession(anon, attachReq(dev.Msg.GetSession(), 1, 0, ""))
	_, unknown := svc.AttachSession(anon, attachReq(strings.Repeat("0", 64), 1, 0, ""))
	requireAttachRefusal(t, err, connect.CodeNotFound, sandbox.RefusalRequest)
	if err.Error() != unknown.Error() {
		t.Fatalf("%q differs from an unknown fingerprint's %q", err, unknown)
	}
	e, _ := svc.sessions.get(dev.Msg.GetSessionId(), "anon")
	e.mu.Lock()
	unchanged := e.generation == 1 && !e.claimed
	e.mu.Unlock()
	if !unchanged {
		t.Fatal("a refused attach changed the dev-mode session")
	}
}

// After its close, a session's fingerprint finds nothing, over the wire exactly as an
// unknown one.
func TestAttachOverRPCAfterCloseIsNotFound(t *testing.T) {
	svc, _ := sessionService()
	client := attachServer(t, svc, fakeVerifier{token: "shared-token", scopes: []string{ScopeCodeRun}})
	o, err := client.OpenSession(context.Background(), bound(&plimsollv1.OpenSessionRequest{Protocol: protocol.Number}, "shared-token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CloseSession(context.Background(), bound(&plimsollv1.CloseSessionRequest{Protocol: protocol.Number,
		SessionId: o.Msg.GetSessionId(), Generation: 1}, "shared-token")); err != nil {
		t.Fatal(err)
	}
	attach := func(fp string) error {
		_, err := client.AttachSession(context.Background(), bound(&plimsollv1.AttachSessionRequest{Protocol: protocol.Number,
			Session: fp, Checkpoint: &plimsollv1.SessionCheckpoint{Generation: 1}}, "shared-token"))
		return err
	}
	closed, unknown := attach(o.Msg.GetSession()), attach(strings.Repeat("0", 64))
	requireAttachRefusal(t, closed, connect.CodeNotFound, sandbox.RefusalRequest)
	if closed.Error() != unknown.Error() {
		t.Fatalf("%q differs from an unknown fingerprint's %q", closed, unknown)
	}
}

// An expired session cannot be attached, whether the provider has ended it or its
// absolute deadline has passed before the provider noticed; either way it says what
// an unknown fingerprint says.
func TestAttachAfterExpiryIsNotFound(t *testing.T) {
	for _, how := range []string{"provider ended it", "deadline passed"} {
		t.Run(how, func(t *testing.T) {
			svc, p := sessionService()
			ctx := authenticatedContext("alice")
			o, err := svc.OpenSession(ctx, openReq())
			if err != nil {
				t.Fatal(err)
			}
			e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
			if how == "provider ended it" {
				p.Opened()[0].End(sandbox.SessionExpired)
				<-e.gone
			} else {
				e.mu.Lock()
				e.expires = time.Now().Add(-time.Second)
				e.mu.Unlock()
			}
			_, err = svc.AttachSession(ctx, attachReq(o.Msg.GetSession(), 1, 0, ""))
			_, unknown := svc.AttachSession(ctx, attachReq(strings.Repeat("0", 64), 1, 0, ""))
			requireAttachRefusal(t, err, connect.CodeNotFound, sandbox.RefusalRequest)
			if err.Error() != unknown.Error() {
				t.Fatalf("%q differs from an unknown fingerprint's %q", err, unknown)
			}
			e.mu.Lock()
			generation := e.generation
			e.mu.Unlock()
			if generation != 1 {
				t.Fatal("a refused attach advanced the generation")
			}
		})
	}
}

// Every attach is charged to its caller's rate before the lookup, so one that finds
// nothing, or finds another caller's session, costs what a good one costs.
func TestAttachUnknownAndOtherCallerCostARateToken(t *testing.T) {
	svc, _ := sessionService()
	svc.Limiter = NewCodeLimiter(4, 4, 2, 2) // two runs a minute per caller, both available now
	alice, bob := authenticatedContext("alice"), authenticatedContext("bob")
	o, err := svc.OpenSession(alice, openReq())
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.AttachSession(bob, attachReq(strings.Repeat("0", 64), 1, 0, ""))
	requireAttachRefusal(t, err, connect.CodeNotFound, sandbox.RefusalRequest)
	_, err = svc.AttachSession(bob, attachReq(o.Msg.GetSession(), 1, 0, ""))
	requireAttachRefusal(t, err, connect.CodeNotFound, sandbox.RefusalRequest)
	// bob's two tokens are spent: his next attach is refused for its rate, before the lookup.
	_, err = svc.AttachSession(bob, attachReq(strings.Repeat("0", 64), 1, 0, ""))
	requireAttachRefusal(t, err, connect.CodeResourceExhausted, sandbox.RefusalCapacity)
	// alice's bucket is her own: the open took one token, and her attach takes the other.
	if _, err := svc.AttachSession(alice, attachReq(o.Msg.GetSession(), 1, 0, "")); err != nil {
		t.Fatal(err)
	}
}

// A refused attach leaves an info line with the caller, the refusal's reason, the trace
// ID and, only for the caller's own session, its fingerprint: never the session ID, a
// generation, a count, a digest, or the fingerprint a caller sent.
func TestRefusedAttachIsLoggedWithoutSecrets(t *testing.T) {
	svc, _ := sessionService()
	var log bytes.Buffer
	svc.Logger = slog.New(slog.NewJSONHandler(&log, nil))
	alice, bob := authenticatedContext("alice"), authenticatedContext("bob")
	o, err := svc.OpenSession(alice, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id, fp := o.Msg.GetSessionId(), o.Msg.GetSession()
	out, err := svc.SessionRun(alice, callReq(id, "1"))
	if err != nil {
		t.Fatal(err)
	}
	digest := out.Msg.GetRun().GetRecord().GetRecordSha256()
	if _, err := svc.AttachSession(alice, attachReq(fp, 1, 1, digest)); err != nil {
		t.Fatal(err)
	}
	unknownFP := strings.Repeat("7", 64)
	cases := []struct {
		ctx    context.Context
		req    *connect.Request[plimsollv1.AttachSessionRequest]
		reason string
		own    bool
	}{
		{bob, attachReq(unknownFP, 9, 0, ""), "request", false},                  // unknown
		{bob, attachReq(fp, 2, 1, digest), "request", false},                     // another caller's
		{alice, attachReq(fp, 1, 1, digest), "permission", true},                 // stale generation
		{alice, attachReq(fp, 2, 0, ""), "request", true},                        // head mismatch
		{alice, attachReq(fp, 0, 1, digest), "request", false},                   // zero generation
		{context.Background(), attachReq(fp, 2, 1, digest), "permission", false}, // unauthenticated
	}
	for i, c := range cases {
		c.req.Msg.TraceId = fmt.Sprintf("job:%d", i)
		if _, err := svc.AttachSession(c.ctx, c.req); err == nil {
			t.Fatalf("case %d attached", i)
		}
	}
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(log.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatal(err)
		}
		if m["msg"] == "session attach refused" {
			lines = append(lines, m)
		}
	}
	if len(lines) != len(cases) {
		t.Fatalf("%d refusal lines for %d refusals", len(lines), len(cases))
	}
	allowed := map[string]bool{"time": true, "level": true, "msg": true, "caller": true, "session": true, "reason": true, "trace_id": true}
	for i, m := range lines {
		for k := range m {
			if !allowed[k] {
				t.Fatalf("refusal line %d carries %q: %v", i, k, m)
			}
		}
		_, hasSession := m["session"]
		if m["level"] != "INFO" || m["reason"] != cases[i].reason || m["trace_id"] != fmt.Sprintf("job:%d", i) ||
			hasSession != cases[i].own || (hasSession && m["session"] != fp) {
			t.Fatalf("refusal line %d: %v", i, m)
		}
	}
	for _, secret := range []string{id, digest, unknownFP} {
		if strings.Contains(log.String(), secret) {
			t.Fatal("the audit log holds a session ID, a digest or a caller's fingerprint")
		}
	}
}

// A call must state at least the floor its session was opened with; a weaker one is
// refused before anything runs.
func TestRunWithWeakerFloorThanOpenRefused(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	open := openReq()
	open.Msg.MinimumIsolation = "container"
	o, err := svc.OpenSession(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	for _, floor := range []string{"", "process"} {
		run := callReq(o.Msg.GetSessionId(), "1")
		run.Msg.MinimumIsolation = floor
		_, err := svc.SessionRun(ctx, run)
		requireAttachRefusal(t, err, connect.CodeInvalidArgument, sandbox.RefusalRequest)
	}
	if p.Opened()[0].Calls() != 0 {
		t.Fatal("a call under the open's floor ran")
	}
	run := callReq(o.Msg.GetSessionId(), "1")
	run.Msg.MinimumIsolation = "container"
	if _, err := svc.SessionRun(ctx, run); err != nil {
		t.Fatal(err)
	}
}

// The open's floor does not replace the daemon's own (SANDBOX_MIN_ISOLATION): a call
// that keeps the open's floor is still refused under a daemon floor the session cannot
// meet. As in TestTheDaemonFloorHoldsOnSessions, the floor is raised after the open,
// the only way to reach the call path with a session below it.
func TestOpenFloorAndDaemonFloorBothApply(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	open := openReq()
	open.Msg.MinimumIsolation = "process"
	o, err := svc.OpenSession(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	svc.Floor = sandbox.IsolationKernel
	run := callReq(o.Msg.GetSessionId(), "1")
	run.Msg.MinimumIsolation = "process"
	_, err = svc.SessionRun(ctx, run)
	requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalIsolation)
	run.Msg.MinimumIsolation = ""
	_, err = svc.SessionRun(ctx, run)
	requireAttachRefusal(t, err, connect.CodeInvalidArgument, sandbox.RefusalRequest)
	if p.Opened()[0].Calls() != 0 {
		t.Fatal("a call under a floor ran")
	}
	svc.Floor = sandbox.IsolationUnknown
	run.Msg.MinimumIsolation = "process"
	if _, err := svc.SessionRun(ctx, run); err != nil {
		t.Fatal(err)
	}
}

// Zero is no generation at all: a malformed run, close or attach, refused as such
// before the lookup, so it neither waits behind a call in flight nor claims the session.
func TestZeroGenerationIsAnInvalidRequestEverywhere(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
	give, err := e.takeTurn(ctx) // a call in flight holds the turn
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{o.Msg.GetSessionId(), strings.Repeat("0", 32)} {
		run := callReq(id, "1")
		run.Msg.Generation = 0
		_, err := svc.SessionRun(ctx, run)
		requireAttachRefusal(t, err, connect.CodeInvalidArgument, sandbox.RefusalRequest)
		c := closeReq(id)
		c.Msg.Generation = 0
		_, err = svc.CloseSession(ctx, c)
		requireAttachRefusal(t, err, connect.CodeInvalidArgument, sandbox.RefusalRequest)
	}
	for _, fp := range []string{o.Msg.GetSession(), strings.Repeat("0", 64)} {
		_, err = svc.AttachSession(ctx, attachReq(fp, 0, 0, ""))
		requireAttachRefusal(t, err, connect.CodeInvalidArgument, sandbox.RefusalRequest)
	}
	e.mu.Lock()
	unchanged := e.generation == 1 && !e.claimed && len(e.waiting) == 0
	e.mu.Unlock()
	give()
	if !unchanged || p.Opened()[0].Calls() != 0 || p.Opened()[0].Err() != nil {
		t.Fatal("a zero generation waited, claimed, or reached the provider")
	}
}

// The stale-owner and mismatch refusals say the same constant thing every time: no
// generation, count or digest of the session's, which the refused worker does not
// hold and must not learn.
func TestStaleAndMismatchErrorsRevealNothing(t *testing.T) {
	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id, fp := o.Msg.GetSessionId(), o.Msg.GetSession()
	out, err := svc.SessionRun(ctx, callReq(id, "1"))
	if err != nil {
		t.Fatal(err)
	}
	digest := out.Msg.GetRun().GetRecord().GetRecordSha256()
	if _, err := svc.AttachSession(ctx, attachReq(fp, 1, 1, digest)); err != nil {
		t.Fatal(err)
	}
	stale := []error{}
	_, err = svc.SessionRun(ctx, callReq(id, "2"))
	stale = append(stale, err)
	_, err = svc.CloseSession(ctx, closeReq(id))
	stale = append(stale, err)
	_, err = svc.AttachSession(ctx, attachReq(fp, 1, 1, digest))
	stale = append(stale, err)
	_, mismatch := svc.AttachSession(ctx, attachReq(fp, 2, 0, ""))
	message := func(err error) string {
		var ce *connect.Error
		if !errors.As(err, &ce) {
			t.Fatalf("not a connect error: %v", err)
		}
		return ce.Message()
	}
	for _, err := range stale {
		requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalPermission)
		if message(err) != textStaleOwner {
			t.Fatalf("stale refusal says %q", message(err))
		}
	}
	requireAttachRefusal(t, mismatch, connect.CodeFailedPrecondition, sandbox.RefusalRequest)
	if message(mismatch) != textCheckpointMismatch {
		t.Fatalf("mismatch refusal says %q", message(mismatch))
	}
	for _, text := range []string{textStaleOwner, textCheckpointMismatch} {
		if strings.ContainsAny(text, "0123456789") {
			t.Fatalf("%q holds a number", text)
		}
	}
}

// The generation never wraps: at its largest value an attach is refused and the
// current owner carries on.
func TestGenerationOverflowRefused(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.sessions.get(o.Msg.GetSessionId(), "alice")
	e.mu.Lock()
	e.generation = math.MaxUint64
	e.mu.Unlock()
	_, err = svc.AttachSession(ctx, attachReq(o.Msg.GetSession(), math.MaxUint64, 0, ""))
	requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalPermission)
	e.mu.Lock()
	generation := e.generation
	e.mu.Unlock()
	if generation != math.MaxUint64 {
		t.Fatal("the generation wrapped")
	}
	run := callReq(o.Msg.GetSessionId(), "1")
	run.Msg.Generation = math.MaxUint64
	if _, err := svc.SessionRun(ctx, run); err != nil || p.Opened()[0].Calls() != 1 {
		t.Fatalf("the current owner was refused: %v", err)
	}
}
