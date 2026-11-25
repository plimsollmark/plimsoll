package rpc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// headOf is the session's head as the daemon holds it; a generation of 1 and no calls for
// an ID the daemon does not hold, so a test of an unknown session gets past the head's
// form.
func headOf(svc *SandboxService, id string) *plimsollv1.SessionCheckpoint {
	svc.sessions.mu.Lock()
	e := svc.sessions.byID[id]
	svc.sessions.mu.Unlock()
	if e == nil {
		return &plimsollv1.SessionCheckpoint{Generation: 1}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return &plimsollv1.SessionCheckpoint{Generation: e.generation, Calls: e.calls, LastRecordSha256: e.last}
}

// headRun sends a session call. When the request states no head, it states the opener's
// generation (1) and the count and last record the daemon holds at the moment of sending:
// the worker that opened the session, having seen every answer (atGeneration states
// another generation). A request that states a head is sent as it is. The request is
// copied, so a test may send the same one twice.
func headRun(svc *SandboxService, ctx context.Context, req *connect.Request[plimsollv1.SessionRunRequest]) (*connect.Response[plimsollv1.SessionRunResponse], error) {
	m := proto.Clone(req.Msg).(*plimsollv1.SessionRunRequest)
	if m.Head == nil {
		m.Head = headOf(svc, m.GetSessionId())
		m.Head.Generation = 1
	}
	out := connect.NewRequest(m)
	for k, v := range req.Header() {
		out.Header()[k] = v
	}
	return svc.SessionRun(ctx, out)
}

// atGeneration makes m state the session's current count and last record with the
// given generation: a call from a worker at that generation that saw every answer.
func atGeneration(svc *SandboxService, m *plimsollv1.SessionRunRequest, generation uint64) {
	h := headOf(svc, m.GetSessionId())
	h.Generation = generation
	m.Head = h
}

// headMismatchOf is the daemon's head on a call's head mismatch refusal, or nil.
func headMismatchOf(err error) *plimsollv1.SessionCheckpoint {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return nil
	}
	for _, d := range ce.Details() {
		if v, derr := d.Value(); derr == nil {
			if h, ok := v.(*plimsollv1.SessionHeadMismatch); ok {
				return h.GetHead()
			}
		}
	}
	return nil
}

func entryOf(t *testing.T, svc *SandboxService, id string) *sessionEntry {
	t.Helper()
	e, ok := svc.sessions.get(id, "alice")
	if !ok {
		t.Fatal("no such session")
	}
	return e
}

func keptAnswerOf(e *sessionEntry) *plimsollv1.RunResponse {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.keptAnswer
}

// A call that states no head, or a malformed one, is a malformed request: refused before
// the session is looked up, marked, nothing run.
func TestASessionCallMustStateAWellFormedHead(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := o.Msg.GetSessionId()
	for name, head := range map[string]*plimsollv1.SessionCheckpoint{
		"no head":                {},
		"a digest before a call": {Generation: 1, LastRecordSha256: record.SessionFingerprint("x")},
		"a count with no digest": {Generation: 1, Calls: 1},
		"a digest in upper case": {Generation: 1, Calls: 1, LastRecordSha256: strings.ToUpper(record.SessionFingerprint("x"))},
	} {
		req := callReq(id, "1")
		if name != "no head" {
			req.Msg.Head = head
		}
		_, err := svc.SessionRun(ctx, req)
		if name == "no head" {
			// Refused as having no head, not as a zero generation: a client that predates
			// the head (it sent the generation in field 7) is told what it lacks.
			requireAttachRefusal(t, err, connect.CodeInvalidArgument, sandbox.RefusalRequest)
			if !strings.Contains(err.Error(), "requires the head it expects") {
				t.Errorf("no head: %v", err)
			}
		} else if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
		if _, marked := notDispatchedOf(err); !marked {
			t.Errorf("%s: unmarked: %v", name, err)
		}
	}
	if p.Opened()[0].Calls() != 0 {
		t.Fatal("a call with a malformed head ran")
	}
}

// A call whose head carries the current generation but another count or last record is a
// head mismatch: refused before anything runs, marked (reason request), with the daemon's
// head as its detail, and nothing moves: the call with the right head runs next, at the
// next place in the chain.
func TestAHeadMismatchIsRefusedAndMovesNothing(t *testing.T) {
	svc, p := sessionService()
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := o.Msg.GetSessionId()
	first, err := headRun(svc, ctx, callReq(id, "1"))
	if err != nil {
		t.Fatal(err)
	}
	r1 := first.Msg.GetRun().GetRecord().GetRecordSha256()
	want := &plimsollv1.SessionCheckpoint{Generation: 1, Calls: 1, LastRecordSha256: r1}
	for name, head := range map[string]*plimsollv1.SessionCheckpoint{
		"a count behind": {Generation: 1},
		"a count ahead":  {Generation: 1, Calls: 2, LastRecordSha256: r1},
		"another digest": {Generation: 1, Calls: 1, LastRecordSha256: record.SessionFingerprint("another record")},
	} {
		req := callReq(id, "2")
		req.Msg.Head = head
		_, err := svc.SessionRun(ctx, req)
		requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalRequest)
		var ce *connect.Error
		if !errors.As(err, &ce) || ce.Message() != protocol.CheckpointMismatchText {
			t.Errorf("%s: the refusal's text: %v", name, err)
		}
		if got := headMismatchOf(err); !proto.Equal(got, want) {
			t.Errorf("%s: the detail states the head %v, want %v", name, got, want)
		}
		if !proto.Equal(headOf(svc, id), want) || p.Opened()[0].Calls() != 1 {
			t.Fatalf("%s moved the head (%v) or ran (%d calls)", name, headOf(svc, id), p.Opened()[0].Calls())
		}
	}
	next, err := headRun(svc, ctx, callReq(id, "2"))
	if err != nil {
		t.Fatal(err)
	}
	if r := next.Msg.GetRun().GetRecord(); r.GetSequence() != 2 || r.GetPreviousSha256() != r1 {
		t.Fatalf("the next call is %d after %q", r.GetSequence(), r.GetPreviousSha256())
	}
}

// A stale generation is refused as a stale owner, as before the head, whatever count and
// digest the call states, and the refusal says nothing of the session's head.
func TestAStaleGenerationIsStaleWhateverTheHead(t *testing.T) {
	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := o.Msg.GetSessionId()
	if _, err := headRun(svc, ctx, callReq(id, "1")); err != nil {
		t.Fatal(err)
	}
	for _, head := range []*plimsollv1.SessionCheckpoint{{Generation: 2}, headOf(svc, id)} {
		head.Generation = 2
		req := callReq(id, "2")
		req.Msg.Head = head
		_, err := svc.SessionRun(ctx, req)
		requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalPermission)
		if headMismatchOf(err) != nil {
			t.Fatal("a stale owner's refusal states the session's head")
		}
	}
}

// keptAnswerSession opens a session on a daemon that keeps answers up to keep bytes (the
// open asking for keep_no_answer when noAnswer), on provider p, and runs a cell whose
// answer is then "lost": the checkpoint before it, its request digest and its answer.
func keptAnswerSession(t *testing.T, p sandbox.Sandbox, keep int, noAnswer bool) (svc *SandboxService, id, fp string, cp *plimsollv1.SessionCheckpoint, lost string, answer *plimsollv1.RunResponse) {
	t.Helper()
	svc = NewSandboxService(p)
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20, KeptAnswerBytes: keep, KeptAnswersTotalBytes: 64 << 20}
	ctx := authenticatedContext("alice")
	open := openReq()
	open.Msg.KeepNoAnswer = noAnswer
	o, err := svc.OpenSession(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	id, fp = o.Msg.GetSessionId(), o.Msg.GetSession()
	if _, err := headRun(svc, ctx, callReq(id, "1")); err != nil {
		t.Fatal(err)
	}
	cp = headOf(svc, id)
	call := cellReq(id, "kept_answer_marker_5521 = 1")
	resp, err := headRun(svc, ctx, call)
	if err != nil {
		return svc, id, fp, cp, record.SessionRunRequestDigest(call.Msg), nil
	}
	return svc, id, fp, cp, record.SessionRunRequestDigest(call.Msg), resp.Msg.GetRun()
}

func cellReq(id, code string) *connect.Request[plimsollv1.SessionRunRequest] {
	return connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: id,
		Payload: &plimsollv1.SessionRunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "python", Code: code}}})
}

// attachAcross attaches across the lost call's gap and returns the answer.
func attachAcross(t *testing.T, svc *SandboxService, fp string, cp *plimsollv1.SessionCheckpoint, lost string) *plimsollv1.AttachSessionResponse {
	t.Helper()
	got, err := svc.AttachSession(authenticatedContext("alice"), lostAttachReq(fp, cp.GetGeneration(), cp.GetCalls(), cp.GetLastRecordSha256(), lost))
	if err != nil {
		t.Fatal(err)
	}
	if got.Msg.GetLostRecord() == nil {
		t.Fatal("the attach across the gap returned no lost record")
	}
	return got.Msg
}

// The attach across the lost call's gap returns its answer, exactly as the daemon sent
// it, and the audit line says an answer came back but holds none of it.
func TestAnAttachAcrossTheGapReturnsTheKeptAnswer(t *testing.T) {
	svc, _, fp, cp, lost, answer := keptAnswerSession(t, &sandboxtest.Sessions{}, 4<<20, false)
	var log bytes.Buffer
	svc.Logger = slog.New(slog.NewJSONHandler(&log, nil))
	got := attachAcross(t, svc, fp, cp, lost)
	if !proto.Equal(got.GetLostAnswer(), answer) || !proto.Equal(got.GetLostAnswer().GetRecord(), got.GetLostRecord()) {
		t.Fatalf("the lost answer %v is not the call's %v", got.GetLostAnswer(), answer)
	}
	if !strings.Contains(log.String(), `"lost_answer":true`) || strings.Contains(log.String(), "kept_answer_marker_5521") {
		t.Fatalf("the audit line: %s", log.String())
	}
}

// A call refused for its head, as the worker that lost the answer would send it from its
// stale head, leaves the kept answer for the attach across the gap.
func TestAHeadMismatchLeavesTheKeptAnswer(t *testing.T) {
	svc, id, fp, cp, lost, answer := keptAnswerSession(t, &sandboxtest.Sessions{}, 4<<20, false)
	retry := cellReq(id, "kept_answer_marker_5521 = 1")
	retry.Msg.Head = cp
	_, err := svc.SessionRun(authenticatedContext("alice"), retry)
	requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalRequest)
	if got := attachAcross(t, svc, fp, cp, lost); !proto.Equal(got.GetLostAnswer(), answer) {
		t.Fatal("the head mismatch dropped the kept answer")
	}
}

// The next call drops the kept answer when it starts, even when it is then refused
// without running (here by the caller's rate): no answer outlives the start of the call
// after it. The attach across the gap then returns the record alone.
func TestTheNextCallDropsTheKeptAnswerWhenItStarts(t *testing.T) {
	svc, id, fp, cp, lost, _ := keptAnswerSession(t, &sandboxtest.Sessions{}, 4<<20, false)
	ctx := authenticatedContext("alice")
	svc.Limiter = NewCodeLimiter(10, 10, 1, 1)
	if err := svc.Limiter.Charge("alice"); err != nil {
		t.Fatal(err)
	}
	_, err := headRun(svc, ctx, callReq(id, "3"))
	requireAttachRefusal(t, err, connect.CodeResourceExhausted, sandbox.RefusalCapacity)
	if keptAnswerOf(entryOf(t, svc, id)) != nil {
		t.Fatal("the call that started kept the answer before it")
	}
	svc.Limiter = nil
	if got := attachAcross(t, svc, fp, cp, lost); got.GetLostAnswer() != nil {
		t.Fatal("an answer came back after the next call started")
	}
}

// An idle session keeps no answer: the idle timer drops it when it fires, and the attach
// across the gap of a suspended session returns the record alone.
func TestASuspendDropsTheKeptAnswer(t *testing.T) {
	p := &sandboxtest.Sessions{}
	svc, id, fp, cp, lost, _ := keptAnswerSession(t, p, 4<<20, false)
	e := entryOf(t, svc, id)
	e.mu.Lock()
	gen := e.idleGen
	e.mu.Unlock()
	svc.suspend(e, gen)
	if p.Opened()[0].Suspends() != 1 || keptAnswerOf(e) != nil {
		t.Fatalf("after the idle timer: %d suspends, kept answer %v", p.Opened()[0].Suspends(), keptAnswerOf(e))
	}
	if got := attachAcross(t, svc, fp, cp, lost); got.GetLostAnswer() != nil {
		t.Fatal("a suspended session returned an answer")
	}
}

// A close drops the kept answer, and so does an end the provider reaches by itself.
func TestACloseAndAnEndDropTheKeptAnswer(t *testing.T) {
	svc, id, _, _, _, _ := keptAnswerSession(t, &sandboxtest.Sessions{}, 4<<20, false)
	e := entryOf(t, svc, id)
	if keptAnswerOf(e) == nil {
		t.Fatal("nothing was kept")
	}
	if _, err := svc.CloseSession(authenticatedContext("alice"), closeReq(id)); err != nil {
		t.Fatal(err)
	}
	if keptAnswerOf(e) != nil {
		t.Fatal("the close kept the answer")
	}

	p := &sandboxtest.Sessions{}
	svc, id, _, _, _, _ = keptAnswerSession(t, p, 4<<20, false)
	e = entryOf(t, svc, id)
	if keptAnswerOf(e) == nil {
		t.Fatal("nothing was kept")
	}
	p.Opened()[0].End(sandbox.SessionExpired)
	p.Opened()[0].FinishDelete()
	select {
	case <-e.gone:
	case <-time.After(10 * time.Second):
		t.Fatal("the session's end was never seen")
	}
	if keptAnswerOf(e) != nil {
		t.Fatal("the ended session kept the answer")
	}
}

// The cap is the proto size of the answer: an answer of exactly the cap is kept, one byte
// over it leaves the record alone, and a cap of 0 keeps none.
func TestTheKeptAnswerCap(t *testing.T) {
	_, _, _, _, _, answer := keptAnswerSession(t, &sandboxtest.Sessions{}, 4<<20, false)
	size := proto.Size(answer)
	for _, c := range []struct {
		keep int
		kept bool
	}{{size, true}, {size - 1, false}, {0, false}} {
		svc, _, fp, cp, lost, _ := keptAnswerSession(t, &sandboxtest.Sessions{}, c.keep, false)
		if got := attachAcross(t, svc, fp, cp, lost); (got.GetLostAnswer() != nil) != c.kept {
			t.Errorf("a cap of %d on an answer of %d bytes: kept %v", c.keep, size, got.GetLostAnswer() != nil)
		}
	}
}

// A session opened with keep_no_answer keeps none, whatever the operator's cap.
func TestKeepNoAnswerKeepsNone(t *testing.T) {
	svc, id, fp, cp, lost, _ := keptAnswerSession(t, &sandboxtest.Sessions{}, 4<<20, true)
	if keptAnswerOf(entryOf(t, svc, id)) != nil {
		t.Fatal("keep_no_answer kept an answer")
	}
	if got := attachAcross(t, svc, fp, cp, lost); got.GetLostAnswer() != nil {
		t.Fatal("keep_no_answer returned an answer")
	}
}

// An unanswered call has no answer to keep: the attach across its gap returns its record
// and no answer, not the answer of the call before it.
func TestAnUnansweredCallLeavesNoAnswer(t *testing.T) {
	svc := NewSandboxService(&failingSessions{Sessions: &sandboxtest.Sessions{}, failCall: 2})
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20, KeptAnswerBytes: 4 << 20, KeptAnswersTotalBytes: 64 << 20}
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id, fp := o.Msg.GetSessionId(), o.Msg.GetSession()
	if _, err := headRun(svc, ctx, callReq(id, "1")); err != nil {
		t.Fatal(err)
	}
	if keptAnswerOf(entryOf(t, svc, id)) == nil {
		t.Fatal("the first call's answer was not kept")
	}
	cp := headOf(svc, id)
	call := callReq(id, "2")
	if _, err := headRun(svc, ctx, call); err == nil {
		t.Fatal("the failing call was answered")
	}
	lost := record.SessionRunRequestDigest(call.Msg)
	if keptAnswerOf(entryOf(t, svc, id)) != nil {
		t.Fatal("an answer is kept after an unanswered call")
	}
	got := attachAcross(t, svc, fp, cp, lost)
	if got.GetLostRecord().GetUnanswered() == "" || got.GetLostAnswer() != nil {
		t.Fatalf("the unanswered call's record %v, answer %v", got.GetLostRecord(), got.GetLostAnswer())
	}
}
