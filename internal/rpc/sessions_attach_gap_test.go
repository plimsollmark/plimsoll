package rpc

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The explained gap (option A of the PydanticAI design's section 3.3, decided by the main
// session on 2026-11-18): an attach from a checkpoint exactly one call behind the head is
// taken over only when the caller names that call's request digest and the session's last
// record is that call, following the checkpoint; the record comes back. Any other gap is a
// mismatch and moves nothing.

func lostAttachReq(fingerprint string, generation, calls uint64, last, lost string) *connect.Request[plimsollv1.AttachSessionRequest] {
	r := attachReq(fingerprint, generation, calls, last)
	r.Msg.LostRequestSha256 = lost
	return r
}

// A session with one answered call: the open, the call's record, and the request of a
// second call, run and "lost", with its answer's record.
func sessionWithALostCall(t *testing.T) (svc *SandboxService, id, fp string, first, lost *plimsollv1.RunRecord, lostReq *plimsollv1.SessionRunRequest) {
	t.Helper()
	svc, _ = sessionService()
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id, fp = o.Msg.GetSessionId(), o.Msg.GetSession()
	a, err := headRun(svc, ctx, callReq(id, "1"))
	if err != nil {
		t.Fatal(err)
	}
	call := callReq(id, "2")
	b, err := headRun(svc, ctx, call)
	if err != nil {
		t.Fatal(err)
	}
	return svc, id, fp, a.Msg.GetRun().GetRecord(), b.Msg.GetRun().GetRecord(), call.Msg
}

func TestExplainedGapAttachReturnsTheLostCall(t *testing.T) {
	svc, id, fp, first, lost, lostReq := sessionWithALostCall(t)
	var log bytes.Buffer
	svc.Logger = slog.New(slog.NewJSONHandler(&log, nil))
	ctx := authenticatedContext("alice")
	got, err := svc.AttachSession(ctx, lostAttachReq(fp, 1, 1, first.GetRecordSha256(), record.SessionRunRequestDigest(lostReq)))
	if err != nil {
		t.Fatal(err)
	}
	head := got.Msg.GetCheckpoint()
	if head.GetGeneration() != 2 || head.GetCalls() != 2 || head.GetLastRecordSha256() != lost.GetRecordSha256() {
		t.Fatalf("head %v after an explained gap", head)
	}
	if !proto.Equal(got.Msg.GetLostRecord(), lost) {
		t.Fatalf("the lost record %v is not the call's %v", got.Msg.GetLostRecord(), lost)
	}
	next := callReq(id, "3")
	atGeneration(svc, next.Msg, 2)
	if _, err := headRun(svc, ctx, next); err != nil {
		t.Fatalf("the attached worker's next call: %v", err)
	}
	if !strings.Contains(log.String(), `"explained_gap":true`) || strings.Contains(log.String(), lost.GetRequestSha256()) || strings.Contains(log.String(), id) {
		t.Fatalf("the attach's audit line: %s", log.String())
	}
}

// The lost call may be one the daemon answered unanswered: its record is the one kept.
func TestExplainedGapForAnUnansweredCall(t *testing.T) {
	svc, p := sessionService()
	svc.Sandbox = &failingSessions{Sessions: p, failCall: 1}
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	call := callReq(o.Msg.GetSessionId(), "1")
	_, err = headRun(svc, ctx, call)
	var ce *connect.Error
	var unanswered *plimsollv1.RunRecord
	if errors.As(err, &ce) {
		for _, d := range ce.Details() {
			if v, _ := d.Value(); v != nil {
				if u, ok := v.(*plimsollv1.UnansweredCall); ok {
					unanswered = u.GetRecord()
				}
			}
		}
	}
	if unanswered == nil {
		t.Fatalf("no unanswered record: %v", err)
	}
	got, err := svc.AttachSession(ctx, lostAttachReq(o.Msg.GetSession(), 1, 0, "", record.SessionRunRequestDigest(call.Msg)))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got.Msg.GetLostRecord(), unanswered) {
		t.Fatal("the lost record is not the unanswered call's")
	}
}

// Every gap the rule does not explain is a mismatch, and the session stays at generation
// 1 with its head: the exact head attaches afterwards at generation 2.
func TestAnUnexplainedGapNeverMovesOwnership(t *testing.T) {
	for name, attach := range map[string]func(fp string, first, lost *plimsollv1.RunRecord, lostDigest string) *connect.Request[plimsollv1.AttachSessionRequest]{
		"no digest named": func(fp string, first, _ *plimsollv1.RunRecord, _ string) *connect.Request[plimsollv1.AttachSessionRequest] {
			return lostAttachReq(fp, 1, 1, first.GetRecordSha256(), "")
		},
		"another call's digest": func(fp string, first, _ *plimsollv1.RunRecord, _ string) *connect.Request[plimsollv1.AttachSessionRequest] {
			return lostAttachReq(fp, 1, 1, first.GetRecordSha256(), first.GetRequestSha256())
		},
		"a made-up digest": func(fp string, first, _ *plimsollv1.RunRecord, _ string) *connect.Request[plimsollv1.AttachSessionRequest] {
			return lostAttachReq(fp, 1, 1, first.GetRecordSha256(), record.SessionFingerprint("no such call"))
		},
		"two calls behind": func(fp string, _, _ *plimsollv1.RunRecord, lostDigest string) *connect.Request[plimsollv1.AttachSessionRequest] {
			return lostAttachReq(fp, 1, 0, "", lostDigest)
		},
		"one behind, another last record": func(fp string, _, _ *plimsollv1.RunRecord, lostDigest string) *connect.Request[plimsollv1.AttachSessionRequest] {
			return lostAttachReq(fp, 1, 1, record.SessionFingerprint("another record"), lostDigest)
		},
		"one ahead": func(fp string, _, lost *plimsollv1.RunRecord, lostDigest string) *connect.Request[plimsollv1.AttachSessionRequest] {
			return lostAttachReq(fp, 1, 3, lost.GetRecordSha256(), lostDigest)
		},
		"the right last record with another count": func(fp string, first, _ *plimsollv1.RunRecord, lostDigest string) *connect.Request[plimsollv1.AttachSessionRequest] {
			return lostAttachReq(fp, 1, 5, first.GetRecordSha256(), lostDigest)
		},
	} {
		t.Run(name, func(t *testing.T) {
			svc, _, fp, first, lost, lostReq := sessionWithALostCall(t)
			ctx := authenticatedContext("alice")
			_, err := svc.AttachSession(ctx, attach(fp, first, lost, record.SessionRunRequestDigest(lostReq)))
			requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalRequest)
			if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), textCheckpointMismatch) {
				t.Fatalf("not the mismatch refusal: %v", err)
			}
			got, err := svc.AttachSession(ctx, attachReq(fp, 1, 2, lost.GetRecordSha256()))
			if err != nil || got.Msg.GetCheckpoint().GetGeneration() != 2 || got.Msg.GetLostRecord() != nil {
				t.Fatalf("the refused attach moved ownership: %v, %v", got, err)
			}
		})
	}
}

// A digest named with the exact head (the pending call never ran) attaches as usual, with
// no lost record.
func TestANamedDigestWithTheExactHeadAttachesPlainly(t *testing.T) {
	svc, _, fp, _, lost, _ := sessionWithALostCall(t)
	got, err := svc.AttachSession(authenticatedContext("alice"), lostAttachReq(fp, 1, 2, lost.GetRecordSha256(), record.SessionFingerprint("never sent")))
	if err != nil || got.Msg.GetLostRecord() != nil || got.Msg.GetCheckpoint().GetCalls() != 2 {
		t.Fatalf("%v, %v", got, err)
	}
}

func TestAMalformedLostDigestIsAnInvalidRequest(t *testing.T) {
	svc, _, fp, first, _, _ := sessionWithALostCall(t)
	for _, bad := range []string{"abc", strings.ToUpper(record.SessionFingerprint("x")), record.SessionFingerprint("x") + "0"} {
		_, err := svc.AttachSession(authenticatedContext("alice"), lostAttachReq(fp, 1, 1, first.GetRecordSha256(), bad))
		requireAttachRefusal(t, err, connect.CodeInvalidArgument, sandbox.RefusalRequest)
	}
}

// Two explained attaches from one checkpoint: exactly one moves ownership.
func TestTwoExplainedAttachesFromOneCheckpoint(t *testing.T) {
	svc, _, fp, first, _, lostReq := sessionWithALostCall(t)
	ctx := authenticatedContext("alice")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Go(func() {
			_, errs[i] = svc.AttachSession(ctx, lostAttachReq(fp, 1, 1, first.GetRecordSha256(), record.SessionRunRequestDigest(lostReq)))
		})
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
			continue
		}
		requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalPermission)
	}
	if ok != 1 {
		t.Fatalf("%d explained attaches succeeded: %v", ok, errs)
	}
}

// The explained gap does not lift the generation rule: a stale generation is stale.
func TestAnExplainedGapFromAStaleGenerationIsStale(t *testing.T) {
	svc, _, fp, first, lost, lostReq := sessionWithALostCall(t)
	ctx := authenticatedContext("alice")
	if _, err := svc.AttachSession(ctx, attachReq(fp, 1, 2, lost.GetRecordSha256())); err != nil {
		t.Fatal(err)
	}
	_, err := svc.AttachSession(ctx, lostAttachReq(fp, 1, 1, first.GetRecordSha256(), record.SessionRunRequestDigest(lostReq)))
	requireAttachRefusal(t, err, connect.CodeFailedPrecondition, sandbox.RefusalPermission)
}
