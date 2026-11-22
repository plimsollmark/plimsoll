package clientsuite

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
)

func authed[T any](msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+ReattachToken)
	return req
}

// The liar's honest answer (forge-none) is exactly what the real handler answers for the
// same checkpoint, so every forgery differs from a real answer in its one field and no
// other; and each named forgery does change the answer.
func TestAttachLiarForgesFromTheHonestAnswer(t *testing.T) {
	d := ServeAttachLiar(t)
	c := plimsollv1connect.NewSandboxServiceClient(http.DefaultClient, d.URL)
	ctx := context.Background()
	open, err := c.OpenSession(ctx, authed(&plimsollv1.OpenSessionRequest{Protocol: protocol.Number, MinimumIsolation: "container"}))
	if err != nil {
		t.Fatal(err)
	}
	call := cellCall(open.Msg.GetSessionId(), "x = 1", "")
	call.MinimumIsolation = "container" // every call states the floor set at open
	ran, err := c.SessionRun(ctx, authed(call))
	if err != nil {
		t.Fatal(err)
	}
	req := &plimsollv1.AttachSessionRequest{Protocol: protocol.Number, Session: open.Msg.GetSession(),
		Checkpoint: &plimsollv1.SessionCheckpoint{Generation: open.Msg.GetGeneration(), Calls: 1, LastRecordSha256: ran.Msg.GetRun().GetRecord().GetRecordSha256()}}
	honest := d.Forge(req, "none")
	for _, name := range AttachForgeries {
		if forged := d.Forge(req, name); forged == nil || proto.Equal(forged, honest) {
			t.Errorf("forgery %s changes nothing", name)
		}
	}
	real, err := c.AttachSession(ctx, authed(req))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(real.Msg, honest) {
		t.Fatalf("the honest forgery differs from the real answer:\n%v\n%v", honest, real.Msg)
	}
	if d.Closes(open.Msg.GetSession()) != 0 {
		t.Fatal("a close was counted that nobody sent")
	}
}

func cellCall(id, code, trace string) *plimsollv1.SessionRunRequest {
	return &plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: id, Generation: 1, TraceId: trace,
		Payload: &plimsollv1.SessionRunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "python", Code: code}}}
}

// The liar's honest explained-gap answer (forge-lost-none) is exactly what the real handler
// answers an attach one call behind that names the lost call, and each named forgery of it
// changes the answer.
func TestAttachLiarForgesTheExplainedGapFromTheHonestAnswer(t *testing.T) {
	d := ServeAttachLiar(t)
	c := plimsollv1connect.NewSandboxServiceClient(http.DefaultClient, d.URL)
	ctx := context.Background()
	open, err := c.OpenSession(ctx, authed(&plimsollv1.OpenSessionRequest{Protocol: protocol.Number}))
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.SessionRun(ctx, authed(cellCall(open.Msg.GetSessionId(), "x = 1", "")))
	if err != nil {
		t.Fatal(err)
	}
	lostCall := cellCall(open.Msg.GetSessionId(), "y = 2", DropAnswerTrace)
	if _, err := c.SessionRun(ctx, authed(lostCall)); err == nil {
		t.Fatal("a dropped answer arrived")
	}
	req := &plimsollv1.AttachSessionRequest{Protocol: protocol.Number, Session: open.Msg.GetSession(),
		Checkpoint:        &plimsollv1.SessionCheckpoint{Generation: 1, Calls: 1, LastRecordSha256: first.Msg.GetRun().GetRecord().GetRecordSha256()},
		LostRequestSha256: record.SessionRunRequestDigest(lostCall)}
	honest := d.Forge(req, "lost-none")
	if honest == nil || honest.GetLostRecord() == nil {
		t.Fatal("no honest explained-gap answer")
	}
	for _, name := range AttachLostForgeries {
		if forged := d.Forge(req, name); forged == nil || proto.Equal(forged, honest) {
			t.Errorf("forgery %s changes nothing", name)
		}
	}
	real, err := c.AttachSession(ctx, authed(req))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(real.Msg, honest) {
		t.Fatalf("the honest explained-gap forgery differs from the real answer:\n%v\n%v", honest, real.Msg)
	}
}

// A session call carrying the drop-answer trace ID runs on the provider, and its caller
// gets no answer.
func TestReattachDaemonRunsADroppedCall(t *testing.T) {
	d := ServeReattach(t)
	c := plimsollv1connect.NewSandboxServiceClient(http.DefaultClient, d.URL)
	ctx := context.Background()
	open, err := c.OpenSession(ctx, authed(&plimsollv1.OpenSessionRequest{Protocol: protocol.Number}))
	if err != nil {
		t.Fatal(err)
	}
	call := &plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: open.Msg.GetSessionId(), Generation: 1, TraceId: DropAnswerTrace,
		Payload: &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
	if _, err := c.SessionRun(ctx, authed(call)); err == nil || connect.CodeOf(err) != connect.CodeUnavailable && connect.CodeOf(err) != connect.CodeUnknown {
		t.Fatalf("a dropped answer arrived: %v", err)
	}
	if d.ProviderCalls() != 1 {
		t.Fatalf("the provider ran %d calls, want the dropped one", d.ProviderCalls())
	}
	call.TraceId = ""
	if _, err := c.SessionRun(ctx, authed(call)); err != nil {
		t.Fatal(err)
	}
	if d.ProviderCalls() != 2 {
		t.Fatalf("the provider ran %d calls, want 2", d.ProviderCalls())
	}
}

// The vectors parse as the file says: at least one of each, every text named once.
func TestCheckpointVectorsAreWellFormed(t *testing.T) {
	var v struct {
		Valid, Invalid []struct{ Name, JSON string }
	}
	if err := json.Unmarshal(CheckpointVectors, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Valid) == 0 || len(v.Invalid) == 0 {
		t.Fatal("no vectors")
	}
	var names []string
	for _, c := range append(v.Valid, v.Invalid...) {
		if c.Name == "" || c.JSON == "" || slices.Contains(names, c.Name) {
			t.Errorf("vector %q: a vector needs a name of its own and a text", c.Name)
		}
		names = append(names, c.Name)
	}
}
