package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The explained gap (option A of the PydanticAI design's section 3.3) in the Go client,
// against the shared reattach daemon and attach liar.

// lostCallSession opens a session at url, runs one cell, saves the checkpoint, and runs a
// second cell whose answer the daemon drops: the checkpoint from before the lost call and
// the lost call's request digest.
func lostCallSession(t *testing.T, url string, floor sandbox.IsolationClass) (*Session, Checkpoint, string) {
	t.Helper()
	ctx := context.Background()
	a, err := reattachRemote(t, url).OpenSession(ctx, SessionOptions{MinimumIsolation: floor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.RunCell(ctx, cell("x = 1")); err != nil {
		t.Fatal(err)
	}
	cp, err := a.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.RunCell(NewTraceContext(ctx, clientsuite.DropAnswerTrace), cell("y = 2")); err == nil {
		t.Fatal("a dropped answer arrived")
	}
	lost := a.LostRequestSHA256()
	if lost == "" {
		t.Fatal("the stopped session names no lost call")
	}
	return a, cp, lost
}

// Naming the lost call takes the session over across the gap: the attached session
// carries the chain on after the lost call's record, in the same interpreter.
func TestExplainedGapCarriesTheChainOn(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	_, cp, lost := lostCallSession(t, d.URL, sandbox.IsolationUnknown)
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: lost})
	if err != nil {
		t.Fatal(err)
	}
	lc := b.LostCall()
	if lc == nil || lc.RequestSHA256 != lost || lc.Sequence != cp.Calls+1 || lc.PreviousSHA256 != cp.LastRecordSHA256 {
		t.Fatalf("the lost call's record %+v", lc)
	}
	res, err := b.RunCell(ctx, cell("z = 3"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "python 3: z = 3" || res.Record.Sequence != cp.Calls+2 || res.Record.PreviousSHA256 != lc.SHA256 {
		t.Fatalf("the next call %q, record %+v", res.Stdout, res.Record)
	}
	if sum, err := b.Close(ctx); err != nil || sum.Calls != 3 {
		t.Fatalf("close: %+v, %v", sum, err)
	}
}

// The first call after the attach is refused, with nothing sent, when it repeats the lost
// call; the note is then spent, so the same call sent again runs.
func TestTheFirstCallMayNotRepeatTheLostCall(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	_, cp, lost := lostCallSession(t, d.URL, sandbox.IsolationUnknown)
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: lost})
	if err != nil {
		t.Fatal(err)
	}
	ran := d.ProviderCalls()
	_, err = b.RunCell(ctx, cell("y = 2"))
	if reason, marked := sandbox.NotDispatchedReason(err); !errors.Is(err, ErrCallAlreadySent) || !marked || reason != sandbox.RefusalRequest {
		t.Fatalf("the repeat: %v (marked %v, %v)", err, marked, reason)
	}
	// The refusal says what the client knows, in the words the Python and TypeScript
	// clients use too (internal/wiretables copies CallAlreadySentText into both, and each
	// suite holds its error to the copy): the call was sent once. The lost call's record
	// says whether it finished (Session.LostCall).
	if !strings.Contains(err.Error(), CallAlreadySentText) || strings.Contains(err.Error(), "ran once") {
		t.Fatalf("the repeat's text: %v", err)
	}
	if d.ProviderCalls() != ran {
		t.Fatal("the repeated call ran")
	}
	if b.Stopped() != nil {
		t.Fatal("the refused repeat stopped the session")
	}
	if _, err := b.RunCell(ctx, cell("y = 2")); err != nil {
		t.Fatalf("the same call after the first: %v", err)
	}
}

// A different first call runs and spends the note: the lost call may be sent after it.
func TestADifferentFirstCallRunsAndSpendsTheNote(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	_, cp, lost := lostCallSession(t, d.URL, sandbox.IsolationUnknown)
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: lost})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.RunCell(ctx, cell("w = 0")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.RunCell(ctx, cell("y = 2")); err != nil {
		t.Fatalf("the lost call after another: %v", err)
	}
}

// A first call the daemon refuses with the not-dispatched mark ran nothing, so it leaves
// the note: a checkpoint saved after it still carries the note, and the lost call sent next
// is refused with nothing sent.
func TestAFirstCallTheDaemonRefusesLeavesTheNote(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	_, cp, lost := lostCallSession(t, d.URL, sandbox.IsolationUnknown)
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: lost})
	if err != nil {
		t.Fatal(err)
	}
	ran := d.ProviderCalls()
	refused := cell("w = 0")
	refused.MinimumIsolation = sandbox.IsolationVM // above the session's tier: refused before it runs
	_, err = b.RunCell(ctx, refused)
	if reason, marked := sandbox.NotDispatchedReason(err); !marked || reason != sandbox.RefusalIsolation {
		t.Fatalf("the refused first call: %v (marked %v, %v)", err, marked, reason)
	}
	if cp2, err := b.Checkpoint(); err != nil || cp2.LostCallSHA256 != lost || cp2.Calls != cp.Calls+1 {
		t.Fatalf("the checkpoint after the refused first call: %+v, %v", cp2, err)
	}
	if _, err := b.RunCell(ctx, cell("y = 2")); !errors.Is(err, ErrCallAlreadySent) {
		t.Fatalf("the lost call after a refused first call: %v", err)
	}
	if d.ProviderCalls() != ran {
		t.Fatal("a call ran")
	}
}

// A checkpoint saved before the first call carries the note to another worker, which
// refuses the repeat too; one saved after it carries none.
func TestACheckpointCarriesTheNoteUntilTheFirstCall(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	_, cp, lost := lostCallSession(t, d.URL, sandbox.IsolationUnknown)
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: lost})
	if err != nil {
		t.Fatal(err)
	}
	cp2, err := b.Checkpoint()
	if err != nil || cp2.LostCallSHA256 != lost || cp2.Calls != cp.Calls+1 {
		t.Fatalf("the checkpoint after the explained attach: %+v, %v", cp2, err)
	}
	c, err := reattachRemote(t, d.URL).AttachSession(ctx, cp2, AttachOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunCell(ctx, cell("y = 2")); !errors.Is(err, ErrCallAlreadySent) {
		t.Fatalf("the third worker's repeat: %v", err)
	}
	cp3, err := c.Checkpoint()
	if err != nil || cp3.LostCallSHA256 != "" {
		t.Fatalf("the note outlived the first call: %+v, %v", cp3, err)
	}
}

// Naming another call than the lost one is the plain mismatch: ownership does not move,
// and naming the right one afterwards still works.
func TestAWrongLostDigestIsAMismatch(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	_, cp, lost := lostCallSession(t, d.URL, sandbox.IsolationUnknown)
	_, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: record.SessionFingerprint("another call")})
	if !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("a wrong digest: %v", err)
	}
	if _, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: "ABC"}); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("a malformed digest: %v", err)
	}
	if _, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: lost}); err != nil {
		t.Fatalf("the refused attaches moved ownership: %v", err)
	}
}

// Each forged explained-gap answer is refused as a broken chain, with no close sent; the
// honest one is taken.
func TestForgedExplainedGapAnswersAreRefused(t *testing.T) {
	d := clientsuite.ServeAttachLiar(t)
	ctx := context.Background()
	a, cp, lost := lostCallSession(t, d.URL, sandbox.IsolationContainer)
	b := reattachRemote(t, d.URL)
	for _, name := range clientsuite.AttachLostForgeries {
		_, err := b.AttachSession(NewTraceContext(ctx, "forge-"+name), cp, AttachOptions{LostRequestSHA256: lost})
		if !errors.Is(err, record.ErrChain) || connect.CodeOf(err) != connect.CodeDataLoss {
			t.Errorf("forgery %s: %v", name, err)
		}
	}
	if n := d.Closes(a.Fingerprint()); n != 0 {
		t.Fatalf("%d closes were sent", n)
	}
	s, err := b.AttachSession(NewTraceContext(ctx, "forge-lost-none"), cp, AttachOptions{LostRequestSHA256: lost})
	if err != nil || s.LostCall() == nil {
		t.Fatalf("the honest explained answer: %v", err)
	}
}
