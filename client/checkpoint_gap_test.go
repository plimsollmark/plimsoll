package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"

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

// Naming the lost call takes the session over across the gap: the attached session is
// recovering, holding the lost call's record and its answer, checked; once resolved it
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
	if lc == nil || lc.RequestSHA256 != lost || lc.Record == nil || lc.Record.RequestSHA256 != lost ||
		lc.Record.Sequence != cp.Calls+1 || lc.Record.PreviousSHA256 != cp.LastRecordSHA256 {
		t.Fatalf("the lost call %+v", lc)
	}
	// The answer the worker that sent the call never got: its output, and its record the
	// lost one.
	if lc.Answer == nil || string(lc.Answer.GetCell().GetStdout()) != "python 2: y = 2" || lc.Answer.GetRecord().GetRecordSha256() != lc.Record.SHA256 {
		t.Fatalf("the lost call's answer %v", lc.Answer)
	}
	b.ResolveLostCall()
	if b.LostCall() != nil {
		t.Fatal("the session is still recovering after ResolveLostCall")
	}
	res, err := b.RunCell(ctx, cell("z = 3"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "python 3: z = 3" || res.Record.Sequence != cp.Calls+2 || res.Record.PreviousSHA256 != lc.Record.SHA256 {
		t.Fatalf("the next call %q, record %+v", res.Stdout, res.Record)
	}
	if sum, err := b.Close(ctx); err != nil || sum.Calls != 3 {
		t.Fatalf("close: %+v, %v", sum, err)
	}
}

// A recovering session refuses every call before it is sent, the lost call's repeat and
// any other alike, with the words every client uses (internal/wiretables copies
// RecoveringText into the Python and TypeScript clients), and the refusals neither stop
// it nor resolve it. Once the application resolves it, calls run, the repeat included:
// running it again is then the application's decision.
func TestARecoveringSessionRefusesEveryCallUntilResolved(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	_, cp, lost := lostCallSession(t, d.URL, sandbox.IsolationUnknown)
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: lost})
	if err != nil {
		t.Fatal(err)
	}
	ran := d.ProviderCalls()
	for _, code := range []string{"y = 2", "w = 0", "y = 2"} {
		_, err = b.RunCell(ctx, cell(code))
		if reason, marked := sandbox.NotDispatchedReason(err); !errors.Is(err, ErrRecovering) || !marked || reason != sandbox.RefusalRequest {
			t.Fatalf("a call while recovering (%s): %v (marked %v, %v)", code, err, marked, reason)
		}
		if !strings.Contains(err.Error(), RecoveringText) {
			t.Fatalf("the refusal's text: %v", err)
		}
	}
	if _, _, err := b.Exchange(ctx, &plimsollv1.RunRequest{Protocol: Protocol, Payload: &plimsollv1.RunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "python", Code: "y = 2"}}}); !errors.Is(err, ErrRecovering) {
		t.Fatalf("an exchange while recovering: %v", err)
	}
	if d.ProviderCalls() != ran {
		t.Fatal("a call ran while recovering")
	}
	if b.Stopped() != nil || b.LostCall() == nil {
		t.Fatalf("the refusals stopped (%v) or resolved the session", b.Stopped())
	}
	// Saving the head does not resolve it either.
	if _, err := b.Checkpoint(); err != nil || b.LostCall() == nil {
		t.Fatalf("the checkpoint: %v; recovering %v", err, b.LostCall() != nil)
	}
	b.ResolveLostCall()
	if _, err := b.RunCell(ctx, cell("y = 2")); err != nil {
		t.Fatalf("the repeat after the session was resolved: %v", err)
	}
}

// A call the daemon refuses with the not-dispatched mark changes nothing of the recovering
// state: it is refused before it is sent, so the daemon never sees it.
func TestRecoveringOutlivesARefusedCall(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	_, cp, lost := lostCallSession(t, d.URL, sandbox.IsolationUnknown)
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: lost})
	if err != nil {
		t.Fatal(err)
	}
	refused := cell("w = 0")
	refused.MinimumIsolation = sandbox.IsolationVM
	if _, err := b.RunCell(ctx, refused); !errors.Is(err, ErrRecovering) {
		t.Fatalf("a call with a floor above the tier while recovering: %v", err)
	}
	if cp2, err := b.Checkpoint(); err != nil || cp2.RecoveringRequestSHA256 != lost || cp2.Calls != cp.Calls+1 {
		t.Fatalf("the checkpoint: %+v, %v", cp2, err)
	}
}

// A checkpoint saved while recovering carries the state to another worker, which knows
// the lost call by its request digest alone and refuses every call until it resolves it;
// a checkpoint saved after that carries none.
func TestACheckpointCarriesTheRecoveringState(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	_, cp, lost := lostCallSession(t, d.URL, sandbox.IsolationUnknown)
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: lost})
	if err != nil {
		t.Fatal(err)
	}
	cp2, err := b.Checkpoint()
	if err != nil || cp2.RecoveringRequestSHA256 != lost || cp2.Calls != cp.Calls+1 {
		t.Fatalf("the checkpoint after the explained attach: %+v, %v", cp2, err)
	}
	c, err := reattachRemote(t, d.URL).AttachSession(ctx, cp2, AttachOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if lc := c.LostCall(); lc == nil || lc.RequestSHA256 != lost || lc.Record != nil || lc.Answer != nil {
		t.Fatalf("the third worker's lost call: %+v", lc)
	}
	ran := d.ProviderCalls()
	if _, err := c.RunCell(ctx, cell("w = 0")); !errors.Is(err, ErrRecovering) || d.ProviderCalls() != ran {
		t.Fatalf("the third worker's call while recovering: %v", err)
	}
	c.ResolveLostCall()
	if _, err := c.RunCell(ctx, cell("w = 0")); err != nil {
		t.Fatal(err)
	}
	cp3, err := c.Checkpoint()
	if err != nil || cp3.RecoveringRequestSHA256 != "" {
		t.Fatalf("the state outlived its resolution: %+v, %v", cp3, err)
	}
}

// A session opened with KeepNoAnswer gets the lost call's record back and no answer.
func TestKeepNoAnswerReturnsTheRecordAlone(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	a, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{KeepNoAnswer: true})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := a.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.RunCell(NewTraceContext(ctx, clientsuite.DropAnswerTrace), cell("y = 2")); err == nil {
		t.Fatal("a dropped answer arrived")
	}
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{LostRequestSHA256: a.LostRequestSHA256()})
	if err != nil {
		t.Fatal(err)
	}
	if lc := b.LostCall(); lc == nil || lc.Record == nil || lc.Record.ResultSHA256 == "" || lc.Answer != nil {
		t.Fatalf("the lost call %+v", lc)
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

// Calls sent at once on one session all run, one after another: each takes its head inside
// the queue that serializes the session's calls, after the call before it has moved it, so
// none is refused for its head.
func TestConcurrentCallsOnOneSessionEachStateTheHead(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	s, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 8)
	for i := 0; i < cap(errs); i++ {
		go func() {
			_, err := s.RunCell(ctx, cell("x = 1"))
			errs <- err
		}()
	}
	for i := 0; i < cap(errs); i++ {
		if err := <-errs; err != nil {
			t.Fatalf("a concurrent call: %v", err)
		}
	}
	if d.ProviderCalls() != cap(errs) {
		t.Fatalf("%d calls ran, want %d", d.ProviderCalls(), cap(errs))
	}
}
