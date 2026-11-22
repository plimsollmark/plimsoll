package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The checks of session reattach (R2 of the sessions builds plan), against the shared
// daemons and vectors of internal/clientsuite, which the Python and TypeScript suites
// read too.

const daemonName = "suite-daemon"

func reattachRemote(t *testing.T, url string, opts ...Option) *Remote {
	t.Helper()
	return newRemote(t, url, append([]Option{WithToken(clientsuite.ReattachToken), WithDaemonName(daemonName)}, opts...)...)
}

func cell(code string) sandbox.CellRequest {
	return sandbox.CellRequest{Language: sandbox.LanguagePython, Code: code}
}

// Every valid vector parses, and the JSON this client writes for it parses back to the
// same checkpoint; every invalid vector is refused.
func TestCheckpointVectors(t *testing.T) {
	var v struct {
		Valid, Invalid []struct{ Name, JSON string }
	}
	if err := json.Unmarshal(clientsuite.CheckpointVectors, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Valid {
		cp, err := ParseCheckpoint([]byte(c.JSON))
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		out, err := json.Marshal(cp)
		if err != nil {
			t.Fatal(err)
		}
		if again, err := ParseCheckpoint(out); err != nil || again != cp {
			t.Errorf("%s: written as %s, read back as %+v, %v", c.Name, out, again, err)
		}
	}
	for _, c := range v.Invalid {
		if cp, err := ParseCheckpoint([]byte(c.JSON)); !errors.Is(err, ErrInvalidCheckpoint) {
			t.Errorf("%s: accepted as %+v (%v)", c.Name, cp, err)
		}
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	s, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{MinimumIsolation: sandbox.IsolationContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCell(ctx, cell("x = 1")); err != nil {
		t.Fatal(err)
	}
	cp, err := s.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if cp.Daemon != daemonName || cp.Session != s.Fingerprint() || cp.Generation != 1 || cp.Calls != 1 || cp.LastRecordSHA256 == "" ||
		cp.OpenFloor != "container" || cp.Isolation != "container" || cp.Provider != "fake-sessions" {
		t.Fatalf("checkpoint %+v", cp)
	}
	text, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(text), s.id) || strings.Contains(string(text), clientsuite.ReattachToken) {
		t.Fatalf("the checkpoint carries a secret: %s", text)
	}
	back, err := ParseCheckpoint(text)
	if err != nil || back != cp {
		t.Fatalf("read back %+v, %v", back, err)
	}
}

// A client with no daemon name, and a session stopped, closed or ended, give no checkpoint.
func TestCheckpointRefusedWhenStoppedClosedEnded(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()

	unnamed, err := newRemote(t, d.URL, WithToken(clientsuite.ReattachToken)).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unnamed.Checkpoint(); !errors.Is(err, ErrNoCheckpoint) {
		t.Fatalf("no daemon name: %v", err)
	}

	r := reattachRemote(t, d.URL)
	closed, err := r.OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := closed.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := closed.Checkpoint(); !errors.Is(err, ErrNoCheckpoint) {
		t.Fatalf("closed: %v", err)
	}

	stopped, err := r.OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stopped.RunCell(NewTraceContext(ctx, clientsuite.DropAnswerTrace), cell("1")); err == nil {
		t.Fatal("a dropped answer arrived")
	}
	if _, err := stopped.Checkpoint(); !errors.Is(err, ErrNoCheckpoint) || !errors.Is(err, ErrSessionUnanswered) {
		t.Fatalf("stopped: %v", err)
	}

	ended, err := r.OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	opened := d.Provider.Opened()
	opened[len(opened)-1].End(sandbox.SessionExpired)
	if _, err := ended.RunCell(ctx, cell("1")); !errors.Is(err, sandbox.ErrSessionEnded) {
		t.Fatalf("a call on the ended session: %v", err)
	}
	if _, err := ended.Checkpoint(); !errors.Is(err, ErrNoCheckpoint) || !errors.Is(err, sandbox.ErrSessionEnded) {
		t.Fatalf("ended: %v", err)
	}
}

// A second client attaches from the first's checkpoint and carries on: the same sandbox
// (the interpreter remembers), and its first call's record is the chain's next.
func TestAttachContinuesTheChain(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	a, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"x = 1", "y = 2"} {
		if _, err := a.RunCell(ctx, cell(code)); err != nil {
			t.Fatal(err)
		}
	}
	cp, err := a.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.RunCell(ctx, cell("z = 3"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "python 3: z = 3" {
		t.Fatalf("the attached session's cell answered %q, not the third of the same interpreter", res.Stdout)
	}
	if res.Record.Sequence != cp.Calls+1 || res.Record.PreviousSHA256 != cp.LastRecordSHA256 || res.Record.Session != cp.Session {
		t.Fatalf("record %+v does not follow the checkpoint %+v", res.Record, cp)
	}
	next, err := b.Checkpoint()
	if err != nil || next.Generation != cp.Generation+1 || next.Calls != 3 || next.LastRecordSHA256 != res.Record.SHA256 {
		t.Fatalf("the attached session's checkpoint %+v, %v", next, err)
	}
	sum, err := b.Close(ctx)
	if err != nil || sum.Calls != 3 {
		t.Fatalf("close: %+v, %v", sum, err)
	}
}

// After another worker attached, the first worker's next call is refused before it runs:
// marked not dispatched with reason permission, the provider sees no call, and the
// worker sends nothing more.
func TestStaleWorkerIsRefusedBeforeDispatch(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	a, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := a.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{}); err != nil {
		t.Fatal(err)
	}
	before := d.ProviderCalls()
	_, err = a.RunCell(ctx, cell("1"))
	if reason, marked := sandbox.NotDispatchedReason(err); !errors.Is(err, ErrStaleOwner) || !marked || reason != sandbox.RefusalPermission {
		t.Fatalf("the stale worker's call: %v (marked %v, %v)", err, marked, reason)
	}
	if d.ProviderCalls() != before {
		t.Fatal("the provider ran the stale worker's call")
	}
	if !errors.Is(a.Stopped(), ErrStaleOwner) {
		t.Fatalf("the stale worker is not stopped: %v", a.Stopped())
	}
	if _, err := a.RunCell(ctx, cell("1")); !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("the stale worker's next call: %v", err)
	}
	if _, err := a.Checkpoint(); !errors.Is(err, ErrNoCheckpoint) {
		t.Fatalf("a stale worker gave a checkpoint: %v", err)
	}
}

// A stale worker cannot close the session another worker now holds.
func TestStaleWorkerCannotClose(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	a, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := a.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Close(ctx); !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("the stale worker's close: %v", err)
	}
	if !errors.Is(a.Stopped(), ErrStaleOwner) {
		t.Fatalf("the stale worker is not stopped after its close: %v", a.Stopped())
	}
	if _, err := b.RunCell(ctx, cell("still open")); err != nil {
		t.Fatalf("the session did not survive the stale close: %v", err)
	}
}

// failingHTTP fails the test if anything is sent.
type failingHTTP struct{ t *testing.T }

func (f failingHTTP) Do(req *http.Request) (*http.Response, error) {
	f.t.Errorf("a request was sent: %s", req.URL.Path)
	return nil, errors.New("nothing may be sent")
}

func TestAttachRefusesLocally(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	s, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	invalid := cp
	invalid.Generation = 0
	other := cp
	other.Daemon = "another-daemon"
	silent := WithHTTPClient(failingHTTP{t})
	rec := recorderFunc(func(*plimsollv1.RunRequest, *plimsollv1.RunResponse) error { return nil })
	for name, c := range map[string]struct {
		r    *Remote
		cp   Checkpoint
		want error
	}{
		"an invalid checkpoint":       {reattachRemote(t, d.URL, silent), invalid, ErrInvalidCheckpoint},
		"another daemon's checkpoint": {reattachRemote(t, d.URL, silent), other, ErrInvalidCheckpoint},
		"a client with no name":       {newRemote(t, d.URL, WithToken(clientsuite.ReattachToken), silent), cp, ErrInvalidCheckpoint},
		"a client with a recorder":    {reattachRemote(t, d.URL, silent, WithRecorder(rec)), cp, ErrRecorderCannotAttach},
	} {
		_, err := c.r.AttachSession(ctx, c.cp, AttachOptions{})
		if reason, marked := sandbox.NotDispatchedReason(err); !errors.Is(err, c.want) || !marked || reason != sandbox.RefusalRequest {
			t.Errorf("%s: %v (marked %v, %v)", name, err, marked, reason)
		}
	}
	if _, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{}); err != nil {
		t.Fatalf("the checkpoint was spent by a local refusal: %v", err)
	}
}

// Each forged answer is refused as a broken chain, and no close is sent for the session.
func TestForgedAttachAnswerIsRejectedWithoutClose(t *testing.T) {
	d := clientsuite.ServeAttachLiar(t)
	ctx := context.Background()
	s, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{MinimumIsolation: sandbox.IsolationContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCell(ctx, cell("1")); err != nil {
		t.Fatal(err)
	}
	cp, err := s.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	b := reattachRemote(t, d.URL)
	for _, name := range clientsuite.AttachForgeries {
		_, err := b.AttachSession(NewTraceContext(ctx, "forge-"+name), cp, AttachOptions{})
		if !errors.Is(err, record.ErrChain) || connect.CodeOf(err) != connect.CodeDataLoss {
			t.Errorf("forgery %s: %v", name, err)
		}
	}
	if n := d.Closes(cp.Session); n != 0 {
		t.Fatalf("%d closes were sent for the session", n)
	}
	if _, err := b.AttachSession(NewTraceContext(ctx, "forge-none"), cp, AttachOptions{}); err != nil {
		t.Fatalf("the honest answer was refused: %v", err)
	}
}

// An open answer that states another floor or rule than the open sent is refused, and the
// session it names is closed, as for every refused open.
func TestOpenAnswerMustEchoTheFloorAndRule(t *testing.T) {
	url := clientsuite.ServeLiar(t)
	for _, trace := range []string{"bad-floor", "bad-rule"} {
		_, err := newRemote(t, url).OpenSession(NewTraceContext(context.Background(), trace), SessionOptions{MinimumIsolation: sandbox.IsolationProcess})
		if !errors.Is(err, record.ErrChain) {
			t.Errorf("%s: %v", trace, err)
		}
	}
	if _, err := newRemote(t, url).OpenSession(context.Background(), SessionOptions{MinimumIsolation: sandbox.IsolationProcess}); err != nil {
		t.Fatalf("an honest echo was refused: %v", err)
	}
}

// Two workers attach from one checkpoint at once: exactly one gets the session, the other
// is refused as stale.
func TestTwoAttachesFromOneCheckpoint(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	s, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Go(func() { _, errs[i] = reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{}) })
	}
	wg.Wait()
	ok, stale := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrStaleOwner):
			stale++
		default:
			t.Errorf("attach: %v", err)
		}
	}
	if ok != 1 || stale != 1 {
		t.Fatalf("%d attaches succeeded and %d were stale, want one each", ok, stale)
	}
}

// The daemon ran a call whose answer the client never saw: an attach from the checkpoint
// saved before it is refused as a mismatch, marked not dispatched, and ownership does not
// move.
func TestLostAnswerPreventsAttach(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	a, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := a.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.RunCell(NewTraceContext(ctx, clientsuite.DropAnswerTrace), cell("lost")); err == nil {
		t.Fatal("a dropped answer arrived")
	}
	if d.ProviderCalls() != 1 {
		t.Fatalf("the provider ran %d calls, want the one whose answer was lost", d.ProviderCalls())
	}
	_, err = reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{})
	if reason, marked := sandbox.NotDispatchedReason(err); !errors.Is(err, ErrCheckpointMismatch) || !marked || reason != sandbox.RefusalRequest {
		t.Fatalf("attach after a lost answer: %v (marked %v, %v)", err, marked, reason)
	}
	if errors.Is(err, ErrStaleOwner) {
		t.Fatal("a mismatch reads as stale")
	}
}

// lostAttachHTTP sends every request, and loses the answer to an attach after the daemon
// handled it, counting the attaches sent.
type lostAttachHTTP struct{ attaches atomic.Int32 }

func (l *lostAttachHTTP) Do(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultClient.Do(req)
	if err == nil && strings.HasSuffix(req.URL.Path, "/AttachSession") {
		l.attaches.Add(1)
		_ = resp.Body.Close()
		return nil, errors.New("the connection dropped after the daemon answered")
	}
	return resp, err
}

// An attach whose answer was lost comes back as the transport's error, sent once and never
// again: the daemon raised the generation, so the checkpoint is now stale.
func TestAttachIsNeverRetried(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	s, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	lost := &lostAttachHTTP{}
	_, err = reattachRemote(t, d.URL, WithHTTPClient(lost)).AttachSession(ctx, cp, AttachOptions{})
	if _, marked := sandbox.NotDispatchedReason(err); err == nil || marked {
		t.Fatalf("a lost attach answer: %v (marked %v)", err, marked)
	}
	if n := lost.attaches.Load(); n != 1 {
		t.Fatalf("the attach was sent %d times", n)
	}
	if _, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{}); !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("the lost attach did not move ownership: %v", err)
	}
}
