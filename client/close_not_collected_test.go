package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// verifyAs reads bundle and verifies it under key, accepting a session not proven complete
// (the tests read its report).
func verifyAs(t *testing.T, key ed25519.PrivateKey, bundle []byte) ([]attest.Entry, attest.Report, error) {
	t.Helper()
	entries, err := attest.ReadBundle(bytes.NewReader(bundle))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := attest.VerifyBundle(entries, attest.NewVerifier(key.Public().(ed25519.PublicKey)), attest.AcceptNotProvenComplete)
	return entries, rep, err
}

// Finding hunt-quality-20's own test, through the client and a real daemon handler: a
// session call, then a close the daemon answers NotFound (as after a restart, which
// forgets every session), then a checkpoint. The harness signs that the close could not be
// collected; the bundle verifies with the session reported as not proven complete; a
// resumed harness continues it; and the client sends nothing more on the session.
func TestACloseTheDaemonCannotFindIsSignedAsNotCollected(t *testing.T) {
	url, _ := sessionServer(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var bundle bytes.Buffer
	harness := attest.NewHarness(attest.NewSigner(key), &bundle)
	r := newRemote(t, url, WithRecorder(harness))
	ctx := context.Background()
	s, err := r.OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.RunJavaScript(ctx, sandbox.Request{Code: "console.log(1)"})
	if err != nil {
		t.Fatal(err)
	}
	s.id = "00000000000000000000000000000000" // what a restarted daemon finds: no such session
	sum, err := s.Close(ctx)
	if !errors.Is(err, ErrCloseNotCollected) || connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("close of a session the daemon cannot find: %v; want ErrCloseNotCollected wrapping NotFound", err)
	}
	if sum.Calls != 1 || sum.LastRecordSHA256 != res.Record.SHA256 || sum.Session != s.Fingerprint() {
		t.Fatalf("summary %+v; want the one call this client saw", sum)
	}
	if err := harness.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	entries, rep, err := verifyAs(t, key, bundle.Bytes())
	if err != nil {
		t.Fatalf("the bundle: %v", err)
	}
	if len(rep.Sessions) != 1 || rep.Sessions[0].Closed || rep.Sessions[0].Calls != 1 || rep.Sessions[0].NotCollected.Reason != attest.CloseNotCollectedNotFound {
		t.Fatalf("report %+v; want one session, not closed, 1 call, not found", rep.Sessions)
	}
	var more bytes.Buffer
	resumed, err := attest.ResumeHarness(attest.NewSigner(key), entries, &more)
	if err != nil {
		t.Fatalf("ResumeHarness: %v", err)
	}
	if err := resumed.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyAs(t, key, append(bundle.Bytes(), more.Bytes()...)); err != nil {
		t.Fatalf("the resumed bundle: %v", err)
	}
	// The session has ended for this client: a later close and a later call are refused,
	// not dispatched, and nothing more reaches the bundle.
	n := bundle.Len()
	if _, err := s.Close(ctx); !errors.Is(err, ErrCloseNotCollected) || errors.Is(err, ErrNotRecorded) || !strings.Contains(err.Error(), "its ending is already signed") {
		t.Fatalf("a second close: %v; want it refused before anything is sent", err)
	} else if _, marked := sandbox.NotDispatchedReason(err); !marked {
		t.Fatalf("a second close is not marked not dispatched: %v", err)
	}
	if _, err := s.RunJavaScript(ctx, sandbox.Request{Code: "1"}); !errors.Is(err, ErrCloseNotCollected) {
		t.Fatalf("a call after the signed ending: %v", err)
	}
	if bundle.Len() != n {
		t.Fatal("the bundle grew after the session's signed ending")
	}
	if _, err := s.Checkpoint(); err == nil {
		t.Fatal("a checkpoint of a session whose ending is signed")
	}
}

// otherCall is a call by another holder of s's session ID and credential.
func otherCall(t *testing.T, s *Session, code string) {
	t.Helper()
	req := connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: Protocol, SessionId: s.id,
		Head:    &plimsollv1.SessionCheckpoint{Generation: s.generation, Calls: s.calls, LastRecordSha256: s.last},
		Payload: &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: code}}})
	s.r.auth(req)
	if _, err := s.r.client.SessionRun(context.Background(), req); err != nil {
		t.Fatalf("the other holder's call: %v", err)
	}
}

// otherClose is a close by another holder of s's session ID, returning the daemon's count.
// The daemon then forgets the session, as a restart would, and answers a later close
// NotFound.
func otherClose(t *testing.T, s *Session) uint64 {
	t.Helper()
	req := connect.NewRequest(&plimsollv1.CloseSessionRequest{Protocol: Protocol, SessionId: s.id, Generation: s.generation})
	s.r.auth(req)
	resp, err := s.r.client.CloseSession(context.Background(), req)
	if err != nil {
		t.Fatalf("the other holder's close: %v", err)
	}
	return resp.Msg.GetCalls()
}

// hunt-quality-32 (review 148, its scratch case S2): another holder's call lands between
// two of ours, so our second call comes back numbered after a gap and the client refuses
// it (DataLoss) and stops the session; the other holder closes; our close is NotFound. The
// client caught a call it did not send, so nothing is signed: the close's error says why,
// and the bundle, which holds no ending for the session, fails VerifyBundle as it did
// before the statement existed.
func TestASessionCaughtWithAnotherHoldersCallSignsNothing(t *testing.T) {
	url, _ := sessionServer(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var bundle bytes.Buffer
	harness := attest.NewHarness(attest.NewSigner(key), &bundle)
	ctx := context.Background()
	s, err := newRemote(t, url, WithRecorder(harness)).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunJavaScript(ctx, sandbox.Request{Code: "console.log(1)"}); err != nil {
		t.Fatal(err)
	}
	otherCall(t, s, "console.log('between')")
	// The daemon refuses our call for its head before it runs: the other holder's call
	// moved the head. The client stops the session over it, as over a chain that breaks.
	_, err = s.RunJavaScript(ctx, sandbox.Request{Code: "console.log(2)"})
	if _, marked := sandbox.NotDispatchedReason(err); !errors.Is(err, ErrHeadMismatch) || !marked {
		t.Fatalf("our call after the other holder's: %v; want a head mismatch, not dispatched", err)
	}
	if stopped := s.Stopped(); !errors.Is(stopped, ErrHeadMismatch) || !errors.Is(stopped, record.ErrChain) {
		t.Fatalf("the session after a head mismatch: %v; want it stopped over the chain", stopped)
	}
	if n := otherClose(t, s); n != 2 {
		t.Fatalf("the daemon counted %d calls; want 2", n)
	}
	n := bundle.Len()
	_, err = s.Close(ctx)
	if err == nil || errors.Is(err, ErrCloseNotCollected) || !errors.Is(err, record.ErrChain) || connect.CodeOf(err) != connect.CodeNotFound ||
		!strings.Contains(err.Error(), "nothing was signed") || !strings.Contains(err.Error(), "failed its record or chain check") {
		t.Fatalf("our close: %v; want NotFound, the chain check that stopped the session, and nothing signed", err)
	}
	if bundle.Len() != n {
		t.Fatal("the harness wrote a line for the close")
	}
	if err := harness.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyAs(t, key, bundle.Bytes()); !errors.Is(err, attest.ErrChain) || !strings.Contains(err.Error(), "has no close statement") {
		t.Fatalf("the bundle: %v; want it refused, its session without an ending", err)
	}
}

// hunt-quality-33 (review 148, its scratch case S3): a proxy lets the daemon run our
// second call and then answers 502, as a connection dropped in a restart would; the client
// stops the session knowing the lost call's request digest; the daemon then has no such
// session. The statement names that digest, and the verified report carries it: the call
// that may have run is in the file, though no line holds it.
func TestALostCallIsNamedInTheStatement(t *testing.T) {
	url, _ := sessionServer(t)
	var runs atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, url+r.URL.Path, bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		if err != nil || strings.HasSuffix(r.URL.Path, "/SessionRun") && runs.Add(1) == 2 {
			http.Error(w, "connection reset", http.StatusBadGateway) // the daemon ran it; the answer is lost
			return
		}
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(out)
	}))
	defer proxy.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var bundle bytes.Buffer
	harness := attest.NewHarness(attest.NewSigner(key), &bundle)
	ctx := context.Background()
	s, err := newRemote(t, proxy.URL, WithRecorder(harness)).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunJavaScript(ctx, sandbox.Request{Code: "console.log(1)"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.RunJavaScript(ctx, sandbox.Request{Code: "console.log(2)"})
	if _, marked := sandbox.NotDispatchedReason(err); err == nil || marked || !errors.Is(s.Stopped(), ErrSessionUnanswered) {
		t.Fatalf("the call whose answer was lost: %v (stopped: %v); want an unmarked error and a stopped session", err, s.Stopped())
	}
	lost := s.LostRequestSHA256()
	if lost == "" {
		t.Fatal("the client kept no digest of the lost call")
	}
	if n := otherClose(t, s); n != 2 {
		t.Fatalf("the daemon counted %d calls; want 2, the lost one run", n)
	}
	if _, err := s.Close(ctx); !errors.Is(err, ErrCloseNotCollected) {
		t.Fatalf("our close: %v; want ErrCloseNotCollected", err)
	}
	if err := harness.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	_, rep, err := verifyAs(t, key, bundle.Bytes())
	if err != nil {
		t.Fatalf("the bundle: %v", err)
	}
	got := rep.Sessions[0]
	if got.Calls != 1 || got.NotCollected == nil || got.NotCollected.CallsSeen != 1 || got.NotCollected.UnansweredRequestSHA256 != lost {
		t.Fatalf("report %+v (%+v); want 1 call seen and the lost call's request %s", got, got.NotCollected, lost)
	}
	if u := rep.Unanswered(); len(u) != 1 || u[0] != lost || !strings.Contains(got.NotCollected.Describe(), "(request "+lost+"): it may have run") {
		t.Fatalf("Unanswered %v; the words %q", u, got.NotCollected.Describe())
	}
}

// A close refused because another worker took the session over is signed as not collected
// with the stale-owner reason, and the calls this client saw.
func TestAStaleOwnersCloseIsSignedAsNotCollected(t *testing.T) {
	d := clientsuite.ServeReattach(t)
	ctx := context.Background()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var bundle bytes.Buffer
	harness := attest.NewHarness(attest.NewSigner(key), &bundle)
	a, err := reattachRemote(t, d.URL, WithRecorder(harness)).OpenSession(ctx, SessionOptions{})
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
	b, err := reattachRemote(t, d.URL).AttachSession(ctx, cp, AttachOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.RunCell(ctx, cell("y = 2")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Close(ctx); !errors.Is(err, ErrCloseNotCollected) || !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("the old worker's close: %v; want ErrCloseNotCollected and ErrStaleOwner", err)
	}
	if err := harness.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	_, rep, err := verifyAs(t, key, bundle.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Sessions[0]; got.Closed || got.Calls != 1 || got.NotCollected.Reason != attest.CloseNotCollectedStaleOwner {
		t.Fatalf("report %+v (%+v); want 1 call seen, stale owner", got, got.NotCollected)
	}
	if _, err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

// unavailableClose answers every close Unavailable, with no mark: the close may still be
// collected, so nothing is signed.
type unavailableClose struct{ sessionLiar }

func (*unavailableClose) CloseSession(context.Context, *connect.Request[plimsollv1.CloseSessionRequest]) (*connect.Response[plimsollv1.CloseSessionResponse], error) {
	return nil, connect.NewError(connect.CodeUnavailable, errors.New("the daemon is restarting"))
}

// notFoundUnmarked answers every close NotFound without the daemon's not-dispatched mark,
// as a proxy in front of the daemon might.
type notFoundUnmarked struct{ sessionLiar }

func (*notFoundUnmarked) CloseSession(context.Context, *connect.Request[plimsollv1.CloseSessionRequest]) (*connect.Response[plimsollv1.CloseSessionResponse], error) {
	return nil, connect.NewError(connect.CodeNotFound, errors.New("no route"))
}

// notCollectedCounter is a CloseNotCollectedRecorder that counts what it is handed.
type notCollectedCounter struct {
	fullRecorder
	statements int
}

func (n *notCollectedCounter) RecordCloseNotCollected(string, uint64, string, string, string) error {
	n.statements++
	return nil
}

// Only the daemon's own refusals that no close will ever answer are signed: a close that
// failed any other way (unavailable, an unmarked NotFound) signs nothing, and a close whose
// count differs from the client's chain stays DataLoss, unsigned.
func TestOnlyACloseThatCanNeverBeCollectedIsSigned(t *testing.T) {
	for name, h := range map[string]plimsollv1connect.SandboxServiceHandler{
		"unavailable":        &unavailableClose{},
		"an unmarked 404":    &notFoundUnmarked{},
		"a mismatched count": &sessionLiar{closeCalls: 7},
	} {
		rec := &notCollectedCounter{}
		mux := http.NewServeMux()
		path, handler := rpc.NewHandler(h)
		mux.Handle(path, handler)
		srv := httptest.NewServer(mux)
		s, err := newRemote(t, srv.URL, WithRecorder(rec)).OpenSession(context.Background(), SessionOptions{})
		if err != nil {
			srv.Close()
			t.Fatalf("%s: %v", name, err)
		}
		_, err = s.Close(context.Background())
		srv.Close()
		if err == nil || errors.Is(err, ErrCloseNotCollected) || rec.statements != 0 || rec.closes.Load() != 0 {
			t.Errorf("%s: %v, %d statements, %d closes signed; want an error, nothing signed", name, err, rec.statements, rec.closes.Load())
		}
	}
}

// closeCounter is an HTTP client that counts the CloseSession requests it sends.
type closeCounter struct{ n atomic.Int32 }

func (c *closeCounter) Do(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/CloseSession") {
		c.n.Add(1)
	}
	return http.DefaultClient.Do(r)
}

// Finding hunt-quality-97, through the client, a real daemon handler and the harness:
// another holder's call lands after ours, so our close finds a count it did not see
// (DataLoss) and signs nothing. A second close, as a deferred Close after an explicit one
// makes, returns the same summary and error and sends nothing, so the harness never signs
// that the close could not be collected, and the bundle, with no ending for the session,
// is refused even when a session not proven complete is accepted.
func TestASecondCloseAfterACaughtCallKeepsTheBundleRefused(t *testing.T) {
	url, _ := sessionServer(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var bundle bytes.Buffer
	harness := attest.NewHarness(attest.NewSigner(key), &bundle)
	wire := &closeCounter{}
	ctx := context.Background()
	s, err := newRemote(t, url, WithRecorder(harness), WithHTTPClient(wire)).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunJavaScript(ctx, sandbox.Request{Code: "console.log(1)"}); err != nil {
		t.Fatal(err)
	}
	otherCall(t, s, "console.log('not ours')")
	first, err1 := s.Close(ctx)
	if connect.CodeOf(err1) != connect.CodeDataLoss || !errors.Is(err1, record.ErrChain) || first.Calls != 2 {
		t.Fatalf("our close: %+v, %v; want the daemon's count of 2 and DataLoss wrapping record.ErrChain", first, err1)
	}
	n := bundle.Len()
	second, err2 := s.Close(ctx)
	if second != first || err2 != err1 {
		t.Fatalf("a second close: %+v, %v; want the first close's %+v, %v", second, err2, first, err1)
	}
	if got := wire.n.Load(); got != 1 {
		t.Fatalf("%d closes on the wire; want 1", got)
	}
	if bundle.Len() != n {
		t.Fatal("the harness wrote a line for the second close")
	}
	if err := harness.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyAs(t, key, bundle.Bytes()); !errors.Is(err, attest.ErrChain) || !strings.Contains(err.Error(), "has no close statement") {
		t.Fatalf("the bundle: %v; want it refused, its session without an ending", err)
	}
}

// After a close that succeeded, a second close returns the first summary, with no error and
// one close on the wire, and the bundle verifies with the session closed.
func TestASecondCloseAfterAGoodOneReturnsTheFirstSummary(t *testing.T) {
	url, _ := sessionServer(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var bundle bytes.Buffer
	harness := attest.NewHarness(attest.NewSigner(key), &bundle)
	wire := &closeCounter{}
	ctx := context.Background()
	s, err := newRemote(t, url, WithRecorder(harness), WithHTTPClient(wire)).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunJavaScript(ctx, sandbox.Request{Code: "console.log(1)"}); err != nil {
		t.Fatal(err)
	}
	first, err := s.Close(ctx)
	if err != nil || first.Calls != 1 {
		t.Fatalf("our close: %+v, %v", first, err)
	}
	second, err := s.Close(ctx)
	if err != nil || second != first {
		t.Fatalf("a second close: %+v, %v; want the first summary %+v and no error", second, err, first)
	}
	if got := wire.n.Load(); got != 1 {
		t.Fatalf("%d closes on the wire; want 1", got)
	}
	if err := harness.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if _, rep, err := verifyAs(t, key, bundle.Bytes()); err != nil || len(rep.Sessions) != 1 || !rep.Sessions[0].Closed {
		t.Fatalf("the bundle: %+v, %v; want one closed session", rep.Sessions, err)
	}
}

// A close that got no answer is sent again: the first close's answer is lost in transit
// (the proxy answers 502 after the daemon closed the session, as a dropped connection
// would), so the second close is sent, and the daemon, which holds the session no longer,
// answers NotFound.
func TestACloseWithNoAnswerIsSentAgain(t *testing.T) {
	url, _ := sessionServer(t)
	wire := &closeCounter{}
	var lose atomic.Bool
	lose.Store(true)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, url+r.URL.Path, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if strings.HasSuffix(r.URL.Path, "/CloseSession") && lose.Swap(false) {
			http.Error(w, "connection reset", http.StatusBadGateway)
			return
		}
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(out)
	}))
	defer proxy.Close()
	ctx := context.Background()
	s, err := newRemote(t, proxy.URL, WithHTTPClient(wire)).OpenSession(ctx, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Close(ctx); err == nil || connect.CodeOf(err) == connect.CodeNotFound {
		t.Fatalf("the close whose answer was lost: %v; want an error that is not the daemon's", err)
	}
	if _, err := s.Close(ctx); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("the close sent again: %v; want the daemon's NotFound", err)
	}
	if got := wire.n.Load(); got != 2 {
		t.Fatalf("%d closes on the wire; want 2", got)
	}
}
