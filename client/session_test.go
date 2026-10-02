package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// sessionServer is a real daemon handler over the fake session provider.
func sessionServer(t *testing.T) (string, *sandboxtest.Sessions) {
	t.Helper()
	p := &sandboxtest.Sessions{}
	svc := rpc.NewSandboxService(p)
	svc.Sessions = rpc.SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute}
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, p
}

// A session's calls, recorded by the harness through the client, form a bundle
// that verifies: every record signed, chained, and closed with the daemon's count.
func TestSessionThroughTheClientVerifiesAsABundle(t *testing.T) {
	url, _ := sessionServer(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var bundle bytes.Buffer
	r := newRemote(t, url, WithRecorder(attest.NewHarness(attest.NewSigner(key), &bundle)))
	info, err := r.Describe(context.Background())
	if err != nil || !info.SupportsSessions || info.SessionLifetime != time.Minute {
		t.Fatalf("describe: %+v, %v", info, err)
	}
	s, err := r.OpenSession(context.Background(), SessionOptions{MinimumIsolation: sandbox.IsolationContainer})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		res, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "console.log(1)"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Stdout) != i || res.Record == nil || res.Record.Sequence != uint64(i) || res.Record.Session != s.Fingerprint() {
			t.Fatalf("call %d: %+v", i, res)
		}
	}
	if _, err := s.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	// Two cells, the second with a file: each is checked and chained like any call.
	for i, c := range []sandbox.CellRequest{
		{Language: sandbox.LanguagePython, Code: "x = 1"},
		{Language: sandbox.LanguagePython, Code: "x + 1", Files: []sandbox.File{{Path: "in/a.csv", Content: "a,b"}}},
	} {
		res, err := s.RunCell(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("python %d: %s", i+1, c.Code)
		if res.Stdout != want || res.InterpreterStarted != (i == 0) || res.Record == nil || res.Record.Sequence != uint64(5+i) {
			t.Fatalf("cell %d: %+v", i+1, res)
		}
	}
	sum, err := s.Close(context.Background())
	if err != nil || sum.Calls != 6 || sum.End != sandbox.SessionClosed {
		t.Fatalf("close: %+v, %v", sum, err)
	}
	entries, err := attest.ReadBundle(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := attest.VerifyBundle(entries, attest.NewVerifier(key.Public().(ed25519.PublicKey)))
	if err != nil || len(rep.Sessions) != 1 || rep.Sessions[0].Calls != 6 {
		t.Fatalf("bundle: %+v, %v", rep, err)
	}
}

func TestClientOpenSessionRestoresSoftwareMismatch(t *testing.T) {
	url, p := sessionServer(t) // the fake session provider states no software identity
	rule := sandbox.SoftwareRule{Mode: sandbox.SoftwareExact, Identities: []string{"oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64)}}
	_, err := newRemote(t, url).OpenSession(context.Background(), SessionOptions{Software: rule})
	if !errors.Is(err, sandbox.ErrSoftwareMismatch) {
		t.Fatalf("open mismatch lost its typed error: %v", err)
	}
	if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalEnvironment {
		t.Fatalf("open mismatch lost its environment refusal: %v, %v", reason, ok)
	}
	if len(p.Opened()) != 0 {
		t.Fatal("a mismatched OpenSession reached the provider")
	}
}

// A language hint travels to the provider without repeats, and a hint naming a
// language plimsoll does not know is refused before anything is sent.
func TestClientOpenSessionSendsTheLanguageHint(t *testing.T) {
	url, p := sessionServer(t)
	r := newRemote(t, url)
	s, err := r.OpenSession(context.Background(), SessionOptions{Languages: []sandbox.Language{sandbox.LanguagePython, sandbox.LanguagePython}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	if got := p.Opened()[0].Options.Languages; !slices.Equal(got, []sandbox.Language{sandbox.LanguagePython}) {
		t.Fatalf("the provider was asked for languages %v; want python", got)
	}
	_, err = r.OpenSession(context.Background(), SessionOptions{Languages: []sandbox.Language{"cobol"}})
	if reason, ok := sandbox.NotDispatchedReason(err); !errors.Is(err, sandbox.ErrInvalidRequest) || !ok || reason != sandbox.RefusalRequest {
		t.Fatalf("an unknown language: %v; want a request refusal", err)
	}
	if len(p.Opened()) != 1 {
		t.Fatal("a hint naming an unknown language reached the daemon")
	}
}

// A call made by another holder of the session ID shows as a gap in the chain at
// this client's next call, and in the close's count.
func TestSessionClientCatchesACallItDidNotMake(t *testing.T) {
	url, _ := sessionServer(t)
	r := newRemote(t, url)
	s, err := r.OpenSession(context.Background(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	// The other holder's call executes; it sees a chain it did not start, too.
	other := &Session{r: r, id: s.id, fingerprint: s.fingerprint}
	if _, err := other.RunJavaScript(context.Background(), sandbox.Request{Code: "2"}); !errors.Is(err, record.ErrChain) {
		t.Fatalf("the other holder's call: %v", err)
	}
	_, err = s.RunJavaScript(context.Background(), sandbox.Request{Code: "3"})
	if connect.CodeOf(err) != connect.CodeDataLoss || !errors.Is(err, record.ErrChain) {
		t.Fatalf("the call after a foreign one: %v", err)
	}
	if _, err := s.Close(context.Background()); !errors.Is(err, record.ErrChain) {
		t.Fatalf("the close after a foreign call: %v", err)
	}
}

// An ended session's refusal comes back as the sandbox package's typed end, marked
// not dispatched, exactly as a local session reports it.
func TestSessionEndCrossesTheWireTyped(t *testing.T) {
	url, p := sessionServer(t)
	s, err := newRemote(t, url).OpenSession(context.Background(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p.Opened()[0].End(sandbox.SessionDiskExceeded)
	_, err = s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if !errors.Is(err, sandbox.ErrSessionEnded) || sandbox.SessionEndReason(err) != sandbox.SessionDiskExceeded {
		t.Fatalf("a call on an ended session: %v", err)
	}
	if r, ok := sandbox.NotDispatchedReason(err); !ok || r != sandbox.RefusalRequest {
		t.Fatalf("not marked as not dispatched: %v", err)
	}
	if sandbox.SessionEndReason(s.Ended()) != sandbox.SessionDiskExceeded {
		t.Fatalf("Ended: %v", s.Ended())
	}
	sum, err := s.Close(context.Background())
	if err != nil || sum.End != sandbox.SessionDiskExceeded || sum.Calls != 0 {
		t.Fatalf("close after the end: %+v, %v", sum, err)
	}
}

// lossyHTTP drops the answer to every SessionRun while drop is set, after the daemon
// handled it: a dropped connection, a proxy's error, a lost reply.
type lossyHTTP struct{ drop atomic.Bool }

func (l *lossyHTTP) Do(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultClient.Do(req)
	if err == nil && l.drop.Load() && strings.HasSuffix(req.URL.Path, "/SessionRun") {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, errors.New("the connection dropped after the daemon answered")
	}
	return resp, err
}

// A call that ended without an answer may have run, so the session refuses every
// later call before sending it, marked not dispatched, instead of sending calls that
// would run and then fail the chain check.
func TestSessionSendsNothingAfterAnUnansweredCall(t *testing.T) {
	url, p := sessionServer(t)
	lossy := &lossyHTTP{}
	r := newRemote(t, url, WithHTTPClient(lossy))
	s, err := r.OpenSession(context.Background(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	lossy.drop.Store(true)
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "2"}); err == nil {
		t.Fatal("the call whose answer was dropped succeeded")
	}
	lossy.drop.Store(false)
	_, err = s.RunJavaScript(context.Background(), sandbox.Request{Code: "3"})
	if reason, marked := sandbox.NotDispatchedReason(err); !errors.Is(err, ErrSessionUnanswered) || !marked || reason != sandbox.RefusalRequest {
		t.Fatalf("the call after an unanswered one: %v; want ErrSessionUnanswered, marked request", err)
	}
	if n := p.Opened()[0].Calls(); n != 2 {
		t.Fatalf("the daemon ran %d calls, want 2: the refused call was sent", n)
	}
}

// recordingHTTP keeps every SessionRun request the client sends.
type recordingHTTP struct {
	mu   sync.Mutex
	runs []*plimsollv1.SessionRunRequest
}

func (h *recordingHTTP) Do(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/SessionRun") {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		m := &plimsollv1.SessionRunRequest{}
		if err := proto.Unmarshal(body, m); err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.runs = append(h.runs, m)
		h.mu.Unlock()
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	return http.DefaultClient.Do(req)
}

// The floor given at open goes with every call, the stronger of it and the call's
// own, so a call never asks for less than the session was opened with.
func TestSessionCallsCarryTheSessionFloor(t *testing.T) {
	url, _ := sessionServer(t)
	rec := &recordingHTTP{}
	r := newRemote(t, url, WithHTTPClient(rec))
	s, err := r.OpenSession(context.Background(), SessionOptions{MinimumIsolation: sandbox.IsolationContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	if got := rec.runs[0].GetMinimumIsolation(); got != "container" {
		t.Fatalf("the call's floor on the wire: %q; want the session's, container", got)
	}
}

// fingerprintLiar opens sessions whose fingerprint is not their ID's, and counts the
// closes it receives.
type fingerprintLiar struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
	closes atomic.Int32
}

func (*fingerprintLiar) OpenSession(context.Context, *connect.Request[plimsollv1.OpenSessionRequest]) (*connect.Response[plimsollv1.OpenSessionResponse], error) {
	return connect.NewResponse(&plimsollv1.OpenSessionResponse{SessionId: "00112233445566778899aabbccddeeff", Session: "not-its-fingerprint", Isolation: "container"}), nil
}

func (l *fingerprintLiar) CloseSession(context.Context, *connect.Request[plimsollv1.CloseSessionRequest]) (*connect.Response[plimsollv1.CloseSessionResponse], error) {
	l.closes.Add(1)
	return connect.NewResponse(&plimsollv1.CloseSessionResponse{}), nil
}

// A session whose fingerprint does not match its ID is refused, and closed first: it
// exists on the daemon either way, and nothing else holds its ID.
func TestSessionFingerprintMismatchClosesTheSession(t *testing.T) {
	liar := &fingerprintLiar{}
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(liar)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	_, err := newRemote(t, srv.URL).OpenSession(context.Background(), SessionOptions{})
	if connect.CodeOf(err) != connect.CodeDataLoss {
		t.Fatalf("a mismatched fingerprint: %v; want DataLoss", err)
	}
	if n := liar.closes.Load(); n != 1 {
		t.Fatalf("the session was closed %d times; want 1", n)
	}
}

// breakingSessions opens fake sessions whose second snippet call runs (the fake
// counts it) and then returns an unmarked error, as an exec stream that broke after
// the code ran does.
type breakingSessions struct{ *sandboxtest.Sessions }

func (p *breakingSessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &breakingSession{Session: s}, nil
}

type breakingSession struct {
	sandbox.Session
	n int
}

func (s *breakingSession) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	res, err := s.Session.RunJavaScript(ctx, req)
	if s.n++; s.n == 2 {
		return res, errors.New("the exec stream broke after the code ran")
	}
	return res, err
}

// A session call that may have run but ended in an error is in the chain: the client
// checks the record the daemon sends with the error, the session goes on, the harness
// signs it, and the bundle verifies with the close counting every call that ran.
func TestUnansweredCallIsSignedAndTheSessionGoesOn(t *testing.T) {
	p := &breakingSessions{Sessions: &sandboxtest.Sessions{}}
	svc := rpc.NewSandboxService(p)
	svc.Sessions = rpc.SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute}
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var bundle bytes.Buffer
	r := newRemote(t, srv.URL, WithRecorder(attest.NewHarness(attest.NewSigner(key), &bundle)))
	s, err := r.OpenSession(context.Background(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.RunJavaScript(context.Background(), sandbox.Request{Code: "2"})
	var ue *UnansweredCallError
	if !errors.As(err, &ue) || ue.Record.Sequence != 2 || ue.Record.Unanswered == "" {
		t.Fatalf("the call that broke after running: %v; want an UnansweredCallError for call 2", err)
	}
	if _, marked := sandbox.NotDispatchedReason(err); marked {
		t.Fatal("a call that may have run came back marked not dispatched")
	}
	res, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "3"})
	if err != nil || res.Record.Sequence != 3 {
		t.Fatalf("the call after: %+v, %v; want call 3 on the same session", res, err)
	}
	sum, err := s.Close(context.Background())
	if ran := p.Opened()[0].Calls(); err != nil || sum.Calls != uint64(ran) {
		t.Fatalf("close: %+v, %v; the session ran %d calls", sum, err, ran)
	}
	entries, err := attest.ReadBundle(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := attest.VerifyBundle(entries, attest.NewVerifier(key.Public().(ed25519.PublicKey)))
	if err != nil || len(rep.Sessions) != 1 || rep.Sessions[0].Calls != 3 {
		t.Fatalf("bundle: %+v, %v; want one session of 3 calls", rep, err)
	}
}

// fullRecorder records which kinds of entries it was handed.
type fullRecorder struct {
	runs, unanswered, closes atomic.Int32
}

func (f *fullRecorder) Record(*plimsollv1.RunRequest, *plimsollv1.RunResponse) error {
	f.runs.Add(1)
	return nil
}
func (f *fullRecorder) RecordUnanswered(*plimsollv1.RunRequest, *plimsollv1.RunRecord) error {
	f.unanswered.Add(1)
	return nil
}
func (f *fullRecorder) RecordClose(string, uint64, string) error { f.closes.Add(1); return nil }

// sessionLiar opens one session honestly and then lies: its CloseSession reports
// closeCalls calls, and its SessionRun fails with an unanswered record whose evidence
// is the given provider, tier and software identity.
type sessionLiar struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
	closeCalls                   uint64
	provider, isolation, softwar string
}

const liarID = "00112233445566778899aabbccddeeff"

func (l *sessionLiar) OpenSession(context.Context, *connect.Request[plimsollv1.OpenSessionRequest]) (*connect.Response[plimsollv1.OpenSessionResponse], error) {
	return connect.NewResponse(&plimsollv1.OpenSessionResponse{SessionId: liarID, Session: record.SessionFingerprint(liarID),
		Sandbox: "fake", Isolation: "vm", ExpiresUnixMs: time.Now().Add(time.Minute).UnixMilli()}), nil
}

func (l *sessionLiar) SessionRun(_ context.Context, req *connect.Request[plimsollv1.SessionRunRequest]) (*connect.Response[plimsollv1.SessionRunResponse], error) {
	rec := record.StampUnanswered(sandbox.RunRecord{
		RequestSHA256: record.SessionRunRequestDigest(req.Msg), Provider: l.provider, Isolation: l.isolation,
		SoftwareIdentity: l.softwar, SoftwareRuleID: softwareRuleOf(req.Msg).ID(),
		Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000100),
		Session: record.SessionFingerprint(liarID), Sequence: 1,
	}, "unknown")
	ce := connect.NewError(connect.CodeUnknown, errors.New("the stream broke"))
	if d, err := connect.NewErrorDetail(&plimsollv1.UnansweredCall{Record: rec}); err == nil {
		ce.AddDetail(d)
	}
	return nil, ce
}

func softwareRuleOf(m *plimsollv1.SessionRunRequest) sandbox.SoftwareRule {
	r := m.GetSoftwareRule()
	return sandbox.SoftwareRule{Mode: sandbox.SoftwareMode(r.GetMode()), Identities: r.GetIdentities()}
}

func (l *sessionLiar) CloseSession(context.Context, *connect.Request[plimsollv1.CloseSessionRequest]) (*connect.Response[plimsollv1.CloseSessionResponse], error) {
	return connect.NewResponse(&plimsollv1.CloseSessionResponse{Session: record.SessionFingerprint(liarID), Calls: l.closeCalls}), nil
}

func liarRemote(t *testing.T, l *sessionLiar, rec Recorder) *Remote {
	t.Helper()
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(l)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return newRemote(t, srv.URL, WithRecorder(rec))
}

// A close whose count differs from the client's chain is DataLoss and is never signed;
// nor is the close of a session refused at open (v0.15.0 review, M5.2).
func TestAMismatchedCloseIsNotSigned(t *testing.T) {
	rec := &fullRecorder{}
	s, err := liarRemote(t, &sessionLiar{closeCalls: 7}, rec).OpenSession(context.Background(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Close(context.Background()); connect.CodeOf(err) != connect.CodeDataLoss || !errors.Is(err, record.ErrChain) {
		t.Fatalf("a close counting 7 calls of none: %v; want DataLoss wrapping record.ErrChain", err)
	}
	if n := rec.closes.Load(); n != 0 {
		t.Fatalf("the mismatched close was signed %d times", n)
	}
	liar := &fingerprintLiar{}
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(liar)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if _, err := newRemote(t, srv.URL, WithRecorder(rec)).OpenSession(context.Background(), SessionOptions{}); err == nil {
		t.Fatal("a mismatched fingerprint opened")
	}
	if n := rec.closes.Load(); n != 0 || liar.closes.Load() != 1 {
		t.Fatalf("the refused open's close was signed %d times (closed %d)", n, liar.closes.Load())
	}
}

// An unanswered call's record must state the evidence the session stated at open and
// meet the call's floor and software rule, or it is DataLoss and never signed
// (v0.15.0 review, M5.3).
func TestAnUnansweredRecordIsCheckedAgainstTheSession(t *testing.T) {
	for name, l := range map[string]*sessionLiar{
		"below the floor":      {provider: "fake", isolation: "process"},
		"another provider":     {provider: "other", isolation: "vm"},
		"another tier":         {provider: "fake", isolation: "kernel"},
		"software not allowed": {provider: "fake", isolation: "vm", softwar: "oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &fullRecorder{}
			rule := sandbox.SoftwareRule{Mode: sandbox.SoftwareApproved, Identities: []string{"oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64)}}
			if name != "software not allowed" {
				rule = sandbox.SoftwareRule{}
			}
			s, err := liarRemote(t, l, rec).OpenSession(context.Background(), SessionOptions{MinimumIsolation: sandbox.IsolationKernel})
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.RunJavaScript(context.Background(), sandbox.Request{Code: "1", Software: rule})
			var ue *UnansweredCallError
			if connect.CodeOf(err) != connect.CodeDataLoss || errors.As(err, &ue) {
				t.Fatalf("err = %v; want DataLoss, not an accepted unanswered call", err)
			}
			if n := rec.unanswered.Load(); n != 0 {
				t.Fatalf("the record was signed %d times", n)
			}
		})
	}
}

// recordOnly is a Recorder that cannot keep a session's unanswered calls or close.
type recordOnly struct{}

func (recordOnly) Record(*plimsollv1.RunRequest, *plimsollv1.RunResponse) error { return nil }

// A Recorder that cannot keep a whole chain is refused at open, before anything is
// sent, instead of silently dropping records (v0.15.0 review, M5.4).
func TestARecorderThatCannotKeepAChainIsRefusedAtOpen(t *testing.T) {
	url, p := sessionServer(t)
	_, err := newRemote(t, url, WithRecorder(recordOnly{})).OpenSession(context.Background(), SessionOptions{})
	if _, marked := sandbox.NotDispatchedReason(err); err == nil || !marked {
		t.Fatalf("open with a recorder that cannot keep a chain: %v; want a not-dispatched refusal", err)
	}
	if n := len(p.Opened()); n != 0 {
		t.Fatalf("%d sessions were opened", n)
	}
}
