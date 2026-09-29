package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/client"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// exchange is a request and a response carrying a record, as a daemon sends it;
// link sets a session call's chain fields.
func exchange(code, stdout string, link sandbox.RunRecord) (*plimsollv1.RunRequest, *plimsollv1.RunResponse) {
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: code}}}
	resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte(stdout)}}}
	r := sandbox.RunRecord{
		Version: record.Version, RequestSHA256: record.RunRequestDigest(req), ResultSHA256: record.ResultDigest(resp),
		Provider: "fake", Isolation: "vm", Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000100),
		Session: link.Session, Sequence: link.Sequence, PreviousSHA256: link.PreviousSHA256,
	}
	r.SHA256 = record.Digest(r)
	resp.Record = record.ToWire(r)
	return req, resp
}

// session builds n signed calls of one session plus its close entry.
func session(t *testing.T, s *Signer, id string, n int) []Entry {
	t.Helper()
	fp := record.SessionFingerprint(id)
	var out []Entry
	prev := ""
	for i := 1; i <= n; i++ {
		req, resp := exchange("step()", strings.Repeat("x", i), sandbox.RunRecord{Session: fp, Sequence: uint64(i), PreviousSHA256: prev})
		e, err := s.entry(req, resp, record.FromWire(resp.GetRecord()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
		prev = resp.GetRecord().GetRecordSha256()
	}
	c, err := s.Close(SessionClose{Session: fp, Calls: uint64(n), LastRecordSHA256: prev})
	if err != nil {
		t.Fatal(err)
	}
	return append(out, c)
}

func TestPAEMatchesTheDSSEExample(t *testing.T) {
	// The worked example in the DSSE protocol specification.
	got := string(PAE("http://example.com/HelloWorld", []byte("hello world")))
	if got != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Fatalf("PAE = %q", got)
	}
}

func TestSignAndVerify(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	req, resp := exchange("console.log(1)", "1\n", sandbox.RunRecord{})
	e, err := s.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := v.Verify(e.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SHA256 != resp.GetRecord().GetRecordSha256() || rec.Provider != "fake" {
		t.Fatalf("verified record %+v", rec)
	}
	// Another key does not verify it.
	if _, err := NewVerifier(newKey(t).Public().(ed25519.PublicKey)).Verify(e.Envelope); !errors.Is(err, ErrSignature) {
		t.Fatalf("another key: %v", err)
	}
	// A changed payload does not verify, even re-encoded validly.
	payload, _ := base64.StdEncoding.DecodeString(e.Envelope.Payload)
	forged := e.Envelope
	forged.Payload = base64.StdEncoding.EncodeToString(bytes.Replace(payload, []byte(`"fake"`), []byte(`"e2b"`), 1))
	if _, err := v.Verify(forged); !errors.Is(err, ErrSignature) {
		t.Fatalf("a changed payload: %v", err)
	}
	// A record whose digest does not match its fields is never signed.
	bad := record.FromWire(resp.GetRecord())
	bad.Provider = "e2b"
	if _, err := s.Sign(bad); !errors.Is(err, ErrUnchecked) {
		t.Fatalf("an unchecked record: %v", err)
	}
	// Nor is a response without a record, or one whose record does not match.
	if _, err := s.Call(req, &plimsollv1.RunResponse{Sandbox: "fake"}); !errors.Is(err, record.ErrNoRecord) {
		t.Fatalf("no record: %v", err)
	}
	tampered := proto.Clone(resp).(*plimsollv1.RunResponse)
	tampered.GetJavascript().Stdout = []byte("2\n")
	if _, err := s.Call(req, tampered); !errors.Is(err, record.ErrMismatch) {
		t.Fatalf("a mismatched record: %v", err)
	}
}

func TestVersionOneRecordIsNotSignedByNewHarness(t *testing.T) {
	key := newKey(t)
	req, resp := exchange("old", "ok", sandbox.RunRecord{})
	r := record.FromWire(resp.GetRecord())
	r.Version = 1
	r.SHA256 = record.Digest(r)
	resp.Record = record.ToWire(r)
	signer := NewSigner(key)
	if _, err := signer.Sign(r); !errors.Is(err, ErrSigningVersion) {
		t.Fatalf("Sign accepted a new version 1 record: %v", err)
	}
	if _, err := signer.Call(req, resp); !errors.Is(err, ErrSigningVersion) {
		t.Fatalf("Call signed a version 1 daemon response: %v", err)
	}
}

func TestPublishedVersionOneBundleRemainsVerifiable(t *testing.T) {
	data, err := os.ReadFile("../docs/examples/sessions/bundle.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ReadBundle(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := os.ReadFile("../docs/examples/sessions/harness.pub")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ParsePublicKey(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	report, err := VerifyBundle(entries, NewVerifier(publicKey))
	if err != nil || len(report.Sessions) != 1 || report.Sessions[0].Calls != 5 {
		t.Fatalf("published version 1 bundle: report %+v, err %v", report, err)
	}
}

// A signer's own key signing a statement of another type is not a run record.
func TestVerifyRefusesOtherStatements(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	c, err := s.Close(SessionClose{Session: record.SessionFingerprint("s"), Calls: 1, LastRecordSHA256: "00"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(c.Envelope); !errors.Is(err, ErrStatement) {
		t.Fatalf("a close statement verified as a record: %v", err)
	}
	req, resp := exchange("1", "", sandbox.RunRecord{})
	e, _ := s.Call(req, resp)
	if _, err := v.VerifyClose(e.Envelope); !errors.Is(err, ErrStatement) {
		t.Fatalf("a record verified as a close: %v", err)
	}
}

func TestKeysRoundTripThroughPEM(t *testing.T) {
	privPEM, pubPEM, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	req, resp := exchange("1", "", sandbox.RunRecord{})
	e, err := NewSigner(priv).Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerifier(pub).Verify(e.Envelope); err != nil {
		t.Fatal(err)
	}
	if e.Envelope.Signatures[0].KeyID != KeyID(pub) || len(KeyID(pub)) != 64 {
		t.Fatalf("key id %q", e.Envelope.Signatures[0].KeyID)
	}
	if _, err := ParsePrivateKey(pubPEM); err == nil {
		t.Fatal("a public key parsed as a private key")
	}
}

func TestVerifyBundle(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	req, resp := exchange("console.log(1)", "1\n", sandbox.RunRecord{})
	single, err := s.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	a := session(t, s, "session-a", 3)
	b := session(t, s, "session-b", 2)
	// Two sessions interleaved with a single run verify as long as each chain holds.
	good := []Entry{a[0], b[0], single, a[1], b[1], b[2], a[2], a[3]}
	rep, err := VerifyBundle(good, v)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Runs != 1 || len(rep.Sessions) != 2 || rep.Sessions[0].Calls != 3 || rep.Sessions[1].Calls != 2 {
		t.Fatalf("report %+v", rep)
	}

	storedEdit := single
	edited := &plimsollv1.RunResponse{}
	if err := proto.Unmarshal(single.Response, edited); err != nil {
		t.Fatal(err)
	}
	edited.GetJavascript().Stdout = []byte("2\n")
	storedEdit.Response, _ = proto.Marshal(edited)

	for name, c := range map[string]struct {
		entries []Entry
		want    error
	}{
		"a stored result edited":      {[]Entry{storedEdit}, ErrStored},
		"a middle call dropped":       {[]Entry{a[0], a[2], a[3]}, ErrChain},
		"two calls swapped":           {[]Entry{a[1], a[0], a[2], a[3]}, ErrChain},
		"the last call and close cut": {[]Entry{a[0], a[1]}, ErrChain},
		"the last call cut":           {[]Entry{a[0], a[1], a[3]}, ErrChain},
		"a call replayed":             {[]Entry{a[0], a[1], a[1], a[2], a[3]}, ErrChain},
		"a call after the close":      {[]Entry{a[0], a[1], a[2], a[3], a[2]}, ErrChain},
		"a close with no calls":       {[]Entry{a[3]}, ErrChain},
		"another session's call":      {[]Entry{a[0], b[1], a[1], a[2], a[3]}, ErrChain},
		"signed by another key":       {session(t, NewSigner(newKey(t)), "session-c", 1), ErrSignature},
	} {
		if _, err := VerifyBundle(c.entries, v); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

// A session that ran no call is its close statement alone, which verifies; a close
// that claims calls the bundle does not hold, a second close, and a call after the
// close do not.
func TestVerifyBundleEmptySession(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	closeOf := func(name string, calls uint64, last string) Entry {
		t.Helper()
		e, err := s.Close(SessionClose{Session: record.SessionFingerprint(name), Calls: calls, LastRecordSHA256: last})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	empty := closeOf("empty", 0, "")
	a := session(t, s, "session-a", 2)
	rep, err := VerifyBundle([]Entry{a[0], empty, a[1], a[2]}, v)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Sessions) != 2 || rep.Sessions[1].Calls != 0 || rep.Sessions[1].Session != record.SessionFingerprint("empty") {
		t.Fatalf("report %+v", rep)
	}
	for name, bundle := range map[string][]Entry{
		"a close claiming a call":      {closeOf("empty", 1, "")},
		"a close naming a last record": {closeOf("empty", 0, strings.Repeat("0", 64))},
		"a second close":               {empty, empty},
		"a call after the close":       {empty, session(t, s, "empty", 1)[0]},
	} {
		if _, err := VerifyBundle(bundle, v); !errors.Is(err, ErrChain) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBundleRoundTripsThroughJSONLines(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	var buf bytes.Buffer
	for _, e := range session(t, s, "s", 2) {
		if err := WriteEntry(&buf, e); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(entries, NewVerifier(key.Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBundle(strings.NewReader(`{"envelope":{},"extra":1}`)); err == nil {
		t.Fatal("an unknown field was accepted")
	}
}

func TestReplayComparesResultDigests(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	req1, resp1 := exchange("a()", "same\n", sandbox.RunRecord{})
	req2, resp2 := exchange("b()", "drifts\n", sandbox.RunRecord{})
	e1, _ := s.Call(req1, resp1)
	e2, _ := s.Call(req2, resp2)
	entries := append([]Entry{e1, e2}, session(t, s, "s", 1)...)
	send := func(_ context.Context, req *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		out := "same\n"
		if req.GetJavascript().GetCode() == "b()" {
			out = "moved\n"
		}
		return &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte(out)}}}, nil
	}
	got, err := Replay(context.Background(), entries, NewVerifier(key.Public().(ed25519.PublicKey)), send)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Match() || got[1].Match() {
		t.Fatalf("replay %+v", got)
	}
}

// End to end: a real daemon (the wasm provider) behind the official client,
// whose recorder is a Harness; the bundle it writes verifies.
func TestHarnessRecordsThroughTheClient(t *testing.T) {
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(rpc.NewSandboxService(sandboxtest.Wasm()),
		connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	key := newKey(t)
	var bundle bytes.Buffer
	remote, err := client.New(srv.URL, client.WithRecorder(NewHarness(NewSigner(key), &bundle)))
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"console.log(6*7)", "console.log('again')"} {
		if _, err := remote.RunJavaScript(context.Background(), sandbox.Request{Code: code}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := ReadBundle(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyBundle(entries, NewVerifier(key.Public().(ed25519.PublicKey)))
	if err != nil || rep.Runs != 2 {
		t.Fatalf("report %+v, %v", rep, err)
	}
	// The wasm engine is deterministic for these snippets, so a replay matches.
	send := func(ctx context.Context, req *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		resp, err := plimsollv1connect.NewSandboxServiceClient(http.DefaultClient, srv.URL).Run(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}
	replayed, err := Replay(context.Background(), entries, NewVerifier(key.Public().(ed25519.PublicKey)), send)
	if err != nil || len(replayed) != 2 || !replayed[0].Match() || !replayed[1].Match() {
		t.Fatalf("replay %+v, %v", replayed, err)
	}
}

type replaySender struct{ s *client.Session }

func (r replaySender) Send(ctx context.Context, req *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
	resp, _, err := r.s.Exchange(ctx, req)
	return resp, err
}

func (r replaySender) Close(ctx context.Context) error {
	_, err := r.s.Close(ctx)
	return err
}

// A recorded session replays into a fresh session call by call: the fake answers
// its nth call with n characters, so a replay in order reproduces every result.
func TestSessionRecordsVerifyAndReplay(t *testing.T) {
	p := &sandboxtest.Sessions{}
	svc := rpc.NewSandboxService(p)
	svc.Sessions = rpc.SessionConfig{MaxSessions: 2, Lifetime: time.Minute, IdleTimeout: time.Minute}
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	key := newKey(t)
	var bundle bytes.Buffer
	remote, err := client.New(srv.URL, client.WithRecorder(NewHarness(NewSigner(key), &bundle)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := remote.OpenSession(context.Background(), client.SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "step()"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadBundle(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := VerifyBundle(entries, NewVerifier(key.Public().(ed25519.PublicKey))); err != nil || len(rep.Sessions) != 1 || rep.Sessions[0].Calls != 3 {
		t.Fatalf("verify: %+v, %v", rep, err)
	}
	plain, err := client.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReplaySessions(context.Background(), entries, NewVerifier(key.Public().(ed25519.PublicKey)), func(ctx context.Context) (SessionSender, error) {
		s, err := plain.OpenSession(ctx, client.SessionOptions{})
		return replaySender{s}, err
	})
	if err != nil || len(got) != 3 {
		t.Fatalf("replay: %+v, %v", got, err)
	}
	for _, r := range got {
		if !r.Match() || r.Session == "" {
			t.Fatalf("replay: %+v", r)
		}
	}
	if len(p.Opened()) != 2 {
		t.Fatalf("the replay did not use a fresh session: %d opened", len(p.Opened()))
	}

	// A session closed before any call leaves a bundle that verifies.
	var emptyBundle bytes.Buffer
	recorded, err := client.New(srv.URL, client.WithRecorder(NewHarness(NewSigner(key), &emptyBundle)))
	if err != nil {
		t.Fatal(err)
	}
	unused, err := recorded.OpenSession(context.Background(), client.SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unused.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, err = ReadBundle(&emptyBundle)
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := VerifyBundle(entries, NewVerifier(key.Public().(ed25519.PublicKey))); err != nil || len(rep.Sessions) != 1 || rep.Sessions[0].Calls != 0 {
		t.Fatalf("a session with no call: %+v, %v", rep, err)
	}
}

// A module output that is a NaN other than Go's own (C's NAN is 0x7ff8000000000000)
// survives the bundle: stored messages are binary, so its signed digest still
// matches after a write and a read.
func TestBundleKeepsNaNBits(t *testing.T) {
	key := newKey(t)
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Module{Module: &plimsollv1.ModuleRun{
		Model: "m", EndTime: 1, Step: 0.5, Rows: []*plimsollv1.ModuleRow{{Values: []float64{1}}}}}}
	resp := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "kernel", Result: &plimsollv1.RunResponse_Module{Module: &plimsollv1.ModuleResult{
		Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED, Width: 1,
		Runs: []*plimsollv1.ModuleRowResult{{Status: 1, Outputs: []float64{math.Float64frombits(0x7ff8000000000000)}}}}}}
	r := sandbox.RunRecord{Version: record.Version, RequestSHA256: record.RunRequestDigest(req), ResultSHA256: record.ResultDigest(resp),
		Provider: "docker", Isolation: "kernel", Started: time.UnixMilli(1), Ended: time.UnixMilli(2)}
	r.SHA256 = record.Digest(r)
	resp.Record = record.ToWire(r)
	e, err := NewSigner(key).Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteEntry(&buf, e); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(entries, NewVerifier(key.Public().(ed25519.PublicKey))); err != nil {
		t.Fatalf("a NaN output did not survive the bundle: %v", err)
	}
}
