package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/attest"
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
	sum, err := s.Close(context.Background())
	if err != nil || sum.Calls != 4 || sum.End != sandbox.SessionClosed {
		t.Fatalf("close: %+v, %v", sum, err)
	}
	entries, err := attest.ReadBundle(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := attest.VerifyBundle(entries, attest.NewVerifier(key.Public().(ed25519.PublicKey)))
	if err != nil || len(rep.Sessions) != 1 || rep.Sessions[0].Calls != 4 {
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
