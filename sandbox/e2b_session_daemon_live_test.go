package sandbox_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestLiveE2BDaemonClosesAnUnclaimedSession is the live proof of the daemon's unclaimed
// close on a provider billed by the second: a session opened through the daemon and
// never named again is closed at its first idle timeout, its microVM is deleted (gone
// from the listing ReconcileOrphans reads, which is what ends E2B's billing for it), and
// a late call is refused, not dispatched, with the end unclaimed. It drives the daemon's
// RPC handler through the Go client, as a caller would. It spends one microVM for about
// the idle timeout, so it runs only with E2B_SESSION_LIVE=1 and E2B_API_KEY (make
// e2b-session-live), like TestLiveE2BSessions.
func TestLiveE2BDaemonClosesAnUnclaimedSession(t *testing.T) {
	if os.Getenv("E2B_SESSION_LIVE") != "1" {
		t.Skip("set E2B_SESSION_LIVE=1 (make e2b-session-live): this spends E2B credits")
	}
	key := os.Getenv("E2B_API_KEY")
	if key == "" {
		t.Fatal("E2B_SESSION_LIVE=1 but E2B_API_KEY is not set")
	}
	e := &sandbox.E2B{APIKey: key, Template: os.Getenv("E2B_TEMPLATE"), DefaultTimeout: 60 * time.Second, MaxTimeout: 90 * time.Second}
	t.Cleanup(func() { requireNothingLeft(t, e) })
	// Long enough that the listing right after the open finds the sandbox before the
	// close can; short enough that the microVM costs a few seconds.
	const idle = 10 * time.Second
	svc := rpc.NewSandboxService(e)
	svc.Sessions = rpc.SessionConfig{MaxSessions: 2, MaxPerCaller: 1, Lifetime: 5 * time.Minute, IdleTimeout: idle}
	svc.Limiter = rpc.NewCodeLimiter(2, 0, 0, 0)
	svc.Spend = rpc.NewSpendCap(900) // a daemon allowance, as a metered deployment sets
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	r, err := client.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	s, err := r.OpenSession(ctx, client.SessionOptions{})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	opened := time.Now()
	listed, err := sandbox.E2BOwnSandboxes(ctx, e)
	if err != nil || len(listed) != 1 {
		t.Fatalf("after the open, this instance's sandboxes: %v, %v; want one", listed, err)
	}
	// Nothing names the session from here on, since any call would claim it: the daemon
	// alone must close it, and E2B stop listing its sandbox.
	for len(listed) > 0 {
		if time.Since(opened) > idle+2*time.Minute {
			t.Fatalf("%v after the open, E2B still lists %v", time.Since(opened), listed)
		}
		time.Sleep(time.Second)
		if listed, err = sandbox.E2BOwnSandboxes(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("the open took %v; E2B stopped listing the sandbox %v after it (idle timeout %v)",
		opened.Sub(start).Round(time.Millisecond), time.Since(opened).Round(time.Millisecond), idle)
	if time.Since(opened) < idle {
		t.Fatalf("the sandbox was gone %v after the open, before the idle timeout", time.Since(opened))
	}

	_, err = s.RunJavaScript(ctx, sandbox.Request{Code: "1"})
	var ended *sandbox.SessionEndedError
	if !errors.As(err, &ended) || ended.Reason != sandbox.SessionUnclaimed {
		t.Fatalf("a call after the close: %v; want the session ended unclaimed", err)
	}
	if _, marked := sandbox.NotDispatchedReason(err); !marked {
		t.Fatalf("a call after the close: %v; want it marked not dispatched", err)
	}
	sum, err := s.Close(ctx)
	if err != nil || sum.End != sandbox.SessionUnclaimed || sum.Calls != 0 {
		t.Fatalf("the close: %+v, %v; want the end unclaimed and no calls", sum, err)
	}
}
