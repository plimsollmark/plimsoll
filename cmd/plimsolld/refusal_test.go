package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/client"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

type tokenTable map[string]rpc.Principal

func (t tokenTable) VerifyToken(_ context.Context, token string) (rpc.Principal, bool, error) {
	p, ok := t[token]
	return p, ok, nil
}

// TestRefusalsAnswerBeforeAHeldBackBody drives the daemon's own RPC wiring and server
// over raw HTTP/1.1 sockets. Each refusal is sent with a declared 100-byte body of
// which only "{}" arrives. Before unreadbody, Go's server read the rest of that body
// before writing the refusal, so each one waited for the client (30 s, the read
// timeout, for a client that never sends it).
func TestRefusalsAnswerBeforeAHeldBackBody(t *testing.T) {
	verifier := tokenTable{
		"token-a-0123456789abcdef0123456789": {UserID: "a", Scopes: []string{rpc.ScopeCodeRun}},
		"token-b-0123456789abcdef0123456789": {UserID: "b", Scopes: []string{rpc.ScopeCodeRun}},
		"token-n-0123456789abcdef0123456789": {UserID: "n"},
	}
	svc := rpc.NewSandboxService(&countingSandbox{})
	path, connectHandler := plimsollv1connect.NewSandboxServiceHandler(svc,
		connect.WithInterceptors(rpc.AuthInterceptor(verifier)), connect.WithReadMaxBytes(maxRequestBytes))
	// entered reports that a request holds its decode slot: it is inside
	// LimitHTTPConcurrency, where Connect is about to read the body.
	entered := make(chan struct{}, 4)
	mux := http.NewServeMux()
	mux.Handle(path, guardRPC(verifier, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		connectHandler.ServeHTTP(w, r)
	})))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(ln.Addr().String(), mux, nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()

	send := func(t *testing.T, token, framing string) (net.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		auth := ""
		if token != "" {
			auth = "Authorization: Bearer " + token + "\r\n"
		}
		head := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n%s", plimsollv1connect.SandboxServiceDescribeProcedure, auth)
		partial := "Content-Length: 100\r\n\r\n{}"
		switch framing {
		case "chunked":
			partial = "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n"
		case "oversized":
			partial = fmt.Sprintf("Content-Length: %d\r\n\r\n{}", maxRequestBytes+1)
		}
		if _, err := io.WriteString(conn, head+partial); err != nil {
			t.Fatal(err)
		}
		return conn, bufio.NewReader(conn)
	}
	expect := func(t *testing.T, conn net.Conn, br *bufio.Reader, status int) {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("no answer while the body was held back: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != status || !resp.Close {
			t.Fatalf("got %d (close %v), want %d closing the connection", resp.StatusCode, resp.Close, status)
		}
	}

	for _, framing := range []string{"content-length", "chunked"} {
		t.Run("no credential/"+framing, func(t *testing.T) {
			conn, br := send(t, "", framing)
			expect(t, conn, br, http.StatusUnauthorized)
		})
		t.Run("unknown credential/"+framing, func(t *testing.T) {
			conn, br := send(t, "token-x-0123456789abcdef0123456789", framing)
			expect(t, conn, br, http.StatusUnauthorized)
		})
		t.Run("missing scope/"+framing, func(t *testing.T) {
			conn, br := send(t, "token-n-0123456789abcdef0123456789", framing)
			expect(t, conn, br, http.StatusForbidden)
		})
	}

	t.Run("declared body over the cap", func(t *testing.T) {
		// Refused from the header alone: the raw-bytes cap used to trip only once the
		// bytes arrived, so this held a decode slot until the read timeout.
		conn, br := send(t, "token-b-0123456789abcdef0123456789", "oversized")
		expect(t, conn, br, http.StatusTooManyRequests)
	})

	t.Run("a read body keeps the connection", func(t *testing.T) {
		// The wrapper closes a connection whose body was not read to its end, so it
		// relies on Connect reading a whole request; if that changed, every call would
		// open a new connection.
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for i := range 2 {
			_, _ = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nAuthorization: Bearer token-b-0123456789abcdef0123456789\r\nContent-Length: 2\r\n\r\n{}",
				plimsollv1connect.SandboxServiceDescribeProcedure)
			<-entered
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("call %d: %v", i, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || resp.Close {
				t.Fatalf("call %d: got %d (close %v), want 200 keeping the connection", i, resp.StatusCode, resp.Close)
			}
		}
	})

	t.Run("caller at its decode cap", func(t *testing.T) {
		// One slot in two per caller: a's first request holds a's only slot while its
		// body is held back, so a's second is refused at the cap.
		send(t, "token-a-0123456789abcdef0123456789", "content-length")
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the first request never took its decode slot")
		}
		conn, br := send(t, "token-a-0123456789abcdef0123456789", "content-length")
		expect(t, conn, br, http.StatusTooManyRequests)

		// Another caller is unaffected.
		client := plimsollv1connect.NewSandboxServiceClient(http.DefaultClient, "http://"+addr)
		req := connect.NewRequest(&plimsollv1.DescribeRequest{})
		req.Header().Set("Authorization", "Bearer token-b-0123456789abcdef0123456789")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := client.Describe(ctx, req); err != nil {
			t.Fatalf("another caller's Describe: %v", err)
		}
	})
}

// blockingSandbox holds every snippet until release is closed, reporting each start.
type blockingSandbox struct {
	countingSandbox
	started chan struct{}
	release chan struct{}
}

func (s *blockingSandbox) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	s.started <- struct{}{}
	<-s.release
	return s.countingSandbox.RunJavaScript(ctx, req)
}

// The daemon gives a request's decode slot back once Connect has decoded it
// (rpc.ReleaseDecodeSlot first among rpcMux's interceptors), so a run that takes long
// does not hold its caller's decode capacity: with one slot per caller, a second call
// of the same caller reaches the provider while the first still runs. Without the
// interceptor the slot is held for the whole run and the second call is refused.
func TestARunningCallHoldsNoDecodeSlot(t *testing.T) {
	const token = "token-a-0123456789abcdef0123456789"
	verifier := tokenTable{token: {UserID: "a", Scopes: []string{rpc.ScopeCodeRun}}}
	sb := &blockingSandbox{started: make(chan struct{}, 2), release: make(chan struct{})}
	svc := rpc.NewSandboxService(sb)
	srv := httptest.NewServer(rpcMux(svc, verifier, 1, sb)) // two decode slots, one per caller
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(sb.release) })
	remote, err := client.New(srv.URL, client.WithToken(token))
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	// The second call is sent only once the first is running: while the first is still
	// being decoded, refusing the second is right.
	for i := range 2 {
		go func() {
			_, err := remote.RunJavaScript(context.Background(), sandbox.Request{Code: "1", Timeout: 5 * time.Second})
			errs <- err
		}()
		select {
		case <-sb.started:
		case err := <-errs:
			t.Fatalf("call %d ended before it reached the provider: %v; want the running call's decode slot given back once it was decoded", i+1, err)
		case <-time.After(10 * time.Second):
			t.Fatalf("call %d never reached the provider", i+1)
		}
	}
}
