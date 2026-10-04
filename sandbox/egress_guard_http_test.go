package sandbox

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeE2BGuard struct {
	token string
	// block, when non-nil, holds EgressGuardCall until it is closed, so a test can
	// keep an admission slot occupied; entered signals that it has been reached.
	block   chan struct{}
	entered chan struct{}
	calls   atomic.Int64
}

func (f *fakeE2BGuard) EgressGuardPath() string { return "/v1/e2b/guard" }

func (f *fakeE2BGuard) EgressGuardKnownToken(token string) bool { return token == f.token }

func (f *fakeE2BGuard) EgressGuardCall(_ context.Context, token, method, path string, body []byte) EgressGuardResponse {
	f.calls.Add(1)
	if f.entered != nil {
		f.entered <- struct{}{}
	}
	if f.block != nil {
		<-f.block
	}
	if token != f.token || method != http.MethodGet || path != "/v1/items" || string(body) != `{"x":1}` {
		return EgressGuardResponse{Status: http.StatusUnauthorized, Body: []byte("bad envelope")}
	}
	return EgressGuardResponse{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{"ok":true}`)}
}

// countingReader reports how many times a request body was actually read, which is
// how the "authenticate before decoding" property is observed rather than asserted.
type countingReader struct {
	r     io.Reader
	reads atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.r.Read(p)
}

func TestEgressGuardHTTPHandlerFramesBrokerCall(t *testing.T) {
	t.Parallel()
	h := EgressGuardHTTPHandler(&fakeE2BGuard{token: "run-token"}, "/v1/e2b/guard", 0, 0)
	req := httptest.NewRequest(http.MethodPost, "https://guard.example/v1/e2b/guard", strings.NewReader(`{"method":"GET","path":"/v1/items","body":{"x":1}}`))
	req.Header.Set(EgressGuardHeader, "run-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status/content-type = %d/%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q", body)
	}
}

// An unauthenticated caller must be refused before its body is read: the guard URL
// is publicly reachable, so decoding first would let anyone spend the process's
// memory and parsing work without holding a per-run credential.
func TestEgressGuardHTTPHandlerRejectsUnknownTokenBeforeReadingBody(t *testing.T) {
	guard := &fakeE2BGuard{token: "run-token"}
	h := EgressGuardHTTPHandler(guard, "/v1/e2b/guard", 0, 0)
	for _, token := range []string{"", "wrong-token"} {
		body := &countingReader{r: strings.NewReader(`{"method":"GET","path":"/v1/items","body":{"x":1}}`)}
		req := httptest.NewRequest(http.MethodPost, "https://guard.example/v1/e2b/guard", body)
		if token != "" {
			req.Header.Set(EgressGuardHeader, token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: status = %d, want 401", token, rec.Code)
		}
		if n := body.reads.Load(); n != 0 {
			t.Fatalf("token %q: request body was read %d times before authentication", token, n)
		}
	}
	if n := guard.calls.Load(); n != 0 {
		t.Fatalf("unauthenticated requests reached the provider %d times", n)
	}
}

// Authenticated decode work is bounded: past the in-flight cap the handler sheds
// instead of queueing, so concurrent callers cannot stack up buffered envelopes.
func TestEgressGuardHTTPHandlerShedsPastInFlightCap(t *testing.T) {
	guard := &fakeE2BGuard{token: "run-token", block: make(chan struct{}), entered: make(chan struct{})}
	h := EgressGuardHTTPHandler(guard, "/v1/e2b/guard", 1, 0)
	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://guard.example/v1/e2b/guard", strings.NewReader(`{"method":"GET","path":"/v1/items","body":{"x":1}}`))
		req.Header.Set(EgressGuardHeader, "run-token")
		return req
	}

	held := make(chan struct{})
	go func() {
		defer close(held)
		h.ServeHTTP(httptest.NewRecorder(), newReq())
	}()
	<-guard.entered // the first request now holds the only slot

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newReq())
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("second concurrent request: status = %d, want 503", rec.Code)
	}
	if n := guard.calls.Load(); n != 1 {
		t.Fatalf("shed request still reached the provider (calls = %d)", n)
	}

	close(guard.block)
	<-held
}

// twoTokenGuard knows two live runs' credentials and answers every call.
type twoTokenGuard struct{ calls atomic.Int64 }

func (g *twoTokenGuard) EgressGuardPath() string { return "/v1/e2b/guard" }
func (g *twoTokenGuard) EgressGuardKnownToken(token string) bool {
	return token == "run-a" || token == "run-b"
}
func (g *twoTokenGuard) EgressGuardCall(context.Context, string, string, string, []byte) EgressGuardResponse {
	g.calls.Add(1)
	return EgressGuardResponse{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{"ok":true}`)}
}

// One run that opens more guard requests than its share and dribbles their bodies
// must not leave another run without a slot (v0.15.0 review, M3).
func TestEgressGuardOneRunCannotTakeEverySlot(t *testing.T) {
	guard := &twoTokenGuard{}
	h := EgressGuardHTTPHandler(guard, "/v1/e2b/guard", 2, 1)
	var stalled []*io.PipeWriter
	done := make(chan struct{}, 4)
	for range 4 {
		pr, pw := io.Pipe()
		stalled = append(stalled, pw)
		req := httptest.NewRequest(http.MethodPost, "https://guard.example/v1/e2b/guard", pr)
		req.Header.Set(EgressGuardHeader, "run-a")
		go func() { h.ServeHTTP(httptest.NewRecorder(), req); done <- struct{}{} }()
	}
	defer func() {
		for _, pw := range stalled {
			_ = pw.CloseWithError(io.ErrUnexpectedEOF)
		}
		for range 4 {
			<-done
		}
	}()
	time.Sleep(100 * time.Millisecond) // let run-a's requests take what they can
	req := httptest.NewRequest(http.MethodPost, "https://guard.example/v1/e2b/guard", strings.NewReader(`{"method":"GET","path":"/v1/items"}`))
	req.Header.Set(EgressGuardHeader, "run-b")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("run-b: status %d (%s); want 200 while run-a stalls its own requests", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

// An admitted request that dribbles its body loses its slot at the body deadline, not
// at the server's 30 s read timeout (v0.15.0 review, M3).
func TestEgressGuardBodyDeadline(t *testing.T) {
	old := egressGuardBodyDeadline
	egressGuardBodyDeadline = 200 * time.Millisecond
	defer func() { egressGuardBodyDeadline = old }()
	srv := httptest.NewServer(EgressGuardHTTPHandler(&twoTokenGuard{}, "/v1/e2b/guard", 1, 1))
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "POST /v1/e2b/guard HTTP/1.1\r\nHost: guard\r\n"+EgressGuardHeader+": run-a\r\nContent-Length: 100\r\n\r\n{\"method\":")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	started := time.Now()
	status, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.Contains(status, "413") || time.Since(started) > 3*time.Second {
		t.Fatalf("a stalled body: %q after %v; want 413 at the body deadline", status, time.Since(started))
	}
	// The slot is free again: the other run gets through.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/e2b/guard", strings.NewReader(`{"method":"GET","path":"/v1/items"}`))
	req.Header.Set(EgressGuardHeader, "run-b")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("after the deadline: %v %v", resp, err)
	}
	resp.Body.Close()
}
