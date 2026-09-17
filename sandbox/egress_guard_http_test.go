package sandbox

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
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
	h := EgressGuardHTTPHandler(&fakeE2BGuard{token: "run-token"}, "/v1/e2b/guard", 0)
	req := httptest.NewRequest(http.MethodPost, "https://guard.example/v1/e2b/guard", strings.NewReader(`{"method":"GET","path":"/v1/items","body":{"x":1}}`))
	req.Header.Set(E2BGuardHeader, "run-token")
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
	h := EgressGuardHTTPHandler(guard, "/v1/e2b/guard", 0)
	for _, token := range []string{"", "wrong-token"} {
		body := &countingReader{r: strings.NewReader(`{"method":"GET","path":"/v1/items","body":{"x":1}}`)}
		req := httptest.NewRequest(http.MethodPost, "https://guard.example/v1/e2b/guard", body)
		if token != "" {
			req.Header.Set(E2BGuardHeader, token)
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
	h := EgressGuardHTTPHandler(guard, "/v1/e2b/guard", 1)
	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://guard.example/v1/e2b/guard", strings.NewReader(`{"method":"GET","path":"/v1/items","body":{"x":1}}`))
		req.Header.Set(E2BGuardHeader, "run-token")
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
