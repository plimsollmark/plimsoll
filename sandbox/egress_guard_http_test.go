package sandbox

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeE2BGuard struct {
	token string
}

func (f fakeE2BGuard) EgressGuardPath() string { return "/v1/e2b/guard" }
func (f fakeE2BGuard) EgressGuardCall(_ context.Context, token, method, path string, body []byte) EgressGuardResponse {
	if token != f.token || method != http.MethodGet || path != "/v1/items" || string(body) != `{"x":1}` {
		return EgressGuardResponse{Status: http.StatusUnauthorized, Body: []byte("bad envelope")}
	}
	return EgressGuardResponse{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{"ok":true}`)}
}

func TestEgressGuardHTTPHandlerFramesBrokerCall(t *testing.T) {
	h := EgressGuardHTTPHandler(fakeE2BGuard{token: "run-token"}, "/v1/e2b/guard")
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
