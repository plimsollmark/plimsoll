package rpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/sandbox"
)

type verifierFunc func(context.Context, string) (Principal, bool, error)

func (f verifierFunc) VerifyToken(ctx context.Context, token string) (Principal, bool, error) {
	return f(ctx, token)
}

type panicOnReadBody struct{ closed atomic.Bool }

func (*panicOnReadBody) Read([]byte) (int, error) { panic("unauthenticated body was read") }
func (b *panicOnReadBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestAuthenticateHTTPRejectsBeforeReadingBody(t *testing.T) {
	body := &panicOnReadBody{}
	req := httptest.NewRequest(http.MethodPost, plimsollv1connect.SandboxServiceRunJavaScriptV2Procedure, nil)
	req.Body = body
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	AuthenticateHTTP(fakeVerifier{token: "good", scopes: []string{ScopeCodeRun}}, next).ServeHTTP(recorder, req)
	if called {
		t.Fatal("unauthenticated request reached Connect handler")
	}
	if !body.closed.Load() {
		t.Fatal("rejected request body was not closed")
	}
}

// fakeVerifier accepts exactly one token and returns a principal with fixed scopes.
type fakeVerifier struct {
	token  string
	scopes []string
}

func (v fakeVerifier) VerifyToken(_ context.Context, token string) (Principal, bool, error) {
	if token != v.token {
		return Principal{}, false, nil
	}
	return Principal{UserID: "u1", Scopes: v.scopes}, true, nil
}

func newAuthTestClient(t *testing.T, verifier TokenVerifier) plimsollv1connect.SandboxServiceClient {
	t.Helper()
	svc := NewSandboxService(&fakeSandbox{jsResult: sandbox.Result{Stdout: "ok", Sandbox: "fake"}})
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithInterceptors(AuthInterceptor(verifier)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux) // Connect unary works over HTTP/1.1
	t.Cleanup(srv.Close)
	return plimsollv1connect.NewSandboxServiceClient(srv.Client(), srv.URL)
}

func callRun(client plimsollv1connect.SandboxServiceClient, token string) error {
	req := connect.NewRequest(&plimsollv1.RunJavaScriptV2Request{Code: "console.log(1)"})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	_, err := client.RunJavaScriptV2(context.Background(), req)
	return err
}

func TestAuthAllowsTokenWithScope(t *testing.T) {
	client := newAuthTestClient(t, fakeVerifier{token: "good", scopes: []string{ScopeCodeRun}})
	if err := callRun(client, "good"); err != nil {
		t.Fatalf("expected success, got %v (code %v)", err, connect.CodeOf(err))
	}
}

func TestAuthAllowsV2IsolationProceduresWithCodeRunScope(t *testing.T) {
	client := newAuthTestClient(t, fakeVerifier{token: "good", scopes: []string{ScopeCodeRun}})
	js := connect.NewRequest(&plimsollv1.RunJavaScriptV2Request{Code: "1", MinimumIsolation: "process"})
	js.Header().Set("Authorization", "Bearer good")
	if _, err := client.RunJavaScriptV2(context.Background(), js); err != nil {
		t.Fatalf("RunJavaScriptV2 auth: %v", err)
	}
	project := connect.NewRequest(&plimsollv1.RunProjectV2Request{Steps: []string{"true"}, MinimumIsolation: "process"})
	project.Header().Set("Authorization", "Bearer good")
	if _, err := client.RunProjectV2(context.Background(), project); err != nil {
		t.Fatalf("RunProjectV2 auth: %v", err)
	}
}

func TestAuthRejectsMissingToken(t *testing.T) {
	client := newAuthTestClient(t, fakeVerifier{token: "good", scopes: []string{ScopeCodeRun}})
	if code := connect.CodeOf(callRun(client, "")); code != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", code)
	}
}

func TestAuthRejectsUnknownToken(t *testing.T) {
	client := newAuthTestClient(t, fakeVerifier{token: "good", scopes: []string{ScopeCodeRun}})
	if code := connect.CodeOf(callRun(client, "wrong")); code != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", code)
	}
}

func TestAuthRejectsTokenWithoutScope(t *testing.T) {
	client := newAuthTestClient(t, fakeVerifier{token: "good", scopes: []string{"devices:read"}})
	if code := connect.CodeOf(callRun(client, "good")); code != connect.CodePermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", code)
	}
}

func TestAuthDevModeAllowsEverything(t *testing.T) {
	client := newAuthTestClient(t, nil) // nil verifier = open dev mode
	if err := callRun(client, ""); err != nil {
		t.Fatalf("dev mode should allow unauthenticated calls, got %v", err)
	}
}

func TestAuthRejectsIdentitylessPrincipal(t *testing.T) {
	for _, id := range []string{"", "*", " alice ", "alice\nadmin", string([]byte{0xff})} {
		t.Run(fmt.Sprintf("%q", id), func(t *testing.T) {
			v := verifierFunc(func(context.Context, string) (Principal, bool, error) {
				return Principal{UserID: id, Scopes: []string{ScopeCodeRun}}, true, nil
			})
			if code := connect.CodeOf(callRun(newAuthTestClient(t, v), "token")); code != connect.CodeUnauthenticated {
				t.Fatalf("code = %v, want Unauthenticated", code)
			}
		})
	}
}

func TestAuthVerifierFailureIsUnavailableAndRedacted(t *testing.T) {
	v := verifierFunc(func(context.Context, string) (Principal, bool, error) {
		return Principal{}, false, errors.New("database password leaked in detail")
	})
	err := callRun(newAuthTestClient(t, v), "token")
	if code := connect.CodeOf(err); code != connect.CodeUnavailable {
		t.Fatalf("code = %v, want Unavailable", code)
	}
	if strings.Contains(err.Error(), "password") {
		t.Fatalf("verifier detail leaked to caller: %v", err)
	}
}

func TestBearerTokenRequiresBearerScheme(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer token": "token",
		"bearer token": "token",
		"BEARER token": "token",
		"token":        "",
		"Basic token":  "",
		"Bearer":       "",
		"Bearer a b":   "",
		"":             "",
	} {
		if got := bearerToken(header); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}
