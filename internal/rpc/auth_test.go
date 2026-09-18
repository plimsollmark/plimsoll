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
	req := httptest.NewRequest(http.MethodPost, plimsollv1connect.SandboxServiceRunProcedure, nil)
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
	svc := NewSandboxService(&fakeSandbox{
		jsResult:  sandbox.Result{Stdout: "ok", Sandbox: "fake"},
		modResult: sandbox.ModuleResult{Sandbox: "fake", Outcome: sandbox.ProjectOutcomeCompleted},
	})
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithInterceptors(AuthInterceptor(verifier)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux) // Connect unary works over HTTP/1.1
	t.Cleanup(srv.Close)
	return plimsollv1connect.NewSandboxServiceClient(srv.Client(), srv.URL)
}

func callRun(client plimsollv1connect.SandboxServiceClient, token string) error {
	req := jsReq("console.log(1)")
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	_, err := client.Run(context.Background(), req)
	return err
}

func TestAuthAllowsTokenWithScope(t *testing.T) {
	client := newAuthTestClient(t, fakeVerifier{token: "good", scopes: []string{ScopeCodeRun}})
	if err := callRun(client, "good"); err != nil {
		t.Fatalf("expected success, got %v (code %v)", err, connect.CodeOf(err))
	}
}

// Every payload kind rides the one procedure and so the one scope entry. The
// module case is the regression: before the envelope, the module procedure was
// absent from the scope map, and an unlisted procedure is refused whenever a
// verifier is configured, so module runs worked only in open dev mode.
func TestAuthAllowsEveryKindWithCodeRunScope(t *testing.T) {
	client := newAuthTestClient(t, fakeVerifier{token: "good", scopes: []string{ScopeCodeRun}})
	for name, req := range map[string]*connect.Request[plimsollv1.RunRequest]{
		"javascript": withFloor(jsReq("1"), "process"),
		"project":    withFloor(projectReq(&plimsollv1.ProjectRun{Steps: []string{"true"}}), "process"),
		"module":     withFloor(moduleReq(moduleRequest([]float64{1, 2, 0})), "process"),
	} {
		req.Header().Set("Authorization", "Bearer good")
		if _, err := client.Run(context.Background(), req); err != nil {
			t.Fatalf("%s under a configured verifier: %v", name, err)
		}
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
