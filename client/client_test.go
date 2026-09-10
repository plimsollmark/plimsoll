package client

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// startServer runs a real plimsolld handler (wasm provider) over httptest and
// returns its URL. verifier=nil means keyless.
func startServer(t *testing.T, verifier rpc.TokenVerifier) string {
	t.Helper()
	svc := rpc.NewSandboxService(sandboxtest.Wasm())
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(verifier)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// startLoggingServer is startServer with the daemon's audit stream captured, so a
// test can assert what the SERVER recorded rather than what the client believes it
// sent. Keyless.
func startLoggingServer(t *testing.T, log *bytes.Buffer) string {
	t.Helper()
	svc := rpc.NewSandboxService(sandboxtest.Wasm())
	svc.Logger = slog.New(slog.NewJSONHandler(log, &slog.HandlerOptions{Level: slog.LevelInfo}))
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestRemoteCarriesTraceIDOntoTheServerAuditLine is the whole join, proven across
// the wire rather than at either end of it: a correlation id put on the context by
// an embedding caller must come out on the DAEMON's audit line. Every other test
// of this feature checks one hop; this one checks that the hops connect.
//
// It is worth its cost because the failure mode is silent. A caller that sets an
// id and never learns it was dropped believes its logs correlate, and only finds
// out during the incident when it goes looking for the other half.
func TestRemoteCarriesTraceIDOntoTheServerAuditLine(t *testing.T) {
	var log bytes.Buffer
	r := newRemote(t, startLoggingServer(t, &log))

	ctx := NewTraceContext(context.Background(), "9af31c02")
	if _, err := r.RunJavaScript(ctx, sandbox.Request{Code: "1", Timeout: 5 * time.Second}); err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if got := log.String(); !strings.Contains(got, `"trace_id":"9af31c02"`) {
		t.Errorf("server audit line has no trace id, so the caller's log cannot join to it\nlog: %s", got)
	}
}

// The same path with a hostile id: the server must drop it whole rather than
// record a path into the stream that promises it holds none. Proven end to end
// because a client-side or wire-side repair would defeat the server's guard.
func TestRemoteHostileTraceIDIsDroppedByTheServer(t *testing.T) {
	var log bytes.Buffer
	r := newRemote(t, startLoggingServer(t, &log))

	ctx := NewTraceContext(context.Background(), "/v1/customers/8821?ssn=123-45-6789")
	if _, err := r.RunJavaScript(ctx, sandbox.Request{Code: "1", Timeout: 5 * time.Second}); err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	got := log.String()
	if !strings.Contains(got, `"trace_id_rejected":true`) {
		t.Errorf("server did not record that it dropped a non-conforming id\nlog: %s", got)
	}
	for _, leak := range []string{"customers", "ssn", "8821"} {
		if strings.Contains(got, leak) {
			t.Errorf("hostile trace id leaked %q into the daemon audit stream\nlog: %s", leak, got)
		}
	}
}

func newRemote(t *testing.T, baseURL string, opts ...Option) *Remote {
	t.Helper()
	r, err := New(baseURL, opts...)
	if err != nil {
		t.Fatalf("New(%q): %v", baseURL, err)
	}
	return r
}

func TestNewValidatesBaseURLAndFailsClosedOnRemoteHTTP(t *testing.T) {
	for _, raw := range []string{
		"https://plimsoll.example",
		"https://plimsoll.example/grpc",
		"http://localhost:8746",
		"http://LOCALHOST:8746",
		"http://127.0.0.1:8746",
		"http://[::1]:8746",
	} {
		if _, err := New(raw); err != nil {
			t.Errorf("New(%q) rejected valid URL: %v", raw, err)
		}
	}

	for _, raw := range []string{
		"", " https://plimsoll.example", "plimsoll.example", "//plimsoll.example",
		"ftp://plimsoll.example", "http://", "https://user@plimsoll.example",
		"https://plimsoll.example/path?debug=1", "https://plimsoll.example/#fragment",
	} {
		if _, err := New(raw); !errors.Is(err, ErrInvalidBaseURL) {
			t.Errorf("New(%q) error = %v, want ErrInvalidBaseURL", raw, err)
		}
	}

	if _, err := New("http://plimsoll.internal:8746"); !errors.Is(err, ErrInsecureHTTP) {
		t.Fatalf("remote HTTP error = %v, want ErrInsecureHTTP", err)
	}
	if _, err := New("http://plimsoll.internal:8746", WithInsecureHTTP()); err != nil {
		t.Fatalf("explicit insecure HTTP opt-in rejected: %v", err)
	}
	if _, err := New("ftp://plimsoll.internal", WithInsecureHTTP()); !errors.Is(err, ErrInvalidBaseURL) {
		t.Fatalf("WithInsecureHTTP legalized invalid scheme: %v", err)
	}
}

type legacyDescribeServer struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
}

type weakEvidenceServer struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
}

func (weakEvidenceServer) RunJavaScriptV2(context.Context, *connect.Request[plimsollv1.RunJavaScriptV2Request]) (*connect.Response[plimsollv1.RunJavaScriptV2Response], error) {
	return connect.NewResponse(&plimsollv1.RunJavaScriptV2Response{
		Stdout: []byte("already executed"), Sandbox: "forged", Isolation: "container",
	}), nil
}

func (weakEvidenceServer) RunProjectV2(context.Context, *connect.Request[plimsollv1.RunProjectV2Request]) (*connect.Response[plimsollv1.RunProjectV2Response], error) {
	return connect.NewResponse(&plimsollv1.RunProjectV2Response{
		Sandbox: "forged", Isolation: "unknown",
	}), nil
}

func (legacyDescribeServer) Describe(context.Context, *connect.Request[plimsollv1.DescribeRequest]) (*connect.Response[plimsollv1.DescribeResponse], error) {
	return connect.NewResponse(&plimsollv1.DescribeResponse{Sandbox: "legacy", Isolation: "kernel"}), nil
}

type v1OnlyHTTPBackend struct {
	jsRuns      int
	projectRuns int
}

func (s *v1OnlyHTTPBackend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// These are the only execution routes an old binary exposes. If the official
	// client regresses to either path, record that code could have executed.
	switch req.URL.Path {
	case "/plimsoll.v1.SandboxService/RunJavaScript":
		s.jsRuns++
	case "/plimsoll.v1.SandboxService/RunProject":
		s.projectRuns++
	default:
		_ = connect.NewErrorWriter().Write(w, req,
			connect.NewError(connect.CodeUnimplemented, errors.New("procedure is not implemented by this old backend")))
	}
}

func TestDescribeReportsMinimumIsolationProtocolSupport(t *testing.T) {
	current := newRemote(t, startServer(t, nil))
	info, err := current.Describe(context.Background())
	if err != nil || !info.SupportsMinimumIsolation {
		t.Fatalf("current Describe = %+v, err=%v; want minimum-isolation support", info, err)
	}

	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(legacyDescribeServer{}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	legacy := newRemote(t, server.URL)
	info, err = legacy.Describe(context.Background())
	if err != nil {
		t.Fatalf("legacy Describe: %v", err)
	}
	if info.SupportsMinimumIsolation {
		t.Fatalf("legacy server without feature field reported support: %+v", info)
	}
}

func TestEveryRequestUsesV2AndCannotExecuteOnV1OnlyBackend(t *testing.T) {
	backend := &v1OnlyHTTPBackend{}
	server := httptest.NewServer(backend)
	t.Cleanup(server.Close)
	r := newRemote(t, server.URL)

	for name, minimum := range map[string]sandbox.IsolationClass{
		"floored":   sandbox.IsolationProcess,
		"unfloored": sandbox.IsolationUnknown,
	} {
		t.Run(name, func(t *testing.T) {
			_, jsErr := r.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: minimum})
			if connect.CodeOf(jsErr) != connect.CodeUnimplemented {
				t.Fatalf("JavaScript code = %v, err=%v; want Unimplemented", connect.CodeOf(jsErr), jsErr)
			}
			_, projectErr := r.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"true"}, MinimumIsolation: minimum})
			if connect.CodeOf(projectErr) != connect.CodeUnimplemented {
				t.Fatalf("project code = %v, err=%v; want Unimplemented", connect.CodeOf(projectErr), projectErr)
			}
		})
	}
	if backend.jsRuns != 0 || backend.projectRuns != 0 {
		t.Fatalf("official client reached old execution routes: JS/project=%d/%d", backend.jsRuns, backend.projectRuns)
	}
}

func TestRemoteClassifiesWeakResponseEvidenceAsPostDispatchDataLoss(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(weakEvidenceServer{}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	r := newRemote(t, server.URL)

	js, jsErr := r.RunJavaScript(context.Background(), sandbox.Request{
		Code: "mutate()", MinimumIsolation: sandbox.IsolationKernel,
	})
	if connect.CodeOf(jsErr) != connect.CodeDataLoss || !errors.Is(jsErr, sandbox.ErrIsolationEvidenceMismatch) {
		t.Fatalf("JavaScript result=%+v err=%v, want DataLoss/ErrIsolationEvidenceMismatch", js, jsErr)
	}
	if errors.Is(jsErr, sandbox.ErrInsufficientIsolation) || js.Stdout != "already executed" {
		t.Fatalf("post-dispatch mismatch was classified as safe rejection or lost evidence: result=%+v err=%v", js, jsErr)
	}

	project, projectErr := r.RunProject(context.Background(), sandbox.ProjectRequest{
		Steps: []string{"mutate"}, MinimumIsolation: sandbox.IsolationVM,
	})
	if connect.CodeOf(projectErr) != connect.CodeDataLoss || !errors.Is(projectErr, sandbox.ErrIsolationEvidenceMismatch) {
		t.Fatalf("project result=%+v err=%v, want DataLoss/ErrIsolationEvidenceMismatch", project, projectErr)
	}
	if errors.Is(projectErr, sandbox.ErrInsufficientIsolation) {
		t.Fatalf("project post-dispatch mismatch was classified as safe rejection: %v", projectErr)
	}
}

// TestRemoteRunJavaScriptKeyless drives the real wasm sandbox through the Connect
// client with no token (keyless server).
func TestRemoteRunJavaScriptKeyless(t *testing.T) {
	url := startServer(t, nil)
	r := newRemote(t, url)
	res, err := r.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(6*7)`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "42") {
		t.Fatalf("got exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if res.Sandbox != "wasm" {
		t.Fatalf("sandbox = %q, want wasm (provider name flows back through RPC)", res.Sandbox)
	}
}

func TestRemoteSerializesAndServerEnforcesPerRequestMinimumIsolation(t *testing.T) {
	url := startServer(t, nil) // wasm reports process isolation
	r := newRemote(t, url)

	_, err := r.RunJavaScript(context.Background(), sandbox.Request{
		Code: "1", MinimumIsolation: sandbox.IsolationKernel,
	})
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("JavaScript code = %v, want FailedPrecondition (err: %v)", connect.CodeOf(err), err)
	}
	if !errors.Is(err, sandbox.ErrInsufficientIsolation) {
		t.Fatalf("JavaScript error = %v, want ErrInsufficientIsolation", err)
	}

	// The server checks the floor before provider dispatch. WASM would normally
	// return ErrUnsupported for projects, so FailedPrecondition proves the project
	// request field also crossed the official client/server wire.
	_, err = r.RunProject(context.Background(), sandbox.ProjectRequest{
		Steps: []string{"true"}, MinimumIsolation: sandbox.IsolationVM,
	})
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !errors.Is(err, sandbox.ErrInsufficientIsolation) {
		t.Fatalf("project error = %v, want FailedPrecondition/ErrInsufficientIsolation", err)
	}

	res, err := r.RunJavaScript(context.Background(), sandbox.Request{
		Code: "console.log(1)", MinimumIsolation: sandbox.IsolationProcess,
	})
	if err != nil || res.Isolation != sandbox.IsolationProcess {
		t.Fatalf("matching process floor: result=%+v err=%v", res, err)
	}
}

// TestRemoteWithToken confirms the token is sent and accepted by a fail-closed server.
func TestRemoteWithToken(t *testing.T) {
	url := startServer(t, fakeVerifier{token: "tok", scopes: []string{rpc.ScopeCodeRun}})
	r := newRemote(t, url, WithToken("tok"))
	res, err := r.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log("ok")`})
	if err != nil {
		t.Fatalf("authenticated call failed: %v", err)
	}
	if !strings.Contains(res.Stdout, "ok") {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

// TestRemoteMissingTokenRejected confirms a fail-closed server rejects a tokenless client.
func TestRemoteMissingTokenRejected(t *testing.T) {
	url := startServer(t, fakeVerifier{token: "tok", scopes: []string{rpc.ScopeCodeRun}})
	r := newRemote(t, url) // no token
	_, err := r.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(1)`})
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

// fakeVerifier accepts exactly one token.
type fakeVerifier struct {
	token  string
	scopes []string
}

func (v fakeVerifier) VerifyToken(_ context.Context, token string) (rpc.Principal, bool, error) {
	if token != v.token {
		return rpc.Principal{}, false, nil
	}
	return rpc.Principal{UserID: "u1", Scopes: v.scopes}, true, nil
}

// TestTimeoutMsClamps verifies the client clamps (not truncates) an oversized budget
// to the proto int32 field: a value beyond int32 (~24.8 days) would otherwise wrap to
// a negative/short deadline instead of the large one the caller asked for.
func TestTimeoutMsClamps(t *testing.T) {
	const maxInt32 = 1<<31 - 1
	if got := timeoutMs(2 * time.Second); got != 2000 {
		t.Errorf("timeoutMs(2s) = %d, want 2000", got)
	}
	if got := timeoutMs(-1 * time.Second); got != 0 {
		t.Errorf("timeoutMs(-1s) = %d, want 0", got)
	}
	if got := timeoutMs(time.Nanosecond); got != 1 {
		t.Errorf("timeoutMs(1ns) = %d, want 1 (positive budgets must not become provider-default 0)", got)
	}
	// 30 days in ms is > int32 max; must clamp to MaxInt32, never wrap negative.
	if got := timeoutMs(30 * 24 * time.Hour); got != maxInt32 {
		t.Errorf("timeoutMs(30d) = %d, want %d (no int32 wrap)", got, maxInt32)
	}
}

func TestRemoteNeverSilentlyDropsRawGrant(t *testing.T) {
	r := newRemote(t, "http://127.0.0.1:1")
	grant := &sandbox.HostAPIGrant{BaseURL: "https://host.internal"}
	if _, err := r.RunJavaScript(context.Background(), sandbox.Request{Code: "1", Grant: grant}); !errors.Is(err, ErrRawGrantUnsupported) {
		t.Fatalf("RunJavaScript error = %v, want ErrRawGrantUnsupported", err)
	}
	if _, err := r.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"true"}, Grant: grant}); !errors.Is(err, ErrRawGrantUnsupported) {
		t.Fatalf("RunProject error = %v, want ErrRawGrantUnsupported", err)
	}
}

func TestRemoteSendsNamedGrantProfile(t *testing.T) {
	url := startServer(t, nil)
	r := newRemote(t, url, WithJavaScriptGrantProfile("missing-profile"))
	_, err := r.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument proving grant_profile reached server", connect.CodeOf(err))
	}
}

func TestRemoteGrantProfilesAreOperationSpecific(t *testing.T) {
	url := startServer(t, nil)
	r := newRemote(t, url, WithJavaScriptGrantProfile("missing-profile"))
	// The JavaScript profile must not bleed into an isolated project call. WASM
	// rejects projects as Unsupported; an unknown profile would be InvalidArgument.
	_, err := r.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"true"}})
	if !errors.Is(err, sandbox.ErrUnsupported) {
		t.Fatalf("project error = %v, want provider ErrUnsupported rather than leaked JS profile", err)
	}
}

func TestRestoreSandboxErrorPreservesSentinelAndConnectCode(t *testing.T) {
	for _, tc := range []struct {
		code     connect.Code
		sentinel error
	}{
		{connect.CodeCanceled, context.Canceled},
		{connect.CodeDeadlineExceeded, context.DeadlineExceeded},
		{connect.CodeFailedPrecondition, sandbox.ErrDisabled},
		{connect.CodeUnimplemented, sandbox.ErrUnsupported},
		{connect.CodeResourceExhausted, sandbox.ErrAtCapacity},
		{connect.CodeInvalidArgument, sandbox.ErrInvalidRequest},
	} {
		wireErr := connect.NewError(tc.code, errors.New("wire detail"))
		got := restoreSandboxError(wireErr)
		if !errors.Is(got, tc.sentinel) {
			t.Errorf("code %v: errors.Is(%v) = false", tc.code, tc.sentinel)
		}
		if connect.CodeOf(got) != tc.code {
			t.Errorf("code %v became %v", tc.code, connect.CodeOf(got))
		}
	}
	isolationWireErr := connect.NewError(connect.CodeFailedPrecondition,
		errors.New(sandbox.ErrInsufficientIsolation.Error()+": provider isolation container is below requested minimum kernel"))
	if got := restoreSandboxError(isolationWireErr); !errors.Is(got, sandbox.ErrInsufficientIsolation) || errors.Is(got, sandbox.ErrDisabled) {
		t.Fatalf("isolation FailedPrecondition restored as %v", got)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	loop := []string{"localhost", "127.0.0.1", "::1"}
	remote := []string{"plimsoll", "10.0.0.5", "example.com", ""}
	for _, h := range loop {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false, want true", h)
		}
	}
	for _, h := range remote {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true, want false", h)
		}
	}
}

// TestTraceContextRoundTrip proves the id set at the caller's boundary reaches the
// wire request. Without this the join key is set and silently dropped, which is
// worse than not having one: the caller believes its logs correlate.
func TestTraceContextRoundTrip(t *testing.T) {
	ctx := NewTraceContext(context.Background(), "9af31c02")
	if got := TraceIDFrom(ctx); got != "9af31c02" {
		t.Fatalf("TraceIDFrom = %q, want 9af31c02", got)
	}
}

// An empty id must not put a value in the context, so a caller that conditionally
// correlates cannot accidentally send "".
func TestTraceContextIgnoresEmpty(t *testing.T) {
	ctx := NewTraceContext(context.Background(), "")
	if got := TraceIDFrom(ctx); got != "" {
		t.Fatalf("TraceIDFrom = %q, want empty", got)
	}
}

// A context that never saw NewTraceContext is the common case and must not panic
// on the type assertion.
func TestTraceIDFromBareContext(t *testing.T) {
	if got := TraceIDFrom(context.Background()); got != "" {
		t.Fatalf("TraceIDFrom = %q, want empty", got)
	}
}
