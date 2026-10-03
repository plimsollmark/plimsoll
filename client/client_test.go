package client

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
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

// stamped answers req with resp and the record a daemon states for it.
func stamped(req *connect.Request[plimsollv1.RunRequest], resp *plimsollv1.RunResponse) *connect.Response[plimsollv1.RunResponse] {
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req.Msg)}, resp)
	return connect.NewResponse(resp)
}

// unrecordedServer answers every run without a record.
type unrecordedServer struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
}

func (unrecordedServer) Run(context.Context, *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	return connect.NewResponse(&plimsollv1.RunResponse{Sandbox: "unrecorded", Isolation: "vm",
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("already executed")}}}), nil
}

type weakEvidenceServer struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
}

// Run answers with forged evidence of the request's kind: a daemon that ran the
// code behind a weaker boundary than the floor and says so.
func (weakEvidenceServer) Run(_ context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	switch req.Msg.GetPayload().(type) {
	case *plimsollv1.RunRequest_Javascript:
		return stamped(req, &plimsollv1.RunResponse{Sandbox: "forged", Isolation: "container",
			Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("already executed")}}}), nil
	case *plimsollv1.RunRequest_Project:
		return stamped(req, &plimsollv1.RunResponse{Sandbox: "forged", Isolation: "unknown",
			Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{}}}), nil
	}
	return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("no payload"))
}

// otherProtocolServer is a daemon on another protocol number: it records what
// the client stated and refuses exactly as plimsolld does, before any dispatch.
type otherProtocolServer struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
	serves     uint32
	stated     []uint32
	dispatched int
}

func (s *otherProtocolServer) Run(_ context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	s.stated = append(s.stated, req.Msg.GetProtocol())
	if req.Msg.GetProtocol() != s.serves {
		return nil, notDispatchedWireErr(connect.CodeUnimplemented,
			plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PROTOCOL, protocol.Mismatch(s.serves, req.Msg.GetProtocol()))
	}
	s.dispatched++
	return connect.NewResponse(&plimsollv1.RunResponse{Sandbox: "other", Isolation: "vm",
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{}}}), nil
}

func (s *otherProtocolServer) Describe(context.Context, *connect.Request[plimsollv1.DescribeRequest]) (*connect.Response[plimsollv1.DescribeResponse], error) {
	return connect.NewResponse(&plimsollv1.DescribeResponse{Sandbox: "other", Isolation: "vm", Protocol: s.serves}), nil
}

// Describe's informational statements survive the wire into Info.
func TestDescribeReportsEnvironmentsAndResources(t *testing.T) {
	svc := rpc.NewSandboxService(sandboxtest.Wasm())
	svc.Resources = sandbox.Resources{MemoryMB: 128}
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	info, err := newRemote(t, srv.URL).Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := sandboxtest.Wasm().Environments()
	if !reflect.DeepEqual(info.Environments, want) || !strings.HasPrefix(want.JavaScript.Identity, "quickjs-wasm:sha256:") {
		t.Fatalf("Environments = %+v, want %+v", info.Environments, want)
	}
	if info.Resources != (sandbox.Resources{MemoryMB: 128}) {
		t.Fatalf("Resources = %+v", info.Resources)
	}
}

// Describe reports the daemon's protocol number and the client exposes it, so a
// consumer can compare before it sends anything.
func TestDescribeReportsProtocol(t *testing.T) {
	info, err := newRemote(t, startServer(t, nil)).Describe(context.Background())
	if err != nil || info.Protocol != Protocol {
		t.Fatalf("Describe = %+v, err=%v; want protocol %d", info, err, Protocol)
	}
}

// Every request states the client's protocol number, and a daemon on another
// number refuses it before dispatch: the client reports ErrProtocolMismatch, not
// an unsupported operation, for every payload kind.
func TestEveryRequestStatesProtocolAndOtherNumberRefusesBeforeDispatch(t *testing.T) {
	backend := &otherProtocolServer{serves: Protocol + 1}
	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(backend))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	r := newRemote(t, server.URL)

	info, err := r.Describe(context.Background())
	if err != nil || info.Protocol == Protocol {
		t.Fatalf("Describe = %+v, err=%v; want the other daemon's number", info, err)
	}
	_, jsErr := r.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	_, projectErr := r.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"true"}})
	_, moduleErr := r.RunModule(context.Background(), sandbox.ModuleRequest{Model: "m", Rows: [][]float64{{1}}, EndTime: 1, Step: 0.01})
	for name, err := range map[string]error{"javascript": jsErr, "project": projectErr, "module": moduleErr} {
		if !errors.Is(err, ErrProtocolMismatch) || errors.Is(err, sandbox.ErrUnsupported) || connect.CodeOf(err) != connect.CodeUnimplemented {
			t.Errorf("%s: err = %v; want ErrProtocolMismatch (Unimplemented), not ErrUnsupported", name, err)
		}
	}
	if len(backend.stated) != 3 {
		t.Fatalf("daemon saw %d requests, want 3", len(backend.stated))
	}
	for _, n := range backend.stated {
		if n != Protocol {
			t.Fatalf("client stated protocol %d, want %d", n, Protocol)
		}
	}
	if backend.dispatched != 0 {
		t.Fatalf("a daemon on another number dispatched %d runs", backend.dispatched)
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
	// An unknown profile is refused exactly like one the caller is not on; the name
	// in the refusal proves grant_profile reached the server.
	if connect.CodeOf(err) != connect.CodePermissionDenied || !strings.Contains(err.Error(), "missing-profile") {
		t.Fatalf("err = %v, want PermissionDenied naming the profile, proving grant_profile reached server", err)
	}
}

func TestRemoteGrantProfilesAreOperationSpecific(t *testing.T) {
	url := startServer(t, nil)
	r := newRemote(t, url, WithJavaScriptGrantProfile("missing-profile"))
	// The JavaScript profile must not bleed into an isolated project call. WASM
	// rejects projects as Unsupported; an unknown profile would be PermissionDenied.
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
	// The reason separates the two meanings of FailedPrecondition, not the text:
	// a message that merely names the isolation sentinel, with no detail, is the
	// disabled-provider condition and is not marked as refused before dispatch.
	isolationWireErr := notDispatchedWireErr(connect.CodeFailedPrecondition,
		plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION, "provider isolation container is below requested minimum kernel")
	got := restoreSandboxError(isolationWireErr)
	if !errors.Is(got, sandbox.ErrInsufficientIsolation) || errors.Is(got, sandbox.ErrDisabled) {
		t.Fatalf("isolation FailedPrecondition restored as %v", got)
	}
	if r, ok := sandbox.NotDispatchedReason(got); !ok || r != sandbox.RefusalIsolation {
		t.Fatalf("isolation refusal reason = %v, %v; want isolation, true", r, ok)
	}
	textOnly := restoreSandboxError(connect.NewError(connect.CodeFailedPrecondition,
		errors.New(sandbox.ErrInsufficientIsolation.Error())))
	if errors.Is(textOnly, sandbox.ErrInsufficientIsolation) {
		t.Fatalf("message text alone restored the isolation sentinel: %v", textOnly)
	}
	if _, ok := sandbox.NotDispatchedReason(textOnly); ok {
		t.Fatalf("an error without the detail must read as possibly executed: %v", textOnly)
	}
}

func notDispatchedWireErr(code connect.Code, reason plimsollv1.NotDispatchedReason, msg string) *connect.Error {
	ce := connect.NewError(code, errors.New(msg))
	d, err := connect.NewErrorDetail(&plimsollv1.NotDispatched{Reason: reason})
	if err != nil {
		panic(err)
	}
	ce.AddDetail(d)
	return ce
}

// The real daemon marks each refusal that ran nothing, the client restores the
// mark, and sandbox.NotDispatchedReason reads it exactly as it would from a local
// provider. A completed run carries no error at all.
func TestRemoteRefusalsCarryNotDispatchedReason(t *testing.T) {
	r := newRemote(t, startServer(t, nil)) // wasm: process tier, no projects
	ctx := context.Background()
	for name, tc := range map[string]struct {
		run  func() error
		want sandbox.Refusal
	}{
		"empty snippet": {func() error { _, err := r.RunJavaScript(ctx, sandbox.Request{}); return err }, sandbox.RefusalRequest},
		"floor": {func() error {
			_, err := r.RunJavaScript(ctx, sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM})
			return err
		}, sandbox.RefusalIsolation},
		"wasm project": {func() error { _, err := r.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"true"}}); return err }, sandbox.RefusalUnsupported},
		"wasm module": {func() error {
			_, err := r.RunModule(ctx, sandbox.ModuleRequest{Model: "m", Rows: [][]float64{{1}}, EndTime: 1, Step: 1})
			return err
		}, sandbox.RefusalUnsupported},
	} {
		err := tc.run()
		if got, ok := sandbox.NotDispatchedReason(err); !ok || got != tc.want {
			t.Errorf("%s: reason = %v, %v (err %v); want %v, true", name, got, ok, err, tc.want)
		}
	}
	if _, err := r.RunJavaScript(ctx, sandbox.Request{Code: "console.log(1)"}); err != nil {
		t.Fatalf("a completed run returned %v", err)
	}
}

func TestRemoteRestoresSoftwareMismatch(t *testing.T) {
	r := newRemote(t, startServer(t, nil)) // wasm states no selected image
	rule := sandbox.SoftwareRule{Mode: sandbox.SoftwareExact, Identities: []string{"oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64)}}
	_, err := r.RunJavaScript(context.Background(), sandbox.Request{Code: "1", Software: rule})
	if !errors.Is(err, sandbox.ErrSoftwareMismatch) {
		t.Fatalf("software mismatch lost its typed error: %v", err)
	}
	if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalEnvironment {
		t.Fatalf("software mismatch lost its environment refusal: %v, %v", reason, ok)
	}
}

// A failure after dispatch carries no detail, so it never reads as safe to retry.
func TestRemoteInternalErrorIsNotMarked(t *testing.T) {
	err := restoreSandboxError(connect.NewError(connect.CodeInternal, errors.New("provider crashed mid-run")))
	if _, ok := sandbox.NotDispatchedReason(err); ok {
		t.Fatalf("internal error read as not dispatched: %v", err)
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

// The client returns the daemon's run record once it has checked it against the
// request it sent and the response it received.
func TestRemoteReturnsACheckedRunRecord(t *testing.T) {
	r := newRemote(t, startServer(t, nil))
	res, err := r.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(6*7)`})
	if err != nil {
		t.Fatal(err)
	}
	rec := res.Record
	if rec == nil {
		t.Fatal("no run record")
	}
	if rec.Provider != "wasm" || rec.Isolation != "process" || !strings.HasPrefix(rec.Environment, "quickjs-wasm:sha256:") {
		t.Fatalf("evidence: %+v", rec)
	}
	if rec.SHA256 != record.Digest(*rec) || rec.Ended.Before(rec.Started) {
		t.Fatalf("record: %+v", rec)
	}
}

// tamperingServer is a daemon, or anything between it and the client, that
// changes a result after the record was computed.
type tamperingServer struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
	inner *rpc.SandboxService
}

func (s tamperingServer) Run(ctx context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	resp, err := s.inner.Run(ctx, req)
	if err == nil {
		resp.Msg.GetJavascript().Stdout = []byte("43\n")
	}
	return resp, err
}

func TestRemoteClassifiesAMismatchedRecordAsDataLoss(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(tamperingServer{inner: rpc.NewSandboxService(sandboxtest.Wasm())}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	res, err := newRemote(t, server.URL).RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(6*7)`})
	if connect.CodeOf(err) != connect.CodeDataLoss || !errors.Is(err, record.ErrMismatch) {
		t.Fatalf("err = %v, want DataLoss wrapping record.ErrMismatch", err)
	}
	if res.Stdout != "43\n" || res.Record != nil {
		t.Fatalf("the result must come back as received, without a record: %+v", res)
	}
}

type recorderFunc func(*plimsollv1.RunRequest, *plimsollv1.RunResponse) error

func (f recorderFunc) Record(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) error {
	return f(req, resp)
}

// The recorder sees each checked exchange, and its failure returns the executed
// result with ErrNotRecorded. An answer with no record is DataLoss before any
// recorder sees it, with the result still returned: the run may have executed.
func TestRemoteRecorder(t *testing.T) {
	var seen []string
	ok := recorderFunc(func(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) error {
		seen = append(seen, req.GetJavascript().GetCode()+" -> "+resp.GetRecord().GetRecordSha256())
		return nil
	})
	url := startServer(t, nil)
	res, err := newRemote(t, url, WithRecorder(ok)).RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(1)`})
	if err != nil || len(seen) != 1 || !strings.HasSuffix(seen[0], res.Record.SHA256) {
		t.Fatalf("seen %v, err %v", seen, err)
	}

	failing := recorderFunc(func(*plimsollv1.RunRequest, *plimsollv1.RunResponse) error { return errors.New("disk full") })
	res, err = newRemote(t, url, WithRecorder(failing)).RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(1)`})
	if !errors.Is(err, ErrNotRecorded) || res.Stdout != "1\n" || res.Record == nil {
		t.Fatalf("a failing recorder: result %+v, err %v", res, err)
	}

	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(unrecordedServer{}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	seen = nil
	res, err = newRemote(t, server.URL, WithRecorder(ok)).RunJavaScript(context.Background(), sandbox.Request{Code: "x"})
	if connect.CodeOf(err) != connect.CodeDataLoss || !errors.Is(err, record.ErrNoRecord) || res.Stdout != "already executed" || len(seen) != 0 {
		t.Fatalf("no record: result %+v, err %v, recorded %v", res, err, seen)
	}
}

// A redirect is never followed: the code would go to wherever it points. That holds
// for an HTTP client the caller supplies too, which by default follows a 307.
func TestRedirectIsNotFollowed(t *testing.T) {
	for name, opts := range map[string][]Option{
		"default":  {WithToken("tok")},
		"caller's": {WithToken("tok"), WithHTTPClient(&http.Client{Timeout: time.Minute})},
	} {
		t.Run(name, func(t *testing.T) { redirectNotFollowed(t, opts) })
	}
}

func redirectNotFollowed(t *testing.T, opts []Option) {
	var elsewhere int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere++
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	r, err := New(srv.URL, opts...)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = r.RunJavaScript(ctx, sandbox.Request{Code: "secret()", Timeout: 5 * time.Second})
	if err == nil || connect.CodeOf(err) != connect.CodeUnknown {
		t.Fatalf("a run answered with a redirect: %v (code %v); want an error, unknown", err, connect.CodeOf(err))
	}
	if elsewhere != 0 {
		t.Fatalf("the redirect target received %d requests; want none", elsewhere)
	}
}

// A recorder that fails must not hide evidence below the floor: the answer is
// DataLoss wrapping ErrIsolationEvidenceMismatch, and the recorder never sees it.
func TestRecorderFailureKeepsTheIsolationCheck(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(weakEvidenceServer{}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	var recorded int
	failing := recorderFunc(func(*plimsollv1.RunRequest, *plimsollv1.RunResponse) error {
		recorded++
		return errors.New("disk full")
	})
	res, err := newRemote(t, server.URL, WithRecorder(failing)).RunJavaScript(context.Background(), sandbox.Request{
		Code: "mutate()", MinimumIsolation: sandbox.IsolationVM,
	})
	if connect.CodeOf(err) != connect.CodeDataLoss || !errors.Is(err, sandbox.ErrIsolationEvidenceMismatch) || res.Stdout != "already executed" {
		t.Fatalf("result %+v, err %v; want the result with DataLoss wrapping ErrIsolationEvidenceMismatch", res, err)
	}
	if recorded != 0 {
		t.Fatalf("the recorder was handed %d exchanges below the floor; want none", recorded)
	}
}

// unansweredV2Server answers with a version 2 record that also names an unanswered
// code, a field version 2's digest does not cover.
type unansweredV2Server struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
}

func (unansweredV2Server) Run(_ context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	resp := stamped(req, &plimsollv1.RunResponse{Sandbox: "forged", Isolation: "vm",
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("ran")}}})
	resp.Msg.Record.Unanswered = "unknown"
	return resp, nil
}

func TestVersion2RecordStatingUnansweredIsDataLoss(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(unansweredV2Server{}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	_, err := newRemote(t, server.URL).RunJavaScript(context.Background(), sandbox.Request{Code: "x"})
	if connect.CodeOf(err) != connect.CodeDataLoss || !errors.Is(err, record.ErrMismatch) {
		t.Fatalf("err = %v, want DataLoss wrapping record.ErrMismatch", err)
	}
}
