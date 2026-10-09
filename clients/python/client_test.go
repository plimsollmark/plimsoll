// Package python holds no Go code but this test: it serves the real RPC handler
// and runs the Python client's suite against it, so the client is proven against
// the daemon it talks to rather than against a recording of one. It also hands the
// suite a fixture of run-record digests the Go record package computed over JSON
// the Go protobuf encoder wrote, so the two digest implementations are compared on
// the daemon's own encoding of awkward values.
package python

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// TestPython serves six daemons and runs the Python suite against them:
//
//   - wasm: the real wasm provider, for single runs and its refusals;
//   - auth: the same behind a bearer token;
//   - tamper: the real wasm provider with each snippet's output changed after its
//     record was computed, as anything between the daemon and the client could;
//   - scripted: a provider that runs nothing and answers projects, modules and
//     snippets with fixed, awkward results, behind the real handler, which states
//     their records;
//   - liar: a handler that breaks the protocol in the ways the client must catch;
//   - sessions: the in-memory session provider, with POST /test/end-last ending the
//     most recently opened session as a lifetime or a disk budget would;
//   - tls: the real wasm provider over TLS, its certificate (for 127.0.0.1, ::1 and
//     example.com) handed to the suite as the only trusted authority.
//
// The suite fails rather than skips when it is run here, so a green test means
// every case ran. It needs python3 >= 3.10 and nothing else.
func TestPython(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		clientSkipOrFail(t, "python3 is not installed")
	}
	if out, err := exec.Command(python, "-c", "import sys; sys.exit(sys.version_info < (3, 10))").CombinedOutput(); err != nil {
		clientSkipOrFail(t, "the client needs Python 3.10 or later: %v %s", err, out)
	}

	sessions := &sandboxtest.Sessions{}
	sessionSvc := quiet(rpc.NewSandboxService(sessions))
	sessionSvc.Sessions = rpc.SessionConfig{MaxSessions: 16, MaxPerOwner: 1, Lifetime: time.Minute, IdleTimeout: time.Minute}
	ends := map[string]sandbox.SessionEnd{"expired": sandbox.SessionExpired, "disk_exceeded": sandbox.SessionDiskExceeded}

	fixture := filepath.Join(t.TempDir(), "digests.json")
	writeFixture(t, fixture)
	tlsURL, tlsCA := serveTLS(t, quiet(rpc.NewSandboxService(sandboxtest.Wasm())))

	env := append(os.Environ(),
		"PLIMSOLL_WASM_URL="+serve(t, quiet(rpc.NewSandboxService(sandboxtest.Wasm())), nil, nil),
		"PLIMSOLL_AUTH_URL="+serve(t, quiet(rpc.NewSandboxService(sandboxtest.Wasm())), verifier{token: "py-token"}, nil),
		"PLIMSOLL_TAMPER_URL="+serve(t, tampering{quiet(rpc.NewSandboxService(sandboxtest.Wasm()))}, nil, nil),
		"PLIMSOLL_SCRIPTED_URL="+serve(t, quiet(rpc.NewSandboxService(scripted{})), nil, nil),
		"PLIMSOLL_LIAR_URL="+serve(t, liar{}, nil, nil),
		"PLIMSOLL_SESSIONS_URL="+serve(t, sessionSvc, nil, func(mux *http.ServeMux) {
			mux.HandleFunc("POST /test/end-last", func(w http.ResponseWriter, r *http.Request) {
				opened := sessions.Opened()
				reason, ok := ends[r.URL.Query().Get("reason")]
				if len(opened) == 0 || !ok {
					http.Error(w, "no session, or an unknown reason", http.StatusBadRequest)
					return
				}
				opened[len(opened)-1].End(reason)
			})
		}),
		"PLIMSOLL_BREAKING_URL="+serve(t, breakingSvc(), nil, nil),
		"PLIMSOLL_LOSSY_URL="+lossyProxy(t, serve(t, plainSessionSvc(), nil, nil)),
		"PLIMSOLL_TLS_URL="+tlsURL,
		"PLIMSOLL_TLS_CA="+tlsCA,
		"PLIMSOLL_SCRIPTED_SOFTWARE="+scriptedSoftware,
		"PLIMSOLL_GO_PROTOCOL="+strconv.FormatUint(uint64(protocol.Number), 10),
		"PLIMSOLL_GO_RECORD_VERSION="+strconv.Itoa(record.Version),
		"PLIMSOLL_DIGEST_FIXTURE="+fixture,
		"PLIMSOLL_INTEGRATION_REQUIRED=1",
		"PYTHONPATH=src",
		"PYTHONDONTWRITEBYTECODE=1",
	)
	cmd := exec.Command(python, "-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("python3 -m unittest: %v", err)
	}
	// unittest -v marks a skip "... skipped 'reason'" and counts them "(skipped=N)"; a
	// test whose name contains the word must not read as one.
	if pythonSkip.Match(out) {
		t.Fatal("the Python suite skipped a case; under this test every case must run")
	}
}

func clientSkipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("PLIMSOLL_REQUIRE_CLIENTS") == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

var pythonSkip = regexp.MustCompile(`(?m)\.\.\. skipped|skipped=[0-9]+`)

// quiet is svc without its audit log, which would only fill the test output.
func quiet(svc *rpc.SandboxService) *rpc.SandboxService {
	svc.Logger = slog.New(slog.DiscardHandler)
	return svc
}

func serve(t *testing.T, h plimsollv1connect.SandboxServiceHandler, v rpc.TokenVerifier, extra func(*http.ServeMux)) string {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := plimsollv1connect.NewSandboxServiceHandler(h, connect.WithInterceptors(rpc.AuthInterceptor(v)))
	mux.Handle(path, handler)
	if extra != nil {
		extra(mux)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// serveTLS serves h over TLS and returns its URL and a PEM file of its certificate,
// which is self-signed and so the authority a client must trust to reach it.
func serveTLS(t *testing.T, h plimsollv1connect.SandboxServiceHandler) (url, caFile string) {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := plimsollv1connect.NewSandboxServiceHandler(h, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, handler)
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL, caFile
}

// verifier accepts exactly one token, with the code:run scope.
type verifier struct{ token string }

func (v verifier) VerifyToken(_ context.Context, token string) (rpc.Principal, bool, error) {
	if token != v.token {
		return rpc.Principal{}, false, nil
	}
	return rpc.Principal{UserID: "python", Scopes: []string{rpc.ScopeCodeRun}}, true, nil
}

// tampering is the real handler with every snippet's output changed after the
// daemon stated its record.
type tampering struct{ *rpc.SandboxService }

func (s tampering) Run(ctx context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	resp, err := s.SandboxService.Run(ctx, req)
	if err == nil && resp.Msg.GetJavascript() != nil {
		resp.Msg.GetJavascript().Stdout = []byte("43\n")
	}
	return resp, err
}

const scriptedSoftware = "oci-manifest:linux/amd64@sha256:5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"

// scripted is a provider that runs nothing. It states a software identity, so a
// caller's software rule is admitted or refused by the real handler, and it answers
// with the values a JSON client is most likely to get wrong: bytes that are not
// UTF-8, negative zero, the largest and smallest doubles, an integer-valued double
// beyond 2^53, and NaN.
type scripted struct{}

var _ sandbox.Sandbox = scripted{}

func (scripted) Name() string                           { return "scripted" }
func (scripted) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationContainer }
func (scripted) SupportsProjects() bool                 { return true }
func (scripted) SupportsModules() bool                  { return true }

func (scripted) Environments() sandbox.Environments {
	kind := sandbox.PayloadEnvironment{Identity: "scripted-image:sha256:0001", SoftwareIdentity: scriptedSoftware, MaxTimeout: time.Minute}
	return sandbox.Environments{JavaScript: kind, Project: kind, Module: kind, Policy: "scripted-policy:sha256:00"}
}

func (scripted) RunJavaScript(_ context.Context, req sandbox.Request) (sandbox.Result, error) {
	return sandbox.Result{
		Stdout: "\xff\xfe" + req.Code, Stderr: "warn\n", ExitCode: 3, StdoutTruncated: true,
		Duration: 5 * time.Millisecond, Sandbox: "scripted", Isolation: sandbox.IsolationContainer,
		SoftwareIdentity: scriptedSoftware, EnvironmentIdentity: "scripted-image:sha256:0001",
	}, nil
}

func (scripted) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	out := sandbox.ProjectResult{
		Sandbox: "scripted", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted,
		SoftwareIdentity: scriptedSoftware, EnvironmentIdentity: "scripted-image:sha256:0001",
	}
	files := map[string]string{}
	for _, f := range req.Files {
		files[f.Path] = f.Content
	}
	for i, step := range req.Steps {
		out.Steps = append(out.Steps, sandbox.StepResult{Command: step, Stdout: strconv.Itoa(i) + "\n", Stderr: "\x00\xff", ExitCode: i, Duration: time.Millisecond})
	}
	for _, a := range req.Artifacts {
		if content, ok := files[a]; ok {
			out.Artifacts = append(out.Artifacts, sandbox.Artifact{Path: a, Content: append([]byte(content), 0x00, 0xff)})
		}
	}
	return out, nil
}

// canonicalNaN is the quiet NaN Python's float("nan") has. JSON writes every NaN as
// "NaN", so only this one survives the trip with its bits; see the NaN cases.
var canonicalNaN = math.Float64frombits(0x7ff8000000000000)

func (scripted) RunModule(_ context.Context, req sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	out := sandbox.ModuleResult{
		Width: 3, Sandbox: "scripted", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted,
		SoftwareIdentity: scriptedSoftware, EnvironmentIdentity: "scripted-image:sha256:0001",
		Stdout: "rows=" + strconv.Itoa(len(req.Rows)) + "\n",
	}
	for i, row := range req.Rows {
		outputs := []float64{row[0], math.Copysign(0, -1), math.MaxFloat64, math.SmallestNonzeroFloat64, 1e21, 123456789012345678901}
		switch req.Model {
		case "nan":
			outputs[1] = canonicalNaN
		case "nan-payload":
			outputs[1] = math.NaN() // Go's NaN carries a payload bit JSON cannot state
		case "nan-negative":
			outputs[1] = math.Float64frombits(0xfff8000000000000) // x86's default NaN, from 0/0
		}
		status := int32(2)
		if i == 1 {
			status, outputs = -3, nil
		}
		out.Runs = append(out.Runs, sandbox.ModuleRun{Status: status, Outputs: outputs})
	}
	return out, nil
}

// liar answers in the ways the client must refuse: weaker evidence than the floor,
// no record, a result of another kind, another protocol, an unmarked failure, and a
// session whose fingerprint or tier is not what was asked for.
type liar struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
}

func (liar) Describe(context.Context, *connect.Request[plimsollv1.DescribeRequest]) (*connect.Response[plimsollv1.DescribeResponse], error) {
	return connect.NewResponse(&plimsollv1.DescribeResponse{Sandbox: "liar", Isolation: "vm", Protocol: protocol.Number + 1}), nil
}

func stamped(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) *connect.Response[plimsollv1.RunResponse] {
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req), Started: time.UnixMilli(1), Ended: time.UnixMilli(2)}, resp)
	return connect.NewResponse(resp)
}

func notDispatched(code connect.Code, reason plimsollv1.NotDispatchedReason, msg string) error {
	err := connect.NewError(code, errors.New(msg))
	if d, derr := connect.NewErrorDetail(&plimsollv1.NotDispatched{Reason: reason}); derr == nil {
		err.AddDetail(d)
	}
	return err
}

func (liar) Run(_ context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	if req.Msg.GetProtocol() != protocol.Number {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the client stated another protocol"))
	}
	executed := &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("already executed")}}
	switch req.Msg.GetJavascript().GetCode() {
	case "weak-evidence":
		return stamped(req.Msg, &plimsollv1.RunResponse{Sandbox: "liar", Isolation: "container", Result: executed}), nil
	case "no-record":
		return connect.NewResponse(&plimsollv1.RunResponse{Sandbox: "liar", Isolation: "vm", Result: executed}), nil
	case "wrong-kind":
		return stamped(req.Msg, &plimsollv1.RunResponse{Sandbox: "liar", Isolation: "vm",
			Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{}}}), nil
	case "other-protocol":
		return nil, notDispatched(connect.CodeUnimplemented, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PROTOCOL, protocol.Mismatch(protocol.Number+1, protocol.Number))
	default:
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed after dispatch"))
	}
}

func (liar) OpenSession(_ context.Context, req *connect.Request[plimsollv1.OpenSessionRequest]) (*connect.Response[plimsollv1.OpenSessionResponse], error) {
	const id = "00112233445566778899aabbccddeeff"
	fingerprint := record.SessionFingerprint(id)
	if req.Msg.GetTraceId() == "bad-fingerprint" {
		fingerprint = record.SessionFingerprint("another session")
	}
	return connect.NewResponse(&plimsollv1.OpenSessionResponse{SessionId: id, Session: fingerprint, Sandbox: "liar", Isolation: "container"}), nil
}

// SessionRun answers every call with the record of a call that may have run, stating
// evidence the session did not state at open: "weaker" names the tier process,
// anything else names another provider.
func (liar) SessionRun(_ context.Context, req *connect.Request[plimsollv1.SessionRunRequest]) (*connect.Response[plimsollv1.SessionRunResponse], error) {
	provider, isolation := "liar", "container"
	if req.Msg.GetJavascript().GetCode() == "weaker" {
		isolation = "process"
	} else {
		provider = "other"
	}
	rec := record.StampUnanswered(sandbox.RunRecord{
		RequestSHA256: record.SessionRunRequestDigest(req.Msg), Provider: provider, Isolation: isolation,
		Started: time.UnixMilli(1), Ended: time.UnixMilli(2),
		Session: record.SessionFingerprint("00112233445566778899aabbccddeeff"), Sequence: 1,
	}, "unknown")
	err := connect.NewError(connect.CodeUnknown, errors.New("the stream broke after the code ran"))
	if d, derr := connect.NewErrorDetail(&plimsollv1.UnansweredCall{Record: rec}); derr == nil {
		err.AddDetail(d)
	}
	return nil, err
}

func (liar) CloseSession(context.Context, *connect.Request[plimsollv1.CloseSessionRequest]) (*connect.Response[plimsollv1.CloseSessionResponse], error) {
	return connect.NewResponse(&plimsollv1.CloseSessionResponse{
		Session: record.SessionFingerprint("00112233445566778899aabbccddeeff"), Ended: plimsollv1.SessionEnd_SESSION_END_CLOSED,
	}), nil
}

// --- the digest fixture -----------------------------------------------------------

type fixtureCase struct {
	Name    string          `json:"name"`
	Message json.RawMessage `json:"message"`
	Digest  string          `json:"digest"`
}

type digestFixture struct {
	Requests     []fixtureCase `json:"requests"`
	Results      []fixtureCase `json:"results"`
	Records      []fixtureCase `json:"records"`
	Fingerprints []struct {
		ID     string `json:"id"`
		Digest string `json:"digest"`
	} `json:"fingerprints"`
}

func marshal(t *testing.T, m proto.Message) json.RawMessage {
	t.Helper()
	b, err := protojson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeFixture writes run-record digests the Go record package computes, each with
// its message as Go's protobuf JSON encoder writes it (the encoder Connect uses).
func writeFixture(t *testing.T, path string) {
	t.Helper()
	identities := []string{"oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64), "oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64)}
	js := &plimsollv1.JavaScriptRun{Code: "console.log('héllo ☃ 𝄞\\n')", GrantProfile: "profile-1"}
	project := &plimsollv1.ProjectRun{
		Files: []*plimsollv1.ProjectFile{{Path: "main.py", Content: "print('\\u00e9')\n"}, {Path: "empty.txt"}, {Path: "nul.bin", Content: "a\x00b"}},
		Steps: []string{"python3 main.py", ""}, Artifacts: []string{"out.txt"},
	}
	module := &plimsollv1.ModuleRun{Model: "Lorenz", EndTime: 1e-7, Step: 5e-324, Rows: []*plimsollv1.ModuleRow{
		{Values: []float64{math.Copysign(0, -1), math.MaxFloat64, 1e21, 123456789012345678901, -1.5e-300}}, {Values: []float64{}},
	}}
	var f digestFixture
	for _, c := range []struct {
		name string
		msg  *plimsollv1.RunRequest
	}{
		{"protocol 1 javascript", &plimsollv1.RunRequest{Protocol: 1, MinimumIsolation: "vm", TimeoutMs: math.MaxInt32, Payload: &plimsollv1.RunRequest_Javascript{Javascript: js}}},
		{"protocol 2 javascript, exact rule", &plimsollv1.RunRequest{Protocol: 2, TimeoutMs: -5, TraceId: "t",
			SoftwareRule: &plimsollv1.SoftwareRule{Mode: "exact", Identities: identities[:1]}, Payload: &plimsollv1.RunRequest_Javascript{Javascript: js}}},
		{"protocol 2 project, approved rule", &plimsollv1.RunRequest{Protocol: 2, MinimumIsolation: "kernel",
			SoftwareRule: &plimsollv1.SoftwareRule{Mode: "approved", Identities: identities}, Payload: &plimsollv1.RunRequest_Project{Project: project}}},
		{"protocol 2 empty project", &plimsollv1.RunRequest{Protocol: 2, Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{}}}},
		{"protocol 2 module", &plimsollv1.RunRequest{Protocol: 2, Payload: &plimsollv1.RunRequest_Module{Module: module}}},
		{"protocol 2 no payload", &plimsollv1.RunRequest{Protocol: 2}},
	} {
		f.Requests = append(f.Requests, fixtureCase{c.name, marshal(t, c.msg), record.RunRequestDigest(c.msg)})
	}
	for _, c := range []struct {
		name string
		msg  *plimsollv1.RunResponse
	}{
		{"javascript", &plimsollv1.RunResponse{Sandbox: "docker", DurationMs: 9, Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{
			Stdout: []byte{0xff, 0x00, 'a'}, Stderr: []byte("é"), ExitCode: -1, TimedOut: true, StdoutTruncated: true, StderrTruncated: true,
			Advice: []*plimsollv1.AdviceFinding{{Pattern: "fan_out", ExtraCalls: 3}},
		}}}},
		{"project", &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{
			Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_SETUP_FAILED, OutcomeDetail: "détail", ArtifactsTruncated: true,
			Steps:     []*plimsollv1.StepResult{{Command: "a", Stdout: []byte{0}, ExitCode: math.MinInt32, DurationMs: 1 << 40, StderrTruncated: true}, {}},
			Artifacts: []*plimsollv1.Artifact{{Path: "out.txt", Content: []byte{0xfe}}, {Path: "empty"}},
		}}}},
		{"project with an outcome this client does not name", &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{Outcome: 9}}}},
		{"module", &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Module{Module: &plimsollv1.ModuleResult{
			Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED, Width: 4, Stdout: []byte("rows=2\n"), Stderr: []byte{0x80},
			Runs: []*plimsollv1.ModuleRowResult{
				{Status: 1, Outputs: []float64{math.Copysign(0, -1), math.Inf(1), math.Inf(-1), canonicalNaN}},
				{Status: -3},
				{Status: 1, Outputs: []float64{math.MaxFloat64, math.SmallestNonzeroFloat64, 1e21, 123456789012345678901}},
			},
		}}}},
		{"no result", &plimsollv1.RunResponse{Sandbox: "x"}},
	} {
		f.Results = append(f.Results, fixtureCase{c.name, marshal(t, c.msg), record.ResultDigest(c.msg)})
	}
	for _, c := range []struct {
		name string
		rec  sandbox.RunRecord
	}{
		{"version 2 session call", sandbox.RunRecord{Version: 2, RequestSHA256: "r", ResultSHA256: "s", Provider: "openshell", Isolation: "container",
			Environment: "e", Policy: "p", SoftwareIdentity: identities[0], SoftwareRuleID: "exact:" + identities[0],
			Started: time.UnixMilli(-1), Ended: time.UnixMilli(math.MaxInt64), Session: "f", Sequence: math.MaxUint64, PreviousSHA256: "prev"}},
		{"version 1 single run", sandbox.RunRecord{Version: 1, Provider: "wasm", Isolation: "process", Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000812)}},
	} {
		c.rec.SHA256 = "not covered by its own digest"
		f.Records = append(f.Records, fixtureCase{c.name, marshal(t, record.ToWire(c.rec)), record.Digest(c.rec)})
	}
	for _, id := range []string{"", "00112233445566778899aabbccddeeff", "é"} {
		f.Fingerprints = append(f.Fingerprints, struct {
			ID     string `json:"id"`
			Digest string `json:"digest"`
		}{id, record.SessionFingerprint(id)})
	}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The package ships its own copy of the license, because a published package carries
// nothing from outside its directory; it must stay the repository's license.
func TestLicenseMatchesRepository(t *testing.T) {
	own, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(filepath.Join("..", "..", "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if string(own) != string(root) {
		t.Fatal("LICENSE differs from the repository's LICENSE; copy it again")
	}
}

func plainSessionSvc() *rpc.SandboxService {
	svc := quiet(rpc.NewSandboxService(&sandboxtest.Sessions{}))
	svc.Sessions = rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Minute}
	return svc
}

func breakingSvc() *rpc.SandboxService {
	svc := quiet(rpc.NewSandboxService(&breakingSessions{Sessions: &sandboxtest.Sessions{}}))
	svc.Sessions = rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Minute}
	return svc
}

// breakingSessions opens fake sessions whose second snippet call runs and then
// returns an unmarked error, as an exec stream that broke after the code ran does:
// the daemon sends that call's record with the error.
type breakingSessions struct{ *sandboxtest.Sessions }

func (p *breakingSessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &breakingSession{Session: s}, nil
}

type breakingSession struct {
	sandbox.Session
	n int
}

func (s *breakingSession) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	res, err := s.Session.RunJavaScript(ctx, req)
	if s.n++; s.n == 2 {
		return res, errors.New("the exec stream broke after the code ran")
	}
	return res, err
}

// lossyProxy forwards to target and drops the answer to the second SessionRun after
// the daemon handled it: the call ran, and its answer never arrives.
func lossyProxy(t *testing.T, target string) string {
	var runs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		out, err := http.NewRequestWithContext(r.Context(), r.Method, target+r.URL.Path, bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		out.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		answer, _ := io.ReadAll(resp.Body)
		if strings.HasSuffix(r.URL.Path, "/SessionRun") && runs.Add(1) == 2 {
			if conn, _, herr := w.(http.Hijacker).Hijack(); herr == nil {
				_ = conn.Close()
			}
			return
		}
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(answer)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
