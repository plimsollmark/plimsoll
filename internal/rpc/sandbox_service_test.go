package rpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// fakeSandbox is a controllable sandbox.Sandbox for tests.
type fakeSandbox struct {
	jsResult   sandbox.Result
	jsErr      error
	projResult sandbox.ProjectResult
	projErr    error
	modResult  sandbox.ModuleResult
	modErr     error
	lastReq    sandbox.Request
	lastProj   sandbox.ProjectRequest
	lastMod    sandbox.ModuleRequest
}

func (f *fakeSandbox) Name() string                           { return "fake" }
func (f *fakeSandbox) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationVM }
func (f *fakeSandbox) RunJavaScript(_ context.Context, req sandbox.Request) (sandbox.Result, error) {
	f.lastReq = req
	return f.jsResult, f.jsErr
}
func (f *fakeSandbox) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	f.lastProj = req
	return f.projResult, f.projErr
}
func (f *fakeSandbox) RunModule(_ context.Context, req sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	f.lastMod = req
	if f.modErr == nil && f.modResult.Outcome == sandbox.ProjectOutcomeUnspecified {
		return sandbox.ModuleResult{}, sandbox.ErrUnsupported
	}
	return f.modResult, f.modErr
}

// projectCapableFake wraps fakeSandbox with a declared project capability.
type projectCapableFake struct {
	fakeSandbox
	supports                bool
	supportsModule          bool
	supportsJavaScriptGrant bool
	supportsProjectGrant    bool
}

type contextDeadlineSandbox struct{ fakeSandbox }

type isolationFake struct {
	*fakeSandbox
	isolation sandbox.IsolationClass
}

func (f *isolationFake) IsolationClass() sandbox.IsolationClass { return f.isolation }

func (f *contextDeadlineSandbox) RunJavaScript(ctx context.Context, _ sandbox.Request) (sandbox.Result, error) {
	<-ctx.Done()
	return sandbox.Result{}, ctx.Err()
}

func (f *projectCapableFake) SupportsProjects() bool { return f.supports }
func (f *projectCapableFake) SupportsModules() bool  { return f.supportsModule }
func (f *projectCapableFake) SupportsJavaScriptGrants() bool {
	return f.supportsJavaScriptGrant
}
func (f *projectCapableFake) SupportsProjectGrants() bool { return f.supportsProjectGrant }

func authenticatedContext(userID string) context.Context {
	return context.WithValue(context.Background(), principalKey{}, Principal{UserID: userID, Scopes: []string{ScopeCodeRun}})
}

func TestDescribeReportsMeasuredCapabilities(t *testing.T) {
	// A provider that declares its project capability is reported verbatim, including
	// project-grant support (both operation grant bits are surfaced independently).
	svc := NewSandboxService(&projectCapableFake{supports: true, supportsJavaScriptGrant: true, supportsProjectGrant: true})
	resp, err := svc.Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{}))
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if resp.Msg.GetSandbox() != "fake" || resp.Msg.GetIsolation() != "vm" || !resp.Msg.GetSupportsProject() ||
		!resp.Msg.GetSupportsJavascriptGrants() || !resp.Msg.GetSupportsProjectGrants() || resp.Msg.GetProtocol() != protocol.Number {
		t.Fatalf("bad describe: %+v", resp.Msg)
	}

	// A provider that declares nothing must be reported as NOT supporting
	// projects — capability claims fail closed.
	svc = NewSandboxService(&fakeSandbox{})
	resp, err = svc.Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{}))
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if resp.Msg.GetSupportsProject() || resp.Msg.GetSupportsJavascriptGrants() || resp.Msg.GetSupportsProjectGrants() || resp.Msg.GetProtocol() != protocol.Number {
		t.Fatal("undeclared provider capabilities must be false and the protocol number stated")
	}
}

func TestRunJavaScriptMapsResult(t *testing.T) {
	fake := &fakeSandbox{jsResult: sandbox.Result{Stdout: "hi 3", ExitCode: 0, Sandbox: "fake", Duration: 7 * time.Millisecond}}
	svc := NewSandboxService(fake)
	resp, err := svc.Run(context.Background(), withTimeout(jsReq("console.log('hi', 1+2)"), 1500))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Msg.GetJavascript().GetStdout()) != "hi 3" || resp.Msg.GetSandbox() != "fake" || resp.Msg.GetDurationMs() != 7 {
		t.Fatalf("bad response: %+v", resp.Msg)
	}
	if fake.lastReq.Timeout != 1500*time.Millisecond {
		t.Fatalf("timeout = %v, want 1.5s", fake.lastReq.Timeout)
	}
}

func TestRunJavaScriptEnforcesMinimumIsolationBeforeAdmissionAndDispatch(t *testing.T) {
	fake := &fakeSandbox{}
	svc := NewSandboxService(&isolationFake{fakeSandbox: fake, isolation: sandbox.IsolationContainer})
	_, err := svc.Run(context.Background(), withFloor(jsReq("1"), "kernel"))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), sandbox.ErrInsufficientIsolation.Error()) {
		t.Fatalf("error = %v, want FailedPrecondition with isolation detail", err)
	}
	if fake.lastReq.Code != "" {
		t.Fatal("weak provider executed the JavaScript request")
	}
	if total, _ := svc.RunCounts(); total != 0 {
		t.Fatalf("runs total = %d, want 0 before admission/dispatch", total)
	}

	fake.jsResult = sandbox.Result{Sandbox: "fake", Isolation: sandbox.IsolationContainer}
	if _, err := svc.Run(context.Background(), withFloor(jsReq("1"), "container")); err != nil {
		t.Fatalf("matching floor rejected: %v", err)
	}
	if fake.lastReq.MinimumIsolation != sandbox.IsolationContainer {
		t.Fatalf("minimum isolation = %v, want container", fake.lastReq.MinimumIsolation)
	}
}

func TestRunRequestsRejectInvalidMinimumIsolation(t *testing.T) {
	for _, raw := range []string{"none", "unknown", "Kernel", " kernel ", "strong"} {
		t.Run(raw, func(t *testing.T) {
			fake := &fakeSandbox{}
			svc := NewSandboxService(fake)
			_, err := svc.Run(context.Background(), withFloor(jsReq("1"), raw))
			if connect.CodeOf(err) != connect.CodeInvalidArgument || !errors.Is(err, sandbox.ErrInvalidRequest) {
				t.Fatalf("error = %v, want InvalidArgument/ErrInvalidRequest", err)
			}
			if fake.lastReq.Code != "" {
				t.Fatal("invalid floor reached provider")
			}
		})
	}
}

func TestRunJavaScriptUnknownGrantProfile(t *testing.T) {
	svc := NewSandboxService(&fakeSandbox{}) // no Grants registry configured
	_, err := svc.Run(context.Background(), jsGrantReq("1", "nope"))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument for an unknown grant_profile", connect.CodeOf(err))
	}
}

func TestRunJavaScriptGrantProfileFlowsToRequest(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok-xyz")
	path := filepath.Join(t.TempDir(), "grants.json")
	if err := os.WriteFile(path, []byte(`{"profiles":{"hue":{"base_url":"https://hue.internal","allow":["GET /v1/lights"],"allowed_callers":["mcp-a"],"token":{"type":"static","env":"HUE_TOKEN"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := grants.Load(path)
	if err != nil {
		t.Fatalf("load grants: %v", err)
	}
	fake := &fakeSandbox{jsResult: sandbox.Result{Sandbox: "fake"}}
	svc := NewSandboxService(fake)
	svc.Grants = reg
	if _, err := svc.Run(authenticatedContext("mcp-a"), jsGrantReq("1", "hue")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.lastReq.Grant == nil {
		t.Fatal("grant_profile did not flow to Request.Grant")
	}
	if fake.lastReq.Grant.BaseURL != "https://hue.internal" {
		t.Fatalf("wrong grant resolved: %+v", fake.lastReq.Grant)
	}
}

func TestRunJavaScriptGrantProfileEnforcesCallerACL(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok-xyz")
	path := filepath.Join(t.TempDir(), "grants.json")
	if err := os.WriteFile(path, []byte(`{"profiles":{"hue":{"base_url":"https://hue.internal","allow":["GET /v1/lights"],"allowed_callers":["mcp-a"],"token":{"type":"static","env":"HUE_TOKEN"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := grants.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeSandbox{}
	svc := NewSandboxService(fake)
	svc.Grants = reg
	req := jsGrantReq("1", "hue")
	if _, err := svc.Run(authenticatedContext("mcp-b"), req); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("other caller code = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if _, err := svc.Run(context.Background(), req); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("anonymous caller code = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if fake.lastReq.Code != "" {
		t.Fatal("denied grant request reached the sandbox")
	}
}

func TestRunJavaScriptEmitsAuditLog(t *testing.T) {
	var buf bytes.Buffer
	fake := &fakeSandbox{jsResult: sandbox.Result{Stdout: "ok", Sandbox: "fake", Duration: 5 * time.Millisecond}}
	svc := NewSandboxService(fake)
	svc.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if _, err := svc.Run(context.Background(), jsReq("console.log(1)")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`"msg":"code run"`, `"op":"javascript"`, `"caller":"anon"`, `"sandbox":"fake"`, `"code_bytes":14`} {
		if !strings.Contains(out, want) {
			t.Errorf("audit log missing %q\nlog: %s", want, out)
		}
	}
	if strings.Contains(out, "console.log") {
		t.Errorf("audit log must NOT contain the code contents\nlog: %s", out)
	}
}

// The join is the point: a caller that stamps its own correlation id must be able
// to find this run in plimsoll's log from its own record of the same request.
func TestRunJavaScriptAuditCarriesTraceID(t *testing.T) {
	var buf bytes.Buffer
	fake := &fakeSandbox{jsResult: sandbox.Result{Stdout: "ok", Sandbox: "fake"}}
	svc := NewSandboxService(fake)
	svc.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if _, err := svc.Run(context.Background(), withTrace(jsReq("console.log(1)"), "9af31c02")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, `"trace_id":"9af31c02"`) {
		t.Errorf("audit log missing the caller's trace id\nlog: %s", out)
	}
}

// A caller that does not correlate must leave the line exactly as it was, so
// adding this field cannot perturb an existing operator's log shape.
func TestRunJavaScriptAuditOmitsAbsentTraceID(t *testing.T) {
	var buf bytes.Buffer
	svc := NewSandboxService(&fakeSandbox{jsResult: sandbox.Result{Stdout: "ok", Sandbox: "fake"}})
	svc.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if _, err := svc.Run(context.Background(), jsReq("1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out := buf.String(); strings.Contains(out, "trace_id") {
		t.Errorf("audit log mentions trace_id for a caller that sent none\nlog: %s", out)
	}
}

// The invariant this field is most likely to break. A caller-controlled string on
// a metadata-only audit line is exactly how a raw path gets into a stream that
// claims it cannot hold one, so the hostile value must be dropped whole and the
// drop recorded without echoing what was dropped.
func TestRunJavaScriptAuditRejectsHostileTraceID(t *testing.T) {
	var buf bytes.Buffer
	svc := NewSandboxService(&fakeSandbox{jsResult: sandbox.Result{Stdout: "ok", Sandbox: "fake"}})
	svc.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if _, err := svc.Run(context.Background(), withTrace(jsReq("1"), "/v1/customers/8821?ssn=123-45-6789")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"trace_id_rejected":true`) {
		t.Errorf("audit log did not record that it dropped a non-conforming trace id\nlog: %s", out)
	}
	for _, leak := range []string{"customers", "ssn", "8821"} {
		if strings.Contains(out, leak) {
			t.Errorf("rejected trace id leaked %q into the audit log\nlog: %s", leak, out)
		}
	}
}

func TestRunProjectAuditCarriesTraceID(t *testing.T) {
	var buf bytes.Buffer
	svc := NewSandboxService(&fakeSandbox{})
	svc.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if _, err := svc.Run(context.Background(), withTrace(projectReq(&plimsollv1.ProjectRun{Files: []*plimsollv1.ProjectFile{{Path: "main.js", Content: "1"}}, Steps: []string{"node main.js"}}), "9af31c02")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, `"trace_id":"9af31c02"`) {
		t.Errorf("project audit log missing the caller's trace id\nlog: %s", out)
	}
}

func TestRunJavaScriptRejectsEmptyCode(t *testing.T) {
	svc := NewSandboxService(&fakeSandbox{})
	_, err := svc.Run(context.Background(), jsReq(""))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

func TestDisabledSandboxIsFailedPrecondition(t *testing.T) {
	svc := NewSandboxService(sandbox.Disabled{})
	_, err := svc.Run(context.Background(), jsReq("1"))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", connect.CodeOf(err))
	}
}

func TestRunProjectRejectsTraversalPath(t *testing.T) {
	svc := NewSandboxService(&fakeSandbox{})
	_, err := svc.Run(context.Background(), projectReq(&plimsollv1.ProjectRun{Files: []*plimsollv1.ProjectFile{{Path: "../escape.js", Content: "x"}}, Steps: []string{"node escape.js"}}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument for traversal path", connect.CodeOf(err))
	}
}

func TestRunProjectRequiresSteps(t *testing.T) {
	svc := NewSandboxService(&fakeSandbox{})
	_, err := svc.Run(context.Background(), projectReq(&plimsollv1.ProjectRun{}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument when no steps", connect.CodeOf(err))
	}
}

func TestRunProjectMapsStepsAndArtifacts(t *testing.T) {
	fake := &fakeSandbox{projResult: sandbox.ProjectResult{
		Sandbox:   "fake",
		Steps:     []sandbox.StepResult{{Command: "node main.js", Stdout: "ok", ExitCode: 0, Duration: 3 * time.Millisecond}},
		Artifacts: []sandbox.Artifact{{Path: "out.txt", Content: []byte("data")}},
	}}
	svc := NewSandboxService(fake)
	resp, err := svc.Run(context.Background(), projectReq(&plimsollv1.ProjectRun{Files: []*plimsollv1.ProjectFile{{Path: "main.js", Content: "console.log('ok')"}}, Steps: []string{"node main.js"}, Artifacts: []string{"out.txt"}}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Msg.GetProject().GetSteps()) != 1 || string(resp.Msg.GetProject().GetSteps()[0].GetStdout()) != "ok" {
		t.Fatalf("bad steps: %+v", resp.Msg.GetProject().GetSteps())
	}
	if len(resp.Msg.GetProject().GetArtifacts()) != 1 || string(resp.Msg.GetProject().GetArtifacts()[0].GetContent()) != "data" {
		t.Fatalf("bad artifacts: %+v", resp.Msg.GetProject().GetArtifacts())
	}
}

func TestRunProjectEnforcesMinimumIsolationBeforeDispatch(t *testing.T) {
	fake := &fakeSandbox{}
	svc := NewSandboxService(&isolationFake{fakeSandbox: fake, isolation: sandbox.IsolationProcess})
	_, err := svc.Run(context.Background(), withFloor(projectReq(&plimsollv1.ProjectRun{Steps: []string{"true"}}), "vm"))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (err: %v)", connect.CodeOf(err), err)
	}
	if len(fake.lastProj.Steps) != 0 {
		t.Fatal("weak provider executed the project request")
	}
}

func TestRunProjectRejectsArtifactAmplification(t *testing.T) {
	svc := NewSandboxService(&fakeSandbox{})
	tooMany := make([]string, sandbox.MaxProjectArtifacts+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("out-%d", i)
	}
	_, err := svc.Run(context.Background(), projectReq(&plimsollv1.ProjectRun{Steps: []string{"true"}, Artifacts: tooMany}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("too-many artifact code = %v, want InvalidArgument", connect.CodeOf(err))
	}

	_, err = svc.Run(context.Background(), projectReq(&plimsollv1.ProjectRun{Steps: []string{"true"}, Artifacts: []string{"empty", "empty"}}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("duplicate artifact code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

func TestRunProjectRejectsNonCanonicalAndNULPaths(t *testing.T) {
	svc := NewSandboxService(&fakeSandbox{})
	for _, p := range []string{"./a.js", "dir//a.js", "a\x00b.js"} {
		_, err := svc.Run(context.Background(), projectReq(&plimsollv1.ProjectRun{Files: []*plimsollv1.ProjectFile{{Path: p, Content: "1"}}, Steps: []string{"true"}}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("path %q code = %v, want InvalidArgument", p, connect.CodeOf(err))
		}
	}
}

func TestProviderOutputBytesPassThroughVerbatim(t *testing.T) {
	// Guest output is a bytes field on the wire, so invalid UTF-8 must survive
	// UNCHANGED \u2014 the old string fields repaired it lossily during serialization.
	bad := string([]byte{'o', 'k', 0xff})
	fake := &fakeSandbox{jsResult: sandbox.Result{Stdout: bad, Stderr: bad, Sandbox: "fake"}}
	resp, err := NewSandboxService(fake).Run(context.Background(), jsReq("1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp.Msg.GetJavascript().GetStdout(), []byte(bad)) || !bytes.Equal(resp.Msg.GetJavascript().GetStderr(), []byte(bad)) {
		t.Fatalf("guest output bytes were altered on the wire: %q", resp.Msg.GetJavascript().GetStdout())
	}
}

func TestOutcomeDetailIsValidUTF8OnWire(t *testing.T) {
	// Outcome detail can be built from guest stderr, so it still needs the UTF-8
	// repair guard that protobuf string fields require.
	bad := string([]byte{'e', 0xff})
	fake := &fakeSandbox{projResult: sandbox.ProjectResult{Sandbox: "fake", Outcome: sandbox.ProjectOutcomeProtocolError, Detail: bad}}
	resp, err := NewSandboxService(fake).Run(context.Background(), projectReq(&plimsollv1.ProjectRun{Steps: []string{"true"}}))
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(resp.Msg.GetProject().GetOutcomeDetail()) {
		t.Fatalf("invalid UTF-8 escaped the response boundary: %q", resp.Msg.GetProject().GetOutcomeDetail())
	}
	if !strings.Contains(resp.Msg.GetProject().GetOutcomeDetail(), "\uFFFD") {
		t.Fatalf("invalid byte was not replaced: %q", resp.Msg.GetProject().GetOutcomeDetail())
	}
}

func TestRunResponsesCarryTypedOutcomeAndTruncation(t *testing.T) {
	fake := &fakeSandbox{
		jsResult: sandbox.Result{Sandbox: "fake", Stdout: "partial", StdoutTruncated: true, StderrTruncated: true},
		projResult: sandbox.ProjectResult{
			Sandbox:            "fake",
			Outcome:            sandbox.ProjectOutcomeSetupFailed,
			Detail:             "illegal file path: ../x",
			ArtifactsTruncated: true,
			Steps:              []sandbox.StepResult{{Command: "node x.js", Stdout: "s", StdoutTruncated: true, StderrTruncated: true}},
		},
	}
	svc := NewSandboxService(fake)

	js, err := svc.Run(context.Background(), jsReq("1"))
	if err != nil {
		t.Fatal(err)
	}
	if !js.Msg.GetJavascript().GetStdoutTruncated() || !js.Msg.GetJavascript().GetStderrTruncated() {
		t.Fatalf("truncation flags lost on the JS wire: %+v", js.Msg)
	}

	proj, err := svc.Run(context.Background(), projectReq(&plimsollv1.ProjectRun{Steps: []string{"node x.js"}}))
	if err != nil {
		t.Fatal(err)
	}
	if proj.Msg.GetProject().GetOutcome() != plimsollv1.ProjectOutcome_PROJECT_OUTCOME_SETUP_FAILED {
		t.Fatalf("outcome = %v, want SETUP_FAILED", proj.Msg.GetProject().GetOutcome())
	}
	if proj.Msg.GetProject().GetOutcomeDetail() != "illegal file path: ../x" {
		t.Fatalf("outcome detail = %q", proj.Msg.GetProject().GetOutcomeDetail())
	}
	if !proj.Msg.GetProject().GetArtifactsTruncated() {
		t.Fatal("artifact truncation flag lost on the wire")
	}
	st := proj.Msg.GetProject().GetSteps()
	if len(st) != 1 || !st[0].GetStdoutTruncated() || !st[0].GetStderrTruncated() {
		t.Fatalf("step truncation flags lost on the wire: %+v", st)
	}
}

func TestContextErrorsPreserveRPCSemanticsAndMetrics(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code connect.Code
	}{{context.Canceled, connect.CodeCanceled}, {context.DeadlineExceeded, connect.CodeDeadlineExceeded}} {
		svc := NewSandboxService(&fakeSandbox{jsErr: tc.err})
		_, err := svc.Run(context.Background(), jsReq("1"))
		if connect.CodeOf(err) != tc.code {
			t.Errorf("%v mapped to %v, want %v", tc.err, connect.CodeOf(err), tc.code)
		}
		if _, failed := svc.RunCounts(); failed != 0 {
			t.Errorf("%v counted as infrastructure failure", tc.err)
		}
	}
}

func TestRunProjectAuditIncludesOutcome(t *testing.T) {
	var buf bytes.Buffer
	fake := &fakeSandbox{projResult: sandbox.ProjectResult{Sandbox: "fake", Isolation: sandbox.IsolationVM,
		Steps: []sandbox.StepResult{{Command: "slow", ExitCode: 124, TimedOut: true}}}}
	svc := NewSandboxService(fake)
	svc.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	if _, err := svc.Run(context.Background(), projectReq(&plimsollv1.ProjectRun{Steps: []string{"slow"}})); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"msg":"project run"`, `"exit_code":124`, `"timed_out":true`, `"duration_ms":`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("audit log missing %q: %s", want, buf.String())
		}
	}
}

func TestUnsupportedAndDisabledNotCountedAsFailed(t *testing.T) {
	// ErrUnsupported (wasm project) is a client/config condition, not an infra fault.
	unsup := NewSandboxService(&fakeSandbox{projErr: sandbox.ErrUnsupported})
	_, _ = unsup.Run(context.Background(), projectReq(&plimsollv1.ProjectRun{Files: []*plimsollv1.ProjectFile{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}}))
	if _, failed := unsup.RunCounts(); failed != 0 {
		t.Errorf("runsFailed = %d after ErrUnsupported, want 0", failed)
	}

	// ErrDisabled likewise (a deliberately-off provider is not an infra failure).
	dis := NewSandboxService(sandbox.Disabled{})
	_, _ = dis.Run(context.Background(), jsReq("1"))
	if _, failed := dis.RunCounts(); failed != 0 {
		t.Errorf("runsFailed = %d after ErrDisabled, want 0", failed)
	}

	// Admission shedding is expected backpressure, not a broken provider.
	busy := NewSandboxService(&fakeSandbox{jsErr: sandbox.ErrAtCapacity})
	_, err := busy.Run(context.Background(), jsReq("1"))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("ErrAtCapacity mapped to %v, want ResourceExhausted", connect.CodeOf(err))
	}
	if _, failed := busy.RunCounts(); failed != 0 {
		t.Errorf("runsFailed = %d after ErrAtCapacity, want 0", failed)
	}

	// A real infrastructure error DOES count.
	infra := NewSandboxService(&fakeSandbox{jsErr: errors.New("docker daemon unreachable")})
	_, _ = infra.Run(context.Background(), jsReq("1"))
	if _, failed := infra.RunCounts(); failed != 1 {
		t.Errorf("runsFailed = %d after infra error, want 1", failed)
	}
}

func TestLimiterShedsLoadAtCapacity(t *testing.T) {
	l := NewCodeLimiter(1, 0, 0, 0) // global cap 1, no per-key, no rate
	release, err := l.Acquire(context.Background(), "k")
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	if _, err := l.Acquire(context.Background(), "k"); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("second acquire code = %v, want ResourceExhausted", connect.CodeOf(err))
	}
	release()
	if release2, err := l.Acquire(context.Background(), "k"); err != nil {
		t.Fatalf("acquire after release failed: %v", err)
	} else {
		release2()
	}
}

// TestLimiterPerKeyConcurrency: one principal cannot hold more than its per-key cap
// even when the global pool has room, and a different principal is unaffected.
func TestLimiterPerKeyConcurrency(t *testing.T) {
	l := NewCodeLimiter(10, 1, 0, 0) // global 10, per-key 1
	relA, err := l.Acquire(context.Background(), "a")
	if err != nil {
		t.Fatalf("a #1 acquire failed: %v", err)
	}
	if _, err := l.Acquire(context.Background(), "a"); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a #2 code = %v, want ResourceExhausted (per-key cap)", connect.CodeOf(err))
	}
	relB, err := l.Acquire(context.Background(), "b") // different principal: fine
	if err != nil {
		t.Fatalf("b acquire failed even though global pool has room: %v", err)
	}
	relA()
	relB()
	if l.Stats().PerKeyFull != 1 {
		t.Errorf("PerKeyFull = %d, want 1", l.Stats().PerKeyFull)
	}
	// After releasing, a can run again.
	if rel, err := l.Acquire(context.Background(), "a"); err != nil {
		t.Fatalf("a acquire after release failed: %v", err)
	} else {
		rel()
	}
}

// TestLimiterRateBurstBounded: with burst=2, a principal gets exactly two immediate
// starts (releasing concurrency between them) and is then rate-limited, since the
// bucket does not refill meaningfully within the test.
func TestLimiterRateBurstBounded(t *testing.T) {
	l := NewCodeLimiter(10, 0, 60, 2) // 60/min sustained, burst 2
	for i := 0; i < 2; i++ {
		rel, err := l.Acquire(context.Background(), "k")
		if err != nil {
			t.Fatalf("burst acquire %d failed: %v", i, err)
		}
		rel() // free concurrency so only the rate limit can bite next
	}
	if _, err := l.Acquire(context.Background(), "k"); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("3rd acquire code = %v, want ResourceExhausted (burst exhausted)", connect.CodeOf(err))
	}
	if l.Stats().RateLimited != 1 {
		t.Errorf("RateLimited = %d, want 1", l.Stats().RateLimited)
	}
}

func TestLimiterDoesNotResetPartiallyRefilledIdleBucket(t *testing.T) {
	l := NewCodeLimiter(10, 0, 1, 1000)
	start := time.Unix(1_000, 0)
	l.lastTrim = start
	l.buckets["caller"] = &bucket{tokens: 0, last: start}

	// Three minutes at one token/minute refills only three of the 1000-token
	// burst. The trim pass must preserve that debt instead of deleting the bucket
	// and recreating it full.
	l.mu.Lock()
	if !l.takeTokenLocked("caller", start.Add(3*time.Minute)) {
		l.mu.Unlock()
		t.Fatal("partially refilled bucket should have one token available")
	}
	remaining := l.buckets["caller"].tokens
	l.mu.Unlock()
	if remaining >= 999 {
		t.Fatalf("idle bucket reset to a full burst: remaining=%v", remaining)
	}
}

// TestClampTimeoutMs verifies the RPC-edge defense-in-depth clamp: an attacker-
// supplied timeout_ms is bounded at maxRunTimeout, a non-positive value passes
// through as 0 (so the provider applies its own default), and a normal value is
// preserved. This is the single chokepoint so no provider is the only backstop.
func TestClampTimeoutMs(t *testing.T) {
	const maxInt32 = 1<<31 - 1
	cases := []struct {
		name string
		in   int32
		want time.Duration
	}{
		{"negative -> 0 (provider default)", -5, 0},
		{"zero -> 0 (provider default)", 0, 0},
		{"normal passthrough", 2000, 2 * time.Second},
		{"at ceiling", int32(maxRunTimeout.Milliseconds()), maxRunTimeout},
		{"above ceiling clamped", int32(maxRunTimeout.Milliseconds()) + 1, maxRunTimeout},
		{"int32 max clamped", maxInt32, maxRunTimeout},
	}
	for _, c := range cases {
		if got := clampTimeoutMs(c.in); got != c.want {
			t.Errorf("%s: clampTimeoutMs(%d) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

func TestRPCDeadlineIsEnforcedThroughContext(t *testing.T) {
	svc := NewSandboxService(&contextDeadlineSandbox{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := svc.Run(ctx, jsReq("1"))
	if connect.CodeOf(err) != connect.CodeDeadlineExceeded {
		t.Fatalf("code = %v, want DeadlineExceeded", connect.CodeOf(err))
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("provider outlived RPC deadline: %v", elapsed)
	}
}

func TestRunContextHasIndependentGlobalCeiling(t *testing.T) {
	ctx, cancel := runContext(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("run context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > maxRunTimeout {
		t.Fatalf("run context remaining = %v, want (0,%v]", remaining, maxRunTimeout)
	}
}
