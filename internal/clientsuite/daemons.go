// Package clientsuite is what the Go drivers of the client suites share
// (clients/python/client_test.go, clients/python/frameworks_test.go,
// clients/typescript/client_test.go): one set of named
// daemons, honest and hostile, served over the real RPC handler where one exists, and the
// checks every published client package makes of itself. Each driver serves the whole
// table and hands every daemon's variables to its suite, and each client says, in its
// driver, which daemons its suite does not use and why (Declined); CheckDeclined fails a
// daemon a suite neither uses nor declines, so a daemon added for one client is seen by
// the other. Only tests import it.
//
// Before 2026-11-18 each driver built its own: the Python one 20 named daemons, the
// TypeScript one 16, ten names in one list only, and two names (the sessions and the
// pooled daemon) meaning a different daemon in each (review of the published half,
// item 7).
package clientsuite

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/answertest"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// Daemon is one named daemon of the table: the variables it sets (its URL first, then
// any companion value), and what a suite uses it to test.
type Daemon struct {
	Name  string
	Vars  []string
	Tests string
	// serve starts the daemon and returns its variables' values, in Vars order.
	serve func(t *testing.T) []string
}

// Daemons is the table every driver serves.
var Daemons = []Daemon{
	{"wasm", []string{"PLIMSOLL_WASM_URL"},
		"the real wasm provider: single runs, their records and refusals", serveOne(func() plimsollv1connect.SandboxServiceHandler {
			return Quiet(rpc.NewSandboxService(sandboxtest.Wasm()))
		})},
	{"auth", []string{"PLIMSOLL_AUTH_URL", "PLIMSOLL_AUTH_TOKEN"},
		"the wasm provider behind a bearer token, which the second variable holds", serveAuth},
	{"tamper", []string{"PLIMSOLL_TAMPER_URL"},
		"the wasm provider with each snippet's output changed after its record was stated, as anything between daemon and client could", serveOne(func() plimsollv1connect.SandboxServiceHandler {
			return tampering{Quiet(rpc.NewSandboxService(sandboxtest.Wasm()))}
		})},
	{"scripted", []string{"PLIMSOLL_SCRIPTED_URL", "PLIMSOLL_SCRIPTED_SOFTWARE"},
		"a provider that runs nothing and answers with the values a JSON client is most likely to get wrong (bytes that are not UTF-8, negative zero, extreme doubles, NaN), stating the software identity the second variable holds", serveScripted},
	{"liar", []string{"PLIMSOLL_LIAR_URL"},
		"a handler that breaks the protocol in the ways a client must catch: another protocol, weaker evidence than the floor, no record, a result of another kind, an unmarked failure, a session whose fingerprint is not its ID (an open with trace ID bad-fingerprint) or whose open answer states another floor or rule than the open sent (bad-floor, bad-rule), and unanswered records stating evidence the session did not", serveLiar},
	{"sessions", []string{"PLIMSOLL_SESSIONS_URL"},
		"the in-memory session provider; POST /test/end-last?reason=expired|disk_exceeded ends the newest session, POST /test/end-sessions ends every open one, as a lifetime would", serveSessions},
	{"owner-cap", []string{"PLIMSOLL_OWNER_CAP_URL"},
		"the session provider with each owner capped at one session, so an owner's second open replaces its least recently used", serveOwnerCap},
	{"breaking", []string{"PLIMSOLL_BREAKING_URL"},
		"sessions whose second call (a snippet or a cell) runs and then fails unmarked, so the daemon sends that call's unanswered record", serveOne(func() plimsollv1connect.SandboxServiceHandler {
			return sessionService(&breakingSessions{Sessions: &sandboxtest.Sessions{}}, rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Minute})
		})},
	{"lossy", []string{"PLIMSOLL_LOSSY_URL"},
		"a proxy in front of a session daemon that drops the answer to the second SessionRun after the daemon ran it", serveLossy},
	{"quick-idle", []string{"PLIMSOLL_QUICK_IDLE_URL"},
		"a session daemon whose idle timeout is its shortest, 1 s, so a session no request names is closed as unclaimed; POST /test/wait-ended answers once every session ended (200) or after 10 s (504)", serveQuickIdle},
	{"pooled", []string{"PLIMSOLL_POOLED_URL"},
		"a daemon stating a pool of 2 that always has a member waiting, whose fresh projects are answered as echo answers them; POST /test/opened answers with the warm-only opens, the members ended and the fresh runs", servePooled},
	{"drained", []string{"PLIMSOLL_DRAINED_URL"},
		"the pooled daemon with no member waiting: a warm-only open is refused, and a Run cell that prefers a member runs fresh", serveOne(func() plimsollv1connect.SandboxServiceHandler {
			return sessionService(pooledEcho{Sessions: &sandboxtest.Sessions{}, fresh: &atomic.Int32{}}, rpc.SessionConfig{MaxSessions: 16, Pool: 2, Lifetime: time.Minute, IdleTimeout: time.Minute})
		})},
	{"one-call", []string{"PLIMSOLL_ONE_CALL_URL"},
		"a daemon stating a pool of 2 with members always waiting (sandboxtest.Pooled); POST /test/counts answers with the Runs that reached it, those that preferred a member, the members claimed and the fresh runs", serveCounted(2, 1<<20)},
	{"no-pool", []string{"PLIMSOLL_NO_POOL_URL"},
		"the counting daemon stating no pool, with five members its provider would hand over if asked", serveCounted(0, 5)},
	{"claim-miss", []string{"PLIMSOLL_CLAIM_MISS_URL"},
		"the counting daemon stating a pool of 2 whose provider has no member to hand over", serveCounted(2, 0)},
	{"echo", []string{"PLIMSOLL_ECHO_URL"},
		"a provider that runs nothing and answers a project with the plan it received (file paths, steps, the cell's code), so a suite checks what a fresh executeCode call sends", serveOne(func() plimsollv1connect.SandboxServiceHandler { return Quiet(rpc.NewSandboxService(projectEcho{})) })},
	{"tool-echo", []string{"PLIMSOLL_TOOL_ECHO_URL"},
		"a provider that runs nothing and answers a framework code tool's project with its files' contents, steps and budget, or with the failure a marker in the code names (ECHO:HOLD, EXIT, TIMEOUT, SETUP, PROTOCOL, LOUD, LOST, WARN); its routes under /test/ count the projects, hold a Describe or a Run until released, and report the last trace ID (toolecho.go)", serveToolEcho},
	{"grant-echo", []string{"PLIMSOLL_GRANT_ECHO_URL", "PLIMSOLL_GRANT_ECHO_TOKEN"},
		"the tool-echo provider named docker (a provider whose Python steps reach the broker), stating project grants, behind a bearer token the second variable holds, serving one grant profile, echo-api; a granted project's plan also names the grant's routes (grantecho.go)", serveGrantEcho("docker")},
	{"grant-echo-guard", []string{"PLIMSOLL_GRANT_ECHO_GUARD_URL", "PLIMSOLL_GRANT_ECHO_GUARD_TOKEN"},
		"the grant-echo daemon with its provider named e2b, whose Python steps get no route to the broker", serveGrantEcho("e2b")},
	{"replay", []string{"PLIMSOLL_REPLAY_REFUSAL_URL", "PLIMSOLL_REPLAY_SUCCESS_URL", "PLIMSOLL_REPLAY_RUNS_URL"},
		"two proxies that answer every request after the first with the first one's answer, in front of one daemon whose run count the third variable reports, so a suite shows the daemon ran the call it was given another answer for", serveReplay},
	{"unbound", []string{"PLIMSOLL_UNBOUND_URL"},
		"the real handler without the request ID echo (rpc.BindAnswers left out)", serveUnbound},
	{"early-refusal", []string{"PLIMSOLL_EARLY_REFUSAL_URL"},
		"a daemon whose read cap of 256 bytes refuses a body before any handler runs", serveEarlyRefusal},
	{"no-procedure", []string{"PLIMSOLL_NO_PROCEDURE_URL"},
		"a daemon serving no procedure at all, behind the request ID echo", serveNoProcedure},
	{"reattach", []string{"PLIMSOLL_REATTACH_URL", "PLIMSOLL_REATTACH_TOKEN"},
		"the in-memory session provider behind the bearer token the second variable holds, for attach (open development mode refuses it): a SessionRun whose trace ID is drop-answer runs and its connection is cut before the answer; GET /test/calls answers {\"calls\": n}, the snippets and cells the provider ran; GET /test/checkpoint-vectors answers with the shared checkpoint vectors (reattach.go)", serveReattach},
	{"attach-liar", []string{"PLIMSOLL_ATTACH_LIAR_URL"},
		"the reattach daemon, behind the same token, whose answer to an attach with trace ID forge-<name> is the honest one with one thing forged and the session left as it was (GET /test/forgeries lists the names; forge-none is the honest answer), and whose answer to an attach one call behind that names the lost call, with trace ID forge-lost-<name>, is the honest explained-gap answer with one thing forged (GET /test/lost-forgeries; forge-lost-none is honest); GET /test/closes?session=<fingerprint> answers {\"closes\": n}", serveAttachLiar},
	{"files", []string{"PLIMSOLL_FILES_URL"},
		"sessions whose file calls an in-memory work folder answers, for the shared file-call cases (internal/clientcases/testdata/files-calls.json): a call whose path is cut fails unmarked after it reached the provider, and a SessionRun with trace ID forge-files-<name> gets the honest answer with one thing forged (files.go, FilesForgeries)", serveFiles},
	{"tls", []string{"PLIMSOLL_TLS_URL", "PLIMSOLL_TLS_CA"},
		"the wasm provider over TLS; its self-signed certificate (for 127.0.0.1, ::1 and example.com) is in the PEM file the second variable names, the only authority a client must trust to reach it", serveTLSDaemon},
}

// Env serves every daemon of the table for t and returns its variables as NAME=value.
func Env(t *testing.T) []string {
	t.Helper()
	var env []string
	for _, d := range Daemons {
		values := d.serve(t)
		if len(values) != len(d.Vars) {
			t.Fatalf("clientsuite: %s set %d values for %d variables", d.Name, len(values), len(d.Vars))
		}
		for i, v := range d.Vars {
			env = append(env, v+"="+values[i])
		}
	}
	return env
}

// CheckDeclined fails t unless every variable of the table is read by some file of the
// suite (the files the globs match, under the driver's directory) or is named in declined
// with the reason the suite does not use it, and unless no declined variable is read after
// all. A daemon added for one client therefore has to be used or declined by the other.
func CheckDeclined(t *testing.T, declined map[string]string, globs ...string) {
	t.Helper()
	var text strings.Builder
	n := 0
	for _, g := range globs {
		files, err := filepath.Glob(g)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			text.Write(b)
			n++
		}
	}
	if n == 0 {
		t.Fatalf("no suite file matches %v", globs)
	}
	for _, problem := range declinedProblems(Daemons, declined, text.String()) {
		t.Error(problem)
	}
}

// declinedProblems is CheckDeclined's rule over a suite's text: one line per variable
// the suite neither reads nor declines, reads although it declines it, or declines with
// no reason, and per declined name no daemon sets.
func declinedProblems(daemons []Daemon, declined map[string]string, text string) []string {
	var out []string
	known := map[string]bool{}
	for _, d := range daemons {
		for _, v := range d.Vars {
			known[v] = true
			used := regexp.MustCompile(`\b` + v + `\b`).MatchString(text)
			why, isDeclined := declined[v]
			switch {
			case used && isDeclined:
				out = append(out, fmt.Sprintf("%s (the %s daemon) is declined (%q) but the suite reads it: drop it from the declined list", v, d.Name, why))
			case !used && !isDeclined:
				out = append(out, fmt.Sprintf("the suite neither reads %s (the %s daemon: %s) nor declines it: use it, or add it to the driver's declined list with the reason", v, d.Name, d.Tests))
			case isDeclined && strings.TrimSpace(why) == "":
				out = append(out, fmt.Sprintf("%s is declined without a reason", v))
			}
		}
	}
	var stale []string
	for v := range declined {
		if !known[v] {
			stale = append(stale, v)
		}
	}
	sort.Strings(stale)
	for _, v := range stale {
		out = append(out, fmt.Sprintf("the declined list names %s, which no daemon of the table sets", v))
	}
	return out
}

// LicenseMatchesRepository fails t unless the client package in the working directory
// ships the repository's license: a published package carries nothing from outside its
// directory, so it has a copy of its own.
func LicenseMatchesRepository(t *testing.T) {
	t.Helper()
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

// --- serving ---------------------------------------------------------------------

// Quiet is svc without its audit log, which would only fill the test output.
func Quiet(svc *rpc.SandboxService) *rpc.SandboxService {
	svc.Logger = slog.New(slog.DiscardHandler)
	return svc
}

func sessionService(p sandbox.Sandbox, cfg rpc.SessionConfig) *rpc.SandboxService {
	svc := Quiet(rpc.NewSandboxService(p))
	svc.Sessions = cfg
	return svc
}

// Serve serves h behind the real interceptors (v nil: no authentication) and returns
// its URL; extra adds test endpoints beside the procedures.
func Serve(t *testing.T, h plimsollv1connect.SandboxServiceHandler, v rpc.TokenVerifier, extra func(*http.ServeMux)) string {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := rpc.NewHandler(h, connect.WithInterceptors(rpc.AuthInterceptor(v)))
	mux.Handle(path, handler)
	if extra != nil {
		extra(mux)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func serveOne(h func() plimsollv1connect.SandboxServiceHandler) func(*testing.T) []string {
	return func(t *testing.T) []string { return []string{Serve(t, h(), nil, nil)} }
}

// authToken is the one token the auth daemon accepts, with the code:run scope.
const authToken = "client-suite-token"

type verifier struct{ token string }

func (v verifier) VerifyToken(_ context.Context, token string) (rpc.Principal, bool, error) {
	if token != v.token {
		return rpc.Principal{}, false, nil
	}
	return rpc.Principal{UserID: "client-suite", Scopes: []string{rpc.ScopeCodeRun}}, true, nil
}

func serveAuth(t *testing.T) []string {
	return []string{Serve(t, Quiet(rpc.NewSandboxService(sandboxtest.Wasm())), verifier{token: authToken}, nil), authToken}
}

func serveTLSDaemon(t *testing.T) []string {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := rpc.NewHandler(Quiet(rpc.NewSandboxService(sandboxtest.Wasm())), connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, handler)
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{srv.URL, ca}
}

// --- tamper ----------------------------------------------------------------------

// tampering is the real handler with every snippet's output changed after the daemon
// stated its record.
type tampering struct{ *rpc.SandboxService }

func (s tampering) Run(ctx context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	resp, err := s.SandboxService.Run(ctx, req)
	if err == nil && resp.Msg.GetJavascript() != nil {
		resp.Msg.GetJavascript().Stdout = []byte("43\n")
	}
	return resp, err
}

// --- scripted --------------------------------------------------------------------

// ScriptedSoftware is the software identity the scripted provider states, so a
// caller's software rule is admitted or refused by the real handler.
const ScriptedSoftware = "oci-manifest:linux/amd64@sha256:5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"

func serveScripted(t *testing.T) []string {
	return []string{Serve(t, Quiet(rpc.NewSandboxService(scripted{})), nil, nil), ScriptedSoftware}
}

// scripted is a provider that runs nothing. It states a software identity, and it
// answers with the values a JSON client is most likely to get wrong: bytes that are not
// UTF-8, negative zero, the largest and smallest doubles, an integer-valued double beyond
// 2^53, and NaN.
type scripted struct{}

var _ sandbox.Sandbox = scripted{}

func (scripted) Name() string                           { return "scripted" }
func (scripted) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationContainer }
func (scripted) SupportsProjects() bool                 { return true }
func (scripted) SupportsModules() bool                  { return true }

func (scripted) Environments() sandbox.Environments {
	kind := sandbox.PayloadEnvironment{Identity: "scripted-image:sha256:0001", SoftwareIdentity: ScriptedSoftware, MaxTimeout: time.Minute}
	project := kind
	project.Languages = []sandbox.Language{sandbox.LanguagePython, sandbox.LanguageJavaScript}
	return sandbox.Environments{JavaScript: kind, Project: project, Module: kind, Policy: "scripted-policy:sha256:00"}
}

func (scripted) RunJavaScript(_ context.Context, req sandbox.Request) (sandbox.Result, error) {
	return sandbox.Result{
		Stdout: "\xff\xfe" + req.Code, Stderr: "warn\n", ExitCode: 3, StdoutTruncated: true,
		Duration: 5 * time.Millisecond, Sandbox: "scripted", Isolation: sandbox.IsolationContainer,
		SoftwareIdentity: ScriptedSoftware, EnvironmentIdentity: "scripted-image:sha256:0001",
	}, nil
}

func (scripted) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	out := sandbox.ProjectResult{
		Sandbox: "scripted", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted,
		SoftwareIdentity: ScriptedSoftware, EnvironmentIdentity: "scripted-image:sha256:0001",
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

// CanonicalNaN is the quiet NaN Python's float("nan") has. JSON writes every NaN as
// "NaN", so only this one survives the trip with its bits.
var CanonicalNaN = math.Float64frombits(0x7ff8000000000000)

func (scripted) RunModule(_ context.Context, req sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	out := sandbox.ModuleResult{
		Width: 3, Sandbox: "scripted", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted,
		SoftwareIdentity: ScriptedSoftware, EnvironmentIdentity: "scripted-image:sha256:0001",
		Stdout: "rows=" + strconv.Itoa(len(req.Rows)) + "\n",
	}
	for i, row := range req.Rows {
		outputs := []float64{row[0], math.Copysign(0, -1), math.MaxFloat64, math.SmallestNonzeroFloat64, 1e21, 123456789012345678901}
		switch req.Model {
		case "nan":
			outputs[1] = CanonicalNaN
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

// --- liar ------------------------------------------------------------------------

func serveLiar(t *testing.T) []string {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := rpc.NewHandler(liar{})
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return []string{srv.URL}
}

// liarSessionID is the one session ID the liar opens.
const liarSessionID = "00112233445566778899aabbccddeeff"

// liar answers in the ways a client must refuse. Describe states another protocol. A
// snippet's code picks the lie: weak-evidence (the tier container), no-record,
// wrong-kind (a project's result), other-protocol (a protocol refusal); anything else
// fails unmarked after dispatch. A session opens as provider liar at container, with
// another session's fingerprint when the open's trace ID is bad-fingerprint, and another
// floor or rule than the open sent when it is bad-floor or bad-rule, and answers
// every call with the record of a call that may have run, stating evidence the session did
// not state at open: "weaker" names the tier process, anything else another provider.
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
	fingerprint := record.SessionFingerprint(liarSessionID)
	if req.Msg.GetTraceId() == "bad-fingerprint" {
		fingerprint = record.SessionFingerprint("another session")
	}
	// The floor and rule the open sent are echoed, as the daemon echoes them, except when
	// the trace ID asks for another floor (bad-floor) or rule (bad-rule).
	floor, rule := req.Msg.GetMinimumIsolation(), req.Msg.GetSoftwareRule()
	switch req.Msg.GetTraceId() {
	case "bad-floor":
		floor = "vm"
	case "bad-rule":
		rule = &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{"oci-manifest:other"}}
	}
	return connect.NewResponse(&plimsollv1.OpenSessionResponse{Generation: 1, SessionId: liarSessionID, Session: fingerprint, Sandbox: "liar", Isolation: "container",
		ExpiresUnixMs: time.Now().Add(time.Minute).UnixMilli(), MinimumIsolation: floor, SoftwareRule: rule}), nil
}

func (liar) SessionRun(_ context.Context, req *connect.Request[plimsollv1.SessionRunRequest]) (*connect.Response[plimsollv1.SessionRunResponse], error) {
	provider, isolation := "liar", "container"
	if req.Msg.GetJavascript().GetCode() == "weaker" {
		isolation = "process"
	} else {
		provider = "other"
	}
	rec := record.StampUnanswered(sandbox.RunRecord{
		RequestSHA256: record.SessionRunRequestDigest(req.Msg), Provider: provider, Isolation: isolation,
		Started: time.UnixMilli(1), Ended: time.UnixMilli(2), Session: record.SessionFingerprint(liarSessionID), Sequence: 1,
	}, "unknown")
	err := connect.NewError(connect.CodeUnknown, errors.New("the stream broke after the code ran"))
	if d, derr := connect.NewErrorDetail(&plimsollv1.UnansweredCall{Record: rec}); derr == nil {
		err.AddDetail(d)
	}
	return nil, err
}

func (liar) CloseSession(context.Context, *connect.Request[plimsollv1.CloseSessionRequest]) (*connect.Response[plimsollv1.CloseSessionResponse], error) {
	return connect.NewResponse(&plimsollv1.CloseSessionResponse{
		Session: record.SessionFingerprint(liarSessionID), Ended: plimsollv1.SessionEnd_SESSION_END_CLOSED,
	}), nil
}

// --- sessions --------------------------------------------------------------------

func serveSessions(t *testing.T) []string {
	sessions := &sandboxtest.Sessions{}
	svc := sessionService(sessions, rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Minute})
	ends := map[string]sandbox.SessionEnd{"expired": sandbox.SessionExpired, "disk_exceeded": sandbox.SessionDiskExceeded}
	return []string{Serve(t, svc, nil, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /test/end-last", func(w http.ResponseWriter, r *http.Request) {
			opened := sessions.Opened()
			reason, ok := ends[r.URL.Query().Get("reason")]
			if len(opened) == 0 || !ok {
				http.Error(w, "no session, or an unknown reason", http.StatusBadRequest)
				return
			}
			opened[len(opened)-1].End(reason)
		})
		mux.HandleFunc("POST /test/end-sessions", func(http.ResponseWriter, *http.Request) {
			for _, s := range sessions.Opened() {
				s.End(sandbox.SessionExpired)
			}
		})
	})}
}

func serveOwnerCap(t *testing.T) []string {
	svc := sessionService(&sandboxtest.Sessions{}, rpc.SessionConfig{MaxSessions: 16, MaxPerOwner: 1, Lifetime: time.Minute, IdleTimeout: time.Minute})
	return []string{Serve(t, svc, nil, nil)}
}

// quickIdle serves a daemon whose idle timeout is the shortest it takes, 1 s, so it
// closes a session no request named by then as unclaimed.
func serveQuickIdle(t *testing.T) []string {
	p := &sandboxtest.Sessions{}
	svc := sessionService(p, rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Second})
	return []string{Serve(t, svc, nil, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /test/wait-ended", func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			if p.WaitEnded(ctx) != nil {
				http.Error(w, "a session is still open", http.StatusGatewayTimeout)
			}
		})
	})}
}

// breakingSessions opens fake sessions whose second call, a snippet or a cell, runs and
// then returns an unmarked error, as an exec stream or a relay lost after the code ran
// does: the daemon sends that call's record with the error.
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

func (s *breakingSession) RunCell(ctx context.Context, req sandbox.CellRequest) (sandbox.CellResult, error) {
	res, err := s.Session.RunCell(ctx, req)
	if s.n++; s.n == 2 {
		return res, errors.New("the relay was lost after the code ran")
	}
	return res, err
}

// serveLossy forwards to a plain session daemon and drops the answer to the second
// SessionRun after the daemon handled it: the call ran, and its answer never arrives.
func serveLossy(t *testing.T) []string {
	target := Serve(t, sessionService(&sandboxtest.Sessions{}, rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Minute}), nil, nil)
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
	return []string{srv.URL}
}

// --- pools -----------------------------------------------------------------------

// projectEcho runs nothing: it answers a project with the plan it received (the file
// paths, the steps, and the code in .plimsoll/cell.*). It states both languages. A cell
// holding ECHO:NOSTEP is answered with no step report, as a run whose report was lost is.
type projectEcho struct{}

func (projectEcho) Name() string                           { return "project-echo" }
func (projectEcho) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationContainer }
func (projectEcho) SupportsProjects() bool                 { return true }
func (projectEcho) Environments() sandbox.Environments {
	langs := []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython}
	return sandbox.Environments{Project: sandbox.PayloadEnvironment{Languages: langs}}
}
func (projectEcho) RunJavaScript(context.Context, sandbox.Request) (sandbox.Result, error) {
	return sandbox.Result{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}
func (projectEcho) RunModule(context.Context, sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	return sandbox.ModuleResult{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}
func (projectEcho) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	plan := struct {
		Files []string `json:"files"`
		Steps []string `json:"steps"`
		Cell  string   `json:"cell"`
	}{Steps: req.Steps}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, f.Path)
		if f.Path == ".plimsoll/cell.py" || f.Path == ".plimsoll/cell.js" {
			plan.Cell = f.Content
		}
	}
	if strings.Contains(plan.Cell, "ECHO:NOSTEP") {
		return sandbox.ProjectResult{
			Sandbox: "project-echo", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeProtocolError, Detail: "the runner's report was lost",
		}, nil
	}
	out, _ := json.Marshal(plan)
	return sandbox.ProjectResult{
		Sandbox: "project-echo", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted,
		Steps: []sandbox.StepResult{{Command: req.Steps[0], Stdout: string(out)}},
	}, nil
}

// pooledEcho is a provider with a warm pool: sessions as sandboxtest.Sessions keeps them
// (its Warm members serve warm-only opens), fresh projects answered as projectEcho answers
// them and counted, so a test tells a pool member's answer to a Run cell
// ("<language> <n>: <code>") from a fresh run's (the plan).
type pooledEcho struct {
	projectEcho
	*sandboxtest.Sessions
	fresh *atomic.Int32
}

func (pooledEcho) Name() string                           { return "pooled-echo" }
func (pooledEcho) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationContainer }
func (p pooledEcho) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	return p.projectEcho.RunJavaScript(ctx, req)
}
func (p pooledEcho) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	p.fresh.Add(1)
	return p.projectEcho.RunProject(ctx, req)
}
func (p pooledEcho) RunModule(ctx context.Context, req sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	return p.projectEcho.RunModule(ctx, req)
}

func servePooled(t *testing.T) []string {
	sessions := &sandboxtest.Sessions{Warm: 1 << 20}
	var fresh atomic.Int32
	svc := sessionService(pooledEcho{Sessions: sessions, fresh: &fresh}, rpc.SessionConfig{MaxSessions: 16, Pool: 2, Lifetime: time.Minute, IdleTimeout: time.Minute})
	return []string{Serve(t, svc, nil, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /test/opened", func(w http.ResponseWriter, _ *http.Request) {
			warmOnly, ended := 0, 0
			for _, s := range sessions.Opened() {
				if s.Options.WarmOnly {
					warmOnly++
				}
				if s.Err() != nil {
					ended++
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]int{"warmOnly": warmOnly, "fresh": int(fresh.Load()), "ended": ended})
		})
	})}
}

// countingRuns counts the Run requests that reach the daemon, and those that asked for a
// pool member (prefer_warm).
type countingRuns struct {
	*rpc.SandboxService
	runs, preferWarm atomic.Int32
}

func (c *countingRuns) Run(ctx context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	c.runs.Add(1)
	if req.Msg.GetPreferWarm() {
		c.preferWarm.Add(1)
	}
	return c.SandboxService.Run(ctx, req)
}

// serveCounted serves a daemon that states a pool of pool, whose provider hands warm
// warm-only opens a pool member and runs fresh projects (sandboxtest.Pooled), and that
// answers POST /test/counts with the Runs that reached it, those that asked for a member,
// the members claimed and the fresh runs made.
func serveCounted(pool, warm int) func(*testing.T) []string {
	return func(t *testing.T) []string {
		p := sandboxtest.NewPooled(warm)
		c := &countingRuns{SandboxService: sessionService(p, rpc.SessionConfig{MaxSessions: 16, Pool: pool, Lifetime: time.Minute, IdleTimeout: time.Minute})}
		return []string{Serve(t, c, nil, func(mux *http.ServeMux) {
			mux.HandleFunc("POST /test/counts", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]int{"runs": int(c.runs.Load()), "preferWarm": int(c.preferWarm.Load()),
					"claimed": len(p.Opened()), "fresh": len(p.FreshRuns())})
			})
		})}
	}
}

// --- answer binding (failure-injection review, findings 1 and 3) -------------------

func serveReplay(t *testing.T) []string {
	svc := Quiet(rpc.NewSandboxService(sandboxtest.Wasm()))
	upstream := Serve(t, svc, nil, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /runs", func(w http.ResponseWriter, _ *http.Request) {
			total, _ := svc.RunCounts()
			_, _ = fmt.Fprint(w, total)
		})
	})
	return []string{answertest.Replay(t, upstream), answertest.Replay(t, upstream), upstream + "/runs"}
}

func serveUnbound(t *testing.T) []string {
	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(Quiet(rpc.NewSandboxService(sandboxtest.Wasm()))))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return []string{srv.URL}
}

func serveEarlyRefusal(t *testing.T) []string {
	mux := http.NewServeMux()
	mux.Handle(rpc.NewHandler(Quiet(rpc.NewSandboxService(sandboxtest.Wasm())), connect.WithReadMaxBytes(256)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return []string{srv.URL}
}

func serveNoProcedure(t *testing.T) []string {
	srv := httptest.NewServer(rpc.BindAnswers(http.NotFoundHandler()))
	t.Cleanup(srv.Close)
	return []string{srv.URL}
}

// ServeLiar serves the liar daemon for t and returns its URL, for the Go client's tests.
func ServeLiar(t *testing.T) string { return serveLiar(t)[0] }
