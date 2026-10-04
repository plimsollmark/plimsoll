package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/pipeline.golden from the current handlers")

// pipelineCase is one call through a handler: what the provider answers, and the call.
type pipelineCase struct {
	name string
	call func(t *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error)
}

func runJS(svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
	resp, err := svc.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, TraceId: "trace-1",
		Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "console.log(1)"}}}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func runProj(svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
	resp, err := svc.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, TraceId: "trace-2",
		Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
			Files:     []*plimsollv1.ProjectFile{{Path: "main.js", Content: "console.log(2)"}, {Path: "data.txt", Content: "abc"}},
			Steps:     []string{"node main.js", "node main.js"},
			Artifacts: []string{"out.txt"},
		}}}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func runMod(svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
	resp, err := svc.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, TraceId: "trace-3",
		Payload: &plimsollv1.RunRequest_Module{Module: &plimsollv1.ModuleRun{Model: "vanderpol",
			Rows: []*plimsollv1.ModuleRow{{Values: []float64{1, 2}}, {Values: []float64{1, 2}}}, EndTime: 1, Step: 0.1}}}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// failingCells is a session provider whose cells fail as infrastructure does.
type failingCells struct{ *sandboxtest.Sessions }

func (p *failingCells) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &failingCell{s}, nil
}

type failingCell struct{ sandbox.Session }

func (*failingCell) RunCell(context.Context, sandbox.CellRequest) (sandbox.CellResult, error) {
	return sandbox.CellResult{}, errors.New("the interpreter's relay broke")
}

func sessionCall(t *testing.T, svc *SandboxService, ctx context.Context, payload func(*plimsollv1.SessionRunRequest)) (*plimsollv1.RunResponse, error) {
	t.Helper()
	opened, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	req := &plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: opened.Msg.GetSessionId(), TraceId: "trace-s"}
	payload(req)
	resp, err := svc.SessionRun(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg.GetRun(), nil
}

func pipelineCases() []pipelineCase {
	nan := math.Float64frombits(0x7ff8000000000001)
	// A run case serves its own fake, logging where the session cases' service logs.
	ok := func(svc *SandboxService, f *fakeSandbox) *SandboxService {
		s := NewSandboxService(f)
		s.Logger = svc.Logger
		return s
	}
	cases := []pipelineCase{
		{"run javascript", func(_ *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			return runJS(ok(svc, &fakeSandbox{jsResult: sandbox.Result{Stdout: "out", Stderr: "err", ExitCode: 3, Duration: 5 * time.Millisecond,
				Sandbox: "fake", Isolation: sandbox.IsolationVM, SoftwareIdentity: "sw:1", EnvironmentIdentity: "env:1"}}), ctx)
		}},
		{"run javascript, infrastructure failure", func(_ *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			return runJS(ok(svc, &fakeSandbox{jsErr: errors.New("docker answered nonsense")}), ctx)
		}},
		{"run javascript, refused by the provider", func(_ *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			return runJS(ok(svc, &fakeSandbox{jsErr: sandbox.NotDispatched(sandbox.RefusalEnvironment, fmt.Errorf("%w: image unproven", sandbox.ErrUnsupported))}), ctx)
		}},
		{"run project", func(_ *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			return runProj(ok(svc, &fakeSandbox{projResult: sandbox.ProjectResult{Sandbox: "fake", Isolation: sandbox.IsolationVM,
				Outcome: sandbox.ProjectOutcomeCompleted, Detail: "fine", SoftwareIdentity: "sw:2",
				Steps: []sandbox.StepResult{{Command: "node main.js", Stdout: "2\n", ExitCode: 0, Duration: time.Millisecond},
					{Command: "node main.js", Stderr: "late", ExitCode: 7, TimedOut: true, Duration: 2 * time.Millisecond}},
				Artifacts: []sandbox.Artifact{{Path: "out.txt", Content: []byte("o")}}, ArtifactsTruncated: true}}), ctx)
		}},
		{"run project, infrastructure failure", func(_ *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			return runProj(ok(svc, &fakeSandbox{projErr: errors.New("the runner vanished")}), ctx)
		}},
		{"run module", func(_ *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			return runMod(ok(svc, &fakeSandbox{modResult: sandbox.ModuleResult{Sandbox: "fake", Isolation: sandbox.IsolationVM,
				Outcome: sandbox.ProjectOutcomeCompleted, Width: 2, Duration: 9 * time.Millisecond, Stdout: "s", Stderr: "e",
				Runs: []sandbox.ModuleRun{{Status: 10, Outputs: []float64{1, nan}}, {Status: 10, Outputs: []float64{1, nan}}}}}), ctx)
		}},
		{"run module, rows that repeat an answer", func(_ *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			var rows []*plimsollv1.ModuleRow
			var runs []sandbox.ModuleRun
			for i := range 8 {
				rows = append(rows, &plimsollv1.ModuleRow{Values: []float64{float64(i) * 0.001}})
				runs = append(runs, sandbox.ModuleRun{Status: 10, Outputs: []float64{1}})
			}
			s := ok(svc, &fakeSandbox{modResult: sandbox.ModuleResult{Sandbox: "fake", Isolation: sandbox.IsolationVM,
				Outcome: sandbox.ProjectOutcomeCompleted, Width: 1, Duration: 9 * time.Millisecond, Runs: runs}})
			resp, err := s.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number,
				Payload: &plimsollv1.RunRequest_Module{Module: &plimsollv1.ModuleRun{Model: "vanderpol", Rows: rows, EndTime: 1, Step: 0.1}}}))
			if err != nil {
				return nil, err
			}
			return resp.Msg, nil
		}},
		{"run module, infrastructure failure", func(_ *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			return runMod(ok(svc, &fakeSandbox{modErr: errors.New("the worker vanished")}), ctx)
		}},
		{"session javascript", func(t *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			return sessionCall(t, svc, ctx, func(r *plimsollv1.SessionRunRequest) {
				r.Payload = &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}
			})
		}},
		{"session project", func(t *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			return sessionCall(t, svc, ctx, func(r *plimsollv1.SessionRunRequest) {
				r.Payload = &plimsollv1.SessionRunRequest_Project{Project: &plimsollv1.ProjectRun{
					Files: []*plimsollv1.ProjectFile{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}}}
			})
		}},
		{"session cell", func(t *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			return sessionCall(t, svc, ctx, func(r *plimsollv1.SessionRunRequest) {
				r.Payload = &plimsollv1.SessionRunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "python", Code: "x = 1",
					Files: []*plimsollv1.ProjectFile{{Path: "in.txt", Content: "i"}}}}
			})
		}},
		{"session cell, infrastructure failure", func(t *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
			svc.Sandbox = &failingCells{svc.Sandbox.(*sandboxtest.Sessions)}
			return sessionCall(t, svc, ctx, func(r *plimsollv1.SessionRunRequest) {
				r.Payload = &plimsollv1.SessionRunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "javascript", Code: "1"}}
			})
		}},
	}
	// Granted runs that brokered calls, in every advice mode, succeeding and failing:
	// the host-call summary, the findings and the advice on the wire (advice_test.go's
	// profiles).
	for _, profile := range []string{"p-off", "p-operator", "p-caller", "p-agg", "p-catalog-caller", "p-declared-ungranted"} {
		for _, project := range []bool{false, true} {
			for _, fail := range []bool{false, true} {
				name := fmt.Sprintf("granted %s, profile %s, failing %v", map[bool]string{false: "javascript", true: "project"}[project], profile, fail)
				cases = append(cases, pipelineCase{name, func(t *testing.T, svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
					s := adviceService(t, nil)
					s.Logger = svc.Logger
					if fail {
						f := s.Sandbox.(*fakeSandbox)
						f.jsErr, f.projErr = errors.New("broke after brokering"), errors.New("broke after brokering")
					}
					req := jsGrantReq("host.get('/v1/lights/1')", profile)
					if project {
						req = projectReq(&plimsollv1.ProjectRun{Files: []*plimsollv1.ProjectFile{{Path: "main.mjs", Content: "x"}},
							Steps: []string{"node main.mjs"}, GrantProfile: profile})
					}
					resp, err := s.Run(authenticatedContext("mcp-a"), req)
					if err != nil {
						return nil, err
					}
					return resp.Msg, nil
				}})
			}
		}
	}
	return cases
}

// masked hides the fields of an audit line that differ between two identical calls.
func masked(_ []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case "time", "duration_ms", "session":
		return slog.String(a.Key, "*")
	}
	return a
}

// TestEveryKindsAuditLineAndResponseArePinned records, for every payload kind as a run
// and as a session call, succeeding and failing, the audit line the handler writes and
// the response it returns (record and durations aside), and compares them with
// testdata/pipeline.golden. Refactoring the request pipeline must leave both as they
// are; `go test ./internal/rpc -run Pinned -update` rewrites the file when a change is
// meant.
func TestEveryKindsAuditLineAndResponseArePinned(t *testing.T) {
	var got bytes.Buffer
	for _, tc := range pipelineCases() {
		var logs bytes.Buffer
		svc, _ := sessionService()
		svc.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo, ReplaceAttr: masked}))
		resp, err := tc.call(t, svc, authenticatedContext("alice"))
		fmt.Fprintf(&got, "== %s\n", tc.name)
		if err != nil {
			reason, marked := notDispatchedOf(err) // the mark as a client reads it
			fmt.Fprintf(&got, "error %s marked=%v reason=%v\n", connect.CodeOf(err), marked, reason)
		} else {
			// A project's duration is the handler's clock; every other kind's is the
			// provider's, and stays pinned.
			resp.Record = nil
			if p := resp.GetProject(); p != nil {
				resp.DurationMs = 0
				for _, s := range p.Steps {
					s.DurationMs = 0
				}
			}
			b, merr := protojson.MarshalOptions{UseProtoNames: true}.Marshal(resp)
			if merr != nil {
				t.Fatal(merr)
			}
			var canon any
			_ = json.Unmarshal(b, &canon)
			b, _ = json.Marshal(canon)
			fmt.Fprintf(&got, "response %s\n", b)
		}
		// The lines as written: attribute order and any repeated key count.
		for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
			if line != "" && !strings.Contains(line, `"msg":"session opened"`) {
				fmt.Fprintf(&got, "audit %s\n", line)
			}
		}
	}
	path := filepath.Join("testdata", "pipeline.golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		gl, wl := strings.Split(got.String(), "\n"), strings.Split(string(want), "\n")
		for i := 0; i < max(len(gl), len(wl)); i++ {
			g, w := "", ""
			if i < len(gl) {
				g = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if g != w {
				t.Fatalf("line %d differs from %s:\n got  %s\n want %s", i+1, path, g, w)
			}
		}
	}
}

// A refusal before admission spends no rate token, for every kind: an unmet floor, an
// unmet software rule, a grant the caller may not use. With one token, each refusal
// leaves it for the call after.
func TestRefusalsBeforeAdmissionSpendNoRateToken(t *testing.T) {
	ctx := authenticatedContext("alice")
	floor := func(r *plimsollv1.RunRequest) { r.MinimumIsolation = "vm" }
	rule := func(r *plimsollv1.RunRequest) {
		r.SoftwareRule = &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{"oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64)}}
	}
	grant := func(r *plimsollv1.RunRequest) {
		switch p := r.Payload.(type) {
		case *plimsollv1.RunRequest_Javascript:
			p.Javascript.GrantProfile = "nobody-has-this"
		case *plimsollv1.RunRequest_Project:
			p.Project.GrantProfile = "nobody-has-this"
		}
	}
	kinds := map[string]func() *plimsollv1.RunRequest{
		"javascript": func() *plimsollv1.RunRequest {
			return &plimsollv1.RunRequest{Protocol: protocol.Number, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
		},
		"project": func() *plimsollv1.RunRequest {
			return &plimsollv1.RunRequest{Protocol: protocol.Number, Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
				Files: []*plimsollv1.ProjectFile{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}}}}
		},
		"module": func() *plimsollv1.RunRequest {
			return &plimsollv1.RunRequest{Protocol: protocol.Number, Payload: &plimsollv1.RunRequest_Module{Module: &plimsollv1.ModuleRun{Model: "vanderpol",
				Rows: []*plimsollv1.ModuleRow{{Values: []float64{1}}}, EndTime: 1, Step: 0.5}}}
		},
	}
	for name, build := range kinds {
		for refusal, change := range map[string]func(*plimsollv1.RunRequest){"floor": floor, "rule": rule, "grant": grant} {
			if name == "module" && refusal == "grant" {
				continue // a module payload names no grant
			}
			t.Run(name+"/"+refusal, func(t *testing.T) {
				f := &isolationFake{fakeSandbox: &fakeSandbox{modResult: sandbox.ModuleResult{Outcome: sandbox.ProjectOutcomeCompleted}}, isolation: sandbox.IsolationContainer}
				svc := NewSandboxService(f)
				svc.Limiter = NewCodeLimiter(10, 10, 1, 1)
				refused := build()
				change(refused)
				if _, err := svc.Run(ctx, connect.NewRequest(refused)); err == nil {
					t.Fatal("the call was not refused")
				} else if _, marked := notDispatchedOf(err); !marked {
					t.Fatalf("the refusal is not marked not dispatched: %v", err)
				}
				if _, err := svc.Run(ctx, connect.NewRequest(build())); err != nil {
					t.Fatalf("the call after a refusal: %v (the refusal spent the token)", err)
				}
			})
		}
	}
}

// A cell refused for its floor or its software rule spends no rate token either.
// Opening takes one of two tokens; the refused cells take none.
func TestRefusedCellsSpendNoRateToken(t *testing.T) {
	svc, _ := sessionService()
	svc.Limiter = NewCodeLimiter(10, 10, 1, 2)
	ctx := authenticatedContext("alice")
	opened, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	cell := func(change func(*plimsollv1.SessionRunRequest)) error {
		req := &plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: opened.Msg.GetSessionId(),
			Payload: &plimsollv1.SessionRunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "python", Code: "1"}}}
		change(req)
		_, err := svc.SessionRun(ctx, connect.NewRequest(req))
		return err
	}
	if err := cell(func(r *plimsollv1.SessionRunRequest) { r.MinimumIsolation = "vm" }); !errors.Is(err, sandbox.ErrInsufficientIsolation) {
		t.Fatalf("a cell above the session's tier: %v", err)
	}
	if err := cell(func(r *plimsollv1.SessionRunRequest) {
		r.SoftwareRule = &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{"oci-manifest:linux/amd64@sha256:" + strings.Repeat("c", 64)}}
	}); !errors.Is(err, sandbox.ErrSoftwareMismatch) {
		t.Fatalf("a cell whose rule the session's software fails: %v", err)
	}
	if err := cell(func(*plimsollv1.SessionRunRequest) {}); err != nil {
		t.Fatalf("the cell after two refusals: %v (a refusal spent the token)", err)
	}
}

// A malformed session call is refused as malformed at once, even while the session's
// turn is held by another call: validation comes before the turn. Before the request
// pipeline it waited for the turn and was refused as busy, a capacity refusal that
// invites the caller to retry a request that can never run.
func TestSessionCallIsValidatedBeforeItsTurn(t *testing.T) {
	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	opened, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, ok := svc.sessions.get(opened.Msg.GetSessionId(), "alice")
	if !ok {
		t.Fatal("the session is not registered")
	}
	give, err := e.takeTurn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer give()
	cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	_, err = svc.SessionRun(cctx, connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: opened.Msg.GetSessionId(),
		Payload: &plimsollv1.SessionRunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "cobol", Code: "1"}}}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a malformed call behind a held turn: %v (%s); want InvalidArgument", err, connect.CodeOf(err))
	}
}

// A session call refused before it ran is not counted by the session's chain, and
// carries no unanswered-call record (which the client, reading the not-dispatched mark,
// would not chain either, so the next record check would fail): refused at admission
// (the caller's rate), by the provider (a sandbox it could not read back, whose mark
// rides an Internal code) and for its grant (a profile the caller may not use). Before
// the request pipeline all three were chained as unanswered calls that may have run:
// the handler read the mark with sandbox.NotDispatchedReason, which sees neither a mark
// refuse puts on the wire nor one mapSandboxErr replaced the error text of.
func TestSessionCallsRefusedBeforeTheyRanAreNotChained(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(svc *SandboxService)
		call  func(id string) *connect.Request[plimsollv1.SessionRunRequest]
	}{
		{"over the caller's rate", func(svc *SandboxService) { svc.Limiter = NewCodeLimiter(10, 10, 1, 1) }, func(id string) *connect.Request[plimsollv1.SessionRunRequest] {
			return callReq(id, "1")
		}},
		{"a sandbox the provider could not read back", func(svc *SandboxService) {
			svc.Sandbox = &unreadableSessions{svc.Sandbox.(*sandboxtest.Sessions)}
		}, func(id string) *connect.Request[plimsollv1.SessionRunRequest] { return callReq(id, "1") }},
		{"a grant profile the caller may not use", func(*SandboxService) {}, func(id string) *connect.Request[plimsollv1.SessionRunRequest] {
			return connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: id,
				Payload: &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1", GrantProfile: "nobody-has-this"}}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := sessionService()
			tc.setup(svc)
			ctx := authenticatedContext("alice")
			opened, err := svc.OpenSession(ctx, openReq())
			if err != nil {
				t.Fatal(err)
			}
			id := opened.Msg.GetSessionId()
			_, err = svc.SessionRun(ctx, tc.call(id))
			if _, marked := notDispatchedOf(err); !marked {
				t.Fatalf("the refusal: %v; want it marked not dispatched", err)
			}
			var ce *connect.Error
			if errors.As(err, &ce) {
				for _, d := range ce.Details() {
					if d.Type() == "plimsoll.v1.UnansweredCall" {
						t.Fatal("a call refused before it ran carries an unanswered-call record")
					}
				}
			}
			closed, err := svc.CloseSession(ctx, closeReq(id))
			if err != nil {
				t.Fatal(err)
			}
			if closed.Msg.GetCalls() != 0 {
				t.Fatalf("the chain counts %d calls; want 0, the refused call is not one", closed.Msg.GetCalls())
			}
		})
	}
}

// unreadableSessions is a session provider whose snippets are refused as a sandbox
// that could not be read back is (review F4).
type unreadableSessions struct{ *sandboxtest.Sessions }

func (p *unreadableSessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &unreadableSession{s}, nil
}

type unreadableSession struct{ sandbox.Session }

func (*unreadableSession) RunJavaScript(context.Context, sandbox.Request) (sandbox.Result, error) {
	return sandbox.Result{}, sandbox.RefuseUnreadable(errors.New("the gateway is restarting"))
}

// A caller whose context is done takes no turn, even a free one, so it spends no rate
// token or slot on a session it will not use; the refusal says nothing ran.
func TestAGoneCallerTakesNoTurn(t *testing.T) {
	svc, _ := sessionService()
	opened, err := svc.OpenSession(authenticatedContext("alice"), openReq())
	if err != nil {
		t.Fatal(err)
	}
	e, ok := svc.sessions.get(opened.Msg.GetSessionId(), "alice")
	if !ok {
		t.Fatal("the session is not registered")
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	for range 50 {
		give, err := e.takeTurn(gone)
		if err == nil {
			give()
			t.Fatal("a caller whose context was done took the session's free turn")
		}
		if _, marked := notDispatchedOf(err); !marked {
			t.Fatalf("the refusal is not marked not dispatched: %v", err)
		}
	}
}
