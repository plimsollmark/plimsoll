package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// tierlessFake is a provider whose results name no isolation tier: the provider's bug
// the daemon refuses to answer as a record (release-55).
type tierlessFake struct{ fakeSandbox }

func (*tierlessFake) Name() string { return "tierless" }
func (f *tierlessFake) RunJavaScript(_ context.Context, req sandbox.Request) (sandbox.Result, error) {
	f.lastReq = req
	return sandbox.Result{Sandbox: "tierless", Stdout: "ran"}, nil
}
func (f *tierlessFake) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	f.lastProj = req
	return sandbox.ProjectResult{Sandbox: "tierless", Outcome: sandbox.ProjectOutcomeCompleted}, nil
}
func (f *tierlessFake) RunModule(_ context.Context, req sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	f.lastMod = req
	return sandbox.ModuleResult{Sandbox: "tierless", Outcome: sandbox.ProjectOutcomeCompleted}, nil
}
func (*tierlessFake) SupportsProjects() bool { return true }

// failedLine is the audit line of a failed run in buf, decoded, or nil.
func failedLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if msg, _ := m["msg"].(string); strings.HasSuffix(msg, " failed") {
			return m
		}
	}
	return nil
}

// A result that names no tier is the provider's bug, and the code may have run: the
// daemon answers it as an internal error, unmarked, never as a record naming "unknown"
// that every official client refuses only after the fact, and its error line names the
// provider (release-55).
func TestAResultNamingNoTierIsAnInternalError(t *testing.T) {
	for name, req := range map[string]*plimsollv1.RunRequest{
		"snippet": {Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}},
		"project": {Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
			Files: []*plimsollv1.ProjectFile{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}}}},
		"module": {Payload: &plimsollv1.RunRequest_Module{Module: &plimsollv1.ModuleRun{
			Model: "vanderpol", Rows: []*plimsollv1.ModuleRow{{Values: []float64{1, 2}}}, EndTime: 1, Step: 0.1}}},
	} {
		req.Protocol = protocol.Number
		var buf bytes.Buffer
		svc := NewSandboxService(&tierlessFake{})
		svc.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
		resp, err := svc.Run(authenticatedContext("alice"), connect.NewRequest(req))
		if err == nil {
			t.Errorf("%s: answered %+v; want an internal error", name, resp.Msg)
			continue
		}
		if connect.CodeOf(err) != connect.CodeInternal {
			t.Errorf("%s: %v; want an internal error", name, err)
		}
		if _, marked := notDispatchedOf(err); marked {
			t.Errorf("%s: marked not dispatched, but the code may have run", name)
		}
		line := failedLine(t, &buf)
		if line == nil || line["sandbox"] != "tierless" || line["level"] != "ERROR" || !strings.Contains(buf.String(), "named no isolation tier") {
			t.Errorf("%s: log %s; want an error line naming the provider and the missing tier", name, buf.String())
		}
	}
}

// tierlessSessions opens sessions whose results, or whose stated tier, name none.
type tierlessSessions struct {
	*sandboxtest.Sessions
	session bool // the session itself states no tier; otherwise only its results
}

func (p *tierlessSessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &tierlessSession{Session: s, session: p.session}, nil
}

type tierlessSession struct {
	sandbox.Session
	session bool
}

func (s *tierlessSession) Isolation() sandbox.IsolationClass {
	if s.session {
		return sandbox.IsolationUnknown
	}
	return s.Session.Isolation()
}

func (s *tierlessSession) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	res, err := s.Session.RunJavaScript(ctx, req)
	res.Isolation = sandbox.IsolationUnknown
	return res, err
}

// A session call whose result names no tier is an internal error too, and the
// session's chain records it as a call that ended without an answer.
func TestASessionCallNamingNoTierIsAnInternalError(t *testing.T) {
	svc, p := sessionService()
	svc.Sandbox = &tierlessSessions{Sessions: p}
	ctx := authenticatedContext("alice")
	opened, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	_, err = headRun(svc, ctx, callReq(opened.Msg.GetSessionId(), "1"))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("a session call naming no tier: %v; want an internal error", err)
	}
	if _, marked := notDispatchedOf(err); marked {
		t.Fatal("marked not dispatched, but the code may have run")
	}
}

// A session whose provider states no tier for it is refused at the open, before any
// call: nothing of the caller's has run (an open carries no code), and every record of
// its calls, the unanswered ones included, would name "unknown".
func TestASessionNamingNoTierIsRefusedAtOpen(t *testing.T) {
	svc, p := sessionService()
	svc.Sandbox = &tierlessSessions{Sessions: p, session: true}
	var buf bytes.Buffer
	svc.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	_, err := svc.OpenSession(authenticatedContext("alice"), openReq())
	if reason, marked := notDispatchedOf(err); !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ENVIRONMENT {
		t.Fatalf("an open naming no tier: %v (marked %v, %v); want a refusal marked not dispatched, environment", err, marked, reason)
	}
	if log := buf.String(); !strings.Contains(log, `"why":"no_tier"`) || !strings.Contains(log, "names no isolation tier") || !strings.Contains(log, `"sandbox":"fake-sessions"`) {
		t.Errorf("log %s; want the refused open's line naming the provider and why", log)
	}
	if len(p.Opened()) != 1 {
		t.Fatalf("opened %d sessions; want the one refused", len(p.Opened()))
	}
	if err := p.WaitEnded(context.Background()); err != nil {
		t.Fatalf("the refused session was not closed: %v", err)
	}
}
