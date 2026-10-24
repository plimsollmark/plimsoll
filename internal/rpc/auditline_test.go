package rpc

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/auditline"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Every kind of run line the daemon writes decodes as auditline.Run, the one type every
// reader uses, with the fields that say how the run ended. A project stopped before any
// step reported is timed out with no exit code: it was once logged timed_out=false,
// exit_code=0 (review, 2026-10-23).
func TestEveryRunLineDecodesAsTheSharedType(t *testing.T) {
	exit := func(n int) *int { return &n }
	stopped := sandbox.ProjectResult{Sandbox: "fake", Isolation: sandbox.IsolationVM, Outcome: sandbox.ProjectOutcomeTimedOut,
		Detail: "the run's deadline passed"}
	project := sandbox.ProjectResult{Sandbox: "fake", Isolation: sandbox.IsolationVM, Outcome: sandbox.ProjectOutcomeCompleted,
		Steps: []sandbox.StepResult{{Command: "node main.js", ExitCode: 2}}}
	for _, tc := range []struct {
		name     string
		fake     *fakeSandbox
		run      func(*SandboxService) error
		msg, op  string
		outcome  string
		exit     *int
		timedOut bool
	}{
		{"snippet", &fakeSandbox{jsResult: sandbox.Result{Sandbox: "fake", Isolation: sandbox.IsolationVM, ExitCode: 3}},
			func(s *SandboxService) error { _, err := runJS(s, context.Background()); return err },
			auditline.Code, "javascript", "", exit(3), false},
		{"project stopped before any step reported", &fakeSandbox{projResult: stopped},
			func(s *SandboxService) error { _, err := runProj(s, context.Background()); return err },
			auditline.Project, "project", "timed_out", nil, true},
		{"project", &fakeSandbox{projResult: project},
			func(s *SandboxService) error { _, err := runProj(s, context.Background()); return err },
			auditline.Project, "project", "completed", exit(2), false},
		{"module", &fakeSandbox{modResult: sandbox.ModuleResult{Sandbox: "fake", Isolation: sandbox.IsolationVM,
			Outcome: sandbox.ProjectOutcomeCompleted, Width: 1, Runs: []sandbox.ModuleRun{{Status: 10, Outputs: []float64{1}}, {Status: 10, Outputs: []float64{1}}}}},
			func(s *SandboxService) error { _, err := runMod(s, context.Background()); return err },
			auditline.Module, "module", "completed", nil, false},
	} {
		var buf bytes.Buffer
		svc := NewSandboxService(tc.fake)
		svc.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
		if err := tc.run(svc); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		runs, err := auditline.Parse(&buf)
		if err != nil || len(runs) != 1 {
			t.Fatalf("%s: %d run lines, %v: %s", tc.name, len(runs), err, buf.String())
		}
		r := runs[0]
		switch {
		case r.Msg != tc.msg || r.Op != tc.op || r.Outcome != tc.outcome || r.TimedOut != tc.timedOut:
			t.Errorf("%s: msg %q, op %q, outcome %q, timed out %v", tc.name, r.Msg, r.Op, r.Outcome, r.TimedOut)
		case (r.ExitCode == nil) != (tc.exit == nil) || (r.ExitCode != nil && *r.ExitCode != *tc.exit):
			t.Errorf("%s: exit code %v, want %v", tc.name, r.ExitCode, tc.exit)
		case r.Caller == "" || r.Sandbox != "fake" || r.Isolation != "vm":
			t.Errorf("%s: caller %q, sandbox %q, isolation %q", tc.name, r.Caller, r.Sandbox, r.Isolation)
		}
	}
}

// A session's ordinary end is not an infrastructure failure; a sandbox that failed under
// its session is (review B9, 2026-10-23).
func TestOnlyASandboxThatFailedUnderItsSessionCountsAsAFailure(t *testing.T) {
	for end, infra := range map[sandbox.SessionEnd]bool{
		sandbox.SessionClosed: false, sandbox.SessionExpired: false, sandbox.SessionDiskExceeded: false,
		sandbox.SessionReplaced: false, sandbox.SessionNotFound: false,
		sandbox.SessionBoundaryFailed: true, sandbox.SessionSandboxChanged: true,
	} {
		if got := isInfraErr(&sandbox.SessionEndedError{Reason: end}); got != infra {
			t.Errorf("%v: counted as a failure %v, want %v", end, got, infra)
		}
	}
}
