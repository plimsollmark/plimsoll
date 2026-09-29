package rpc

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// describedFake states environments and a policy, as a real provider does.
type describedFake struct{ fakeSandbox }

func (*describedFake) Environments() sandbox.Environments {
	return sandbox.Environments{
		JavaScript: sandbox.PayloadEnvironment{Identity: "test-image:js"},
		Project:    sandbox.PayloadEnvironment{Identity: "test-image:project"},
		Module:     sandbox.PayloadEnvironment{Identity: "test-image:module"},
		Policy:     "test-policy:1",
	}
}

// otherNamedFake is the same provider under another name, for comparing records
// of one request across providers.
type otherNamedFake struct{ fakeSandbox }

func (*otherNamedFake) Name() string { return "other" }

func finishedFake(name string) fakeSandbox {
	return fakeSandbox{
		jsResult:   sandbox.Result{Stdout: "4\n", Sandbox: name, Isolation: sandbox.IsolationVM, Duration: 3 * time.Millisecond},
		projResult: sandbox.ProjectResult{Sandbox: name, Isolation: sandbox.IsolationVM, Outcome: sandbox.ProjectOutcomeCompleted, Steps: []sandbox.StepResult{{Command: "true"}}},
		modResult:  sandbox.ModuleResult{Sandbox: name, Isolation: sandbox.IsolationVM, Outcome: sandbox.ProjectOutcomeCompleted, Width: 1, Runs: []sandbox.ModuleRun{{Status: 1, Outputs: []float64{0.5}}}},
	}
}

// Every kind's response carries a record the caller can check against what it
// sent and received, stating the kind's environment, the policy and the times.
func TestRunRecordStatesEachKind(t *testing.T) {
	svc := NewSandboxService(&describedFake{finishedFake("fake")})
	for _, c := range []struct {
		kind        string
		req         *connect.Request[plimsollv1.RunRequest]
		environment string
	}{
		{"javascript", jsReq("console.log(2+2)"), "test-image:js"},
		{"project", envelopeReq(&plimsollv1.ProjectRun{Steps: []string{"true"}}), "test-image:project"},
		{"module", envelopeReq(&plimsollv1.ModuleRun{Model: "m", Rows: []*plimsollv1.ModuleRow{{Values: []float64{1}}}, EndTime: 1, Step: 0.5}), "test-image:module"},
	} {
		before := time.Now().Truncate(time.Millisecond)
		resp, err := svc.Run(context.Background(), c.req)
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		after := time.Now()
		rec, err := record.Check(c.req.Msg, resp.Msg)
		if err != nil || rec == nil {
			t.Fatalf("%s: the record does not check: %v, %v", c.kind, rec, err)
		}
		if rec.Environment != c.environment || rec.Policy != "test-policy:1" || rec.Provider != "fake" || rec.Isolation != "vm" {
			t.Errorf("%s: evidence %+v", c.kind, rec)
		}
		if rec.Started.Before(before) || rec.Ended.Before(rec.Started) || rec.Ended.After(after) {
			t.Errorf("%s: times %v to %v outside %v to %v", c.kind, rec.Started, rec.Ended, before, after)
		}
		if rec.Session != "" || rec.Sequence != 0 || rec.PreviousSHA256 != "" {
			t.Errorf("%s: a single run carries session fields: %+v", c.kind, rec)
		}
	}
}

// One request gets one request digest whichever provider runs it; the records
// differ where the evidence does.
func TestRequestDigestIsTheSameOnEveryProvider(t *testing.T) {
	a := NewSandboxService(&describedFake{finishedFake("fake")})
	b := NewSandboxService(&otherNamedFake{finishedFake("other")})
	ra, err := a.Run(context.Background(), jsReq("console.log(2+2)"))
	if err != nil {
		t.Fatal(err)
	}
	rb, err := b.Run(context.Background(), jsReq("console.log(2+2)"))
	if err != nil {
		t.Fatal(err)
	}
	if ra.Msg.GetRecord().GetRequestSha256() != rb.Msg.GetRecord().GetRequestSha256() {
		t.Error("the same request got different request digests on two providers")
	}
	if ra.Msg.GetRecord().GetResultSha256() != rb.Msg.GetRecord().GetResultSha256() {
		t.Error("the same output got different result digests on two providers")
	}
	if ra.Msg.GetRecord().GetRecordSha256() == rb.Msg.GetRecord().GetRecordSha256() {
		t.Error("records naming different providers share a digest")
	}
}

// A refusal answers no response, so it carries no record: nothing ran to state.
func TestRefusedRunHasNoRecord(t *testing.T) {
	svc := NewSandboxService(&describedFake{finishedFake("fake")})
	req := jsReq("1")
	req.Msg.MinimumIsolation = "bogus"
	if resp, err := svc.Run(context.Background(), req); err == nil || resp != nil {
		t.Fatalf("an invalid floor ran: %v, %v", resp, err)
	}
}
