package rpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// describedFake states environments and a policy, as a real provider does.
type describedFake struct {
	fakeSandbox
	env *sandbox.Environments
	// silent models a provider that could not establish which software it ran.
	silent bool
}

// A real provider reports the software each run launched; the daemon states that
// and never the Describe answer read before admission.
func (f *describedFake) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	res, err := f.fakeSandbox.RunJavaScript(ctx, req)
	if !f.silent {
		res.SoftwareIdentity = f.Environments().JavaScript.SoftwareIdentity
	}
	return res, err
}

func (f *describedFake) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	res, err := f.fakeSandbox.RunProject(ctx, req)
	if !f.silent {
		res.SoftwareIdentity = f.Environments().Project.SoftwareIdentity
	}
	return res, err
}

func (f *describedFake) RunModule(ctx context.Context, req sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	res, err := f.fakeSandbox.RunModule(ctx, req)
	if !f.silent {
		res.SoftwareIdentity = f.Environments().Module.SoftwareIdentity
	}
	return res, err
}

func (f *describedFake) Environments() sandbox.Environments {
	if f.env != nil {
		return *f.env
	}
	return sandbox.Environments{
		JavaScript: sandbox.PayloadEnvironment{Identity: "test-image:js", SoftwareIdentity: "oci-manifest:linux/amd64@sha256:aaaa"},
		Project:    sandbox.PayloadEnvironment{Identity: "test-image:project", SoftwareIdentity: "oci-manifest:linux/amd64@sha256:bbbb"},
		Module:     sandbox.PayloadEnvironment{Identity: "test-image:module", SoftwareIdentity: "oci-manifest:linux/amd64@sha256:cccc"},
		Policy:     "test-policy:1",
	}
}

func TestSoftwareRuleIsCheckedBeforeDispatchAndBoundToRecord(t *testing.T) {
	fake := &describedFake{fakeSandbox: finishedFake("fake")}
	svc := NewSandboxService(fake)
	id := fake.Environments().JavaScript.SoftwareIdentity
	req := jsReq("console.log(2+2)")
	req.Msg.SoftwareRule = &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{id}}
	resp, err := svc.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := record.Check(req.Msg, resp.Msg)
	if err != nil || rec.SoftwareIdentity != id || rec.SoftwareRuleID != "exact:"+id {
		t.Fatalf("record: %+v, %v", rec, err)
	}
	if fake.lastReq.Software.ID() != rec.SoftwareRuleID {
		t.Fatalf("provider did not receive the rule: %+v", fake.lastReq.Software)
	}
	// Describe can be cached by a placement client. The daemon reads its current
	// selection on every request and refuses an image changed since that answer.
	changed := fake.Environments()
	changed.JavaScript.SoftwareIdentity = "oci-manifest:linux/amd64@sha256:dddd"
	fake.env = &changed
	fake.lastReq = sandbox.Request{}
	_, err = svc.Run(context.Background(), req)
	if !errors.Is(err, sandbox.ErrSoftwareMismatch) || fake.lastReq.Code != "" {
		t.Fatalf("stale description dispatched code: %v, %+v", err, fake.lastReq)
	}
	approved := jsReq("console.log(2+2)")
	approved.Msg.SoftwareRule = &plimsollv1.SoftwareRule{Mode: "approved", Identities: []string{id, changed.JavaScript.SoftwareIdentity}}
	resp, err = svc.Run(context.Background(), approved)
	if err != nil {
		t.Fatal(err)
	}
	rec, err = record.Check(approved.Msg, resp.Msg)
	if err != nil || rec.SoftwareIdentity != changed.JavaScript.SoftwareIdentity || rec.SoftwareRuleID == "" {
		t.Fatalf("approved set: %+v, %v", rec, err)
	}
	// A run that could not establish its software states none, even though Describe
	// named one before admission, and the caller's record check refuses it.
	fake.silent = true
	resp, err = svc.Run(context.Background(), approved)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Msg.GetSoftwareIdentity(); got != "" {
		t.Fatalf("response states software the run did not establish: %q", got)
	}
	if _, err := record.Check(approved.Msg, resp.Msg); err == nil {
		t.Fatal("record check accepted a run with no software identity under a required rule")
	}
}

func TestProjectAndModuleSoftwareRulesRefuseBeforeDispatch(t *testing.T) {
	fake := &describedFake{fakeSandbox: finishedFake("fake")}
	svc := NewSandboxService(fake)
	wrong := &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{"oci-manifest:linux/amd64@sha256:wrong"}}
	for _, req := range []*connect.Request[plimsollv1.RunRequest]{
		envelopeReq(&plimsollv1.ProjectRun{Steps: []string{"true"}}),
		envelopeReq(&plimsollv1.ModuleRun{Model: "m", Rows: []*plimsollv1.ModuleRow{{Values: []float64{1}}}, EndTime: 1, Step: 0.5}),
	} {
		req.Msg.SoftwareRule = wrong
		_, err := svc.Run(context.Background(), req)
		if !errors.Is(err, sandbox.ErrSoftwareMismatch) {
			t.Fatalf("software rule did not refuse %T: %v", req.Msg.GetPayload(), err)
		}
		if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalEnvironment {
			t.Fatalf("software rule lacks environment refusal for %T: %v, %v", req.Msg.GetPayload(), reason, ok)
		}
	}
	if fake.lastProj.Steps != nil || fake.lastMod.Model != "" {
		t.Fatalf("a mismatched request reached the provider: project %+v, module %+v", fake.lastProj, fake.lastMod)
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
	svc := NewSandboxService(&describedFake{fakeSandbox: finishedFake("fake")})
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
	a := NewSandboxService(&describedFake{fakeSandbox: finishedFake("fake")})
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
	svc := NewSandboxService(&describedFake{fakeSandbox: finishedFake("fake")})
	req := jsReq("1")
	req.Msg.MinimumIsolation = "bogus"
	if resp, err := svc.Run(context.Background(), req); err == nil || resp != nil {
		t.Fatalf("an invalid floor ran: %v, %v", resp, err)
	}
}
