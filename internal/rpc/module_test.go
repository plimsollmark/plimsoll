package rpc

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func moduleRequest(rows ...[]float64) *plimsollv1.ModuleRun {
	req := &plimsollv1.ModuleRun{Model: "vanderpol", EndTime: 20, Step: 0.01}
	for _, r := range rows {
		req.Rows = append(req.Rows, &plimsollv1.ModuleRow{Values: r})
	}
	return req
}

func TestRunModuleMapsRowsAndRuns(t *testing.T) {
	fake := &fakeSandbox{modResult: sandbox.ModuleResult{
		Runs:      []sandbox.ModuleRun{{Status: 2, Outputs: []float64{1, 2, 3, 4}}, {Status: -3}},
		Width:     2,
		Sandbox:   "fake",
		Isolation: sandbox.IsolationVM,
		Outcome:   sandbox.ProjectOutcomeCompleted,
		Stdout:    "wasmedge-worker(table) ok=1 failed=1",
	}}
	svc := NewSandboxService(fake)
	resp, err := svc.Run(context.Background(), moduleReq(moduleRequest([]float64{0.5, 2, 0}, []float64{1.5, 2, 0})))
	if err != nil {
		t.Fatal(err)
	}
	if fake.lastMod.Model != "vanderpol" || len(fake.lastMod.Rows) != 2 || fake.lastMod.Rows[1][0] != 1.5 || fake.lastMod.EndTime != 20 || fake.lastMod.Step != 0.01 {
		t.Fatalf("provider saw %+v", fake.lastMod)
	}
	m := resp.Msg.GetModule()
	if m.GetWidth() != 2 || resp.Msg.GetSandbox() != "fake" || resp.Msg.GetIsolation() != "vm" || m.GetOutcome() != plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED {
		t.Fatalf("response header = %+v", resp.Msg)
	}
	if len(m.GetRuns()) != 2 || m.GetRuns()[0].GetStatus() != 2 || len(m.GetRuns()[0].GetOutputs()) != 4 || m.GetRuns()[1].GetStatus() != -3 || len(m.GetRuns()[1].GetOutputs()) != 0 {
		t.Fatalf("runs = %+v", m.GetRuns())
	}
	if string(m.GetStdout()) != "wasmedge-worker(table) ok=1 failed=1" {
		t.Fatalf("stdout = %q", m.GetStdout())
	}
}

func TestRunModuleRejectsInvalidBeforeDispatch(t *testing.T) {
	for name, req := range map[string]*connect.Request[plimsollv1.RunRequest]{
		"ragged":  moduleReq(moduleRequest([]float64{1, 2, 3}, []float64{1})),
		"no rows": moduleReq(moduleRequest()),
		"model path": func() *connect.Request[plimsollv1.RunRequest] {
			r := moduleRequest([]float64{1})
			r.Model = "../x"
			return moduleReq(r)
		}(),
		"zero step": func() *connect.Request[plimsollv1.RunRequest] {
			r := moduleRequest([]float64{1})
			r.Step = 0
			return moduleReq(r)
		}(),
		"bad floor": withFloor(moduleReq(moduleRequest([]float64{1})), "titanium"),
		"over budget": func() *connect.Request[plimsollv1.RunRequest] {
			r := moduleRequest()
			for range 600 {
				r.Rows = append(r.Rows, &plimsollv1.ModuleRow{Values: []float64{1}})
			}
			return moduleReq(r)
		}(),
	} {
		fake := &fakeSandbox{}
		_, err := NewSandboxService(fake).Run(context.Background(), req)
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: code %v, want InvalidArgument (%v)", name, connect.CodeOf(err), err)
		}
		if fake.lastMod.Model != "" {
			t.Errorf("%s: dispatched to the provider", name)
		}
	}
}

func TestRunModuleUnsupportedIsUnimplementedAndNotAFailure(t *testing.T) {
	svc := NewSandboxService(&fakeSandbox{}) // no module result configured: ErrUnsupported
	_, err := svc.Run(context.Background(), moduleReq(moduleRequest([]float64{1, 2, 0})))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("code %v, want Unimplemented (%v)", connect.CodeOf(err), err)
	}
	if _, failed := svc.RunCounts(); failed != 0 {
		t.Fatalf("ErrUnsupported counted as an infrastructure failure")
	}
	// The provider's ErrInvalidRequest (the worker's over-budget refusal) is InvalidArgument too.
	svc = NewSandboxService(&fakeSandbox{modErr: sandbox.ErrInvalidRequest})
	if _, err := svc.Run(context.Background(), moduleReq(moduleRequest([]float64{1, 2, 0}))); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("provider ErrInvalidRequest mapped to %v", connect.CodeOf(err))
	}
}

func TestRunModuleEnforcesMinimumIsolationBeforeDispatch(t *testing.T) {
	fake := &fakeSandbox{}
	svc := NewSandboxService(&isolationFake{fakeSandbox: fake, isolation: sandbox.IsolationContainer})
	_, err := svc.Run(context.Background(), withFloor(moduleReq(moduleRequest([]float64{1, 2, 0})), "vm"))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("code %v, want FailedPrecondition (%v)", connect.CodeOf(err), err)
	}
	if fake.lastMod.Model != "" {
		t.Fatal("dispatched despite an impossible floor")
	}
}

// TestRunModuleAuditNamesModelNeverValues: the audit line is metadata (model id,
// row count, row width, step bound, outcome), and a parameter value, however
// distinctive, never appears in it.
func TestRunModuleAuditNamesModelNeverValues(t *testing.T) {
	var buf bytes.Buffer
	fake := &fakeSandbox{modResult: sandbox.ModuleResult{Sandbox: "fake", Isolation: sandbox.IsolationVM, Outcome: sandbox.ProjectOutcomeCompleted, Width: 2,
		Runs: []sandbox.ModuleRun{{Status: 5, Outputs: make([]float64, 10)}}}}
	svc := NewSandboxService(fake)
	svc.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	req := withTrace(moduleReq(moduleRequest([]float64{3.14159265358979, 2.718281828, 0})), "sweep-42")
	if _, err := svc.Run(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	for _, want := range []string{`"msg":"module run"`, `"model":"vanderpol"`, `"rows":1`, `"row_width":3`, `"max_steps":2002`, `"outcome":"completed"`, `"runs":1`, `"width":2`, `"trace_id":"sweep-42"`, `"duration_ms":`} {
		if !strings.Contains(line, want) {
			t.Errorf("audit line missing %q: %s", want, line)
		}
	}
	for _, leak := range []string{"3.14159", "2.71828"} {
		if strings.Contains(line, leak) {
			t.Errorf("audit line carries a parameter value %q: %s", leak, line)
		}
	}
}

func TestDescribeReportsModuleSupport(t *testing.T) {
	for _, tc := range []struct {
		sb   sandbox.Sandbox
		want bool
	}{
		{&projectCapableFake{supportsModule: true}, true},
		{&projectCapableFake{}, false},
		{&fakeSandbox{}, false}, // declares nothing: never advertised
		{sandbox.Disabled{}, false},
	} {
		resp, err := NewSandboxService(tc.sb).Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Msg.GetSupportsModule() != tc.want {
			t.Errorf("%T: supports_module = %v, want %v", tc.sb, resp.Msg.GetSupportsModule(), tc.want)
		}
	}
}
