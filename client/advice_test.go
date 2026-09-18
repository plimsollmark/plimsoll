package client

import (
	"context"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"connectrpc.com/connect"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/sandbox"
)

type adviceResponseServer struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
	advice []*plimsollv1.AdviceFinding
}

func (s adviceResponseServer) Run(_ context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	resp := &plimsollv1.RunResponse{Sandbox: "fixture", Isolation: "process"}
	switch req.Msg.GetPayload().(type) {
	case *plimsollv1.RunRequest_Javascript:
		resp.Result = &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{
			Stdout: []byte{0xff, 'o', 'k'}, Stderr: []byte("guest failed"), ExitCode: 7, Advice: s.advice,
		}}
	case *plimsollv1.RunRequest_Project:
		resp.Result = &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{
			Advice:  s.advice,
			Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED,
			Steps:   []*plimsollv1.StepResult{{Command: "node main.js", Stdout: []byte{0xff, 'o', 'k'}, Stderr: []byte("guest failed"), ExitCode: 7}},
		}}
	}
	return connect.NewResponse(resp), nil
}

// The wire already contained these fields before the official client exposed
// them. Prove their survival across real Connect decoding for both operations,
// including a 64-bit byte count, absent advice, and a normal failed guest run.
func TestRemotePreservesAdviceAndExecutionResults(t *testing.T) {
	wire := &plimsollv1.AdviceFinding{
		Pattern: "fan_out", Severity: "medium", Remedy: "batch", Method: "GET",
		Route: "/items/*", Detail: "Use the granted collection route.",
		SuggestedMethod: "GET", SuggestedRoute: "/items", ExtraCalls: 17,
		AddedLatencyMs: 123, BytesMoved: 1 << 33,
	}
	want := sandbox.AdviceFinding{
		Pattern: "fan_out", Severity: "medium", Remedy: "batch", Method: "GET",
		Route: "/items/*", Detail: "Use the granted collection route.",
		SuggestedMethod: "GET", SuggestedRoute: "/items", ExtraCalls: 17,
		AddedLatency: 123 * time.Millisecond, BytesMoved: 1 << 33,
	}
	for _, present := range []bool{false, true} {
		name := "absent"
		var findings []*plimsollv1.AdviceFinding
		var expected []sandbox.AdviceFinding
		if present {
			name = "present"
			findings = []*plimsollv1.AdviceFinding{wire}
			expected = []sandbox.AdviceFinding{want}
		}
		t.Run(name, func(t *testing.T) {
			_, handler := plimsollv1connect.NewSandboxServiceHandler(adviceResponseServer{advice: findings})
			server := httptest.NewServer(handler)
			defer server.Close()
			remote := newRemote(t, server.URL)
			ctx := context.Background()
			result, err := remote.RunJavaScript(ctx, sandbox.Request{Code: "throw Error('failed')"})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result.Advice, expected) || result.Stdout != string([]byte{0xff, 'o', 'k'}) || result.Stderr != "guest failed" || result.ExitCode != 7 || result.Isolation != sandbox.IsolationProcess {
				t.Fatalf("snippet result lost evidence or execution data: %+v", result)
			}
			project, err := remote.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"node main.js"}})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(project.Advice, expected) || project.Outcome != sandbox.ProjectOutcomeCompleted || project.Isolation != sandbox.IsolationProcess || len(project.Steps) != 1 {
				t.Fatalf("project result lost evidence or execution data: %+v", project)
			}
			step := project.Steps[0]
			if step.Stdout != result.Stdout || step.Stderr != result.Stderr || step.ExitCode != result.ExitCode {
				t.Fatalf("project execution changed: %+v", step)
			}
		})
	}
}
