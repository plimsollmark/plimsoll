package rpc

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The helpers below build a Run request the way the official client does: a
// payload of one kind inside an envelope stamped with the protocol number. The
// with* helpers set the envelope fields every kind shares.

func envelopeReq(payload any) *connect.Request[plimsollv1.RunRequest] {
	msg := &plimsollv1.RunRequest{Protocol: protocol.Number}
	switch p := payload.(type) {
	case *plimsollv1.JavaScriptRun:
		msg.Payload = &plimsollv1.RunRequest_Javascript{Javascript: p}
	case *plimsollv1.ProjectRun:
		msg.Payload = &plimsollv1.RunRequest_Project{Project: p}
	case *plimsollv1.ModuleRun:
		msg.Payload = &plimsollv1.RunRequest_Module{Module: p}
	case nil:
	default:
		panic("envelopeReq: not a payload kind")
	}
	return connect.NewRequest(msg)
}

func jsReq(code string) *connect.Request[plimsollv1.RunRequest] {
	return envelopeReq(&plimsollv1.JavaScriptRun{Code: code})
}

func jsGrantReq(code, profile string) *connect.Request[plimsollv1.RunRequest] {
	return envelopeReq(&plimsollv1.JavaScriptRun{Code: code, GrantProfile: profile})
}

func projectReq(p *plimsollv1.ProjectRun) *connect.Request[plimsollv1.RunRequest] {
	return envelopeReq(p)
}

func moduleReq(m *plimsollv1.ModuleRun) *connect.Request[plimsollv1.RunRequest] {
	return envelopeReq(m)
}

func withFloor(r *connect.Request[plimsollv1.RunRequest], floor string) *connect.Request[plimsollv1.RunRequest] {
	r.Msg.MinimumIsolation = floor
	return r
}

func withTrace(r *connect.Request[plimsollv1.RunRequest], id string) *connect.Request[plimsollv1.RunRequest] {
	r.Msg.TraceId = id
	return r
}

func withTimeout(r *connect.Request[plimsollv1.RunRequest], ms int32) *connect.Request[plimsollv1.RunRequest] {
	r.Msg.TimeoutMs = ms
	return r
}

func withProtocol(r *connect.Request[plimsollv1.RunRequest], n uint32) *connect.Request[plimsollv1.RunRequest] {
	r.Msg.Protocol = n
	return r
}

// The protocol number is checked before anything else: a request that omits it
// is a client bug, a request on another number comes from a client this daemon
// must not serve, and in neither case may the payload reach the provider or
// count as a run.
func TestRunRefusesWrongProtocolBeforeReadingPayload(t *testing.T) {
	for name, tc := range map[string]struct {
		protocol uint32
		code     connect.Code
	}{
		"omitted": {0, connect.CodeInvalidArgument},
		"newer":   {protocol.Number + 1, connect.CodeUnimplemented},
		"older":   {protocol.Number + 100, connect.CodeUnimplemented},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeSandbox{jsResult: sandbox.Result{Sandbox: "fake"}}
			svc := NewSandboxService(fake)
			_, err := svc.Run(context.Background(), withProtocol(jsReq("1"), tc.protocol))
			if connect.CodeOf(err) != tc.code {
				t.Fatalf("code = %v, want %v (%v)", connect.CodeOf(err), tc.code, err)
			}
			if fake.lastReq.Code != "" {
				t.Fatal("payload reached the provider despite the protocol refusal")
			}
			if total, _ := svc.RunCounts(); total != 0 {
				t.Fatalf("runs total = %d, want 0", total)
			}
		})
	}
}

// An envelope with no payload is a malformed request, not an empty snippet.
func TestRunRefusesEmptyPayload(t *testing.T) {
	fake := &fakeSandbox{}
	_, err := NewSandboxService(fake).Run(context.Background(), envelopeReq(nil))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (%v)", connect.CodeOf(err), err)
	}
	if fake.lastReq.Code != "" || fake.lastProj.Steps != nil || fake.lastMod.Model != "" {
		t.Fatal("an empty payload reached the provider")
	}
}

// Describe states the number Run will check, so a caller can compare before it
// sends anything.
func TestDescribeReportsProtocol(t *testing.T) {
	resp, err := NewSandboxService(&fakeSandbox{}).Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetProtocol() != protocol.Number {
		t.Fatalf("describe protocol = %d, want %d", resp.Msg.GetProtocol(), protocol.Number)
	}
}
