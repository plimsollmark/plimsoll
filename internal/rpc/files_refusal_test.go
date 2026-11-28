package rpc

import (
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
)

// filesRun is one file call: a stat of a file in the work folder.
func filesRun() *plimsollv1.FilesRun {
	return &plimsollv1.FilesRun{Scope: plimsollv1.FilesScope_FILES_SCOPE_WORK,
		Op: &plimsollv1.FilesRun_Stat{Stat: &plimsollv1.FilesStat{Path: []byte("main.py")}}}
}

// A files payload where it cannot run: Run refuses it as a request (a file call is a session
// call), and a session whose provider carries no file calls (no sandbox.FileRunner) refuses it
// as unsupported, both before anything is dispatched, so no provider sees it and no call is
// counted in the chain. files_test.go has the sessions that carry them.
func TestFilesPayloadsAreRefusedBeforeDispatch(t *testing.T) {
	fake := &fakeSandbox{}
	run := connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, Payload: &plimsollv1.RunRequest_Files{Files: filesRun()}})
	_, err := NewSandboxService(fake).Run(authenticatedContext("alice"), run)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("Run with a files payload: %v; want InvalidArgument", err)
	}
	wantNotDispatched(t, "Run with a files payload", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST)
	if fake.lastReq.Code != "" {
		t.Fatal("the files payload reached the provider")
	}

	svc, _ := sessionService()
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	call := connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: id,
		Payload: &plimsollv1.SessionRunRequest_Files{Files: filesRun()}})
	_, err = headRun(svc, ctx, call)
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("a session's file call: %v; want Unimplemented", err)
	}
	wantNotDispatched(t, "a session's file call", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSUPPORTED)
	// Nothing ran: the next call is the session's first.
	resp, err := headRun(svc, ctx, callReq(id, "1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Msg.GetRun().GetRecord().GetSequence(); got != 1 {
		t.Fatalf("the call after a refused file call is call %d, want 1", got)
	}
}
