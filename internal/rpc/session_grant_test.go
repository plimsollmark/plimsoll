package rpc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// A session call that selects a grant profile is refused before anything runs,
// PermissionDenied with reason permission, unless the profile sets allow_in_sessions:
// in a session, code an earlier call left running could use the grant while the call
// runs. A profile that sets it reaches the session's call.
func TestSessionGrantProfileNeedsAllowInSessions(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok-xyz")
	path := filepath.Join(t.TempDir(), "grants.json")
	const profile = `"base_url":"https://hue.internal","allow":["GET /v1/lights"],"allowed_callers":["alice"],"token":{"type":"static","env":"HUE_TOKEN"}`
	if err := os.WriteFile(path, []byte(`{"profiles":{"plain":{`+profile+`},"shared":{`+profile+`,"allow_in_sessions":true}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := grants.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := sessionService()
	svc.Grants = reg
	ctx := authenticatedContext("alice")
	opened, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	call := func(grantProfile string) (*connect.Response[plimsollv1.SessionRunResponse], error) {
		return svc.SessionRun(ctx, connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: opened.Msg.GetSessionId(),
			Payload: &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1", GrantProfile: grantProfile}}}))
	}

	_, err = call("plain")
	reason, marked := sandbox.NotDispatchedReason(err)
	if connect.CodeOf(err) != connect.CodePermissionDenied || !errors.Is(err, sandbox.ErrGrantNotForSessions) || !marked || reason != sandbox.RefusalPermission {
		t.Fatalf("a session call with a profile that does not allow sessions: %v (reason %v, marked %v); want PermissionDenied, refused, permission", err, reason, marked)
	}
	// The fake answers its nth dispatched call with n x's, so one x means the refused
	// call was never dispatched.
	got, err := call("shared")
	if err != nil {
		t.Fatalf("a session call with a profile that allows sessions: %v", err)
	}
	if out := string(got.Msg.GetRun().GetJavascript().GetStdout()); out != "x" {
		t.Fatalf("stdout %q, want the first dispatched call's \"x\"", out)
	}
}

// A granted session call that the profile does not allow in sessions is refused
// before admission: it spends no rate token. Opening takes one of two tokens, the
// refused call none, so the allowed call after it still gets the second.
func TestRefusedSessionGrantSpendsNoRateToken(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok-xyz")
	path := filepath.Join(t.TempDir(), "grants.json")
	const profile = `"base_url":"https://hue.internal","allow":["GET /v1/lights"],"allowed_callers":["alice"],"token":{"type":"static","env":"HUE_TOKEN"}`
	if err := os.WriteFile(path, []byte(`{"profiles":{"plain":{`+profile+`},"shared":{`+profile+`,"allow_in_sessions":true}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := grants.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := sessionService()
	svc.Grants = reg
	svc.Limiter = NewCodeLimiter(10, 10, 1, 2)
	ctx := authenticatedContext("alice")
	opened, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	call := func(grantProfile string) error {
		_, err := svc.SessionRun(ctx, connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: opened.Msg.GetSessionId(),
			Payload: &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1", GrantProfile: grantProfile}}}))
		return err
	}
	if err := call("plain"); !errors.Is(err, sandbox.ErrGrantNotForSessions) {
		t.Fatalf("the plain profile in a session: %v", err)
	}
	if err := call("shared"); err != nil {
		t.Fatalf("the allowed call after a refused one: %v (the refusal spent the token)", err)
	}
}
