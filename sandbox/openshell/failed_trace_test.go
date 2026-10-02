package openshell

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// brokeredThenLost makes one brokered call from the guest, then ends the exec stream
// with no exit status, as a gateway that loses the stream mid-run does.
func brokeredThenLost(fw *fakeForwarding) func(e *fakeExec) error {
	return grantScript(fw, func(e *fakeExec) error {
		e.readAll()
		if sock := fw.guestSocket(e); sock != "" {
			getLines(sock, "/items/42", 1)
		}
		return connect.NewError(connect.CodeUnavailable, errors.New("the exec stream was lost"))
	})
}

// TestAFailedRunKeepsTheCallsItBrokered: brokered calls happen whatever becomes of
// the exec stream afterwards, so a run that fails after dispatch still returns its
// call trace (external review of v0.10.0, finding 12, 2026-09-28).
func TestAFailedRunKeepsTheCallsItBrokered(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	up, calls := liveUpstream(t)
	f.run = brokeredThenLost(fw)
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", Grant: grantFor(up.URL)})
	if err == nil {
		t.Fatal("a run whose stream ended without an exit status succeeded")
	}
	if calls.Load() != 1 || res.CallTrace == nil || len(res.CallTrace.Calls) != 1 {
		t.Fatalf("upstream calls %d, returned trace %+v", calls.Load(), res.CallTrace)
	}
}

// TestAFailedSessionCallKeepsTheCallsItBrokered is the same for a session call.
func TestAFailedSessionCallKeepsTheCallsItBrokered(t *testing.T) {
	f, _, s, sc := openFake(t, sandbox.SessionOptions{})
	fw := withForwarding(t, f)
	up, calls := liveUpstream(t)
	sc.payload = brokeredThenLost(fw)
	grant := grantFor(up.URL)
	grant.AllowInSessions = true // a session call needs a grant that allows sessions
	res, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1", Grant: grant})
	if err == nil {
		t.Fatal("a session call whose stream ended without an exit status succeeded")
	}
	if calls.Load() != 1 || res.CallTrace == nil || len(res.CallTrace.Calls) != 1 {
		t.Fatalf("upstream calls %d, returned trace %+v", calls.Load(), res.CallTrace)
	}
}
