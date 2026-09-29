package openshell

import (
	"context"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestOutputAfterTheExitEventIsKept: the protocol does not promise that the exit event
// follows the last output frame, so output that arrives after it is kept, not dropped
// (external review of v0.10.0, documentation item 3, 2026-09-28).
func TestOutputAfterTheExitEventIsKept(t *testing.T) {
	f, p := newFake(t)
	f.run = func(e *fakeExec) error {
		e.readAll()
		if err := e.stdout([]byte("before\n")); err != nil {
			return err
		}
		if err := e.exit(0); err != nil {
			return err
		}
		return e.stdout([]byte("after\n"))
	}
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "before\nafter\n" || res.ExitCode != 0 {
		t.Fatalf("stdout %q exit %d: want both lines and exit 0", res.Stdout, res.ExitCode)
	}
}
