package sandbox

import (
	"context"
	"strings"
	"testing"
)

// TestWasmMarksOutputTruncation runs the in-process provider with a tiny output
// cap and verifies the result carries the truncation flag with unmarked output.
func TestWasmMarksOutputTruncation(t *testing.T) {
	t.Parallel()
	w := testWasm()
	w.MaxOutputBytes = 16
	res, err := w.RunJavaScript(context.Background(), Request{Code: `console.log("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")`})
	if err != nil {
		t.Fatal(err)
	}
	if !res.StdoutTruncated {
		t.Fatalf("stdout not flagged truncated: %+v", res)
	}
	if len(res.Stdout) > 16 || strings.Contains(res.Stdout, "truncated") {
		t.Fatalf("stdout = %q, want a bare 16-byte cap with no in-band marker", res.Stdout)
	}
	if res.StderrTruncated {
		t.Fatal("stderr flagged truncated without overflow")
	}
}

// TestProjectOutcomeStrings pins the stable log/wire names.
func TestProjectOutcomeStrings(t *testing.T) {
	want := map[ProjectOutcome]string{
		ProjectOutcomeUnspecified:   "unspecified",
		ProjectOutcomeCompleted:     "completed",
		ProjectOutcomeSetupFailed:   "setup_failed",
		ProjectOutcomeTimedOut:      "timed_out",
		ProjectOutcomeProtocolError: "protocol_error",
		ProjectOutcome(99):          "unspecified",
	}
	for o, s := range want {
		if o.String() != s {
			t.Errorf("outcome %d String() = %q, want %q", int(o), o.String(), s)
		}
	}
}
