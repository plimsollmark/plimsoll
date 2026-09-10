package sandbox

import (
	"context"
	"strings"
	"testing"
)

// TestCappedBufferReportsTruncationOutOfBand verifies the output cap drops bytes
// silently and reports it ONLY via Truncated(): consumers get exactly the bytes
// the guest wrote (no in-band marker) plus a machine-readable flag.
func TestCappedBufferReportsTruncationOutOfBand(t *testing.T) {
	var b cappedBuffer
	b.limit = 8
	_, _ = b.Write([]byte("0123456789"))
	if b.String() != "01234567" {
		t.Fatalf("retained %q, want the exact 8-byte prefix", b.String())
	}
	if strings.Contains(b.String(), "truncated") {
		t.Fatal("in-band truncation marker leaked into output")
	}
	if !b.Truncated() {
		t.Fatal("dropped bytes not reported")
	}

	var exact cappedBuffer
	exact.limit = 4
	_, _ = exact.Write([]byte("abcd"))
	if exact.Truncated() {
		t.Fatal("write exactly at the cap flagged as truncated")
	}
}

// TestCappedStreamReportsTruncation is the e2b-side equivalent of the
// cappedBuffer test: byte-exact prefix, out-of-band flag.
func TestCappedStreamReportsTruncation(t *testing.T) {
	c := &cappedStream{max: 4}
	c.append([]byte("abc"))
	c.append([]byte("defg"))
	if c.b.String() != "abcd" || !c.dropped {
		t.Fatalf("got %q dropped=%v, want exact 4-byte prefix with dropped=true", c.b.String(), c.dropped)
	}
	within := &cappedStream{max: 4}
	within.append([]byte("abcd"))
	if within.dropped {
		t.Fatal("append exactly at the cap flagged as truncated")
	}
}

// TestWasmMarksOutputTruncation runs the in-process provider with a tiny output
// cap and verifies the result carries the truncation flag with unmarked output.
func TestWasmMarksOutputTruncation(t *testing.T) {
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
