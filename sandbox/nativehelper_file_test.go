package sandbox

import (
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// TestNativeRunnerKeepsTheSharedLimits: the project runner's marker, per-stream cap,
// transfer budget, flood exit and artifact budget are the ones runnerwire and every provider
// keep, and the comment above the cap says it is per stream (finding release-44, said of the
// Node runner's comment, which once said "in all, not per stream").
func TestNativeRunnerKeepsTheSharedLimits(t *testing.T) {
	b, err := os.ReadFile("internal/nativehelper/program/src/runner.rs")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		line string
		ok   bool
	}{
		{`const MARKER: &str = "` + runnerwire.Marker + `";`, true},
		{`const MAX_STEP_OUTPUT: usize = 1 << 20;`, ProjectStepOutputCap == 1<<20},
		{`const MAX_STEP_TRANSFER: usize = 32 << 20;`, ProjectStepTransferBudget == 32<<20},
		{`const EXIT_OUTPUT_FLOODED: i64 = 153;`, true},
		{`const MAX_ARTIFACT_BYTES: u64 = 8 << 20;`, true},
	} {
		if !regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(c.line)+`$`).Match(b) || !c.ok {
			t.Errorf("runner.rs does not state %s, the value the rest of plimsoll keeps", c.line)
		}
	}
	above := regexp.MustCompile(`(?s)((?:///[^\n]*\n)+)const MAX_STEP_OUTPUT: `).FindSubmatch(b)
	if above == nil || !regexp.MustCompile(`\bstreams?\b`).Match(above[1]) || regexp.MustCompile(`not per stream|in all`).Match(above[1]) {
		t.Errorf("the comment above runner.rs's MAX_STEP_OUTPUT does not say the cap is each stream's: %q", above)
	}
}

// TestNativeHelperWantIsThePin: the startup test requires the committed helper's SHA-256 and
// identity, and a handed-in build's when a test set one.
func TestNativeHelperWantIsThePin(t *testing.T) {
	pin, err := nativehelper.Pinned(runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	got, err := nativeHelperWant()
	handed := dockerNativeHelperWant.SHA256 != ""
	if err != nil || (!handed && got != pin) || (handed && got != dockerNativeHelperWant) {
		t.Fatalf("nativeHelperWant: %+v, %v; the pin is %+v, the handed-in build %+v", got, err, pin, dockerNativeHelperWant)
	}
	if len(pin.SHA256) != 64 || strings.Trim(pin.SHA256, "0123456789abcdef") != "" {
		t.Fatalf("the pin %q is not a hex SHA-256", pin.SHA256)
	}
	if id := strings.TrimPrefix(pin.Identity, "inputs "); len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" {
		t.Fatalf("the pinned identity %q is not inputs and a hex SHA-256", pin.Identity)
	}
}
