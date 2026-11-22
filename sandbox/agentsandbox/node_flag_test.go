package agentsandbox

import (
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
)

// The project runner is the native helper, started by the shell that makes the work
// directory, with no guard library and no node (finding rust-native-helper-26 was about the
// node runner's debugger; the helper has none).
func TestRunnerCommandStartsTheNativeHelper(t *testing.T) {
	t.Parallel()
	if !strings.HasSuffix(runnerCommand[2], "&& exec "+nativehelper.RunProjectShell) || strings.Contains(runnerCommand[2], "LD_PRELOAD") || strings.Contains(runnerCommand[2], "node") {
		t.Errorf("the runner starts as %q", runnerCommand[2])
	}
}
