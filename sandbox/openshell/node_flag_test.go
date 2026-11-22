package openshell

import (
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The project runner is the native helper, with no guard library and no node (finding
// rust-native-helper-26 was about the node runner's debugger; the helper has none); a
// session's snippet is the guest's own node.
func TestRunnerCommandStartsTheNativeHelper(t *testing.T) {
	t.Parallel()
	if c := runnerCommand[2]; !strings.HasSuffix(c, "&& exec "+nativehelper.RunProjectShell) || strings.Contains(c, "LD_PRELOAD") || strings.Contains(c, "node") {
		t.Errorf("the runner starts as %q", c)
	}
	if strings.Contains(sessionSnippetCommand[2], sessionkit.NodeSignalFlag) {
		t.Errorf("a session's snippet starts as %q; it is the guest's node", sessionSnippetCommand[2])
	}
	if slices.ContainsFunc(runnerCommand, func(a string) bool { return strings.Contains(a, "NODE_OPTIONS") }) {
		t.Error("the runner's command sets NODE_OPTIONS")
	}
}
