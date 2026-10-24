package agentsandbox

import (
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/projecttest"
)

// The one-shot project contract (sandbox/projecttest) on a live cluster: agent-sandbox
// runs a project's steps through the in-sandbox runner, as docker and OpenShell do. The
// hung-step budget is 30 s: a claim that waits for the warm pool to boot a replacement (a
// Kata VM takes seconds) counts against it.
func TestProjectConformanceLive(t *testing.T) {
	projecttest.Run(t, liveProvider(t), 30*time.Second)
}
