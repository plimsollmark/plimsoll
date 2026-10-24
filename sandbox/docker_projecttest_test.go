package sandbox_test

import (
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/dockertest"
	"github.com/plimsollmark/plimsoll/sandbox/projecttest"
)

// The docker provider, through the in-sandbox runner, keeps the one-shot project
// contract, in a run and in a session's calls.
func TestDockerProjectConformance(t *testing.T) {
	t.Run("run", func(t *testing.T) { projecttest.Run(t, dockertest.Sandbox(t), 8*time.Second) })
	t.Run("session", func(t *testing.T) { projecttest.Run(t, openDockerSession(t, sessionDocker(t)), 8*time.Second) })
}

// The runner's per-step cap, transfer budget and flood exit are the ones every provider
// keeps.
func TestTheRunnersStepCapIsTheShared(t *testing.T) {
	b, err := os.ReadFile("../docker/runner.mjs")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^const MAX_STEP_OUTPUT = 1 << 20;`).Match(b) || sandbox.ProjectStepOutputCap != 1<<20 {
		t.Fatal("runner.mjs's MAX_STEP_OUTPUT is not sandbox.ProjectStepOutputCap (1 MiB)")
	}
	if !regexp.MustCompile(`(?m)^const MAX_STEP_TRANSFER = 32 << 20;`).Match(b) || sandbox.ProjectStepTransferBudget != 32<<20 ||
		!regexp.MustCompile(`(?m)^const EXIT_OUTPUT_FLOODED = 153;`).Match(b) {
		t.Fatal("runner.mjs's MAX_STEP_TRANSFER or EXIT_OUTPUT_FLOODED is not the shared budget (32 MiB) and flood exit (153)")
	}
}
