package sandbox_test

import (
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/dockertest"
	"github.com/plimsollmark/plimsoll/sandbox/projecttest"
)

// The docker provider, through the in-sandbox runner, keeps the one-shot project
// contract, in a run and in a session's calls.
func TestDockerProjectConformance(t *testing.T) {
	t.Parallel()
	// The two run side by side, each with containers of its own.
	t.Run("run", func(t *testing.T) { t.Parallel(); projecttest.Run(t, dockertest.Sandbox(t), 8*time.Second) })
	t.Run("session", func(t *testing.T) {
		t.Parallel()
		projecttest.Run(t, openDockerSession(t, sessionDocker(t)), 8*time.Second)
	})
}
