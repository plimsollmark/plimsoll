package sandbox_test

import (
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/projecttest"
)

// The one-shot project contract against the real exec-based providers (make e2b-suite,
// make dockercloud-suite). Each case is one microVM for a few seconds, the hung step's
// for its 20 s budget: under a cent for the eight on either service.
func TestE2BProjectConformanceLive(t *testing.T) {
	projecttest.Run(t, sandbox.E2BLive(t), 20*time.Second)
}

func TestDockerCloudProjectConformanceLive(t *testing.T) {
	projecttest.Run(t, sandbox.DockerCloudLive(t), 20*time.Second)
}
