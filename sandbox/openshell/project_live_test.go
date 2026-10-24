package openshell

import (
	"context"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/projecttest"
)

// The one-shot project contract (sandbox/projecttest) on a live gateway, in a run and
// in a session's calls: OpenShell runs a project's steps through the in-sandbox runner.
func TestOpenShellProjectConformanceLive(t *testing.T) {
	p := liveProvider(t, nil)
	t.Run("run", func(t *testing.T) { projecttest.Run(t, p, 15*time.Second) })
	t.Run("session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		s, err := p.OpenSession(ctx, sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		t.Cleanup(func() { _ = s.Close(context.Background()) })
		projecttest.Run(t, s, 15*time.Second)
	})
}
