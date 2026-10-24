package daemonproc

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A daemon that exits before it is ready is reported at once, with the exit, not after
// the whole wait: copied starters in four examples never noticed, so a daemon that died
// at startup cost minutes (review B9, 2026-10-23).
func TestADaemonThatExitsAtStartupIsReportedAtOnce(t *testing.T) {
	sh, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no false(1) on this machine")
	}
	start := time.Now()
	_, err = Start(context.Background(), sh, Options{Ready: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "exited before it was ready") {
		t.Fatalf("Start: %v; want the daemon's early exit", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("reported after %v of a 1 minute wait", took)
	}
}
