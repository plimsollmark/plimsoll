package sandbox

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// suspendedRemovalBound is how long a suspended session's end may take, from the end to its
// Done, here: half of one removal try (removeAttemptBudget, 10 s). The removal of a paused
// container measured 138 ms under runc and, unpaused first, 170 ms under gVisor
// (unpauseForRemoval), so half a try leaves room for a loaded host; without the unpause, a
// paused gVisor container's rm -f takes 10.2 s and the first try is killed, so a suspended
// gVisor session's end took about 11 s and fails this bound (hunt-quality-106).
const suspendedRemovalBound = removeAttemptBudget / 2

// suspendedSession opens a session of the docker provider the suite selects with lifetime,
// starts a JavaScript interpreter in it (so a relay's docker exec is attached, as in a
// session in use), suspends it and checks docker reports the container paused. It is closed
// and waited for when the test ends.
func suspendedSession(t *testing.T, lifetime time.Duration) (*dockerSession, context.Context) {
	t.Helper()
	d := testDocker()
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	if err := d.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	opened, err := d.OpenSession(ctx, SessionOptions{Lifetime: lifetime, DiskBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	s := opened.(*dockerSession)
	t.Cleanup(func() {
		_ = s.Close(context.Background())
		select {
		case <-s.Done():
		case <-time.After(DockerRemoveBudget + 5*time.Second):
			t.Errorf("session %s was not removed within the removal budget", s.name)
		}
	})
	if res, err := s.RunCell(ctx, CellRequest{Language: LanguageJavaScript, Code: "globalThis.kept = 1", Timeout: 30 * time.Second}); err != nil || res.ExitCode != 0 || !res.InterpreterStarted {
		t.Fatalf("the cell before the suspend: %+v, %v", res, err)
	}
	if holds, err := s.Suspend(ctx); err != nil || !holds {
		t.Fatalf("Suspend: holds memory %v, %v", holds, err)
	}
	if out, err := exec.Command("docker", "inspect", "--type", "container", "--format", "{{.State.Paused}}", s.name).Output(); err != nil || strings.TrimSpace(string(out)) != "true" {
		t.Fatalf("after Suspend docker reports the container paused %q (%v); want true", strings.TrimSpace(string(out)), err)
	}
	return s, ctx
}

// requireRemoved fails unless s's Done closed within suspendedRemovalBound of end, the
// container is gone, and no process on this host still names it (a relay's docker exec CLI,
// which waits for ever on a paused container: hunt-quality-99).
func requireRemoved(t *testing.T, s *dockerSession, end time.Time) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(time.Until(end.Add(DockerRemoveBudget + 5*time.Second))):
		t.Fatalf("Done of the suspended session %s did not close within the removal budget", s.name)
	}
	took := time.Since(end)
	t.Logf("runtime %s: the suspended session's end to Done: %v (bound %v)", cmp.Or(s.d.Runtime, "docker's default"), took.Round(time.Millisecond), suspendedRemovalBound)
	if took > suspendedRemovalBound {
		t.Errorf("the suspended session's container took %v from the end to Done; want under %v: one removal try, not a killed try and a second", took.Round(time.Millisecond), suspendedRemovalBound)
	}
	if out, err := exec.Command("docker", "ps", "-a", "-q", "--no-trunc", "--filter", "name=^"+s.name+"$").Output(); err != nil || len(bytes.TrimSpace(out)) != 0 {
		t.Errorf("after Done the container is still listed: %q (%v)", strings.TrimSpace(string(out)), err)
	}
	cmdlines, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range cmdlines {
		if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte(s.name)) {
			t.Errorf("after Done a process still names the container: %s %q", filepath.Dir(p), bytes.ReplaceAll(b, []byte{0}, []byte{' '}))
		}
	}
}

// A suspended session closed by its caller (hunt-quality-103): its paused container, with a
// relay attached, is gone within one removal try, under runc and under gVisor
// (SANDBOX_DOCKER_RUNTIME=runsc), and no relay's docker exec is left.
func TestDockerSessionClosedWhileSuspendedIsRemoved(t *testing.T) {
	t.Parallel()
	s, ctx := suspendedSession(t, 3*time.Minute)
	end := time.Now()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	requireRemoved(t, s, end)
}

// A suspended session whose lifetime ends while it is paused (hunt-quality-103): the same,
// timed from the end of its lifetime.
func TestDockerSessionLifetimeEndingWhileSuspendedRemovesIt(t *testing.T) {
	t.Parallel()
	s, _ := suspendedSession(t, 20*time.Second)
	requireRemoved(t, s, s.ExpiresAt())
	var ended *SessionEndedError
	if err := s.Err(); !errors.As(err, &ended) || ended.Reason != SessionExpired {
		t.Errorf("the session ended with %v; want its lifetime's end", err)
	}
}
