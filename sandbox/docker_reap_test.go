package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// reapStubDocker puts a stand-in docker CLI first on PATH. Its label listing answers
// listing (one "name<TAB>expires" per line); its rm -f of hang never returns (the process
// itself sleeps, so killing it closes its output); every other rm -f succeeds and is
// written to the returned log, one name a line; an exact-name listing answers "gone".
func reapStubDocker(t *testing.T, listing, hang string) (log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "removed")
	script := "#!/bin/sh\n[ \"$1\" = --config ] && shift 2\n[ \"$1\" = --host ] && shift 2\n" +
		"if [ \"$1\" = ps ]; then case \"$*\" in *label=*) printf '%s' '" + listing + "';; esac; exit 0; fi\n" +
		"if [ \"$1\" = rm ]; then if [ \"$3\" = '" + hang + "' ]; then exec sleep 60; fi; echo \"$3\" >> '" + log + "'; exit 0; fi\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func removedNames(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// A failed Preflight leaves the pinned daemon as it was, and the orphan pass goes on
// against it: an expired container is removed and a quarantined removal is retried
// (hunt-quality-100). Before, the pass read the whole verified state, which any failed
// Preflight makes unready, and returned 0, nil without running docker at all.
func TestDockerReconcileRunsWhileTheLastPreflightFailed(t *testing.T) {
	old := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	log := reapStubDocker(t, "plsm-session-expired\t"+old+"\n", "")
	d := &DockerSandbox{}
	d.stateMu.Lock()
	d.daemonHost = "unix:///nonexistent/plimsoll-test/docker.sock" // pinned by an earlier Preflight
	d.ready = false                                                // the last Preflight failed
	d.stateMu.Unlock()
	released := false
	d.quarantine.Hold("plsm-session-quarantined", func() { released = true })
	d.quarantine.Done("plsm-session-quarantined", false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	n, err := d.ReconcileOrphans(ctx)
	if err != nil || n != 2 {
		t.Fatalf("ReconcileOrphans on a provider whose last Preflight failed: n=%d err=%v; want both containers removed", n, err)
	}
	if !released || d.quarantine.Held("plsm-session-quarantined") {
		t.Fatalf("the quarantined removal was not retried: released %v, held %v", released, d.quarantine.Held("plsm-session-quarantined"))
	}
	got := removedNames(t, log)
	slices.Sort(got)
	if strings.Join(got, " ") != "plsm-session-expired plsm-session-quarantined" {
		t.Fatalf("docker rm -f ran for %q", got)
	}
}

// Before any Preflight pinned a daemon there is none the pass may run docker against:
// it removes nothing, starts no docker, and says so once per change, not once a pass.
func TestDockerReconcileWithoutAPinnedDaemonRunsNoDockerAndSaysSoOnce(t *testing.T) {
	log := reapStubDocker(t, "", "")
	d := &DockerSandbox{}
	d.quarantine.Hold("plsm-session-quarantined", nil)
	d.quarantine.Done("plsm-session-quarantined", false)
	for i := range 2 {
		if n, err := d.ReconcileOrphans(context.Background()); n != 0 || err != nil {
			t.Fatalf("pass %d without a pinned daemon: n=%d err=%v", i, n, err)
		}
	}
	if got := removedNames(t, log); len(got) != 0 {
		t.Fatalf("docker ran without a pinned daemon: %v", got)
	}
	if !d.reapSkipped.Load() {
		t.Fatal("the skipped pass was not recorded")
	}
	// Once per change: the passes above logged the skip once, and its next pass, the same
	// state, logs nothing; a pinned daemon logs the change back once.
	if d.noteReapSkipped(true) {
		t.Fatal("a skipped pass after a skipped pass logged again")
	}
	if !d.noteReapSkipped(false) || d.noteReapSkipped(false) {
		t.Fatal("the pass running again was not logged exactly once")
	}
}

// One expired container whose removal hangs costs its share of the pass, never the
// other names' tries (hunt-quality-101): with the hanging one listed first, as docker ps
// lists the newest first, every other expired name and the quarantined one are still
// removed in the same pass, and the pass keeps to its deadline. Before, the expired
// names' removals ran under the pass's whole context, so the hanging one took all of it
// and every later name, the quarantine's retries included, got an ended context.
func TestDockerReconcileGivesEveryNameAShareOfThePass(t *testing.T) {
	old := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	listing := "plsm-run-hangs\t" + old + "\nplsm-session-older\t" + old + "\nplsm-run-oldest\t" + old + "\n"
	log := reapStubDocker(t, listing, "plsm-run-hangs")
	d := &DockerSandbox{}
	d.stateMu.Lock()
	d.daemonHost = "unix:///nonexistent/plimsoll-test/docker.sock"
	d.stateMu.Unlock()
	released := false
	d.quarantine.Hold("plsm-session-quarantined", func() { released = true })
	d.quarantine.Done("plsm-session-quarantined", false)
	const pass = 4 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), pass)
	defer cancel()
	start := time.Now()
	n, err := d.ReconcileOrphans(ctx)
	took := time.Since(start)
	got := removedNames(t, log)
	t.Logf("pass: n=%d err=%v in %v; removed %v", n, err, took.Round(time.Millisecond), got)
	if n != 3 || !released {
		t.Fatalf("one hanging removal starved the pass: %d confirmed gone (want 3), the quarantined capacity released %v", n, released)
	}
	if strings.Join(got, " ") != "plsm-session-quarantined plsm-session-older plsm-run-oldest" {
		t.Fatalf("docker rm -f ran for %v; want the quarantined name first, then every expired name but the hanging one", got)
	}
	if took > pass+time.Second {
		t.Fatalf("the pass took %v against its %v deadline", took, pass)
	}
}
