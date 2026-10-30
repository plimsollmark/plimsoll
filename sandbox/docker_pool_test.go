package sandbox

import (
	"context"
	"errors"
	"maps"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/poolkit"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The pool's own behavior (the split, claims, rebalancing, places held through
// removals) is tested in sandbox/internal/poolkit; these are docker's side of it.

// unstartedPool is a docker pool installed in d whose filler never started, so Close
// waits for it until its context ends: a filler still making a member.
func unstartedPool(t *testing.T, d *DockerSandbox, stated ...string) *dockerPool {
	t.Helper()
	h := d.poolHooks()
	h.Discard = func(_ *dockerSession, gone func()) { gone() }
	p, err := poolkit.New(h, 1, time.Minute, stated)
	if err != nil {
		t.Fatal(err)
	}
	d.pool.Store(p)
	return p
}

// A hint naming a language plimsoll does not know is refused; one the environment
// does not run is dropped, since a hint changes latency, never behavior; what is left
// comes back in the environment's order without repeats.
func TestSessionLanguagesChecksTheHint(t *testing.T) {
	stated := []Language{LanguageJavaScript, LanguagePython}
	got, err := SessionLanguages([]Language{LanguagePython, LanguageJavaScript, LanguagePython}, stated)
	if err != nil || !slices.Equal(got, stated) {
		t.Fatalf("SessionLanguages = %v, %v; want %v", got, err, stated)
	}
	if got, err := SessionLanguages(nil, stated); err != nil || len(got) != 0 {
		t.Fatalf("no hint: %v, %v; want none", got, err)
	}
	_, err = SessionLanguages([]Language{"cobol"}, stated)
	if r, ok := NotDispatchedReason(err); !errors.Is(err, ErrInvalidRequest) || !ok || r != RefusalRequest {
		t.Fatalf("an unknown language: %v; want a request refusal", err)
	}
	if got, err := SessionLanguages([]Language{LanguagePython, LanguageJavaScript}, []Language{LanguageJavaScript}); err != nil || !slices.Equal(got, []Language{LanguageJavaScript}) {
		t.Fatalf("a language the environment does not run: %v, %v; want it dropped", got, err)
	}
	if got, err := SessionLanguages([]Language{LanguagePython, LanguagePython}, nil); err != nil || !slices.Equal(got, []Language{LanguagePython}) {
		t.Fatalf("no stated languages: %v, %v; want the hint without repeats", got, err)
	}
}

// Drain is bounded by its context while the pool's filler is busy making a member,
// and a filler that never started cannot hold it up: before the fix Drain waited for
// the filler with no bound, and a pool whose first member failed never closed done,
// so a Drain racing StartSessionPool never returned.
func TestDrainIsBoundedWhileThePoolFillerRuns(t *testing.T) {
	d := DefaultDocker("")
	unstartedPool(t, d, "javascript")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- d.Drain(ctx) }()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Drain reported success while the pool's filler had not stopped")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Drain did not return within 10 s of its 1 s context")
	}
}

// A Drain whose pool's filler did not stop in time returns the pool's error and leaves
// no goroutine waiting for removals: the filler can still add one (it removes the
// member it was making once it sees the pool stopped), and a WaitGroup must not be
// added to from zero while it is waited on. Before the fix Drain went on to wait.
func TestDrainLeavesNoWaitBehindAPoolStillFilling(t *testing.T) {
	d := DefaultDocker("")
	unstartedPool(t, d, "javascript")
	removed := d.sessions.Removal() // a removal still in flight
	defer removed()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := d.Drain(ctx); err == nil || !strings.Contains(err.Error(), "still making a member") {
		t.Fatalf("Drain = %v; want the pool's error", err)
	}
	buf := make([]byte, 1<<20)
	if stacks := string(buf[:runtime.Stack(buf, true)]); strings.Contains(stacks, "(*DockerSandbox).Drain.func") || strings.Contains(stacks, "(*Registry).WaitRemovals") {
		t.Fatalf("Drain left a goroutine behind:\n%s", stacks)
	}
}

// A pool started after Drain is refused: nothing would stop its filler, which would
// keep making containers for a daemon that is shutting down.
func TestPoolStartedAfterDrainIsRefused(t *testing.T) {
	d := DefaultDocker("")
	d.projectLanguages = []Language{LanguageJavaScript}
	if err := d.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := d.StartSessionPool(context.Background(), 1, time.Minute)
	if !errors.Is(err, errDraining) || d.pool.Load() != nil {
		t.Fatalf("StartSessionPool after Drain = %v (pool installed %v); want refused as shutting down", err, d.pool.Load() != nil)
	}
}

// A Drain whose context ends while an open is still in flight still ends the sessions
// already open: the open in flight is refused once it finishes (activate checks
// draining), and the open ones would otherwise be left to the reaper. Before the fix
// Drain returned at once and left them open.
func TestDrainEndsOpenSessionsWhileAnOpenIsInFlight(t *testing.T) {
	d := DefaultDocker("")
	b, err := startDockerSessionBroker()
	if err != nil {
		t.Fatal(err)
	}
	s := &dockerSession{d: d, broker: b}
	s.life = sessionkit.NewLife("plsm-session-test", s.hooks())
	if err := d.activate(s, time.Now().Add(time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	leave, ok := d.sessions.Enter() // an open still in flight
	if !ok {
		t.Fatal("an open was refused before Drain")
	}
	defer leave()
	dctx, dcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer dcancel()
	if err := d.Drain(dctx); err == nil || !strings.Contains(err.Error(), "still opening") {
		t.Fatalf("Drain = %v; want it to report the open in flight", err)
	}
	if got := SessionEndReason(s.Err()); got != SessionShutdown {
		t.Fatalf("the open session ended with %v after Drain; want shutdown", got)
	}
}

// An open the provider refuses leaves the pool's demand as it was: a caller asking
// again and again for a floor the provider cannot meet (or for anything while it is at
// capacity) would otherwise move the pool toward its languages, away from the callers
// it serves. Before the fix the hint was recorded before the floor was checked.
func TestRefusedOpenLeavesPoolDemandUnchanged(t *testing.T) {
	d := DefaultDocker("")
	d.ready, d.daemonHost, d.verifiedRuntime, d.verifiedGuestUID = true, "unix:///var/run/docker.sock", d.Runtime, d.guestUID()
	d.verifiedImageIDs = map[string]string{d.Image: "sha256:snippet", d.ProjectImage: "sha256:project"}
	d.projectLanguages = []Language{LanguageJavaScript, LanguagePython}
	p := unstartedPool(t, d, "javascript", "python")
	for range 20 {
		_, err := d.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute, MinimumIsolation: IsolationVM, Languages: []Language{LanguagePython}})
		if _, refused := NotDispatchedReason(err); !refused {
			t.Fatalf("an open with a VM floor on a container-tier provider: %v; want refused", err)
		}
	}
	if got := p.Demand(); !maps.Equal(got, map[string]float64{"javascript,python": 1}) {
		t.Fatalf("20 refused opens moved the pool's demand to %v", got)
	}
}

// testLife is a pool member's lifecycle in a test that never runs a call.
func testLife() *sessionkit.Life { return sessionkit.NewLife("plsm-session-test", sessionkit.Hooks{}) }
