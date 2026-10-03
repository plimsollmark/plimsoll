package sandbox

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// A member is handed over only under the execution state it was made under, only for
// a lifetime its label covers, only while it is younger than the idle bound, and only
// while every interpreter it was given still has its relay. Whatever is passed over
// is removed, and the oldest usable member goes first.
func TestPoolClaimsOnlyAMemberItMayHandOver(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	state := dockerExecutionState{host: "unix:///d.sock", runtime: "runsc", isolation: IsolationKernel,
		projectImageID: "sha256:aa", projectManifest: "sha256:bb"}
	member := func(name string, st dockerExecutionState, age time.Duration) *dockerSession {
		return &dockerSession{name: name, key: dockerPoolKey(st), born: now.Add(-age),
			label: now.Add(-age).Add(dockerPoolMaxIdle + time.Hour)}
	}
	other := state
	other.runtime, other.isolation = "runc", IsolationContainer
	rebuilt := state
	rebuilt.projectImageID = "sha256:cc"
	unattached := member("unattached", state, time.Minute)
	unattached.warm = []string{"python"} // never warmed: no relay attached
	var removed []string
	p := &dockerPool{now: func() time.Time { return now }, wake: make(chan struct{}, 1),
		discard: func(s *dockerSession) { removed = append(removed, s.name) }}
	p.ready = []*dockerSession{
		member("other-runtime", other, time.Minute),
		member("other-image", rebuilt, time.Minute),
		member("too-old", state, dockerPoolMaxIdle+time.Second),
		unattached,
		member("oldest-usable", state, 10*time.Minute),
		member("newer", state, time.Minute),
	}
	got := p.claim(state, now.Add(time.Hour), nil)
	if got == nil || got.name != "oldest-usable" {
		t.Fatalf("claimed %v; want oldest-usable", got)
	}
	want := []string{"other-runtime", "other-image", "too-old", "unattached"}
	if len(p.ready) != 1 || p.ready[0].name != "newer" || !slices.Equal(removed, want) {
		t.Fatalf("left %d members, removed %v; want newer left and %v removed", len(p.ready), removed, want)
	}
	removed = nil
	if got := p.claim(state, now.Add(2*time.Hour), nil); got != nil {
		t.Fatalf("claimed %s for a lifetime its label does not cover", got.name)
	}
	if len(p.ready) != 0 || !slices.Equal(removed, []string{"newer"}) {
		t.Fatalf("left %d members, removed %v; want newer removed", len(p.ready), removed)
	}
	if (*dockerPool)(nil).claim(state, now, nil) != nil {
		t.Fatal("a provider without a pool claimed a member")
	}
}

// The pool's size is divided across language sets in proportion to their weight,
// exactly, summing to the size.
func TestPoolSharesDivideTheSizeByWeight(t *testing.T) {
	for _, c := range []struct {
		demand map[string]float64
		size   int
		want   map[string]float64
	}{
		{map[string]float64{"javascript,python": 1}, 3, map[string]float64{"javascript,python": 3}},
		{map[string]float64{"python": 0.5, "javascript": 0.5}, 3, map[string]float64{"javascript": 1.5, "python": 1.5}},
		{map[string]float64{"a": 0.7, "b": 0.2, "c": 0.1}, 4, map[string]float64{"a": 2.8, "b": 0.8, "c": 0.4}},
		{map[string]float64{}, 2, map[string]float64{}},
	} {
		got := poolShares(c.demand, c.size)
		if !maps.EqualFunc(got, c.want, func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }) {
			t.Errorf("poolShares(%v, %d) = %v; want %v", c.demand, c.size, got, c.want)
		}
	}
}

// Opens move the split: a pool that starts with every member warming every language
// gives most of its members to Python once Python is what sessions ask for, and
// forgets a set nobody asks for any more, so the table stays bounded.
func TestPoolDemandFollowsObservedHints(t *testing.T) {
	all, py := "javascript,python", "python"
	p := &dockerPool{size: 4, demand: map[string]float64{all: 1}}
	for range 20 {
		p.observe([]Language{LanguagePython})
	}
	if got := poolShares(p.demand, p.size); math.Round(got[py]) != 3 || math.Round(got[all]) != 1 {
		t.Fatalf("after 20 Python opens the shares are %v; want about 3 Python and 1 of every language", got)
	}
	for range 50 {
		p.observe([]Language{LanguagePython})
	}
	if _, ok := p.demand[all]; ok || len(p.demand) != 1 {
		t.Fatalf("after 70 Python opens the table is %v; want only Python", p.demand)
	}
	p.observe([]Language{LanguageJavaScript, LanguagePython})
	if got := poolShares(p.demand, p.size); math.Round(got[py]) != 4 {
		t.Fatalf("one open of every language moved the shares to %v; want all 4 still Python", got)
	}
}

// poolSim drives a pool's split the way the daemon does, with no docker: each open
// observes its hint and claims the closest member (OpenSession), then the filler
// refills (run): a full pool may rebalance, a short one adds a member of next. The
// clock moves on by step per open.
type poolSim struct {
	p       *dockerPool
	stated  []Language
	clock   time.Time
	step    time.Duration
	removed int // members rebalance removed
}

func newPoolSim(size int, stated []Language, step time.Duration) *poolSim {
	s := &poolSim{stated: stated, clock: time.Unix(1e9, 0), step: step}
	s.p = &dockerPool{size: size, demand: map[string]float64{languageSetKey(stated): 1},
		now: func() time.Time { return s.clock }, discard: func(*dockerSession) { s.removed++ }}
	s.fill()
	return s
}

func (s *poolSim) fill() {
	for {
		if !s.p.short() {
			if !s.p.rebalance() {
				return
			}
			continue
		}
		s.p.ready = append(s.p.ready, &dockerSession{warm: languageNames(s.p.next(s.stated))})
	}
}

// open is one session asking for want; it reports whether the member it was handed
// warms every language asked for.
func (s *poolSim) open(want []Language) bool {
	s.clock = s.clock.Add(s.step)
	s.p.observe(want)
	got := s.p.ready[closestMember(s.p.ready, want)]
	s.p.ready = slices.DeleteFunc(s.p.ready, func(m *dockerSession) bool { return m == got })
	s.fill()
	for _, l := range want {
		if !slices.Contains(got.warm, string(l)) {
			return false
		}
	}
	return true
}

func languageNames(langs []Language) []string {
	out := make([]string, len(langs))
	for i, l := range langs {
		out[i] = string(l)
	}
	return out
}

func runsOf(n int, sets ...[]Language) [][]Language {
	var out [][]Language
	for _, set := range sets {
		for range n {
			out = append(out, set)
		}
	}
	return out
}

// Callers that cycle through languages keep every set they ask for in the table and,
// once the split has settled, cost one container per open (the claimed one's
// replacement) and almost nothing more, at sizes 1 to 32, one open a second: demand that
// takes turns (alternating, three sets rotating, two to one, runs of three or five of
// each) never moves a member, and longer runs move at most one a minute. History: in
// v0.17.0 a pool of 4 or fewer forgot every set but the last one asked for, so each open
// moved the whole pool; in v0.17.1 a fixed 1/16 rate swung larger pools' shares by up to
// size/16 a open, so even two sets alternating moved a member every open from size 9; in
// v0.17.2 runs of six or more still moved a member every few opens, for nothing, since
// claims and refills follow demand by themselves.
func TestPoolCyclingHintsDoNotChurn(t *testing.T) {
	js, py, all := []Language{LanguageJavaScript}, []Language{LanguagePython}, []Language{LanguageJavaScript, LanguagePython}
	stated := []Language{LanguageJavaScript, LanguagePython}
	for _, c := range []struct {
		name    string
		pattern [][]Language
		still   bool // no move at all once settled
	}{
		{"alternating", [][]Language{js, py}, true},
		{"rotating", [][]Language{js, py, all}, true},
		{"two to one", [][]Language{js, js, py}, true},
		{"every language, then Python, then JavaScript twice", [][]Language{all, py, js, js}, true},
		{"runs of three", runsOf(3, js, py), true},
		{"runs of five", runsOf(5, js, py), true},
		{"runs of six", runsOf(6, js, py), false},
		{"runs of eleven", runsOf(11, js, py), false},
		{"three sets in runs of five", runsOf(5, js, py, all), false},
		{"runs of forty", runsOf(40, js, py), false},
	} {
		for size := 1; size <= 32; size++ {
			// 1000 opens, ten seconds apart, settle the split: a pool of 32 forgets the
			// starting set only after about 800, and the members that warm it, which no
			// claim takes while closer ones wait, go at one a minute.
			sim := newPoolSim(size, stated, 10*time.Second)
			for i := range 1000 {
				sim.open(c.pattern[i%len(c.pattern)])
			}
			sim.removed, sim.step = 0, time.Second
			const settled = 600
			for i := range settled {
				sim.open(c.pattern[(1000+i)%len(c.pattern)])
			}
			for _, w := range c.pattern {
				if _, ok := sim.p.demand[languageSetKey(w)]; !ok && len(c.pattern) < 40 {
					t.Errorf("%s, size %d: %v was forgotten though it is asked for every %d opens: %v", c.name, size, w, len(c.pattern), sim.p.demand)
				}
			}
			if limit := settled / 60; sim.removed > limit || (c.still && sim.removed != 0) {
				t.Errorf("%s, size %d: %d members removed by rebalancing in %d settled opens, one a second; want %s", c.name, size, sim.removed, settled,
					map[bool]string{true: "none", false: fmt.Sprintf("at most one a minute (%d)", limit)}[c.still])
			}
		}
	}
}

// A pool of 4 or fewer does not split: every member warms every language the image
// runs, so every session finds its languages warm whatever the mix, and a pool of 5 or
// more is the smallest that divides by demand. Before,
// a split pool of 1 warmed the set narrowly ahead (0 of 200 alternating opens warm), a
// pool of 2 with three sets in turn found two in three, and a language under a quarter
// of the demand, or a burst, found a split pool of 1 to 3 warm 75 to 91% of the time.
func TestPoolOfFourOrFewerWarmsEveryLanguage(t *testing.T) {
	js, py, all := []Language{LanguageJavaScript}, []Language{LanguagePython}, []Language{LanguageJavaScript, LanguagePython}
	for _, pattern := range [][][]Language{{js, py}, {js, py, all}, {js, js, js, py}, runsOf(40, js, py)} {
		for size := 1; size < poolSplitMinSize; size++ {
			sim := newPoolSim(size, []Language{LanguageJavaScript, LanguagePython}, time.Second)
			for i := range 200 {
				sim.open(pattern[i%len(pattern)])
			}
			hits := 0
			for i := range 300 {
				if sim.open(pattern[i%len(pattern)]) {
					hits++
				}
			}
			if hits != 300 || sim.removed != 0 {
				t.Errorf("size %d, %d hints in turn: %d of 300 opens found their languages warm, %d members moved; want all, none", size, len(pattern), hits, sim.removed)
			}
		}
	}
	sim := newPoolSim(poolSplitMinSize-1, []Language{LanguageJavaScript, LanguagePython}, time.Second)
	for range 300 {
		sim.clock = sim.clock.Add(time.Minute)
		sim.open(py)
	}
	for _, m := range sim.p.ready {
		if !slices.Equal(m.warm, []string{"javascript", "python"}) {
			t.Errorf("after 300 Python opens a member of a pool of %d warms %v; want every language", poolSplitMinSize-1, m.warm)
		}
	}
}

// Rebalancing is a slow janitor: it moves at most one member a minute, however far
// the split is from the shares; claims and refills do the rest.
func TestPoolRebalancesAtMostOnceAMinute(t *testing.T) {
	now := time.Unix(1e9, 0)
	removed := 0
	p := &dockerPool{size: poolSplitMinSize, demand: map[string]float64{"python": 1}, now: func() time.Time { return now },
		discard: func(*dockerSession) { removed++ }}
	for range poolSplitMinSize {
		p.ready = append(p.ready, &dockerSession{warm: []string{"javascript"}})
	}
	if !p.rebalance() || p.rebalance() {
		t.Fatalf("rebalance moved %d members at once; want 1", removed)
	}
	p.ready = append(p.ready, &dockerSession{warm: []string{"python"}})
	now = now.Add(poolMoveInterval - time.Second)
	if p.rebalance() {
		t.Fatal("rebalance moved a second member within a minute")
	}
	now = now.Add(time.Second)
	if !p.rebalance() || removed != 2 {
		t.Fatalf("rebalance did not move the next member a minute later (%d removed)", removed)
	}
}

// The margin and the one-move-a-minute bound do not freeze the pool: when sessions
// that asked only for JavaScript start asking only for Python, one every 10 seconds,
// the pool turns to Python within 2 x size minutes, short only of the members the old
// set's fading weight still earns. Claims take the Python members first, so the
// JavaScript ones, which no claim takes, go through rebalance.
func TestPoolFollowsARealShift(t *testing.T) {
	js, py := []Language{LanguageJavaScript}, []Language{LanguagePython}
	for _, size := range []int{poolSplitMinSize, 8, 16, 32} {
		sim := newPoolSim(size, []Language{LanguageJavaScript, LanguagePython}, 10*time.Second)
		for range 12 * size {
			sim.open(js)
		}
		for range 12 * size {
			sim.open(py)
		}
		n := 0
		for _, s := range sim.p.ready {
			if slices.Equal(s.warm, []string{"python"}) {
				n++
			}
		}
		if want := size - 1 - size/16; n < want {
			t.Errorf("size %d: %d members warm Python alone after %d Python opens over %v; want at least %d", size, n, 12*size, time.Duration(12*size)*sim.step, want)
		}
	}
}

// When the image no longer runs a language the table still asks for (an embedder's
// second EnsureReady found no Python), the pool makes what it can and settles: before
// the fix the member it made counted as a set nobody wanted, so a full pool removed it
// and made the same set again, with no backoff, until the old set's weight faded.
func TestPoolSettlesWhenASetCannotBeMade(t *testing.T) {
	sim := newPoolSim(2, []Language{LanguageJavaScript, LanguagePython}, time.Second)
	sim.stated = []Language{LanguageJavaScript}
	for _, m := range sim.p.ready {
		m.warm = []string{"javascript", "python"}
	}
	sim.removed = 0
	for range 100 {
		sim.clock = sim.clock.Add(time.Minute)
		sim.fill()
	}
	if sim.removed > sim.p.size || sim.p.rebalance() {
		t.Fatalf("the pool moved %d members and has not settled (demand %v); want at most %d moves", sim.removed, sim.p.demand, sim.p.size)
	}
}

// A claim takes the member warming the most of the hinted languages, then the one
// warming the fewest others, then the oldest; with nothing warming a hinted language
// it still takes a member, since the container is most of the cold cost.
func TestClosestMemberPrefersTheOneWarmingTheHint(t *testing.T) {
	members := []*dockerSession{
		{name: "both", warm: []string{"javascript", "python"}},
		{name: "python", warm: []string{"python"}},
		{name: "javascript", warm: []string{"javascript"}},
		{name: "python-newer", warm: []string{"python"}},
	}
	for _, c := range []struct {
		pool []*dockerSession
		want []Language
		name string
	}{
		{members, []Language{LanguagePython}, "python"},
		{members, []Language{LanguageJavaScript, LanguagePython}, "both"},
		{members, []Language{LanguageJavaScript}, "javascript"},
		{members[2:3], []Language{LanguagePython}, "javascript"},
		{members[:0], []Language{LanguagePython}, ""},
	} {
		name := ""
		if i := closestMember(c.pool, c.want); i >= 0 {
			name = c.pool[i].name
		}
		if name != c.name {
			t.Errorf("closestMember(%d members, %v) = %q; want %q", len(c.pool), c.want, name, c.name)
		}
	}
}

// When the pool is full but one set is above its share and another below, rebalance
// removes one member of the surplus set, oldest first, and nothing more.
func TestPoolRebalanceMovesOneMember(t *testing.T) {
	var removed []string
	p := &dockerPool{size: poolSplitMinSize, demand: map[string]float64{"python": 1}, now: time.Now, discard: func(s *dockerSession) { removed = append(removed, s.name) }}
	for i := range poolSplitMinSize {
		p.ready = append(p.ready, &dockerSession{name: fmt.Sprint("both", i), warm: []string{"javascript", "python"}})
	}
	if !p.rebalance() || !slices.Equal(removed, []string{"both0"}) || len(p.ready) != poolSplitMinSize-1 {
		t.Fatalf("rebalance removed %v and left %d; want the oldest removed and %d left", removed, len(p.ready), poolSplitMinSize-1)
	}
	p.ready, p.lastMove, removed = nil, time.Time{}, nil
	for i := range poolSplitMinSize {
		p.ready = append(p.ready, &dockerSession{name: fmt.Sprint("py", i), warm: []string{"python"}})
	}
	if p.rebalance() || removed != nil {
		t.Fatalf("a pool at its shares rebalanced, removing %v", removed)
	}
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
	d.pool.Store(&dockerPool{d: d, stop: make(chan struct{}), done: make(chan struct{}), discard: func(*dockerSession) {}})
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

// A pool whose first member cannot be made has no filler, so start closes done itself:
// anything waiting for the filler (Drain, through close) returns at once.
func TestPoolThatFailsToStartHasNoFillerToWaitFor(t *testing.T) {
	d := DefaultDocker("") // never made ready, so making a member fails at once
	p := &dockerPool{d: d, size: 1, stop: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1),
		demand: map[string]float64{"javascript": 1}, discard: func(*dockerSession) {}}
	d.projectLanguages = []Language{LanguageJavaScript}
	if err := p.start(context.Background()); err == nil {
		t.Fatal("a pool whose first member could not be made started")
	}
	select {
	case <-p.done:
	default:
		t.Fatal("the pool failed to start but done is still open, so close would wait forever")
	}
}

// A Drain whose pool's filler did not stop in time returns the pool's error and leaves
// no goroutine waiting for removals: the filler can still add one (it removes the
// member it was making once it sees the pool stopped), and a WaitGroup must not be
// added to from zero while it is waited on. Before the fix Drain went on to wait.
func TestDrainLeavesNoWaitBehindAPoolStillFilling(t *testing.T) {
	d := DefaultDocker("")
	d.pool.Store(&dockerPool{d: d, stop: make(chan struct{}), done: make(chan struct{}), discard: func(*dockerSession) {}})
	d.sessions.deletes.Add(1) // a removal still in flight
	defer d.sessions.deletes.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := d.Drain(ctx); err == nil || !strings.Contains(err.Error(), "still making a member") {
		t.Fatalf("Drain = %v; want the pool's error", err)
	}
	buf := make([]byte, 1<<20)
	if stacks := string(buf[:runtime.Stack(buf, true)]); strings.Contains(stacks, "(*DockerSandbox).Drain.func") {
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
	ctx, cancel := context.WithCancel(context.Background())
	s := &dockerSession{d: d, broker: b, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	d.sessions.open = map[*dockerSession]struct{}{s: {}}
	d.sessions.opening.Add(1) // an open still in flight
	defer d.sessions.opening.Done()
	dctx, dcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer dcancel()
	if err := d.Drain(dctx); err == nil || !strings.Contains(err.Error(), "still opening") {
		t.Fatalf("Drain = %v; want it to report the open in flight", err)
	}
	if got := SessionEndReason(s.Err()); got != SessionShutdown {
		t.Fatalf("the open session ended with %v after Drain; want shutdown", got)
	}
}

// Drain reports success only once every session it found open has been removed, even
// one that another goroutine (its lifetime timer, a client's Close) had begun to end:
// before the fix Drain's own finish returned early for such a session, and Drain
// waited on a removals count the other goroutine had not added to yet, so it returned
// nil with the container still there (and could race that Add).
func TestDrainWaitsForASessionAnotherGoroutineIsEnding(t *testing.T) {
	d := DefaultDocker("")
	b, err := startDockerSessionBroker()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &dockerSession{d: d, broker: b, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	if err := d.activate(s, time.Now().Add(time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	// Another goroutine's finish has claimed the end and not yet reached its removal.
	s.mu.Lock()
	s.end = &SessionEndedError{Reason: SessionExpired}
	s.life.Stop()
	s.mu.Unlock()
	dctx, dcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer dcancel()
	if err := d.Drain(dctx); err == nil {
		t.Fatal("Drain reported success while a session it found open was still being ended")
	}
}

// An open the provider refuses leaves the pool's demand as it was: a caller asking
// again and again for a floor the provider cannot meet (or for anything while it is at
// capacity) would otherwise move the pool toward its languages, away from the callers
// it serves. Before the fix the hint was recorded before the floor was checked.
func TestRefusedOpenLeavesPoolDemandUnchanged(t *testing.T) {
	d := DefaultDocker("")
	d.ready, d.daemonHost, d.verifiedRuntime = true, "unix:///var/run/docker.sock", d.Runtime
	d.verifiedImageIDs = map[string]string{d.Image: "sha256:snippet", d.ProjectImage: "sha256:project"}
	d.projectLanguages = []Language{LanguageJavaScript, LanguagePython}
	p := &dockerPool{d: d, size: 1, now: time.Now, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
		demand: map[string]float64{"javascript,python": 1}, discard: func(*dockerSession) {}}
	d.pool.Store(p)
	for range 20 {
		_, err := d.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute, MinimumIsolation: IsolationVM, Languages: []Language{LanguagePython}})
		if _, refused := NotDispatchedReason(err); !refused {
			t.Fatalf("an open with a VM floor on a container-tier provider: %v; want refused", err)
		}
	}
	if !maps.Equal(p.demand, map[string]float64{"javascript,python": 1}) {
		t.Fatalf("20 refused opens moved the pool's demand to %v", p.demand)
	}
}
