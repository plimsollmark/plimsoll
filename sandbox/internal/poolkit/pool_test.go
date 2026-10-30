package poolkit

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"sync"
	"testing"
	"time"
)

const (
	js = "javascript"
	py = "python"
)

// fake is a member with no sandbox: dead says its relays ended.
type fake struct {
	name string
	dead bool
}

// testHold is sandbox.WithCapacity in miniature: release runs once the work and every
// hold taken under its context have ended.
type testHold struct {
	mu      sync.Mutex
	n       int
	release func()
}

type holdKey struct{}

func (h *testHold) done() {
	h.mu.Lock()
	h.n--
	last := h.n == 0
	h.mu.Unlock()
	if last {
		h.release()
	}
}

func withHold(ctx context.Context, release func()) (context.Context, func()) {
	h := &testHold{n: 1, release: release}
	var once sync.Once
	return context.WithValue(ctx, holdKey{}, h), func() { once.Do(h.done) }
}

// takeHold is HoldCapacity in miniature.
func takeHold(ctx context.Context) func() {
	h := ctx.Value(holdKey{}).(*testHold)
	h.mu.Lock()
	h.n++
	h.mu.Unlock()
	var once sync.Once
	return func() { once.Do(h.done) }
}

// testHooks are hooks whose Make fails (a test that makes members sets its own) and
// whose Discard reports every removal done at once, after recording it.
func testHooks(removed *[]string) Hooks[*fake] {
	return Hooks[*fake]{
		Provider: "test",
		State:    func() (string, error) { return "state", nil },
		Stated:   func() []string { return []string{js, py} },
		Make: func(context.Context, []string, time.Time) (*fake, string, error) {
			return nil, "", errors.New("no sandboxes in this test")
		},
		Attached: func(m *fake, _ string) bool { return !m.dead },
		Name:     func(m *fake) string { return m.name },
		Discard: func(m *fake, gone func()) {
			if removed != nil {
				*removed = append(*removed, m.name)
			}
			gone()
		},
		Hold: withHold,
	}
}

func testPool(t *testing.T, h Hooks[*fake], size int, stated []string) *Pool[*fake] {
	t.Helper()
	p, err := New(h, size, time.Hour, stated)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A member is handed over only under the execution state it was made under, only for
// a lifetime its declaration covers, only while it is younger than the idle bound,
// and only while every interpreter it was given still has its relay. Whatever is
// passed over is removed, and the oldest usable member goes first.
func TestPoolClaimsOnlyAMemberItMayHandOver(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var removed []string
	p := testPool(t, testHooks(&removed), 6, []string{js, py})
	p.now = func() time.Time { return now }
	mk := func(name, key string, age time.Duration) *member[*fake] {
		return &member[*fake]{m: &fake{name: name}, name: name, key: key, born: now.Add(-age),
			label: now.Add(-age).Add(MaxIdle + time.Hour)}
	}
	unattached := mk("unattached", "state", time.Minute)
	unattached.warm = []string{py}
	unattached.m.dead = true // its relay ended
	p.ready = []*member[*fake]{
		mk("other-runtime", "runc", time.Minute),
		mk("other-image", "rebuilt", time.Minute),
		mk("too-old", "state", MaxIdle+time.Second),
		unattached,
		mk("oldest-usable", "state", 10*time.Minute),
		mk("newer", "state", time.Minute),
	}
	got, ok := p.Claim("state", now.Add(time.Hour), nil)
	if !ok || got.name != "oldest-usable" {
		t.Fatalf("claimed %v; want oldest-usable", got)
	}
	want := []string{"other-runtime", "other-image", "too-old", "unattached"}
	if len(p.ready) != 1 || p.ready[0].name != "newer" || !slices.Equal(removed, want) {
		t.Fatalf("left %d members, removed %v; want newer left and %v removed", len(p.ready), removed, want)
	}
	removed = nil
	if got, ok := p.Claim("state", now.Add(2*time.Hour), nil); ok {
		t.Fatalf("claimed %s for a lifetime its declaration does not cover", got.name)
	}
	if len(p.ready) != 0 || !slices.Equal(removed, []string{"newer"}) {
		t.Fatalf("left %d members, removed %v; want newer removed", len(p.ready), removed)
	}
	if _, ok := (*Pool[*fake])(nil).Claim("state", now, nil); ok {
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
		got := shares(c.demand, c.size)
		if !maps.EqualFunc(got, c.want, func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }) {
			t.Errorf("shares(%v, %d) = %v; want %v", c.demand, c.size, got, c.want)
		}
	}
}

// Opens move the split: a pool that starts with every member warming every language
// gives most of its members to Python once Python is what sessions ask for, and
// forgets a set nobody asks for any more, so the table stays bounded.
func TestPoolDemandFollowsObservedHints(t *testing.T) {
	all := "javascript,python"
	p := testPool(t, testHooks(nil), 4, []string{js, py})
	for range 20 {
		p.Observe([]string{py})
	}
	if got := shares(p.demand, p.size); math.Round(got[py]) != 3 || math.Round(got[all]) != 1 {
		t.Fatalf("after 20 Python opens the shares are %v; want about 3 Python and 1 of every language", got)
	}
	for range 50 {
		p.Observe([]string{py})
	}
	if _, ok := p.demand[all]; ok || len(p.demand) != 1 {
		t.Fatalf("after 70 Python opens the table is %v; want only Python", p.demand)
	}
	p.Observe([]string{js, py})
	if got := shares(p.demand, p.size); math.Round(got[py]) != 4 {
		t.Fatalf("one open of every language moved the shares to %v; want all 4 still Python", got)
	}
	if got := p.Demand(); !maps.Equal(got, p.demand) {
		t.Fatalf("Demand() = %v; want a copy of %v", got, p.demand)
	}
}

// poolSim drives a pool's split the way a provider does, with no sandboxes: each open
// observes its hint and claims the closest member (OpenSession), then the filler
// refills (run): a full pool may rebalance, a short one adds a member of next. The
// clock moves on by step per open.
type poolSim struct {
	p       *Pool[*fake]
	stated  []string
	clock   time.Time
	step    time.Duration
	removed int // members rebalance removed
}

func newPoolSim(t *testing.T, size int, stated []string, step time.Duration) *poolSim {
	s := &poolSim{stated: stated, clock: time.Unix(1e9, 0), step: step}
	h := testHooks(nil)
	h.Discard = func(_ *fake, gone func()) { s.removed++; gone() }
	s.p = testPool(t, h, size, stated)
	s.p.now = func() time.Time { return s.clock }
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
		s.p.ready = append(s.p.ready, &member[*fake]{m: &fake{}, warm: s.p.next(s.stated)})
	}
}

// open is one session asking for want; it reports whether the member it was handed
// warms every language asked for.
func (s *poolSim) open(want []string) bool {
	s.clock = s.clock.Add(s.step)
	s.p.Observe(want)
	got := s.p.ready[closest(s.p.ready, want)]
	s.p.ready = slices.DeleteFunc(s.p.ready, func(m *member[*fake]) bool { return m == got })
	s.fill()
	for _, l := range want {
		if !slices.Contains(got.warm, l) {
			return false
		}
	}
	return true
}

func runsOf(n int, sets ...[]string) [][]string {
	var out [][]string
	for _, set := range sets {
		for range n {
			out = append(out, set)
		}
	}
	return out
}

// Callers that cycle through languages keep every set they ask for in the table and,
// once the split has settled, cost one sandbox per open (the claimed one's
// replacement) and almost nothing more, at sizes 1 to 32, one open a second: demand that
// takes turns (alternating, three sets rotating, two to one, runs of three or five of
// each) never moves a member, and longer runs move at most one a minute. History: in
// v0.17.0 a pool of 4 or fewer forgot every set but the last one asked for, so each open
// moved the whole pool; in v0.17.1 a fixed 1/16 rate swung larger pools' shares by up to
// size/16 a open, so even two sets alternating moved a member every open from size 9; in
// v0.17.2 runs of six or more still moved a member every few opens, for nothing, since
// claims and refills follow demand by themselves.
func TestPoolCyclingHintsDoNotChurn(t *testing.T) {
	jsOnly, pyOnly, all := []string{js}, []string{py}, []string{js, py}
	for _, c := range []struct {
		name    string
		pattern [][]string
		still   bool // no move at all once settled
	}{
		{"alternating", [][]string{jsOnly, pyOnly}, true},
		{"rotating", [][]string{jsOnly, pyOnly, all}, true},
		{"two to one", [][]string{jsOnly, jsOnly, pyOnly}, true},
		{"every language, then Python, then JavaScript twice", [][]string{all, pyOnly, jsOnly, jsOnly}, true},
		{"runs of three", runsOf(3, jsOnly, pyOnly), true},
		{"runs of five", runsOf(5, jsOnly, pyOnly), true},
		{"runs of six", runsOf(6, jsOnly, pyOnly), false},
		{"runs of eleven", runsOf(11, jsOnly, pyOnly), false},
		{"three sets in runs of five", runsOf(5, jsOnly, pyOnly, all), false},
		{"runs of forty", runsOf(40, jsOnly, pyOnly), false},
	} {
		for size := 1; size <= 32; size++ {
			// 1000 opens, ten seconds apart, settle the split: a pool of 32 forgets the
			// starting set only after about 800, and the members that warm it, which no
			// claim takes while closer ones wait, go at one a minute.
			sim := newPoolSim(t, size, all, 10*time.Second)
			for i := range 1000 {
				sim.open(c.pattern[i%len(c.pattern)])
			}
			sim.removed, sim.step = 0, time.Second
			const settled = 600
			for i := range settled {
				sim.open(c.pattern[(1000+i)%len(c.pattern)])
			}
			for _, w := range c.pattern {
				if _, ok := sim.p.demand[SetKey(w)]; !ok && len(c.pattern) < 40 {
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
// runs, so every session handed a member finds its languages warm whatever the mix, and a pool of 5 or
// more is the smallest that divides by demand. Before,
// a split pool of 1 warmed the set narrowly ahead (0 of 200 alternating opens warm), a
// pool of 2 with three sets in turn found two in three, and a language under a quarter
// of the demand, or a burst, found a split pool of 1 to 3 warm 75 to 91% of the time.
func TestPoolOfFourOrFewerWarmsEveryLanguage(t *testing.T) {
	jsOnly, pyOnly, all := []string{js}, []string{py}, []string{js, py}
	for _, pattern := range [][][]string{{jsOnly, pyOnly}, {jsOnly, pyOnly, all}, {jsOnly, jsOnly, jsOnly, pyOnly}, runsOf(40, jsOnly, pyOnly)} {
		for size := 1; size < SplitMinSize; size++ {
			sim := newPoolSim(t, size, all, time.Second)
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
	sim := newPoolSim(t, SplitMinSize-1, all, time.Second)
	for range 300 {
		sim.clock = sim.clock.Add(time.Minute)
		sim.open(pyOnly)
	}
	for _, m := range sim.p.ready {
		if !slices.Equal(m.warm, all) {
			t.Errorf("after 300 Python opens a member of a pool of %d warms %v; want every language", SplitMinSize-1, m.warm)
		}
	}
}

// Rebalancing is a slow janitor: it moves at most one member a minute, however far
// the split is from the shares; claims and refills do the rest.
func TestPoolRebalancesAtMostOnceAMinute(t *testing.T) {
	now := time.Unix(1e9, 0)
	var removed []string
	p := testPool(t, testHooks(&removed), SplitMinSize, []string{js, py})
	p.now = func() time.Time { return now }
	p.demand = map[string]float64{py: 1}
	for range SplitMinSize {
		p.ready = append(p.ready, &member[*fake]{m: &fake{}, warm: []string{js}})
	}
	if !p.rebalance() || p.rebalance() {
		t.Fatalf("rebalance moved %d members at once; want 1", len(removed))
	}
	p.ready = append(p.ready, &member[*fake]{m: &fake{}, warm: []string{py}})
	now = now.Add(MoveInterval - time.Second)
	if p.rebalance() {
		t.Fatal("rebalance moved a second member within a minute")
	}
	now = now.Add(time.Second)
	if !p.rebalance() || len(removed) != 2 {
		t.Fatalf("rebalance did not move the next member a minute later (%d removed)", len(removed))
	}
}

// The margin and the one-move-a-minute bound do not freeze the pool: when sessions
// that asked only for JavaScript start asking only for Python, one every 10 seconds,
// the pool turns to Python within 2 x size minutes, short only of the members the old
// set's fading weight still earns. Claims take the Python members first, so the
// JavaScript ones, which no claim takes, go through rebalance.
func TestPoolFollowsARealShift(t *testing.T) {
	for _, size := range []int{SplitMinSize, 8, 16, 32} {
		sim := newPoolSim(t, size, []string{js, py}, 10*time.Second)
		for range 12 * size {
			sim.open([]string{js})
		}
		for range 12 * size {
			sim.open([]string{py})
		}
		n := 0
		for _, s := range sim.p.ready {
			if slices.Equal(s.warm, []string{py}) {
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
	sim := newPoolSim(t, 2, []string{js, py}, time.Second)
	sim.stated = []string{js}
	for _, m := range sim.p.ready {
		m.warm = []string{js, py}
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
// it still takes a member, since the sandbox is most of the cold cost.
func TestClosestMemberPrefersTheOneWarmingTheHint(t *testing.T) {
	m := func(name string, warm ...string) *member[*fake] { return &member[*fake]{name: name, warm: warm} }
	members := []*member[*fake]{m("both", js, py), m("python", py), m("javascript", js), m("python-newer", py)}
	for _, c := range []struct {
		pool []*member[*fake]
		want []string
		name string
	}{
		{members, []string{py}, "python"},
		{members, []string{js, py}, "both"},
		{members, []string{js}, "javascript"},
		{members[2:3], []string{py}, "javascript"},
		{members[:0], []string{py}, ""},
	} {
		name := ""
		if i := closest(c.pool, c.want); i >= 0 {
			name = c.pool[i].name
		}
		if name != c.name {
			t.Errorf("closest(%d members, %v) = %q; want %q", len(c.pool), c.want, name, c.name)
		}
	}
}

// When the pool is full but one set is above its share and another below, rebalance
// removes one member of the surplus set, oldest first, and nothing more.
func TestPoolRebalanceMovesOneMember(t *testing.T) {
	var removed []string
	p := testPool(t, testHooks(&removed), SplitMinSize, []string{js, py})
	p.demand = map[string]float64{py: 1}
	for i := range SplitMinSize {
		p.ready = append(p.ready, &member[*fake]{m: &fake{name: fmt.Sprint("both", i)}, warm: []string{js, py}})
	}
	if !p.rebalance() || !slices.Equal(removed, []string{"both0"}) || len(p.ready) != SplitMinSize-1 {
		t.Fatalf("rebalance removed %v and left %d; want the oldest removed and %d left", removed, len(p.ready), SplitMinSize-1)
	}
	p.ready, p.lastMove, removed = nil, time.Time{}, nil
	for i := range SplitMinSize {
		p.ready = append(p.ready, &member[*fake]{m: &fake{name: fmt.Sprint("py", i)}, warm: []string{py}})
	}
	if p.rebalance() || removed != nil {
		t.Fatalf("a pool at its shares rebalanced, removing %v", removed)
	}
}

// A pool whose first member cannot be made has no filler, so Start closes done itself:
// anything waiting for the filler (Close) returns at once.
func TestPoolThatFailsToStartHasNoFillerToWaitFor(t *testing.T) {
	p := testPool(t, testHooks(nil), 1, []string{js})
	if err := p.Start(context.Background()); err == nil {
		t.Fatal("a pool whose first member could not be made started")
	}
	select {
	case <-p.done:
	default:
		t.Fatal("the pool failed to start but done is still open, so Close would wait forever")
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("Close after a failed Start: %v", err)
	}
}

// Close is bounded by its context while the filler is still making a member, and says
// so.
func TestPoolCloseIsBoundedWhileTheFillerMakesAMember(t *testing.T) {
	h := testHooks(nil)
	started, release := make(chan struct{}, 1), make(chan struct{})
	n := 0
	h.Make = func(ctx context.Context, langs []string, label time.Time) (*fake, string, error) {
		n++
		if n > 1 {
			started <- struct{}{}
			<-release // a make that does not give up when asked
		}
		return &fake{name: fmt.Sprint("m", n)}, "state", nil
	}
	p := testPool(t, h, 2, []string{js})
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := p.Close(ctx); err == nil {
		t.Fatal("Close reported success while the filler was still making a member")
	}
	close(release)
	<-p.done
}

// A member taken out of the pool counts against its size until its sandbox is gone
// (review F9): admission charged the pool size runs' memory, so the replacement waits
// for the removal instead of running beside the sandbox it replaces.
func TestPoolReplacesAMemberOnlyOnceItsSandboxIsGone(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var pending []func() // removals not yet reported gone
	h := testHooks(nil)
	h.Discard = func(_ *fake, gone func()) { pending = append(pending, gone) }
	p := testPool(t, h, 1, []string{js})
	p.now = func() time.Time { return now }
	p.ready = []*member[*fake]{{m: &fake{name: "too-old"}, name: "too-old", key: "state", born: now.Add(-MaxIdle - time.Second), label: now.Add(time.Hour)}}
	if got, ok := p.Claim("state", now.Add(time.Minute), nil); ok {
		t.Fatalf("claimed %s, a member past its idle bound", got.name)
	}
	<-p.wake // the claim's own request for a refill
	if len(pending) != 1 {
		t.Fatalf("%d removals started; want 1", len(pending))
	}
	if p.short() {
		t.Fatal("the pool asks for a replacement while the member's sandbox is still being removed")
	}
	pending[0]()
	if !p.short() {
		t.Fatal("the pool is not short once the sandbox is gone")
	}
	select {
	case <-p.wake:
	default:
		t.Fatal("the removal did not wake the filler")
	}
}

// A member that failed to start holds its place until its removal, which holds the
// context Make was given, is confirmed (review, 2026-10-24): a run of failing starts
// whose removals give up cannot grow the pool past its size.
func TestPoolHoldsAFailedMemberPlaceUntilItsRemovalIsConfirmed(t *testing.T) {
	h := testHooks(nil)
	var confirm func()
	h.Make = func(ctx context.Context, _ []string, _ time.Time) (*fake, string, error) {
		confirm = takeHold(ctx) // the removal, still unconfirmed when Make returns
		return nil, "", errors.New("the interpreter would not start")
	}
	p := testPool(t, h, 1, []string{js})
	if err := p.add(context.Background()); err == nil {
		t.Fatal("add succeeded with a failing Make")
	}
	if p.short() {
		t.Fatal("the failed member's place came back before its sandbox was confirmed gone")
	}
	confirm()
	if !p.short() {
		t.Fatal("the place did not come back once the sandbox was confirmed gone")
	}
}

// A member made after the pool stopped is removed at once, never put in ready.
func TestPoolRemovesAMemberMadeAfterItStopped(t *testing.T) {
	var removed []string
	h := testHooks(&removed)
	p := testPool(t, h, 1, []string{js})
	h.Make = func(context.Context, []string, time.Time) (*fake, string, error) {
		p.stopOnce.Do(func() { close(p.stop) }) // Close begins while the member is made
		return &fake{name: "late"}, "state", nil
	}
	p.h = h
	if err := p.add(context.Background()); !errors.Is(err, errStopped) {
		t.Fatalf("add = %v; want the pool stopped", err)
	}
	if len(p.ready) != 0 || !slices.Equal(removed, []string{"late"}) || len(p.Members()) != 0 {
		t.Fatalf("ready %d, removed %v; want the late member removed and none ready", len(p.ready), removed)
	}
}
