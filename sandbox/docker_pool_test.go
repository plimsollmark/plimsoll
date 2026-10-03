package sandbox

import (
	"context"
	"errors"
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

// Callers that cycle through languages keep every set they ask for in the table and,
// once the split has settled, cost one container per open (the claimed one's
// replacement), never a rebalance: alternating JavaScript and Python, rotating through
// JavaScript, Python and no hint (every language), two JavaScript opens to one Python,
// and runs of three and of five opens of each, in pools of 1 to 32. With two or more
// members an alternating open always finds its language warm. Before the fixes a pool
// of 4 or fewer forgot every set but the last one asked for (one open's weight fell
// below the forget floor after a single decay), so each open moved the whole pool; and
// with a fixed rate of 1/16 an open swung a set's share by up to size/16 members, so
// larger pools moved a member on every open or every run, even for two sets alternating.
func TestPoolCyclingHintsDoNotChurn(t *testing.T) {
	js, py, all := []Language{LanguageJavaScript}, []Language{LanguagePython}, []Language{LanguageJavaScript, LanguagePython}
	patterns := map[string][][]Language{
		"alternating":   {js, py},
		"rotating":      {js, py, all},
		"two to one":    {js, js, py},
		"runs of three": {js, js, js, py, py, py},
		"runs of five":  {js, js, js, js, js, py, py, py, py, py},
	}
	for name, pattern := range patterns {
		for size := 1; size <= 32; size++ {
			removed := 0
			p := &dockerPool{size: size, demand: map[string]float64{"javascript,python": 1},
				discard: func(*dockerSession) { removed++ }}
			// fill is the filler's loop (run): rebalance only a full pool, else add one
			// member of the set furthest below its share.
			fill := func() {
				for {
					if !p.short() {
						if !p.rebalance() {
							return
						}
						continue
					}
					p.mu.Lock()
					want, _, _, _ := p.gaps()
					p.ready = append(p.ready, &dockerSession{warm: strings.Split(want, ",")})
					p.mu.Unlock()
				}
			}
			fill()
			hits := 0
			// 1000 opens settle the split: a pool of 32 forgets the starting set only
			// after about 800.
			for i := range 1150 {
				want := pattern[i%len(pattern)]
				p.observe(want)
				p.mu.Lock()
				got := p.ready[closestMember(p.ready, want)]
				p.ready = slices.DeleteFunc(p.ready, func(s *dockerSession) bool { return s == got })
				p.mu.Unlock()
				if i == 1000 {
					removed, hits = 0, 0
				}
				if slices.Equal(got.warm, languageNames(want)) {
					hits++
				}
				fill()
			}
			for _, w := range pattern {
				if _, ok := p.demand[languageSetKey(w)]; !ok {
					t.Errorf("%s, size %d: %v was forgotten though it is asked for every %d opens: %v", name, size, w, len(pattern), p.demand)
				}
			}
			if removed != 0 {
				t.Errorf("%s, size %d: %d members removed by rebalancing in the last 150 opens; want none", name, size, removed)
			}
			if name == "alternating" && size >= 2 && hits != 150 {
				t.Errorf("%s, size %d: %d of the last 150 opens found exactly their language warm; want all", name, size, hits)
			}
		}
	}
}

// The margin that keeps cycling demand from moving members does not freeze the pool:
// once sessions ask only for Python, the pool turns to Python within a few turnovers,
// short only of the members the old set's fading weight still earns.
func TestPoolFollowsARealShift(t *testing.T) {
	py := []Language{LanguagePython}
	for _, size := range []int{1, 2, 4, 8, 16, 32} {
		p := &dockerPool{size: size, demand: map[string]float64{"javascript,python": 1}, discard: func(*dockerSession) {}}
		fill := func() {
			for {
				if !p.short() {
					if !p.rebalance() {
						return
					}
					continue
				}
				want, _, _, _ := p.gaps()
				p.ready = append(p.ready, &dockerSession{warm: strings.Split(want, ",")})
			}
		}
		fill()
		for range 12 * size {
			p.observe(py)
			got := p.ready[closestMember(p.ready, py)]
			p.ready = slices.DeleteFunc(p.ready, func(s *dockerSession) bool { return s == got })
			fill()
		}
		n := 0
		for _, s := range p.ready {
			if slices.Equal(s.warm, []string{"python"}) {
				n++
			}
		}
		if want := size - 1 - size/16; n < want {
			t.Errorf("size %d: %d Python members after %d Python opens; want at least %d", size, n, 12*size, want)
		}
	}
}

// When the image no longer runs a language the table still asks for (an embedder's
// second EnsureReady found no Python), the pool makes what it can and settles: before
// the fix the member it made counted as a set nobody wanted, so a full pool removed it
// and made the same set again, with no backoff, until the old set's weight faded.
func TestPoolSettlesWhenASetCannotBeMade(t *testing.T) {
	stated := []Language{LanguageJavaScript}
	moves := 0
	p := &dockerPool{size: 2, demand: map[string]float64{"javascript,python": 1}, discard: func(*dockerSession) { moves++ }}
	for range 100 {
		if !p.short() {
			if !p.rebalance() {
				break
			}
			continue
		}
		p.ready = append(p.ready, &dockerSession{warm: languageNames(p.next(stated))})
	}
	if moves > p.size || p.short() || p.rebalance() {
		t.Fatalf("the pool moved %d members and has not settled (ready %d, demand %v); want at most %d moves", moves, len(p.ready), p.demand, p.size)
	}
}

func languageNames(langs []Language) []string {
	out := make([]string, len(langs))
	for i, l := range langs {
		out[i] = string(l)
	}
	return out
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
	p := &dockerPool{size: 2, demand: map[string]float64{"python": 1}, discard: func(s *dockerSession) { removed = append(removed, s.name) }}
	p.ready = []*dockerSession{{name: "old", warm: []string{"javascript", "python"}}, {name: "new", warm: []string{"javascript", "python"}}}
	if !p.rebalance() || !slices.Equal(removed, []string{"old"}) || len(p.ready) != 1 {
		t.Fatalf("rebalance removed %v and left %d; want old removed and one left", removed, len(p.ready))
	}
	p.ready = append(p.ready, &dockerSession{name: "py", warm: []string{"python"}})
	p.ready = p.ready[1:]
	p.ready = append(p.ready, &dockerSession{name: "py2", warm: []string{"python"}})
	removed = nil
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
