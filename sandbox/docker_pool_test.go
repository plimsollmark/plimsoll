package sandbox

import (
	"context"
	"errors"
	"maps"
	"math"
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

// Callers that alternate between two languages keep both sets in the table and, once
// the split has settled, cost one container per open (the claimed one's replacement),
// never a rebalance; with two or more members each open finds its language warm. Before
// the fix a pool of 4 or fewer forgot every set but the last one asked for (one open's
// weight was below the forget floor after a single decay), so each open moved the whole
// pool to the language the next open did not want; a pool of 1 also flipped its one
// member on every open as two near-equal weights crossed.
func TestPoolAlternatingHintsDoNotChurn(t *testing.T) {
	js, py := []Language{LanguageJavaScript}, []Language{LanguagePython}
	for _, size := range []int{1, 2, 3, 4, 8} {
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
		for i := range 200 {
			want := js
			if i%2 == 1 {
				want = py
			}
			p.observe(want)
			p.mu.Lock()
			got := p.ready[closestMember(p.ready, want)]
			p.ready = slices.DeleteFunc(p.ready, func(s *dockerSession) bool { return s == got })
			p.mu.Unlock()
			if i == 100 {
				removed = 0
				hits = 0
			}
			if slices.Contains(got.warm, string(want[0])) {
				hits++
			}
			fill()
		}
		if _, ok := p.demand["javascript"]; !ok {
			t.Errorf("size %d: JavaScript was forgotten though every other open asks for it: %v", size, p.demand)
		}
		if _, ok := p.demand["python"]; !ok {
			t.Errorf("size %d: Python was forgotten though every other open asks for it: %v", size, p.demand)
		}
		if removed != 0 {
			t.Errorf("size %d: %d members removed by rebalancing in the last 100 alternating opens; want none", size, removed)
		}
		if size >= 2 && hits != 100 {
			t.Errorf("size %d: %d of the last 100 opens found their language warm; want all", size, hits)
		}
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
