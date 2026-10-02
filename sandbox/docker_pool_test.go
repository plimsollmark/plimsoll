package sandbox

import (
	"errors"
	"maps"
	"slices"
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

// The pool's size is divided across language sets by weight: whole parts first, the
// rest to the largest remainders, ties to the set named first, always summing to the
// size.
func TestPoolSharesDivideTheSizeByWeight(t *testing.T) {
	for _, c := range []struct {
		demand map[string]float64
		size   int
		want   map[string]int
	}{
		{map[string]float64{"javascript,python": 1}, 3, map[string]int{"javascript,python": 3}},
		{map[string]float64{"python": 0.5, "javascript": 0.5}, 3, map[string]int{"javascript": 2, "python": 1}},
		{map[string]float64{"a": 0.7, "b": 0.2, "c": 0.1}, 4, map[string]int{"a": 3, "b": 1, "c": 0}},
		{map[string]float64{"a": 0.01, "b": 0.01}, 1, map[string]int{"a": 1, "b": 0}},
		{map[string]float64{}, 2, map[string]int{}},
	} {
		if got := poolShares(c.demand, c.size); !maps.Equal(got, c.want) {
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
	if got := poolShares(p.demand, p.size); got[py] != 3 || got[all] != 1 {
		t.Fatalf("after 20 Python opens the shares are %v; want 3 Python and 1 of every language", got)
	}
	for range 40 {
		p.observe([]Language{LanguagePython})
	}
	if _, ok := p.demand[all]; ok || len(p.demand) != 1 {
		t.Fatalf("after 60 Python opens the table is %v; want only Python", p.demand)
	}
	p.observe([]Language{LanguageJavaScript, LanguagePython})
	if got := poolShares(p.demand, p.size); got[py] != 4 {
		t.Fatalf("one open of every language moved the shares to %v; want all 4 still Python", got)
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
