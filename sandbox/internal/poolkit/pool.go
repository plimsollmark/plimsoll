// Package poolkit is the warm session pool a session provider keeps (docker and
// openshell): never-used sandboxes made ready ahead of OpenSession, each with an
// interpreter started and its relay attached for a set of the languages the image
// runs, so an open hands one over instead of creating a sandbox and the first cell of
// each of those languages sends its code at once. The provider says how a member is
// made, checked and removed (Hooks); the pool decides how many wait, which languages
// each warms, which one a claim takes, and when one is replaced.
//
// Which sets it keeps follows the language hints sessions open with (no hint is every
// language): each open adds to a decaying weight per set, and the pool's fixed size
// is divided across the sets by weight. It starts with every member warming every
// language, so callers that send no hints see every member warm every language. What
// it keeps to:
//
//   - A member has run no guest code: only the provider's own programs (its init, the
//     main process, the interpreter launcher, the interpreters and their relays). A
//     claim makes it an ordinary session for one caller, and closing that session
//     removes the sandbox, as for any session. Nothing returns to the pool.
//   - A member is claimed only while it matches the current execution state (Hooks.
//     State) and every relay it was given is still attached. Any other member is
//     removed.
//   - A sandbox declares the end of its lifetime at creation, and the provider's
//     orphan pass reaps by it. So a member declares its creation plus MaxIdle plus the
//     longest lifetime it may be given, and a member idle past MaxIdle is replaced: a
//     crashed daemon's members are reaped within that bound.
//   - An unclaimed member runs only the provider's programs, so it holds its idle
//     footprint, not its memory limit, and no concurrency slot.
//   - Hints move members between sets and never add any: the operator's size bounds
//     the members, and so the memory, whatever callers ask for.
//
// The package knows nothing of sandboxes beyond the hooks, so it imports neither the
// sandbox package nor a provider's.
package poolkit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// MaxIdle is how long a member waits for a claim before it is replaced. It bounds how
// long a crashed daemon's unclaimed members outlive it beyond the session lifetime
// their declaration covers; replacing a member costs one sandbox start per half hour.
const MaxIdle = 30 * time.Minute

// addBudget bounds making one member: a create, a read-back, a process list, and per
// language a launch (whose script gives up after 20 seconds) and a relay.
const addBudget = 2 * time.Minute

// demandRate is the most weight an open gives its language set; every set's weight
// first shrinks by the same share. A pool of more than 4 gives 1/(4 size) instead
// (rate), so one open moves a set's share of the pool by at most a quarter member
// whatever the size, and the split follows roughly the last max(16, 4 x size) opens:
// long enough that one odd caller moves no member, short enough that a change in what
// callers run moves the pool within a few turnovers of it.
const demandRate = 1.0 / 16

// moveMargin is how much more than one member a move must be worth before rebalance
// makes it: the deficit of the set below its share and the surplus of the set above
// it, in members, must sum to more than 1 + moveMargin. Moving one member brings that
// sum down by up to 2, so a move worth just over 1 only trades which set is off by
// half a member; and one open moves a share by at most a quarter member, so demand
// that takes turns (two or three sets in turn, or runs of up to five opens each) never
// moves a member once settled.
const moveMargin = 0.75

// MoveInterval is how often rebalance may move a member. Claims and refills already
// follow demand (a claim takes the member closest to its hint and the refill makes the
// set furthest below its share), so rebalance only clears out members of sets holding
// less than a quarter of the weight, which claims seldom take; longer runs of one
// language would otherwise move a member every few opens for nothing. So rebalancing
// costs at most one sandbox start a minute, whatever callers ask for.
const MoveInterval = time.Minute

// SplitMinSize is the smallest pool that divides its members across language sets. A
// smaller one warms every language the image runs in every member. Measured in
// simulation on v0.17.3, split pools of 1 to 3 found a language fewer than a quarter
// of sessions asked for, or a burst of opens, warm 75 to 91% of the time against 100%
// warming every language, and the most a split of 4 or fewer can save is four idle
// interpreters.
const SplitMinSize = 5

var errStopped = errors.New("the session pool stopped")

// Hooks are what the pool asks of its provider about members of type M.
type Hooks[M any] struct {
	// Provider names the provider in the pool's errors and log lines.
	Provider string
	// State is the key of the execution state a member made now would be made under
	// (for docker: the daemon, runtime, tier, image and manifest). A member is handed
	// over only under the key it was made under.
	State func() (string, error)
	// Stated is the languages the image runs, in the image's order.
	Stated func() []string
	// Make creates a never-used member under the current execution state, declaring
	// label as the end of its lifetime, with an interpreter started and its relay
	// attached for each of langs, and returns it with the key of the state it was made
	// under. A member that fails partway is removed under ctx, which carries the
	// pool's hold on its place (Hold), so the place comes back only once the sandbox
	// is confirmed gone.
	Make func(ctx context.Context, langs []string, label time.Time) (M, string, error)
	// Attached reports whether m's relay for lang is still attached.
	Attached func(m M, lang string) bool
	// Name is m's sandbox name.
	Name func(m M) string
	// Discard removes a member nobody will claim, off the caller's path, and calls gone
	// once its sandbox is confirmed removed (a removal that gives up calls it only when
	// the provider's orphan pass confirms it gone).
	Discard func(m M, gone func())
	// Hold returns ctx carrying release, and the function to call in its place once
	// the work under ctx returns: release then runs once every hold taken under ctx
	// has ended too (sandbox.WithCapacity).
	Hold func(ctx context.Context, release func()) (context.Context, func())
}

// member is one waiting member and what the pool knows of it.
type member[M any] struct {
	m     M
	name  string
	key   string    // the execution state it was made under
	born  time.Time // when the pool began making it
	label time.Time // the end of the lifetime its sandbox declares
	warm  []string  // the languages whose interpreters it started
}

// Pool is a provider's session pool.
type Pool[M any] struct {
	h        Hooks[M]
	size     int
	lifetime time.Duration // the longest lifetime a member may be given
	now      func() time.Time

	wake     chan struct{} // a claim asks for a refill
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{} // closed when the filler has returned

	mu    sync.Mutex
	ready []*member[M] // oldest first
	// retiring counts members taken out of ready whose sandboxes are still being
	// removed. They count against size (short): admission charged the pool size runs'
	// memory, and a removed member's sandbox holds its share until it is gone, so a
	// replacement waits for it (review F9). A member leaves ready and enters retiring
	// under one hold of mu.
	retiring int
	// making counts members being made, and made members that failed to start whose
	// sandbox is not yet confirmed gone: each holds a place, so a run of failing
	// starts whose removals give up cannot grow the pool past its size (review,
	// 2026-10-24).
	making   int
	lastMove time.Time // when rebalance last moved a member
	stated   []string  // the languages the image runs, as next last saw them
	// demand is the decaying weight of each language set (SetKey) opens asked for. The
	// weights sum to at most 1, and a set whose weight falls below a quarter of one
	// open's is forgotten (about 22 opens after it was last asked for, in a pool of 4
	// or fewer, if it was asked for once). The floor is below one open's weight: a set
	// would otherwise be forgotten at the next open of another, however often it is
	// asked for.
	demand map[string]float64
}

// SetKey names a set of languages, in the order given.
func SetKey[L ~string](langs []L) string {
	parts := make([]string, len(langs))
	for i, l := range langs {
		parts[i] = string(l)
	}
	return strings.Join(parts, ",")
}

// New is a pool of size members for sessions given a lifetime of at most lifetime,
// starting with every member warming every language in stated. It makes nothing
// until Start.
func New[M any](h Hooks[M], size int, lifetime time.Duration, stated []string) (*Pool[M], error) {
	if size <= 0 || lifetime <= 0 {
		return nil, fmt.Errorf("%s: a session pool needs a positive size and lifetime (got %d, %v)", h.Provider, size, lifetime)
	}
	all := SetKey(stated)
	if all == "" {
		return nil, fmt.Errorf("%s: session pool: no interpreter languages are known for the image (run EnsureReady first)", h.Provider)
	}
	return &Pool[M]{h: h, size: size, lifetime: lifetime, now: time.Now,
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
		demand: map[string]float64{all: 1}, stated: slices.Clone(stated)}, nil
}

// Start makes the first member and starts the filler, which makes the rest in the
// background, so a pool that cannot make one fails here. A pool whose first member
// cannot be made has no filler, so Start closes done itself: a Close that found the
// pool meanwhile waits for done and would otherwise wait forever.
func (p *Pool[M]) Start(ctx context.Context) error {
	if err := p.add(ctx); err != nil {
		close(p.done)
		return err
	}
	go p.run()
	return nil
}

// Demand is a copy of the weight of each language set opens asked for.
func (p *Pool[M]) Demand() map[string]float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.demand)
}

// shares divides size members across language sets in proportion to their weight,
// exactly: shares are fractions of a member and sum to size.
func shares(demand map[string]float64, size int) map[string]float64 {
	total := 0.0
	for _, w := range demand {
		total += w
	}
	out := make(map[string]float64, len(demand))
	if total <= 0 {
		return out
	}
	for k, w := range demand {
		out[k] = float64(size) * w / total
	}
	return out
}

// Observe records that a session opened wanting set. A provider calls it for an open
// it did not refuse first (so a caller whose opens are refused cannot move the pool
// toward its languages), and before Claim, so the refill the claim asks for sees it;
// an open refused when Claim finds no member (a warm-only one) calls it only after a
// Claim that found one.
func (p *Pool[M]) Observe(set []string) {
	if p == nil {
		return
	}
	key := SetKey(set)
	rate := p.rate()
	floor := rate / 4
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, w := range p.demand {
		if w *= 1 - rate; w < floor && k != key {
			delete(p.demand, k)
		} else {
			p.demand[k] = w
		}
	}
	p.demand[key] += rate
}

// rate is the weight one open gives its set (demandRate).
func (p *Pool[M]) rate() float64 { return min(demandRate, 1/(4*float64(p.size))) }

// gaps compares the ready members of each language set with the set's exact share:
// want is the set furthest below its share and need how many members it lacks; spare
// is the set furthest above it and over how many members it has beyond it. want is ""
// when no set is below its share, spare when none is above; ties go to the set named
// first. Call with mu held.
func (p *Pool[M]) gaps() (want, spare string, need, over float64) {
	sh := shares(p.target(), p.size)
	have := make(map[string]int)
	for _, s := range p.ready {
		have[SetKey(s.warm)]++
	}
	keys := make([]string, 0, len(sh)+len(have))
	for k := range sh {
		keys = append(keys, k)
	}
	for k := range have {
		if _, ok := sh[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		if d := sh[k] - float64(have[k]); d > need {
			want, need = k, d
		} else if -d > over {
			spare, over = k, -d
		}
	}
	return want, spare, need, over
}

// add makes one member, warming the language set furthest below its share, and puts
// it at the back of the queue.
func (p *Pool[M]) add(ctx context.Context) error {
	stated := p.h.Stated()
	if len(stated) == 0 {
		return errors.New("no interpreter languages are known for the image (run EnsureReady first)")
	}
	langs := p.next(stated)
	born := p.now()
	p.mu.Lock()
	p.making++
	p.mu.Unlock()
	// The place is given back once the member is in ready, or, for one that failed to
	// start, once its sandbox is confirmed gone (a removal under ctx holds it).
	ctx, made := p.h.Hold(ctx, p.made)
	defer made()
	m, key, err := p.h.Make(ctx, langs, born.Add(MaxIdle+p.lifetime))
	if err != nil {
		return err
	}
	s := &member[M]{m: m, name: p.h.Name(m), key: key, born: born, label: born.Add(MaxIdle + p.lifetime), warm: langs}
	p.mu.Lock()
	select {
	case <-p.stop:
		p.retiring++
		p.mu.Unlock()
		p.drop(s)
		return errStopped
	default:
	}
	p.ready = append(p.ready, s)
	p.mu.Unlock()
	return nil
}

// next is the language set the next member warms: the set furthest below its share,
// less any language the image no longer states (an embedder's later EnsureReady may
// find fewer), or every stated language when nothing is left. When that is not the set
// asked for, the asked-for set's weight moves to it, so the table names only sets the
// pool can make: otherwise the member counts as a set nobody wants, and a full pool
// removes it and makes the same set again, with no backoff, until the old weight fades.
func (p *Pool[M]) next(stated []string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stated = slices.Clone(stated)
	want, _, _, _ := p.gaps()
	var langs []string
	for _, l := range stated {
		if slices.Contains(strings.Split(want, ","), l) {
			langs = append(langs, l)
		}
	}
	if len(langs) == 0 {
		langs = slices.Clone(stated)
	}
	if made := SetKey(langs); made != want {
		if w, ok := p.demand[want]; ok {
			p.demand[made] += w
			delete(p.demand, want)
		}
	}
	return langs
}

// asked reports whether set holds at least a quarter of the weight. Call with mu held.
func (p *Pool[M]) asked(set string) bool {
	total := 0.0
	for _, w := range p.demand {
		total += w
	}
	return total > 0 && p.demand[set] >= total/4
}

// target is the demand the pool divides its size by: the table, or in a pool smaller
// than SplitMinSize all of it on every language the image runs. Call with mu held.
func (p *Pool[M]) target() map[string]float64 {
	if p.size < SplitMinSize {
		if all := SetKey(p.stated); all != "" {
			return map[string]float64{all: 1}
		}
	}
	return p.demand
}

// usable reports whether s may be handed to a session made under key that ends at
// expires.
func (p *Pool[M]) usable(s *member[M], key string, expires time.Time) bool {
	if s.key != key || expires.After(s.label) || p.now().Sub(s.born) > MaxIdle {
		return false
	}
	for _, l := range s.warm {
		if !p.h.Attached(s.m, l) {
			return false
		}
	}
	return true
}

// Claim hands over the ready member that was made under key, may live until expires,
// and warms the most of want: then the one warming the fewest languages beyond want,
// then the oldest. Any member beats none, since creating the sandbox is most of what a
// claim saves. It reports false when no member may be handed over. The members it
// finds unusable are removed, and the filler is asked to make up the difference.
func (p *Pool[M]) Claim(key string, expires time.Time, want []string) (M, bool) {
	var zero M
	if p == nil {
		return zero, false
	}
	var got *member[M]
	var stale []*member[M]
	p.mu.Lock()
	kept := make([]*member[M], 0, len(p.ready))
	for _, s := range p.ready {
		if p.usable(s, key, expires) {
			kept = append(kept, s)
		} else {
			stale = append(stale, s)
		}
	}
	if i := closest(kept, want); i >= 0 {
		got = kept[i]
		kept = slices.Delete(kept, i, i+1)
	}
	p.ready = kept
	p.retiring += len(stale)
	p.mu.Unlock()
	p.drop(stale...)
	select {
	case p.wake <- struct{}{}:
	default:
	}
	if got == nil {
		return zero, false
	}
	return got.m, true
}

// closest is the index of the member warming the most of want, then the fewest
// languages beyond it, then the first (the oldest); -1 when there is none.
func closest[M any](members []*member[M], want []string) int {
	best, bestHit, bestExtra := -1, 0, 0
	for i, s := range members {
		hit := 0
		for _, l := range s.warm {
			if slices.Contains(want, l) {
				hit++
			}
		}
		if extra := len(s.warm) - hit; best < 0 || hit > bestHit || (hit == bestHit && extra < bestExtra) {
			best, bestHit, bestExtra = i, hit, extra
		}
	}
	return best
}

// rebalance removes the oldest member of the language set furthest above its share
// when another set is below its share, the move is worth more than one member
// (moveMargin), no member moved in the last MoveInterval, and the surplus set holds
// less than a quarter of the weight (a member of a set sessions still ask for is one a
// claim will take), so the next add makes one of the set below its share. It reports
// whether it removed one.
func (p *Pool[M]) rebalance() bool {
	p.mu.Lock()
	want, spare, need, over := p.gaps()
	var gone *member[M]
	if want != "" && spare != "" && need+over > 1+moveMargin && p.now().Sub(p.lastMove) >= MoveInterval && !p.asked(spare) {
		for i, s := range p.ready {
			if SetKey(s.warm) == spare {
				gone = s
				p.ready = slices.Delete(p.ready, i, i+1)
				p.retiring++
				p.lastMove = p.now()
				break
			}
		}
	}
	p.mu.Unlock()
	if gone == nil {
		return false
	}
	p.drop(gone)
	return true
}

// retire removes members past their idle bound or made under another execution
// state, and members whose relays ended.
func (p *Pool[M]) retire() {
	key, err := p.h.State()
	if err != nil {
		return
	}
	// expires is now: retire tests only state, age and relays, never the lifetime.
	now := p.now()
	var stale []*member[M]
	p.mu.Lock()
	kept := p.ready[:0]
	for _, s := range p.ready {
		if p.usable(s, key, now) {
			kept = append(kept, s)
		} else {
			stale = append(stale, s)
		}
	}
	p.ready = kept
	p.retiring += len(stale)
	p.mu.Unlock()
	p.drop(stale...)
}

// drop discards members the caller took out of ready and counted in retiring. It is
// called without mu held, since a discard may report the removal at once.
func (p *Pool[M]) drop(members ...*member[M]) {
	for _, s := range members {
		p.h.Discard(s.m, p.retired)
	}
}

// retired is a removal's report that a retiring member's sandbox is gone: the pool is
// short by one more, and the filler is woken to make the replacement.
func (p *Pool[M]) retired() {
	p.mu.Lock()
	p.retiring--
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// short reports whether the pool may make a member: members ready, being made, and
// still being removed together hold fewer than size sandboxes.
func (p *Pool[M]) short() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ready)+p.making+p.retiring < p.size
}

// made gives back the place a member being made held: it is in ready now, or it failed
// to start and its sandbox is confirmed gone.
func (p *Pool[M]) made() {
	p.mu.Lock()
	p.making--
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// run is the filler: it keeps the pool at its size, one member at a time so a burst
// of claims cannot stampede the provider, backing off while members fail.
func (p *Pool[M]) run() {
	defer close(p.done)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-p.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	backoff := time.Second
	for {
		p.retire()
		if !p.short() {
			p.rebalance()
		}
		if p.short() {
			actx, acancel := context.WithTimeout(ctx, addBudget)
			err := p.add(actx)
			acancel()
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				backoff = time.Second
				continue
			}
			slog.Warn(p.h.Provider+": the session pool could not make a member", "err", err)
			select {
			case <-time.After(backoff):
			case <-p.stop:
				return
			}
			backoff = min(2*backoff, time.Minute)
			continue
		}
		select {
		case <-p.wake:
		case <-tick.C:
		case <-p.stop:
			return
		}
	}
}

// Close stops the filler, waits for it until ctx ends, and removes every ready member.
// A filler still making a member when ctx ends removes that member itself once it sees
// the pool stopped (add), but possibly after Close returned; its declared lifetime
// bounds how long it can outlive the daemon.
func (p *Pool[M]) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.stopOnce.Do(func() { close(p.stop) })
	var err error
	select {
	case <-p.done:
	default:
		select {
		case <-p.done:
		case <-ctx.Done():
			err = fmt.Errorf("%s: the session pool is still making a member: %w", p.h.Provider, ctx.Err())
		}
	}
	p.mu.Lock()
	ready := p.ready
	p.ready = nil
	p.retiring += len(ready)
	p.mu.Unlock()
	p.drop(ready...)
	return err
}

// Members are the names of the ready members, which the provider's orphan pass must
// not reap.
func (p *Pool[M]) Members() []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	names := make([]string, 0, len(p.ready))
	for _, s := range p.ready {
		names = append(names, s.name)
	}
	return names
}
