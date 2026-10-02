package sandbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
)

// The docker session pool keeps never-used session containers ready, each with an
// interpreter started and its relay attached for a set of the languages the project
// image runs, so OpenSession hands one over instead of creating a container, and the
// first cell of each of those languages sends its code at once. Which sets it keeps
// follows the language hints sessions open with (SessionOptions.Languages; no hint is
// every language): each open adds to a decaying weight per set, and the pool's fixed
// size is divided across the sets by weight. It starts with every member warming every
// language, so callers that send no hints see the pool as before. What it keeps to:
//
//   - A member has run no guest code: only docker's init, sleep, the interpreter
//     launcher, the interpreters and their relays, all plimsoll's own. A claim makes
//     it an ordinary session for one caller, and closing that session removes the
//     container, as for any session. Nothing returns to the pool.
//   - A member is claimed only while it matches the current execution state (daemon,
//     runtime, tier, project image and manifest) and every relay it was given is still
//     attached. Any other member is removed.
//   - A container declares the end of its lifetime in a label fixed at creation, and
//     ReconcileOrphans reaps by it. So a member declares its creation plus
//     dockerPoolMaxIdle plus the longest lifetime it may be given, and a member idle
//     past dockerPoolMaxIdle is replaced: a crashed daemon's members are reaped within
//     that bound.
//   - An unclaimed member runs only plimsoll's programs, so it holds its idle
//     footprint, not its memory limit, and no concurrency slot.
//   - Hints move members between sets and never add any: the operator's size bounds
//     the members, and so the memory, whatever callers ask for.

// dockerPoolMaxIdle is how long a member waits for a claim before it is replaced. It
// bounds how long a crashed daemon's unclaimed members outlive it beyond the session
// lifetime their label covers; replacing a member costs one container start per half
// hour.
const dockerPoolMaxIdle = 30 * time.Minute

// dockerPoolAddBudget bounds making one member: a create, a read-back, a process list,
// and per language a launch (whose script gives up after 20 seconds) and a relay.
const dockerPoolAddBudget = 2 * time.Minute

// poolDemandRate is the weight an open gives its language set; every other set's
// weight shrinks by the same share, so the split follows roughly the last 16 to 32
// opens: long enough that one odd caller moves no member, short enough that a change
// in what callers run moves the pool within a few dozen sessions.
const poolDemandRate = 1.0 / 16

// poolMoveMargin is how much more than one member a move must be worth before
// rebalance makes it: the deficit of the set below its share and the surplus of the
// set above it, in members, must sum to more than 1 + poolMoveMargin. Moving one
// member brings that sum down by up to 2, so a move worth just over 1 only trades
// which set is off by half a member; demand alternating between two sets then never
// moves a member (in a pool of 1, the member stays put until one set holds more than
// about 62% of the weight).
const poolMoveMargin = 0.25

var errPoolStopped = errors.New("docker: the session pool stopped")

// dockerPool is a docker provider's session pool.
type dockerPool struct {
	d        *DockerSandbox
	size     int
	lifetime time.Duration // the longest lifetime a member may be given
	now      func() time.Time
	discard  func(*dockerSession) // removes a member nobody will claim (remove; a test's recorder)

	wake     chan struct{} // a claim asks for a refill
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{} // closed when the filler has returned

	mu    sync.Mutex
	ready []*dockerSession // oldest first
	// demand is the decaying weight of each language set (languageSetKey) opens asked
	// for. The weights sum to at most 1, and a set whose weight falls below a quarter
	// of one open's (a quarter of one member's share, in a pool of more than 16) is
	// forgotten, which bounds the table at max(64, 4 x size) sets. The floor is never
	// above one open's weight: a set would otherwise be forgotten at the next open of
	// another, however often it is asked for.
	demand map[string]float64
}

// languageSetKey names a set of languages, in the order given.
func languageSetKey[L ~string](langs []L) string {
	parts := make([]string, len(langs))
	for i, l := range langs {
		parts[i] = string(l)
	}
	return strings.Join(parts, ",")
}

// poolShares divides size members across language sets in proportion to their
// weight, exactly: shares are fractions of a member and sum to size.
func poolShares(demand map[string]float64, size int) map[string]float64 {
	total := 0.0
	for _, w := range demand {
		total += w
	}
	shares := make(map[string]float64, len(demand))
	if total <= 0 {
		return shares
	}
	for k, w := range demand {
		shares[k] = float64(size) * w / total
	}
	return shares
}

// observe records that a session opened wanting set.
func (p *dockerPool) observe(set []Language) {
	key := languageSetKey(set)
	floor := min(1/(4*float64(p.size)), poolDemandRate/4)
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, w := range p.demand {
		if w *= 1 - poolDemandRate; w < floor && k != key {
			delete(p.demand, k)
		} else {
			p.demand[k] = w
		}
	}
	p.demand[key] += poolDemandRate
}

// gaps compares the ready members of each language set with the set's exact share:
// want is the set furthest below its share and need how many members it lacks; spare
// is the set furthest above it and over how many members it has beyond it. want is ""
// when no set is below its share, spare when none is above; ties go to the set named
// first. Call with mu held.
func (p *dockerPool) gaps() (want, spare string, need, over float64) {
	shares := poolShares(p.demand, p.size)
	have := make(map[string]int)
	for _, s := range p.ready {
		have[languageSetKey(s.warm)]++
	}
	keys := make([]string, 0, len(shares)+len(have))
	for k := range shares {
		keys = append(keys, k)
	}
	for k := range have {
		if _, ok := shares[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		if d := shares[k] - float64(have[k]); d > need {
			want, need = k, d
		} else if -d > over {
			spare, over = k, -d
		}
	}
	return want, spare, need, over
}

// dockerPoolKey is the execution state a member was made under; a member is claimed
// only under the same one.
func dockerPoolKey(st dockerExecutionState) string {
	return strings.Join([]string{st.host, st.runtime, st.isolation.String(), st.platform, st.projectImageID, st.projectManifest}, "\x00")
}

// StartSessionPool keeps size never-used session containers ready, each with a set of
// the languages the project image runs warm (every one until hints say otherwise),
// for sessions given a lifetime of at most lifetime. It makes the first member before it returns, so a pool that cannot make
// one fails here, and makes the rest in the background. Call it once, after
// EnsureReady (whose smoke test finds the languages); Drain stops it.
func (d *DockerSandbox) StartSessionPool(ctx context.Context, size int, lifetime time.Duration) error {
	if size <= 0 || lifetime <= 0 {
		return fmt.Errorf("docker: a session pool needs a positive size and lifetime (got %d, %v)", size, lifetime)
	}
	if !d.SupportsSessions() {
		return fmt.Errorf("%w: docker sessions need a project image", ErrUnsupported)
	}
	d.stateMu.RLock()
	all := languageSetKey(d.projectLanguages)
	d.stateMu.RUnlock()
	if all == "" {
		return errors.New("docker: session pool: no interpreter languages are known for the project image (run EnsureReady first)")
	}
	p := &dockerPool{d: d, size: size, lifetime: lifetime, now: time.Now,
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
		demand: map[string]float64{all: 1}}
	p.discard = p.remove
	if !d.pool.CompareAndSwap(nil, p) {
		return errors.New("docker: the session pool is already started")
	}
	if err := p.start(ctx); err != nil {
		d.pool.Store(nil)
		return fmt.Errorf("docker: session pool: %w", err)
	}
	return nil
}

// start makes the first member and starts the filler. A pool whose first member
// cannot be made has no filler, so start closes done itself: a Drain that loaded the
// pool meanwhile waits for done and would otherwise wait forever.
func (p *dockerPool) start(ctx context.Context) error {
	if err := p.add(ctx); err != nil {
		close(p.done)
		return err
	}
	go p.run()
	return nil
}

// add makes one member, warming the language set furthest below its share, and puts
// it at the back of the queue.
func (p *dockerPool) add(ctx context.Context) error {
	state, err := p.d.executionState()
	if err != nil {
		return err
	}
	p.d.stateMu.RLock()
	stated := slices.Clone(p.d.projectLanguages)
	p.d.stateMu.RUnlock()
	if len(stated) == 0 {
		return errors.New("no interpreter languages are known for the project image (run EnsureReady first)")
	}
	p.mu.Lock()
	want, _, _, _ := p.gaps()
	p.mu.Unlock()
	// A set names only languages the image stated when it was asked for; one the
	// image no longer states is dropped, and a set left empty is every language.
	var langs []Language
	for _, l := range stated {
		if slices.Contains(strings.Split(want, ","), string(l)) {
			langs = append(langs, l)
		}
	}
	if len(langs) == 0 {
		langs = stated
	}
	born := p.now()
	s, err := p.d.newSessionContainer(ctx, state, born.Add(dockerPoolMaxIdle+p.lifetime))
	if err != nil {
		return err
	}
	s.born = born
	for _, l := range langs {
		if err := s.interps.Warm(ctx, s.execFunc, s.attach, string(l), dockerSessionWork); err != nil {
			s.abandon()
			return fmt.Errorf("starting the %s interpreter: %w", l, err)
		}
		s.warm = append(s.warm, string(l))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.stop:
		p.discard(s)
		return errPoolStopped
	default:
	}
	p.ready = append(p.ready, s)
	return nil
}

// usable reports whether s may be handed to a session made under key that ends at
// expires.
func (p *dockerPool) usable(s *dockerSession, key string, expires time.Time) bool {
	if s.key != key || expires.After(s.label) || p.now().Sub(s.born) > dockerPoolMaxIdle {
		return false
	}
	for _, l := range s.warm {
		if !s.interps.Attached(l) {
			return false
		}
	}
	return true
}

// claim hands over the ready member that matches state, may live until expires, and
// warms the most of want: then the one warming the fewest languages beyond want, then
// the oldest. Any member beats none, since creating the container is most of what a
// claim saves. It returns nil when no member may be handed over. The members it finds
// unusable are removed, and the filler is asked to make up the difference.
func (p *dockerPool) claim(state dockerExecutionState, expires time.Time, want []Language) *dockerSession {
	if p == nil {
		return nil
	}
	key := dockerPoolKey(state)
	var got *dockerSession
	var stale []*dockerSession
	p.mu.Lock()
	kept := make([]*dockerSession, 0, len(p.ready))
	for _, s := range p.ready {
		if p.usable(s, key, expires) {
			kept = append(kept, s)
		} else {
			stale = append(stale, s)
		}
	}
	if i := closestMember(kept, want); i >= 0 {
		got = kept[i]
		kept = slices.Delete(kept, i, i+1)
	}
	p.ready = kept
	p.mu.Unlock()
	for _, s := range stale {
		p.discard(s)
	}
	select {
	case p.wake <- struct{}{}:
	default:
	}
	return got
}

// closestMember is the index of the member warming the most of want, then the fewest
// languages beyond it, then the first (the oldest); -1 when there is none.
func closestMember(members []*dockerSession, want []Language) int {
	best, bestHit, bestExtra := -1, 0, 0
	for i, s := range members {
		hit := 0
		for _, l := range s.warm {
			if slices.Contains(want, Language(l)) {
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
// when another set is below its share and the move is worth more than one member
// (poolMoveMargin), so the next add makes one of that set. It moves one member a
// call, so a change in demand costs at most one container start per member moved.
// It reports whether it removed one.
func (p *dockerPool) rebalance() bool {
	p.mu.Lock()
	want, spare, need, over := p.gaps()
	var gone *dockerSession
	if want != "" && spare != "" && need+over > 1+poolMoveMargin {
		for i, s := range p.ready {
			if languageSetKey(s.warm) == spare {
				gone = s
				p.ready = slices.Delete(p.ready, i, i+1)
				break
			}
		}
	}
	p.mu.Unlock()
	if gone == nil {
		return false
	}
	p.discard(gone)
	return true
}

// retire removes members past their idle bound or made under another execution
// state, and members whose relays ended.
func (p *dockerPool) retire() {
	state, err := p.d.executionState()
	if err != nil {
		return
	}
	key := dockerPoolKey(state)
	// expires is now: retire tests only state, age and relays, never the lifetime.
	now := p.now()
	var stale []*dockerSession
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
	p.mu.Unlock()
	for _, s := range stale {
		p.discard(s)
	}
}

// remove removes a member's container off the caller's path; Drain waits for it.
func (p *dockerPool) remove(s *dockerSession) {
	p.d.sessions.mu.Lock()
	p.d.sessions.deletes.Add(1)
	p.d.sessions.mu.Unlock()
	go func() {
		defer p.d.sessions.deletes.Done()
		s.abandon()
	}()
}

func (p *dockerPool) short() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ready) < p.size
}

// run is the filler: it keeps the pool at its size, one member at a time so a burst
// of claims cannot stampede the docker daemon, backing off while members fail.
func (p *dockerPool) run() {
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
			actx, acancel := context.WithTimeout(ctx, dockerPoolAddBudget)
			err := p.add(actx)
			acancel()
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				backoff = time.Second
				continue
			}
			slog.Warn("docker: the session pool could not make a member", "err", err)
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

// close stops the filler, waits for it until ctx ends, and removes every ready
// member. A filler still making a member when ctx ends removes that member itself
// once it sees the pool stopped (add), but possibly after Drain returned; its label
// bounds how long it can outlive the daemon.
func (p *dockerPool) close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.stopOnce.Do(func() { close(p.stop) })
	var err error
	select {
	case <-p.done:
	case <-ctx.Done():
		err = fmt.Errorf("docker: the session pool is still making a member: %w", ctx.Err())
	}
	p.mu.Lock()
	ready := p.ready
	p.ready = nil
	p.mu.Unlock()
	for _, s := range ready {
		p.discard(s)
	}
	return err
}

// members are the names of the ready members, which ReconcileOrphans must not reap.
func (p *dockerPool) members() []string {
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
