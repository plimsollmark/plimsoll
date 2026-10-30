package openshell

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/poolkit"
)

// The openshell session pool keeps never-used session sandboxes ready, each with an
// interpreter started and its relay attached for a set of the languages the image
// runs (sandbox/internal/poolkit says how many, which languages, which a claim takes
// and what the pool keeps to). What is particular to OpenShell:
//
//   - A member is a session sandbox made exactly as OpenSession makes one (the run
//     policy, sleep as the main process, read back and its processes recorded), and
//     its relays are exec streams held open to the gateway, as a session's are.
//   - It is claimed only under the tier and gateway version the last driver check
//     reported; the image, policy and resources are the provider's configuration, and
//     the read-back before every call (the first included) compares them.
//   - Its sandbox declares poolkit.MaxIdle plus the longest lifetime a member may be
//     given, so another instance's ReconcileOrphans reaps a crashed daemon's members
//     within that bound; this instance tracks them, so its own pass never does.
//   - What a session gives up on a gateway other clients can reach holds for a
//     member too: such a client can change the sandbox while it waits, as it can
//     between a session's calls, and the read-back catches only what it compares.

// openshellPool is an openshell provider's session pool.
type openshellPool = poolkit.Pool[*session]

var _ sandbox.SessionPool = (*Provider)(nil)

// poolKey is the execution state a member is made under: the tier and the gateway
// version the driver check reported.
func poolKey(tier sandbox.IsolationClass, version string) string {
	return tier.String() + "\x00" + version
}

// statedLanguages are the languages the image runs, as the smoke test found.
func (p *Provider) statedLanguages() []string {
	langs := p.SessionEnvironments().Project.Languages
	out := make([]string, len(langs))
	for i, l := range langs {
		out[i] = string(l)
	}
	return out
}

// StartSessionPool keeps size never-used session sandboxes ready, each with a set of
// the languages the image runs warm (every one until hints say otherwise), for
// sessions given a lifetime of at most lifetime. It makes the first member before it
// returns, so a pool that cannot make one fails here, and makes the rest in the
// background. Call it once, after EnsureReady (whose smoke test finds the languages);
// Drain stops it.
func (p *Provider) StartSessionPool(ctx context.Context, size int, lifetime time.Duration) error {
	return p.startPool(ctx, p.poolHooks(), size, lifetime)
}

// startPool is StartSessionPool with the hooks given (a test's may warm nothing).
func (p *Provider) startPool(ctx context.Context, h poolkit.Hooks[*session], size int, lifetime time.Duration) error {
	pool, err := poolkit.New(h, size, lifetime, p.statedLanguages())
	if err != nil {
		return err
	}
	// Under the lock Drain sets draining with, so a Drain either finds this pool and
	// stops it or has already begun, and the pool is refused.
	installed := false
	if !p.sessions.Unless(func() { installed = p.sessionPool.CompareAndSwap(nil, pool) }) {
		return errDraining
	}
	if !installed {
		return errors.New("openshell: the session pool is already started")
	}
	if err := pool.Start(ctx); err != nil {
		p.sessionPool.Store(nil)
		return fmt.Errorf("openshell: session pool: %w", err)
	}
	return nil
}

// poolHooks are what the pool asks of the provider.
func (p *Provider) poolHooks() poolkit.Hooks[*session] {
	return poolkit.Hooks[*session]{
		Provider: Name,
		State: func() (string, error) {
			p.mu.Lock()
			tier, version := p.tier, p.version
			p.mu.Unlock()
			if tier == sandbox.IsolationUnknown {
				return "", errors.New("openshell: the isolation tier is unknown until a driver check passes")
			}
			return poolKey(tier, version), nil
		},
		Stated:   p.statedLanguages,
		Make:     p.makePoolMember,
		Attached: func(s *session, lang string) bool { return s.life.Interps.Attached(lang) },
		Name:     func(s *session) string { return s.b.name },
		Discard:  p.discardPoolMember,
		Hold:     sandbox.WithCapacity,
	}
}

// makePoolMember checks the driver, creates a session sandbox declaring label as the
// end of its lifetime, and warms langs in it. A member that fails partway is deleted
// under ctx, so the pool's hold on its place lasts until the gateway confirms it gone.
func (p *Provider) makePoolMember(ctx context.Context, langs []string, label time.Time) (*session, string, error) {
	check, cancel := context.WithTimeout(context.WithoutCancel(ctx), driverCheckBudget)
	tier, err := p.checkDriver(check)
	cancel()
	if err != nil {
		return nil, "", err
	}
	key := poolKey(tier, p.gatewayVersion())
	s, err := p.newSession(ctx, tier, time.Until(label))
	if err != nil {
		return nil, "", err
	}
	for _, l := range langs {
		if err := s.life.Interps.Warm(ctx, s.execFunc, s.attach, l, workDir); err != nil {
			s.life.Abandon()
			p.deleteLater(ctx, s.b)
			return nil, "", fmt.Errorf("starting the %s interpreter: %w", l, err)
		}
	}
	return s, key, nil
}

// discardPoolMember stops a member's relays and interpreters and deletes its sandbox
// off the caller's path, reporting it gone once the gateway confirms it gone; a delete
// that gives up leaves it quarantined, and gone waits for ReconcileOrphans. Drain
// waits for the delete, since the name stays tracked until then.
func (p *Provider) discardPoolMember(s *session, gone func()) {
	s.life.Abandon()
	p.quarantine.Hold(s.b.name, func() {
		p.leases.Untrack(s.b.name)
		gone()
	})
	go p.destroy(s.b)
}

// claimPoolMember counts an open that wants langs toward the pool's demand, then hands
// over the closest member made under tier and the current gateway version that may
// live until expires, or nil when there is no pool or no such member. A warm-only open
// (warmOnly) is refused when it gets nil, so it counts only after a claim that found a
// member: refused warm-only opens cost the caller nothing, and counted they would steer
// the pool to whatever such a caller names (found in review, 2026-10-28).
func (p *Provider) claimPoolMember(tier sandbox.IsolationClass, expires time.Time, langs []sandbox.Language, warmOnly bool) *session {
	pool := p.sessionPool.Load()
	if pool == nil {
		return nil
	}
	want := make([]string, len(langs))
	for i, l := range langs {
		want[i] = string(l)
	}
	if !warmOnly {
		pool.Observe(want)
	}
	s, ok := pool.Claim(poolKey(tier, p.gatewayVersion()), expires, want)
	if ok && warmOnly {
		pool.Observe(want)
	}
	return s
}
