package sandbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/poolkit"
)

// The docker session pool keeps never-used session containers ready, each with an
// interpreter started and its relay attached for a set of the languages the project
// image runs (sandbox/internal/poolkit says how many, which languages, which a claim
// takes and what the pool keeps to). What is particular to docker: a member is a
// session container made exactly as OpenSession makes one, claimed only under the
// execution state the last Preflight verified (daemon, runtime, tier, platform,
// project image and manifest), and its container's lifetime label covers
// poolkit.MaxIdle plus the longest lifetime a member may be given, which
// ReconcileOrphans reaps by.

// dockerPool is a docker provider's session pool.
type dockerPool = poolkit.Pool[*dockerSession]

// dockerPoolKey is the execution state a member was made under; a member is claimed
// only under the same one.
func dockerPoolKey(st dockerExecutionState) string {
	return strings.Join([]string{st.host, st.runtime, st.isolation.String(), st.platform, st.projectImageID, st.projectManifest}, "\x00")
}

// languageNames are langs as the pool names them.
func languageNames[L ~string](langs []L) []string {
	out := make([]string, len(langs))
	for i, l := range langs {
		out[i] = string(l)
	}
	return out
}

// StartSessionPool keeps size never-used session containers ready, each with a set of
// the languages the project image runs warm (every one until hints say otherwise),
// for sessions given a lifetime of at most lifetime. It makes the first member before
// it returns, so a pool that cannot make one fails here, and makes the rest in the
// background. Call it once, after EnsureReady (whose smoke test finds the languages);
// Drain stops it.
func (d *DockerSandbox) StartSessionPool(ctx context.Context, size int, lifetime time.Duration) error {
	if !d.SupportsSessions() {
		return fmt.Errorf("%w: docker sessions need a project image", ErrUnsupported)
	}
	p, err := poolkit.New(d.poolHooks(), size, lifetime, d.statedLanguages())
	if err != nil {
		return err
	}
	// Under the lock Drain sets draining with, so a Drain either finds this pool and
	// stops it or has already begun, and the pool is refused.
	installed := false
	if !d.sessions.Unless(func() { installed = d.pool.CompareAndSwap(nil, p) }) {
		return errDraining
	}
	if !installed {
		return errors.New("docker: the session pool is already started")
	}
	if err := p.Start(ctx); err != nil {
		d.pool.Store(nil)
		return fmt.Errorf("docker: session pool: %w", err)
	}
	return nil
}

// statedLanguages are the languages the project image runs, as the smoke test found.
func (d *DockerSandbox) statedLanguages() []string {
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	return languageNames(d.projectLanguages)
}

// poolHooks are what the pool asks of the provider.
func (d *DockerSandbox) poolHooks() poolkit.Hooks[*dockerSession] {
	return poolkit.Hooks[*dockerSession]{
		Provider: "docker",
		State: func() (string, error) {
			st, err := d.executionState()
			if err != nil {
				return "", err
			}
			return dockerPoolKey(st), nil
		},
		Stated: d.statedLanguages,
		Make:   d.makePoolMember,
		Attached: func(s *dockerSession, lang string) bool {
			return s.life.Interps.Attached(lang)
		},
		Name:    func(s *dockerSession) string { return s.name },
		Discard: d.discardPoolMember,
		Hold:    WithCapacity,
	}
}

// makePoolMember creates a session container under the current execution state, its
// label declaring label, and warms langs in it; a member that fails partway is
// removed under ctx.
func (d *DockerSandbox) makePoolMember(ctx context.Context, langs []string, label time.Time) (*dockerSession, string, error) {
	state, err := d.executionState()
	if err != nil {
		return nil, "", err
	}
	s, err := d.newSessionContainer(ctx, state, label)
	if err != nil {
		return nil, "", err
	}
	for _, l := range langs {
		if err := s.life.Interps.Warm(ctx, s.execFunc, s.attach, l, dockerSessionWork); err != nil {
			s.abandon(ctx)
			return nil, "", fmt.Errorf("starting the %s interpreter: %w", l, err)
		}
	}
	return s, dockerPoolKey(state), nil
}

// discardPoolMember removes a member's container off the caller's path and reports it
// gone once it is confirmed gone; Drain waits for the attempt. The member's place in
// the pool is held as a call's capacity is (WithCapacity): a removal that gives up
// leaves the container quarantined, and the place is given back only when
// ReconcileOrphans confirms it gone, so failing removals cannot let the filler make
// containers past the pool's size (review, 2026-10-24).
func (d *DockerSandbox) discardPoolMember(s *dockerSession, gone func()) {
	removed := d.sessions.Removal()
	go func() {
		defer removed()
		ctx, done := WithCapacity(context.Background(), gone)
		s.abandon(ctx)
		done()
	}()
}
