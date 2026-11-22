package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// readyCache is the daemon's one bound on what /readyz costs, in front of every
// provider's Preflight. /readyz needs no credential, and a provider's Preflight can be a
// process launch (wslc starts wslc.exe over WSL interop on every call) or a remote call,
// so without it anyone who can reach the listener decides how often the daemon pays for
// one: one HTTP/2 connection carried 250 checks at once (hunt-security-2, 2026-11-20).
//
// At most one Preflight is in flight. Its answer, failure as well as success, is reused
// for readyWindow after the check ended. A request that arrives while a check runs
// waits for that check's answer, up to its own request's end, and never starts another.
// The check runs detached from every request, under readyBudget: a poller that hangs up
// can neither cancel it nor leave its own cancellation as the answer.
//
// It differs from providerkit.Check (openshell's and agentsandbox's cache) in one
// respect: a request that arrives during a check waits for it instead of being given the
// previous answer at once, so an answer older than the window is never served.
// cmd/plimsolld cannot import sandbox/internal/providerkit, and moving Check out would
// change what those two providers answer during a check; the daemon's cache is therefore
// its own, here, and nothing new is exported.
type readyCache struct {
	pf     sandbox.Preflighter
	window time.Duration
	budget time.Duration
	now    func() time.Time

	mu     sync.Mutex
	have   bool      // a check has ended
	at     time.Time // when the last check ended
	err    error     // its answer
	flight chan struct{}
}

const (
	// readyWindow is how long one Preflight answer stands. Kubernetes polls a readiness
	// endpoint every 10 s unless told otherwise (periodSeconds' default), so at half that
	// every poll at the default period still gets a check of its own, and pollers that
	// ask faster share one; a flood gets one check per 5 s. It is also the window the
	// providers' own caches already use (docker, openshell, agentsandbox: 5 s), so it adds
	// no staleness they did not already have. Readiness changes when a daemon, gateway or
	// runtime goes away, which nothing reports sooner than the next check anyway.
	readyWindow = 5 * time.Second
	// readyBudget bounds one detached check, and is the budget the maintenance loop gives
	// a Preflight too. It sits above every provider's own bound, so a slow check is the
	// provider's to report: that bound is sandbox.PreflightBound, which every in-tree
	// provider's check is held under where its number is declared, and this budget is
	// computed from it. Until 2026-11-20 it was 30 s typed here and again in the
	// maintenance loop, beside a comment naming docker's 10 s, while wslc's own bound was
	// 30 s, so not under it (hunt-quality-58); the margin is a judgment.
	readyBudget = sandbox.PreflightBound + readyMargin
	readyMargin = 10 * time.Second
)

func newReadyCache(pf sandbox.Preflighter) *readyCache {
	return &readyCache{pf: pf, window: readyWindow, budget: readyBudget, now: time.Now}
}

// check returns the provider's readiness: the standing answer, or the answer of the check
// in flight (starting one if none is), or an error if ctx ends first.
func (c *readyCache) check(ctx context.Context) error {
	c.mu.Lock()
	if c.have && c.now().Sub(c.at) < c.window {
		err := c.err
		c.mu.Unlock()
		return err
	}
	if c.flight == nil {
		c.flight = make(chan struct{})
		go c.run(c.flight)
	}
	done := c.flight
	c.mu.Unlock()
	select {
	case <-done:
		c.mu.Lock()
		err := c.err
		c.mu.Unlock()
		return err
	case <-ctx.Done():
		return fmt.Errorf("the request ended before the readiness check did: %w", ctx.Err())
	}
}

func (c *readyCache) run(done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), c.budget)
	defer cancel()
	var err error
	func() {
		// This goroutine is the daemon's, not a request's: a provider that panics in
		// Preflight is not ready, and must not take the daemon down.
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("the provider's readiness check panicked: %v", r)
			}
		}()
		err = c.pf.Preflight(ctx)
	}()
	c.mu.Lock()
	c.have, c.at, c.err, c.flight = true, c.now(), err, nil
	c.mu.Unlock()
	close(done)
}
