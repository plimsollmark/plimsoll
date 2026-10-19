// Package providerkit holds what the providers that run each payload in a sandbox reached over
// an API (openshell, agentsandbox) share: output capping, timeout clamping, deadline-aware
// errors, a cancellable sleep, a cached readiness check and a retried delete.
package providerkit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
)

// Capture keeps the first Limit bytes written to it and records whether it dropped any.
// The retained prefix is never annotated in-band.
type Capture struct {
	Buf     []byte
	Limit   int
	Dropped bool
}

func (c *Capture) Write(p []byte) {
	if room := c.Limit - len(c.Buf); room > 0 {
		if len(p) > room {
			c.Buf = append(c.Buf, p[:room]...)
			c.Dropped = true
		} else {
			c.Buf = append(c.Buf, p...)
		}
	} else if len(p) > 0 {
		c.Dropped = true
	}
}

// ClampTimeout is the request's timeout, def when it asks for none, and never past max.
func ClampTimeout(req, def, max time.Duration) time.Duration {
	if req <= 0 {
		req = def
	}
	return min(req, max)
}

// DeadlineAware keeps the caller's deadline recognizable: work that ran out of time is
// reported as context.DeadlineExceeded rather than as whatever transport error the
// cancelled call produced.
func DeadlineAware(ctx context.Context, err error) error {
	if ctxErr := deadline.Expired(ctx); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("%w: %v", ctxErr, err)
	}
	return err
}

// Sleep waits d, or until ctx ends.
func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Check is a readiness check whose answer is reused for TTL. The daemon serves /readyz
// without authentication and every check here is calls to a remote API, so without it
// anyone who can reach /readyz could make the daemon call that API as fast as they can
// send requests. A call made while a check is in flight gets the last answer at once (Err
// before any check has finished), and a check runs detached from its caller's
// cancellation under its own budget, so a poll that hangs up cannot leave its own
// cancellation as the cached answer.
type Check struct {
	TTL time.Duration
	Err error // the answer before any check has finished

	mu      sync.Mutex
	at      time.Time
	running bool
}

// Run runs check, or returns the cached answer.
func (c *Check) Run(ctx context.Context, budget time.Duration, check func(context.Context) error) error {
	c.mu.Lock()
	if c.running || (!c.at.IsZero() && time.Since(c.at) < c.TTL) {
		err := c.Err
		c.mu.Unlock()
		return err
	}
	c.running = true
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
	defer cancel()
	err := check(ctx)
	c.mu.Lock()
	c.at, c.Err, c.running = time.Now(), err, false
	c.mu.Unlock()
	return err
}

// deleteAttempts is how many times Delete tries.
const deleteAttempts = 3

// Delete runs attempt on its own context of budget, so it still runs after the run's
// context has ended, up to three times, waiting a second longer after each failure. It
// returns how many attempts it made and the last error, nil once one succeeded.
func Delete(budget time.Duration, attempt func(context.Context) error) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	for i := 1; ; i++ {
		err := attempt(ctx)
		if err == nil || i == deleteAttempts || ctx.Err() != nil {
			return i, err
		}
		if Sleep(ctx, time.Duration(i)*time.Second) != nil {
			return i, err
		}
	}
}
