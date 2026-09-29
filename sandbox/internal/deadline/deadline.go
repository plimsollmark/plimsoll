// Package deadline holds the one rule every provider uses to decide that a run
// timed out.
package deadline

import (
	"context"
	"time"
)

// Expired is ctx.Err(), or context.DeadlineExceeded once ctx's deadline has passed
// although the context's timer has not fired yet. A provider that tells a remote end
// the deadline (a gateway, an in-guest timeout, a propagated Connect timeout) can see
// the call end on it before that timer runs: on a loaded machine an OpenShell exec
// stream's deadline error arrived 2 ms past the deadline with ctx.Err() still nil, and
// a user's endless loop was reported as a gateway failure instead of a timeout
// (measured 2026-09-29). A run that reached its deadline timed out, whichever side
// noticed first.
func Expired(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
		return context.DeadlineExceeded
	}
	return nil
}
