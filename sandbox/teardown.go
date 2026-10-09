package sandbox

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// A provider billed by the second deletes each run's microVM before it returns,
// retrying within its BillingTeardown. When every try fails, the microVM bills on
// until the provider's own lifetime for it ends, which it set at create: the run's
// deadline plus 10 s on E2B, plus 30 s on Docker Cloud, both within BillingTeardown.
// A caller that meters runs (internal/rpc's SpendCap) watches the call's context with
// WatchTeardown and, when the provider reports TeardownGaveUp, charges the run its
// whole reservation (its timeout plus BillingTeardown, which covers that lifetime)
// instead of the time the call took, so no later call spends seconds the leaked
// microVM is still billing.

type teardownKey struct{}

// teardownWatch is what a watched context carries: whether a delete gave up, and the
// latest time a provider said what it could not delete may bill until (Unix nanoseconds,
// 0 when none said).
type teardownWatch struct {
	failed atomic.Bool
	until  atomic.Int64
}

// WatchTeardown returns ctx carrying a watch, and gaveUp, which reports whether a
// provider said a delete under ctx gave up.
func WatchTeardown(ctx context.Context) (watched context.Context, gaveUp func() bool) {
	w := &teardownWatch{}
	return context.WithValue(ctx, teardownKey{}, w), w.failed.Load
}

// WatchTeardownUntil is WatchTeardown for a caller that needs, beside whether a delete
// gave up, until when what was not deleted may bill (zero when the provider did not
// say): a failed session open, whose sandbox has no run's reservation to cover it.
func WatchTeardownUntil(ctx context.Context) (watched context.Context, gaveUp func() (bool, time.Time)) {
	w := &teardownWatch{}
	return context.WithValue(ctx, teardownKey{}, w), func() (bool, time.Time) {
		if n := w.until.Load(); n != 0 {
			return w.failed.Load(), time.Unix(0, n)
		}
		return w.failed.Load(), time.Time{}
	}
}

// TeardownGaveUp is what a provider billed by the second calls, with the run's
// context, when it could not delete the run's microVM. Without a watch it does
// nothing.
func TeardownGaveUp(ctx context.Context) {
	if w, ok := ctx.Value(teardownKey{}).(*teardownWatch); ok {
		w.failed.Store(true)
	}
}

// TeardownGaveUpUntil is TeardownGaveUp with the time the microVM may bill until: the
// end of the provider's own lifetime for it. The latest one said is kept.
func TeardownGaveUpUntil(ctx context.Context, until time.Time) {
	w, ok := ctx.Value(teardownKey{}).(*teardownWatch)
	if !ok {
		return
	}
	w.failed.Store(true)
	for n := until.UnixNano(); ; {
		old := w.until.Load()
		if n <= old || w.until.CompareAndSwap(old, n) {
			return
		}
	}
}

// BillsUntiler is a Session on a provider billed by the second whose sandbox can
// outlive its end: after Done, BillsUntil is when the provider's own lifetime for the
// sandbox ends if its delete gave up, and zero when it was deleted. A caller that
// charges sessions for their time charges until then.
type BillsUntiler interface {
	BillsUntil() time.Time
}

// requestNeverLeft reports whether err, from sending a create request, proves the
// request never reached the provider: a failed name lookup or a failed dial, both
// before any byte of it was written. Every other error (a reset, a deadline reached
// mid-request, an answer lost, a transport that reports its failures its own way)
// leaves open whether the provider acted on it, so a create that failed with one may
// have made a microVM that bills, and its run is charged as one whose delete gave up.
func requestNeverLeft(err error) bool {
	var dns *net.DNSError
	var op *net.OpError
	return errors.As(err, &dns) || errors.As(err, &op) && op.Op == "dial"
}
