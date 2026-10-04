package sandbox

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
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

// WatchTeardown returns ctx carrying a watch, and gaveUp, which reports whether a
// provider said a delete under ctx gave up.
func WatchTeardown(ctx context.Context) (watched context.Context, gaveUp func() bool) {
	var failed atomic.Bool
	return context.WithValue(ctx, teardownKey{}, &failed), failed.Load
}

// TeardownGaveUp is what a provider billed by the second calls, with the run's
// context, when it could not delete the run's microVM. Without a watch it does
// nothing.
func TeardownGaveUp(ctx context.Context) {
	if f, ok := ctx.Value(teardownKey{}).(*atomic.Bool); ok {
		f.Store(true)
	}
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
