package sandbox

import (
	"context"
	"slices"
	"sync"
)

// A call's capacity (a concurrency slot, and with it a share of the memory budget) is
// given back when its sandbox is gone, not when the call returns. Most providers
// delete the sandbox before returning. One that deletes it afterwards, to keep a slow
// delete off the result path (openshell, about 5 s), would otherwise free the slot
// while the sandbox, and any process the run left in it, still lives (review F14).
//
// So an admitter (the RPC limiter, WithAdmission) wraps its release with WithCapacity
// and calls the function it returns when the call returns, and such a provider calls
// HoldCapacity during the call and the function it returns once the sandbox is gone.
// The release runs when the last of the two has happened.

type capacityKey struct{}

// capacityHold is one admitter's grant: its release runs when the count of the call
// and the holds taken under it reaches zero, once.
type capacityHold struct {
	mu       sync.Mutex
	n        int
	released bool
	release  func()
}

func (h *capacityHold) add() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.released {
		return false
	}
	h.n++
	return true
}

func (h *capacityHold) done() {
	h.mu.Lock()
	h.n--
	last := h.n == 0 && !h.released
	if last {
		h.released = true
	}
	h.mu.Unlock()
	if last {
		h.release()
	}
}

// WithCapacity returns ctx carrying release, which gives back what an admitter granted
// for one call, and the function the admitter calls when the call returns, in place of
// release: release then runs once the call has returned and every HoldCapacity taken
// under the returned context has ended. The returned function does nothing after its
// first call. Admitters nest: a hold keeps each of them.
func WithCapacity(ctx context.Context, release func()) (context.Context, func()) {
	h := &capacityHold{n: 1, release: release}
	parent, _ := ctx.Value(capacityKey{}).([]*capacityHold)
	var once sync.Once
	return context.WithValue(ctx, capacityKey{}, append(slices.Clip(parent), h)), func() { once.Do(h.done) }
}

// HoldCapacity keeps the capacity admitted for the call ctx belongs to until the
// returned function is called, past the call's return. A provider whose sandbox
// outlives the call takes it before returning and calls the function once the sandbox
// is gone, on every path (a delete that gave up included: that sandbox is then the
// orphan reaper's). Without an admitter in ctx, or taken after the call's capacity was
// already given back, it holds nothing. The returned function does nothing after its
// first call.
func HoldCapacity(ctx context.Context) func() {
	all, _ := ctx.Value(capacityKey{}).([]*capacityHold)
	var held []*capacityHold
	for _, h := range all {
		if h.add() {
			held = append(held, h)
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for _, h := range held {
				h.done()
			}
		})
	}
}
