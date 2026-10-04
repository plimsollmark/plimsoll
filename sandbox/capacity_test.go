package sandbox

import (
	"context"
	"errors"
	"testing"
)

// Capacity comes back once the call has returned and every hold has ended, in either
// order, once; nested admitters are each held; a hold taken without an admitter, or
// after the capacity came back, holds nothing (review F14).
func TestCapacityComesBackWhenTheCallAndItsHoldsHaveEnded(t *testing.T) {
	outer, inner := 0, 0
	ctx, outerDone := WithCapacity(context.Background(), func() { outer++ })
	ctx, innerDone := WithCapacity(ctx, func() { inner++ })

	gone := HoldCapacity(ctx) // the provider's sandbox outlives the call
	innerDone()
	outerDone()
	if outer != 0 || inner != 0 {
		t.Fatalf("given back while the sandbox lives: outer %d, inner %d", outer, inner)
	}
	gone()
	gone()
	if outer != 1 || inner != 1 {
		t.Fatalf("after the sandbox is gone: outer %d, inner %d; want 1 and 1", outer, inner)
	}
	HoldCapacity(ctx)() // too late: nothing is held, nothing is given back twice
	innerDone()
	if outer != 1 || inner != 1 {
		t.Fatalf("a late hold or a second done gave capacity back again: outer %d, inner %d", outer, inner)
	}

	n := 0
	ctx, done := WithCapacity(context.Background(), func() { n++ })
	gone = HoldCapacity(ctx)
	gone() // the sandbox is gone before the call returns
	if n != 0 {
		t.Fatal("given back before the call returned")
	}
	done()
	if n != 1 {
		t.Fatalf("given back %d times; want 1", n)
	}
	HoldCapacity(context.Background())() // no admitter: a no-op
}

// outlivingSandbox's sandboxes outlive their calls: each run takes a HoldCapacity
// and leaves ending it to the test.
type outlivingSandbox struct {
	blockingSandbox
	gone []func()
}

func (o *outlivingSandbox) RunJavaScript(ctx context.Context, _ Request) (Result, error) {
	o.gone = append(o.gone, HoldCapacity(ctx))
	return Result{Sandbox: "fake"}, nil
}

// WithAdmission keeps a run's slot and memory while the provider holds the run's
// capacity past its return, and gives both back when the hold ends.
func TestAdmissionFollowsTheProvidersHold(t *testing.T) {
	inner := &outlivingSandbox{}
	sb, err := WithAdmission(inner, AdmissionConfig{MaxConcurrent: 2, TotalMemoryMB: 256, PerRunMemoryMB: 256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb.RunJavaScript(context.Background(), Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.RunJavaScript(context.Background(), Request{Code: "2"}); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("a run while the first one's sandbox holds the memory budget: %v", err)
	}
	inner.gone[0]()
	if _, err := sb.RunJavaScript(context.Background(), Request{Code: "3"}); err != nil {
		t.Fatalf("a run once the sandbox is gone: %v", err)
	}
}
