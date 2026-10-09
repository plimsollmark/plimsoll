package sandbox

import (
	"context"
	"testing"
	"time"
)

// A gave-up signal keeps the latest end any provider reported, and a provider that
// reports none still marks the delete given up, with no end.
func TestTeardownGaveUpUntilKeepsTheLatestEnd(t *testing.T) {
	ctx, gaveUp := WatchTeardownUntil(context.Background())
	if gave, until := gaveUp(); gave || !until.IsZero() {
		t.Fatalf("before any report: %v %v", gave, until)
	}
	late, early := time.Now().Add(time.Hour), time.Now().Add(time.Minute)
	TeardownGaveUpUntil(ctx, late)
	TeardownGaveUpUntil(ctx, early)
	if gave, until := gaveUp(); !gave || until.UnixNano() != late.UnixNano() {
		t.Fatalf("after two reports: %v %v; want the later end %v", gave, until, late)
	}
	ctx, gaveUp = WatchTeardownUntil(context.Background())
	TeardownGaveUp(ctx)
	if gave, until := gaveUp(); !gave || !until.IsZero() {
		t.Fatalf("a report with no end: %v %v; want given up, no end", gave, until)
	}
	// The plain watch still sees an until report as given up.
	pctx, plain := WatchTeardown(context.Background())
	TeardownGaveUpUntil(pctx, late)
	if !plain() {
		t.Fatal("WatchTeardown missed a report that named an end")
	}
}
