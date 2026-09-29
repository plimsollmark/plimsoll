package deadline

import (
	"context"
	"testing"
	"time"
)

// lateTimer is a context whose deadline has passed but whose timer has not fired:
// Err is still nil. A loaded machine produces exactly this.
type lateTimer struct {
	context.Context
	deadline time.Time
}

func (c lateTimer) Deadline() (time.Time, bool) { return c.deadline, true }
func (c lateTimer) Err() error                  { return nil }

// TestExpiredDoesNotWaitForTheTimer pins the timeout classification against the
// context's timer running late. Before this rule, 4 of 10 runs of openshell's
// TestRunJavaScriptTimeout failed under -race with 36 busy processes on 24 CPUs, the
// run reported as a gateway error; 0 of 30 after (2026-09-29).
func TestExpiredDoesNotWaitForTheTimer(t *testing.T) {
	if err := Expired(lateTimer{context.Background(), time.Now().Add(-2 * time.Millisecond)}); err != context.DeadlineExceeded {
		t.Fatalf("a passed deadline with the timer not yet fired: %v, want DeadlineExceeded", err)
	}
	if err := Expired(lateTimer{context.Background(), time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("a deadline an hour away: %v", err)
	}
	if err := Expired(context.Background()); err != nil {
		t.Fatalf("no deadline: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Expired(cancelled); err != context.Canceled {
		t.Fatalf("a cancelled context: %v, want Canceled", err)
	}
}
