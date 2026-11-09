package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// A call the daemon refuses at capacity, marked not dispatched, is sent again until it
// clears; a refusal for any other reason, an unmarked capacity error and one that outlasts
// the patience come back at once or when it runs out.
func TestWhenFreeResendsOnlyMarkedCapacityRefusals(t *testing.T) {
	w, wm, p := capacityWait, capacityWaitMax, capacityPatience
	capacityWait, capacityWaitMax, capacityPatience = time.Millisecond, 2*time.Millisecond, time.Second
	defer func() { capacityWait, capacityWaitMax, capacityPatience = w, wm, p }()
	ctx := context.Background()
	full := sandbox.NotDispatched(sandbox.RefusalCapacity, errors.Join(sandbox.ErrAtCapacity, errors.New("rate limit: 30 runs/min per caller")))

	sends := 0
	v, err := whenFree(ctx, "t", func() (int, error) {
		if sends++; sends < 4 {
			return 0, full
		}
		return 7, nil
	})
	if err != nil || v != 7 || sends != 4 {
		t.Fatalf("capacity refused three times then answered: got %d, %v after %d sends, want 7, nil after 4", v, err, sends)
	}

	for name, e := range map[string]error{
		"refused for the request":    sandbox.NotDispatched(sandbox.RefusalRequest, sandbox.ErrInvalidRequest),
		"capacity with no mark":      sandbox.ErrAtCapacity,
		"an error that may have run": errors.New("connection reset"),
	} {
		sends = 0
		if _, err := whenFree(ctx, "t", func() (int, error) { sends++; return 0, e }); !errors.Is(err, e) || sends != 1 {
			t.Errorf("%s: %v after %d sends, want it back after 1", name, err, sends)
		}
	}

	capacityPatience = 20 * time.Millisecond
	sends = 0
	start := time.Now()
	if _, err := whenFree(ctx, "t", func() (int, error) { sends++; return 0, full }); !errors.Is(err, sandbox.ErrAtCapacity) || sends < 2 {
		t.Errorf("never free: %v after %d sends, want the refusal back after several", err, sends)
	}
	if time.Since(start) > time.Second {
		t.Errorf("never free: gave up after %s, want about the patience", time.Since(start))
	}

	cctx, cancel := context.WithCancel(ctx)
	capacityPatience = time.Minute
	sends = 0
	if _, err := whenFree(cctx, "t", func() (int, error) { sends++; cancel(); return 0, full }); !errors.Is(err, context.Canceled) || sends != 1 {
		t.Errorf("cancelled while waiting: %v after %d sends, want context.Canceled after 1", err, sends)
	}
}
