package rpc

import (
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/settings"
)

// The defaults the RPC layer states without an environment are the settings table's,
// never typed a second time (finding release-43): the ship scan's wait bound without a
// limiter follows SANDBOX_MAX_CONCURRENT's declared default, and the claim window of a
// session that never suspends is SANDBOX_SESSION_IDLE's. Not parallel: it changes the
// table's declared default for its length.
func TestDefaultsAreTheSettingsTables(t *testing.T) {
	saved := settings.MaxConcurrent.Default
	t.Cleanup(func() { settings.MaxConcurrent.Default = saved })
	for _, c := range []struct {
		declared string
		want     waitBound
	}{{"8", waitBound{all: 8, perCaller: 4}}, {"6", waitBound{all: 6, perCaller: 3}}, {"1", waitBound{all: 1, perCaller: 1}}} {
		settings.MaxConcurrent.Default = c.declared
		if got := NewSandboxService(&fakeSandbox{}).scanWaitBound(); got != c.want {
			t.Errorf("with SANDBOX_MAX_CONCURRENT's default %s, the scan's wait bound without a limiter is %+v; want %+v", c.declared, got, c.want)
		}
	}
	if idle, _ := settings.SessionIdle.Get(settings.Unset); sessionClaimWindow != idle {
		t.Errorf("the claim window is %v; want SANDBOX_SESSION_IDLE's default %v", sessionClaimWindow, idle)
	}
}

// A warm cell's budget is reservation's arithmetic, and the same as the copy it replaced
// (written out here) for every request and statement either side of each bound.
func TestCellBudgetIsTheArithmeticItReplaced(t *testing.T) {
	old := func(requested, stated time.Duration) time.Duration {
		budget := requested
		if budget <= 0 {
			budget = stated
		}
		if budget <= 0 || budget > maxRunTimeout {
			budget = maxRunTimeout
		}
		return budget
	}
	values := []time.Duration{-time.Second, 0, time.Millisecond, 30 * time.Second, maxRunTimeout - 1, maxRunTimeout, maxRunTimeout + 1, time.Hour}
	for _, requested := range values {
		for _, stated := range values {
			if got, want := cellBudget(requested, stated), old(requested, stated); got != want {
				t.Errorf("cellBudget(%v, %v) = %v; the copy it replaced gave %v", requested, stated, got, want)
			}
		}
	}
}
