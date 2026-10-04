package rpc

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// A metered provider (sandbox.Metered: E2B, Docker Cloud) bills the operator for every
// second a run's microVM exists, so a caller's request rate is the operator's bill. A
// rate limit bounds runs per minute, not seconds per day. SpendCap bounds the seconds:
// a caller's own daily allowance (its paid_seconds_per_day in PLIMSOLL_CLIENTS_FILE) and
// one daemon-wide allowance (SANDBOX_PAID_SECONDS_PER_DAY), both in seconds of wall
// time measured by the daemon around the provider call, which covers the microVM's
// create, the run and its delete. A run whose microVM the provider could not delete
// (sandbox.TeardownGaveUp) is charged its whole reservation instead: the microVM bills
// until the provider's own lifetime for it ends, the run's deadline plus 10 s on E2B
// or 30 s on Docker Cloud, which the reservation's teardown bound covers. Days are UTC
// calendar days.
//
// A UTC day's counters hold what ran in it: a run that crosses midnight is counted in
// the new day for the part it ran after midnight (today).
//
// The allowances are per daemon: daemons sharing one clients file each keep their own
// counts, and placement retries a refused call on another backend, so a caller with
// allowance N on K daemons can spend K times N. And the counters live in memory:
// plimsoll stores nothing, so a restart forgets the day's spend, the caller's and the
// daemon's alike, and a caller can spend its allowance again after one.

// SpendCap holds today's spend per caller and in total.
type SpendCap struct {
	// Total is the daemon-wide allowance in seconds per UTC day; 0 = none.
	Total int64
	now   func() time.Time

	mu     sync.Mutex
	day    string
	total  float64
	caller map[string]float64
	open   map[*held]struct{} // reservations not yet settled

	// refusedCaller and refusedDaemon count refusals, for /metrics.
	refusedCaller, refusedDaemon atomic.Int64
}

// Refused reports how many runs were refused for a caller's allowance and for the
// daemon's.
func (c *SpendCap) Refused() (caller, daemon int64) {
	if c == nil {
		return 0, 0
	}
	return c.refusedCaller.Load(), c.refusedDaemon.Load()
}

// NewSpendCap returns a cap with a daemon-wide allowance of total seconds a day (0 =
// none); each caller's own comes with its principal.
func NewSpendCap(total int64) *SpendCap {
	return &SpendCap{Total: total, now: time.Now}
}

// held is one run's reservation until it settles.
type held struct {
	principal string
	want      float64   // seconds reserved
	start     time.Time // when they were
	day       string    // the UTC day they are counted in now
	carried   bool      // reserved the day before day, still running at its midnight
}

// today rolls the counters over at a new UTC day. A run reserved before midnight and
// still running is counted in the new day as well, in full until it settles, then for
// the part it ran after midnight: a run crossing midnight spends seconds of both days.
// Call with mu held.
func (c *SpendCap) today() string {
	d := c.now().UTC().Format(time.DateOnly)
	if d != c.day {
		c.day, c.total, c.caller = d, 0, map[string]float64{}
		for h := range c.open {
			h.day, h.carried = d, true
			c.caller[h.principal] += h.want
			c.total += h.want
		}
	}
	return d
}

// reserve takes reserved seconds from the caller's allowance (perCaller, 0 = none) and
// the daemon's, refusing not dispatched, reason capacity, when either would go over.
// The returned settle charges what the run took, at most what was reserved, and gives
// the rest back; it returns the seconds charged. A run that crossed midnight is
// charged to the new day for the part it ran after midnight (today).
func (c *SpendCap) reserve(principal string, perCaller int64, reserved time.Duration) (settle func(took time.Duration) float64, err error) {
	want := reserved.Seconds()
	c.mu.Lock()
	defer c.mu.Unlock()
	day := c.today()
	if perCaller > 0 && c.caller[principal]+want > float64(perCaller) {
		c.refusedCaller.Add(1)
		return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity, fmt.Errorf(
			"paid budget: this caller has %d of its %d paid seconds left on this daemon until 00:00 UTC, and this run reserves %d (its timeout plus the provider's teardown); a shorter timeout reserves less",
			left(perCaller, c.caller[principal]), perCaller, int64(math.Ceil(want))))
	}
	if c.Total > 0 && c.total+want > float64(c.Total) {
		// No numbers: they would tell one caller what the others spent.
		c.refusedDaemon.Add(1)
		return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity, errors.New(
			"paid budget: the daemon's allowance for today cannot cover this run until 00:00 UTC; a shorter timeout reserves less"))
	}
	c.caller[principal] += want
	c.total += want
	h := &held{principal: principal, want: want, start: c.now(), day: day}
	if c.open == nil {
		c.open = map[*held]struct{}{}
	}
	c.open[h] = struct{}{}
	var once sync.Once
	charged := 0.0
	return func(took time.Duration) float64 {
		once.Do(func() {
			charged = min(max(took.Seconds(), 0), want)
			c.mu.Lock()
			defer c.mu.Unlock()
			// Roll over first: a run whose settle is the first thing after midnight
			// is carried into the new day like one that settles later.
			c.today()
			delete(c.open, h)
			if h.day != c.day {
				return // counted in a day that has ended
			}
			counted := charged
			if h.carried {
				midnight, _ := time.Parse(time.DateOnly, h.day)
				counted = min(max(h.start.Add(took).Sub(midnight).Seconds(), 0), charged)
			}
			c.caller[principal] -= want - counted
			c.total -= want - counted
		})
		return charged
	}, nil
}

func left(allowance int64, spent float64) int64 {
	return max(0, allowance-int64(math.Ceil(spent)))
}

// spent reports today's seconds for one caller and in total, for tests and the log.
func (c *SpendCap) spent(principal string) (caller, total float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.today()
	return c.caller[principal], c.total
}
