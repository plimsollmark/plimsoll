package rpc

import (
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

// held is one run's reservation until it settles, or a sandbox still billing after its
// delete gave up (owed) until that billing ends.
type held struct {
	principal string
	want      float64   // seconds reserved
	start     time.Time // when they were
	day       string    // the UTC day they are counted in now
	carried   bool      // reserved the day before day, still running at its midnight
	// owed: a sandbox nothing of plimsoll's uses any more bills until until (its delete
	// gave up). Already charged in full; it stays open only so each midnight before
	// until counts the part after that midnight in the new day.
	owed  bool
	until time.Time
}

// today rolls the counters over at a new UTC day. A run reserved before midnight and
// still running is counted in the new day as well, in full until it settles, then for
// the part it ran after midnight: a run crossing midnight spends seconds of both days.
// Call with mu held.
func (c *SpendCap) today() string {
	d := c.now().UTC().Format(time.DateOnly)
	if d != c.day {
		c.day, c.total, c.caller = d, 0, map[string]float64{}
		midnight, _ := time.Parse(time.DateOnly, d)
		for h := range c.open {
			if h.owed {
				// A leaked sandbox's billing after midnight is the new day's.
				if !h.until.After(midnight) {
					delete(c.open, h)
					continue
				}
				rest := h.until.Sub(midnight).Seconds()
				c.caller[h.principal] += rest
				c.total += rest
				continue
			}
			h.day, h.carried = d, true
			c.caller[h.principal] += h.want
			c.total += h.want
		}
	}
	return d
}

// owe charges principal, and the daemon, for a sandbox nothing of plimsoll's uses any
// more that bills until until because its delete gave up: from now to until, counted
// in today, and for the part past each midnight in that day too. It is never refused:
// the seconds are billed whether or not an allowance has room, and charging them keeps
// later runs from spending them twice. It returns the seconds charged now.
func (c *SpendCap) owe(principal string, until time.Time) float64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.today()
	now := c.now()
	secs := until.Sub(now).Seconds()
	if secs <= 0 {
		return 0
	}
	c.caller[principal] += secs
	c.total += secs
	if c.open == nil {
		c.open = map[*held]struct{}{}
	}
	c.open[&held{principal: principal, want: secs, start: now, day: c.day, owed: true, until: until}] = struct{}{}
	return secs
}

// reserve takes reserved seconds from the caller's allowance (perCaller, 0 = none) and
// the daemon's, refusing not dispatched, reason capacity, when either would go over.
// The returned settle charges what the run took, at most what was reserved, and gives
// the rest back; it returns the seconds charged. A run that crossed midnight is
// charged to the new day for the part it ran after midnight (today). billsUntil is,
// for a run whose delete gave up, when the provider said its sandbox may bill until
// (zero when it did not say): the run owes until then, not only until its
// reservation's window ends (leak).
func (c *SpendCap) reserve(principal string, perCaller int64, reserved time.Duration) (settle func(took time.Duration, billsUntil time.Time) float64, err error) {
	c.mu.Lock()
	h, err := c.take(principal, perCaller, reserved.Seconds(), runRefusal)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	charged := 0.0
	return func(took time.Duration, billsUntil time.Time) float64 {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			charged = c.give(h, took)
			if charged >= h.want {
				charged += c.leak(h, billsUntil)
			}
		})
		return charged
	}, nil
}

// leak carries a settled run's debt to billsUntil, when the provider said its sandbox
// bills past the window the reservation covered: the seconds after that window (or
// after now, if it has closed) are charged to today, and the hold stays owed until
// billsUntil, so each midnight before then counts the rest in the new day. Without
// this, a slow create's sandbox billed past the window while the books let it go at
// the window's end, and at a midnight in between (round-7 review, 2026-10-08). It
// returns the seconds charged; c.mu is held.
func (c *SpendCap) leak(h *held, billsUntil time.Time) float64 {
	end := h.start.Add(time.Duration(h.want * float64(time.Second)))
	if !billsUntil.After(end) {
		return 0
	}
	now := c.now()
	from := end
	if now.After(from) {
		from = now
	}
	extra := billsUntil.Sub(from).Seconds()
	if extra <= 0 {
		return 0
	}
	c.today()
	c.caller[h.principal] += extra
	c.total += extra
	if c.open == nil {
		c.open = map[*held]struct{}{}
	}
	h.owed, h.until = true, billsUntil
	c.open[h] = struct{}{}
	return extra
}

// refusalText says what a refused reservation was for, in the caller's refusal: the
// subject and what its reservation is made of.
type refusalText struct{ subject, parts, shorter string }

var (
	runRefusal     = refusalText{"this run", "its timeout plus the provider's teardown", "a shorter timeout reserves less"}
	sessionRefusal = refusalText{"this session", "its call's timeout, the idle time before it is paused, and the provider's teardown",
		"a shorter timeout or idle timeout reserves less"}
)

// take reserves want seconds for principal, as reserve does; c.mu is held.
func (c *SpendCap) take(principal string, perCaller int64, want float64, why refusalText) (*held, error) {
	day := c.today()
	if perCaller > 0 && c.caller[principal]+want > float64(perCaller) {
		c.refusedCaller.Add(1)
		return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity, fmt.Errorf(
			"paid budget: this caller has %d of its %d paid seconds left on this daemon until 00:00 UTC, and %s reserves %d (%s); %s",
			left(perCaller, c.caller[principal]), perCaller, why.subject, int64(math.Ceil(want)), why.parts, why.shorter))
	}
	if c.Total > 0 && c.total+want > float64(c.Total) {
		// No numbers: they would tell one caller what the others spent.
		c.refusedDaemon.Add(1)
		return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity, fmt.Errorf(
			"paid budget: the daemon's allowance for today cannot cover %s until 00:00 UTC; %s", why.subject, why.shorter))
	}
	c.caller[principal] += want
	c.total += want
	h := &held{principal: principal, want: want, start: c.now(), day: day}
	if c.open == nil {
		c.open = map[*held]struct{}{}
	}
	c.open[h] = struct{}{}
	return h, nil
}

// give settles h: it charges took, at most what h reserved, gives the rest back, and
// returns the seconds charged; c.mu is held.
func (c *SpendCap) give(h *held, took time.Duration) float64 {
	charged := min(max(took.Seconds(), 0), h.want)
	// Roll over first: a run whose settle is the first thing after midnight is
	// carried into the new day like one that settles later.
	c.today()
	delete(c.open, h)
	// Charged its whole reservation while the window it covers is still open: the run's
	// delete gave up and its microVM bills until that window ends (sandbox.WatchTeardown).
	// It stays open as owed, so a midnight before then counts the rest in the new day
	// (round-3 review: settled before midnight, the liability left the books).
	if end := h.start.Add(time.Duration(h.want * float64(time.Second))); charged >= h.want && end.After(c.now()) {
		h.owed, h.until = true, end
		c.open[h] = struct{}{}
	}
	if h.day != c.day {
		return charged // counted in a day that has ended
	}
	counted := charged
	if h.carried {
		midnight, _ := time.Parse(time.DateOnly, h.day)
		counted = min(max(h.start.Add(took).Sub(midnight).Seconds(), 0), charged)
	}
	c.caller[h.principal] -= h.want - counted
	c.total -= h.want - counted
	return charged
}

// A session on a metered provider bills for every second its sandbox runs, calls or
// not, from the open until a suspend stops it (a paused E2B sandbox bills no compute)
// and from the call that resumes it until the next, or until the sandbox is deleted.
// A sessionMeter charges that time to the same allowances runs draw on: while the
// session runs it holds one reservation reaching to the latest moment the session
// could still be running before its idle suspend, renewed by every call, and settled
// at a suspend and at the end.
type sessionMeter struct {
	c         *SpendCap
	principal string
	perCaller int64

	mu      sync.Mutex
	h       *held     // the running span's reservation; nil while suspended or ended
	since   time.Time // when h was taken
	charged float64   // seconds charged so far, for the log
}

func (c *SpendCap) meter(principal string, perCaller int64) *sessionMeter {
	return &sessionMeter{c: c, principal: principal, perCaller: perCaller}
}

// cover makes the reservation reach want from now. With nothing held (an open, or a
// call that resumes the session) it takes want. Otherwise, unless what is held reaches
// that far already, it charges what ran since the last cover and takes want from now,
// in one step under the cap's lock. A refusal (capacity, not dispatched) leaves the
// session covered as far as it was.
func (m *sessionMeter) cover(want time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.c
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if m.h == nil {
		h, err := c.take(m.principal, m.perCaller, want.Seconds(), sessionRefusal)
		if err != nil {
			return err
		}
		m.h, m.since = h, now
		return nil
	}
	ran := now.Sub(m.since)
	held := time.Duration(m.h.want * float64(time.Second))
	if ran+want <= held {
		return nil
	}
	m.charged += c.give(m.h, ran)
	h, err := c.take(m.principal, m.perCaller, want.Seconds(), sessionRefusal)
	if err != nil {
		// What the old reservation still covered was just given back, under this same
		// lock, so it can be taken again: the session stays covered to where it was.
		rest := max(held-ran, 0)
		m.h, _ = c.take(m.principal, m.perCaller, rest.Seconds(), sessionRefusal)
		m.since = now
		return err
	}
	m.h, m.since = h, now
	return nil
}

// stop charges what ran since the last cover and holds nothing more: the session was
// suspended, or its sandbox is gone. It returns the session's seconds charged so far.
func (m *sessionMeter) stop() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.h != nil {
		m.c.mu.Lock()
		m.charged += m.c.give(m.h, m.c.now().Sub(m.since))
		m.c.mu.Unlock()
		m.h = nil
	}
	return m.charged
}

// running reports whether the meter holds a reservation: the session's sandbox runs.
func (m *sessionMeter) running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.h != nil
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
