package rpc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
)

// bucket is a per-principal token bucket: tokens refill continuously at
// refillPerSec up to a capacity (burst), so the enforced start-rate is smooth with
// an explicit, tunable burst — unlike a fixed window, which lets a caller fire a
// full window's worth at the end of one window and again right after it resets
// (~2× the intended rate in a sub-second span).
type bucket struct {
	tokens float64
	last   time.Time
}

// CodeLimiter is admission control for sandbox runs. It sheds load (never queues)
// so a flood cannot pile up goroutines or containers, and enforces three
// independent limits so no single principal can monopolize the shared pool:
//
//   - a GLOBAL concurrency cap (total in-flight runs);
//   - a PER-PRINCIPAL concurrency cap (in-flight runs for one key), so one caller
//     holding long-lived runs cannot starve everyone else out of the global pool;
//   - a PER-PRINCIPAL rate (token bucket), smoothing starts/min with a bounded burst.
type CodeLimiter struct {
	sem    chan struct{} // global concurrency
	perKey int           // max in-flight per principal (<=0 = only the global cap)
	perMin int           // sustained starts/min per principal (<=0 = no rate limit)
	burst  float64       // token-bucket capacity
	refill float64       // tokens per second (perMin/60)

	mu       sync.Mutex
	inflight map[string]int // in-flight runs per key
	buckets  map[string]*bucket
	lastTrim time.Time

	// observability counters (design-review #9): why load was shed.
	atCapacity  atomic.Int64 // global pool full
	perKeyFull  atomic.Int64 // per-principal concurrency cap hit
	rateLimited atomic.Int64 // per-principal rate exceeded
}

// NewCodeLimiter builds a limiter.
//
//	maxConcurrent: global in-flight cap (clamped to >=1).
//	perKeyConcurrent: max in-flight per principal (<=0 disables the per-key cap).
//	perMinute: sustained starts/min per principal (<=0 disables rate limiting).
//	burst: token-bucket capacity (<=0 defaults to perMinute, i.e. one minute of runs).
func NewCodeLimiter(maxConcurrent, perKeyConcurrent, perMinute, burst int) *CodeLimiter {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	b := float64(burst)
	if b <= 0 {
		b = float64(perMinute)
	}
	return &CodeLimiter{
		sem:      make(chan struct{}, maxConcurrent),
		perKey:   perKeyConcurrent,
		perMin:   perMinute,
		burst:    b,
		refill:   float64(perMinute) / 60.0,
		inflight: make(map[string]int),
		buckets:  make(map[string]*bucket),
	}
}

// Acquire reserves a slot for key. The returned release func must be called when
// the run finishes. On any limit it returns a connect ResourceExhausted error and
// reserves nothing (all partial reservations are rolled back).
func (l *CodeLimiter) Acquire(_ context.Context, key string) (func(), error) {
	// 1) Global concurrency: shed immediately if the pool is full.
	select {
	case l.sem <- struct{}{}:
	default:
		l.atCapacity.Add(1)
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("sandbox is at capacity, retry shortly"))
	}

	// 2+3) Per-principal concurrency and rate, under one lock so the decision is
	// consistent. On failure, give the global slot back before returning.
	l.mu.Lock()
	if l.perKey > 0 && l.inflight[key] >= l.perKey {
		l.mu.Unlock()
		<-l.sem
		l.perKeyFull.Add(1)
		return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("per-caller concurrency limit reached (%d in flight)", l.perKey))
	}
	if l.perMin > 0 && !l.takeTokenLocked(key, time.Now()) {
		l.mu.Unlock()
		<-l.sem
		l.rateLimited.Add(1)
		return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("rate limit: %d runs/min per caller", l.perMin))
	}
	l.inflight[key]++
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if l.inflight[key] > 1 {
				l.inflight[key]--
			} else {
				delete(l.inflight, key) // don't leak a key once it has no runs
			}
			l.mu.Unlock()
			<-l.sem
		})
	}, nil
}

// takeTokenLocked refills key's bucket for the elapsed time and consumes one token,
// reporting whether a token was available. Caller holds l.mu.
func (l *CodeLimiter) takeTokenLocked(key string, now time.Time) bool {
	if now.Sub(l.lastTrim) > time.Minute { // occasionally evict full, idle buckets
		for k, b := range l.buckets {
			// Recreating a bucket starts it at a full burst. Only evict when the
			// existing bucket would also be full now; otherwise eviction would grant
			// a partially-refilled caller extra tokens merely for being idle.
			refilled := b.tokens + now.Sub(b.last).Seconds()*l.refill
			if now.Sub(b.last) > 2*time.Minute && refilled >= l.burst {
				delete(l.buckets, k)
			}
		}
		l.lastTrim = now
	}

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.refill
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Stats is a snapshot of shed-load counters for metrics/observability.
type Stats struct {
	AtCapacity  int64 // runs shed because the global pool was full
	PerKeyFull  int64 // runs shed because a caller hit its concurrency cap
	RateLimited int64 // runs shed because a caller exceeded its rate
	InFlight    int64 // runs currently holding a global slot
}

// Stats returns the current shed-load counters and in-flight count.
func (l *CodeLimiter) Stats() Stats {
	return Stats{
		AtCapacity:  l.atCapacity.Load(),
		PerKeyFull:  l.perKeyFull.Load(),
		RateLimited: l.rateLimited.Load(),
		InFlight:    int64(len(l.sem)),
	}
}
