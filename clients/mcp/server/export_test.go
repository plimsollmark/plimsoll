package server

import (
	"context"
	"errors"
	"sync"
	"time"
)

// RetireBudget sets the background close budget, returning a reset.
func RetireBudget(d time.Duration) func() {
	old := retireBudget
	retireBudget = d
	return func() { retireBudget = old }
}

// BlockNextReceiptWrite makes the next receipt write wait, as a slow disk's sync would,
// until release is called; blocked is closed once it waits.
func BlockNextReceiptWrite(s *Server) (blocked <-chan struct{}, release func()) {
	return BlockReceiptWriteAfter(s, 0)
}

// BlockReceiptWriteAfter is BlockNextReceiptWrite for the write after the next skip.
func BlockReceiptWriteAfter(s *Server, skip int) (blocked <-chan struct{}, release func()) {
	ch, waiting := make(chan struct{}), make(chan struct{})
	s.receipts.mu.Lock()
	s.receipts.block, s.receipts.blocking, s.receipts.blockSkip = ch, waiting, skip
	s.receipts.mu.Unlock()
	return waiting, func() { close(ch) }
}

// CallTimeout sets s's whole-call budget, below the floor New checks, so a test can
// reach a wait that budget once bounded.
func CallTimeout(s *Server, d time.Duration) {
	s.cfg.CallTimeout = d
}

// SandboxesHeld is how many sandboxes s holds open to tool calls.
func SandboxesHeld(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.boxes)
}

// ReceiptsOfAfterPendingClose is how a close reports a handle whose earlier close is
// still unfinished when the answer is due, after a later one finished as given.
func ReceiptsOfAfterPendingClose(s *Server, last, reason string) (string, string) {
	b := &box{changed: make(chan struct{})}
	release := make(chan struct{})
	defer close(release)
	spawn(s, b, func(*closing) closed { <-release; return closed{receipts: "closed"} })
	<-spawn(s, b, func(*closing) closed { return closed{receipts: last, reason: reason} }).done
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return s.receiptsOf(ctx, b)
}

// ReceiptsOfWhenAFailureMeetsTheDeadline is how a close reports a handle whose earlier
// close publishes an incomplete outcome just as the answer's deadline ends: both are
// ready when the wait returns.
func ReceiptsOfWhenAFailureMeetsTheDeadline(s *Server) (string, string) {
	b := &box{changed: make(chan struct{})}
	release := make(chan struct{})
	spawn(s, b, func(*closing) closed {
		<-release
		return closed{receipts: "incomplete", reason: "the write failed"}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer SetAwait(func(ctx context.Context, ch <-chan struct{}) {
		close(release)
		<-ch
		cancel()
		<-ctx.Done()
	})()
	return s.receiptsOf(ctx, b)
}

// SetAwait replaces how the server waits for a channel or a deadline, returning a reset.
func SetAwait(f func(ctx context.Context, ch <-chan struct{})) func() {
	old := await
	await = f
	return func() { await = old }
}

func spawn(s *Server, b *box, run func(*closing) closed) *closing {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spawnLocked(b, run)
}

// ClosingsHeld is how many unfinished closings s holds, and how many the open sandbox
// handle keeps.
func ClosingsHeld(s *Server, handle string) (server, sandbox int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.boxes[handle]; b != nil {
		sandbox = len(b.closings)
	}
	return len(s.closings), sandbox
}

// ReceiptsEnded reports whether the receipt store has ended.
func ReceiptsEnded(s *Server) bool {
	s.receipts.mu.Lock()
	defer s.receipts.mu.Unlock()
	return s.receipts.ended
}

// FailSyncDirOnce makes the first sync of dir fail, returning how many times dir has
// been synced since and a reset.
func FailSyncDirOnce(dir string) (synced func() int, reset func()) {
	old := syncDir
	var count int
	var mu sync.Mutex
	syncDir = func(d string) error {
		if d != dir {
			return old(d)
		}
		mu.Lock()
		count++
		first := count == 1
		mu.Unlock()
		if first {
			return errors.New("the directory sync failed (test)")
		}
		return old(d)
	}
	return func() int { mu.Lock(); defer mu.Unlock(); return count }, func() { syncDir = old }
}

// AdvanceReceiptsClock moves the receipt store's clock d ahead.
func AdvanceReceiptsClock(s *Server, d time.Duration) {
	s.receipts.mu.Lock()
	defer s.receipts.mu.Unlock()
	now := s.receipts.now
	s.receipts.now = func() time.Time { return now().Add(d) }
}

// ChecksAtOnce runs n quota checks that all begin while the store is held, so they wait
// for it together, and returns how many walks they made and their answers.
func ChecksAtOnce(s *Server, n int) (walks int64, errs []error) {
	r := s.receipts
	var joined, done sync.WaitGroup
	joined.Add(n)
	quotaJoin = joined.Done
	defer func() { quotaJoin = nil }()
	before := r.walks.Load()
	r.mu.Lock()
	errs = make([]error, n)
	for i := range n {
		done.Add(1)
		go func() { defer done.Done(); errs[i] = r.Full() }()
	}
	joined.Wait()
	r.mu.Unlock()
	done.Wait()
	return r.walks.Load() - before, errs
}

// MeasureWithTickingClock makes the store's clock move step on at every reading, forces
// a measurement, and returns the clock's first reading and when the store says the
// measurement was made.
func MeasureWithTickingClock(s *Server, step time.Duration) (first, measuredAt time.Time) {
	r := s.receipts
	r.mu.Lock()
	t0, n := time.Now(), 0
	r.now = func() time.Time { n++; return t0.Add(time.Duration(n) * step) }
	r.measuredAt = time.Time{}
	r.mu.Unlock()
	_ = r.Full()
	r.mu.Lock()
	defer r.mu.Unlock()
	return t0.Add(step), r.measuredAt
}

// ReceiptsCounted is what the receipt store counts its directory as holding, and what a
// walk of it measures now.
func ReceiptsCounted(s *Server) (counted, measured int64) {
	s.receipts.mu.Lock()
	defer s.receipts.mu.Unlock()
	measured, _ = s.receipts.measure()
	return s.receipts.used, measured
}

// FailNextReceiptCreate makes the next receipt file creation fail.
func FailNextReceiptCreate(s *Server) {
	s.receipts.mu.Lock()
	s.receipts.failCreate = true
	s.receipts.mu.Unlock()
}

// FailNextRollback makes the next cut back after a failed receipt write fail.
func FailNextRollback(s *Server) {
	s.receipts.mu.Lock()
	s.receipts.failRollback = true
	s.receipts.mu.Unlock()
}

// SessionsHeld is how many sessions the receipt store still holds.
func SessionsHeld(s *Server) int {
	s.receipts.mu.Lock()
	defer s.receipts.mu.Unlock()
	return len(s.receipts.sessions)
}

// FailNextReceiptWrite makes the next receipt write fail, as a full disk would.
func FailNextReceiptWrite(s *Server) {
	s.receipts.mu.Lock()
	s.receipts.failNext = true
	s.receipts.mu.Unlock()
}

// Cut is cut, the output truncation.
func Cut(out string, max int) (string, bool) { return cut(out, max) }

// AgeTombstones moves every revocation back by d, as if it had happened earlier.
func AgeTombstones(s *Server, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.grants {
		g.revokedAt = g.revokedAt.Add(-d)
	}
}

// CarryGrant gives dst the workspace binding src was issued, as a request that
// authenticated earlier and arrives late would carry it.
func CarryGrant(dst, src context.Context) context.Context {
	return context.WithValue(dst, grantContextKey{}, src.Value(grantContextKey{}))
}

// HoldRuns counts n more calls that run code as held, as if they were running.
func HoldRuns(s *Server, n int) {
	s.mu.Lock()
	s.outstanding += n
	s.mu.Unlock()
}
