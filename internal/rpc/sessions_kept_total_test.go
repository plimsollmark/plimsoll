package rpc

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// keptMarker is the cell every session of these tests runs for its kept answer.
const keptMarker = "kept_total_marker_7713 = 1"

// keptTotalService is a daemon that keeps answers up to 4 MiB each and total bytes in
// all, with room for many sessions.
func keptTotalService(total int64) *SandboxService {
	svc := NewSandboxService(&sandboxtest.Sessions{})
	svc.Sessions = SessionConfig{MaxSessions: 32, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20,
		KeptAnswerBytes: 4 << 20, KeptAnswersTotalBytes: total}
	return svc
}

// keptSession is a session that ran one call and then the marker cell, whose answer is
// "lost": the checkpoint before it and its request digest.
type keptSession struct {
	id, fp string
	cp     *plimsollv1.SessionCheckpoint
	lost   string
}

func openKeptSession(t *testing.T, svc *SandboxService) keptSession {
	t.Helper()
	ctx := authenticatedContext("alice")
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	s := keptSession{id: o.Msg.GetSessionId(), fp: o.Msg.GetSession()}
	if _, err := headRun(svc, ctx, callReq(s.id, "1")); err != nil {
		t.Fatal(err)
	}
	s.cp = headOf(svc, s.id)
	call := cellReq(s.id, keptMarker)
	if _, err := headRun(svc, ctx, call); err != nil {
		t.Fatal(err)
	}
	s.lost = record.SessionRunRequestDigest(call.Msg)
	return s
}

// keptHeld is the daemon's total, the sum of what each session's kept answer holds of it
// (the two must be the same number), and how many sessions keep an answer.
func keptHeld(t *testing.T, svc *SandboxService) (total, sum int64, kept int) {
	t.Helper()
	svc.sessions.mu.Lock()
	entries := make([]*sessionEntry, 0, len(svc.sessions.byID))
	for _, e := range svc.sessions.byID {
		entries = append(entries, e)
	}
	svc.sessions.mu.Unlock()
	for _, e := range entries {
		e.mu.Lock()
		if e.keptAnswer != nil {
			sum += e.keptSize
			kept++
		} else if e.keptSize != 0 {
			t.Errorf("a session with no kept answer holds %d bytes of the total", e.keptSize)
		}
		e.mu.Unlock()
	}
	return svc.sessions.kept.Load(), sum, kept
}

// keptBy reports whether session id keeps an answer.
func keptBy(t *testing.T, svc *SandboxService, id string) bool {
	t.Helper()
	return keptAnswerOf(entryOf(t, svc, id)) != nil
}

// keptSizeOf is the proto size of the answer to keptMarker as the daemon counts it: what
// one session's kept answer holds of the total on a daemon with room for it.
func keptSizeOf(t *testing.T) int64 {
	t.Helper()
	svc := keptTotalService(64 << 20)
	openKeptSession(t, svc)
	held, sum, kept := keptHeld(t, svc)
	if kept != 1 || held != sum || held == 0 {
		t.Fatalf("the marker's answer was not kept: total %d, held %d, %d kept", held, sum, kept)
	}
	return held
}

// The daemon's total bounds every session's kept answers together: with room for two
// answers and a half, the first two sessions keep theirs and the third and fourth keep
// none, though each of their records is still kept, so an attach across their gap
// returns the lost record without an answer. The total equals what the sessions hold
// after every call.
func TestKeptAnswersNeverPassTheDaemonsTotal(t *testing.T) {
	size := keptSizeOf(t)
	total := size*2 + size/2
	svc := keptTotalService(total)
	var sessions []keptSession
	for i := range 4 {
		sessions = append(sessions, openKeptSession(t, svc))
		held, sum, kept := keptHeld(t, svc)
		if held > total || held != sum {
			t.Fatalf("after session %d: the total is %d, the sessions hold %d, the bound is %d", i+1, held, sum, total)
		}
		if want := min(i+1, 2); kept != want {
			t.Fatalf("after session %d: %d answers kept, want %d", i+1, kept, want)
		}
	}
	for i, s := range sessions {
		// attachAcross fails the test when the lost record does not come back.
		got := attachAcross(t, svc, s.fp, s.cp, s.lost)
		if (got.GetLostAnswer() != nil) != (i < 2) {
			t.Errorf("session %d: an answer came back %v", i+1, got.GetLostAnswer() != nil)
		}
	}
}

// A dropped answer gives its bytes back: a session's next call gives its old answer's
// bytes back before it keeps the new one (the total does not grow with calls), and a
// close frees the room, so the next session's answer is kept.
func TestADroppedAnswerGivesItsBytesBack(t *testing.T) {
	size := keptSizeOf(t)
	bound := size + size/2
	svc := keptTotalService(bound)
	first := openKeptSession(t, svc)
	if held, sum, kept := keptHeld(t, svc); held != sum || kept != 1 {
		t.Fatalf("one session: total %d, held %d, %d kept; want the same, 1", held, sum, kept)
	}
	ctx := authenticatedContext("alice")
	for range 3 {
		if _, err := headRun(svc, ctx, cellReq(first.id, keptMarker)); err != nil {
			t.Fatal(err)
		}
		if held, sum, kept := keptHeld(t, svc); held != sum || held > bound || kept != 1 {
			t.Fatalf("after another call: total %d, held %d, %d kept; want the same, at most %d, 1", held, sum, kept, bound)
		}
	}
	second := openKeptSession(t, svc)
	if held, sum, kept := keptHeld(t, svc); held != sum || kept != 1 || keptBy(t, svc, second.id) {
		t.Fatalf("a second session with no room: total %d, held %d, %d kept, by it %v", held, sum, kept, keptBy(t, svc, second.id))
	}
	if _, err := svc.CloseSession(ctx, closeReq(first.id)); err != nil {
		t.Fatal(err)
	}
	if held, _, kept := keptHeld(t, svc); held != 0 || kept != 0 {
		t.Fatalf("after the close: total %d, %d kept; want 0, 0", held, kept)
	}
	if _, err := headRun(svc, ctx, cellReq(second.id, keptMarker)); err != nil {
		t.Fatal(err)
	}
	if held, sum, kept := keptHeld(t, svc); held != sum || kept != 1 || !keptBy(t, svc, second.id) {
		t.Fatalf("the second session after the close: total %d, held %d, %d kept, by it %v", held, sum, kept, keptBy(t, svc, second.id))
	}
}

// A total of 0 keeps no answer at all, whatever the per-answer cap.
func TestAKeptTotalOfZeroKeepsNone(t *testing.T) {
	svc := keptTotalService(0)
	s := openKeptSession(t, svc)
	if held, _, kept := keptHeld(t, svc); held != 0 || kept != 0 {
		t.Fatalf("a total of 0: total %d, %d kept", held, kept)
	}
	if got := attachAcross(t, svc, s.fp, s.cp, s.lost); got.GetLostAnswer() != nil {
		t.Fatal("a total of 0 returned an answer")
	}
}

// Sessions keeping answers at once cannot together take the total past its bound: eight
// sessions, room for three answers, every session calling at once, round after round.
func TestKeptAnswersKeptAtOnceStayUnderTheTotal(t *testing.T) {
	size := keptSizeOf(t)
	total := size * 3
	svc := keptTotalService(total)
	var sessions []keptSession
	for range 8 {
		sessions = append(sessions, openKeptSession(t, svc))
	}
	ctx := authenticatedContext("alice")
	for round := range 10 {
		var wg sync.WaitGroup
		for _, s := range sessions {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := headRun(svc, ctx, cellReq(s.id, keptMarker)); err != nil {
					t.Error(err)
				}
				if held := svc.sessions.kept.Load(); held > total {
					t.Errorf("round %d: the total reached %d past its bound %d", round, held, total)
				}
			}()
		}
		wg.Wait()
		held, sum, kept := keptHeld(t, svc)
		if held != sum || held > total || kept > 3 {
			t.Fatalf("round %d: total %d, held %d, %d kept; bound %d", round, held, sum, kept, total)
		}
	}
}

// TestNoAnswerIsKeptForAnEndedSession: a call's answer that arrives after watch has ended
// the session (the call ended it itself) is not kept, and the daemon's total is unchanged;
// one kept before the end is dropped by it and gives its bytes back (finding release-110:
// with the order left to the race, 25 of 200 sessions kept an answer after their end, and
// 36 of them filled a total that held three answers). The order is forced here, not raced.
func TestNoAnswerIsKeptForAnEndedSession(t *testing.T) {
	answer := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "process"}
	var pool atomic.Int64
	e := &sessionEntry{keptCap: 4 << 20, keptTotal: 64 << 20, keptPool: &pool}

	e.keepLocked(answer)
	if e.keptAnswer == nil || pool.Load() == 0 {
		t.Fatalf("a live session kept nothing (pool %d)", pool.Load())
	}
	// watch's end: mark ended, drop the kept answer.
	e.ended = true
	e.dropKeptLocked()
	if e.keptAnswer != nil || pool.Load() != 0 {
		t.Fatalf("the end left %v kept and %d bytes held", e.keptAnswer != nil, pool.Load())
	}
	// The answer of the call that ended the session, arriving after the end.
	e.keepLocked(answer)
	if e.keptAnswer != nil || pool.Load() != 0 {
		t.Fatalf("an ended session kept an answer: %v kept, %d bytes held", e.keptAnswer != nil, pool.Load())
	}
}

// TestACallThatEndsItsSessionLeavesNothingKept: 200 sessions, each ended by its own call
// (the fake's cell that fills the disk budget), leave no kept answer and the daemon's
// total at zero, whichever order the call's answer and the session's end take (finding
// release-110 measured 25 leaks in this loop).
func TestACallThatEndsItsSessionLeavesNothingKept(t *testing.T) {
	svc := keptTotalService(64 << 20)
	svc.Sessions.MaxSessions = 256
	ctx := authenticatedContext("alice")
	for i := 0; i < 200; i++ {
		o, err := svc.OpenSession(ctx, openReq())
		if err != nil {
			t.Fatal(err)
		}
		id := o.Msg.GetSessionId()
		if _, err := headRun(svc, ctx, cellReq(id, sandboxtest.CellEndsSession)); err != nil {
			t.Fatal(err)
		}
	}
	// Let every watch run, then read the total and every entry.
	deadline := time.Now().Add(10 * time.Second)
	for {
		total, sum, kept := keptHeld(t, svc)
		if total == 0 && sum == 0 && kept == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after 200 sessions each ended by its own call: total %d, held %d, %d sessions keep an answer", total, sum, kept)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
