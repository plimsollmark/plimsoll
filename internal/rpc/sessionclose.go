package rpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The daemon closes a session by itself in four places: an idle session that could not
// be paused and whose caller's paid allowance cannot cover another idle period
// (suspend), a session no request named by its first idle timeout (closeUnclaimed), an
// opened session its open cannot hand over (its caller gone, the software rule or the
// isolation floor not met by what opened), and a pool member after its one call
// (warmCell). Each used to be its own copy of a close, and the copies drifted: the
// first closed with the context its pause had already spent, ignored the error, logged
// "session closed" and tried nothing more, so on a provider billed by the second the
// session ran, and billed, to the end of its lifetime, past the caller's allowance,
// while the log said it was closed (finding hunt-quality-1, 2026-11-20). closeOwn is the
// one close all four make now. A replaced session's close (replace) makes one try
// through tryClose and no more: a failure there undoes the replacement, and the owner
// keeps the session.
//
// A session's lifetime end and a drain are the provider's (sandbox/internal/sessionkit
// ends a session at its lifetime; plimsolld calls the provider's Drain), so neither is a
// close of this layer's.

// ownClose names a close the daemon makes by itself, for its log lines.
type ownClose struct {
	// why is a fixed word of this file's, never a caller's: unpaid, unclaimed,
	// caller_gone, software_rule, below_floor, no_id or pool_member.
	why     string
	session string // the session's fingerprint; "" for one never handed over
	caller  string
	// paid is the session's meter on a provider billed by the second; nil otherwise.
	paid *sessionMeter
}

// ownClose describes a close of e's.
func (e *sessionEntry) ownClose(why string) ownClose {
	return ownClose{why: why, session: e.fingerprint, caller: e.principal, paid: e.paid}
}

// closeRetry is how a failed close of the daemon's own is tried again: after first, then
// after twice as long each time, attempts tries in all (the first included).
type closeRetry struct {
	first    time.Duration
	attempts int
}

// sessionCloseRetry tries again 10 s after a failed close, since what a provider fails
// with for a moment (a rate-limit answer, a dropped connection to its API) has usually
// cleared in seconds (a judgment, not a measurement); it doubles each wait so a provider
// that is down is not called in a loop; six tries span 310 s of waits (10, 20, 40, 80,
// 160) plus up to sessionOrphanCloseBudget each, past which the failure is no blip and
// the operator has an error line to act on. The provider's lifetime for the session ends
// it at last, and its paid time is held until then. A test sets SandboxService.closeRetry
// instead, since a retry outlives the call that started it.
var sessionCloseRetry = closeRetry{first: 10 * time.Second, attempts: 6}

// retryPolicy is the service's closeRetry, or sessionCloseRetry when none is set.
func (s *SandboxService) retryPolicy() closeRetry {
	if s.closeRetry.attempts > 0 {
		return s.closeRetry
	}
	return sessionCloseRetry
}

// tryClose makes one close of sess on a budget of its own (sessionOrphanCloseBudget,
// which covers a provider's stop), never a context a caller or a pause has spent: the
// close that used the pause's spent context failed at once (hunt-quality-1). It keeps
// ctx's values only. A provider that panics while closing has failed to close: this can
// run on a timer's goroutine, where a panic would end the daemon.
func (s *SandboxService) tryClose(ctx context.Context, sess sandbox.Session, budget time.Duration) (err error) {
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			s.logger().LogAttrs(closeCtx, slog.LevelError, "the provider panicked while closing a session", panicAttrs(r)...)
			err = errClosePanicked
		}
	}()
	return sess.Close(closeCtx)
}

var errClosePanicked = errors.New("the provider panicked while closing")

// closeTook reports whether a close ended the session: it says so, or the session ended
// anyway.
func closeTook(err error, sess sandbox.Session) bool {
	return err == nil || sess.Err() != nil
}

// closeOwn closes sess, a session the daemon ends by itself, and reports whether it
// ended. A close that fails with the session still open is logged as a failed close,
// never as a close, with the provider's name; on a provider billed by the second the
// session's meter then holds the time the sandbox may still bill, to the end of its
// lifetime and its delete, whatever the allowance has room for (sessionMeter.bill); and
// the close is tried again on its own goroutine (sessionCloseRetry) until it takes, the
// session ends, or the tries run out. The caller writes its own line for a close that
// took, and what the session's end gives back (its slot, its place, the meter's
// settle) follows Done, as before.
func (s *SandboxService) closeOwn(ctx context.Context, sess sandbox.Session, c ownClose) bool {
	// Read once, here: the tries after this one run on a goroutine of their own.
	budget, policy := sessionOrphanCloseBudget, s.retryPolicy()
	err := s.tryClose(ctx, sess, budget)
	if closeTook(err, sess) {
		return true
	}
	s.closeFailed(ctx, sess, c, 1, err)
	go s.retryClose(ctx, sess, c, budget, policy)
	return false
}

// closeFailed records a failed try of a close of the daemon's own: the meter holds what
// the sandbox may still bill, the failure counts in /metrics, and the log says so.
func (s *SandboxService) closeFailed(ctx context.Context, sess sandbox.Session, c ownClose, attempt int, err error) {
	s.closeFailures.Add(1)
	attrs := append(s.closeAttrs(c), slog.Int("attempt", attempt), errAttr(err))
	if c.paid != nil {
		held := c.paid.bill(time.Until(sess.ExpiresAt()) + s.meteredTeardown())
		attrs = append(attrs, slog.Float64("paid_seconds_held", held))
	}
	s.logger().LogAttrs(ctx, slog.LevelWarn, "session close failed; the session may still be running, and the daemon tries again", attrs...)
}

// retryClose tries a failed close again, with backoff, until it takes, the session ends
// by itself, or policy's tries run out.
func (s *SandboxService) retryClose(ctx context.Context, sess sandbox.Session, c ownClose, budget time.Duration, policy closeRetry) {
	wait := policy.first
	for attempt := 2; attempt <= policy.attempts; attempt, wait = attempt+1, wait*2 {
		timer := time.NewTimer(wait)
		select {
		case <-sess.Done():
			timer.Stop()
		case <-timer.C:
		}
		if sess.Err() != nil {
			s.logger().LogAttrs(ctx, slog.LevelInfo, "session ended by itself while its failed close was being tried again",
				append(s.closeAttrs(c), slog.Int("attempts", attempt-1))...)
			return
		}
		err := s.tryClose(ctx, sess, budget)
		if closeTook(err, sess) {
			s.logger().LogAttrs(ctx, slog.LevelInfo, "session closed after a failed close",
				append(s.closeAttrs(c), slog.Int("attempt", attempt))...)
			return
		}
		s.closeFailed(ctx, sess, c, attempt, err)
	}
	s.closeGaveUp.Add(1)
	s.logger().LogAttrs(ctx, slog.LevelError, "session close gave up; the provider's lifetime for the session ends it, and its paid time is held until then",
		append(s.closeAttrs(c), slog.Int("attempts", policy.attempts), slog.Time("expires", sess.ExpiresAt()))...)
}

func (s *SandboxService) closeAttrs(c ownClose) []slog.Attr {
	attrs := []slog.Attr{slog.String("why", c.why), slog.String("sandbox", s.Sandbox.Name()), slog.String("caller", c.caller)}
	if c.session != "" {
		attrs = append(attrs, slog.String("session", c.session))
	}
	return attrs
}

// SessionCloseCounts returns, for /metrics, how many tries of a close the daemon made by
// itself failed with the session still open, and how many such closes gave up.
func (s *SandboxService) SessionCloseCounts() (failed, gaveUp int64) {
	return s.closeFailures.Load(), s.closeGaveUp.Load()
}

// panicStackBytes bounds a recovered panic's stack in the log: a provider's call depth
// fits in it many times over.
const panicStackBytes = 8192

// panicAttrs describe a recovered panic for the log by its type and the stack where it
// happened, never its value: a provider's panic value can be built from what a run
// returned (its output, its files' names), which is guest-controlled, while a stack is
// function names, files, lines and argument words.
func panicAttrs(r any) []slog.Attr {
	stack := debug.Stack()
	if len(stack) > panicStackBytes {
		stack = append(stack[:panicStackBytes:panicStackBytes], "...(cut)"...)
	}
	return []slog.Attr{slog.String("panic_type", fmt.Sprintf("%T", r)), slog.String("stack", string(stack))}
}
