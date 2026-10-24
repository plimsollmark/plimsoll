package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The sandbox lifecycle. One rule for each piece of state:
//
//   - Server.mu guards the boxes map, the set of unfinished closings, every box's busy,
//     closings, issue and changed, the counters opening and outstanding, and stopped.
//     A box out of the map is closed to calls.
//   - A box's sess, langs and first are touched only by the holder of its turn.
//   - A call admitted to a box checks again, once it holds the turn, that the box is
//     still open: a close that began while it waited wins, and nothing is reopened or
//     run for it.
//   - A session this server will not use again (closed, ended, stopped, or left by
//     shutdown) gets a closing, registered under Server.mu in the step that lets the
//     session go: one goroutine owns it to the end (the turn when a call holds it, the
//     daemon's close within retireBudget and once more if unconfirmed, receipts
//     settled once), signals first when the first attempt has an answer and done with
//     the final result. Everyone else only waits, each with a deadline of its own,
//     which ends that wait and never the close, and reads the state again after it. An
//     unfinished closing holds a place under the cap, and shutdown waits for every one.
//   - An open reserves its place before it goes to the network, so opens at once cannot
//     pass MaxSandboxes. At the cap an open is refused: nothing is closed for room,
//     since closing destroys a sandbox's state, which takes a close_sandbox naming it.
//     The connections of one app the owner approved over the remote transport hold at
//     most one place fewer than the cap between them (connectionShare), so one app alone
//     never fills the server against another, which can neither see nor close its
//     sandboxes.

const (
	// maxQueuedPerSandbox is how many calls one sandbox holds, running and waiting.
	maxQueuedPerSandbox = 4
	// maxOutstanding is how many calls that run code (run_code, ExtendRun tools) this
	// server holds at once.
	maxOutstanding = 16
)

// retireBudget bounds a background close of a session this server dropped (a
// variable, so a test can shorten it).
var retireBudget = 30 * time.Second

// box is one sandbox open_sandbox opened. turn admits one call at a time.
type box struct {
	handle string
	grant  string
	group  string // the approved app its grant belongs to (connectorGrant.group)
	turn   chan struct{}

	// Owned by the holder of turn.
	sess  *client.Session // nil once its sandbox is gone: the next call opens another
	langs []sandbox.Language
	first bool // the next call is the first in its sandbox
	// kit, when open_sandbox named one, goes with the next call while kitDue: the first
	// in each sandbox the handle runs in.
	kit    *Kit
	kitDue bool
	// lastEnd is why the handle's last sandbox ended, told once, by the next call, which
	// runs in a new one.
	lastEnd string

	// Guarded by Server.mu.
	busy     int
	closings []*closing    // closes of this handle's sessions not yet finished
	issue    string        // why a finished one's receipts are incomplete, if one's are
	unclosed error         // the first deletion of one the daemon did not confirm
	changed  chan struct{} // closed, and replaced, as each of closings finishes
}

func (b *box) acquire(ctx context.Context) error {
	select {
	case b.turn <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *box) unlock() { <-b.turn }

// closed is how a close ended: err is a deletion the daemon did not confirm; receipts
// and reason, with receipts on, how its session's receipts ended.
type closed struct {
	err              error
	receipts, reason string
}

// A closing is the whole close of one session this server let go, the one retry and
// its receipts included (for a box's last close, whatever session the box holds when
// its turn frees, or none). first is closed once the first attempt to delete has an
// answer, firstErr being a deletion the daemon did not confirm; done once the close is
// finished, with its result. Each field is set before its channel is closed and read
// only after.
type closing struct {
	grant       string
	group       string
	first, done chan struct{}
	firstErr    error
	result      closed
	once        sync.Once
}

// answered records the first attempt's answer, once.
func (c *closing) answered(err error) {
	c.once.Do(func() {
		c.firstErr = err
		close(c.first)
	})
}

// await waits for ch or the end of ctx; whoever calls it reads the state again after,
// so an answer that came as the deadline did is not lost. A variable, so a test can make
// both ready at once.
var await = func(ctx context.Context, ch <-chan struct{}) {
	select {
	case <-ch:
	case <-ctx.Done():
	}
}

// spawnLocked registers a closing, of b's session when b is given, and starts the
// goroutine that owns it to the end. s.mu is held, so the closing takes its place under
// the cap, and in what shutdown waits for, in the same step that let the session go;
// the goroutine takes s.mu only when done, and b then keeps only its outcome.
func (s *Server) spawnLocked(b *box, run func(*closing) closed) *closing {
	c := &closing{first: make(chan struct{}), done: make(chan struct{})}
	if b != nil {
		c.grant, c.group = b.grant, b.group
	}
	s.closings[c] = struct{}{}
	if b != nil {
		b.closings = append(b.closings, c)
	}
	go func() {
		c.result = run(c)
		c.answered(c.result.err) // a close with no session to delete answers with its result
		s.mu.Lock()
		if g := s.grants[c.grant]; g != nil && g.cleanupErr == nil && c.result.err != nil {
			g.cleanupErr = c.result.err
		}
		delete(s.closings, c)
		if b != nil {
			b.closings = slices.DeleteFunc(b.closings, func(x *closing) bool { return x == c })
			if c.result.receipts == "incomplete" && b.issue == "" {
				b.issue = c.result.reason
			}
			if c.result.err != nil && b.unclosed == nil {
				b.unclosed = c.result.err
			}
			close(b.changed)
			b.changed = make(chan struct{})
		}
		s.mu.Unlock()
		close(c.done)
	}()
	return c
}

// retire closes sess, which no box will use again, in the background; b, when the
// session was b's, keeps the outcome. Call it before sess is let go.
func (s *Server) retire(b *box, sess *client.Session) {
	if sess == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.spawnLocked(b, func(c *closing) closed { return s.closeSession(c, sess) })
}

// closeSession is the whole close of sess: deleted within retireBudget, once more
// within another if the daemon did not confirm it, then its receipts settled once.
func (s *Server) closeSession(c *closing, sess *client.Session) closed {
	err := s.deleteSession(sess)
	c.answered(err)
	if err != nil {
		s.logClose(err)
		if err = s.deleteSession(sess); err != nil {
			s.logClose(err)
		}
	}
	state, reason := s.settle(sess)
	return closed{err: err, receipts: state, reason: reason}
}

// deleteSession asks the daemon to delete sess, within retireBudget. A close the daemon
// answered deleted the sandbox, even if its signed close could not be kept, or its count
// of calls differs from the chain this server saw (normal after an answer was lost: the
// call ran, the client never believed it): either leaves the receipts incomplete, not the
// sandbox alive. Read as unconfirmed, the second leaked into a retried close and a
// "deletion not confirmed" report for a sandbox already gone (review B6, 2026-10-23).
// The receipts are failed here, since a session none of whose calls was stored has no
// file whose missing close would say so.
func (s *Server) deleteSession(sess *client.Session) error {
	ctx, cancel := context.WithTimeout(context.Background(), retireBudget)
	defer cancel()
	_, err := sess.Close(ctx)
	switch {
	case err == nil, errors.Is(err, client.ErrNotRecorded):
		return nil
	case errors.Is(err, record.ErrChain):
		s.cfg.Logger.Warn("a sandbox closed with calls this server did not see answered; its receipts end incomplete", "error", err)
		s.receipts.unseen(sess.Fingerprint())
		return nil
	}
	return err
}

// logClose reports a deletion the daemon did not confirm.
func (s *Server) logClose(err error) {
	s.cfg.Logger.Warn("closing a sandbox failed; the daemon ends it at its lifetime", "error", err)
}

// settle ends the receipts of sess, whose close is done, and logs them when they ended
// incomplete: whatever answer also says so, the log is the one record of every such
// session, a sandbox closed for room or at shutdown included.
func (s *Server) settle(sess *client.Session) (state, reason string) {
	state, reason = s.receipts.settle(sess.Fingerprint())
	if state == "incomplete" {
		s.cfg.Logger.Warn("a sandbox's receipts are incomplete", "reason", reason)
	}
	return state, reason
}

// closeBoxLocked starts the last close of b, which the caller has just taken out of the
// map under s.mu: its closing takes b's place in that same step. Its owner waits for
// b's turn however long a call holds it (a stuck receipt write included), then closes
// whatever session b holds.
func (s *Server) closeBoxLocked(b *box) *closing {
	return s.spawnLocked(b, func(c *closing) closed {
		_ = b.acquire(context.Background())
		defer b.unlock()
		sess := b.sess
		b.sess = nil
		if sess == nil {
			return closed{receipts: "closed"}
		}
		return s.closeSession(c, sess)
	})
}

// deletionsOf waits, until ctx ends, for every close of b's sessions to finish: err is
// the first deletion the daemon did not confirm, and pending says one was unfinished
// when ctx ended.
func (s *Server) deletionsOf(ctx context.Context, b *box) (pending bool, err error) {
	for {
		s.mu.Lock()
		unclosed, unfinished, changed := b.unclosed, len(b.closings), b.changed
		s.mu.Unlock()
		switch {
		case unclosed != nil:
			return false, unclosed
		case unfinished == 0:
			return false, nil
		case ctx.Err() != nil:
			return true, nil
		}
		await(ctx, changed)
	}
}

// replacementPlace waits until a new sandbox for b, whose last one the daemon ended, fits
// under the cap. b holds its place already, but its ended sandbox holds another until
// its deletion finishes, so a daemon that kept ending sandboxes would otherwise push the
// server past MaxSandboxes; the wait is for b's own deletions, and if the cap is still
// full once they are done (or ctx ends first), the call is refused, nothing run.
func (s *Server) replacementPlace(ctx context.Context, b *box) *failure {
	for {
		s.mu.Lock()
		over := len(s.boxes)+s.opening+len(s.closings) > s.cfg.MaxSandboxes
		mine, changed := len(b.closings), b.changed
		s.mu.Unlock()
		if !over {
			return nil
		}
		if mine == 0 || ctx.Err() != nil {
			return refused(sandbox.RefusalCapacity, "the daemon ended sandbox %s's last sandbox, and this server's cap of %d open sandboxes has no place for a new one until the sandboxes being deleted are gone. Nothing ran; call again shortly.", b.handle, s.cfg.MaxSandboxes)
		}
		await(ctx, changed)
	}
}

// receiptsOf is how the receipts of a closed box's sessions ended, every one the handle
// had: incomplete as soon as any finished close says so, closed once all have finished
// without, and unknown only if one is still unfinished when ctx has ended.
func (s *Server) receiptsOf(ctx context.Context, b *box) (string, string) {
	for {
		s.mu.Lock()
		issue, unfinished, changed := b.issue, len(b.closings), b.changed
		s.mu.Unlock()
		switch {
		case issue != "":
			return "incomplete", issue
		case unfinished == 0:
			return "closed", ""
		case ctx.Err() != nil:
			return "unknown", "an earlier sandbox of this handle was still being closed when this answer was due"
		}
		await(ctx, changed)
	}
}

// openSession opens a checked session: the floor and software rule are checked on
// the open and on every call, and the daemon is asked for a bounded lifetime.
func (s *Server) openSession(ctx context.Context) (*client.Session, []sandbox.Language, *failure) {
	info, err := s.describe(ctx)
	if err != nil {
		return nil, nil, s.failed(ctx, err)
	}
	if !info.SupportsSessions {
		return nil, nil, refused(sandbox.RefusalUnsupported, "this plimsoll daemon (%s) keeps no sessions (its SANDBOX_MAX_SESSIONS is 0, or its provider has none), so every run_code call runs fresh; call run_code without sandbox", info.Sandbox)
	}
	langs := s.offered(info.SessionEnvironment)
	if len(langs) == 0 {
		return nil, nil, refused(sandbox.RefusalUnsupported, "a sandbox here runs %v, none of the %s this server offers", info.SessionEnvironment.Languages, joinNames(s.cfg.Languages))
	}
	sess, err := s.remote.OpenSession(ctx, client.SessionOptions{
		MinimumIsolation: s.cfg.MinimumIsolation,
		Software:         s.cfg.Software,
		Lifetime:         s.cfg.SessionLifetime,
		Languages:        langs,
		Owner:            s.owner(ctx),
	})
	if err != nil {
		s.forgetDescribeOn(err)
		// An open sends no code, so whatever failed, nothing ran.
		f := s.failed(ctx, err)
		if f.Ran != "no" {
			f.Ran = "no"
			f.Summary = fmt.Sprintf("Nothing ran: the sandbox did not open: %v", err)
		}
		return nil, nil, f
	}
	return sess, langs, nil
}

var shuttingDown = refused(sandbox.RefusalCapacity, "this server is shutting down")

func (s *Server) openSandbox(ctx context.Context, in openInput) (openOutput, *failure) {
	var k *Kit
	if in.Kit != "" {
		if k = s.kit(in.Kit); k == nil {
			return openOutput{}, refused(sandbox.RefusalRequest, "this server has no kit %q", in.Kit)
		}
	}
	if f := s.full(); f != nil {
		return openOutput{}, f
	}
	// The daemon's cap on one owner's sandboxes, which it enforces by closing one.
	perOwner := 0
	if info, err := s.describe(ctx); err == nil {
		perOwner = info.SessionsPerOwner
	}
	// Reserve a place before going to the network, so opens at once cannot pass the
	// cap. At the cap nothing is closed for room: the refusal names the idle sandboxes,
	// and closing one is a close_sandbox the user can see.
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return openOutput{}, shuttingDown
	}
	g, group := grantID(ctx), ""
	if gr := s.grantLocked(ctx); gr != nil {
		group = gr.group
	}
	if share := s.connectionShare(g); share > 0 {
		// The app's share counts every grant of it; only this grant's own sandboxes
		// are named, since one grant never sees another's handles.
		held := s.openingBy[group]
		var idle []string
		for h, b := range s.boxes {
			if b.group == group {
				held++
				if b.grant == g && b.busy == 0 {
					idle = append(idle, h)
				}
			}
		}
		for c := range s.closings {
			if c.group == group {
				held++
			}
		}
		if held >= share {
			s.mu.Unlock()
			slices.Sort(idle)
			if len(idle) == 0 {
				return openOutput{}, refused(sandbox.RefusalCapacity, "the connections of one approved app may hold at most %d of this server's %d sandboxes, so that one app alone never fills the server, and every one this connection holds is running a call, opening or being closed (any others belong to another connection of the same app). Nothing was closed to make room; wait for a call to end, or close a sandbox with close_sandbox, then open again.", share, s.cfg.MaxSandboxes)
			}
			f := refused(sandbox.RefusalCapacity, "the connections of one approved app may hold at most %d of this server's %d sandboxes, so that one app alone never fills the server. Nothing was closed to make room: close one you no longer need with close_sandbox, which deletes its files and interpreter state, then open again. Idle now (no call running or waiting): %s.", share, s.cfg.MaxSandboxes, strings.Join(idle, ", "))
			f.IdleSandboxes = idle
			return openOutput{}, f
		}
	}
	if perOwner > 0 {
		// The daemon meets an open at its per-owner cap by closing that owner's least
		// recently used idle sandbox; this server closes nothing for room, so it refuses
		// first, counting what this owner holds (opening and being closed included).
		held := s.openingGrant[g]
		var idle []string
		for h, b := range s.boxes {
			if b.grant == g {
				held++
				if b.busy == 0 {
					idle = append(idle, h)
				}
			}
		}
		for c := range s.closings {
			if c.grant == g {
				held++
			}
		}
		if held >= perOwner {
			s.mu.Unlock()
			slices.Sort(idle)
			f := refused(sandbox.RefusalCapacity, "the plimsoll daemon keeps at most %d sandboxes for one user, and it would make room by deleting one of yours; this server deletes nothing for room. Close one you no longer need with close_sandbox, then open again. Idle now (no call running or waiting): %s.", perOwner, strings.Join(idle, ", "))
			f.IdleSandboxes = idle
			return openOutput{}, f
		}
	}
	if len(s.boxes)+s.opening+len(s.closings) >= s.cfg.MaxSandboxes {
		var idle []string
		others := 0
		for h, b := range s.boxes {
			switch {
			case b.grant != grantID(ctx):
				others++
			case b.busy == 0:
				idle = append(idle, h)
			}
		}
		s.mu.Unlock()
		slices.Sort(idle)
		if len(idle) == 0 && others > 0 {
			// The cap is the server's, shared by every connection the owner
			// approved, and one connection never sees another's handles.
			return openOutput{}, refused(sandbox.RefusalCapacity, "this server's cap of open sandboxes (%d) is reached, and %d of them belong to another connection to this server (another chat or client the owner approved), which this one can neither see nor close. Nothing was closed to make room; close sandboxes from that connection, or wait for them to expire, then open again.", s.cfg.MaxSandboxes, others)
		}
		if len(idle) == 0 {
			return openOutput{}, refused(sandbox.RefusalCapacity, "this server's cap of open sandboxes (%d) is reached, every place held by a sandbox running a call, opening or being closed. Nothing was closed to make room; wait for a call to end, or close a sandbox with close_sandbox, then open again.", s.cfg.MaxSandboxes)
		}
		f := refused(sandbox.RefusalCapacity, "this server's cap of open sandboxes (%d) is reached. Nothing was closed to make room: close one you no longer need with close_sandbox, which deletes its files and interpreter state, then open again. Idle now (no call running or waiting): %s.", s.cfg.MaxSandboxes, strings.Join(idle, ", "))
		f.IdleSandboxes = idle
		return openOutput{}, f
	}
	s.opening++
	s.openingBy[group]++
	s.openingGrant[g]++
	s.mu.Unlock()

	sess, langs, f := s.openSession(ctx)

	s.mu.Lock()
	s.opening--
	if s.openingGrant[g]--; s.openingGrant[g] == 0 {
		delete(s.openingGrant, g)
	}
	if s.openingBy[group]--; s.openingBy[group] == 0 {
		delete(s.openingBy, group)
	}
	if f != nil {
		s.mu.Unlock()
		return openOutput{}, f
	}
	if s.stopped || ctx.Err() != nil || s.grantRevokedLocked(ctx) {
		c := s.spawnLocked(nil, func(c *closing) closed { return s.closeSession(c, sess) })
		c.grant, c.group = g, group
		s.mu.Unlock()
		return openOutput{}, shuttingDown
	}
	b := &box{grant: g, group: group, handle: newHandle(), turn: make(chan struct{}, 1), sess: sess, langs: langs, first: true, kit: k, kitDue: k != nil, changed: make(chan struct{})}
	s.boxes[b.handle] = b
	s.mu.Unlock()

	out := openOutput{Sandbox: b.handle, Languages: names(langs), Isolation: sess.Isolation().String(), ExpiresAt: timeString(sess.ExpiresAt())}
	out.Summary = fmt.Sprintf("Opened sandbox %s at the %q isolation tier; pass it as run_code's sandbox. It runs %s, until %s.", b.handle, out.Isolation, joinNames(langs), out.ExpiresAt)
	if k != nil {
		out.Kit = k.Name
		out.Summary += fmt.Sprintf(" Kit %s is written into it with the first run_code call.", k.Name)
	}
	return out, nil
}

// owner is the end user the daemon counts a sandbox against: the configured owner, and
// in remote mode each connector apart, so the daemon's per-owner cap never weighs one
// connector's sandboxes against another's.
func (s *Server) owner(ctx context.Context) string {
	if g := grantID(ctx); g != "" {
		return s.cfg.Owner + "/connector/" + g
	}
	return s.cfg.Owner
}

// connectionShare is how many places one connection the owner approved over the remote
// transport may hold: one fewer than the cap, so one connection alone never fills the
// server. 0 means no share applies: stdio serves one local workspace, and a cap of one
// leaves nothing to keep back.
func (s *Server) connectionShare(grant string) int {
	if grant == "" || s.cfg.MaxSandboxes < 2 {
		return 0
	}
	return s.cfg.MaxSandboxes - 1
}

func (s *Server) closeSandbox(ctx context.Context, in handleInput) (closeOutput, *failure) {
	s.mu.Lock()
	b := s.boxes[in.Sandbox]
	var c *closing
	if b != nil && b.grant != grantID(ctx) {
		b = nil
	}
	if b != nil {
		delete(s.boxes, in.Sandbox)
		c = s.closeBoxLocked(b)
	}
	s.mu.Unlock()
	if b == nil {
		return closeOutput{}, refused(sandbox.RefusalRequest, "no sandbox %s is open in this server, so there is nothing to close", in.Sandbox)
	}
	out := closeOutput{Sandbox: in.Sandbox}
	await(ctx, c.first)
	select {
	case <-c.first:
	default:
		out.Summary = fmt.Sprintf("Sandbox %s is closed to this server and its handle no longer works. Its deletion goes on in the background (a call still running in it, or the daemon not answering yet), so the daemon has not confirmed it yet; it ends at its lifetime at the latest.", in.Sandbox)
		return out, nil
	}
	if c.firstErr != nil {
		out.Summary = fmt.Sprintf("Sandbox %s is closed to this server and its handle no longer works, but the daemon has not confirmed its deletion (%v); it is tried once more in the background, and ends at its lifetime at the latest.", in.Sandbox, c.firstErr)
		return out, nil
	}
	// The handle's earlier sandboxes, ones the daemon ended and this server replaced, are
	// deleted in the background: deleted is said only once every one is confirmed.
	switch pending, err := s.deletionsOf(ctx, b); {
	case err != nil:
		out.Summary = fmt.Sprintf("Sandbox %s is closed to this server and its handle no longer works, and its last sandbox was deleted, but the daemon did not confirm the deletion of an earlier one (one it ended, which this server replaced): %v. That one ends at its lifetime at the latest.", in.Sandbox, err)
		return out, nil
	case pending:
		out.Summary = fmt.Sprintf("Sandbox %s is closed to this server and its handle no longer works, and its last sandbox was deleted; an earlier one (one the daemon ended, which this server replaced) is still being deleted, so the daemon has not confirmed every deletion yet. It ends at its lifetime at the latest.", in.Sandbox)
		return out, nil
	}
	out.Deleted = true
	out.Summary = fmt.Sprintf("Closed sandbox %s; the daemon deleted it.", in.Sandbox)
	if s.receipts != nil {
		out.Receipts, out.ReceiptsReason = s.receiptsOf(ctx, b)
		switch out.Receipts {
		case "closed":
			out.Summary += " Its receipts are complete: every signed close is stored."
		default:
			out.Summary += fmt.Sprintf(" Its receipts are %s: %s.", out.Receipts, out.ReceiptsReason)
		}
	}
	return out, nil
}

func (s *Server) runIn(ctx context.Context, handle string, lang sandbox.Language, code string, files []sandbox.File) (runOutput, *failure) {
	s.mu.Lock()
	b := s.boxes[handle]
	switch {
	case s.stopped:
		s.mu.Unlock()
		return runOutput{}, shuttingDown
	case b == nil || b.grant != grantID(ctx):
		s.mu.Unlock()
		return runOutput{}, refused(sandbox.RefusalRequest,
			"no sandbox %s is open in this server. A handle ends at close_sandbox or when this server restarts. Open another with open_sandbox, or omit sandbox to run fresh.",
			handle)
	case b.busy >= maxQueuedPerSandbox:
		s.mu.Unlock()
		return runOutput{}, refused(sandbox.RefusalCapacity, "sandbox %s already holds %d calls, running or waiting; wait for their answers", handle, b.busy)
	}
	b.busy++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		b.busy--
		s.mu.Unlock()
	}()
	if err := b.acquire(ctx); err != nil {
		return runOutput{}, refused(sandbox.RefusalCapacity, "the call waited for an earlier call in sandbox %s until this server's deadline", handle)
	}
	defer b.unlock()
	s.mu.Lock()
	gone := s.stopped || s.boxes[handle] != b || s.grantRevokedLocked(ctx) || ctx.Err() != nil
	s.mu.Unlock()
	if gone {
		return runOutput{}, refused(sandbox.RefusalRequest, "sandbox %s was closed while this call waited its turn", handle)
	}

	for attempt := 0; ; attempt++ {
		if b.sess == nil {
			// A sandbox is replaced after the daemon ended the last one, so read what
			// the daemon states again: it may have restarted with other languages.
			s.forgetDescribe()
			if f := s.replacementPlace(ctx, b); f != nil {
				f.SandboxUsable = ptr(false)
				return runOutput{}, f
			}
			sess, langs, f := s.openSession(ctx)
			if f != nil {
				f.SandboxUsable = ptr(false)
				return runOutput{}, f
			}
			b.sess, b.langs, b.first = sess, langs, true
			b.kitDue = b.kit != nil
		}
		use := lang
		if use == "" {
			use = b.langs[0]
		}
		if !slices.Contains(b.langs, use) {
			return runOutput{}, refused(sandbox.RefusalUnsupported, "sandbox %s runs %s, not %s", handle, joinNames(b.langs), use)
		}
		callFiles := files
		if b.kitDue {
			var f *failure
			if callFiles, f = withKitFiles(b.kit, files, len(code)); f != nil {
				return runOutput{}, f
			}
		}
		req := sandbox.CellRequest{Language: use, Code: code, Files: callFiles, Timeout: s.cfg.RunTimeout, MinimumIsolation: s.cfg.MinimumIsolation, Software: s.cfg.Software}
		if f := s.full(); f != nil { // the quota again, at dispatch, for a call that waited
			return runOutput{}, f
		}
		r, err := b.sess.RunCell(ctx, req)
		if answered(err, r.Record) {
			// A result that checked, kept or not: only keeping its record can have failed.
			ended := b.sess.Ended() != nil
			out := s.output(ctx, use, r.ExitCode, r.TimedOut, r.Stdout, r.Stderr, r.StdoutTruncated || r.StderrTruncated, r.Isolation, r.SoftwareIdentity, r.Record)
			out.Receipt = s.receiptFor(r.Record, err)
			out.StateKept = !r.InterpreterEnded && !ended
			out.FreshInterpreter = r.InterpreterStarted
			out.FilesPersist = !ended
			out.FreshSandbox = b.first
			if b.first && b.lastEnd != "" {
				out.SandboxReplaced, b.lastEnd = b.lastEnd, ""
			}
			b.first = false
			b.kitDue = false
			if ended {
				out.SandboxEnded = endWhy(b.sess.Ended())
				b.lastEnd = "ended (" + out.SandboxEnded + ")"
				s.retire(b, b.sess)
				b.sess = nil
			}
			summarize(&out, handle)
			return out, nil
		}
		// A call refused because its sandbox had ended ran nothing, so it runs once
		// more in a new sandbox, which its result says is new.
		var endedErr *sandbox.SessionEndedError
		if _, notDispatched := sandbox.NotDispatchedReason(err); attempt == 0 && notDispatched && errors.As(err, &endedErr) {
			b.lastEnd = "ended (" + endWhy(err) + ")"
			s.retire(b, b.sess)
			b.sess = nil
			continue
		}
		f := s.failed(ctx, err)
		if f.Ran == "maybe" {
			// It may have left files or state: the next call must not say the sandbox is new.
			b.first = false
			if b.kitDue {
				// The kit went with a call that may have run, and a cell's files are written
				// before its code, so it counts as delivered: sending it again would overwrite
				// what the guest has changed since. Should it be missing, kit sends it again.
				b.kitDue = false
				f.Summary += fmt.Sprintf(" Kit %s went with this call; if its files are not in the sandbox, pass kit again.", b.kit.Name)
			}
		}
		if end := b.sess.Ended(); end != nil {
			b.lastEnd = "ended (" + endWhy(end) + ")"
		} else if b.sess.Stopped() != nil {
			// The client stopped trusting the session (an answer it could not bind or check):
			// that is not the daemon's word that the sandbox ended.
			b.lastEnd = "was given up after an answer this server could not trust; its close was requested and its end is unknown"
		}
		if b.sess.Ended() != nil || b.sess.Stopped() != nil {
			s.retire(b, b.sess)
			b.sess = nil
			// A model that reads only "not usable" closes the handle and opens another; the
			// handle itself goes on (the blind trial of 15 October lost turns to that).
			f.Summary += fmt.Sprintf(" Sandbox %s's sandbox has ended, its files and interpreter state with it. The handle still works: its next run_code starts a new sandbox (with the kit it was opened with, if any); close_sandbox frees its place.", handle)
		}
		f.SandboxUsable = ptr(b.sess != nil)
		return runOutput{}, f
	}
}

// Shutdown stops admitting work and cancels every call in progress. Close calls it.
func (s *Server) Shutdown() {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	s.stop()
}

// Close shuts the server down: no tool call is admitted, calls in progress are
// cancelled, and one cleanup closes every sandbox (an idle one at once), waits for the
// calls admitted before shutdown and for background closes, and then ends the receipt
// store. Close waits for that cleanup until ctx ends; the cleanup goes on after it, so
// it finishes without another Close (a host may not wait: Claude Code ends a stdio
// server within half a second, which is why each sandbox has a bounded lifetime).
func (s *Server) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.Shutdown()
		s.closeDone = make(chan struct{})
		go func() {
			s.closeErr = s.cleanup()
			close(s.closeDone)
		}()
	})
	select {
	case <-s.closeDone:
		return s.closeErr
	case <-ctx.Done():
		return fmt.Errorf("closing sandboxes and receipts goes on in the background; the time to wait for it ran out: %w", ctx.Err())
	}
}

// cleanup is the one owner of shutdown's work. It waits without a deadline of its own:
// each close it starts is bounded, and a write in progress cannot be interrupted.
func (s *Server) cleanup() error {
	// An idle box closes at once; a busy one when its call ends, however long a stuck
	// receipt write takes, and then within a budget of its own.
	s.mu.Lock()
	var last []*closing
	for h, b := range s.boxes {
		delete(s.boxes, h)
		last = append(last, s.closeBoxLocked(b))
	}
	s.mu.Unlock()
	// The calls admitted before Shutdown end (any closing they start is registered
	// before they do), then every closing, those started by closings included.
	s.calls.Wait()
	var errs []error
	for _, c := range last {
		<-c.done
		errs = append(errs, c.result.err)
	}
	for {
		s.mu.Lock()
		var unfinished []*closing
		for c := range s.closings {
			unfinished = append(unfinished, c)
		}
		s.mu.Unlock()
		if len(unfinished) == 0 {
			break
		}
		for _, c := range unfinished {
			<-c.done
		}
	}
	s.receipts.Close()
	return errors.Join(errs...)
}

// endWhy is a sandbox's end in words for a result: the daemon's detail (out of memory, with the
// limit) and its reason.
func endWhy(err error) string {
	var e *sandbox.SessionEndedError
	switch {
	case errors.As(err, &e) && e.Detail != "":
		return fmt.Sprintf("%s: %s", e.Reason, e.Detail)
	case errors.As(err, &e):
		return e.Reason.String()
	case err != nil:
		// Not the daemon's word on the end (a transport or a client failure): its text can
		// carry an address, so the model is told the kind, not the text.
		return "the server could not learn how it ended"
	}
	return "it ended"
}
