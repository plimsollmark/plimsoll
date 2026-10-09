package rpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// SessionConfig is the operator's session settings. Sessions are off unless
// MaxSessions is positive, since a session holds a sandbox between calls.
type SessionConfig struct {
	MaxSessions int // open sessions at once, daemon-wide; 0 = sessions off
	// MaxPerCaller is how many of them one principal may hold, suspended ones
	// included; 0 = no cap beyond MaxSessions. A suspended session holds no
	// concurrency slot, so the per-caller concurrency cap alone does not stop one
	// caller from taking every place.
	MaxPerCaller int
	// MaxPerOwner is how many of a principal's sessions one owner (the end user a
	// session is for, OpenSessionRequest.owner) may hold; 0 = no per-owner cap. At
	// the cap, an open closes that owner's least recently used session with no call
	// in progress, so an app running as many processes keeps each user to the cap
	// without locking a user out of new conversations until an old one expires.
	MaxPerOwner int
	Lifetime    time.Duration // absolute, from open; a request may ask for less
	IdleTimeout time.Duration // a session idle this long is suspended; a request may ask for less
	DiskBytes   int64         // what a session's calls may leave behind; 0 = no bound
}

// tombstoneTTL is how long a session that ended by itself stays collectable: its
// owner's CloseSession still gets the final call count and last record, which a
// harness needs to prove the chain was not cut. It only has to outlast the gap
// between the end and a running client's close; ten minutes is a judgment, not a
// measurement, and the rate limit on OpenSession bounds how many can pile up.
const tombstoneTTL = 10 * time.Minute

// sessionSuspendBudget bounds an idle suspend. It sits above the provider's own
// bound, so a slow stop is the provider's to report (openshell allows 60 s for a stop
// and its wait, stopBudget); the margin beyond that is a judgment, not a measurement.
const sessionSuspendBudget = 90 * time.Second

// sessionOpenCharge is what an open on a provider billed by the second reserves for
// itself, besides the idle time after it: its sandbox bills from its create, and an
// E2B open (create, the machine's preparation, the process list) takes seconds, well
// within it.
const sessionOpenCharge = 2 * time.Minute

// sessionOrphanCloseBudget bounds closing a session opened for a caller that gave up:
// nobody waits for that close, but its handler, slot and place do, so it gets the
// suspend's bound, which covers a provider's stop.
var sessionOrphanCloseBudget = sessionSuspendBudget

// sessionEntry is one session in the registry. calls, last and the slot change only
// with turn held, so the chain numbers calls in the order they executed.
type sessionEntry struct {
	id          string // the capability; never logged or recorded
	fingerprint string
	principal   string
	owner       string // OpenSessionRequest.owner; never logged or recorded
	sess        sandbox.Session
	software    sandbox.Environments // identities captured when the session opened
	rule        sandbox.SoftwareRule
	idleTimeout time.Duration
	turn        chan struct{} // one call at a time, in order
	waiting     chan struct{} // the one call (or close) allowed to wait for turn

	mu      sync.Mutex
	calls   uint64
	last    string
	release func() // the held concurrency slot; nil while suspended or ended
	idle    *time.Timer
	// idleAt is when the idle timer last armed was set to fire.
	idleAt time.Time
	// idleGen numbers the idle timers: stopping one or arming the next moves it on, so
	// a timer that fired before it was stopped finds its number stale and does nothing.
	idleGen uint64
	ended   bool
	// replaced: the daemon is closing it for a newer session of its owner. It no
	// longer counts against any cap, and its calls are refused as replaced.
	replaced bool
	used     uint64        // the registry's clock at open and at the end of each call
	gone     chan struct{} // closed once the session has ended and given back its slot
	// paid charges the session's running time on a provider billed by the second
	// (spend.go); nil otherwise.
	paid *sessionMeter
}

// endErr is the session's end as its calls and its close report it: replaced when
// the daemon took it for a newer session of its owner, whatever the provider says.
func (e *sessionEntry) endErr() error {
	e.mu.Lock()
	replaced := e.replaced
	e.mu.Unlock()
	err := e.sess.Err()
	// An end the provider reached by itself (an expiry between the choice and the
	// close, say) is that end; only the close the replacement made is a replacement.
	if replaced && (err == nil || sandbox.SessionEndReason(err) == sandbox.SessionClosed) {
		return &sandbox.SessionEndedError{Reason: sandbox.SessionReplaced,
			Detail: "the daemon closed it to open a newer session for the same owner, which was at its cap"}
	}
	return err
}

type sessionRegistry struct {
	mu        sync.Mutex
	byID      map[string]*sessionEntry
	opening   int            // reservations taken by opens still creating their sandbox
	openingBy map[string]int // the same, by principal and by ownerKey
	clock     atomic.Uint64  // orders sessions by last use
}

// ownerKey names one owner of one principal: owners of different callers never meet.
func ownerKey(principal, owner string) string { return principal + "\x00" + owner }

// tick is the registry's clock, for least recently used.
func (r *sessionRegistry) tick() uint64 { return r.clock.Add(1) }

// reserve takes one of the session places for an open about to create its sandbox,
// counting the sessions that have not ended and the opens already under way, all
// under one lock: two opens at once cannot both see the last place free. add turns
// the reservation into the session; an open that fails gives it back with unreserve.
// A principal past MaxPerCaller (0 = no cap) is refused the same way, its own
// sessions and opens counted.
//
// An owner at MaxPerOwner (0 = no cap; "" = no owner, counted against none) does
// not refuse: its least recently used sessions with no call in progress are taken
// for the open, their turns held so no call starts on them, marked replaced so no
// cap counts them, and returned for the caller to close. Only when too few of them
// are idle is the open refused. A replaced session's place passes to the open, so
// the daemon-wide and per-caller caps cannot refuse an open that replaced one.
func (r *sessionRegistry) reserve(c SessionConfig, principal, owner string) ([]*sessionEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var victims []*sessionEntry
	if owner != "" && c.MaxPerOwner > 0 {
		key := ownerKey(principal, owner)
		var held []*sessionEntry
		for _, e := range r.byID {
			e.mu.Lock()
			// A session the provider has ended is going anyway: it is no victim.
			if e.principal == principal && e.owner == owner && !e.ended && !e.replaced && e.sess.Err() == nil {
				held = append(held, e)
			}
			e.mu.Unlock()
		}
		need := len(held) + r.openingBy[key] + 1 - c.MaxPerOwner
		if need > 0 {
			sort.Slice(held, func(i, j int) bool { return held[i].lastUsed() < held[j].lastUsed() })
			for _, e := range held {
				if len(victims) == need {
					break
				}
				select {
				case e.turn <- struct{}{}: // idle: no call, close, or suspend in progress
					victims = append(victims, e)
				default:
				}
			}
			if len(victims) < need {
				for _, e := range victims {
					<-e.turn
				}
				return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity,
					fmt.Errorf("%w: this owner has %d sessions open, the most one owner keeps, and none can be closed now (each is running a call, suspending, closing, or already taken by another open)", sandbox.ErrAtCapacity, c.MaxPerOwner))
			}
			for _, e := range victims {
				e.mu.Lock()
				e.replaced = true
				e.mu.Unlock()
			}
		}
	}
	var err error
	if r.openLocked("")+r.opening >= c.MaxSessions {
		err = refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity,
			fmt.Errorf("%w: %d sessions are open, the most this daemon keeps", sandbox.ErrAtCapacity, c.MaxSessions))
	} else if c.MaxPerCaller > 0 && r.openLocked(principal)+r.openingBy[principal] >= c.MaxPerCaller {
		err = refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity,
			fmt.Errorf("%w: this caller has %d sessions open, the most one caller keeps", sandbox.ErrAtCapacity, c.MaxPerCaller))
	}
	if err != nil {
		// Unreachable once a session was replaced (its place passed to this open), but
		// a refusal must leave every session as it found it.
		for _, e := range victims {
			e.mu.Lock()
			e.replaced = false
			e.mu.Unlock()
			<-e.turn
		}
		return nil, err
	}
	r.opening++
	if r.openingBy == nil {
		r.openingBy = make(map[string]int)
	}
	r.openingBy[principal]++
	if owner != "" {
		r.openingBy[ownerKey(principal, owner)]++
	}
	return victims, nil
}

// restore gives sessions reserve took back to their owner, counted again and their
// turns released, for an open that will not replace them after all.
func (r *sessionRegistry) restore(victims []*sessionEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range victims {
		e.mu.Lock()
		e.replaced = false
		e.mu.Unlock()
		<-e.turn
	}
}

func (r *sessionRegistry) unreserve(principal, owner string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opening--
	r.doneOpeningLocked(principal, owner)
}

func (r *sessionRegistry) doneOpeningLocked(principal, owner string) {
	keys := []string{principal}
	if owner != "" {
		keys = append(keys, ownerKey(principal, owner))
	}
	for _, k := range keys {
		if r.openingBy[k]--; r.openingBy[k] <= 0 {
			delete(r.openingBy, k)
		}
	}
}

func (e *sessionEntry) lastUsed() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.used
}

// add registers an opened session in the place its open reserved.
func (r *sessionRegistry) add(e *sessionEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byID == nil {
		r.byID = make(map[string]*sessionEntry)
	}
	r.byID[e.id] = e
	r.opening--
	r.doneOpeningLocked(e.principal, e.owner)
}

func (r *sessionRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, id)
}

// get returns the entry only to the principal that opened it. An unknown ID and
// another principal's ID are the same miss, so an ID's existence never leaks.
func (r *sessionRegistry) get(id, principal string) (*sessionEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byID[id]
	if !ok || e.principal != principal {
		return nil, false
	}
	return e, true
}

// openLocked counts the sessions that have not ended and are not being replaced, of
// one principal or ("") all.
func (r *sessionRegistry) openLocked(principal string) int {
	n := 0
	for _, e := range r.byID {
		if principal != "" && e.principal != principal {
			continue
		}
		e.mu.Lock()
		if !e.ended && !e.replaced {
			n++
		}
		e.mu.Unlock()
	}
	return n
}

// errSessionNotFound is the answer for an unknown or a foreign session ID, the same for
// both. It carries a session end, so a client stops using the ID and opens a new session
// on its own: after a restart, which forgets every session, a conversation's next call
// otherwise found the same refusal until its idle close.
func errSessionNotFound() error {
	ce := refuse(connect.CodeNotFound, sandbox.RefusalRequest, errors.New("no such session for this caller"))
	if d, err := connect.NewErrorDetail(&plimsollv1.SessionEnded{Reason: plimsollv1.SessionEnd_SESSION_END_NOT_FOUND, Detail: "no such session for this caller"}); err == nil {
		ce.AddDetail(d)
	}
	return ce
}

// takeTurn waits for the session's turn, refusing at once, not dispatched, when
// another call already waits for it. A client makes one call at a time; without the
// bound, one caller could park any number of requests on its own session, each holding
// a handler and a connection. The returned function gives the turn back.
func (e *sessionEntry) takeTurn(ctx context.Context) (func(), error) {
	if ctx.Err() != nil {
		// A caller that has gone takes no turn, so it spends no rate token and takes
		// no slot for a session it will not use.
		return nil, busy(ctx)
	}
	select {
	case e.turn <- struct{}{}:
		return func() { <-e.turn }, nil
	default:
	}
	select {
	case e.waiting <- struct{}{}:
	default:
		return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity,
			errors.New("another call is already waiting for this session's turn"))
	}
	defer func() { <-e.waiting }()
	select {
	case e.turn <- struct{}{}:
		return func() { <-e.turn }, nil
	case <-ctx.Done():
		return nil, busy(ctx)
	}
}

// busy is the refusal of a call that gave up waiting for its session's turn: the
// session was busy with an earlier call, and nothing of this one ran.
func busy(ctx context.Context) error {
	return mapSandboxErr(sandbox.RefuseGaveUp(ctx))
}

// sessionProvider is the provider's sessions, when it has them and the operator
// enabled them.
func (s *SandboxService) sessionProvider() (sandbox.SessionProvider, bool) {
	sp, ok := s.Sandbox.(sandbox.SessionProvider)
	if !ok || !sp.SupportsSessions() || s.Sessions.MaxSessions <= 0 || s.Sessions.Lifetime <= 0 {
		return nil, false
	}
	return sp, true
}

// minSessionIdle is the shortest idle timeout a caller may ask for. An idle suspend
// that finds a call running tries again one idle timeout later, so a millisecond
// would re-arm a timer a thousand times a second for the length of a long call.
const minSessionIdle = time.Second

// shorter is the operator's duration, or the request's when it asks for less.
func shorter(configured time.Duration, requestedMs uint32) time.Duration {
	if req := time.Duration(requestedMs) * time.Millisecond; req > 0 && req < configured {
		return req
	}
	return configured
}

// OpenSession opens a session for the calling principal.
func (s *SandboxService) OpenSession(ctx context.Context, req *connect.Request[plimsollv1.OpenSessionRequest]) (*connect.Response[plimsollv1.OpenSessionResponse], error) {
	m := req.Msg
	env, err := parseEnvelope(m.GetProtocol(), m.GetMinimumIsolation(), 0, m.GetTraceId(), m.GetSoftwareRule())
	if err != nil {
		return nil, err
	}
	sp, ok := s.sessionProvider()
	if !ok {
		return nil, refuse(connect.CodeUnimplemented, sandbox.RefusalUnsupported,
			fmt.Errorf("%w: this daemon has no sessions (the provider has none, or SANDBOX_MAX_SESSIONS is unset)", sandbox.ErrUnsupported))
	}
	if err := sandbox.CheckMinimumIsolation(s.Sandbox.IsolationClass(), env.minimum); err != nil {
		return nil, mapSandboxErr(err)
	}
	// Every call of a session runs where the provider says sessions run, which on
	// docker is not where a single snippet runs.
	software := sp.SessionEnvironments()
	if err := env.software.Check(software.JavaScript.SoftwareIdentity); err != nil {
		return nil, mapSandboxErr(err)
	}
	if err := env.software.Check(software.Project.SoftwareIdentity); err != nil {
		return nil, mapSandboxErr(err)
	}
	hint := make([]sandbox.Language, len(m.GetLanguages()))
	for i, l := range m.GetLanguages() {
		hint[i] = sandbox.Language(l)
	}
	languages, err := sandbox.SessionLanguages(hint, software.Project.Languages)
	if err != nil {
		return nil, mapSandboxErr(err)
	}
	owner := m.GetOwner()
	if _, bad := sanitizeTraceID(owner); bad {
		return nil, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest,
			fmt.Errorf("%w: owner must be 1 to 64 of A-Z, a-z, 0-9 and . _ : -", sandbox.ErrInvalidRequest))
	}
	principal := auditCaller(ctx)
	replaced, err := s.sessions.reserve(s.Sessions, principal, owner)
	if err != nil {
		return nil, err
	}
	// The place reserve took goes back on every path that ends before the session is
	// added, once, here.
	placed := false
	defer func() {
		if !placed {
			s.sessions.unreserve(principal, owner)
		}
	}()
	lifetime := shorter(s.Sessions.Lifetime, m.GetLifetimeMs())
	idle := shorter(s.Sessions.IdleTimeout, m.GetIdleTimeoutMs())
	if idle > 0 && idle < minSessionIdle {
		idle = minSessionIdle
	}
	// On a provider billed by the second the open reserves its own time and the idle
	// time before the session's first suspend, before anything is made; a session that
	// never suspends would bill for its whole lifetime, so one needs an idle timeout.
	var paid *sessionMeter
	stopPaid := func() {}
	if teardown := s.meteredTeardown(); teardown > 0 {
		if idle <= 0 {
			s.sessions.restore(replaced)
			return nil, refuse(connect.CodeFailedPrecondition, sandbox.RefusalEnvironment,
				fmt.Errorf("%w: a session on a provider billed by the second needs an idle timeout, so it stops billing when idle", sandbox.ErrUnsupported))
		}
		p, _ := PrincipalFrom(ctx)
		paid = s.Spend.meter(principal, p.PaidSecondsPerDay)
		if err := paid.cover(sessionOpenCharge + idle + teardown); err != nil {
			s.sessions.restore(replaced)
			return nil, err
		}
		stopPaid = func() { paid.stop() }
	}
	release, err := s.admitOpen(ctx, principal, replaced)
	if err != nil {
		stopPaid()
		return nil, err
	}
	// A session closed before it is handed over is charged until its sandbox is gone.
	stopPaidOnDone := func(sess sandbox.Session) {
		if paid != nil {
			go func() {
				<-sess.Done()
				paid.stop()
				s.oweLeak(principal, sess, "")
			}()
		}
	}
	started := time.Now()
	// A failed open's slot comes back once whatever sandbox it made is gone, which a
	// provider that deletes it off the result path holds past the return (HoldCapacity).
	openCtx, openFailed := sandbox.WithCapacity(ctx, release)
	// A failed open whose sandbox could not be deleted reports here until when it bills;
	// there is no session left to ask.
	openCtx, openLeaked := sandbox.WatchTeardownUntil(openCtx)
	sess, err := func() (sess sandbox.Session, err error) {
		// A provider that panics while opening is a failed open, so its place and its
		// slot come back below instead of staying taken until a restart. Unmarked: it may
		// have made a sandbox.
		defer func() {
			if r := recover(); r != nil {
				s.logger().LogAttrs(ctx, slog.LevelError, "session open panicked", slog.Any("panic", r))
				sess, err = nil, errors.New("the provider failed while opening the session")
			}
		}()
		return sp.OpenSession(openCtx, sandbox.SessionOptions{MinimumIsolation: env.minimum, Lifetime: lifetime, DiskBytes: s.Sessions.DiskBytes, Languages: languages})
	}()
	if err != nil {
		openFailed()
		stopPaid()
		if gave, until := openLeaked(); gave && paid != nil {
			owed := s.Spend.owe(principal, until)
			s.logger().Warn("a failed session open left a sandbox its delete could not remove; charged until the provider's own lifetime for it ends",
				"caller", principal, "owed_seconds", owed)
		}
		attrs := []slog.Attr{
			slog.String("caller", auditCaller(ctx)),
			slog.String("sandbox", s.Sandbox.Name()),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()),
			slog.String("error", err.Error()),
		}
		s.logger().LogAttrs(ctx, slog.LevelError, "session open failed", append(attrs, traceAttrs(env.traceID)...)...)
		return nil, mapSandboxErr(err)
	}
	// A caller that gave up while the sandbox opened never learns the session's ID,
	// so the session would hold its place until it expired.
	if ctx.Err() != nil {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionOrphanCloseBudget)
		_ = sess.Close(closeCtx)
		cancel()
		go releaseOnDone(sess, release)
		stopPaidOnDone(sess)
		return nil, mapSandboxErr(sandbox.RefuseGaveUp(ctx))
	}
	// The rule again, against what the opened session runs: the provider can refresh
	// its image during the open, so what it stated before may name an earlier one
	// (review F10). Nothing has run in the session, so the refusal is not dispatched,
	// and the session's identity, not the earlier statement, is what the entry, the
	// answer and every call's record carry.
	software = sess.Environments()
	err = env.software.Check(software.JavaScript.SoftwareIdentity)
	if err == nil {
		err = env.software.Check(software.Project.SoftwareIdentity)
	}
	if err != nil {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionOrphanCloseBudget)
		_ = sess.Close(closeCtx)
		cancel()
		go releaseOnDone(sess, release)
		stopPaidOnDone(sess)
		return nil, mapSandboxErr(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionOrphanCloseBudget)
		_ = sess.Close(closeCtx)
		cancel()
		go releaseOnDone(sess, release)
		stopPaidOnDone(sess)
		return nil, mapSandboxErr(err)
	}
	e := &sessionEntry{
		id:          hex.EncodeToString(id),
		principal:   principal,
		owner:       owner,
		used:        s.sessions.tick(),
		sess:        sess,
		software:    software,
		rule:        env.software,
		idleTimeout: idle,
		turn:        make(chan struct{}, 1),
		waiting:     make(chan struct{}, 1),
		release:     release,
		gone:        make(chan struct{}),
		paid:        paid,
	}
	e.fingerprint = record.SessionFingerprint(e.id)
	s.sessions.add(e)
	placed = true
	e.mu.Lock()
	e.armIdle(s)
	e.mu.Unlock()
	go s.watch(e)
	attrs := []slog.Attr{
		slog.String("caller", e.principal),
		slog.String("session", e.fingerprint),
		slog.String("sandbox", s.Sandbox.Name()),
		slog.String("isolation", sess.Isolation().String()),
		slog.Int64("lifetime_ms", lifetime.Milliseconds()),
		slog.Int64("idle_timeout_ms", idle.Milliseconds()),
		slog.Int64("duration_ms", time.Since(started).Milliseconds()),
	}
	if len(languages) > 0 {
		names := make([]string, len(languages))
		for i, l := range languages {
			names[i] = string(l)
		}
		attrs = append(attrs, slog.String("languages", strings.Join(names, ",")))
	}
	s.logger().LogAttrs(ctx, slog.LevelInfo, "session opened", append(attrs, traceAttrs(env.traceID)...)...)
	return connect.NewResponse(&plimsollv1.OpenSessionResponse{
		SessionId:        e.id,
		Session:          e.fingerprint,
		Sandbox:          s.Sandbox.Name(),
		Isolation:        sess.Isolation().String(),
		ExpiresUnixMs:    sess.ExpiresAt().UnixMilli(),
		IdleTimeoutMs:    uint32(idle / time.Millisecond),
		SoftwareIdentity: software.JavaScript.SoftwareIdentity,
	}), nil
}

// replace closes a session reserve took for a newer session of its owner, holding
// its turn (taken by reserve), and reports whether it held a concurrency slot, which
// comes back only once its sandbox is gone. Its later calls are refused as replaced.
func (s *SandboxService) replace(ctx context.Context, e *sessionEntry) (took bool) {
	e.mu.Lock()
	e.stopIdle()
	e.mu.Unlock()
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionOrphanCloseBudget)
	defer cancel()
	err := func() (err error) {
		// A provider that panics while closing has not closed it, as far as anyone can
		// tell; the session is given back below rather than left half replaced.
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("the provider panicked while closing: %v", r)
			}
		}()
		return e.sess.Close(closeCtx)
	}()
	// The close took if it says so, or if the session ended anyway.
	took = err == nil || e.sess.Err() != nil
	if !took {
		s.logger().Warn("replaced session close failed; it stays open", "session", e.fingerprint, "error", err.Error())
		s.sessions.restore([]*sessionEntry{e})
		e.mu.Lock()
		e.armIdle(s)
		e.mu.Unlock()
		return false
	}
	<-e.turn
	s.logger().LogAttrs(ctx, slog.LevelInfo, "session replaced",
		slog.String("caller", e.principal), slog.String("session", e.fingerprint))
	return true
}

// admitOpen admits an open, and only then closes the sessions reserve took for it
// (victims), so a refused open (its caller gone, its rate spent, no slot) closes
// nothing. The open's concurrency slot is the first victim's that holds one, taken
// over rather than freed and taken again, so a full daemon cannot refuse it, and the
// open then waits, within the request's bound, for that victim's sandbox to be gone,
// since the slot stands for its memory. A victim whose close fails stays open and
// counted, and the open is refused.
func (s *SandboxService) admitOpen(ctx context.Context, principal string, victims []*sessionEntry) (func(), error) {
	if ctx.Err() != nil {
		s.sessions.restore(victims)
		return nil, mapSandboxErr(sandbox.RefuseGaveUp(ctx))
	}
	if len(victims) == 0 {
		return s.limit(ctx)
	}
	var src *sessionEntry
	var release func()
	for i, v := range victims {
		v.mu.Lock()
		if v.release != nil {
			src, release, v.release = v, v.release, nil // watch will not give it back now
		}
		v.mu.Unlock()
		if src != nil {
			// Closed first, so a later victim's failed close finds it closed already.
			victims = append([]*sessionEntry{src}, append(victims[:i:i], victims[i+1:]...)...)
			break
		}
	}
	giveBack := func() {
		if src != nil {
			src.mu.Lock()
			src.release = release
			src.mu.Unlock()
		} else if release != nil {
			release()
		}
	}
	var err error
	if src != nil {
		if s.Limiter != nil {
			err = s.Limiter.Charge(principal) // the slot is taken over; the start still counts
		}
	} else {
		release, err = s.limit(ctx)
	}
	if err != nil {
		giveBack()
		s.sessions.restore(victims)
		return nil, err
	}
	for i, v := range victims {
		if !s.replace(ctx, v) {
			// v is open and counted again; the victims after it were not touched.
			s.sessions.restore(victims[i+1:])
			switch {
			case v == src:
				giveBack()
			case src != nil:
				go releaseOnDone(src.sess, release) // src, first, is closing: its slot comes back when it is gone
			default:
				release()
			}
			return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity,
				fmt.Errorf("%w: the owner's least recently used session could not be closed to make room", sandbox.ErrAtCapacity))
		}
	}
	if src != nil {
		select {
		case <-src.sess.Done():
		case <-ctx.Done():
			go releaseOnDone(src.sess, release)
			return nil, mapSandboxErr(sandbox.RefuseGaveUp(ctx))
		}
	}
	return release, nil
}

// oweLeak charges a session's caller, after its end, for a sandbox the provider could
// not delete and that bills on until the provider's own lifetime for it ends
// (sandbox.BillsUntiler). label names the session in the log when it was handed over.
func (s *SandboxService) oweLeak(principal string, sess sandbox.Session, label string) {
	bu, ok := sess.(sandbox.BillsUntiler)
	if !ok {
		return
	}
	until := bu.BillsUntil()
	if until.IsZero() {
		return
	}
	if owed := s.Spend.owe(principal, until); owed > 0 {
		s.logger().Warn("a session's sandbox outlived its delete; charged until the provider's own lifetime for it ends",
			"session", label, "caller", principal, "owed_seconds", owed)
	}
}

// releaseOnDone gives back a closed session's slot once its sandbox is gone (Done).
func releaseOnDone(sess sandbox.Session, release func()) {
	<-sess.Done()
	release()
}

// watch waits for the session to end, however it ends, and gives back its slot.
// An entry that ended by itself stays collectable for tombstoneTTL.
func (s *SandboxService) watch(e *sessionEntry) {
	<-e.sess.Done()
	if e.paid != nil {
		// Done closes once the sandbox is deleted, so the charge covers the delete.
		s.logger().Info("session paid time", "session", e.fingerprint, "paid_seconds", e.paid.stop())
		s.oweLeak(e.principal, e.sess, e.fingerprint)
	}
	e.mu.Lock()
	e.ended = true
	e.stopIdle()
	if e.release != nil {
		e.release()
		e.release = nil
	}
	e.mu.Unlock()
	close(e.gone)
	time.AfterFunc(tombstoneTTL, func() { s.sessions.remove(e.id) })
}

// stopIdle stops the idle timer and makes any callback of it already fired stale;
// e.mu is held. Stop alone cannot recall a callback that has fired and not yet run.
func (e *sessionEntry) stopIdle() {
	if e.idle != nil {
		e.idle.Stop()
	}
	e.idleGen++
}

// armIdle starts the idle timer for a full idle period from now; e.mu is held.
func (e *sessionEntry) armIdle(s *SandboxService) {
	e.armIdleAt(s, time.Now().Add(e.idleTimeout))
}

// armIdleAt starts the idle timer to fire at at, at once when at has passed; e.mu is
// held.
func (e *sessionEntry) armIdleAt(s *SandboxService, at time.Time) {
	if e.idleTimeout <= 0 || e.ended || e.replaced {
		return
	}
	e.stopIdle()
	gen := e.idleGen
	e.idleAt = at
	e.idle = time.AfterFunc(max(time.Until(at), 0), func() { s.suspend(e, gen) })
}

// suspend suspends an idle session and gives back its slot, unless a call has
// taken the turn in the meantime. A session whose suspended sandbox still holds its
// memory (a paused container) keeps its slot: the slot is its share of the host's
// memory budget, and that memory is still in use.
func (s *SandboxService) suspend(e *sessionEntry, gen uint64) {
	select {
	case e.turn <- struct{}{}:
	default:
		// A call holds the turn. It rearms the timer when it ends, but it does so
		// before giving the turn back, so a short idle timeout can fire in between and
		// land here: rearm, or nothing would suspend the session until its next call.
		e.mu.Lock()
		if gen == e.idleGen {
			e.armIdle(s)
		}
		e.mu.Unlock()
		return
	}
	defer func() { <-e.turn }()
	e.mu.Lock()
	// A timer that fired, then waited while a call took the turn, ran and armed a fresh
	// one, is stale: the session was used since, and suspending it now would end the
	// interpreters (on e2b) of a call that just finished (round-3 review).
	if gen != e.idleGen || e.ended || e.release == nil || e.sess.Err() != nil {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), sessionSuspendBudget)
	defer cancel()
	holdsMemory, err := func() (holds bool, err error) {
		// This runs on a timer's goroutine, where a panic would end the daemon: a
		// provider that panics while suspending has failed to suspend.
		defer func() {
			if r := recover(); r != nil {
				holds, err = false, fmt.Errorf("the provider panicked while suspending: %v", r)
			}
		}()
		return e.sess.Suspend(ctx)
	}()
	if err != nil {
		if e.sess.Err() == nil {
			// The session goes on (the suspend gave up waiting for a turn its recovery
			// held): try again after another idle period, or an abandoned session would
			// keep its slot for its whole lifetime. A failure the session cannot survive
			// ends it, so this cannot repeat faster than the idle timeout.
			s.logger().Warn("session suspend failed", "session", e.fingerprint, "error", err.Error())
			// Still running and still billing: another idle period is reserved, or, when
			// the allowance cannot cover it, the session is closed rather than run unpaid.
			if e.paid != nil {
				if perr := e.paid.cover(e.idleTimeout + s.meteredTeardown()); perr != nil {
					s.logger().Warn("session closed: it could not be suspended and its paid allowance cannot cover another idle period",
						"session", e.fingerprint, "error", perr.Error())
					_ = e.sess.Close(ctx)
					return
				}
			}
			e.mu.Lock()
			e.armIdle(s)
			e.mu.Unlock()
		}
		return
	}
	if e.paid != nil {
		// A suspended sandbox of a provider billed by the second no longer bills.
		e.paid.stop()
	}
	if !holdsMemory {
		e.mu.Lock()
		if e.release != nil {
			e.release()
			e.release = nil
		}
		e.mu.Unlock()
	}
	s.logger().Info("session suspended", "session", e.fingerprint, "idle_ms", e.idleTimeout.Milliseconds(), "holds_memory", holdsMemory)
}

// SessionRun runs one call in the caller's session.
func (s *SandboxService) SessionRun(ctx context.Context, req *connect.Request[plimsollv1.SessionRunRequest]) (*connect.Response[plimsollv1.SessionRunResponse], error) {
	received := time.Now()
	m := req.Msg
	env, err := parseEnvelope(m.GetProtocol(), m.GetMinimumIsolation(), m.GetTimeoutMs(), m.GetTraceId(), m.GetSoftwareRule())
	if err != nil {
		return nil, err
	}
	e, ok := s.sessions.get(m.GetSessionId(), auditCaller(ctx))
	if !ok {
		return nil, errSessionNotFound()
	}
	var k kind
	switch p := m.GetPayload().(type) {
	case *plimsollv1.SessionRunRequest_Javascript:
		k = &javascriptKind{p: p.Javascript}
	case *plimsollv1.SessionRunRequest_Project:
		k = &projectKind{p: p.Project}
	case *plimsollv1.SessionRunRequest_Cell:
		k = &cellKind{p: p.Cell, runner: e.sess}
	default:
		return nil, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest, errors.New("payload must be exactly one of javascript, project or cell"))
	}
	// The open's rule cannot be silently dropped by a raw session caller. The
	// request must carry the effective rule so its digest and record bind it.
	effective, err := sandbox.MergeSoftwareRules(e.rule, env.software)
	if err != nil {
		return nil, mapSandboxErr(err)
	}
	if effective.ID() != env.software.ID() {
		return nil, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest,
			fmt.Errorf("%w: session call omitted the software rule established at open", sandbox.ErrInvalidRequest))
	}
	callTimeout := reservation(env.timeout, k.environment(target{software: e.software}).MaxTimeout, 0)
	t := target{
		provider: s.Sandbox.Name(),
		tier:     e.sess.Isolation(),
		admit:    func(ctx context.Context) (func(), error) { return s.admitCall(ctx, e, callTimeout) },
		js:       e.sess.RunJavaScript,
		project:  e.sess.RunProject,
		software: e.software,
		session:  true,
	}
	// Checked before the turn: a call that can never run is refused as what it is, at
	// once, not after waiting behind the call in progress (and never as busy, which
	// invites a retry).
	ctx, err = s.check(ctx, env, k, t)
	if err != nil {
		return nil, err
	}
	// One call at a time, in arrival order, so the chain numbers calls as they ran.
	give, err := e.takeTurn(ctx)
	if err != nil {
		return nil, err
	}
	defer give()
	if err := e.endErr(); err != nil {
		return nil, refuseEnded(err)
	}
	e.mu.Lock()
	idleAt := e.idleAt
	e.stopIdle()
	e.mu.Unlock()
	// refused: nothing of this call ran. Such a call does not count as use, so the
	// session suspends when it would have without it: a fresh idle period after a
	// refusal let a caller keep a session billed by the second running past its
	// allowance by sending calls the allowance refuses (round-7 review, 2026-10-08).
	refused := false
	defer func() {
		e.mu.Lock()
		if refused && !idleAt.IsZero() {
			e.armIdleAt(s, idleAt)
		} else {
			e.armIdle(s)
			e.used = s.sessions.tick()
		}
		e.mu.Unlock()
	}()

	e.mu.Lock()
	seq := e.calls + 1
	e.mu.Unlock()
	t.attrs = []slog.Attr{slog.String("session", e.fingerprint), slog.Uint64("session_call", seq)}
	resp, err := func() (resp *plimsollv1.RunResponse, err error) {
		// A provider that panics may already have run the call. Recovered here, the
		// panic is an unmarked error, so the call is chained as unanswered like any
		// other that may have run, instead of unwinding past the chain.
		defer func() {
			if r := recover(); r != nil {
				s.logger().LogAttrs(ctx, slog.LevelError, "session call panicked", slog.String("session", e.fingerprint), slog.Any("panic", r))
				resp, err = nil, mapSandboxErr(errors.New("the provider failed during the call")) // unmarked: it may have run
			}
		}()
		return s.run(ctx, env, k, t)
	}()
	if err != nil {
		// The mark as the client reads it: an admission refusal (the caller's rate, no
		// slot) is marked by refuse, on the wire only.
		if _, marked := notDispatchedOf(err); marked {
			refused = true
			return nil, err // nothing ran, so the chain does not count it
		}
		return nil, s.unanswered(ctx, e, m, env, seq, received, err)
	}
	e.mu.Lock()
	link := sandbox.RunRecord{Session: e.fingerprint, Sequence: seq, PreviousSHA256: e.last}
	e.mu.Unlock()
	resp.Record = s.runRecord(record.SessionRunRequestDigest(m), resp, received, time.Now(), link, env.software)
	e.mu.Lock()
	e.calls, e.last = seq, resp.Record.GetRecordSha256()
	e.mu.Unlock()
	out := &plimsollv1.SessionRunResponse{Run: resp}
	// Err, not Done: Done waits for the sandbox's delete, and a call that ended the
	// session must say so in its own answer.
	var se *sandbox.SessionEndedError
	if errors.As(e.endErr(), &se) {
		out.Ended, out.EndDetail = sessionEndWire(se.Reason), wireString(se.Detail)
	}
	return connect.NewResponse(out), nil
}

// admitCall is a session call's admission: a slot first when the session is
// suspended (a capacity refusal there ran nothing and is safe to retry), then, on a
// provider billed by the second, its paid time (the call's timeout, the idle time
// after it, the teardown), then one run charged to the caller's rate. The slot stays
// held until the session is suspended again or ends.
func (s *SandboxService) admitCall(_ context.Context, e *sessionEntry, timeout time.Duration) (func(), error) {
	took := false
	giveBack := func() {
		if took {
			// The call is refused and the session was not resumed, so the slot this
			// call took goes back now, not at the next idle suspend. The release is
			// idempotent, so a concurrent end (watch) releasing it too is harmless.
			e.mu.Lock()
			if e.release != nil {
				e.release()
				e.release = nil
			}
			e.mu.Unlock()
		}
	}
	if s.Limiter != nil {
		e.mu.Lock()
		suspended := e.release == nil
		e.mu.Unlock()
		if suspended {
			rel, err := s.Limiter.Hold(e.principal)
			if err != nil {
				return nil, err
			}
			e.mu.Lock()
			if e.release == nil && !e.ended {
				e.release, took = rel, true
			} else {
				rel()
			}
			e.mu.Unlock()
		}
	}
	resuming := false
	if e.paid != nil {
		resuming = !e.paid.running()
		if err := e.paid.cover(timeout + e.idleTimeout + s.meteredTeardown()); err != nil {
			giveBack()
			return nil, err
		}
	}
	if s.Limiter != nil {
		if err := s.Limiter.Charge(e.principal); err != nil {
			giveBack()
			if resuming {
				e.paid.stop() // the session stays suspended: nothing ran, nothing bills
			}
			return nil, err
		}
	}
	return func() {}, nil
}

// meteredTeardown is the provider's BillingTeardown when it bills by the second and the
// daemon charges paid time (Spend); 0 otherwise.
func (s *SandboxService) meteredTeardown() time.Duration {
	if s.Spend == nil {
		return 0
	}
	return sandbox.MeteredTeardown(s.Sandbox)
}

// CloseSession ends the caller's session, or collects one that ended by itself, and
// states its chain's length and last record.
func (s *SandboxService) CloseSession(ctx context.Context, req *connect.Request[plimsollv1.CloseSessionRequest]) (*connect.Response[plimsollv1.CloseSessionResponse], error) {
	if err := checkProtocol(req.Msg.GetProtocol()); err != nil {
		return nil, err
	}
	e, ok := s.sessions.get(req.Msg.GetSessionId(), auditCaller(ctx))
	if !ok {
		return nil, errSessionNotFound()
	}
	// Wait for a call in flight, so the count covers it.
	give, err := e.takeTurn(ctx)
	if err != nil {
		return nil, err
	}
	defer give()
	e.mu.Lock()
	e.stopIdle()
	e.mu.Unlock()
	_ = e.sess.Close(ctx)
	// Close starts the end and Done says the sandbox is gone, which takes the
	// provider's delete. The wait is the caller's to bound: a provider slow to finish
	// must not hold the session's turn past it. The entry stays until Done, so closing
	// again collects the count. Unmarked, because the close has begun.
	select {
	case <-e.sess.Done():
	case <-ctx.Done():
		return nil, mapSandboxErr(fmt.Errorf("the session is still ending; close it again to collect its count: %w", ctx.Err()))
	}
	s.sessions.remove(e.id)
	end := sandbox.SessionClosed
	var se *sandbox.SessionEndedError
	if errors.As(e.endErr(), &se) {
		end = se.Reason
	}
	e.mu.Lock()
	calls, last := e.calls, e.last
	e.mu.Unlock()
	s.logger().LogAttrs(ctx, slog.LevelInfo, "session closed",
		slog.String("caller", e.principal),
		slog.String("session", e.fingerprint),
		slog.Uint64("calls", calls),
		slog.String("end", end.String()),
	)
	return connect.NewResponse(&plimsollv1.CloseSessionResponse{
		Session:          e.fingerprint,
		Calls:            calls,
		LastRecordSha256: last,
		Ended:            sessionEndWire(end),
	}), nil
}

// refuseEnded is the refusal of a call on an ended session: FailedPrecondition,
// marked not dispatched, with the end as a SessionEnded detail.
func refuseEnded(end error) error {
	return mapSandboxErr(sandbox.RefuseEndedSession(end))
}

var sessionEnds = map[sandbox.SessionEnd]plimsollv1.SessionEnd{
	sandbox.SessionClosed:           plimsollv1.SessionEnd_SESSION_END_CLOSED,
	sandbox.SessionExpired:          plimsollv1.SessionEnd_SESSION_END_EXPIRED,
	sandbox.SessionDiskExceeded:     plimsollv1.SessionEnd_SESSION_END_DISK_EXCEEDED,
	sandbox.SessionMainProcessEnded: plimsollv1.SessionEnd_SESSION_END_MAIN_PROCESS_ENDED,
	sandbox.SessionBoundaryFailed:   plimsollv1.SessionEnd_SESSION_END_BOUNDARY_FAILED,
	sandbox.SessionSandboxChanged:   plimsollv1.SessionEnd_SESSION_END_SANDBOX_CHANGED,
	sandbox.SessionShutdown:         plimsollv1.SessionEnd_SESSION_END_SHUTDOWN,
	sandbox.SessionReplaced:         plimsollv1.SessionEnd_SESSION_END_REPLACED,
	sandbox.SessionNotFound:         plimsollv1.SessionEnd_SESSION_END_NOT_FOUND,
}

func sessionEndWire(e sandbox.SessionEnd) plimsollv1.SessionEnd {
	return sessionEnds[e]
}

// unanswered chains the record of a session call that may have run but ended in err
// (an error without a not-dispatched mark) and returns err carrying it as an
// UnansweredCall detail. Without it the next call would chain cleanly, the close count
// would match the caller's, and a verified chain could hide a call that ran. The
// record's evidence is what the session stated at open, since there is no response to
// read it from, and its error code is plimsoll's own word for err, never err's text.
func (s *SandboxService) unanswered(ctx context.Context, e *sessionEntry, m *plimsollv1.SessionRunRequest, env envelope, seq uint64, received time.Time, err error) error {
	payload := e.software.Project
	if m.GetJavascript() != nil {
		payload = e.software.JavaScript
	}
	ce, ok := err.(*connect.Error)
	if !ok {
		errors.As(mapSandboxErr(err), &ce) // unmarked, as err is
	}
	e.mu.Lock()
	rec := record.StampUnanswered(sandbox.RunRecord{
		RequestSHA256:    record.SessionRunRequestDigest(m),
		Provider:         s.Sandbox.Name(),
		Isolation:        e.sess.Isolation().String(),
		Environment:      payload.Identity,
		SoftwareIdentity: payload.SoftwareIdentity,
		SoftwareRuleID:   env.software.ID(),
		Policy:           s.policy(),
		Started:          received,
		Ended:            recordEnd(received, time.Now()),
		Session:          e.fingerprint,
		Sequence:         seq,
		PreviousSHA256:   e.last,
	}, ce.Code().String())
	e.calls, e.last = seq, rec.GetRecordSha256()
	e.mu.Unlock()
	if detail, derr := connect.NewErrorDetail(&plimsollv1.UnansweredCall{Record: rec}); derr == nil {
		ce.AddDetail(detail)
	}
	s.logger().LogAttrs(ctx, slog.LevelWarn, "session call unanswered",
		slog.String("caller", auditCaller(ctx)), slog.String("session", e.fingerprint),
		slog.Uint64("session_call", seq), slog.String("session_call_unanswered", ce.Code().String()))
	return ce
}
