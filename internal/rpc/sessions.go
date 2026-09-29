package rpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// SessionConfig is the operator's session settings. Sessions are off unless
// MaxSessions is positive, since a session holds a sandbox between calls.
type SessionConfig struct {
	MaxSessions int           // open sessions at once, daemon-wide; 0 = sessions off
	Lifetime    time.Duration // absolute, from open; a request may ask for less
	IdleTimeout time.Duration // a session idle this long is suspended; a request may ask for less
	DiskBytes   int64         // what a session's calls may leave behind; 0 = no bound
}

// tombstoneTTL is how long a session that ended by itself stays collectable: its
// owner's CloseSession still gets the final call count and last record, which a
// harness needs to prove the chain was not cut.
const tombstoneTTL = 10 * time.Minute

// sessionSuspendBudget bounds an idle suspend.
const sessionSuspendBudget = 90 * time.Second

// sessionEntry is one session in the registry. calls, last and the slot change only
// with turn held, so the chain numbers calls in the order they executed.
type sessionEntry struct {
	id          string // the capability; never logged or recorded
	fingerprint string
	principal   string
	sess        sandbox.Session
	idleTimeout time.Duration
	turn        chan struct{} // one call at a time, in order

	mu      sync.Mutex
	calls   uint64
	last    string
	release func() // the held concurrency slot; nil while suspended or ended
	idle    *time.Timer
	ended   bool
}

type sessionRegistry struct {
	mu      sync.Mutex
	byID    map[string]*sessionEntry
	opening int // reservations taken by opens still creating their sandbox
}

// reserve takes one of max session places for an open about to create its sandbox,
// counting the sessions that have not ended and the opens already under way, all
// under one lock: two opens at once cannot both see the last place free. add turns
// the reservation into the session; an open that fails gives it back with unreserve.
func (r *sessionRegistry) reserve(max int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.openLocked()+r.opening >= max {
		return false
	}
	r.opening++
	return true
}

func (r *sessionRegistry) unreserve() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opening--
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

// openLocked counts the sessions that have not ended.
func (r *sessionRegistry) openLocked() int {
	n := 0
	for _, e := range r.byID {
		e.mu.Lock()
		if !e.ended {
			n++
		}
		e.mu.Unlock()
	}
	return n
}

func errSessionNotFound() error {
	return refuse(connect.CodeNotFound, sandbox.RefusalRequest, errors.New("no such session for this caller"))
}

// busy is the refusal of a call that gave up waiting for its session's turn: the
// session was busy with an earlier call, and nothing of this one ran.
func busy(ctx context.Context) error {
	return mapSandboxErr(sandbox.NotDispatched(sandbox.RefusalCapacity, ctx.Err()))
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
	env, err := parseEnvelope(m.GetProtocol(), m.GetMinimumIsolation(), 0, m.GetTraceId())
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
	if !s.sessions.reserve(s.Sessions.MaxSessions) {
		return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity,
			fmt.Errorf("%w: %d sessions are open, the most this daemon keeps", sandbox.ErrAtCapacity, s.Sessions.MaxSessions))
	}
	release, err := s.limit(ctx)
	if err != nil {
		s.sessions.unreserve()
		return nil, err
	}
	lifetime := shorter(s.Sessions.Lifetime, m.GetLifetimeMs())
	idle := shorter(s.Sessions.IdleTimeout, m.GetIdleTimeoutMs())
	started := time.Now()
	sess, err := sp.OpenSession(ctx, sandbox.SessionOptions{MinimumIsolation: env.minimum, Lifetime: lifetime, DiskBytes: s.Sessions.DiskBytes})
	if err != nil {
		release()
		s.sessions.unreserve()
		attrs := []slog.Attr{
			slog.String("caller", auditCaller(ctx)),
			slog.String("sandbox", s.Sandbox.Name()),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()),
			slog.String("error", err.Error()),
		}
		s.logger().LogAttrs(ctx, slog.LevelError, "session open failed", append(attrs, traceAttrs(env.traceID)...)...)
		return nil, mapSandboxErr(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		release()
		s.sessions.unreserve()
		_ = sess.Close(context.Background())
		return nil, mapSandboxErr(err)
	}
	e := &sessionEntry{
		id:          hex.EncodeToString(id),
		principal:   auditCaller(ctx),
		sess:        sess,
		idleTimeout: idle,
		turn:        make(chan struct{}, 1),
		release:     release,
	}
	e.fingerprint = record.SessionFingerprint(e.id)
	s.sessions.add(e)
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
	s.logger().LogAttrs(ctx, slog.LevelInfo, "session opened", append(attrs, traceAttrs(env.traceID)...)...)
	return connect.NewResponse(&plimsollv1.OpenSessionResponse{
		SessionId:     e.id,
		Session:       e.fingerprint,
		Sandbox:       s.Sandbox.Name(),
		Isolation:     sess.Isolation().String(),
		ExpiresUnixMs: sess.ExpiresAt().UnixMilli(),
		IdleTimeoutMs: uint32(idle / time.Millisecond),
	}), nil
}

// watch waits for the session to end, however it ends, and gives back its slot.
// An entry that ended by itself stays collectable for tombstoneTTL.
func (s *SandboxService) watch(e *sessionEntry) {
	<-e.sess.Done()
	e.mu.Lock()
	e.ended = true
	if e.idle != nil {
		e.idle.Stop()
	}
	if e.release != nil {
		e.release()
		e.release = nil
	}
	e.mu.Unlock()
	time.AfterFunc(tombstoneTTL, func() { s.sessions.remove(e.id) })
}

// armIdle starts the idle timer; e.mu is held.
func (e *sessionEntry) armIdle(s *SandboxService) {
	if e.idleTimeout <= 0 || e.ended {
		return
	}
	if e.idle != nil {
		e.idle.Stop()
	}
	e.idle = time.AfterFunc(e.idleTimeout, func() { s.suspend(e) })
}

// suspend suspends an idle session and gives back its slot, unless a call has
// taken the turn in the meantime.
func (s *SandboxService) suspend(e *sessionEntry) {
	select {
	case e.turn <- struct{}{}:
	default:
		return // a call is running; it rearms the timer when it ends
	}
	defer func() { <-e.turn }()
	e.mu.Lock()
	if e.ended || e.release == nil || e.sess.Err() != nil {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), sessionSuspendBudget)
	defer cancel()
	if err := e.sess.Suspend(ctx); err != nil {
		if e.sess.Err() == nil {
			s.logger().Warn("session suspend failed", "session", e.fingerprint, "error", err.Error())
		}
		return
	}
	e.mu.Lock()
	if e.release != nil {
		e.release()
		e.release = nil
	}
	e.mu.Unlock()
	s.logger().Info("session suspended", "session", e.fingerprint, "idle_ms", e.idleTimeout.Milliseconds())
}

// SessionRun runs one call in the caller's session.
func (s *SandboxService) SessionRun(ctx context.Context, req *connect.Request[plimsollv1.SessionRunRequest]) (*connect.Response[plimsollv1.SessionRunResponse], error) {
	received := time.Now()
	m := req.Msg
	env, err := parseEnvelope(m.GetProtocol(), m.GetMinimumIsolation(), m.GetTimeoutMs(), m.GetTraceId())
	if err != nil {
		return nil, err
	}
	e, ok := s.sessions.get(m.GetSessionId(), auditCaller(ctx))
	if !ok {
		return nil, errSessionNotFound()
	}
	if m.GetPayload() == nil {
		return nil, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest, errors.New("payload must be exactly one of javascript or project"))
	}
	// One call at a time, in arrival order, so the chain numbers calls as they ran.
	select {
	case e.turn <- struct{}{}:
	case <-ctx.Done():
		return nil, busy(ctx)
	}
	defer func() { <-e.turn }()
	if err := e.sess.Err(); err != nil {
		return nil, refuseEnded(err)
	}
	e.mu.Lock()
	if e.idle != nil {
		e.idle.Stop()
	}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.armIdle(s)
		e.mu.Unlock()
	}()

	e.mu.Lock()
	seq := e.calls + 1
	e.mu.Unlock()
	t := target{
		provider: s.Sandbox.Name(),
		tier:     e.sess.Isolation(),
		admit:    func(ctx context.Context) (func(), error) { return s.admitCall(ctx, e) },
		js:       e.sess.RunJavaScript,
		project:  e.sess.RunProject,
		attrs:    []slog.Attr{slog.String("session", e.fingerprint), slog.Uint64("session_call", seq)},
	}
	var resp *plimsollv1.RunResponse
	switch p := m.GetPayload().(type) {
	case *plimsollv1.SessionRunRequest_Javascript:
		resp, err = s.runJavaScript(ctx, env, p.Javascript, t)
	case *plimsollv1.SessionRunRequest_Project:
		resp, err = s.runProject(ctx, env, p.Project, t)
	}
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	link := sandbox.RunRecord{Session: e.fingerprint, Sequence: seq, PreviousSHA256: e.last}
	e.mu.Unlock()
	resp.Record = s.runRecord(record.SessionRunRequestDigest(m), resp, received, time.Now(), link)
	e.mu.Lock()
	e.calls, e.last = seq, resp.Record.GetRecordSha256()
	e.mu.Unlock()
	out := &plimsollv1.SessionRunResponse{Run: resp}
	select {
	case <-e.sess.Done():
		var se *sandbox.SessionEndedError
		if errors.As(e.sess.Err(), &se) {
			out.Ended, out.EndDetail = sessionEndWire(se.Reason), wireString(se.Detail)
		}
	default:
	}
	return connect.NewResponse(out), nil
}

// admitCall is a session call's admission: a slot first when the session is
// suspended (a capacity refusal there ran nothing and is safe to retry), then one
// run charged to the caller's rate. The slot stays held until the session is
// suspended again or ends.
func (s *SandboxService) admitCall(_ context.Context, e *sessionEntry) (func(), error) {
	if s.Limiter == nil {
		return func() {}, nil
	}
	e.mu.Lock()
	suspended := e.release == nil
	e.mu.Unlock()
	took := false
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
	if err := s.Limiter.Charge(e.principal); err != nil {
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
		return nil, err
	}
	return func() {}, nil
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
	select {
	case e.turn <- struct{}{}:
	case <-ctx.Done():
		return nil, busy(ctx)
	}
	defer func() { <-e.turn }()
	e.mu.Lock()
	if e.idle != nil {
		e.idle.Stop()
	}
	e.mu.Unlock()
	_ = e.sess.Close(ctx)
	// Close starts the end and Done says it has happened; nothing requires the two
	// to coincide. The wait is the caller's to bound: a provider slow to finish must
	// not hold the session's turn past it. The entry stays until Done, so closing
	// again collects the count. Unmarked, because the close has begun.
	select {
	case <-e.sess.Done():
	case <-ctx.Done():
		return nil, mapSandboxErr(fmt.Errorf("the session is still ending; close it again to collect its count: %w", ctx.Err()))
	}
	s.sessions.remove(e.id)
	end := sandbox.SessionClosed
	var se *sandbox.SessionEndedError
	if errors.As(e.sess.Err(), &se) {
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
}

func sessionEndWire(e sandbox.SessionEnd) plimsollv1.SessionEnd {
	return sessionEnds[e]
}
