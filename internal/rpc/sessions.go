package rpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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
	MaxSessions int // open sessions at once, daemon-wide; 0 = sessions off
	// MaxPerCaller is how many of them one principal may hold, suspended ones
	// included; 0 = no cap beyond MaxSessions. A suspended session holds no
	// concurrency slot, so the per-caller concurrency cap alone does not stop one
	// caller from taking every place.
	MaxPerCaller int
	Lifetime     time.Duration // absolute, from open; a request may ask for less
	IdleTimeout  time.Duration // a session idle this long is suspended; a request may ask for less
	DiskBytes    int64         // what a session's calls may leave behind; 0 = no bound
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
	ended   bool
}

type sessionRegistry struct {
	mu        sync.Mutex
	byID      map[string]*sessionEntry
	opening   int            // reservations taken by opens still creating their sandbox
	openingBy map[string]int // the same, by principal
}

// reserve takes one of max session places for an open about to create its sandbox,
// counting the sessions that have not ended and the opens already under way, all
// under one lock: two opens at once cannot both see the last place free. add turns
// the reservation into the session; an open that fails gives it back with unreserve.
// A principal past perCaller (0 = no cap) is refused the same way, its own sessions
// and opens counted.
func (r *sessionRegistry) reserve(max, perCaller int, principal string) (ok, callerFull bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.openLocked("")+r.opening >= max {
		return false, false
	}
	if perCaller > 0 && r.openLocked(principal)+r.openingBy[principal] >= perCaller {
		return false, true
	}
	r.opening++
	if r.openingBy == nil {
		r.openingBy = make(map[string]int)
	}
	r.openingBy[principal]++
	return true, false
}

func (r *sessionRegistry) unreserve(principal string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opening--
	r.doneOpeningLocked(principal)
}

func (r *sessionRegistry) doneOpeningLocked(principal string) {
	if r.openingBy[principal]--; r.openingBy[principal] <= 0 {
		delete(r.openingBy, principal)
	}
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
	r.doneOpeningLocked(e.principal)
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

// openLocked counts the sessions that have not ended, of one principal or ("") all.
func (r *sessionRegistry) openLocked(principal string) int {
	n := 0
	for _, e := range r.byID {
		if principal != "" && e.principal != principal {
			continue
		}
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

// takeTurn waits for the session's turn, refusing at once, not dispatched, when
// another call already waits for it. A client makes one call at a time; without the
// bound, one caller could park any number of requests on its own session, each holding
// a handler and a connection. The returned function gives the turn back.
func (e *sessionEntry) takeTurn(ctx context.Context) (func(), error) {
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
	principal := auditCaller(ctx)
	if ok, callerFull := s.sessions.reserve(s.Sessions.MaxSessions, s.Sessions.MaxPerCaller, principal); callerFull {
		return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity,
			fmt.Errorf("%w: this caller has %d sessions open, the most one caller keeps", sandbox.ErrAtCapacity, s.Sessions.MaxPerCaller))
	} else if !ok {
		return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity,
			fmt.Errorf("%w: %d sessions are open, the most this daemon keeps", sandbox.ErrAtCapacity, s.Sessions.MaxSessions))
	}
	release, err := s.limit(ctx)
	if err != nil {
		s.sessions.unreserve(principal)
		return nil, err
	}
	lifetime := shorter(s.Sessions.Lifetime, m.GetLifetimeMs())
	idle := shorter(s.Sessions.IdleTimeout, m.GetIdleTimeoutMs())
	if idle > 0 && idle < minSessionIdle {
		idle = minSessionIdle
	}
	started := time.Now()
	sess, err := sp.OpenSession(ctx, sandbox.SessionOptions{MinimumIsolation: env.minimum, Lifetime: lifetime, DiskBytes: s.Sessions.DiskBytes, Languages: languages})
	if err != nil {
		release()
		s.sessions.unreserve(principal)
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
		release()
		s.sessions.unreserve(principal)
		return nil, mapSandboxErr(sandbox.RefuseGaveUp(ctx))
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		release()
		s.sessions.unreserve(principal)
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionOrphanCloseBudget)
		_ = sess.Close(closeCtx)
		cancel()
		return nil, mapSandboxErr(err)
	}
	e := &sessionEntry{
		id:          hex.EncodeToString(id),
		principal:   principal,
		sess:        sess,
		software:    software,
		rule:        env.software,
		idleTimeout: idle,
		turn:        make(chan struct{}, 1),
		waiting:     make(chan struct{}, 1),
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
// taken the turn in the meantime. A session whose suspended sandbox still holds its
// memory (a paused container) keeps its slot: the slot is its share of the host's
// memory budget, and that memory is still in use.
func (s *SandboxService) suspend(e *sessionEntry) {
	select {
	case e.turn <- struct{}{}:
	default:
		// A call holds the turn. It rearms the timer when it ends, but it does so
		// before giving the turn back, so a short idle timeout can fire in between and
		// land here: rearm, or nothing would suspend the session until its next call.
		e.mu.Lock()
		e.armIdle(s)
		e.mu.Unlock()
		return
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
	holdsMemory, err := e.sess.Suspend(ctx)
	if err != nil {
		if e.sess.Err() == nil {
			s.logger().Warn("session suspend failed", "session", e.fingerprint, "error", err.Error())
		}
		return
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
	if m.GetPayload() == nil {
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
	// One call at a time, in arrival order, so the chain numbers calls as they ran.
	give, err := e.takeTurn(ctx)
	if err != nil {
		return nil, err
	}
	defer give()
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
		software: e.software,
		session:  true,
		attrs:    []slog.Attr{slog.String("session", e.fingerprint), slog.Uint64("session_call", seq)},
	}
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
		switch p := m.GetPayload().(type) {
		case *plimsollv1.SessionRunRequest_Javascript:
			return s.runJavaScript(ctx, env, p.Javascript, t)
		case *plimsollv1.SessionRunRequest_Project:
			return s.runProject(ctx, env, p.Project, t)
		case *plimsollv1.SessionRunRequest_Cell:
			return s.runCell(ctx, env, p.Cell, e.sess, t)
		}
		return nil, nil
	}()
	if err != nil {
		if _, marked := sandbox.NotDispatchedReason(err); marked {
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

// runCell is the cell kind: code handed to the session's interpreter for its
// language, after the cell's files are written. A cell carries no grant.
func (s *SandboxService) runCell(ctx context.Context, env envelope, p *plimsollv1.CellRun, runner sandbox.CellRunner, t target) (*plimsollv1.RunResponse, error) {
	files := make([]sandbox.File, 0, len(p.GetFiles()))
	for _, f := range p.GetFiles() {
		files = append(files, sandbox.File{Path: f.GetPath(), Content: f.GetContent()})
	}
	sbReq := sandbox.CellRequest{
		Language: sandbox.Language(p.GetLanguage()), Code: p.GetCode(), Files: files,
		Timeout: env.timeout, MinimumIsolation: env.minimum, Software: env.software,
	}
	if err := sandbox.ValidateCellRequest(sbReq); err != nil {
		return nil, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest, err)
	}
	if err := sandbox.CheckMinimumIsolation(t.tier, sbReq.MinimumIsolation); err != nil {
		return nil, mapSandboxErr(err)
	}
	if err := sbReq.Software.Check(t.software.Project.SoftwareIdentity); err != nil {
		return nil, mapSandboxErr(err)
	}
	release, err := t.admit(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	s.runsTotal.Add(1)
	runCtx, cancel := runContext(ctx)
	defer cancel()
	started := time.Now()
	res, err := runner.RunCell(runCtx, sbReq)
	attrs := []slog.Attr{
		slog.String("op", "cell"),
		slog.String("caller", auditCaller(ctx)),
		slog.String("language", string(sbReq.Language)),
		slog.Int("code_bytes", len(sbReq.Code)),
		slog.Int("files", len(files)),
	}
	if err != nil {
		if isInfraErr(err) {
			s.runsFailed.Add(1)
		}
		attrs = append(attrs,
			slog.String("sandbox", t.provider),
			slog.String("isolation", t.tier.String()),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()),
			slog.String("error", err.Error()))
		attrs = append(append(attrs, traceAttrs(env.traceID)...), t.attrs...)
		s.logger().LogAttrs(ctx, slog.LevelError, "code run failed", attrs...)
		return nil, mapSandboxErr(err)
	}
	attrs = append(attrs,
		slog.String("sandbox", res.Sandbox),
		slog.String("isolation", res.Isolation.String()),
		slog.Int("exit_code", res.ExitCode),
		slog.Bool("timed_out", res.TimedOut),
		slog.Bool("interpreter_started", res.InterpreterStarted),
		slog.Bool("interpreter_ended", res.InterpreterEnded),
		slog.Int64("duration_ms", res.Duration.Milliseconds()))
	attrs = append(append(attrs, traceAttrs(env.traceID)...), t.attrs...)
	s.logger().LogAttrs(ctx, slog.LevelInfo, "code run", attrs...)
	return &plimsollv1.RunResponse{
		Sandbox:          wireString(res.Sandbox),
		Isolation:        res.Isolation.String(),
		DurationMs:       res.Duration.Milliseconds(),
		SoftwareIdentity: t.ranSoftware(res.SoftwareIdentity, t.software.Project.SoftwareIdentity),
		Environment:      describedEnvironment(res.EnvironmentIdentity, t.software.Project.Identity),
		Result: &plimsollv1.RunResponse_Cell{Cell: &plimsollv1.CellResult{
			Stdout:             []byte(res.Stdout),
			Stderr:             []byte(res.Stderr),
			ExitCode:           int32(res.ExitCode),
			TimedOut:           res.TimedOut,
			StdoutTruncated:    res.StdoutTruncated,
			StderrTruncated:    res.StderrTruncated,
			InterpreterStarted: res.InterpreterStarted,
			InterpreterEnded:   res.InterpreterEnded,
		}},
	}, nil
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
	give, err := e.takeTurn(ctx)
	if err != nil {
		return nil, err
	}
	defer give()
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
