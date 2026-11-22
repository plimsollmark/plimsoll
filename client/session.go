package client

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/softwarewire"
	"github.com/plimsollmark/plimsoll/internal/wireenum"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// SessionOptions is what OpenSession asks for. A zero duration takes the
// daemon's; a longer one than the daemon's is cut to it.
type SessionOptions struct {
	MinimumIsolation sandbox.IsolationClass
	Software         sandbox.SoftwareRule
	Lifetime         time.Duration
	IdleTimeout      time.Duration
	// Languages are the languages the session's cells will use: a hint, so a daemon
	// with a warm pool hands over a sandbox with those interpreters already running.
	// A cell in any language the daemon states still runs.
	Languages []sandbox.Language
	// Owner names the end user the session is for (an account ID, an email), so a
	// daemon with a per-owner cap (SANDBOX_MAX_SESSIONS_PER_OWNER) keeps each user to
	// it across every process of the app: at the cap, the daemon closes that user's
	// least recently used session with no call in progress. It never leaves this
	// process: the daemon gets a digest keyed by the client's token (ownerDigest).
	// Empty: the session counts against no owner.
	Owner string
	// WarmOnly asks for a waiting pool member or nothing: on a daemon with no member
	// to hand over the open is refused, not dispatched, reason capacity
	// (sandbox.ErrAtCapacity), and no sandbox is made, so the caller can run fresh
	// instead. It never closes another session of the owner to make room. A daemon
	// that predates the field would have ignored it and made a sandbox, so it came
	// with protocol 5, which such a daemon refuses before reading the open. A cell for
	// one call needs no session of its own: RunCell with CellOptions.PreferWarm.
	WarmOnly bool
}

// ownerDigest is what an owner is sent as: hex(HMAC-SHA256(key = SHA-256("plimsoll
// session owner key v2\n" + the client's token), message = "plimsoll session owner
// v2\n" + owner)), the same in every official client, so the processes of one app
// agree on a user. The daemon stores only a token's SHA-256, so it cannot test a
// guessed name against a digest; without a token anyone can. The key is derived, not
// the token itself: HMAC replaces a key longer than 64 bytes with its SHA-256, which
// for a long imported token is exactly the token_sha256 the clients file holds.
func ownerDigest(token, owner string) string {
	if owner == "" {
		return ""
	}
	key := sha256.Sum256([]byte("plimsoll session owner key v2\n" + token))
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("plimsoll session owner v2\n" + owner))
	return hex.EncodeToString(m.Sum(nil))
}

// Session is an open session on a remote daemon: one sandbox for many calls, in
// which files persist between calls and no process outlives its call. Calls are
// serialized by the daemon. The client checks every call's record against the
// chain it has seen, so a call another holder of the session ID made is caught
// at the next call (record.ErrChain, as DataLoss).
type Session struct {
	r           *Remote
	id          string
	generation  uint64
	fingerprint string
	provider    string // the provider, tier and software the daemon stated at open,
	isolation   sandbox.IsolationClass
	identity    string // which an unanswered call's record must repeat
	// qualification is the sentence the daemon stated beside the tier at open, which an
	// unanswered call's record must repeat too.
	qualification string
	software      sandbox.SoftwareRule   // the rule given at open
	openFloor     sandbox.IsolationClass // the floor given at open, as the daemon echoed it
	floor         sandbox.IsolationClass // the floor sent with every call: the open's
	expires       time.Time
	idle          time.Duration

	mu    sync.Mutex
	calls uint64
	last  string
	// lostCall is the request digest the session's next call is refused for repeating,
	// set by an attach across an explained gap (or inherited with a checkpoint), spent by
	// that refusal or by the next call that may have run (a call the daemon refuses with
	// the not-dispatched mark leaves it); lostRecord is that attach's record of the lost
	// call. Under mu.
	lostCall   string
	lostRecord *sandbox.RunRecord

	// State accessors must not wait for mu, held across a network exchange.
	stateMu sync.Mutex
	end     *sandbox.SessionEndedError
	// unanswered is the first call that ended without an answer this client could
	// check: an error without a not-dispatched mark and without the record the daemon
	// chains for such a call (lost with the answer, or failing its check). That call
	// may have run and moved the daemon's chain on, so every later call would run and
	// then fail the chain check; they are refused here instead, before anything is
	// sent. A call or close refused because another worker attached the session stops
	// it the same way (ErrStaleOwner).
	unanswered error
	// closed: the daemon answered this client's close, or the recorder signed that it
	// could not be collected (signedEnd), so Checkpoint refuses.
	closed bool
	// signedEnd: the recorder signed that this session's close could not be collected,
	// which ends it in the bundle; no later close is sent.
	signedEnd bool
	// answered is the first close the daemon answered with its count, and what Close
	// returned for it (a count that differs from this client's chain included): every
	// later close returns the same, and sends and signs nothing (finding hunt-quality-97).
	// Under mu.
	answered *closeAnswer
	// lostRequest is the request digest of the call after which the session stopped with
	// no answer this client could check: the call an attach may name as lost.
	lostRequest string
	// checkFailed: the session stopped over an answer this client received and refused,
	// because its record or the chain failed the check (a record that does not match the
	// call, a call numbered after a gap, a result of another kind): proof that the
	// daemon's chain holds something this client did not send, or that its answers are
	// not to be believed. A close that cannot be collected then signs nothing.
	checkFailed bool
}

// UnansweredCallError is a session call that may have run but ended in Err. Its
// unanswered Record, checked against the call sent and the chain, is in the session's
// chain, so the session goes on and the call is not hidden from a verifier. The
// call's outcome is unknown: it is never a retry signal.
type UnansweredCallError struct {
	Record *sandbox.RunRecord
	Err    error
}

func (e *UnansweredCallError) Error() string {
	return fmt.Sprintf("client: session call %d may have run but ended without a result (%s): %v", e.Record.Sequence, e.Record.Unanswered, e.Err)
}

func (e *UnansweredCallError) Unwrap() error { return e.Err }

// UnansweredRecorder is a Recorder that also signs the record of a session call
// that may have run but ended in an error. attest.Harness is one.
type UnansweredRecorder interface {
	Recorder
	RecordUnanswered(req *plimsollv1.RunRequest, rec *plimsollv1.RunRecord) error
}

// ErrSessionUnanswered refuses a call on a session an earlier call of which ended
// without an answer this client could check. It is marked not dispatched: the call
// was never sent. Open a new session.
var ErrSessionUnanswered = errors.New("client: an earlier call of this session ended without an answer this client could check, and may have run")

// SessionRecorder is a Recorder that also signs a session's close: the daemon's
// count of executed calls and its last record, which lets a verifier tell a
// complete chain from a cut one. attest.Harness is one.
type SessionRecorder interface {
	Recorder
	RecordClose(session string, calls uint64, lastRecordSHA256 string) error
}

// CloseNotCollectedRecorder is a SessionRecorder that also signs its own statement that a
// session's close could not be collected: the daemon refused the close with no count, and
// never will give one (CloseNotFound, CloseStaleOwner). The session then ends in the
// bundle with the calls this client saw, reported as not proven complete.
// unansweredRequestSHA256 is the request digest of a call this client sent after those and
// got no answer for (it may have run), "" when there is none: at most one, since the first
// call left without an answer stops the session and every later one is refused before it
// is sent. attest.Harness is one. A SessionRecorder that is not one leaves such a session
// without an ending, and its bundle does not verify.
type CloseNotCollectedRecorder interface {
	SessionRecorder
	RecordCloseNotCollected(session string, callsSeen uint64, lastRecordSHA256, unansweredRequestSHA256, reason string) error
}

// The reasons Close hands a CloseNotCollectedRecorder, as attest's statement names them.
const (
	// CloseNotFound: the daemon that answered the close said NotFound, marked not
	// dispatched, "no such session for this caller": after a restart, after the time it
	// keeps an ended session's count, after another holder of the session ID closed it, or
	// from a daemon behind a load balancer that never had the session.
	CloseNotFound = "not_found"
	// CloseStaleOwner: the daemon refused the close because another worker took the
	// session over (ErrStaleOwner).
	CloseStaleOwner = "stale_owner"
)

// ErrCloseNotCollected is a close the daemon refused with no count and never will answer
// (CloseNotFound, CloseStaleOwner). When the Remote's Recorder is a
// CloseNotCollectedRecorder it has signed that, and the session ends there: this client
// sends nothing more on it, its close included.
var ErrCloseNotCollected = errors.New("client: the session's close could not be collected, so the daemon's count of its calls is unknown")

// notCollected names why a failed close can never be collected, or "" when it might be
// (a timeout, a dropped connection, any error without the daemon's mark).
func notCollected(err error) string {
	if errors.Is(err, ErrStaleOwner) {
		return CloseStaleOwner
	}
	if _, marked := sandbox.NotDispatchedReason(err); marked && connect.CodeOf(err) == connect.CodeNotFound {
		return CloseNotFound
	}
	return ""
}

// ErrRecorderCannotKeepSessions refuses a session, before anything is sent, on a
// Remote whose Recorder cannot keep a whole chain: a session's chain also holds the
// records of calls that may have run without an answer and the daemon's close, and a
// Recorder that is not also an UnansweredRecorder and a SessionRecorder would drop
// them, leaving a bundle that does not verify.
var ErrRecorderCannotKeepSessions = errors.New("client: the Recorder cannot keep a session's chain; it must also implement UnansweredRecorder and SessionRecorder")

// OpenSession opens a session. The session ID it holds is a capability: it is sent
// only to the daemon, and never appears in a record, a log line or an error.
func (r *Remote) OpenSession(ctx context.Context, opts SessionOptions) (*Session, error) {
	if r.recorder != nil {
		_, unanswered := r.recorder.(UnansweredRecorder)
		_, closes := r.recorder.(SessionRecorder)
		if !unanswered || !closes {
			return nil, sandbox.NotDispatched(sandbox.RefusalRequest, ErrRecorderCannotKeepSessions)
		}
	}
	languages, err := sandbox.SessionLanguages(opts.Languages, nil)
	if err != nil {
		return nil, err
	}
	wireLanguages := make([]string, len(languages))
	for i, l := range languages {
		wireLanguages[i] = string(l)
	}
	req := connect.NewRequest(&plimsollv1.OpenSessionRequest{
		Protocol:         Protocol,
		MinimumIsolation: minimumIsolationWire(opts.MinimumIsolation),
		TraceId:          TraceIDFrom(ctx),
		LifetimeMs:       durationMs(opts.Lifetime),
		IdleTimeoutMs:    durationMs(opts.IdleTimeout),
		SoftwareRule:     softwarewire.ToWire(opts.Software),
		Languages:        wireLanguages,
		Owner:            ownerDigest(r.token, opts.Owner),
		WarmOnly:         opts.WarmOnly,
	})
	r.auth(req)
	resp, err := r.client.OpenSession(ctx, req)
	if err != nil {
		return nil, restoreSandboxError(err)
	}
	m := resp.Msg
	s := &Session{
		r:             r,
		id:            m.GetSessionId(),
		generation:    m.GetGeneration(),
		fingerprint:   m.GetSession(),
		provider:      m.GetSandbox(),
		isolation:     sandbox.ParseIsolationClass(m.GetIsolation()),
		identity:      m.GetSoftwareIdentity(),
		qualification: m.GetIsolationQualification(),
		software:      opts.Software,
		openFloor:     opts.MinimumIsolation,
		floor:         opts.MinimumIsolation,
		expires:       time.UnixMilli(m.GetExpiresUnixMs()),
		idle:          time.Duration(m.GetIdleTimeoutMs()) * time.Millisecond,
	}
	// A session refused here is closed (it exists on the daemon either way, and nothing
	// else holds its ID), but its close is not signed: it names whatever fingerprint the
	// daemon chose.
	if s.generation != 1 {
		// Every daemon opens a session at generation 1, so that is the number its close
		// must carry, whatever this answer said.
		s.generation = 1
		s.closeRejected(ctx)
		return nil, connect.NewError(connect.CodeDataLoss, fmt.Errorf("%w: the daemon's answer to the open states an ownership generation other than 1", record.ErrChain))
	}
	if s.fingerprint != record.SessionFingerprint(s.id) {
		s.closeRejected(ctx)
		return nil, connect.NewError(connect.CodeDataLoss, fmt.Errorf("%w: the daemon's session fingerprint does not match its session ID", record.ErrChain))
	}
	if m.GetMinimumIsolation() != minimumIsolationWire(opts.MinimumIsolation) || softwarewire.FromWire(m.GetSoftwareRule()).ID() != opts.Software.ID() {
		// The floor and rule the daemon keeps for the session are what an attach answer
		// repeats and a checkpoint states, so they must be the ones sent.
		s.closeRejected(ctx)
		return nil, connect.NewError(connect.CodeDataLoss, fmt.Errorf("%w: the daemon's answer to the open states another floor or software rule than the open sent", record.ErrChain))
	}
	if err := sandbox.CheckResultIsolation(s.isolation, opts.MinimumIsolation); err != nil {
		s.closeRejected(ctx)
		return nil, connect.NewError(connect.CodeDataLoss, err)
	}
	if !opts.Software.Allows(m.GetSoftwareIdentity()) {
		s.closeRejected(ctx)
		return nil, connect.NewError(connect.CodeDataLoss, sandbox.ErrSoftwareMismatch)
	}
	return s, nil
}

func durationMs(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	return uint32(min(d.Milliseconds(), int64(^uint32(0))))
}

// rejectedCloseBudget bounds closing a session refused at its open. The close runs
// detached from the open's context, so a caller that gave up still has the sandbox
// closed, but within its own budget: the caller is waiting for the refusal, and a
// close that stalls would otherwise hold it up to the HTTP client's limit. The daemon
// ends a session it never hears from again at its lifetime.
var rejectedCloseBudget = 10 * time.Second

// closeRejected closes a session refused at open, unsigned and within its budget.
func (s *Session) closeRejected(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rejectedCloseBudget)
	defer cancel()
	_, _ = s.close(ctx, false)
}

// Fingerprint is the SHA-256 of the session ID, as the session's records carry it.
func (s *Session) Fingerprint() string { return s.fingerprint }

// Isolation is the tier the daemon measured when the session opened.
func (s *Session) Isolation() sandbox.IsolationClass { return s.isolation }

// IsolationQualification is the sentence the daemon stated beside that tier at open, ""
// when the provider states none. Every call's record states it too.
func (s *Session) IsolationQualification() string { return s.qualification }

// ExpiresAt is when the session's lifetime ends.
func (s *Session) ExpiresAt() time.Time { return s.expires }

// IdleTimeout is how long the session may go without a call before the daemon
// suspends it (the next call resumes it).
func (s *Session) IdleTimeout() time.Duration { return s.idle }

// Ended returns the session's end once a response has reported it, else nil.
func (s *Session) Ended() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.end == nil {
		return nil
	}
	return s.end
}

// Stopped returns why this client sends no more calls, or nil until it stops: after an
// answer it could not check (wrapping ErrSessionUnanswered and the original cause), or
// after the daemon refused a call or close because another worker attached the session
// (wrapping ErrStaleOwner), or after its recorder signed that its close could not be
// collected (wrapping ErrCloseNotCollected). It is distinct from Ended, which reports an
// end the daemon stated.
func (s *Session) Stopped() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.unanswered
}

func (s *Session) setStopped(cause error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.unanswered == nil {
		s.unanswered = fmt.Errorf("%w: %w; open a new session", ErrSessionUnanswered, cause)
	}
}

// setStale stops the session because another worker owns it now.
func (s *Session) setStale(cause error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.unanswered == nil {
		s.unanswered = fmt.Errorf("%w: %w; this worker must not use the session again", ErrStaleOwner, cause)
	}
}

// LostRequestSHA256 is the request digest of the call after which this session stopped
// with no answer it could check (Stopped wraps ErrSessionUnanswered), or "": the call that
// may have run, for another worker's AttachSession to name (AttachOptions) together with a
// checkpoint saved before it.
func (s *Session) LostRequestSHA256() string {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.lostRequest
}

// LostCall is the record of the call that was sent once and whose answer was lost, on a
// session attached across an explained gap (AttachOptions.LostRequestSHA256), or nil: what
// the attach learned of it. Its output is lost. The record says whether the daemon
// answered it: a result digest when the daemon answered, which does not show that the call
// ran to its end (a step stopped at its time limit and a setup that failed are answers
// too), an unanswered code when it ended without an answer, so that it may have done none,
// part or all of its work.
func (s *Session) LostCall() *sandbox.RunRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lostRecord
}

// stopAfter stops the session after sending the call whose request digest is digest
// without an answer this client could check: checkFailed when an answer came and failed
// the record or chain check, not when none came.
func (s *Session) stopAfter(digest string, cause error, checkFailed bool) {
	s.stateMu.Lock()
	if s.unanswered == nil {
		s.lostRequest, s.checkFailed = digest, checkFailed
	}
	s.stateMu.Unlock()
	s.setStopped(cause)
}

// stoppedByFailedCheck returns why this client stopped the session over an answer that
// failed its record or chain check, or nil.
func (s *Session) stoppedByFailedCheck() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if !s.checkFailed {
		return nil
	}
	return s.unanswered
}

func (s *Session) endingSigned() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.signedEnd
}

func (s *Session) isClosed() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.closed
}

func (s *Session) setEnd(end *sandbox.SessionEndedError) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.end = end
}

// RunJavaScript runs a snippet in the session.
func (s *Session) RunJavaScript(ctx context.Context, in sandbox.Request) (sandbox.Result, error) {
	fail := sandbox.Result{Sandbox: s.r.Name()}
	if err := sandbox.ValidateRequest(in); err != nil {
		return fail, err
	}
	if in.Grant != nil {
		return fail, ErrRawGrantUnsupported
	}
	software, err := sandbox.MergeSoftwareRules(s.software, in.Software)
	if err != nil {
		return fail, err
	}
	floor := max(s.floor, in.MinimumIsolation)
	req := s.envelope(ctx, in.Timeout, floor, software)
	req.Payload = &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: in.Code, GrantProfile: s.r.jsGrant}}
	resp, rec, err := s.call(ctx, req)
	if resp == nil {
		return fail, err
	}
	res, ok := javascriptResult(resp, rec)
	if !ok {
		return fail, connect.NewError(connect.CodeDataLoss, ErrResultKindMismatch)
	}
	return res, err
}

// RunProject runs a project in the session; its files persist for later calls.
func (s *Session) RunProject(ctx context.Context, in sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	fail := sandbox.ProjectResult{Sandbox: s.r.Name()}
	if err := sandbox.ValidateProjectRequest(in); err != nil {
		return fail, err
	}
	if in.Grant != nil {
		return fail, ErrRawGrantUnsupported
	}
	p := &plimsollv1.ProjectRun{Steps: in.Steps, Artifacts: in.Artifacts, GrantProfile: s.r.projectGrant}
	for _, f := range in.Files {
		p.Files = append(p.Files, &plimsollv1.ProjectFile{Path: f.Path, Content: f.Content})
	}
	software, err := sandbox.MergeSoftwareRules(s.software, in.Software)
	if err != nil {
		return fail, err
	}
	floor := max(s.floor, in.MinimumIsolation)
	req := s.envelope(ctx, in.Timeout, floor, software)
	req.Payload = &plimsollv1.SessionRunRequest_Project{Project: p}
	resp, rec, err := s.call(ctx, req)
	if resp == nil {
		return fail, err
	}
	res, ok := projectResult(resp, rec)
	if !ok {
		return fail, connect.NewError(connect.CodeDataLoss, ErrResultKindMismatch)
	}
	return res, err
}

// RunCell runs code in the session's interpreter for in.Language; what earlier
// cells defined is there, unless the result says a fresh interpreter started.
func (s *Session) RunCell(ctx context.Context, in sandbox.CellRequest) (sandbox.CellResult, error) {
	fail := sandbox.CellResult{Sandbox: s.r.Name()}
	if err := sandbox.ValidateCellRequest(in); err != nil {
		return fail, err
	}
	c := &plimsollv1.CellRun{Language: string(in.Language), Code: in.Code}
	for _, f := range in.Files {
		c.Files = append(c.Files, &plimsollv1.ProjectFile{Path: f.Path, Content: f.Content})
	}
	software, err := sandbox.MergeSoftwareRules(s.software, in.Software)
	if err != nil {
		return fail, err
	}
	floor := max(s.floor, in.MinimumIsolation)
	req := s.envelope(ctx, in.Timeout, floor, software)
	req.Payload = &plimsollv1.SessionRunRequest_Cell{Cell: c}
	resp, rec, err := s.call(ctx, req)
	if resp == nil {
		return fail, err
	}
	res, ok := cellResult(resp, rec)
	if !ok {
		return fail, connect.NewError(connect.CodeDataLoss, ErrResultKindMismatch)
	}
	return res, err
}

func (s *Session) envelope(ctx context.Context, timeout time.Duration, minimum sandbox.IsolationClass, software sandbox.SoftwareRule) *plimsollv1.SessionRunRequest {
	return &plimsollv1.SessionRunRequest{
		Protocol:         Protocol,
		MinimumIsolation: minimumIsolationWire(minimum),
		TraceId:          TraceIDFrom(ctx),
		TimeoutMs:        timeoutMs(timeout),
		SessionId:        s.id,
		Generation:       s.generation,
		SoftwareRule:     softwarewire.ToWire(software),
	}
}

// call sends one session call, checks its record against the chain this client has
// seen, and hands the exchange to the Recorder as the equivalent Run request (the
// same digest, without the session ID). Calls are serialized here too, so the
// chain this client tracks follows the daemon's.
func (s *Session) call(ctx context.Context, msg *plimsollv1.SessionRunRequest) (*plimsollv1.RunResponse, *sandbox.RunRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stopped := s.Stopped(); stopped != nil {
		return nil, nil, sandbox.NotDispatched(sandbox.RefusalRequest, stopped)
	}
	// The first call after an attach across an explained gap: a repeat of the lost call is
	// a retry of a call that was already sent once, refused here with nothing sent, and the
	// refusal spends the note. Only the first call is checked: any other call spends the
	// note once it is sent, unless the daemon refuses it with the not-dispatched mark,
	// since then nothing ran, the head is where it was, and the next call is still the
	// first.
	digest := record.SessionRunRequestDigest(msg)
	if s.lostCall != "" && digest == s.lostCall {
		s.lostCall = ""
		return nil, nil, sandbox.NotDispatched(sandbox.RefusalRequest, ErrCallAlreadySent)
	}
	req := connect.NewRequest(msg)
	s.r.auth(req)
	resp, err := s.r.client.SessionRun(ctx, req)
	if err != nil {
		rec := unansweredDetail(err)
		err = restoreSandboxError(err)
		var se *sandbox.SessionEndedError
		if errors.As(err, &se) {
			s.setEnd(se)
		}
		if _, marked := sandbox.NotDispatchedReason(err); marked {
			if errors.Is(err, ErrStaleOwner) {
				s.setStale(err)
			}
			return nil, nil, err
		}
		s.lostCall = ""
		if rec == nil {
			s.stopAfter(digest, err, false)
			return nil, nil, err
		}
		r, cerr := record.CheckUnanswered(msg, rec, s.fingerprint, s.calls, s.last)
		if cerr == nil && (r.Provider != s.provider || r.Isolation != s.isolation.String() || r.SoftwareIdentity != s.identity || r.IsolationQualification != s.qualification) {
			// With no response to compare it with, the record's evidence must be what
			// the session stated at open.
			cerr = fmt.Errorf("%w: the unanswered call's record names %s at %q running %q, the session opened as %s at %q running %q (or the tier's qualification differs from the one stated at open)",
				record.ErrMismatch, r.Provider, r.Isolation, r.SoftwareIdentity, s.provider, s.isolation, s.identity)
		}
		if cerr != nil {
			s.stopAfter(digest, cerr, true)
			return nil, nil, connect.NewError(connect.CodeDataLoss, cerr)
		}
		s.calls, s.last = r.Sequence, r.SHA256
		if ur, ok := s.r.recorder.(UnansweredRecorder); ok {
			if rerr := ur.RecordUnanswered(record.AsRunRequest(msg), rec); rerr != nil {
				return nil, nil, fmt.Errorf("%w (%w): %w", ErrNotRecorded, rerr, &UnansweredCallError{Record: r, Err: err})
			}
		}
		return nil, nil, &UnansweredCallError{Record: r, Err: err}
	}
	s.lostCall = ""
	run := resp.Msg.GetRun()
	if run == nil {
		s.stopAfter(digest, ErrResultKindMismatch, true)
		return nil, nil, connect.NewError(connect.CodeDataLoss, ErrResultKindMismatch)
	}
	if e := resp.Msg.GetEnded(); e != plimsollv1.SessionEnd_SESSION_END_UNSPECIFIED {
		s.setEnd(&sandbox.SessionEndedError{Reason: wireenum.SessionEndFromWire(e), Detail: resp.Msg.GetEndDetail()})
	}
	rec, err := record.CheckSessionCall(msg, run, s.fingerprint, s.calls, s.last)
	if err != nil {
		s.stopAfter(digest, err, true)
		return run, nil, connect.NewError(connect.CodeDataLoss, err)
	}
	s.calls, s.last = rec.Sequence, rec.SHA256
	if s.r.recorder != nil {
		if err := s.r.recorder.Record(record.AsRunRequest(msg), run); err != nil {
			return run, rec, fmt.Errorf("%w: %w", ErrNotRecorded, err)
		}
	}
	return run, rec, nil
}

// SessionSummary is what CloseSession states about the session's chain.
type SessionSummary struct {
	Session          string // the fingerprint
	Calls            uint64
	LastRecordSHA256 string
	End              sandbox.SessionEnd // closed, or an earlier end
}

// Close ends the session (or collects one that ended by itself) and returns the
// daemon's count of executed calls and last record. When the count or the last
// record differs from the chain this client has seen, some call it did not make
// ran in the session: that is DataLoss wrapping record.ErrChain, with the summary,
// and nothing is signed. A SessionRecorder signs the daemon's statement only when it
// matches the chain this client has seen. Once the daemon has answered a close with its
// count, every later Close returns that same summary and error, and sends and signs
// nothing.
//
// A close the daemon refuses with no count and never will answer (NotFound with the
// not-dispatched mark, or ErrStaleOwner) is ErrCloseNotCollected. When the Recorder is a
// CloseNotCollectedRecorder, it has then signed its own statement of that, with the
// calls this client saw (the summary returned), and the session ends there: Stopped
// reports it, and every later call and close is refused, not dispatched. Any other
// failure (a timeout, a dropped connection) signs nothing, and the close may be tried
// again. A session this client stopped over an answer that failed its record or chain
// check (another holder's call between two of its own, a record that does not match the
// call) signs nothing either, whatever the close's error: the client has proof that
// something it did not send ran, so its bundle keeps no ending for the session and does
// not verify, and the error says why.
func (s *Session) Close(ctx context.Context) (SessionSummary, error) { return s.close(ctx, true) }

func (s *Session) close(ctx context.Context, sign bool) (SessionSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.answered; a != nil {
		// The daemon has answered this session's close: it holds the session no longer, so
		// a close sent again would be NotFound, which must not read as a close that could
		// not be collected (and be signed so, when this client caught a call it did not
		// make), nor be signed as a second ending.
		return a.sum, a.err
	}
	if s.endingSigned() {
		// The harness has signed this session's ending: a daemon close after it would be a
		// second ending, which no bundle verifies with, so none is asked for.
		return SessionSummary{Session: s.fingerprint}, sandbox.NotDispatched(sandbox.RefusalRequest,
			fmt.Errorf("%w: its ending is already signed", ErrCloseNotCollected))
	}
	req := connect.NewRequest(&plimsollv1.CloseSessionRequest{Protocol: Protocol, SessionId: s.id, Generation: s.generation})
	s.r.auth(req)
	resp, err := s.r.client.CloseSession(ctx, req)
	if err != nil {
		err = restoreSandboxError(err)
		if errors.Is(err, ErrStaleOwner) {
			s.setStale(err)
		}
		sum := SessionSummary{Session: s.fingerprint, Calls: s.calls, LastRecordSHA256: s.last}
		reason := notCollected(err)
		ncr, ok := s.r.recorder.(CloseNotCollectedRecorder)
		if reason == "" || !ok || !sign {
			return SessionSummary{Session: s.fingerprint}, err
		}
		if caught := s.stoppedByFailedCheck(); caught != nil {
			// This client caught something it did not send in the session's chain, or an
			// answer it could not believe; the statement would read as an ordinary daemon
			// restart. Nothing is signed, so the bundle has no ending for the session and
			// fails verify, as it did before the statement existed.
			return SessionSummary{Session: s.fingerprint}, fmt.Errorf("client: the session's close could not be collected (%s), and nothing was signed: "+
				"this client stopped the session over an answer that failed its record or chain check, so the bundle holds no ending for the session and does not verify (%w): %w",
				reason, caught, err)
		}
		// The daemon will never state this session's count. The harness signs that, with
		// the calls this client saw, so the bundle ends the session as not proven complete
		// rather than not at all, and this client sends nothing more on it. A call sent after
		// those with no answer (the session stopped on it: LostRequestSHA256) is named too,
		// since it may have run and no line of the bundle holds it.
		if rerr := ncr.RecordCloseNotCollected(s.fingerprint, s.calls, s.last, s.LostRequestSHA256(), reason); rerr != nil {
			return sum, fmt.Errorf("%w: the statement that the close could not be collected: %w (%w: %w)", ErrNotRecorded, rerr, ErrCloseNotCollected, err)
		}
		s.stateMu.Lock()
		s.closed, s.signedEnd = true, true
		if s.unanswered == nil {
			s.unanswered = fmt.Errorf("%w; its ending is signed: open a new session", ErrCloseNotCollected)
		}
		s.stateMu.Unlock()
		return sum, fmt.Errorf("%w (%s), and the harness signed that: %w", ErrCloseNotCollected, reason, err)
	}
	s.stateMu.Lock()
	s.closed = true
	s.stateMu.Unlock()
	sum, err := s.closeAnswered(resp.Msg, sign)
	s.answered = &closeAnswer{sum: sum, err: err}
	return sum, err
}

// closeAnswer is a close the daemon answered with its count, and what Close made of it.
type closeAnswer struct {
	sum SessionSummary
	err error
}

// closeAnswered checks the daemon's answer to a close against the chain this client saw,
// and signs it when it matches.
func (s *Session) closeAnswered(m *plimsollv1.CloseSessionResponse, sign bool) (SessionSummary, error) {
	sum := SessionSummary{Session: m.GetSession(), Calls: m.GetCalls(), LastRecordSHA256: m.GetLastRecordSha256(), End: wireenum.SessionEndFromWire(m.GetEnded())}
	if sum.Session != s.fingerprint || sum.Calls != s.calls || sum.LastRecordSHA256 != s.last {
		return sum, connect.NewError(connect.CodeDataLoss, fmt.Errorf("%w: the daemon counts %d calls ending %q, this client saw %d ending %q",
			record.ErrChain, sum.Calls, sum.LastRecordSHA256, s.calls, s.last))
	}
	if sr, ok := s.r.recorder.(SessionRecorder); ok && sign {
		if err := sr.RecordClose(sum.Session, sum.Calls, sum.LastRecordSHA256); err != nil {
			return sum, fmt.Errorf("%w: the close: %w", ErrNotRecorded, err)
		}
	}
	return sum, nil
}

// Exchange sends a stored Run request's fields as a call in this session, the
// session ID filled in: how a harness replays a recorded session into a fresh one
// (see Remote.Exchange). A module request has no session form and is refused
// before anything is sent.
func (s *Session) Exchange(ctx context.Context, req *plimsollv1.RunRequest) (*plimsollv1.RunResponse, *sandbox.RunRecord, error) {
	msg := &plimsollv1.SessionRunRequest{
		Protocol:         req.GetProtocol(),
		MinimumIsolation: req.GetMinimumIsolation(),
		TraceId:          req.GetTraceId(),
		TimeoutMs:        req.GetTimeoutMs(),
		SessionId:        s.id,
		Generation:       s.generation,
		SoftwareRule:     req.GetSoftwareRule(),
	}
	switch p := req.GetPayload().(type) {
	case *plimsollv1.RunRequest_Javascript:
		msg.Payload = &plimsollv1.SessionRunRequest_Javascript{Javascript: p.Javascript}
	case *plimsollv1.RunRequest_Project:
		msg.Payload = &plimsollv1.SessionRunRequest_Project{Project: p.Project}
	case *plimsollv1.RunRequest_Cell:
		msg.Payload = &plimsollv1.SessionRunRequest_Cell{Cell: p.Cell}
	default:
		return nil, nil, sandbox.NotDispatched(sandbox.RefusalRequest, fmt.Errorf("%w: only snippets, projects and cells run in a session", sandbox.ErrInvalidRequest))
	}
	return s.call(ctx, msg)
}

// unansweredDetail reads the record the daemon chains for a session call that may
// have run but ended in an error, or nil.
func unansweredDetail(err error) *plimsollv1.RunRecord {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return nil
	}
	for _, d := range ce.Details() {
		if v, derr := d.Value(); derr == nil {
			if u, ok := v.(*plimsollv1.UnansweredCall); ok {
				return u.GetRecord()
			}
		}
	}
	return nil
}
