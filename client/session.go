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
	fingerprint string
	provider    string // the provider, tier and software the daemon stated at open,
	isolation   sandbox.IsolationClass
	identity    string // which an unanswered call's record must repeat
	software    sandbox.SoftwareRule
	floor       sandbox.IsolationClass // the floor given at open, sent with every call
	expires     time.Time
	idle        time.Duration

	mu    sync.Mutex
	calls uint64
	last  string

	// State accessors must not wait for mu, held across a network exchange.
	stateMu sync.Mutex
	end     *sandbox.SessionEndedError
	// unanswered is the first call that ended without an answer this client could
	// check: an error without a not-dispatched mark and without the record the daemon
	// chains for such a call (lost with the answer, or failing its check). That call
	// may have run and moved the daemon's chain on, so every later call would run and
	// then fail the chain check; they are refused here instead, before anything is
	// sent.
	unanswered error
}

// UnansweredCallError is a session call that may have run but ended in Err. Its
// version 3 Record, checked against the call sent and the chain, is in the session's
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
	})
	r.auth(req)
	resp, err := r.client.OpenSession(ctx, req)
	if err != nil {
		return nil, restoreSandboxError(err)
	}
	m := resp.Msg
	s := &Session{
		r:           r,
		id:          m.GetSessionId(),
		fingerprint: m.GetSession(),
		provider:    m.GetSandbox(),
		isolation:   sandbox.ParseIsolationClass(m.GetIsolation()),
		identity:    m.GetSoftwareIdentity(),
		software:    opts.Software,
		floor:       opts.MinimumIsolation,
		expires:     time.UnixMilli(m.GetExpiresUnixMs()),
		idle:        time.Duration(m.GetIdleTimeoutMs()) * time.Millisecond,
	}
	// A session refused here is closed (it exists on the daemon either way, and nothing
	// else holds its ID), but its close is not signed: it names whatever fingerprint the
	// daemon chose.
	if s.fingerprint != record.SessionFingerprint(s.id) {
		_, _ = s.close(context.WithoutCancel(ctx), false)
		return nil, connect.NewError(connect.CodeDataLoss, fmt.Errorf("%w: the daemon's session fingerprint does not match its session ID", record.ErrChain))
	}
	if err := sandbox.CheckResultIsolation(s.isolation, opts.MinimumIsolation); err != nil {
		_, _ = s.close(context.WithoutCancel(ctx), false)
		return nil, connect.NewError(connect.CodeDataLoss, err)
	}
	if !opts.Software.Allows(m.GetSoftwareIdentity()) {
		_, _ = s.close(context.WithoutCancel(ctx), false)
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

// Fingerprint is the SHA-256 of the session ID, as the session's records carry it.
func (s *Session) Fingerprint() string { return s.fingerprint }

// Isolation is the tier the daemon measured when the session opened.
func (s *Session) Isolation() sandbox.IsolationClass { return s.isolation }

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

// Stopped returns why this client sends no more calls after an answer it could not
// check, or nil until it stops. It wraps ErrSessionUnanswered and the original cause;
// it is distinct from Ended, which reports an end the daemon stated.
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
			return nil, nil, err
		}
		if rec == nil {
			s.setStopped(err)
			return nil, nil, err
		}
		r, cerr := record.CheckUnanswered(msg, rec, s.fingerprint, s.calls, s.last)
		if cerr == nil && (r.Provider != s.provider || r.Isolation != s.isolation.String() || r.SoftwareIdentity != s.identity) {
			// With no response to compare it with, the record's evidence must be what
			// the session stated at open.
			cerr = fmt.Errorf("%w: the unanswered call's record names %s at %q running %q, the session opened as %s at %q running %q",
				record.ErrMismatch, r.Provider, r.Isolation, r.SoftwareIdentity, s.provider, s.isolation, s.identity)
		}
		if cerr != nil {
			s.setStopped(cerr)
			return nil, nil, connect.NewError(connect.CodeDataLoss, cerr)
		}
		s.calls, s.last = r.Sequence, r.SHA256
		if ur, ok := s.r.recorder.(UnansweredRecorder); ok {
			if rerr := ur.RecordUnanswered(record.AsRunRequest(msg), rec); rerr != nil {
				return nil, nil, fmt.Errorf("%w: %w", ErrNotRecorded, &UnansweredCallError{Record: r, Err: err})
			}
		}
		return nil, nil, &UnansweredCallError{Record: r, Err: err}
	}
	run := resp.Msg.GetRun()
	if run == nil {
		s.setStopped(ErrResultKindMismatch)
		return nil, nil, connect.NewError(connect.CodeDataLoss, ErrResultKindMismatch)
	}
	if e := resp.Msg.GetEnded(); e != plimsollv1.SessionEnd_SESSION_END_UNSPECIFIED {
		s.setEnd(&sandbox.SessionEndedError{Reason: sessionEndFromWire(e), Detail: resp.Msg.GetEndDetail()})
	}
	rec, err := record.CheckSessionCall(msg, run, s.fingerprint, s.calls, s.last)
	if err != nil {
		s.setStopped(err)
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
// matches the chain this client has seen.
func (s *Session) Close(ctx context.Context) (SessionSummary, error) { return s.close(ctx, true) }

func (s *Session) close(ctx context.Context, sign bool) (SessionSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req := connect.NewRequest(&plimsollv1.CloseSessionRequest{Protocol: Protocol, SessionId: s.id})
	s.r.auth(req)
	resp, err := s.r.client.CloseSession(ctx, req)
	if err != nil {
		return SessionSummary{Session: s.fingerprint}, restoreSandboxError(err)
	}
	m := resp.Msg
	sum := SessionSummary{Session: m.GetSession(), Calls: m.GetCalls(), LastRecordSHA256: m.GetLastRecordSha256(), End: sessionEndFromWire(m.GetEnded())}
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
