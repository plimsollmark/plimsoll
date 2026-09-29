package client

import (
	"context"
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
	isolation   sandbox.IsolationClass
	software    sandbox.SoftwareRule
	expires     time.Time
	idle        time.Duration

	mu    sync.Mutex
	calls uint64
	last  string
	end   *sandbox.SessionEndedError
}

// SessionRecorder is a Recorder that also signs a session's close: the daemon's
// count of executed calls and its last record, which lets a verifier tell a
// complete chain from a cut one. attest.Harness is one.
type SessionRecorder interface {
	Recorder
	RecordClose(session string, calls uint64, lastRecordSHA256 string) error
}

// OpenSession opens a session. The session ID it holds is a capability: it is sent
// only to the daemon, and never appears in a record, a log line or an error.
func (r *Remote) OpenSession(ctx context.Context, opts SessionOptions) (*Session, error) {
	req := connect.NewRequest(&plimsollv1.OpenSessionRequest{
		Protocol:         Protocol,
		MinimumIsolation: minimumIsolationWire(opts.MinimumIsolation),
		TraceId:          TraceIDFrom(ctx),
		LifetimeMs:       durationMs(opts.Lifetime),
		IdleTimeoutMs:    durationMs(opts.IdleTimeout),
		SoftwareRule:     softwarewire.ToWire(opts.Software),
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
		isolation:   sandbox.ParseIsolationClass(m.GetIsolation()),
		software:    opts.Software,
		expires:     time.UnixMilli(m.GetExpiresUnixMs()),
		idle:        time.Duration(m.GetIdleTimeoutMs()) * time.Millisecond,
	}
	if s.fingerprint != record.SessionFingerprint(s.id) {
		return nil, connect.NewError(connect.CodeDataLoss, fmt.Errorf("%w: the daemon's session fingerprint does not match its session ID", record.ErrChain))
	}
	if err := sandbox.CheckResultIsolation(s.isolation, opts.MinimumIsolation); err != nil {
		_, _ = s.Close(context.WithoutCancel(ctx))
		return nil, connect.NewError(connect.CodeDataLoss, err)
	}
	if !opts.Software.Allows(m.GetSoftwareIdentity()) {
		_, _ = s.Close(context.WithoutCancel(ctx))
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.end == nil {
		return nil
	}
	return s.end
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
	req := s.envelope(ctx, in.Timeout, in.MinimumIsolation, software)
	req.Payload = &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: in.Code, GrantProfile: s.r.jsGrant}}
	resp, rec, err := s.call(ctx, req)
	if resp == nil {
		return fail, err
	}
	res, ok := javascriptResult(resp, rec)
	if !ok {
		return fail, connect.NewError(connect.CodeDataLoss, ErrResultKindMismatch)
	}
	if err != nil {
		return res, err
	}
	if err := sandbox.CheckResultIsolation(res.Isolation, in.MinimumIsolation); err != nil {
		return res, connect.NewError(connect.CodeDataLoss, err)
	}
	return res, nil
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
	req := s.envelope(ctx, in.Timeout, in.MinimumIsolation, software)
	req.Payload = &plimsollv1.SessionRunRequest_Project{Project: p}
	resp, rec, err := s.call(ctx, req)
	if resp == nil {
		return fail, err
	}
	res, ok := projectResult(resp, rec)
	if !ok {
		return fail, connect.NewError(connect.CodeDataLoss, ErrResultKindMismatch)
	}
	if err != nil {
		return res, err
	}
	if err := sandbox.CheckResultIsolation(res.Isolation, in.MinimumIsolation); err != nil {
		return res, connect.NewError(connect.CodeDataLoss, err)
	}
	return res, nil
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
	req := connect.NewRequest(msg)
	s.r.auth(req)
	resp, err := s.r.client.SessionRun(ctx, req)
	if err != nil {
		err = restoreSandboxError(err)
		var se *sandbox.SessionEndedError
		if errors.As(err, &se) {
			s.end = se
		}
		return nil, nil, err
	}
	run := resp.Msg.GetRun()
	if run == nil {
		return nil, nil, connect.NewError(connect.CodeDataLoss, ErrResultKindMismatch)
	}
	if e := resp.Msg.GetEnded(); e != plimsollv1.SessionEnd_SESSION_END_UNSPECIFIED {
		s.end = &sandbox.SessionEndedError{Reason: sessionEndFromWire(e), Detail: resp.Msg.GetEndDetail()}
	}
	rec, err := record.CheckSessionCall(msg, run, s.fingerprint, s.calls, s.last)
	if err != nil {
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
// ran in the session: that is DataLoss wrapping record.ErrChain, with the summary.
// A SessionRecorder signs the daemon's statement either way.
func (s *Session) Close(ctx context.Context) (SessionSummary, error) {
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
	if sr, ok := s.r.recorder.(SessionRecorder); ok {
		if err := sr.RecordClose(sum.Session, sum.Calls, sum.LastRecordSHA256); err != nil {
			return sum, fmt.Errorf("%w: the close: %w", ErrNotRecorded, err)
		}
	}
	if sum.Session != s.fingerprint || sum.Calls != s.calls || sum.LastRecordSHA256 != s.last {
		return sum, connect.NewError(connect.CodeDataLoss, fmt.Errorf("%w: the daemon counts %d calls ending %q, this client saw %d ending %q",
			record.ErrChain, sum.Calls, sum.LastRecordSHA256, s.calls, s.last))
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
	default:
		return nil, nil, sandbox.NotDispatched(sandbox.RefusalRequest, fmt.Errorf("%w: only snippets and projects run in a session", sandbox.ErrInvalidRequest))
	}
	return s.call(ctx, msg)
}
