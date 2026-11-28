package rpc

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/fileswire"
	"github.com/plimsollmark/plimsoll/internal/softwarewire"
	"github.com/plimsollmark/plimsoll/internal/wireenum"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// sessionInfo returns only the immutable open policy and the supplied generation.
// A new message is made each time so an in-process caller cannot mutate the policy.
func (e *sessionEntry) sessionInfo(generation uint64) *plimsollv1.OpenSessionResponse {
	minimum := ""
	if e.minimum != sandbox.IsolationUnknown {
		minimum = e.minimum.String()
	}
	var files []plimsollv1.FilesScope
	workDir := ""
	if fr, ok := e.sess.(sandbox.FileRunner); ok {
		files, workDir = fileswire.Scopes(fr.FileScopes()), wireString(fr.WorkDir())
	}
	return &plimsollv1.OpenSessionResponse{
		SessionId: e.id, Session: e.fingerprint, Generation: generation,
		Sandbox: e.provider, Isolation: e.isolation.String(),
		SoftwareIdentity: e.software.JavaScript.SoftwareIdentity,
		MinimumIsolation: minimum, SoftwareRule: softwarewire.ToWire(e.rule),
		ExpiresUnixMs: e.expires.UnixMilli(), IdleTimeoutMs: uint32(e.idleTimeout / time.Millisecond),
		IsolationQualification: e.qualification,
		FileScopes:             files, WorkDir: workDir,
	}
}

func (r *sessionRegistry) lookupFingerprint(fingerprint, principal string) (*sessionEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byFingerprint[fingerprint]
	if !ok || !e.authenticated || e.principal != principal {
		return nil, false
	}
	return e, true
}

func validSessionDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// The texts of the ownership refusals. Each is a constant, so no refusal states a
// number of the session's (a generation, a count of calls, a digest): a stale worker
// learns that it is stale, never what the current owner holds. The two the clients
// match (stale and mismatch) are the protocol package's, which internal/wiretables
// writes into the Python and TypeScript clients.
const (
	textGenerationZero     = "session ownership generation must be positive"
	textStaleOwner         = protocol.StaleOwnerText
	textCheckpointMismatch = protocol.CheckpointMismatchText
	textGenerationSpent    = "session ownership generation exhausted"
)

// checkHeadForm refuses a session call whose head is missing or malformed (no head, a
// zero generation, a count of zero with a digest, a count with no valid digest): a
// malformed request, refused before the session is looked up, as a zero generation is.
func checkHeadForm(head *plimsollv1.SessionCheckpoint) error {
	switch {
	case head == nil:
		return refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest, errors.New("session call requires the head it expects"))
	case head.GetGeneration() == 0:
		return refuseZeroGeneration()
	case !validHead(head):
		return refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest, errors.New("session call's head is malformed"))
	}
	return nil
}

// validHead reports whether a head's count and last record digest agree: no digest
// before the first call, a SHA-256 in lowercase hex after it.
func validHead(h *plimsollv1.SessionCheckpoint) bool {
	if h.GetCalls() == 0 {
		return h.GetLastRecordSha256() == ""
	}
	return validSessionDigest(h.GetLastRecordSha256())
}

// refuseZeroGeneration refuses a run, close or attach that carries no ownership
// generation: a malformed request, refused before the session is looked up or its
// turn taken, so it never waits behind a call in flight.
func refuseZeroGeneration() error {
	return refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest, errors.New(textGenerationZero))
}

// AttachSession transfers ownership only from an exact, trusted checkpoint, or from one
// exactly one call behind whose call the caller names and the daemon's last record
// confirms (the explained gap, explainsGap), returning that call's record.
// It shares the run/close turn, but takes no sandbox slot and touches no provider.
// Every refusal is written to the audit log at info: the caller, the refusal's
// reason, the trace ID and, once the lookup found the caller's own session, its
// fingerprint; never the generation, the count, a digest or the session ID.
func (s *SandboxService) AttachSession(ctx context.Context, req *connect.Request[plimsollv1.AttachSessionRequest]) (*connect.Response[plimsollv1.AttachSessionResponse], error) {
	var found string // the fingerprint of the caller's own session, once looked up
	resp, err := s.attachSession(ctx, req.Msg, &found)
	if err != nil {
		attrs := []slog.Attr{slog.String("caller", auditCaller(ctx))}
		if found != "" {
			attrs = append(attrs, slog.String("session", found))
		}
		reason := sandbox.RefusalUnknown
		if r, marked := notDispatchedOf(err); marked {
			reason = wireenum.RefusalFromWire(r)
		}
		attrs = append(attrs, slog.String("reason", reason.String()))
		s.logger().LogAttrs(ctx, slog.LevelInfo, "session attach refused", append(attrs, traceAttrs(req.Msg.GetTraceId())...)...)
		markRefusalLogged(ctx)
		return nil, err
	}
	return resp, nil
}

func (s *SandboxService) attachSession(ctx context.Context, m *plimsollv1.AttachSessionRequest, found *string) (*connect.Response[plimsollv1.AttachSessionResponse], error) {
	if err := checkProtocol(m.GetProtocol()); err != nil {
		return nil, err
	}
	principal, ok := PrincipalFrom(ctx)
	if !ok || principal.UserID == "" {
		return nil, refuse(connect.CodeUnauthenticated, sandbox.RefusalPermission, errors.New("session attach requires authentication"))
	}
	if !principal.HasScope(ScopeCodeRun) {
		return nil, refuse(connect.CodePermissionDenied, sandbox.RefusalPermission, errors.New("session attach requires code:run"))
	}
	// Charged right after authentication, before the checkpoint is read or the session
	// looked up, so a refused attach costs what a good one costs: one for an unknown
	// session, another caller's, or a stale or malformed checkpoint takes a token too,
	// and a caller cannot loop refused attaches for free or hold a session's one
	// waiting place with them.
	if s.Limiter != nil {
		if err := s.Limiter.Charge(principal.UserID); err != nil {
			return nil, err
		}
	}
	cp := m.GetCheckpoint()
	if cp != nil && cp.GetGeneration() == 0 {
		return nil, refuseZeroGeneration()
	}
	lost := m.GetLostRequestSha256()
	if !validSessionDigest(m.GetSession()) || cp == nil || !validHead(cp) ||
		(lost != "" && !validSessionDigest(lost)) {
		return nil, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest, errors.New("session attach requires a valid fingerprint and checkpoint"))
	}
	e, ok := s.sessions.lookupFingerprint(m.GetSession(), principal.UserID)
	if !ok {
		return nil, errSessionNotFound()
	}
	*found = e.fingerprint
	// A stale checkpoint is refused before the turn too, so it never holds the
	// session's one waiting place; the comparison under the turn is the one that counts.
	if err := e.checkGeneration(cp.GetGeneration()); err != nil {
		return nil, err
	}
	ctx, cancel := runContext(ctx)
	defer cancel()
	give, err := e.takeTurn(ctx)
	if err != nil {
		return nil, err
	}
	defer give()
	if ctx.Err() != nil {
		return nil, busy(ctx)
	}
	// An ended session cannot be attached, and says so as an unknown one does: a
	// provider's expiry callback may be late, so the absolute deadline is checked too.
	// endErr takes mu itself, so it is read first; a session that ends after this
	// check is like one that ends just after the attach, and its next call says so.
	ended := e.endErr() != nil
	e.mu.Lock()
	if ended || e.ended || !time.Now().Before(e.expires) {
		e.mu.Unlock()
		return nil, errSessionNotFound()
	}
	if cp.GetGeneration() != e.generation {
		e.mu.Unlock()
		return nil, refuse(connect.CodeFailedPrecondition, sandbox.RefusalPermission, errors.New(textStaleOwner))
	}
	// The head, or the explained gap: the checkpoint is exactly one call behind, the
	// caller named a call's request digest, and the session's last record is that call,
	// following the checkpoint. Compared here, under the turn and the lock, with the
	// generation's advance below, so an unexplained gap never moves ownership.
	var lostRecord *plimsollv1.RunRecord
	var lostAnswer *plimsollv1.RunResponse
	if cp.GetCalls() != e.calls || cp.GetLastRecordSha256() != e.last {
		if !explainsGap(cp, lost, e.calls, e.lastRecord) {
			e.mu.Unlock()
			return nil, refuse(connect.CodeFailedPrecondition, sandbox.RefusalRequest, errors.New(textCheckpointMismatch))
		}
		lostRecord = proto.Clone(e.lastRecord).(*plimsollv1.RunRecord)
		// The lost call's answer, when the daemon answered it and still keeps it: its
		// record is lastRecord, since the two are set, replaced and dropped together.
		if e.keptAnswer != nil {
			lostAnswer = proto.Clone(e.keptAnswer).(*plimsollv1.RunResponse)
		}
	}
	if e.generation == math.MaxUint64 {
		e.mu.Unlock()
		return nil, refuse(connect.CodeFailedPrecondition, sandbox.RefusalPermission, errors.New(textGenerationSpent))
	}
	if ctx.Err() != nil {
		e.mu.Unlock()
		return nil, busy(ctx)
	}
	previous := e.generation
	e.generation++
	e.claimed = true
	generation, calls, last := e.generation, e.calls, e.last
	e.mu.Unlock()
	s.logger().LogAttrs(ctx, slog.LevelInfo, "session attached", append([]slog.Attr{
		slog.String("caller", e.principal), slog.String("session", e.fingerprint),
		slog.Uint64("old_generation", previous), slog.Uint64("generation", generation),
		slog.Uint64("calls", calls), slog.Bool("explained_gap", lostRecord != nil), slog.Bool("lost_answer", lostAnswer != nil),
	}, traceAttrs(m.GetTraceId())...)...)
	return connect.NewResponse(&plimsollv1.AttachSessionResponse{
		SessionInfo: e.sessionInfo(generation),
		Checkpoint:  &plimsollv1.SessionCheckpoint{Generation: generation, Calls: calls, LastRecordSha256: last},
		LostRecord:  lostRecord,
		LostAnswer:  lostAnswer,
	}), nil
}

// explainsGap reports whether a checkpoint that is not the head is exactly one call
// behind it and the caller named that call: the session's last record (rec, the head's
// own) is the checkpoint's next call, follows the checkpoint's last record, and carries
// the request digest the caller named. Nothing else differing from the head is accepted.
func explainsGap(cp *plimsollv1.SessionCheckpoint, lost string, calls uint64, rec *plimsollv1.RunRecord) bool {
	return lost != "" && rec != nil && calls > 0 && cp.GetCalls() == calls-1 &&
		rec.GetSequence() == calls && rec.GetPreviousSha256() == cp.GetLastRecordSha256() &&
		rec.GetRequestSha256() == lost
}
