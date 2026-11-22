package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/softwarewire"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// CheckpointVersion is the one version of Checkpoint this client writes and reads.
const CheckpointVersion = 1

// DaemonNamePattern is the grammar of a daemon's name (WithDaemonName): the application's
// own short name for the daemon, never a URL, so a checkpoint read back from a store can
// only pick a client the application configured, never point one at another server. The
// Python and TypeScript clients apply the same grammar (internal/wiretables writes it).
const DaemonNamePattern = `^[A-Za-z0-9._-]{1,64}$`

// SoftwareRuleIDPattern is the grammar of a software rule's ID as a checkpoint states it
// (sandbox.SoftwareRule.ID): "exact:" and one software identity, or "approved:sha256:" and
// the approved set's digest.
const SoftwareRuleIDPattern = `^(?:exact:[A-Za-z0-9._:/@+-]{1,256}|approved:sha256:[0-9a-f]{64})$`

var (
	daemonNameForm = regexp.MustCompile(DaemonNamePattern)
	ruleIDForm     = regexp.MustCompile(SoftwareRuleIDPattern)
	identityForm   = regexp.MustCompile(sandbox.SoftwareIdentityPattern)
	decimalForm    = regexp.MustCompile(`^"(?:0|[1-9][0-9]*)"$`)
)

// Checkpoint is what an application saves, in a store it protects, so another process can
// carry on with a session (Remote.AttachSession). It holds no secret: not the session ID,
// not a credential. It is the session's public chain head (the ownership generation, the
// count of calls and the last record's digest) and the policy the session stated at open,
// which an attach answer must repeat exactly.
//
// Its JSON form is the one every official client reads and writes: these names, every
// key present, the generation and the count as decimal strings (a JavaScript number cannot
// hold every uint64). ParseCheckpoint reads it.
//
// The store must be one only the application can write: anyone holding the caller's
// credential and a checkpoint (or the session's run records, which carry the fingerprint
// and the head) can take the session over.
type Checkpoint struct {
	Version int `json:"version"`
	// Daemon is the application's own name for the daemon (WithDaemonName), never a URL.
	Daemon string `json:"daemon"`
	// Session is the fingerprint: the SHA-256 of the session ID, 64 lowercase hex digits.
	Session          string `json:"session"`
	Generation       uint64 `json:"generation,string"`
	Calls            uint64 `json:"calls,string"`
	LastRecordSHA256 string `json:"last_record_sha256"`
	// The provider, tier, the sentence beside the tier and the software the daemon stated
	// at open.
	Provider               string `json:"provider"`
	Isolation              string `json:"isolation"`
	IsolationQualification string `json:"isolation_qualification"`
	SoftwareIdentity       string `json:"software_identity"`
	// OpenFloor is the floor sent at open, as the daemon echoed it; "" for none.
	OpenFloor string `json:"open_floor"`
	// OpenRule is the ID of the software rule sent at open, "" for none.
	OpenRule      string `json:"open_rule"`
	ExpiresUnixMs int64  `json:"expires_unix_ms"`
	IdleTimeoutMs uint32 `json:"idle_timeout_ms"`
	// LostCallSHA256 is the request digest of a call that was sent once with no answer
	// reaching any worker (an attach explained the gap it left), which the session's next
	// call is refused for repeating (ErrCallAlreadySent); "" for none. A checkpoint carries
	// it until that next call, unless the daemon refused that call with the not-dispatched
	// mark: nothing ran, so the call after it is still the next.
	LostCallSHA256 string `json:"lost_call_sha256"`
}

// AttachOptions is what an attach may name beyond its checkpoint.
type AttachOptions struct {
	// LostRequestSHA256 is the request digest of the call this application believes ran
	// after the checkpoint with no answer reaching it (Session.LostRequestSHA256 gives it
	// for a call of this process), or "" for none. With it, the daemon takes the session
	// over from a checkpoint exactly one call behind its head when its last record is that
	// call, following the checkpoint (the explained gap), and returns the record, which
	// AttachSession checks again before carrying the chain on; the attached session then
	// refuses its first call if it repeats that call. Any other gap stays
	// ErrCheckpointMismatch, and ownership does not move.
	LostRequestSHA256 string
}

// ErrInvalidCheckpoint marks a checkpoint that is not one this client can attach with.
var ErrInvalidCheckpoint = errors.New("client: invalid session checkpoint")

// ErrNoCheckpoint refuses Session.Checkpoint: the client has no daemon name, or the
// session is stopped, closed or ended.
var ErrNoCheckpoint = errors.New("client: this session cannot be checkpointed")

// ErrRecorderCannotAttach refuses an attach on a Remote with a Recorder: a signing
// recorder cannot resume a chain it did not sign from the session's first call.
var ErrRecorderCannotAttach = errors.New("client: a Recorder cannot resume a session's chain it did not sign from the start, so a Remote with one cannot attach")

// ErrStaleOwner is a session call, close or attach the daemon refused because another
// worker attached the session (or its ownership generation is spent): nothing ran, and
// the session goes on for its new owner. After it on a call or a close, this Session
// sends nothing more.
var ErrStaleOwner = errors.New("client: another worker owns this session")

// ErrCheckpointMismatch is an attach the daemon refused because the checkpoint is not the
// session's head: a call ran after the checkpoint was saved, its answer perhaps lost.
// Nothing ran, and ownership did not move.
var ErrCheckpointMismatch = errors.New("client: the checkpoint is not the session's head")

// CallAlreadySentText is what every official client says when it refuses a repeat of a
// lost call (ErrCallAlreadySent here; the Python and TypeScript clients' CallAlreadySentError,
// whose copies internal/wiretables writes). It says what the client knows: the call was
// sent once and no answer reached a worker. The lost call's record says whether the
// daemon answered it (Session.LostCall): a result digest when the daemon answered, which
// does not show that the call ran to its end, an unanswered code when it ended without an
// answer and may have done none, part or all of its work.
const CallAlreadySentText = "this call was already sent once in the session, and its answer was lost"

// ErrCallAlreadySent refuses, before anything is sent, the first call of a session taken
// over across an explained gap when it repeats the lost call: that call was already sent
// once and its answer was lost, so this is a retry of it. It is never a retry signal. Only
// the first call is checked.
var ErrCallAlreadySent = errors.New("client: " + CallAlreadySentText)

// Validate reports whether c is a checkpoint this client can attach with, wrapping
// ErrInvalidCheckpoint when it is not.
func (c Checkpoint) Validate() error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrInvalidCheckpoint, what) }
	switch {
	case c.Version != CheckpointVersion:
		return bad("unknown version")
	case !daemonNameForm.MatchString(c.Daemon):
		return bad("the daemon name is not 1 to 64 of [A-Za-z0-9._-]")
	case !validDigest(c.Session):
		return bad("the fingerprint is not 64 lowercase hex digits")
	case c.Generation == 0:
		return bad("the generation is zero")
	case c.Calls == 0 && c.LastRecordSHA256 != "", c.Calls > 0 && !validDigest(c.LastRecordSHA256):
		return bad("the last record does not match the count of calls")
	case c.Provider == "" || len(c.Provider) > 256 || !utf8.ValidString(c.Provider):
		return bad("the provider is empty or malformed")
	case !isFloor(c.Isolation):
		return bad("the tier is not one a session runs at")
	case !record.ValidQualification(c.IsolationQualification):
		return bad("the isolation qualification is malformed")
	case c.SoftwareIdentity != "" && (len(c.SoftwareIdentity) > sandbox.MaxSoftwareIdentityBytes || !identityForm.MatchString(c.SoftwareIdentity)):
		return bad("the software identity is malformed")
	case c.OpenFloor != "" && !isFloor(c.OpenFloor):
		return bad("the open floor is not a tier")
	case sandbox.CheckResultIsolation(sandbox.ParseIsolationClass(c.Isolation), sandbox.ParseIsolationClass(c.OpenFloor)) != nil:
		return bad("the tier is below the open floor")
	case c.OpenRule != "" && !ruleIDForm.MatchString(c.OpenRule):
		return bad("the open rule is not a software rule's ID")
	case c.ExpiresUnixMs <= 0:
		return bad("the expiry is not a positive time")
	case c.LostCallSHA256 != "" && (!validDigest(c.LostCallSHA256) || c.Calls == 0):
		return bad("the lost call is not a request digest of a call the session ran")
	}
	return nil
}

// isFloor reports whether s names a tier a request may state as its floor: every tier but
// none.
func isFloor(s string) bool {
	t := sandbox.ParseIsolationClass(s)
	return t != sandbox.IsolationUnknown && t != sandbox.IsolationNone
}

func validDigest(s string) bool {
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

// checkpointKeys is every key of the JSON form, each required.
var checkpointKeys = []string{"version", "daemon", "session", "generation", "calls", "last_record_sha256", "provider", "isolation",
	"isolation_qualification", "software_identity", "open_floor", "open_rule", "expires_unix_ms", "idle_timeout_ms", "lost_call_sha256"}

// ParseCheckpoint reads a checkpoint's JSON form and validates it: one object holding every
// key and no other, nothing after it. Its errors wrap ErrInvalidCheckpoint.
func ParseCheckpoint(data []byte) (Checkpoint, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: %w", ErrInvalidCheckpoint, err)
	}
	if len(keys) != len(checkpointKeys) {
		return Checkpoint{}, fmt.Errorf("%w: the object does not hold exactly the checkpoint's %d keys", ErrInvalidCheckpoint, len(checkpointKeys))
	}
	for _, k := range checkpointKeys {
		if _, ok := keys[k]; !ok {
			return Checkpoint{}, fmt.Errorf("%w: no %s", ErrInvalidCheckpoint, k)
		}
	}
	// encoding/json reads "01" into a uint64 marked ,string; the form is the canonical
	// decimal, as every client writes it.
	for _, k := range []string{"generation", "calls"} {
		if !decimalForm.Match(keys[k]) {
			return Checkpoint{}, fmt.Errorf("%w: %s is not a decimal string with no leading zero", ErrInvalidCheckpoint, k)
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var c Checkpoint
	if err := d.Decode(&c); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: %w", ErrInvalidCheckpoint, err)
	}
	if d.More() {
		return Checkpoint{}, fmt.Errorf("%w: text after the object", ErrInvalidCheckpoint)
	}
	if err := c.Validate(); err != nil {
		return Checkpoint{}, err
	}
	return c, nil
}

// Checkpoint returns the session's checkpoint, for the application to save where only it
// can write. It refuses (ErrNoCheckpoint) when the client has no daemon name
// (WithDaemonName) and when the session is stopped, closed or ended. It waits for a call
// in flight, so the head it states follows that call.
func (s *Session) Checkpoint() (Checkpoint, error) {
	if s.r.daemonName == "" {
		return Checkpoint{}, fmt.Errorf("%w: the client has no daemon name (WithDaemonName)", ErrNoCheckpoint)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Stopped(); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: %w", ErrNoCheckpoint, err)
	}
	if s.isClosed() {
		return Checkpoint{}, fmt.Errorf("%w: the session is closed", ErrNoCheckpoint)
	}
	if err := s.Ended(); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: %w", ErrNoCheckpoint, err)
	}
	return Checkpoint{
		Version: CheckpointVersion, Daemon: s.r.daemonName, Session: s.fingerprint,
		Generation: s.generation, Calls: s.calls, LastRecordSHA256: s.last,
		Provider: s.provider, Isolation: s.isolation.String(), IsolationQualification: s.qualification, SoftwareIdentity: s.identity,
		OpenFloor: minimumIsolationWire(s.openFloor), OpenRule: s.software.ID(),
		ExpiresUnixMs: s.expires.UnixMilli(), IdleTimeoutMs: uint32(s.idle / time.Millisecond),
		LostCallSHA256: s.lostCall,
	}, nil
}

// AttachSession takes over the session cp names, carrying its chain on from cp's head:
// the daemon raises the session's ownership generation by one, and every call or close a
// worker holding an older one sends is refused before it runs (ErrStaleOwner).
//
// It refuses locally, sending nothing, when cp does not validate, when cp names another
// daemon than this client's (WithDaemonName), and on a Remote with a Recorder
// (ErrRecorderCannotAttach). The daemon refuses an unknown, ended or another caller's
// session as NotFound, a stale generation as ErrStaleOwner and a checkpoint that is not
// its head (a call ran after cp was saved) as ErrCheckpointMismatch; open development
// mode refuses every attach.
//
// The answer must repeat cp exactly: its fingerprint (and the SHA-256 of the session ID it
// returns), the generation one past cp's, cp's count and last record, and the provider,
// tier, qualification, software, open floor, open rule, expiry and idle timeout. Any
// difference is DataLoss wrapping record.ErrChain, and the session is not closed: a bad
// answer gives this client no right to destroy a session another worker may be using.
// With opts.LostRequestSHA256, the answer may instead carry the lost call's record and a
// head one call past cp's; that record must check on its own, be the call opts named, at
// cp's next place in the chain, stating the evidence the session stated at open, and be
// the new head (Session.LostCall returns it). A lost call's record the attach did not
// name is refused the same way.
//
// A transport failure or a canceled attach comes back as it is and is never retried: the
// daemon may have raised the generation, so cp may already be stale.
func (r *Remote) AttachSession(ctx context.Context, cp Checkpoint, opts AttachOptions) (*Session, error) {
	if err := cp.Validate(); err != nil {
		return nil, sandbox.NotDispatched(sandbox.RefusalRequest, err)
	}
	if opts.LostRequestSHA256 != "" && !validDigest(opts.LostRequestSHA256) {
		return nil, sandbox.NotDispatched(sandbox.RefusalRequest, fmt.Errorf("%w: the lost call's request digest is not 64 lowercase hex digits", ErrInvalidCheckpoint))
	}
	if r.daemonName == "" || cp.Daemon != r.daemonName {
		return nil, sandbox.NotDispatched(sandbox.RefusalRequest, fmt.Errorf("%w: it names the daemon %q, this client is %q", ErrInvalidCheckpoint, cp.Daemon, r.daemonName))
	}
	if r.recorder != nil {
		return nil, sandbox.NotDispatched(sandbox.RefusalRequest, ErrRecorderCannotAttach)
	}
	req := connect.NewRequest(&plimsollv1.AttachSessionRequest{
		Protocol: Protocol,
		Session:  cp.Session,
		Checkpoint: &plimsollv1.SessionCheckpoint{
			Generation: cp.Generation, Calls: cp.Calls, LastRecordSha256: cp.LastRecordSHA256,
		},
		TraceId:           TraceIDFrom(ctx),
		LostRequestSha256: opts.LostRequestSHA256,
	})
	r.auth(req)
	resp, err := r.client.AttachSession(ctx, req)
	if err != nil {
		return nil, restoreSandboxError(err)
	}
	s, err := r.attached(cp, opts.LostRequestSHA256, resp.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeDataLoss, fmt.Errorf("%w: the daemon's answer to the attach %s", record.ErrChain, err))
	}
	return s, nil
}

// attached checks an attach answer against the checkpoint it answers and builds the
// session from it, or says what differs.
func (r *Remote) attached(cp Checkpoint, lost string, m *plimsollv1.AttachSessionResponse) (*Session, error) {
	info, head := m.GetSessionInfo(), m.GetCheckpoint()
	rule := softwarewire.FromWire(info.GetSoftwareRule())
	var lostCall *sandbox.RunRecord
	if m.GetLostRecord() != nil {
		lr, err := lostRecord(cp, lost, m.GetLostRecord())
		if err != nil {
			return nil, err
		}
		lostCall = lr
	}
	calls, last, note := cp.Calls, cp.LastRecordSHA256, cp.LostCallSHA256
	if lostCall != nil {
		calls, last, note = lostCall.Sequence, lostCall.SHA256, lostCall.RequestSHA256
	}
	switch {
	case info == nil || head == nil:
		return nil, errors.New("lacks the session or its checkpoint")
	case info.GetSession() != cp.Session || record.SessionFingerprint(info.GetSessionId()) != cp.Session:
		return nil, errors.New("names another session, or a session ID whose SHA-256 is not the fingerprint")
	case info.GetGeneration() == 0 || info.GetGeneration()-1 != cp.Generation || head.GetGeneration() != info.GetGeneration():
		return nil, errors.New("states a generation other than one past the checkpoint's")
	case head.GetCalls() != calls || head.GetLastRecordSha256() != last:
		return nil, errors.New("states another chain head than the checkpoint's (or, across an explained gap, than the lost call's)")
	case info.GetSandbox() != cp.Provider || info.GetIsolation() != cp.Isolation || info.GetIsolationQualification() != cp.IsolationQualification ||
		info.GetSoftwareIdentity() != cp.SoftwareIdentity:
		return nil, errors.New("states another provider, tier, qualification or software than the session stated at open")
	case info.GetMinimumIsolation() != cp.OpenFloor || rule.Validate() != nil || rule.ID() != cp.OpenRule:
		return nil, errors.New("states another floor or software rule than the session was opened with")
	case info.GetExpiresUnixMs() != cp.ExpiresUnixMs || info.GetIdleTimeoutMs() != cp.IdleTimeoutMs:
		return nil, errors.New("states another lifetime or idle timeout than the session's")
	}
	// Everything now equals the checkpoint, which Validate held to its own floor: the tier
	// meets the open's floor.
	floor := sandbox.ParseIsolationClass(cp.OpenFloor)
	isolation := sandbox.ParseIsolationClass(info.GetIsolation())
	return &Session{
		r:             r,
		id:            info.GetSessionId(),
		generation:    info.GetGeneration(),
		fingerprint:   info.GetSession(),
		provider:      info.GetSandbox(),
		isolation:     isolation,
		identity:      info.GetSoftwareIdentity(),
		qualification: info.GetIsolationQualification(),
		software:      rule,
		floor:         floor,
		openFloor:     floor,
		expires:       time.UnixMilli(info.GetExpiresUnixMs()),
		idle:          time.Duration(info.GetIdleTimeoutMs()) * time.Millisecond,
		calls:         calls,
		last:          last,
		lostCall:      note,
		lostRecord:    lostCall,
	}, nil
}

// lostRecord checks the record an attach answer returns for the call the attach named
// (lost): a live record that checks on its own, of the session cp names, at cp's next
// place in the chain, carrying the named request digest and the evidence the session
// stated at open. It says what differs.
func lostRecord(cp Checkpoint, lost string, m *plimsollv1.RunRecord) (*sandbox.RunRecord, error) {
	r := record.FromWire(m)
	switch {
	case lost == "":
		return nil, errors.New("carries a lost call's record, but the attach named no lost call")
	case r.Version != record.Version:
		return nil, fmt.Errorf("carries a lost call's record of version %d, not the live version %d", r.Version, record.Version)
	case record.CheckStored(r) != nil:
		return nil, fmt.Errorf("carries a lost call's record that does not check: %w", record.CheckStored(r))
	case r.Session != cp.Session || cp.Calls == math.MaxUint64 || r.Sequence != cp.Calls+1 || r.PreviousSHA256 != cp.LastRecordSHA256:
		return nil, errors.New("carries a lost call's record that is not the checkpoint's next call")
	case r.RequestSHA256 != lost:
		return nil, errors.New("carries the record of another call than the one the attach named")
	case r.Provider != cp.Provider || r.Isolation != cp.Isolation || r.SoftwareIdentity != cp.SoftwareIdentity || r.IsolationQualification != cp.IsolationQualification:
		return nil, errors.New("carries a lost call's record stating other evidence than the session stated at open")
	}
	return &r, nil
}

// checkpointMismatch reports whether err is the daemon's refusal of a checkpoint that is
// not the session's head: its text is protocol.CheckpointMismatchText.
func checkpointMismatch(err error) bool {
	var ce *connect.Error
	return errors.As(err, &ce) && ce.Message() == protocol.CheckpointMismatchText
}
