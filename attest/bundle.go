package attest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/plimsollmark/plimsoll/protocol"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// ClosePredicateType names a session-close statement: the daemon's count of a
// session's executed calls and its last record, signed by the harness when the
// session ends, so a verifier can tell a complete chain from a cut one.
const ClosePredicateType = "https://plimsollmark.github.io/plimsoll/session-close/v1"

// SessionClose is a session-close statement's predicate.
type SessionClose struct {
	Session          string `json:"session"` // the session fingerprint
	Calls            uint64 `json:"calls"`
	LastRecordSHA256 string `json:"last_record_sha256"`
}

// CloseNotCollectedPredicateType names the harness's own statement that a session's
// close could not be collected: the daemon answered the client's close with no count
// (CloseNotCollectedNotFound, CloseNotCollectedStaleOwner), so the session ends in the
// bundle with the calls the client saw and without the daemon's count of them. It is
// told from a daemon's close by this type, inside the signed payload: VerifyClose refuses
// it, and SignStatement cannot make one.
const CloseNotCollectedPredicateType = "https://plimsollmark.github.io/plimsoll/session-close-not-collected/v1"

// The reasons a SessionCloseNotCollected may state: the only failures of a close after
// which the daemon will never answer it with a count.
const (
	// CloseNotCollectedNotFound: the daemon that answered the close said NotFound, marked
	// not dispatched: "no such session for this caller". That is its answer, not a fact
	// about the session: it gives it after a restart, more than the 10 minutes it keeps an
	// ended session's count, after another holder of the session ID closed it, to another
	// caller's credential, and to a close a load balancer sent to a daemon that never had
	// the session (which may then still be alive elsewhere).
	CloseNotCollectedNotFound = "not_found"
	// CloseNotCollectedStaleOwner: the daemon refused the close because another worker
	// took the session over.
	CloseNotCollectedStaleOwner = "stale_owner"
)

// SessionCloseNotCollected is the predicate of the harness's statement that a session's
// close could not be collected. CallsSeen and LastRecordSHA256 are the client's own count
// and last record, never the daemon's.
//
// UnansweredRequestSHA256 is the request digest (as a run record's request_sha256 would
// state it) of a call the client sent after those calls and got no answer for, which may
// have run: "" when there was none. There is at most one. A session's calls are sent one
// at a time, and the first that ends with no answer the client can check stops the
// session, so every later call is refused before it is sent; a call the daemon answered
// with the record of a call that may have run is in the chain itself, among CallsSeen.
type SessionCloseNotCollected struct {
	Session                 string `json:"session"` // the session fingerprint
	CallsSeen               uint64 `json:"calls_seen"`
	LastRecordSHA256        string `json:"last_record_sha256"`        // "" exactly when CallsSeen is 0
	UnansweredRequestSHA256 string `json:"unanswered_request_sha256"` // "" when no call was sent and left unanswered
	Reason                  string `json:"reason"`                    // CloseNotCollectedNotFound or CloseNotCollectedStaleOwner
	NotedUnixMs             int64  `json:"noted_unix_ms"`             // the harness's clock when it signed; its word, checked against nothing
}

// check refuses a statement no harness of this release writes.
func (c SessionCloseNotCollected) check() error {
	switch {
	case !isSHA256Hex(c.Session):
		return errors.New("its session is not a fingerprint")
	case c.Reason != CloseNotCollectedNotFound && c.Reason != CloseNotCollectedStaleOwner:
		return fmt.Errorf("reason %q is not one of %q and %q", prefixed(c.Reason, 40), CloseNotCollectedNotFound, CloseNotCollectedStaleOwner)
	case c.NotedUnixMs <= 0:
		return errors.New("it states no time")
	case (c.CallsSeen == 0) != (c.LastRecordSHA256 == ""), c.LastRecordSHA256 != "" && !isSHA256Hex(c.LastRecordSHA256):
		return errors.New("its count and its last record disagree, or the last record is not a digest")
	case c.UnansweredRequestSHA256 != "" && !isSHA256Hex(c.UnansweredRequestSHA256):
		return errors.New("its unanswered call's request is not a digest")
	}
	return nil
}

// NotCollectedReasonText is a SessionCloseNotCollected's reason in the words
// plimsoll-attest prints: what the daemon answered, never a fact about the session the
// harness cannot know.
func NotCollectedReasonText(reason string) string {
	if reason == CloseNotCollectedStaleOwner {
		return "another worker took the session over"
	}
	return "the daemon that answered the close said it has no such session for this caller"
}

// Describe is the statement in the words plimsoll-attest verify prints for it.
func (c SessionCloseNotCollected) Describe() string {
	saw := fmt.Sprintf("these %d calls in this order", c.CallsSeen)
	switch c.CallsSeen {
	case 0:
		saw = "no call of it"
	case 1:
		saw = "this 1 call"
	}
	s := fmt.Sprintf("NOT PROVEN COMPLETE: its close could not be collected (%s); the harness signed that the client saw %s, and the daemon's own count of the session's calls is unknown",
		NotCollectedReasonText(c.Reason), saw)
	return s + c.DescribeUnanswered()
}

// DescribeUnanswered is the statement's unanswered call in the words plimsoll-attest
// prints after the rest, or "" when it names none.
func (c SessionCloseNotCollected) DescribeUnanswered() string {
	switch {
	case c.UnansweredRequestSHA256 == "":
		return ""
	case c.CallsSeen == 0:
		return fmt.Sprintf("; and one call was sent with no answer (request %s): it may have run", c.UnansweredRequestSHA256)
	case c.CallsSeen == 1:
		return fmt.Sprintf("; and one more call was sent after it with no answer (request %s): it may have run", c.UnansweredRequestSHA256)
	}
	return fmt.Sprintf("; and one more call was sent after them with no answer (request %s): it may have run", c.UnansweredRequestSHA256)
}

// Entry is one line of a bundle. A call entry holds the request as sent (for a
// session call, its fields as a RunRequest, without the session ID) and the
// response as received, each as its binary protobuf encoding (base64 in the JSON
// line), and the envelope over the run record. A close entry holds only the
// envelope over a SessionClose. Binary, not protobuf JSON: JSON writes every NaN
// as "NaN" and reads it back as one particular NaN, so a module output carrying
// any other NaN (C's NAN is 0x7ff8000000000000) would no longer match its signed
// digest.
//
// Every line also carries Link, the harness's signed statement of the line's place in
// the bundle (LinkPredicateType). A checkpoint line is a Link alone.
type Entry struct {
	Request  []byte    `json:"request,omitempty"`
	Response []byte    `json:"response,omitempty"`
	Envelope Envelope  `json:"envelope,omitzero"`
	Link     *Envelope `json:"link,omitempty"`
}

// LinkPredicateType names a bundle link: the harness's signed statement that a line
// is the given position in its bundle and follows the given line. Verification
// follows the links from the first line, so a line deleted, moved,
// inserted or changed breaks the chain, and requires the bundle's last line to be a
// checkpoint: a link stating how many lines come before it, which the harness writes
// when it finishes. A cut tail therefore loses the checkpoint and fails, unless it is
// cut back to an earlier checkpoint (a bundle appended to over several harness runs
// has one per run): that is proven only by the caller's own count (VerifyExpected).
const LinkPredicateType = "https://plimsollmark.github.io/plimsoll/bundle-link/v1"

// Link is a bundle link's predicate.
type Link struct {
	Index    uint64 `json:"index"`                  // the line's 1-based position
	Previous string `json:"previous_sha256"`        // LineDigest of the line before; "" on the first
	Entry    string `json:"entry_sha256,omitempty"` // ContentDigest of the line's entry; "" on a checkpoint
	// Checkpoint marks a line that is the link alone, stating that Lines lines come
	// before it.
	Checkpoint bool   `json:"checkpoint,omitempty"`
	Lines      uint64 `json:"lines,omitempty"`
}

type linkStatement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Link      `json:"predicate"`
}

// ContentDigest is the SHA-256 of an entry without its link, which the line's link
// signs: the line's bytes as stored with its link member (always the last) removed.
// ReadBundle refuses a line that is not exactly the encoding json.Marshal gives its
// entry, so this is a digest of stored bytes.
func ContentDigest(e Entry) string {
	e.Link = nil
	return digestJSON(e)
}

// LineDigest is the SHA-256 of a whole line as stored, its link included, without the
// line's newline: what the next line's link names.
func LineDigest(e Entry) string { return digestJSON(e) }

func digestJSON(e Entry) string {
	b, _ := json.Marshal(e) // an Entry always marshals
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// signLink signs a link statement; its subject is the line it places (the entry's
// content digest, or for a checkpoint the line before it).
func (s *Signer) signLink(l Link) (Envelope, error) {
	subject := l.Entry
	if l.Checkpoint {
		subject = l.Previous
	}
	st := linkStatement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "bundle-line", Digest: map[string]string{"sha256": subject}}},
		PredicateType: LinkPredicateType,
		Predicate:     l,
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return Envelope{}, err
	}
	return s.envelope(payload), nil
}

// VerifyLink checks a link envelope's signature and statement.
func (v *Verifier) VerifyLink(env Envelope) (Link, error) {
	payload, err := v.signedPayload(env)
	if err != nil {
		return Link{}, err
	}
	var st linkStatement
	if err := decodeStrict(payload, &st); err != nil {
		return Link{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	l := st.Predicate
	subject := l.Entry
	if l.Checkpoint {
		subject = l.Previous
	}
	if st.Type != StatementType || st.PredicateType != LinkPredicateType || len(st.Subject) != 1 ||
		st.Subject[0].Name != "bundle-line" || len(st.Subject[0].Digest) != 1 || st.Subject[0].Digest["sha256"] != subject {
		return Link{}, fmt.Errorf("%w: not a bundle-link statement", ErrStatement)
	}
	// One signature, this key's: a link the harness wrote carries nothing else, so a
	// copy with a signature added is not one.
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID != v.keyID {
		return Link{}, fmt.Errorf("%w: a bundle link carries exactly one signature, the harness's", ErrStatement)
	}
	return l, nil
}

// ErrIncomplete means a bundle does not end with a checkpoint: the harness did not
// finish it, or its tail was cut.
var ErrIncomplete = errors.New("attest: the bundle does not end with a checkpoint")

// ErrLink means a bundle's lines do not form the harness's unbroken chain: a line
// deleted, moved, inserted or changed.
var ErrLink = errors.New("attest: broken bundle chain")

// verifyLinks follows the bundle's links from its first line and requires its last
// line to be a checkpoint. It returns whether each line is a checkpoint.
func verifyLinks(entries []Entry, v *Verifier) ([]bool, error) {
	checkpoint := make([]bool, len(entries))
	prev := ""
	for i, e := range entries {
		fail := func(err error) ([]bool, error) { return nil, fmt.Errorf("entry %d: %w", i+1, err) }
		if e.Link == nil {
			return fail(fmt.Errorf("%w: the line has no link", ErrLink))
		}
		l, err := v.VerifyLink(*e.Link)
		if err != nil {
			return fail(err)
		}
		switch {
		case l.Index != uint64(i+1):
			return fail(fmt.Errorf("%w: the line says it is line %d", ErrLink, l.Index))
		case l.Previous != prev:
			return fail(fmt.Errorf("%w: the line follows %q, the line before it is %q", ErrLink, l.Previous, prev))
		case l.Checkpoint && (l.Lines != uint64(i) || l.Entry != "" || e.Request != nil || e.Response != nil ||
			e.Envelope.PayloadType != "" || e.Envelope.Payload != "" || e.Envelope.Signatures != nil):
			return fail(fmt.Errorf("%w: a checkpoint that is not a link alone after %d lines", ErrLink, i))
		case !l.Checkpoint && (l.Lines != 0 || l.Entry != ContentDigest(e)):
			return fail(fmt.Errorf("%w: the line's link signs other content", ErrLink))
		}
		checkpoint[i] = l.Checkpoint
		prev = LineDigest(e)
	}
	if len(entries) == 0 || !checkpoint[len(entries)-1] {
		return nil, ErrIncomplete
	}
	return checkpoint, nil
}

// Call checks the record resp carries against req and resp, signs it, and
// returns the bundle entry. This is the harness's one step per call: nothing is
// signed that the harness did not recompute from its own copy of both messages.
// For a session call, req is the call as a Run request (record.AsRunRequest),
// whose digest is the call's; its place in the chain is VerifyBundle's to check.
func (s *Signer) Call(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) (Entry, error) {
	// A harness writes: it signs the current version only, though CheckExchange reads
	// every published one for stored evidence.
	if m := resp.GetRecord(); m != nil && int(m.GetVersion()) != record.Version {
		return Entry{}, fmt.Errorf("%w: the daemon answered with record version %d; a harness signs version %d only", ErrSigningVersion, m.GetVersion(), record.Version)
	}
	rec, err := record.CheckExchange(req, resp)
	if err != nil {
		return Entry{}, err
	}
	return s.entry(req, resp, *rec)
}

func (s *Signer) entry(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse, rec sandbox.RunRecord) (Entry, error) {
	env, err := s.Sign(rec)
	if err != nil {
		return Entry{}, err
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return Entry{}, err
	}
	respBytes, err := proto.Marshal(resp)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Request: reqBytes, Response: respBytes, Envelope: env}, nil
}

// Unanswered checks the record of a session call that may have run but ended in an
// error against the request sent (the call as a Run request, record.AsRunRequest),
// signs it, and returns the bundle entry: the request and the signed record, no
// response. Its place in the chain is VerifyBundle's to check, as for Call; a record that
// names no session is refused here, since no verifier accepts one (ErrChain).
func (s *Signer) Unanswered(req *plimsollv1.RunRequest, rec *plimsollv1.RunRecord) (Entry, error) {
	r := record.FromWire(rec)
	if err := record.CheckUnansweredExchange(req, r); err != nil {
		return Entry{}, err
	}
	if r.Session == "" {
		return Entry{}, fmt.Errorf("%w: an unanswered record outside a session; only a session call ends unanswered", ErrChain)
	}
	env, err := s.Sign(r)
	if err != nil {
		return Entry{}, err
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Request: reqBytes, Envelope: env}, nil
}

// Close signs a session-close statement.
func (s *Signer) Close(c SessionClose) (Entry, error) {
	st := closeStatement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "session", Digest: map[string]string{"sha256": c.Session}}},
		PredicateType: ClosePredicateType,
		Predicate:     c,
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Envelope: s.envelope(payload)}, nil
}

type closeStatement struct {
	Type          string       `json:"_type"`
	Subject       []Subject    `json:"subject"`
	PredicateType string       `json:"predicateType"`
	Predicate     SessionClose `json:"predicate"`
}

// VerifyClose checks a close envelope's signature and statement.
func (v *Verifier) VerifyClose(env Envelope) (SessionClose, error) {
	payload, err := v.signedPayload(env)
	if err != nil {
		return SessionClose{}, err
	}
	var st closeStatement
	if err := decodeStrict(payload, &st); err != nil {
		return SessionClose{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if st.Type != StatementType || st.PredicateType != ClosePredicateType || len(st.Subject) != 1 ||
		st.Subject[0].Name != "session" || st.Subject[0].Digest["sha256"] != st.Predicate.Session || len(st.Subject[0].Digest) != 1 {
		return SessionClose{}, fmt.Errorf("%w: not a session-close statement", ErrStatement)
	}
	return st.Predicate, nil
}

type closeNotCollectedStatement struct {
	Type          string                   `json:"_type"`
	Subject       []Subject                `json:"subject"`
	PredicateType string                   `json:"predicateType"`
	Predicate     SessionCloseNotCollected `json:"predicate"`
}

// CloseNotCollected signs the harness's statement that a session's close could not be
// collected. It refuses a statement VerifyCloseNotCollected would refuse.
func (s *Signer) CloseNotCollected(c SessionCloseNotCollected) (Entry, error) {
	if err := c.check(); err != nil {
		return Entry{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	payload, err := json.Marshal(closeNotCollectedStatement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "session", Digest: map[string]string{"sha256": c.Session}}},
		PredicateType: CloseNotCollectedPredicateType,
		Predicate:     c,
	})
	if err != nil {
		return Entry{}, err
	}
	return Entry{Envelope: s.envelope(payload)}, nil
}

// VerifyCloseNotCollected checks the envelope of a statement that a session's close could
// not be collected: the signature, the statement, and its fields (a closed set of reasons,
// a time, a count and last record that agree).
func (v *Verifier) VerifyCloseNotCollected(env Envelope) (SessionCloseNotCollected, error) {
	payload, err := v.signedPayload(env)
	if err != nil {
		return SessionCloseNotCollected{}, err
	}
	var st closeNotCollectedStatement
	if err := decodeStrict(payload, &st); err != nil {
		return SessionCloseNotCollected{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if st.Type != StatementType || st.PredicateType != CloseNotCollectedPredicateType || len(st.Subject) != 1 ||
		st.Subject[0].Name != "session" || len(st.Subject[0].Digest) != 1 || st.Subject[0].Digest["sha256"] != st.Predicate.Session {
		return SessionCloseNotCollected{}, fmt.Errorf("%w: not a statement that a session's close could not be collected", ErrStatement)
	}
	if err := st.Predicate.check(); err != nil {
		return SessionCloseNotCollected{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	return st.Predicate, nil
}

// statementNamespace prefixes every predicate type plimsoll defines.
const statementNamespace = "https://plimsollmark.github.io/plimsoll/"

// known are the predicate types a bundle line's envelope may carry that this release reads
// (a link's type included, which belongs in the link and is refused anywhere else).
var known = map[string]bool{PredicateType: true, ClosePredicateType: true, CloseNotCollectedPredicateType: true, LinkPredicateType: true}

// ErrUnknownStatement means a bundle line carries a statement this key signed whose
// predicate type is plimsoll's but not one this release reads as a bundle line. A later
// release may have written it, and then a newer verifier reads it. But plimsoll also
// signs statements with a harness key that are never bundle lines (SignStatement: the
// examples' own receipts, for one), so a key holder can put one of those in a line too,
// and no release will read it there. Either way the line is refused;
// only the bundle key's holder can reach this answer, since links are checked first.
var ErrUnknownStatement = errors.New("attest: the line holds a kind of plimsoll statement this release does not read as a bundle line: a newer release may have written it (upgrade the verifier); if none has, plimsoll writes no such line")

// unknownStatement refuses an envelope this verifier's key signed over a plimsoll
// predicate type it does not read as ErrUnknownStatement, and leaves every other envelope
// to the reading of its own type: one no signature of this key verifies stays a signature
// failure, never "upgrade".
func (v *Verifier) unknownStatement(env Envelope) error {
	pt := predicateType(env)
	if known[pt] || !strings.HasPrefix(pt, statementNamespace) {
		return nil
	}
	if _, err := v.signedPayload(env); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", ErrUnknownStatement, prefixed(pt, 120))
}

// isEnding reports whether an envelope carries a session's ending: a close or a statement
// that its close could not be collected.
func isEnding(env Envelope) bool {
	pt := predicateType(env)
	return pt == ClosePredicateType || pt == CloseNotCollectedPredicateType
}

// Ending is a session's ending line as VerifyEnding reads it: exactly one of Close (the
// daemon's count, which the harness signed) and NotCollected (the harness's own statement
// that the daemon gave none) is set.
type Ending struct {
	Close        *SessionClose
	NotCollected *SessionCloseNotCollected
}

// verifyEnding reads an ending envelope by its type.
func (v *Verifier) verifyEnding(env Envelope) (Ending, error) {
	if predicateType(env) == CloseNotCollectedPredicateType {
		n, err := v.VerifyCloseNotCollected(env)
		if err != nil {
			return Ending{}, err
		}
		return Ending{NotCollected: &n}, nil
	}
	c, err := v.VerifyClose(env)
	if err != nil {
		return Ending{}, err
	}
	return Ending{Close: &c}, nil
}

// VerifyEnding checks one session-ending line of a bundle on its own, as VerifyEntry
// checks a call line: the line's link (the harness's signature over this line's content at
// the place its Index states) and the statement. What it cannot check is the bundle: that
// the session's chain before it is whole and that its count is that chain's are
// VerifyBundle's.
func VerifyEnding(v *Verifier, e Entry) (Ending, Link, error) {
	if e.Link == nil {
		return Ending{}, Link{}, fmt.Errorf("%w: the line has no link", ErrLink)
	}
	l, err := v.VerifyLink(*e.Link)
	if err != nil {
		return Ending{}, Link{}, err
	}
	if l.Checkpoint || l.Lines != 0 || l.Index == 0 || l.Entry != ContentDigest(e) {
		return Ending{}, Link{}, fmt.Errorf("%w: the line's link signs other content", ErrLink)
	}
	if e.Request != nil || e.Response != nil || !isEnding(e.Envelope) {
		if err := v.unknownStatement(e.Envelope); err != nil {
			return Ending{}, Link{}, err
		}
		return Ending{}, Link{}, fmt.Errorf("%w: the line is not a session's ending", ErrStatement)
	}
	end, err := v.verifyEnding(e.Envelope)
	if err != nil {
		return Ending{}, Link{}, err
	}
	return end, l, nil
}

// predicateType reads which statement an envelope carries, before verifying it.
func predicateType(env Envelope) string {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return ""
	}
	var st struct {
		PredicateType string `json:"predicateType"`
	}
	if json.Unmarshal(payload, &st) != nil {
		return ""
	}
	return st.PredicateType
}

// Report summarizes a verified bundle.
type Report struct {
	Runs     int             // single runs
	Sessions []SessionReport // in order of first appearance
}

// SessionReport is one verified session chain.
type SessionReport struct {
	Session string // fingerprint
	Calls   int
	// Closed: the session ends in the daemon's close, whose count of calls and last record
	// are the chain's. Not closed, it ends in the harness's statement that its close could
	// not be collected (NotCollected): it is NOT PROVEN COMPLETE. Its lines are the
	// harness's and in order, none removed, but calls the client did not see (another
	// holder of the session ID, or the worker that took it over) would not show, since
	// only the daemon's count shows those.
	Closed       bool
	NotCollected *SessionCloseNotCollected
}

// ErrNotProvenComplete means a verified bundle holds a session that ends in the
// harness's statement that its close could not be collected, where the daemon's count of
// the session's calls is required (Report.Complete, plimsoll-attest verify -require-close).
var ErrNotProvenComplete = errors.New("attest: a session is not proven complete: its close could not be collected, so the daemon's count of its calls is unknown")

// Complete returns nil when every session of the report ends in the daemon's close, and
// otherwise ErrNotProvenComplete naming each session that does not: the check for a
// reader who needs the daemon's count of every session's calls, which VerifyBundle
// requires unless it is given AcceptNotProvenComplete.
func (r Report) Complete() error {
	var open []string
	for _, s := range r.Sessions {
		if !s.Closed {
			open = append(open, prefixed(s.Session, 12)) // prefixed marks the cut with "..."
		}
	}
	if len(open) > 0 {
		return fmt.Errorf("%w: sessions %v", ErrNotProvenComplete, open)
	}
	return nil
}

// VerifyBundle checks the bundle's chain of links (every line where the harness put
// it, ending with a checkpoint: verifyLinks) and every entry: each signature, each
// record against the stored request and response it came with, and each session's
// chain (calls
// numbered from 1 without a gap, each naming the record before it, ending in a
// close statement whose count and last record match). A chain without a close
// statement fails: its tail cannot be told from a cut one. A session that ran no
// call is its close statement alone, with a count of zero and no last record.
//
// The harness's statement that a session's close could not be collected
// (SessionCloseNotCollected) also ends a session, under the same rules (its count of the
// calls the client saw and its last record must be the chain's). Such a session is not
// proven complete, and by default VerifyBundle refuses the bundle with
// ErrNotProvenComplete, returning the report beside the error, so a caller that reads only
// the error never takes such a session for a closed one. A caller that accepts the weaker
// ending passes AcceptNotProvenComplete, as plimsoll-attest verify does, and gets the
// session reported as not Closed. A session with neither ending always fails.
func VerifyBundle(entries []Entry, v *Verifier, opts ...VerifyOption) (Report, error) {
	rep, _, err := verifyEntries(entries, v)
	if err != nil {
		return Report{}, err
	}
	if !slices.Contains(opts, AcceptNotProvenComplete) {
		if err := rep.Complete(); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// VerifyOption changes what VerifyBundle and VerifyExpected accept.
type VerifyOption int

// AcceptNotProvenComplete accepts a session that ends in the harness's statement that its
// close could not be collected, reported as not Closed (SessionReport.NotCollected says
// why): its calls are the session's first ones, none between them, but the daemon's count
// is unknown, so the daemon may have run more after the last. The caller that passes it
// must say so where it reports the session, as plimsoll-attest verify does ("NOT PROVEN
// COMPLETE").
const AcceptNotProvenComplete VerifyOption = 1

// VerifyEntry checks one call line of a bundle on its own, for a holder of the line
// without the bundle around it: the record's signature; the stored request and
// response against the signed record, as VerifyBundle checks every line; and the
// line's link, which must be the harness's signature over this line's content at the
// place its Index states. It returns the record and that link. What it cannot check is
// the bundle itself: that the line is in the bundle its holder names, that the chain
// around it is whole, and (for a session's call) where it stands in its session's
// chain, are VerifyBundle's.
func VerifyEntry(v *Verifier, e Entry) (sandbox.RunRecord, Link, error) {
	if e.Link == nil {
		return sandbox.RunRecord{}, Link{}, fmt.Errorf("%w: the line has no link", ErrLink)
	}
	l, err := v.VerifyLink(*e.Link)
	if err != nil {
		return sandbox.RunRecord{}, Link{}, err
	}
	if l.Checkpoint || l.Lines != 0 || l.Index == 0 || l.Entry != ContentDigest(e) {
		return sandbox.RunRecord{}, Link{}, fmt.Errorf("%w: the line's link signs other content", ErrLink)
	}
	if err := v.unknownStatement(e.Envelope); err != nil {
		return sandbox.RunRecord{}, Link{}, err
	}
	rec, err := v.Verify(e.Envelope)
	if err != nil {
		return sandbox.RunRecord{}, Link{}, err
	}
	if err := matchStored(e, rec); err != nil {
		return sandbox.RunRecord{}, Link{}, err
	}
	// What one line shows of the chain rules, it is held to, as VerifyBundle holds it.
	if rec.Session == "" && (rec.Unanswered != "" || rec.Sequence != 0 || rec.PreviousSHA256 != "") {
		return sandbox.RunRecord{}, Link{}, fmt.Errorf("%w: a single run's record that is unanswered or carries chain fields", ErrChain)
	}
	return rec, l, nil
}

// VerifyCall verifies a call line's statement and its record against the stored request
// and response alone, with no link and no bundle around it: what a line from before
// links (v0.10.0 to v0.17.x) can prove, and what VerifyEntry proves of a linked line
// before its link. It authenticates the recorded exchange, not where the line stands:
// a holder can drop or reorder such lines unseen, which is why ReadBundle refuses a
// bundle of them whole. plimsoll-attest verify-record is its command (review,
// 2026-10-26).
func VerifyCall(v *Verifier, e Entry) (sandbox.RunRecord, error) {
	if len(e.Request) == 0 && len(e.Response) == 0 {
		return sandbox.RunRecord{}, fmt.Errorf("%w: the line holds no call", ErrStatement)
	}
	rec, err := v.Verify(e.Envelope)
	if err != nil {
		return sandbox.RunRecord{}, err
	}
	if err := matchStored(e, rec); err != nil {
		return sandbox.RunRecord{}, err
	}
	return rec, nil
}

// verifyEntries is VerifyBundle, also returning each call entry's signed record by
// index (the zero record for a close statement), so a replay reads its baseline from
// what was signed rather than from the stored response.
func verifyEntries(entries []Entry, v *Verifier) (Report, []sandbox.RunRecord, error) {
	type chain struct {
		calls  uint64
		last   string
		closed bool
		index  int
	}
	checkpoint, err := verifyLinks(entries, v)
	if err != nil {
		return Report{}, nil, err
	}
	var rep Report
	recs := make([]sandbox.RunRecord, len(entries))
	chains := map[string]*chain{}
	for i, e := range entries {
		fail := func(err error) (Report, []sandbox.RunRecord, error) {
			return Report{}, nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		if checkpoint[i] {
			continue
		}
		if isEnding(e.Envelope) {
			// An ending is its envelope alone, as VerifyEnding holds one line to: stored
			// messages beside it would be read as a call by CountCalls and the -expect check.
			if e.Request != nil || e.Response != nil {
				return fail(fmt.Errorf("%w: a session's ending line stores a request or a response", ErrStatement))
			}
			end, err := v.verifyEnding(e.Envelope)
			if err != nil {
				return fail(err)
			}
			// A daemon's close and the harness's statement that none could be collected
			// end a session under one rule: the count and last record are the chain's.
			session, calls, last, how := "", uint64(0), "", "closed"
			if end.Close != nil {
				session, calls, last = end.Close.Session, end.Close.Calls, end.Close.LastRecordSHA256
			} else {
				session, calls, last = end.NotCollected.Session, end.NotCollected.CallsSeen, end.NotCollected.LastRecordSHA256
				how = "ended with its close not collected"
			}
			ch := chains[session]
			if ch == nil {
				// A session that ran no call has no chain before its ending: valid
				// only if the ending says so. A count or a last record here means
				// the bundle lost the session's calls.
				if calls != 0 || last != "" {
					return fail(fmt.Errorf("%w: session %s %s after %d calls ending %s, the bundle holds none",
						ErrChain, session, how, calls, last))
				}
				ch = &chain{index: len(rep.Sessions)}
				chains[session] = ch
				rep.Sessions = append(rep.Sessions, SessionReport{Session: session})
			} else {
				switch {
				case ch.closed:
					return fail(fmt.Errorf("%w: a second ending for session %s", ErrChain, session))
				case calls != ch.calls || last != ch.last:
					return fail(fmt.Errorf("%w: session %s %s after %d calls ending %s, the bundle holds %d ending %s",
						ErrChain, session, how, calls, last, ch.calls, ch.last))
				}
			}
			ch.closed = true
			rep.Sessions[ch.index].Closed = end.Close != nil
			rep.Sessions[ch.index].NotCollected = end.NotCollected
			continue
		}
		if err := v.unknownStatement(e.Envelope); err != nil {
			return fail(err)
		}
		rec, err := v.Verify(e.Envelope)
		if err != nil {
			return fail(err)
		}
		if err := matchStored(e, rec); err != nil {
			return fail(err)
		}
		recs[i] = rec
		if rec.Unanswered != "" && rec.Session == "" {
			return fail(fmt.Errorf("%w: an unanswered record outside a session", ErrChain))
		}
		if rec.Session == "" {
			if rec.Sequence != 0 || rec.PreviousSHA256 != "" {
				return fail(fmt.Errorf("%w: a single run's record carries chain fields", ErrChain))
			}
			rep.Runs++
			continue
		}
		ch := chains[rec.Session]
		if ch == nil {
			ch = &chain{index: len(rep.Sessions)}
			chains[rec.Session] = ch
			rep.Sessions = append(rep.Sessions, SessionReport{Session: rec.Session})
		}
		switch {
		case ch.closed:
			return fail(fmt.Errorf("%w: a call after session %s ended", ErrChain, rec.Session))
		case rec.Sequence != ch.calls+1:
			return fail(fmt.Errorf("%w: session %s call %d follows call %d", ErrChain, rec.Session, rec.Sequence, ch.calls))
		case rec.PreviousSHA256 != ch.last:
			return fail(fmt.Errorf("%w: session %s call %d names previous %q, the bundle's is %q", ErrChain, rec.Session, rec.Sequence, rec.PreviousSHA256, ch.last))
		}
		ch.calls, ch.last = rec.Sequence, rec.SHA256
		rep.Sessions[ch.index].Calls = int(rec.Sequence)
	}
	for _, s := range rep.Sessions {
		if !chains[s.Session].closed {
			return Report{}, nil, fmt.Errorf("%w: session %s has no close statement, nor the harness's statement that its close could not be collected, so its last calls could have been cut", ErrChain, s.Session)
		}
	}
	return rep, recs, nil
}

// ErrChain means a session's calls do not form an unbroken, closed chain.
var ErrChain = errors.New("attest: broken session chain")

// ErrStored means a stored request or response does not match the signed record.
var ErrStored = errors.New("attest: the stored request or response does not match the signed record")

func matchStored(e Entry, rec sandbox.RunRecord) error {
	if rec.Unanswered != "" {
		// An unanswered call stored its request and no response: the same check the
		// signer and the live client ran.
		if len(e.Response) != 0 {
			return fmt.Errorf("%w: an unanswered call's entry stores a response", ErrStored)
		}
		req := &plimsollv1.RunRequest{}
		if err := proto.Unmarshal(e.Request, req); err != nil {
			return fmt.Errorf("%w: request: %v", ErrStored, err)
		}
		if err := record.CheckUnansweredExchange(req, rec); err != nil {
			return fmt.Errorf("%w: %w", ErrStored, err)
		}
		return nil
	}
	req, resp, err := e.Messages()
	if err != nil {
		return err
	}
	// The same check the signer ran and the live client runs: the digests, the
	// evidence, the environment and selected software the response states, and the
	// request's software rule. Anything less accepts a stored exchange the client
	// would have refused.
	if _, err := record.CheckExchange(req, resp); err != nil {
		return fmt.Errorf("%w: %w", ErrStored, err)
	}
	// The stored response carries its own copy of the record. Every field of it must
	// be the signed record's, not only its digest field: a reader of the bundle, and
	// any tool built on the stored response, would otherwise trust unsigned values. Both
	// copies have passed the check of their own digest against their fields (CheckExchange
	// above, Verify before), and the digest's domain names the version, so equal versions
	// and equal digests are every field equal.
	stored := record.FromWire(resp.GetRecord())
	if stored.Version != rec.Version || stored.SHA256 != rec.SHA256 {
		return fmt.Errorf("%w: the response's own record", ErrStored)
	}
	return nil
}

// Messages decodes a call entry's stored request and response.
func (e Entry) Messages() (*plimsollv1.RunRequest, *plimsollv1.RunResponse, error) {
	req, resp := &plimsollv1.RunRequest{}, &plimsollv1.RunResponse{}
	if err := proto.Unmarshal(e.Request, req); err != nil {
		return nil, nil, fmt.Errorf("%w: request: %v", ErrStored, err)
	}
	if err := proto.Unmarshal(e.Response, resp); err != nil {
		return nil, nil, fmt.Errorf("%w: response: %v", ErrStored, err)
	}
	return req, resp, nil
}

// ReadBundle reads a bundle: one JSON entry per line.
func ReadBundle(r io.Reader) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), MaxLineBytes)
	sc.Split(splitLines)
	for n := 1; sc.Scan(); n++ {
		line := sc.Bytes()
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("bundle line %d: %w", n, err)
		}
		// A line is exactly the harness's encoding of its entry: so the digests the
		// links state are over the stored bytes, and no reader can find more in a line
		// (trailing data, a repeated key, a key in another case, whitespace, an escape,
		// a blank line) than Go's decoder does.
		canonical, err := json.Marshal(e)
		if err != nil || !bytes.Equal(canonical, line) {
			return nil, fmt.Errorf("bundle line %d: %w", n, ErrLine)
		}
		// Every line the harness writes carries its signed link, and verification
		// refuses a line without one, so it is refused here, as it is read: a file of
		// empty entries ("{}" lines) would otherwise be kept whole before verification
		// began, each costing far more memory than its three bytes. With a link required,
		// what is kept grows with the file's own size.
		if e.Link == nil {
			return nil, fmt.Errorf("bundle line %d: %w: the line has no link", n, ErrLink)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// MaxLineBytes bounds a bundle line, newline included: ReadBundle reads no longer one,
// and WriteEntry writes none. It rests on the two message caps: a call line holds the
// request (plimsolld accepts at most 8 MiB, maxRequestBytes in cmd/plimsolld) and the
// response (the client accepts at most client.MaxResponseBytes, 32 MiB), each in base64,
// about 53.3 MiB together, which leaves about 10.6 MiB for the record's envelope, the
// link and the JSON around them. TestMaxLineBytesHoldsTheLargestExchange fails when
// either cap grows past what this holds.
const MaxLineBytes = 64 << 20

// splitLines splits at each newline exactly as written: a carriage return stays in the
// line (and fails it), and a last line without its newline is refused, since the next
// append would run into it.
func splitLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return 0, nil, fmt.Errorf("%w: the last line has no newline", ErrLine)
	}
	return 0, nil, nil
}

// ErrLine means a bundle line is not exactly the harness's encoding of an entry.
var ErrLine = errors.New("attest: the line is not exactly the harness's encoding of its entry (whitespace, a key's case, a repeated key, an escape or trailing data)")

// ErrLineTooLong means an entry's line would be longer than MaxLineBytes. WriteEntry
// refuses it before writing anything, so the bundle is as it was.
var ErrLineTooLong = errors.New("attest: the entry is longer than a bundle line may be")

// writeLimit is MaxLineBytes, the longest line WriteEntry writes; a variable only so a
// test can reach the refusal without building a 64 MiB line.
var writeLimit = MaxLineBytes

// WriteEntry appends one entry to a bundle. An entry whose line would pass MaxLineBytes
// is ErrLineTooLong, and nothing is written.
func WriteEntry(w io.Writer, e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b)+1 > writeLimit {
		return fmt.Errorf("%w: its line would be %d bytes, past the %d a bundle line may hold; nothing was written", ErrLineTooLong, len(b)+1, writeLimit)
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// Replayed is one recorded call sent again.
type Replayed struct {
	Entry    int    // 1-based index in the bundle
	Session  string // the recorded session's fingerprint; "" for a single run
	Recorded string // the signed result digest
	Replayed string // the new run's result digest; "" when it failed
	Err      error  // the new run's error, if any
	// Unanswered is the recorded call's error code when it ended without a result
	// (an unanswered record): there is no recorded result, so it never matches.
	Unanswered string
}

// Match reports whether the new run reproduced the recorded result.
func (r Replayed) Match() bool { return r.Err == nil && r.Unanswered == "" && r.Replayed == r.Recorded }

// Replay sends every single run in a bundle again through send and compares
// result digests. It is meaningful for deterministic workloads (the physics
// oracle's trajectory is one); a workload that reads the clock or random
// numbers differs by design. Session calls are skipped: replaying them needs a
// fresh session and the calls in order. The bundle is verified with v first (as
// VerifyBundle does, a session not proven complete accepted: a replay re-runs what the
// bundle holds and claims nothing of what it lacks) and nothing is sent unless it
// verifies; each baseline is the signed record's result digest.
func Replay(ctx context.Context, entries []Entry, v *Verifier, opts ReplayOptions, send func(context.Context, *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error)) ([]Replayed, error) {
	_, recs, err := verifyEntries(entries, v)
	if err != nil {
		return nil, err
	}
	var out []Replayed
	for i, e := range entries {
		if e.Envelope.Payload == "" || isEnding(e.Envelope) || recs[i].Session != "" {
			continue // a checkpoint, a session's ending, a session call
		}
		req, _, err := e.Messages()
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		r := Replayed{Entry: i + 1, Recorded: recs[i].ResultSHA256}
		if skip := notReplayable(req, opts); skip != nil {
			r.Err = skip
			out = append(out, r)
			continue
		}
		got, err := send(ctx, req)
		if err != nil {
			r.Err = err
		} else {
			r.Replayed = record.ResultDigest(got)
		}
		out = append(out, r)
	}
	return out, nil
}

// ReplayOptions says what a replay may send again. A recorded request that carries a
// grant profile reaches the upstream API again when sent, with a fresh route budget,
// so it is not replayed unless WithGrants; a request recorded under another protocol
// number is never replayed, since the fields that number governs may run differently
// now. Both used to be sent as stored (review, 2026-10-26).
type ReplayOptions struct {
	WithGrants bool
}

// ErrNotReplayable marks a recorded request the replay did not send; the Replayed's
// Err says why.
var ErrNotReplayable = errors.New("attest: the recorded request was not replayed")

func notReplayable(req *plimsollv1.RunRequest, opts ReplayOptions) error {
	profile := req.GetJavascript().GetGrantProfile()
	if profile == "" {
		profile = req.GetProject().GetGrantProfile()
	}
	switch {
	case req.GetProtocol() != protocol.Number:
		return fmt.Errorf("%w: recorded under protocol %d, and this replay speaks %d", ErrNotReplayable, req.GetProtocol(), protocol.Number)
	case profile != "" && !opts.WithGrants:
		return fmt.Errorf("%w: it carries grant profile %q, which would call the upstream API again (allow grants to send it)", ErrNotReplayable, profile)
	}
	return nil
}

// SessionSender is a fresh session that a replay sends a recorded session's calls
// into, as their stored Run requests.
type SessionSender interface {
	Send(ctx context.Context, req *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error)
	Close(ctx context.Context) error
}

// ReplaySessions replays each session in a bundle into a fresh session from open,
// its calls in their recorded order, and compares result digests call by call. A
// session's later calls read what its earlier calls wrote, so only a whole session
// replays; a deterministic session reproduces every call. The bundle is verified
// with v first, as in Replay.
func ReplaySessions(ctx context.Context, entries []Entry, v *Verifier, opts ReplayOptions, open func(context.Context) (SessionSender, error)) ([]Replayed, error) {
	_, recs, err := verifyEntries(entries, v)
	if err != nil {
		return nil, err
	}
	var order []string
	calls := map[string][]int{}
	for i, e := range entries {
		fp := recs[i].Session
		if e.Envelope.Payload == "" || isEnding(e.Envelope) || fp == "" {
			continue
		}
		if _, seen := calls[fp]; !seen {
			order = append(order, fp)
		}
		calls[fp] = append(calls[fp], i)
	}
	var out []Replayed
	for _, fp := range order {
		// A session replays whole, so one call that may not be sent keeps the session
		// unopened and marks every call of it.
		var openErr error
		for _, i := range calls[fp] {
			req, _, _ := entries[i].Messages()
			if openErr = notReplayable(req, opts); openErr != nil {
				break
			}
		}
		var sender SessionSender
		if openErr == nil {
			sender, openErr = open(ctx)
		}
		for _, i := range calls[fp] {
			req, _, _ := entries[i].Messages()
			r := Replayed{Entry: i + 1, Session: fp, Recorded: recs[i].ResultSHA256, Unanswered: recs[i].Unanswered}
			switch {
			case openErr != nil:
				r.Err = openErr
			default:
				got, err := sender.Send(ctx, req)
				if err != nil {
					r.Err = err
				} else {
					r.Replayed = record.ResultDigest(got)
				}
			}
			out = append(out, r)
		}
		if openErr == nil {
			_ = sender.Close(ctx)
		}
	}
	return out, nil
}

// Harness signs every exchange it is given and appends it to a bundle, each line
// linked to the one before it; Checkpoint ends what it wrote. It is a
// client.Recorder: client.New(url, client.WithRecorder(h)) signs every run the
// client makes. Safe for concurrent use.
type Harness struct {
	mu     sync.Mutex
	signer *Signer
	w      io.Writer
	lines  uint64 // lines in the bundle so far
	prev   string // LineDigest of the last
	err    error  // a failed write: the bundle may hold a partial line, so nothing more is appended
	// ended holds the sessions whose ending (a close, or the statement that none could be
	// collected) is in the bundle, so a second one is refused before it is written.
	ended map[string]bool
}

// harnessNow is the harness's clock, which a statement that a session's close could not
// be collected states; a variable so a test can fix it.
var harnessNow = time.Now

// NewHarness returns a Harness that signs with s and writes a new bundle to w.
func NewHarness(s *Signer, w io.Writer) *Harness {
	return &Harness{signer: s, w: w, ended: map[string]bool{}}
}

// ResumeHarness returns a Harness that appends to the bundle whose lines are
// existing, writing to w: it refuses unless existing verifies under the signer's own
// key and ends with a checkpoint, so it never extends a bundle it cannot prove whole.
// An empty existing starts a new bundle.
func ResumeHarness(s *Signer, existing []Entry, w io.Writer) (*Harness, error) {
	h := NewHarness(s, w)
	if len(existing) == 0 {
		return h, nil
	}
	// A session not proven complete has ended, as a closed one has: the bundle is whole, so
	// it can be continued, and the harness writes no second ending for it.
	rep, err := VerifyBundle(existing, NewVerifier(s.key.Public().(ed25519.PublicKey)), AcceptNotProvenComplete)
	if err != nil {
		return nil, fmt.Errorf("attest: will not append to a bundle that does not verify: %w", err)
	}
	// A verified bundle has an ending for every session in it.
	for _, sr := range rep.Sessions {
		h.ended[sr.Session] = true
	}
	h.lines, h.prev = uint64(len(existing)), LineDigest(existing[len(existing)-1])
	return h, nil
}

// write links e as the bundle's next line, signs the link and writes the line.
func (h *Harness) write(e Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.writeLocked(e)
}

// writeEnding writes e, a session's ending, unless the bundle already holds one for the
// session: VerifyBundle refuses a second, so it would leave a bundle that never verifies.
func (h *Harness) writeEnding(session string, e Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ended[session] {
		return fmt.Errorf("%w: session %s already has its ending in this bundle; nothing was written", ErrChain, session)
	}
	if err := h.writeLocked(e); err != nil {
		return err
	}
	h.ended[session] = true
	return nil
}

// writeLocked is write, with h.mu held.
func (h *Harness) writeLocked(e Entry) error {
	if h.err != nil {
		return h.err
	}
	link, err := h.signer.signLink(Link{Index: h.lines + 1, Previous: h.prev, Entry: ContentDigest(e)})
	if err != nil {
		return err
	}
	e.Link = &link
	if err := WriteEntry(h.w, e); err != nil {
		if errors.Is(err, ErrLineTooLong) {
			return err // nothing was written: the bundle and this harness are as they were
		}
		h.err = fmt.Errorf("attest: a write failed and the bundle may hold a partial line, so this harness appends nothing more: %w", err)
		return h.err
	}
	h.lines, h.prev = h.lines+1, LineDigest(e)
	return nil
}

// Checkpoint writes a checkpoint: a link stating how many lines come before it. A
// bundle verifies only when its last line is one, so call it when the harness is
// done; writing more after it is fine, and a later checkpoint covers them.
func (h *Harness) Checkpoint() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return h.err
	}
	link, err := h.signer.signLink(Link{Index: h.lines + 1, Previous: h.prev, Checkpoint: true, Lines: h.lines})
	if err != nil {
		return err
	}
	e := Entry{Link: &link}
	if err := WriteEntry(h.w, e); err != nil {
		h.err = fmt.Errorf("attest: a write failed and the bundle may hold a partial line, so this harness appends nothing more: %w", err)
		return h.err
	}
	h.lines, h.prev = h.lines+1, LineDigest(e)
	return nil
}

// Record checks the exchange's record, signs it and writes the entry.
func (h *Harness) Record(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) error {
	e, err := h.signer.Call(req, resp)
	if err != nil {
		return err
	}
	return h.write(e)
}

// RecordUnanswered signs the record of a session call that may have run but ended
// in an error, and writes it. With it, Harness is a client.UnansweredRecorder.
func (h *Harness) RecordUnanswered(req *plimsollv1.RunRequest, rec *plimsollv1.RunRecord) error {
	e, err := h.signer.Unanswered(req, rec)
	if err != nil {
		return err
	}
	return h.write(e)
}

// RecordClose signs a session's close, as the daemon stated it, and writes it.
// With it, Harness is a client.SessionRecorder.
func (h *Harness) RecordClose(session string, calls uint64, lastRecordSHA256 string) error {
	e, err := h.signer.Close(SessionClose{Session: session, Calls: calls, LastRecordSHA256: lastRecordSHA256})
	if err != nil {
		return err
	}
	return h.writeEnding(session, e)
}

// RecordCloseNotCollected signs the harness's own statement that a session's close could
// not be collected, for reason (CloseNotCollectedNotFound or CloseNotCollectedStaleOwner),
// after callsSeen calls the client saw ending in lastRecordSHA256 and, when
// unansweredRequestSHA256 is not "", one more call it sent with that request digest and
// got no answer for, and writes it. It ends the session in the bundle, which verifies with
// that session reported as not proven complete. With it, Harness is a
// client.CloseNotCollectedRecorder.
func (h *Harness) RecordCloseNotCollected(session string, callsSeen uint64, lastRecordSHA256, unansweredRequestSHA256, reason string) error {
	e, err := h.signer.CloseNotCollected(SessionCloseNotCollected{
		Session: session, CallsSeen: callsSeen, LastRecordSHA256: lastRecordSHA256, UnansweredRequestSHA256: unansweredRequestSHA256,
		Reason: reason, NotedUnixMs: harnessNow().UnixMilli(),
	})
	if err != nil {
		return err
	}
	return h.writeEnding(session, e)
}

// Expected is the caller's own record of the calls it made through a harness, from its own
// log, for VerifyExpected. Each digest is a request digest (RunRecord.RequestSHA256, which
// the client checked against what it sent), in any order.
type Expected struct {
	// Requests are the calls that returned a record, an unanswered session call's
	// included (a call whose line ended without a result; a refused call leaves none).
	// The bundle must hold exactly these call lines, each as many times as listed.
	Requests []string
	// Unanswered are the calls the client sent and got no answer for, so no record and
	// no line: each must be named, as many times, by a session's statement that its
	// close could not be collected (Report.Unanswered). A statement's call left out here
	// is reported (Report.Unanswered) and required of nothing, and it never stands in
	// for a line of Requests.
	Unanswered []string
}

// VerifyExpected verifies the bundle with v, as VerifyBundle does, and returns its report
// only when it also holds the caller's own record of what it ran. It verifies first
// itself, so no caller can hold the counts of lines no signature checked against its
// list (hunt-quality-24). A call it lacks, a call it holds without being expected, and a
// call whose request is not the one the caller sent all fail. Two calls with one digest
// sent the same request (record.RunRequestDigest leaves out only the trace_id), so
// counting them is exact and nothing has to be unique. It proves the harness was handed
// every such call, as well as the caller's log does; the links prove only that the file
// is what the harness wrote. It binds what was sent, not what came back.
//
// A call sent with no answer is matched only against the statements, and a call that
// returned a record only against the lines, so the comparison stays exact: a statement
// naming a call never makes up for a line cut from the bundle, as it did when a listed
// digest could be matched by either (the security scan of 2026-11-20, F9 and F10: the answered retry of a call whose
// answer was lost, cut off with the bundle's tail, went unnoticed). Like VerifyBundle, it
// refuses a session not proven complete unless given AcceptNotProvenComplete.
func VerifyExpected(entries []Entry, v *Verifier, want Expected, opts ...VerifyOption) (Report, error) {
	rep, err := VerifyBundle(entries, v, opts...)
	if err != nil {
		return Report{}, err
	}
	if err := expected(entries, want, rep.Unanswered()); err != nil {
		return Report{}, err
	}
	return rep, nil
}

// Unanswered returns the request digests of the calls the bundle's sessions sent and got
// no answer for, each named by its session's statement that the close could not be
// collected (at most one a session), in the order of the sessions. Such a call is in no
// line of the bundle; it may have run.
func (r Report) Unanswered() []string {
	var out []string
	for _, s := range r.Sessions {
		if s.NotCollected != nil && s.NotCollected.UnansweredRequestSHA256 != "" {
			out = append(out, s.NotCollected.UnansweredRequestSHA256)
		}
	}
	return out
}

// digestCounts counts each request digest in ds, refusing one that is no digest.
func digestCounts(ds []string) (map[string]int, error) {
	n := map[string]int{}
	for _, d := range ds {
		if !isSHA256Hex(d) {
			return nil, fmt.Errorf("%w: %q is not a request digest (64 lowercase hex characters)", ErrExpected, prefixed(d, 80))
		}
		n[d]++
	}
	return n, nil
}

// expected is VerifyExpected's comparison, over entries VerifyBundle has verified. stated
// are the digests the bundle's statements name as sent with no answer (Report.Unanswered).
func expected(entries []Entry, list Expected, stated []string) error {
	want, err := digestCounts(list.Requests)
	if err != nil {
		return err
	}
	sentUnanswered, err := digestCounts(list.Unanswered)
	if err != nil {
		return err
	}
	statedN := map[string]int{}
	for _, d := range stated {
		statedN[d]++
	}
	got := map[string]int{}
	trace := map[string]string{} // a digest's trace_id in the bundle, to name it in a message
	for i, e := range entries {
		if e.Request == nil {
			continue // a checkpoint or a close
		}
		req := &plimsollv1.RunRequest{}
		if err := proto.Unmarshal(e.Request, req); err != nil {
			return fmt.Errorf("entry %d: %w: request: %v", i+1, ErrStored, err)
		}
		d := record.RunRequestDigest(req)
		got[d]++
		if id := req.GetTraceId(); id != "" {
			trace[d] = id
		}
	}
	var missing, extra, unstated []string
	name := func(d string, n int) string {
		s := d[:16]
		if id := trace[d]; id != "" {
			s += fmt.Sprintf(" (trace_id %q)", id)
		}
		if n > 1 {
			s += fmt.Sprintf(" x%d", n)
		}
		return s
	}
	for d, n := range want {
		if short := n - got[d]; short > 0 {
			s := name(d, short)
			if statedN[d] > 0 {
				// The caller may have listed a call that got no answer as one that returned
				// a record; the statement is no line, so it is still missing, and says why.
				s += " (a session's statement names it as sent with no answer, which is no line: list such a call as unanswered)"
			}
			missing = append(missing, s)
		}
	}
	for d, n := range got {
		if want[d] < n {
			extra = append(extra, name(d, n-want[d]))
		}
	}
	for d, n := range sentUnanswered {
		if short := n - statedN[d]; short > 0 {
			unstated = append(unstated, name(d, short))
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	slices.Sort(unstated)
	switch {
	case len(unstated) > 0:
		return fmt.Errorf("%w: requests missing %v, not expected %v, listed as sent with no answer but named so by no session's statement %v", ErrExpected, missing, extra, unstated)
	case len(missing) > 0 || len(extra) > 0:
		return fmt.Errorf("%w: requests missing %v, not expected %v", ErrExpected, missing, extra)
	}
	return nil
}

// isSHA256Hex reports whether s is a SHA-256 digest as the records write it.
func isSHA256Hex(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// prefixed cuts s to at most n bytes for an error message.
func prefixed(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// CountCalls is how many calls a bundle records: single runs and session calls,
// answered or not.
func CountCalls(entries []Entry) int {
	n := 0
	for _, e := range entries {
		if e.Request != nil {
			n++
		}
	}
	return n
}

// ErrExpected means a bundle's calls are not the ones the caller says it made.
var ErrExpected = errors.New("attest: the bundle's calls are not the caller's")
