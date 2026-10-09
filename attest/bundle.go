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
	"io"
	"slices"
	"sync"

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
	sig := ed25519.Sign(s.key, PAE(PayloadType, payload))
	return Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: s.keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// VerifyLink checks a link envelope's signature and statement.
func (v *Verifier) VerifyLink(env Envelope) (Link, error) {
	payload, err := v.signedPayload(env)
	if err != nil {
		return Link{}, err
	}
	var st linkStatement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
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
// response. Its place in the chain is VerifyBundle's to check, as for Call.
func (s *Signer) Unanswered(req *plimsollv1.RunRequest, rec *plimsollv1.RunRecord) (Entry, error) {
	r := record.FromWire(rec)
	if err := record.CheckUnansweredExchange(req, r); err != nil {
		return Entry{}, err
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
	sig := ed25519.Sign(s.key, PAE(PayloadType, payload))
	return Entry{Envelope: Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: s.keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}}, nil
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
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return SessionClose{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if st.Type != StatementType || st.PredicateType != ClosePredicateType || len(st.Subject) != 1 ||
		st.Subject[0].Name != "session" || st.Subject[0].Digest["sha256"] != st.Predicate.Session || len(st.Subject[0].Digest) != 1 {
		return SessionClose{}, fmt.Errorf("%w: not a session-close statement", ErrStatement)
	}
	return st.Predicate, nil
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
}

// VerifyBundle checks the bundle's chain of links (every line where the harness put
// it, ending with a checkpoint: verifyLinks) and every entry: each signature, each
// record against the stored request and response it came with, and each session's
// chain (calls
// numbered from 1 without a gap, each naming the record before it, ending in a
// close statement whose count and last record match). A chain without a close
// statement fails: its tail cannot be told from a cut one. A session that ran no
// call is its close statement alone, with a count of zero and no last record.
func VerifyBundle(entries []Entry, v *Verifier) (Report, error) {
	rep, _, err := verifyEntries(entries, v)
	return rep, err
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
		if predicateType(e.Envelope) == ClosePredicateType {
			c, err := v.VerifyClose(e.Envelope)
			if err != nil {
				return fail(err)
			}
			ch := chains[c.Session]
			if ch == nil {
				// A session that ran no call has no chain before its close: valid
				// only if the close says so. A count or a last record here means
				// the bundle lost the session's calls.
				if c.Calls != 0 || c.LastRecordSHA256 != "" {
					return fail(fmt.Errorf("%w: session %s closed after %d calls ending %s, the bundle holds none",
						ErrChain, c.Session, c.Calls, c.LastRecordSHA256))
				}
				chains[c.Session] = &chain{closed: true, index: len(rep.Sessions)}
				rep.Sessions = append(rep.Sessions, SessionReport{Session: c.Session})
				continue
			}
			switch {
			case ch.closed:
				return fail(fmt.Errorf("%w: a second close for session %s", ErrChain, c.Session))
			case c.Calls != ch.calls || c.LastRecordSHA256 != ch.last:
				return fail(fmt.Errorf("%w: session %s closed after %d calls ending %s, the bundle holds %d ending %s",
					ErrChain, c.Session, c.Calls, c.LastRecordSHA256, ch.calls, ch.last))
			}
			ch.closed = true
			continue
		}
		rec, err := v.Verify(e.Envelope)
		if err != nil {
			return fail(err)
		}
		if err := matchStored(e, rec); err != nil {
			return fail(err)
		}
		recs[i] = rec
		if rec.Version == record.UnansweredVersion && rec.Session == "" {
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
			return fail(fmt.Errorf("%w: a call after session %s was closed", ErrChain, rec.Session))
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
			return Report{}, nil, fmt.Errorf("%w: session %s has no close statement, so its last calls could have been cut", ErrChain, s.Session)
		}
	}
	return rep, recs, nil
}

// ErrChain means a session's calls do not form an unbroken, closed chain.
var ErrChain = errors.New("attest: broken session chain")

// ErrStored means a stored request or response does not match the signed record.
var ErrStored = errors.New("attest: the stored request or response does not match the signed record")

func matchStored(e Entry, rec sandbox.RunRecord) error {
	if rec.Version == record.UnansweredVersion {
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
	// any tool built on the stored response, would otherwise trust unsigned values.
	stored := record.FromWire(resp.GetRecord())
	if stored.Version != rec.Version || stored.SHA256 != rec.SHA256 || record.Digest(stored) != record.Digest(rec) {
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
// and WriteEntry writes none.
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

// WriteEntry appends one entry to a bundle.
func WriteEntry(w io.Writer, e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxLineBytes {
		return fmt.Errorf("%w: a line of %d bytes is past the %d a bundle line may hold", ErrLine, len(b)+1, MaxLineBytes)
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
	// (a version 3 record): there is no recorded result, so it never matches.
	Unanswered string
}

// Match reports whether the new run reproduced the recorded result.
func (r Replayed) Match() bool { return r.Err == nil && r.Unanswered == "" && r.Replayed == r.Recorded }

// Replay sends every single run in a bundle again through send and compares
// result digests. It is meaningful for deterministic workloads (the physics
// oracle's trajectory is one); a workload that reads the clock or random
// numbers differs by design. Session calls are skipped: replaying them needs a
// fresh session and the calls in order. The bundle is verified with v first (as
// VerifyBundle does) and nothing is sent unless it verifies; each baseline is the
// signed record's result digest.
func Replay(ctx context.Context, entries []Entry, v *Verifier, send func(context.Context, *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error)) ([]Replayed, error) {
	_, recs, err := verifyEntries(entries, v)
	if err != nil {
		return nil, err
	}
	var out []Replayed
	for i, e := range entries {
		if e.Envelope.Payload == "" || predicateType(e.Envelope) == ClosePredicateType || recs[i].Session != "" {
			continue // a checkpoint, a close, a session call
		}
		req, _, err := e.Messages()
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		r := Replayed{Entry: i + 1, Recorded: recs[i].ResultSHA256}
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
func ReplaySessions(ctx context.Context, entries []Entry, v *Verifier, open func(context.Context) (SessionSender, error)) ([]Replayed, error) {
	_, recs, err := verifyEntries(entries, v)
	if err != nil {
		return nil, err
	}
	var order []string
	calls := map[string][]int{}
	for i, e := range entries {
		fp := recs[i].Session
		if e.Envelope.Payload == "" || predicateType(e.Envelope) == ClosePredicateType || fp == "" {
			continue
		}
		if _, seen := calls[fp]; !seen {
			order = append(order, fp)
		}
		calls[fp] = append(calls[fp], i)
	}
	var out []Replayed
	for _, fp := range order {
		sender, openErr := open(ctx)
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
}

// NewHarness returns a Harness that signs with s and writes a new bundle to w.
func NewHarness(s *Signer, w io.Writer) *Harness { return &Harness{signer: s, w: w} }

// ResumeHarness returns a Harness that appends to the bundle whose lines are
// existing, writing to w: it refuses unless existing verifies under the signer's own
// key and ends with a checkpoint, so it never extends a bundle it cannot prove whole.
// An empty existing starts a new bundle.
func ResumeHarness(s *Signer, existing []Entry, w io.Writer) (*Harness, error) {
	h := &Harness{signer: s, w: w}
	if len(existing) == 0 {
		return h, nil
	}
	if _, err := VerifyBundle(existing, NewVerifier(s.key.Public().(ed25519.PublicKey))); err != nil {
		return nil, fmt.Errorf("attest: will not append to a bundle that does not verify: %w", err)
	}
	h.lines, h.prev = uint64(len(existing)), LineDigest(existing[len(existing)-1])
	return h, nil
}

// write links e as the bundle's next line, signs the link and writes the line.
func (h *Harness) write(e Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	link, err := h.signer.signLink(Link{Index: h.lines + 1, Previous: h.prev, Entry: ContentDigest(e)})
	if err != nil {
		return err
	}
	e.Link = &link
	if err := WriteEntry(h.w, e); err != nil {
		return err
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
	link, err := h.signer.signLink(Link{Index: h.lines + 1, Previous: h.prev, Checkpoint: true, Lines: h.lines})
	if err != nil {
		return err
	}
	e := Entry{Link: &link}
	if err := WriteEntry(h.w, e); err != nil {
		return err
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
	return h.write(e)
}

// VerifyExpected checks a verified bundle against the caller's own record of what it
// ran: requestDigests are the request digests (RunRecord.RequestSHA256, which the
// client checked against what it sent) of every call the caller made through this
// harness that returned a record, an unanswered session call's included (a refused
// call leaves none), from its own log, in any order. The bundle must hold exactly
// those requests, each as many times as listed: a call it lacks, a call it holds
// without being expected, and a call whose request is not the one the caller sent all
// fail. Two calls with one digest sent the same request (record.RunRequestDigest
// leaves out only the trace_id), so counting them is exact and nothing has to be
// unique. It proves the harness was handed every such call, as well as the caller's
// log does; the links prove only that the file is what the harness wrote. It binds
// what was sent, not what came back.
func VerifyExpected(entries []Entry, requestDigests []string) error {
	want := map[string]int{}
	for _, d := range requestDigests {
		if !isSHA256Hex(d) {
			return fmt.Errorf("%w: %q is not a request digest (64 lowercase hex characters)", ErrExpected, prefixed(d, 80))
		}
		want[d]++
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
	var missing, extra []string
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
		if got[d] < n {
			missing = append(missing, name(d, n-got[d]))
		}
	}
	for d, n := range got {
		if want[d] < n {
			extra = append(extra, name(d, n-want[d]))
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	if len(missing) > 0 || len(extra) > 0 {
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
