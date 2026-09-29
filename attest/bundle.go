package attest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
type Entry struct {
	Request  []byte   `json:"request,omitempty"`
	Response []byte   `json:"response,omitempty"`
	Envelope Envelope `json:"envelope"`
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

// VerifyBundle checks every entry: each signature, each record against the
// stored request and response it came with, and each session's chain (calls
// numbered from 1 without a gap, each naming the record before it, ending in a
// close statement whose count and last record match). A chain without a close
// statement fails: its tail cannot be told from a cut one. A session that ran no
// call is its close statement alone, with a count of zero and no last record.
func VerifyBundle(entries []Entry, v *Verifier) (Report, error) {
	type chain struct {
		calls  uint64
		last   string
		closed bool
		index  int
	}
	var rep Report
	chains := map[string]*chain{}
	for i, e := range entries {
		fail := func(err error) (Report, error) { return Report{}, fmt.Errorf("entry %d: %w", i+1, err) }
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
			return Report{}, fmt.Errorf("%w: session %s has no close statement, so its last calls could have been cut", ErrChain, s.Session)
		}
	}
	return rep, nil
}

// ErrChain means a session's calls do not form an unbroken, closed chain.
var ErrChain = errors.New("attest: broken session chain")

// ErrStored means a stored request or response does not match the signed record.
var ErrStored = errors.New("attest: the stored request or response does not match the signed record")

func matchStored(e Entry, rec sandbox.RunRecord) error {
	req, resp, err := e.Messages()
	if err != nil {
		return err
	}
	switch {
	case record.RunRequestDigest(req) != rec.RequestSHA256:
		return fmt.Errorf("%w: the request", ErrStored)
	case record.ResultDigest(resp) != rec.ResultSHA256:
		return fmt.Errorf("%w: the result", ErrStored)
	case resp.GetSandbox() != rec.Provider || resp.GetIsolation() != rec.Isolation:
		return fmt.Errorf("%w: the evidence", ErrStored)
	case resp.GetRecord().GetRecordSha256() != rec.SHA256:
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
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("bundle line %d: %w", n, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// WriteEntry appends one entry to a bundle.
func WriteEntry(w io.Writer, e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
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
}

// Match reports whether the new run reproduced the recorded result.
func (r Replayed) Match() bool { return r.Err == nil && r.Replayed == r.Recorded }

// Replay sends every single run in a bundle again through send and compares
// result digests. It is meaningful for deterministic workloads (the physics
// oracle's trajectory is one); a workload that reads the clock or random
// numbers differs by design. Session calls are skipped: replaying them needs a
// fresh session and the calls in order. Entries are not verified here; run
// VerifyBundle first.
func Replay(ctx context.Context, entries []Entry, send func(context.Context, *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error)) ([]Replayed, error) {
	var out []Replayed
	for i, e := range entries {
		if predicateType(e.Envelope) == ClosePredicateType {
			continue
		}
		req, resp, err := e.Messages()
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		if resp.GetRecord().GetSession() != "" {
			continue
		}
		r := Replayed{Entry: i + 1, Recorded: resp.GetRecord().GetResultSha256()}
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
// replays; a deterministic session reproduces every call. Entries are not verified
// here; run VerifyBundle first.
func ReplaySessions(ctx context.Context, entries []Entry, open func(context.Context) (SessionSender, error)) ([]Replayed, error) {
	var order []string
	calls := map[string][]int{}
	for i, e := range entries {
		if predicateType(e.Envelope) == ClosePredicateType {
			continue
		}
		_, resp, err := e.Messages()
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		fp := resp.GetRecord().GetSession()
		if fp == "" {
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
			req, resp, _ := entries[i].Messages()
			r := Replayed{Entry: i + 1, Session: fp, Recorded: resp.GetRecord().GetResultSha256()}
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

// Harness signs every exchange it is given and appends it to a bundle. It is a
// client.Recorder: client.New(url, client.WithRecorder(h)) signs every run the
// client makes. Safe for concurrent use.
type Harness struct {
	mu     sync.Mutex
	signer *Signer
	w      io.Writer
}

// NewHarness returns a Harness that signs with s and writes entries to w.
func NewHarness(s *Signer, w io.Writer) *Harness { return &Harness{signer: s, w: w} }

// Record checks the exchange's record, signs it and writes the entry.
func (h *Harness) Record(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) error {
	e, err := h.signer.Call(req, resp)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return WriteEntry(h.w, e)
}

// RecordClose signs a session's close, as the daemon stated it, and writes it.
// With it, Harness is a client.SessionRecorder.
func (h *Harness) RecordClose(session string, calls uint64, lastRecordSHA256 string) error {
	e, err := h.signer.Close(SessionClose{Session: session, Calls: calls, LastRecordSHA256: lastRecordSHA256})
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return WriteEntry(h.w, e)
}
