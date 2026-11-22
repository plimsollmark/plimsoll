package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// notCollected is the harness's statement that the close of session id could not be
// collected after calls calls ending in last.
func notCollected(t *testing.T, s *Signer, id string, calls uint64, last, reason string) Entry {
	t.Helper()
	e, err := s.CloseNotCollected(SessionCloseNotCollected{Session: record.SessionFingerprint(id), CallsSeen: calls, LastRecordSHA256: last, Reason: reason, NotedUnixMs: 1790000000200})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// lastOf is the record digest of a session's last call among entries (its calls, then
// its close, as session builds them).
func lastOf(t *testing.T, calls []Entry) string {
	t.Helper()
	_, resp, err := calls[len(calls)-1].Messages()
	if err != nil {
		t.Fatal(err)
	}
	return resp.GetRecord().GetRecordSha256()
}

// signRaw signs a statement payload as it stands, with no check: how a forger holding the
// key, or a careless harness, would write one.
func signRaw(t *testing.T, s *Signer, st any) Entry {
	t.Helper()
	payload, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return Entry{Envelope: s.envelope(payload)}
}

// The finding's own case, hunt-quality-20: a session's calls, a close the daemon could not
// answer (not found), a single run, a checkpoint. The bundle verifies, the session is
// reported as not proven complete with the reason and the calls the client saw, and a
// resumed harness continues the bundle.
func TestASessionWhoseCloseCouldNotBeCollectedVerifies(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 2)
	req, resp := exchange("console.log(1)", "1\n", sandbox.RunRecord{})
	single, err := s.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	h := NewHarness(s, &buf)
	for _, e := range []Entry{a[0], a[1]} {
		if err := h.write(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.RecordCloseNotCollected(record.SessionFingerprint("session-a"), 2, lastOf(t, a[:2]), "", CloseNotCollectedNotFound); err != nil {
		t.Fatal(err)
	}
	if err := h.write(single); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyBundle(entries, v, AcceptNotProvenComplete)
	if err != nil {
		t.Fatalf("a session whose close could not be collected: %v", err)
	}
	if rep.Runs != 1 || len(rep.Sessions) != 1 {
		t.Fatalf("report %+v", rep)
	}
	got := rep.Sessions[0]
	if got.Closed || got.Calls != 2 || got.NotCollected == nil || got.NotCollected.Reason != CloseNotCollectedNotFound || got.NotCollected.CallsSeen != 2 || got.NotCollected.NotedUnixMs <= 0 {
		t.Fatalf("the session is reported as %+v (statement %+v); want not closed, 2 calls, not found", got, got.NotCollected)
	}
	if d := got.NotCollected.Describe(); !strings.Contains(d, "NOT PROVEN COMPLETE") || !strings.Contains(d, "the daemon's own count of the session's calls is unknown") ||
		!strings.Contains(d, "(the daemon that answered the close said it has no such session for this caller)") {
		t.Fatalf("the words a reader sees: %q", got.NotCollected.Describe())
	}
	// The expected-count check holds the bundle to the caller's own list: the two session
	// calls and the single run. It passes, and the session is still not proven complete.
	digests := []string{record.RunRequestDigest(req)}
	for _, e := range a[:2] {
		r, _, _ := e.Messages()
		digests = append(digests, record.RunRequestDigest(r))
	}
	if rep, err := VerifyExpected(entries, v, Expected{Requests: digests}, AcceptNotProvenComplete); err != nil || rep.Sessions[0].Closed {
		t.Fatalf("VerifyExpected: %+v, %v", rep, err)
	}
	// A resumed harness continues it.
	var more bytes.Buffer
	resumed, err := ResumeHarness(s, entries, &more)
	if err != nil {
		t.Fatalf("ResumeHarness on the bundle: %v", err)
	}
	if err := resumed.write(single); err != nil {
		t.Fatal(err)
	}
	if err := resumed.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	whole, err := ReadBundle(bytes.NewReader(append(buf.Bytes(), more.Bytes()...)))
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := VerifyBundle(whole, v, AcceptNotProvenComplete); err != nil || rep.Runs != 2 || rep.Sessions[0].Closed {
		t.Fatalf("the resumed bundle: %+v, %v", rep, err)
	}
	// The stale-owner reason reads as its own words.
	b := session(t, s, "session-b", 1)
	rep, err = VerifyBundle(seal(t, s, b[0], notCollected(t, s, "session-b", 1, lastOf(t, b[:1]), CloseNotCollectedStaleOwner)), v, AcceptNotProvenComplete)
	if err != nil || !strings.Contains(rep.Sessions[0].NotCollected.Describe(), "(another worker took the session over); the harness signed that the client saw this 1 call,") {
		t.Fatalf("a stale owner's statement: %+v, %v", rep, err)
	}
}

// A session with neither the daemon's close nor the harness's statement still fails: its
// last calls could have been cut.
func TestASessionWithNeitherEndingStillFails(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 2)
	req, resp := exchange("console.log(1)", "1\n", sandbox.RunRecord{})
	single, err := s.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	entries := seal(t, s, a[0], a[1], single)
	if _, err := VerifyBundle(entries, v); !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "has no close statement") {
		t.Fatalf("a session with no ending: %v; want ErrChain", err)
	}
	if _, err := ResumeHarness(s, entries, &bytes.Buffer{}); !errors.Is(err, ErrChain) {
		t.Fatalf("ResumeHarness on a session with no ending: %v; want ErrChain", err)
	}
}

// The statement is not the daemon's close and cannot be taken for one: a reader who needs
// the daemon's count (Report.Complete, verify -require-close) refuses it, VerifyClose
// refuses it, and no generic statement path signs or opens one.
func TestTheStatementDoesNotStandInForAClose(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 1)
	stmt := notCollected(t, s, "session-a", 1, lastOf(t, a[:1]), CloseNotCollectedNotFound)
	rep, err := VerifyBundle(seal(t, s, a[0], stmt), v, AcceptNotProvenComplete)
	if err != nil {
		t.Fatal(err)
	}
	if err := rep.Complete(); !errors.Is(err, ErrNotProvenComplete) {
		t.Fatalf("Complete on a session ended by the statement: %v; want ErrNotProvenComplete", err)
	}
	if rep, err := VerifyBundle(seal(t, s, a...), v); err != nil || rep.Complete() != nil || !rep.Sessions[0].Closed {
		t.Fatalf("a closed session: %+v, %v", rep, err)
	}
	if _, err := v.VerifyClose(stmt.Envelope); !errors.Is(err, ErrStatement) {
		t.Fatalf("VerifyClose read the statement: %v", err)
	}
	if _, err := v.VerifyCloseNotCollected(a[1].Envelope); !errors.Is(err, ErrStatement) {
		t.Fatalf("VerifyCloseNotCollected read a daemon close: %v", err)
	}
	pred := SessionCloseNotCollected{Session: record.SessionFingerprint("x"), Reason: CloseNotCollectedNotFound, NotedUnixMs: 1}
	subjects := []Subject{{Name: "session", Digest: map[string]string{"sha256": pred.Session}}}
	if _, err := s.SignStatement(CloseNotCollectedPredicateType, subjects, pred); !errors.Is(err, ErrReservedPredicate) {
		t.Fatalf("SignStatement made one: %v", err)
	}
	if _, err := v.OpenStatement(stmt.Envelope, CloseNotCollectedPredicateType, &pred); !errors.Is(err, ErrReservedPredicate) {
		t.Fatalf("OpenStatement opened one: %v", err)
	}
}

// hunt-quality-38: the library fails closed. VerifyBundle and VerifyExpected refuse a
// session that ends in the statement with ErrNotProvenComplete (VerifyBundle returning the
// report beside it) unless the caller passes AcceptNotProvenComplete, so a caller that
// reads only the error never takes it for a closed session. ResumeHarness and Replay accept
// it: a resumed bundle and a replay claim nothing of what the bundle lacks.
func TestTheLibraryRefusesASessionNotProvenCompleteByDefault(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 1)
	entries := seal(t, s, a[0], notCollected(t, s, "session-a", 1, lastOf(t, a[:1]), CloseNotCollectedNotFound))
	req0, _, err := a[0].Messages()
	if err != nil {
		t.Fatal(err)
	}
	digests := []string{record.RunRequestDigest(req0)}
	rep, err := VerifyBundle(entries, v)
	if !errors.Is(err, ErrNotProvenComplete) || len(rep.Sessions) != 1 || rep.Sessions[0].Closed || rep.Sessions[0].NotCollected == nil {
		t.Fatalf("VerifyBundle by default: %+v, %v; want ErrNotProvenComplete and the report", rep, err)
	}
	if _, err := VerifyExpected(entries, v, Expected{Requests: digests}); !errors.Is(err, ErrNotProvenComplete) {
		t.Fatalf("VerifyExpected by default: %v; want ErrNotProvenComplete", err)
	}
	if _, err := VerifyBundle(entries, v, AcceptNotProvenComplete); err != nil {
		t.Fatalf("VerifyBundle accepting: %v", err)
	}
	if _, err := VerifyExpected(entries, v, Expected{Requests: digests}, AcceptNotProvenComplete); err != nil {
		t.Fatalf("VerifyExpected accepting: %v", err)
	}
	if _, err := VerifyBundle(seal(t, s, a...), v); err != nil {
		t.Fatalf("a session the daemon closed, by default: %v", err)
	}
	if _, err := ResumeHarness(s, entries, &bytes.Buffer{}); err != nil {
		t.Fatalf("ResumeHarness: %v", err)
	}
	sent := 0
	if _, err := Replay(context.Background(), entries, v, ReplayOptions{}, func(context.Context, *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		sent++
		return nil, errors.New("not sent in this test")
	}); err != nil || sent != 0 {
		t.Fatalf("Replay: %v (%d sent); want it to verify and send no session call", err, sent)
	}
}

// A forged statement is refused: another key, another session, a wrong last record or
// count, a reason outside the set, no time, a subject that is not its session.
func TestAForgedStatementIsRefused(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 2)
	last := lastOf(t, a[:2])
	fp := record.SessionFingerprint("session-a")
	raw := func(p SessionCloseNotCollected, subject string) Entry {
		return signRaw(t, s, closeNotCollectedStatement{Type: StatementType, PredicateType: CloseNotCollectedPredicateType,
			Subject: []Subject{{Name: "session", Digest: map[string]string{"sha256": subject}}}, Predicate: p})
	}
	good := SessionCloseNotCollected{Session: fp, CallsSeen: 2, LastRecordSHA256: last, Reason: CloseNotCollectedNotFound, NotedUnixMs: 1790000000200}
	if _, err := VerifyBundle(seal(t, s, a[0], a[1], raw(good, fp)), v, AcceptNotProvenComplete); err != nil {
		t.Fatalf("the honest statement, signed raw: %v", err)
	}
	with := func(f func(*SessionCloseNotCollected)) SessionCloseNotCollected { p := good; f(&p); return p }
	other := record.SessionFingerprint("session-b")
	for name, c := range map[string]struct {
		ending Entry
		want   error
	}{
		"signed by another key":                {notCollected(t, NewSigner(newKey(t)), "session-a", 2, last, CloseNotCollectedNotFound), ErrSignature},
		"another session":                      {raw(with(func(p *SessionCloseNotCollected) { p.Session = other }), other), ErrChain},
		"a wrong last record":                  {raw(with(func(p *SessionCloseNotCollected) { p.LastRecordSHA256 = strings.Repeat("0", 64) }), fp), ErrChain},
		"one call fewer":                       {raw(with(func(p *SessionCloseNotCollected) { p.CallsSeen = 1 }), fp), ErrChain},
		"a reason outside the set":             {raw(with(func(p *SessionCloseNotCollected) { p.Reason = "timeout" }), fp), ErrStatement},
		"no time":                              {raw(with(func(p *SessionCloseNotCollected) { p.NotedUnixMs = 0 }), fp), ErrStatement},
		"a subject of another":                 {raw(good, other), ErrStatement},
		"calls with no last record":            {raw(with(func(p *SessionCloseNotCollected) { p.LastRecordSHA256 = "" }), fp), ErrStatement},
		"a session that is no print":           {raw(with(func(p *SessionCloseNotCollected) { p.Session = "session-a" }), "session-a"), ErrStatement},
		"an unanswered call that is no digest": {raw(with(func(p *SessionCloseNotCollected) { p.UnansweredRequestSHA256 = "d92e84d1" }), fp), ErrStatement},
	} {
		if _, err := VerifyBundle(seal(t, s, a[0], a[1], c.ending), v); !errors.Is(err, c.want) {
			t.Errorf("%s: %v; want %v", name, err, c.want)
		}
	}
	// A statement claiming calls for a session the bundle holds none of, beside a session
	// that is whole: the claimed calls are not in the bundle.
	claimed := raw(with(func(p *SessionCloseNotCollected) { p.Session = other; p.CallsSeen = 1 }), other)
	if _, err := VerifyBundle(seal(t, s, append(append([]Entry{}, a...), claimed)...), v); !errors.Is(err, ErrChain) {
		t.Errorf("a statement claiming a call the bundle does not hold: %v; want ErrChain", err)
	}
	// The harness itself signs no statement the verifier would refuse.
	if _, err := s.CloseNotCollected(with(func(p *SessionCloseNotCollected) { p.Reason = "timeout" })); !errors.Is(err, ErrStatement) {
		t.Fatalf("the signer signed an unknown reason: %v", err)
	}
}

// hunt-quality-33: the statement names the call the client sent after the ones it saw and
// got no answer for. The verified report carries its request digest (Report.Unanswered),
// the words say it may have run, and the caller's own list of request digests may name it
// or not: listed, it is matched as sent and unanswered, never reported missing; a second
// listing of it is missing, since only one such call was sent.
func TestAnUnansweredCallIsStated(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 1)
	req0, _, err := a[0].Messages()
	if err != nil {
		t.Fatal(err)
	}
	sent := record.RunRequestDigest(req0)
	lostReq, _ := exchange("console.log('lost')", "", sandbox.RunRecord{})
	lost := record.RunRequestDigest(lostReq)
	stmt, err := s.CloseNotCollected(SessionCloseNotCollected{Session: record.SessionFingerprint("session-a"), CallsSeen: 1, LastRecordSHA256: lastOf(t, a[:1]),
		UnansweredRequestSHA256: lost, Reason: CloseNotCollectedNotFound, NotedUnixMs: 1790000000200})
	if err != nil {
		t.Fatal(err)
	}
	entries := seal(t, s, a[0], stmt)
	rep, err := VerifyBundle(entries, v, AcceptNotProvenComplete)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Unanswered(); len(got) != 1 || got[0] != lost {
		t.Fatalf("Unanswered: %v; want [%s]", got, lost)
	}
	if want := "; and one more call was sent after it with no answer (request " + lost + "): it may have run"; !strings.HasSuffix(rep.Sessions[0].NotCollected.Describe(), want) {
		t.Fatalf("the words: %q; want them to end %q", rep.Sessions[0].NotCollected.Describe(), want)
	}
	if CountCalls(entries) != 1 {
		t.Fatalf("CountCalls %d; the unanswered call is in no line", CountCalls(entries))
	}
	// The caller's list names the call sent with no answer as such (Expected.Unanswered),
	// matched against the statements only, or leaves it out, when it is reported and
	// required of nothing. Listed as a call that returned a record, it is missing: the
	// statement is no line (the security scan of 2026-11-20, F9).
	for name, c := range map[string]struct {
		list Expected
		ok   bool
	}{
		"the answered call alone":                    {Expected{Requests: []string{sent}}, true},
		"both calls, the lost one as unanswered":     {Expected{Requests: []string{sent}, Unanswered: []string{lost}}, true},
		"both calls, the lost one as a record":       {Expected{Requests: []string{sent, lost}}, false},
		"the unanswered call twice":                  {Expected{Requests: []string{sent}, Unanswered: []string{lost, lost}}, false},
		"the unanswered call alone":                  {Expected{Unanswered: []string{lost}}, false},
		"another call in place of the lost":          {Expected{Requests: []string{sent}, Unanswered: []string{strings.Repeat("a", 64)}}, false},
		"the answered call listed as unanswered too": {Expected{Requests: []string{sent}, Unanswered: []string{sent}}, false},
		"an unanswered call that is no digest":       {Expected{Requests: []string{sent}, Unanswered: []string{"d92e84d1"}}, false},
	} {
		_, err := VerifyExpected(entries, v, c.list, AcceptNotProvenComplete)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrExpected)) {
			t.Errorf("%s: %v; want ok %v", name, err, c.ok)
		}
		if name == "both calls, the lost one as a record" && (err == nil || !strings.Contains(err.Error(), "a session's statement names it as sent with no answer, which is no line: list such a call as unanswered")) {
			t.Errorf("%s: the error does not say why: %v", name, err)
		}
	}
	// With no call before it, the words say so.
	none, err := s.CloseNotCollected(SessionCloseNotCollected{Session: record.SessionFingerprint("session-b"), UnansweredRequestSHA256: lost, Reason: CloseNotCollectedNotFound, NotedUnixMs: 1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err = VerifyBundle(seal(t, s, none), v, AcceptNotProvenComplete)
	if err != nil || !strings.Contains(rep.Sessions[0].NotCollected.Describe(), "saw no call of it, and the daemon's own count of the session's calls is unknown; and one call was sent with no answer (request "+lost+"): it may have run") {
		t.Fatalf("a statement of no call and one unanswered: %+v, %v", rep, err)
	}
}

// F9 of the security scan of 2026-11-20: the call sent with no answer is
// sent again and answered, as a single run after a checkpoint. A holder of the file cuts it
// back to that checkpoint, which leaves a bundle that verifies; the caller's list names the
// retry, which returned a record, so the cut bundle must be short of it. The statement's
// unanswered call never stands in for a line.
func TestACutRetryOfAnUnansweredCallIsMissing(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 1)
	req0, _, err := a[0].Messages()
	if err != nil {
		t.Fatal(err)
	}
	sent := record.RunRequestDigest(req0)
	retryReq, retryResp := exchange("console.log('lost')", "", sandbox.RunRecord{})
	lost := record.RunRequestDigest(retryReq)
	var buf bytes.Buffer
	h := NewHarness(s, &buf)
	if err := h.write(a[0]); err != nil {
		t.Fatal(err)
	}
	if err := h.RecordCloseNotCollected(record.SessionFingerprint("session-a"), 1, lastOf(t, a[:1]), lost, CloseNotCollectedNotFound); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if err := h.Record(retryReq, retryResp); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	whole, err := ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	cut := whole[:3] // the session's call, the statement, the first checkpoint
	if _, err := VerifyBundle(cut, v, AcceptNotProvenComplete); err != nil {
		t.Fatalf("the cut bundle verifies as a bundle (the list is what catches the cut): %v", err)
	}
	// The session's call and the retry each returned a record; the lost call got no answer,
	// and a caller may say so or not.
	for _, list := range []Expected{
		{Requests: []string{sent, lost}},
		{Requests: []string{sent, lost}, Unanswered: []string{lost}},
	} {
		if _, err := VerifyExpected(whole, v, list, AcceptNotProvenComplete); err != nil {
			t.Fatalf("the whole bundle, %+v: %v", list, err)
		}
		if _, err := VerifyExpected(cut, v, list, AcceptNotProvenComplete); !errors.Is(err, ErrExpected) {
			t.Fatalf("the bundle cut back before the retry, %+v: %v; want ErrExpected", list, err)
		}
	}
}

// After the statement the session has ended: a daemon's close of it, a second statement
// and a call of it are a broken chain in the bundle, and the harness refuses to write a
// second ending (its own, or after a resume), writing nothing.
func TestADaemonCloseAfterTheStatementIsRefused(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 2)
	stmt := notCollected(t, s, "session-a", 1, lastOf(t, a[:1]), CloseNotCollectedNotFound)
	closeOne, err := s.Close(SessionClose{Session: record.SessionFingerprint("session-a"), Calls: 1, LastRecordSHA256: lastOf(t, a[:1])})
	if err != nil {
		t.Fatal(err)
	}
	for name, bundle := range map[string][]Entry{
		"the daemon's close after it": {a[0], stmt, closeOne},
		"the statement after a close": {a[0], closeOne, stmt},
		"a second statement":          {a[0], stmt, stmt},
		"a call after it":             {a[0], stmt, a[1]},
	} {
		if _, err := VerifyBundle(seal(t, s, bundle...), v); !errors.Is(err, ErrChain) {
			t.Errorf("%s: %v; want ErrChain", name, err)
		}
	}
	fp := record.SessionFingerprint("session-a")
	var buf bytes.Buffer
	h := NewHarness(s, &buf)
	if err := h.write(a[0]); err != nil {
		t.Fatal(err)
	}
	if err := h.RecordCloseNotCollected(fp, 1, lastOf(t, a[:1]), "", CloseNotCollectedNotFound); err != nil {
		t.Fatal(err)
	}
	n := buf.Len()
	if err := h.RecordClose(fp, 1, lastOf(t, a[:1])); !errors.Is(err, ErrChain) || buf.Len() != n {
		t.Fatalf("the harness wrote a daemon close after the statement: %v (%d bytes, was %d)", err, buf.Len(), n)
	}
	if err := h.RecordCloseNotCollected(fp, 1, lastOf(t, a[:1]), "", CloseNotCollectedNotFound); !errors.Is(err, ErrChain) || buf.Len() != n {
		t.Fatalf("the harness wrote a second statement: %v", err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := ResumeHarness(s, entries, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.RecordClose(fp, 1, lastOf(t, a[:1])); !errors.Is(err, ErrChain) {
		t.Fatalf("a resumed harness wrote a close after the statement: %v", err)
	}
}

// One ending line checks on its own (VerifyEnding): its link and its statement; a line
// whose content its link does not sign, and a call line, are refused.
func TestVerifyEndingChecksOneLine(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 1)
	entries := seal(t, s, a[0], notCollected(t, s, "session-a", 1, lastOf(t, a[:1]), CloseNotCollectedStaleOwner))
	end, l, err := VerifyEnding(v, entries[1])
	if err != nil || end.NotCollected == nil || end.Close != nil || end.NotCollected.Reason != CloseNotCollectedStaleOwner || l.Index != 2 {
		t.Fatalf("VerifyEnding: %+v %+v, %v", end, l, err)
	}
	closed := seal(t, s, a...)
	if end, _, err := VerifyEnding(v, closed[1]); err != nil || end.Close == nil || end.Close.Calls != 1 {
		t.Fatalf("VerifyEnding on a daemon close: %+v, %v", end, err)
	}
	moved := entries[1]
	moved.Envelope = closed[1].Envelope // another ending under this line's link
	if _, _, err := VerifyEnding(v, moved); !errors.Is(err, ErrLink) {
		t.Fatalf("an ending its link does not sign: %v", err)
	}
	if _, _, err := VerifyEnding(v, entries[0]); !errors.Is(err, ErrStatement) {
		t.Fatalf("a call line as an ending: %v", err)
	}
}

// hunt-quality-37: an ending line (the daemon's close or the harness's statement) is its
// envelope alone. One that also stores a request or a response, under a link that signs it
// all, is refused by VerifyBundle and by VerifyEnding alike, so it never counts as a call
// for CountCalls or the -expect check.
func TestAnEndingLineWithStoredMessagesIsRefused(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 1)
	stmt := notCollected(t, s, "session-a", 1, lastOf(t, a[:1]), CloseNotCollectedNotFound)
	for name, ending := range map[string]Entry{"the daemon's close": a[1], "the statement": stmt} {
		for what, add := range map[string]func(*Entry){
			"a request":  func(e *Entry) { e.Request = a[0].Request },
			"a response": func(e *Entry) { e.Response = a[0].Response },
		} {
			e := ending
			add(&e)
			entries := seal(t, s, a[0], e)
			if _, err := VerifyBundle(entries, v); !errors.Is(err, ErrStatement) {
				t.Errorf("%s with %s, VerifyBundle: %v; want ErrStatement", name, what, err)
			}
			if _, _, err := VerifyEnding(v, entries[1]); !errors.Is(err, ErrStatement) {
				t.Errorf("%s with %s, VerifyEnding: %v; want ErrStatement", name, what, err)
			}
		}
		if _, err := VerifyBundle(seal(t, s, a[0], ending), v, AcceptNotProvenComplete); err != nil {
			t.Errorf("%s alone: %v", name, err)
		}
	}
}

// What a verifier of a published release does with the statement, as the design reads it
// from their code: v0.18.0 to v0.27.2 send every line that is not a checkpoint or a
// daemon close to Verifier.Verify, which reads it as an invalid run-record statement, not
// "upgrade the verifier". From this release on, a plimsoll statement of a kind the release
// does not read, signed by the bundle's key, is ErrUnknownStatement ("upgrade the
// verifier"); one another key signed, or outside plimsoll's names, is refused as before.
func TestAnOlderReaderAndAnUnknownStatement(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	a := session(t, s, "session-a", 1)
	stmt := notCollected(t, s, "session-a", 1, lastOf(t, a[:1]), CloseNotCollectedNotFound)
	if _, err := v.Verify(stmt.Envelope); !errors.Is(err, ErrStatement) || errors.Is(err, record.ErrVersion) || errors.Is(err, ErrUnknownStatement) {
		t.Fatalf("the statement put to Verify, as v0.18.0 to v0.27.2 put it: %v; want ErrStatement", err)
	}
	later := func(s *Signer, pt string) Entry {
		return signRaw(t, s, map[string]any{"_type": StatementType, "predicateType": pt,
			"subject": []Subject{{Name: "session", Digest: map[string]string{"sha256": record.SessionFingerprint("x")}}}, "predicate": map[string]any{"new": 1}})
	}
	for name, c := range map[string]struct {
		line Entry
		want error
	}{
		"a later plimsoll statement":           {later(s, statementNamespace+"session-something-new/v1"), ErrUnknownStatement},
		"a later plimsoll statement, forged":   {later(NewSigner(newKey(t)), statementNamespace+"session-something-new/v1"), ErrSignature},
		"a statement outside plimsoll's names": {later(s, "https://example.com/other/v1"), ErrStatement},
	} {
		entries := seal(t, s, a[0], a[1], c.line)
		_, err := VerifyBundle(entries, v)
		if !errors.Is(err, c.want) || (c.want != ErrUnknownStatement && errors.Is(err, ErrUnknownStatement)) {
			t.Errorf("%s: %v; want %v", name, err, c.want)
		}
		if c.want == ErrUnknownStatement && !strings.Contains(err.Error(), "a kind of plimsoll statement this release does not read as a bundle line: "+
			"a newer release may have written it (upgrade the verifier); if none has, plimsoll writes no such line") {
			t.Errorf("%s: the words %q", name, err)
		}
		// One line checked on its own gives the same answer, as a call line or as an ending.
		_, _, err = VerifyEnding(v, entries[2])
		if !errors.Is(err, c.want) || (c.want != ErrUnknownStatement && errors.Is(err, ErrUnknownStatement)) {
			t.Errorf("%s, VerifyEnding: %v; want %v", name, err, c.want)
		}
		asCall := entries[0]
		asCall.Envelope = c.line.Envelope
		asCall.Link = nil
		_, _, err = VerifyEntry(v, seal(t, s, asCall)[0])
		if !errors.Is(err, c.want) || (c.want != ErrUnknownStatement && errors.Is(err, ErrUnknownStatement)) {
			t.Errorf("%s, VerifyEntry: %v; want %v", name, err, c.want)
		}
	}
}

// The bundles the published releases wrote still verify, and every session in them reads
// as closed by the daemon: the new ending changes nothing for them.
func TestPublishedBundlesReadAsClosed(t *testing.T) {
	for _, dir := range []string{"v0.22.0-sessions", "v0.27.1-sessions", "v0.27.1-agentsandbox"} {
		entries, v := publishedBundle(t, dir)
		rep, err := VerifyBundle(entries, v)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if err := rep.Complete(); err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
	}
}
