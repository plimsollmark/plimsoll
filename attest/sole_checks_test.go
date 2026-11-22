package attest

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The tests in this file are each the one test of a check no other test missed when it
// was deleted (hunt-quality-29, private/reviews/hunt-quality-record-and-attest-2026-11-20.md):
// each builds the case only that check refuses.

// One run's signed envelope over another run's stored request and response is not a
// line of either: the stored response's own record must be the signed one. Without that
// comparison, run A's signature vouches for run B's code and output in VerifyCall (what
// verify-record runs on a line from before links), VerifyEntry and VerifyBundle.
func TestASignatureOverAnotherRunsExchangeIsRefused(t *testing.T) {
	s, v := newKeyPair(t)
	reqA, respA := exchange("console.log('a')", "a\n", sandbox.RunRecord{})
	reqB, respB := exchange("console.log('b')", "b\n", sandbox.RunRecord{})
	a, err := s.Call(reqA, respA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Call(reqB, respB)
	if err != nil {
		t.Fatal(err)
	}
	swapped := Entry{Request: b.Request, Response: b.Response, Envelope: a.Envelope}
	if _, err := VerifyCall(v, swapped); !errors.Is(err, ErrStored) {
		t.Errorf("VerifyCall: %v, want ErrStored", err)
	}
	lines := seal(t, s, swapped)
	if _, _, err := VerifyEntry(v, lines[0]); !errors.Is(err, ErrStored) {
		t.Errorf("VerifyEntry: %v, want ErrStored", err)
	}
	if _, err := VerifyBundle(lines, v); !errors.Is(err, ErrStored) {
		t.Errorf("VerifyBundle: %v, want ErrStored", err)
	}
}

// A session call that names a record other than the one before it breaks the chain,
// even when its sequence number is right and the close counts it.
func TestACallNamingAWrongPreviousRecordBreaksTheChain(t *testing.T) {
	s, v := newKeyPair(t)
	fp := record.SessionFingerprint("session-p")
	req1, resp1 := exchange("step()", "1", sandbox.RunRecord{Session: fp, Sequence: 1})
	first, err := s.entry(req1, resp1, record.FromWire(resp1.GetRecord()))
	if err != nil {
		t.Fatal(err)
	}
	wrong := strings.Repeat("ab", 32)
	req2, resp2 := exchange("step()", "2", sandbox.RunRecord{Session: fp, Sequence: 2, PreviousSHA256: wrong})
	second, err := s.entry(req2, resp2, record.FromWire(resp2.GetRecord()))
	if err != nil {
		t.Fatal(err)
	}
	closed, err := s.Close(SessionClose{Session: fp, Calls: 2, LastRecordSHA256: resp2.GetRecord().GetRecordSha256()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(seal(t, s, first, second, closed), v); !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "names previous") {
		t.Fatalf("a call naming a wrong previous record: %v, want ErrChain", err)
	}
}

// unansweredSingleRun is a signed entry of an unanswered record that names no session,
// which only a session call can be. It is signed through the signer's own envelope, as a
// harness older than its refusal could have signed it.
func unansweredSingleRun(t *testing.T, s *Signer) Entry {
	t.Helper()
	req := &plimsollv1.RunRequest{Protocol: 2, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
	wire := record.StampUnanswered(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req), Provider: "docker", Isolation: "container",
		Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000001000)}, "unavailable")
	e, err := s.entry(req, &plimsollv1.RunResponse{}, record.FromWire(wire))
	if err != nil {
		t.Fatal(err)
	}
	e.Response = nil // an unanswered call's entry stores its request alone
	return e
}

// An unanswered record outside a session is refused by a whole bundle and by one line
// checked alone: a single run that came back has a result, and one that did not has no
// chain to stand in.
func TestAnUnansweredSingleRunIsRefused(t *testing.T) {
	s, v := newKeyPair(t)
	lines := seal(t, s, unansweredSingleRun(t, s))
	if _, err := VerifyBundle(lines, v); !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "outside a session") {
		t.Errorf("VerifyBundle: %v, want ErrChain for an unanswered record outside a session", err)
	}
	if _, _, err := VerifyEntry(v, lines[0]); !errors.Is(err, ErrChain) {
		t.Errorf("VerifyEntry: %v, want ErrChain", err)
	}
	// Nor does the signer sign one, through Unanswered or a harness.
	req := &plimsollv1.RunRequest{Protocol: 2, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
	wire := record.StampUnanswered(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req), Provider: "docker", Isolation: "container",
		Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000001000)}, "unavailable")
	if _, err := s.Unanswered(req, wire); !errors.Is(err, ErrChain) {
		t.Errorf("Signer.Unanswered: %v, want ErrChain", err)
	}
}

// A single run's line whose record states a sequence number or a previous record (the
// chain fields of a session call) is refused by VerifyEntry, as by VerifyBundle.
func TestVerifyEntryRefusesASingleRunWithChainFields(t *testing.T) {
	s, v := newKeyPair(t)
	for name, link := range map[string]sandbox.RunRecord{
		"a sequence number": {Sequence: 1},
		"a previous record": {PreviousSHA256: strings.Repeat("cd", 32)},
		"both chain fields": {Sequence: 2, PreviousSHA256: strings.Repeat("ef", 32)},
	} {
		req, resp := exchange("console.log(1)", "1\n", link)
		e, err := s.entry(req, resp, record.FromWire(resp.GetRecord()))
		if err != nil {
			t.Fatal(err)
		}
		lines := seal(t, s, e)
		if _, _, err := VerifyEntry(v, lines[0]); !errors.Is(err, ErrChain) {
			t.Errorf("%s: VerifyEntry: %v, want ErrChain", name, err)
		}
		if _, err := VerifyBundle(lines, v); !errors.Is(err, ErrChain) {
			t.Errorf("%s: VerifyBundle: %v, want ErrChain", name, err)
		}
	}
}

// A run-record statement whose one subject names a digest other than its record's is not
// a statement of that record, though the predicate checks on its own.
func TestVerifyRefusesASubjectThatIsNotTheRecord(t *testing.T) {
	s, v := newKeyPair(t)
	req, resp := exchange("console.log(1)", "1\n", sandbox.RunRecord{})
	rec := record.FromWire(resp.GetRecord())
	if _, err := record.CheckExchange(req, resp); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: SubjectName, Digest: map[string]string{"sha256": strings.Repeat("0", 64)}}},
		PredicateType: PredicateType,
		Predicate:     predicateOf(rec),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(s.envelope(payload)); !errors.Is(err, ErrStatement) || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("a subject other than the record: %v, want ErrStatement", err)
	}
}

// A close statement whose subject names another session than its predicate is not a
// session-close statement.
func TestVerifyCloseRefusesASubjectOfAnotherSession(t *testing.T) {
	s, v := newKeyPair(t)
	payload, err := json.Marshal(closeStatement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "session", Digest: map[string]string{"sha256": record.SessionFingerprint("another")}}},
		PredicateType: ClosePredicateType,
		Predicate:     SessionClose{Session: record.SessionFingerprint("this one")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyClose(s.envelope(payload)); !errors.Is(err, ErrStatement) {
		t.Fatalf("a close whose subject is another session: %v, want ErrStatement", err)
	}
}

// An envelope of more than MaxSignatures signatures is refused before any is checked,
// even when every one of them is the harness's valid signature.
func TestAnEnvelopeOfTooManySignaturesIsRefused(t *testing.T) {
	s, v := newKeyPair(t)
	req, resp := exchange("console.log(1)", "1\n", sandbox.RunRecord{})
	e, err := s.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	full := e.Envelope
	full.Signatures = nil
	for range MaxSignatures {
		full.Signatures = append(full.Signatures, e.Envelope.Signatures[0])
	}
	if _, err := v.Verify(full); err != nil {
		t.Fatalf("%d signatures: %v", MaxSignatures, err)
	}
	over := full
	over.Signatures = append(append([]Signature(nil), full.Signatures...), e.Envelope.Signatures[0])
	if _, err := v.Verify(over); !errors.Is(err, ErrStatement) || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("%d signatures: %v, want ErrStatement", MaxSignatures+1, err)
	}
}

// Every field of a run record survives the predicate: predicateOf then record gives back
// the record it was given, every field set to a value other than its zero. A field added
// to sandbox.RunRecord and left out of either, or out of the predicate's JSON, fails here
// (before this test, predicateOf dropping the instance passed every attest test).
func TestThePredicateCarriesEveryRecordField(t *testing.T) {
	var r sandbox.RunRecord
	rv := reflect.ValueOf(&r).Elem()
	for i := range rv.NumField() {
		f, name := rv.Field(i), rv.Type().Field(i).Name
		switch {
		case f.Type() == reflect.TypeFor[time.Time]():
			// Whole milliseconds in UTC, as the wire carries them; a distinct time per field.
			f.Set(reflect.ValueOf(time.UnixMilli(1790000000000 + int64(i)*1001).UTC()))
		case f.Kind() == reflect.String:
			f.SetString("value of " + name)
		case f.Kind() == reflect.Int:
			f.SetInt(int64(100 + i))
		case f.Kind() == reflect.Uint64:
			f.SetUint(uint64(200 + i))
		case f.Kind() == reflect.Bool:
			f.SetBool(true)
		default:
			t.Fatalf("RunRecord.%s is a %s; this test cannot fill it yet, so it cannot prove the predicate carries it", name, f.Type())
		}
	}
	if back := predicateOf(r).record(); !reflect.DeepEqual(back, r) {
		t.Fatalf("predicateOf then record:\n got %+v\nwant %+v", back, r)
	}
	// Through the JSON a signature covers, and the strict reading a verifier makes.
	b, err := json.Marshal(predicateOf(r))
	if err != nil {
		t.Fatal(err)
	}
	var p Predicate
	if err := decodeStrict(b, &p); err != nil {
		t.Fatal(err)
	}
	if back := p.record(); !reflect.DeepEqual(back, r) {
		t.Fatalf("through the predicate's JSON:\n got %+v\nwant %+v", back, r)
	}
	// And each field alone: no other field's value can stand in for a dropped one.
	for i := range rv.NumField() {
		var one sandbox.RunRecord
		reflect.ValueOf(&one).Elem().Field(i).Set(rv.Field(i))
		if back := predicateOf(one).record(); !reflect.DeepEqual(back, one) {
			t.Errorf("RunRecord.%s alone does not survive the predicate: got %+v", rv.Type().Field(i).Name, back)
		}
	}
}
