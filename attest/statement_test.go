package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const testPredicateType = "https://example.com/verdict/v1"

type testVerdict struct {
	Verdict string `json:"verdict"`
	Runs    int    `json:"runs"`
}

var testSubject = []Subject{{Name: SubjectName, Digest: map[string]string{"sha256": strings.Repeat("ab", 32)}}}

func TestStatementRoundTrip(t *testing.T) {
	key := newKey(t)
	env, err := NewSigner(key).SignStatement(testPredicateType, testSubject, testVerdict{Verdict: "pass", Runs: 4})
	if err != nil {
		t.Fatal(err)
	}
	var got testVerdict
	subjects, err := NewVerifier(publicOf(key)).OpenStatement(env, testPredicateType, &got)
	if err != nil {
		t.Fatal(err)
	}
	if got != (testVerdict{Verdict: "pass", Runs: 4}) || len(subjects) != 1 || subjects[0].Digest["sha256"] != testSubject[0].Digest["sha256"] {
		t.Fatalf("opened %+v about %+v", got, subjects)
	}
}

func TestStatementRejectsRepeatedJSONNames(t *testing.T) {
	key := newKey(t)
	s, v := NewSigner(key), NewVerifier(publicOf(key))
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"passed":false,"passed":true}`),
		json.RawMessage(`{"nested":[{"passed":false,"\u0070assed":true}]}`),
	} {
		if _, err := s.SignStatement(testPredicateType, testSubject, raw); err == nil {
			t.Errorf("signed a predicate with repeated names: %s", raw)
		}
		// A trusted key can be used outside SignStatement; opening must check too.
		payload, err := json.Marshal(statement{Type: StatementType, Subject: testSubject, PredicateType: testPredicateType, Predicate: raw})
		if err != nil {
			t.Fatal(err)
		}
		var got json.RawMessage
		if _, err := v.OpenStatement(s.envelope(payload), testPredicateType, &got); err == nil {
			t.Errorf("opened an externally signed predicate with repeated names: %s", raw)
		}
	}
	// Case-sensitive schema names and numbers outside float64's range remain valid.
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"x":1,"X":2,"nested":[{},[],{"n":1e5000}]}`),
		json.RawMessage(`[]`), json.RawMessage(`true`),
	} {
		env, err := s.SignStatement(testPredicateType, testSubject, raw)
		if err != nil {
			t.Fatalf("valid predicate refused: %s: %v", raw, err)
		}
		var got json.RawMessage
		if _, err := v.OpenStatement(env, testPredicateType, &got); err != nil {
			t.Fatalf("valid predicate could not be opened: %s: %v", raw, err)
		}
	}
}

func TestStatementRefusals(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(publicOf(key))
	good, err := s.SignStatement(testPredicateType, testSubject, testVerdict{Verdict: "pass"})
	if err != nil {
		t.Fatal(err)
	}
	// A payload re-encoded with its signature kept: what an edit by someone without the
	// key looks like.
	edited := func(from, to string) Envelope {
		payload, _ := base64.StdEncoding.DecodeString(good.Payload)
		out := good
		out.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(payload), from, to, 1)))
		return out
	}
	// A statement signed over a payload this package would never produce.
	signedRaw := func(payload string) Envelope { return s.envelope([]byte(payload)) }
	sub := `"subject":[{"name":"run-record","digest":{"sha256":"` + strings.Repeat("ab", 32) + `"}}]`
	for _, c := range []struct {
		name string
		env  Envelope
		typ  string
		want error
	}{
		{"an edited verdict", edited(`"pass"`, `"fail"`), testPredicateType, ErrSignature},
		{"another key", mustSign(t, NewSigner(newKey(t)), testPredicateType, testSubject), testPredicateType, ErrSignature},
		{"another predicate type", good, "https://example.com/other/v1", ErrStatement},
		{"a run record's type", good, PredicateType, ErrReservedPredicate},
		{"an unknown predicate field", signedRaw(`{"_type":"` + StatementType + `",` + sub + `,"predicateType":"` + testPredicateType + `","predicate":{"verdict":"pass","extra":1}}`), testPredicateType, ErrStatement},
		{"an unknown statement field", signedRaw(`{"_type":"` + StatementType + `",` + sub + `,"predicateType":"` + testPredicateType + `","predicate":{},"x":1}`), testPredicateType, ErrStatement},
		{"a null predicate", signedRaw(`{"_type":"` + StatementType + `",` + sub + `,"predicateType":"` + testPredicateType + `","predicate":null}`), testPredicateType, ErrStatement},
		{"no predicate", signedRaw(`{"_type":"` + StatementType + `",` + sub + `,"predicateType":"` + testPredicateType + `"}`), testPredicateType, ErrStatement},
		{"no subject", signedRaw(`{"_type":"` + StatementType + `","subject":[],"predicateType":"` + testPredicateType + `","predicate":{}}`), testPredicateType, ErrStatement},
		{"a short digest", signedRaw(`{"_type":"` + StatementType + `","subject":[{"name":"x","digest":{"sha256":"ab"}}],"predicateType":"` + testPredicateType + `","predicate":{}}`), testPredicateType, ErrStatement},
		{"data after the statement", signedRaw(`{"_type":"` + StatementType + `",` + sub + `,"predicateType":"` + testPredicateType + `","predicate":{}} {}`), testPredicateType, ErrStatement},
		{"another statement type", signedRaw(`{"_type":"https://in-toto.io/Statement/v0.1",` + sub + `,"predicateType":"` + testPredicateType + `","predicate":{}}`), testPredicateType, ErrStatement},
	} {
		var p testVerdict
		if _, err := v.OpenStatement(c.env, c.typ, &p); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestSignStatementRefusals(t *testing.T) {
	s := NewSigner(newKey(t))
	for _, typ := range []string{PredicateType, LinkPredicateType, ClosePredicateType} {
		if _, err := s.SignStatement(typ, testSubject, testVerdict{}); !errors.Is(err, ErrReservedPredicate) {
			t.Errorf("%s: got %v, want ErrReservedPredicate", typ, err)
		}
	}
	for name, c := range map[string]struct {
		typ      string
		subjects []Subject
		pred     any
	}{
		"no predicate type":   {"", testSubject, testVerdict{}},
		"no subject":          {testPredicateType, nil, testVerdict{}},
		"an unnamed subject":  {testPredicateType, []Subject{{Digest: map[string]string{"sha256": strings.Repeat("ab", 32)}}}, testVerdict{}},
		"no digest":           {testPredicateType, []Subject{{Name: "x"}}, testVerdict{}},
		"an uppercase digest": {testPredicateType, []Subject{{Name: "x", Digest: map[string]string{"sha256": strings.Repeat("AB", 32)}}}, testVerdict{}},
		"a nil predicate":     {testPredicateType, testSubject, nil},
	} {
		if _, err := s.SignStatement(c.typ, c.subjects, c.pred); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func mustSign(t *testing.T, s *Signer, typ string, subjects []Subject) Envelope {
	t.Helper()
	env, err := s.SignStatement(typ, subjects, testVerdict{Verdict: "pass"})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func publicOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// Every verifier reads a signed payload one way: a name respelled in another case, which
// encoding/json would accept as the same field, is refused, whether it repeats a field
// (two readings of one payload) or stands alone. Each payload is re-signed by the
// trusted key, so only the decoding stands between it and acceptance.
func TestVerifiersRefuseNamesSpelledAnotherWay(t *testing.T) {
	key := newKey(t)
	s, v := NewSigner(key), NewVerifier(publicOf(key))
	_, resp := exchange("x()", "out", sandbox.RunRecord{})
	run, err := s.Sign(record.FromWire(resp.GetRecord()))
	if err != nil {
		t.Fatal(err)
	}
	closed, err := s.Close(SessionClose{Session: record.SessionFingerprint("s"), Calls: 1, LastRecordSHA256: strings.Repeat("cd", 32)})
	if err != nil {
		t.Fatal(err)
	}
	link := *seal(t, s, traced(t, s, "a"))[0].Link
	stmt, err := s.SignStatement(testPredicateType, testSubject, testVerdict{Verdict: "pass", Runs: 1})
	if err != nil {
		t.Fatal(err)
	}
	verifiers := map[string]struct {
		env    Envelope
		verify func(Envelope) error
	}{
		"run record":    {run, func(e Envelope) error { _, err := v.Verify(e); return err }},
		"session close": {closed.Envelope, func(e Envelope) error { _, err := v.VerifyClose(e); return err }},
		"bundle link":   {link, func(e Envelope) error { _, err := v.VerifyLink(e); return err }},
		"statement": {stmt, func(e Envelope) error {
			var got testVerdict
			_, err := v.OpenStatement(e, testPredicateType, &got)
			return err
		}},
	}
	for name, c := range verifiers {
		payload, err := v.signedPayload(c.env)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.verify(s.envelope(payload)); err != nil {
			t.Fatalf("%s: the payload as signed is refused: %v", name, err)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(payload, &top); err != nil {
			t.Fatal(err)
		}
		variants := map[string][]byte{
			"a second predicate spelled Predicate": append(append(bytes.TrimSuffix(payload, []byte("}")), `,"Predicate":`...), append(top["predicate"], '}')...),
			"the subject's name spelled Name":      bytes.Replace(payload, []byte(`"name":`), []byte(`"Name":`), 1),
			"_type spelled _TYPE":                  bytes.Replace(payload, []byte(`"_type":`), []byte(`"_TYPE":`), 1),
		}
		for what, p := range variants {
			if bytes.Equal(p, payload) {
				t.Fatalf("%s: variant %q changed nothing", name, what)
			}
			if err := c.verify(s.envelope(p)); err == nil {
				t.Errorf("%s: accepted %s: %s", name, what, p)
			}
		}
	}
}
