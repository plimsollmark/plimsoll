package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
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
