package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// signedPredicate signs a run-record statement over the verified record of a fresh run,
// with its predicate's version set to version and, when extra is true, one field this
// release does not know added to the predicate.
func signedPredicate(t *testing.T, s *Signer, version int, extra bool) Envelope {
	t.Helper()
	_, resp := exchange("console.log(1)", "1\n", sandbox.RunRecord{})
	rec := record.FromWire(resp.GetRecord())
	p := predicateOf(rec)
	p.Version = version
	payload, err := json.Marshal(Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: SubjectName, Digest: map[string]string{"sha256": rec.SHA256}}},
		PredicateType: PredicateType,
		Predicate:     p,
	})
	if err != nil {
		t.Fatal(err)
	}
	if extra {
		payload = bytes.Replace(payload, []byte(`"predicate":{`), []byte(`"predicate":{"future_field":"a newer release states this",`), 1)
		if !bytes.Contains(payload, []byte("future_field")) {
			t.Fatal("the extra field was not added")
		}
	}
	return s.envelope(payload)
}

// A record of a version this verifier does not read answers "upgrade the verifier"
// (record.ErrVersion), whether or not it states a field this release does not know: every
// record version so far has added fields, so a newer record usually does (hunt-quality-28).
// A record of a version it reads is still read strictly: an unknown field there is an
// invalid statement, not a newer one.
func TestANewerRecordAsksForANewerVerifierEvenWithNewFields(t *testing.T) {
	s, v := newKeyPair(t)
	newer := record.Version + 1
	for name, c := range map[string]struct {
		version int
		extra   bool
		want    error
	}{
		"a newer version with this release's fields":    {newer, false, record.ErrVersion},
		"a newer version with a field this one lacks":   {newer, true, record.ErrVersion},
		"version zero, which no release wrote":          {0, true, record.ErrVersion},
		"the current version with an unknown field":     {record.Version, true, ErrStatement},
		"the current version, as signed by the harness": {record.Version, false, nil},
	} {
		_, err := v.Verify(signedPredicate(t, s, c.version, c.extra))
		switch {
		case c.want == nil && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%s: %v, want %v", name, err, c.want)
		case errors.Is(c.want, record.ErrVersion) && errors.Is(err, ErrStatement):
			t.Errorf("%s: %v also reads as an invalid statement", name, err)
		}
	}
	// Only a signed payload's version is read: another key's envelope is still ErrSignature.
	other, _ := newKeyPair(t)
	if _, err := v.Verify(signedPredicate(t, other, newer, true)); !errors.Is(err, ErrSignature) {
		t.Errorf("another key's newer record: %v, want ErrSignature", err)
	}
}
