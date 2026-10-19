package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrReservedPredicate means SignStatement or OpenStatement was given a predicate
// type this package handles only through its own checked paths: a run record (Sign,
// Verify), a bundle link and a session close. A generic signer could otherwise put
// the harness's signature on a run record nobody checked.
var ErrReservedPredicate = errors.New("attest: this predicate type is signed and verified only through its own checked path")

// reserved are the predicate types SignStatement and OpenStatement refuse.
var reserved = map[string]bool{PredicateType: true, LinkPredicateType: true, ClosePredicateType: true}

// statement is an in-toto Statement v1 with any predicate, as SignStatement encodes it.
type statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     any       `json:"predicate"`
}

// openedStatement is a statement as OpenStatement reads it, the predicate kept raw
// until the statement's own fields are checked.
type openedStatement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// SignStatement signs an in-toto statement of predicateType about subjects, with
// predicate encoded by encoding/json, as a DSSE envelope in the encoding Sign uses
// for run records. It is for statements a harness makes about runs it has checked
// (a verdict bound to run records, say): the subjects name what the statement is
// about, usually run records by their digest. It refuses the reserved predicate
// types, an empty predicate type, and subjects OpenStatement would refuse.
func (s *Signer) SignStatement(predicateType string, subjects []Subject, predicate any) (Envelope, error) {
	if reserved[predicateType] {
		return Envelope{}, fmt.Errorf("%w: %s", ErrReservedPredicate, predicateType)
	}
	if predicateType == "" {
		return Envelope{}, errors.New("attest: a statement needs a predicate type")
	}
	if err := checkSubjects(subjects); err != nil {
		return Envelope{}, err
	}
	payload, err := json.Marshal(statement{Type: StatementType, Subject: subjects, PredicateType: predicateType, Predicate: predicate})
	if err != nil {
		return Envelope{}, err
	}
	if !predicatePresent(payload) {
		return Envelope{}, errors.New("attest: the predicate encodes as null")
	}
	return s.envelope(payload), nil
}

// OpenStatement checks env's signature by this verifier's key and that it carries an
// in-toto statement of predicateType, decodes the predicate into predicate (a
// pointer), refusing any field predicate does not have, and returns the subjects.
// It proves who signed which statement; what the predicate claims is the caller's
// to check against the subjects.
func (v *Verifier) OpenStatement(env Envelope, predicateType string, predicate any) ([]Subject, error) {
	if reserved[predicateType] {
		return nil, fmt.Errorf("%w: %s", ErrReservedPredicate, predicateType)
	}
	payload, err := v.signedPayload(env)
	if err != nil {
		return nil, err
	}
	var st openedStatement
	if err := decodeStrict(payload, &st); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if st.Type != StatementType || st.PredicateType != predicateType {
		return nil, fmt.Errorf("%w: statement type %q, predicate type %q", ErrStatement, st.Type, st.PredicateType)
	}
	if err := checkSubjects(st.Subject); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if !predicatePresent(payload) {
		return nil, fmt.Errorf("%w: no predicate", ErrStatement)
	}
	if err := decodeStrict(st.Predicate, predicate); err != nil {
		return nil, fmt.Errorf("%w: predicate: %v", ErrStatement, err)
	}
	return st.Subject, nil
}

// checkSubjects requires at least one subject, each named, with at least one digest,
// every digest value non-empty and a sha256 one 64 lowercase hex digits.
func checkSubjects(subjects []Subject) error {
	if len(subjects) == 0 {
		return errors.New("attest: a statement needs at least one subject")
	}
	for i, s := range subjects {
		if s.Name == "" || len(s.Digest) == 0 {
			return fmt.Errorf("attest: subject %d has no name or no digest", i+1)
		}
		for alg, d := range s.Digest {
			if alg == "" || d == "" || (alg == "sha256" && !isSHA256Hex(d)) {
				return fmt.Errorf("attest: subject %d's %q digest is not well formed", i+1, alg)
			}
		}
	}
	return nil
}

// predicatePresent reports whether a statement's predicate member exists and is not
// null; a null predicate would decode into any pointer as its zero value.
func predicatePresent(payload []byte) bool {
	var st struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	return json.Unmarshal(payload, &st) == nil && len(st.Predicate) > 0 && !bytes.Equal(bytes.TrimSpace(st.Predicate), []byte("null"))
}

// decodeStrict decodes exactly one JSON value from data into v, refusing unknown
// fields and anything after the value.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}

// envelope signs payload, an encoded in-toto statement, as a DSSE envelope with one
// signature by this key. Every statement this package signs goes through it.
func (s *Signer) envelope(payload []byte) Envelope {
	sig := ed25519.Sign(s.key, PAE(PayloadType, payload))
	return Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: s.keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
}
