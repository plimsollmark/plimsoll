package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
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
	if err := uniqueJSONKeys(payload); err != nil {
		return Envelope{}, fmt.Errorf("attest: %w", err)
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
// uniqueJSONKeys refuses ambiguous objects, including inside an opaque RawMessage
// predicate. Signatures bind bytes; readers must not disagree about repeated names.
// Names are case-sensitive as JSON specifies, so distinct schema keys stay distinct.
func uniqueJSONKeys(data []byte) error {
	// Valid checks one complete value and the standard decoder's nesting bound.
	if !json.Valid(data) {
		return errors.New("invalid JSON statement")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type object struct {
		keys map[string]bool // nil for an array
		key  bool            // the next string is an object's name, not a value
	}
	var stack []object
	for {
		token, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok && (delimiter == '}' || delimiter == ']') {
			stack = stack[:len(stack)-1]
			continue
		}
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.keys != nil {
				if top.key {
					name := token.(string) // Valid and Token enforce an object's name here.
					if top.keys[name] {
						return fmt.Errorf("repeated JSON object name %q", name)
					}
					top.keys[name], top.key = true, false
					continue
				}
				top.key = true
			}
		}
		switch token {
		case json.Delim('{'):
			stack = append(stack, object{keys: map[string]bool{}, key: true})
		case json.Delim('['):
			stack = append(stack, object{})
		}
	}
}

// decodeStrict decodes data, one JSON value, into v, refusing unknown fields and data
// after the value.
//
// Every verifier in this package decodes a signed payload through it, so the payload
// reads one way to every reader of the same bytes: no name repeated at any depth
// (uniqueJSONKeys), and every name of an object one of this package's own types defines
// spelled exactly as the type spells it. encoding/json matches names regardless of case
// and keeps the last of two, so without the second rule a payload signed with both
// "predicate" and "Predicate" would say one thing here and another to an in-toto
// verifier. Objects held raw (json.RawMessage) or as maps are data, not schema: their
// names are checked for repeats only, so a predicate schema in which "x" and "X" are
// different fields stays valid.
func decodeStrict(data []byte, v any) error {
	if err := uniqueJSONKeys(data); err != nil {
		return err
	}
	var value any
	generic := json.NewDecoder(bytes.NewReader(data))
	generic.UseNumber()
	if err := generic.Decode(&value); err != nil {
		return err
	}
	if err := exactNames(value, reflect.TypeOf(v)); err != nil {
		return err
	}
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

var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

// exactNames walks value, one decoded JSON value, beside t, the Go type it is decoded
// into, and refuses an object name t's struct does not spell exactly. A value of the
// wrong shape is left for the decoder to refuse.
func exactNames(value any, t reflect.Type) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t == rawMessageType {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		fields := jsonFields(t)
		for name, inner := range object {
			field, ok := fields[name]
			if !ok {
				return fmt.Errorf("JSON object name %q is not one this schema spells", name)
			}
			if err := exactNames(inner, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		items, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, inner := range items {
			if err := exactNames(inner, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		for _, inner := range object {
			if err := exactNames(inner, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// jsonFields is the names encoding/json gives t's fields, as written, each with its
// type; an untagged embedded struct's fields are promoted, and the outer name wins.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" || (!f.IsExported() && !f.Anonymous) {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" && f.Anonymous {
			embedded := f.Type
			if embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				for n, ft := range jsonFields(embedded) {
					if _, taken := fields[n]; !taken {
						fields[n] = ft
					}
				}
				continue
			}
		}
		if name == "" {
			name = f.Name
		}
		fields[name] = f.Type
	}
	return fields
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
