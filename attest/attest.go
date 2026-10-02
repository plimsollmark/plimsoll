// Package attest is the harness's half of plimsoll's run records: it signs a
// checked record as a DSSE envelope around an in-toto Statement v1, verifies
// envelopes and whole bundles (signatures, digests, and each session's chain),
// and replays stored requests to compare results. It runs outside the daemon,
// which computes records (package record) and never holds a key: the daemon runs
// hostile code, so a key there would be one engine escape away from forging
// every record. Ed25519, SHA-256 and JSON from the standard library; no other
// dependency.
package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const (
	// PayloadType is the DSSE payload type of an in-toto statement.
	PayloadType = "application/vnd.in-toto+json"
	// StatementType is the in-toto Statement v1 type.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateType names a plimsoll run record as a predicate. Its fields and
	// encoding are docs/run-records.md.
	PredicateType = "https://plimsollmark.github.io/plimsoll/run-record/v1"
	// SubjectName is the one subject of a run-record statement: the record itself,
	// whose digest is the SHA-256 over its canonical encoding (not over a file).
	SubjectName = "run-record"
)

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64 (standard, padded) of the statement
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature; KeyID is the signer's KeyID.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64 of the Ed25519 signature over PAE
}

// Statement is an in-toto Statement v1 whose predicate is a run record.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Subject is an in-toto resource descriptor with a name and a digest set.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Predicate is a run record in the wire message's field names.
type Predicate struct {
	Version          int    `json:"version"`
	RequestSHA256    string `json:"request_sha256"`
	ResultSHA256     string `json:"result_sha256"`
	Provider         string `json:"provider"`
	Isolation        string `json:"isolation"`
	Environment      string `json:"environment"`
	SoftwareIdentity string `json:"software_identity,omitempty"`
	SoftwareRuleID   string `json:"software_rule_id,omitempty"`
	Policy           string `json:"policy"`
	StartedUnixMs    int64  `json:"started_unix_ms"`
	EndedUnixMs      int64  `json:"ended_unix_ms"`
	Session          string `json:"session"`
	Sequence         uint64 `json:"sequence"`
	PreviousSHA256   string `json:"previous_sha256"`
	Unanswered       string `json:"unanswered,omitempty"` // version 3 only
	RecordSHA256     string `json:"record_sha256"`
}

func predicateOf(r sandbox.RunRecord) Predicate {
	return Predicate{
		Version: r.Version, RequestSHA256: r.RequestSHA256, ResultSHA256: r.ResultSHA256,
		Provider: r.Provider, Isolation: r.Isolation, Environment: r.Environment, Policy: r.Policy,
		SoftwareIdentity: r.SoftwareIdentity, SoftwareRuleID: r.SoftwareRuleID,
		StartedUnixMs: r.Started.UnixMilli(), EndedUnixMs: r.Ended.UnixMilli(),
		Session: r.Session, Sequence: r.Sequence, PreviousSHA256: r.PreviousSHA256,
		Unanswered: r.Unanswered, RecordSHA256: r.SHA256,
	}
}

func (p Predicate) record() sandbox.RunRecord {
	return sandbox.RunRecord{
		Version: p.Version, RequestSHA256: p.RequestSHA256, ResultSHA256: p.ResultSHA256,
		Provider: p.Provider, Isolation: p.Isolation, Environment: p.Environment, Policy: p.Policy,
		SoftwareIdentity: p.SoftwareIdentity, SoftwareRuleID: p.SoftwareRuleID,
		Started: time.UnixMilli(p.StartedUnixMs).UTC(), Ended: time.UnixMilli(p.EndedUnixMs).UTC(),
		Session: p.Session, Sequence: p.Sequence, PreviousSHA256: p.PreviousSHA256,
		Unanswered: p.Unanswered, SHA256: p.RecordSHA256,
	}
}

// PAE is DSSE's pre-authentication encoding, the bytes a signature covers:
// "DSSEv1", the payload type and the payload, each length an ASCII decimal,
// separated by single spaces.
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// KeyID names a public key: lowercase hex SHA-256 of its PKIX DER encoding.
func KeyID(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// Signer signs run records with one Ed25519 key.
type Signer struct {
	key   ed25519.PrivateKey
	keyID string
}

// NewSigner returns a Signer for key.
func NewSigner(key ed25519.PrivateKey) *Signer {
	return &Signer{key: key, keyID: KeyID(key.Public().(ed25519.PublicKey))}
}

// KeyID is the signer's key ID.
func (s *Signer) KeyID() string { return s.keyID }

// ErrUnchecked means a record was handed to Sign without its own digest
// matching its fields. Sign signs only checked records (record.Check), whose
// content digests the caller has already recomputed from what it sent and
// received; this refusal catches a record assembled any other way.
var ErrUnchecked = errors.New("attest: the record's digest does not match its fields; sign only records record.Check returned")

// ErrSigningVersion means Sign was given a record version this harness no longer
// signs. Verification can still accept older signed records already in bundles.
var ErrSigningVersion = errors.New("attest: the harness only signs the current run record version")

// Sign wraps rec in an in-toto statement and signs it as a DSSE envelope: an
// answered call's record at record.Version, or an unanswered session call's at
// record.UnansweredVersion.
func (s *Signer) Sign(rec sandbox.RunRecord) (Envelope, error) {
	if (rec.Version != record.Version || rec.Unanswered != "") && (rec.Version != record.UnansweredVersion || rec.Unanswered == "") {
		return Envelope{}, fmt.Errorf("%w: got %d, current versions are %d and, for an unanswered call, %d", ErrSigningVersion, rec.Version, record.Version, record.UnansweredVersion)
	}
	if rec.SHA256 != record.Digest(rec) {
		return Envelope{}, ErrUnchecked
	}
	st := Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: SubjectName, Digest: map[string]string{"sha256": rec.SHA256}}},
		PredicateType: PredicateType,
		Predicate:     predicateOf(rec),
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

// Verifier checks envelopes against one Ed25519 public key.
type Verifier struct {
	pub   ed25519.PublicKey
	keyID string
}

// NewVerifier returns a Verifier for pub.
func NewVerifier(pub ed25519.PublicKey) *Verifier {
	return &Verifier{pub: pub, keyID: KeyID(pub)}
}

// ErrSignature means no signature in an envelope verifies under the key.
var ErrSignature = errors.New("attest: no valid signature from this key")

// ErrStatement means a verified payload is not a run-record statement this
// package accepts: another statement or predicate type, subjects other than the
// one record, or a record whose digest does not match its fields.
var ErrStatement = errors.New("attest: the payload is not a valid run-record statement")

// Verify checks the envelope's signature and statement and returns the record
// it carries. It proves who signed which record; checking the record against
// stored requests and results is VerifyBundle's.
func (v *Verifier) Verify(env Envelope) (sandbox.RunRecord, error) {
	payload, err := v.signedPayload(env)
	if err != nil {
		return sandbox.RunRecord{}, err
	}
	var st Statement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return sandbox.RunRecord{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if st.Type != StatementType || st.PredicateType != PredicateType || len(st.Subject) != 1 ||
		st.Subject[0].Name != SubjectName || len(st.Subject[0].Digest) != 1 {
		return sandbox.RunRecord{}, fmt.Errorf("%w: types or subjects", ErrStatement)
	}
	rec := st.Predicate.record()
	switch {
	case rec.Version != 1 && rec.Version != record.Version && rec.Version != record.UnansweredVersion:
		return sandbox.RunRecord{}, fmt.Errorf("%w: record version %d", ErrStatement, rec.Version)
	case (rec.Version == record.UnansweredVersion) != (rec.Unanswered != ""):
		return sandbox.RunRecord{}, fmt.Errorf("%w: only a version %d record names an unanswered call, and it must", ErrStatement, record.UnansweredVersion)
	}
	if rec.Version == 1 && (rec.SoftwareIdentity != "" || rec.SoftwareRuleID != "") {
		return sandbox.RunRecord{}, fmt.Errorf("%w: version 1 cannot carry software admission fields", ErrStatement)
	}
	if st.Subject[0].Digest["sha256"] != rec.SHA256 || rec.SHA256 != record.Digest(rec) {
		return sandbox.RunRecord{}, fmt.Errorf("%w: the record's digest does not match its fields or the subject", ErrStatement)
	}
	return rec, nil
}

// signedPayload returns an envelope's payload once a signature from this key
// verifies over it.
func (v *Verifier) signedPayload(env Envelope) ([]byte, error) {
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("%w: payload type %q", ErrStatement, env.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64: %v", ErrStatement, err)
	}
	for _, s := range env.Signatures {
		if s.KeyID != "" && s.KeyID != v.keyID {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err == nil && ed25519.Verify(v.pub, PAE(env.PayloadType, payload), sig) {
			return payload, nil
		}
	}
	return nil, ErrSignature
}

// GenerateKey makes an Ed25519 key pair and returns both halves PEM-encoded:
// the private key as PKCS #8, the public key as PKIX.
func GenerateKey() (privatePEM, publicPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}

// ParsePrivateKey reads a PEM PKCS #8 Ed25519 private key.
func ParsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("attest: no PEM PRIVATE KEY block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("attest: the private key is not Ed25519")
	}
	return priv, nil
}

// ParsePublicKey reads a PEM PKIX Ed25519 public key.
func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("attest: no PEM PUBLIC KEY block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("attest: the public key is not Ed25519")
	}
	return pub, nil
}
