// Package receipt checks role-bound signed assertions and timestamps offline.
// Trusted policy is an input established by the consumer, never taken from evidence.
// A successful check authenticates assertions; it does not reproduce their claims.
package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/attest/tsa"
)

// MaxBytes bounds each receipt or policy before JSON decoding. One MiB accommodates
// up to eight ordinary signed assertions and certificate chains without unbounded input.
const MaxBytes = 1 << 20

const maxRoles = 8

// Policy names the one expected artifact and every required role. Its origin must be
// authenticated outside the supplied receipt. Version is 1, the receipt profile version.
type Policy struct {
	Version int            `json:"version"`
	Subject attest.Subject `json:"subject"`
	Roles   []Role         `json:"roles"`
}

// Role pins an Ed25519 public key, assertion type and timestamp roots for a role.
// The name is a policy label, not evidence of a person's organizational identity.
type Role struct {
	Name              string `json:"name"`
	PredicateType     string `json:"predicate_type"`
	PublicKeyPEM      string `json:"public_key_pem"`
	TimestampRootsPEM string `json:"timestamp_roots_pem"`
}

// Receipt groups standard objects. Byte slices use JSON base64 strings, preserving
// the exact envelope file, including its signature, for the timestamp's message imprint.
type Receipt struct {
	Version      int           `json:"version"`
	Endorsements []Endorsement `json:"endorsements"`
}

// Endorsement carries one DSSE envelope file and an RFC 3161 TimeStampResp over
// SHA-256 of those exact file bytes. It carries no trusted key or root configuration.
type Endorsement struct {
	Role      string `json:"role"`
	Envelope  []byte `json:"envelope"`
	Timestamp []byte `json:"timestamp"`
}

// Report records checked identities and the assertions they signed, without claiming
// the assertions were independently reproduced or the roles independently controlled.
type Report struct {
	Subject             attest.Subject `json:"subject"`
	DistinctSigningKeys int            `json:"distinct_signing_keys"`
	Assertions          []Assertion    `json:"assertions"`
}

// Assertion is an authenticated assertion with its authority's claimed time. Accuracy
// is omitted when zero or unstated, never interpreted as a perfectly accurate clock.
type Assertion struct {
	Role           string          `json:"role"`
	KeyID          string          `json:"keyid"`
	PredicateType  string          `json:"predicate_type"`
	Predicate      json.RawMessage `json:"predicate"`
	WitnessedAt    time.Time       `json:"witnessed_at"`
	Accuracy       string          `json:"accuracy,omitempty"`
	TimestampRoot  string          `json:"timestamp_root_sha256"`
	EnvelopeSHA256 string          `json:"envelope_sha256"`
}

// Verify checks exactly the policy's roles against exactly its expected artifact.
// Both inputs are bounded and strict: unknown, duplicate and differently cased schema
// fields are refused. There are no file, network, system-root or embedded-trust lookups.
// No partial report is returned on error. It deliberately does not enforce a deadline,
// refresh revocation information, or evaluate application-specific predicate contents.
func Verify(receiptJSON, trustedPolicyJSON []byte) (Report, error) {
	var policy Policy
	if err := decode(trustedPolicyJSON, &policy, "version", "subject", "roles"); err != nil {
		return Report{}, fmt.Errorf("receipt: trusted policy: %w", err)
	}
	var evidence Receipt
	if err := decode(receiptJSON, &evidence, "version", "endorsements"); err != nil {
		return Report{}, fmt.Errorf("receipt: evidence: %w", err)
	}
	if policy.Version != 1 || evidence.Version != 1 {
		return Report{}, errors.New("receipt: policy and receipt versions must be 1")
	}
	if len(policy.Roles) == 0 || len(policy.Roles) > maxRoles || len(evidence.Endorsements) != len(policy.Roles) {
		return Report{}, errors.New("receipt: require 1 to 8 policy roles and exactly one endorsement for each")
	}
	var subjectFields struct {
		Subject json.RawMessage `json:"subject"`
	}
	if err := json.Unmarshal(trustedPolicyJSON, &subjectFields); err != nil {
		return Report{}, err
	}
	if err := checkSubject(subjectFields.Subject); err != nil {
		return Report{}, fmt.Errorf("receipt: expected subject: %w", err)
	}
	var rawPolicy struct {
		Roles []json.RawMessage `json:"roles"`
	}
	var rawEvidence struct {
		Endorsements []json.RawMessage `json:"endorsements"`
	}
	_ = json.Unmarshal(trustedPolicyJSON, &rawPolicy)
	_ = json.Unmarshal(receiptJSON, &rawEvidence)
	for _, raw := range rawPolicy.Roles {
		var role Role
		if err := decode(raw, &role, "name", "predicate_type", "public_key_pem", "timestamp_roots_pem"); err != nil {
			return Report{}, fmt.Errorf("receipt: policy role: %w", err)
		}
	}
	byRole := make(map[string]Endorsement)
	for _, raw := range rawEvidence.Endorsements {
		// Decode transport fields as strings: encoding/json also accepts number
		// arrays for []byte, which this base64-only profile deliberately refuses.
		var wire struct {
			Role      string `json:"role"`
			Envelope  string `json:"envelope"`
			Timestamp string `json:"timestamp"`
		}
		if err := decode(raw, &wire, "role", "envelope", "timestamp"); err != nil {
			return Report{}, fmt.Errorf("receipt: endorsement: %w", err)
		}
		envelope, err := base64.StdEncoding.Strict().DecodeString(wire.Envelope)
		if err != nil {
			return Report{}, fmt.Errorf("receipt: envelope base64: %w", err)
		}
		timestamp, err := base64.StdEncoding.Strict().DecodeString(wire.Timestamp)
		if err != nil {
			return Report{}, fmt.Errorf("receipt: timestamp base64: %w", err)
		}
		e := Endorsement{Role: wire.Role, Envelope: envelope, Timestamp: timestamp}
		if _, exists := byRole[e.Role]; exists {
			return Report{}, fmt.Errorf("receipt: repeated endorsement role %q", e.Role)
		}
		byRole[e.Role] = e
	}
	report := Report{Subject: policy.Subject}
	keys, roles := map[string]bool{}, map[string]bool{}
	for _, role := range policy.Roles {
		typeURI, typeErr := url.Parse(role.PredicateType)
		if !validRole(role.Name) || roles[role.Name] || typeErr != nil || typeURI.Scheme == "" {
			return Report{}, errors.New("receipt: invalid or repeated policy role, or missing assertion type")
		}
		roles[role.Name] = true
		e, ok := byRole[role.Name]
		if !ok {
			return Report{}, fmt.Errorf("receipt: missing endorsement for %q", role.Name)
		}
		assertion, err := verifyRole(e, role, policy.Subject)
		if err != nil {
			return Report{}, fmt.Errorf("receipt: role %q: %w", role.Name, err)
		}
		keys[assertion.KeyID] = true
		report.Assertions = append(report.Assertions, assertion)
	}
	report.DistinctSigningKeys = len(keys)
	return report, nil
}

func verifyRole(e Endorsement, role Role, expected attest.Subject) (Assertion, error) {
	pub, err := attest.ParsePublicKey([]byte(role.PublicKeyPEM))
	if err != nil {
		return Assertion{}, err
	}
	roots, err := tsa.ParseRoots([]byte(role.TimestampRootsPEM))
	if err != nil {
		return Assertion{}, err
	}
	var env attest.Envelope
	if err := decode(e.Envelope, &env, "payloadType", "payload", "signatures"); err != nil {
		return Assertion{}, fmt.Errorf("envelope: %w", err)
	}
	if len(env.Signatures) != 1 {
		return Assertion{}, errors.New("each role envelope must contain exactly one signature")
	}
	var rawEnv struct {
		Signatures []json.RawMessage `json:"signatures"`
	}
	_ = json.Unmarshal(e.Envelope, &rawEnv)
	var sig attest.Signature
	if err := decode(rawEnv.Signatures[0], &sig, "keyid", "sig"); err != nil {
		return Assertion{}, err
	}
	var predicate json.RawMessage
	subjects, err := attest.NewVerifier(pub).OpenStatement(env, role.PredicateType, &predicate)
	if err != nil {
		return Assertion{}, err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(predicate), []byte("{")) {
		return Assertion{}, errors.New("statement predicate must be a JSON object")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Assertion{}, err
	}
	var statement struct {
		Subject []json.RawMessage `json:"subject"`
	}
	if err := decode(payload, &statement, "_type", "subject", "predicateType", "predicate"); err != nil {
		return Assertion{}, err
	}
	if len(subjects) != 1 || subjects[0].Name != expected.Name || len(subjects[0].Digest) != 1 || subjects[0].Digest["sha256"] != expected.Digest["sha256"] {
		return Assertion{}, errors.New("statement must name exactly the expected subject and SHA-256 digest")
	}
	if err := checkSubject(statement.Subject[0]); err != nil {
		return Assertion{}, err
	}
	digest := sha256.Sum256(e.Envelope)
	tok, err := tsa.Verify(e.Timestamp, digest[:], nil, roots)
	if err != nil {
		return Assertion{}, err
	}
	result := Assertion{
		Role: role.Name, KeyID: attest.KeyID(pub), PredicateType: role.PredicateType,
		Predicate: predicate, WitnessedAt: tok.Time, TimestampRoot: tok.RootSHA256,
		EnvelopeSHA256: hex.EncodeToString(digest[:]),
	}
	if tok.Accuracy > 0 {
		result.Accuracy = tok.Accuracy.String()
	}
	return result, nil
}

func checkSubject(raw []byte) error {
	var s struct {
		Name   string          `json:"name"`
		Digest json.RawMessage `json:"digest"`
	}
	if err := decode(raw, &s, "name", "digest"); err != nil {
		return err
	}
	var d map[string]string
	if err := decode(s.Digest, &d, "sha256"); err != nil {
		return err
	}
	digest := d["sha256"]
	b, err := hex.DecodeString(digest)
	if s.Name == "" || err != nil || len(b) != sha256.Size || digest != strings.ToLower(digest) {
		return errors.New("subject needs a name and one lowercase SHA-256 digest")
	}
	return nil
}

// decode requires every named field with its exact spelling and a non-null value.
// The consuming schema checks field meanings without Go's case folding.
func decode(data []byte, v any, fields ...string) error {
	if len(data) == 0 || len(data) > MaxBytes || !utf8.Valid(data) {
		return errors.New("JSON object is empty, exceeds 1 MiB or is not UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("expected a JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return errors.New("repeated or invalid JSON field")
		}
		found := false
		for _, allowed := range fields {
			found = found || key == allowed
		}
		if !found {
			return fmt.Errorf("unknown JSON field %q", key)
		}
		seen[key] = true
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return err
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("null JSON field %q", key)
		}
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("data after JSON object")
	}
	for _, field := range fields {
		if !seen[field] {
			return fmt.Errorf("missing JSON field %q", field)
		}
	}
	return json.Unmarshal(data, v)
}

func validRole(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
