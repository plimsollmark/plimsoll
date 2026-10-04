package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const idA = "oci-manifest:linux/amd64@sha256:1111111111111111111111111111111111111111111111111111111111111111"
const idB = "oci-manifest:linux/amd64@sha256:2222222222222222222222222222222222222222222222222222222222222222"
const envA = "docker-image:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const envB = "docker-image:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// softwareExchange is a protocol-2 exchange under an exact rule naming ruleID,
// whose response states identity and env, with the record a daemon stamps.
func softwareExchange(ruleID, identity, env string) (*plimsollv1.RunRequest, *plimsollv1.RunResponse) {
	req := &plimsollv1.RunRequest{Protocol: 2,
		SoftwareRule: &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{ruleID}},
		Payload:      &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "kernel",
		Environment: env, SoftwareIdentity: identity,
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("ok")}}}
	resp.Record = record.Stamp(sandbox.RunRecord{
		RequestSHA256:  record.RunRequestDigest(req),
		SoftwareRuleID: sandbox.SoftwareRule{Mode: sandbox.SoftwareExact, Identities: []string{ruleID}}.ID(),
		Started:        time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000100),
	}, resp)
	return req, resp
}

func TestVerifyBundleRefusesTamperedResponseSoftware(t *testing.T) {
	key := newKey(t)
	signer, verifier := NewSigner(key), NewVerifier(key.Public().(ed25519.PublicKey))
	req, resp := softwareExchange(idA, idA, envA)
	entry, err := signer.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	bad := proto.Clone(resp).(*plimsollv1.RunResponse)
	bad.SoftwareIdentity, bad.Environment = idB, envB
	if entry.Response, err = proto.Marshal(bad); err != nil {
		t.Fatal(err)
	}
	if _, err := record.Check(req, bad); !errors.Is(err, record.ErrMismatch) {
		t.Fatalf("the live client must refuse this: %v", err)
	}
	if _, err := VerifyBundle(seal(t, signer, entry), verifier); err == nil {
		t.Fatal("VerifyBundle accepted a response stating software the signed record does not")
	}
}

func TestVerifyBundleRefusesRuleIdentityMismatch(t *testing.T) {
	key := newKey(t)
	signer, verifier := NewSigner(key), NewVerifier(key.Public().(ed25519.PublicKey))
	req, resp := softwareExchange(idA, idB, envA) // rule requires idA, the run states idB
	if _, err := record.CheckExchange(req, resp); !errors.Is(err, record.ErrMismatch) {
		t.Fatalf("CheckExchange must refuse this: %v", err)
	}
	entry, err := signer.entry(req, resp, record.FromWire(resp.GetRecord()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(seal(t, signer, entry), verifier); err == nil {
		t.Fatal("VerifyBundle accepted a record whose identity is outside the request's rule")
	}
}

// signV1 signs a version-1 record the way a v0.11.1 harness would, with the same
// key: Sign refuses version 1 now, so the envelope is built directly.
func signV1(t *testing.T, key ed25519.PrivateKey, rec sandbox.RunRecord) Envelope {
	t.Helper()
	st := Statement{Type: StatementType,
		Subject:       []Subject{{Name: SubjectName, Digest: map[string]string{"sha256": rec.SHA256}}},
		PredicateType: PredicateType, Predicate: predicateOf(rec)}
	payload, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, PAE(PayloadType, payload))
	return Envelope{PayloadType: PayloadType,
		Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{KeyID: KeyID(key.Public().(ed25519.PublicKey)),
			Sig: base64.StdEncoding.EncodeToString(sig)}}}
}

// A version-1 record states no software, and no bundle that verifies now (bundles
// carry links since F7) can hold one, so none is accepted.
func TestVerifyRefusesVersionOneRecords(t *testing.T) {
	key := newKey(t)
	verifier := NewVerifier(key.Public().(ed25519.PublicKey))
	req := &plimsollv1.RunRequest{Protocol: 1,
		Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "one()"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "kernel",
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("1")}}}
	rec := sandbox.RunRecord{Version: 1,
		RequestSHA256: record.RunRequestDigest(req), ResultSHA256: record.ResultDigest(resp),
		Provider: "docker", Isolation: "kernel",
		Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000100)}
	rec.SHA256 = record.Digest(rec)
	if _, err := verifier.Verify(signV1(t, key, rec)); !errors.Is(err, ErrStatement) {
		t.Fatalf("a version 1 record: %v; want refused: a bundle signs version 2 and 3 only", err)
	}
}
