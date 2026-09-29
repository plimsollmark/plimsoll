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
	if _, err := VerifyBundle([]Entry{entry}, verifier); err == nil {
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
	if _, err := VerifyBundle([]Entry{entry}, verifier); err == nil {
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

// A session is served by one daemon, so its chain has one record version. A version-1
// link states no software, so a chain mixing versions could hold a call that says
// nothing about what ran and still verify. Checking each stored exchange does not
// catch this: each link is valid alone.
func TestVerifyBundleRefusesMixedVersionChain(t *testing.T) {
	key := newKey(t)
	signer, verifier := NewSigner(key), NewVerifier(key.Public().(ed25519.PublicKey))
	fp := record.SessionFingerprint("a-session-id")

	// Call 1: version 1, no software fields.
	req1 := &plimsollv1.RunRequest{Protocol: 1,
		Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "one()"}}}
	resp1 := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "kernel",
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("1")}}}
	rec1 := sandbox.RunRecord{Version: 1,
		RequestSHA256: record.RunRequestDigest(req1), ResultSHA256: record.ResultDigest(resp1),
		Provider: "docker", Isolation: "kernel",
		Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000100),
		Session: fp, Sequence: 1}
	rec1.SHA256 = record.Digest(rec1)
	resp1.Record = record.ToWire(rec1)
	rb, _ := proto.Marshal(req1)
	pb, _ := proto.Marshal(resp1)
	e1 := Entry{Request: rb, Response: pb, Envelope: signV1(t, key, rec1)}

	// Call 2: version 2, under an exact rule, chained onto call 1.
	req2, resp2 := softwareExchange(idA, idA, envA)
	req2.Payload = &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "two()"}}
	resp2.Record = record.Stamp(sandbox.RunRecord{
		RequestSHA256:  record.RunRequestDigest(req2),
		SoftwareRuleID: sandbox.SoftwareRule{Mode: sandbox.SoftwareExact, Identities: []string{idA}}.ID(),
		Started:        time.UnixMilli(1790000000200), Ended: time.UnixMilli(1790000000300),
		Session: fp, Sequence: 2, PreviousSHA256: rec1.SHA256}, resp2)
	e2, err := signer.Call(req2, resp2)
	if err != nil {
		t.Fatal(err)
	}
	ce, err := signer.Close(SessionClose{Session: fp, Calls: 2,
		LastRecordSHA256: resp2.GetRecord().GetRecordSha256()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle([]Entry{e1, e2, ce}, verifier); err == nil {
		t.Fatal("VerifyBundle accepted a session chain mixing record versions 1 and 2")
	}
}
