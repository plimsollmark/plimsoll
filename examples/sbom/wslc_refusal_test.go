package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/sbom/cdxutil"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// wslcRun is one WSL containers project run's request and answer, stating sentence.
func wslcRun(sentence string) (*plimsollv1.RunRequest, *plimsollv1.RunResponse) {
	req := &plimsollv1.RunRequest{Protocol: protocol.Number, MinimumIsolation: "vm", TimeoutMs: 30000,
		Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
			Files: []*plimsollv1.ProjectFile{{Path: "main.js", Content: "console.log(1)"}}, Steps: []string{"node main.js"}}}}
	resp := &plimsollv1.RunResponse{Sandbox: "wslc", Isolation: "vm", Environment: "wslc-image:sha256:" + strings.Repeat("c3", 32),
		IsolationQualification: sentence,
		Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED,
			Steps: []*plimsollv1.StepResult{{Command: "node main.js", Stdout: []byte("1\n")}}}}}
	return req, resp
}

// version4WSLBundle is a bundle of one WSL run whose record is version 4, as a release before v0.28.0 wrote it (no
// field for the sentence), signed by key and linked as a harness links a line. The harness signs only the current
// version, so the statement and the links are built here, in the form attest verifies.
func version4WSLBundle(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	req, resp := wslcRun("")
	req.Protocol = 5
	started := time.UnixMilli(1790000000000)
	r := sandbox.RunRecord{Version: 4, RequestSHA256: record.RunRequestDigest(req), ResultSHA256: record.ResultDigest(resp),
		Provider: "wslc", Isolation: "vm", Environment: resp.Environment, Started: started, Ended: started.Add(time.Second)}
	r.SHA256 = record.Digest(r)
	resp.Record = record.ToWire(r)
	pub := key.Public().(ed25519.PublicKey)
	sign := func(payload []byte) attest.Envelope {
		return attest.Envelope{PayloadType: attest.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload),
			Signatures: []attest.Signature{{KeyID: attest.KeyID(pub), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(key, attest.PAE(attest.PayloadType, payload)))}}}
	}
	marshal := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	statement := attest.Statement{Type: attest.StatementType, PredicateType: attest.PredicateType,
		Subject: []attest.Subject{{Name: attest.SubjectName, Digest: map[string]string{"sha256": r.SHA256}}},
		Predicate: attest.Predicate{Version: 4, RequestSHA256: r.RequestSHA256, ResultSHA256: r.ResultSHA256, Provider: r.Provider,
			Isolation: r.Isolation, Environment: r.Environment, StartedUnixMs: r.Started.UnixMilli(), EndedUnixMs: r.Ended.UnixMilli(),
			RecordSHA256: r.SHA256}}
	type linkStatement struct {
		Type          string           `json:"_type"`
		Subject       []attest.Subject `json:"subject"`
		PredicateType string           `json:"predicateType"`
		Predicate     attest.Link      `json:"predicate"`
	}
	link := func(l attest.Link, subject string) *attest.Envelope {
		env := sign(marshal(linkStatement{Type: attest.StatementType, PredicateType: attest.LinkPredicateType,
			Subject: []attest.Subject{{Name: "bundle-line", Digest: map[string]string{"sha256": subject}}}, Predicate: l}))
		return &env
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	respBytes, err := proto.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	e := attest.Entry{Request: reqBytes, Response: respBytes, Envelope: sign(marshal(statement))}
	content := attest.ContentDigest(e)
	e.Link = link(attest.Link{Index: 1, Entry: content}, content)
	previous := attest.LineDigest(e)
	checkpoint := attest.Entry{Link: link(attest.Link{Index: 2, Previous: previous, Checkpoint: true, Lines: 1}, previous)}
	var buf bytes.Buffer
	buf.Write(marshal(e))
	buf.WriteByte('\n')
	buf.Write(marshal(checkpoint))
	buf.WriteByte('\n')
	return buf.Bytes()
}

// The page's checker refuses a WSL bill of materials whose record states no sentence, of version 5 and of version 4,
// on its own line, with every other line passing. The emitter refuses to write such a BOM, so without this test
// nothing would show that a reader's own check refuses one another emitter, or this one with that refusal broken,
// wrote: it is written here with the emitter's refusal switched off. Deleting the provider clause of check.js's
// qualification line makes both BOMs pass and this test fail; -check refuses both.
func TestCheckJSRefusesAWSLBOMWithoutItsQualification(t *testing.T) {
	privPEM, pubPEM, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := attest.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	var v5 bytes.Buffer
	h := attest.NewHarness(attest.NewSigner(key), &v5)
	req, resp := wslcRun("")
	started := time.UnixMilli(1790000000000)
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req), Started: started, Ended: started.Add(time.Second)}, resp)
	if err := h.Record(req, resp); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	bundles := map[string][]byte{"version 5": v5.Bytes(), "version 4": version4WSLBundle(t, key)}
	// Another emitter's view: the BOM is written though the record states no sentence.
	checkQualification = func(sandbox.RunRecord) error { return nil }
	t.Cleanup(func() { checkQualification = cdxutil.CheckQualification })
	boms := map[string][]byte{}
	srcs := map[string]source{}
	for name, b := range bundles {
		s, err := sources(b, pubPEM, defaults().Pages)
		if err != nil || len(s) != 1 {
			t.Fatalf("%s: sources: %d, %v", name, len(s), err)
		}
		if s[0].Record.Version != map[string]int{"version 5": 5, "version 4": 4}[name] || s[0].Record.IsolationQualification != "" {
			t.Fatalf("%s: the record is version %d with sentence %q", name, s[0].Record.Version, s[0].Record.IsolationQualification)
		}
		if boms[name], err = buildBOM(s[0], defaults()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		srcs[name] = s[0]
	}
	for name, lines := range browserCheck(t, boms) {
		for id, ok := range lines {
			if want := id != "qualification"; ok != want {
				t.Errorf("%s: check.js line %s is %v, want %v (only the qualification line may fail)", name, id, ok, want)
			}
		}
		if _, ok := lines["qualification"]; !ok {
			t.Errorf("%s: check.js gave no qualification line: %v", name, lines)
		}
	}
	checkQualification = cdxutil.CheckQualification
	for name, raw := range boms {
		if _, err := checkBOM(raw, pubPEM, nil, have(srcs[name])); err == nil || !strings.Contains(err.Error(), "states no isolation qualification") {
			t.Errorf("%s: -check: %v, want the qualification refusal", name, err)
		}
	}
}
