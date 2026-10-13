package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	emit "github.com/action-state-group/capsule-emit-go"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// effectMode reads the derived effect_mode out of a built capsule.
func effectMode(t *testing.T, payload []byte) string {
	t.Helper()
	var got struct {
		Assurance struct {
			EffectMode string `json:"effect_mode"`
		} `json:"assurance"`
	}
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	return got.Assurance.EffectMode
}

// buildAndVerify builds one capsule and has the emitter's verifier accept it.
func buildAndVerify(t *testing.T, in emit.Input) emit.BuiltPayload {
	t.Helper()
	built, err := emit.Build(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	res, err := emit.VerifyCapsule(built.JSON)
	if err != nil || !res.OK {
		t.Fatalf("the emitter's verifier refused it: %v %+v", err, res)
	}
	return built
}

// pyCheckAll runs the Python reference verifier over every capsule file in dir,
// one by one and as a store, when AAC_VERIFIER names it; otherwise it says so.
func pyCheckAll(t *testing.T, dir string, want int) {
	t.Helper()
	bin := os.Getenv("AAC_VERIFIER")
	if bin == "" {
		t.Log("AAC_VERIFIER not set: the Python reference verifier did not check these capsules")
		return
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != want {
		t.Fatalf("%d capsules written for %d expected", len(files), want)
	}
	for _, f := range files {
		if v, detail := pyRun(bin, f); v != pyAccepted {
			t.Errorf("the Python reference verifier did not accept %s: %s", filepath.Base(f), v.text(detail))
		}
	}
	if v, detail := pyRun(bin, "--store", dir); v != pyAccepted {
		t.Errorf("the Python reference verifier did not accept the store: %s", v.text(detail))
	}
	t.Logf("the Python reference verifier checked %d capsules and their store", len(files))
}

// The published session bundle exercises only completed runs. Every other row of
// the table is proved here: each builds a capsule the emitter's verifier accepts,
// with the effect_mode the spec derives for it, and so does the row for a session
// call that got no answer. With AAC_VERIFIER naming the capsule project's Python
// reference verifier, each is also checked by that independent implementation.
func TestEveryVerdictRowVerifies(t *testing.T) {
	want := map[plimsollv1.ProjectOutcome]string{
		plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED:      "confirmed",
		plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT:      "dispatched_unconfirmed",
		plimsollv1.ProjectOutcome_PROJECT_OUTCOME_SETUP_FAILED:   "dispatched_unconfirmed",
		plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR: "dispatched_unconfirmed",
	}
	if len(want) != len(verdicts) {
		t.Fatalf("the test covers %d outcomes, the table has %d", len(want), len(verdicts))
	}
	src := source{operator: "test", developer: "test", batch: "test", importedAt: time.Date(2026, 9, 30, 1, 0, 0, 0, time.UTC)}
	rec := sandbox.RunRecord{SHA256: strings.Repeat("a", 64), Provider: "docker", Isolation: "container",
		Ended: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)}
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{}}}
	dir := t.TempDir()
	for o, mode := range want {
		resp := &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{Outcome: o}}}
		in, err := capsuleInput(rec, req, resp, "", src)
		if err != nil {
			t.Fatalf("%v: %v", o, err)
		}
		built := buildAndVerify(t, in)
		if got := effectMode(t, built.JSON); got != mode {
			t.Errorf("%v: effect_mode %q, want %q", o, got, mode)
		}
		if err := os.WriteFile(filepath.Join(dir, built.CapsuleID+".json"), built.JSON, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A session call that may have run but got no answer: a version 3 record, no
	// response, the error's status code in the reason object.
	lost := rec
	lost.SHA256, lost.Version, lost.Unanswered = strings.Repeat("b", 64), record.UnansweredVersion, "unavailable"
	in, err := capsuleInput(lost, req, nil, "", src)
	if err != nil {
		t.Fatalf("unanswered: %v", err)
	}
	if in.Disposition.VerdictClass != emit.VerdictErrored || in.Effect.Status != emit.EffectDispatched || in.Effect.ResponseDigest != "" {
		t.Errorf("unanswered: verdict %s, status %s, response digest %q", in.Disposition.VerdictClass, in.Effect.Status, in.Effect.ResponseDigest)
	}
	built := buildAndVerify(t, in)
	if got := effectMode(t, built.JSON); got != "dispatched_unconfirmed" {
		t.Errorf("unanswered: effect_mode %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, built.CapsuleID+".json"), built.JSON, 0o644); err != nil {
		t.Fatal(err)
	}
	// An unanswered call with a response is a contradiction, refused.
	if _, err := capsuleInput(lost, req, &plimsollv1.RunResponse{}, "", src); err == nil {
		t.Error("an unanswered record with a response was stated")
	}
	pyCheckAll(t, dir, len(want)+1)
}

// A snippet and a cell have no outcome field: timed out reads as the timed_out
// row, and anything else as completed, whatever its exit code.
func TestSnippetAndCellOutcome(t *testing.T) {
	for _, c := range []struct {
		resp *plimsollv1.RunResponse
		want plimsollv1.ProjectOutcome
	}{
		{&plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{ExitCode: 0}}}, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED},
		{&plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{ExitCode: 1}}}, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED},
		{&plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{ExitCode: 137, TimedOut: true}}}, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT},
		{&plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Cell{Cell: &plimsollv1.CellResult{ExitCode: 0, InterpreterStarted: true}}}, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED},
		{&plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Cell{Cell: &plimsollv1.CellResult{ExitCode: 1}}}, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED},
		{&plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Cell{Cell: &plimsollv1.CellResult{ExitCode: 137, TimedOut: true}}}, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT},
	} {
		got, err := outcome(c.resp)
		if err != nil || got != c.want {
			t.Errorf("%+v: got %v, %v; want %v", c.resp.GetResult(), got, err, c.want)
		}
	}
	if _, err := outcome(&plimsollv1.RunResponse{}); err == nil {
		t.Error("a response with no result was given an outcome")
	}
}

// A call with a host-API grant is refused: its code could have written somewhere
// outside the sandbox, the response says nothing about what it did, and the
// irreversibility class has no value for "unknown".
func TestGrantedCallRefused(t *testing.T) {
	ended := time.Date(2026, 9, 28, 23, 27, 18, 0, time.UTC)
	rec := sandbox.RunRecord{SHA256: strings.Repeat("a", 64), Ended: ended}
	src := source{operator: "o", developer: "d", batch: "b", importedAt: ended.Add(time.Second)}
	snippet := func(grant string) *plimsollv1.RunRequest {
		return &plimsollv1.RunRequest{Protocol: 3, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1", GrantProfile: grant}}}
	}
	project := func(grant string) *plimsollv1.RunRequest {
		return &plimsollv1.RunRequest{Protocol: 3, Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{GrantProfile: grant}}}
	}
	snippetResp := &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{}}}
	projectResp := &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED}}}
	for _, c := range []struct {
		req  *plimsollv1.RunRequest
		resp *plimsollv1.RunResponse
	}{{snippet("external-write"), snippetResp}, {project("external-write"), projectResp}} {
		if _, err := capsuleInput(rec, c.req, c.resp, "", src); err == nil || !strings.Contains(err.Error(), `granted "external-write"`) {
			t.Errorf("%T: a granted call was not refused: %v", c.req.GetPayload(), err)
		}
	}
	// The same calls with no grant are stated, as the lowest irreversibility class.
	for _, c := range []struct {
		req  *plimsollv1.RunRequest
		resp *plimsollv1.RunResponse
	}{{snippet(""), snippetResp}, {project(""), projectResp}} {
		in, err := capsuleInput(rec, c.req, c.resp, "", src)
		if err != nil {
			t.Fatalf("%T: %v", c.req.GetPayload(), err)
		}
		if in.Effect.IrreversibilityClass != emit.IrreversibilityTwoWay || in.Effect.EffectAttestation != emit.AttestationRuntimeClaimed {
			t.Errorf("%T: class %s, attestation %s", c.req.GetPayload(), in.Effect.IrreversibilityClass, in.Effect.EffectAttestation)
		}
	}
}

// A bundle with a cell and a call that got no answer, signed by a fresh harness,
// is stated whole: the cell as a completed run, the lost call as errored and
// dispatched, chained after it.
func TestSessionWithCellAndUnansweredCall(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	h := attest.NewHarness(attest.NewSigner(priv), &buf)
	t0 := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	session := strings.Repeat("b", 64)

	req1 := &plimsollv1.RunRequest{Protocol: 3, Payload: &plimsollv1.RunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "python", Code: "1 + 1"}}}
	resp1 := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "container",
		Result: &plimsollv1.RunResponse_Cell{Cell: &plimsollv1.CellResult{Stdout: []byte("2\n"), InterpreterStarted: true}}}
	r1 := sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req1), Started: t0, Ended: t0.Add(time.Second), Session: session, Sequence: 1}
	resp1.Record = record.Stamp(r1, resp1)
	if err := h.Record(req1, resp1); err != nil {
		t.Fatal(err)
	}
	req2 := &plimsollv1.RunRequest{Protocol: 3, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "'lost'"}}}
	r2 := sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req2), Provider: "docker", Isolation: "container",
		Started: t0.Add(2 * time.Second), Ended: t0.Add(3 * time.Second), Session: session, Sequence: 2, PreviousSHA256: resp1.Record.GetRecordSha256()}
	wire2 := record.StampUnanswered(r2, "unavailable")
	if err := h.RecordUnanswered(req2, wire2); err != nil {
		t.Fatal(err)
	}
	if err := h.RecordClose(session, 2, wire2.GetRecordSha256()); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	entries, err := attest.ReadBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	v := attest.NewVerifier(pub)
	if _, err := attest.VerifyBundle(entries, v); err != nil {
		t.Fatal(err)
	}
	src := source{operator: "test", developer: "test", batch: "test", importedAt: t0.Add(time.Hour)}
	caps, err := state(entries, src, v)
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != 2 {
		t.Fatalf("%d capsules, want 2", len(caps))
	}
	cell, lost := caps[0], caps[1]
	if cell.Verdict != "executed" || cell.Status != "confirmed" || cell.Result != "cell, exit 0" || cell.Parent != "" {
		t.Errorf("cell: %+v", cell)
	}
	if lost.Verdict != "errored" || lost.Status != "dispatched" || lost.Result != "unanswered: unavailable" || lost.Parent != cell.ID {
		t.Errorf("lost call: %+v", lost)
	}
	dir := t.TempDir()
	for _, c := range caps {
		res, err := emit.VerifyCapsule(c.Payload)
		if err != nil || !res.OK {
			t.Fatalf("call %d: the emitter's verifier refused it: %v %+v", c.Sequence, err, res)
		}
		if err := os.WriteFile(filepath.Join(dir, c.ID+".json"), c.Payload, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pyCheckAll(t, dir, 2)
}

// published is what docs/examples/capsule states: the bundle it read, the import
// time it used and the capsule ID of each call. A capsule's ID does not depend on
// its signer, so anyone who runs this program on that bundle with no flags gets
// these IDs.
func TestPublishedCapsulesReproduce(t *testing.T) {
	root := filepath.Join("..", "..", "docs", "examples", "sessions")
	b, err := os.ReadFile(filepath.Join(root, "bundle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != publishedBundleSHA256 {
		t.Fatalf("the sessions bundle is %x, the published import read %s: re-run the capsule example and publish its page", sum, publishedBundleSHA256)
	}
	pemBytes, err := os.ReadFile(filepath.Join(root, "harness.pub"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := attest.ParsePublicKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := attest.ReadBundle(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	v := attest.NewVerifier(pub)
	if _, err := attest.VerifyBundle(entries, v); err != nil {
		t.Fatal(err)
	}
	src, err := sourceFor(b, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	caps, err := state(entries, src, v)
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != len(publishedIDs) {
		t.Fatalf("%d capsules, %d published", len(caps), len(publishedIDs))
	}
	for i, c := range caps {
		if c.ID != publishedIDs[i] {
			t.Errorf("call %d: capsule %s, published %s", c.Sequence, c.ID, publishedIDs[i])
		}
	}
}

// The published defaults (operator, developer, import time) belong to the
// published bundle. Any other bundle must name all three, since the published
// identity and an import time in the past would be false statements about it.
func TestOtherBundleNeedsItsOwnSource(t *testing.T) {
	published, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "sessions", "bundle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	src, err := sourceFor(published, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if src.operator != defaultOperator || src.developer != defaultDeveloper || src.importedAt.Format(time.RFC3339) != publishedImportedAt {
		t.Errorf("the published bundle did not take the published defaults: %+v", src)
	}
	other := append([]byte("{}\n"), published...)
	if _, err := sourceFor(other, "", "", ""); err == nil {
		t.Error("another bundle took the published defaults")
	}
	for _, c := range [][3]string{{"", "d", "2026-10-12T00:00:00Z"}, {"o", "", "2026-10-12T00:00:00Z"}, {"o", "d", ""}} {
		if _, err := sourceFor(other, c[0], c[1], c[2]); err == nil {
			t.Errorf("%q: accepted with a value missing", c)
		}
	}
	if _, err := sourceFor(other, "o", "d", "yesterday"); err == nil {
		t.Error("an unparseable import time was accepted")
	}
	src, err = sourceFor(other, "o", "d", "2026-10-12T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if src.operator != "o" || src.developer != "d" || !src.importedAt.Equal(time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("another bundle's source: %+v", src)
	}
	sum := sha256.Sum256(other)
	if src.batch != "plimsoll-bundle:sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("batch %s does not name the bundle", src.batch)
	}
	// The published bundle may still be stated under another identity.
	if src, err := sourceFor(published, "o", "", ""); err != nil || src.operator != "o" || src.developer != defaultDeveloper {
		t.Errorf("the published bundle under another operator: %+v, %v", src, err)
	}
}

// The Python verifier's three outcomes are told apart by its exit status, and
// only a refusal passes a negative check: a verifier that could not run, or died
// on the input, judged nothing.
func TestVerifierVerdicts(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		bin  string
		want pyVerdict
	}{
		{script("accepts", "exit 0"), pyAccepted},
		{script("refuses", "echo '[error] tampered'; exit 1"), pyRefused},
		{script("usage", "echo 'usage: verify' >&2; exit 2"), pyCannotRun},
		{script("dies", "kill -9 $$"), pyCannotRun},
		{filepath.Join(dir, "missing"), pyCannotRun},
	} {
		if v, detail := pyRun(c.bin, "x.json"); v != c.want {
			t.Errorf("%s: %v (%s), want %v", filepath.Base(c.bin), v, detail, c.want)
		}
	}
	if v, detail := pyRun(script("refuses2", "echo '[error] tampered'; exit 1"), "x.json"); detail != "tampered" {
		t.Errorf("the refusal's reasons were %q", v.text(detail))
	}
	if pyNegative("t", pyCannotRun, "").OK || pyNegative("t", pyAccepted, "").OK || !pyNegative("t", pyRefused, "").OK {
		t.Error("a negative check passes on something other than a refusal")
	}
	if pyPositive("t", "accepted", pyCannotRun, "").OK || pyPositive("t", "accepted", pyRefused, "").OK || !pyPositive("t", "accepted", pyAccepted, "").OK {
		t.Error("a positive check passes on something other than acceptance")
	}
	if got := pyCannotRun.text("exit status 2"); got != "could not run: exit status 2" {
		t.Errorf("text: %q", got)
	}
}

// The Python verifier must be the one this example documents; a missing binary
// is a skip in an ordinary run, never a silent pass.
func TestPythonVerifierIsRunnable(t *testing.T) {
	bin := os.Getenv("AAC_VERIFIER")
	if bin == "" {
		t.Skip("AAC_VERIFIER not set")
	}
	if out, err := exec.Command(bin, "--help").CombinedOutput(); err != nil {
		t.Fatalf("%s --help: %v\n%s", bin, err, out)
	}
}

// An import stamped at or before its record's time is refused before the emitter
// sees it.
func TestImportMustFollowRecord(t *testing.T) {
	ended := time.Date(2026, 9, 28, 23, 27, 18, 0, time.UTC)
	rec := sandbox.RunRecord{SHA256: strings.Repeat("a", 64), Ended: ended}
	req := &plimsollv1.RunRequest{Protocol: 1}
	resp := &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{}}}
	for _, at := range []time.Time{ended, ended.Add(-time.Second)} {
		if _, err := capsuleInput(rec, req, resp, "", source{operator: "o", developer: "d", batch: "b", importedAt: at}); err == nil {
			t.Errorf("an import at %s of a record ended %s was accepted", at, ended)
		}
	}
}

// A module run's doubles cannot enter a -05 JSON digest, even when every one is
// written as an integer: the outputs below would pass the emitter, and -0 would
// digest as 0.
func TestModuleRunRefused(t *testing.T) {
	ended := time.Date(2026, 9, 28, 23, 27, 18, 0, time.UTC)
	rec := sandbox.RunRecord{SHA256: strings.Repeat("a", 64), Ended: ended}
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Module{Module: &plimsollv1.ModuleRun{EndTime: 1, Step: 1}}}
	resp := &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Module{Module: &plimsollv1.ModuleResult{
		Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED,
		Width:   2,
		Runs:    []*plimsollv1.ModuleRowResult{{Status: 1, Outputs: []float64{0, math.Copysign(0, -1)}}},
	}}}
	_, err := capsuleInput(rec, req, resp, "", source{operator: "o", developer: "d", batch: "b", importedAt: ended.Add(time.Second)})
	if err == nil || !strings.Contains(err.Error(), "module run") {
		t.Fatalf("a module run was not refused: %v", err)
	}
}
