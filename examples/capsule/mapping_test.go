package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	emit "github.com/action-state-group/capsule-emit-go"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The published session bundle exercises only completed runs. Every other row of
// the table is proved here: each builds a capsule the emitter's verifier accepts,
// with the effect_mode the spec derives for it. With AAC_VERIFIER naming the
// capsule project's Python reference verifier, each is also checked by that
// independent implementation.
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
		built, err := emit.Build(in)
		if err != nil {
			t.Fatalf("%v: build: %v", o, err)
		}
		res, err := emit.VerifyCapsule(built.JSON)
		if err != nil || !res.OK {
			t.Fatalf("%v: the emitter's verifier refused it: %v %+v", o, err, res)
		}
		var got struct {
			Assurance struct {
				EffectMode string `json:"effect_mode"`
			} `json:"assurance"`
		}
		if err := json.Unmarshal(built.JSON, &got); err != nil {
			t.Fatal(err)
		}
		if got.Assurance.EffectMode != mode {
			t.Errorf("%v: effect_mode %q, want %q", o, got.Assurance.EffectMode, mode)
		}
		if err := os.WriteFile(filepath.Join(dir, built.CapsuleID+".json"), built.JSON, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := os.Getenv("AAC_VERIFIER")
	if bin == "" {
		t.Log("AAC_VERIFIER not set: the Python reference verifier did not check these rows")
		return
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != len(want) {
		t.Fatalf("%d capsules written for %d rows", len(files), len(want))
	}
	for _, f := range files {
		ok, detail := pyRun(bin, f)
		if !ok {
			t.Errorf("the Python reference verifier refused %s: %s", filepath.Base(f), detail)
		}
	}
	t.Logf("the Python reference verifier checked %d rows, one capsule each", len(files))
}

// A snippet has no outcome field: timed out reads as the timed_out row, and
// anything else as completed, whatever its exit code.
func TestSnippetOutcome(t *testing.T) {
	for _, c := range []struct {
		r    *plimsollv1.JavaScriptResult
		want plimsollv1.ProjectOutcome
	}{
		{&plimsollv1.JavaScriptResult{ExitCode: 0}, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED},
		{&plimsollv1.JavaScriptResult{ExitCode: 1}, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED},
		{&plimsollv1.JavaScriptResult{ExitCode: 137, TimedOut: true}, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT},
	} {
		got, err := outcome(&plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Javascript{Javascript: c.r}})
		if err != nil || got != c.want {
			t.Errorf("%+v: got %v, %v; want %v", c.r, got, err, c.want)
		}
	}
	if _, err := outcome(&plimsollv1.RunResponse{}); err == nil {
		t.Error("a response with no result was given an outcome")
	}
}

// published is what docs/examples/capsule states: the import time it used and the
// capsule ID of each call. A capsule's ID does not depend on its signer, so
// anyone who runs this program with -imported-at set to that time gets these IDs.
var published = struct {
	importedAt string
	ids        []string
}{
	importedAt: publishedImportedAt,
	ids:        publishedIDs,
}

func TestPublishedCapsulesReproduce(t *testing.T) {
	root := filepath.Join("..", "..", "docs", "examples", "sessions")
	b, err := os.ReadFile(filepath.Join(root, "bundle.jsonl"))
	if err != nil {
		t.Fatal(err)
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
	if _, err := attest.VerifyBundle(entries, attest.NewVerifier(pub)); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, published.importedAt)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := state(entries, publishedSource(b, at))
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != len(published.ids) {
		t.Fatalf("%d capsules, %d published", len(caps), len(published.ids))
	}
	for i, c := range caps {
		if c.ID != published.ids[i] {
			t.Errorf("call %d: capsule %s, published %s", c.Sequence, c.ID, published.ids[i])
		}
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
