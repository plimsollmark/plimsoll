package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// hunt-quality-38: the page says "every record signed, chained and closed" of a bundle that
// verifies, so a bundle whose session ends in the harness's statement that its close could
// not be collected (a daemon restart in the middle of the run) is refused, with the reason,
// never reported as closed.
func TestASessionNotProvenCompleteIsRefused(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var bundle bytes.Buffer
	h := attest.NewHarness(attest.NewSigner(key), &bundle)
	fp := record.SessionFingerprint("session-a")
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "step(1)"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm", Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("x")}}}
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req), Session: fp, Sequence: 1}, resp)
	if err := h.Record(req, resp); err != nil {
		t.Fatal(err)
	}
	if err := h.RecordCloseNotCollected(fp, 1, resp.GetRecord().GetRecordSha256(), "", attest.CloseNotCollectedNotFound); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	entries, err := attest.ReadBundle(bytes.NewReader(bundle.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	v := attest.NewVerifier(key.Public().(ed25519.PublicKey))
	c := verify("the bundle", entries, v)
	if c.Pass || c.Verdict != "refused" || !strings.Contains(c.Detail, "not proven complete") {
		t.Fatalf("verify: %+v; want it refused as not proven complete", c)
	}
	if _, err := attest.VerifyBundle(entries, v); !errors.Is(err, attest.ErrNotProvenComplete) {
		t.Fatalf("VerifyBundle: %v", err)
	}
}

// The committed page is written by a run that needs an OpenShell gateway; this
// test catches the drift that needs none: every fixed sentence of the template
// must appear in the committed page, in order, and the bundle and key it points
// to must be beside it.
func TestCommittedPageCarriesItsTemplateText(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "examples", "sessions")
	raw, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	page, at := string(raw), 0
	for _, s := range []string{
		"<h1>One sandbox, five calls: an OpenShell session with a signed chain of records</h1>",
		"<h2>The calls</h2>",
		"<h2>The chain</h2>",
		"<h2>The verifier</h2>",
		"<h2>What happens around each call</h2>",
		"<h2>What this does not show</h2>",
		"go run ./examples/sessions",
	} {
		i := strings.Index(page[at:], s)
		if i < 0 {
			t.Fatalf("the committed page does not carry %q (edit both, or regenerate with go run ./examples/sessions)", s)
		}
		at += i + len(s)
	}
	for _, f := range []string{"bundle.jsonl", "harness.pub"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("the page links %s: %v", f, err)
		}
	}
}
