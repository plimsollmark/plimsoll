package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestReplayVerifiesTheBundleFirst: replay must refuse a bundle whose signature does
// not verify before it contacts any daemon. Port 1 on loopback never listens, so a
// replay that verified first never needs it (external review of v0.10.0, finding 5,
// 2026-09-28).
func TestReplayVerifiesTheBundleFirst(t *testing.T) {
	dir := t.TempDir()
	prefixPath := filepath.Join(dir, "harness")
	if err := keygen([]string{"-out", prefixPath}); err != nil {
		t.Fatal(err)
	}
	signer, err := loadSigner(prefixPath + ".key")
	if err != nil {
		t.Fatal(err)
	}
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "console.log(1)"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("1\n")}}}
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}, resp)
	e, err := signer.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Envelope.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	e.Envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
	var bundle bytes.Buffer
	if err := attest.WriteEntry(&bundle, e); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle.jsonl")
	if err := os.WriteFile(path, bundle.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = replay([]string{"-daemon", "http://127.0.0.1:1", "-pub", prefixPath + ".pub", path}, &out)
	if !errors.Is(err, attest.ErrSignature) {
		t.Fatalf("replay of a bundle with a bad signature: %v (output %q), want attest.ErrSignature before any send", err, out.String())
	}
}

// TestPrefixNeverPanics: a digest shorter than the display width prints whole.
func TestPrefixNeverPanics(t *testing.T) {
	if got := prefix("", 16); got != "" {
		t.Fatalf("prefix of empty: %q", got)
	}
	if got := prefix("abc", 16); got != "abc" {
		t.Fatalf("prefix of short: %q", got)
	}
	if got := prefix("0123456789abcdef0123", 16); got != "0123456789abcdef" {
		t.Fatalf("prefix of long: %q", got)
	}
}
