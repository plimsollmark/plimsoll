package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyReceiptCommand(t *testing.T) {
	fixtures := filepath.Join("..", "..", "attest", "receipt", "testdata")
	policy := filepath.Join(fixtures, "policy.json")
	artifact := filepath.Join(fixtures, "widget.txt")
	var out bytes.Buffer
	if err := verifyReceipt([]string{"-policy", policy, "-artifact", artifact, filepath.Join(fixtures, "valid.json")}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"distinct_signing_keys": 2`) {
		t.Fatal(out.String())
	}
	for _, name := range []string{"changed-envelope.json", "missing.json"} {
		out.Reset()
		if err := verifyReceipt([]string{"-policy", policy, "-artifact", artifact, filepath.Join(fixtures, name)}, &out); err == nil || out.Len() != 0 {
			t.Fatalf("invalid input %s: %v, output %q", name, err, out.String())
		}
	}
	if err := verifyReceipt([]string{filepath.Join(fixtures, "valid.json")}, &out); err == nil {
		t.Fatal("accepted implicit trust")
	}
	wrongArtifact := filepath.Join(t.TempDir(), "other.txt")
	if err := os.WriteFile(wrongArtifact, []byte("changed widget"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := verifyReceipt([]string{"-policy", policy, "-artifact", wrongArtifact, filepath.Join(fixtures, "valid.json")}, &out); err == nil || !strings.Contains(err.Error(), "artifact bytes") || out.Len() != 0 {
		t.Fatalf("changed artifact: %v, %q", err, out.String())
	}
	huge := filepath.Join(t.TempDir(), "huge.json")
	if err := os.WriteFile(huge, bytes.Repeat([]byte(" "), (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readReceiptInput(huge); err == nil {
		t.Fatal("read unbounded input")
	}
}
