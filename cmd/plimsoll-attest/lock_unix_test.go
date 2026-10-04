//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// An append waits for the lock another holder has on the bundle, and goes on once it
// is released: the lock, not luck, keeps concurrent runs in turn.
func TestAppendWaitsForTheBundleLock(t *testing.T) {
	dir := t.TempDir()
	prefixPath := filepath.Join(dir, "harness")
	if err := keygen([]string{"-out", prefixPath}); err != nil {
		t.Fatal(err)
	}
	signer, err := loadSigner(prefixPath + ".key")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle.jsonl")
	holder, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	unlock, err := lockFile(holder, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("1\n")}}}
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}, resp)
	done := make(chan error, 1)
	go func() { done <- appendRun(path, signer, req, resp, false) }()
	select {
	case err := <-done:
		t.Fatalf("the append did not wait for the lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the append did not go on once the lock was released")
	}
}
