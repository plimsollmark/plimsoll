//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// A bundle and a side file of unsealed records hold every run's code and output, so
// they are created owner-only whatever the umask (they were 0644 under the usual
// 022 umask); a run refuses to add to an existing
// bundle other users can read unless -shared-bundle says it is shared on purpose, and
// leaves its mode alone; and each side file is a new one, never an existing file
// another user could read.
func TestBundlesAreOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	dir := t.TempDir()
	prefixPath := filepath.Join(dir, "harness")
	if err := keygen([]string{"-out", prefixPath}); err != nil {
		t.Fatal(err)
	}
	signer, err := loadSigner(prefixPath + ".key")
	if err != nil {
		t.Fatal(err)
	}
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "secret()"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("1\n")}}}
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}, resp)
	bundle := filepath.Join(dir, "bundle.jsonl")
	if err := appendRun(bundle, signer, req, resp, false); err != nil {
		t.Fatal(err)
	}
	side, err := keepUnsealed(bundle, signer, req, resp)
	if err != nil {
		t.Fatal(err)
	}
	again, err := keepUnsealed(bundle, signer, req, resp)
	if err != nil {
		t.Fatal(err)
	}
	if again == side {
		t.Fatal("a second unsealed record went into the first one's file; each must be a new file")
	}
	for _, p := range []string{bundle, side, again} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s was created %v; want 0600", filepath.Base(p), st.Mode().Perm())
		}
	}

	if err := os.Chmod(bundle, 0o640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(bundle)
	err = appendRun(bundle, signer, req, resp, false)
	if err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Fatalf("appending to a bundle its group can read: %v; want refused", err)
	}
	if after, _ := os.ReadFile(bundle); !bytes.Equal(before, after) {
		t.Fatal("the refused append still wrote to the bundle")
	}
	if err := checkAppendable(bundle, signer, false); err == nil {
		t.Fatal("the check before a run passed a bundle its group can read")
	}
	if err := appendRun(bundle, signer, req, resp, true); err != nil {
		t.Fatalf("-shared-bundle: %v", err)
	}
	if st, _ := os.Stat(bundle); st.Mode().Perm() != 0o640 {
		t.Fatalf("the bundle's mode became %v; a run never changes it", st.Mode().Perm())
	}
}
