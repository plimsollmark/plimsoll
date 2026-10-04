package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestReplayVerifiesTheBundleFirst: replay must refuse a bundle that does not verify
// (here a bad signature, and no harness link) before it contacts any daemon. Port 1 on loopback never listens, so a
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
	// The line carries no harness link either, which verification finds first: any
	// verification error before a send is what this test is about.
	if !errors.Is(err, attest.ErrLink) && !errors.Is(err, attest.ErrSignature) {
		t.Fatalf("replay of a bundle that does not verify: %v (output %q), want its verification error before any send", err, out.String())
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

// verify with -expect or -expect-count holds the bundle to the caller's own record of
// its calls: exactly those requests, by digest, or exactly that many.
func TestVerifyExpect(t *testing.T) {
	dir := t.TempDir()
	prefixPath := filepath.Join(dir, "harness")
	if err := keygen([]string{"-out", prefixPath}); err != nil {
		t.Fatal(err)
	}
	signer, err := loadSigner(prefixPath + ".key")
	if err != nil {
		t.Fatal(err)
	}
	var bundle bytes.Buffer
	h := attest.NewHarness(signer, &bundle)
	digest := map[string]string{}
	for _, id := range []string{"t-1", "t-2"} {
		req := &plimsollv1.RunRequest{Protocol: 1, TraceId: id, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "console.log('" + id + "')"}}}
		digest[id] = record.RunRequestDigest(req)
		resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
			Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("1\n")}}}
		resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}, resp)
		if err := h.Record(req, resp); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle.jsonl")
	if err := os.WriteFile(path, bundle.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	expect := func(ids string) string {
		p := filepath.Join(dir, "expect.txt")
		if err := os.WriteFile(p, []byte(ids), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var out bytes.Buffer
	pub := prefixPath + ".pub"
	// One digest per line, in any order; what follows it on a line is a label.
	if err := verify([]string{"-pub", pub, "-expect", expect(digest["t-2"] + " t-2\n\n" + digest["t-1"] + "\n"), path}, &out); err != nil {
		t.Fatalf("the caller's own two calls: %v", err)
	}
	if err := verify([]string{"-pub", pub, "-expect", expect(digest["t-1"] + "\n" + digest["t-2"] + "\n" + digest["t-2"] + "\n"), path}, &out); !errors.Is(err, attest.ErrExpected) {
		t.Fatalf("a call the bundle lacks: %v", err)
	}
	if err := verify([]string{"-pub", pub, "-expect", expect("t-1\nt-2\n"), path}, &out); !errors.Is(err, attest.ErrExpected) {
		t.Fatalf("trace_ids instead of digests: %v", err)
	}
	if err := verify([]string{"-pub", pub, "-expect-count", "2", path}, &out); err != nil {
		t.Fatalf("-expect-count 2: %v", err)
	}
	if err := verify([]string{"-pub", pub, "-expect-count", "3", path}, &out); !errors.Is(err, attest.ErrExpected) {
		t.Fatalf("-expect-count 3: %v", err)
	}
}

// Runs appending to one bundle at once take turns (a lock on the file), so the bundle
// stays whole: each continues the chain the one before it left. Before, each run
// resumed the chain it read at its start, and two at once broke it for good.
func TestConcurrentRunsKeepTheBundleWhole(t *testing.T) {
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
	const runs = 8
	var wg sync.WaitGroup
	errs := make(chan error, runs)
	for i := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &plimsollv1.RunRequest{Protocol: 1, TraceId: fmt.Sprint("t-", i), Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
			resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
				Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("1\n")}}}
			resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}, resp)
			errs <- appendRun(path, signer, req, resp, false)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := verify([]string{"-pub", prefixPath + ".pub", "-expect-count", fmt.Sprint(runs), path}, &out); err != nil {
		t.Fatalf("after %d concurrent runs: %v", runs, err)
	}
}

// run refuses a bundle it cannot continue before anything runs, so no run's record is
// lost to it: here a bundle another key signed, and a daemon that never answers (port
// 1), which a run that checked first never needs.
func TestRunChecksTheBundleBeforeItRuns(t *testing.T) {
	dir := t.TempDir()
	mine, theirs := filepath.Join(dir, "mine"), filepath.Join(dir, "theirs")
	for _, p := range []string{mine, theirs} {
		if err := keygen([]string{"-out", p}); err != nil {
			t.Fatal(err)
		}
	}
	other, err := loadSigner(theirs + ".key")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle.jsonl")
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("1\n")}}}
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}, resp)
	if err := appendRun(path, other, req, resp, false); err != nil {
		t.Fatal(err)
	}
	reqPath := filepath.Join(dir, "request.json")
	if err := os.WriteFile(reqPath, []byte(`{"protocol": 1, "javascript": {"code": "console.log(1)"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = run([]string{"-daemon", "http://127.0.0.1:1", "-key", mine + ".key", "-bundle", path, reqPath}, &out)
	if err == nil || !strings.Contains(err.Error(), "nothing was run") {
		t.Fatalf("a run onto another key's bundle: %v (output %q); want refused before it ran", err, out.String())
	}
}

// failAfter writes its first n bytes to w and fails from then on: a disk filling up
// in the middle of a line.
type failAfter struct {
	w io.Writer
	n int
}

func (f *failAfter) Write(p []byte) (int, error) {
	if len(p) > f.n {
		k, _ := f.w.Write(p[:f.n])
		f.n -= k
		return k, errors.New("no space left on device")
	}
	f.n -= len(p)
	return f.w.Write(p)
}

// An append that fails part way (a line cut short, or a run's entry written and its
// checkpoint not) leaves the bundle as it was, so the next run continues it instead of
// refusing a bundle that no longer verifies.
func TestAFailedAppendLeavesTheBundleAsItWas(t *testing.T) {
	dir := t.TempDir()
	prefixPath := filepath.Join(dir, "harness")
	if err := keygen([]string{"-out", prefixPath}); err != nil {
		t.Fatal(err)
	}
	signer, err := loadSigner(prefixPath + ".key")
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(id string) (*plimsollv1.RunRequest, *plimsollv1.RunResponse) {
		req := &plimsollv1.RunRequest{Protocol: 1, TraceId: id, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
		resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
			Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("1\n")}}}
		resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}, resp)
		return req, resp
	}
	path := filepath.Join(dir, "bundle.jsonl")
	req, resp := exchange("a")
	if err := appendRun(path, signer, req, resp, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bundleWriter = func(f *os.File) io.Writer { return f }
		bundleSync = (*os.File).Sync
	})
	var synced []int64 // the bundle's size at each sync
	bundleSync = func(f *os.File) error {
		if fi, err := f.Stat(); err == nil {
			synced = append(synced, fi.Size())
		}
		return f.Sync()
	}
	entryLine := 0
	for _, cut := range []int{100, -1} { // mid-line; after the entry, before the checkpoint
		synced = nil
		bundleWriter = func(f *os.File) io.Writer {
			n := cut
			if n < 0 {
				n = entryLine
			}
			return &failAfter{w: f, n: n}
		}
		req, resp := exchange("lost")
		if entryLine == 0 {
			var line bytes.Buffer
			h := attest.NewHarness(signer, &line)
			if err := h.Record(req, resp); err != nil {
				t.Fatal(err)
			}
			entryLine = line.Len()
		}
		if err := appendRun(path, signer, req, resp, false); err == nil {
			t.Fatalf("cut at %d: the append reported success", cut)
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
			t.Fatalf("cut at %d: a failed append changed the bundle (%d bytes, was %d)", cut, len(after), len(before))
		}
		if len(synced) == 0 || synced[len(synced)-1] != int64(len(before)) {
			t.Fatalf("cut at %d: the cut back to %d bytes was not synced (syncs at sizes %v)", cut, len(before), synced)
		}
	}
	// A cut that cannot be synced is reported as an uncertain bundle, not as the
	// bundle left as it was.
	bundleWriter = func(f *os.File) io.Writer { return &failAfter{w: f, n: 100} }
	bundleSync = func(*os.File) error { return errors.New("input/output error") }
	req, resp = exchange("lost")
	if err := appendRun(path, signer, req, resp, false); err == nil || !strings.Contains(err.Error(), "could not be synced") {
		t.Fatalf("a failed append whose cut could not be synced: %v", err)
	}
	bundleSync = (*os.File).Sync
	bundleWriter = func(f *os.File) io.Writer { return f }
	req, resp = exchange("b")
	if err := appendRun(path, signer, req, resp, false); err != nil {
		t.Fatalf("the run after a failed append: %v", err)
	}
	expect := filepath.Join(dir, "expect")
	// exchange sends one request under two trace_ids: one digest, listed twice.
	d := record.RunRequestDigest(req)
	if err := os.WriteFile(expect, []byte(d+" a\n"+d+" b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := verify([]string{"-pub", prefixPath + ".pub", "-expect", expect, path}, &out); err != nil {
		t.Fatal(err)
	}
}
