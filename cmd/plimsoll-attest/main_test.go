package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

func TestKeygenRefusesExistingOutputs(t *testing.T) {
	for _, suffix := range []string{".key", ".pub"} {
		for _, kind := range []string{"file", "symlink", "dangling symlink", "hardlink", "directory"} {
			t.Run(suffix+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				prefixPath := filepath.Join(dir, "pair")
				path := prefixPath + suffix
				victim := filepath.Join(dir, "victim")
				original := []byte("existing file must stay unchanged\n")
				if err := os.WriteFile(victim, original, 0o600); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "file":
					err = os.WriteFile(path, original, 0o600)
				case "symlink":
					err = os.Symlink(victim, path)
				case "dangling symlink":
					err = os.Symlink(filepath.Join(dir, "missing-target"), path)
				case "hardlink":
					err = os.Link(victim, path)
				case "directory":
					err = os.Mkdir(path, 0o700)
				}
				if err != nil {
					t.Fatal(err)
				}
				before, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := keygen([]string{"-out", prefixPath}); !errors.Is(err, os.ErrExist) {
					t.Fatalf("keygen with existing %s %s: %v, want file-exists error", suffix, kind, err)
				}
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(before, after) {
					t.Fatalf("existing output replaced or removed: %v", err)
				}
				if kind != "directory" && kind != "dangling symlink" {
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, original) {
						t.Fatalf("existing output changed: %q, %v", got, err)
					}
				}
				got, err := os.ReadFile(victim)
				if err != nil || !bytes.Equal(got, original) {
					t.Fatalf("victim changed: %q, %v", got, err)
				}
				if _, err := os.Lstat(filepath.Join(dir, "missing-target")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("dangling-link target created: %v", err)
				}
				other := prefixPath + ".key"
				if suffix == ".key" {
					other = prefixPath + ".pub"
				}
				if _, err := os.Lstat(other); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed pair left a new output %s: %v", other, err)
				}
			})
		}
	}
}

func TestKeygenCreatesMatchingPair(t *testing.T) {
	for _, trailingSlash := range []bool{false, true} {
		t.Run(fmt.Sprint("trailing slash=", trailingSlash), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "nested")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			prefixPath := filepath.Join(dir, "pair")
			if trailingSlash {
				prefixPath = dir + string(os.PathSeparator)
			}
			if err := keygen([]string{"-out", prefixPath}); err != nil {
				t.Fatal(err)
			}
			privPEM, err := os.ReadFile(prefixPath + ".key")
			if err != nil {
				t.Fatal(err)
			}
			priv, err := attest.ParsePrivateKey(privPEM)
			if err != nil {
				t.Fatal(err)
			}
			pubPEM, err := os.ReadFile(prefixPath + ".pub")
			if err != nil {
				t.Fatal(err)
			}
			pub, err := attest.ParsePublicKey(pubPEM)
			if err != nil {
				t.Fatal(err)
			}
			if !pub.Equal(priv.Public()) {
				t.Fatal("generated public and private keys do not match")
			}
		})
	}
}

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

// A failed run says whether anything ran: a refusal marked not dispatched names its reason
// (the daemon tells an environment refusal's detail only in its log, so the mark is all the
// caller gets), and an unmarked error says the code may have run.
func TestRunFailedSaysWhetherAnythingRan(t *testing.T) {
	marked := runFailed(sandbox.NotDispatched(sandbox.RefusalEnvironment, errors.New("internal error 4c81")))
	if !strings.Contains(marked.Error(), "refused before dispatch (reason environment), so nothing ran") {
		t.Fatalf("a marked refusal: %v", marked)
	}
	if reason, ok := sandbox.NotDispatchedReason(marked); !ok || reason != sandbox.RefusalEnvironment {
		t.Fatalf("the mark is kept on the returned error: %v %v", reason, ok)
	}
	unmarked := runFailed(errors.New("internal error 9f00"))
	if !strings.Contains(unmarked.Error(), "may have run") || strings.Contains(unmarked.Error(), "nothing ran") {
		t.Fatalf("an unmarked error: %v", unmarked)
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

// verify-entry checks a line on its own where the bundle is not whole (here, no
// checkpoint yet), says what it does not establish, and refuses a changed line.
func TestVerifyEntryChecksOneLine(t *testing.T) {
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
	for _, id := range []string{"t-1", "t-2"} {
		req := &plimsollv1.RunRequest{Protocol: 1, TraceId: id, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "console.log('" + id + "')"}}}
		resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
			Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte(id + "\n")}}}
		resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}, resp)
		if err := h.Record(req, resp); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "open.jsonl")
	if err := os.WriteFile(path, bundle.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	pub := prefixPath + ".pub"
	var out bytes.Buffer
	if err := verify([]string{"-pub", pub, path}, &out); err == nil {
		t.Fatal("verify accepted a bundle with no checkpoint")
	}
	for _, line := range []string{"1", "2"} {
		out.Reset()
		if err := verifyEntry([]string{"-pub", pub, "-line", line, path}, &out); err != nil {
			t.Fatalf("line %s: %v", line, err)
		}
		if !strings.HasPrefix(out.String(), "entry verified: line "+line) || !strings.Contains(out.String(), "Not established by this check: the bundle around the line") {
			t.Errorf("line %s: %s", line, out.String())
		}
	}
	if err := verifyEntry([]string{"-pub", pub, "-line", "3", path}, &out); err == nil || !strings.Contains(err.Error(), "has 2 lines") {
		t.Errorf("a line past the end: %v", err)
	}
	lines := strings.SplitN(bundle.String(), "\n", 3)
	var e attest.Entry
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil {
		t.Fatal(err)
	}
	e.Response[len(e.Response)-1] ^= 1
	changed, _ := json.Marshal(e)
	tampered := filepath.Join(dir, "tampered.jsonl")
	if err := os.WriteFile(tampered, []byte(lines[0]+"\n"+string(changed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyEntry([]string{"-pub", pub, "-line", "2", tampered}, &out); err == nil {
		t.Error("verify-entry accepted a line whose stored response was changed")
	}
	if err := verifyEntry([]string{"-pub", pub, "-line", "1", tampered}, &out); err != nil {
		t.Errorf("the unchanged line beside it: %v", err)
	}
	// A line copied out of its bundle signs its place there: checked as line 1 it is a
	// broken bundle chain, not a session's, since it is a single run.
	alone := filepath.Join(dir, "alone.jsonl")
	if err := os.WriteFile(alone, []byte(lines[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyEntry([]string{"-pub", pub, "-line", "1", alone}, &out); !errors.Is(err, attest.ErrLink) || errors.Is(err, attest.ErrChain) || !strings.Contains(err.Error(), "written as line 2") {
		t.Errorf("line 2 checked out of place: %v", err)
	}
	// A stored line checks while a later one is half written (a crash mid-append), and
	// the half-written one is refused as unfinished.
	torn := filepath.Join(dir, "torn.jsonl")
	if err := os.WriteFile(torn, []byte(lines[0]+"\n"+lines[1][:len(lines[1])/2]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyEntry([]string{"-pub", pub, "-line", "1", torn}, &out); err != nil {
		t.Errorf("a stored line before a torn one: %v", err)
	}
	if err := verifyEntry([]string{"-pub", pub, "-line", "2", torn}, &out); err == nil || !strings.Contains(err.Error(), "not finished") {
		t.Errorf("the torn line: %v", err)
	}
	// A checkpoint holds no call: verify-entry says so, rather than reporting its
	// link as one over other content, which would read as tampering.
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	whole := filepath.Join(dir, "whole.jsonl")
	if err := os.WriteFile(whole, bundle.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verify([]string{"-pub", pub, whole}, &out); err != nil {
		t.Fatalf("the whole bundle: %v", err)
	}
	if err := verifyEntry([]string{"-pub", pub, "-line", "3", whole}, &out); err == nil || !strings.Contains(err.Error(), "holds no call") {
		t.Errorf("the checkpoint line: %v", err)
	}
}

// TestSignAndOpenAStatement: sign-statement puts the harness key on a standard in-toto
// statement and open-statement returns exactly what was signed, refusing another key, another
// type, an edited payload, the reserved run record type, an input with unknown fields, and an
// existing output file.
func TestSignAndOpenAStatement(t *testing.T) {
	dir := t.TempDir()
	harness := filepath.Join(dir, "harness")
	other := filepath.Join(dir, "other")
	for _, p := range []string{harness, other} {
		if err := keygen([]string{"-out", p}); err != nil {
			t.Fatal(err)
		}
	}
	const testResult = "https://in-toto.io/attestation/test-result/v0.1"
	in := filepath.Join(dir, "statement.json")
	statement := `{"subject":[{"name":"https://github.com/example/repo","digest":{"gitCommit":"627534fc71de105aeb7e71098970bb51d7096349"}}],` +
		`"predicate":{"result":"PASSED","configuration":[{"name":"plimsoll run record","digest":{"sha256":"` + strings.Repeat("ab", 32) + `"}}],"passedTests":["sums"]}}`
	if err := os.WriteFile(in, []byte(statement), 0o600); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "test-result.intoto.json")
	var out bytes.Buffer
	if err := signStatement([]string{"-key", harness + ".key", "-type", testResult, "-out", env, in}, &out); err != nil {
		t.Fatal(err)
	}
	if err := signStatement([]string{"-key", harness + ".key", "-type", testResult, "-out", env, in}, &out); err == nil {
		t.Fatal("sign-statement wrote over an existing envelope")
	}
	out.Reset()
	if err := openStatement([]string{"-pub", harness + ".pub", "-type", testResult, env}, &out); err != nil {
		t.Fatal(err)
	}
	var got signedStatement
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var want signedStatement
	if err := json.Unmarshal([]byte(statement), &want); err != nil {
		t.Fatal(err)
	}
	pub, err := loadPublic(harness + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != attest.KeyID(pub) || fmt.Sprint(got.Subject) != fmt.Sprint(want.Subject) {
		t.Fatalf("opened %+v", got)
	}
	var gotPred, wantPred any
	if err := json.Unmarshal(got.Predicate, &gotPred); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want.Predicate, &wantPred); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(gotPred) != fmt.Sprint(wantPred) {
		t.Fatalf("predicate %s, signed %s", got.Predicate, want.Predicate)
	}
	if err := openStatement([]string{"-pub", other + ".pub", "-type", testResult, env}, io.Discard); err == nil {
		t.Fatal("open-statement accepted another key")
	}
	if err := openStatement([]string{"-pub", harness + ".pub", "-type", "https://openvex.dev/ns/v0.2.0", env}, io.Discard); err == nil {
		t.Fatal("open-statement accepted another predicate type")
	}
	raw, err := os.ReadFile(env)
	if err != nil {
		t.Fatal(err)
	}
	var e attest.Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	e.Payload = base64.StdEncoding.EncodeToString(bytes.Replace(payload, []byte("PASSED"), []byte("FAILED"), 1))
	edited, _ := json.Marshal(e)
	editedPath := filepath.Join(dir, "edited.json")
	if err := os.WriteFile(editedPath, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := openStatement([]string{"-pub", harness + ".pub", "-type", testResult, editedPath}, io.Discard); err == nil {
		t.Fatal("open-statement accepted an edited payload")
	}
	if err := signStatement([]string{"-key", harness + ".key", "-type", attest.PredicateType, "-out", filepath.Join(dir, "rec.json"), in}, io.Discard); !errors.Is(err, attest.ErrReservedPredicate) {
		t.Fatalf("signing the run record type: %v", err)
	}
	extra := filepath.Join(dir, "extra.json")
	if err := os.WriteFile(extra, []byte(`{"subject":[],"predicate":{},"note":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := signStatement([]string{"-key", harness + ".key", "-type", testResult, "-out", filepath.Join(dir, "x.json"), extra}, io.Discard); err == nil {
		t.Fatal("sign-statement accepted a field it does not know")
	}
}
