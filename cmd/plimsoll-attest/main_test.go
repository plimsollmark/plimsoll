package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/protocol"
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
	// A negative count is a mistake, not "no count": only the flag's own -1 means that.
	for _, n := range []string{"-2", "-100"} {
		if err := verify([]string{"-pub", pub, "-expect-count", n, path}, &out); err == nil || !strings.Contains(err.Error(), "0 or more") {
			t.Errorf("-expect-count %s: %v, want refused", n, err)
		}
	}
	if err := verify([]string{"-pub", pub, "-expect-count", "-1", path}, &out); err != nil {
		t.Errorf("-expect-count -1, the flag's default: %v", err)
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
	marked := runFailed(nil, nil, sandbox.NotDispatched(sandbox.RefusalEnvironment, errors.New("internal error 4c81")))
	if !strings.Contains(marked.Error(), "refused before dispatch (reason environment), so nothing ran") {
		t.Fatalf("a marked refusal: %v", marked)
	}
	if reason, ok := sandbox.NotDispatchedReason(marked); !ok || reason != sandbox.RefusalEnvironment {
		t.Fatalf("the mark is kept on the returned error: %v %v", reason, ok)
	}
	unmarked := runFailed(nil, nil, errors.New("internal error 9f00"))
	if !strings.Contains(unmarked.Error(), "may have run") || strings.Contains(unmarked.Error(), "nothing ran") {
		t.Fatalf("an unmarked error: %v", unmarked)
	}
}

// An answer that came back with a record that failed its check is a run that happened: the
// message says so, names the check (the floor included) and what the daemon stated, and
// never says no record came back (hunt-quality-23). The errors are wrapped as
// client.Remote returns them, DataLoss around the record package's sentinel.
func TestRunFailedSaysWhichCheckARecordFailed(t *testing.T) {
	req := &plimsollv1.RunRequest{Protocol: 6, MinimumIsolation: "vm", Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "container", Record: &plimsollv1.RunRecord{Version: 9},
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{ExitCode: 3}}}
	for name, c := range map[string]struct {
		err  error
		want string
	}{
		"below the floor": {sandbox.ErrIsolationEvidenceMismatch, `its isolation tier "container" is below the request's floor "vm"`},
		"no record":       {record.ErrNoRecord, "it carries no run record"},
		"another version": {record.ErrVersion, "its run record is version 9"},
		"a mismatch":      {record.ErrMismatch, "its run record does not match the request sent and the answer received"},
	} {
		err := runFailed(req, resp, connect.NewError(connect.CodeDataLoss, c.err))
		msg := err.Error()
		if !strings.Contains(msg, "the code ran: the daemon answered that it ran on docker (container): exit 3") || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if strings.Contains(msg, "no record came back") || !strings.Contains(msg, "the bundle is unchanged") || !errors.Is(err, c.err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An error with no answer, or one this does not know, still says the code may have run.
	if err := runFailed(req, nil, errors.New("connection reset")); !strings.Contains(err.Error(), "may have run") {
		t.Errorf("a transport error: %v", err)
	}
	if err := runFailed(req, resp, errors.New("something else")); !strings.Contains(err.Error(), "may have run") {
		t.Errorf("an unknown error with an answer: %v", err)
	}
}

// hostileServer answers every run as a hostile daemon would: its sandbox and isolation
// strings hold an escape sequence, a carriage return, a newline and a right-to-left
// override, written to rewrite the operator's screen. stamped gives the answer a record
// made for it, so it can pass the client's check; otherwise it carries none.
type hostileServer struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
	sandbox, isolation string
	stamped            bool
}

func (s hostileServer) Run(_ context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	resp := &plimsollv1.RunResponse{Sandbox: s.sandbox, Isolation: s.isolation,
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{}}}
	if s.stamped {
		resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req.Msg)}, resp)
	}
	return connect.NewResponse(resp), nil
}

// F8 and F11 of the security scan of 2026-11-20: what plimsoll-attest run
// prints of a daemon's answer, on success and when the answer fails its check, shows the
// daemon's control and format characters as visible escapes, never raw. The check here is
// its own list of such characters, not the function under test.
func TestRunPrintsADaemonsStringsAsEscapes(t *testing.T) {
	raw := func(r rune) bool {
		return r < 0x20 || r >= 0x7f && r <= 0x9f || r == 0x2028 || r == 0x2029 || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
	}
	forged := "docker\x1b[2K\rran on docker (vm): exit 0\nrecord forged\u202e"
	dir := t.TempDir()
	prefixPath := filepath.Join(dir, "harness")
	if err := keygen([]string{"-out", prefixPath}); err != nil {
		t.Fatal(err)
	}
	reqPath := filepath.Join(dir, "request.json")
	if err := os.WriteFile(reqPath, []byte(fmt.Sprintf(`{"protocol": %d, "javascript": {"code": "1"}}`, protocol.Number)), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, srv := range map[string]hostileServer{
		// Its digests match; its provider's name fails the record check's character rule
		// (TestRunRefusesAProviderNameWithControlCharacters), and the refusal shows the name.
		"an answer whose provider the check refuses": {sandbox: forged, isolation: "vm", stamped: true},
		"an answer with no record":                   {sandbox: forged, isolation: "vm\x1b]0;title\x07"},
		"a record that does not match":               {sandbox: forged, isolation: forged, stamped: true},
	} {
		mux := http.NewServeMux()
		mux.Handle(rpc.NewHandler(srv))
		server := httptest.NewServer(mux)
		var out bytes.Buffer
		err := run([]string{"-daemon", server.URL, "-key", prefixPath + ".key", "-bundle", filepath.Join(dir, name+".jsonl"), reqPath}, &out)
		server.Close()
		shown := out.String()
		if err != nil {
			shown += failure(err) + "\n" // what main prints
		}
		if i := strings.IndexFunc(strings.TrimSuffix(shown, "\n"), func(r rune) bool { return raw(r) && r != '\n' }); i >= 0 {
			t.Errorf("%s: printed a raw control or format character at byte %d: %q", name, i, shown)
		}
		if !strings.Contains(shown, `docker\x1b[2K\x0dran on docker (vm): exit 0\x0arecord forged\u202e`) {
			t.Errorf("%s: the daemon's words are not shown as escapes: %q", name, shown)
		}
	}
}

// An answer whose provider name holds a control or bidirectional format character is
// refused by the record check (record.ValidText), DataLoss, and nothing is signed: the
// name is shown to every reader of a bundle beside the tier, and the tier and the
// qualification were already held to that rule. The name otherwise passes every check: the
// record is stamped from the answer itself, so its digests match.
func TestRunRefusesAProviderNameWithControlCharacters(t *testing.T) {
	dir := t.TempDir()
	prefixPath := filepath.Join(dir, "harness")
	if err := keygen([]string{"-out", prefixPath}); err != nil {
		t.Fatal(err)
	}
	reqPath := filepath.Join(dir, "request.json")
	if err := os.WriteFile(reqPath, []byte(fmt.Sprintf(`{"protocol": %d, "javascript": {"code": "1"}}`, protocol.Number)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"docker\x1b[2Kvm", "docker\rvm", "docker\nvm", "docker\u202ecod", "docker\u009b", "docker\u2066x"} {
		mux := http.NewServeMux()
		mux.Handle(rpc.NewHandler(hostileServer{sandbox: name, isolation: "vm", stamped: true}))
		server := httptest.NewServer(mux)
		bundle := filepath.Join(dir, fmt.Sprintf("%x.jsonl", name))
		var out bytes.Buffer
		err := run([]string{"-daemon", server.URL, "-key", prefixPath + ".key", "-bundle", bundle, reqPath}, &out)
		server.Close()
		if connect.CodeOf(err) != connect.CodeDataLoss || !errors.Is(err, record.ErrMismatch) {
			t.Errorf("provider %q: %v (code %v); want the record check's refusal, DataLoss", name, err, connect.CodeOf(err))
		}
		if _, marked := sandbox.NotDispatchedReason(err); marked {
			t.Errorf("provider %q: marked not dispatched; the code ran", name)
		}
		if b, rerr := os.ReadFile(bundle); !errors.Is(rerr, os.ErrNotExist) {
			t.Errorf("provider %q: the bundle holds %d bytes (%v); want nothing signed", name, len(b), rerr)
		}
	}
	// The same server with an ordinary name is signed: the refusal is the name's alone.
	mux := http.NewServeMux()
	mux.Handle(rpc.NewHandler(hostileServer{sandbox: "docker", isolation: "vm", stamped: true}))
	server := httptest.NewServer(mux)
	defer server.Close()
	var out bytes.Buffer
	if err := run([]string{"-daemon", server.URL, "-key", prefixPath + ".key", "-bundle", filepath.Join(dir, "ordinary.jsonl"), reqPath}, &out); err != nil {
		t.Fatalf("an ordinary provider name: %v", err)
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
	var said bytes.Buffer
	if err := verify([]string{"-pub", pub, whole}, &said); err != nil {
		t.Fatalf("the whole bundle: %v", err)
	}
	if s := said.String(); !strings.HasPrefix(s, "verified 3 entries") || strings.Contains(s, "NOT PROVEN") {
		t.Errorf("verify on a bundle of single runs printed %q; want it to begin plainly \"verified\"", s)
	}
	if err := verifyEntry([]string{"-pub", pub, "-line", "3", whole}, &out); err == nil || !strings.Contains(err.Error(), "holds no call") {
		t.Errorf("the checkpoint line: %v", err)
	}
}

// A session whose close could not be collected: verify accepts the bundle and says the
// session is not proven complete, and what that means; -require-close refuses it;
// verify-entry checks the statement's line and names it the harness's word. A daemon's
// close line is checked by verify-entry too.
func TestVerifySaysASessionIsNotProvenComplete(t *testing.T) {
	dir := t.TempDir()
	prefixPath := filepath.Join(dir, "harness")
	if err := keygen([]string{"-out", prefixPath}); err != nil {
		t.Fatal(err)
	}
	signer, err := loadSigner(prefixPath + ".key")
	if err != nil {
		t.Fatal(err)
	}
	pub := prefixPath + ".pub"
	sessionOf := func(h *attest.Harness, id string, calls int) (string, string) {
		t.Helper()
		fp, prev := record.SessionFingerprint(id), ""
		for i := 1; i <= calls; i++ {
			req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: fmt.Sprintf("step(%d)", i)}}}
			resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
				Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("x")}}}
			resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req), Session: fp, Sequence: uint64(i), PreviousSHA256: prev}, resp)
			if err := h.Record(req, resp); err != nil {
				t.Fatal(err)
			}
			prev = resp.GetRecord().GetRecordSha256()
		}
		return fp, prev
	}
	var bundle bytes.Buffer
	h := attest.NewHarness(signer, &bundle)
	fp, last := sessionOf(h, "session-a", 2)
	// Session a's third call was sent and its answer lost: the statement names it.
	lost := record.RunRequestDigest(&plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "step(3)"}}})
	if err := h.RecordCloseNotCollected(fp, 2, last, lost, attest.CloseNotCollectedNotFound); err != nil {
		t.Fatal(err)
	}
	fpB, lastB := sessionOf(h, "session-b", 1)
	if err := h.RecordClose(fpB, 1, lastB); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "runs.jsonl")
	if err := os.WriteFile(path, bundle.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := verify([]string{"-pub", pub, "-expect-count", "3", path}, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if want := "verified, NOT PROVEN COMPLETE: 6 entries signed by key "; !strings.HasPrefix(out.String(), want) {
		t.Errorf("verify printed %q; want it to begin %q", out.String(), want)
	}
	for _, want := range []string{
		"session " + fp[:12] + "…, 2 calls (the session's first 2, none between them), NOT PROVEN COMPLETE: its close could not be collected (the daemon that answered the close said it has no such session for this caller); the harness signed that the client saw these 2 calls in this order, and the daemon's own count of the session's calls is unknown" +
			"; and one more call was sent after them with no answer (request " + lost + "): it may have run;",
		"session " + fpB[:12] + "…, 1 call, chain closed",
		"\nnot proven complete means: these are the session's first 2 calls, in order, none removed and none between them; the daemon may have run more after the last " +
			"(made by another holder of the session ID, by the worker that took the session over, or a call this program sent whose answer was lost), " +
			"and only the daemon's count, which could not be collected, would show them; -require-close refuses such a bundle\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("verify printed %q; want it to say %q", out.String(), want)
		}
	}
	if err := verify([]string{"-pub", pub, "-require-close", path}, &out); !errors.Is(err, attest.ErrNotProvenComplete) {
		t.Fatalf("verify -require-close: %v; want ErrNotProvenComplete", err)
	} else if want := "sessions [" + fp[:12] + "...] (-require-close)"; !strings.HasSuffix(err.Error(), want) || strings.Contains(err.Error(), "…") {
		t.Errorf("verify -require-close says %q; want it to end %q, one ellipsis", err, want)
	}
	out.Reset()
	if err := verifyEntry([]string{"-pub", pub, "-line", "3", path}, &out); err != nil {
		t.Fatalf("verify-entry on the statement: %v", err)
	}
	if s := out.String(); !strings.Contains(s, "the harness's statement that session "+fp[:12]+"…'s close could not be collected (the daemon that answered the close said it has no such session for this caller), after 2 calls the client saw") ||
		!strings.Contains(s, "; and one more call was sent after them with no answer (request "+lost+"): it may have run. It is the harness's word, not the daemon's") {
		t.Errorf("verify-entry on the statement printed %q", s)
	}
	// The caller's own count and list may state the call sent with no answer or not: stated
	// (-expect-unanswered, an "unanswered" line), it is matched against the statements; left
	// out, it is shown. Counted or listed as a call that returned a record, it is missing
	// (the security scan of 2026-11-20, F9).
	files := 0
	digestsFile := func(ds ...string) string {
		files++
		p := filepath.Join(dir, fmt.Sprintf("expect-%d.txt", files))
		if err := os.WriteFile(p, []byte(strings.Join(ds, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	entries, err := attest.ReadBundle(bytes.NewReader(bundle.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var held []string
	for _, e := range entries {
		if r, _, err := e.Messages(); err == nil && e.Request != nil {
			held = append(held, record.RunRequestDigest(r))
		}
	}
	for name, c := range map[string]struct {
		args []string
		ok   bool
	}{
		"-expect-count without the lost call":   {[]string{"-expect-count", "3"}, true},
		"-expect-count with it":                 {[]string{"-expect-count", "4"}, false},
		"-expect-count and -expect-unanswered":  {[]string{"-expect-count", "3", "-expect-unanswered", "1"}, true},
		"-expect-unanswered alone":              {[]string{"-expect-unanswered", "1"}, true},
		"-expect-unanswered none":               {[]string{"-expect-count", "3", "-expect-unanswered", "0"}, false},
		"-expect-unanswered two":                {[]string{"-expect-unanswered", "2"}, false},
		"-expect without the lost call":         {[]string{"-expect", digestsFile(held...)}, true},
		"-expect with it as a record":           {[]string{"-expect", digestsFile(append(append([]string{}, held...), lost)...)}, false},
		"-expect with it as unanswered":         {[]string{"-expect", digestsFile(append(append([]string{}, held...), "unanswered "+lost+" step-3")...)}, true},
		"-expect with it as unanswered twice":   {[]string{"-expect", digestsFile(append(append([]string{}, held...), "unanswered "+lost, "unanswered "+lost)...)}, false},
		"-expect with an empty unanswered line": {[]string{"-expect", digestsFile(append(append([]string{}, held...), "unanswered")...)}, false},
	} {
		out.Reset()
		err := verify(append(append([]string{"-pub", pub}, c.args...), path), &out)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, attest.ErrExpected)) {
			t.Errorf("%s: %v; want ok %v", name, err, c.ok)
		}
		if err == nil && !strings.Contains(out.String(), "(request "+lost+"): it may have run") {
			t.Errorf("%s: the output does not name the call sent with no answer: %q", name, out.String())
		}
	}
	out.Reset()
	if err := verifyEntry([]string{"-pub", pub, "-line", "5", path}, &out); err != nil || !strings.Contains(out.String(), "the daemon's close of session "+fpB[:12]+"…: its own count is 1 call,") {
		t.Errorf("verify-entry on the daemon's close: %q, %v", out.String(), err)
	}
}

// F10 of the security scan of 2026-11-20: a session ends with its close
// not collected and one call sent with no answer, a checkpoint follows, then one more
// recorded call and a checkpoint. A holder of the file cuts it back to the first
// checkpoint. The caller's count of the calls that returned a record, and its list, must
// both find the cut bundle short.
func TestVerifyCountsACutBundleShort(t *testing.T) {
	dir := t.TempDir()
	prefixPath := filepath.Join(dir, "harness")
	if err := keygen([]string{"-out", prefixPath}); err != nil {
		t.Fatal(err)
	}
	signer, err := loadSigner(prefixPath + ".key")
	if err != nil {
		t.Fatal(err)
	}
	pub := prefixPath + ".pub"
	call := func(code string, session string, seq uint64) (*plimsollv1.RunRequest, *plimsollv1.RunResponse) {
		req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: code}}}
		resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: "vm",
			Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("x")}}}
		resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req), Session: session, Sequence: seq}, resp)
		return req, resp
	}
	var bundle bytes.Buffer
	h := attest.NewHarness(signer, &bundle)
	fp := record.SessionFingerprint("session-a")
	req1, resp1 := call("step(1)", fp, 1)
	if err := h.Record(req1, resp1); err != nil {
		t.Fatal(err)
	}
	lostReq, _ := call("step(2)", "", 0)
	lost := record.RunRequestDigest(lostReq)
	if err := h.RecordCloseNotCollected(fp, 1, resp1.GetRecord().GetRecordSha256(), lost, attest.CloseNotCollectedNotFound); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	cutAt := bundle.Len()
	// The retry of the lost call, answered: the same request, so the same digest.
	retryReq, retryResp := call("step(2)", "", 0)
	if err := h.Record(retryReq, retryResp); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	whole := filepath.Join(dir, "whole.jsonl")
	cut := filepath.Join(dir, "cut.jsonl")
	if err := os.WriteFile(whole, bundle.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cut, bundle.Bytes()[:cutAt], 0o600); err != nil {
		t.Fatal(err)
	}
	list := filepath.Join(dir, "expect.txt")
	if err := os.WriteFile(list, []byte(record.RunRequestDigest(req1)+" step-1\n"+lost+" the retry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	marked := filepath.Join(dir, "expect-marked.txt")
	if err := os.WriteFile(marked, []byte(record.RunRequestDigest(req1)+" step-1\nunanswered "+lost+" step-2, lost\n"+lost+" the retry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, args := range [][]string{{"-expect-count", "2"}, {"-expect-count", "2", "-expect-unanswered", "1"}, {"-expect", list}, {"-expect", marked}} {
		if err := verify(append(append([]string{"-pub", pub}, args...), whole), &out); err != nil {
			t.Errorf("verify %v of the whole bundle: %v", args, err)
		}
		if err := verify(append(append([]string{"-pub", pub}, args...), cut), &out); !errors.Is(err, attest.ErrExpected) {
			t.Errorf("verify %v of the bundle cut back before the retry: %v; want ErrExpected", args, err)
		}
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

// verify-record reads a line from before links, which every other reader refuses; it is
// how a v0.10.0 to v0.17.x record is still checked (review, 2026-10-26).
func TestVerifyRecordReadsAPreLinkLine(t *testing.T) {
	const dir = "../../attest/testdata/published/v0.11.1-sessions/"
	var out bytes.Buffer
	if err := verifyRecord([]string{"-pub", dir + "harness.pub", "-line", "1", dir + "bundle.jsonl"}, &out); err != nil || !strings.Contains(out.String(), "record verified") {
		t.Fatalf("verify-record on a v0.11.1 line: %v, %q", err, out.String())
	}
	if !strings.Contains(out.String(), "carries no link") {
		t.Fatalf("the line has no link, which the report must say: %q", out.String())
	}
	if err := verifyEntry([]string{"-pub", dir + "harness.pub", "-line", "1", dir + "bundle.jsonl"}, &out); err == nil {
		t.Fatal("verify-entry must refuse a line with no link")
	}
}

// Every kind of result a Run answer can carry gets a line of its own, never "no result":
// the test walks the answer's result oneof, so a kind added later without an arm in
// summary fails here (finding release-54: a cell run printed "no result").
func TestSummaryNamesEveryResultKind(t *testing.T) {
	oneof := (&plimsollv1.RunResponse{}).ProtoReflect().Descriptor().Oneofs().ByName("result")
	if oneof == nil || oneof.Fields().Len() < 4 {
		t.Fatalf("RunResponse's result oneof: %v", oneof)
	}
	for i := range oneof.Fields().Len() {
		f := oneof.Fields().Get(i)
		resp := &plimsollv1.RunResponse{}
		m := resp.ProtoReflect()
		m.Set(f, m.NewField(f))
		if got := summary(resp); got == "no result" {
			t.Errorf("a %s result is summarized as %q", f.Name(), got)
		}
	}
	if got := summary(&plimsollv1.RunResponse{}); got != "no result" {
		t.Errorf("an answer with no result: %q", got)
	}
	cell := &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Cell{Cell: &plimsollv1.CellResult{ExitCode: 3}}}
	if got := summary(cell); got != "cell, exit 3" {
		t.Errorf("a cell that exited 3: %q", got)
	}
}
