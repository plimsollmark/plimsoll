// Command plimsoll-attest is a harness for plimsoll's run records, run outside
// the daemon: it makes a signing key, runs a request and signs its checked
// record into a bundle, verifies a bundle (signatures, digests, the bundle's
// chain of links, session chains, and with -expect the caller's own list of its
// calls), and replays a bundle's single runs to compare results.
//
//	plimsoll-attest keygen -out harness
//	plimsoll-attest run -daemon http://127.0.0.1:8080 -key harness.key -bundle runs.jsonl request.json
//	plimsoll-attest verify -pub harness.pub runs.jsonl
//	plimsoll-attest replay -daemon http://127.0.0.1:8080 -pub harness.pub runs.jsonl
//	plimsoll-attest verify-record -pub harness.pub -line 1 old-runs.jsonl
//
// replay sends each single run again, and each recorded session's calls, in
// order, into a fresh session.
//
// The request file is a plimsoll.v1.RunRequest in protobuf JSON, for example
// {"protocol": 4, "javascript": {"code": "console.log(1)"}}. The daemon's
// bearer token is read from PLIMSOLL_CALLER_TOKEN, and the signing key from
// -key or, when that is absent, from PLIMSOLL_ATTEST_KEY (the PEM itself), so
// neither appears in a process listing. The key never goes to the daemon.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const usage = `usage:
  plimsoll-attest keygen -out PREFIX            write PREFIX.key (mode 0600) and PREFIX.pub
  plimsoll-attest run -daemon URL -key FILE -bundle FILE [-shared-bundle] REQUEST.json
                                                run one request, append its signed record
                                                (under a lock on the file, so runs take turns;
                                                no lock on Windows, Solaris, illumos or AIX:
                                                run one at a time there); a bundle other
                                                users can read is refused without -shared-bundle
  plimsoll-attest verify -pub FILE [-expect FILE | -expect-count N] BUNDLE
                                                check signatures, digests, the bundle's chain
                                                of links and session chains; with -expect, that
                                                it holds exactly the requests your own log lists,
                                                one request digest (request_sha256) per line
  plimsoll-attest verify-entry -pub FILE -line N BUNDLE
                                                check one call line on its own: its signature,
                                                its stored request and response, and its link;
                                                not the bundle around it, nor (for a session
                                                call) that its session's chain is whole
  plimsoll-attest verify-record -pub FILE -line N BUNDLE
                                                check one call line's signature and its stored
                                                request and response alone, with no link: for a
                                                line from before links (v0.10.0 to v0.17.x); it
                                                proves the exchange, not the line's place
  plimsoll-attest replay -daemon URL -pub FILE [-with-grants] BUNDLE
                                                verify the bundle as verify does, then run each
                                                single run again and each session in a fresh
                                                session, compare results; a request recorded
                                                with a grant profile, or under another protocol
                                                number, is reported and not sent (-with-grants
                                                sends the former)
  plimsoll-attest sign-statement -key FILE -type URI -out FILE STATEMENT.json
                                                sign an in-toto statement the harness makes
                                                about evidence it checked; STATEMENT.json holds
                                                {"subject": [...], "predicate": {...}}; the run
                                                record, link and close types are refused
  plimsoll-attest open-statement -pub FILE -type URI ENVELOPE.json
                                                check the envelope's signature and type, print
                                                {"keyid", "subject", "predicate"} as JSON; what
                                                the predicate claims is the reader's to check
  plimsoll-attest verify-receipt -policy TRUSTED_POLICY.json -artifact FILE RECEIPT.json
                                                check role keys, expected artifact and outside
                                                timestamps offline; print signed assertions,
                                                without independently reproducing their claims

environment:
  PLIMSOLL_CALLER_TOKEN   bearer token for the daemon (omit for an open dev daemon)
  PLIMSOLL_ATTEST_KEY     the signing key's PEM, when -key is not given
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "run":
		err = run(os.Args[2:], os.Stdout)
	case "verify":
		err = verify(os.Args[2:], os.Stdout)
	case "verify-entry":
		err = verifyEntry(os.Args[2:], os.Stdout)
	case "verify-record":
		err = verifyRecord(os.Args[2:], os.Stdout)
	case "replay":
		err = replay(os.Args[2:], os.Stdout)
	case "sign-statement":
		err = signStatement(os.Args[2:], os.Stdout)
	case "open-statement":
		err = openStatement(os.Args[2:], os.Stdout)
	case "verify-receipt":
		err = verifyReceipt(os.Args[2:], os.Stdout)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "plimsoll-attest:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "path prefix for PREFIX.key and PREFIX.pub")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errors.New("keygen needs -out PREFIX and nothing else")
	}
	priv, pub, err := attest.GenerateKey()
	if err != nil {
		return err
	}
	return writeKeyPair(*out, priv, pub)
}

// Both outputs must be new directory entries, including when an existing entry
// is a link. Keep cleanup in the opened directory if its path is later replaced.
func writeKeyPair(prefix string, priv, pub []byte) (err error) {
	// Split without cleaning: link/../pair follows the filesystem's directory
	// semantics, which can differ from lexically removing link/.. first.
	directory, _ := filepath.Split(prefix + ".key")
	if directory == "" {
		directory = "."
	}
	dir, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	created := make([]string, 0, 2)
	defer func() {
		if err != nil {
			for _, name := range created {
				err = errors.Join(err, dir.Remove(name))
			}
		}
	}()
	for _, output := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{prefix + ".key", priv, 0o600},
		{prefix + ".pub", pub, 0o644},
	} {
		name := filepath.Base(output.path)
		f, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, output.mode)
		if err != nil {
			return err
		}
		created = append(created, name)
		_, writeErr := f.Write(output.data)
		if err := errors.Join(writeErr, f.Close()); err != nil {
			return err
		}
	}
	return nil
}

func loadSigner(path string) (*attest.Signer, error) {
	var pemBytes []byte
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		pemBytes = b
	} else if v := os.Getenv("PLIMSOLL_ATTEST_KEY"); v != "" {
		pemBytes = []byte(v)
	} else {
		return nil, errors.New("no signing key: give -key FILE or set PLIMSOLL_ATTEST_KEY")
	}
	key, err := attest.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	return attest.NewSigner(key), nil
}

func remote(daemon string, opts ...client.Option) (*client.Remote, error) {
	if tok := os.Getenv("PLIMSOLL_CALLER_TOKEN"); tok != "" {
		opts = append(opts, client.WithToken(tok))
	}
	return client.New(daemon, opts...)
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	daemon := fs.String("daemon", "", "the daemon's base URL")
	keyPath := fs.String("key", "", "the signing key (PEM PKCS #8 Ed25519)")
	bundlePath := fs.String("bundle", "", "the bundle to append to (created if absent, readable by its owner only)")
	shared := fs.Bool("shared-bundle", false, "append even when the bundle is readable by other users: a bundle shared on purpose")
	timeout := fs.Duration("timeout", 6*time.Minute, "how long to wait for the run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *daemon == "" || *bundlePath == "" || fs.NArg() != 1 {
		return errors.New("run needs -daemon URL, -bundle FILE and one REQUEST.json")
	}
	signer, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	req := &plimsollv1.RunRequest{}
	if err := protojson.Unmarshal(raw, req); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	// Before anything runs: a bundle this harness cannot continue (another key's, one
	// cut, one in an older format) refuses the run, so no run's record is lost to it.
	if err := checkAppendable(*bundlePath, signer, *shared); err != nil {
		return fmt.Errorf("%w; nothing was run", err)
	}
	// The exchange is kept in memory while the run takes its time, and appended once
	// it is back: so two runs on one bundle take turns only for the append.
	got := &captured{}
	r, err := remote(*daemon, client.WithRecorder(got))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	resp, rec, err := r.Exchange(ctx, req)
	if err != nil {
		return runFailed(err) // a run that failed has no record, and the bundle is unchanged
	}
	fmt.Fprintf(stdout, "ran on %s (%s): %s\n", resp.GetSandbox(), resp.GetIsolation(), summary(resp))
	if err := appendRun(*bundlePath, signer, got.req, got.resp, *shared); err != nil {
		// The run happened: its signed record is kept beside the bundle, unlinked,
		// rather than lost.
		side, serr := keepUnsealed(*bundlePath, signer, got.req, got.resp)
		if serr != nil {
			return fmt.Errorf("the run's record could not be appended (%w), nor kept beside the bundle (%v)", err, serr)
		}
		return fmt.Errorf("the run's record could not be appended (%w); its signed entry is in %s, without a link", err, side)
	}
	fmt.Fprintf(stdout, "record %s signed into %s; request %s (the line for verify -expect)\n", rec.SHA256, *bundlePath, rec.RequestSHA256)
	return nil
}

// bundleMode is the mode a bundle, and a side file of unsealed records, is created
// with: owner only. Each holds the requests and responses in full, the submitted code
// and its output included, which other users of the machine have no business reading.
const bundleMode = 0o600

// refuseShared refuses a bundle its group or others can read or write (one made before
// bundles were created owner-only, or loosened since), unless shared says it is shared
// on purpose: a run would add its code and output to what other users can read. It
// never changes the mode itself. On Windows, where Go reports every writable file as
// 0666 and access is a matter of ACLs, it checks nothing.
func refuseShared(f *os.File, shared bool) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if m := st.Mode().Perm(); m&0o077 != 0 && !shared {
		return fmt.Errorf("%s is open to other users (mode %v) and would hold this run's code and output too: chmod 600 it, or pass -shared-bundle if it is shared on purpose", f.Name(), m)
	}
	return nil
}

// lockWait bounds how long a run waits for another's append to the same bundle.
const lockWait = 2 * time.Minute

// resume reads the bundle in f and returns a harness that continues it at f's end.
func resume(f *os.File, signer *attest.Signer) (*attest.Harness, error) {
	existing, err := attest.ReadBundle(f)
	if err != nil {
		return nil, cannotContinue(err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	h, err := attest.ResumeHarness(signer, existing, bundleWriter(f))
	if err != nil {
		return nil, cannotContinue(err)
	}
	return h, nil
}

// bundleWriter is what a resumed harness writes the bundle through; a variable so a
// test can make a write fail part way.
var bundleWriter = func(f *os.File) io.Writer { return f }

// bundleSync syncs the bundle to disk; a variable so a test can watch or fail it.
var bundleSync = (*os.File).Sync

// cannotContinue says what to do with a bundle this harness cannot continue.
func cannotContinue(err error) error {
	return fmt.Errorf("%w. A bundle signed by another key, or written before bundle links, cannot be continued: start a new one. One damaged by a crash while appending (a partial or unsealed last line) is whole again once cut back to its last checkpoint line, if the damage is after it", err)
}

// checkAppendable reports whether the bundle at path (absent: a new one) is one this
// signer can continue, without taking the lock or writing.
func checkAppendable(path string, signer *attest.Signer, shared bool) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := refuseShared(f, shared); err != nil {
		return err
	}
	existing, err := attest.ReadBundle(f)
	if err != nil {
		return cannotContinue(err)
	}
	if _, err := attest.ResumeHarness(signer, existing, io.Discard); err != nil {
		return cannotContinue(err)
	}
	return nil
}

// keepUnsealed writes the exchange's signed entry, without a link, to a new file
// beside the bundle, owner-only and never an existing one (which could be readable by
// others): a run's record the bundle could not take, kept rather than lost. It returns
// the file's path.
func keepUnsealed(bundle string, signer *attest.Signer, req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) (string, error) {
	e, err := signer.Call(req, resp)
	if err != nil {
		return "", err
	}
	var r [4]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "", err
	}
	path := fmt.Sprintf("%s.unsealed-%s-%x.jsonl", bundle, time.Now().UTC().Format("20060102T150405Z"), r)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, bundleMode)
	if err != nil {
		return "", err
	}
	err = attest.WriteEntry(f, e)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

// runFailed says what a failed run's error means for its caller: a refusal the daemon marked
// as made before anything was dispatched ran nothing and names its reason; any other error
// may have come after the code started, so it is never a safe automatic retry. The daemon
// tells an environment refusal's detail only in its log, so the mark is the caller's one
// account of it.
func runFailed(err error) error {
	if reason, ok := sandbox.NotDispatchedReason(err); ok {
		return fmt.Errorf("refused before dispatch (reason %s), so nothing ran; the bundle is unchanged: %w", reason, err)
	}
	return fmt.Errorf("failed with no not-dispatched mark, so the code may have run; no record came back and the bundle is unchanged: %w", err)
}

// captured is a client.Recorder that keeps the one exchange of a run.
type captured struct {
	req  *plimsollv1.RunRequest
	resp *plimsollv1.RunResponse
}

func (c *captured) Record(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) error {
	c.req, c.resp = req, resp
	return nil
}

// appendRun signs the exchange into the bundle at path, continuing its chain and
// ending with a checkpoint, under an exclusive lock on the file: it re-reads the
// bundle, which must verify whole under this key (attest.ResumeHarness), then appends.
func appendRun(path string, signer *attest.Signer, req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse, shared bool) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, bundleMode)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := refuseShared(f, shared); err != nil {
		return err
	}
	unlock, err := lockFile(f, lockWait)
	if err != nil {
		return err
	}
	defer unlock()
	h, err := resume(f, signer)
	if err != nil {
		return err
	}
	end, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	// The entry, its checkpoint, and both on disk, or the bundle as it was: a write
	// that fails part way would otherwise leave a cut line or an entry without its
	// checkpoint, which no later run could continue. The caller keeps the run's record
	// in a side file instead.
	err = h.Record(req, resp)
	if err == nil {
		err = h.Checkpoint()
	}
	if err == nil {
		err = bundleSync(f)
	}
	if err != nil {
		// The cut is synced too: unsynced, a crash could bring the partial line back.
		if terr := f.Truncate(end); terr != nil {
			return fmt.Errorf("%w; cutting the bundle back to its last checkpoint failed too (%v), so it may hold part of a line: verify it before the next run", err, terr)
		}
		if serr := bundleSync(f); serr != nil {
			return fmt.Errorf("%w; the bundle was cut back to its last checkpoint, but the cut could not be synced (%v), so after a crash it may hold part of a line: verify it before the next run", err, serr)
		}
	}
	return err
}

func summary(resp *plimsollv1.RunResponse) string {
	switch r := resp.GetResult().(type) {
	case *plimsollv1.RunResponse_Javascript:
		return fmt.Sprintf("exit %d", r.Javascript.GetExitCode())
	case *plimsollv1.RunResponse_Project:
		return fmt.Sprintf("%s, %d steps", r.Project.GetOutcome(), len(r.Project.GetSteps()))
	case *plimsollv1.RunResponse_Module:
		return fmt.Sprintf("%s, %d rows", r.Module.GetOutcome(), len(r.Module.GetRuns()))
	}
	return "no result"
}

// loadPublic reads the harness's public key from a PEM file.
func loadPublic(path string) (ed25519.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return attest.ParsePublicKey(pemBytes)
}

// prefix shortens a digest for display without assuming its length.
func prefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func readBundle(path string) ([]attest.Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return attest.ReadBundle(f)
}

func verify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "the harness's public key (PEM PKIX Ed25519)")
	expectPath := fs.String("expect", "", "a file of the request digests (request_sha256 in each run record) of every call you made through this harness, one per line, from your own log; anything after the digest on a line is a label: the bundle must hold exactly those requests, each as many times as listed")
	expectCount := fs.Int("expect-count", -1, "how many calls you made through this harness, from your own records: the bundle must hold exactly that many")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubPath == "" || fs.NArg() != 1 {
		return errors.New("verify needs -pub FILE and one BUNDLE")
	}
	pub, err := loadPublic(*pubPath)
	if err != nil {
		return err
	}
	entries, err := readBundle(fs.Arg(0))
	if err != nil {
		return err
	}
	rep, err := attest.VerifyBundle(entries, attest.NewVerifier(pub))
	if err != nil {
		return err
	}
	// The links prove the file is what the harness wrote; whether the harness was
	// handed every call is the caller's own records' to say.
	if *expectPath != "" {
		raw, err := os.ReadFile(*expectPath)
		if err != nil {
			return err
		}
		var digests []string
		for _, line := range strings.Split(string(raw), "\n") {
			if f := strings.Fields(line); len(f) > 0 {
				digests = append(digests, f[0])
			}
		}
		if err := attest.VerifyExpected(entries, digests); err != nil {
			return err
		}
	}
	if *expectCount >= 0 && attest.CountCalls(entries) != *expectCount {
		return fmt.Errorf("%w: the bundle holds %d calls, you expected %d", attest.ErrExpected, attest.CountCalls(entries), *expectCount)
	}
	fmt.Fprintf(stdout, "verified %d entries signed by key %s, whole to its last checkpoint: %d single runs", len(entries), attest.KeyID(pub), rep.Runs)
	for _, s := range rep.Sessions {
		fmt.Fprintf(stdout, "; session %s…, %d calls, chain closed", prefix(s.Session, 12), s.Calls)
	}
	fmt.Fprintln(stdout)
	return nil
}

// verifyEntry checks one line of a bundle on its own (attest.VerifyEntry), for a line
// whose bundle is not whole yet, such as a call of a session still open. It says what
// the check does not establish: verify, over a whole bundle, is unchanged.
func verifyEntry(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify-entry", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "the harness's public key (PEM PKIX Ed25519)")
	line := fs.Int("line", 0, "the line to check, from 1")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubPath == "" || *line < 1 || fs.NArg() != 1 {
		return errors.New("verify-entry needs -pub FILE, -line N (from 1) and one BUNDLE")
	}
	pub, err := loadPublic(*pubPath)
	if err != nil {
		return err
	}
	entry, err := readLine(fs.Arg(0), *line)
	if err != nil {
		return err
	}
	// A checkpoint and a session's close statement carry no call; VerifyEntry would
	// refuse them as a link over other content, which reads as tampering.
	if len(entry.Request) == 0 && len(entry.Response) == 0 {
		return fmt.Errorf("line %d of %s holds no call: it is a checkpoint or a session's close statement, which plimsoll-attest verify checks with the whole bundle", *line, fs.Arg(0))
	}
	rec, link, err := attest.VerifyEntry(attest.NewVerifier(pub), entry)
	if err != nil {
		return err
	}
	if link.Index != uint64(*line) {
		// The line's place is the bundle's chain, whether the run was a session's or not.
		return fmt.Errorf("%w: line %d's link says it was written as line %d", attest.ErrLink, *line, link.Index)
	}
	what := "a single run"
	if rec.Session != "" {
		what = fmt.Sprintf("call %d of session %s…", rec.Sequence, prefix(rec.Session, 12))
	}
	if rec.Unanswered != "" {
		what += fmt.Sprintf(", which ended without an answer (%s) and may have run", rec.Unanswered)
	}
	fmt.Fprintf(stdout, "entry verified: line %d, signed by key %s: record %s, %s; the signed record states provider %s and isolation %q. "+
		"It authenticates the recorded messages, not that what the guest printed is true. "+
		"Not established by this check: the bundle around the line, and for a session call that its session's chain is whole; plimsoll-attest verify checks a whole bundle\n",
		*line, attest.KeyID(pub), rec.SHA256, what, rec.Provider, rec.Isolation)
	return nil
}

// signedStatement is a statement's two parts as sign-statement reads them and
// open-statement prints them.
type signedStatement struct {
	KeyID     string           `json:"keyid,omitempty"`
	Subject   []attest.Subject `json:"subject"`
	Predicate json.RawMessage  `json:"predicate"`
}

// decodeOne decodes exactly one JSON value into v, refusing a field v does not have
// and anything after the value.
func decodeOne(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

// signStatement signs an in-toto statement in the standard DSSE envelope, so a tool
// that reads a standard predicate (in-toto's test-result, OpenVEX) takes it as it is.
// The harness signs what it is given: a statement means what its maker derived it
// from, so the reader rebuilds the predicate from the evidence it names and compares.
func signStatement(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign-statement", flag.ContinueOnError)
	keyPath := fs.String("key", "", "the signing key (PEM PKCS #8 Ed25519)")
	predicateType := fs.String("type", "", "the predicate type URI")
	out := fs.String("out", "", "where to write the envelope (never over an existing file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *predicateType == "" || *out == "" || fs.NArg() != 1 {
		return errors.New("sign-statement needs -type URI, -out FILE and one STATEMENT.json")
	}
	signer, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var in signedStatement
	if err := decodeOne(raw, &in); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	if in.KeyID != "" {
		return fmt.Errorf("%s: keyid is what open-statement prints, not an input", fs.Arg(0))
	}
	if len(in.Predicate) == 0 {
		return fmt.Errorf("%s: no predicate", fs.Arg(0))
	}
	env, err := signer.SignStatement(*predicateType, in.Subject, in.Predicate)
	if err != nil {
		return err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed a statement of type %s about %d subject(s) with key %s\n", *predicateType, len(in.Subject), signer.KeyID())
	return nil
}

// openStatement checks an envelope against a trusted key and a predicate type and
// prints the statement it carries. It proves who signed which statement, nothing
// about whether the predicate is true.
func openStatement(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("open-statement", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "the signer's public key (PEM PKIX Ed25519)")
	predicateType := fs.String("type", "", "the predicate type URI the statement must carry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubPath == "" || *predicateType == "" || fs.NArg() != 1 {
		return errors.New("open-statement needs -pub FILE, -type URI and one ENVELOPE.json")
	}
	pub, err := loadPublic(*pubPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if len(raw) > attest.MaxLineBytes {
		// Every other reader is bounded; this one read a file whole (review, 2026-10-26).
		return fmt.Errorf("%s is larger than %d bytes, the most an envelope may be", fs.Arg(0), attest.MaxLineBytes)
	}
	var env attest.Envelope
	if err := decodeOne(raw, &env); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	var predicate json.RawMessage
	subjects, err := attest.NewVerifier(pub).OpenStatement(env, *predicateType, &predicate)
	if err != nil {
		return err
	}
	data, err := json.Marshal(signedStatement{KeyID: attest.KeyID(pub), Subject: subjects, Predicate: predicate})
	if err != nil {
		return err
	}
	_, err = stdout.Write(append(data, '\n'))
	return err
}

// readLine reads line n of a bundle and nothing after it, parsing that line alone with
// the bundle reader's strict rules: a line being written after it, or a malformed line
// elsewhere, does not stop a stored line from being checked. Lines before it are only
// counted, in bounded memory.
// readRawLine reads line n of path, newline included, bounded as a bundle line is.
func readRawLine(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 64<<10)
	for i := 1; i < n; i++ {
		for {
			_, err := br.ReadSlice('\n')
			if err == nil {
				break
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("%s has %d lines, not %d", path, i-1, n)
			}
			return nil, err
		}
	}
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > attest.MaxLineBytes {
			return nil, fmt.Errorf("%w: line %d of %s is longer than a bundle line may be", attest.ErrLine, n, path)
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return nil, fmt.Errorf("%s has %d lines, not %d", path, n-1, n)
			}
			return nil, fmt.Errorf("%w: line %d of %s is not finished (no newline): it may still be being written", attest.ErrLine, n, path)
		}
		return nil, err
	}
	return line, nil
}

// readLine reads line n of a bundle as ReadBundle reads it: a link is required.
func readLine(path string, n int) (attest.Entry, error) {
	line, err := readRawLine(path, n)
	if err != nil {
		return attest.Entry{}, err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(line))
	if err != nil {
		return attest.Entry{}, fmt.Errorf("line %d of %s: %w", n, path, err)
	}
	return entries[0], nil
}

// readCallLine reads line n as readLine does, but without ReadBundle's link
// requirement, since a line from before links has none (verify-record). The line is
// still exactly the harness's encoding of its entry.
func readCallLine(path string, n int) (attest.Entry, error) {
	line, err := readRawLine(path, n)
	if err != nil {
		return attest.Entry{}, err
	}
	var e attest.Entry
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return attest.Entry{}, fmt.Errorf("line %d of %s: %w", n, path, err)
	}
	canonical, err := json.Marshal(e)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSuffix(line, []byte("\n"))) {
		return attest.Entry{}, fmt.Errorf("line %d of %s: %w", n, path, attest.ErrLine)
	}
	return e, nil
}

// verifyRecord checks one call line with no link: a line from before links, or a
// linked line whose link is not read here.
func verifyRecord(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify-record", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "the harness's public key (PEM PKIX Ed25519)")
	line := fs.Int("line", 0, "the line to check, from 1")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubPath == "" || *line < 1 || fs.NArg() != 1 {
		return errors.New("verify-record needs -pub FILE, -line N (from 1) and one BUNDLE")
	}
	pub, err := loadPublic(*pubPath)
	if err != nil {
		return err
	}
	entry, err := readCallLine(fs.Arg(0), *line)
	if err != nil {
		return err
	}
	if len(entry.Request) == 0 && len(entry.Response) == 0 {
		return fmt.Errorf("line %d of %s holds no call: it is a checkpoint or a session's close statement", *line, fs.Arg(0))
	}
	rec, err := attest.VerifyCall(attest.NewVerifier(pub), entry)
	if err != nil {
		return err
	}
	what := "a single run"
	if rec.Session != "" {
		what = fmt.Sprintf("call %d of session %s…", rec.Sequence, prefix(rec.Session, 12))
	}
	if rec.Unanswered != "" {
		what += fmt.Sprintf(", which ended without an answer (%s) and may have run", rec.Unanswered)
	}
	linked := "The line carries no link"
	if entry.Link != nil {
		linked = "The line carries a link this check did not read (plimsoll-attest verify-entry reads it)"
	}
	fmt.Fprintf(stdout, "record verified: line %d, signed by key %s: a version %d record %s, %s; it states provider %s and isolation %q. "+
		"It authenticates the recorded request and response, not that what the guest printed is true. %s. "+
		"Not established by this check: the line's place in any bundle, so a holder could have dropped or reordered such lines unseen\n",
		*line, attest.KeyID(pub), rec.Version, rec.SHA256, what, rec.Provider, rec.Isolation, linked)
	return nil
}

func replay(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	withGrants := fs.Bool("with-grants", false, "send recorded requests that carry a grant profile too; they call the upstream API again")
	daemon := fs.String("daemon", "", "the daemon's base URL")
	pubPath := fs.String("pub", "", "the harness's public key (PEM PKIX Ed25519); the bundle is verified before anything is sent")
	timeout := fs.Duration("timeout", 6*time.Minute, "how long to wait for each run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *daemon == "" || *pubPath == "" || fs.NArg() != 1 {
		return errors.New("replay needs -daemon URL, -pub FILE and one BUNDLE")
	}
	pub, err := loadPublic(*pubPath)
	if err != nil {
		return err
	}
	v := attest.NewVerifier(pub)
	entries, err := readBundle(fs.Arg(0))
	if err != nil {
		return err
	}
	// Verify before dialing: a bundle that does not verify sends nothing anywhere.
	if _, err := attest.VerifyBundle(entries, v); err != nil {
		return err
	}
	r, err := remote(*daemon)
	if err != nil {
		return err
	}
	send := func(ctx context.Context, req *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		ctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		resp, _, err := r.Exchange(ctx, req)
		return resp, err
	}
	opts := attest.ReplayOptions{WithGrants: *withGrants}
	results, err := attest.Replay(context.Background(), entries, v, opts, send)
	if err != nil {
		return err
	}
	sessions, err := attest.ReplaySessions(context.Background(), entries, v, opts, func(ctx context.Context) (attest.SessionSender, error) {
		s, err := r.OpenSession(ctx, client.SessionOptions{})
		if err != nil {
			return nil, err
		}
		return sessionSender{s: s, timeout: *timeout}, nil
	})
	if err != nil {
		return err
	}
	results = append(results, sessions...)
	differ, skipped := 0, 0
	for _, res := range results {
		switch {
		case errors.Is(res.Err, attest.ErrNotReplayable):
			skipped++
			fmt.Fprintf(stdout, "entry %d: not replayed: %v\n", res.Entry, res.Err)
		case res.Err != nil:
			differ++
			fmt.Fprintf(stdout, "entry %d: the replay failed: %v\n", res.Entry, res.Err)
		case res.Unanswered != "":
			// The recorded call ended without a result, so there is nothing to compare;
			// it used to print as a different result (review, 2026-10-26).
			skipped++
			fmt.Fprintf(stdout, "entry %d: the recorded call ended without a result (%s), nothing to compare; the replay gave %s\n", res.Entry, res.Unanswered, prefix(res.Replayed, 16))
		case res.Match() && res.Session != "":
			fmt.Fprintf(stdout, "entry %d (session %s…): same result (%s)\n", res.Entry, prefix(res.Session, 12), prefix(res.Recorded, 16))
		case res.Match():
			fmt.Fprintf(stdout, "entry %d: same result (%s)\n", res.Entry, prefix(res.Recorded, 16))
		default:
			differ++
			fmt.Fprintf(stdout, "entry %d: different result: recorded %s, replayed %s\n", res.Entry, prefix(res.Recorded, 16), prefix(res.Replayed, 16))
		}
	}
	if skipped > 0 {
		fmt.Fprintf(stdout, "%d of %d recorded calls were not compared\n", skipped, len(results))
	}
	if differ > 0 {
		return fmt.Errorf("%d of %d replays did not reproduce the recorded result", differ, len(results))
	}
	return nil
}

// sessionSender replays a recorded session's calls into a fresh client session.
type sessionSender struct {
	s       *client.Session
	timeout time.Duration
}

func (ss sessionSender) Send(ctx context.Context, req *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, ss.timeout)
	defer cancel()
	resp, _, err := ss.s.Exchange(ctx, req)
	return resp, err
}

func (ss sessionSender) Close(ctx context.Context) error {
	_, err := ss.s.Close(ctx)
	return err
}
