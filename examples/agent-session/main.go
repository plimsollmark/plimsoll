// Command agent-session gathers runs carrying one coding session's trace through plimsoll's MCP
// server into a signed statement: which runs, behind which isolation tier, on which
// provider, and the weakest tier among them.
//
// The MCP server signs every run into its receipts directory (PLIMSOLL_MCP_RECEIPTS_DIR);
// hook.py, beside this file, makes each run carry the coding session's ID as its trace,
// which the receipt signs with the request. This reads the receipts, checks every file
// whole against the receipts key, and keeps the runs whose trace is the session's.
//
//	go run ./examples/agent-session -receipts DIR -pub harness.pub -session ID -key harness.key -out session.intoto.json
//	go run ./examples/agent-session -receipts DIR -pub harness.pub -session ID -check session.intoto.json
//
// A statement covers the runs that carried the trace when it was made, and records each
// receipts file it read by length and SHA-256; -check confirms each file still begins with
// those bytes, that the runs with the trace inside them are exactly the statement's, as
// stated, and reports runs with the trace it does not cover (added since, or in files it
// could not read). The trace is a caller-supplied label, not authenticated session identity:
// another caller can reuse it. Code run outside plimsoll leaves no receipt here.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// PredicateType names the statement this command signs.
const PredicateType = "https://plimsollmark.github.io/plimsoll/agent-session-runs/v1"

// traceForm is the daemon's rule for a trace; hook.py applies the same one.
// hashedPrefix begins every trace made by hashing a session ID.
const hashedPrefix = "session-sha256:"

var traceForm = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// TraceFor is the trace a coding session's runs carry: the session ID itself when it fits
// the rule and does not itself begin "session-sha256:", else "session-sha256:" and the first
// 48 hex digits of its SHA-256. An ID that begins with the prefix is always hashed, so no
// literal ID can take the trace another session's ID hashes to.
func TraceFor(sessionID string) string {
	if traceForm.MatchString(sessionID) && !strings.HasPrefix(sessionID, hashedPrefix) {
		return sessionID
	}
	sum := sha256.Sum256([]byte(sessionID))
	return hashedPrefix + hex.EncodeToString(sum[:])[:48]
}

// Run is one run of the session as its signed record states it.
type Run struct {
	Record      string    `json:"record"`
	File        string    `json:"file"`
	Line        int       `json:"line"`
	Isolation   string    `json:"isolation"`
	Provider    string    `json:"provider"`
	Environment string    `json:"environment,omitempty"`
	Started     time.Time `json:"started"`
	Ended       time.Time `json:"ended"`
	Unanswered  string    `json:"unanswered,omitempty"`
}

// File is a receipts file read whole when the statement was made: its name, its length then,
// and the SHA-256 of those bytes. Receipts files only grow, so a later check confirms that
// each one still begins with exactly these bytes, and that the runs with the trace inside
// them are exactly the statement's.
type File struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Predicate is the statement's claim.
type Predicate struct {
	Trace            string   `json:"trace"`
	Runs             []Run    `json:"runs"`
	WeakestIsolation string   `json:"weakestIsolation"`
	Files            []File   `json:"files"`
	UnverifiedFiles  []string `json:"unverifiedFiles,omitempty"`
}

// gather reads every receipts file in dir, checks each whole under pub, and returns the
// runs that carry trace. A file that does not verify (a session still open, a segment a
// failed write ended) stops it, unless ignoreUnverified, when the file is named in the
// predicate and none of its runs counts.
func gather(dir string, pub ed25519.PublicKey, trace string, ignoreUnverified bool) (Predicate, error) {
	p := Predicate{Trace: trace, Runs: []Run{}, Files: []File{}}
	var names []string
	for _, pattern := range []string{"runs-*.jsonl", "session-*.jsonl"} {
		m, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return p, err
		}
		names = append(names, m...)
	}
	slices.Sort(names)
	if len(names) == 0 {
		return p, fmt.Errorf("%s holds no receipts files (runs-*.jsonl, session-*.jsonl)", dir)
	}
	v := attest.NewVerifier(pub)
	for _, path := range names {
		name := filepath.Base(path)
		raw, err := os.ReadFile(path)
		if err != nil {
			return p, err
		}
		entries, err := attest.ReadBundle(strings.NewReader(string(raw)))
		if err == nil {
			_, err = attest.VerifyBundle(entries, v)
		}
		if err != nil {
			if !ignoreUnverified {
				return p, fmt.Errorf("%s does not verify whole (close any open sandbox first, or pass -ignore-unverified): %w", name, err)
			}
			p.UnverifiedFiles = append(p.UnverifiedFiles, name)
			continue
		}
		sum := sha256.Sum256(raw)
		p.Files = append(p.Files, File{Name: name, Bytes: int64(len(raw)), SHA256: hex.EncodeToString(sum[:])})
		for n, e := range entries {
			if e.Request == nil {
				continue // a checkpoint or a session's close
			}
			var req plimsollv1.RunRequest
			if err := proto.Unmarshal(e.Request, &req); err != nil {
				return p, fmt.Errorf("%s line %d: %w", name, n+1, err)
			}
			if req.GetTraceId() != trace {
				continue
			}
			rec, err := v.Verify(e.Envelope)
			if err != nil {
				return p, fmt.Errorf("%s line %d: %w", name, n+1, err)
			}
			p.Runs = append(p.Runs, Run{Record: rec.SHA256, File: name, Line: n + 1, Isolation: rec.Isolation,
				Provider: rec.Provider, Environment: rec.Environment, Started: rec.Started.UTC(), Ended: rec.Ended.UTC(),
				Unanswered: rec.Unanswered})
		}
	}
	slices.SortStableFunc(p.Runs, func(a, b Run) int { return a.Started.Compare(b.Started) })
	p.WeakestIsolation = weakest(p.Runs)
	return p, nil
}

// weakest is the lowest tier among the runs, as plimsoll orders tiers; a tier plimsoll
// does not know counts as none.
func weakest(runs []Run) string {
	if len(runs) == 0 {
		return ""
	}
	low := sandbox.ParseIsolationClass(runs[0].Isolation)
	for _, r := range runs[1:] {
		if c := sandbox.ParseIsolationClass(r.Isolation); c < low {
			low = c
		}
	}
	return low.String()
}

func subjects(runs []Run) []attest.Subject {
	out := make([]attest.Subject, len(runs))
	for i, r := range runs {
		out[i] = attest.Subject{Name: "plimsoll run record", Digest: map[string]string{"sha256": r.Record}}
	}
	return out
}

// check opens a statement under pub and confirms every run it lists is in got, the
// receipts as they are now, exactly as stated, and that its weakest tier and trace are
// right. It returns how many runs carry the trace now that the statement does not list.
// check confirms a statement against the receipts as they are now and returns how many runs
// with its trace it does not cover: runs added since, or in files it could not read.
func check(env attest.Envelope, pub ed25519.PublicKey, got Predicate, dir string) (int, error) {
	var stated Predicate
	subs, err := attest.NewVerifier(pub).OpenStatement(env, PredicateType, &stated)
	if err != nil {
		return 0, err
	}
	if stated.Trace != got.Trace {
		return 0, fmt.Errorf("the statement is about trace %q, not %q", stated.Trace, got.Trace)
	}
	if len(stated.Runs) == 0 || stated.WeakestIsolation != weakest(stated.Runs) {
		return 0, errors.New("the statement's weakest tier is not the weakest of its runs")
	}
	if fmt.Sprint(subs) != fmt.Sprint(subjects(stated.Runs)) {
		return 0, errors.New("the statement's subjects are not its runs' records")
	}
	// By file and line: two runs may share a record digest (the same request and result
	// in the same millisecond), never a line.
	at := func(r Run) string { return fmt.Sprintf("%s:%d", r.File, r.Line) }
	now := map[string]Run{}
	for _, r := range got.Runs {
		now[at(r)] = r
	}
	// Each file the statement read must still begin with the bytes it read; inside[name] is
	// how many lines those bytes hold.
	inside := map[string]int{}
	for _, f := range stated.Files {
		if f.Name != filepath.Base(f.Name) || f.Bytes < 0 {
			return 0, fmt.Errorf("the statement names a receipts file %q this check will not read", f.Name)
		}
		raw, err := os.ReadFile(filepath.Join(dir, f.Name))
		if err != nil {
			return 0, fmt.Errorf("%s, which the statement read, cannot be read now: %w", f.Name, err)
		}
		if int64(len(raw)) < f.Bytes {
			return 0, fmt.Errorf("%s is shorter than when the statement read it", f.Name)
		}
		if sum := sha256.Sum256(raw[:f.Bytes]); hex.EncodeToString(sum[:]) != f.SHA256 {
			return 0, fmt.Errorf("%s does not begin with the bytes the statement read", f.Name)
		}
		inside[f.Name] = bytes.Count(raw[:f.Bytes], []byte("\n"))
	}
	for _, r := range stated.Runs {
		have, ok := now[at(r)]
		if !ok {
			return 0, fmt.Errorf("run %s… is not in the receipts with this trace", r.Record[:12])
		}
		if have != r {
			return 0, fmt.Errorf("run %s… is stated differently from its signed record", r.Record[:12])
		}
		if n, ok := inside[r.File]; !ok || r.Line > n {
			return 0, fmt.Errorf("run %s… is not inside the part of %s the statement read", r.Record[:12], r.File)
		}
		delete(now, at(r))
	}
	for _, r := range now {
		if n, ok := inside[r.File]; ok && r.Line <= n {
			return 0, fmt.Errorf("run %s… at %s carries the trace inside what the statement read, and the statement leaves it out", r.Record[:12], at(r))
		}
	}
	return len(now), nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "agent-session:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("agent-session", flag.ContinueOnError)
	dir := fs.String("receipts", "", "the MCP server's receipts directory")
	pubPath := fs.String("pub", "", "the receipts key's public half (PEM)")
	session := fs.String("session", "", "the coding session's ID, as the agent's host names it")
	trace := fs.String("trace", "", "the trace itself, instead of -session")
	keyPath := fs.String("key", "", "the key to sign the statement with (PEM); with -out")
	out := fs.String("out", "", "where to write the signed statement (never over a file)")
	checkPath := fs.String("check", "", "a statement to check against the receipts")
	ignore := fs.Bool("ignore-unverified", false, "skip receipts files that do not verify whole, naming them in the statement")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *pubPath == "" || (*session == "") == (*trace == "") || (*out == "") == (*checkPath == "") || fs.NArg() != 0 {
		return errors.New("give -receipts, -pub, one of -session or -trace, and one of -out (with -key) or -check")
	}
	t := *trace
	if *session != "" {
		t = TraceFor(*session)
	} else if !traceForm.MatchString(t) {
		return fmt.Errorf("-trace %q is not a trace plimsoll keeps", t)
	}
	pubPEM, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		return err
	}
	got, err := gather(*dir, pub, t, *ignore)
	if err != nil {
		return err
	}
	if *checkPath != "" {
		raw, err := os.ReadFile(*checkPath)
		if err != nil {
			return err
		}
		var env attest.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return err
		}
		later, err := check(env, pub, got, *dir)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "statement checked: every receipts file it read begins with the bytes it read, and holds exactly its runs with trace %s, as stated; %d run(s) with the trace it does not cover (added since, or in files it could not read)\n", t, later)
		return nil
	}
	if len(got.Runs) == 0 {
		return fmt.Errorf("no run in %s carries trace %s", *dir, t)
	}
	if *keyPath == "" {
		return errors.New("-out needs -key")
	}
	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	key, err := attest.ParsePrivateKey(keyPEM)
	if err != nil {
		return err
	}
	env, err := attest.NewSigner(key).SignStatement(PredicateType, subjects(got.Runs), got)
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
	fmt.Fprintf(stdout, "signed %d run(s) of trace %s, weakest tier %s, from %d receipts file(s)\n", len(got.Runs), t, got.WeakestIsolation, len(got.Files))
	return nil
}
