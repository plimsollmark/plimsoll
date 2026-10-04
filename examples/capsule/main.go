// Command capsule states plimsoll's published session bundle as Agent Action
// Capsules (draft-mih-scitt-agent-action-capsule-05), one per call, and writes a
// page with every capsule ID and each verifier's result.
//
// It reads nothing but the bundle and the harness's public key that the sessions
// example published, and it trusts nothing it has not verified: plimsoll's own
// verifier checks the bundle's signatures, records and chain first, and only a
// record it accepted becomes a capsule. Each capsule is marked backfilled, cites
// the run record it came from by digest, and is signed by a key made for this
// run, whose public half is written beside the capsules.
//
// This is its own module because the capsule emitter needs Go 1.27 and brings
// dependencies (COSE, CBOR, database drivers) that plimsoll's own module does not
// take on. Run it from this directory:
//
//	go run . -aac ../../tmp/aac/venv/bin/agent-action-capsule
//
// -aac names the capsule project's independent Python reference verifier; without
// it the page says that check was not run.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	emit "github.com/action-state-group/capsule-emit-go"
	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
)

//go:embed page.html
var pageHTML string

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "capsule:", err)
		os.Exit(1)
	}
}

// capsule is one sealed call and what the page shows about it.
type capsule struct {
	Sequence  uint64
	Session   string
	Verdict   string
	Status    string
	ID        string
	Parent    string
	Record    string // the plimsoll run record's SHA-256, the capsule's source_ref
	Result    string // what the call's own code did
	Payload   []byte
	Envelope  []byte
	GoCapsule string // VerifyCapsule's verdict
	GoEnv     string // VerifyEnvelope's verdict
}

// ran is a check that was run.
func ran(verifier, what, want, got string, ok bool) check {
	return check{Verifier: verifier, What: what, Want: want, Got: got, OK: ok}
}

// check is one verifier run the page reports.
type check struct {
	Verifier string
	What     string
	Want     string
	Got      string
	OK       bool
	Skipped  bool // not run: shown on the page, never counted as a failure
}

func run() error {
	bundlePath := flag.String("bundle", filepath.Join("..", "..", "docs", "examples", "sessions", "bundle.jsonl"), "the signed session bundle to state as capsules")
	pubPath := flag.String("pub", filepath.Join("..", "..", "docs", "examples", "sessions", "harness.pub"), "the harness public key that signed the bundle")
	outDir := flag.String("out", filepath.Join("..", "..", "docs", "examples", "capsule"), "where the page, capsules and producer key go")
	importedAt := flag.String("imported-at", publishedImportedAt, "the import time every capsule states (RFC 3339); the default is the published import's, which reproduces every published capsule ID")
	aac := flag.String("aac", "", "path to the capsule project's Python reference verifier, agent-action-capsule")
	flag.Parse()

	at, err := time.Parse(time.RFC3339, *importedAt)
	if err != nil {
		return fmt.Errorf("-imported-at: %w", err)
	}

	bundleBytes, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	pubPEM, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		return err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(bundleBytes))
	if err != nil {
		return err
	}
	var checks []check

	// plimsoll's verifier first: nothing becomes a capsule that it did not accept.
	rep, err := attest.VerifyBundle(entries, attest.NewVerifier(pub))
	if err != nil {
		return fmt.Errorf("plimsoll's verifier refused the bundle, so nothing was stated: %w", err)
	}
	checks = append(checks, ran("plimsoll attest (Go)", "the published session bundle: every signature, every record against its stored request and response, the bundle's chain of links and its checkpoint, the session's chain and its close statement",
		"accepted", fmt.Sprintf("accepted: %s, %s", plural(rep.Runs, "single run"), plural(len(rep.Sessions), "session")), true))
	tail, err := dropLastCall(entries)
	if err != nil {
		return err
	}
	_, terr := attest.VerifyBundle(tail, attest.NewVerifier(pub))
	checks = append(checks, ran("plimsoll attest (Go)", "the bundle with its last call removed (the next line's link names the removed line, and the close statement still counts the call)",
		"refused", verdictText(terr == nil, errText(terr)), terr != nil))

	src := publishedSource(bundleBytes, at.UTC())

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	identity, err := emit.NewEd25519SigningIdentity(priv)
	if err != nil {
		return err
	}
	producerPub := priv.Public().(ed25519.PublicKey)

	caps, err := state(entries, src)
	if err != nil {
		return err
	}
	for i := range caps {
		env, err := emit.Sign(emit.BuiltPayload{CapsuleID: caps[i].ID, JSON: caps[i].Payload}, identity)
		if err != nil {
			return fmt.Errorf("call %d sign: %w", caps[i].Sequence, err)
		}
		caps[i].Envelope = env
		if err := goVerify(&caps[i], producerPub); err != nil {
			return err
		}
	}
	checks = append(checks, ran("capsule-emit-go (Go)", fmt.Sprintf("each of the %d capsules: VerifyCapsule (structure and identity) and VerifyEnvelope (the COSE_Sign1 signature, from the key written beside them)", len(caps)),
		"all accepted", "all accepted", true))
	tampered, err := goTamper(caps[len(caps)/2])
	if err != nil {
		return err
	}
	checks = append(checks, tampered...)

	if err := write(*outDir, caps, producerPub); err != nil {
		return err
	}
	if *aac != "" {
		py, err := pyVerify(*aac, *outDir, caps)
		if err != nil {
			return err
		}
		checks = append(checks, py...)
	} else {
		checks = append(checks, check{Verifier: "agent-action-capsule (Python)", What: "the independent reference verifier", Want: "run", Got: "not run: pass -aac", Skipped: true})
	}
	for _, c := range checks {
		if !c.OK && !c.Skipped {
			return fmt.Errorf("check failed: %s, %s: want %s, got %s", c.Verifier, c.What, c.Want, c.Got)
		}
	}
	if err := render(filepath.Join(*outDir, "index.html"), caps, checks, src, len(entries)); err != nil {
		return err
	}
	for _, c := range caps {
		fmt.Printf("call %d | %-8s | %s | record %s | %s\n", c.Sequence, c.Verdict, c.ID, c.Record[:16], c.Result)
	}
	for _, c := range checks {
		fmt.Printf("check    | %-30s | %s -> %s\n", c.Verifier, c.What, c.Got)
	}
	fmt.Printf("page     | wrote %s with %d capsules; imported-at %s\n", filepath.Join(*outDir, "index.html"), len(caps), at.Format(time.RFC3339))
	return nil
}

// state builds one unsigned capsule per call in a bundle plimsoll's verifier has
// already accepted, chaining each session's calls in order. Nothing here uses a
// key, so the capsule IDs are a function of the bundle and src alone.
func state(entries []attest.Entry, src source) ([]capsule, error) {
	var caps []capsule
	last := map[string]string{} // session fingerprint -> the previous call's capsule ID
	for i, e := range entries {
		if len(e.Request) == 0 {
			continue // a session's close statement: it states a count, not a run
		}
		req, resp := &plimsollv1.RunRequest{}, &plimsollv1.RunResponse{}
		if err := proto.Unmarshal(e.Request, req); err != nil {
			return nil, fmt.Errorf("entry %d request: %w", i, err)
		}
		if err := proto.Unmarshal(e.Response, resp); err != nil {
			return nil, fmt.Errorf("entry %d response: %w", i, err)
		}
		rec, err := record.CheckExchange(req, resp)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		parent := ""
		if rec.Session != "" {
			parent = last[rec.Session]
		}
		in, err := capsuleInput(*rec, req, resp, parent, src)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		built, err := emit.Build(in)
		if err != nil {
			return nil, fmt.Errorf("entry %d build: %w", i, err)
		}
		if rec.Session != "" {
			last[rec.Session] = built.CapsuleID
		}
		caps = append(caps, capsule{
			Sequence: rec.Sequence, Session: rec.Session, ID: built.CapsuleID, Parent: parent, Record: rec.SHA256,
			Verdict: string(in.Disposition.VerdictClass), Status: string(in.Effect.Status), Result: summary(resp),
			Payload: built.JSON,
		})
	}
	if len(caps) == 0 {
		return nil, errors.New("the bundle holds no call")
	}
	return caps, nil
}

// goVerify runs the emitter's own verifiers over one capsule, and refuses one
// whose envelope was signed by any key but this run's.
func goVerify(c *capsule, producer ed25519.PublicKey) error {
	res, err := emit.VerifyCapsule(c.Payload)
	if err != nil || !res.OK {
		return fmt.Errorf("VerifyCapsule refused capsule %s: %v %+v", c.ID, err, res)
	}
	if res.CapsuleID == nil || *res.CapsuleID != c.ID {
		return fmt.Errorf("VerifyCapsule computed another ID for capsule %s", c.ID)
	}
	auth, err := emit.VerifyEnvelope(c.ID, c.Envelope)
	if err != nil {
		return fmt.Errorf("VerifyEnvelope refused capsule %s: %w", c.ID, err)
	}
	if !bytes.Equal(auth.PublicKey, producer) {
		return fmt.Errorf("capsule %s is signed by another key", c.ID)
	}
	c.GoCapsule, c.GoEnv = "accepted", "accepted"
	return nil
}

// goTamper shows the Go verifiers refusing a capsule with its verdict changed,
// and an envelope moved onto another capsule's ID.
func goTamper(c capsule) ([]check, error) {
	edited := bytes.Replace(c.Payload, []byte(`"`+c.Verdict+`"`), []byte(`"denied"`), 1)
	if bytes.Equal(edited, c.Payload) {
		return nil, fmt.Errorf("could not find the verdict in capsule %s to change it", c.ID)
	}
	res, err := emit.VerifyCapsule(edited)
	got := "accepted"
	if err != nil || !res.OK {
		got = "refused"
	}
	out := []check{ran("capsule-emit-go (Go)", fmt.Sprintf("call %d's capsule with its verdict changed from %s to denied", c.Sequence, c.Verdict), "refused", got, got == "refused")}

	other := strings.Repeat("0", 64)
	_, err = emit.VerifyEnvelope(other, c.Envelope)
	got = "accepted"
	if err != nil {
		got = "refused"
	}
	out = append(out, ran("capsule-emit-go (Go)", fmt.Sprintf("call %d's signature presented for a different capsule ID", c.Sequence), "refused", got, got == "refused"))
	return out, nil
}

// write lays out what a reader needs to check the page: the store the Python
// verifier reads (one JSON file per capsule, named by ID), the envelopes, and the
// producer's public key.
func write(dir string, caps []capsule, pub ed25519.PublicKey) error {
	store := filepath.Join(dir, "capsules")
	if err := os.RemoveAll(store); err != nil {
		return err
	}
	if err := os.MkdirAll(store, 0o755); err != nil {
		return err
	}
	var envs bytes.Buffer
	for _, c := range caps {
		if err := os.WriteFile(filepath.Join(store, c.ID+".json"), append(append([]byte(nil), c.Payload...), '\n'), 0o644); err != nil {
			return err
		}
		line, err := json.Marshal(map[string]string{"capsule_id": c.ID, "cose_sign1": base64.StdEncoding.EncodeToString(c.Envelope)})
		if err != nil {
			return err
		}
		envs.Write(append(line, '\n'))
	}
	if err := os.WriteFile(filepath.Join(dir, "envelopes.jsonl"), envs.Bytes(), 0o644); err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "producer.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
}

// pyVerify runs the independent Python reference verifier: each capsule, the
// store's chain checks, and two tampered copies it must refuse.
func pyVerify(bin, dir string, caps []capsule) ([]check, error) {
	store := filepath.Join(dir, "capsules")
	var out []check
	accepted := 0
	for _, c := range caps {
		if ok, _ := pyRun(bin, filepath.Join(store, c.ID+".json")); ok {
			accepted++
		}
	}
	out = append(out, ran("agent-action-capsule (Python)", fmt.Sprintf("each of the %d capsules on its own", len(caps)),
		fmt.Sprintf("%d accepted", len(caps)), fmt.Sprintf("%d accepted", accepted), accepted == len(caps)))

	ok, detail := pyRun(bin, "--store", store)
	out = append(out, ran("agent-action-capsule (Python)", "the capsules directory as one store (chain checks across capsules)",
		"accepted", verdictText(ok, detail), ok))

	tmp, err := os.MkdirTemp("", "capsule-tamper-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	mid := caps[len(caps)/2]
	edited := bytes.Replace(mid.Payload, []byte(`"`+mid.Verdict+`"`), []byte(`"denied"`), 1)
	path := filepath.Join(tmp, "edited.json")
	if err := os.WriteFile(path, edited, 0o644); err != nil {
		return nil, err
	}
	ok, detail = pyRun(bin, path)
	out = append(out, ran("agent-action-capsule (Python)", fmt.Sprintf("call %d's capsule with its verdict changed from %s to denied", mid.Sequence, mid.Verdict),
		"refused", verdictText(ok, detail), !ok))

	dropped := filepath.Join(tmp, "dropped")
	if err := os.MkdirAll(dropped, 0o755); err != nil {
		return nil, err
	}
	for _, c := range caps {
		if c.ID == mid.ID {
			continue
		}
		if err := os.WriteFile(filepath.Join(dropped, c.ID+".json"), c.Payload, 0o644); err != nil {
			return nil, err
		}
	}
	ok, detail = pyRun(bin, "--store", dropped)
	out = append(out, ran("agent-action-capsule (Python)", fmt.Sprintf("the store with call %d's capsule removed", mid.Sequence),
		"refused", verdictText(ok, detail), !ok))

	// The tail: no capsule names the last one as its parent, so a store check
	// cannot see it go. Catching that is the witnessed log's job, not this
	// verifier's; the check records the behaviour, it does not grade it.
	lastCap := caps[len(caps)-1]
	short := filepath.Join(tmp, "short")
	if err := os.MkdirAll(short, 0o755); err != nil {
		return nil, err
	}
	for _, c := range caps {
		if c.ID == lastCap.ID {
			continue
		}
		if err := os.WriteFile(filepath.Join(short, c.ID+".json"), c.Payload, 0o644); err != nil {
			return nil, err
		}
	}
	ok, detail = pyRun(bin, "--store", short)
	out = append(out, ran("agent-action-capsule (Python)", fmt.Sprintf("the store with the last call's capsule (call %d) removed, and no witnessed log", lastCap.Sequence),
		"accepted: a store check cannot see a missing tail; a witnessed log checkpoint is what catches it", verdictText(ok, detail), ok))

	env, err := pyEnvelopes(filepath.Join(filepath.Dir(bin), "python"), dir, caps)
	if err != nil {
		return nil, err
	}
	return append(out, env...), nil
}

// pyEnvelopes checks every signature with the capsule project's own Python
// verifier (verify_envelopes.py), which reaches COSE_Sign1 through scitt-cose's
// from-scratch implementation: no COSE code is shared with the Go signer.
func pyEnvelopes(python, dir string, caps []capsule) ([]check, error) {
	b, err := exec.Command(python, "verify_envelopes.py", dir).Output()
	if err != nil {
		return nil, fmt.Errorf("verify_envelopes.py: %w (install agent-action-capsule[envelope])", err)
	}
	var r struct {
		Envelopes int `json:"envelopes"`
		Accepted  int `json:"accepted_with_producer_key"`
		Flipped   struct {
			OK    bool     `json:"ok"`
			Codes []string `json:"codes"`
		} `json:"flipped_bit"`
		Moved struct {
			OK    bool     `json:"ok"`
			Codes []string `json:"codes"`
		} `json:"moved"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("verify_envelopes.py output: %w", err)
	}
	const who = "agent-action-capsule with scitt-cose (Python)"
	mid := caps[len(caps)/2]
	next := caps[(len(caps)/2+1)%len(caps)]
	return []check{
		ran(who, fmt.Sprintf("each of the %d signatures (COSE_Sign1 over the capsule ID), authenticated to the key in producer.pub", r.Envelopes),
			fmt.Sprintf("%d accepted", len(caps)), fmt.Sprintf("%d accepted", r.Accepted), r.Envelopes == len(caps) && r.Accepted == len(caps)),
		ran(who, fmt.Sprintf("call %d's signature with one bit flipped", mid.Sequence),
			"refused", verdictText(r.Flipped.OK, strings.Join(r.Flipped.Codes, "; ")), !r.Flipped.OK),
		ran(who, fmt.Sprintf("call %d's signature presented for call %d's capsule", mid.Sequence, next.Sequence),
			"refused", verdictText(r.Moved.OK, strings.Join(r.Moved.Codes, "; ")), !r.Moved.OK),
	}, nil
}

// dropLastCall is the bundle without its last call entry, close statement kept.
func dropLastCall(entries []attest.Entry) ([]attest.Entry, error) {
	for i := len(entries) - 1; i >= 0; i-- {
		if len(entries[i].Request) > 0 {
			return append(append([]attest.Entry(nil), entries[:i]...), entries[i+1:]...), nil
		}
	}
	return nil, errors.New("the bundle holds no call")
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// summary is what a call's own code did, in a few words.
func summary(resp *plimsollv1.RunResponse) string {
	switch r := resp.GetResult().(type) {
	case *plimsollv1.RunResponse_Javascript:
		s := fmt.Sprintf("snippet, exit %d", r.Javascript.GetExitCode())
		if r.Javascript.GetTimedOut() {
			s += ", timed out"
		}
		return s
	case *plimsollv1.RunResponse_Project:
		var codes []string
		for _, st := range r.Project.GetSteps() {
			codes = append(codes, fmt.Sprint(st.GetExitCode()))
		}
		return fmt.Sprintf("project, %s, step exits %s", outcomeWord(r.Project.GetOutcome()), strings.Join(codes, ","))
	case *plimsollv1.RunResponse_Module:
		return fmt.Sprintf("module, %s, %d rows", outcomeWord(r.Module.GetOutcome()), len(r.Module.GetRuns()))
	}
	return "no result"
}

func outcomeWord(o plimsollv1.ProjectOutcome) string {
	return strings.ToLower(strings.TrimPrefix(o.String(), "PROJECT_OUTCOME_"))
}

// pyRun runs the Python verifier and returns whether it accepted, with its
// error findings (the "[error]" lines) as the reason, or "no errors".
func pyRun(bin string, args ...string) (bool, string) {
	cmd := exec.Command(bin, append([]string{"verify"}, args...)...)
	b, err := cmd.CombinedOutput()
	var errs []string
	for _, line := range strings.Split(string(b), "\n") {
		if _, after, ok := strings.Cut(line, "[error] "); ok {
			errs = append(errs, strings.TrimSpace(after))
		}
	}
	if len(errs) == 0 {
		return err == nil, "no errors"
	}
	return err == nil, strings.Join(errs, "; ")
}

// hexDigest is a SHA-256 in hex, as the verifiers print them.
var hexDigest = regexp.MustCompile(`[0-9a-f]{64}`)

// verdictText is a verifier's answer and its reasons, whole: each 64-digit
// digest is shortened to its first 16 digits so the reasons stay readable.
func verdictText(ok bool, detail string) string {
	v := "refused"
	if ok {
		v = "accepted"
	}
	if detail == "" {
		return v
	}
	return v + ": " + hexDigest.ReplaceAllStringFunc(detail, func(h string) string { return h[:16] + "..." })
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func render(path string, caps []capsule, checks []check, src source, entries int) error {
	t, err := template.New("page").Funcs(template.FuncMap{
		"short": func(s string) string {
			if len(s) > 16 {
				return s[:16] + "..."
			}
			return s
		},
	}).Parse(pageHTML)
	if err != nil {
		return err
	}
	passed, run := 0, 0
	for _, c := range checks {
		if c.Skipped {
			continue
		}
		run++
		if c.OK {
			passed++
		}
	}
	var b bytes.Buffer
	if err := t.Execute(&b, map[string]any{
		"Passed":     passed,
		"Run":        run,
		"Capsules":   caps,
		"Checks":     checks,
		"Batch":      src.batch,
		"ImportedAt": src.importedAt.Format(time.RFC3339),
		"Entries":    entries,
		"Spec":       emit.SpecVersion,
	}); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}
