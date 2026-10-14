package qualify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/adapter/fleetsim"
)

// PredicateType names a qualification statement: the platform's signed account of one
// run's evidence and the verdict it supports. It is separate from the run record the
// attest harness signs, which says what the sandbox was asked and answered; this one
// says what the vendor saw and what follows from it.
const PredicateType = "https://plimsollmark.github.io/plimsoll/examples/adapter/qualification/v1"

// Predicate is a qualification statement's predicate.
type Predicate struct {
	// Run is the run's 1-based line in the bundle of run records.
	Run int `json:"run"`
	// Simulator is the vendor simulator's version, fleetsim.Version.
	Simulator string `json:"simulator"`
	// Adapter is the file the run judged (the probe, for a probe run), as carried in
	// the run's request; Harness is harness.js's SHA-256, "" for a probe run.
	Adapter FileDigest `json:"adapter"`
	Harness string     `json:"harness_sha256,omitempty"`
	// Evidence is what the verdict is made from.
	Evidence Evidence `json:"evidence"`
	// Rules are the rules' outcomes, and Verdict "pass" when every rule held.
	Rules   []Outcome `json:"rules"`
	Verdict string    `json:"verdict"`
}

// FileDigest names a file of the run's request.
type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type statement struct {
	Type          string           `json:"_type"`
	Subject       []attest.Subject `json:"subject"`
	PredicateType string           `json:"predicateType"`
	Predicate     Predicate        `json:"predicate"`
}

// Verdict is the verdict Evaluate's pass gives.
func Verdict(pass bool) string {
	if pass {
		return "pass"
	}
	return "fail"
}

// Sign signs p as an in-toto statement whose subject is the run record with digest
// recordSHA256, in a DSSE envelope, with the same key and encoding the attest harness
// uses for run records.
func Sign(key ed25519.PrivateKey, recordSHA256 string, p Predicate) (attest.Envelope, error) {
	payload, err := json.Marshal(statement{
		Type:          attest.StatementType,
		Subject:       []attest.Subject{{Name: attest.SubjectName, Digest: map[string]string{"sha256": recordSHA256}}},
		PredicateType: PredicateType,
		Predicate:     p,
	})
	if err != nil {
		return attest.Envelope{}, err
	}
	sig := ed25519.Sign(key, attest.PAE(attest.PayloadType, payload))
	return attest.Envelope{
		PayloadType: attest.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []attest.Signature{{KeyID: attest.KeyID(key.Public().(ed25519.PublicKey)), Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// Verified is one statement that passed Verify.
type Verified struct {
	Predicate Predicate
	Record    string // the run record's digest, the statement's subject
}

// Verify checks qualification statements against the bundle of run records they speak
// for. The caller has already verified the bundle (attest.VerifyBundle); entries is it,
// checkpoint included. For every statement it checks:
//
//   - the signature, by pub, over the statement's DSSE encoding;
//   - that its subject is the record of the bundle line it names, and that no two
//     statements name the same line, and every run line has one;
//   - that the adapter (or probe) file, harness.js and plan.json it names are the ones
//     that run's signed request carried, and the step it ran names the scenario;
//   - that the report and exit code it holds are what that run's signed response printed;
//   - that its scenario is the simulator's own definition of that scenario;
//   - that its rules and verdict are what Evaluate makes of its evidence.
//
// And across statements: each adapter run was served under exactly one credential (the
// probe under at most one), and no two runs shared one. What Verify cannot check is the ledger itself: that is the
// vendor's account as the signer read it, and trusting it is trusting the signer.
func Verify(pub ed25519.PublicKey, statements []attest.Envelope, entries []attest.Entry) ([]Verified, error) {
	v := attest.NewVerifier(pub)
	runs := 0
	for _, e := range entries {
		if len(e.Request) > 0 {
			runs++
		}
	}
	if len(statements) != runs {
		return nil, fmt.Errorf("%d statements for %d runs", len(statements), runs)
	}
	seen := map[int]bool{}
	credentials := map[string]int{}
	var out []Verified
	for i, env := range statements {
		p, subject, err := open(pub, env)
		if err != nil {
			return nil, fmt.Errorf("statement %d: %w", i+1, err)
		}
		if p.Run < 1 || p.Run > len(entries) || seen[p.Run] {
			return nil, fmt.Errorf("statement %d: names run %d, which is not a run line or already has a statement", i+1, p.Run)
		}
		seen[p.Run] = true
		entry := entries[p.Run-1]
		rec, err := v.Verify(entry.Envelope)
		if err != nil {
			return nil, fmt.Errorf("statement %d: run %d's record: %w", i+1, p.Run, err)
		}
		if err := check(p, subject, rec.SHA256, entry); err != nil {
			return nil, fmt.Errorf("statement %d (run %d): %w", i+1, p.Run, err)
		}
		for _, c := range p.Evidence.Credentials {
			if prev, dup := credentials[c.ID]; dup {
				return nil, fmt.Errorf("statement %d (run %d): its credential also served run %d", i+1, p.Run, prev)
			}
			credentials[c.ID] = p.Run
		}
		out = append(out, Verified{Predicate: p, Record: subject})
	}
	return out, nil
}

// VerifyOne checks one qualification statement against the one bundle line it speaks
// for, for a holder of that line without the bundle around it: the line itself, as
// attest.VerifyEntry checks it; that the statement names the line's place in its
// bundle; and everything Verify checks of one statement against its run. The checks
// across runs, that every run has one statement and that no credential served two
// runs, are Verify's: one line cannot show them.
func VerifyOne(pub ed25519.PublicKey, env attest.Envelope, entry attest.Entry) (Verified, error) {
	p, subject, err := open(pub, env)
	if err != nil {
		return Verified{}, err
	}
	rec, link, err := attest.VerifyEntry(attest.NewVerifier(pub), entry)
	if err != nil {
		return Verified{}, fmt.Errorf("the run's line: %w", err)
	}
	if uint64(p.Run) != link.Index {
		return Verified{}, fmt.Errorf("the statement names run %d, the line is line %d of its bundle", p.Run, link.Index)
	}
	if err := check(p, subject, rec.SHA256, entry); err != nil {
		return Verified{}, err
	}
	return Verified{Predicate: p, Record: subject}, nil
}

// check is one opened statement (p, with its subject digest) against the line of the
// run it names, whose verified record has digest record.
func check(p Predicate, subject, record string, entry attest.Entry) error {
	if subject != record {
		return fmt.Errorf("its subject %s is not run %d's record %s", short(subject), p.Run, short(record))
	}
	if err := matchRun(p, entry); err != nil {
		return err
	}
	want, ok := fleetsim.Scenarios[p.Evidence.Scenario.Name]
	if !ok || !reflect.DeepEqual(want, p.Evidence.Scenario) || p.Simulator != fleetsim.Version {
		return fmt.Errorf("the scenario is not %s's %q", fleetsim.Version, p.Evidence.Scenario.Name)
	}
	rules, pass := Evaluate(p.Evidence)
	if !reflect.DeepEqual(rules, p.Rules) || Verdict(pass) != p.Verdict {
		return fmt.Errorf("its verdict %q does not follow from its evidence, which gives %q", p.Verdict, Verdict(pass))
	}
	// An adapter run calls the vendor, so the vendor saw its credential; the probe's
	// calls are all refused before the vendor, so it may have seen none.
	if n := len(p.Evidence.Credentials); n > 1 || (n == 0 && p.Evidence.Kind == KindAdapter) {
		return fmt.Errorf("the vendor saw %d credentials, want one", n)
	}
	return nil
}

// open checks env's signature and returns its predicate and subject digest.
func open(pub ed25519.PublicKey, env attest.Envelope) (Predicate, string, error) {
	if env.PayloadType != attest.PayloadType || len(env.Signatures) != 1 || env.Signatures[0].KeyID != attest.KeyID(pub) {
		return Predicate{}, "", errors.New("not one signature by this key")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Predicate{}, "", err
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil || !ed25519.Verify(pub, attest.PAE(env.PayloadType, payload), sig) {
		return Predicate{}, "", errors.New("the signature does not verify")
	}
	var st statement
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if err := d.Decode(&st); err != nil {
		return Predicate{}, "", err
	}
	if st.Type != attest.StatementType || st.PredicateType != PredicateType || len(st.Subject) != 1 || st.Subject[0].Name != attest.SubjectName {
		return Predicate{}, "", errors.New("not a qualification statement")
	}
	return st.Predicate, st.Subject[0].Digest["sha256"], nil
}

// matchRun checks p against what run's signed request carried and response printed.
func matchRun(p Predicate, entry attest.Entry) error {
	req, resp, err := entry.Messages()
	if err != nil {
		return err
	}
	files := map[string]string{}
	for _, f := range req.GetProject().GetFiles() {
		files[f.GetPath()] = f.GetContent()
	}
	steps := req.GetProject().GetSteps()
	results := resp.GetProject().GetSteps()
	if len(steps) != 1 || len(results) != 1 {
		return errors.New("the run is not one project step")
	}
	content, ok := files[p.Adapter.Path]
	if !ok || digest(content) != p.Adapter.SHA256 {
		return fmt.Errorf("the request did not carry %s with that digest", p.Adapter.Path)
	}
	stdout := string(results[0].GetStdout())
	if int(results[0].GetExitCode()) != p.Evidence.ExitCode {
		return fmt.Errorf("the run exited %d, the statement says %d", results[0].GetExitCode(), p.Evidence.ExitCode)
	}
	switch p.Evidence.Kind {
	case KindAdapter:
		if digest(files["harness.js"]) != p.Harness {
			return errors.New("the request did not carry that harness.js")
		}
		var plan Plan
		if err := json.Unmarshal([]byte(files["plan.json"]), &plan); err != nil || !reflect.DeepEqual(plan, p.Evidence.Plan) {
			return errors.New("the request's plan.json is not the statement's plan")
		}
		if want := "node harness.js " + p.Evidence.Scenario.Name + " " + p.Adapter.Path; steps[0] != want {
			return fmt.Errorf("the run's step is %q, not %q", steps[0], want)
		}
		if !sameJSON(ReadReport(stdout), p.Evidence.Report) {
			return errors.New("the report is not the one the run printed")
		}
	case KindProbe:
		if !strings.HasPrefix(steps[0], "node "+p.Adapter.Path+" ") {
			return fmt.Errorf("the run's step is %q", steps[0])
		}
		if !sameJSON(ReadProbe(stdout), p.Evidence.Probe) {
			return errors.New("the probe report is not the one the run printed")
		}
	default:
		return fmt.Errorf("unknown kind %q", p.Evidence.Kind)
	}
	return nil
}

func sameJSON(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Digest is the SHA-256 the statements name files by.
func Digest(s string) string { return digest(s) }

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// ReadStatements reads a qualification file: one DSSE envelope per line.
func ReadStatements(data []byte) ([]attest.Envelope, error) {
	var out []attest.Envelope
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		var env attest.Envelope
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		if err := d.Decode(&env); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, env)
	}
	return out, nil
}

// Rewrite returns a copy of env with its predicate changed by edit and its signature
// kept: what a copy edited by someone without the key looks like.
func Rewrite(env attest.Envelope, edit func(*Predicate)) (attest.Envelope, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return env, err
	}
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return env, err
	}
	edit(&st.Predicate)
	b, err := json.Marshal(st)
	if err != nil {
		return env, err
	}
	out := env
	out.Payload = base64.StdEncoding.EncodeToString(b)
	out.Signatures = slices.Clone(env.Signatures)
	return out, nil
}

// Subject returns env's subject digest and predicate without checking the signature;
// for building tampered copies, never for trusting one.
func Subject(env attest.Envelope) (string, Predicate, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return "", Predicate{}, err
	}
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil || len(st.Subject) != 1 {
		return "", Predicate{}, errors.New("not a statement")
	}
	return st.Subject[0].Digest["sha256"], st.Predicate, nil
}
