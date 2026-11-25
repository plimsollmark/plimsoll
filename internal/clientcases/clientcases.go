// Package clientcases is the account of the test cases every client (Go, Python and
// TypeScript) must pass, and the judge that fails a client whose test run skipped a case
// or reached another verdict than the case's file states.
//
// A case is one input (a record, an answer, a request, a checkpoint text) and what every
// client must say about it, on each path that reads that kind of input (a path is one
// place in a client that checks it: a session call's unanswered record, an attach's lost
// record, a stored record, a digest). A verdict is what one client said, one per case and
// path. Each client's runner, its own test files, feeds the cases to the client's own
// checking code, asserts each verdict in its own language, and also hands the verdicts to
// the judge: the Go runners in memory, the Python and TypeScript suites as one JSON line
// per verdict in the file PLIMSOLL_CASE_VERDICTS names, which their Go drivers
// (clients/python, clients/typescript) read after the suite.
//
// The account covers every shared file, old and new, by id, without copying any:
// record/testdata/golden.json and record/testdata/published (the digest vectors and the
// records every reader must refuse), internal/clientsuite/testdata/checkpoint-vectors.json,
// protocol/testdata/answers.json, the attach liar's forgeries (internal/clientsuite), and
// this package's own testdata/records.json. testdata/differences.json names every place a
// client may answer otherwise, and why; the judge fails a difference the client no longer
// shows.
package clientcases

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The paths a case may name. A record case names every path that reads that kind of
// record; a client runs each path it has.
const (
	PathDigest            = "digest"             // a digest recomputed from its input (request, result, record, session fingerprint)
	PathStored            = "stored"             // a record checked on its own, as stored evidence is (Go's record.CheckStored)
	PathStatesOnly        = "states-only"        // the same check of a record on its own, as the Python and TypeScript clients make it (_states_only, statesOnlyProblem)
	PathDecode            = "decode"             // a record read from its wire form
	PathQualification     = "qualification"      // a tier's qualification sentence within its bounds
	PathMeets             = "meets"              // a tier against a floor
	PathCheckpoint        = "checkpoint"         // a checkpoint's text parsed
	PathErrorAnswer       = "error-answer"       // a daemon's error answer read: its code, mark, session end and binding
	PathAttachLive        = "attach-live"        // a whole attach against the attach liar, each answer forged in one thing
	PathSessionUnanswered = "session-unanswered" // the record an unanswered session call's error carries
	PathAttachLost        = "attach-lost"        // the lost call's record an attach answer returns
	PathSessionHead       = "session-head"       // a session call the daemon refuses for its head, and the call after it
)

// Client is one client's paths, each with the test file that runs it.
type Client struct {
	Name string
	// Paths maps each path the client has to the repository-relative test file that gives
	// its verdicts; the judge names that file when a verdict is missing.
	Paths map[string]string
	// Checks says whether the client's verdicts name the kind of rule that failed
	// (mismatch, chain, version, no_record, floor, malformed) beside the outcome. A client
	// that does not is compared on the outcome alone, and the judge says so in its count.
	Checks bool
}

// Clients is the three clients and the paths each has.
var Clients = map[string]Client{
	"go": {Name: "go", Checks: true, Paths: map[string]string{
		PathDigest:            "record/shared_cases_test.go",
		PathStored:            "record/shared_cases_test.go",
		PathDecode:            "record/shared_cases_test.go",
		PathQualification:     "record/shared_cases_test.go",
		PathMeets:             "record/shared_cases_test.go",
		PathSessionUnanswered: "record/shared_cases_test.go",
		PathCheckpoint:        "client/shared_cases_test.go",
		PathErrorAnswer:       "client/shared_cases_test.go",
		PathAttachLive:        "client/shared_cases_test.go",
		PathAttachLost:        "client/shared_cases_test.go",
		PathSessionHead:       "client/shared_cases_test.go",
	}},
	"python": {Name: "python", Checks: true, Paths: map[string]string{
		PathDigest:            "clients/python/tests/test_record.py",
		PathStatesOnly:        "clients/python/tests/test_record.py",
		PathDecode:            "clients/python/tests/test_record.py",
		PathQualification:     "clients/python/tests/test_record.py",
		PathMeets:             "clients/python/tests/test_record.py",
		PathCheckpoint:        "clients/python/tests/test_reattach.py",
		PathErrorAnswer:       "clients/python/tests/test_answers.py",
		PathAttachLive:        "clients/python/tests/test_reattach.py",
		PathSessionUnanswered: "clients/python/tests/test_shared_cases.py",
		PathAttachLost:        "clients/python/tests/test_shared_cases.py",
		PathSessionHead:       "clients/python/tests/test_reattach.py",
	}},
	// The TypeScript client's errors carry no kind of rule yet (PlimsollError has a code
	// and flags; the rule is only in the message), so its verdicts state the outcome alone.
	"typescript": {Name: "typescript", Checks: false, Paths: map[string]string{
		PathDigest:            "clients/typescript/test/record.test.ts",
		PathStatesOnly:        "clients/typescript/test/record.test.ts",
		PathDecode:            "clients/typescript/test/record.test.ts",
		PathQualification:     "clients/typescript/test/record.test.ts",
		PathMeets:             "clients/typescript/test/record.test.ts",
		PathCheckpoint:        "clients/typescript/test/reattach.test.ts",
		PathErrorAnswer:       "clients/typescript/test/answers.test.ts",
		PathAttachLive:        "clients/typescript/test/reattach.test.ts",
		PathSessionUnanswered: "clients/typescript/test/shared-cases.test.ts",
		PathAttachLost:        "clients/typescript/test/shared-cases.test.ts",
		PathSessionHead:       "clients/typescript/test/reattach.test.ts",
	}},
}

// Case is one shared case and what every client must say about it on each path it names.
type Case struct {
	ID     string
	Family string // the group it belongs to, for the counts: "golden/refused", "answers", ...
	File   string // the repository-relative file that holds it
	Paths  []string
	// Expect is the verdict each path must give.
	Expect map[string]json.RawMessage
	// Outcome marks a case whose verdict is "accept" or "<outcome>/<check>": outcome is
	// may_have_run (an error with no not-dispatched mark) or not_dispatched:<reason>, and
	// check the kind of rule that failed. A client without Checks is compared on the
	// outcome alone.
	Outcome bool
}

// Difference is one place a client answers otherwise than a case's file states, with why.
type Difference struct {
	Client string          `json:"client"`
	Cases  []string        `json:"cases"`
	Says   json.RawMessage `json:"says"` // the verdict the client gives instead, or "not_checked": it gives none
	Basis  string          `json:"basis"`
	Why    string          `json:"why"`
}

// NotChecked is a difference's verdict for a case the client does not run.
const NotChecked = `"not_checked"`

// Reserved is an id kept for a case a later step writes, so no other case takes it.
type Reserved struct {
	ID      string `json:"id"`
	Finding string `json:"finding"`
	Step    string `json:"step"`
	What    string `json:"what"`
}

// Account is every shared case, by id.
type Account struct {
	Cases       []*Case
	byID        map[string]*Case
	Differences []Difference
	Retired     map[string]bool
	Reserved    []Reserved
}

// Verdict is what one client said about one case on one path.
type Verdict struct {
	ID   string          `json:"id"`
	Path string          `json:"path"`
	Says json.RawMessage `json:"says"`
}

// Say is a verdict whose says is v, JSON-encoded.
func Say(id, path string, v any) Verdict {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return Verdict{ID: id, Path: path, Says: b}
}

// SaysOf is the Go client's verdict on an error: "accept" for none, else the outcome a
// caller acts on and the kind of rule, from the record package's errors.
func SaysOf(err error) string {
	if err == nil {
		return "accept"
	}
	outcome := "may_have_run"
	if reason, ok := sandbox.NotDispatchedReason(err); ok {
		outcome = "not_dispatched:" + reason.String()
	}
	check := "other"
	switch {
	case errors.Is(err, record.ErrChain):
		check = "chain"
	case errors.Is(err, record.ErrVersion):
		check = "version"
	case errors.Is(err, record.ErrNoRecord):
		check = "no_record"
	case errors.Is(err, sandbox.ErrInsufficientIsolation):
		check = "floor"
	case errors.Is(err, record.ErrMismatch):
		check = "mismatch"
	}
	return outcome + "/" + check
}

// Load reads every shared file under root, the repository's root.
func Load(root string) (*Account, error) {
	a := &Account{byID: map[string]*Case{}, Retired: map[string]bool{}}
	for _, step := range []func(string) error{a.loadGolden, a.loadPublished, a.loadCheckpoints, a.loadAnswers, a.loadRecords, a.loadDifferences} {
		if err := step(root); err != nil {
			return nil, err
		}
	}
	a.addForgeries()
	for id := range a.Retired {
		if a.byID[id] != nil {
			return nil, fmt.Errorf("case %s: its id is retired and may not be used again", id)
		}
	}
	for _, r := range a.Reserved {
		if a.byID[r.ID] != nil {
			return nil, fmt.Errorf("case %s: its id is reserved for %s (%s)", r.ID, r.Step, r.Finding)
		}
	}
	return a, a.checkDifferences()
}

// Case is the case with this id, or nil.
func (a *Account) Case(id string) *Case { return a.byID[id] }

func (a *Account) add(c *Case) error {
	if a.byID[c.ID] != nil {
		return fmt.Errorf("case %s is held twice (%s and %s)", c.ID, a.byID[c.ID].File, c.File)
	}
	for _, p := range c.Paths {
		if _, ok := c.Expect[p]; !ok {
			return fmt.Errorf("case %s names the path %s and no verdict for it", c.ID, p)
		}
	}
	if len(c.Expect) != len(c.Paths) {
		return fmt.Errorf("case %s states a verdict for a path it does not name", c.ID)
	}
	a.Cases = append(a.Cases, c)
	a.byID[c.ID] = c
	return nil
}

// one is a case with one verdict on all its paths.
func one(id, family, file string, says any, outcome bool, paths ...string) *Case {
	b, err := json.Marshal(says)
	if err != nil {
		panic(err)
	}
	c := &Case{ID: id, Family: family, File: file, Paths: paths, Expect: map[string]json.RawMessage{}, Outcome: outcome}
	for _, p := range paths {
		c.Expect[p] = b
	}
	return c
}

func readJSON(root, rel string, v any) error {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	return nil
}

// vectors is the part of a golden file that both golden.json and the published files hold.
type vectors struct {
	Requests            []struct{ Name, SHA256 string } `json:"requests"`
	Results             []struct{ Name, SHA256 string } `json:"results"`
	Records             []struct{ Name, SHA256 string } `json:"records"`
	SessionFingerprints []struct{ Name, SHA256 string } `json:"sessionFingerprints"`
}

func (a *Account) loadVectors(prefix, file string, v vectors) error {
	var cs []*Case
	for _, r := range v.Requests {
		cs = append(cs, one(prefix+"requests/"+r.Name, prefix+"requests", file, r.SHA256, false, PathDigest))
	}
	for _, r := range v.Results {
		cs = append(cs, one(prefix+"results/"+r.Name, prefix+"results", file, r.SHA256, false, PathDigest))
	}
	for _, r := range v.Records {
		cs = append(cs, one(prefix+"records/"+r.Name, prefix+"records", file, r.SHA256, false, PathDigest))
		// Every record a release wrote passes the record check on its own.
		cs = append(cs, one(prefix+"records/"+r.Name+"/check", prefix+"records", file, "accept", true, PathStored, PathStatesOnly))
	}
	for _, r := range v.SessionFingerprints {
		cs = append(cs, one(prefix+"sessionFingerprints/"+r.Name, prefix+"sessionFingerprints", file, r.SHA256, false, PathDigest))
	}
	for _, c := range cs {
		if err := a.add(c); err != nil {
			return err
		}
	}
	return nil
}

const goldenFile = "record/testdata/golden.json"

func (a *Account) loadGolden(root string) error {
	var g struct {
		vectors
		Refused        []struct{ Name string } `json:"refused"`
		Malformed      []struct{ Name string } `json:"malformed"`
		Qualifications []struct {
			Name  string
			Valid bool
		} `json:"qualifications"`
		Meets []struct {
			Tier, Floor string
			Meets       bool
		} `json:"meets"`
	}
	if err := readJSON(root, goldenFile, &g); err != nil {
		return err
	}
	if err := a.loadVectors("golden/", goldenFile, g.vectors); err != nil {
		return err
	}
	var cs []*Case
	for _, r := range g.Refused {
		cs = append(cs, one("golden/refused/"+r.Name, "golden/refused", goldenFile, "may_have_run/mismatch", true, PathStored, PathStatesOnly))
	}
	for _, r := range g.Malformed {
		cs = append(cs, one("golden/malformed/"+r.Name, "golden/malformed", goldenFile, "may_have_run/malformed", true, PathDecode))
	}
	for _, q := range g.Qualifications {
		cs = append(cs, one("golden/qualifications/"+q.Name, "golden/qualifications", goldenFile, map[bool]string{true: "valid", false: "invalid"}[q.Valid], false, PathQualification))
	}
	for _, m := range g.Meets {
		cs = append(cs, one(MeetsID(m.Tier, m.Floor), "golden/meets", goldenFile, map[bool]string{true: "meets", false: "below"}[m.Meets], false, PathMeets))
	}
	for _, c := range cs {
		if err := a.add(c); err != nil {
			return err
		}
	}
	return nil
}

// MeetsID is the id of golden.json's row for a tier against a floor.
func MeetsID(tier, floor string) string { return "golden/meets/" + tier + "|" + floor }

func (a *Account) loadPublished(root string) error {
	files, err := filepath.Glob(filepath.Join(root, "record/testdata/published/*-golden.json"))
	if err != nil || len(files) == 0 {
		return fmt.Errorf("no published vectors under %s: %v", root, err)
	}
	for _, f := range files {
		rel := "record/testdata/published/" + filepath.Base(f)
		var v vectors
		if err := readJSON(root, rel, &v); err != nil {
			return err
		}
		if err := a.loadVectors(PublishedPrefix(filepath.Base(f)), rel, v); err != nil {
			return err
		}
	}
	return nil
}

// PublishedPrefix is the id prefix of a published file's cases: "published/v0.22.0/".
func PublishedPrefix(base string) string {
	return "published/" + strings.TrimSuffix(base, "-golden.json") + "/"
}

const checkpointFile = "internal/clientsuite/testdata/checkpoint-vectors.json"

func (a *Account) loadCheckpoints(root string) error {
	var v struct{ Valid, Invalid []struct{ Name string } }
	if err := readJSON(root, checkpointFile, &v); err != nil {
		return err
	}
	for _, c := range v.Valid {
		if err := a.add(one("checkpoint/valid/"+c.Name, "checkpoint/valid", checkpointFile, "parsed", false, PathCheckpoint)); err != nil {
			return err
		}
	}
	for _, c := range v.Invalid {
		if err := a.add(one("checkpoint/invalid/"+c.Name, "checkpoint/invalid", checkpointFile, "refused", false, PathCheckpoint)); err != nil {
			return err
		}
	}
	return nil
}

const answersFile = "protocol/testdata/answers.json"

func (a *Account) loadAnswers(root string) error {
	var v struct {
		Answers []struct {
			Name   string
			Expect json.RawMessage
		}
	}
	if err := readJSON(root, answersFile, &v); err != nil {
		return err
	}
	for _, x := range v.Answers {
		var expect any
		if err := json.Unmarshal(x.Expect, &expect); err != nil {
			return err
		}
		if err := a.add(one("answers/"+x.Name, "answers", answersFile, expect, false, PathErrorAnswer)); err != nil {
			return err
		}
	}
	return nil
}

const forgeriesFile = "internal/clientsuite/reattach.go"

// addForgeries accounts for the attach liar's forgeries: each forged answer is refused
// as a broken chain, and each honest one is taken.
func (a *Account) addForgeries() {
	for _, n := range clientsuite.AttachForgeries {
		_ = a.add(one("attach/forgeries/"+n, "attach/forgeries", forgeriesFile, "may_have_run/chain", true, PathAttachLive))
	}
	_ = a.add(one("attach/forgeries/none", "attach/forgeries", forgeriesFile, "accept", true, PathAttachLive))
	for _, n := range clientsuite.AttachLostForgeries {
		_ = a.add(one("attach/lost-forgeries/"+n, "attach/lost-forgeries", forgeriesFile, "may_have_run/chain", true, PathAttachLive))
	}
	_ = a.add(one("attach/lost-forgeries/lost-none", "attach/lost-forgeries", forgeriesFile, "accept", true, PathAttachLive))
	// A call the attach liar sends on with its head's count raised (HeadMismatchTrace): the
	// daemon refuses it before it runs, and the client stops the session, so the call after
	// it is refused before it is sent (the liar counts no second call).
	_ = a.add(one("session/head-mismatch", "session/head", forgeriesFile, map[string]any{"call": "not_dispatched:request", "next": "not_dispatched:request", "nextSent": false}, false, PathSessionHead))
}

// RecordsFile is this package's own cases, written by hand until a generator writes them.
const RecordsFile = "internal/clientcases/testdata/records.json"

func (a *Account) loadRecords(root string) error {
	var v struct {
		Retired  []string   `json:"retired"`
		Reserved []Reserved `json:"reserved"`
		Cases    []struct {
			ID     string                     `json:"id"`
			Family string                     `json:"family"`
			Paths  []string                   `json:"paths"`
			Expect map[string]json.RawMessage `json:"expect"`
		} `json:"cases"`
	}
	if err := readJSON(root, RecordsFile, &v); err != nil {
		return err
	}
	for _, id := range v.Retired {
		a.Retired[id] = true
	}
	a.Reserved = v.Reserved
	for _, c := range v.Cases {
		if err := a.add(&Case{ID: c.ID, Family: c.Family, File: RecordsFile, Paths: c.Paths, Expect: c.Expect, Outcome: true}); err != nil {
			return err
		}
	}
	return nil
}

const differencesFile = "internal/clientcases/testdata/differences.json"

func (a *Account) loadDifferences(root string) error {
	var v struct {
		Differences []Difference `json:"differences"`
	}
	if err := readJSON(root, differencesFile, &v); err != nil {
		return err
	}
	a.Differences = v.Differences
	return nil
}

func (a *Account) checkDifferences() error {
	seen := map[string]bool{}
	for _, d := range a.Differences {
		if _, ok := Clients[d.Client]; !ok {
			return fmt.Errorf("a difference names the client %q, which is not one of the three", d.Client)
		}
		if !slices.Contains([]string{"language", "design", "open"}, d.Basis) || d.Why == "" || len(d.Says) == 0 || len(d.Cases) == 0 {
			return fmt.Errorf("a difference of %s needs cases, what it says, a basis (language, design or open) and why", d.Client)
		}
		for _, id := range d.Cases {
			c := a.byID[id]
			if c == nil {
				return fmt.Errorf("a difference of %s names the case %s, which no file holds", d.Client, id)
			}
			if seen[d.Client+"\x00"+id] {
				return fmt.Errorf("two differences of %s name the case %s", d.Client, id)
			}
			seen[d.Client+"\x00"+id] = true
			for _, p := range c.Paths {
				if same(c, Clients[d.Client], c.Expect[p], d.Says) {
					return fmt.Errorf("a difference of %s says of %s what the file states", d.Client, id)
				}
			}
		}
	}
	return nil
}

func (a *Account) difference(client, id string) *Difference {
	for i, d := range a.Differences {
		if d.Client == client && slices.Contains(d.Cases, id) {
			return &a.Differences[i]
		}
	}
	return nil
}

// canonical is a JSON value re-encoded with sorted keys and no spaces.
func canonical(b json.RawMessage) string {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return "invalid JSON: " + string(b)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

// outcomeOnly is an outcome verdict without its kind of rule.
func outcomeOnly(b json.RawMessage) string {
	var s string
	if json.Unmarshal(b, &s) != nil {
		return canonical(b)
	}
	head, _, _ := strings.Cut(s, "/")
	out, _ := json.Marshal(head)
	return string(out)
}

// same reports whether a verdict says what want says, for this client.
func same(c *Case, cl Client, want, got json.RawMessage) bool {
	if c.Outcome && !cl.Checks {
		return outcomeOnly(want) == outcomeOnly(got)
	}
	return canonical(want) == canonical(got)
}

// Problems is everything wrong with a client's verdicts: a case on one of the client's
// paths with no verdict, a verdict for an id no file holds or on a path the case does not
// name, a case answered twice on one path, a verdict other than the file states (unless a
// difference names that client and case and says it), and a difference the client no
// longer shows. files, when given, narrows the paths judged to those the named test files
// run (the Go client's runners are two files, each judged at its own end).
func (a *Account) Problems(client string, vs []Verdict, files ...string) []string {
	cl, ok := Clients[client]
	if !ok {
		return []string{fmt.Sprintf("no client %q", client)}
	}
	inScope := func(p string) bool {
		f, has := cl.Paths[p]
		return has && (len(files) == 0 || slices.Contains(files, f))
	}
	var out []string
	type key struct{ id, path string }
	seen := map[key]int{}
	for _, v := range vs {
		if a.Retired[v.ID] {
			out = append(out, fmt.Sprintf("%s: a verdict for a retired id", v.ID))
			continue
		}
		c := a.byID[v.ID]
		if c == nil {
			out = append(out, fmt.Sprintf("%s: a verdict for an id no file holds", v.ID))
			continue
		}
		if !slices.Contains(c.Paths, v.Path) || !inScope(v.Path) {
			out = append(out, fmt.Sprintf("%s: a verdict on the path %s, which the case does not name or this runner does not run", v.ID, v.Path))
			continue
		}
		k := key{v.ID, v.Path}
		seen[k]++
		if seen[k] > 1 {
			out = append(out, fmt.Sprintf("%s on %s: answered %d times", v.ID, v.Path, seen[k]))
			continue
		}
		want := c.Expect[v.Path]
		if d := a.difference(client, v.ID); d != nil {
			switch {
			case canonical(d.Says) == canonical(json.RawMessage(NotChecked)):
				out = append(out, fmt.Sprintf("%s on %s: the difference says %s does not check it, and it gave a verdict (%s): remove the difference if it is checked now", v.ID, v.Path, client, canonical(v.Says)))
			case same(c, cl, want, v.Says):
				out = append(out, fmt.Sprintf("%s on %s: %s now says what the file states, so its difference (%s) is stale: remove it", v.ID, v.Path, client, d.Why))
			case !same(c, cl, d.Says, v.Says):
				out = append(out, fmt.Sprintf("%s on %s: says %s, the file states %s and the difference %s", v.ID, v.Path, canonical(v.Says), canonical(want), canonical(d.Says)))
			}
			continue
		}
		if !same(c, cl, want, v.Says) {
			out = append(out, fmt.Sprintf("%s on %s: says %s, the file (%s) states %s", v.ID, v.Path, canonical(v.Says), c.File, canonical(want)))
		}
	}
	for _, c := range a.Cases {
		for _, p := range c.Paths {
			if !inScope(p) || seen[key{c.ID, p}] > 0 {
				continue
			}
			if d := a.difference(client, c.ID); d != nil && canonical(d.Says) == canonical(json.RawMessage(NotChecked)) {
				continue
			}
			out = append(out, fmt.Sprintf("%s on %s: no verdict (%s should give it; the case is in %s)", c.ID, p, cl.Paths[p], c.File))
		}
	}
	return out
}

// Counts is, per family and path, how many cases a client's paths hold and how many
// verdicts it gave; one line per family and path, and a total.
func (a *Account) Counts(client string, vs []Verdict, files ...string) string {
	cl := Clients[client]
	type key struct{ family, path string }
	cases, given, unchecked := map[key]int{}, map[key]int{}, 0
	for _, c := range a.Cases {
		for _, p := range c.Paths {
			if f, ok := cl.Paths[p]; ok && (len(files) == 0 || slices.Contains(files, f)) {
				cases[key{c.Family, p}]++
				if d := a.difference(client, c.ID); d != nil && canonical(d.Says) == canonical(json.RawMessage(NotChecked)) {
					unchecked++
				}
			}
		}
	}
	for _, v := range vs {
		if c := a.byID[v.ID]; c != nil {
			given[key{c.Family, v.Path}]++
		}
	}
	var keys []key
	for k := range cases {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].family != keys[j].family {
			return keys[i].family < keys[j].family
		}
		return keys[i].path < keys[j].path
	})
	var b strings.Builder
	nc, nv := 0, 0
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-38s %-19s %4d cases %4d verdicts\n", k.family, k.path, cases[k], given[k])
		nc += cases[k]
		nv += given[k]
	}
	note := ""
	if !cl.Checks {
		note = " (compared on the outcome alone: this client's errors name no kind of rule)"
	}
	fmt.Fprintf(&b, "  %s: %d case-paths, %d verdicts, %d not checked by a stated difference%s", client, nc, nv, unchecked, note)
	return b.String()
}

// Judge fails t with every problem in a client's verdicts and logs its counts.
func Judge(t testing.TB, a *Account, client string, vs []Verdict, files ...string) {
	t.Helper()
	t.Logf("shared cases, %s:\n%s", client, a.Counts(client, vs, files...))
	for _, p := range a.Problems(client, vs, files...) {
		t.Errorf("shared case, %s: %s", client, p)
	}
}

// ReadVerdicts reads a verdict file: one JSON verdict per line.
func ReadVerdicts(path string) ([]Verdict, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vs []Verdict
	for i, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var v Verdict
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil || v.ID == "" || v.Path == "" || len(v.Says) == 0 {
			return nil, fmt.Errorf("%s line %d is not a verdict: %q (%v)", path, i+1, line, err)
		}
		vs = append(vs, v)
	}
	return vs, nil
}
