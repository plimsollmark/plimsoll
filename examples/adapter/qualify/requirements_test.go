package qualify

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/examples/adapter/fleetsim"
)

func shippedRequirements(t *testing.T) Requirements {
	t.Helper()
	_, r := shippedRequirementsFile(t)
	return r
}

// shippedRequirementsFile is the shipped file's bytes and what ReadRequirements reads.
func shippedRequirementsFile(t *testing.T) ([]byte, Requirements) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "contract", "requirements.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := ReadRequirements(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.SHA256() != Digest(string(data)) {
		t.Fatalf("digest %s, want the file's", r.SHA256())
	}
	return data, r
}

// The shipped file traces every adapter rule to a requirement, REQ-001 to REQ-008 in
// the rules' order, one rule each.
func TestShippedRequirementsCoverEveryRule(t *testing.T) {
	r := shippedRequirements(t)
	if len(r.Requirements) != len(AdapterRules) {
		t.Fatalf("%d requirements for %d rules", len(r.Requirements), len(AdapterRules))
	}
	for i, q := range r.Requirements {
		if want := fmt.Sprintf("REQ-%03d", i+1); q.ID != want || !slices.Equal(q.Rules, []string{AdapterRules[i].ID}) {
			t.Errorf("requirement %d is %s over %v, want %s over %s", i+1, q.ID, q.Rules, want, AdapterRules[i].ID)
		}
	}
	if u := r.Unmapped(); len(u) != 0 {
		t.Fatalf("rules no requirement names: %v", u)
	}
}

func TestReadRequirementsRefuses(t *testing.T) {
	for label, c := range map[string]struct{ file, want string }{
		"an unknown field":         {`{"title":"t","requirements":[{"id":"REQ-001","text":"x shall y","rules":[],"owner":"me"}]}`, "unknown field"},
		"data after the object":    {`{"title":"t","requirements":[{"id":"REQ-001","text":"x shall y","rules":[]}]} {}`, "data after"},
		"no requirements":          {`{"title":"t","requirements":[]}`, "no requirements"},
		"a malformed ID":           {`{"requirements":[{"id":"REQ-4","text":"x shall y","rules":[]}]}`, "REQ-NNN"},
		"an ID used twice":         {`{"requirements":[{"id":"REQ-001","text":"x shall y","rules":[]},{"id":"REQ-001","text":"x shall z","rules":[]}]}`, "used twice"},
		"a sentence without shall": {`{"requirements":[{"id":"REQ-001","text":"the adapter marshalls JSON","rules":[]}]}`, "no \"shall\""},
		"an unknown rule":          {`{"requirements":[{"id":"REQ-001","text":"x shall y","rules":["no_network"]}]}`, "not an adapter rule"},
		"a rule named twice":       {`{"requirements":[{"id":"REQ-001","text":"x shall y","rules":["robot_at_target","robot_at_target"]}]}`, "twice"},
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := ReadRequirements([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestJudge(t *testing.T) {
	r := shippedRequirements(t)
	s := fleetsim.Scenarios[fleetsim.ScenarioNominal]
	outcomes, pass := Evaluate(good(NewPlan(1), s))
	if !pass {
		t.Fatal("the clean run did not pass")
	}
	verdicts, err := Judge(r, outcomes)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range verdicts {
		if v.Status != Held || len(v.Failed) != 0 {
			t.Errorf("clean run: %+v", v)
		}
	}

	// A second order for the first command: REQ-004 does not hold, and only REQ-004.
	twice := good(NewPlan(1), s)
	extra := twice.Ledger[0]
	extra.ID = "m9"
	twice.Ledger = append(twice.Ledger, extra)
	outcomes, _ = Evaluate(twice)
	if verdicts, err = Judge(r, outcomes); err != nil {
		t.Fatal(err)
	}
	for _, v := range verdicts {
		want := Held
		if v.ID == "REQ-004" {
			want = NotHeld
		}
		if v.Status != want {
			t.Errorf("two orders for one command: %s is %s, want %s (%v)", v.ID, v.Status, want, v.Failed)
		}
	}

	// Many rules per requirement: it fails on the one that did not hold, and names only
	// that one; a requirement naming no rule is not tested, never held.
	mixed, err := ReadRequirements([]byte(`{"requirements":[
		{"id":"REQ-001","text":"orders shall be right","rules":["right_robot_and_target","one_order_per_command"]},
		{"id":"REQ-002","text":"the adapter shall log every call","rules":[]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if verdicts, err = Judge(mixed, outcomes); err != nil {
		t.Fatal(err)
	}
	want := []RequirementVerdict{
		{ID: "REQ-001", Status: NotHeld, Rules: []string{"right_robot_and_target", "one_order_per_command"}, Failed: []string{"one_order_per_command"}},
		{ID: "REQ-002", Status: NotTested, Rules: []string{}},
	}
	if fmt.Sprint(verdicts) != fmt.Sprint(want) {
		t.Fatalf("got %+v, want %+v", verdicts, want)
	}
	if u := mixed.Unmapped(); len(u) != 6 || slices.Contains(u, "one_order_per_command") {
		t.Fatalf("unmapped %v", u)
	}

	// The probe's outcomes decide no adapter requirement.
	probe, _ := Evaluate(Evidence{Kind: KindProbe})
	if _, err := Judge(r, probe); err == nil || !strings.Contains(err.Error(), "do not carry") {
		t.Fatalf("probe outcomes: %v", err)
	}
	if _, err := Judge(r, append(outcomes, outcomes[0])); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a rule carried twice: %v", err)
	}
}

func TestLookup(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f := signedRuns(t, key, len(fleetsim.ScenarioOrder), false)
	r := f.reqs
	verified, err := Verify(pub, r, f.envs, f.entries)
	if err != nil {
		t.Fatal(err)
	}
	adapter := Digest("// adapter")

	q, err := Lookup(r, verified, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if !q.Qualified || len(q.Runs) != len(fleetsim.ScenarioOrder) || len(q.Missing) != 0 || q.Requirements != r.SHA256() ||
		!slices.Equal(q.Paths, []string{"adapter-v2.js"}) || !slices.Equal(q.Harnesses, []string{Digest("// harness")}) {
		t.Fatalf("every scenario, every rule held: %+v", q)
	}
	for _, tl := range q.Tallies {
		if tl.Held != len(fleetsim.ScenarioOrder) || tl.Runs != tl.Held || len(tl.FailedIn) != 0 {
			t.Errorf("%+v", tl)
		}
	}

	// Three scenarios run: every requirement held in 3 of 3, and not qualified, since
	// five scenarios were never run.
	q, err = Lookup(r, verified[:3], adapter)
	if err != nil || q.Qualified || len(q.Missing) != len(fleetsim.ScenarioOrder)-3 || q.Tallies[3].Held != 3 {
		t.Fatalf("three scenarios: %+v, %v", q, err)
	}

	// One run's REQ-004 not held: 7 of 8, failed in that scenario, not qualified.
	broken := slices.Clone(verified)
	e := broken[3].Predicate.Evidence
	extra := e.Ledger[0]
	extra.ID = "m9"
	e.Ledger = append(slices.Clone(e.Ledger), extra)
	broken[3].Predicate.Evidence = e
	broken[3].Predicate.Rules, _ = Evaluate(e)
	// The rules changed and the signed verdicts did not: refused, as unverified.
	if _, err := Lookup(r, broken, adapter); err == nil || !strings.Contains(err.Error(), "run 4: its signed requirement verdicts do not follow") {
		t.Fatalf("verdicts behind their rules: %v", err)
	}
	broken[3].Predicate.RequirementVerdicts, _ = Judge(r, broken[3].Predicate.Rules)
	if q, err = Lookup(r, broken, adapter); err != nil || q.Qualified {
		t.Fatalf("one failed run: %+v, %v", q, err)
	}
	if tl := q.Tallies[3]; tl.ID != "REQ-004" || tl.Held != 7 || !slices.Equal(tl.FailedIn, []string{fleetsim.ScenarioOrder[3] + " (run 4)"}) {
		t.Fatalf("REQ-004: %+v", tl)
	}

	// The same run given twice is refused, not counted twice.
	if _, err := Lookup(r, append(slices.Clone(verified), verified[0]), adapter); err == nil || !strings.Contains(err.Error(), "given twice") {
		t.Fatalf("a run given twice: %v", err)
	}

	// A changed adapter: nothing signed names its digest.
	changed := Digest("// adapter\n")
	if _, err := Lookup(r, verified, changed); !errors.Is(err, ErrNoQualification) || !strings.Contains(err.Error(), changed) {
		t.Fatalf("a changed adapter: %v", err)
	}
	// A probe statement never qualifies the file it names.
	probe := slices.Clone(verified[:1])
	probe[0].Predicate.Evidence.Kind = KindProbe
	if _, err := Lookup(r, probe, adapter); !errors.Is(err, ErrNoQualification) {
		t.Fatalf("a probe statement: %v", err)
	}
	// Statements verified against one file are not an answer for another.
	reworded := oneWordChanged(t, f.reqData)
	if _, err := Lookup(reworded, verified, adapter); err == nil || !strings.Contains(err.Error(), "does not pin requirements "+short(reworded.SHA256())) {
		t.Fatalf("another requirements file: %v", err)
	}
	if _, err := Lookup(Requirements{}, verified, adapter); err == nil || !strings.Contains(err.Error(), "no requirements file") {
		t.Fatalf("no requirements file: %v", err)
	}
}
