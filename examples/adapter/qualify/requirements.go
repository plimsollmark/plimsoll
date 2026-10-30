package qualify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/plimsollmark/plimsoll/examples/adapter/fleetsim"
)

// Requirements is a requirements file: what the platform requires of an adapter, one
// "shall" sentence under each requirement ID, each mapped onto the rules that decide it.
// A requirement verdict is derived from the rules' outcomes and never judged apart from
// them, so it is only as good as the rules it names.
type Requirements struct {
	Title        string        `json:"title"`
	About        string        `json:"about,omitempty"`
	Requirements []Requirement `json:"requirements"`

	sha256 string // the digest of the bytes it was read from
}

// Requirement is one requirement: its ID (REQ- and three digits), its sentence, and the
// adapter rules that decide it. One that names no rule is reported as not tested.
type Requirement struct {
	ID    string   `json:"id"`
	Text  string   `json:"text"`
	Rules []string `json:"rules"`
}

var (
	requirementID = regexp.MustCompile(`^REQ-[0-9]{3}$`)
	shall         = regexp.MustCompile(`\bshall\b`)
)

// ReadRequirements reads and checks a requirements file. It refuses unknown fields and
// anything after the object, an ID not of the form REQ-NNN or used twice, a sentence
// without "shall", and a rule that is not one of AdapterRules or is named twice by one
// requirement.
func ReadRequirements(data []byte) (Requirements, error) {
	var r Requirements
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return Requirements{}, fmt.Errorf("requirements file: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return Requirements{}, errors.New("requirements file: data after the object")
	}
	if len(r.Requirements) == 0 {
		return Requirements{}, errors.New("requirements file: no requirements")
	}
	known := map[string]bool{}
	for _, rl := range AdapterRules {
		known[rl.ID] = true
	}
	seen := map[string]bool{}
	for _, q := range r.Requirements {
		switch {
		case !requirementID.MatchString(q.ID):
			return Requirements{}, fmt.Errorf("requirements file: %q is not an ID of the form REQ-NNN", q.ID)
		case seen[q.ID]:
			return Requirements{}, fmt.Errorf("requirements file: %s is used twice", q.ID)
		case !shall.MatchString(q.Text):
			return Requirements{}, fmt.Errorf("requirements file: %s's text has no \"shall\"", q.ID)
		}
		seen[q.ID] = true
		named := map[string]bool{}
		for _, rule := range q.Rules {
			if !known[rule] {
				return Requirements{}, fmt.Errorf("requirements file: %s names %q, which is not an adapter rule", q.ID, rule)
			}
			if named[rule] {
				return Requirements{}, fmt.Errorf("requirements file: %s names %s twice", q.ID, rule)
			}
			named[rule] = true
		}
	}
	r.sha256 = digest(string(data))
	return r, nil
}

// SHA256 is the digest of the bytes r was read from.
func (r Requirements) SHA256() string { return r.sha256 }

// Unmapped is the adapter rules no requirement names, in AdapterRules' order: checks the
// platform makes that trace to no requirement. A gap to report, not an error.
func (r Requirements) Unmapped() []string {
	named := map[string]bool{}
	for _, q := range r.Requirements {
		for _, rule := range q.Rules {
			named[rule] = true
		}
	}
	var out []string
	for _, rl := range AdapterRules {
		if !named[rl.ID] {
			out = append(out, rl.ID)
		}
	}
	return out
}

// A requirement verdict's status.
const (
	Held      = "held"       // every rule it names held
	NotHeld   = "not_held"   // at least one rule it names did not
	NotTested = "not_tested" // it names no rule, so nothing decided it
)

// RequirementVerdict is one requirement's verdict for one run.
type RequirementVerdict struct {
	ID     string   `json:"id"`
	Status string   `json:"status"`
	Rules  []string `json:"rules,omitempty"`  // the rules that decided it
	Failed []string `json:"failed,omitempty"` // which of them did not hold
}

// Judge gives each requirement's verdict from one run's rule outcomes, as Evaluate made
// them. It reads nothing else, so a requirement verdict cannot disagree with the rules.
// The example signs its result in each adapter statement, and Verify rebuilds it.
// It refuses outcomes that lack a rule a requirement names, or carry one twice: the
// boundary probe's outcomes, for one, are judged by other rules and decide no adapter
// requirement.
func Judge(r Requirements, outcomes []Outcome) ([]RequirementVerdict, error) {
	held := map[string]bool{}
	for _, o := range outcomes {
		if _, dup := held[o.Rule]; dup {
			return nil, fmt.Errorf("the outcomes carry %s twice", o.Rule)
		}
		held[o.Rule] = o.Held
	}
	var out []RequirementVerdict
	for _, q := range r.Requirements {
		v := RequirementVerdict{ID: q.ID, Status: NotTested, Rules: slices.Clone(q.Rules)}
		if len(q.Rules) > 0 {
			v.Status = Held
		}
		for _, rule := range q.Rules {
			ok, present := held[rule]
			if !present {
				return nil, fmt.Errorf("%s names %s, which the outcomes do not carry", q.ID, rule)
			}
			if !ok {
				v.Status = NotHeld
				v.Failed = append(v.Failed, rule)
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// ErrNoQualification is Lookup's answer when no verified adapter statement names the
// adapter's digest: whatever was qualified before, this exact file was not, and needs
// its runs.
var ErrNoQualification = errors.New("no qualification for adapter digest")

// Qualification is what verified statements say of one adapter, by its digest, against
// one requirements file.
type Qualification struct {
	Adapter      string   // the adapter's SHA-256
	Paths        []string // the paths the statements name it by
	Requirements string   // the requirements file's SHA-256
	Harnesses    []string // the harness.js digests its runs used
	Runs         []QualifiedRun
	Tallies      []RequirementTally // one per requirement, in the file's order
	Missing      []string           // the simulator's scenarios no run covered
	Unmapped     []string           // the rules no requirement names
	Qualified    bool               // every requirement held in every run, and every scenario ran
}

// QualifiedRun is one run of the adapter: its line in the bundle, its scenario and its
// requirement verdicts.
type QualifiedRun struct {
	Run      int
	Scenario string
	Verdicts []RequirementVerdict
}

// RequirementTally is one requirement across the adapter's runs.
type RequirementTally struct {
	ID, Text  string
	Held      int // runs it held in
	Runs      int
	NotTested bool     // it names no rule
	FailedIn  []string // "scenario (run N)" for each run it did not hold in
}

// Lookup answers, for the adapter with digest adapterSHA256, what the verified
// statements say against requirements r, the file Verify checked them against. Each
// statement counts once, by its run record, and only adapter statements count: the
// boundary probe is judged by other rules and never qualifies an adapter. A statement
// that pins another requirements file, or whose signed requirement verdicts are not
// Judge's reading of its rules through r, is refused: it was not verified against r.
// When none names the digest the error wraps ErrNoQualification; the answer speaks for
// the statements given, never for every statement anyone signed.
func Lookup(r Requirements, verified []Verified, adapterSHA256 string) (Qualification, error) {
	if r.SHA256() == "" {
		return Qualification{}, errNoRequirements
	}
	q := Qualification{Adapter: adapterSHA256, Requirements: r.SHA256(), Unmapped: r.Unmapped()}
	covered := map[string]bool{}
	records := map[string]bool{}
	for _, v := range verified {
		p := v.Predicate
		if p.Evidence.Kind != KindAdapter || p.Adapter.SHA256 != adapterSHA256 {
			continue
		}
		// One run counted twice would inflate every tally; a run is its record.
		if records[v.Record] {
			return Qualification{}, fmt.Errorf("run %d: its record %s is given twice", p.Run, short(v.Record))
		}
		records[v.Record] = true
		if p.Requirements == nil || p.Requirements.SHA256 != r.SHA256() {
			return Qualification{}, fmt.Errorf("run %d: its statement does not pin requirements %s", p.Run, short(r.SHA256()))
		}
		verdicts, err := Judge(r, p.Rules)
		if err != nil {
			return Qualification{}, fmt.Errorf("run %d: %w", p.Run, err)
		}
		if !sameJSON(verdicts, p.RequirementVerdicts) {
			return Qualification{}, fmt.Errorf("run %d: its signed requirement verdicts do not follow from its rules", p.Run)
		}
		q.Runs = append(q.Runs, QualifiedRun{Run: p.Run, Scenario: p.Evidence.Scenario.Name, Verdicts: verdicts})
		covered[p.Evidence.Scenario.Name] = true
		if !slices.Contains(q.Paths, p.Adapter.Path) {
			q.Paths = append(q.Paths, p.Adapter.Path)
		}
		if !slices.Contains(q.Harnesses, p.Harness) {
			q.Harnesses = append(q.Harnesses, p.Harness)
		}
	}
	if len(q.Runs) == 0 {
		return Qualification{}, fmt.Errorf("%w %s: no verified adapter statement names it; rerun required", ErrNoQualification, adapterSHA256)
	}
	slices.SortFunc(q.Runs, func(a, b QualifiedRun) int { return a.Run - b.Run })
	q.Qualified = true
	for i, req := range r.Requirements {
		t := RequirementTally{ID: req.ID, Text: req.Text, Runs: len(q.Runs), NotTested: len(req.Rules) == 0}
		for _, run := range q.Runs {
			switch run.Verdicts[i].Status {
			case Held:
				t.Held++
			case NotHeld:
				t.FailedIn = append(t.FailedIn, fmt.Sprintf("%s (run %d)", run.Scenario, run.Run))
			}
		}
		q.Qualified = q.Qualified && t.Held == t.Runs
		q.Tallies = append(q.Tallies, t)
	}
	for _, sc := range fleetsim.ScenarioOrder {
		if !covered[sc] {
			q.Missing = append(q.Missing, sc)
		}
	}
	q.Qualified = q.Qualified && len(q.Missing) == 0
	return q, nil
}
