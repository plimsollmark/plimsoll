package main

// A staged experiment is one experiment made as several runs of one job, each building some of
// the job's groups (-groups, -build) on the same sealed fresh set, and read together by a rule
// fixed before the first run. Its page directory holds:
//
//   - stages/<name>/: one run's files as the run wrote them (bundle.jsonl.gz, harness.pub,
//     fresh.json, run.json, transcripts.jsonl.gz), and the evidence.json and agents.json that
//     -staged -render derives from them, as a run does;
//   - experiment.json: the stages in the order they ran, the registered rule (its pairs, its
//     resampling, its margins and the words of its outcomes) and the model's list prices;
//   - evidence.json: every number the page states, derived from the two above and nothing else;
//   - index.html: the page.
//
// -staged -verify checks each stage as -verify checks a run (every signature, every record
// against the request and answer stored with it, the leak scan, the sets each grading run held),
// that every stage was made under the design this program writes for the job, on the same sealed
// set, by the same model, building groups no other stage built, and that evidence.json and
// index.html are exactly what those files render. The rule's outcome is decided here, by code,
// from the agents' scores; experiment.json gives its words, not its result.

import (
	"bytes"
	"cmp"
	_ "embed"
	"errors"
	"fmt"
	"html"
	"html/template"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed staged.html
var stagedTemplate string

const (
	stagesDir      = "stages"
	experimentName = "experiment.json"
	experimentFmt  = "plimsoll.squeeze-staged/1"
)

// The four outcomes a registered rule decides between, in the order it tries them.
const (
	outcomeOrder   = "ORDER SHOWED"
	outcomeWords   = "WORDS ONLY"
	outcomeNoneSee = "NO RECIPE EFFECT SEEN"
	outcomeUnclear = "INCONCLUSIVE"
)

var ruleOutcomes = []string{outcomeOrder, outcomeWords, outcomeNoneSee, outcomeUnclear}

// Experiment is experiment.json.
type Experiment struct {
	Format string   `json:"format"`
	About  string   `json:"about"`
	Stages []string `json:"stages"` // the stage directories under stages/, in the order they ran
	Rule   Rule     `json:"rule"`
	Prices Prices   `json:"prices"`
	// Before are model calls made for the experiment outside any stage (a check before the run),
	// counted into its cost.
	Before []Extra `json:"before_run"`
}

// Rule is the registered rule: two measures an agent, each pair of groups' difference with a 95%
// and a 90% interval from resampling the agents, and the outcome the intervals decide.
type Rule struct {
	About string `json:"about"`
	// BaseArm is the untreated group; when its mean landings are at or above Ceiling, landings
	// are not read, since no difference in them could show.
	BaseArm string  `json:"ceiling_base_arm"`
	Ceiling float64 `json:"ceiling"`
	// Primary and each of Others are [base, treatment]; a pair's difference is the treatment's
	// mean minus the base's.
	Primary  [2]string    `json:"primary"`
	Others   [][2]string  `json:"others"`
	Resample Resample     `json:"resample"`
	Margins  RuleMargins  `json:"margins"`
	Measures []RuleMeaner `json:"measures"`
	Outcomes []RuleMeaner `json:"outcomes"`
}

// Resample is the rule's resampling: N times, each group's agents drawn again at random with
// repeats, by CPython's random.Random(Seed), as the rule's own script draws them.
type Resample struct {
	Unit string `json:"unit"`
	N    int    `json:"n"`
	Seed uint64 `json:"seed"`
}

// RuleMargins are the equivalence margins of NO RECIPE EFFECT SEEN: a difference whose 90%
// interval sits inside them is too small to matter.
type RuleMargins struct {
	Landed float64 `json:"landed"` // a fraction of the fresh flights
	Words  float64 `json:"words"`  // recipe items
}

// RuleMeaner is a named thing of the rule and what it means, in the rule's words.
type RuleMeaner struct {
	Name  string `json:"name"`
	Means string `json:"means"`
}

// Prices are the model's list prices, per million tokens, as checked on a date.
type Prices struct {
	Model      string  `json:"model"`
	Checked    string  `json:"checked"`
	Source     string  `json:"source"`
	Input      float64 `json:"input"`
	CacheWrite float64 `json:"cache_write"`
	CacheRead  float64 `json:"cache_read"`
	Output     float64 `json:"output"`
}

// Extra is model calls made outside the stages, with the tokens they used.
type Extra struct {
	What       string `json:"what"`
	Calls      int    `json:"calls"`
	Input      int    `json:"input"` // not read from the cache or written to it
	CacheWrite int    `json:"cache_write"`
	CacheRead  int    `json:"cache_read"`
	Output     int    `json:"output"`
}

// StagedEvidence is everything a staged page states, and evidence.json beside it.
type StagedEvidence struct {
	Job           string          `json:"job"`
	Model         string          `json:"model"`
	API           string          `json:"api"`
	Design        string          `json:"design_sha256"` // every stage's, and the digest of the design document this program writes
	FreshSHA256   string          `json:"fresh_sha256"`
	FreshCount    int             `json:"fresh_count"`
	PracticeCount int             `json:"practice_count"`
	CPUBudget     int             `json:"cpu_budget_seconds"`
	Stages        []StageEvidence `json:"stages"`
	Groups        []ArmEvidence   `json:"groups"`
	Pairs         []PairEvidence  `json:"pairs"`
	LandedRead    bool            `json:"landed_read"`
	Outcome       string          `json:"outcome"`
	Agents        []AgentScore    `json:"agents"`
	Cost          Cost            `json:"cost"`
}

// StageEvidence is one stage: its run's times, signing key, calls and sandboxes.
type StageEvidence struct {
	Name               string    `json:"name"`
	Groups             []string  `json:"groups"`
	Agents             int       `json:"agents"`
	Started            time.Time `json:"started"`
	Ended              time.Time `json:"ended"`
	Harness            string    `json:"harness"` // the stage's signing key's ID
	Lines              int       `json:"lines"`
	GradingRuns        int       `json:"grading_runs"`
	SessionCalls       int       `json:"session_calls"`
	PracticeRuns       int       `json:"practice_runs"`
	Needles            int       `json:"needles"`
	Hits               int       `json:"hits"`
	SetsHeld           bool      `json:"sets_held"`
	Provider           string    `json:"provider"`
	Tier               string    `json:"tier"`
	Environment        string    `json:"environment"`
	Flights            int       `json:"flights"`
	CPUEnded           int       `json:"cpu_ended_flights"`
	GradeMedianSeconds float64   `json:"grade_median_seconds"`
	GradeMaxSeconds    float64   `json:"grade_max_seconds"`
	Usage              usage     `json:"usage"`
	CostUSD            float64   `json:"cost_usd"`
}

// ArmEvidence is one group: its recipe as given, its agents' landings and words.
type ArmEvidence struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Recipe    string `json:"recipe"`
	Scrambled bool   `json:"scrambled,omitempty"`
	Stage     string `json:"stage"`
	Agents    int    `json:"agents"`
	// Landed is the mean fraction of fresh flights an agent's controller landed. A single
	// group's mean carries no interval of its own: the registered rule reads differences
	// between groups, and only those carry one (the owner's decision of 2026-11-07).
	Landed float64 `json:"landed"`
	Low    int     `json:"low"`  // the fewest fresh flights one agent landed
	High   int     `json:"high"` // the most
	// Words is the mean count of recipe words named in code; Naming the agents that named any.
	Words  float64  `json:"words"`
	Naming []string `json:"naming"`
	// Quoted is how many agents quoted their recipe (agents.json quoted_recipe); SaidPartly how
	// many said, asked after the session, that they followed it only partly or only in part.
	Quoted     int `json:"quoted"`
	SaidPartly int `json:"said_only_partly"`
	RNG        int `json:"rng"`
	Generator  int `json:"generator_constant"`
}

// PairEvidence is one pair's differences on both measures.
type PairEvidence struct {
	Name   string `json:"name"` // "recipe minus scrambled"
	Base   string `json:"base"`
	Treat  string `json:"treatment"`
	Landed Delta  `json:"landed"`
	Words  Delta  `json:"words"`
}

// Delta is a difference of means and its intervals.
type Delta struct {
	Difference float64    `json:"difference"`
	Interval95 [2]float64 `json:"interval95"`
	Interval90 [2]float64 `json:"interval90"`
}

// AgentScore is one agent as the page lists it.
type AgentScore struct {
	ID            string   `json:"id"`
	Group         string   `json:"group"`
	Stage         string   `json:"stage"`
	Fresh         int      `json:"fresh"`
	FreshTotal    int      `json:"fresh_total"`
	FreshBits     string   `json:"fresh_bits"` // one character a sealed flight, in the set's order: 1 landed, 0 not
	Practice      int      `json:"practice"`
	PracticeTotal int      `json:"practice_total"`
	Turns         int      `json:"turns"`
	FlyCalls      int      `json:"fly_calls"`
	Flights       int      `json:"flights"`
	Ended         string   `json:"ended"`
	QuotedRecipe  bool     `json:"quoted_recipe"`
	ItemsNamed    []string `json:"items_named"`
	SaidPartly    bool     `json:"said_only_partly"`
	Controller    string   `json:"controller_sha256"`
	Bytes         int      `json:"controller_bytes"`
	Records       int      `json:"records"`
}

// Cost is what the model calls cost at the list prices, from the tokens each stage's run.json
// and experiment.json's calls before the run record.
type Cost struct {
	Calls       int     `json:"calls"` // the stages' calls
	StagesUSD   float64 `json:"stages_usd"`
	BeforeCalls int     `json:"before_calls"`
	BeforeUSD   float64 `json:"before_usd"`
	TotalUSD    float64 `json:"total_usd"`
}

// saidPartly finds an after-session answer that says the recipe was followed only partly.
var saidPartly = regexp.MustCompile(`(?i)\bonly (?:partly|in part)\b`)

// stageRun is one stage's files, read and checked.
type stageRun struct {
	name   string
	dir    string
	rf     RunFile
	ev     *Evidence
	agents []AgentRecord
}

func readExperiment(dir string) (*Experiment, error) {
	var exp Experiment
	if err := readJSON(filepath.Join(dir, experimentName), &exp); err != nil {
		return nil, err
	}
	if exp.Format != experimentFmt {
		return nil, fmt.Errorf("%s: format %q, not %q", experimentName, exp.Format, experimentFmt)
	}
	if len(exp.Stages) == 0 {
		return nil, fmt.Errorf("%s names no stage", experimentName)
	}
	var names []string
	for _, o := range exp.Rule.Outcomes {
		names = append(names, o.Name)
	}
	if !slices.Equal(names, ruleOutcomes) {
		return nil, fmt.Errorf("%s: the rule's outcomes are %q; this program decides between %q, in that order", experimentName, names, ruleOutcomes)
	}
	if exp.Rule.Resample.N < 100 {
		return nil, fmt.Errorf("%s: the rule resamples %d times", experimentName, exp.Rule.Resample.N)
	}
	return &exp, nil
}

// readStages reads and checks every stage: each verifies as a run does, was made under this
// program's design for the job, and all flew one sealed set with one model.
func readStages(dir string, job *Job, exp *Experiment) ([]stageRun, error) {
	var out []stageRun
	built := map[string]string{} // group -> the stage that built it
	for _, name := range exp.Stages {
		sd := filepath.Join(dir, stagesDir, name)
		if !runName.MatchString(name) {
			return nil, fmt.Errorf("%s: not a stage's name (lowercase letters, digits and hyphens)", sd)
		}
		var rf RunFile
		if err := readJSON(filepath.Join(sd, "run.json"), &rf); err != nil {
			return nil, err
		}
		if rf.Job != job.Name {
			return nil, fmt.Errorf("%s is a run of %q, not of %q", sd, rf.Job, job.Name)
		}
		design, err := designBytes(job, rf.API, rf.Model)
		if err != nil {
			return nil, err
		}
		if rf.DesignSHA256 == "" || rf.DesignSHA256 != digest(design) {
			return nil, fmt.Errorf("%s was made under the design %q; this program writes %s for this job, API and model", sd, rf.DesignSHA256, digest(design))
		}
		if lost := incomplete(rf); len(lost) > 0 {
			return nil, fmt.Errorf("%s lost calls or sessions: %s", sd, strings.Join(lost, "; "))
		}
		ev, err := derive(sd, job)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sd, err)
		}
		if len(ev.Scan.Hits) > 0 || !ev.Scan.SetsHeld {
			return nil, fmt.Errorf("%s: the leak scan found %v, or a grading run did not hold exactly its sets", sd, ev.Scan.Hits)
		}
		agents, err := agentRecords(sd, job, ev)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sd, err)
		}
		if len(rf.Groups) == 0 {
			return nil, fmt.Errorf("%s built every group; a stage builds the groups -groups names", sd)
		}
		if err := coversStage(job, rf, ev, agents); err != nil {
			return nil, fmt.Errorf("%s: %w", sd, err)
		}
		for _, g := range rf.Groups {
			if s, dup := built[g]; dup {
				return nil, fmt.Errorf("group %s was built by stage %s and by stage %s", g, s, name)
			}
			built[g] = name
		}
		if len(out) > 0 {
			first := out[0].rf
			if rf.Model != first.Model || rf.API != first.API || rf.FreshSHA256 != first.FreshSHA256 {
				return nil, fmt.Errorf("%s: model %s, API %s, fresh set %s; the first stage's are %s, %s, %s", sd, rf.Model, rf.API, rf.FreshSHA256, first.Model, first.API, first.FreshSHA256)
			}
			if !rf.Started.After(out[len(out)-1].rf.Ended) {
				return nil, fmt.Errorf("%s started before the stage before it ended", sd)
			}
		}
		out = append(out, stageRun{name: name, dir: sd, rf: rf, ev: ev, agents: agents})
	}
	for _, c := range job.Courses {
		for _, g := range c.Groups {
			if g.Build > 0 && built[g.ID] == "" {
				return nil, fmt.Errorf("no stage built group %s", g.ID)
			}
		}
	}
	return out, nil
}

// coversStage refuses a stage whose agents are not exactly what it built and graded: the agent
// records come from the unsigned transcripts, so a transcript left out would drop an agent from
// every number while each check of what is present still passed. Every rebuild the signed bundle
// graded and every rebuild run.json lists must have its one agent, and each group the stage built
// must hold the stage's build size (-build, else the job's).
func coversStage(job *Job, rf RunFile, ev *Evidence, agents []AgentRecord) error {
	have := map[string]bool{}
	perGroup := map[string]int{}
	for _, a := range agents {
		if have[a.ID] {
			return fmt.Errorf("agent %s has two transcripts", a.ID)
		}
		have[a.ID] = true
		perGroup[a.Group]++
	}
	for _, c := range ev.Courses {
		for _, g := range c.Groups {
			for _, r := range g.Rebuilds {
				if id := c.ID + "." + g.ID + "." + strings.TrimPrefix(r.Name, "r"); !have[id] {
					return fmt.Errorf("the signed bundle grades rebuild %s, which has no transcript", id)
				}
			}
		}
	}
	for _, b := range rf.Built {
		if id := fmt.Sprintf("%s.%s.%d", b.Course, b.Group, b.N); !have[id] {
			return fmt.Errorf("run.json built rebuild %s, which has no transcript", id)
		}
	}
	for _, c := range job.Courses {
		for _, g := range c.Groups {
			if !slices.Contains(rf.Groups, g.ID) {
				continue
			}
			want := g.Build
			if rf.Build > 0 {
				want = rf.Build
			}
			if perGroup[g.ID] != want {
				return fmt.Errorf("group %s has %d agents; the stage built %d", g.ID, perGroup[g.ID], want)
			}
		}
	}
	return nil
}

// stagedEvidence states the experiment: each group's landings and words, each pair's
// differences, the rule's outcome, every agent, the stages and the cost.
func stagedEvidence(exp *Experiment, job *Job, stages []stageRun) (*StagedEvidence, error) {
	if len(job.Courses) != 1 {
		return nil, errors.New("a staged page reads a job of one course")
	}
	course := job.Courses[0]
	first := stages[0]
	se := &StagedEvidence{Job: job.Name, Model: first.rf.Model, API: first.rf.API, Design: first.rf.DesignSHA256, FreshSHA256: first.rf.FreshSHA256,
		FreshCount: first.ev.FreshCount, PracticeCount: len(course.Practice), CPUBudget: cpuBudgetSeconds, Agents: []AgentScore{}}
	landed, words := map[string][]float64{}, map[string][]float64{}
	arms := map[string]*ArmEvidence{}
	for _, st := range stages {
		s := StageEvidence{Name: st.name, Groups: st.rf.Groups, Started: st.rf.Started, Ended: st.rf.Ended, Harness: st.ev.Harness, Lines: st.ev.Lines,
			GradingRuns: st.ev.Scan.GradingRuns, SessionCalls: st.ev.Scan.SessionCalls, PracticeRuns: st.ev.Scan.PracticeRuns, Needles: st.ev.Scan.Needles,
			Hits: len(st.ev.Scan.Hits), SetsHeld: st.ev.Scan.SetsHeld, Provider: st.ev.Provider, Tier: st.ev.Tier, Environment: st.ev.Environment,
			Flights: st.ev.Flights, CPUEnded: st.ev.CPUEnded, GradeMedianSeconds: st.ev.GradeMedianSeconds, GradeMaxSeconds: st.ev.GradeMaxSeconds,
			Usage: st.rf.Usage, Agents: len(st.agents)}
		c, err := exp.Prices.cost(st.rf.Usage.Prompt-st.rf.Usage.CacheRead-st.rf.Usage.CacheWrite, st.rf.Usage.CacheWrite, st.rf.Usage.CacheRead, st.rf.Usage.Completion)
		if err != nil {
			return nil, fmt.Errorf("stage %s: %w", st.name, err)
		}
		s.CostUSD = round4(c)
		se.Cost.Calls += st.rf.Usage.Calls
		se.Cost.StagesUSD += c
		se.Stages = append(se.Stages, s)
		for _, a := range st.agents {
			if !slices.Contains(st.rf.Groups, a.Group) {
				return nil, fmt.Errorf("stage %s holds agent %s of group %s, which it did not build", st.name, a.ID, a.Group)
			}
			// The rule reads every agent or none: an agent whose grading gave no score stops it.
			if !a.Graded || a.GradeProblem != "" {
				return nil, fmt.Errorf("agent %s has no score (%s); the rule reads every agent or none", a.ID, cmp.Or(a.GradeProblem, "not graded"))
			}
			total := a.FreshTotal
			if a.Invalid {
				total = first.ev.FreshCount // refused by the course: it flew nothing, 0 landed by rule
			}
			landed[a.Group] = append(landed[a.Group], float64(a.Fresh)/float64(total))
			words[a.Group] = append(words[a.Group], float64(a.ItemsNamedCount))
			g := findRebuild(st.ev, a.Course, a.Group, a.N)
			score := AgentScore{ID: a.ID, Group: a.Group, Stage: st.name, Fresh: a.Fresh, FreshTotal: total, Practice: a.Practice, PracticeTotal: a.PracticeOf,
				Turns: a.Turns, FlyCalls: a.FlyCalls, Flights: a.Flights, Ended: a.Ended, QuotedRecipe: a.QuotedRecipe, ItemsNamed: a.ItemsNamed,
				SaidPartly: a.Recipe != "" && saidPartly.MatchString(a.AfterAnswer), Controller: a.Controller, Records: len(a.Records)}
			if g != nil {
				score.Bytes, score.FreshBits = g.Bytes, g.FreshBits
			}
			if a.Invalid {
				score.FreshBits = strings.Repeat("0", total) // it flew nothing
			}
			se.Agents = append(se.Agents, score)
			arm := arms[a.Group]
			if arm == nil {
				arm = &ArmEvidence{ID: a.Group, Stage: st.name, Recipe: a.Recipe, Scrambled: a.Scrambled, Naming: []string{}, Low: a.Fresh, High: a.Fresh}
				arms[a.Group] = arm
			}
			arm.Agents++
			arm.Low, arm.High = min(arm.Low, a.Fresh), max(arm.High, a.Fresh)
			if a.ItemsNamedCount > 0 {
				arm.Naming = append(arm.Naming, a.ID)
			}
			if a.QuotedRecipe {
				arm.Quoted++
			}
			if score.SaidPartly {
				arm.SaidPartly++
			}
			if a.RNG {
				arm.RNG++
			}
			if a.GeneratorK {
				arm.Generator++
			}
		}
	}
	for _, x := range exp.Before {
		c, err := exp.Prices.cost(x.Input, x.CacheWrite, x.CacheRead, x.Output)
		if err != nil {
			return nil, err
		}
		se.Cost.BeforeCalls += x.Calls
		se.Cost.BeforeUSD += c
	}
	se.Cost.TotalUSD = round4(se.Cost.StagesUSD + se.Cost.BeforeUSD)
	se.Cost.StagesUSD, se.Cost.BeforeUSD = round4(se.Cost.StagesUSD), round4(se.Cost.BeforeUSD)

	rs := exp.Rule.Resample
	for _, g := range course.Groups {
		arm := arms[g.ID]
		if arm == nil {
			continue
		}
		arm.Label = g.Label
		arm.Landed, arm.Words = fmean(landed[g.ID]), fmean(words[g.ID])
		se.Groups = append(se.Groups, *arm)
	}
	pairs := append([][2]string{exp.Rule.Primary}, exp.Rule.Others...)
	for _, p := range pairs {
		base, treat := p[0], p[1]
		if arms[base] == nil || arms[treat] == nil {
			return nil, fmt.Errorf("the rule's pair %s and %s names a group no stage built", base, treat)
		}
		pe := PairEvidence{Name: treat + " minus " + base, Base: base, Treat: treat}
		for _, m := range []struct {
			d  *Delta
			by map[string][]float64
		}{{&pe.Landed, landed}, {&pe.Words, words}} {
			b, t := m.by[base], m.by[treat]
			diffs := resampleDiffs(b, t, rs.N, rs.Seed)
			*m.d = Delta{Difference: fmean(t) - fmean(b), Interval95: quantiles(diffs, 0.95), Interval90: quantiles(diffs, 0.90)}
		}
		se.Pairs = append(se.Pairs, pe)
	}
	if arms[exp.Rule.BaseArm] == nil {
		return nil, fmt.Errorf("the rule's untreated group %s was built by no stage", exp.Rule.BaseArm)
	}
	se.LandedRead = fmean(landed[exp.Rule.BaseArm]) < exp.Rule.Ceiling
	outcome, err := decide(exp.Rule, se)
	if err != nil {
		return nil, err
	}
	se.Outcome = outcome
	return se, nil
}

// decide applies the registered rule as its own script does: on each value rounded to four
// places, ORDER SHOWED when the primary pair's 95% interval sits above zero on words, or on
// landings when they are read; else WORDS ONLY when recipe minus none and scrambled minus none
// both do on words; else NO RECIPE EFFECT SEEN when the primary pair's 90% intervals sit inside
// the margins (landings only when read) and so does recipe minus none on words; else INCONCLUSIVE.
func decide(r Rule, se *StagedEvidence) (string, error) {
	pair := func(name string) (*PairEvidence, error) {
		for i := range se.Pairs {
			if se.Pairs[i].Name == name {
				return &se.Pairs[i], nil
			}
		}
		return nil, fmt.Errorf("the rule reads the pair %q, which it does not list", name)
	}
	prim, err := pair(r.Primary[1] + " minus " + r.Primary[0])
	if err != nil {
		return "", err
	}
	rn, err := pair("recipe minus none")
	if err != nil {
		return "", err
	}
	sn, err := pair("scrambled minus none")
	if err != nil {
		return "", err
	}
	above := func(d Delta) bool { return round4(d.Interval95[0]) > 0 }
	inside := func(d Delta, margin float64) bool {
		return -margin < round4(d.Interval90[0]) && round4(d.Interval90[1]) < margin
	}
	switch {
	case above(prim.Words) || (se.LandedRead && above(prim.Landed)):
		return outcomeOrder, nil
	case above(rn.Words) && above(sn.Words):
		return outcomeWords, nil
	case inside(prim.Words, r.Margins.Words) && (!se.LandedRead || inside(prim.Landed, r.Margins.Landed)) && inside(rn.Words, r.Margins.Words):
		return outcomeNoneSee, nil
	}
	return outcomeUnclear, nil
}

func (p Prices) cost(input, cacheWrite, cacheRead, output int) (float64, error) {
	if input < 0 || cacheWrite < 0 || cacheRead < 0 || output < 0 {
		return 0, fmt.Errorf("token counts %d, %d, %d, %d: a prompt holds its cache reads and writes", input, cacheWrite, cacheRead, output)
	}
	return (float64(input)*p.Input + float64(cacheWrite)*p.CacheWrite + float64(cacheRead)*p.CacheRead + float64(output)*p.Output) / 1e6, nil
}

// round4 is Python's round(x, 4): the float nearest the correctly rounded decimal, ties to even.
func round4(x float64) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', 4, 64), 64)
	return v
}

// --- the resampling, as CPython draws it ---------------------------------------------------

// pyRandom is CPython's random.Random for a whole-number seed: the Mersenne Twister (MT19937)
// seeded by init_by_array of the seed's 32-bit words, and choice by getrandbits with rejection,
// so the intervals here are exactly the ones the registered rule's script prints.
type pyRandom struct {
	mt  [624]uint32
	mti int
}

func newPyRandom(seed uint64) *pyRandom {
	key := []uint32{uint32(seed)}
	if seed>>32 != 0 {
		key = append(key, uint32(seed>>32))
	}
	r := &pyRandom{}
	r.mt[0] = 19650218
	for i := 1; i < 624; i++ {
		r.mt[i] = 1812433253*(r.mt[i-1]^(r.mt[i-1]>>30)) + uint32(i)
	}
	i, j := 1, 0
	for k := max(624, len(key)); k > 0; k-- {
		r.mt[i] = (r.mt[i] ^ ((r.mt[i-1] ^ (r.mt[i-1] >> 30)) * 1664525)) + key[j] + uint32(j)
		i++
		j++
		if i >= 624 {
			r.mt[0], i = r.mt[623], 1
		}
		if j >= len(key) {
			j = 0
		}
	}
	for k := 623; k > 0; k-- {
		r.mt[i] = (r.mt[i] ^ ((r.mt[i-1] ^ (r.mt[i-1] >> 30)) * 1566083941)) - uint32(i)
		i++
		if i >= 624 {
			r.mt[0], i = r.mt[623], 1
		}
	}
	r.mt[0] = 0x80000000
	r.mti = 624
	return r
}

func (r *pyRandom) uint32() uint32 {
	const n, m = 624, 397
	mag := [2]uint32{0, 0x9908b0df}
	if r.mti >= n {
		kk := 0
		for ; kk < n-m; kk++ {
			y := (r.mt[kk] & 0x80000000) | (r.mt[kk+1] & 0x7fffffff)
			r.mt[kk] = r.mt[kk+m] ^ (y >> 1) ^ mag[y&1]
		}
		for ; kk < n-1; kk++ {
			y := (r.mt[kk] & 0x80000000) | (r.mt[kk+1] & 0x7fffffff)
			r.mt[kk] = r.mt[kk+(m-n)] ^ (y >> 1) ^ mag[y&1]
		}
		y := (r.mt[n-1] & 0x80000000) | (r.mt[0] & 0x7fffffff)
		r.mt[n-1] = r.mt[m-1] ^ (y >> 1) ^ mag[y&1]
		r.mti = 0
	}
	y := r.mt[r.mti]
	r.mti++
	y ^= y >> 11
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18
	return y
}

// below is random.Random._randbelow(n) for 0 < n < 2**32: getrandbits(n.bit_length()), drawn
// again until it is under n.
func (r *pyRandom) below(n int) int {
	k := 0
	for v := n; v > 0; v >>= 1 {
		k++
	}
	for {
		if x := int(r.uint32() >> (32 - k)); x < n {
			return x
		}
	}
}

// mean is statistics.fmean(rng.choice(v) for _ in v): len(v) draws with repeats, averaged.
func (r *pyRandom) mean(v []float64) float64 {
	pick := make([]float64, len(v))
	for i := range pick {
		pick[i] = v[r.below(len(v))]
	}
	return fmean(pick)
}

// resampleDiffs is the rule's resampling of one pair: n times, the treatment's agents drawn
// again, then the base's, and the difference of their means; sorted.
func resampleDiffs(base, treat []float64, n int, seed uint64) []float64 {
	r := newPyRandom(seed)
	out := make([]float64, n)
	for i := range out {
		t := r.mean(treat)
		out[i] = t - r.mean(base)
	}
	slices.Sort(out)
	return out
}

// quantiles is the rule script's interval at a level: the sorted values at int(lo*n) and
// int((1-lo)*n)-1, lo = (1-level)/2, in float64 as Python computes them.
func quantiles(sorted []float64, level float64) [2]float64 {
	n := float64(len(sorted))
	lo := (1 - level) / 2
	return [2]float64{sorted[int(lo*n)], sorted[int((1-lo)*n)-1]}
}

// fmean is statistics.fmean: math.fsum of the values over their count.
func fmean(v []float64) float64 {
	if len(v) == 0 {
		return math.NaN()
	}
	return fsum(v) / float64(len(v))
}

// fsum is Python's math.fsum: the correctly rounded sum (Shewchuk's partials, with its final
// half-even correction).
func fsum(xs []float64) float64 {
	var p []float64
	for _, x := range xs {
		i := 0
		for _, y := range p {
			if math.Abs(x) < math.Abs(y) {
				x, y = y, x
			}
			hi := x + y
			lo := y - (hi - x)
			if lo != 0 {
				p[i] = lo
				i++
			}
			x = hi
		}
		p = append(p[:i], x)
	}
	n := len(p)
	if n == 0 {
		return 0
	}
	n--
	hi, lo := p[n], 0.0
	for n > 0 {
		x := hi
		n--
		y := p[n]
		hi = x + y
		lo = y - (hi - x)
		if lo != 0 {
			break
		}
	}
	if n > 0 && ((lo < 0 && p[n-1] < 0) || (lo > 0 && p[n-1] > 0)) {
		y := lo * 2
		x := hi + y
		if y == x-hi {
			hi = x
		}
	}
	return hi
}

// --- writing and checking the page ------------------------------------------------------------

// writeStageFiles writes a stage's evidence.json and agents.json, as a run of a job with no page
// writes them.
func writeStageFiles(st stageRun) error {
	if err := writeJSON(filepath.Join(st.dir, "evidence.json"), st.ev); err != nil {
		return err
	}
	return writeJSON(filepath.Join(st.dir, "agents.json"), st.agents)
}

func renderStaged(dir string, job *Job) error {
	exp, err := readExperiment(dir)
	if err != nil {
		return err
	}
	stages, err := readStages(dir, job, exp)
	if err != nil {
		return err
	}
	for _, st := range stages {
		if err := writeStageFiles(st); err != nil {
			return err
		}
	}
	se, err := stagedEvidence(exp, job, stages)
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "evidence.json"), se); err != nil {
		return err
	}
	page, err := renderStagedPage(exp, job, se, stages)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), page, 0o644); err != nil {
		return err
	}
	method, err := renderMethodPage(exp, job, se, stages)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, methodPage), method, 0o644); err != nil {
		return err
	}
	fmt.Printf("rendered  | %s and %s: %s\n", filepath.Join(dir, "index.html"), filepath.Join(dir, methodPage), se.Outcome)
	return nil
}

// methodPage is the second page beside index.html: the method, the statistics and related work,
// for readers who know AI, written from the same files.
const methodPage = "method.html"

// verifyStaged checks every stage and that the page's files are what they render.
func verifyStaged(dir string, job *Job) error {
	exp, err := readExperiment(dir)
	if err != nil {
		return err
	}
	stages, err := readStages(dir, job, exp)
	if err != nil {
		return err
	}
	same := func(path string, v any) error {
		want, err := encodeJSON(v)
		if err != nil {
			return err
		}
		if have, err := os.ReadFile(path); err != nil || !bytes.Equal(have, want) {
			return fmt.Errorf("%s is not what the stages' files state; run -staged -render", path)
		}
		return nil
	}
	for _, st := range stages {
		if err := same(filepath.Join(st.dir, "evidence.json"), st.ev); err != nil {
			return err
		}
		if err := same(filepath.Join(st.dir, "agents.json"), st.agents); err != nil {
			return err
		}
	}
	se, err := stagedEvidence(exp, job, stages)
	if err != nil {
		return err
	}
	if err := same(filepath.Join(dir, "evidence.json"), se); err != nil {
		return err
	}
	page, err := renderStagedPage(exp, job, se, stages)
	if err != nil {
		return err
	}
	if have, err := os.ReadFile(filepath.Join(dir, "index.html")); err != nil || !bytes.Equal(have, page) {
		return errors.New("index.html is not what the evidence renders; run -staged -render")
	}
	method, err := renderMethodPage(exp, job, se, stages)
	if err != nil {
		return err
	}
	if have, err := os.ReadFile(filepath.Join(dir, methodPage)); err != nil || !bytes.Equal(have, method) {
		return fmt.Errorf("%s is not what the evidence renders; run -staged -render", methodPage)
	}
	for _, s := range se.Stages {
		fmt.Printf("verified  | stage %s: %d lines signed by %s; %d grading runs on the sealed sets (fresh %s…); %d session calls and %d practice runs scanned for %d forbidden strings, none found\n",
			s.Name, s.Lines, s.Harness, s.GradingRuns, se.FreshSHA256[:16], s.SessionCalls, s.PracticeRuns, s.Needles)
	}
	fmt.Printf("design    | every stage made under %s, the design this program writes for %s on %s\n", se.Design, se.Job, se.Model)
	for _, g := range se.Groups {
		fmt.Printf("group     | %-9s %2d agents, fresh flights landed %.1f%% (lowest %d, highest %d of %d), recipe words named in code %.3g\n",
			g.ID, g.Agents, 100*g.Landed, g.Low, g.High, se.FreshCount, g.Words)
	}
	for _, p := range se.Pairs {
		fmt.Printf("pair      | %-22s landed %+.1f points (95%% %+.1f to %+.1f), words %+.3g\n", p.Name, 100*p.Landed.Difference, 100*p.Landed.Interval95[0], 100*p.Landed.Interval95[1], p.Words.Difference)
	}
	fmt.Printf("rule      | %s\n", se.Outcome)
	return nil
}

// --- the page ---------------------------------------------------------------------------------

// stagedPage is what staged.html and method.html see.
type stagedPage struct {
	Ev         *StagedEvidence
	Exp        *Experiment
	Job        *Job
	Course     CourseJob
	stages     []stageRun
	freshSeeds []uint32 // the sealed set, in the order every grading run flew it
	byID       map[string]AgentRecord
	src        map[string]string // each agent's graded controller, from its transcript
}

func newStagedPage(exp *Experiment, job *Job, se *StagedEvidence, stages []stageRun) (stagedPage, error) {
	p := stagedPage{Ev: se, Exp: exp, Job: job, Course: job.Courses[0], stages: stages, byID: map[string]AgentRecord{}, src: map[string]string{}}
	for _, st := range stages {
		for _, a := range st.agents {
			p.byID[a.ID] = a
		}
		ts, err := readTranscripts(st.dir)
		if err != nil {
			return p, err
		}
		for _, t := range ts {
			p.src[fmt.Sprintf("%s.%s.%d", t.Course, t.Group, t.N)] = t.Controller
		}
	}
	var fresh SealedSet
	if err := readJSON(filepath.Join(stages[0].dir, "fresh.json"), &fresh); err != nil {
		return p, err
	}
	if digest(fresh.encode()) != se.FreshSHA256 {
		return p, fmt.Errorf("%s/fresh.json is not the set the stages committed to (%s)", stages[0].dir, se.FreshSHA256)
	}
	p.freshSeeds = fresh.Seeds
	return p, nil
}

// ModelBases are the addresses each stage's model calls were sent to, in stage order: a local
// relay on the experimenter's machine that enforced the spending cap, which the page explains.
// Each must be a loopback address, or the page's sentence would be false.
func (p stagedPage) ModelBases() ([]string, error) {
	var out []string
	for _, st := range p.stages {
		base := st.rf.ModelBase
		if base == "" {
			return nil, fmt.Errorf("stage %s's run.json records no model_base", st.name)
		}
		if !strings.HasPrefix(base, "http://127.0.0.1:") && !strings.HasPrefix(base, "http://localhost:") {
			return nil, fmt.Errorf("stage %s sent its model calls to %q, which is not a local relay", st.name, base)
		}
		out = append(out, base)
	}
	return out, nil
}

func renderStagedPage(exp *Experiment, job *Job, se *StagedEvidence, stages []stageRun) ([]byte, error) {
	return renderStagedTemplate("staged", stagedTemplate, exp, job, se, stages)
}

func renderMethodPage(exp *Experiment, job *Job, se *StagedEvidence, stages []stageRun) ([]byte, error) {
	return renderStagedTemplate("method", methodTemplate, exp, job, se, stages)
}

func renderStagedTemplate(name, text string, exp *Experiment, job *Job, se *StagedEvidence, stages []stageRun) ([]byte, error) {
	p, err := newStagedPage(exp, job, se, stages)
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New(name).Funcs(template.FuncMap{
		"seq":  seq,
		"list": func(v ...any) []any { return v },
		"add":  func(a, b int) int { return a + b },
		"mul":  func(a, b int) int { return a * b },
		"div":  func(a, b int) int { return a / b },
		"mod":  func(a, b int) int { return a % b },
		"addf": func(a, b float64) float64 { return round1(a + b) },
		"mulf": func(a, b float64) float64 { return round1(a * b) },
		"f1":   func(x float64) string { return strconv.FormatFloat(x, 'f', 1, 64) },
		"f3":   func(x float64) string { return strconv.FormatFloat(x, 'f', 3, 64) },
		"flights": func(x float64) string {
			s := fmt.Sprintf("%+.1f", x)
			if s == "-0.0" || s == "+0.0" {
				return "0.0"
			}
			return s
		},
		"pct":     func(x float64) string { return fmt.Sprintf("%.1f%%", 100*x) },
		"pts":     func(x float64) string { return signed(100 * x) },
		"usd":     func(x float64) string { return fmt.Sprintf("$%.2f", x) },
		"short":   func(s string) string { return s[:min(16, len(s))] + "…" },
		"comma":   comma,
		"numword": numberWord,
		"upper":   func(s string) string { return strings.ToUpper(s[:1]) + s[1:] },
		"lower":   strings.ToLower,
		"clock":   func(t time.Time) string { return t.UTC().Format("15:04") },
		"day":     func(t time.Time) string { return t.UTC().Format("2006-01-02") },
		"minutes": func(a, b time.Time) int { return int(math.Round(b.Sub(a).Minutes())) },
		"assert": func(ok bool, claim string) (string, error) {
			if !ok {
				return "", fmt.Errorf("the page says %q, and the evidence does not", claim)
			}
			return "", nil
		},
		"md":    mdBlock,
		"plain": mdInline,
		"pct0":  func(x float64) string { return fmt.Sprintf("%.0f%%", 100*x) },
		"float": func(n int) float64 { return float64(n) },
		"sub0":  func(x float64) float64 { return -x },
		"subf":  func(a, b float64) float64 { return a - b },
		"sub":   func(a, b int) int { return a - b },
		// wdiff writes a count of recipe items, or a difference of them: 0, -0.125, +0.5.
		"wdiff": func(x float64) string {
			if x == 0 {
				return "0"
			}
			return fmt.Sprintf("%+.3g", x)
		},
	}).Parse(text)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return nil, err
	}
	return applyGlossary(buf.Bytes())
}

func signed(x float64) string {
	s := fmt.Sprintf("%+.1f", x)
	if s == "-0.0" || s == "+0.0" {
		return "0.0"
	}
	return s
}

// Group is a group's evidence by ID.
func (p stagedPage) Group(id string) (*ArmEvidence, error) {
	for i := range p.Ev.Groups {
		if p.Ev.Groups[i].ID == id {
			return &p.Ev.Groups[i], nil
		}
	}
	return nil, fmt.Errorf("no group %q", id)
}

// Name is how the page names a group: by the recipe it was given.
func (p stagedPage) Name(id string) (string, error) {
	g, err := p.Group(id)
	switch {
	case err != nil:
		return "", err
	case g.Recipe == "":
		return "No recipe", nil
	case g.Scrambled:
		return "Scrambled recipe", nil
	}
	return "Honest recipe", nil
}

// Pair is a pair's evidence by name.
func (p stagedPage) Pair(name string) (*PairEvidence, error) {
	for i := range p.Ev.Pairs {
		if p.Ev.Pairs[i].Name == name {
			return &p.Ev.Pairs[i], nil
		}
	}
	return nil, fmt.Errorf("no pair %q", name)
}

// Stage is a stage's evidence by name.
func (p stagedPage) Stage(name string) (*StageEvidence, error) {
	for i := range p.Ev.Stages {
		if p.Ev.Stages[i].Name == name {
			return &p.Ev.Stages[i], nil
		}
	}
	return nil, fmt.Errorf("no stage %q", name)
}

// Agent is an agent's score by ID.
func (p stagedPage) Agent(id string) (*AgentScore, error) {
	for i := range p.Ev.Agents {
		if p.Ev.Agents[i].ID == id {
			return &p.Ev.Agents[i], nil
		}
	}
	return nil, fmt.Errorf("no agent %q", id)
}

// GroupAgents are a group's agents in the order they were built.
func (p stagedPage) GroupAgents(id string) []AgentScore {
	var out []AgentScore
	for _, a := range p.Ev.Agents {
		if a.Group == id {
			out = append(out, a)
		}
	}
	return out
}

// Answer is an agent's whole answer to the question asked after its session, rendered.
func (p stagedPage) Answer(id string) (template.HTML, error) {
	a, ok := p.byID[id]
	if !ok || a.AfterAnswer == "" {
		return "", fmt.Errorf("agent %q has no answer to quote", id)
	}
	return mdBlock(a.AfterAnswer), nil
}

// Quote is the part of an agent's answer from the first place from occurs to the end of the
// first to after it, verbatim: an excerpt, never a paraphrase.
func (p stagedPage) Quote(id, from, to string) (template.HTML, error) {
	a, ok := p.byID[id]
	if !ok {
		return "", fmt.Errorf("no agent %q", id)
	}
	i := strings.Index(a.AfterAnswer, from)
	if i < 0 {
		return "", fmt.Errorf("agent %s's answer does not say %q", id, from)
	}
	j := strings.Index(a.AfterAnswer[i+len(from):], to)
	if j < 0 {
		return "", fmt.Errorf("agent %s's answer does not say %q after %q", id, to, from)
	}
	return mdInline(a.AfterAnswer[i : i+len(from)+j+len(to)]), nil
}

// Says is a phrase an agent's answer holds, verbatim, so the page can quote it in a sentence.
func (p stagedPage) Says(id, phrase string) (string, error) {
	if a, ok := p.byID[id]; !ok || !strings.Contains(a.AfterAnswer, phrase) {
		return "", fmt.Errorf("agent %s's answer does not say %q", id, phrase)
	}
	return phrase, nil
}

// Saying is how many of a group's answers hold a phrase, case ignored.
func (p stagedPage) Saying(group, phrase string) int {
	n := 0
	for _, a := range p.byID {
		if a.Group == group && strings.Contains(strings.ToLower(a.AfterAnswer), strings.ToLower(phrase)) {
			n++
		}
	}
	return n
}

// RecordsPerAgent is how many grading runs graded each controller: the same for every agent.
func (p stagedPage) RecordsPerAgent() (int, error) {
	n := -1
	for _, a := range p.Ev.Agents {
		if n >= 0 && a.Records != n {
			return 0, fmt.Errorf("agent %s was graded in %d runs, others in %d", a.ID, a.Records, n)
		}
		n = a.Records
	}
	return n, nil
}

// CacheShare is the share of every stage's prompt tokens read from the prompt cache.
func (p stagedPage) CacheShare() string {
	read, prompt := 0, 0
	for _, s := range p.Ev.Stages {
		read += s.Usage.CacheRead
		prompt += s.Usage.Prompt
	}
	return fmt.Sprintf("%.0f%%", 100*float64(read)/float64(max(prompt, 1)))
}

// Question is the question an agent was asked after its session.
func (p stagedPage) Question(withRecipe bool) string {
	if withRecipe {
		return afterQuestion("a recipe")
	}
	return afterQuestion("")
}

// BriefTail is what a group's brief says after the course's API text: where the recipe is
// given, and what the agent is asked to do.
func (p stagedPage) BriefTail(id string) (string, error) {
	for _, g := range p.Course.Groups {
		if g.ID == id {
			b := brief(p.Course.ID, p.Course.recipeFor(g))
			const after = "Your artifact lives at controller.js in your work directory.\n"
			i := strings.Index(b, after)
			if i < 0 {
				return "", errors.New("the brief no longer says where the artifact lives")
			}
			return b[i+len(after):], nil
		}
	}
	return "", fmt.Errorf("no group %q", id)
}

// System is the system prompt every agent was given.
func (p stagedPage) System() string { return systemPrompt }

// CodeLines are the lines of an agent's graded controller that hold any of the given strings,
// trimmed, in order: the page shows code as it was graded.
func (p stagedPage) CodeLines(id string, holds ...string) (string, error) {
	src, ok := p.src[id]
	if !ok {
		return "", fmt.Errorf("no controller for agent %q", id)
	}
	var out []string
	found := map[string]bool{}
	for _, line := range strings.Split(src, "\n") {
		for _, h := range holds {
			if strings.Contains(line, h) {
				out = append(out, strings.TrimSpace(line))
				found[h] = true
				break
			}
		}
	}
	for _, h := range holds {
		if !found[h] {
			return "", fmt.Errorf("agent %s's controller has no line holding %q", id, h)
		}
	}
	return strings.Join(out, "\n"), nil
}

// CommentOnly is true when one of an item's patterns matches an agent's controller only inside a
// comment: the word is in the file, and the registered measure, which removes comments, does not
// count it.
func (p stagedPage) CommentOnly(id, item string) (bool, error) {
	src, ok := p.src[id]
	if !ok {
		return false, fmt.Errorf("no controller for agent %q", id)
	}
	l, ok := courseItems(p.Course)
	if !ok {
		return false, errors.New("the course lists no recipe items")
	}
	for _, it := range l.Items {
		if it.Item != item {
			continue
		}
		whole := itemsNamed([]RecipeItem{it}, src, baselineIdentifiers())
		code := itemsNamed([]RecipeItem{it}, stripComments(src), baselineIdentifiers())
		return len(whole) == 1 && len(code) == 0, nil
	}
	return false, fmt.Errorf("no recipe item %q", item)
}

// Items are the course's recipe items, as the measure reads them.
func (p stagedPage) Items() []RecipeItem {
	l, _ := courseItems(p.Course)
	return l.Items
}

// ItemPatterns writes an item's patterns as the page lists them.
func (p stagedPage) ItemPatterns(it RecipeItem) string { return strings.Join(it.Any, "  ·  ") }

// Minutes is how long a stage ran, in whole minutes.
func (p stagedPage) Minutes(s StageEvidence) int {
	return int(math.Round(s.Ended.Sub(s.Started).Minutes()))
}

// Totals are the flights flown and the grading runs over every stage.
func (p stagedPage) Totals() map[string]int {
	t := map[string]int{}
	for _, s := range p.Ev.Stages {
		t["flights"] += s.Flights
		t["grading"] += s.GradingRuns
		t["session"] += s.SessionCalls
		t["practice"] += s.PracticeRuns
		t["lines"] += s.Lines
		t["hits"] += s.Hits
	}
	t["agents"] = len(p.Ev.Agents)
	return t
}

// ZeroIn is true when an interval holds zero (by the rule's rounding).
func (p stagedPage) ZeroIn(iv [2]float64) bool { return round4(iv[0]) <= 0 && 0 <= round4(iv[1]) }

// Above is true when an interval sits above zero (by the rule's rounding).
func (p stagedPage) Above(iv [2]float64) bool { return round4(iv[0]) > 0 }

// Below is true when an interval sits below zero (by the rule's rounding).
func (p stagedPage) Below(iv [2]float64) bool { return round4(iv[1]) < 0 }

// AllZero is true when no agent of any of the named groups named a recipe word in code.
func (p stagedPage) AllZero(ids ...string) bool {
	for _, a := range p.Ev.Agents {
		if slices.Contains(ids, a.Group) && len(a.ItemsNamed) > 0 {
			return false
		}
	}
	return true
}

// mdBlock writes an agent's answer, which is markdown, as HTML: every character escaped first,
// then paragraphs, "- " lists, **bold** and `code` only, so nothing the model wrote becomes
// markup of its own.
func mdBlock(s string) template.HTML {
	var b strings.Builder
	inList := false
	for _, para := range strings.Split(strings.TrimSpace(s), "\n\n") {
		lines := strings.Split(para, "\n")
		for _, line := range lines {
			line = strings.TrimRight(line, " ")
			if rest, ok := strings.CutPrefix(line, "- "); ok {
				if !inList {
					b.WriteString("<ul>")
					inList = true
				}
				b.WriteString("<li>" + string(mdInline(rest)) + "</li>")
				continue
			}
			if inList {
				b.WriteString("</ul>")
				inList = false
			}
			if line != "" {
				b.WriteString("<p>" + string(mdInline(line)) + "</p>")
			}
		}
		if inList {
			b.WriteString("</ul>")
			inList = false
		}
	}
	return template.HTML(b.String())
}

var (
	mdBold = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdCode = regexp.MustCompile("`([^`]+)`")
)

// mdInline escapes a line and keeps its **bold** and `code`.
func mdInline(s string) template.HTML {
	e := html.EscapeString(s)
	e = mdCode.ReplaceAllString(e, "<code>$1</code>")
	e = mdBold.ReplaceAllString(e, "<b>$1</b>")
	return template.HTML(e)
}

// --- the drawings -----------------------------------------------------------------------------

// Strip is one group's agents drawn on the fresh-flights axis: a dot an agent and the group's
// mean, as SVG. A single group's mean is drawn with no interval (the owner's decision of
// 2026-11-07): the registered rule's intervals belong to the differences between groups.
type Strip struct {
	Group   *ArmEvidence
	Dots    []StripDot
	Mean    float64 // x of the mean
	Height  int
	Axis    []AxisTick
	Width   int
	Midline int
}

// StripDot is one agent's dot.
type StripDot struct {
	X, Y float64
	Tip  string
}

// AxisTick is one labeled tick.
type AxisTick struct {
	X      float64
	Label  string
	Anchor string // the label's text-anchor: an end tick's label leans inward so a phone's larger axis text is not cut off
}

// anchored sets each tick's text-anchor: start within stripPad*2 of the left edge, end within it of the right, middle elsewhere.
func anchored(ticks []AxisTick) []AxisTick {
	for i := range ticks {
		switch {
		case ticks[i].X <= 2*stripPad:
			ticks[i].Anchor = "start"
		case ticks[i].X >= stripWidth-2*stripPad:
			ticks[i].Anchor = "end"
		default:
			ticks[i].Anchor = "middle"
		}
	}
	return ticks
}

const (
	stripWidth = 600
	stripPad   = 14 // room at each end for a dot
	dotR       = 7
	dotStep    = 16
)

// FreshAxis is the shared x axis of the strips: whole fresh flights from a multiple of four below
// the lowest score to the set's size.
func (p stagedPage) FreshAxis() (lo, hi int) {
	low := p.Ev.FreshCount
	for _, g := range p.Ev.Groups {
		low = min(low, g.Low)
	}
	return max(0, (low-2)/4*4), p.Ev.FreshCount
}

func (p stagedPage) fx(flights float64) float64 {
	lo, hi := p.FreshAxis()
	return math.Round((stripPad+(flights-float64(lo))/float64(hi-lo)*(stripWidth-2*stripPad))*10) / 10
}

// Strips draws every group, all at the height of the tallest stack of equal scores.
func (p stagedPage) Strips() []Strip {
	tallest := 1
	for _, g := range p.Ev.Groups {
		count := map[int]int{}
		for _, a := range p.GroupAgents(g.ID) {
			count[a.Fresh]++
			tallest = max(tallest, count[a.Fresh])
		}
	}
	h := 2*dotR + (tallest-1)*dotStep + 16
	var out []Strip
	for gi := range p.Ev.Groups {
		g := &p.Ev.Groups[gi]
		s := Strip{Group: g, Height: h, Width: stripWidth, Midline: h / 2}
		n := float64(p.Ev.FreshCount)
		s.Mean = p.fx(g.Landed * n)
		agents := p.GroupAgents(g.ID)
		stack := map[int][]AgentScore{}
		for _, a := range agents {
			stack[a.Fresh] = append(stack[a.Fresh], a)
		}
		for _, a := range agents {
			col := stack[a.Fresh]
			k := slices.IndexFunc(col, func(x AgentScore) bool { return x.ID == a.ID })
			y := float64(h)/2 + (float64(k)-float64(len(col)-1)/2)*dotStep
			s.Dots = append(s.Dots, StripDot{X: p.fx(float64(a.Fresh)), Y: y,
				Tip: fmt.Sprintf("%s: %d of %d fresh flights landed, %d of %d practice", a.ID, a.Fresh, a.FreshTotal, a.Practice, a.PracticeTotal)})
		}
		out = append(out, s)
	}
	return out
}

// FreshTicks are the strips' axis ticks, every four flights.
func (p stagedPage) FreshTicks() []AxisTick {
	lo, hi := p.FreshAxis()
	var out []AxisTick
	for f := lo; f <= hi; f += 4 {
		out = append(out, AxisTick{X: p.fx(float64(f)), Label: strconv.Itoa(f)})
	}
	return anchored(out)
}

// DiffRow is one pair drawn on the points axis: its difference and its 90% and 95% intervals.
type DiffRow struct {
	Pair                   *PairEvidence
	X, Lo95, Hi95, Lo, Hi  float64
	Zero                   float64
	Tip                    string
	Above, Below, HoldZero bool
}

// diffAxis is the points axis: from a multiple of 2.5 points below the lowest interval end (and
// zero) to one above the highest.
func (p stagedPage) diffAxis() (lo, hi float64) {
	lo, hi = 0, 0
	for _, pe := range p.Ev.Pairs {
		lo = min(lo, 100*pe.Landed.Interval95[0])
		hi = max(hi, 100*pe.Landed.Interval95[1])
	}
	return math.Floor(lo/2.5)*2.5 - 2.5, math.Ceil(hi/2.5)*2.5 + 2.5
}

func (p stagedPage) dx(points float64) float64 {
	lo, hi := p.diffAxis()
	return math.Round((stripPad+(points-lo)/(hi-lo)*(stripWidth-2*stripPad))*10) / 10
}

// DiffRows draws every pair's landings.
func (p stagedPage) DiffRows() []DiffRow {
	var out []DiffRow
	for i := range p.Ev.Pairs {
		pe := &p.Ev.Pairs[i]
		d := pe.Landed
		out = append(out, DiffRow{Pair: pe, X: p.dx(100 * d.Difference), Lo95: p.dx(100 * d.Interval95[0]), Hi95: p.dx(100 * d.Interval95[1]),
			Lo: p.dx(100 * d.Interval90[0]), Hi: p.dx(100 * d.Interval90[1]), Zero: p.dx(0),
			Tip: fmt.Sprintf("%s: %s points (95%% interval %s to %s; 90%% interval %s to %s)", pe.Name, signed(100*d.Difference),
				signed(100*d.Interval95[0]), signed(100*d.Interval95[1]), signed(100*d.Interval90[0]), signed(100*d.Interval90[1])),
			Above: p.Above(d.Interval95), Below: p.Below(d.Interval95), HoldZero: p.ZeroIn(d.Interval95)})
	}
	return out
}

// DiffTicks are the points axis's ticks, every 5 points.
func (p stagedPage) DiffTicks() []AxisTick {
	lo, hi := p.diffAxis()
	var out []AxisTick
	for v := math.Ceil(lo/5) * 5; v <= hi; v += 5 {
		out = append(out, AxisTick{X: p.dx(v), Label: signed(v)})
	}
	for i := range out {
		out[i].Label = strings.TrimSuffix(out[i].Label, ".0")
	}
	return anchored(out)
}

// HeadBar is one group's average share of the fresh flights landed, drawn from zero on a 0 to 100%
// axis, so the summary box's comparison is seen at its true size before section 3's zoomed axes.
type HeadBar struct {
	Group *ArmEvidence
	End   float64 // x of the bar's end
	Path  string  // the bar: square at zero, rounded at its end
	Tip   string
}

// sx is the share axis: 0 to 100% across the strip.
func sx(share float64) float64 {
	return math.Round((stripPad+share*(stripWidth-2*stripPad))*10) / 10
}

// HeadBar draws one group's bar.
func (p stagedPage) HeadBar(id string) (HeadBar, error) {
	g, err := p.Group(id)
	if err != nil {
		return HeadBar{}, err
	}
	x0, x1, y0, y1, r := float64(stripPad), sx(g.Landed), 6.0, 28.0, 4.0
	return HeadBar{Group: g, End: x1,
		Path: fmt.Sprintf("M%.1f %.1f H%.1f Q%.1f %.1f %.1f %.1f V%.1f Q%.1f %.1f %.1f %.1f H%.1f Z",
			x0, y0, x1-r, x1, y0, x1, y0+r, y1-r, x1, y1, x1-r, y1, x0),
		Tip: fmt.Sprintf("%s: %d agents, %s of the %d sealed flights landed on average", g.Label, g.Agents,
			fmt.Sprintf("%.1f%%", 100*g.Landed), p.Ev.FreshCount)}, nil
}

// HeadGap is a pair's difference drawn twice: as the gap between its two bars on the share axis,
// and as a dot with its 95% interval on section 3's points axis.
type HeadGap struct {
	Pair        *PairEvidence
	Base, Treat *ArmEvidence
	From, To    float64 // the gap on the share axis
	Row         DiffRow
	ZeroPct     float64 // where zero sits on the points axis, as a share of its width
	PerFresh    float64 // the difference in flights, of the fresh set
}

// HeadGap finds the named pair and checks that its difference is its two groups' averages apart.
func (p stagedPage) HeadGap(name string) (HeadGap, error) {
	pe, err := p.Pair(name)
	if err != nil {
		return HeadGap{}, err
	}
	base, err := p.Group(pe.Base)
	if err != nil {
		return HeadGap{}, err
	}
	treat, err := p.Group(pe.Treat)
	if err != nil {
		return HeadGap{}, err
	}
	if math.Abs(treat.Landed-base.Landed-pe.Landed.Difference) > 1e-9 {
		return HeadGap{}, fmt.Errorf("%s: difference %v is not %s's %v less %s's %v", name, pe.Landed.Difference,
			treat.ID, treat.Landed, base.ID, base.Landed)
	}
	var row DiffRow
	for _, r := range p.DiffRows() {
		if r.Pair.Name == name {
			row = r
		}
	}
	return HeadGap{Pair: pe, Base: base, Treat: treat, From: sx(min(base.Landed, treat.Landed)), To: sx(max(base.Landed, treat.Landed)),
		Row: row, ZeroPct: math.Round(row.Zero/stripWidth*1000) / 10, PerFresh: pe.Landed.Difference * float64(p.Ev.FreshCount)}, nil
}

// ShareTicks are the share axis's ticks, every 25%.
func (p stagedPage) ShareTicks() []AxisTick {
	var out []AxisTick
	for v := 0; v <= 100; v += 25 {
		out = append(out, AxisTick{X: sx(float64(v) / 100), Label: strconv.Itoa(v) + "%"})
	}
	return anchored(out)
}

// AllLanded reports whether every recorded flight in the figure ended in a landing, so the
// caption that says so is written from the tracks and cannot outlive a failed flight.
func (f *FlightFigure) AllLanded() bool {
	for _, t := range f.Tracks {
		if !t.Landed {
			return false
		}
	}
	return len(f.Tracks) > 0
}

// FlyCapped are the agents that used every fly call the job allows, in the order built.
func (p stagedPage) FlyCapped() []AgentScore {
	var out []AgentScore
	for _, a := range p.Ev.Agents {
		if a.FlyCalls >= p.Job.Rebuild.FlyCalls {
			out = append(out, a)
		}
	}
	return out
}
