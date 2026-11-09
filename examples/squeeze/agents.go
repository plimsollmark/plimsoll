package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// agents.json is one record per built rebuild: what it was given, whether it quoted its recipe,
// which of the recipe's items its controller's identifiers name, whether that code carries a
// random number generator, its calls, why it stopped, its answer to the question asked after,
// and its scores. Every check here is code, declared before the run in the job (the recipe
// items) and the design document (the patterns); the scores come from the signed grading runs
// through evidence.json, never from the transcript or the agent's own account.

// AgentRecord is one built rebuild.
type AgentRecord struct {
	ID        string `json:"id"` // course.group.n
	Course    string `json:"course"`
	Group     string `json:"group"`
	N         int    `json:"n"`
	Recipe    string `json:"recipe"` // as given
	Scrambled bool   `json:"scrambled,omitempty"`
	// Quoted is the longest run of consecutive words of the recipe as given found in what the
	// agent wrote (its text, reasoning summaries and tool inputs), case and punctuation ignored;
	// QuotedOriginal the same for the loop's own recipe in its own order (for the scrambled
	// group, whether it put the plan back together; for the control, the chance level).
	Quoted         int  `json:"quoted"`
	QuotedOriginal int  `json:"quoted_original"`
	QuotedRecipe   bool `json:"quoted_recipe"` // Quoted is at least quotedMin words
	// ItemsNamed are the recipe items one of whose patterns matches an identifier of the final
	// controller's code (comments removed, case ignored) that the baseline every sandbox starts
	// with does not hold: recipe words named in code, a measure of the recipe's words taken up,
	// not of what the code does. ItemsNamedRaw keeps the baseline's identifiers (the baseline names
	// one item itself, its altitude integral integralY), so a reader sees what was left out.
	// ItemsOf is how many items the course's recipe lists.
	ItemsNamed      []string `json:"items_named"`
	ItemsNamedCount int      `json:"items_named_count"`
	ItemsNamedRaw   []string `json:"items_named_raw"`
	ItemsOf         int      `json:"items_of"`
	RNG             bool     `json:"rng"`                // a random number generator, by rngPattern
	GeneratorK      bool     `json:"generator_constant"` // the simulator's own generator: the hackathon's check
	Controller      string   `json:"controller_sha256,omitempty"`
	From            string   `json:"controller_from"`
	Graded          bool     `json:"graded"` // a grading run answered for this controller
	Valid           bool     `json:"valid"`
	// Invalid: the course's validator refused the controller's source, so it flew no flight: its
	// own failure, 0 landed by rule. GradeProblem: why its grading gave no score though its source
	// was not refused (a run with no record, a run whose time ran out): the grading's failure, not
	// the controller's, so it has no score. BuildProblem: why the session ended short (run.json's).
	Invalid      bool   `json:"invalid,omitempty"`
	GradeProblem string `json:"grade_problem,omitempty"`
	BuildProblem string `json:"build_problem,omitempty"`
	// Regraded names the regrade (regrades/<name>, -regrade) whose grading these scores are, when
	// the run's own grading of the controller failed.
	Regraded    string   `json:"regraded,omitempty"`
	Fresh       int      `json:"fresh"`
	FreshTotal  int      `json:"fresh_total"`
	Practice    int      `json:"practice"`
	PracticeOf  int      `json:"practice_total"`
	Records     []string `json:"records,omitempty"`
	Turns       int      `json:"turns"`
	FlyCalls    int      `json:"fly_calls"`
	Flights     int      `json:"flights"`
	Runs        int      `json:"runs"`
	Ended       string   `json:"ended"`
	Calls       Counts   `json:"calls"`
	Reasoning   int      `json:"reasoning_chars"`
	AfterAnswer string   `json:"after_answer,omitempty"`
}

// Counts are a rebuild's tool calls by tool and by how they went.
type Counts struct {
	ByTool map[string]int `json:"by_tool"`
	ByKind map[string]int `json:"by_kind"`
}

// quotedMin is how many consecutive recipe words count as quoting it.
const quotedMin = 3

var (
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment  = regexp.MustCompile(`(?m)//.*$`)
	// rngPattern finds a random number generator in a controller's code: JavaScript's own, the
	// simulator's (Mulberry32), and the common hand-written ones by name or constant.
	rngPattern = regexp.MustCompile(`(?i)\bmath\s*\.\s*random\b|getrandomvalues|0x6d2b79f5|\b1831565813\b|mulberry|xorshift|splitmix|\blcg\b|\b(?:1664525|1013904223|1103515245|2654435761|2654435769|6364136223846793005)\b|0x9e3779b9|\bp?rng\b`)
	wordRe     = regexp.MustCompile(`[a-z0-9]+(?:[/+][a-z0-9]+)*|\+`)
)

func stripComments(src string) string {
	return lineComment.ReplaceAllString(blockComment.ReplaceAllString(src, " "), " ")
}

func words(s string) []string { return wordRe.FindAllString(strings.ToLower(s), -1) }

// longestRun is the longest run of consecutive words of recipe found in text.
func longestRun(recipe, text []string) int {
	best := 0
	prev := make([]int, len(recipe)+1)
	for _, w := range text {
		cur := make([]int, len(recipe)+1)
		for j, r := range recipe {
			if r == w {
				cur[j+1] = prev[j] + 1
				best = max(best, cur[j+1])
			}
		}
		prev = cur
	}
	return best
}

// writing is everything a transcript's agent wrote, in order.
func writing(t Transcript) string {
	var b strings.Builder
	for _, turn := range t.Turns {
		b.WriteString(turn.Answer.Reasoning + "\n" + turn.Answer.Text + "\n")
		for _, c := range turn.Answer.Calls {
			var in map[string]any
			if json.Unmarshal(c.Input, &in) == nil {
				for _, k := range sortedKeys(in) {
					if s, ok := in[k].(string); ok {
						b.WriteString(s + "\n")
					}
				}
			}
		}
	}
	return b.String()
}

// identifier is the unit a recipe item's patterns match in: a run of letters, digits and
// underscores (every pattern of the jobs matches word characters only).
var identifier = regexp.MustCompile(`\w+`)

// baselineIdentifiers are the identifiers of the baseline controller every rebuild's sandbox
// starts with (rebuildFiles): an identifier a controller kept from it names nothing the agent
// added, so itemsNamed passes over it.
func baselineIdentifiers() map[string]bool {
	out := map[string]bool{}
	for _, id := range identifier.FindAllString(stripComments(courseFile("baselines/stabilizer.js")), -1) {
		out[id] = true
	}
	return out
}

// itemsNamed are the items one of whose patterns, case ignored, matches an identifier of code
// (comments already removed) that skip does not hold, in the items' order.
func itemsNamed(items []RecipeItem, code string, skip map[string]bool) []string {
	named := []string{}
	ids := identifier.FindAllString(code, -1)
	for _, it := range items {
		found := false
		for _, p := range it.Any {
			re := regexp.MustCompile("(?i)" + p)
			for _, id := range ids {
				if !skip[id] && re.MatchString(id) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			named = append(named, it.Item)
		}
	}
	return named
}

// courseItems are the recipe items every controller on a course is checked for: the first of
// its loops that lists items, so the control group's controllers are read by the same patterns.
func courseItems(c CourseJob) (Loop, bool) {
	for _, l := range c.Loops {
		if len(l.Items) > 0 {
			return l, true
		}
	}
	return Loop{}, false
}

// designedSession refuses a transcript whose session was not the one the design states for its
// group: its recipe, its system prompt, its brief and its after-session question must be what this
// program writes for the group. The run's design digest is in run.json, which is unsigned; this ties
// what each agent was actually sent to that design.
func designedSession(cj CourseJob, t Transcript) error {
	i := slices.IndexFunc(cj.Groups, func(g Group) bool { return g.ID == t.Group })
	if cj.ID == "" || i < 0 {
		return fmt.Errorf("the transcript names no group of the job's course %q", t.Course)
	}
	g := cj.Groups[i]
	recipe := cj.recipeFor(g)
	switch {
	case t.Recipe != recipe || t.Scrambled != g.Scramble:
		return errors.New("the transcript's recipe is not its group's")
	case t.System != systemPrompt:
		return errors.New("the transcript's system prompt is not the one every rebuild is given")
	case t.Prompt != brief(t.Course, recipe):
		return errors.New("the transcript's brief is not its group's")
	case t.Question != "" && t.Question != afterQuestion(recipe):
		return errors.New("the transcript's after-session question is not its group's")
	}
	return nil
}

// agentRecords derives agents.json from the run's transcripts, its run.json and the evidence.
func agentRecords(dir string, job *Job, ev *Evidence) ([]AgentRecord, error) {
	ts, err := readTranscripts(dir)
	if err != nil {
		return nil, err
	}
	var rf RunFile
	if err := readJSON(filepath.Join(dir, "run.json"), &rf); err != nil {
		return nil, err
	}
	built := map[string]Built{}
	for _, b := range rf.Built {
		built[fmt.Sprintf("%s.%s.%d", b.Course, b.Group, b.N)] = b
	}
	out := []AgentRecord{}
	for _, t := range ts {
		id := fmt.Sprintf("%s.%s.%d", t.Course, t.Group, t.N)
		var cj CourseJob
		for _, c := range job.Courses {
			if c.ID == t.Course {
				cj = c
			}
		}
		b, ok := built[id]
		if !ok {
			return nil, fmt.Errorf("transcript %s has no rebuild in run.json", id)
		}
		// The words measure, the generator checks and a page's code excerpts read this text, so the
		// text itself must hash to the digest the transcript declares, which must in turn be the
		// graded controller's (below): a declared digest alone ties nothing to the text.
		if (t.SHA256 != "" && digest([]byte(t.Controller)) != t.SHA256) || (t.SHA256 == "" && t.Controller != "") {
			return nil, fmt.Errorf("%s: the transcript's controller text is not the controller its digest names", id)
		}
		if err := designedSession(cj, t); err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		r := AgentRecord{ID: id, Course: t.Course, Group: t.Group, N: t.N, Recipe: t.Recipe, Scrambled: t.Scrambled, From: t.From,
			Turns: b.Turns, FlyCalls: b.FlyCalls, Flights: b.Flights, Runs: b.Runs, Ended: t.Ended, Controller: t.SHA256,
			ItemsNamed: []string{}, ItemsNamedRaw: []string{}, Calls: Counts{ByTool: map[string]int{}, ByKind: map[string]int{}}}
		text := words(writing(t))
		if t.Recipe != "" {
			r.Quoted = longestRun(words(t.Recipe), text)
		}
		if l, ok := courseItems(cj); ok {
			r.QuotedOriginal = longestRun(words(l.Recipe), text)
			r.ItemsOf = len(l.Items)
			code := stripComments(t.Controller)
			r.ItemsNamed = itemsNamed(l.Items, code, baselineIdentifiers())
			r.ItemsNamedRaw = itemsNamed(l.Items, code, nil)
			r.ItemsNamedCount = len(r.ItemsNamed)
		}
		r.QuotedRecipe = r.Quoted >= quotedMin
		r.RNG = rngPattern.MatchString(stripComments(t.Controller))
		r.GeneratorK = generatorConstant.MatchString(t.Controller)
		for _, turn := range t.Turns {
			r.Reasoning += len(turn.Answer.Reasoning)
			for _, res := range turn.Results {
				r.Calls.ByTool[res.Name]++
				r.Calls.ByKind[res.Kind]++
			}
		}
		if t.After != nil {
			r.AfterAnswer = t.After.Text
		}
		r.BuildProblem = b.Problem
		if t.SHA256 != "" {
			g := findRebuild(ev, t.Course, t.Group, t.N)
			switch {
			case g == nil:
				// Kept, not refused: the agent's spend is sunk, and the attempt is excluded by this
				// reason until -regrade grades its controller.
				r.GradeProblem = "no grading run of it came back with a record"
			case g.SHA256 != t.SHA256:
				return nil, fmt.Errorf("%s: the transcript's controller is not the one the signed grading runs graded", id)
			default:
				r.Graded, r.Valid, r.Records = true, g.Valid, g.Records
				r.Fresh, r.FreshTotal, r.Practice, r.PracticeOf = g.Fresh, g.FreshTotal, g.Practice, g.PracticeTotal
				if !g.Valid && strings.HasPrefix(g.Problem, problemInvalid) {
					r.Invalid = true
				} else if !g.Valid {
					r.GradeProblem = g.Problem
				}
			}
		}
		out = append(out, r)
	}
	regs, err := readRegrades(dir, job, ev.FreshSHA256)
	if err != nil {
		return nil, err
	}
	applyRegrades(out, regs)
	return out, nil
}

// findRebuild is rebuild n of a group's grading in ev, or nil.
func findRebuild(ev *Evidence, course, group string, n int) *Graded1 {
	name := "r" + strconv.Itoa(n)
	for ci := range ev.Courses {
		c := &ev.Courses[ci]
		if c.ID != course {
			continue
		}
		for gi := range c.Groups {
			g := &c.Groups[gi]
			if g.ID != group {
				continue
			}
			for ri := range g.Rebuilds {
				if g.Rebuilds[ri].Name == name {
					return &g.Rebuilds[ri]
				}
			}
		}
	}
	return nil
}
