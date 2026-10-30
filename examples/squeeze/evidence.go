package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Evidence is everything the page states about plimsoll's run. It is derived from the signed
// bundle, the job, the published fresh set and run.json, and nothing else; -verify derives it
// again and compares it with evidence.json byte for byte.
type Evidence struct {
	Job         string    `json:"job"`
	Harness     string    `json:"harness"` // the signing key's ID
	Lines       int       `json:"lines"`
	Runs        int       `json:"runs"` // single runs: grading, practice and flight-recording runs
	Sessions    int       `json:"sessions"`
	SessionRuns int       `json:"session_calls"`
	Started     time.Time `json:"started"`
	Sealed      time.Time `json:"sealed"`
	Ended       time.Time `json:"ended"`
	FreshSHA256 string    `json:"fresh_sha256"`
	FreshCount  int       `json:"fresh_count"`
	FreshGiven  bool      `json:"fresh_given,omitempty"` // the fresh set was an earlier run's (-fresh)
	CPUBudget   int       `json:"cpu_budget_seconds"`
	Provider    string    `json:"provider"`
	Tier        string    `json:"tier"`
	Environment string    `json:"environment"`
	// The CPU the graded controllers used: the most any flight the budget let finish used, whose
	// it was, how many flights the budget ended, and whose they were.
	MaxFlightCPU float64  `json:"max_flight_cpu"`
	MaxCPUWho    string   `json:"max_cpu_who"`
	CPUEnded     int      `json:"cpu_ended_flights"`
	CPUEndedBy   []CPUEnd `json:"cpu_ended_by"`
	// The most CPU a controller's runtime took to start before its code ran: not counted.
	MaxStartCPU float64 `json:"max_start_cpu"`
	Flights     int     `json:"flights"`
	// Grading run wall time, as the records state it: the median and the longest.
	GradeMedianSeconds float64 `json:"grade_median_seconds"`
	GradeMaxSeconds    float64 `json:"grade_max_seconds"`
	// The median time of a grading run on the fresh set alone: what a fresh test costs here.
	FreshMedianSeconds float64 `json:"fresh_median_seconds"`

	Courses []CourseEvidence `json:"courses"`
	// Sets are the loops' own controllers flown again, each run a -loops-only run in sets/ beside
	// the page, on this page's fresh set and on others: how much a fresh score moves from one set
	// of flights to another, and whether the same set gives the same flights twice.
	Sets     []SetEvidence `json:"sets,omitempty"`
	Scan     Scan          `json:"scan"`
	Model    string        `json:"model,omitempty"`
	Usage    usage         `json:"usage"`
	Built    []Built       `json:"built"`
	Missing  []Missing     `json:"missing"`
	Failures []string      `json:"failures"`
}

// CourseEvidence is one course: its sets, its loops and their verdicts, its groups.
type CourseEvidence struct {
	ID             string          `json:"id"`
	Label          string          `json:"label"`
	Tag            string          `json:"tag"`
	PracticeCount  int             `json:"practice_count"`
	PracticeSHA256 string          `json:"practice_sha256"`
	Loops          []LoopEvidence  `json:"loops"`
	Groups         []GroupEvidence `json:"groups"`
	Tracks         []Track         `json:"tracks"`
}

// LoopEvidence is a loop: its recipe, its own controller's scores, and the squeeze's verdict.
type LoopEvidence struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Recipe       string   `json:"recipe"`
	RecipeTokens int      `json:"recipe_tokens"`
	Tokenizer    string   `json:"tokenizer"`
	Own          *Graded1 `json:"own,omitempty"`
	Verdict      *Verdict `json:"verdict,omitempty"`
}

// GroupEvidence is one group of rebuilds.
type GroupEvidence struct {
	ID             string    `json:"id"`
	Label          string    `json:"label"`
	From           string    `json:"from"`
	Built          int       `json:"built"`    // made here by the model
	Imported       int       `json:"imported"` // made elsewhere, graded here
	Missing        int       `json:"missing"`  // produced no controller
	Rebuilds       []Graded1 `json:"rebuilds"`
	PracticeMedian float64   `json:"practice_median"`
	FreshMedian    float64   `json:"fresh_median"`
	SeedHunters    int       `json:"seed_hunters"`
}

// Graded1 is one controller's grading run.
type Graded1 struct {
	Name          string   `json:"name"` // "r3", or "loop"
	SHA256        string   `json:"sha256"`
	Bytes         int      `json:"bytes"`
	Valid         bool     `json:"valid"`
	Problem       string   `json:"problem,omitempty"`
	Practice      int      `json:"practice"`
	PracticeTotal int      `json:"practice_total"`
	Fresh         int      `json:"fresh"`
	FreshTotal    int      `json:"fresh_total"`
	PracticeBits  string   `json:"practice_bits"` // one character a flight: 1 passed, 0 failed
	FreshBits     string   `json:"fresh_bits"`
	FreshEnds     []Count  `json:"fresh_ends"` // how the fresh flights ended
	MaxCPU        float64  `json:"max_cpu"`    // the most CPU a flight the budget let finish used
	CPUEnded      int      `json:"cpu_ended"`  // flights the CPU budget ended, in either set
	Flown         int      `json:"flown"`      // flights in the sets its runs answered
	SeedHunt      bool     `json:"seed_hunt"`  // the controller holds the simulator's random number generator
	Records       []string `json:"records"`    // the grading runs' record digests: practice, then fresh
	Seconds       float64  `json:"seconds"`    // the two grading runs' time, as their records state it
}

// CPUEnd is one controller whose flights the CPU budget ended: how many, and the latest
// simulated second at which it ended one.
type CPUEnd struct {
	Who     string  `json:"who"`
	Flights int     `json:"flights"`
	Within  float64 `json:"within_seconds"`
}

// Count is how many flights ended one way.
type Count struct {
	End string `json:"end"`
	N   int    `json:"n"`
}

// Track is one recorded flight for the page: positions in centimeters, tracksFPS a second.
type Track struct {
	Who     string   `json:"who"`
	N       string   `json:"n"`
	Set     string   `json:"set"` // practice or fresh
	Seed    uint32   `json:"seed"`
	Success bool     `json:"success"`
	End     string   `json:"end"`
	Seconds float64  `json:"seconds"`
	XYZ     [][3]int `json:"xyz"`
}

// SetEvidence is one fresh set and the runs that flew the loops' own controllers on it.
type SetEvidence struct {
	SHA256  string `json:"sha256"`
	Flights int    `json:"flights"`
	// Page is true for this page's own fresh set, whose first run is the page's own run.
	Page  bool      `json:"page"`
	Runs  []string  `json:"runs"` // "page" for the page's run, else the run's directory under sets/
	Loops []SetLoop `json:"loops"`
}

// SetLoop is one loop's own controller on one set: its fresh score in each of the set's runs, and
// whether every run landed exactly the same flights, on this set and on the practice set.
type SetLoop struct {
	Course string `json:"course"`
	Loop   string `json:"loop"`
	Fresh  []int  `json:"fresh"` // one a run, in Runs' order
	Same   bool   `json:"same"`
}

// Scan is the leak scan over every call into a rebuild's sandbox and every practice run.
type Scan struct {
	SessionCalls int      `json:"session_calls"`
	PracticeRuns int      `json:"practice_runs"`
	GradingRuns  int      `json:"grading_runs"`
	Needles      int      `json:"needles"` // forbidden strings looked for
	Hits         []string `json:"hits"`
	// SetsHeld is true when every grading run held exactly its course's practice set and the
	// published fresh set.
	SetsHeld bool `json:"sets_held"`
}

// The Mulberry32 constant at the heart of the simulator's seed-to-flight generator. A
// controller that holds it carries a copy of the generator: the hackathon's code check for
// the seed hunt, where a controller recognizes a flight by regenerating it from its seed.
var generatorConstant = regexp.MustCompile(`(?i)0x6d2b79f5|1831565813`)

var tracePattern = regexp.MustCompile(`^sq\.([a-z][a-z0-9-]*)\.([a-z][a-z0-9-]*)\.(loop|[0-9]+)\.(build|fly|practice|fresh|tracks)$`)

type call struct {
	line    int
	course  string
	who     string
	n       string
	purpose string
	req     *plimsollv1.RunRequest
	resp    *plimsollv1.RunResponse
	rec     sandbox.RunRecord
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func encodeJSON(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func writeJSON(path string, v any) error {
	b, err := encodeJSON(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// setsDir is the directory beside a page that holds the loops' own controllers flown again:
// one subdirectory a run, each the files a -loops-only run of the page's job writes (runFiles).
const setsDir = "sets"

var runName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// derive reads dir's files and states the evidence: the page's run, and the runs in sets/. It
// fails on a bundle that does not verify, a call it cannot attribute, a fresh set whose digest is
// not the one run.json committed to, or a run in sets/ that is not the page's loops flown again.
func derive(dir string, job *Job) (*Evidence, error) {
	ev, err := deriveRun(dir, job)
	if err != nil {
		return nil, err
	}
	names, err := os.ReadDir(filepath.Join(dir, setsDir))
	if errors.Is(err, os.ErrNotExist) {
		return ev, nil
	}
	if err != nil {
		return nil, err
	}
	loops := job.loopsOnly()
	type run struct {
		name string
		ev   *Evidence
	}
	runs := []run{{name: "page", ev: ev}}
	for _, n := range names {
		sub := filepath.Join(dir, setsDir, n.Name())
		if !n.IsDir() || !runName.MatchString(n.Name()) || n.Name() == "page" {
			return nil, fmt.Errorf("%s: not a run's directory (lowercase letters, digits and hyphens)", sub)
		}
		var rf RunFile
		if err := readJSON(filepath.Join(sub, "run.json"), &rf); err != nil {
			return nil, err
		}
		if rf.Job != loops.Name {
			return nil, fmt.Errorf("%s is a run of %q, not of %q (the page's loops flown again)", sub, rf.Job, loops.Name)
		}
		sev, err := deriveRun(sub, loops)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sub, err)
		}
		if sev.Scan.SessionCalls > 0 || sev.Scan.PracticeRuns > 0 {
			return nil, fmt.Errorf("%s holds rebuild calls; a run in %s/ flies the loops' own controllers alone", sub, setsDir)
		}
		if !sev.Scan.SetsHeld || len(sev.Failures) > 0 {
			return nil, fmt.Errorf("%s: a grading run did not hold exactly its sets, or a call came back without a record", sub)
		}
		runs = append(runs, run{name: n.Name(), ev: sev})
	}
	if len(runs) == 1 {
		return ev, nil
	}
	// The sets, the page's first, then the others by digest; each set's runs in directory order.
	bySet := map[string]*SetEvidence{}
	runsOf := map[string][]*Evidence{}
	for _, r := range runs {
		sh := r.ev.FreshSHA256
		if bySet[sh] == nil {
			bySet[sh] = &SetEvidence{SHA256: sh, Flights: r.ev.FreshCount, Page: sh == ev.FreshSHA256}
		}
		bySet[sh].Runs = append(bySet[sh].Runs, r.name)
		runsOf[sh] = append(runsOf[sh], r.ev)
	}
	shas := make([]string, 0, len(bySet))
	for sh := range bySet {
		shas = append(shas, sh)
	}
	slices.SortFunc(shas, func(a, b string) int {
		if bySet[a].Page != bySet[b].Page {
			if bySet[a].Page {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	})
	for _, sh := range shas {
		se := bySet[sh]
		for _, cj := range job.Courses {
			for _, lj := range cj.Loops {
				sl := SetLoop{Course: cj.ID, Loop: lj.ID, Same: true}
				var first *Graded1
				for _, rev := range runsOf[sh] {
					own := findOwn(rev, cj.ID, lj.ID)
					if own == nil || !own.Valid {
						sl.Fresh = nil
						break
					}
					if pageOwn := findOwn(ev, cj.ID, lj.ID); pageOwn != nil && pageOwn.SHA256 != own.SHA256 {
						return nil, fmt.Errorf("sets/: a run flew %s's %s loop with a controller that is not the page's", cj.ID, lj.ID)
					}
					if first == nil {
						first = own
					} else if own.FreshBits != first.FreshBits || own.PracticeBits != first.PracticeBits {
						sl.Same = false
					}
					sl.Fresh = append(sl.Fresh, own.Fresh)
				}
				if sl.Fresh != nil {
					se.Loops = append(se.Loops, sl)
				}
			}
		}
		ev.Sets = append(ev.Sets, *se)
	}
	return ev, nil
}

// findOwn is a loop's own controller's grading in ev, or nil.
func findOwn(ev *Evidence, course, loop string) *Graded1 {
	for _, c := range ev.Courses {
		if c.ID != course {
			continue
		}
		for _, l := range c.Loops {
			if l.ID == loop {
				return l.Own
			}
		}
	}
	return nil
}

// deriveRun states the evidence of one run's files in dir.
func deriveRun(dir string, job *Job) (*Evidence, error) {
	var rf RunFile
	if err := readJSON(filepath.Join(dir, "run.json"), &rf); err != nil {
		return nil, err
	}
	freshFile, err := os.ReadFile(filepath.Join(dir, "fresh.json"))
	if err != nil {
		return nil, err
	}
	if digest(freshFile) != rf.FreshSHA256 {
		return nil, errors.New("fresh.json is not the set run.json committed to")
	}
	var fresh SealedSet
	if err := json.Unmarshal(freshFile, &fresh); err != nil {
		return nil, err
	}
	pubPEM, err := os.ReadFile(filepath.Join(dir, "harness.pub"))
	if err != nil {
		return nil, err
	}
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		return nil, err
	}
	entries, err := readBundle(dir)
	if err != nil {
		return nil, err
	}
	v := attest.NewVerifier(pub)
	rep, err := attest.VerifyBundle(entries, v)
	if err != nil {
		return nil, fmt.Errorf("bundle.jsonl does not verify under harness.pub: %w", err)
	}
	ev := &Evidence{Job: job.Name, Harness: attest.KeyID(pub), Lines: len(entries), Runs: rep.Runs, Sessions: len(rep.Sessions),
		Started: rf.Started, Sealed: rf.Sealed, Ended: rf.Ended, FreshSHA256: rf.FreshSHA256, FreshCount: len(fresh.Seeds), FreshGiven: rf.FreshGiven,
		CPUBudget: cpuBudgetSeconds, Model: rf.Model, Usage: rf.Usage, Built: rf.Built, Missing: rf.Missing, Failures: rf.Failures}
	for _, s := range rep.Sessions {
		ev.SessionRuns += s.Calls
	}

	var calls []call
	for n, e := range entries {
		if e.Request == nil {
			continue // a session's close, or a checkpoint
		}
		rec, err := v.Verify(e.Envelope)
		if err != nil {
			return nil, err
		}
		c := call{line: n + 1, rec: rec, req: &plimsollv1.RunRequest{}, resp: &plimsollv1.RunResponse{}}
		if err := proto.Unmarshal(e.Request, c.req); err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		if err := proto.Unmarshal(e.Response, c.resp); err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		m := tracePattern.FindStringSubmatch(c.req.GetTraceId())
		if m == nil {
			return nil, fmt.Errorf("line %d: trace id %q names no controller of this job", n+1, c.req.GetTraceId())
		}
		c.course, c.who, c.n, c.purpose = m[1], m[2], m[3], m[4]
		if (c.purpose == "build") != (rec.Session != "") {
			return nil, fmt.Errorf("line %d: a %s call %s a session", n+1, c.purpose, map[bool]string{true: "inside", false: "outside"}[rec.Session != ""])
		}
		calls = append(calls, c)
	}

	courses := map[string]*CourseJob{}
	for i := range job.Courses {
		courses[job.Courses[i].ID] = &job.Courses[i]
	}
	practiceFiles := map[string][]byte{}
	for id, c := range courses {
		practiceFiles[id] = practiceSet(*c).encode()
	}

	// Pass 1: the grading runs, one per controller and set, which also hold each loop's own
	// controller for the scan.
	type setRun struct {
		fs      FlightSet
		problem string
		rec     sandbox.RunRecord
		src     []byte
		line    int
	}
	runs := map[string]map[string]setRun{} // course/who/n -> set -> run
	var keys []string
	loopSrc := map[string][]byte{}
	ev.Scan.SetsHeld = true
	var seconds, freshSeconds []float64
	providers, tiers, envs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, c := range calls {
		if c.purpose != "practice" && c.purpose != "fresh" {
			continue
		}
		cj, ok := courses[c.course]
		if !ok {
			return nil, fmt.Errorf("line %d: course %q is not in the job", c.line, c.course)
		}
		files := projectFiles(c.req)
		src, ok := files["controller.js"]
		if !ok {
			return nil, fmt.Errorf("line %d: a grading run with no controller", c.line)
		}
		want := freshFile
		if c.purpose == "practice" {
			want = practiceFiles[c.course]
		}
		other := map[string]string{"practice": "fresh.json", "fresh": "practice.json"}[c.purpose]
		if _, both := files[other]; both || !bytes.Equal(files[c.purpose+".json"], want) {
			ev.Scan.SetsHeld = false
		}
		if c.n == "loop" {
			if _, ok := cj.loop(c.who); !ok {
				return nil, fmt.Errorf("line %d: loop %q is not in the job", c.line, c.who)
			}
			loopSrc[c.course+"/"+c.who] = src
		}
		key := c.course + "/" + c.who + "/" + c.n
		if runs[key] == nil {
			runs[key] = map[string]setRun{}
			keys = append(keys, key)
		}
		if _, dup := runs[key][c.purpose]; dup {
			return nil, fmt.Errorf("line %d: %s graded twice on its %s set", c.line, key, c.purpose)
		}
		fs, problem := readSet(c.resp.GetProject())
		runs[key][c.purpose] = setRun{fs: fs, problem: problem, rec: c.rec, src: src, line: c.line}
		seconds = append(seconds, c.rec.Ended.Sub(c.rec.Started).Seconds())
		if c.purpose == "fresh" {
			freshSeconds = append(freshSeconds, c.rec.Ended.Sub(c.rec.Started).Seconds())
		}
		providers[c.rec.Provider], tiers[sandbox.ParseIsolationClass(c.rec.Isolation).String()], envs[c.rec.Environment] = true, true, true
		ev.Scan.GradingRuns++
	}
	graded := map[string]Graded1{} // course/who/n
	for _, key := range keys {
		parts := strings.SplitN(key, "/", 3)
		p, havePractice := runs[key]["practice"]
		f, haveFresh := runs[key]["fresh"]
		src := p.src
		if !havePractice {
			src = f.src
		}
		if havePractice && haveFresh && !bytes.Equal(p.src, f.src) {
			return nil, fmt.Errorf("lines %d and %d: %s's two grading runs hold different controllers", p.line, f.line, key)
		}
		one := Graded1{Name: "loop", SHA256: digest(src), Bytes: len(src), SeedHunt: generatorConstant.Match(src)}
		if parts[2] != "loop" {
			one.Name = "r" + parts[2]
		}
		switch {
		case !havePractice || !haveFresh:
			one.Problem = "a grading run came back without a record"
		case p.problem != "":
			one.Problem = "practice: " + p.problem
		case f.problem != "" && p.fs.Valid:
			one.Problem = fmt.Sprintf("fresh: %s (practice: %d of %d)", f.problem, p.fs.Passed, p.fs.Total)
		case f.problem != "":
			one.Problem = "fresh: " + f.problem
		case !p.fs.Valid:
			one.Problem = "invalid controller: " + clip(p.fs.Error, 120)
		default:
			one.Valid = true
		}
		for _, r := range []setRun{p, f} {
			if r.rec.SHA256 != "" {
				one.Records = append(one.Records, r.rec.SHA256)
				one.Seconds += round1(r.rec.Ended.Sub(r.rec.Started).Seconds())
			}
		}
		// Every flight a set's run answered counts, whether or not the controller's other set was
		// graded: a flight the CPU budget ended is a fact about the controller either way.
		within := 0.0
		for _, r := range []setRun{p, f} {
			if r.problem != "" || !r.fs.Valid {
				continue
			}
			for _, fl := range r.fs.Results {
				ev.Flights++
				one.Flown++
				ev.MaxStartCPU = max(ev.MaxStartCPU, fl.StartCPUSeconds)
				if strings.HasPrefix(fl.Reason, "controller used more than") {
					one.CPUEnded++
					within = max(within, fl.SimulatedSeconds)
					continue
				}
				one.MaxCPU = max(one.MaxCPU, fl.CPUSeconds)
				if fl.CPUSeconds > ev.MaxFlightCPU {
					ev.MaxFlightCPU, ev.MaxCPUWho = fl.CPUSeconds, parts[0]+" "+parts[1]+" "+one.Name
				}
			}
		}
		if one.CPUEnded > 0 {
			ev.CPUEnded += one.CPUEnded
			ev.CPUEndedBy = append(ev.CPUEndedBy, CPUEnd{Who: parts[0] + " " + parts[1] + " " + one.Name, Flights: one.CPUEnded, Within: round1(within)})
		}
		if one.Valid {
			one.Practice, one.PracticeTotal, one.PracticeBits = p.fs.Passed, p.fs.Total, bits(p.fs.Results)
			one.Fresh, one.FreshTotal, one.FreshBits = f.fs.Passed, f.fs.Total, bits(f.fs.Results)
			one.FreshEnds = ends(f.fs.Results)
		}
		graded[key] = one
	}
	if ev.CPUEndedBy == nil {
		ev.CPUEndedBy = []CPUEnd{}
	}
	ev.Provider, ev.Tier, ev.Environment = only(providers), only(tiers), only(envs)
	if len(seconds) > 0 {
		slices.Sort(seconds)
		ev.GradeMedianSeconds = round1(seconds[len(seconds)/2])
		ev.GradeMaxSeconds = round1(seconds[len(seconds)-1])
	}
	if len(freshSeconds) > 0 {
		slices.Sort(freshSeconds)
		ev.FreshMedianSeconds = round1(freshSeconds[len(freshSeconds)/2])
	}

	// Pass 2: the leak scan over every call into a rebuild's sandbox and every practice run.
	needles := forbidden(job, fresh, loopSrc)
	ev.Scan.Needles = len(needles)
	ev.Scan.Hits = []string{}
	for _, c := range calls {
		if c.purpose != "build" && c.purpose != "fly" {
			continue
		}
		if c.purpose == "build" {
			ev.Scan.SessionCalls++
		} else {
			ev.Scan.PracticeRuns++
		}
		for _, text := range requestTexts(c.req) {
			for _, nd := range needles {
				if nd.sandboxOnly && c.purpose == "fly" {
					continue
				}
				if nd.find(text) {
					ev.Scan.Hits = append(ev.Scan.Hits, fmt.Sprintf("line %d (%s.%s.%s.%s): %s", c.line, c.course, c.who, c.n, c.purpose, nd.name))
				}
			}
		}
	}

	// Pass 3: the recorded flights.
	tracks := map[string][]Track{}
	for _, c := range calls {
		if c.purpose != "tracks" {
			continue
		}
		cj := courses[c.course]
		for _, a := range c.resp.GetProject().GetArtifacts() {
			var t struct {
				Seed   uint32 `json:"seed"`
				Result Flight `json:"result"`
				Frames []struct {
					Pos struct{ X, Y, Z float64 } `json:"pos"`
				} `json:"frames"`
			}
			if err := json.Unmarshal(a.GetContent(), &t); err != nil {
				return nil, fmt.Errorf("line %d: track %s: %w", c.line, a.GetPath(), err)
			}
			tr := Track{Who: c.who, N: c.n, Set: "fresh", Seed: t.Seed, Success: t.Result.Success, End: endOf(t.Result.Reason), Seconds: t.Result.SimulatedSeconds}
			if slices.Contains(cj.Practice, t.Seed) {
				tr.Set = "practice"
			}
			for _, fr := range t.Frames {
				tr.XYZ = append(tr.XYZ, [3]int{cm(fr.Pos.X), cm(fr.Pos.Y), cm(fr.Pos.Z)})
			}
			tracks[c.course] = append(tracks[c.course], tr)
		}
	}

	// The courses, loops, groups and verdicts, in the job's order.
	for _, cj := range job.Courses {
		ce := CourseEvidence{ID: cj.ID, Label: cj.Label, Tag: cj.Tag, PracticeCount: len(cj.Practice), PracticeSHA256: digest(practiceFiles[cj.ID]), Tracks: tracks[cj.ID]}
		slices.SortFunc(ce.Tracks, func(a, b Track) int {
			if k := compareUnits("", a.Who, a.N, "", b.Who, b.N); k != 0 {
				return k
			}
			return strings.Compare(b.Set, a.Set) // practice before fresh
		})
		groupOf := map[string]*GroupEvidence{}
		for _, gj := range cj.Groups {
			ge := GroupEvidence{ID: gj.ID, Label: gj.Label, From: gj.From, Imported: len(gj.Import), Built: gj.Build}
			for _, m := range rf.Missing {
				if m.Course == cj.ID && m.Group == gj.ID {
					ge.Missing++
				}
			}
			var practice, freshScores []int
			for key, g := range graded {
				if strings.HasPrefix(key, cj.ID+"/"+gj.ID+"/") && g.Name != "loop" {
					ge.Rebuilds = append(ge.Rebuilds, g)
				}
			}
			slices.SortFunc(ge.Rebuilds, func(a, b Graded1) int { return compareUnits("", "", a.Name[1:], "", "", b.Name[1:]) })
			for _, g := range ge.Rebuilds {
				if g.Valid {
					practice = append(practice, g.Practice)
					freshScores = append(freshScores, g.Fresh)
				}
				if g.SeedHunt {
					ge.SeedHunters++
				}
			}
			ge.PracticeMedian, ge.FreshMedian = median(practice), median(freshScores)
			ce.Groups = append(ce.Groups, ge)
			groupOf[gj.ID] = &ce.Groups[len(ce.Groups)-1]
		}
		var none []int
		haveNone := false
		for _, gj := range cj.Groups {
			if gj.From == "" {
				haveNone = true
				for _, g := range groupOf[gj.ID].Rebuilds {
					if g.Valid {
						none = append(none, g.Practice)
					}
				}
			}
		}
		for _, lj := range cj.Loops {
			le := LoopEvidence{ID: lj.ID, Label: lj.Label, Recipe: lj.Recipe, RecipeTokens: lj.RecipeTokens, Tokenizer: lj.Tokenizer}
			if g, ok := graded[cj.ID+"/"+lj.ID+"/loop"]; ok {
				le.Own = &g
				for _, gj := range cj.Groups {
					if gj.From != lj.ID || !g.Valid {
						continue
					}
					ge := groupOf[gj.ID]
					var practice, freshScores []int
					for _, r := range ge.Rebuilds {
						if r.Valid {
							practice = append(practice, r.Practice)
							freshScores = append(freshScores, r.Fresh)
						}
					}
					vd := verdict(lj.ID, g.Practice, g.PracticeTotal, g.Fresh, g.FreshTotal, practice, freshScores, len(ge.Rebuilds)+ge.Missing, none, haveNone)
					le.Verdict = &vd
				}
			}
			ce.Loops = append(ce.Loops, le)
		}
		ev.Courses = append(ev.Courses, ce)
	}
	return ev, nil
}

func projectFiles(req *plimsollv1.RunRequest) map[string][]byte {
	out := map[string][]byte{}
	for _, f := range req.GetProject().GetFiles() {
		out[f.GetPath()] = []byte(f.GetContent())
	}
	return out
}

// requestTexts is every string a request carries into a sandbox: code, files, steps.
func requestTexts(req *plimsollv1.RunRequest) []string {
	var out []string
	if js := req.GetJavascript(); js != nil {
		out = append(out, js.GetCode())
	}
	if p := req.GetProject(); p != nil {
		for _, f := range p.GetFiles() {
			out = append(out, f.GetPath(), f.GetContent())
		}
		out = append(out, p.GetSteps()...)
	}
	if c := req.GetCell(); c != nil {
		out = append(out, c.GetCode())
		for _, f := range c.GetFiles() {
			out = append(out, f.GetPath(), f.GetContent())
		}
	}
	return out
}

// needle is one forbidden string. A seed matches only as a whole number, not inside a longer
// one; a file matches whole, or by its SHA-256 written out.
type needle struct {
	name  string
	text  string
	digit bool
	// sandboxOnly needles are forbidden in a rebuild's own sandbox only: a practice run holds
	// the simulator by design (the controller in it cannot read it), a rebuild's sandbox never.
	sandboxOnly bool
}

func (n needle) find(s string) bool {
	for i := 0; ; {
		k := strings.Index(s[i:], n.text)
		if k < 0 {
			return false
		}
		at := i + k
		end := at + len(n.text)
		if !n.digit || ((at == 0 || !isDigit(s[at-1])) && (end == len(s) || !isDigit(s[end]))) {
			return true
		}
		i = at + 1
	}
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// forbidden is what no rebuild's sandbox and no practice run may hold: every sealed seed, each
// loop's own controller (whole, or its digest), and the simulator's source files.
func forbidden(job *Job, fresh SealedSet, loopSrc map[string][]byte) []needle {
	var out []needle
	for _, c := range job.Courses {
		for _, s := range c.Practice {
			out = append(out, needle{name: "a practice seed of the " + c.ID + " course", text: strconv.FormatUint(uint64(s), 10), digit: true})
		}
	}
	for _, s := range fresh.Seeds {
		out = append(out, needle{name: "a fresh seed", text: strconv.FormatUint(uint64(s), 10), digit: true})
	}
	keys := make([]string, 0, len(loopSrc))
	for k := range loopSrc {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		src := loopSrc[k]
		out = append(out, needle{name: "the loop's controller " + k, text: string(src)}, needle{name: "the SHA-256 of the loop's controller " + k, text: digest(src)})
	}
	for _, name := range []string{"sim.mjs", "task-easy.mjs", "task-hard.mjs"} {
		out = append(out, needle{name: "the simulator file " + name, text: courseFile(name), sandboxOnly: true})
	}
	return out
}

func bits(fs []Flight) string {
	var b strings.Builder
	for _, f := range fs {
		if f.Success {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	return b.String()
}

// endOf puts a flight's end into a fixed set of words, so no text a controller wrote reaches
// the page.
func endOf(reason string) string {
	switch {
	case reason == "landed":
		return "landed"
	case reason == "time limit":
		return "ran out of time"
	case reason == "floor crash", reason == "wall or ceiling crash", reason == "flipped", reason == "gate frame collision":
		return reason
	case strings.HasPrefix(reason, "malformed action"):
		return "malformed action"
	case strings.HasPrefix(reason, "controller used more than"):
		return "CPU budget"
	case strings.Contains(reason, "wall time (a hang)"):
		return "hang"
	case strings.HasPrefix(reason, "controller error"), strings.HasPrefix(reason, "controller exited"), strings.HasPrefix(reason, "controller did not"), strings.HasPrefix(reason, "controller startup"):
		return "controller error"
	}
	return "other"
}

func ends(fs []Flight) []Count {
	m := map[string]int{}
	for _, f := range fs {
		if !f.Success {
			m[endOf(f.Reason)]++
		}
	}
	var out []Count
	for k, n := range m {
		out = append(out, Count{End: k, N: n})
	}
	slices.SortFunc(out, func(a, b Count) int {
		if a.N != b.N {
			return b.N - a.N
		}
		return strings.Compare(a.End, b.End)
	})
	return out
}

func cm(x float64) int {
	if x < 0 {
		return -int(-x*100 + 0.5)
	}
	return int(x*100 + 0.5)
}

// only is the one key of m, or the keys joined when there are several.
func only(m map[string]bool) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return strings.Join(ks, ", ")
}

// bundleName is the published bundle: gzip-compressed, since every grading run repeats the
// course's files and they compress about tenfold. `gunzip -k` gives the plain bundle.jsonl
// plimsoll-attest reads.
const bundleName = "bundle.jsonl.gz"

// readBundle reads dir's bundle, compressed or (as a run writes it) plain.
func readBundle(dir string) ([]attest.Entry, error) {
	if f, err := os.Open(filepath.Join(dir, bundleName)); err == nil {
		defer f.Close()
		z, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", bundleName, err)
		}
		return attest.ReadBundle(z)
	}
	f, err := os.Open(filepath.Join(dir, "bundle.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return attest.ReadBundle(f)
}

// compressBundle replaces dir's bundle.jsonl with bundle.jsonl.gz. The gzip header carries no
// name and no time, so the same bundle always compresses to the same bytes.
func compressBundle(dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, "bundle.jsonl"))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	z, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := z.Write(raw); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, bundleName), buf.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Remove(filepath.Join(dir, "bundle.jsonl"))
}
