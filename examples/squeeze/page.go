package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"regexp"
	"strconv"
	"strings"
)

//go:embed page.html
var pageTemplate string

// hackathonJSON is the hackathon's recorded numbers (did-it-learn's runs/d1 and runs/h1), as the
// page shows them, labeled as the hackathon's: they were not made or signed by plimsoll.
//
//go:embed hackathon.json
var hackathonJSON []byte

// Hackathon is hackathon.json.
type Hackathon struct {
	Source    string  `json:"source"`
	Recorded  string  `json:"recorded"`
	Tolerance float64 `json:"tolerance"`
	Secret    string  `json:"heldout_secret_sha256"`
	// SeedListTokens is the hackathon's count of the cheater's 16 practice seeds written out.
	SeedListTokens int        `json:"seed_list_tokens"`
	SeedListNote   string     `json:"seed_list_note"`
	Courses        []HKCourse `json:"courses"`
}

// HKCourse is one hackathon course.
type HKCourse struct {
	ID     string    `json:"id"`
	Tag    string    `json:"tag"`
	Label  string    `json:"label"`
	Loops  []HKLoop  `json:"loops"`
	Groups []HKGroup `json:"groups"`
}

// HKLoop is one hackathon loop.
type HKLoop struct {
	ID           string    `json:"id"`
	BestRound    int       `json:"best_round"`
	Practice     int       `json:"practice"`
	Fresh        int       `json:"fresh"`
	Rounds       []HKRound `json:"rounds"`
	SeedHunt     bool      `json:"seed_hunt"`
	RecordTokens int       `json:"record_tokens"`
	Recipe       string    `json:"recipe"`
	RecipeTokens int       `json:"recipe_tokens"`
	Drafts       []HKDraft `json:"drafts"`
	Judge        HKJudge   `json:"judge"`
}

// HKRound is one round of a hackathon loop.
type HKRound struct {
	Round    int     `json:"round"`
	Practice int     `json:"practice"`
	Fresh    int     `json:"fresh"`
	Critic   float64 `json:"critic"`
}

// HKDraft is one draft of a recipe, with its count.
type HKDraft struct {
	Recipe string `json:"recipe"`
	Tokens int    `json:"tokens"`
}

// HKJudge is the hackathon judge's verdict for a loop.
type HKJudge struct {
	Inflation   float64           `json:"predicted_inflation_trials"`
	RecipeValue float64           `json:"recipe_value_trials"`
	HeldoutGap  float64           `json:"heldout_gap_trials"`
	Verdict     string            `json:"verdict"`
	Memorized   bool              `json:"artifact_memorized"`
	Sensitivity map[string]string `json:"sensitivity"`
}

// HKGroup is one hackathon group of rebuilds.
type HKGroup struct {
	ID             string      `json:"id"`
	From           string      `json:"from"`
	Rebuilds       []HKRebuild `json:"rebuilds"`
	Produced       int         `json:"produced"`
	Of             int         `json:"of"`
	PracticeMedian float64     `json:"practice_median"`
	FreshMedian    float64     `json:"fresh_median"`
}

// HKRebuild is one hackathon rebuild.
type HKRebuild struct {
	Name     string `json:"name"`
	Valid    bool   `json:"valid"`
	Practice int    `json:"practice"`
	Fresh    int    `json:"fresh"`
	SeedHunt bool   `json:"seed_hunt"`
}

// argonScanTxt is the transcript argon-scan.sh prints: the did-it-learn entry's leaked practice
// seed looked for with plimsoll-withheld, offline, in the files its harness shipped before and
// after the fix. The page quotes it whole and states its finds from it.
//
//go:embed argon-scan.txt
var argonScanTxt string

// ArgonScan is argon-scan.txt as the page reads it.
type ArgonScan struct {
	Lines         []ArgonLine
	Before, After string // the two commits scanned
	Shipped       int    // files rebuilt for the commit before the fix
	Finds         []ArgonFind
	CleanFiles    int    // files the scan of the fix read and found clean
	Seed          string // the withheld value the first find's label names
}

// ArgonLine is one line of the transcript, with a class when it is the scan's own verdict.
type ArgonLine struct{ Text, Class string }

// ArgonFind is one line of plimsoll-withheld's scan output: a label, its mode and the file.
type ArgonFind struct{ Label, Mode, File string }

var (
	argonCommit = regexp.MustCompile(`^# did-it-learn ([0-9a-f]{40}) \((12:44|12:55),`)
	argonFiles  = regexp.MustCompile(`^#   (\d+) files: `)
	argonFind   = regexp.MustCompile(`^(\S+) \((refuse|audit)\): (\S+)$`)
	argonClean  = regexp.MustCompile(`^clean: (\d+) files against set [0-9a-f]{64}$`)
)

// parseArgonScan reads the transcript, and refuses one that does not hold both commits, the
// before scan's finds and the after scan's clean line: the page states all of them.
func parseArgonScan(txt string) (*ArgonScan, error) {
	a := &ArgonScan{}
	lines := strings.Split(strings.TrimRight(txt, "\n"), "\n")
	for i, line := range lines {
		l := ArgonLine{Text: line}
		if m := argonCommit.FindStringSubmatch(line); m != nil {
			if m[2] == "12:44" {
				a.Before = m[1]
				if i+1 < len(lines) {
					if f := argonFiles.FindStringSubmatch(lines[i+1]); f != nil {
						a.Shipped, _ = strconv.Atoi(f[1])
					}
				}
			} else {
				a.After = m[1]
			}
		}
		if m := argonFind.FindStringSubmatch(line); m != nil {
			a.Finds = append(a.Finds, ArgonFind{Label: m[1], Mode: m[2], File: strings.TrimPrefix(m[3], "tmp/argon-scan/before/workspace/")})
			l.Class = "hit"
		}
		if m := argonClean.FindStringSubmatch(line); m != nil {
			a.CleanFiles, _ = strconv.Atoi(m[1])
			l.Class = "ok"
		}
		if strings.HasPrefix(line, "$ sed -n ") && i+1 < len(lines) {
			a.Seed = lines[i+1]
		}
		a.Lines = append(a.Lines, l)
	}
	if a.Before == "" || a.After == "" || a.Shipped == 0 || len(a.Finds) == 0 || a.CleanFiles == 0 || a.Seed == "" {
		return nil, fmt.Errorf("argon-scan.txt: missing a commit, the file count, a find, the clean line or the seed: %+v", a)
	}
	return a, nil
}

// canaryDemoTxt is the transcript canary-demo.sh prints: plimsoll-eval-integrity's canary run on
// a stand-in harness, passing, then failing on each leak put back and on a harness that planted
// nothing. The page quotes it whole and states its results from it.
//
//go:embed canary-demo.txt
var canaryDemoTxt string

// CanaryDemo is canary-demo.txt as the page reads it.
type CanaryDemo struct {
	Lines []ArgonLine
	// Checks are the canary checks in transcript order.
	Checks []CanaryCheck
}

// CanaryCheck is one canary check in the transcript: the folders it read, its exit code, and
// the lines it printed before its verdict (hits, or places nothing was planted in).
type CanaryCheck struct {
	Planted, Requests string
	Exit              int
	Found             []string
}

var (
	canaryCheckCmd = regexp.MustCompile(`^\$ plimsoll-eval-integrity canary check --sealed canary\.json --planted (\S+) --requests (\S+)$`)
	canaryExit     = regexp.MustCompile(`^\(exit (\d+)\)$`)
)

// parseCanaryDemo reads the transcript, and refuses one without a passing check followed by
// failing ones that each say why: the page states what each failure caught.
func parseCanaryDemo(txt string) (*CanaryDemo, error) {
	c := &CanaryDemo{}
	var cur *CanaryCheck
	for _, line := range strings.Split(strings.TrimRight(txt, "\n"), "\n") {
		l := ArgonLine{Text: line}
		m := canaryCheckCmd.FindStringSubmatch(line)
		switch {
		case m != nil:
			c.Checks = append(c.Checks, CanaryCheck{Planted: m[1], Requests: m[2], Exit: -1})
			cur = &c.Checks[len(c.Checks)-1]
		case cur != nil && canaryExit.MatchString(line):
			cur.Exit, _ = strconv.Atoi(canaryExit.FindStringSubmatch(line)[1])
			cur = nil
		case cur != nil && strings.HasPrefix(line, "canary: OK"):
			l.Class = "ok"
		case cur != nil && strings.HasPrefix(line, "canary: FAILED"):
			l.Class = "hit"
		case cur != nil:
			cur.Found = append(cur.Found, line)
			l.Class = "hit"
		}
		c.Lines = append(c.Lines, l)
	}
	if len(c.Checks) < 2 || c.Checks[0].Exit != 0 || len(c.Checks[0].Found) != 0 {
		return nil, fmt.Errorf("canary-demo.txt: the first check must pass and at least one must follow it: %+v", c.Checks)
	}
	for _, k := range c.Checks[1:] {
		if k.Exit != 1 || len(k.Found) == 0 {
			return nil, fmt.Errorf("canary-demo.txt: every check after the first must fail and say why: %+v", k)
		}
	}
	return c, nil
}

func loadHackathon() (*Hackathon, error) {
	dec := json.NewDecoder(bytes.NewReader(hackathonJSON))
	dec.DisallowUnknownFields()
	var h Hackathon
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("hackathon.json: %w", err)
	}
	return &h, nil
}

func (h *Hackathon) course(id string) *HKCourse {
	for i := range h.Courses {
		if h.Courses[i].ID == id {
			return &h.Courses[i]
		}
	}
	return nil
}

// pageData is what the template sees: the evidence, the hackathon's numbers, the two transcripts, and
// the evidence and the numbers as one JSON value for the page's drawings.
type pageData struct {
	Ev     *Evidence
	HK     *Hackathon
	Argon  *ArgonScan
	Canary *CanaryDemo
	Data   template.JS
}

func renderPage(ev *Evidence) ([]byte, error) {
	hk, err := loadHackathon()
	if err != nil {
		return nil, err
	}
	argon, err := parseArgonScan(argonScanTxt)
	if err != nil {
		return nil, err
	}
	canary, err := parseCanaryDemo(canaryDemoTxt)
	if err != nil {
		return nil, err
	}
	// encoding/json escapes <, > and & inside strings, so the value cannot close the script
	// element it sits in.
	data, err := json.Marshal(map[string]any{"ev": ev, "hk": hk})
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("page").Funcs(template.FuncMap{
		"short": func(s string) string {
			if len(s) > 16 {
				return s[:16] + "…"
			}
			return s
		},
		"date":     func(ev *Evidence) string { return ev.Ended.Format("2006-01-02") },
		"pct":      func(a, b int) string { return fmt.Sprintf("%.0f%%", 100*float64(a)/float64(max(b, 1))) },
		"words":    func(s string) int { return len(strings.Fields(s)) },
		"comma":    comma,
		"andlist":  andList,
		"numword":  numberWord,
		"loopname": loopName,
	}).Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, pageData{Ev: ev, HK: hk, Argon: argon, Canary: canary, Data: template.JS(data)}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// The template's lookups: a course's loop or group, in the hackathon's numbers or plimsoll's.

func (p pageData) HKLoop(course, id string) *HKLoop {
	if c := p.HK.course(course); c != nil {
		for i := range c.Loops {
			if c.Loops[i].ID == id {
				return &c.Loops[i]
			}
		}
	}
	return nil
}

func (p pageData) HKGroup(course, id string) *HKGroup {
	if c := p.HK.course(course); c != nil {
		for i := range c.Groups {
			if c.Groups[i].ID == id {
				return &c.Groups[i]
			}
		}
	}
	return nil
}

func (p pageData) EvCourse(course string) *CourseEvidence {
	for i := range p.Ev.Courses {
		if p.Ev.Courses[i].ID == course {
			return &p.Ev.Courses[i]
		}
	}
	return nil
}

func (p pageData) EvLoop(course, id string) *LoopEvidence {
	if c := p.EvCourse(course); c != nil {
		for i := range c.Loops {
			if c.Loops[i].ID == id {
				return &c.Loops[i]
			}
		}
	}
	return nil
}

func (p pageData) EvGroup(course, id string) *GroupEvidence {
	if c := p.EvCourse(course); c != nil {
		for i := range c.Groups {
			if c.Groups[i].ID == id {
				return &c.Groups[i]
			}
		}
	}
	return nil
}

// SeedHunters is how many of the group's rebuilds hold the simulator's generator.
func (g *HKGroup) SeedHunters() int {
	n := 0
	for _, r := range g.Rebuilds {
		if r.SeedHunt {
			n++
		}
	}
	return n
}

// Produced is how many of the group's rebuilds left a valid controller.
func (g *GroupEvidence) Produced() int {
	n := 0
	for _, r := range g.Rebuilds {
		if r.Valid {
			n++
		}
	}
	return n
}

// Spread is one loop's own controller across every fresh set in the evidence's sets: its score on
// each (the set's first run; the page's own run for the page's set), the lowest and highest, the
// fewest runs any set had, and whether every set's runs landed exactly the same flights.
type Spread struct {
	Counts        []int
	Total         int
	Low, High     int
	FewestRuns    int
	Same          bool
	Course, Label string
}

// Spread is nil when the evidence has fewer than two sets with a score for the loop.
func (p pageData) Spread(course, loop string) *Spread {
	sp := &Spread{Same: true, Course: course}
	if c := p.EvCourse(course); c != nil {
		sp.Label = c.Label
	}
	for _, set := range p.Ev.Sets {
		for _, l := range set.Loops {
			if l.Course != course || l.Loop != loop {
				continue
			}
			n := l.Fresh[0]
			if len(sp.Counts) == 0 || n < sp.Low {
				sp.Low = n
			}
			if len(sp.Counts) == 0 || n > sp.High {
				sp.High = n
			}
			if len(sp.Counts) == 0 || len(l.Fresh) < sp.FewestRuns {
				sp.FewestRuns = len(l.Fresh)
			}
			sp.Counts = append(sp.Counts, n)
			sp.Total = set.Flights
			sp.Same = sp.Same && l.Same
		}
	}
	if len(sp.Counts) < 2 {
		return nil
	}
	return sp
}

// andList writes 56, 48 and 62.
func andList(xs []int) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = strconv.Itoa(x)
	}
	if len(s) < 2 {
		return strings.Join(s, "")
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// numberWord writes a small count as the page's prose does: three, not 3.
func numberWord(n int) string {
	words := []string{"no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"}
	if n >= 0 && n < len(words) {
		return words[n]
	}
	return strconv.Itoa(n)
}

// comma writes n with thousands separators, as the page's prose does.
func comma(n int) string {
	if n < 0 {
		return "-" + comma(-n)
	}
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// NControllers is how many controllers plimsoll graded.
func (p pageData) NControllers() int {
	n := p.NRebuilds()
	for _, c := range p.Ev.Courses {
		for _, l := range c.Loops {
			if l.Own != nil {
				n++
			}
		}
	}
	return n
}

// NRebuilds is how many of them are rebuilds.
func (p pageData) NRebuilds() int {
	n := 0
	for _, c := range p.Ev.Courses {
		for _, g := range c.Groups {
			n += len(g.Rebuilds)
		}
	}
	return n
}

// Agreement compares each controller's practice score on plimsoll with the hackathon's.
type Agreement struct {
	Same, Total int
	Diffs       []Diff
	Hunters     int // how many of the controllers that moved hold the seed shortcut
}

// Diff is one controller whose practice score moved.
type Diff struct {
	Who, Tag string
	HK, PL   int
	Hunt     bool
}

func (p pageData) Agreement() *Agreement {
	a := &Agreement{}
	for _, c := range p.Ev.Courses {
		hc := p.HK.course(c.ID)
		if hc == nil {
			continue
		}
		add := func(who, tag string, hk int, g Graded1) {
			if !g.Valid {
				return
			}
			a.Total++
			if g.Practice == hk {
				a.Same++
				return
			}
			a.Diffs = append(a.Diffs, Diff{Who: who, Tag: tag, HK: hk, PL: g.Practice, Hunt: g.SeedHunt})
			if g.SeedHunt {
				a.Hunters++
			}
		}
		for _, l := range c.Loops {
			if hl := p.HKLoop(c.ID, l.ID); hl != nil && l.Own != nil {
				add(c.Label+", "+loopName(l.ID)+"'s own controller", hc.Tag+" "+l.ID+" loop", hl.Practice, *l.Own)
			}
		}
		for _, g := range c.Groups {
			hg := p.HKGroup(c.ID, g.ID)
			if hg == nil {
				continue
			}
			for _, r := range g.Rebuilds {
				for _, hr := range hg.Rebuilds {
					if hr.Name == r.Name && hr.Valid {
						add(c.Label+", rebuild "+r.Name+" "+groupName(g.ID), hc.Tag+" "+g.ID+" "+r.Name, hr.Practice, r)
					}
				}
			}
		}
	}
	return a
}

func loopName(id string) string {
	if id == "cheater" {
		return "the cheating loop"
	}
	return "the honest loop"
}

func groupName(id string) string {
	switch id {
	case "cheater":
		return "from the cheater's recipe"
	case "honest":
		return "from the honest recipe"
	}
	return "from no recipe"
}

// Trouble is a controller the CPU budget stopped on some flights, or one plimsoll graded but
// could not score, beside the hackathon's numbers for it.
type Trouble struct {
	Who, Tag string
	Problem  string  // why it has no score, in plain words; "" when it has one
	CPUEnded int     // flights the CPU budget ended
	Flown    int     // flights it was graded on
	Within   float64 // the latest simulated second at which the budget ended one
	Hunt     bool    // it holds the simulator's generator
	HK       *HKRebuild
}

// Trouble lists them in the evidence's order: courses, then groups, then rebuilds.
func (p pageData) Trouble() []Trouble {
	var out []Trouble
	for _, c := range p.Ev.Courses {
		tag := c.ID
		if hc := p.HK.course(c.ID); hc != nil {
			tag = hc.Tag
		}
		add := func(who, short string, g Graded1, hk *HKRebuild) {
			if g.Valid && g.CPUEnded == 0 {
				return
			}
			t := Trouble{Who: who, Tag: tag + " " + short, CPUEnded: g.CPUEnded, Flown: g.Flown, Hunt: g.SeedHunt, HK: hk}
			if !g.Valid {
				t.Problem = plainProblem(g.Problem)
			}
			for _, e := range p.Ev.CPUEndedBy {
				if e.Who == c.ID+" "+short {
					t.Within = e.Within
				}
			}
			out = append(out, t)
		}
		for _, l := range c.Loops {
			if l.Own != nil {
				add(c.Label+", "+loopName(l.ID)+"'s own controller", l.ID+" loop", *l.Own, nil)
			}
		}
		for _, g := range c.Groups {
			hg := p.HKGroup(c.ID, g.ID)
			for _, r := range g.Rebuilds {
				var hk *HKRebuild
				if hg != nil {
					for i := range hg.Rebuilds {
						if hg.Rebuilds[i].Name == r.Name {
							hk = &hg.Rebuilds[i]
						}
					}
				}
				add(c.Label+", rebuild "+r.Name+" "+groupName(g.ID), g.ID+" "+r.Name, r, hk)
			}
		}
	}
	return out
}

// plainProblem says why a controller has no score in the page's words.
func plainProblem(problem string) string {
	switch {
	case strings.HasPrefix(problem, "fresh: the run's time ran out"):
		return fmt.Sprintf("its fresh run did not finish inside the provider's %d-second limit, so it has no fresh score", int(gradeTimeout.Seconds()))
	case strings.HasPrefix(problem, "practice: the run's time ran out"):
		return fmt.Sprintf("its practice run did not finish inside the provider's %d-second limit, so it has no practice score", int(gradeTimeout.Seconds()))
	case strings.HasPrefix(problem, "invalid controller"):
		return "the course refused it as a controller"
	case problem == "a grading run came back without a record":
		return "one of its grading runs came back without a record, so it has no score"
	}
	return "it has no score (" + problem + ")"
}
