package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"math"
	"strings"
)

//go:embed page.html
var pageTemplate string

// pageData is what the template reads: the evidence, and views of it the page draws.
type pageData struct {
	Ev       *evidence
	Gold     *attempt // plimsoll-bash on plimsoll, runc, the solving policy
	Wrong    *attempt
	GVisor   *attempt
	Shipped  *attempt // verifiers' shipped bash harness on plimsoll
	Docker   *attempt // the baseline: the shipped harness on verifiers' docker runtime
	Records  int      // every record in every published log
	Sessions int
	Rows     []configRow
	Chain    []chainCell
	Phases   []phaseKey
	Bars     []barGroup
	// What this attempt's calls add under runc against the docker runtime, in seconds, and
	// provisioning and teardown on plimsoll runc against the docker runtime, in words.
	ExtraAttempt, StartSays, TeardownSays string
}

type configRow struct {
	What, Harness, Runtime, Tier, Reward, Records, Note string
	Good                                                bool
}

type chainCell struct {
	N      int
	Seq    uint64
	Op     string
	Phase  string
	Color  string
	Short  string
	Millis int64
}

type phaseKey struct{ Name, Color, Says string }

var phaseColors = map[string]string{"boot": "#6a6fc0", "setup": "#e8a317", "agent": "#0f766e", "finalize": "#a8a8a2", "scoring": "#c2410c", "after": "#a8a8a2", "unknown": "#a8a8a2"}

var phaseSays = map[string]string{
	"boot":     "boot: the runtime starts",
	"setup":    "setup: the task writes its files",
	"agent":    "agent: the script's tool calls",
	"finalize": "finalize",
	"scoring":  "scoring: the grader reads the answer",
}

type barGroup struct {
	Op, Label string
	Bars      []bar
}

// bar is one median, its width a percentage of the largest median on the chart.
type bar struct {
	Who   string
	Ms    float64
	Min   float64
	Max   float64
	N     int
	W     float64
	Color string
}

func (d *pageData) find(name string) *attempt {
	for i := range d.Ev.Attempts {
		if d.Ev.Attempts[i].Name == name {
			return &d.Ev.Attempts[i]
		}
	}
	return nil
}

func newPageData(ev *evidence) pageData {
	d := pageData{Ev: ev}
	d.Gold, d.Wrong, d.GVisor = d.find("uuid-gold-runc"), d.find("uuid-wrong-runc"), d.find("uuid-gold-runsc")
	d.Shipped, d.Docker = d.find("uuid-shipped-runc"), d.find("uuid-gold-docker")
	for _, l := range ev.Logs {
		d.Records += l.Go.Records
		d.Sessions += l.Go.Sessions
	}
	logs := map[string]publishedLog{}
	for _, l := range ev.Logs {
		logs[l.File] = l
	}
	for _, v := range ev.Validate {
		l := logs[v.Log]
		d.Rows = append(d.Rows, configRow{
			What: "plimsoll-sum through vf-validate: the gold answer, then the untouched task", Harness: "none", Runtime: "plimsoll, " + nameRuntime(v.DockerRuntime),
			Tier: tiers(l.Go), Reward: fmt.Sprintf("gold %s, untouched %s", passFail(v.Gold), reward(v.Untouched.Reward)),
			Records: fmt.Sprintf("%d in %d sessions", l.Go.Records, l.Go.Sessions), Note: "the untouched task graded in a fresh sandbox", Good: v.Valid,
		})
	}
	for _, a := range ev.Attempts {
		harness := a.Harness
		if harness == "bash" {
			harness = "bash, as verifiers ships it"
		}
		r := configRow{What: "uuid_ctf, " + policyName(a.Policy), Harness: harness, Reward: reward(a.Reward), Good: a.Reward != nil}
		if a.Runtime == "plimsoll" {
			l := logs[a.Log]
			r.Runtime, r.Tier = "plimsoll, "+nameRuntime(a.DockerRuntime), tiers(l.Go)
			r.Records = fmt.Sprintf("%d in %d %s", l.Go.Records, l.Go.Sessions, plural(l.Go.Sessions, "session", "sessions"))
		} else {
			r.Runtime, r.Tier, r.Records = "verifiers' docker runtime", "not stated", "none (this runtime keeps no records)"
		}
		switch {
		case a.Error != "":
			r.What, r.Reward, r.Note, r.Good = "uuid_ctf, verifiers' shipped harness", "no attempt", "stopped in its own setup: "+a.Error, false
		case a.Policy == "wrong":
			r.Note = "the grader can say no"
		case a.Runtime != "plimsoll":
			r.Note = "the baseline"
		}
		d.Rows = append(d.Rows, r)
	}
	if d.Gold != nil {
		for i, c := range d.Gold.Chain {
			d.Chain = append(d.Chain, chainCell{N: i + 1, Seq: c.Sequence, Op: c.Op, Phase: c.Phase, Color: phaseColors[c.Phase], Short: c.SHA256[:8], Millis: c.Millis})
		}
		seen := map[string]bool{}
		for _, c := range d.Gold.Chain {
			if !seen[c.Phase] {
				seen[c.Phase] = true
				says := phaseSays[c.Phase]
				if says == "" {
					says = c.Phase
				}
				d.Phases = append(d.Phases, phaseKey{Name: c.Phase, Color: phaseColors[c.Phase], Says: says})
			}
		}
	}
	if len(ev.Calls.Rows) == 3 {
		who := []struct{ key, label, color string }{
			{"docker", "verifiers' docker runtime", "#8a8a85"},
			{"plimsoll-runc", "plimsoll, runc", "#0f766e"},
			{"plimsoll-runsc", "plimsoll, gVisor", "#6a6fc0"},
		}
		ops := []struct{ key, label string }{
			{"start", "start (provision)"}, {"run_true", "run a command (true)"}, {"write_1k", "write 1 KiB"}, {"read_1k", "read 1 KiB"}, {"teardown", "teardown"},
		}
		top := 0.0
		for _, w := range who {
			for _, op := range ops {
				top = math.Max(top, ev.Calls.Rows[w.key][op.key].Median)
			}
		}
		for _, op := range ops {
			g := barGroup{Op: op.key, Label: op.label}
			for _, w := range who {
				s := ev.Calls.Rows[w.key][op.key]
				g.Bars = append(g.Bars, bar{Who: w.label, Ms: s.Median, Min: s.Min, Max: s.Max, N: s.N, W: math.Round(math.Max(0.5, s.Median/top*70)*10) / 10, Color: w.color})
			}
			d.Bars = append(d.Bars, g)
		}
		runc, docker := ev.Calls.Rows["plimsoll-runc"], ev.Calls.Rows["docker"]
		if d.Gold != nil {
			d.ExtraAttempt = fmt.Sprintf("%.1f", (runc["run_true"].Median-docker["run_true"].Median)*float64(len(d.Gold.Chain))/1000)
		}
		d.StartSays = compare(runc["start"].Median, docker["start"].Median)
		d.TeardownSays = compare(runc["teardown"].Median, docker["teardown"].Median)
	}
	return d
}

func (d pageData) AllRechecked() bool {
	for _, l := range d.Ev.Logs {
		if l.Go.Records == 0 || len(l.Go.Incomplete) != 0 || l.Go.Closed != l.Go.Sessions {
			return false
		}
	}
	return len(d.Ev.Logs) > 0
}

// compare says how plimsoll's median sits against the docker runtime's.
func compare(plimsoll, docker float64) string {
	how := "longer"
	if plimsoll < docker {
		how = "less time"
	}
	return fmt.Sprintf("%s on plimsoll (%.0f ms under runc, against %.0f ms)", how, plimsoll, docker)
}

func nameRuntime(rt string) string {
	if rt == "runsc" {
		return "gVisor (runsc)"
	}
	return "runc"
}

func policyName(p string) string {
	switch p {
	case "gold":
		return "the solving script"
	case "wrong":
		return "a wrong answer"
	}
	return p
}

func tiers(c logCheck) string {
	var names []string
	for _, t := range []string{"process", "container", "kernel", "vm", "unknown", ""} {
		if n, ok := c.Tiers[t]; ok {
			names = append(names, fmt.Sprintf("%s (%d)", orWord(t, "none stated"), n))
		}
	}
	return strings.Join(names, ", ")
}

func orWord(s, w string) string {
	if s == "" {
		return w
	}
	return s
}

func passFail(r checkRow) string {
	if r.Valid {
		return "passes"
	}
	return "fails (" + r.Reason + ")"
}

func reward(r *float64) string {
	if r == nil {
		return "none"
	}
	return fmt.Sprintf("%.1f", *r)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// render is the page for ev, byte for byte the same for the same evidence.
func render(ev *evidence) ([]byte, error) {
	t, err := template.New("page").Funcs(template.FuncMap{
		"reward": reward,
		"ms":     func(f float64) string { return fmt.Sprintf("%.0f", f) },
		"sec":    func(f float64) string { return fmt.Sprintf("%.1f", f) },
		"short": func(s string) string {
			if len(s) > 12 {
				return s[:12]
			}
			return s
		},
		"plural":    plural,
		"tiers":     tiers,
		"add":       func(a, b int) int { return a + b },
		"phase":     func(a *attempt, p string) string { return fmt.Sprintf("%.2f", a.Seconds[p]) },
		"runtime":   nameRuntime,
		"multiline": func(s string) bool { return strings.Contains(s, "\n") },
		"minor": func(v string) string {
			if p := strings.SplitN(v, ".", 3); len(p) >= 2 {
				return p[0] + "." + p[1]
			}
			return v
		},
		"shortID": func(s string) string {
			s = strings.TrimPrefix(s, "sha256:")
			if len(s) > 12 {
				return s[:12]
			}
			return s
		},
	}).Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, newPageData(ev)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
