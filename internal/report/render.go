package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"
)

//go:embed report.html.tmpl
var reportTemplate string

// Render writes a self-contained HTML report for the given records to w. The output
// embeds all CSS and JS inline and loads nothing over the network, so it renders
// offline from a file:// URL.
func Render(w io.Writer, records []Record, opts Options) error {
	data := aggregate(records, opts)
	tmpl, err := template.New("report").Funcs(templateFuncs).Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("parse report template: %w", err)
	}
	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	return nil
}

// profileAgg is one grant profile's rolled-up cost across the report's runs.
type profileAgg struct {
	Profile        string
	Runs           int
	HostCalls      int
	Findings       int
	AgentFixable   int
	APIChange      int
	ExtraCalls     int
	AddedLatencyMs int64
	BytesMoved     int
}

// patternAgg is one detector pattern's rolled-up cost across the report's runs.
type patternAgg struct {
	Pattern        string
	Remedy         string
	Severity       string // the most severe instance seen
	Count          int
	AgentFixable   int
	ExtraCalls     int
	AddedLatencyMs int64
	BytesMoved     int
}

// runView is one run as the template renders it: the record plus a stable id used to
// toggle its findings panel.
type runView struct {
	ID int
	Record
	When string
}

// reportData is the fully-aggregated model handed to the template.
type reportData struct {
	Title               string
	Source              string
	Generated           string
	TotalRuns           int
	RunsWithAdvice      int
	TotalHostCalls      int
	TotalFindings       int
	TotalAgentFixable   int
	TotalAPIChange      int
	TotalExtraCalls     int
	TotalAddedLatencyMs int64
	TotalBytesMoved     int
	Profiles            []profileAgg
	Patterns            []patternAgg
	Runs                []runView
}

func aggregate(records []Record, opts Options) reportData {
	gen := opts.Generated
	if gen.IsZero() {
		gen = time.Now()
	}
	title := opts.Title
	if title == "" {
		title = "plimsoll — Prospector report"
	}
	d := reportData{
		Title:     title,
		Source:    opts.Source,
		Generated: gen.UTC().Format("2006-01-02 15:04:05 UTC"),
		TotalRuns: len(records),
	}

	profiles := map[string]*profileAgg{}
	patterns := map[string]*patternAgg{}
	for i, r := range records {
		if r.Advice != "" {
			d.RunsWithAdvice++
		}
		d.TotalHostCalls += r.HostCalls
		d.TotalFindings += r.FindingCount
		d.TotalAgentFixable += r.AgentFixable
		d.TotalExtraCalls += r.ExtraCalls
		d.TotalAddedLatencyMs += r.AddedLatencyMs
		d.TotalBytesMoved += r.BytesMoved

		pa := profiles[r.Profile]
		if pa == nil {
			pa = &profileAgg{Profile: r.Profile}
			profiles[r.Profile] = pa
		}
		pa.Runs++
		pa.HostCalls += r.HostCalls
		pa.Findings += r.FindingCount
		pa.AgentFixable += r.AgentFixable
		pa.ExtraCalls += r.ExtraCalls
		pa.AddedLatencyMs += r.AddedLatencyMs
		pa.BytesMoved += r.BytesMoved

		for _, f := range r.Findings {
			if !f.AgentFixable {
				pa.APIChange++
				d.TotalAPIChange++
			}
			key := f.Pattern
			pat := patterns[key]
			if pat == nil {
				pat = &patternAgg{Pattern: f.Pattern, Remedy: f.Remedy, Severity: f.Severity}
				patterns[key] = pat
			}
			pat.Count++
			if severityRank(f.Severity) > severityRank(pat.Severity) {
				pat.Severity = f.Severity
			}
			if f.AgentFixable {
				pat.AgentFixable++
			}
			pat.ExtraCalls += f.ExtraCalls
			pat.AddedLatencyMs += f.AddedLatencyMs
			pat.BytesMoved += f.BytesMoved
		}

		when := ""
		if !r.Time.IsZero() {
			when = r.Time.UTC().Format("2006-01-02 15:04:05")
		}
		d.Runs = append(d.Runs, runView{ID: i, Record: r, When: when})
	}

	d.Profiles = make([]profileAgg, 0, len(profiles))
	for _, p := range profiles {
		d.Profiles = append(d.Profiles, *p)
	}
	// Largest modelled latency first; ties broken by profile name for determinism.
	sort.Slice(d.Profiles, func(i, j int) bool {
		if d.Profiles[i].AddedLatencyMs != d.Profiles[j].AddedLatencyMs {
			return d.Profiles[i].AddedLatencyMs > d.Profiles[j].AddedLatencyMs
		}
		if d.Profiles[i].Findings != d.Profiles[j].Findings {
			return d.Profiles[i].Findings > d.Profiles[j].Findings
		}
		return d.Profiles[i].Profile < d.Profiles[j].Profile
	})

	d.Patterns = make([]patternAgg, 0, len(patterns))
	for _, p := range patterns {
		d.Patterns = append(d.Patterns, *p)
	}
	sort.Slice(d.Patterns, func(i, j int) bool {
		if d.Patterns[i].Count != d.Patterns[j].Count {
			return d.Patterns[i].Count > d.Patterns[j].Count
		}
		return d.Patterns[i].Pattern < d.Patterns[j].Pattern
	})
	return d
}

// severityRank orders the detector severities so patternAgg can keep the worst.
func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

var templateFuncs = template.FuncMap{
	"bytes":         humanBytes,
	"ms":            humanMillis,
	"sevKey":        severityKey,
	"cost":          findingCost,
	"prettyPattern": prettyPattern,
}

// severityKey is the css-safe token for a severity (defaults to info).
func severityKey(s string) string {
	switch s {
	case "high", "medium", "low":
		return s
	default:
		return "info"
	}
}

// prettyPattern turns a pattern id (fan_out) into a display label (Fan-out). The
// aggregate_in_code and sequential_calls detectors were deleted on 2026-09-16; their
// labels stay so an operator's retained audit stream from before that date still
// renders as it did, rather than relabelling or dropping history.
func prettyPattern(p string) string {
	switch p {
	case "fan_out":
		return "Fan-out (N+1)"
	case "aggregate_in_code":
		return "Aggregate in code"
	case "repeated_read":
		return "Repeated read"
	case "sequential_calls":
		return "Sequential calls"
	default:
		return p
	}
}

// findingCost renders a finding's numbers as one compact clause, or "" when it
// carries no positive number. The labels say what each number is: the call count
// is measured, the latency is a model (summed round trips beyond one call), and the
// bytes are the gross total the pattern moved, not a saving.
func findingCost(f Finding) string {
	var parts []string
	if f.ExtraCalls > 0 {
		parts = append(parts, fmt.Sprintf("%d calls beyond one", f.ExtraCalls))
	}
	if f.AddedLatencyMs > 0 {
		parts = append(parts, "about "+humanMillis(f.AddedLatencyMs)+" beyond one call (modelled)")
	}
	if f.BytesMoved > 0 {
		parts = append(parts, humanBytes(f.BytesMoved)+" moved in total")
	}
	return strings.Join(parts, " · ")
}

// humanBytes renders a byte count in the largest unit that stays readable.
func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// humanMillis renders a millisecond duration in a readable unit.
func humanMillis(ms int64) string {
	switch {
	case ms >= 1000:
		return fmt.Sprintf("%.2f s", float64(ms)/1000)
	default:
		return fmt.Sprintf("%d ms", ms)
	}
}
