// Command report renders docs/measurements/session-latency/*.json, written by the
// session-latency command, as one self-contained HTML page:
//
//	go run ./measurements/session-latency/report > docs/measurements/session-latency/index.html
package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type sample struct {
	Name   string    `json:"name"`
	Detail string    `json:"detail"`
	Ms     []float64 `json:"ms"`
}

type run struct {
	Provider  string   `json:"provider"`
	Runtime   string   `json:"runtime"`
	Tier      string   `json:"tier"`
	Image     string   `json:"image"`
	Machine   string   `json:"machine"`
	When      string   `json:"when"`
	Reps      int      `json:"reps"`
	GapMs     int      `json:"gapMs"`
	Samples   []sample `json:"samples"`
	Languages []string `json:"languages"`
	File      string   `json:"-"` // the data file's name, for the page's link to it
}

// Taken is when the run was measured, to the minute.
func (r run) Taken() string {
	t, err := time.Parse(time.RFC3339Nano, r.When)
	if err != nil {
		return r.When
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// median of the named sample, 0 when the run has none.
func (r run) median(name string) float64 {
	for _, s := range r.Samples {
		if s.Name == name {
			return quantile(s.Ms, 0.5)
		}
	}
	return 0
}

// Reload is how many times faster a call is when the array stays in the
// interpreter than when every call builds it.
func (r run) Reload() string {
	fresh, kept := r.median("reload: fresh run per call"), r.median("reload: kept in the interpreter")
	if fresh == 0 || kept == 0 {
		return "not measured"
	}
	return fmt.Sprintf("%.1fx faster (%.0f ms against %.0f ms)", fresh/kept, kept, fresh)
}

func (r run) Label() string {
	switch {
	case r.Provider == "docker" && r.Runtime == "runsc":
		return "docker, gVisor"
	case r.Provider == "docker":
		return "docker, runc"
	}
	return r.Provider
}

func quantile(ms []float64, q float64) float64 {
	s := slices.Clone(ms)
	slices.Sort(s)
	return s[int(q*float64(len(s)-1)+0.5)]
}

type row struct {
	Name, Detail string
	Cells        []cell
}

type cell struct {
	Median, P10, P90 float64
	Present          bool
}

type bar struct {
	Y, W                float64
	Label, Value, Color string
}

type group struct {
	Name string
	Y    float64
	Bars []bar
}

var colors = []string{"#2f6db5", "#c2702b", "#3f8f5a", "#8a4fa8"}

func main() {
	if err := render(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func render(w io.Writer) error {
	paths, err := filepath.Glob("docs/measurements/session-latency/*.json")
	if err != nil {
		return err
	}
	var runs []run
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var r run
		if err := json.Unmarshal(b, &r); err != nil {
			return err
		}
		r.File = filepath.Base(p)
		runs = append(runs, r)
	}
	order := map[string]int{"docker, runc": 0, "docker, gVisor": 1, "openshell": 2}
	slices.SortFunc(runs, func(a, b run) int { return order[a.Label()] - order[b.Label()] })
	var names []string
	details := map[string]string{}
	for _, r := range runs {
		for _, s := range r.Samples {
			if !slices.Contains(names, s.Name) {
				names = append(names, s.Name)
				details[s.Name] = s.Detail
			}
		}
	}
	var rows []row
	maxMs := 0.0
	for _, n := range names {
		rw := row{Name: n, Detail: details[n]}
		for _, r := range runs {
			c := cell{}
			for _, s := range r.Samples {
				if s.Name == n {
					c = cell{Median: quantile(s.Ms, 0.5), P10: quantile(s.Ms, 0.1), P90: quantile(s.Ms, 0.9), Present: true}
					maxMs = max(maxMs, c.Median)
				}
			}
			rw.Cells = append(rw.Cells, c)
		}
		rows = append(rows, rw)
	}
	// One group of bars per operation, one bar per provider, on a shared linear scale.
	const width, left, barH = 560.0, 230.0, 14.0
	var groups []group
	y := 10.0
	for _, rw := range rows {
		g := group{Name: rw.Name, Y: y + barH}
		for i, c := range rw.Cells {
			if !c.Present {
				continue
			}
			g.Bars = append(g.Bars, bar{Y: y, W: max(1, c.Median/maxMs*width), Label: runs[i].Label(),
				Value: fmt.Sprintf("%.0f ms", c.Median), Color: colors[i%len(colors)]})
			y += barH + 2
		}
		groups = append(groups, g)
		y += 14
	}
	page := template.Must(template.New("page").Funcs(template.FuncMap{
		"ms":    func(v float64) string { return fmt.Sprintf("%.0f", v) },
		"color": func(i int) string { return colors[i%len(colors)] },
		"join":  strings.Join,
	}).Parse(pageHTML))
	if err := page.Execute(w, map[string]any{
		"Runs": runs, "Rows": rows, "Groups": groups, "Height": y + 10, "Left": left, "Width": width + left + 90,
	}); err != nil {
		return err
	}
	return nil
}

const pageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Session latency: what an agent's code tool pays per call</title>
<style>
:root{color-scheme:light;--ink:#1d2330;--muted:#5b6475;--rule:#d9dde5;--bg:#ffffff;--tile:#f4f6f9}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:28px 22px 60px}
h1{font-size:24px;margin:0 0 6px} h2{font-size:18px;margin:30px 0 8px}
p.sub{color:var(--muted);margin:0 0 18px}
table{border-collapse:collapse;width:100%;font-size:14px} th,td{border-bottom:1px solid var(--rule);padding:6px 8px;text-align:right;vertical-align:top}
th:first-child,td:first-child{text-align:left} td small{color:var(--muted)}
.legend span{display:inline-block;margin-right:16px} .legend i{display:inline-block;width:12px;height:12px;margin-right:6px;vertical-align:-1px}
svg{max-width:100%;height:auto} .note{background:var(--tile);border-radius:8px;padding:12px 14px;margin:14px 0}
code{background:var(--tile);padding:1px 4px;border-radius:4px} .scroll{overflow-x:auto}
pre{overflow-x:auto;background:var(--tile);padding:10px 12px;border-radius:6px} pre code{padding:0}
</style></head><body><main>
<nav style="display:flex;flex-wrap:wrap;gap:6px 20px;align-items:baseline;padding:0 0 12px;margin:0 0 20px;border-bottom:1px solid #d1d9e0;font-size:15px"><a href="https://plimsollmark.github.io/plimsoll/" style="font-weight:700;color:#0f4a85;text-decoration:none">plimsoll home</a><a href="https://plimsollmark.github.io/plimsoll/measurements/warm-pool/index.html">Warm pool</a><a href="https://plimsollmark.github.io/plimsoll/trainers/">Lessons</a><a href="https://github.com/plimsollmark/plimsoll">Source on GitHub ↗</a></nav>
<h1>Session latency: what an agent's code tool pays per call</h1>
<p class="sub">Measured {{range $i, $r := .Runs}}{{if $i}}; {{end}}{{$r.Label}} ({{$r.Tier}} tier, {{$r.Reps}} repetitions, {{$r.Taken}}){{end}}.
Machine: {{(index .Runs 0).Machine}}. Image for plimsoll: {{(index .Runs 0).Image}}. plimsoll's providers were called directly, not through
the daemon, whose overhead plus the client's was about 3 to 4 ms a round trip in the TypeScript client's tests. Each timed call
followed an untimed pause of 250 ms, because an agent's calls are seconds apart (its model thinks between them) and a docker
session finishes its cleanup after answering.</p>

<p><strong>No network is in these numbers:</strong> the providers ran beside the program timing them. A daemon hosted
away from its caller adds that network round trip to every call. The terms session, cell and relay are defined in
<a href="https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md">the sessions guide (EXTERNAL · source repo ↗)</a>;
the time a warm pool takes off a session's first call is on <a href="../warm-pool/index.html">the warm-pool page
(INTERNAL · measurement →)</a>.</p>

<h2>What keeping state buys</h2>
<p>A call that uses an array of 10 million values (80 MB) an earlier call loaded, against a call that has to build it again:</p>
<ul>{{range .Runs}}<li><strong>{{.Label}}</strong>: {{.Reload}}</li>{{end}}</ul>
<p>The more an agent's data costs to load, the larger the difference; building this array takes about 0.1 s of plain
compute, and parsing a real file of that size takes longer.</p>

<h2>Every operation</h2>
<div class="legend">{{range $i, $r := .Runs}}<span><i style="background:{{color $i}}"></i>{{$r.Label}}</span>{{end}}</div>
<svg viewBox="0 0 {{.Width}} {{.Height}}" role="img" aria-label="Median milliseconds per operation and provider">
{{range .Groups}}<text x="0" y="{{.Y}}" font-size="12" fill="#1d2330">{{.Name}}</text>
{{range .Bars}}<rect x="{{$.Left}}" y="{{.Y}}" width="{{.W}}" height="14" fill="{{.Color}}"><title>{{.Label}}: {{.Value}}</title></rect>
<text x="{{$.Left}}" dx="{{.W}}" dy="11" y="{{.Y}}" font-size="11" fill="#5b6475"> {{.Value}}</text>
{{end}}{{end}}</svg>

<h2>Medians, with the 10th and 90th percentiles</h2>
<div class="scroll"><table><thead><tr><th>Operation</th>{{range .Runs}}<th>{{.Label}}</th>{{end}}</tr></thead><tbody>
{{range .Rows}}<tr><td>{{.Name}}<br><small>{{.Detail}}</small></td>{{range .Cells}}<td>{{if .Present}}{{ms .Median}} ms<br><small>{{ms .P10}} to {{ms .P90}}</small>{{else}}<small>not run</small>{{end}}</td>{{end}}</tr>
{{end}}</tbody></table></div>

<div class="note"><strong>Where a docker session call's time goes.</strong> One <code>docker inspect</code> that reads the
container's settings back, then, for a snippet, one <code>docker exec</code> that starts a <code>node</code> process. A cell starts
no process: it goes as one line to a relay the session keeps attached beside the interpreter (since 2026-10-01). The sweep that
proves no process of the call is left, a second <code>docker exec</code>, runs after the answer has gone back; a call that arrives
while it runs waits for it. OpenShell does the same since 2026-10-01: a relay on an exec stream held open, and the sweep after
answering.</div>

<div class="note"><strong>How to read it.</strong> A "fresh" row creates a sandbox for the call and deletes it afterwards. A
"session" row is a call in a sandbox kept open; the sweep that kills the call's leftover processes runs after the answer on
both providers. A "cell" runs in an interpreter the session keeps alive, so variables survive between calls; the "first" cell includes
starting that interpreter. The two "reload" rows are the case keeping state is for: an array of 10 million values built
on every call, against the same array kept in the interpreter and only averaged.</div>

<h2>The data and how to rerun it</h2>
<p>Raw samples beside this page: {{range $i, $r := .Runs}}{{if $i}}, {{end}}<a href="{{$r.File}}">{{$r.File}}</a>{{end}}. The
programs are in <a href="https://github.com/plimsollmark/plimsoll/tree/main/measurements/session-latency">measurements/session-latency
(EXTERNAL · source repo ↗)</a>. From a checkout, with the images <code>make docker-images</code> builds (gVisor installed for
the runsc run, and an OpenShell gateway with the <code>SANDBOX_OPENSHELL_*</code> settings in the environment for the
openshell run):</p>
<pre><code>go run ./measurements/session-latency -provider docker
go run ./measurements/session-latency -provider docker -runtime runsc
go run ./measurements/session-latency -provider openshell
go run ./measurements/session-latency/report &gt; docs/measurements/session-latency/index.html</code></pre>
<p>Your numbers will differ from these: they are one machine's. What should carry over is the order of the rows and the
ratios between them.</p>
</main></body></html>
`
