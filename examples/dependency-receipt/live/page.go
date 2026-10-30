package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"maps"
	"slices"
	"strings"
)

// The page's template. It is not named page.html: the public export checks every .html
// file's relative links where the file sits (scripts/export-public.sh), and maps only
// examples/NAME/page.html to docs/examples/NAME/, while this one renders into
// docs/examples/dependency-receipt/, two levels from here.
//
//go:embed page.html.tmpl
var pageTemplate string

// pageData is what the template reads: the evidence, and the views of it the page draws.
// Every number on the page is a field of the evidence or counted from one here.
type pageData struct {
	Ev                     *evidence
	Quiet, Network, Canary *runFacts
	// The network package's install script and its one call whose outcome the log does not
	// show; the canary package's install script and its refused open.
	NetScript, CanaryScript *group
	Connect, Refused        call
	NetSends                int // datagrams the network script sent to port 53
	NetHidden               int // its sends whose destination the log does not name
	Joined                  int // runs whose receipt names the run's record
	Refusals                int // the receipt command's runs that exited 1
	// Over the three receipts: every attempted call, and how many are a mkdir answering
	// "file exists" or "no such file or directory", or a connect to the name-service socket.
	Attempted, AttemptedMkdir, AttemptedNscd int
	Edit                                     editFacts
	Settings                                 [][2]string
	// The startup smoke test's outbound connections, in order, and whether every one timed
	// out or found no route.
	Egress        [][2]string
	EgressTried   int
	EgressBlocked bool
}

// nscd is the socket glibc's name lookups try first; the image has no such service.
const nscd = "/var/run/nscd/socket"

func newPageData(ev *evidence) (pageData, error) {
	d := pageData{Ev: ev, Edit: ev.Edit}
	for i := range ev.Runs {
		r := &ev.Runs[i]
		switch r.Fixture {
		case "quiet":
			d.Quiet = r
		case "network":
			d.Network = r
		case "canary":
			d.Canary = r
		}
		if r.Record != "" && strings.HasPrefix(r.Instance, "k8s-pod-uid:") {
			d.Joined++
		}
		d.Attempted += r.Seen.Totals.Attempted.Sum()
		for _, g := range r.Seen.Groups {
			for _, c := range g.Calls {
				switch {
				case c.Side != "attempted":
				case c.Kind == "mkdir" && (strings.HasPrefix(c.Result, "errno=17 ") || strings.HasPrefix(c.Result, "errno=2 ")):
					d.AttemptedMkdir++
				case c.Kind == "connect" && c.What == nscd:
					d.AttemptedNscd++
				}
			}
		}
	}
	for _, t := range ev.Transcripts {
		if t.Exit == 1 {
			d.Refusals++
		}
	}
	if d.Quiet == nil || d.Network == nil || d.Canary == nil {
		return d, fmt.Errorf("the evidence holds %d runs, not the quiet, network and canary ones", len(ev.Runs))
	}
	d.NetScript, d.CanaryScript = scriptGroup(d.Network), scriptGroup(d.Canary)
	if d.NetScript == nil || d.CanaryScript == nil {
		return d, fmt.Errorf("no install script group in the network or canary run")
	}
	for _, c := range d.NetScript.Calls {
		switch {
		case c.Side == "undetermined" && c.Kind == "connect":
			d.Connect = c
		case c.Kind == "send" && strings.Contains(c.What, "port 53"):
			d.NetSends++
		case c.Kind == "send" && strings.Contains(c.What, "not in the log"):
			d.NetHidden++
		}
	}
	for _, c := range d.CanaryScript.Calls {
		if c.Side == "attempted" && strings.HasPrefix(c.Kind, "open") && d.Refused.Kind == "" {
			d.Refused = c
		}
	}
	d.EgressTried, d.EgressBlocked = len(ev.Smoke.Egress), len(ev.Smoke.Egress) > 0
	for _, k := range slices.Sorted(maps.Keys(ev.Smoke.Egress)) {
		v := ev.Smoke.Egress[k]
		d.Egress = append(d.Egress, [2]string{k, v})
		if v != "timeout" && v != "ENETUNREACH" {
			d.EgressBlocked = false
		}
	}
	keys := make([]string, 0, len(ev.Daemon))
	for k := range ev.Daemon {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		d.Settings = append(d.Settings, [2]string{k, ev.Daemon[k]})
	}
	return d, nil
}

func scriptGroup(r *runFacts) *group {
	for i := range r.Seen.Groups {
		if r.Seen.Groups[i].Kind == "script" {
			return &r.Seen.Groups[i]
		}
	}
	return nil
}

// label names a group as the page shows it.
func label(r *runFacts, g group) string {
	switch g.Kind {
	case "sandbox":
		return "The pod's start and sandboxd"
	case "check":
		return "plimsoll's check of the pod"
	case "runner":
		return "plimsoll's runner"
	case "script":
		return "The package's " + g.Script + " script"
	case "step":
		if g.Step == 1 {
			return "Step 1: npm install"
		}
		return fmt.Sprintf("Step %d: the import", g.Step)
	}
	return g.Kind
}

// says is one plain sentence on who a group is, from what started it.
func says(r *runFacts, g group) string {
	switch g.Kind {
	case "sandbox":
		return "The pod's first process, which runsc starts from the container spec, so the log shows no program load for it, and what it forked without loading a program. The first process bound ports 9090 and 8080, sandboxd's two ports in the template: it is sandboxd, agent-sandbox's daemon in the pod."
	case "check":
		return "The command plimsoll sends before any of the run's code: it reads the kernel's first log line (gVisor's boot line), the boot ID, the seccomp mode (the kernel's filter on which calls a process may make) and the mount table."
	case "runner":
		return "plimsoll's in-sandbox runner, node /runner.mjs: it writes the run's files, checks that a step cannot open its descriptors, then starts each step in its own shell."
	case "script":
		return "npm runs this when it installs the package: package.json says \"" + g.Script + "\": \"" + r.Scripts[g.Script] + "\". Everything here is the package's own code."
	case "step":
		if g.Step == 1 {
			return "npm itself, installing the package from its directory, offline. Its install script, if it has one, is the next group."
		}
		return "node loading the installed package: this is the package's own code running at import time."
	}
	return ""
}

func shortCmd(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + " …"
}

// render is the page for ev, byte for byte the same for the same evidence.
func render(ev *evidence) ([]byte, error) {
	d, err := newPageData(ev)
	if err != nil {
		return nil, err
	}
	t, err := template.New("page").Funcs(template.FuncMap{
		"label": label,
		"says":  says,
		"short": func(s string, n int) string {
			if len(s) > n {
				return s[:n]
			}
			return s
		},
		"cmd":   shortCmd,
		"kb":    func(n int) string { return fmt.Sprintf("%.0f KB", float64(n)/1000) },
		"mb":    func(n int64) string { return fmt.Sprintf("%.1f MB", float64(n)/1e6) },
		"comma": comma,
		"uid":   func(inst string) string { return strings.TrimPrefix(inst, "k8s-pod-uid:") },
		"exit": func(p *int) string {
			if p == nil {
				return "not in the log"
			}
			return fmt.Sprint(*p)
		},
		"plural": func(n int, one, many string) string {
			if n == 1 {
				return one
			}
			return many
		},
		"sec":  func(ms int64) string { return fmt.Sprintf("%.1f s", float64(ms)/1000) },
		"add":  func(a, b int) int { return a + b },
		"side": func(c counts) int { return c.Sum() },
		"pkg":  func(g group) bool { return g.Package() },
		"lines": func(s string) []string {
			return strings.Split(strings.TrimRight(s, "\n"), "\n")
		},
		"stepRan": func(r *runFacts, n int) bool { return len(r.Steps) >= n },
	}).Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, d); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// comma writes n with thousands separators.
func comma(n any) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var out []string
	for len(s) > 3 {
		out = append([]string{s[len(s)-3:]}, out...)
		s = s[:len(s)-3]
	}
	out = append([]string{s}, out...)
	if neg {
		return "-" + strings.Join(out, ",")
	}
	return strings.Join(out, ",")
}
