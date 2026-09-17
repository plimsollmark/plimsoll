// Command prospector-report renders plimsoll's exported audit stream into a
// single self-contained HTML report (Prospector Phase 4) — the no-Grafana companion
// to the dashboard. It reads newline-delimited JSON "code run" audit lines from a
// file or stdin and writes a static, dependency-free page.
//
// With -grants pointing at the same grants file the daemon runs, the report also
// embeds a paste-ready API-design prompt (Prospector Phase 3) under each API-change
// finding, using the profile's declared routes. Everything the report shows is
// metadata only: route templates, verbs, counts, and timings, never a path, body, or
// credential.
//
// Usage:
//
//	prospector-report [flags] [audit.jsonl]
//	plimsolld ... | prospector-report -o report.html
//
// Flags:
//
//	-o       output HTML file (default: stdout)
//	-grants  grants JSON file; enables API-design prompts for API-change findings
//	-title   report title
//	-source  provenance note shown in the header (default: the input file name)
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/insights"
	"github.com/plimsollmark/plimsoll/internal/report"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "prospector-report:", err)
		os.Exit(1)
	}
}

func run() error {
	out := flag.String("o", "", "output HTML file (default: stdout)")
	grantsPath := flag.String("grants", "", "grants JSON file; enables API-design prompts for API-change findings")
	title := flag.String("title", "", "report title")
	source := flag.String("source", "", "provenance note shown in the header (default: the input file name)")
	flag.Parse()

	// Input: a positional file argument, else stdin.
	var (
		in     io.Reader = os.Stdin
		inName           = "stdin"
	)
	if arg := flag.Arg(0); arg != "" {
		f, err := os.Open(arg)
		if err != nil {
			return fmt.Errorf("open audit stream: %w", err)
		}
		defer f.Close()
		in = f
		inName = arg
	}

	records, err := report.Parse(in)
	if err != nil {
		return err
	}

	// Optional: attach a Phase 3 API-design prompt to each API-change finding, grounded
	// in the profile's declared routes. Agent-fixable findings are left alone — their
	// fix is switching to a route that already exists, not a new endpoint.
	if *grantsPath != "" {
		reg, err := grants.Load(*grantsPath)
		if err != nil {
			return fmt.Errorf("load grants: %w", err)
		}
		attachPrompts(records, reg)
	}

	src := *source
	if src == "" {
		src = inName
	}
	opts := report.Options{Title: *title, Source: src, Generated: time.Now()}

	w := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer f.Close()
		w = f
	}
	if err := report.Render(w, records, opts); err != nil {
		return err
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "wrote %s (%d runs)\n", *out, len(records))
	}
	return nil
}

// attachPrompts fills DesignPrompt on every finding that names no route at all, using
// insights.Prompt over its profile's Allow list. It mutates the records in place.
//
// Two classes are deliberately skipped, because a design prompt asks the customer's AI to
// invent an endpoint: a finding whose route is already granted (the agent switches to it)
// and one whose route the API already exposes but the profile does not grant (the
// operator adds an allow line). Handing either of those a "design a new endpoint" prompt
// would throw away the concrete answer plimsoll already has.
func attachPrompts(records []report.Record, reg *grants.Registry) {
	// Cache each profile's Allow list so a busy stream resolves it once.
	allows := map[string][]sandbox.HostRoute{}
	lookup := func(profile string) ([]sandbox.HostRoute, bool) {
		if a, ok := allows[profile]; ok {
			return a, len(a) > 0
		}
		p, ok := reg.Get(profile)
		if !ok {
			allows[profile] = nil
			return nil, false
		}
		var a []sandbox.HostRoute
		if g := p.Grant(); g != nil {
			a = g.Allow
		}
		allows[profile] = a
		return a, len(a) > 0
	}

	for ri := range records {
		rec := &records[ri]
		allow, ok := lookup(rec.Profile)
		if !ok {
			continue
		}
		for fi := range rec.Findings {
			f := &rec.Findings[fi]
			if f.Class() != report.ClassNoKnownRoute {
				continue // a route already exists; granting or calling it is the fix
			}
			prompt, ok := insights.Prompt(toInsightsFinding(*f), allow)
			if ok {
				f.DesignPrompt = prompt
			}
		}
	}
}

// toInsightsFinding reconstructs the insights.Finding that Prompt needs from a report
// finding. Only the fields Prompt reads (remedy, method, route, detail, cost) are
// carried; all are trusted metadata that came off the audit line.
func toInsightsFinding(f report.Finding) insights.Finding {
	return insights.Finding{
		Pattern: insights.PatternID(f.Pattern),
		Method:  f.Method,
		Route:   f.Route,
		Remedy:  insights.RemedyClass(f.Remedy),
		Detail:  f.Detail,
		Cost: insights.Cost{
			ExtraCalls:   f.ExtraCalls,
			AddedLatency: time.Duration(f.AddedLatencyMs) * time.Millisecond,
			BytesMoved:   f.BytesMoved,
		},
	}
}
