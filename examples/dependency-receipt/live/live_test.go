package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/receipt"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/runsclog"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
)

const published = "../../../docs/examples/dependency-receipt"

// The published directory verifies, and the page's fixed sentences hold for its evidence: a
// rerun that changes one of them fails here, so the text is reread before it is published.
func TestPublishedFilesVerify(t *testing.T) {
	if err := verifyPublished(published); err != nil {
		t.Fatalf("%v; run go run ./examples/dependency-receipt/live -render, or the whole program", err)
	}
	ev, err := loadEvidence(published)
	if err != nil {
		t.Fatal(err)
	}
	d, err := newPageData(ev)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Bundle.Runs != 3 || ev.Bundle.Lines != 4 {
		t.Errorf("the bundle holds %d runs in %d lines; the page says three runs and a checkpoint", ev.Bundle.Runs, ev.Bundle.Lines)
	}
	for i, want := range fixtures {
		r := ev.Runs[i]
		if r.Fixture != want || r.Line != i+1 {
			t.Errorf("run %d is %s on line %d", i+1, r.Fixture, r.Line)
		}
		if r.Provider != "agentsandbox" || r.Isolation != "kernel" || r.Floor != "kernel" || r.Version != 4 || r.Outcome != "completed" || !strings.HasPrefix(r.Instance, "k8s-pod-uid:") {
			t.Errorf("%s: %s, %s (floor %s), record version %d, %s, %s", r.Fixture, r.Provider, r.Isolation, r.Floor, r.Version, r.Outcome, r.Instance)
		}
		// "as each record names it": one image digest, in every record.
		if !strings.HasPrefix(r.Environment, "agentsandbox-image:sha256:") || r.Environment != ev.Runs[0].Environment {
			t.Errorf("%s: the record's environment is %q", r.Fixture, r.Environment)
		}
		if ev.Daemon["SANDBOX_MIN_ISOLATION"] != "kernel" {
			t.Errorf("the daemon's floor is %q; the page says it refused any run below kernel", ev.Daemon["SANDBOX_MIN_ISOLATION"])
		}
		kinds := map[string]bool{}
		for _, g := range r.Seen.Groups {
			kinds[g.Kind+map[int]string{1: "1", 2: "2"}[g.Step]] = true
			if g.Kind != "sandbox" {
				continue
			}
			// The page says the pod's start loaded no program and that its first process bound
			// sandboxd's two ports.
			ports := 0
			for _, p := range g.Processes {
				if p.Loaded != 0 {
					t.Errorf("%s: PID %d of the pod's start loaded a program", r.Fixture, p.PID)
				}
			}
			for _, c := range g.Calls {
				if c.Kind == "bind" && c.PID == 1 && (c.What == "port 9090" || c.What == "port 8080") && c.Result == "ok" {
					ports++
				}
			}
			if ports != 2 || g.Processes[0].PID != 1 || g.Processes[0].Parent != 0 {
				t.Errorf("%s: the pod's first process bound %d of sandboxd's ports", r.Fixture, ports)
			}
		}
		for _, k := range []string{"sandbox", "check", "runner", "step1"} {
			if !kinds[k] {
				t.Errorf("%s: no %s group", r.Fixture, k)
			}
		}
		// "Most of what the receipts list is npm, not the package."
		total, npm := 0, 0
		for _, g := range r.Seen.Groups {
			n := g.Counts.Effected.Sum() + g.Counts.Attempted.Sum() + g.Counts.Undetermined.Sum() + g.Written
			total += n
			if g.Kind == "step" && g.Step == 1 {
				npm = n
			}
		}
		if 2*npm <= total {
			t.Errorf("%s: npm made %d of %d calls and writes, not most", r.Fixture, npm, total)
		}
	}
	if len(d.Quiet.Scripts) != 0 || scriptGroup(d.Quiet) != nil || len(d.Quiet.Steps) != 2 || d.Quiet.Steps[0].Exit != 0 || d.Quiet.Steps[1].Exit != 0 {
		t.Errorf("quiet: scripts %v, steps %+v", d.Quiet.Scripts, d.Quiet.Steps)
	}
	if d.Network.Scripts["postinstall"] != "node install.js" || len(d.Network.Steps) != 2 || d.Network.Steps[0].Exit != 0 || d.Network.Steps[1].Exit != 0 {
		t.Errorf("network: scripts %v, steps %+v", d.Network.Scripts, d.Network.Steps)
	}
	if d.Network.Seen.Totals.Undetermined.Sum() != 1 || d.Connect.What != tamperAddr+" port 443" || !strings.HasPrefix(d.Connect.Result, "errno=115 ") {
		t.Errorf("network: %d undetermined calls, the script's connect %+v", d.Network.Seen.Totals.Undetermined.Sum(), d.Connect)
	}
	if d.NetSends == 0 || d.NetHidden != 1 {
		t.Errorf("network: %d datagrams to port 53, %d sends with no destination", d.NetSends, d.NetHidden)
	}
	if len(d.Canary.Steps) != 1 || d.Canary.Steps[0].Exit == 0 || d.CanaryScript.Exit == nil || *d.CanaryScript.Exit != 1 {
		t.Errorf("canary: steps %+v, script exit %v", d.Canary.Steps, d.CanaryScript.Exit)
	}
	if d.Refused.What != "/root/.canary" || !strings.Contains(d.Refused.Result, "permission denied") {
		t.Errorf("canary: the refused open is %+v", d.Refused)
	}
	if d.Refusals != 3 || ev.Dropped.Side != "undetermined" || ev.Dropped.Call.Addr != tamperAddr || ev.Dropped.Call.Port != tamperPort {
		t.Errorf("%d refusals; the deleted call %+v on side %s", d.Refusals, ev.Dropped.Call, ev.Dropped.Side)
	}
	if !d.EgressBlocked || d.EgressTried == 0 || ev.Smoke.Tier != "kernel" || !strings.Contains(ev.Smoke.Kernel, "gVisor") {
		t.Errorf("the startup check: %+v", ev.Smoke)
	}
	// "none of them part of plimsolld": the files not yet committed when it was built.
	for _, f := range ev.Build.Uncommitted {
		if !strings.HasPrefix(f, "examples/dependency-receipt/") && !strings.HasPrefix(f, "docs/") && f != "scripts/public-manifest.txt" {
			t.Errorf("plimsolld was built with %s uncommitted", f)
		}
	}

	page, err := os.ReadFile(filepath.Join(published, pageFile))
	if err != nil {
		t.Fatal(err)
	}
	checkPage(t, page)
	var size int64
	if err := filepath.Walk(published, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if size > 2_000_000 {
		t.Errorf("the page's directory is %d bytes, over 2 MB", size)
	}
}

// checkPage holds the page to the site's rules: light only, no dash as punctuation, ids
// unique, and every link to another site or to the glossary labelled with where it goes.
func checkPage(t *testing.T, page []byte) {
	t.Helper()
	if bytes.Contains(page, []byte("prefers-color-scheme")) {
		t.Error("the page has a dark-mode block")
	}
	if regexp.MustCompile("[–—]| -- ").Match(page) {
		t.Error("the page has a dash used as punctuation")
	}
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`\sid="([^"]+)"`).FindAllSubmatch(page, -1) {
		if ids[string(m[1])] {
			t.Errorf("id %q appears twice", m[1])
		}
		ids[string(m[1])] = true
	}
	for _, m := range regexp.MustCompile(`<a href="([^"]+)">([^<]*)</a>`).FindAllSubmatch(page, -1) {
		href, text := string(m[1]), string(m[2])
		switch {
		case strings.HasPrefix(href, "https://plimsollmark.github.io/"):
		case strings.HasPrefix(href, "http"):
			if !strings.Contains(text, "EXTERNAL · ") || !strings.Contains(text, "↗") {
				t.Errorf("the link to %s says %q, not where it goes", href, text)
			}
		case strings.Contains(href, "glossary.html") || strings.HasPrefix(href, "../"):
			if !strings.Contains(text, "INTERNAL · ") {
				t.Errorf("the link to %s says %q, not where it goes", href, text)
			}
		}
	}
}

// -verify refuses the published directory with any one of its files changed.
func TestVerifyRefusesChangedFiles(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, dir string){
		"one byte of a log": func(t *testing.T, dir string) {
			raw, _, err := readPublishedLog(dir, logFile("quiet"))
			if err != nil {
				t.Fatal(err)
			}
			i := bytes.Index(raw, []byte("npm install"))
			raw[i] = 'N'
			if err := writeGzip(filepath.Join(dir, logFile("quiet")), raw); err != nil {
				t.Fatal(err)
			}
		},
		"the tampered receipt replaced by the honest one": func(t *testing.T, dir string) {
			b, err := os.ReadFile(filepath.Join(dir, receiptFile("network")))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, droppedFile), b, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a count in the evidence": func(t *testing.T, dir string) {
			ev, err := loadEvidence(dir)
			if err != nil {
				t.Fatal(err)
			}
			ev.Runs[1].Seen.Written++
			raw, err := json.MarshalIndent(ev, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, evidenceFile), append(raw, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			// The page rendered again from the changed count, so only the files can catch it.
			if err := renderPublished(dir); err != nil {
				t.Fatal(err)
			}
		},
		"the page": func(t *testing.T, dir string) {
			b, err := os.ReadFile(filepath.Join(dir, pageFile))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, pageFile), bytes.Replace(b, []byte("refused"), []byte("accepted"), 1), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			// The unchanged copy verifies: TestPublishedFilesVerify, on the same files.
			dir := t.TempDir()
			copyDir(t, published, dir)
			change(t, dir)
			err := verifyPublished(dir)
			want := map[string]string{
				"one byte of a log": "the quiet receipt: receipt: the signed receipt is not what its evidence rebuilds: the receipt is about log",
				"the tampered receipt replaced by the honest one": "the receipt with a connection deleted: the check said <nil>",
				"a count in the evidence":                         "evidence.json is not what the published files give",
				"the page":                                        "index.html is not what evidence.json renders",
			}[name]
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("verify said %v; want it refused with %q", err, want)
			}
		})
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// see groups processes by the command at their root, matching a step's shell and an install
// script's shell by their exact text, and attributes each call by its PID; it refuses two
// processes with one PID and a call from a PID no process has.
func TestSeeGroupsByCommand(t *testing.T) {
	steps := []string{"npm install ./packages/x", `node -e 'require("x")'`}
	req := &plimsollv1.RunRequest{Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
		Steps: steps,
		Files: []*plimsollv1.ProjectFile{{Path: "packages/x/package.json", Content: `{"scripts":{"postinstall":"node install.js","test":"node t.js"}}`}},
	}}}
	scripts, err := scriptsOf(req, "x")
	if err != nil || len(scripts) != 1 || scripts["postinstall"] != "node install.js" {
		t.Fatalf("scripts %v, %v", scripts, err)
	}
	prog := func(argv ...string) runsclog.Program { return runsclog.Program{Path: argv[0], Argv: argv} }
	p := receipt.Predicate{Processes: []*runsclog.Process{
		{PID: 1},
		{PID: 5, Parent: 1, Programs: []runsclog.Program{prog("sh", "-c", "exec node /runner.mjs"), prog("node", "/runner.mjs")}},
		{PID: 6, Parent: 5, Programs: []runsclog.Program{prog("sh", "-c", steps[0])}},
		{PID: 7, Parent: 6, Programs: []runsclog.Program{prog("sh", "-c", "node install.js")}},
		{PID: 8, Parent: 7, Programs: []runsclog.Program{prog("node", "install.js")}},
		{PID: 9, Parent: 5, Programs: []runsclog.Program{prog("sh", "-c", steps[1])}},
		// Not a step: the text differs by one space.
		{PID: 10, Parent: 5, Programs: []runsclog.Program{prog("sh", "-c", steps[0]+" ")}},
	}}
	p.Effected.Written = []*runsclog.Written{{Path: compileCache + "v22/a", PID: 6, Bytes: 3}, {Path: "/work/x", PID: 8, Bytes: 2}}
	p.Undetermined.Network = []runsclog.Net{{Kind: "connect", PID: 8, Family: "AF_INET", Addr: "203.0.113.7", Port: 443, Result: "errno=115 (operation now in progress)"}}
	p.Attempted.Changes = []runsclog.Change{{Kind: "mkdir", Path: "/work", PID: 6, Result: "errno=17 (file exists)"}}
	s, err := see(p, req, scripts)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range s.Groups {
		var pids []string
		for _, pr := range g.Processes {
			pids = append(pids, strconv.Itoa(pr.PID))
		}
		got = append(got, g.Kind+strconv.Itoa(g.Step)+g.Script+":"+strings.Join(pids, ","))
	}
	if want := "sandbox0:1 runner0:5,10 step1:6 script0postinstall:7,8 step2:9"; strings.Join(got, " ") != want {
		t.Fatalf("groups %s, want %s", strings.Join(got, " "), want)
	}
	script := s.Groups[3]
	if script.Written != 1 || script.Counts.Undetermined.Network != 1 || len(script.Calls) != 2 || !script.Package() {
		t.Fatalf("the script's group: %+v", script)
	}
	if npm := s.Groups[2]; npm.CompileCache != 1 || npm.Counts.Attempted.Changes != 1 || len(npm.Calls) != 1 {
		t.Fatalf("npm's group: %+v", npm)
	}

	dup := p
	dup.Processes = append(append([]*runsclog.Process{}, p.Processes...), &runsclog.Process{PID: 7})
	if _, err := see(dup, req, scripts); err == nil {
		t.Error("two processes with PID 7 were grouped")
	}
	stray := p
	stray.Attempted.Network = []runsclog.Net{{Kind: "connect", PID: 99, Result: "errno=2 (no such file or directory)"}}
	if _, err := see(stray, req, scripts); err == nil {
		t.Error("a call from PID 99, which no process has, was grouped")
	}
}

// The changed byte is the address's last digit, and an edit that does not fit the log is
// refused rather than made.
func TestOneByteEdit(t *testing.T) {
	raw := []byte(`{"msg":"... connect(0x13 socket:[9], 0x7e {Family: AF_INET, Addr: 203.0.113.7, Port: 443}, 0x10)"}`)
	e, err := oneByteEdit(raw)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := applyEdit(raw, e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(changed, []byte("Addr: 203.0.113.8, Port: 443")) || bytes.Equal(changed, raw) {
		t.Fatalf("changed: %s", changed)
	}
	if _, err := applyEdit(changed, e); err == nil {
		t.Error("an edit applied over a byte that is no longer what it states")
	}
	bad := e
	bad.Before = "something else"
	if _, err := applyEdit(raw, bad); err == nil {
		t.Error("an edit whose context is not the log's applied")
	}
	if _, err := oneByteEdit([]byte(`{"msg":"no connect here"}`)); err == nil {
		t.Error("an edit found in a log that never names the address")
	}
}
