// Command agentsandbox writes the agent-sandbox evidence page,
// docs/examples/agentsandbox/index.html, from the files published beside it: the signed
// bundle of two project runs on Kubernetes agent-sandbox under gVisor, their CycloneDX
// bills of materials (written by examples/sbom with -line), and the transcripts of five
// refusals (refusals.json). It also reads the CycloneDX example's bundle, where the same
// two requests ran on docker under gVisor and on Docker Cloud, and compares the three.
//
// It verifies both bundles before writing and starts no sandbox: the runs were recorded on
// a kind cluster, as the page says, and rendering needs none, so the page's test rebuilds
// it byte for byte. From the repository root:
//
//	go run ./examples/agentsandbox
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

//go:embed page.html
var pageHTML string

func main() {
	dir := flag.String("dir", "docs/examples/agentsandbox", "the evidence directory, which the page is written into")
	sbomDir := flag.String("sbom", "docs/examples/sbom", "the CycloneDX example's directory, for the same requests on other providers")
	flag.Parse()
	page, err := render(*dir, *sbomDir)
	if err == nil {
		err = os.WriteFile(filepath.Join(*dir, "index.html"), page, 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentsandbox:", err)
		os.Exit(1)
	}
	fmt.Println("wrote", filepath.Join(*dir, "index.html"))
}

// run is one signed project run as the page shows it.
type run struct {
	Line                          uint64
	Title                         string
	Record, Request, Result       string
	Provider, Tier, Floor         string
	Environment, Image            string
	Started                       string
	Ms                            int64
	Outcome                       string
	Steps                         []step
	BOM                           string
	Rooms                         []room
	SameResultEverywhere, InSBOM  bool
	ResultMatches, ResultMismatch int
}

type step struct {
	Command, Output string
	Exit            int32
	Ms              int64
}

// room is the same request run by one provider, from one of the two bundles.
type room struct {
	Provider, Tier, Environment, Result, Page string
	Ms                                        int64
	Here, SameResult                          bool
}

type refusal struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Did    string   `json:"did"`
	Caller []string `json:"caller"`
	Log    string   `json:"log"`
	Then   string   `json:"then"`
	Means  string   `json:"means"`
}

// recording is refusals.json: what the recording saw that no signed record holds.
type recording struct {
	Recorded string `json:"recorded"`
	Smoke    struct {
		Kernel   string            `json:"kernel"`
		Swept    int               `json:"swept"`
		Writable []string          `json:"writable"`
		Egress   map[string]string `json:"egress"`
		Filled   []string          `json:"filled"`
	} `json:"smoke"`
	RuncSmoke struct {
		Seccomp string `json:"seccomp"`
		Queues  string `json:"queues"`
		Swept   int    `json:"swept"`
	} `json:"runc_smoke"`
	PodKernels struct {
		GVisor   string `json:"gvisor"`
		Remapped string `json:"remapped"`
	} `json:"pod_kernels"`
	Refusals []refusal `json:"refusals"`
}

// beforeFix is the signed run that led to the per-pod tier check: a snippet on a node
// whose runsc handler had been remapped to runc, signed at the kernel tier.
type beforeFix struct {
	Record, Tier, Provider, Stdout string
	Exit                           int32
}

type page struct {
	Before                   beforeFix
	Date, KeyID, Image, Tier string
	AllSame                  bool
	Runs                     []run
	Rec                      recording
	Egress                   []string
}

// signed is one verified single run of a bundle.
type signed struct {
	line uint64
	rec  sandbox.RunRecord
	req  *plimsollv1.RunRequest
	resp *plimsollv1.RunResponse
}

// verified reads a bundle and its key, verifies the whole bundle, and returns its single
// runs with their signed places.
func verified(bundlePath, pubPath string) ([]signed, string, error) {
	pemBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, "", err
	}
	pub, err := attest.ParsePublicKey(pemBytes)
	if err != nil {
		return nil, "", err
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, "", err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(raw))
	if err != nil {
		return nil, "", err
	}
	v := attest.NewVerifier(pub)
	if _, err := attest.VerifyBundle(entries, v); err != nil {
		return nil, "", fmt.Errorf("%s does not verify: %w", bundlePath, err)
	}
	var runs []signed
	for _, e := range entries {
		if len(e.Request) == 0 {
			continue // a checkpoint
		}
		rec, link, err := attest.VerifyEntry(v, e)
		if err != nil {
			return nil, "", err
		}
		req, resp, err := e.Messages()
		if err != nil {
			return nil, "", err
		}
		if rec.Session == "" {
			runs = append(runs, signed{line: link.Index, rec: rec, req: req, resp: resp})
		}
	}
	return runs, attest.KeyID(pub), nil
}

func render(dir, sbomDir string) ([]byte, error) {
	mine, keyID, err := verified(filepath.Join(dir, "bundle.jsonl"), filepath.Join(dir, "harness.pub"))
	if err != nil {
		return nil, err
	}
	if len(mine) != 2 || mine[0].req.GetProject() == nil || mine[1].req.GetProject() == nil {
		return nil, fmt.Errorf("the evidence bundle holds %d runs, not 2 project runs", len(mine))
	}
	before, _, err := verified(filepath.Join(dir, "before-the-fix.jsonl"), filepath.Join(dir, "harness.pub"))
	if err != nil {
		return nil, err
	}
	if len(before) != 1 || before[0].resp.GetJavascript() == nil {
		return nil, errors.New("before-the-fix.jsonl holds no single snippet run")
	}
	b := before[0]
	p0 := beforeFix{Record: b.rec.SHA256, Tier: b.rec.Isolation, Provider: b.rec.Provider,
		Stdout: strings.TrimSpace(string(b.resp.GetJavascript().GetStdout())), Exit: b.resp.GetJavascript().GetExitCode()}
	others, _, err := verified(filepath.Join(sbomDir, "bundle.jsonl"), filepath.Join(sbomDir, "harness.pub"))
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "refusals.json"))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rec recording
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("refusals.json: %w", err)
	}
	if len(rec.Refusals) != 5 {
		return nil, fmt.Errorf("refusals.json holds %d refusals, not 5", len(rec.Refusals))
	}
	p := page{Date: strings.TrimSuffix(rec.Recorded, "Z"), KeyID: keyID, Rec: rec, Before: p0}
	p.Date = strings.Replace(p.Date, "T", " ", 1) + " UTC"
	for _, target := range sortedKeys(rec.Smoke.Egress) {
		p.Egress = append(p.Egress, target+": "+rec.Smoke.Egress[target])
	}
	for _, s := range mine {
		r, err := pageRun(s, dir)
		if err != nil {
			return nil, err
		}
		r.Rooms = append(r.Rooms, room{Provider: r.Provider, Tier: r.Tier, Environment: r.Environment, Result: r.Result, Ms: r.Ms, Here: true, SameResult: true})
		for _, o := range others {
			if o.rec.RequestSHA256 != s.rec.RequestSHA256 || o.req.GetProject() == nil {
				continue
			}
			r.InSBOM = true
			same := o.rec.ResultSHA256 == s.rec.ResultSHA256
			if same {
				r.ResultMatches++
			} else {
				r.ResultMismatch++
			}
			r.Rooms = append(r.Rooms, room{Provider: o.rec.Provider, Tier: o.rec.Isolation, Environment: o.rec.Environment,
				Result: o.rec.ResultSHA256, Ms: o.rec.Ended.Sub(o.rec.Started).Milliseconds(), SameResult: same,
				Page: "../sbom/run-" + o.rec.SHA256[:12] + ".cdx.json"})
		}
		if !r.InSBOM {
			return nil, fmt.Errorf("run %s: no run of the CycloneDX example has its request", r.Record)
		}
		r.SameResultEverywhere = r.ResultMismatch == 0
		p.Runs = append(p.Runs, r)
	}
	p.Image, p.Tier = p.Runs[0].Image, p.Runs[0].Tier
	p.AllSame = p.Runs[0].SameResultEverywhere && p.Runs[1].SameResultEverywhere
	t, err := template.New("page").Funcs(template.FuncMap{"short": short, "inc": func(i int) int { return i + 1 }}).Parse(pageHTML)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := t.Execute(&out, p); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// pageRun is one signed agent-sandbox run, with its BOM, which must be beside the bundle.
func pageRun(s signed, dir string) (run, error) {
	const prefix = "agentsandbox-image:sha256:"
	if s.rec.Provider != "agentsandbox" || !strings.HasPrefix(s.rec.Environment, prefix) {
		return run{}, fmt.Errorf("line %d: provider %q, environment %q: not an agent-sandbox run with a pinned image", s.line, s.rec.Provider, s.rec.Environment)
	}
	pr := s.resp.GetProject()
	r := run{
		Line: s.line, Record: s.rec.SHA256, Request: s.rec.RequestSHA256, Result: s.rec.ResultSHA256,
		Provider: s.rec.Provider, Tier: s.rec.Isolation, Floor: s.req.GetMinimumIsolation(),
		Environment: s.rec.Environment, Image: strings.TrimPrefix(s.rec.Environment, prefix),
		Started: s.rec.Started.UTC().Format(time.RFC3339), Ms: s.rec.Ended.Sub(s.rec.Started).Milliseconds(),
		Outcome: strings.ToLower(strings.TrimPrefix(pr.GetOutcome().String(), "PROJECT_OUTCOME_")),
		BOM:     "run-" + s.rec.SHA256[:12] + ".cdx.json",
	}
	var commands []string
	for _, st := range pr.GetSteps() {
		out := strings.TrimSpace(string(st.GetStdout()) + string(st.GetStderr()))
		if len(out) > 240 {
			out = out[:240] + "…"
		}
		r.Steps = append(r.Steps, step{Command: st.GetCommand(), Output: out, Exit: st.GetExitCode(), Ms: st.GetDurationMs()})
		commands = append(commands, st.GetCommand())
	}
	r.Title = strings.Join(commands, ", then ")
	if _, err := os.Stat(filepath.Join(dir, r.BOM)); err != nil {
		return run{}, fmt.Errorf("line %d: its bill of materials: %w", s.line, err)
	}
	if len(r.Steps) == 0 {
		return run{}, errors.New("a run with no steps")
	}
	return r, nil
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

func sortedKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}
