// Command agentsandbox writes the agent-sandbox evidence page,
// docs/examples/agentsandbox/index.html, from the files published beside it.
//
// rooms.json lists the rooms, the places the same two project requests ran, in the order
// the page shows them. A room recorded for this page names its signed bundle (two project
// runs on Kubernetes agent-sandbox under one runtime class), whose runs' CycloneDX bills of
// materials sit beside it (written by examples/sbom with -line), and may name a signed
// snippet that read what plimsoll's per-pod check reads, with what its startup smoke test
// logged. A room of the CycloneDX example names a provider and tier, and its runs of the
// same requests are found in that example's bundle. A new room is an entry in rooms.json
// and its files; the program and the template have none of their own. Beside them are the
// transcripts of five refusals (refusals.json) and the signed run that led to the per-pod
// check (before-the-fix.jsonl).
//
// It verifies every bundle before writing and starts no sandbox: the runs were recorded on
// a kind cluster, as the page says, and rendering needs none, so the page's test rebuilds
// it byte for byte. From the repository root:
//
//	go run ./examples/agentsandbox
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
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

// roomSpec is one room of rooms.json. A room recorded for this page names its bundle,
// relative to the page, and the runtime class it ran under; a room of the CycloneDX
// example names the provider whose runs of the same requests it holds.
type roomSpec struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Tier     string `json:"tier"`
	Provider string `json:"provider"`

	Bundle       string     `json:"bundle"`
	RuntimeClass string     `json:"runtime_class"`
	Handler      string     `json:"handler"`
	Runtime      string     `json:"runtime"`
	Template     string     `json:"template"`
	Daemon       string     `json:"daemon"`
	PodCheck     *podCheck  `json:"pod_check"`
	Smoke        *roomSmoke `json:"smoke"`
	Shows        []string   `json:"shows"`
	Limits       []string   `json:"limits"`
}

// podCheck names a signed snippet that read, in a pod of the room's pool after plimsoll's
// per-pod check had passed there, what that check reads; and the node's boot ID and kernel
// as the Kubernetes API reported them when it ran, a transcript.
type podCheck struct {
	Bundle     string `json:"bundle"`
	NodeBootID string `json:"node_boot_id"`
	NodeKernel string `json:"node_kernel"`
	Read       string `json:"read"`
}

// roomSmoke is what the room's daemon logged when its startup smoke test passed, a
// transcript.
type roomSmoke struct {
	Kernel   string            `json:"kernel"`
	Swept    int               `json:"swept"`
	Writable []string          `json:"writable"`
	Mounts   map[string]string `json:"mounts"`
	Egress   map[string]string `json:"egress"`
}

// room is a roomSpec as the page shows it.
type room struct {
	roomSpec
	Here           bool   // recorded for this page
	Date           string // when its first run started, for a room recorded here
	FirstBOM       string
	Check          *check
	Egress, Mounts []string
}

// check is a room's pod check as the page shows it: the signed snippet's line and what it
// printed.
type check struct {
	podCheck
	Line          uint64
	Record, Floor string
	Kernel, Boot  string
	Stdout        string
}

// request is one of the two requests: this page's runs of it and every room's result.
type request struct {
	Title, Digest, Floor, Result string
	Steps                        []step // as the first room ran it
	Runs                         []run  // one per room recorded here
	Results                      []result
	SameHere, SameEverywhere     bool // one result digest in the rooms recorded here, in every room
}

// run is one signed project run recorded for this page.
type run struct {
	Room, RoomID, Class string
	Line                uint64
	Bundle              string
	Record, Result      string
	Provider, Tier      string
	Environment, Image  string
	Started             string
	Ms                  int64
	Outcome             string
	Steps               []step
	BOM                 string
	SameAsFirst         bool
}

type step struct {
	Command, Output string
	Exit            int32
	Ms              int64
}

// result is one room's run of a request, for the comparison.
type result struct {
	Room, RoomID, Provider, Tier, Environment, Result, BOM string
	Ms                                                     int64
	Here, SameResult                                       bool
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

// recording is refusals.json: what the gVisor recording saw that no signed record holds.
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
	Version                        int
	Commit                         string // a commit whose plimsoll-attest verifies the file
}

// beforeTheFixCommit is the release whose plimsoll-attest verifies before-the-fix.jsonl, which
// it published byte for byte. That run was signed under record version 2, which no current
// verifier reads, and it cannot be made again: the per-pod check it led to refuses it. So the
// page states it as a transcript and names where it still verifies.
const beforeTheFixCommit = "v0.22.0"

// beforeTheFixSHA256 is the SHA-256 of before-the-fix.jsonl as release v0.22.0 published it.
const beforeTheFixSHA256 = "0c7f9a8bd981bb6ab5eec96261c060a50dd21d044fd5bc3c4cc578b5f3808caa"

// legacyRun reads the one snippet run of before-the-fix.jsonl as it was signed, without
// verifying it: the record its statement states and the stored response's output.
func legacyRun(path string) (beforeFix, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return beforeFix{}, err
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != beforeTheFixSHA256 {
		return beforeFix{}, fmt.Errorf("%s is not the file release %s published and verifies", path, beforeTheFixCommit)
	}
	entries, err := attest.ReadBundle(bytes.NewReader(raw))
	if err != nil {
		return beforeFix{}, err
	}
	var runs []attest.Entry
	for _, e := range entries {
		if len(e.Request) != 0 {
			runs = append(runs, e)
		}
	}
	if len(runs) != 1 {
		return beforeFix{}, fmt.Errorf("%s holds %d runs, not one", path, len(runs))
	}
	_, resp, err := runs[0].Messages()
	if err != nil {
		return beforeFix{}, err
	}
	payload, err := base64.StdEncoding.DecodeString(runs[0].Envelope.Payload)
	if err != nil {
		return beforeFix{}, err
	}
	var st attest.Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return beforeFix{}, err
	}
	js := resp.GetJavascript()
	if js == nil {
		return beforeFix{}, fmt.Errorf("%s holds no snippet run", path)
	}
	return beforeFix{Record: st.Predicate.RecordSHA256, Tier: st.Predicate.Isolation, Provider: st.Predicate.Provider,
		Stdout: strings.TrimSpace(string(js.GetStdout())), Exit: js.GetExitCode(), Version: st.Predicate.Version,
		Commit: beforeTheFixCommit}, nil
}

type page struct {
	Before      beforeFix
	Date, KeyID string
	Image       string // the image every run on this page ran, or "" if they differ
	AllSame     bool
	Signed      int
	Requests    []request
	Rooms       []room   // every room, in rooms.json's order
	Here        []room   // the rooms recorded for this page
	Elsewhere   []string // the CycloneDX example's rooms, by label
	Rec         recording
	Egress      []string
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

var (
	roomID = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	uuid   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// readRooms reads rooms.json and refuses a room the page could not show truthfully.
func readRooms(file string) ([]roomSpec, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc struct {
		Rooms []roomSpec `json:"rooms"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("rooms.json: %w", err)
	}
	if len(doc.Rooms) == 0 || doc.Rooms[0].Bundle == "" {
		return nil, errors.New("rooms.json: the first room must be one recorded for this page")
	}
	ids, elsewhere := map[string]bool{}, map[string]bool{}
	for _, r := range doc.Rooms {
		bad := func(why string) error { return fmt.Errorf("rooms.json: room %q: %s", r.ID, why) }
		switch {
		case !roomID.MatchString(r.ID) || ids[r.ID]:
			return nil, bad("an id must be unique, a lowercase letter then letters, digits or -")
		case strings.TrimSpace(r.Label) == "":
			return nil, bad("no label")
		case sandbox.ParseIsolationClass(r.Tier) == sandbox.IsolationUnknown:
			return nil, bad("no tier plimsoll states")
		}
		ids[r.ID] = true
		if r.Bundle == "" {
			if r.Provider == "" || r.RuntimeClass != "" || r.Handler != "" || r.Runtime != "" || r.Template != "" || r.Daemon != "" || r.PodCheck != nil || r.Smoke != nil || r.Shows != nil || r.Limits != nil {
				return nil, bad("a room of the CycloneDX example names its provider and tier, and nothing recorded here")
			}
			key := r.Provider + " " + r.Tier
			if elsewhere[key] {
				return nil, bad("two rooms name " + key)
			}
			elsewhere[key] = true
			continue
		}
		switch {
		case r.Provider != "":
			return nil, bad("a room recorded here is agent-sandbox's; it names no provider")
		case !localPath(r.Bundle) || path.Base(r.Bundle) != "bundle.jsonl":
			return nil, bad("its bundle must be a bundle.jsonl at or below the page, which its bills of materials cite by that name")
		case r.RuntimeClass == "" || r.Handler == "" || r.Runtime == "" || r.Template == "" || r.Daemon == "":
			return nil, bad("a room recorded here states its runtime class, handler, runtime, template and daemon")
		}
		if c := r.PodCheck; c != nil {
			if _, err := time.Parse(time.RFC3339, c.Read); err != nil || !localPath(c.Bundle) || !uuid.MatchString(c.NodeBootID) || c.NodeKernel == "" {
				return nil, bad("its pod check needs a signed bundle at or below the page, the node's boot ID and kernel, and when they were read")
			}
		}
	}
	return doc.Rooms, nil
}

// localPath reports whether p is a clean relative slash path at or below the page.
func localPath(p string) bool {
	return p != "" && path.Clean(p) == p && !path.IsAbs(p) && p != ".." && !strings.HasPrefix(p, "../") && !strings.Contains(p, "\\")
}

func render(dir, sbomDir string) ([]byte, error) {
	specs, err := readRooms(filepath.Join(dir, "rooms.json"))
	if err != nil {
		return nil, err
	}
	pub := filepath.Join(dir, "harness.pub")
	before, err := legacyRun(filepath.Join(dir, "before-the-fix.jsonl"))
	if err != nil {
		return nil, err
	}
	_, keyID, err := verified(filepath.Join(dir, "bundle.jsonl"), pub)
	if err != nil {
		return nil, err
	}
	p := page{KeyID: keyID, Before: before}
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
	if err := dec.Decode(&p.Rec); err != nil {
		return nil, fmt.Errorf("refusals.json: %w", err)
	}
	if len(p.Rec.Refusals) != 5 {
		return nil, fmt.Errorf("refusals.json holds %d refusals, not 5", len(p.Rec.Refusals))
	}
	p.Date = strings.Replace(strings.TrimSuffix(p.Rec.Recorded, "Z"), "T", " ", 1) + " UTC"
	p.Egress = joined(p.Rec.Smoke.Egress, ": ")

	images := map[string]bool{}
	for i, spec := range specs {
		r := room{roomSpec: spec, Here: spec.Bundle != ""}
		if !r.Here {
			p.Rooms = append(p.Rooms, r)
			continue
		}
		mine, _, err := verified(filepath.Join(dir, filepath.FromSlash(spec.Bundle)), pub)
		if err != nil {
			return nil, err
		}
		if len(mine) != 2 || mine[0].req.GetProject() == nil || mine[1].req.GetProject() == nil {
			return nil, fmt.Errorf("room %s: its bundle holds %d runs, not 2 project runs", spec.ID, len(mine))
		}
		for j, s := range mine {
			pr, err := pageRun(s, dir, spec)
			if err != nil {
				return nil, err
			}
			if i == 0 {
				p.Requests = append(p.Requests, request{Title: pr.Title(), Digest: s.rec.RequestSHA256,
					Floor: s.req.GetMinimumIsolation(), Result: s.rec.ResultSHA256, Steps: pr.Steps})
			} else if s.rec.RequestSHA256 != p.Requests[j].Digest {
				return nil, fmt.Errorf("room %s: line %d ran request %s, not the first room's %s", spec.ID, s.line, s.rec.RequestSHA256, p.Requests[j].Digest)
			}
			pr.SameAsFirst = pr.Result == p.Requests[j].Result
			p.Requests[j].Runs = append(p.Requests[j].Runs, pr)
			images[pr.Image] = true
			p.Signed++
		}
		r.Date = mine[0].rec.Started.UTC().Format("2006-01-02 15:04 UTC")
		r.FirstBOM = p.Requests[0].Runs[len(p.Requests[0].Runs)-1].BOM
		if spec.PodCheck != nil {
			if r.Check, err = podCheckView(dir, pub, spec); err != nil {
				return nil, err
			}
		}
		if spec.Smoke != nil {
			r.Egress, r.Mounts = joined(spec.Smoke.Egress, ": "), joined(spec.Smoke.Mounts, " is ")
		}
		p.Rooms = append(p.Rooms, r)
		p.Here = append(p.Here, r)
	}
	if len(images) == 1 {
		p.Image = slices.Collect(maps.Keys(images))[0]
	}

	listed := map[string]bool{}
	for _, r := range p.Rooms {
		if !r.Here {
			listed[r.Provider+" "+r.Tier] = true
			p.Elsewhere = append(p.Elsewhere, r.Label)
		}
	}
	p.AllSame = true
	for j := range p.Requests {
		q := &p.Requests[j]
		q.SameEverywhere, q.SameHere = true, true
		for _, pr := range q.Runs {
			q.SameHere = q.SameHere && pr.SameAsFirst
		}
		for _, r := range p.Rooms {
			res := result{Room: r.Label, RoomID: r.ID, Here: r.Here}
			if r.Here {
				for _, pr := range q.Runs {
					if pr.RoomID == r.ID {
						res.Provider, res.Tier, res.Environment, res.Result, res.Ms, res.BOM = pr.Provider, pr.Tier, pr.Environment, pr.Result, pr.Ms, pr.BOM
					}
				}
			} else {
				var found []signed
				for _, o := range others {
					if o.rec.RequestSHA256 == q.Digest && o.req.GetProject() != nil && o.rec.Provider == r.Provider && o.rec.Isolation == r.Tier {
						found = append(found, o)
					}
				}
				if len(found) != 1 {
					return nil, fmt.Errorf("room %s: the CycloneDX example holds %d runs of request %s on %s at %s, not 1", r.ID, len(found), q.Digest, r.Provider, r.Tier)
				}
				o := found[0]
				res.Provider, res.Tier, res.Environment, res.Result = o.rec.Provider, o.rec.Isolation, o.rec.Environment, o.rec.ResultSHA256
				res.Ms, res.BOM = o.rec.Ended.Sub(o.rec.Started).Milliseconds(), "../sbom/run-"+o.rec.SHA256[:12]+".cdx.json"
			}
			res.SameResult = res.Result == q.Result
			q.SameEverywhere = q.SameEverywhere && res.SameResult
			q.Results = append(q.Results, res)
		}
		for _, o := range others {
			if o.rec.RequestSHA256 == q.Digest && o.req.GetProject() != nil && !listed[o.rec.Provider+" "+o.rec.Isolation] {
				return nil, fmt.Errorf("the CycloneDX example ran request %s on %s at %s, a room rooms.json does not list", q.Digest, o.rec.Provider, o.rec.Isolation)
			}
		}
		p.AllSame = p.AllSame && q.SameEverywhere
	}

	t, err := template.New("page").Funcs(template.FuncMap{"short": short, "inc": func(i int) int { return i + 1 }, "sep": sep}).Parse(pageHTML)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := t.Execute(&out, p); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// pageRun is one signed agent-sandbox run of a room recorded here, with its BOM, which
// must be beside the room's bundle.
func pageRun(s signed, dir string, spec roomSpec) (run, error) {
	const prefix = "agentsandbox-image:sha256:"
	if s.rec.Provider != "agentsandbox" || !strings.HasPrefix(s.rec.Environment, prefix) {
		return run{}, fmt.Errorf("room %s line %d: provider %q, environment %q: not an agent-sandbox run with a pinned image", spec.ID, s.line, s.rec.Provider, s.rec.Environment)
	}
	if s.rec.Isolation != spec.Tier {
		return run{}, fmt.Errorf("room %s line %d: signed at tier %q, where rooms.json says %q", spec.ID, s.line, s.rec.Isolation, spec.Tier)
	}
	pr := s.resp.GetProject()
	at := path.Dir(spec.Bundle)
	r := run{
		Room: spec.Label, RoomID: spec.ID, Class: spec.RuntimeClass,
		Line: s.line, Bundle: spec.Bundle, Record: s.rec.SHA256, Result: s.rec.ResultSHA256,
		Provider: s.rec.Provider, Tier: s.rec.Isolation,
		Environment: s.rec.Environment, Image: strings.TrimPrefix(s.rec.Environment, prefix),
		Started: s.rec.Started.UTC().Format(time.RFC3339), Ms: s.rec.Ended.Sub(s.rec.Started).Milliseconds(),
		Outcome: strings.ToLower(strings.TrimPrefix(pr.GetOutcome().String(), "PROJECT_OUTCOME_")),
		BOM:     path.Join(at, "run-"+s.rec.SHA256[:12]+".cdx.json"),
	}
	for _, st := range pr.GetSteps() {
		out := strings.TrimSpace(string(st.GetStdout()) + string(st.GetStderr()))
		if len(out) > 240 {
			out = out[:240] + "…"
		}
		r.Steps = append(r.Steps, step{Command: st.GetCommand(), Output: out, Exit: st.GetExitCode(), Ms: st.GetDurationMs()})
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(r.BOM))); err != nil {
		return run{}, fmt.Errorf("room %s line %d: its bill of materials: %w", spec.ID, s.line, err)
	}
	if len(r.Steps) == 0 {
		return run{}, errors.New("a run with no steps")
	}
	return r, nil
}

// Title names a run by its steps.
func (r run) Title() string {
	var commands []string
	for _, st := range r.Steps {
		commands = append(commands, st.Command)
	}
	return strings.Join(commands, ", then ")
}

// The provider's per-pod rules (sandbox/agentsandbox/smoke.go), restated so that the page
// refuses to show as passed a check the provider would have refused.
var (
	gvisorBoot = regexp.MustCompile(`^\[ *0\.000000\] Starting gVisor\.\.\.$`)
	linuxBoot  = regexp.MustCompile(`^\[ *0\.000000\] Linux version \S+ `)
)

// podCheckView reads a room's signed snippet and holds what it printed to the room's tier,
// as the provider's per-pod check does.
func podCheckView(dir, pub string, spec roomSpec) (*check, error) {
	c := spec.PodCheck
	runs, _, err := verified(filepath.Join(dir, filepath.FromSlash(c.Bundle)), pub)
	if err != nil {
		return nil, err
	}
	if len(runs) != 1 || runs[0].resp.GetJavascript() == nil {
		return nil, fmt.Errorf("room %s: %s holds no single snippet run", spec.ID, c.Bundle)
	}
	s := runs[0]
	js := s.resp.GetJavascript()
	if s.rec.Provider != "agentsandbox" || s.rec.Isolation != spec.Tier || js.GetExitCode() != 0 {
		return nil, fmt.Errorf("room %s: the pod check ran on %s at %s and exited %d", spec.ID, s.rec.Provider, s.rec.Isolation, js.GetExitCode())
	}
	v := &check{podCheck: *c, Line: s.line, Record: s.rec.SHA256, Floor: s.req.GetMinimumIsolation(), Stdout: strings.TrimSpace(string(js.GetStdout()))}
	for _, line := range strings.Split(v.Stdout, "\n") {
		if k, ok := strings.CutPrefix(line, "kernel log, first line: "); ok {
			v.Kernel = k
		}
		if b, ok := strings.CutPrefix(line, "boot id: "); ok {
			v.Boot = b
		}
	}
	switch {
	case !uuid.MatchString(v.Boot):
		return nil, fmt.Errorf("room %s: the pod check printed no boot ID", spec.ID)
	case spec.Tier == "vm" && (!linuxBoot.MatchString(v.Kernel) || v.Boot == strings.ToLower(c.NodeBootID)):
		return nil, fmt.Errorf("room %s: the pod check shows kernel log %q and boot ID %s against the node's %s, which the vm tier refuses", spec.ID, v.Kernel, v.Boot, c.NodeBootID)
	case spec.Tier == "kernel" && !gvisorBoot.MatchString(v.Kernel):
		return nil, fmt.Errorf("room %s: the pod check shows kernel log %q, not gVisor's", spec.ID, v.Kernel)
	case spec.Tier != "vm" && spec.Tier != "kernel":
		return nil, fmt.Errorf("room %s: the provider makes no per-pod kernel check at tier %s", spec.ID, spec.Tier)
	}
	return v, nil
}

// sep is what goes before item i of n in a list read as prose: nothing, a comma, or "and".
func sep(i, n int) string {
	switch {
	case i == 0:
		return ""
	case i == n-1:
		return " and "
	default:
		return ", "
	}
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// joined is a map's entries as "key<sep>value", sorted by key.
func joined(m map[string]string, sep string) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		out = append(out, k+sep+m[k])
	}
	return out
}
