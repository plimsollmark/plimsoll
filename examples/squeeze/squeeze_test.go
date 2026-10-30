package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) // the in-memory daemon's audit lines
	os.Exit(m.Run())
}

// The verdict rules ported from the hackathon's judge give the hackathon's own verdicts from
// the hackathon's own numbers: every label, gap and flag, on both courses.
func TestVerdictRulesReproduceTheHackathonJudge(t *testing.T) {
	hk, err := loadHackathon()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, c := range hk.Courses {
		var none []int
		for _, g := range c.Groups {
			if g.From == "" {
				for _, r := range g.Rebuilds {
					if r.Valid {
						none = append(none, r.Practice)
					}
				}
			}
		}
		for _, l := range c.Loops {
			for _, g := range c.Groups {
				if g.From != l.ID {
					continue
				}
				var practice, fresh []int
				for _, r := range g.Rebuilds {
					if r.Valid {
						practice, fresh = append(practice, r.Practice), append(fresh, r.Fresh)
					}
				}
				v := verdict(l.ID, l.Practice, 16, l.Fresh, 64, practice, fresh, g.Of, none, true)
				j := l.Judge
				if v.Label != j.Verdict || v.Inflation != j.Inflation || v.RecipeValue != j.RecipeValue || v.HeldoutGap != j.HeldoutGap || v.Memorized != j.Memorized {
					t.Errorf("%s %s: ported %+v, the hackathon's judge %+v", c.ID, l.ID, v, j)
				}
				for tol, flagged := range v.Sensitivity {
					if want := j.Sensitivity[strconv.Itoa(tol)] == "flag"; flagged != want {
						t.Errorf("%s %s at tolerance %d: flagged %v, the judge %v", c.ID, l.ID, tol, flagged, want)
					}
				}
				checked++
			}
		}
	}
	if checked != 4 {
		t.Fatalf("checked %d loops, want the hackathon's 4", checked)
	}
}

// The paper's rule on the hackathon's numbers: it flags all four loops, the easy course's
// cheater included, which the hackathon's tolerance of 2 flights did not.
func TestPaperRuleOnTheHackathonNumbers(t *testing.T) {
	none := []int{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 15, 16, 16}
	cheater := verdict("cheater", 16, 16, 0, 64, []int{16, 16, 10, 16, 16, 14, 11, 16, 16, 10, 16, 15, 10, 15, 0, 10}, nil, 16, none, true)
	if !cheater.PaperFlag || cheater.Label != labelNothing || !cheater.PaperOverfitOK || !cheater.PaperOverfitInf {
		t.Fatalf("the easy cheater: %+v", cheater)
	}
	honest := verdict("honest", 16, 16, 64, 64, []int{16, 16, 16, 16, 16, 16, 16, 14}, nil, 8, none, true)
	if honest.PaperFlag || honest.PaperOverfitOK {
		t.Fatalf("the easy honest loop: %+v", honest)
	}
}

// lab is an in-memory provider for the tests: sessions that keep the files their calls carry,
// and project runs that "fly" by a rule read from the controller's text instead of a simulator.
// A controller containing ALL passes every flight; one containing ONLY:<seeds> passes those
// seeds alone (a memorizer); any other passes even seeds.
type lab struct {
	*sandboxtest.Sessions
	mu       sync.Mutex
	projects []sandbox.ProjectRequest
	flip     uint32 // a seed whose flights end the other way: a grader that is not deterministic
}

func (l *lab) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := l.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &labSession{Session: s, files: map[string]string{}}, nil
}

func (l *lab) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	l.mu.Lock()
	l.projects = append(l.projects, req)
	l.mu.Unlock()
	files := map[string]string{}
	for _, f := range req.Files {
		files[f.Path] = f.Content
	}
	res := sandbox.ProjectResult{Sandbox: "fake-sessions", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted}
	for _, step := range req.Steps {
		f := strings.Fields(step)
		var cases struct{ Seeds []uint32 }
		if len(f) < 4 || f[0] != "node" || f[1] != "fly.mjs" || json.Unmarshal([]byte(files[f[3]]), &cases) != nil {
			return res, fmt.Errorf("lab: a step it cannot fly: %q", step)
		}
		out := fakeFlights(files["controller.js"], cases.Seeds)
		for i, r := range out.Results {
			if l.flip != 0 && r.Seed == l.flip {
				out.Results[i].Success = !r.Success
			}
		}
		b, _ := json.Marshal(out)
		res.Steps = append(res.Steps, sandbox.StepResult{Command: step, Stdout: string(b) + "\n"})
		if strings.Contains(step, "--record") {
			for _, r := range out.Results {
				track, _ := json.Marshal(map[string]any{"seed": r.Seed, "result": r, "frames": []map[string]any{{"pos": map[string]float64{"x": -2.1, "y": 0.07, "z": -1.65}}, {"pos": map[string]float64{"x": 2.05, "y": 0.07, "z": 1.65}}}})
				res.Artifacts = append(res.Artifacts, sandbox.Artifact{Path: "tracks/seed-" + strconv.FormatUint(uint64(r.Seed), 10) + ".json", Content: track})
			}
		}
	}
	return res, nil
}

var onlyPattern = regexp.MustCompile(`ONLY:([0-9,]+)`)

func fakeFlights(controller string, seeds []uint32) FlightSet {
	if strings.Contains(controller, "INVALID") {
		return FlightSet{Valid: false, Error: "forbidden source token: process"}
	}
	fs := FlightSet{Valid: true, Total: len(seeds)}
	only := map[uint32]bool{}
	if m := onlyPattern.FindStringSubmatch(controller); m != nil {
		for _, s := range strings.Split(m[1], ",") {
			n, _ := strconv.ParseUint(s, 10, 32)
			only[uint32(n)] = true
		}
	}
	for _, s := range seeds {
		ok := s%2 == 0
		switch {
		case strings.Contains(controller, "ALL"):
			ok = true
		case len(only) > 0:
			ok = only[s]
		}
		f := Flight{Seed: s, Success: ok, Reason: "landed", GatesPassed: 3, SimulatedSeconds: 20, CPUSeconds: 0.05}
		if !ok {
			f.Reason, f.GatesPassed = "malformed action: four finite numbers required", 0
		}
		if ok {
			fs.Passed++
		}
		fs.Results = append(fs.Results, f)
	}
	return fs
}

type labSession struct {
	sandbox.Session
	mu    sync.Mutex
	files map[string]string
}

func (s *labSession) RunCell(ctx context.Context, req sandbox.CellRequest) (sandbox.CellResult, error) {
	s.mu.Lock()
	for _, f := range req.Files {
		s.files[f.Path] = f.Content
	}
	s.mu.Unlock()
	return s.Session.RunCell(ctx, req)
}

func (s *labSession) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := sandbox.ProjectResult{Sandbox: "fake-sessions", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted}
	src, ok := s.files["controller.js"]
	exit := 0
	if !ok {
		exit = 1
	}
	res.Steps = []sandbox.StepResult{{Command: req.Steps[0], ExitCode: exit}}
	if ok && len(req.Artifacts) == 1 && req.Artifacts[0] == "controller.js" {
		res.Artifacts = []sandbox.Artifact{{Path: "controller.js", Content: []byte(src)}}
	}
	return res, nil
}

// daemonFor serves l over Connect in memory, sessions on.
func daemonFor(t *testing.T, l *lab) string {
	t.Helper()
	svc := rpc.NewSandboxService(l)
	svc.Sessions = rpc.SessionConfig{MaxSessions: 8, Lifetime: time.Hour, IdleTimeout: time.Hour}
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	d := httptest.NewServer(mux)
	t.Cleanup(d.Close)
	return d.URL
}

// testJob is a small job on the easy course: two loops, a group from each and a control group.
func testJob(build int, imports map[string][]string) *Job {
	practice := []uint32{2711538435, 3107713414, 2893621486, 575937923, 3575332085, 1495601726, 324394184, 3874630936}
	c := CourseJob{ID: "easy", Label: "the easy course", Tag: "t1", Practice: practice,
		Loops: []Loop{{ID: "cheater", Label: "the cheater", Artifact: "loops/cheater.js", Recipe: "Match first obs to seed.", RecipeTokens: 7, Tokenizer: "test"},
			{ID: "honest", Label: "the honest loop", Artifact: "loops/honest.js", Recipe: "Fly well.", RecipeTokens: 3, Tokenizer: "test"}}}
	for _, g := range []struct{ id, from string }{{"cheater", "cheater"}, {"honest", "honest"}, {"none", ""}} {
		c.Groups = append(c.Groups, Group{ID: g.id, Label: g.id, From: g.from, Build: build, Import: imports[g.id]})
	}
	return &Job{Name: "test", Fresh: 16, Courses: []CourseJob{c}, Rebuild: Rebuild{Turns: 6, FlightsPerFly: 4}}
}

func writeImports(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The regrade path end to end against the in-memory lab: imported controllers graded, every
// call signed, the evidence derived from the bundle alone, the page rendered, -verify passing,
// and refusing the published files once one byte of the bundle changes.
func TestRegradeIsSignedAndVerifies(t *testing.T) {
	root := t.TempDir()
	memorizer := "// ONLY:" + "2711538435,3107713414,2893621486,575937923,3575332085,1495601726,324394184,3874630936" + "\nexport default () => ({})\n"
	files := map[string]string{"loops/cheater.js": memorizer, "loops/honest.js": "// ALL, the honest loop's own\n"}
	imports := map[string][]string{}
	for _, g := range []string{"cheater", "honest", "none"} {
		for i := range 7 {
			p := fmt.Sprintf("repro/%s/r%d.js", g, i)
			imports[g] = append(imports[g], p)
			if i == 6 && g == "cheater" {
				continue // a rebuild that produced no controller
			}
			files[p] = "// ALL rebuild\n"
		}
	}
	writeImports(t, root, files)
	job := testJob(0, imports)
	if err := job.check(); err != nil {
		t.Fatal(err)
	}
	l := &lab{Sessions: &sandboxtest.Sessions{}}
	out := filepath.Join(t.TempDir(), "page")
	if err := runAndPublish(context.Background(), job, root, out, daemonFor(t, l), "", "", 3, "", "", "NO_KEY_SET", 0, givenFresh{}); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublished(out, job); err != nil {
		t.Fatalf("the published files do not verify: %v", err)
	}
	page, err := os.ReadFile(filepath.Join(out, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	checkUniqueIDs(t, page)
	var ev Evidence
	raw, _ := os.ReadFile(filepath.Join(out, "evidence.json"))
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	c := ev.Courses[0]
	if c.Loops[0].Own == nil || c.Loops[0].Own.Practice != 8 || c.Loops[0].Own.Fresh != 0 {
		t.Fatalf("the memorizer: %+v", c.Loops[0].Own)
	}
	if v := c.Loops[0].Verdict; v == nil || !v.Memorized || v.Produced != 6 || v.Of != 7 || v.RebuildFresh != 16 {
		t.Fatalf("the memorizer's verdict: %+v", v)
	}
	if c.Groups[0].Missing != 1 || len(c.Groups[0].Rebuilds) != 6 {
		t.Fatalf("the cheater's group: %+v", c.Groups[0])
	}
	if !ev.Scan.SetsHeld || ev.Scan.GradingRuns != 2*(2+20) || len(ev.Scan.Hits) != 0 {
		t.Fatalf("scan %+v", ev.Scan)
	}
	if len(c.Tracks) != 2*2+3 {
		t.Fatalf("%d tracks, want two for each loop and one for each group", len(c.Tracks))
	}
	// Tampering: one byte of a stored response changes, and -verify refuses.
	z, err := os.Open(filepath.Join(out, bundleName))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(z)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	z.Close()
	tampered := bytes.Replace(b, []byte(`"response":"`), []byte(`"response":"A`), 1)
	if bytes.Equal(tampered, b) {
		t.Fatal("no response to tamper with")
	}
	if err := os.WriteFile(filepath.Join(out, "bundle.jsonl"), tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := compressBundle(out); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublished(out, job); err == nil {
		t.Fatal("a tampered bundle verified")
	}
}

// A built rebuild: a scripted model reads its brief, writes a controller, flies the smoke
// flights and new ones, flies one of those again, and answers. Its session holds the brief,
// and the leak scan finds nothing. A second run whose model writes a practice seed into its
// sandbox is caught by the scan, and -verify refuses it.
func TestBuiltRebuildsAreScanned(t *testing.T) {
	defer func(d time.Duration) { closeTimeout = d }(closeTimeout)
	closeTimeout = 250 * time.Millisecond
	for _, leak := range []bool{false, true} {
		t.Run(fmt.Sprintf("leak=%v", leak), func(t *testing.T) {
			var mu sync.Mutex
			fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct{ Messages []message }
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "bad", 400)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				tc := func(name string, args any) {
					b, _ := json.Marshal(args)
					call := map[string]any{"id": "c", "type": "function", "function": map[string]any{"name": name, "arguments": string(b)}}
					json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "tool_calls": []any{call}}}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 10}})
				}
				switch len(req.Messages) {
				case 2:
					src := "// ALL\nexport default function makeController() { return { step() { return { thrust: 0.5, roll: 0, pitch: 0, yawRate: 0 }; } }; }\n"
					if leak {
						src += "// 2711538435\n"
					}
					tc("write_file", map[string]string{"path": "controller.js", "content": src})
				case 4:
					tc("fly", map[string]any{"smoke": true, "count": 2})
				case 6:
					var res struct{ Flights []Flight }
					json.Unmarshal([]byte(req.Messages[5].Content), &res)
					if len(res.Flights) != 6 {
						http.Error(w, "fly did not answer with six flights: "+req.Messages[5].Content, 400)
						return
					}
					tc("fly", map[string]any{"again": []uint32{res.Flights[5].Seed}})
				case 8:
					tc("fly", map[string]any{"again": []int64{12345}})
				default:
					// The last turn outlasts the close's timeout, so a close deadline counted
					// from the open would run out before the close is sent.
					time.Sleep(2 * closeTimeout)
					json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "Done.\nSMOKE=4/4"}}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 10}})
				}
			}))
			t.Cleanup(fake.Close)
			t.Setenv("FAKE_MODEL_KEY", "k")
			root := t.TempDir()
			writeImports(t, root, map[string]string{"loops/cheater.js": "// ONLY:2711538435 the cheater's own\n", "loops/honest.js": "// ALL, the honest loop's own\n"})
			job := testJob(1, nil)
			l := &lab{Sessions: &sandboxtest.Sessions{}}
			out := filepath.Join(t.TempDir(), "page")
			err := runAndPublish(context.Background(), job, root, out, daemonFor(t, l), "", "", 2, "fake", fake.URL, "FAKE_MODEL_KEY", 100000, givenFresh{})
			if err != nil {
				t.Fatal(err)
			}
			var ev Evidence
			raw, _ := os.ReadFile(filepath.Join(out, "evidence.json"))
			if err := json.Unmarshal(raw, &ev); err != nil {
				t.Fatal(err)
			}
			if len(ev.Built) != 3 || ev.Sessions != 3 || ev.Usage.Calls != 15 {
				t.Fatalf("built %+v, %d sessions, usage %+v", ev.Built, ev.Sessions, ev.Usage)
			}
			for _, b := range ev.Built {
				if b.FlyCalls != 2 || b.Turns != 5 || !strings.Contains(b.Final, "SMOKE=4/4") {
					t.Fatalf("rebuild %+v", b)
				}
			}
			// A seed no fly call gave out is refused, and costs no practice run.
			if ev.Scan.PracticeRuns != 6 {
				t.Fatalf("%d practice runs, want two for each rebuild", ev.Scan.PracticeRuns)
			}
			for _, p := range l.projects {
				for _, f := range p.Files {
					if f.Path == "cases.json" && strings.Contains(f.Content, "12345") {
						t.Fatal("a seed the rebuild was never given was flown")
					}
				}
			}
			// The brief is the first call of every session, the recipe in it for a recipe group.
			briefs := 0
			entries, err := readBundle(out)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				var req plimsollv1.RunRequest
				if e.Request == nil || proto.Unmarshal(e.Request, &req) != nil {
					continue
				}
				for _, cf := range req.GetCell().GetFiles() {
					if cf.GetPath() == "BRIEF.md" && strings.Contains(cf.GetContent(), "SMOKE=<passed>/4") {
						briefs++
						if strings.HasPrefix(req.GetTraceId(), "sq.easy.cheater.") != strings.Contains(cf.GetContent(), "Match first obs to seed.") {
							t.Fatalf("%s: the brief and the recipe disagree", req.GetTraceId())
						}
					}
				}
			}
			if briefs != 3 {
				t.Fatalf("%d sessions hold their brief, want 3", briefs)
			}
			err = verifyPublished(out, job)
			if leak {
				if len(ev.Scan.Hits) != 9 || err == nil || !strings.Contains(err.Error(), "a practice seed of the easy course") {
					t.Fatalf("hits %v, verify %v", ev.Scan.Hits, err)
				}
			} else if err != nil || len(ev.Scan.Hits) != 0 {
				t.Fatalf("verify %v, hits %v", err, ev.Scan.Hits)
			}
		})
	}
}

// A job that builds rebuilds starts nothing without the model's key, and nothing without a
// token budget: no spend by accident.
func TestBuildingNeedsAKeyAndABudget(t *testing.T) {
	job := testJob(1, nil)
	if err := runAndPublish(context.Background(), job, "", t.TempDir(), "http://127.0.0.1:1", "", "", 1, "m", "http://127.0.0.1:1", "SQUEEZE_TEST_UNSET_KEY", 1000, givenFresh{}); err != errNoModel {
		t.Fatalf("no key: %v", err)
	}
	t.Setenv("SQUEEZE_TEST_KEY", "k")
	if err := runAndPublish(context.Background(), job, "", t.TempDir(), "http://127.0.0.1:1", "", "", 1, "m", "http://127.0.0.1:1", "SQUEEZE_TEST_KEY", 0, givenFresh{}); err == nil || !strings.Contains(err.Error(), "-max-tokens") {
		t.Fatalf("no budget: %v", err)
	}
}

// The course flies for real: the hand-written baseline (not agent code) on two smoke flights,
// with node, when this machine has one. It checks the port runs, reports CPU per flight, and
// that a controller's source is validated before any flight.
func TestCourseFliesTheBaseline(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on this machine")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the CPU budget reads /proc, which only Linux has")
	}
	dir := t.TempDir()
	files, err := simulatorFiles("easy")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, sandbox.File{Path: "controller.js", Content: courseFile("baselines/stabilizer.js")},
		sandbox.File{Path: "cases.json", Content: string(SealedSet{Seeds: smokeSeeds("easy")[:2]}.encode())},
		sandbox.File{Path: "bad.js", Content: "export default () => process.exit(0)\n"})
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.Path), []byte(f.Content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(controller string) FlightSet {
		cmd := exec.Command(node, "fly.mjs", controller, "cases.json", "--cpu-budget", "1")
		cmd.Dir = dir
		out, _ := cmd.Output()
		fs, err := parseFlights(out)
		if err != nil {
			t.Fatalf("%s: %v (%s)", controller, err, out)
		}
		return fs
	}
	fs := run("controller.js")
	if !fs.Valid && strings.Contains(fs.Error, "permission model") {
		t.Skip("this node has no permission model (Node 20 or later has it): " + fs.Error)
	}
	if !fs.Valid || fs.Total != 2 || len(fs.Results) != 2 {
		t.Fatalf("the baseline: %+v", fs)
	}
	for _, r := range fs.Results {
		if r.SimulatedSeconds <= 0 || r.CPUSeconds <= 0 || r.CPUSeconds > 1 {
			t.Fatalf("flight %+v", r)
		}
	}
	if bad := run("bad.js"); bad.Valid || !strings.Contains(bad.Error, "forbidden source token") {
		t.Fatalf("a controller naming process: %+v", bad)
	}
}

// Every sealed seed is a nine- or ten-digit number, none a practice or smoke seed.
func TestSealFresh(t *testing.T) {
	avoid := map[uint32]bool{4000000000: true}
	s, err := sealFresh(64, avoid)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint32]bool{}
	for _, x := range s.Seeds {
		if x < 100_000_000 || avoid[x] || seen[x] {
			t.Fatalf("seed %d", x)
		}
		seen[x] = true
	}
	if len(s.Nonce) != 64 || len(s.Seeds) != 64 {
		t.Fatalf("%+v", s)
	}
}

// A run given an earlier run's fresh set (-fresh, with -loops-only) flies the loops on exactly
// that file: the same bytes and digest, the same flights, marked as given in run.json, and it
// verifies. Such runs published in sets/ beside a page give each loop's score on every set and
// say whether a set flown twice landed the same flights. A set whose digest is not the one named,
// that is not the file this program writes, that is the wrong size, or that holds a practice
// seed is refused before anything runs.
func TestFlyAgainOnAGivenSet(t *testing.T) {
	root := t.TempDir()
	writeImports(t, root, map[string]string{"loops/cheater.js": "// ONLY:2711538435\n", "loops/honest.js": "// the honest loop's own\n",
		"repro/none/r0.js": "// ALL rebuild\n"})
	job := testJob(0, map[string][]string{"cheater": {"repro/none/r0.js"}, "honest": {"repro/none/r0.js"}, "none": {"repro/none/r0.js"}})
	first := filepath.Join(t.TempDir(), "first")
	if err := runAndPublish(context.Background(), job, root, first, daemonFor(t, &lab{Sessions: &sandboxtest.Sessions{}}), "", "", 2, "", "", "NO_KEY_SET", 0, givenFresh{}); err != nil {
		t.Fatal(err)
	}
	var rf1 RunFile
	if err := readJSON(filepath.Join(first, "run.json"), &rf1); err != nil {
		t.Fatal(err)
	}
	set := filepath.Join(first, "fresh.json")
	loops := job.loopsOnly()
	again := filepath.Join(t.TempDir(), "again")
	if err := runAndPublish(context.Background(), loops, root, again, daemonFor(t, &lab{Sessions: &sandboxtest.Sessions{}}), "", "", 2, "", "", "NO_KEY_SET", 0, givenFresh{path: set, sha256: rf1.FreshSHA256}); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublished(again, loops); err != nil {
		t.Fatalf("the run on the given set does not verify: %v", err)
	}
	b1, _ := os.ReadFile(set)
	b2, _ := os.ReadFile(filepath.Join(again, "fresh.json"))
	var rf2 RunFile
	if err := readJSON(filepath.Join(again, "run.json"), &rf2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) || rf2.FreshSHA256 != rf1.FreshSHA256 || !rf2.FreshGiven || rf1.FreshGiven || rf2.Job != "test-loops" {
		t.Fatalf("given set: same bytes %v, digests %s and %s, given %v and %v, job %q", bytes.Equal(b1, b2), rf1.FreshSHA256, rf2.FreshSHA256, rf1.FreshGiven, rf2.FreshGiven, rf2.Job)
	}
	page, err := os.ReadFile(filepath.Join(again, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range []string{"sealed for this run", "drawn for this page", "drawn for this run"} {
		if bytes.Contains(page, []byte(claim)) {
			t.Errorf("the page of a run on an earlier run's set says %q", claim)
		}
	}
	ev1, err := derive(first, job)
	if err != nil {
		t.Fatal(err)
	}
	ev2, err := derive(again, loops)
	if err != nil {
		t.Fatal(err)
	}
	if ev2.Scan.GradingRuns != 2*2 || len(ev2.Courses[0].Groups) != 0 {
		t.Fatalf("a loops-only run graded %d runs and has groups %+v", ev2.Scan.GradingRuns, ev2.Courses[0].Groups)
	}
	for i, l := range ev1.Courses[0].Loops {
		if a, b := l.Own, ev2.Courses[0].Loops[i].Own; a.FreshBits != b.FreshBits || a.PracticeBits != b.PracticeBits {
			t.Errorf("loop %s: fresh %s then %s, practice %s then %s", l.ID, a.FreshBits, b.FreshBits, a.PracticeBits, b.PracticeBits)
		}
	}

	// The loops flown again, published beside the first run's page in sets/: on its own set, and
	// on a set drawn for another run. The page states each loop on both, and verifies.
	other := filepath.Join(t.TempDir(), "other")
	if err := runAndPublish(context.Background(), loops, root, other, daemonFor(t, &lab{Sessions: &sandboxtest.Sessions{}}), "", "", 2, "", "", "NO_KEY_SET", 0, givenFresh{}); err != nil {
		t.Fatal(err)
	}
	copyRun := func(from, name string) string {
		to := filepath.Join(first, setsDir, name)
		if err := os.MkdirAll(to, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, n := range runFiles {
			b, err := os.ReadFile(filepath.Join(from, n))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(to, n), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return to
	}
	copyRun(again, "again")
	copyRun(other, "other")
	if err := renderPublished(first, job); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublished(first, job); err != nil {
		t.Fatalf("the page with its sets does not verify: %v", err)
	}
	ev, err := derive(first, job)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Sets) != 2 || !ev.Sets[0].Page || ev.Sets[0].SHA256 != rf1.FreshSHA256 || fmt.Sprint(ev.Sets[0].Runs) != "[page again]" ||
		ev.Sets[1].Page || fmt.Sprint(ev.Sets[1].Runs) != "[other]" || len(ev.Sets[0].Loops) != 2 || !ev.Sets[0].Loops[1].Same {
		t.Fatalf("sets: %+v", ev.Sets)
	}
	honest := ev.Sets[0].Loops[1]
	if honest.Loop != "honest" || honest.Fresh[0] != honest.Fresh[1] || honest.Fresh[0] != ev1.Courses[0].Loops[1].Own.Fresh {
		t.Fatalf("the honest loop on the page's set: %+v", honest)
	}
	page, err = os.ReadFile(filepath.Join(first, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte(" on two sets</span>")) || !bytes.Contains(page, []byte("<code>sets/</code>")) {
		t.Error("the page does not show the loops on both sets")
	}
	// A run of the whole job in sets/ is not the loops flown again, and is refused.
	full := copyRun(first, "full")
	if _, err := derive(first, job); err == nil || !strings.Contains(err.Error(), "is a run of") {
		t.Fatalf("a whole run in sets/: %v", err)
	}
	if err := os.RemoveAll(full); err != nil {
		t.Fatal(err)
	}
	// A grader that ends one flight the other way the second time is caught: the set's runs
	// do not land the same flights.
	var fs SealedSet
	if err := readJSON(set, &fs); err != nil {
		t.Fatal(err)
	}
	flipped := filepath.Join(t.TempDir(), "flipped")
	if err := runAndPublish(context.Background(), loops, root, flipped, daemonFor(t, &lab{Sessions: &sandboxtest.Sessions{}, flip: fs.Seeds[3]}), "", "", 2, "", "", "NO_KEY_SET", 0, givenFresh{path: set, sha256: rf1.FreshSHA256}); err != nil {
		t.Fatal(err)
	}
	copyRun(flipped, "flipped")
	if ev, err = derive(first, job); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(ev.Sets[0].Runs) != "[page again flipped]" || ev.Sets[0].Loops[0].Same || ev.Sets[0].Loops[1].Same || !ev.Sets[1].Loops[1].Same {
		t.Fatalf("a set flown with a flight ending the other way: %+v", ev.Sets)
	}

	avoid := map[uint32]bool{job.Courses[0].Practice[0]: true}
	write := func(name string, b []byte) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, _, err := loadFresh(givenFresh{path: set, sha256: rf1.FreshSHA256}, 16, avoid); err != nil {
		t.Fatalf("the earlier run's set: %v", err)
	}
	var s SealedSet
	if err := json.Unmarshal(b1, &s); err != nil {
		t.Fatal(err)
	}
	compact, _ := json.Marshal(s)
	withPractice := s
	withPractice.Seeds = append([]uint32{job.Courses[0].Practice[0]}, s.Seeds[1:]...)
	for name, g := range map[string]givenFresh{
		"another digest":  {path: set, sha256: strings.Repeat("0", 64)},
		"no digest":       {path: set, sha256: "fresh"},
		"other bytes":     {path: write("compact.json", compact), sha256: digest(compact)},
		"a practice seed": {path: write("practice.json", withPractice.encode()), sha256: digest(withPractice.encode())},
	} {
		if _, _, err := loadFresh(g, 16, avoid); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, _, err := loadFresh(givenFresh{path: set, sha256: rf1.FreshSHA256}, 64, avoid); err == nil {
		t.Error("a set of 16 loaded for a job of 64")
	}
}

// The scan finds a seed as a whole number only.
func TestNeedleMatchesWholeNumbers(t *testing.T) {
	n := needle{text: "575937923", digit: true}
	for s, want := range map[string]bool{"x 575937923;": true, "1575937923": false, "5759379234": false, "575937923": true, "a=575937923,b": true} {
		if got := n.find(s); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}

// checkUniqueIDs fails on an element ID the page uses twice, in its markup or in the elements
// its script makes. getElementById returns the first, so a heading and a figure sharing an ID
// leave the figure blank with no error (three figures and the line's slider did, 2026-10-27).
func checkUniqueIDs(t *testing.T, page []byte) {
	t.Helper()
	seen := map[string]int{}
	for _, re := range []*regexp.Regexp{regexp.MustCompile(`\sid="([^"]+)"`), regexp.MustCompile(`\bid: '([^']+)'`)} {
		for _, m := range re.FindAllSubmatch(page, -1) {
			seen[string(m[1])]++
		}
	}
	if len(seen) < 20 {
		t.Fatalf("found only %d IDs; the pattern no longer matches the page", len(seen))
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("the page uses the ID %q %d times", id, n)
		}
	}
}

// The published page is what the committed bundle renders, and the published run is the one the
// README and the page describe: 192 grading runs on the sealed sets with no failure, the
// hackathon's practice score for every one of the 95 controllers plimsoll could score, the loops'
// fresh scores 0, 62, 14 and 56, one controller whose 16 flights the CPU budget ended, and the
// loops flown again on three sets in sets/.
func TestPublishedFilesVerify(t *testing.T) {
	const published = "../../docs/examples/squeeze"
	job, err := loadJob(filepath.Join("jobs", "hackathon-regrade.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPublished(published, job); err != nil {
		t.Fatalf("%v; run go run ./examples/squeeze -render", err)
	}
	page, err := os.ReadFile(filepath.Join(published, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	checkUniqueIDs(t, page)
	ev, err := derive(published, job)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Scan.GradingRuns != 192 || !ev.Scan.SetsHeld || len(ev.Failures) != 0 || ev.CPUEnded != 16 || len(ev.CPUEndedBy) != 1 {
		t.Errorf("grading runs %d, sets held %v, failures %v, flights the budget ended %d by %v",
			ev.Scan.GradingRuns, ev.Scan.SetsHeld, ev.Failures, ev.CPUEnded, ev.CPUEndedBy)
	}
	hk, err := loadHackathon()
	if err != nil {
		t.Fatal(err)
	}
	if a := (pageData{Ev: ev, HK: hk}).Agreement(); a.Same != 95 || a.Total != 95 {
		t.Errorf("practice scores agree for %d of %d controllers: %+v", a.Same, a.Total, a.Diffs)
	}
	var fresh []int
	for _, c := range ev.Courses {
		for _, l := range c.Loops {
			fresh = append(fresh, l.Own.Fresh)
		}
	}
	if fmt.Sprint(fresh) != "[0 62 14 56]" {
		t.Errorf("the loops' fresh scores: %v", fresh)
	}
	// sets/: the four loops flown again twice on the page's set and on two other sets of 64
	// (2026-10-29). Every run of a set landed the same flights; the hard course's honest loop
	// landed 56, 48 and 62.
	var runs []string
	for _, set := range ev.Sets {
		runs = append(runs, fmt.Sprint(len(set.Runs)))
		for _, l := range set.Loops {
			if !l.Same {
				t.Errorf("set %s: the %s %s loop's runs landed different flights: %v", set.SHA256[:12], l.Course, l.Loop, l.Fresh)
			}
		}
	}
	if fmt.Sprint(runs) != "[3 2 2]" || !ev.Sets[0].Page {
		t.Errorf("sets: %+v", ev.Sets)
	}
	if sp := (pageData{Ev: ev, HK: hk}).Spread("hard", "honest"); sp == nil || fmt.Sprint(sp.Counts) != "[56 48 62]" || !sp.Same || sp.FewestRuns != 2 {
		t.Errorf("the hard course's honest loop across the sets: %+v", sp)
	}
}

// The Argon scan the page quotes: one find, the viewer file at 12:44, for the second practice
// seed of the job's easy course; the 12:55 files clean; and the entry's own check named the
// first practice seed, which is what the page says it looked for. With SQUEEZE_DID_IT_LEARN
// naming a did-it-learn checkout, the script is run again and must print the transcript
// exactly (it needs git, Go and Python 3, and writes under tmp/argon-scan/).
func TestArgonScanTranscript(t *testing.T) {
	a, err := parseArgonScan(argonScanTxt)
	if err != nil {
		t.Fatal(err)
	}
	job, err := loadJob(filepath.Join("jobs", "hackathon-regrade.json"))
	if err != nil {
		t.Fatal(err)
	}
	practice := job.Courses[0].Practice
	if len(a.Finds) != 1 || a.Finds[0] != (ArgonFind{Label: "seeds.txt:2", Mode: "refuse", File: "tasks/drone/view.mjs"}) {
		t.Fatalf("finds: %+v", a.Finds)
	}
	if a.Shipped != 13 || a.CleanFiles != a.Shipped {
		t.Fatalf("shipped %d, clean %d", a.Shipped, a.CleanFiles)
	}
	if a.Seed != strconv.FormatUint(uint64(practice[1]), 10) || !strings.Contains(argonScanTxt, "seed-"+a.Seed+".json") {
		t.Fatalf("the found seed %q is not the job's second practice seed %d in a track name", a.Seed, practice[1])
	}
	if !strings.Contains(argonScanTxt, `assert "VALIDATION_SEEDS" not in text and "`+strconv.FormatUint(uint64(practice[0]), 10)+`" not in text`) {
		t.Fatal("the entry's own check, naming the first practice seed, is not in the transcript")
	}
	repo := os.Getenv("SQUEEZE_DID_IT_LEARN")
	if repo == "" {
		t.Log("SQUEEZE_DID_IT_LEARN not set: the transcript is checked, the scan not rerun")
		return
	}
	abs, err := filepath.Abs(repo)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "examples/squeeze/argon-scan.sh", abs)
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("argon-scan.sh: %v", err)
	}
	if string(out) != argonScanTxt {
		t.Fatalf("argon-scan.sh printed something other than argon-scan.txt:\n%s", out)
	}
}

// The canary transcript the page quotes: the stand-in harness's clean run passes, and each of
// the three runs after it fails for the reason the page names: the reference's step time in
// the prompt, the planted clip uploaded under its plan name (shown by an alias, never the
// marker), and a harness that planted nothing, so no place was tested. With
// SQUEEZE_RERUN_CANARY=1 the script is run again (it needs Python 3 and writes under
// tmp/canary-demo/) and must print the transcript exactly: the markers are random, and the
// check never prints one.
func TestCanaryDemoTranscript(t *testing.T) {
	c, err := parseCanaryDemo(canaryDemoTxt)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Checks) != 4 {
		t.Fatalf("%d checks, want 4: %+v", len(c.Checks), c.Checks)
	}
	if k := c.Checks[1]; k.Requests != "run-2" || len(k.Found) != 1 || k.Found[0] != "run-2/0001.json: $.messages[0].content: sealed value reference-times/number (number)" {
		t.Errorf("the leaked step time: %+v", k)
	}
	if k := c.Checks[2]; k.Requests != "run-3" || len(k.Found) != 1 || k.Found[0] != "run-3/<name 1>: (file name): sealed value plan-names/text (text)" {
		t.Errorf("the clip uploaded under its plan name: %+v", k)
	}
	if k := c.Checks[3]; k.Planted != "not-planted" || len(k.Found) != 3 {
		t.Errorf("the harness that planted nothing: %+v", k)
	} else {
		for i, place := range []string{"truth", "reference-times", "plan-names"} {
			if k.Found[i] != "not planted: no marker of place "+place+" is in any hidden file, so that place was not tested" {
				t.Errorf("not planted, line %d: %q", i, k.Found[i])
			}
		}
	}
	if regexp.MustCompile(`cnry[0-9a-z]{12}`).MatchString(canaryDemoTxt) {
		t.Error("the transcript prints a marker")
	}
	if os.Getenv("SQUEEZE_RERUN_CANARY") != "1" {
		t.Log("SQUEEZE_RERUN_CANARY not set: the transcript is checked, the script not rerun")
		return
	}
	if _, err := os.Stat("canary-demo.sh"); errors.Is(err, os.ErrNotExist) {
		t.Skip("canary-demo.sh is not in this checkout: the canary check is not part of the open-source release")
	}
	cmd := exec.Command("sh", "examples/squeeze/canary-demo.sh")
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("canary-demo.sh: %v", err)
	}
	if string(out) != canaryDemoTxt {
		t.Fatalf("canary-demo.sh printed something other than canary-demo.txt:\n%s", out)
	}
}

// TestFlightPlaybackKeepsToOneClock pins the Play button's fix. A frame's
// timestamp is when the frame began, so it can be earlier than a
// performance.now() read in the click that asked for it; the difference then
// gave position -1 and the drawing threw with the room half drawn. The first
// frame sets the start instead, and no start time comes from another clock.
func TestFlightPlaybackKeepsToOneClock(t *testing.T) {
	page, err := os.ReadFile("page.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "if (t0 === null) t0 = ts;") {
		t.Error("playback must take its start from the first frame's timestamp")
	}
	if strings.Contains(string(page), "t0 = performance.now()") {
		t.Error("playback must not start from performance.now(): a frame can be stamped before it")
	}
}

// The drone video and its caption state numbers from one published flight, baked into the
// picture, so a new run has to redraw them: this fails until it does.
func TestDroneVideoMatchesTheRecord(t *testing.T) {
	raw, err := os.ReadFile("../../docs/examples/squeeze/evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	var ev struct {
		Courses []struct {
			ID     string `json:"id"`
			Tracks []struct {
				N, Who, Set, End string
				Seed             uint64
				Success          bool
				Seconds          float64
			} `json:"tracks"`
			Loops []struct {
				ID  string `json:"id"`
				Own struct {
					Practice      int `json:"practice"`
					PracticeTotal int `json:"practice_total"`
					Fresh         int `json:"fresh"`
					FreshTotal    int `json:"fresh_total"`
				} `json:"own"`
			} `json:"loops"`
		} `json:"courses"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		seconds float64
		success bool
		fresh   int
	}{"honest": {13.84, true, 56}, "cheater": {0.93, false, 14}}
	seen := 0
	for _, c := range ev.Courses {
		if c.ID != "hard" {
			continue
		}
		for _, tr := range c.Tracks {
			w, ok := want[tr.Who]
			if !ok || tr.N != "loop" || tr.Set != "fresh" {
				continue
			}
			seen++
			if tr.Seed != 2430153746 || tr.Seconds != w.seconds || tr.Success != w.success {
				t.Errorf("%s: seed %d, %v s, success %v; the video shows seed 2430153746, %v s, success %v", tr.Who, tr.Seed, tr.Seconds, tr.Success, w.seconds, w.success)
			}
		}
		for _, l := range c.Loops {
			seen++
			if l.Own.Practice != 16 || l.Own.PracticeTotal != 16 || l.Own.Fresh != want[l.ID].fresh || l.Own.FreshTotal != 64 {
				t.Errorf("%s: %+v; the video says 16 of 16 and %d of 64", l.ID, l.Own, want[l.ID].fresh)
			}
		}
	}
	if seen != 4 {
		t.Fatalf("found %d of the 4 records the video rests on", seen)
	}
	page, err := os.ReadFile("../../docs/examples/squeeze/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`src="drone-flight.mp4"`, "lands at 13.84 s", "hits the wall at 0.93 s", "they landed 56 and 14"} {
		if !bytes.Contains(page, []byte(s)) {
			t.Errorf("the page lacks %q", s)
		}
	}
}
