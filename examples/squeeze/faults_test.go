package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// A set is graded in parts of at most gradeChunk flights that together are the set, in order,
// none empty; a set that fits one run is graded whole, its own file.
func TestSetPartsCoverTheSet(t *testing.T) {
	for n := 1; n <= 512; n++ {
		s := SealedSet{Name: "fresh", Seeds: make([]uint32, n)}
		for i := range s.Seeds {
			s.Seeds[i] = uint32(1_000_000_000 + i)
		}
		parts := setParts("fresh", s, s.encode())
		if n <= gradeChunk {
			if len(parts) != 1 || parts[0].purpose != "fresh" || string(parts[0].file) != string(s.encode()) {
				t.Fatalf("%d flights: %+v", n, parts)
			}
			continue
		}
		var all []uint32
		for k, p := range parts {
			var got SealedSet
			if err := json.Unmarshal(p.file, &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Seeds) == 0 || len(got.Seeds) > gradeChunk || !partPattern.MatchString(p.purpose) || !strings.HasPrefix(p.purpose, "fresh-") {
				t.Fatalf("%d flights, part %d: %q holds %d", n, k+1, p.purpose, len(got.Seeds))
			}
			all = append(all, got.Seeds...)
		}
		if !slices.Equal(all, s.Seeds) {
			t.Fatalf("%d flights: the parts are not the set", n)
		}
	}
}

// Three ways an agent's attempt can end without a score of its own, kept apart: a controller
// whose grading run ran out of time is the grading's failure (agents.json says why, and it is not
// read as 0 landed); a controller the course's validator refuses is the controller's own (0 by
// rule); a session a sandbox call ended with no answer is a harness fault (its ending says so).
// The run publishes every file and exits non-zero, naming what it lost.
func TestGradingAndHarnessFaultsAreKeptApart(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Messages []chatMessage }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		reply := func(msg map[string]any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": msg}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 10}})
		}
		call := func(name string, args any) {
			b, _ := json.Marshal(args)
			reply(map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "c", "type": "function", "function": map[string]any{"name": name, "arguments": string(b)}}}})
		}
		if len(req.Messages) != 2 {
			reply(map[string]any{"role": "assistant", "content": "Done.\nSMOKE=0/4"})
			return
		}
		brief := req.Messages[1].Content
		switch {
		case strings.Contains(brief, "Match first obs to seed."): // cheater: a slow controller
			call("write_file", map[string]string{"path": "controller.js", "content": "// SLOW but legal\nexport default () => ({})\n"})
		case strings.Contains(brief, "Fly well."): // honest: a controller the validator refuses
			call("write_file", map[string]string{"path": "controller.js", "content": "// INVALID\nexport default () => ({})\n"})
		default: // none: a call the sandbox fails
			call("run_code", map[string]string{"language": "javascript", "code": "//lab-fail"})
		}
	}))
	t.Cleanup(fake.Close)
	t.Setenv("FAKE_MODEL_KEY", "k")
	root := t.TempDir()
	writeImports(t, root, map[string]string{"loops/cheater.js": "// ONLY:2711538435\n", "loops/honest.js": "// ALL\n"})
	job := testJob(1, nil)
	l := &lab{Sessions: &sandboxtest.Sessions{}, slow: func(controller, cases string) bool {
		return strings.Contains(controller, "SLOW") && strings.Contains(cases, `"fresh 2 of 2"`)
	}}
	out := filepath.Join(t.TempDir(), "page")
	err := runAndPublish(context.Background(), job, root, out, daemonFor(t, l), "", "", 2, modelOpts{api: "chat", model: "fake", base: fake.URL, keyEnv: "FAKE_MODEL_KEY", maxTokens: 100000}, givenFresh{})
	if !errors.Is(err, errIncomplete) {
		t.Fatalf("a run that lost a session exited with %v, want errIncomplete", err)
	}
	var agents []AgentRecord
	raw, err := os.ReadFile(filepath.Join(out, "agents.json"))
	if err != nil {
		t.Fatalf("the incomplete run's files were not published: %v", err)
	}
	if err := json.Unmarshal(raw, &agents); err != nil {
		t.Fatal(err)
	}
	by := map[string]AgentRecord{}
	for _, a := range agents {
		by[a.Group] = a
	}
	slow, invalid, fault := by["cheater"], by["honest"], by["none"]
	if !slow.Graded || slow.Valid || slow.Invalid || !strings.Contains(slow.GradeProblem, "run 2 of 2: the run's time ran out") {
		t.Fatalf("the slow controller: %+v", slow)
	}
	if !invalid.Graded || invalid.Valid || !invalid.Invalid || invalid.GradeProblem != "" {
		t.Fatalf("the refused controller: %+v", invalid)
	}
	if fault.Ended != endHarnessFault || fault.BuildProblem == "" || fault.Controller != "" {
		t.Fatalf("the faulted session: %+v", fault)
	}
	var rf RunFile
	if err := readJSON(filepath.Join(out, "run.json"), &rf); err != nil {
		t.Fatal(err)
	}
	if rf.Harness.From != "git" || len(rf.Harness.Commit) != 40 {
		t.Fatalf("run.json does not name the harness's commit: %+v", rf.Harness)
	}
	for _, b := range rf.Built {
		if (b.Group == "none") != (b.Ended == endHarnessFault) {
			t.Fatalf("run.json: %+v", b)
		}
	}
	if err := verifyPublished(out, job); err != nil {
		t.Fatalf("an incomplete run's files must still verify: %v", err)
	}
}

// The recipe items measure is recipe words named in code: an item counts when a pattern matches
// an identifier the shared baseline does not hold. The audit's cases (squeeze-recipe-8): the
// baseline names one item itself (its altitude integral, integralY) and scores 0 once its
// identifiers are left out; Number.isInteger is not an integral and speedSmooth is not a
// setpoint filter; a thrust ramp and any abort still count, as words named; an unnamed filter,
// vFilt and windEst are misses, which a word measure cannot see.
func TestRecipeItemsAreWordsNamedInCode(t *testing.T) {
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	l, ok := courseItems(job.Courses[0])
	if !ok {
		t.Fatal("the job's course lists no recipe items")
	}
	base := stripComments(courseFile("baselines/stabilizer.js"))
	skip := baselineIdentifiers()
	if raw := itemsNamed(l.Items, base, nil); !slices.Equal(raw, []string{"yaw + local pos integrals"}) {
		t.Fatalf("the baseline by the raw patterns names %v", raw)
	}
	for _, c := range []struct {
		code string
		want []string
	}{
		{base, nil},
		{base + "\nlet yawIntegral = 0;\n", []string{"yaw + local pos integrals"}},
		{"if (Number.isInteger(k)) k++;", nil},
		{"let speedSmooth = 0;", nil},
		{"let spFilt = 0, targetSmooth = 0;", []string{"smooth ref filter"}},
		{"const thrust = ramp(t);", []string{"ramp pad descent"}},
		{"let abortLanding = false;", []string{"predictive cross abort"}},
		{"v = 0.8 * v + 0.2 * obs.vel.x;", nil},
		{"let vFilt = 0, windEst = 0;", nil},
		{stripComments("// velocity filter, disturbance observer\nlet x = 0;"), nil},
		{"let velFilter = 0, disturbanceObserver = 0, gateLatch = false, descentRate = 0.2;",
			[]string{"Filter velocity", "fast/slow accel disturbance observer", "gate exit lock", "ramp pad descent"}},
	} {
		got := itemsNamed(l.Items, c.code, skip)
		if !slices.Equal(got, append([]string{}, c.want...)) {
			t.Errorf("%q names %v, want %v", c.code[:min(len(c.code), 60)], got, c.want)
		}
	}
}

// A run stopped part way (a signal, or the machine) keeps what it made: every finished agent's
// transcript was saved as it ended, and the staging directory, its signed bundle in it, is kept
// beside -out as <out>.failed-<time> instead of deleted.
func TestAStoppedRunKeepsWhatItMade(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Messages []chatMessage }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		if !strings.Contains(req.Messages[1].Content, "Match first obs to seed.") {
			cancel() // the second agent's first call: the run is stopped, as an interrupt stops it
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "Done.\nSMOKE=0/4"}}},
			"usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 10}})
	}))
	t.Cleanup(fake.Close)
	t.Setenv("FAKE_MODEL_KEY", "k")
	root := t.TempDir()
	writeImports(t, root, map[string]string{"loops/cheater.js": "// ONLY:2711538435\n", "loops/honest.js": "// ALL\n"})
	l := &lab{Sessions: &sandboxtest.Sessions{}}
	out := filepath.Join(t.TempDir(), "baseline")
	err := runAndPublish(ctx, testJob(1, nil), root, out, daemonFor(t, l), "", "", 1, modelOpts{api: "chat", model: "fake", base: fake.URL, keyEnv: "FAKE_MODEL_KEY", maxTokens: 100000}, givenFresh{})
	if err == nil || !strings.Contains(err.Error(), ".failed-") {
		t.Fatalf("a stopped run: %v", err)
	}
	kept, _ := filepath.Glob(out + ".failed-*")
	if len(kept) != 1 {
		t.Fatalf("kept %v", kept)
	}
	if fi, err := os.Stat(filepath.Join(kept[0], "bundle.jsonl")); err != nil || fi.Size() == 0 {
		t.Fatalf("the signed bundle was not kept: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(kept[0], partialTranscripts))
	if err != nil {
		t.Fatal(err)
	}
	var first Transcript
	if err := json.Unmarshal([]byte(strings.SplitN(string(raw), "\n", 2)[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first.Group != "cheater" || first.Ended != "answered" {
		t.Fatalf("the agent that finished before the stop: %+v", first)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a stopped run published %s", out)
	}
}

// A controller whose grading failed is graded again with no model call (-regrade): on the run's
// own sets, signed by a key of the regrade's own into regrades/<name>/; agents.json then takes its
// scores from there and says which regrade, -verify checks the regrade's bundle, and a second
// regrade finds nothing to do.
func TestARegradeRecoversAFailedGrading(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Messages []chatMessage }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		msg := map[string]any{"role": "assistant", "content": "Done.\nSMOKE=4/4"}
		if len(req.Messages) == 2 {
			src := "// ALL\nexport default () => ({})\n"
			if strings.Contains(req.Messages[1].Content, "Match first obs to seed.") {
				src = "// SLOW but legal, ALL\nexport default () => ({})\n"
			}
			b, _ := json.Marshal(map[string]string{"path": "controller.js", "content": src})
			msg = map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "c", "type": "function", "function": map[string]any{"name": "write_file", "arguments": string(b)}}}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": msg}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 10}})
	}))
	t.Cleanup(fake.Close)
	t.Setenv("FAKE_MODEL_KEY", "k")
	root := t.TempDir()
	writeImports(t, root, map[string]string{"loops/cheater.js": "// ONLY:2711538435\n", "loops/honest.js": "// ALL, the honest loop's own\n"})
	job := testJob(1, nil)
	slow := &lab{Sessions: &sandboxtest.Sessions{}, slow: func(controller, cases string) bool {
		return strings.Contains(controller, "SLOW") && strings.Contains(cases, `"fresh 2 of 2"`)
	}}
	out := filepath.Join(t.TempDir(), "page")
	if err := runAndPublish(context.Background(), job, root, out, daemonFor(t, slow), "", "", 2, modelOpts{api: "chat", model: "fake", base: fake.URL, keyEnv: "FAKE_MODEL_KEY", maxTokens: 100000}, givenFresh{}); err != nil {
		t.Fatal(err)
	}
	agent := func(group string) AgentRecord {
		t.Helper()
		var agents []AgentRecord
		if err := readJSON(filepath.Join(out, "agents.json"), &agents); err != nil {
			t.Fatal(err)
		}
		for _, a := range agents {
			if a.Group == group {
				return a
			}
		}
		t.Fatalf("no agent of group %s", group)
		return AgentRecord{}
	}
	if a := agent("cheater"); a.GradeProblem == "" || a.Valid {
		t.Fatalf("before the regrade: %+v", a)
	}
	steady := &lab{Sessions: &sandboxtest.Sessions{}}
	if err := regradePublished(context.Background(), out, job, daemonFor(t, steady), "", "", 2); err != nil {
		t.Fatal(err)
	}
	a := agent("cheater")
	if a.GradeProblem != "" || !a.Valid || a.Regraded == "" || a.Fresh != 16 || a.FreshTotal != 16 {
		t.Fatalf("after the regrade: %+v", a)
	}
	if other := agent("honest"); other.Regraded != "" {
		t.Fatalf("a controller graded whole was regraded: %+v", other)
	}
	if len(steady.projects) != 1+2 {
		t.Fatalf("the regrade ran %d grading runs; want the one controller's practice run and its two fresh parts", len(steady.projects))
	}
	if err := verifyPublished(out, job); err != nil {
		t.Fatalf("a regraded run must verify: %v", err)
	}
	if err := regradePublished(context.Background(), out, job, daemonFor(t, steady), "", "", 2); err != nil || len(steady.projects) != 3 {
		t.Fatalf("a second regrade: %v, %d runs", err, len(steady.projects))
	}
}
