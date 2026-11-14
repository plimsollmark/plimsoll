package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

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
// an identifier the shared baseline does not hold. The audit's cases: the
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

// cleanTree stands for a checkout whose code is a commit's, whatever this checkout holds, until
// the test ends.
func cleanTree(t *testing.T) {
	t.Helper()
	saved := harnessTree
	harnessTree = func() Tree { return Tree{Commit: strings.Repeat("c", 40), Clean: true, From: "test"} }
	t.Cleanup(func() { harnessTree = saved })
}

// failedGrading publishes a building run of two agents into a new directory, one of whose
// controllers (the cheater's, which runs slow on the fresh set's second part) has a grading that
// failed.
func failedGrading(t *testing.T) (string, *Job) {
	t.Helper()
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
	return out, job
}

// agentOf is the agents.json record of dir's agent of group.
func agentOf(t *testing.T, dir, group string) AgentRecord {
	t.Helper()
	var agents []AgentRecord
	if err := readJSON(filepath.Join(dir, "agents.json"), &agents); err != nil {
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

// A controller whose grading failed is graded again with no model call (-regrade): on the run's
// own sets, signed by a key of the regrade's own into regrades/<name>/; agents.json then takes its
// scores from there and says which regrade, -verify checks the regrade's bundle, a second
// regrade finds nothing to do, and the regrade's run.json records its own harness and the run's
// design digest.
func TestARegradeRecoversAFailedGrading(t *testing.T) {
	cleanTree(t)
	out, job := failedGrading(t)
	if a := agentOf(t, out, "cheater"); a.GradeProblem == "" || a.Valid {
		t.Fatalf("before the regrade: %+v", a)
	}
	steady := &lab{Sessions: &sandboxtest.Sessions{}}
	if err := regradePublished(context.Background(), out, job, daemonFor(t, steady), "", "", 2); err != nil {
		t.Fatal(err)
	}
	a := agentOf(t, out, "cheater")
	if a.GradeProblem != "" || !a.Valid || a.Regraded == "" || a.Fresh != 16 || a.FreshTotal != 16 {
		t.Fatalf("after the regrade: %+v", a)
	}
	if other := agentOf(t, out, "honest"); other.Regraded != "" {
		t.Fatalf("a controller graded whole was regraded: %+v", other)
	}
	if len(steady.projects) != 1+2 {
		t.Fatalf("the regrade ran %d grading runs; want the one controller's practice run and its two fresh parts", len(steady.projects))
	}
	var parent, rf RunFile
	if err := readJSON(filepath.Join(out, "run.json"), &parent); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(filepath.Join(out, regradesDir, a.Regraded, "run.json"), &rf); err != nil {
		t.Fatal(err)
	}
	if rf.DesignSHA256 == "" || rf.DesignSHA256 != parent.DesignSHA256 || rf.Harness.Commit != strings.Repeat("c", 40) || !rf.Harness.Clean {
		t.Fatalf("the regrade's run.json records design %q (the run's %q) and harness %+v", rf.DesignSHA256, parent.DesignSHA256, rf.Harness)
	}
	if err := verifyPublished(out, job); err != nil {
		t.Fatalf("a regraded run must verify: %v", err)
	}
	if err := regradePublished(context.Background(), out, job, daemonFor(t, steady), "", "", 2); err != nil || len(steady.projects) != 3 {
		t.Fatalf("a second regrade: %v, %d runs", err, len(steady.projects))
	}
}

// A regrade grades only with a commit's code: from a checkout whose
// harness code holds a change, it is refused before any grading run, and nothing is written.
func TestARegradeFromADirtyTreeIsRefused(t *testing.T) {
	cleanTree(t)
	out, job := failedGrading(t)
	harnessTree = func() Tree {
		return Tree{Commit: strings.Repeat("c", 40), Clean: false, Dirty: []string{" M examples/squeeze/grade.go"}, From: "test"}
	}
	steady := &lab{Sessions: &sandboxtest.Sessions{}}
	err := regradePublished(context.Background(), out, job, daemonFor(t, steady), "", "", 2)
	if !errors.Is(err, errDirtyRegrade) || !strings.Contains(err.Error(), "grade.go") {
		t.Fatalf("a regrade from a dirty tree: %v", err)
	}
	if len(steady.projects) != 0 {
		t.Fatalf("a refused regrade ran %d grading runs", len(steady.projects))
	}
	if _, err := os.Stat(filepath.Join(out, regradesDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused regrade wrote %s", regradesDir)
	}
}

// A regrade grades only under the run's own design: from a checkout
// whose course file changed since the run (a simulator edited by one line), the design recomputed
// from the job and the embedded course is not the one the run's run.json names, and the regrade is
// refused before any grading run.
func TestARegradeUnderAChangedCourseFileIsRefused(t *testing.T) {
	cleanTree(t)
	out, job := failedGrading(t)
	changed := fstest.MapFS{}
	if err := fs.WalkDir(embeddedCourse, "course", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := embeddedCourse.ReadFile(p)
		if p == "course/sim.mjs" {
			b = append(b, []byte("\n// a change made after the run\n")...)
		}
		changed[p] = &fstest.MapFile{Data: b}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	saved := courseFS
	courseFS = changed
	t.Cleanup(func() { courseFS = saved })
	steady := &lab{Sessions: &sandboxtest.Sessions{}}
	err := regradePublished(context.Background(), out, job, daemonFor(t, steady), "", "", 2)
	if !errors.Is(err, errOtherDesign) || !strings.Contains(err.Error(), "run.json names") {
		t.Fatalf("a regrade under a changed course file: %v", err)
	}
	if len(steady.projects) != 0 {
		t.Fatalf("a refused regrade ran %d grading runs", len(steady.projects))
	}
	courseFS = saved
	if err := regradePublished(context.Background(), out, job, daemonFor(t, steady), "", "", 2); err != nil {
		t.Fatalf("the same regrade under the run's own course: %v", err)
	}
}

// -verify, and with it agents.json, reads a regrade only when its run.json records the run's
// design digest and a commit's code, so a regrade made otherwise, or
// written by hand, is refused rather than its scores taken.
func TestARegradeRecordingAnotherDesignOrADirtyTreeIsRefused(t *testing.T) {
	cleanTree(t)
	out, job := failedGrading(t)
	steady := &lab{Sessions: &sandboxtest.Sessions{}}
	if err := regradePublished(context.Background(), out, job, daemonFor(t, steady), "", "", 2); err != nil {
		t.Fatal(err)
	}
	name := agentOf(t, out, "cheater").Regraded
	path := filepath.Join(out, regradesDir, name, "run.json")
	var good RunFile
	if err := readJSON(path, &good); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		edit func(*RunFile)
		want error
	}{
		{func(rf *RunFile) { rf.DesignSHA256 = strings.Repeat("0", 64) }, errOtherDesign},
		{func(rf *RunFile) { rf.DesignSHA256 = "" }, errOtherDesign},
		{func(rf *RunFile) {
			rf.Harness.Clean, rf.Harness.Dirty = false, []string{" M examples/squeeze/course/sim.mjs"}
		}, errDirtyRegrade},
	} {
		rf := good
		c.edit(&rf)
		if err := writeJSON(path, rf); err != nil {
			t.Fatal(err)
		}
		if err := verifyPublished(out, job); !errors.Is(err, c.want) {
			t.Fatalf("a regrade recording design %q, harness %+v: %v", rf.DesignSHA256, rf.Harness, err)
		}
	}
	if err := writeJSON(path, good); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublished(out, job); err != nil {
		t.Fatalf("the regrade as it was written: %v", err)
	}
}
