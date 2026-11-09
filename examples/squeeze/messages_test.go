package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// The scrambled recipe is fixed by the seed in the code: the same words, shuffled the same way on
// every run, so anyone can rebuild what the scrambled group was given.
func TestScrambleIsFixed(t *testing.T) {
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	honest, _ := job.Courses[0].loop("honest")
	got := scramble(honest.Recipe)
	want := "filter; accel smooth disturbance + ramp fast/slow lock; local exit abort; gate integrals; predictive pos pad observer; Filter ref cross yaw descent. velocity;"
	if got != want {
		t.Fatalf("scrambled recipe:\n got %q\nwant %q", got, want)
	}
	a, b := strings.Fields(honest.Recipe), strings.Fields(got)
	slices.Sort(a)
	slices.Sort(b)
	if !slices.Equal(a, b) || got == honest.Recipe {
		t.Fatal("the scrambled recipe is not the same words in another order")
	}
	if g := job.Courses[0].Groups[1]; !g.Scramble || job.Courses[0].recipeFor(g) != want {
		t.Fatal("the job's scrambled group is not given the scrambled recipe")
	}
}

// fakeMessages is an Anthropic Messages API stand-in that answers like an agent: it writes a
// controller, changes it with its own code, is refused a fly, writes it again, flies, and
// answers; then it answers the question asked after. It checks every request the way the API
// would care about: thinking blocks sent back unchanged with their signatures, a user turn of
// tool results for every tool call, the prompt counted before each call.
type fakeMessages struct {
	mu       sync.Mutex
	starts   []string // each conversation's arm, in the order they started
	counts   int
	creates  int
	problems []string
}

func (f *fakeMessages) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string           `json:"model"`
			Messages []map[string]any `json:"messages"`
			Thinking map[string]any   `json:"thinking"`
			Cache    map[string]any   `json:"cache_control"`
			Max      int              `json:"max_tokens"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("x-api-key") == "" || r.Header.Get("anthropic-version") != anthropicVersion {
			http.Error(w, "no key or version", 401)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/count_tokens") {
			f.counts++
			b, _ := json.Marshal(req.Messages)
			json.NewEncoder(w).Encode(map[string]int{"input_tokens": 2000 + len(b)/4})
			return
		}
		f.creates++
		if req.Thinking["display"] != "summarized" || req.Cache["type"] != "ephemeral" || req.Max != 16000 {
			f.problems = append(f.problems, fmt.Sprintf("request settings: thinking %v, cache %v, max_tokens %d", req.Thinking, req.Cache, req.Max))
		}
		first := req.Messages[0]["content"].([]any)[0].(map[string]any)["text"].(string)
		arm := "none"
		if strings.Contains(first, "velocity;") {
			arm = "scrambled"
			if strings.Contains(first, "Filter velocity;") {
				arm = "recipe"
			}
		}
		n := len(req.Messages)
		// Every assistant turn sent back holds the thinking block this server issued, unchanged.
		for i := 1; i < n; i += 2 {
			blocks := req.Messages[i]["content"].([]any)
			th := blocks[0].(map[string]any)
			if th["type"] != "thinking" || th["signature"] != fmt.Sprintf("sig-%d", i/2+1) {
				f.problems = append(f.problems, fmt.Sprintf("turn %d's thinking block came back changed: %v", i, th))
			}
		}
		recipe := ""
		if _, rest, ok := strings.Cut(first, "which is all you get from it:\n\n    "); ok {
			recipe, _, _ = strings.Cut(rest, "\n")
		}
		src := "// ALL\nexport default function makeController() { const velFilter = 0.2; let integral = 0; return { step() { return { thrust: 0.5, roll: 0, pitch: 0, yawRate: 0 }; } }; }\n"
		if arm == "none" {
			src = strings.Replace(src, "let integral = 0;", "const noise = Math.random();", 1)
		}
		tool := func(name string, input any) map[string]any {
			return map[string]any{"type": "tool_use", "id": fmt.Sprintf("tu-%d", n), "name": name, "input": input}
		}
		var content []any
		turn := (n + 1) / 2
		think := map[string]any{"type": "thinking", "thinking": fmt.Sprintf("Turn %d: I plan the next step.", turn), "signature": fmt.Sprintf("sig-%d", turn)}
		last := req.Messages[n-1]["content"].([]any)
		lastText, _ := last[len(last)-1].(map[string]any)["text"].(string)
		switch {
		case strings.HasPrefix(lastText, "Your session is over"):
			content = []any{think, map[string]any{"type": "text", "text": "I followed the recipe where it fit: " + recipe}}
			if arm == "none" {
				content = []any{think, map[string]any{"type": "text", "text": "A plain waypoint follower."}}
			}
		case n == 1:
			content = []any{think, map[string]any{"type": "text", "text": "The recipe says: " + recipe}, tool("write_file", map[string]string{"path": "controller.js", "content": src})}
		case n == 3:
			content = []any{think, tool("run_code", map[string]string{"language": "javascript", "code": "//lab-write controller.js\n// changed by my own code\n"})}
		case n == 5:
			content = []any{think, tool("fly", map[string]any{"smoke": true})}
		case n == 7:
			if !strings.Contains(fmt.Sprint(last), "not what your last write_file") {
				f.problems = append(f.problems, "a controller changed outside write_file was flown")
			}
			content = []any{think, tool("write_file", map[string]string{"path": "controller.js", "content": src})}
		case n == 9:
			content = []any{think, tool("fly", map[string]any{"smoke": true, "count": 2})}
		default:
			content = []any{think, map[string]any{"type": "text", "text": "Done.\nSMOKE=4/4"}}
		}
		if n == 1 {
			f.starts = append(f.starts, arm)
		}
		stop := "tool_use"
		if _, isTool := content[len(content)-1].(map[string]any)["input"]; !isTool {
			stop = "end_turn"
		}
		json.NewEncoder(w).Encode(map[string]any{"type": "message", "role": "assistant", "content": content, "stop_reason": stop,
			"usage": map[string]int{"input_tokens": 50, "cache_creation_input_tokens": 300, "cache_read_input_tokens": 2000, "output_tokens": 40}})
	}
}

// A building run on the Messages API, end to end against the in-memory lab: the three groups'
// rebuilds start in turn, the reasoning summaries are kept, thinking blocks go back unchanged,
// a controller changed outside write_file is refused a fly, the question is asked after, and
// agents.json reads the records from the transcripts and the signed grading runs alone.
func TestMessagesRunRecordsEachAgent(t *testing.T) {
	defer func(d time.Duration) { closeTimeout = d }(closeTimeout)
	closeTimeout = 2 * time.Second
	f := &fakeMessages{}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	t.Setenv("FAKE_ANTHROPIC_KEY", "k")
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	job.Fresh = 16
	for i := range job.Courses[0].Groups {
		job.Courses[0].Groups[i].Build = 2
	}
	l := &lab{Sessions: &sandboxtest.Sessions{}}
	out := filepath.Join(t.TempDir(), "run")
	mo := modelOpts{api: "messages", model: "claude-sonnet-5-5", base: srv.URL, keyEnv: "FAKE_ANTHROPIC_KEY", maxTokens: 10_000_000}
	if err := runAndPublish(context.Background(), job, "", out, daemonFor(t, l), "", "", 1, mo, givenFresh{}); err != nil {
		t.Fatal(err)
	}
	if len(f.problems) > 0 {
		t.Fatalf("the fake API saw: %v", f.problems)
	}
	if want := []string{"recipe", "scrambled", "none", "recipe", "scrambled", "none"}; !slices.Equal(f.starts, want) {
		t.Fatalf("rebuilds started %v, want %v", f.starts, want)
	}
	if f.counts != f.creates {
		t.Fatalf("%d prompts counted for %d calls: every call is counted first", f.counts, f.creates)
	}
	if err := verifyPublished(out, job); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var agents []AgentRecord
	raw, _ := os.ReadFile(filepath.Join(out, "agents.json"))
	if err := json.Unmarshal(raw, &agents); err != nil || len(agents) != 6 {
		t.Fatalf("agents.json: %v, %d records", err, len(agents))
	}
	for _, a := range agents {
		recipe := a.Group != "none"
		if a.QuotedRecipe != recipe || (recipe && a.Quoted != len(strings.Fields(a.Recipe))) {
			t.Fatalf("%s quoted %d words (quoted_recipe %v)", a.ID, a.Quoted, a.QuotedRecipe)
		}
		if a.Group == "scrambled" && a.QuotedOriginal >= quotedMin {
			t.Fatalf("%s quoted the honest recipe in order, %d words, from a scrambled one", a.ID, a.QuotedOriginal)
		}
		if !slices.Equal(a.ItemsNamed, []string{"Filter velocity", "yaw + local pos integrals"}) && a.Group != "none" {
			t.Fatalf("%s items %v", a.ID, a.ItemsNamed)
		}
		if a.RNG != (a.Group == "none") || a.GeneratorK {
			t.Fatalf("%s rng %v, generator constant %v", a.ID, a.RNG, a.GeneratorK)
		}
		if !a.Graded || a.FreshTotal != 16 || a.From != "write_file" || a.FlyCalls != 1 {
			t.Fatalf("%s: %+v", a.ID, a)
		}
		if a.Calls.ByKind["refused"] != 1 || a.Reasoning == 0 || a.AfterAnswer == "" || a.Ended != "answered" {
			t.Fatalf("%s: refused %d, reasoning %d, after %q, ended %s", a.ID, a.Calls.ByKind["refused"], a.Reasoning, a.AfterAnswer, a.Ended)
		}
	}
	ts, err := readTranscripts(out)
	if err != nil || len(ts) != 6 {
		t.Fatalf("transcripts: %v, %d", err, len(ts))
	}
	for _, tr := range ts {
		if tr.After == nil || strings.Contains(tr.Question, "follow the recipe") != (tr.Recipe != "") || tr.Turns[0].Answer.Reasoning == "" {
			t.Fatalf("transcript %s.%d: question %q, after %v", tr.Group, tr.N, tr.Question, tr.After)
		}
	}
}

// An experiment staged in parts: -groups builds only the named groups, under the same job and design.
func TestMessagesRunBuildsOnlyTheNamedGroups(t *testing.T) {
	defer func(d time.Duration) { closeTimeout = d }(closeTimeout)
	closeTimeout = 2 * time.Second
	f := &fakeMessages{}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	t.Setenv("FAKE_ANTHROPIC_KEY", "k")
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	job.Fresh = 16
	for i := range job.Courses[0].Groups {
		job.Courses[0].Groups[i].Build = 2
	}
	mo := modelOpts{api: "messages", model: "claude-sonnet-5-5", base: srv.URL, keyEnv: "FAKE_ANTHROPIC_KEY", maxTokens: 10_000_000, groups: []string{"none"}}
	out := filepath.Join(t.TempDir(), "run")
	if err := runAndPublish(context.Background(), job, "", out, daemonFor(t, &lab{Sessions: &sandboxtest.Sessions{}}), "", "", 2, mo, givenFresh{}); err != nil {
		t.Fatal(err)
	}
	var rf RunFile
	if err := readJSON(filepath.Join(out, "run.json"), &rf); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.starts, []string{"none", "none"}) || !slices.Equal(rf.Groups, []string{"none"}) || len(rf.Built) != 2 {
		t.Fatalf("started %v, run.json groups %v, %d built", f.starts, rf.Groups, len(rf.Built))
	}
	if err := verifyPublished(out, job); err != nil {
		t.Fatal(err)
	}
	// -build sizes the named groups between stages, at most the job's build for each.
	f.starts = nil
	mo.groups, mo.build = []string{"recipe", "scrambled"}, 1
	out2 := filepath.Join(t.TempDir(), "run")
	if err := runAndPublish(context.Background(), job, "", out2, daemonFor(t, &lab{Sessions: &sandboxtest.Sessions{}}), "", "", 1, mo, givenFresh{}); err != nil {
		t.Fatal(err)
	}
	var rf2 RunFile
	if err := readJSON(filepath.Join(out2, "run.json"), &rf2); err != nil || rf2.Build != 1 || !slices.Equal(f.starts, []string{"recipe", "scrambled"}) {
		t.Fatalf("sized run: %v, build %d, started %v", err, rf2.Build, f.starts)
	}
	mo.build = 3
	if err := runAndPublish(context.Background(), job, "", t.TempDir(), "http://127.0.0.1:1", "", "", 1, mo, givenFresh{}); err == nil || !strings.Contains(err.Error(), "at most 2") {
		t.Fatalf("a size past the job's: %v", err)
	}
	mo.build = 0
	mo.groups = []string{"nonesuch"}
	if err := runAndPublish(context.Background(), job, "", t.TempDir(), "http://127.0.0.1:1", "", "", 1, mo, givenFresh{}); err == nil || !strings.Contains(err.Error(), "-groups") {
		t.Fatalf("an unknown group: %v", err)
	}
}

// A building run spends nothing it was not allowed to: no key, no budget, no -paid for a base
// off this machine, or a design other than the one named, and nothing is sent.
func TestMessagesRunRefusesWithoutItsFlags(t *testing.T) {
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "")
	os.Unsetenv("ANTHROPIC_API_KEY")
	base := modelOpts{api: "messages", model: "claude-sonnet-5-5", maxTokens: 1000}
	mo, _ := modelDefaults(base)
	if err := runAndPublish(context.Background(), job, "", t.TempDir(), "http://127.0.0.1:1", "", "", 1, mo, givenFresh{}); !errors.Is(err, errNoModel) {
		t.Fatalf("no key: %v", err)
	}
	t.Setenv("SQUEEZE_TEST_KEY", "k")
	mo.keyEnv = "SQUEEZE_TEST_KEY"
	if err := runAndPublish(context.Background(), job, "", t.TempDir(), "http://127.0.0.1:1", "", "", 1, mo, givenFresh{}); !errors.Is(err, errNotPaid) {
		t.Fatalf("a base off this machine without -paid: %v", err)
	}
	mo.paid, mo.designSHA = true, strings.Repeat("0", 64)
	defer func(f func() Tree) { harnessTree = f }(harnessTree)
	harnessTree = func() Tree { return Tree{Commit: "c", Clean: true, From: "test"} } // whatever this checkout holds
	if err := runAndPublish(context.Background(), job, "", t.TempDir(), "http://127.0.0.1:1", "", "", 1, mo, givenFresh{}); err == nil || !strings.Contains(err.Error(), "-design-sha256") {
		t.Fatalf("another design: %v", err)
	}
}

// The Messages client counts the prompt first and refuses a call that could take the run past
// its token budget, or a conversation past the prompt cap, without sending it.
func TestMessagesBudgetRefusesBeforeSending(t *testing.T) {
	f := &fakeMessages{}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	for _, c := range []struct {
		limit, cap int
		want       error
	}{{limit: 10_000, want: errBudget}, {limit: 10_000_000, cap: 100, want: errPromptCap}} {
		m := &messagesAPI{base: srv.URL, key: "k", model: "claude-sonnet-5-5", http: srv.Client(), maxTokens: 16000, promptCap: c.cap, b: &budget{limit: c.limit}}
		d := m.start("system", "prompt", rebuildTools(8))
		if _, err := d.next(context.Background(), true); !errors.Is(err, c.want) {
			t.Fatalf("limit %d, cap %d: %v", c.limit, c.cap, err)
		}
	}
	if f.creates != 0 || f.counts != 2 {
		t.Fatalf("%d calls sent, %d prompts counted; want none sent, two counted", f.creates, f.counts)
	}
}
