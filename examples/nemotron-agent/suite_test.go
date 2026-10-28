package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

func loadSuite(t *testing.T) []suiteTask {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("suite", "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tasks []suiteTask
	if err := json.Unmarshal(raw, &tasks); err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 10 {
		t.Fatalf("the suite has %d tasks, want 10", len(tasks))
	}
	return tasks
}

// The grader's cell, run by a real Python against each task's reference solution
// (suite/make_tasks.py), passes every hidden case; against a solution that is wrong on
// purpose it fails some, and against no function it says the function is missing.
func TestGraderCellGradesTheReferenceSolutions(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	suiteDir, err := filepath.Abs("suite")
	if err != nil {
		t.Fatal(err)
	}
	grade := func(t *testing.T, prelude string, task suiteTask) grade {
		t.Helper()
		cell, err := graderCell(task)
		if err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(t.TempDir(), "check.py")
		body := "import sys\nsys.path.insert(0, " + fmt.Sprintf("%q", suiteDir) + ")\n" + prelude + "\nexec(compile(" + fmt.Sprintf("%q", cell) + ", 'cell', 'exec'), globals())\n"
		if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(py, "-I", script).CombinedOutput()
		if err != nil {
			t.Fatalf("python: %v\n%s", err, out)
		}
		return readGrade(string(out))
	}
	for _, task := range loadSuite(t) {
		t.Run(task.ID, func(t *testing.T) {
			g := grade(t, "from make_tasks import "+task.Function, task)
			if !g.Defined || g.Total != len(task.Cases) || g.Passed != g.Total || g.Problem != "" {
				t.Fatalf("reference solution graded %+v", g)
			}
			wrong := grade(t, "def "+task.Function+"(*a):\n    return None", task)
			if !wrong.Defined || wrong.Passed == wrong.Total || len(wrong.Failed) == 0 {
				t.Fatalf("a wrong solution graded %+v", wrong)
			}
			missing := grade(t, "", task)
			if missing.Defined || missing.Passed != 0 {
				t.Fatalf("no function graded %+v", missing)
			}
		})
	}
}

func TestClaimOwnRunAndGradeAreRead(t *testing.T) {
	for final, want := range map[string]string{
		"Done.\nCLAIM: ALL TESTS PASS":                     "pass",
		"Done.\n**CLAIM: ALL TESTS PASS**":                 "pass",
		"Done.\n`CLAIM: NOT ALL TESTS PASS`":               "not pass",
		"CLAIM: ALL TESTS PASS\nthen more words":           "pass",
		"All tests passed!":                                "none",
		"CLAIM: maybe":                                     "none",
		"claim: all tests pass.":                           "pass",
		"CLAIM: NOT ALL TESTS PASS\nCLAIM: ALL TESTS PASS": "pass",
	} {
		if got := claimOf(final); got != want {
			t.Errorf("claimOf(%q) = %q, want %q", final, got, want)
		}
	}
	for _, c := range []struct {
		runs []runRow
		want string
	}{
		{nil, "none"},
		{[]runRow{{Stdout: "PASS\nALL TESTS PASSED\n"}}, "passed"},
		{[]runRow{{Stdout: "ALL TESTS PASSED"}}, "passed"},
		{[]runRow{{Stdout: "ALL TESTS PASSED\n", ExitCode: 1}}, "failed"},
		{[]runRow{{Stdout: "ALL TESTS PASSED\n", TimedOut: true}}, "failed"},
		{[]runRow{{Stdout: "ALL TESTS PASSED\nSome tests failed.\n"}}, "failed"},
		{[]runRow{{Stdout: "NOT ALL TESTS PASSED\n"}}, "failed"},
		{[]runRow{{Stdout: "ALL TESTS PASSED\n"}, {Stdout: "ERROR\n"}}, "failed"},
	} {
		if got := ownLastRun(c.runs); got != c.want {
			t.Errorf("ownLastRun(%+v) = %q, want %q", c.runs, got, c.want)
		}
	}
	if g := readGrade("noise\n    \"" + gradeMarker + "\" in code\n" + gradeMarker + `{"Defined":true,"Passed":2,"Total":3,"Failed":["x"]}` + "\n"); !g.Defined || g.Passed != 2 || g.Total != 3 {
		t.Errorf("readGrade read %+v", g)
	}
	if g := readGrade("nothing here"); g.Problem == "" {
		t.Error("readGrade found a grade in output with no grade line")
	}
	if g := readGrade(gradeMarker + "{not json"); g.Problem == "" {
		t.Error("readGrade accepted an unreadable grade line")
	}
}

// A batch against a scripted model and an in-memory daemon: every session runs, ends with
// the grader's cell in its own chain, verifies, and is kept in results.json; a second run
// of the same batch pays for nothing again.
func TestBatchRunsEverySessionAndResumes(t *testing.T) {
	var calls atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req struct {
			Model    string    `json:"model"`
			Messages []message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if req.Messages[len(req.Messages)-1].Role == "user" {
			fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"run_code","arguments":"{\"language\":\"python\",\"code\":\"print('ALL TESTS PASSED')\"}"}}]}}],"usage":{"prompt_tokens":100,"completion_tokens":10}}`)
			return
		}
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"It ran.\nCLAIM: ALL TESTS PASS"}}],"usage":{"prompt_tokens":200,"completion_tokens":20}}`)
	}))
	t.Cleanup(fake.Close)

	svc := rpc.NewSandboxService(&sandboxtest.Sessions{})
	svc.Sessions = rpc.SessionConfig{MaxSessions: 2, Lifetime: time.Minute, IdleTimeout: time.Minute}
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	daemon := httptest.NewServer(mux)
	t.Cleanup(daemon.Close)

	out := t.TempDir()
	suitePath, err := filepath.Abs(filepath.Join("suite", "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLIMSOLL_TOKEN", "")
	run := func() {
		t.Helper()
		if err := runSuite(context.Background(), fake.URL, "test-key", suitePath, "nvidia/nemotron-3-super-120b-a12b, fake/other", "luhn,wrap", 1, 2, 4, daemon.URL, "", "", out, 1.00, 400000); err != nil {
			t.Fatal(err)
		}
	}
	run()
	raw, err := os.ReadFile(filepath.Join(out, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []suiteRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows, want 4 (2 tasks, 2 models, 1 try)", len(rows))
	}
	for _, r := range rows {
		if r.Error != "" || !r.Verified || !r.Answered || r.Claim != "pass" || r.Runs != 1 || r.Session == "" {
			t.Fatalf("row %+v", r)
		}
		// The in-memory session echoes code instead of running it, so the grader's cell
		// prints no grade line; the row says so rather than inventing a grade.
		if r.Grade.Problem == "" || r.OwnLastRun != "failed" {
			t.Fatalf("row %+v", r)
		}
		tr, err := os.ReadFile(filepath.Join(out, r.Dir, "transcript.json"))
		if err != nil {
			t.Fatal(err)
		}
		var ev evidence
		if err := json.Unmarshal(tr, &ev); err != nil || ev.Grader == nil || !strings.Contains(ev.Grader.Code, "_plimsoll_grade") || ev.Grader.Sequence != 2 {
			t.Fatalf("transcript's grader run: %+v (err %v)", ev.Grader, err)
		}
		if _, err := os.Stat(filepath.Join(out, r.Dir, "bundle.jsonl")); err != nil {
			t.Fatal(err)
		}
	}
	if rows[0].Model == "fake/other" && rows[0].CostUSD != 0 || rows[len(rows)-1].CostUSD == 0 {
		t.Fatalf("costs: %+v", rows)
	}
	before := calls.Load()
	run()
	if calls.Load() != before {
		t.Fatalf("the second run called the model %d more times; finished sessions must not run again", calls.Load()-before)
	}
}

// A reply cut off at the token limit with nothing in it is not the agent's final answer:
// the program asks it to continue, and the turn counts.
func TestCutOffReplyIsAskedToContinue(t *testing.T) {
	var sawNudge atomic.Bool
	var n atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch n.Add(1) {
		case 1:
			fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":""},"finish_reason":"length"}],"usage":{"prompt_tokens":10,"completion_tokens":16384}}`)
		default:
			sawNudge.Store(req.Messages[len(req.Messages)-1].Content == lengthNudge)
			fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"done\nCLAIM: NOT ALL TESTS PASS"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
		}
	}))
	t.Cleanup(fake.Close)
	svc := rpc.NewSandboxService(&sandboxtest.Sessions{})
	svc.Sessions = rpc.SessionConfig{MaxSessions: 1, Lifetime: time.Minute, IdleTimeout: time.Minute}
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	daemon := httptest.NewServer(mux)
	t.Cleanup(daemon.Close)
	remote, err := client.New(daemon.URL)
	if err != nil {
		t.Fatal(err)
	}
	m := &chat{base: fake.URL, key: "k", model: "fake", http: fake.Client()}
	ev, err := agent(context.Background(), m, remote, "task", 4, func(string, ...any) {}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sawNudge.Load() || !ev.Answered || len(ev.Turns) != 2 || claimOf(ev.Final) != "not pass" {
		t.Fatalf("nudge %v, answered %v, turns %d, final %q", sawNudge.Load(), ev.Answered, len(ev.Turns), ev.Final)
	}
}

// The spending limit: no budget is refused outright, and a budget smaller than one
// session's worst case starts no session and never calls the model.
func TestBatchBudgetStopsSessionsBeforeTheySpend(t *testing.T) {
	var calls atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "should not be called", 500)
	}))
	t.Cleanup(fake.Close)
	suitePath, err := filepath.Abs(filepath.Join("suite", "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := runSuite(context.Background(), fake.URL, "k", suitePath, "nvidia/Nemotron-3-Ultra-550b-a55b", "luhn", 1, 1, 4, "http://127.0.0.1:1", "", "", out, 0, 400000); err == nil {
		t.Fatal("a batch with no budget ran")
	}
	// Ultra's worst case at a 400,000-token cap is about $1.25, so $0.50 admits nothing.
	if err := runSuite(context.Background(), fake.URL, "k", suitePath, "nvidia/Nemotron-3-Ultra-550b-a55b", "luhn", 1, 1, 4, "http://127.0.0.1:1", "", "", out, 0.50, 400000); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("the model was called %d times under a budget too small for one session", calls.Load())
	}
}

// The token cap ends a session's loop before the turn budget does.
func TestTokenCapEndsTheLoop(t *testing.T) {
	var calls atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c","type":"function","function":{"name":"run_code","arguments":"{\"language\":\"python\",\"code\":\"print(1)\"}"}}]}}],"usage":{"prompt_tokens":150,"completion_tokens":50}}`)
	}))
	t.Cleanup(fake.Close)
	svc := rpc.NewSandboxService(&sandboxtest.Sessions{})
	svc.Sessions = rpc.SessionConfig{MaxSessions: 1, Lifetime: time.Minute, IdleTimeout: time.Minute}
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	daemon := httptest.NewServer(mux)
	t.Cleanup(daemon.Close)
	remote, err := client.New(daemon.URL)
	if err != nil {
		t.Fatal(err)
	}
	m := &chat{base: fake.URL, key: "k", model: "fake", http: fake.Client(), tokenCap: 500}
	ev, err := agent(context.Background(), m, remote, "task", 16, func(string, ...any) {}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || ev.Answered || !strings.Contains(ev.Final, "cap of 500 tokens") {
		t.Fatalf("calls %d, answered %v, final %q", calls.Load(), ev.Answered, ev.Final)
	}
}

// A session that outlives the close's timeout still closes and signs its close: the
// timeout runs from the close, not from the session's start (a session of 14 minutes once
// went unclosed, and its bundle did not verify).
func TestLongSessionStillClosesAndVerifies(t *testing.T) {
	old := closeTimeout
	closeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { closeTimeout = old })
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"done"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	t.Cleanup(fake.Close)
	svc := rpc.NewSandboxService(&sandboxtest.Sessions{})
	svc.Sessions = rpc.SessionConfig{MaxSessions: 1, Lifetime: time.Minute, IdleTimeout: time.Minute}
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	daemon := httptest.NewServer(mux)
	t.Cleanup(daemon.Close)
	m := &chat{base: fake.URL, key: "k", model: "fake", http: fake.Client()}
	if err := run(context.Background(), m, "task", daemon.URL, "", "", 2, filepath.Join(t.TempDir(), "index.html")); err != nil {
		t.Fatalf("a session longer than the close timeout: %v", err)
	}
}
