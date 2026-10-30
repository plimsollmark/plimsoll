package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const published = "../../docs/examples/verifiers"

func hexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// logOf writes a record log of one session with n calls at tier, closed when closed is set,
// in the shape plimsoll_client.verifiers_runtime writes.
func logOf(t *testing.T, n int, tier string, closed bool) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	session := hexOf("session")
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(enc.Encode(map[string]any{"kind": "open", "session": session, "isolation": tier, "provider": "docker", "runtime": "r1", "time_unix_ms": 1}))
	prev := ""
	start := time.UnixMilli(1793153900551).UTC()
	for i := 1; i <= n; i++ {
		r := sandbox.RunRecord{Version: record.Version, RequestSHA256: hexOf(fmt.Sprint("req", i)), ResultSHA256: hexOf(fmt.Sprint("res", i)),
			Provider: "docker", Isolation: tier, Environment: "docker-image:sha256:" + hexOf("image"),
			Started: start.Add(time.Duration(i) * time.Second), Ended: start.Add(time.Duration(i)*time.Second + 250*time.Millisecond),
			Session: session, Sequence: uint64(i), PreviousSHA256: prev}
		r.SHA256 = record.Digest(r)
		prev = r.SHA256
		must(enc.Encode(map[string]any{"kind": "record", "op": "run", "time_unix_ms": 2, "record": map[string]any{
			"version": r.Version, "request_sha256": r.RequestSHA256, "result_sha256": r.ResultSHA256, "provider": r.Provider,
			"isolation": r.Isolation, "environment": r.Environment, "software_identity": "", "software_rule_id": "", "policy": "",
			"started_unix_ms": r.Started.UnixMilli(), "ended_unix_ms": r.Ended.UnixMilli(), "session": r.Session,
			"sequence": r.Sequence, "previous_sha256": r.PreviousSHA256, "unanswered": "", "instance": "", "sha256": r.SHA256,
		}}))
	}
	if closed {
		must(enc.Encode(map[string]any{"kind": "close", "session": session, "calls": n, "last_record_sha256": prev, "end": "closed", "time_unix_ms": 3}))
	}
	return b.Bytes()
}

// The Go checker accepts a whole log and refuses each way a log can lie: a changed
// field, a dropped call, a close that counts differently, a tier below the floor.
func TestRecordLogRecheckRefusesEveryChange(t *testing.T) {
	good := logOf(t, 4, "container", true)
	c, calls, err := checkRecordLog(good, "container")
	if err != nil {
		t.Fatal(err)
	}
	if c.Sessions != 1 || c.Records != 4 || c.Closed != 1 || c.Tiers["container"] != 4 || len(c.Incomplete) != 0 || len(calls) != 4 || calls[3].Millis != 250 {
		t.Fatalf("check %+v, %d calls", c, len(calls))
	}
	lines := strings.SplitAfter(string(good), "\n")
	changed := strings.Replace(string(good), hexOf("res2"), hexOf("res2x"), 1)
	dropped := strings.Join(append(append([]string{}, lines[:2]...), lines[3:]...), "")
	recount := strings.Replace(string(good), `"calls":4`, `"calls":5`, 1)
	for name, raw := range map[string]string{"a changed result digest": changed, "a dropped call": dropped, "a close that counts five": recount} {
		if _, _, err := checkRecordLog([]byte(raw), "container"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := checkRecordLog(good, "kernel"); err == nil || !strings.Contains(err.Error(), "below kernel") {
		t.Errorf("a container record under a kernel floor: %v", err)
	}
	open, _, err := checkRecordLog(logOf(t, 2, "kernel", false), "kernel")
	if err != nil || len(open.Incomplete) != 1 || !strings.Contains(open.Incomplete[0], "no close") {
		t.Errorf("a session with no close: %+v, %v", open, err)
	}
	if _, _, err := checkRecordLog([]byte(`{"kind":"record","op":"run","record":{},"extra":1}`+"\n"), ""); err == nil {
		t.Error("a line with a field the log does not have was accepted")
	}
}

// The census rules on three made-up tasks: one Terminal-Bench shaped, one that could run,
// one that fetches at grading only.
func TestCensusRules(t *testing.T) {
	root := t.TempDir()
	write := func(task, name, body string) {
		p := filepath.Join(root, task, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("bench", "task.toml", "[environment]\ndocker_image = \"x/y:1\"\nallow_internet = true\n")
	write("bench", "tests/test.sh", "apt-get update\napt-get install -y curl\ncurl -LsSf https://example.invalid | sh\nuvx pytest /tests/test_outputs.py\necho 1 > /logs/verifier/reward.txt\n")
	write("bench", "environment/Dockerfile", "FROM ubuntu\nWORKDIR /app\n")
	write("plain", "task.toml", "[environment]\nallow_internet = false\n")
	write("plain", "tests/test.sh", "python3 check.py\n")
	write("fetches", "task.toml", "[environment]\n")
	write("fetches", "tests/test.sh", "pip install --quiet pytest\n")
	if err := os.MkdirAll(filepath.Join(root, "not-a-task"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, err := takeCensus(root, "r", "c")
	if err != nil {
		t.Fatal(err)
	}
	want := census{Repo: "r", Commit: "c", Tasks: 3, Image: 1, Internet: 1, Fetch: 2, Logs: 1, Tests: 1, App: 1, Runnable: 1}
	if c != want {
		t.Errorf("census %+v, want %+v", c, want)
	}
}

// The transcript comparison counts identical messages and names the lines that differ.
func TestTranscriptComparison(t *testing.T) {
	mk := func(system, id string) *trace {
		var tr trace
		raw := fmt.Sprintf(`{"agent":{"runtime":{"id":"s"}},"nodes":[
			{"tools":[{"name":"bash"}],"message":{"role":"system","content":%q}},
			{"message":{"role":"user","content":"do it"}},
			{"message":{"role":"assistant","tool_calls":[{"id":"%s","name":"bash","arguments":"{\"command\": \"ls\"}"}]}},
			{"message":{"role":"tool","content":"{\n  \"answer\": 1\n}\n"}},
			{"message":{"role":"assistant","content":[{"type":"text","text":"done"}]}}],"timing":{}}`, system, id)
		if err := json.Unmarshal([]byte(raw), &tr); err != nil {
			t.Fatal(err)
		}
		return &tr
	}
	eq := compareTranscripts(mk("You are an agent.\n\nExternal network access is disabled.", "call_1"), mk("You are an agent.", "call_9"))
	if eq.Messages != 5 || eq.Identical != 4 || !eq.SameTools || len(eq.Diffs) != 1 || !strings.Contains(eq.Diffs[0], "External network access is disabled.") {
		t.Errorf("%+v", eq)
	}
	calls := mk("x", "c").toolCalls([]phaseCall{{chainCall: chainCall{SHA256: "abc"}}})
	if len(calls) != 1 || calls[0].Input != "ls" || calls[0].Output != `"answer": 1` || calls[0].Lines != 3 || calls[0].Record != "abc" {
		t.Errorf("%+v", calls)
	}
}

// The task's package must be exactly the pinned files: a changed byte or an added file is
// refused before any of it can run.
func TestTaskFilesArePinned(t *testing.T) {
	dir := t.TempDir()
	if _, err := checkTaskFiles(dir); err == nil {
		t.Fatal("an empty directory passed")
	}
	if err := os.MkdirAll(filepath.Join(dir, "uuid_ctf"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name := range primeFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not the pinned bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := checkTaskFiles(dir); err == nil || !strings.Contains(err.Error(), "taskset.py") {
		t.Fatalf("changed files: %v", err)
	}
}

// The published directory rechecks, and refuses a copy with one byte of one record changed.
func TestPublishedFilesVerify(t *testing.T) {
	if err := verifyPublished(published); err != nil {
		t.Fatalf("%v; run go run ./examples/verifiers -render, or the whole program", err)
	}
	ev, err := loadEvidence(published)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Scripted || ev.Verifiers == "" || ev.Pin != "verifiers=="+ev.Verifiers {
		t.Errorf("scripted %v, verifiers %q, pin %q", ev.Scripted, ev.Verifiers, ev.Pin)
	}
	// The page's fixed sentences (the headline, "the grader can say no", the shipped
	// harness stopping in setup) hold for these results; a rerun that changes one fails
	// here, so the text is reread before it is published.
	d := newPageData(ev)
	for name, got := range map[string]string{
		"uuid_ctf on plimsoll, runc":   reward(d.Gold.Reward),
		"uuid_ctf on plimsoll, gVisor": reward(d.GVisor.Reward),
		"the wrong answer":             reward(d.Wrong.Reward),
		"the docker baseline":          reward(d.Docker.Reward),
		"the shipped harness":          reward(d.Shipped.Reward),
	} {
		want := map[string]string{"the wrong answer": "0.0", "the shipped harness": "none"}[name]
		if want == "" {
			want = "1.0"
		}
		if got != want {
			t.Errorf("%s scored %s; the page's text assumes %s", name, got, want)
		}
	}
	if !strings.Contains(d.Shipped.Error, "bad address") || len(ev.Validate) != 2 || !d.AllRechecked() {
		t.Errorf("shipped harness error %q, %d validations, all rechecked %v", d.Shipped.Error, len(ev.Validate), d.AllRechecked())
	}
	for _, v := range ev.Validate {
		if !v.Valid || !v.Gold.Valid || v.Untouched.Reward == nil || *v.Untouched.Reward != 0 {
			t.Errorf("vf-validate under %s: %+v", v.DockerRuntime, v)
		}
	}
	page, err := os.ReadFile(filepath.Join(published, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`\sid="([^"]+)"`).FindAllSubmatch(page, -1) {
		if ids[string(m[1])] {
			t.Errorf("id %q appears twice", m[1])
		}
		ids[string(m[1])] = true
	}
	if bytes.Contains(page, []byte("prefers-color-scheme")) {
		t.Error("the page has a dark-mode block")
	}
	if regexp.MustCompile("[\u2013\u2014]| -- ").Match(page) {
		t.Error("the page has a dash used as punctuation")
	}

	copyDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(copyDir, "records"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"evidence.json", "index.html"} {
		if err := copyFile(filepath.Join(copyDir, name), filepath.Join(published, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range ev.Logs {
		raw, err := os.ReadFile(filepath.Join(published, filepath.FromSlash(l.File)))
		if err != nil {
			t.Fatal(err)
		}
		if l.File == ev.Logs[0].File {
			i := bytes.Index(raw, []byte(`"result_sha256":"`)) + len(`"result_sha256":"`)
			raw = append([]byte{}, raw...)
			if raw[i] == 'a' {
				raw[i] = 'b'
			} else {
				raw[i] = 'a'
			}
		}
		if err := os.WriteFile(filepath.Join(copyDir, filepath.FromSlash(l.File)), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyPublished(copyDir); err == nil {
		t.Error("a record log with one byte changed rechecked")
	}
}
