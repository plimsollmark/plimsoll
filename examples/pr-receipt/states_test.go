package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The receipt states (states.py): which commit a receipt covers, whether that is the head,
// whether the run completed, what came back, how many tests ran, who it checks against,
// and the verdict that never says passed for partial evidence.

const statesCommit = "627534fc71de105aeb7e71098970bb51d7096349" // what formatsExchange's subject names

type statesCase struct {
	Name       string            `json:"name"`
	X          map[string]any    `json:"x"`
	Signer     string            `json:"signer"`
	Given      map[string]string `json:"given"`
	HeadResult string            `json:"head_result,omitempty"`
	Companions map[string]any    `json:"companions"`
	MinTests   int               `json:"min_tests,omitempty"` // 0: none given
}

type statesResult struct {
	States     map[string]map[string]any
	Unverified []struct{ Code, Detail string }
	Summary    []string
}

// statesDerive runs states.derive on each case, and the summary of what it gave, in one
// python process; it returns the results and the closed set of values per state.
func statesDerive(t *testing.T, cases []statesCase) ([]statesResult, map[string][]string) {
	t.Helper()
	path, err := filepath.Abs("states.py")
	if err != nil {
		t.Fatal(err)
	}
	in, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	const driver = `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('pr_receipt_states', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
out = []
for c in json.load(sys.stdin):
    st, unv = m.derive(c['x'], signer=c['signer'], given=c['given'], head_result=c.get('head_result'), companions=c['companions'], min_tests=c.get('min_tests'))
    out.append({'states': st, 'unverified': unv, 'summary': m.summary({'states': st, 'unverified': unv})})
print(json.dumps({'values': {k: list(v) for k, v in m.VALUES.items()}, 'results': out}))
`
	cmd := exec.Command("python3", "-I", "-c", driver, path)
	cmd.Stdin = strings.NewReader(string(in))
	out, err := cmd.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			t.Fatalf("states.derive: %v\n%s", err, e.Stderr)
		}
		t.Fatal(err)
	}
	var got struct {
		Values  map[string][]string
		Results []statesResult
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return got.Results, got.Values
}

func statesStep(exit int, timedOut bool) map[string]any {
	return map[string]any{"command": "npm test", "duration_ms": "5", "exit_code": exit, "timed_out": timedOut,
		"stdout_truncated": false, "stderr_truncated": false}
}

// statesExchange is a signed exchange as receipt.sh makes one: one step, behind the kernel
// tier, completed, with the request's 30-second limit; change sets anything else.
func statesExchange(change func(x, request, project map[string]any)) map[string]any {
	x := formatsExchange([]string{"npm test"}, []map[string]any{statesStep(0, false)}, nil, nil)
	request := x["request"].(map[string]any)
	request["timeout_ms"] = 30000
	if change != nil {
		change(x, request, x["response"].(map[string]any)["project"].(map[string]any))
	}
	return x
}

// withReport makes the request ask for a JUnit report at reports.xml and the run return it.
func withReport(content string) func(x, request, project map[string]any) {
	return func(x, request, project map[string]any) {
		request["project"].(map[string]any)["artifacts"] = []string{"reports.xml"}
		project["artifacts"] = []map[string]any{returned("reports.xml", content)}
	}
}

const statesTwoPassed = `<testsuites><testcase name="adds"/><testcase name="empty"/></testsuites>`

// statesEntityReport is statesTwoPassed behind a DOCTYPE that declares an entity, used
// once: harmless itself, the shape a nested-entity report has.
const statesEntityReport = `<!DOCTYPE testsuites [<!ENTITY n "adds">]><testsuites><testcase name="&n;"/><testcase name="empty"/></testsuites>`

// Every value of every state, each from the case that should give it, and the verdict says
// passed for one case alone: everything established, against a trusted key, on the head.
func TestReceiptStatesFromSignedResults(t *testing.T) {
	given := map[string]string{"repository": "example/pr-receipt-fixture", "pr": "0", "head": statesCommit}
	other := func(key, value string) map[string]string {
		g := map[string]string{}
		for k, v := range given {
			g[k] = v
		}
		g[key] = value
		return g
	}
	none := map[string]any{"junit": true, "test-result": true}
	type want map[string]string
	cases := []struct {
		c      statesCase
		want   want
		detail map[string]string // a phrase the state's detail must hold
		check  func(t *testing.T, r statesResult)
	}{
		{c: statesCase{Name: "everything established", X: statesExchange(withReport(statesTwoPassed)), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "passed", "signer": "trusted_key", "covers": "known", "candidate": "current", "run": "completed", "steps": "passed", "tests": "discovered", "evidence": "complete"},
			check: func(t *testing.T, r statesResult) {
				if r.States["tests"]["cases"] != 2.0 || r.States["tests"]["passed"] != 2.0 || r.States["tests"]["minimum"] != 1.0 || r.States["covers"]["commit"] != statesCommit || r.States["run"]["isolation"] != "kernel" {
					t.Errorf("fields: %v", r.States)
				}
			}},
		{c: statesCase{Name: "no test report requested", X: statesExchange(nil), Signer: "trusted_key", HeadResult: "match"},
			want:   want{"verdict": "incomplete", "tests": "unknown", "steps": "passed", "evidence": "complete"},
			detail: map[string]string{"tests": "JUNIT_PATH unset", "verdict": "how many tests ran is unknown"},
			check: func(t *testing.T, r statesResult) {
				if !hasCode(r, "test_count") || r.States["tests"]["minimum"] != nil {
					t.Errorf("unverified does not name the test count, or a minimum stands with no report (%v): %v", r.States["tests"]["minimum"], r.Unverified)
				}
			}},
		// A test report was asked for: it must come back readable, list no failure and list at
		// least the minimum (1 unless the checker was given more) of tests that ran.
		{c: statesCase{Name: "a zero-test report", X: statesExchange(withReport(`<testsuites tests="0"></testsuites>`)), Signer: "trusted_key", HeadResult: "match"},
			want:   want{"verdict": "failed", "tests": "zero", "steps": "passed"},
			detail: map[string]string{"tests": "lists no test case", "verdict": "lists 0 tests that ran; the gate requires at least 1 test that ran"}},
		{c: statesCase{Name: "every test skipped", X: statesExchange(withReport(`<testsuites><testcase name="a"><skipped/></testcase></testsuites>`)), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "tests": "zero"}, detail: map[string]string{"tests": "1 test case, all skipped", "verdict": "lists 0 tests that ran"}},
		{c: statesCase{Name: "the report was not returned", X: statesExchange(func(x, request, project map[string]any) {
			request["project"].(map[string]any)["artifacts"] = []string{"reports.xml"}
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "tests": "unknown", "evidence": "partial"}, detail: map[string]string{"tests": "did not write it", "evidence": "did not return `reports.xml`", "verdict": "requires at least 1"}},
		{c: statesCase{Name: "the report was over the budget", X: statesExchange(func(x, request, project map[string]any) {
			request["project"].(map[string]any)["artifacts"] = []string{"reports.xml"}
			project["artifacts_truncated"] = true
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "tests": "unknown", "evidence": "partial"}, detail: map[string]string{"tests": "over the artifact budget", "evidence": "over the artifact budget"}},
		{c: statesCase{Name: "an unreadable report", X: statesExchange(withReport("not xml")), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "tests": "unknown", "evidence": "complete"}, detail: map[string]string{"tests": "not a JUnit report"}},
		// A self-consistent receipt is anyone's, and xml.etree expands the entities a DOCTYPE
		// declares, so a report that declares one is not read, nor one past the 8 MiB a run
		// returns; each would read as two passing tests.
		{c: statesCase{Name: "a report that declares an entity", X: statesExchange(withReport(statesEntityReport)), Signer: "self_consistent", HeadResult: "match"},
			want: want{"tests": "unknown"}, detail: map[string]string{"tests": "not a JUnit report"}},
		{c: statesCase{Name: "a report past the bound", X: statesExchange(withReport(statesTwoPassed[:len(statesTwoPassed)-len("</testsuites>")] +
			strings.Repeat(" ", 8<<20) + "</testsuites>")), Signer: "self_consistent", HeadResult: "match"},
			want: want{"tests": "unknown"}, detail: map[string]string{"tests": "not a JUnit report"}},
		{c: statesCase{Name: "fewer tests than a raised minimum", X: statesExchange(withReport(statesTwoPassed)), Signer: "trusted_key", HeadResult: "match", MinTests: 3},
			want: want{"verdict": "failed", "tests": "discovered", "steps": "passed"}, detail: map[string]string{"verdict": "lists 2 tests that ran; the gate requires at least 3 tests"},
			check: func(t *testing.T, r statesResult) {
				if r.States["tests"]["minimum"] != 3.0 {
					t.Errorf("minimum = %v, want 3", r.States["tests"]["minimum"])
				}
			}},
		{c: statesCase{Name: "a raised minimum met", X: statesExchange(withReport(statesTwoPassed)), Signer: "trusted_key", HeadResult: "match", MinTests: 2},
			want: want{"verdict": "passed", "tests": "discovered"}},
		{c: statesCase{Name: "a minimum with no report requested", X: statesExchange(nil), Signer: "trusted_key", HeadResult: "match", MinTests: 1},
			want: want{"verdict": "failed", "tests": "unknown", "steps": "passed"}, detail: map[string]string{"verdict": "no test report was requested"}},
		{c: statesCase{Name: "a call with no answer stays unknown though its report is missing", X: statesExchange(func(x, request, project map[string]any) {
			request["project"].(map[string]any)["artifacts"] = []string{"reports.xml"}
			x["response"].(map[string]any)["record"].(map[string]any)["unanswered"] = "deadline_exceeded"
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "unknown", "run": "unknown", "tests": "unknown"}},
		{c: statesCase{Name: "output was cut", X: statesExchange(func(x, request, project map[string]any) {
			project["steps"].([]map[string]any)[0]["stdout_truncated"] = true
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "incomplete", "evidence": "partial"}, detail: map[string]string{"evidence": "step 1 stdout", "verdict": "part of the evidence"}},
		{c: statesCase{Name: "the report lists a failure though every step exited 0", X: statesExchange(withReport(formatsJUnit)), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "steps": "passed", "tests": "discovered"}, detail: map[string]string{"verdict": "lists failures", "tests": "1 failed"}},
		{c: statesCase{Name: "a step failed", X: statesExchange(func(x, request, project map[string]any) {
			project["steps"] = []map[string]any{statesStep(1, false)}
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "run": "completed", "steps": "failed"}, detail: map[string]string{"steps": "exited 1"}},
		{c: statesCase{Name: "the run timed out", X: statesExchange(func(x, request, project map[string]any) {
			project["outcome"] = "PROJECT_OUTCOME_TIMED_OUT"
			project["steps"] = []map[string]any{statesStep(124, true)}
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "run": "timed_out", "steps": "failed"}, detail: map[string]string{"run": "30-second limit", "verdict": "did not complete"}},
		{c: statesCase{Name: "setup failed", X: statesExchange(func(x, request, project map[string]any) {
			project["outcome"] = "PROJECT_OUTCOME_SETUP_FAILED"
			project["steps"] = []map[string]any{}
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "run": "setup_failed", "steps": "not_run"}, detail: map[string]string{"run": "0 of 1 steps ran"}},
		{c: statesCase{Name: "the runner failed after every step passed", X: statesExchange(func(x, request, project map[string]any) {
			project["outcome"] = "PROJECT_OUTCOME_RUNNER_FAILED"
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "run": "runner_failed", "steps": "passed"}},
		{c: statesCase{Name: "no readable result", X: statesExchange(func(x, request, project map[string]any) {
			project["outcome"] = "PROJECT_OUTCOME_PROTOCOL_ERROR"
			project["steps"] = []map[string]any{}
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "run": "protocol_error", "steps": "unknown", "evidence": "unknown"}},
		{c: statesCase{Name: "an outcome this reader does not know", X: statesExchange(func(x, request, project map[string]any) {
			project["outcome"] = "PROJECT_OUTCOME_UNSPECIFIED"
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "unknown", "run": "unknown", "evidence": "unknown"}, detail: map[string]string{"run": "PROJECT_OUTCOME_UNSPECIFIED"}},
		{c: statesCase{Name: "a call that got no answer", X: statesExchange(func(x, request, project map[string]any) {
			x["response"].(map[string]any)["record"].(map[string]any)["unanswered"] = "deadline_exceeded"
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "unknown", "run": "unknown"}, detail: map[string]string{"run": "deadline_exceeded"}},
		{c: statesCase{Name: "below the kernel floor", X: statesExchange(func(x, request, project map[string]any) {
			x["response"].(map[string]any)["isolation"] = "container"
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "failed", "run": "completed"}, detail: map[string]string{"run": "below the kernel floor", "verdict": "below the kernel floor"}},
		{c: statesCase{Name: "a step with no exit code", X: statesExchange(func(x, request, project map[string]any) {
			delete(project["steps"].([]map[string]any)[0], "exit_code")
		}), Signer: "trusted_key", HeadResult: "match"},
			want: want{"verdict": "unknown", "steps": "unknown"}},
		{c: statesCase{Name: "signed only with the key it carries", X: statesExchange(withReport(statesTwoPassed)), Signer: "self_consistent", HeadResult: "match"},
			want:   want{"verdict": "incomplete", "signer": "self_consistent", "candidate": "current", "tests": "discovered"},
			detail: map[string]string{"signer": "not who made it", "verdict": "signed only with the key it carries"},
			check: func(t *testing.T, r statesResult) {
				if !hasCode(r, "signer_identity") {
					t.Errorf("unverified does not name the signer: %v", r.Unverified)
				}
			}},
		{c: statesCase{Name: "a receipt for another commit", X: statesExchange(withReport(statesTwoPassed)), Signer: "trusted_key", Given: other("head", strings.Repeat("e", 40)), HeadResult: "differs"},
			want: want{"verdict": "refused", "covers": "known", "candidate": "stale", "steps": "passed"}, detail: map[string]string{"candidate": "not the head `eeee"}},
		{c: statesCase{Name: "another repository", X: statesExchange(nil), Signer: "trusted_key", Given: other("repository", "example/elsewhere"), HeadResult: "differs"},
			want: want{"verdict": "refused", "candidate": "other"}, detail: map[string]string{"candidate": "`example/elsewhere`"}},
		{c: statesCase{Name: "another pull request", X: statesExchange(nil), Signer: "trusted_key", Given: other("pr", "1"), HeadResult: "differs"},
			want: want{"verdict": "refused", "candidate": "other"}, detail: map[string]string{"candidate": "pull request"}},
		{c: statesCase{Name: "no subject", X: statesExchange(func(x, request, project map[string]any) {
			request["project"].(map[string]any)["files"] = []any{}
		}), Signer: "trusted_key", HeadResult: "differs"},
			want: want{"verdict": "refused", "covers": "unknown", "candidate": "other"}},
		{c: statesCase{Name: "the head's commit with other files", X: statesExchange(nil), Signer: "trusted_key", HeadResult: "differs"},
			want: want{"verdict": "refused", "candidate": "mismatch"}},
		{c: statesCase{Name: "the head's request could not be rebuilt", X: statesExchange(withReport(statesTwoPassed)), Signer: "trusted_key", HeadResult: "unbuilt"},
			want: want{"verdict": "unknown", "candidate": "unknown"}, detail: map[string]string{"candidate": "could not be rebuilt"}},
		{c: statesCase{Name: "no head given", X: statesExchange(nil), Signer: "trusted_key", Given: map[string]string{}},
			want: want{"verdict": "unknown", "candidate": "unknown"}},
		{c: statesCase{Name: "the signature does not check", X: statesExchange(withReport(statesTwoPassed)), Signer: "refused", HeadResult: "match"},
			want: want{"verdict": "refused", "signer": "refused", "covers": "unknown", "candidate": "unknown", "run": "unknown", "steps": "unknown", "tests": "unknown", "evidence": "unknown"},
			check: func(t *testing.T, r statesResult) {
				if len(r.Unverified) != 1 || r.Unverified[0].Code != "everything" {
					t.Errorf("unverified: %v", r.Unverified)
				}
			}},
		{c: statesCase{Name: "the check could not run", Signer: "unknown"},
			want: want{"verdict": "unknown", "signer": "unknown", "run": "unknown"}},
		{c: statesCase{Name: "a report beside the receipt that differs from it", X: statesExchange(withReport(statesTwoPassed)), Signer: "trusted_key", HeadResult: "match", Companions: map[string]any{"junit": false, "test-result": true}},
			want: want{"verdict": "refused", "tests": "discovered"}, detail: map[string]string{"verdict": "the junit.xml given with the receipt does not match"}},
		{c: statesCase{Name: "companion files not given", X: statesExchange(func(x, request, project map[string]any) {
			request["project"].(map[string]any)["artifacts"] = []string{"reports.xml", "lcov.info"}
			project["artifacts"] = []map[string]any{returned("reports.xml", statesTwoPassed), returned("lcov.info", formatsLcov)}
		}), Signer: "trusted_key", HeadResult: "match", Companions: map[string]any{}},
			want: want{"verdict": "passed"},
			check: func(t *testing.T, r statesResult) {
				for _, c := range []string{"junit_file", "test_result_statement", "coverage_file", "merge_result", "authorship", "test_quality"} {
					if !hasCode(r, c) {
						t.Errorf("unverified does not name %s: %v", c, r.Unverified)
					}
				}
			}},
	}
	in := make([]statesCase, len(cases))
	for i, c := range cases {
		in[i] = c.c
		if in[i].Given == nil {
			in[i].Given = given
		}
		if in[i].Companions == nil {
			in[i].Companions = none
		}
	}
	results, values := statesDerive(t, in)
	order := []string{"verdict", "signer", "covers", "candidate", "run", "steps", "tests", "evidence"}
	seen := map[string]map[string]bool{}
	for i, c := range cases {
		r := results[i]
		t.Run(c.c.Name, func(t *testing.T) {
			for name, value := range c.want {
				if got := r.States[name]["value"]; got != value {
					t.Errorf("%s = %v, want %s (%v)", name, got, value, r.States[name]["detail"])
				}
			}
			for name, phrase := range c.detail {
				if d, _ := r.States[name]["detail"].(string); !strings.Contains(d, phrase) {
					t.Errorf("%s detail %q does not say %q", name, d, phrase)
				}
			}
			if c.check != nil {
				c.check(t, r)
			}
			// Unknown never rounds up: only an established receipt reads as passed, and the
			// summary's heading says what the verdict says, one line per state below it.
			if v := r.States["verdict"]["value"]; v == "passed" && (c.want["verdict"] != "passed") {
				t.Errorf("partial evidence read as passed: %v", r.States)
			}
			if len(r.Summary) < len(order)+2 || r.Summary[0] != "### plimsoll receipt: "+r.States["verdict"]["value"].(string) {
				t.Fatalf("summary: %q", r.Summary)
			}
			for j, name := range order {
				label := strings.ToUpper(name[:1]) + name[1:]
				if !strings.HasPrefix(r.Summary[2+j], "- **"+label+":** `"+r.States[name]["value"].(string)+"`. ") {
					t.Errorf("summary line %d is not the %s state: %q", 2+j, name, r.Summary[2+j])
				}
			}
		})
		for _, name := range order {
			if seen[name] == nil {
				seen[name] = map[string]bool{}
			}
			v, _ := r.States[name]["value"].(string)
			seen[name][v] = true
			if !contains(values[name], v) {
				t.Errorf("%s: %s = %q is not one of %v", c.c.Name, name, v, values[name])
			}
		}
	}
	// Each value of the closed set is given by some case above.
	for _, name := range order {
		for _, v := range values[name] {
			if seen[name][v] {
				continue
			}
			t.Errorf("no case gives %s = %s", name, v)
		}
	}
}

// receiptStates reads the states.json receipt.sh wrote into out.
func receiptStates(t *testing.T, out string) statesReport {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(out, "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r statesReport
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("states.json: %v\n%s", err, raw)
	}
	return r
}

func wantStates(t *testing.T, name string, r statesReport, want map[string]string) {
	t.Helper()
	for state, value := range want {
		if got := r.States[state]["value"]; got != value {
			t.Errorf("%s: %s = %v, want %s (%v)", name, state, got, value, r.States[state]["detail"])
		}
	}
}

func hasCode(r statesResult, code string) bool {
	for _, u := range r.Unverified {
		if u.Code == code {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

type statesReport struct {
	Verified   bool
	Error      string
	States     map[string]map[string]any
	Unverified []struct{ Code, Detail string }
	Checks     []struct {
		Check  string
		Passed *bool
		Detail string
	}
}

// The published receipt through verify.py: made with a key for the run, so only
// self-consistent; for the published commit, so stale against a fixture commit of its own;
// run completed, every step passed, no test report requested, so how many tests ran is
// unknown. Its verdict is refused, never passed.
func TestReceiptStatesOnThePublishedReceipt(t *testing.T) {
	dir := receiptScratch(t)
	sbom := filepath.Join(dir, "sbom")
	if out, err := exec.Command("go", "-C", "../sbom", "build", "-o", sbom, ".").CombinedOutput(); err != nil {
		t.Fatalf("build the checker: %v\n%s", err, out)
	}
	attestBin := filepath.Join(dir, "plimsoll-attest")
	if out, err := exec.Command("go", "build", "-o", attestBin, "../../cmd/plimsoll-attest").CombinedOutput(); err != nil {
		t.Fatalf("build plimsoll-attest: %v\n%s", err, out)
	}
	receipt, err := filepath.Abs(glob1(t, "evidence/run-*.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := filepath.Abs("evidence")
	if err != nil {
		t.Fatal(err)
	}
	project, commit := receiptFixture(t, dir)
	verify := func(head string, extra ...string) (statesReport, int, []byte) {
		t.Helper()
		args := append([]string{"-I", "verify.py", "--sbom", sbom, "--receipt", receipt, "--repo", project,
			"--repository", "example/pr-receipt-fixture", "--head", head, "--pr", "0", "--command", "npm test",
			"--junit", filepath.Join(evidence, "junit.xml"), "--attest", attestBin,
			"--test-result", filepath.Join(evidence, "test-result.intoto.json")}, extra...)
		out, err := receiptCommand(t, nil, "python3", args...)
		code := 0
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		var r statesReport
		if code != 2 {
			if err := json.Unmarshal(out, &r); err != nil {
				t.Fatalf("not a JSON report (exit %d): %v\n%s", code, err, out)
			}
		}
		return r, code, out
	}
	value := func(r statesReport, name string) string { v, _ := r.States[name]["value"].(string); return v }
	published := map[string]string{"covers": "known", "candidate": "stale", "run": "completed", "steps": "passed", "tests": "unknown", "evidence": "complete", "verdict": "refused"}

	selfReport, code, selfOut := verify(commit, "--self-consistent")
	if code != 1 || selfReport.Verified {
		t.Fatalf("a self-consistent reading was verified (exit %d):\n%s", code, selfOut)
	}
	trusted, code, out := verify(commit, "--trusted-pub", filepath.Join(evidence, "harness.pub"))
	if code != 1 || trusted.Verified {
		t.Fatalf("a receipt for another commit was verified (exit %d):\n%s", code, out)
	}
	for signer, r := range map[string]statesReport{"self_consistent": selfReport, "trusted_key": trusted} {
		if got := value(r, "signer"); got != signer {
			t.Errorf("signer = %s, want %s", got, signer)
		}
		for name, want := range published {
			if got := value(r, name); got != want {
				t.Errorf("%s reading: %s = %s, want %s (%v)", signer, name, got, want, r.States[name]["detail"])
			}
		}
		if r.States["covers"]["commit"] != statesCommit || r.States["candidate"]["head"] != commit || r.States["run"]["isolation"] != "kernel" {
			t.Errorf("%s reading: covers %v, candidate %v, run %v", signer, r.States["covers"], r.States["candidate"], r.States["run"])
		}
	}
	// Self-consistent: the test-result statement is checked against the key the receipt
	// carries, and who signed it stays unverified.
	for _, c := range selfReport.Checks {
		if c.Check != "head" && (c.Passed == nil || !*c.Passed) {
			t.Errorf("self-consistent reading: the %s check did not pass: %s", c.Check, c.Detail)
		}
	}
	if len(selfReport.Checks) != 5 {
		t.Errorf("self-consistent reading: want signature, head, junit, test-result and result checks, got %+v", selfReport.Checks)
	}
	selfCodes := map[string]bool{}
	for _, u := range selfReport.Unverified {
		selfCodes[u.Code] = true
	}
	if !selfCodes["signer_identity"] || !selfCodes["test_count"] || selfCodes["junit_file"] {
		t.Errorf("self-consistent unverified: %v", selfReport.Unverified)
	}

	// For its own commit, which this clone does not hold: the request cannot be rebuilt, so
	// whether it is current stays unknown, and so does the verdict.
	unbuilt, code, out := verify(statesCommit, "--trusted-pub", filepath.Join(evidence, "harness.pub"))
	if code != 1 || value(unbuilt, "candidate") != "unknown" || value(unbuilt, "verdict") != "unknown" {
		t.Errorf("a head the clone lacks: exit %d, candidate %s, verdict %s\n%s", code, value(unbuilt, "candidate"), value(unbuilt, "verdict"), out)
	}

	// Exactly one of the two readings.
	for _, extra := range [][]string{{}, {"--self-consistent", "--trusted-pub", filepath.Join(evidence, "harness.pub")}} {
		if _, code, out := verify(commit, extra...); code != 2 {
			t.Errorf("%v: exit %d, want a usage error\n%s", extra, code, out)
		}
	}
	// A check that could not run still names every state, all unknown.
	empty := filepath.Join(dir, "empty.pub")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	broken, code, out := verify(commit, "--trusted-pub", empty)
	if code != 3 || value(broken, "verdict") != "unknown" || value(broken, "signer") != "unknown" || value(broken, "tests") != "unknown" {
		t.Errorf("an unusable key: exit %d\n%s", code, out)
	}

	// The job summary from the self-consistent report, with the upload's outcome, and with
	// no report at all.
	report := filepath.Join(dir, "states.json")
	if err := os.WriteFile(report, selfOut, 0o644); err != nil {
		t.Fatal(err)
	}
	summary := func(path string, extra ...string) string {
		t.Helper()
		out, err := receiptCommand(t, nil, "python3", append([]string{"-I", "states.py", "summary", path}, extra...)...)
		if err != nil {
			t.Fatalf("states.py summary: %v\n%s", err, out)
		}
		return string(out)
	}
	for outcome, want := range map[string]string{"success": "`uploaded`. Kept as the workflow artifact `plimsoll-pr-0`.",
		"failure": "`not_uploaded`. The upload step ended failure", "skipped": "`not_uploaded`. The upload step did not run", "": "`unknown`."} {
		got := summary(report, "--uploaded", outcome, "--artifact", "plimsoll-pr-0")
		if !strings.HasPrefix(got, "### plimsoll receipt: refused\n") || !strings.Contains(got, "- **Signer:** `self_consistent`.") ||
			!strings.Contains(got, "- **Candidate:** `stale`.") || !strings.Contains(got, "- **Stored:** "+want) {
			t.Errorf("--uploaded %q:\n%s", outcome, got)
		}
	}
	if got := summary(filepath.Join(dir, "missing.json")); !strings.HasPrefix(got, "### plimsoll receipt: unknown\n") || !strings.Contains(got, "did not write states.json") || strings.Contains(got, "Stored") {
		t.Errorf("no report:\n%s", got)
	}
	for name, body := range map[string]string{"empty.json": "", "list.json": "[]", "partial.json": `{"states": {"verdict": {"value": "passed", "detail": "x"}}}`} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := summary(path); !strings.HasPrefix(got, "### plimsoll receipt: unknown\n") || !strings.Contains(got, "states.json is not a report of them") {
			t.Errorf("%s:\n%s", name, got)
		}
	}
}

// Each state, and each of its values, is explained in the README's section on states.
func TestReceiptStatesAreExplainedInTheREADME(t *testing.T) {
	_, values := statesDerive(t, []statesCase{})
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	section := regexp.MustCompile(`(?s)\n## Receipt states[^\n]*\n(.*?)(\n## |\z)`).FindStringSubmatch(string(raw))
	if section == nil {
		t.Fatal("the README has no section headed Receipt states")
	}
	for name, vs := range values {
		if !strings.Contains(section[1], "`"+name+"`") {
			t.Errorf("the README's states section does not name %s", name)
		}
		for _, v := range vs {
			if !strings.Contains(section[1], "`"+v+"`") {
				t.Errorf("the README's states section does not explain %s = %s", name, v)
			}
		}
	}
}

// The workflow writes the receipt's states to the job summary after the upload, whatever
// came before, from the trusted pinned tools, and compares with the event's head.
func TestReceiptWorkflowWritesItsStatesToTheJobSummary(t *testing.T) {
	raw, err := os.ReadFile("workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	w := string(raw)
	for _, s := range []string{
		"      PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}\n",
		"        id: upload\n",
		"        if: ${{ always() }}\n",
		"          UPLOAD_OUTCOME: ${{ steps.upload.outcome }}\n",
		"python3 -I tools/plimsoll/examples/pr-receipt/states.py summary receipt/states.json",
		`--uploaded "$UPLOAD_OUTCOME"`,
		`>> "$GITHUB_STEP_SUMMARY"`,
	} {
		if !strings.Contains(w, s) {
			t.Errorf("workflow.yml does not hold %q", s)
		}
	}
	if up, sum := strings.Index(w, "id: upload"), strings.Index(w, "states.py summary"); up < 0 || sum < up {
		t.Error("the summary step does not come after the upload step, so it cannot say whether the receipt was kept")
	}
	if strings.LastIndex(w, "      - name: ") > strings.Index(w, "states.py summary") {
		t.Error("a step comes after the summary step")
	}
}
