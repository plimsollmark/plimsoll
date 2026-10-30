package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// formatsExchange is junitExchange with what formats.py also reads: the subject file of the
// signed request, the record's environment and start time.
func formatsExchange(steps []string, ran []map[string]any, artifacts []string, returned []map[string]any) map[string]any {
	x := junitExchange(steps, ran, "PROJECT_OUTCOME_COMPLETED", artifacts, returned, false)
	x["request"].(map[string]any)["project"].(map[string]any)["files"] = []any{map[string]any{
		"path":    ".pr-receipt/subject.json",
		"content": `{"commit": "627534fc71de105aeb7e71098970bb51d7096349", "pull_request": "0", "repository": "example/pr-receipt-fixture"}`,
	}}
	record := x["response"].(map[string]any)["record"].(map[string]any)
	record["environment"] = "docker-image:sha256:" + strings.Repeat("d", 64)
	record["started_unix_ms"] = "1792631926772"
	return x
}

func returned(path, content string) map[string]any {
	return map[string]any{"path": path, "content": base64.StdEncoding.EncodeToString([]byte(content))}
}

const formatsJUnit = `<?xml version="1.0" encoding="utf-8"?>
<testsuites>
	<testcase name="adds" classname="test"/>
	<testcase name="breaks" classname="test"><failure message="nope"/></testcase>
	<testcase name="later" classname="test"><skipped/></testcase>
</testsuites>
`

const formatsLcov = `TN:
SF:sum.mjs
FN:1,sum
FNDA:1,sum
BRDA:1,0,0,1
BRDA:1,1,0,-
DA:1,1
DA:2,0
LF:2
LH:1
end_of_record
TN:
SF:lib/util.mjs
DA:1,3
end_of_record
`

// The statement's result comes from the signed exit codes and its test names from the JUnit
// report; the coverage file is the run's lcov in Cobertura, the same bytes every time; a
// report the project wrote badly cannot support PASSED, but never stops the receipt.
func TestReceiptStandardFormats(t *testing.T) {
	dir := receiptScratch(t)
	run := func(name string, x map[string]any) (map[string]any, string, string) {
		t.Helper()
		out := filepath.Join(dir, name)
		junitBOM(t, out, x)
		for _, script := range []string{"junit.py", "formats.py"} {
			if log, err := receiptCommand(t, nil, "python3", "-I", script, out); err != nil {
				t.Fatalf("%s: %s: %v: %s", name, script, err, log)
			}
		}
		var statement map[string]any
		b, err := os.ReadFile(filepath.Join(out, "test-result.statement.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &statement); err != nil {
			t.Fatal(err)
		}
		cov, err := os.ReadFile(filepath.Join(out, "coverage.cobertura.xml"))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return statement, string(cov), string(b)
	}
	command := "node --test test.mjs"
	failed := []map[string]any{{"exit_code": 1, "duration_ms": "40"}}
	artifacts := []string{"reports.xml", "lcov.info"}
	both := []map[string]any{returned("reports.xml", formatsJUnit), returned("lcov.info", formatsLcov)}

	st, cov, raw := run("framework", formatsExchange([]string{command}, failed, artifacts, both))
	pred := st["predicate"].(map[string]any)
	if pred["result"] != "FAILED" {
		t.Errorf("result %v, want FAILED from the exit code", pred["result"])
	}
	if got, _ := json.Marshal(pred["passedTests"]); string(got) != `["adds"]` {
		t.Errorf("passedTests %s", got)
	}
	if got, _ := json.Marshal(pred["failedTests"]); string(got) != `["breaks"]` {
		t.Errorf("failedTests %s", got)
	}
	if got, _ := json.Marshal(st["subject"]); string(got) != `[{"digest":{"gitCommit":"627534fc71de105aeb7e71098970bb51d7096349"},"name":"example/pr-receipt-fixture"}]` {
		t.Errorf("subject %s", got)
	}
	if !strings.Contains(raw, `"isolation": "kernel"`) || !strings.Contains(raw, `"provider": "docker"`) {
		t.Errorf("the run record's configuration entry does not carry the tier and provider:\n%s", raw)
	}
	for _, want := range []string{
		`<coverage line-rate="0.6667" branch-rate="0.5000" lines-covered="2" lines-valid="3" branches-covered="1" branches-valid="2"`,
		`timestamp="1792631926772"`,
		`<package name="." line-rate="0.5000"`, `<package name="lib" line-rate="1.0000"`,
		`<class name="sum.mjs" filename="sum.mjs"`,
		`<line number="1" hits="1" branch="true" condition-coverage="50% (1/2)" />`,
		`<line number="2" hits="0" branch="false" />`,
	} {
		if !strings.Contains(cov, want) {
			t.Errorf("coverage.cobertura.xml lacks %s:\n%s", want, cov)
		}
	}
	if _, again, _ := run("framework-again", formatsExchange([]string{command}, failed, artifacts, both)); again != cov {
		t.Error("the same receipt gave different coverage bytes")
	}

	st, cov, _ = run("steps", formatsExchange([]string{"npm test"}, []map[string]any{{"exit_code": 0}}, nil, nil))
	pred = st["predicate"].(map[string]any)
	if got, _ := json.Marshal(pred["passedTests"]); pred["result"] != "PASSED" || string(got) != `["step 1: npm test"]` || cov != "" {
		t.Errorf("without JUNIT_PATH: result %v, passedTests %s, coverage %q", pred["result"], got, cov)
	}

	bad := []map[string]any{returned("reports.xml", "<testsuites><testcase"), returned("lcov.info", "SF:x\nDA:one,1\n")}
	st, cov, _ = run("unreadable", formatsExchange([]string{command}, []map[string]any{{"exit_code": 0}}, artifacts, bad))
	pred = st["predicate"].(map[string]any)
	if pred["result"] != "FAILED" || pred["passedTests"] != nil || pred["failedTests"] != nil || cov != "" {
		t.Errorf("unreadable reports: %v, coverage %q", pred, cov)
	}
	for name, report := range map[string]string{
		"summary failure":    `<testsuite tests="1" failures="1"/>`,
		"summary error":      `<testsuites errors="1"><testsuite/></testsuites>`,
		"nested failure":     `<testsuites><testsuite failures="1"/></testsuites>`,
		"invalid summary":    `<testsuite failures="unknown"/>`,
		"negative summary":   `<testsuite errors="-1"/>`,
		"unsupported XML":    `<report/>`,
		"namespaced failure": `<testsuite xmlns="urn:junit"><testcase name="x"><failure/></testcase></testsuite>`,
		// Not read at all, though each would pass: a DOCTYPE declaring an entity (the shape
		// of a nested-entity report, which xml.etree would expand), and a report past the
		// 8 MiB a run returns.
		"declared entity": `<!DOCTYPE testsuite [<!ENTITY n "a">]><testsuite tests="1"><testcase name="&n;"/></testsuite>`,
		"past the bound":  `<testsuite tests="1"><testcase name="a"/>` + strings.Repeat(" ", 8<<20) + `</testsuite>`,
	} {
		st, _, _ = run(strings.ReplaceAll(name, " ", "-"), formatsExchange([]string{command}, []map[string]any{{"exit_code": 0}}, artifacts,
			[]map[string]any{returned("reports.xml", report)}))
		if result := st["predicate"].(map[string]any)["result"]; result != "FAILED" {
			t.Errorf("%s: got %v, want FAILED", name, result)
		}
	}
	st, _, _ = run("valid-summary", formatsExchange([]string{command}, []map[string]any{{"exit_code": 0}}, artifacts,
		[]map[string]any{returned("reports.xml", `<testsuite tests="1" failures="0" errors="00"><testcase name="a"/></testsuite>`)}))
	if result := st["predicate"].(map[string]any)["result"]; result != "PASSED" {
		t.Errorf("valid summary: got %v, want PASSED", result)
	}
	// A report in which no test ran shows nothing passed: never PASSED, whatever its counters say.
	for name, report := range map[string]string{
		"zero tests":   `<testsuite tests="0" failures="0" errors="00"/>`,
		"only skipped": `<testsuites><testcase name="a"><skipped/></testcase></testsuites>`,
	} {
		st, _, _ = run(strings.ReplaceAll(name, " ", "-"), formatsExchange([]string{command}, []map[string]any{{"exit_code": 0}}, artifacts,
			[]map[string]any{returned("reports.xml", report)}))
		if result := st["predicate"].(map[string]any)["result"]; result != "FAILED" {
			t.Errorf("%s: got %v, want FAILED", name, result)
		}
	}
	st, _, _ = run("missing-with-zero-exit", formatsExchange([]string{command}, []map[string]any{{"exit_code": 0}}, artifacts, nil))
	if result := st["predicate"].(map[string]any)["result"]; result != "FAILED" {
		t.Errorf("missing requested report: got %v, want FAILED", result)
	}

	// Text that is not an lcov report, or one with no line records, gives no coverage rather
	// than a rate of 1; a branch count of "00" is a branch not taken.
	for name, lcov := range map[string]string{
		"not lcov":           "not an lcov report\n",
		"no line records":    "SF:a.mjs\nend_of_record\n",
		"a record left open": "SF:a.mjs\nDA:1,1\n",
		"a negative count":   "SF:a.mjs\nDA:1,-1\nend_of_record\n",
		"non-ASCII count":    "SF:a.mjs\nDA:1,١\nend_of_record\n",
	} {
		_, cov, _ = run(strings.ReplaceAll(name, " ", "-"), formatsExchange([]string{command}, []map[string]any{{"exit_code": 0}}, artifacts,
			[]map[string]any{returned("reports.xml", formatsJUnit), returned("lcov.info", lcov)}))
		if cov != "" {
			t.Errorf("%s: coverage %q, want none", name, cov)
		}
	}
	st, _, _ = run("contradictory-result", formatsExchange([]string{command}, []map[string]any{{"exit_code": 0}}, artifacts,
		[]map[string]any{returned("reports.xml", formatsJUnit)}))
	if result := st["predicate"].(map[string]any)["result"]; result != "FAILED" {
		t.Errorf("a reported test failure with exit 0 gave %v, want FAILED", result)
	}
	_, cov, _ = run("zero-count", formatsExchange([]string{command}, []map[string]any{{"exit_code": 0}}, artifacts,
		[]map[string]any{returned("reports.xml", formatsJUnit), returned("lcov.info", "SF:a.mjs\nBRDA:1,0,0,00\nDA:1,1\nend_of_record\n")}))
	if !strings.Contains(cov, `branch-rate="0.0000"`) || !strings.Contains(cov, `branches-covered="0"`) {
		t.Errorf("a branch counted 00 counts as taken: %s", cov)
	}

	st, cov, _ = run("missing", formatsExchange([]string{command}, failed, artifacts, nil))
	if pred = st["predicate"].(map[string]any); pred["result"] != "FAILED" || cov != "" {
		t.Errorf("reports not returned: %v, coverage %q", pred, cov)
	}
}
