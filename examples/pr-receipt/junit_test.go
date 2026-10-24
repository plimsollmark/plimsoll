package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// receiptFixture makes a git project holding the fixture files in one commit and returns
// its directory and the commit.
func receiptFixture(t *testing.T, dir string) (string, string) {
	t.Helper()
	project := filepath.Join(dir, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"package.json", "sum.mjs", "test.mjs"} {
		b, err := os.ReadFile(filepath.Join("fixture", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}} {
		if out, err := receiptCommand(t, nil, "git", append([]string{"-C", project}, args...)...); err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
	}
	return project, receiptCommit(t, project)
}

// A JUnit path asks the sandbox to return that one file; anything but a plain relative
// name, or a tracked file the tests would not have to write, is refused before any run.
func TestReceiptJUnitPathPreparation(t *testing.T) {
	dir := receiptScratch(t)
	project, _ := receiptFixture(t, dir)
	base := []string{"TEST_COMMAND=npm test", "PR_NUMBER=7", "PR_REPOSITORY=example/project"}
	prepare := func(name string, extra ...string) (map[string]any, string, error) {
		t.Helper()
		out := filepath.Join(dir, name)
		log, err := receiptCommand(t, append(base[:3:3], extra...), "python3", "-I", "prepare.py", project, out)
		if err != nil {
			return nil, string(log), err
		}
		raw, err := os.ReadFile(filepath.Join(out, "request.json"))
		if err != nil {
			t.Fatal(err)
		}
		var q map[string]any
		if err := json.Unmarshal(raw, &q); err != nil {
			t.Fatal(err)
		}
		return q, string(raw), nil
	}
	_, raw, err := prepare("none")
	if err != nil {
		t.Fatalf("no JUnit path: %v: %s", err, raw)
	}
	// With no path the request is what it was before JUnit existed: no artifacts key.
	if strings.Contains(raw, "artifacts") {
		t.Fatalf("a request with no JUnit path names artifacts:\n%s", raw)
	}
	q, raw, err := prepare("with", "JUNIT_PATH=reports/junit.xml")
	if err != nil {
		t.Fatalf("JUNIT_PATH=reports/junit.xml: %v: %s", err, raw)
	}
	if got := q["project"].(map[string]any)["artifacts"]; len(got.([]any)) != 1 || got.([]any)[0] != "reports/junit.xml" {
		t.Fatalf("artifacts = %v, want [reports/junit.xml]", got)
	}
	for _, bad := range []string{"../junit.xml", "/junit.xml", ".junit.xml", "a//junit.xml", "a/./junit.xml", "a/../junit.xml",
		"reports/", "junit xml", ".pr-receipt/junit.xml", "test.mjs", strings.Repeat("a", 257)} {
		if _, log, err := prepare("bad", "JUNIT_PATH="+bad); err == nil || !strings.Contains(log, "JUNIT_PATH") {
			t.Errorf("JUNIT_PATH=%q: want a refusal naming JUNIT_PATH, got %v: %s", bad, err, log)
		}
	}
}

// junitBOM writes a receipt holding exchange x the way the converter attaches it.
func junitBOM(t *testing.T, dir string, x map[string]any) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exchange, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	bom := map[string]any{"declarations": map[string]any{"evidence": []any{map[string]any{"data": []any{
		map[string]any{"name": "exchange.json", "contents": map[string]any{"attachment": map[string]any{
			"content": base64.StdEncoding.EncodeToString(exchange)}}}}}}}}
	b, err := json.Marshal(bom)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run-test.cdx.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func junitExchange(steps []string, ran []map[string]any, outcome string, artifacts []string, returned []map[string]any, truncated bool) map[string]any {
	return map[string]any{
		"request": map[string]any{"project": map[string]any{"steps": steps, "artifacts": artifacts}},
		"response": map[string]any{
			"isolation": "kernel",
			"record": map[string]any{"record_sha256": strings.Repeat("a", 64), "request_sha256": strings.Repeat("b", 64),
				"result_sha256": strings.Repeat("c", 64), "isolation": "kernel", "provider": "docker"},
			"project": map[string]any{"steps": ran, "outcome": outcome, "artifacts": returned, "artifacts_truncated": truncated},
		},
	}
}

type junitSuites struct {
	Tests    int `xml:"tests,attr"`
	Failures int `xml:"failures,attr"`
	Errors   int `xml:"errors,attr"`
	Skipped  int `xml:"skipped,attr"`
	Suite    struct {
		Properties []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:"value,attr"`
		} `xml:"properties>property"`
		Cases []struct {
			Name    string `xml:"name,attr"`
			Failure *struct {
				Message string `xml:"message,attr"`
			} `xml:"failure"`
			Error *struct {
				Type    string `xml:"type,attr"`
				Message string `xml:"message,attr"`
			} `xml:"error"`
			Skipped *struct{} `xml:"skipped"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

// junit.xml is the framework's report byte for byte when one was requested and returned,
// nothing when it was requested and not returned, and otherwise built from the signed
// steps, the same bytes every time.
func TestReceiptJUnitFromSignedResult(t *testing.T) {
	dir := receiptScratch(t)
	run := func(name string, x map[string]any) (string, []byte) {
		t.Helper()
		out := filepath.Join(dir, name)
		junitBOM(t, out, x)
		log, err := receiptCommand(t, nil, "python3", "-I", "junit.py", out)
		if err != nil {
			t.Fatalf("%s: junit.py: %v: %s", name, err, log)
		}
		b, err := os.ReadFile(filepath.Join(out, "junit.xml"))
		if os.IsNotExist(err) {
			return string(log), nil
		} else if err != nil {
			t.Fatal(err)
		}
		return string(log), b
	}
	parse := func(name string, b []byte) junitSuites {
		t.Helper()
		var s junitSuites
		if err := xml.Unmarshal(b, &s); err != nil {
			t.Fatalf("%s: junit.xml does not parse: %v\n%s", name, err, b)
		}
		return s
	}
	ok := func(ms string) map[string]any {
		return map[string]any{"command": "x", "duration_ms": ms, "exit_code": 0, "timed_out": false}
	}
	twoSteps := []string{`npm test -- --grep "<a & b>"`, "npm run lint"}

	_, passed := run("passed", junitExchange(twoSteps, []map[string]any{ok("1500"), ok("20")}, "PROJECT_OUTCOME_COMPLETED", nil, nil, false))
	s := parse("passed", passed)
	if s.Tests != 2 || s.Failures+s.Errors+s.Skipped != 0 || s.Suite.Cases[0].Name != `step 1: npm test -- --grep "<a & b>"` {
		t.Errorf("passed: %+v", s)
	}
	props := map[string]string{}
	for _, p := range s.Suite.Properties {
		props[p.Name] = p.Value
	}
	if props["plimsoll.record_sha256"] != strings.Repeat("a", 64) || props["plimsoll.isolation"] != "kernel" || props["plimsoll.junit_source"] != "steps" {
		t.Errorf("passed: properties %v", props)
	}
	if _, again := run("passed-again", junitExchange(twoSteps, []map[string]any{ok("1500"), ok("20")}, "PROJECT_OUTCOME_COMPLETED", nil, nil, false)); !bytes.Equal(again, passed) {
		t.Errorf("the same result gave different bytes:\n%s\n%s", passed, again)
	}

	failed := ok("10")
	failed["exit_code"] = 3
	_, b := run("failed", junitExchange(twoSteps, []map[string]any{failed}, "PROJECT_OUTCOME_COMPLETED", nil, nil, false))
	if s := parse("failed", b); s.Failures != 1 || s.Skipped != 1 || s.Suite.Cases[0].Failure == nil || s.Suite.Cases[0].Failure.Message != "exit code 3" || s.Suite.Cases[1].Skipped == nil {
		t.Errorf("failed: %+v", s)
	}

	timedOut := ok("30000")
	timedOut["timed_out"] = true
	_, b = run("timed-out", junitExchange(twoSteps[:1], []map[string]any{timedOut}, "PROJECT_OUTCOME_TIMED_OUT", nil, nil, false))
	if s := parse("timed-out", b); s.Errors != 1 || len(s.Suite.Cases) != 1 || s.Suite.Cases[0].Error == nil || s.Suite.Cases[0].Error.Type != "timeout" {
		t.Errorf("timed out: %+v", s)
	}

	// The runner failed with no step to blame: the outcome is named, never its detail text.
	setup := junitExchange(twoSteps[:1], nil, "PROJECT_OUTCOME_SETUP_FAILED", nil, nil, false)
	setup["response"].(map[string]any)["project"].(map[string]any)["outcome_detail"] = "guest-shaped text"
	_, b = run("setup", setup)
	if s := parse("setup", b); s.Skipped != 1 || s.Errors != 1 || s.Suite.Cases[1].Error.Message != "PROJECT_OUTCOME_SETUP_FAILED" || bytes.Contains(b, []byte("guest-shaped")) {
		t.Errorf("setup failed: %+v\n%s", s, b)
	}

	report := []byte("<testsuites name=\"node\">\n\t<!-- the framework's bytes, kept exactly -->\n</testsuites>\r\n")
	returned := []map[string]any{{"path": "reports/junit.xml", "content": base64.StdEncoding.EncodeToString(report)}}
	log, b := run("framework", junitExchange(twoSteps[:1], []map[string]any{ok("5")}, "PROJECT_OUTCOME_COMPLETED", []string{"reports/junit.xml"}, returned, false))
	if !bytes.Equal(b, report) || !strings.Contains(log, "framework's own reports/junit.xml") {
		t.Errorf("framework report: %q (%s)", b, log)
	}
	for name, truncated := range map[string]bool{"not-written": false, "truncated": true} {
		log, b := run(name, junitExchange(twoSteps[:1], []map[string]any{ok("5")}, "PROJECT_OUTCOME_COMPLETED", []string{"reports/junit.xml"}, nil, truncated))
		want := "did not write it"
		if truncated {
			want = "over the artifact budget"
		}
		if b != nil || !strings.Contains(log, want) {
			t.Errorf("%s: wrote %q; log %q, want it to say %q", name, b, log, want)
		}
	}
}
