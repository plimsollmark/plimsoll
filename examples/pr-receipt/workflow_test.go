package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The receipt job fails closed only while GitHub cannot turn a skip into a pass. Its
// docs (Troubleshooting required status checks, read 2026-10-27): a workflow skipped by
// a path, branch or commit-message filter leaves its required check "Pending", which
// blocks the merge, but a job skipped by its own `if:` reports "Success", and a job that
// needs a failed job is skipped and "may not block merging". So the workflow keeps one
// job, with no job-level condition, no needs and no event filter.
func TestReceiptWorkflowCannotPassBySkipping(t *testing.T) {
	raw, err := os.ReadFile("workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	section := ""
	jobs := 0
	for i, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			section = strings.TrimSuffix(strings.Fields(line)[0], ":")
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key := strings.TrimSuffix(strings.Fields(strings.TrimSpace(line))[0], ":")
		switch section {
		case "on":
			if indent == 2 && key != "pull_request" {
				t.Errorf("line %d: the workflow runs on %q; want pull_request alone", i+1, key)
			}
			if indent > 2 {
				t.Errorf("line %d: %q filters pull_request; a filtered-out run leaves the required check pending, which blocks every pull request the filter skips", i+1, key)
			}
		case "jobs":
			if indent == 2 {
				jobs++
			}
			if indent == 4 && (key == "if" || key == "needs") {
				t.Errorf("line %d: a job-level %q lets the job be skipped, and a skipped job reports Success", i+1, key)
			}
		}
	}
	if jobs != 1 {
		t.Errorf("%d jobs; want the one receipt job, so the required check names it", jobs)
	}
	if !regexp.MustCompile(`(?m)^on:\n  pull_request:\s*$`).MatchString(string(raw)) {
		t.Error("the workflow's trigger is not a bare pull_request")
	}
}
