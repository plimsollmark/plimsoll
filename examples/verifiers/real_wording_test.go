package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// renderGathered gathers a made-up run, with the edits and the solvable file given, and renders
// the page.
func renderGathered(t *testing.T, edit func(s map[string]any), solvable string) string {
	t.Helper()
	src := runOutput(t, edit)
	if solvable != "" {
		if err := os.WriteFile(filepath.Join(src, solvableFile), []byte(solvable), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	if err := gatherReal(src, dir, "/no/such/repo"); err != nil {
		t.Fatal(err)
	}
	real, err := loadReal(dir)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := loadEvidence(published)
	if err != nil {
		t.Fatal(err)
	}
	page, err := render(ev, real)
	if err != nil {
		t.Fatal(err)
	}
	return string(page)
}

// The token budgets are described as what they are: with a per-attempt budget below the run's
// and below the dollar cap, the page says the per-attempt budget is the limit that binds, names
// the longest attempt's tokens from the data, and never claims the dollars always stop a run first.
func TestPageDescribesAPerAttemptBudgetBelowTheDollarCap(t *testing.T) {
	page := renderGathered(t, func(s map[string]any) { realOf(s)["attempt_token_budget"] = 400000 }, "")
	for _, want := range []string{
		"The run also had token budgets: 32 million (32,000,001) billed tokens",
		"the per-attempt budget, not the dollars, is the limit one runaway attempt would reach first",
		"The longest attempt, task 1, billed 220,000 of those 400,000 tokens",
		"a spending limit in force, of which $0.0225 of $0.96 was spent",
		"may be able to read the driver program's memory, where the kernel allows it",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the section does not say %q", want)
		}
	}
	for _, gone := range []string{"always stop a run first", "a spending limit that held", "no attempt was stopped by a budget"} {
		if strings.Contains(page, gone) {
			t.Errorf("the section says %q", gone)
		}
	}
	equal := renderGathered(t, nil, "")
	if strings.Contains(equal, "not the dollars, is the limit") || !strings.Contains(equal, "each at least what the dollar cap buys at the cheapest price") {
		t.Error("equal budgets are described as a per-attempt limit")
	}
	if !strings.Contains(equal, "32 million (32,000,001) for the run") {
		t.Error("the run budget reads as a typo")
	}
	calm := renderGathered(t, func(s map[string]any) {
		realOf(s)["attempt_token_budget"] = 400000
		s["rollouts"].([]map[string]any)[1]["relay_refused"] = nil
	}, "")
	if !strings.Contains(calm, "no attempt was stopped by a budget") {
		t.Error("a run with no stopped attempt does not say so")
	}
}

// That the task is solvable appears only when the private check's file says every instance was.
func TestPageSaysSolvableOnlyWhenTheCheckSaysSo(t *testing.T) {
	const sentence = "The task can be solved from what the sandbox holds"
	page := renderGathered(t, nil, `{"solvable_from_corpus": 3, "of": 3, "checked_on": "2026-10-30"}`)
	if !strings.Contains(page, sentence) || !strings.Contains(page, "on all 3 of these instances (checked 2026-10-30)") {
		t.Error("a passing check is not on the page")
	}
	for name, file := range map[string]string{
		"no file":     "",
		"some solved": `{"solvable_from_corpus": 2, "of": 3, "checked_on": "2026-10-30"}`,
		"none solved": `{"solvable_from_corpus": 0, "of": 3, "checked_on": "2026-10-30"}`,
	} {
		if strings.Contains(renderGathered(t, nil, file), sentence) {
			t.Errorf("%s: the page says the task is solvable", name)
		}
	}
	for name, file := range map[string]string{
		"another run's count":        `{"solvable_from_corpus": 10, "of": 10, "checked_on": "2026-10-30"}`,
		"no date":                    `{"solvable_from_corpus": 3, "of": 3}`,
		"more solved than instances": `{"solvable_from_corpus": 4, "of": 3, "checked_on": "x"}`,
	} {
		src := runOutput(t, nil)
		if err := os.WriteFile(filepath.Join(src, solvableFile), []byte(file), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := gatherReal(src, t.TempDir(), "/no/such/repo"); err == nil {
			t.Errorf("%s was gathered", name)
		}
	}
}

// With a task solved, the page keeps its hedge; with none solved it says what the run found.
func TestPageSaysWhereTheExpectedValueAppeared(t *testing.T) {
	zero := renderGathered(t, func(s map[string]any) { s["rollouts"].([]map[string]any)[0]["reward"] = 0.0 }, "")
	if !strings.Contains(zero, "the expected value appeared in no message of any attempt: no model computed it") {
		t.Error("a run with no solved attempt does not say the value appeared nowhere")
	}
	if strings.Contains(renderGathered(t, nil, ""), "appeared in no message of any attempt") {
		t.Error("a run with a solved attempt says the value appeared nowhere")
	}
}
