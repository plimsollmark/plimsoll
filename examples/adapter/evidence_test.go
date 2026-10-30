package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/examples/adapter/qualify"
)

// The published bundle and qualification statements verify offline: every record's
// signature, every statement bound to its run, every verdict rebuilt from its evidence
// by the rules in package qualify as they are now, and every adapter statement pinning
// the shipped requirements file. A change to the rules that would judge a published run
// differently, or a change to the requirements file, fails here until the example is
// rerun.
func TestPublishedEvidenceVerifies(t *testing.T) {
	t.Chdir(filepath.Join("..", "..")) // runPlan, like the program, reads from the repository root
	reqPath := filepath.Join("examples", "adapter", "contract", "requirements.json")
	verified, reqs, err := verifyDir(filepath.Join("docs", "examples", "adapter"), reqPath)
	if err != nil {
		t.Fatal(err)
	}
	if n, want := len(verified), len(runPlan()); n != want {
		t.Fatalf("%d statements verified, want one per run, %d", n, want)
	}
	adapters := 0
	for _, v := range verified {
		if v.Predicate.Evidence.Kind != qualify.KindAdapter {
			continue
		}
		adapters++
		if v.Predicate.Requirements == nil || v.Predicate.Requirements.SHA256 != reqs.SHA256() || len(v.Predicate.RequirementVerdicts) != len(reqs.Requirements) {
			t.Fatalf("run %d: pin %+v, %d requirement verdicts", v.Predicate.Run, v.Predicate.Requirements, len(v.Predicate.RequirementVerdicts))
		}
	}
	if adapters != len(verified)-1 {
		t.Fatalf("%d adapter statements of %d, want all but the probe's", adapters, len(verified))
	}

	// The same evidence against the requirements file with one word changed: refused, by
	// digest, before any requirement is read.
	data, err := os.ReadFile(reqPath)
	if err != nil {
		t.Fatal(err)
	}
	reworded := filepath.Join(t.TempDir(), "requirements.json")
	if err := os.WriteFile(reworded, bytes.Replace(data, []byte("exactly one order"), []byte("at most one order"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyDir(filepath.Join("docs", "examples", "adapter"), reworded); err == nil || !strings.Contains(err.Error(), "judged against requirements "+reqs.SHA256()[:12]) {
		t.Fatalf("a reworded requirements file: %v", err)
	}
}
