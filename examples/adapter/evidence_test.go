package main

import (
	"path/filepath"
	"testing"
)

// The published bundle and qualification statements verify offline: every record's
// signature, every statement bound to its run, and every verdict rebuilt from its
// evidence by the rules in package qualify as they are now. A change to the rules that
// would judge a published run differently fails here until the example is rerun.
func TestPublishedEvidenceVerifies(t *testing.T) {
	t.Chdir(filepath.Join("..", "..")) // runPlan, like the program, reads from the repository root
	n, err := verifyDir(filepath.Join("docs", "examples", "adapter"))
	if err != nil {
		t.Fatal(err)
	}
	if want := len(runPlan()); n != want {
		t.Fatalf("%d statements verified, want one per run, %d", n, want)
	}
}
