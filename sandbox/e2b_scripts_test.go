package sandbox

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestDockerRunsTheE2BSmokeScript runs the program E2B's smoke test stages in its
// microVM, as a project step the way E2B runs it, in the docker suite's locked-down
// container (guest_scripts_test.go lists every such program): it must print the report the
// smoke test parses, with node's version, the step's directory, and no egress open.
func TestDockerRunsTheE2BSmokeScript(t *testing.T) {
	requireDocker(t)
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := testDocker().RunProject(ctx, ProjectRequest{
		Files: []File{{Path: "plimsoll-smoke.cjs", Content: vmSmokeProbe}},
		Steps: []string{"node plimsoll-smoke.cjs"}, Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("%s %q steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	var report struct {
		Node       string   `json:"node"`
		Cwd        string   `json:"cwd"`
		EgressOpen []string `json:"egressOpen"`
	}
	if err := json.Unmarshal([]byte(res.Steps[0].Stdout), &report); err != nil {
		t.Fatalf("unparseable report %q: %v", res.Steps[0].Stdout, err)
	}
	if report.Node == "" || report.Cwd != "/work" || len(report.EgressOpen) != 0 {
		t.Fatalf("report %+v", report)
	}
}
