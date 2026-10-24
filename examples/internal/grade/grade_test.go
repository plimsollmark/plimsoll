package grade

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

type fakeRunner struct {
	req  sandbox.ProjectRequest
	exit int
}

func (f *fakeRunner) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	f.req = req
	res := sandbox.ProjectResult{Outcome: sandbox.ProjectOutcomeCompleted}
	for i := range req.Steps {
		res.Steps = append(res.Steps, sandbox.StepResult{ExitCode: f.exit, Stdout: `{"score":0.5,"failure":null,"i":` + string(rune('0'+i)) + "}\n"})
	}
	return res, nil
}

// Each trajectory goes up base64-encoded, one step decodes it and runs the shipped
// grader on it, and each step's line comes back under its trajectory's ID.
func TestRunSendsEachTrajectoryToTheShippedGrader(t *testing.T) {
	f := &fakeRunner{}
	g, err := Run(context.Background(), f, "buck-converter", 1e-5, []Trajectory{{ID: "s1", Bytes: []byte{0, 1, 2}}, {ID: "s2", Bytes: []byte{255}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.req.Files) != 2 || f.req.Files[0].Path != "s1.b64" || f.req.Files[0].Content != base64.StdEncoding.EncodeToString([]byte{0, 1, 2}) {
		t.Fatalf("files %+v", f.req.Files)
	}
	if want := "base64 -d s1.b64 > s1.bin && node --no-warnings /oracle/graders/buck-converter.mjs s1.bin 1e-05"; f.req.Steps[0] != want {
		t.Fatalf("step %q, want %q", f.req.Steps[0], want)
	}
	if !strings.Contains(string(g.Lines["s2"]), `"i":1`) || len(g.Lines) != 2 {
		t.Fatalf("lines %v", g.Lines)
	}
}

// A name that could reach the shell, a failed step and a refused grader are errors.
func TestRunRefusesWhatItCannotTrust(t *testing.T) {
	if _, err := Run(context.Background(), &fakeRunner{}, "x; rm -rf /", 1, nil); err == nil {
		t.Fatal("a grader name with shell syntax was accepted")
	}
	if _, err := Run(context.Background(), &fakeRunner{}, "buck-converter", 1, []Trajectory{{ID: "$(id)"}}); err == nil {
		t.Fatal("a trajectory ID with shell syntax was accepted")
	}
	if _, err := Run(context.Background(), &fakeRunner{exit: 2}, "buck-converter", 1, []Trajectory{{ID: "s1"}}); err == nil {
		t.Fatal("a failed grading step was accepted")
	}
}
