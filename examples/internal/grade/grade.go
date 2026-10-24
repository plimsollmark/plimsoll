// Package grade scores trajectories with an environment's grader as the simulation
// image ships it, /oracle/graders/<environment>.mjs, in a project run of its own after
// the run that made them. The examples once restated each grader in Go, and nothing
// tied a restatement to the grader it copied (review D9, 2026-10-23); now the score is
// the shipped grader's, the image that ran it is named by the run's environment
// identity, and a run made through a daemon carries a record binding each trajectory,
// as sent, to the line the grader printed for it.
package grade

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Runner runs the grading run: the in-process provider or the official client,
// whichever ran the example's other runs.
type Runner interface {
	RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error)
}

// Trajectory is one trajectory to grade: its ID (a file name) and its bytes.
type Trajectory struct {
	ID    string
	Bytes []byte
}

// Graded is a grading run: each trajectory's grader line by ID, and the run's result,
// whose Record (set when the run went through a daemon) binds them.
type Graded struct {
	Lines  map[string]json.RawMessage
	Result sandbox.ProjectResult
}

var name = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Run grades each trajectory with grader (an environment name, such as
// "buck-converter") at tick length h seconds, one step per trajectory. A trajectory is
// binary and a project file is text, so each goes up base64-encoded and a step decodes
// it before the grader reads it.
func Run(ctx context.Context, r Runner, grader string, h float64, trajectories []Trajectory) (Graded, error) {
	if !name.MatchString(grader) {
		return Graded{}, fmt.Errorf("grader name %q", grader)
	}
	var files []sandbox.File
	var steps []string
	for _, t := range trajectories {
		if !name.MatchString(t.ID) {
			return Graded{}, fmt.Errorf("trajectory ID %q", t.ID)
		}
		files = append(files, sandbox.File{Path: t.ID + ".b64", Content: base64.StdEncoding.EncodeToString(t.Bytes)})
		steps = append(steps, fmt.Sprintf("base64 -d %s.b64 > %s.bin && node --no-warnings /oracle/graders/%s.mjs %s.bin %s",
			t.ID, t.ID, grader, t.ID, strconv.FormatFloat(h, 'g', -1, 64)))
	}
	res, err := r.RunProject(ctx, sandbox.ProjectRequest{Files: files, Steps: steps, Timeout: 60 * time.Second})
	if err != nil {
		return Graded{}, fmt.Errorf("grading run: %w", err)
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != len(steps) {
		return Graded{}, fmt.Errorf("grading run: outcome %s (%s), %d of %d steps ran", res.Outcome, res.Detail, len(res.Steps), len(steps))
	}
	g := Graded{Lines: map[string]json.RawMessage{}, Result: res}
	for i, t := range trajectories {
		st := res.Steps[i]
		line := strings.TrimSpace(st.Stdout)
		if st.ExitCode != 0 || !json.Valid([]byte(line)) {
			return Graded{}, fmt.Errorf("grading %s: exit %d, stdout %q, stderr %q", t.ID, st.ExitCode, line, strings.TrimSpace(st.Stderr))
		}
		g.Lines[t.ID] = json.RawMessage(line)
	}
	return g, nil
}
