package sandbox

import (
	"context"
	"strings"
	"testing"
)

// The judges' refusals: a controller that does not answer with numbers fails with
// exit 3 (a controller failure), never with a trajectory. Two gaps this closes:
//
//   - A blank line parsed as the number 0 (Number("") is 0, and "".split(/\s+/)
//     is [""]), so a controller that printed nothing, or a policy function that
//     returned an empty array, drove a one-input plant as if it had answered 0.
//     Training rewards whatever the judge accepts, so that is a reward hole.
//   - A controller that exited while ticks remained could make the judge's next
//     write fail with EPIPE before the judge saw the controller's output end.
//     Node raises that as an unhandled error: exit 1, the code a judge uses for
//     its own failures, not the controller's.
//
// And one non-refusal: a controller that answers every tick and then never exits
// used to hold the judge until the sandbox's whole-run budget killed it. The
// trajectory was already complete, so the judge now stops waiting after one
// answer budget and returns its verdict.
const (
	blankController = `import { createInterface } from 'node:readline';
createInterface({ input: process.stdin }).on('line', () => process.stdout.write('\n'));
`
	// Answers the first tick and exits, so the judge's next write races the end of
	// the controller's output.
	exitedController = `import { createInterface } from 'node:readline';
createInterface({ input: process.stdin }).once('line', () => process.stdout.write('0\n', () => process.exit(0)));
`
	// Reads its input and never answers: judge.mjs's per-tick answer budget kills it.
	silentController = `import { createInterface } from 'node:readline';
createInterface({ input: process.stdin }).on('line', () => {});
`
	// Answers every tick and never exits.
	lingeringController = `import { createInterface } from 'node:readline';
createInterface({ input: process.stdin }).on('line', () => process.stdout.write('0\n'));
setInterval(() => {}, 1000);
`
)

func TestDockerJudgesRefuseNonAnswers(t *testing.T) {
	d := testDocker()
	d.ProjectImage = simProjectImage
	requireProjectImage(t, d)

	judges := map[string]string{
		"judge.mjs": "node --no-warnings /oracle/judge.mjs controller.js /models/buck.wasm scenario.txt 0.1 90 trajectory.bin",
		"run.mjs":   "node --no-warnings /oracle/run.mjs controller.js",
	}
	refused := map[string]struct{ code, stderr string }{
		"blank line": {blankController, "at tick 0"},
		"exited":     {exitedController, "at tick 1"},
	}
	run := func(t *testing.T, step, code string) ProjectResult {
		t.Helper()
		res, err := d.RunProject(context.Background(), ProjectRequest{
			Files: []File{{Path: "controller.js", Content: code}, scenarioFile(3, 60, 40)},
			Steps: []string{step},
		})
		if err != nil {
			t.Fatalf("RunProject: %v", err)
		}
		if len(res.Steps) != 1 {
			t.Fatalf("outcome=%s steps=%+v; want one step", res.Outcome, res.Steps)
		}
		return res
	}
	for jn, step := range judges {
		for cn, c := range refused {
			t.Run(jn+"/"+cn, func(t *testing.T) {
				res := run(t, step, c.code)
				if res.Steps[0].ExitCode != 3 {
					t.Fatalf("outcome=%s steps=%+v; want the judge to exit 3", res.Outcome, res.Steps)
				}
				if s := res.Steps[0].Stderr; !strings.Contains(s, c.stderr) {
					t.Fatalf("stderr %q does not name the failure (%q)", s, c.stderr)
				}
			})
		}
		if jn == "judge.mjs" {
			t.Run(jn+"/silent", func(t *testing.T) {
				res := run(t, step, silentController)
				if res.Steps[0].ExitCode != 3 || !strings.Contains(res.Steps[0].Stderr, "did not answer within") {
					t.Fatalf("outcome=%s steps=%+v; want exit 3 at the answer budget", res.Outcome, res.Steps)
				}
			})
		}
		t.Run(jn+"/lingering", func(t *testing.T) {
			res := run(t, step, lingeringController)
			if res.Outcome != ProjectOutcomeCompleted || res.Steps[0].ExitCode != 0 {
				t.Fatalf("outcome=%s steps=%+v; want a verdict once every tick is answered", res.Outcome, res.Steps)
			}
		})
	}
}
