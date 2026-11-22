package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The promise these tests defend: the controller being scored cannot write its own score.
// The trial runners of the sim image (/oracle/judge.mjs, /oracle/run.mjs) run the
// controller as their own child, under the same uid, so it may send its parent signals and
// reach 127.0.0.1. Node opens its debugger on SIGUSR1, listening on 127.0.0.1:9229, and from
// there a controller could rewrite the trajectory and the fingerprint the grader checks it
// against (finding rust-native-helper-34; measured 2026-11-20 on the image of 2026-11-19:
// "Debugger listening on ws://127.0.0.1:9229/...", under runc and gVisor). A step starts the
// runners as plain node, so each re-executes itself with --disable-sigusr1 before it reads
// the scenario or starts the controller.
//
// The controller below does only the first half of that attack, which is the whole door:
// before its first answer it signals its parent and looks for a debugger for about a second,
// then reports what it found on stderr and answers 0 on every tick, as the honest controller
// does. The trajectory and fingerprint must be the honest controller's.
const (
	signallingController = `import { createInterface } from 'node:readline';
import net from 'node:net';
const look = () => new Promise((resolve) => {
  let sent = 'sent';
  try { process.kill(process.ppid, 'SIGUSR1'); } catch (e) { sent = e.code; }
  const once = (n) => {
    const s = net.connect(9229, '127.0.0.1');
    s.on('connect', () => { s.destroy(); resolve(sent + ' open'); });
    s.on('error', () => { if (n > 0) setTimeout(() => once(n - 1), 50); else resolve(sent + ' shut'); });
  };
  once(20);
});
let looked = null;
for await (const line of createInterface({ input: process.stdin })) {
  if (looked === null) { looked = await look(); process.stderr.write('debugger: ' + looked + '\n'); }
  process.stdout.write('0\n');
}
`
	zeroController = `import { createInterface } from 'node:readline';
createInterface({ input: process.stdin }).on('line', () => process.stdout.write('0\n'));
`
	// Ends its trial runner with SIGKILL at the fifth tick: a signal the flag does not stop.
	killingController = `import { createInterface } from 'node:readline';
let k = 0;
for await (const line of createInterface({ input: process.stdin })) {
  if (++k === 5) process.kill(process.ppid, 'SIGKILL');
  process.stdout.write('0\n');
}
`
)

var trialRunnerSteps = map[string]string{
	"judge.mjs": "node --no-warnings /oracle/judge.mjs controller.js /models/buck.wasm scenario.txt 0.1 90 trajectory.bin",
	"run.mjs":   "node --no-warnings /oracle/run.mjs controller.js",
}

// runTrial runs one trial and returns its step, the fingerprint its summary line states, and
// the SHA-256 of the trajectory artifact ("" for either when it is missing).
func runTrial(t *testing.T, d *DockerSandbox, step, controller string) (StepResult, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := d.RunProject(ctx, ProjectRequest{
		Files:     []File{{Path: "controller.js", Content: controller}, scenarioFile(3, 60, 40)},
		Steps:     []string{step},
		Artifacts: []string{"trajectory.bin"},
		Timeout:   60 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if len(res.Steps) != 1 {
		t.Fatalf("outcome %s (%s), steps %+v; want one step", res.Outcome, res.Detail, res.Steps)
	}
	s := res.Steps[0]
	var summary struct {
		Fingerprint string `json:"fingerprint"`
	}
	if line := strings.TrimSpace(s.Stdout); line != "" {
		if err := json.Unmarshal([]byte(line), &summary); err != nil {
			t.Fatalf("stdout %q is not the summary line: %v", s.Stdout, err)
		}
	}
	got := ""
	for _, a := range res.Artifacts {
		if a.Path == "trajectory.bin" {
			sum := sha256.Sum256(a.Content)
			got = hex.EncodeToString(sum[:])
		}
	}
	return s, summary.Fingerprint, got
}

func TestDockerControllerCannotOpenTheTrialRunnerDebugger(t *testing.T) {
	t.Parallel()
	heavyDockerTest(t)
	d := testDocker()
	d.ProjectImage = simProjectImage
	requireProjectImage(t, d)
	for name, step := range trialRunnerSteps {
		t.Run(name, func(t *testing.T) {
			honest, honestPrint, honestFile := runTrial(t, d, step, zeroController)
			if honest.ExitCode != 0 || honestPrint == "" || honestFile != honestPrint {
				t.Fatalf("the honest trial: exit %d, stderr %q, fingerprint %q, trajectory %q", honest.ExitCode, honest.Stderr, honestPrint, honestFile)
			}
			s, print, file := runTrial(t, d, step, signallingController)
			if strings.Contains(s.Stderr, "debugger: sent open") || strings.Contains(s.Stderr, "Debugger listening") {
				t.Errorf("the controller's SIGUSR1 opened its trial runner's debugger on 127.0.0.1:9229 (stderr %q): "+
					"the controller under test could write its own trajectory and fingerprint", s.Stderr)
			} else if !strings.Contains(s.Stderr, "debugger: sent shut") {
				t.Errorf("stderr %q; want the controller to report that it signalled its runner and found the debugger shut", s.Stderr)
			}
			if s.ExitCode != 0 || print != honestPrint || file != honestPrint {
				t.Errorf("exit %d, fingerprint %q, trajectory %q; want exit 0 and the honest trial's %q for both", s.ExitCode, print, file, honestPrint)
			}
		})
	}
}

// A signal the flag does not stop, one that ends the trial runner, gives the caller a failed
// step with no summary line and no trajectory: nothing a grader that checks the step's exit
// and the trajectory against the printed fingerprint can take for a pass. The controller
// cannot write the trajectory itself (it may not write files) and holds no descriptor of the
// step's stdout (its own stdout is the pipe its runner reads).
func TestDockerControllerThatEndsItsTrialRunnerGetsNoVerdict(t *testing.T) {
	t.Parallel()
	heavyDockerTest(t)
	d := testDocker()
	d.ProjectImage = simProjectImage
	requireProjectImage(t, d)
	for name, step := range trialRunnerSteps {
		t.Run(name, func(t *testing.T) {
			s, print, file := runTrial(t, d, step, killingController)
			if s.ExitCode != 128+9 || print != "" || file != "" {
				t.Errorf("exit %d, stdout %q, fingerprint %q, trajectory %q; want exit 137 with no summary line and no trajectory",
					s.ExitCode, s.Stdout, print, file)
			}
		})
	}
}
