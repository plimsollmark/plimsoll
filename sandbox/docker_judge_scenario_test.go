package sandbox

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// scenarioFile is the file a judge step reads its three scenario parameters from.
// /oracle/judge.mjs deletes it before the controller starts.
func scenarioFile(params ...float64) File {
	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = strconv.FormatFloat(p, 'g', -1, 64)
	}
	return File{Path: "scenario.txt", Content: strings.Join(parts, " ") + "\n"}
}

// scenarioSnooper tries every same-uid route to its trial runner's scenario and
// state: every readable command line in the container, the runner's descriptors,
// memory and memory map, and the scenario file itself. It reports what it reached
// on stderr and then answers every tick with 0.
const scenarioSnooper = `import { readFileSync, readdirSync, openSync, closeSync, existsSync, constants } from 'node:fs';
import { createInterface } from 'node:readline';
const p = '/proc/' + process.ppid;
const tryOpen = (f, m) => { try { closeSync(openSync(p + f, m)); return 'open'; } catch (e) { return e.code; } };
const cmdlines = [];
for (const pid of readdirSync('/proc')) {
  if (!/^\d+$/.test(pid)) continue;
  try { cmdlines.push(readFileSync('/proc/' + pid + '/cmdline', 'utf8').split('\0').join(' ')); } catch {}
}
const r = { cmdlines, fd0: tryOpen('/fd/0', constants.O_RDONLY), fd1: tryOpen('/fd/1', constants.O_WRONLY),
  mem: tryOpen('/mem', constants.O_RDONLY), maps: tryOpen('/maps', constants.O_RDONLY),
  environ: tryOpen('/environ', constants.O_RDONLY), scenarioFile: existsSync('scenario.txt') };
process.stderr.write('PROBE ' + JSON.stringify(r) + '\n');
createInterface({ input: process.stdin }).on('line', () => process.stdout.write('0 0\n'));
`

// TestDockerJudgeKeepsScenarioFromController proves the trial runner's two promises
// to an environment with hidden parameters: the controller cannot read the
// scenario (no command line in the container carries it, and its file is gone
// before the controller starts), and it cannot reach the runner's descriptors or
// memory, where the plant, the record and the fingerprint live. Before the runner
// guarded itself and took the scenario from a file, this controller read the
// scenario off the runner's command line.
func TestDockerJudgeKeepsScenarioFromController(t *testing.T) {
	d := testDocker()
	d.ProjectImage = simProjectImage
	requireProjectImage(t, d)

	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{{Path: "controller.js", Content: scenarioSnooper}, scenarioFile(3.217, 60.43, 41.9)},
		Steps: []string{"node --no-warnings /oracle/judge.mjs controller.js /models/shower.wasm scenario.txt 0.1 1 trajectory.bin"},
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("judge did not complete: outcome=%s (%s) steps=%+v", res.Outcome, res.Detail, res.Steps)
	}
	var v struct {
		Params []float64 `json:"params"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Steps[0].Stdout)), &v); err != nil {
		t.Fatalf("judge stdout is not its verdict line: %q (%v)", res.Steps[0].Stdout, err)
	}
	if len(v.Params) != 3 || v.Params[0] != 3.217 || v.Params[1] != 60.43 || v.Params[2] != 41.9 {
		t.Fatalf("judge ran scenario %v, want [3.217 60.43 41.9]", v.Params)
	}
	var probe struct {
		Cmdlines                     []string
		Fd0, Fd1, Mem, Maps, Environ string
		ScenarioFile                 bool
	}
	line := ""
	for _, l := range strings.Split(res.Steps[0].Stderr, "\n") {
		if strings.HasPrefix(l, "PROBE ") {
			line = strings.TrimPrefix(l, "PROBE ")
		}
	}
	if err := json.Unmarshal([]byte(line), &probe); err != nil || len(probe.Cmdlines) == 0 {
		t.Fatalf("no probe report in stderr %q (%v)", res.Steps[0].Stderr, err)
	}
	for _, c := range probe.Cmdlines {
		for _, secret := range []string{"3.217", "60.43", "41.9"} {
			if strings.Contains(c, secret) {
				t.Fatalf("a command line the controller can read carries the scenario: %q", c)
			}
		}
	}
	if probe.ScenarioFile {
		t.Fatal("the scenario file still exists when the controller runs")
	}
	for name, got := range map[string]string{"fd/0": probe.Fd0, "fd/1": probe.Fd1, "mem": probe.Mem} {
		if got != "EACCES" && got != "EPERM" {
			t.Fatalf("the controller opened its runner's %s (%s)", name, got)
		}
	}
	t.Logf("runner maps %s, environ %s (not part of the promise); %d command lines read, none with the scenario",
		probe.Maps, probe.Environ, len(probe.Cmdlines))
}
