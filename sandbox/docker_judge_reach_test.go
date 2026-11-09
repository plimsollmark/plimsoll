package sandbox

import (
	"context"
	"strings"
	"testing"
)

// What a controller may read inside the trial runners (/oracle/judge.mjs, /oracle/run.mjs): its own code and
// nothing else. The plant modules sit beside it under /models, so a controller that loads one through node:wasi
// could simulate the plant as often as it likes inside one run: practice the caller never counts and never sees.
// The runners start the controller under node's permission model with reads allowed only on the regular files
// beside it; this test is the proof, with a controller that tries each way out and reports what it got on stderr,
// and one whose policy module and data file beside it must still load.
const reachController = `import fs from 'node:fs';
import { createInterface } from 'node:readline';
const seen = [];
for (const p of ['/models/buck.wasm', '/oracle/judge.mjs', 'leak.js']) {
  try { fs.readFileSync(p); seen.push(p + ' READ'); } catch (e) { seen.push(p + ' ' + e.code); }
}
try { const { WASI } = await import('node:wasi'); new WASI({ version: 'preview1' }); seen.push('wasi READ'); } catch (e) { seen.push('wasi ' + e.code); }
try { (await import('node:child_process')).execSync('true'); seen.push('child READ'); } catch (e) { seen.push('child ' + e.code); }
process.stderr.write('reach: ' + seen.join(', ') + '\n');
createInterface({ input: process.stdin }).on('line', () => process.stdout.write('0\n'));
`

const policyController = `import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import { u } from './policy.js';
const own = readFileSync('own.bin');                     // a file of its own beside it, as a compiled controller.wasm is
if (own.length !== 3) process.exit(9);
createInterface({ input: process.stdin }).on('line', () => process.stdout.write(u + '\n'));
`

func TestDockerJudgesKeepTheControllerToItsOwnCode(t *testing.T) {
	t.Parallel()
	heavyDockerTest(t)
	d := testDocker()
	d.ProjectImage = simProjectImage
	requireProjectImage(t, d)

	// A link named like code but pointing at a plant must not widen the reads: only regular files are allowed.
	link := "ln -s /models/buck.wasm leak.js && "
	judges := map[string]string{
		"judge.mjs": "node --no-warnings /oracle/judge.mjs controller.js /models/buck.wasm scenario.txt 0.1 90 trajectory.bin",
		"run.mjs":   "node --no-warnings /oracle/run.mjs controller.js",
	}
	run := func(t *testing.T, step string, files ...File) StepResult {
		t.Helper()
		res, err := d.RunProject(context.Background(), ProjectRequest{
			Files: append(files, scenarioFile(3, 60, 40)),
			Steps: []string{step},
		})
		if err != nil {
			t.Fatalf("RunProject: %v", err)
		}
		if len(res.Steps) != 1 {
			t.Fatalf("outcome=%s steps=%+v; want one step", res.Outcome, res.Steps)
		}
		return res.Steps[0]
	}
	for jn, step := range judges {
		t.Run(jn+"/refused", func(t *testing.T) {
			s := run(t, link+step, File{Path: "controller.js", Content: reachController})
			if s.ExitCode != 0 {
				t.Fatalf("exit %d, stderr %q; want the run to complete", s.ExitCode, s.Stderr)
			}
			for _, want := range []string{"/models/buck.wasm ERR_ACCESS_DENIED", "/oracle/judge.mjs ERR_ACCESS_DENIED",
				"leak.js ERR_ACCESS_DENIED", "wasi ERR_ACCESS_DENIED", "child ERR_ACCESS_DENIED"} {
				if !strings.Contains(s.Stderr, want) {
					t.Errorf("stderr %q; want %q", s.Stderr, want)
				}
			}
			if strings.Contains(s.Stderr, " READ") {
				t.Errorf("stderr %q: the controller reached something beyond its own code", s.Stderr)
			}
		})
		t.Run(jn+"/own policy", func(t *testing.T) {
			s := run(t, step, File{Path: "controller.js", Content: policyController},
				File{Path: "policy.js", Content: "export const u = 0;\n"}, File{Path: "own.bin", Content: "abc"})
			if s.ExitCode != 0 {
				t.Fatalf("exit %d, stderr %q; want the controller's own policy module to load", s.ExitCode, s.Stderr)
			}
		})
	}
}
