package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// The physics oracle (private/architecture/oracle-demo-plan.md) through the
// unchanged project API: the module image carries the cart-pole plant as
// WebAssembly and the judge, /oracle/run.mjs; the caller sends one file, its
// controller, and one step names the judge. The judge loads the plant through
// Node's WASI support, runs the controller as a separate process, exchanges one
// line per 10 ms tick, and writes the trajectory after the controller has exited.
//
// The assertion is an exact SHA-256 against the sister repository's local run of
// the same judge on a different Node major: WebAssembly's arithmetic and the
// controller's plain doubles do not depend on the engine, and this is the test
// that says so. A mismatch means the build, the judge or the engine changed the
// numbers, which is exactly what the fingerprint exists to catch.

const oracleTicks = 2000 // 20 s at 10 ms
const oracleWidth = 4    // x, v, theta, omega; plus the force per tick

// Two copies of the controllers exist on purpose (examples/oracle/controllers
// holds the ones the example runs): a drift between them is a different
// fingerprint, which the assertions below refuse.
const oracleAcceptedController = `import { createInterface } from 'node:readline';
const kp = 40, kd = 5, kx = 1, kv = 1;
const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  const [x, v, theta, omega] = line.split(' ').map(Number);
  const u = kp * theta + kd * omega + kx * x + kv * v;
  process.stdout.write(u + '\n');
});
`

const oracleDraftController = `import { createInterface } from 'node:readline';
const kp = 40, kd = 5, kx = -1, kv = -1;
const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
	const [x, v, theta, omega] = line.split(' ').map(Number);
	const u = kp * theta + kd * omega + kx * x + kv * v;
	process.stdout.write(u + '\n');
});
`

const (
	oracleAcceptedSHA256 = "63cfd676924a3896127d60c97333677f3b3c804dd764dba001121f6c234a937f"
	oracleDraftSHA256    = "060d98e8140c03800347c4c947c07b2ab0011c3e6017e9a84529793afbbb53b9"
	oracleDraftFellAt    = 5.96
)

type oracleVerdict struct {
	Fingerprint string   `json:"fingerprint"`
	Ticks       int      `json:"ticks"`
	Width       int      `json:"width"`
	FellAt      *float64 `json:"fell_at"`
	FinalX      float64  `json:"final_x"`
	FinalTheta  float64  `json:"final_theta"`
}

// judge runs one controller through the project API and returns the judge's
// verdict line and the artifact's SHA-256.
func judge(t *testing.T, d *DockerSandbox, controller string) (oracleVerdict, string) {
	t.Helper()
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:     []File{{Path: "controller.js", Content: controller}},
		Steps:     []string{"node --no-warnings /oracle/run.mjs controller.js"},
		Artifacts: []string{"trajectory.bin"},
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("judge did not complete: outcome=%s (%s) steps=%+v", res.Outcome, res.Detail, res.Steps)
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Path != "trajectory.bin" {
		t.Fatalf("artifacts = %+v, want trajectory.bin", res.Artifacts)
	}
	if want := oracleTicks * (oracleWidth + 1) * 8; len(res.Artifacts[0].Content) != want {
		t.Fatalf("trajectory is %d bytes, want %d", len(res.Artifacts[0].Content), want)
	}
	sum := sha256.Sum256(res.Artifacts[0].Content)
	var v oracleVerdict
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Steps[0].Stdout)), &v); err != nil {
		t.Fatalf("judge stdout is not its verdict line: %q (%v)", res.Steps[0].Stdout, err)
	}
	return v, hex.EncodeToString(sum[:])
}

func TestDockerOracleJudgesControllerByFingerprint(t *testing.T) {
	d := testDocker()
	d.ProjectImage = simProjectImage
	requireProjectImage(t, d)

	first, firstSum := judge(t, d, oracleAcceptedController)
	second, secondSum := judge(t, d, oracleAcceptedController)
	if firstSum != secondSum || first.Fingerprint != firstSum {
		t.Fatalf("the same controller twice: artifact %s then %s, judge said %s; the run is not deterministic", firstSum, secondSum, first.Fingerprint)
	}
	if firstSum != oracleAcceptedSHA256 {
		t.Fatalf("accepted controller fingerprint = %s, want %s (the sister repository's local Node run); the build, the judge or the engine changed the arithmetic", firstSum, oracleAcceptedSHA256)
	}
	if first.FellAt != nil || first.Ticks != oracleTicks || first.Width != oracleWidth {
		t.Fatalf("accepted verdict = %+v, want no fall over %d ticks of width %d", first, oracleTicks, oracleWidth)
	}
	if first.FinalTheta > 1e-3 || first.FinalTheta < -1e-3 || first.FinalX > 0.1 || first.FinalX < -0.1 {
		t.Fatalf("accepted controller did not balance and recentre: %+v", first)
	}
	t.Logf("accepted: %s (final x %.4f, theta %.2e)", firstSum, first.FinalX, first.FinalTheta)
	_ = second

	draft, draftSum := judge(t, d, oracleDraftController)
	if draftSum != oracleDraftSHA256 || draft.FellAt == nil || *draft.FellAt != oracleDraftFellAt {
		t.Fatalf("draft controller: fingerprint %s, verdict %+v; want %s, fell at %.2f s", draftSum, draft, oracleDraftSHA256, oracleDraftFellAt)
	}
	if draftSum == firstSum {
		t.Fatal("a different controller produced the accepted fingerprint")
	}
	t.Logf("draft: %s, fell at %.2f s", draftSum, *draft.FellAt)
}

// The worker's per-instance memory cap, proven through the typed operation with
// the Greedy fixture: the middle row asks for 512 MiB, more than the 256-page cap,
// and fails alone with the model's -7; its neighbours complete with their values.
// Without the cap the row would have succeeded inside the container's memory
// limit or, past it, killed the worker and every other row with it.
func TestDockerRunModuleGreedyRowFailsAlone(t *testing.T) {
	d := testDocker()
	d.ModuleImage = simProjectImage
	requireModuleImage(t, d)

	res, err := d.RunModule(context.Background(), ModuleRequest{Model: "greedy", Rows: [][]float64{{1, 42, 0}, {512, 43, 0}, {2, 44, 0}}, EndTime: 1, Step: 1})
	if err != nil {
		t.Fatalf("RunModule greedy: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || res.Width != 1 || len(res.Runs) != 3 {
		t.Fatalf("outcome=%s (%s) width=%d runs=%d; stderr=%q", res.Outcome, res.Detail, res.Width, len(res.Runs), res.Stderr)
	}
	want := []struct {
		status int32
		out    []float64
	}{{1, []float64{42}}, {-7, nil}, {1, []float64{44}}}
	for i, w := range want {
		run := res.Runs[i]
		if run.Status != w.status || len(run.Outputs) != len(w.out) || (len(w.out) == 1 && run.Outputs[0] != w.out[0]) {
			t.Fatalf("row %d = %+v, want status %d outputs %v (rows: %+v)", i, run, w.status, w.out, res.Runs)
		}
	}
	t.Logf("greedy rows: %d, %d, %d", res.Runs[0].Status, res.Runs[1].Status, res.Runs[2].Status)
}
