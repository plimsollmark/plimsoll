package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A controller written in C, compiled to WebAssembly inside the sandbox, and judged
// against the cart-pole plant (examples/wasm-controller). One project run carries
// the C source and the Node shim that the judge spawns as the controller process;
// its first step compiles the source with the wasi-sdk baked into
// plimsoll/sandbox-wasm-cc, and the next four run /oracle/judge.mjs against
// /models/cartpole.wasm on the four swing-up scenarios. No network at either step,
// and nothing in the daemon, the judge or the project API changed to allow it.
//
// Proven here:
//   - the compile is reproducible: two runs produce the same controller.wasm, and
//     its SHA-256 is the one recorded in examples/wasm-controller/fingerprints.json;
//   - every scenario's trajectory has one fingerprint across the two runs, the one
//     recorded in the fixture, and the judge's printed fingerprint is the hash of
//     the artifact it returned;
//   - the controller swings the pole up and holds it in every scenario, scoring at
//     least the fixture's floor (0.85) under the swing-up score;
//   - the module imports nothing: the same source built so that cos becomes a host
//     import is refused by the shim before the first tick.
//
// Whether this reproduces the JavaScript law it was ported from, bit for bit: NOT
// in general. The C source keeps every expression's operand order and compiles
// with -ffp-contract=off, so the only arithmetic that can differ is cos: here it
// is wasi-libc's (musl's, from fdlibm), linked into the module, and in the
// JavaScript controller it is V8's Math.cos, a different implementation that
// disagrees in the last bit on roughly one input in a hundred. On scenario s1 the
// two controllers return forces a few doubles apart at ticks 91 and 176; the
// recorded state stays bit-identical at every tick (the plant rounds the
// difference away), but the record hashes the forces too, so s1, s2 and s3 have
// different fingerprints from the JavaScript law's and s4, where no force
// differs, is identical. examples/wasm-controller's page shows it tick by tick. The
// last subtest is the proof that cos is the whole difference: the same C source,
// built with -Dcos=host_cos so that cos is imported and bound to Math.cos, gives
// the JavaScript law's four fingerprints exactly (the fixture's
// math_cos_fingerprint values).

// wasmCCProjectImage is the tag `make docker-images` gives docker/wasm-cc.Dockerfile.
const wasmCCProjectImage = "plimsoll/sandbox-wasm-cc:latest"

const (
	wasmControllerDir = "../examples/wasm-controller/"
	cartPoleWidth     = 4 // x, v, theta, omega; the judge appends the force
	cartPoleTrack     = 2.4
)

type wasmControllerFixture struct {
	Build                string  `json:"build"`
	MathCosBuild         string  `json:"math_cos_build"`
	ControllerWasmSHA256 string  `json:"controller_wasm_sha256"`
	TickS                float64 `json:"tick_s"`
	TEndS                float64 `json:"t_end_s"`
	MinScore             float64 `json:"min_score"`
	Scenarios            []struct {
		ID                 string     `json:"id"`
		Params             [3]float64 `json:"params"`
		Fingerprint        string     `json:"fingerprint"`
		MathCosFingerprint string     `json:"math_cos_fingerprint"`
	} `json:"scenarios"`
}

func readWasmControllerFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(wasmControllerDir + name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return string(raw)
}

func wasmControllerFixtureFile(t *testing.T) wasmControllerFixture {
	t.Helper()
	var f wasmControllerFixture
	if err := json.Unmarshal([]byte(readWasmControllerFile(t, "fingerprints.json")), &f); err != nil {
		t.Fatalf("fingerprints.json: %v", err)
	}
	if f.Build == "" || f.MathCosBuild == "" || len(f.ControllerWasmSHA256) != 64 || len(f.Scenarios) == 0 || f.TickS <= 0 || f.TEndS <= 0 {
		t.Fatalf("fingerprints.json is incomplete: %+v", f)
	}
	return f
}

// judgeStep is the step that judges controller.js on one scenario and writes its
// trajectory to <id>.bin.
func judgeStep(f wasmControllerFixture, id string, p [3]float64) string {
	num := func(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }
	return "node --no-warnings /oracle/judge.mjs controller.js /models/cartpole.wasm " +
		num(p[0]) + " " + num(p[1]) + " " + num(p[2]) + " " + num(f.TickS) + " " + num(f.TEndS) + " " + id + ".bin"
}

type judgedScenario struct {
	fingerprint string // SHA-256 of the returned artifact
	trajectory  []byte
}

// runWasmController sends one project run: the C source, the shim, a build step,
// then one judge step per scenario. It returns the compiled module and each
// scenario's trajectory, after checking every judge verdict against its artifact.
func runWasmController(t *testing.T, d *DockerSandbox, f wasmControllerFixture, build, shim string) ([]byte, map[string]judgedScenario) {
	t.Helper()
	steps := []string{build}
	artifacts := []string{"controller.wasm"}
	for _, s := range f.Scenarios {
		steps = append(steps, judgeStep(f, s.ID, s.Params))
		artifacts = append(artifacts, s.ID+".bin")
	}
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{
			{Path: "controller.c", Content: readWasmControllerFile(t, "controller/controller.c")},
			{Path: "controller.js", Content: shim},
		},
		Steps:     steps,
		Artifacts: artifacts,
		Timeout:   90 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != len(steps) {
		t.Fatalf("run did not complete: outcome=%s (%s) steps=%+v", res.Outcome, res.Detail, res.Steps)
	}
	for _, st := range res.Steps {
		if st.ExitCode != 0 {
			t.Fatalf("step %q exited %d: stdout %q stderr %q", st.Command, st.ExitCode, st.Stdout, st.Stderr)
		}
	}
	byPath := map[string][]byte{}
	for _, a := range res.Artifacts {
		byPath[a.Path] = a.Content
	}
	wasm := byPath["controller.wasm"]
	if len(wasm) == 0 {
		t.Fatalf("no controller.wasm among the artifacts %v", artifacts)
	}
	out := map[string]judgedScenario{}
	for i, s := range f.Scenarios {
		traj := byPath[s.ID+".bin"]
		var v struct {
			Fingerprint string `json:"fingerprint"`
			Ticks       int    `json:"ticks"`
			Width       int    `json:"width"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(res.Steps[i+1].Stdout)), &v); err != nil {
			t.Fatalf("%s: judge stdout is not its verdict line: %q (%v)", s.ID, res.Steps[i+1].Stdout, err)
		}
		sum := sha256.Sum256(traj)
		fp := hex.EncodeToString(sum[:])
		wantTicks := int(math.Round(f.TEndS / f.TickS))
		if fp != v.Fingerprint || v.Ticks != wantTicks || v.Width != cartPoleWidth || len(traj) != wantTicks*(cartPoleWidth+1)*8 {
			t.Fatalf("%s: judge said %+v, the %d-byte artifact hashes to %s; want %d ticks of width %d", s.ID, v, len(traj), fp, wantTicks, cartPoleWidth)
		}
		out[s.ID] = judgedScenario{fingerprint: fp, trajectory: traj}
	}
	return wasm, out
}

// cartPoleSwingScore is the swing-up score: 1 minus the start of the final
// unbroken upright stretch (cos theta > 0.98) over the run's length, and zero with
// a reason if the cart ever leaves the track (|x| > 2.4 m) or the pole is never
// upright at the end. The trajectory is the judge's record: per tick x, v, theta,
// omega, then the force, as little-endian float64.
func cartPoleSwingScore(traj []byte) (score float64, failure string) {
	stride := cartPoleWidth + 1
	n := len(traj) / 8 / stride
	at := func(k, col int) float64 {
		return math.Float64frombits(binary.LittleEndian.Uint64(traj[(k*stride+col)*8:]))
	}
	upFrom := -1
	for k := 0; k < n; k++ {
		if math.Abs(at(k, 0)) > cartPoleTrack {
			return 0, "off_track"
		}
		if math.Cos(at(k, 2)) > 0.98 {
			if upFrom < 0 {
				upFrom = k
			}
		} else {
			upFrom = -1
		}
	}
	if upFrom < 0 {
		return 0, "never_upright"
	}
	return 1 - float64(upFrom)/float64(n), ""
}

func TestDockerWasmControllerCompiledInTheSandbox(t *testing.T) {
	d := testDocker()
	d.ProjectImage = wasmCCProjectImage
	requireProjectImage(t, d)
	f := wasmControllerFixtureFile(t)
	shim := readWasmControllerFile(t, "controller/controller.js")

	wasm1, first := runWasmController(t, d, f, f.Build, shim)
	wasm2, second := runWasmController(t, d, f, f.Build, shim)

	sum1, sum2 := sha256.Sum256(wasm1), sha256.Sum256(wasm2)
	if sum1 != sum2 {
		t.Fatalf("two compiles of the same source differ: %x and %x", sum1, sum2)
	}
	if got := hex.EncodeToString(sum1[:]); got != f.ControllerWasmSHA256 {
		t.Fatalf("controller.wasm hashes to %s, fixture records %s (a changed source, flag or toolchain)", got, f.ControllerWasmSHA256)
	}
	t.Logf("controller.wasm: %d bytes, %x, identical across two compiles", len(wasm1), sum1)

	for _, s := range f.Scenarios {
		a, b := first[s.ID], second[s.ID]
		if a.fingerprint != b.fingerprint {
			t.Errorf("%s: two runs gave two fingerprints: %s and %s", s.ID, a.fingerprint, b.fingerprint)
			continue
		}
		if a.fingerprint != s.Fingerprint {
			t.Errorf("%s: fingerprint %s, fixture records %s", s.ID, a.fingerprint, s.Fingerprint)
		}
		score, failure := cartPoleSwingScore(a.trajectory)
		if failure != "" || score < f.MinScore {
			t.Errorf("%s: score %.4f, failure %q; want at least %.2f", s.ID, score, failure, f.MinScore)
			continue
		}
		same := "differs from"
		if s.Fingerprint == s.MathCosFingerprint {
			same = "is identical to"
		}
		t.Logf("%s %v: %s, score %.4f (upright from %.2f s); %s the Math.cos build", s.ID, s.Params, a.fingerprint[:16], score, (1-score)*f.TEndS, same)
	}
}

// mathCosShim is the example's shim with one change: the module may import
// env.host_cos, bound to V8's Math.cos. It exists for the proof below and for
// nothing else; the example's own shim provides no imports at all.
func mathCosShim(t *testing.T) string {
	t.Helper()
	shim := readWasmControllerFile(t, "controller/controller.js")
	const empty = "const provided = {};"
	if strings.Count(shim, empty) != 1 {
		t.Fatalf("controller.js no longer declares %q exactly once; update this test with it", empty)
	}
	return strings.Replace(shim, empty, "const provided = { env: { host_cos: Math.cos } };", 1)
}

func TestDockerWasmControllerDiffersFromJavaScriptOnlyInCos(t *testing.T) {
	d := testDocker()
	d.ProjectImage = wasmCCProjectImage
	requireProjectImage(t, d)
	f := wasmControllerFixtureFile(t)

	_, judged := runWasmController(t, d, f, f.MathCosBuild, mathCosShim(t))
	for _, s := range f.Scenarios {
		if got := judged[s.ID].fingerprint; got != s.MathCosFingerprint {
			t.Errorf("%s: with Math.cos the fingerprint is %s, fixture records %s", s.ID, got, s.MathCosFingerprint)
		}
	}
	t.Logf("with cos bound to Math.cos, all %d scenarios reproduce the recorded math_cos fingerprints", len(f.Scenarios))
}

func TestDockerWasmControllerShimRefusesImports(t *testing.T) {
	d := testDocker()
	d.ProjectImage = wasmCCProjectImage
	requireProjectImage(t, d)
	f := wasmControllerFixtureFile(t)
	s := f.Scenarios[0]

	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{
			{Path: "controller.c", Content: readWasmControllerFile(t, "controller/controller.c")},
			{Path: "controller.js", Content: readWasmControllerFile(t, "controller/controller.js")},
		},
		Steps: []string{f.MathCosBuild, judgeStep(f, s.ID, s.Params)},
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 2 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("outcome=%s (%s) steps=%+v; want the build to succeed and the judge to run", res.Outcome, res.Detail, res.Steps)
	}
	judge := res.Steps[1]
	if judge.ExitCode == 0 || !strings.Contains(judge.Stderr, "env.host_cos (function)") {
		t.Fatalf("judge exited %d, stderr %q; want the shim to refuse the env.host_cos import by name", judge.ExitCode, judge.Stderr)
	}
	t.Logf("a module importing cos from the host is refused: %s", strings.TrimSpace(strings.SplitN(judge.Stderr, "\n", 2)[0]))
}
