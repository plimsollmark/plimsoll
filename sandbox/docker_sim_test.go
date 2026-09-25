package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"os/exec"
	"strings"
	"testing"
)

// simProjectImage is the tag `make docker-images` gives docker/sim.Dockerfile.
const simProjectImage = "plimsoll/sandbox-sim:latest"

// The worker's output layout is, per parameter set, an int32 step count followed
// by the module's sim_width() float64 outputs per step (docker/sim/worker.c, same
// as the sister repository's native_main.c): two for the Reference models, three
// for Lorenz. Each sweep below runs simRows parameter sets with
// a fixed communication step of 0.01, so a sweep to t_end takes t_end/0.01 steps.
const (
	simRows          = 100
	simVanDerPolTEnd = 20 // steps per run: 2000
	simBouncingTEnd  = 3  // steps per run: 300
	simRowHeader     = 4

	// Lorenz (docker/sim/models/Lorenz), width 3: rho swept over [20, 40], sigma 10,
	// beta 8/3, 60 s per row (6,000 steps). 50 rows keep the result under the 8 MiB
	// artifact budget (50 * (4 + 6000 * 24) = 7,200,200 bytes plus the record header).
	simLorenzRows = 50
	simLorenzTEnd = 60
)

// Reference checksums: a native C run of the same shim and the same sweep
// (VanDerPol: mu swept over [0.1, 5.0], x0=2, x1=0; BouncingBall: e over
// [0.1, 0.95], h=1, v=0), 2026-09-18, byte-identical to WasmEdge AOT, wasmtime and
// wazero on the same modules. Regenerate from the sister repository with
// `make native` then
// `./native_vdp 100 20 out.bin 0.1 5.0 2.0 0.0 && sha256sum out.bin` and
// `./native_bb 100 3 out.bin 0.1 0.95 1.0 0.0 && sha256sum out.bin`; Lorenz with
// `make lorenz` then `./native_lorenz 50 60 out.bin 20 40 10 2.6666666666666665`.
const (
	simVanDerPolSHA256    = "d1109d62b94796946a2b5a706d45e6259a005b63ee392fed918f39945c980815"
	simBouncingBallSHA256 = "b031e512febeef2aea72b38e52c84e6f5e1bc92396c991c1a2a93218f825a8ec"
	simLorenzSHA256       = "70f1e8e657d804e176f18bf7afb01811a4b0b5f41d4609b74184ab2a6ab6a67e"
)

// TestDockerProjectSimWorker proves the simulation worker image
// through the unchanged project API: the image built from docker/sim.Dockerfile
// carries a WasmEdge AOT worker and three models compiled to WebAssembly, a
// step names the worker and a model, and the sweep's artifact is byte-identical
// to a native C run of the same shim, exact SHA-256, not a tolerance. That is the
// claim the RunModule direction rests on (the direction draft's sections 5d to
// 5f), and this is the test that says whether the shipped seccomp profile and the
// noexec writable mounts admit WasmEdge's AOT loader (dlopen of a shared object
// from the image root) under the configured runtime.
//
// The last step is the other half of "register a model = build an image": a
// byte-identical copy of the model under /work must refuse to load, because
// /work is a noexec tmpfs and an AOT model is machine code that has to be mapped
// executable. The runner stops the chain on the first failure, so that step runs
// last and the run's outcome stays completed. Skips without the image; fails under
// SANDBOX_TEST_REQUIRE_DOCKER=1.
func TestDockerProjectSimWorker(t *testing.T) {
	d := testDocker()
	d.ProjectImage = simProjectImage
	requireProjectImage(t, d)

	res, err := d.RunProject(context.Background(), ProjectRequest{
		Steps: []string{
			"sim-worker /models/vanderpol.so 100 1 20 vanderpol.bin 0.1 5.0 2.0 0.0",
			"sim-worker /models/bouncingball.so 100 1 3 bouncingball.bin 0.1 0.95 1.0 0.0",
			"cp /models/vanderpol.so copy.so && sim-worker copy.so 2 1 1 copy.bin 1.0 2.0 2.0 0.0",
		},
		Artifacts: []string{"vanderpol.bin", "bouncingball.bin"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("outcome = %s (%s), want completed", res.Outcome, res.Detail)
	}
	if len(res.Steps) != 3 {
		t.Fatalf("ran %d steps, want 3: %+v", len(res.Steps), res.Steps)
	}
	for i, name := range []string{"vanderpol", "bouncingball"} {
		if run := res.Steps[i]; run.ExitCode != 0 {
			t.Fatalf("%s sweep exit = %d, stdout=%q stderr=%q", name, run.ExitCode, run.Stdout, run.Stderr)
		}
		t.Logf("%s: %s", name, strings.TrimSpace(res.Steps[i].Stdout))
	}
	if cp := res.Steps[2]; cp.ExitCode == 0 {
		t.Fatalf("a model copied under /work loaded and ran; the noexec writable mounts no longer gate machine code: stdout=%q", cp.Stdout)
	} else if !strings.Contains(cp.Stderr, "load failed") {
		t.Fatalf("the /work copy failed for a reason other than the loader (exit %d): stdout=%q stderr=%q", cp.ExitCode, cp.Stdout, cp.Stderr)
	} else {
		t.Logf("model under /work refused as required (exit %d): %s", cp.ExitCode, strings.TrimSpace(cp.Stderr))
	}
	if res.ArtifactsTruncated {
		t.Fatalf("artifacts were truncated; the two sweeps must fit the artifact budget")
	}

	got := map[string][]byte{}
	for _, a := range res.Artifacts {
		got[a.Path] = a.Content
	}
	if len(got) != 2 {
		t.Fatalf("captured %d artifacts, want vanderpol.bin and bouncingball.bin: %v", len(got), got)
	}
	assertSweepArtifact(t, "vanderpol.bin", got["vanderpol.bin"], simRows, simVanDerPolTEnd, 2, simVanDerPolSHA256)
	assertSweepArtifact(t, "bouncingball.bin", got["bouncingball.bin"], simRows, simBouncingTEnd, 2, simBouncingBallSHA256)
}

// assertSweepArtifact checks the artifact's length against the worker's layout
// (every run completed its full step count, so no run terminated early or hit
// max_steps) and its SHA-256 against the native reference.
func assertSweepArtifact(t *testing.T, name string, b []byte, rows, tEnd, width int, wantSHA string) {
	t.Helper()
	steps := tEnd * 100 // communication step 0.01
	if want := rows * (simRowHeader + 8*width*steps); len(b) != want {
		t.Errorf("%s is %d bytes, want %d (%d runs of %d steps, width %d)", name, len(b), want, rows, steps, width)
		return
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		t.Errorf("%s SHA-256 = %s, want %s (the native reference; a mismatch means the wasm build or the AOT compiler changed the arithmetic)", name, got, wantSHA)
	}
}

// reencodeRuns re-encodes a module result in the sweep layout (int32 steps, then
// the outputs), checking that every run completed exactly wantSteps steps, so a
// table run can be compared with the sweep's native checksum byte for byte.
func reencodeRuns(t *testing.T, res ModuleResult, wantSteps int) []byte {
	t.Helper()
	var sweep []byte
	for i, run := range res.Runs {
		if int(run.Status) != wantSteps {
			t.Fatalf("run %d status = %d, want %d steps", i, run.Status, wantSteps)
		}
		if len(run.Outputs) != int(run.Status)*res.Width {
			t.Fatalf("run %d has %d outputs for %d steps of width %d", i, len(run.Outputs), run.Status, res.Width)
		}
		sweep = binary.LittleEndian.AppendUint32(sweep, uint32(run.Status))
		for _, v := range run.Outputs {
			sweep = binary.LittleEndian.AppendUint64(sweep, math.Float64bits(v))
		}
	}
	return sweep
}

// requireModuleImage is requireProjectImage for the module image.
func requireModuleImage(t *testing.T, d *DockerSandbox) {
	t.Helper()
	requireDocker(t)
	if err := exec.Command("docker", "image", "inspect", d.ModuleImage).Run(); err != nil {
		infraSkip(t, "module image %s not built (run `make docker-images`)", d.ModuleImage)
	}
}

// sweepRows reproduces the worker's sweep-mode parameter sets for VanDerPol
// (p0min + (p0max - p0min) * i / (N - 1), evaluated in the same order with every
// intermediate rounded to float64, so no fused multiply-add can creep in), which
// is what lets a table run be checked against the sweep's native checksum.
func sweepRows(n int, p0min, p0max, p1, p2 float64) [][]float64 {
	rows := make([][]float64, n)
	for i := range rows {
		scaled := float64((p0max - p0min) * float64(i))
		frac := float64(scaled / float64(n-1))
		rows[i] = []float64{float64(p0min + frac), p1, p2}
	}
	return rows
}

// TestDockerRunModule proves the typed operation on the same reference as the
// sweep: the 100 VanDerPol parameter sets, sent as a table through RunModule,
// come back as 100 runs of 2000 steps whose values, re-encoded in the sweep
// layout, hash to the native C checksum. Bit-identity survives the whole path:
// float64 to shortest decimal in the request file, strtod in the worker, the
// module, the versioned record, the decoder. Then every refusal the operation
// promises: a model outside the image is setup_failed with the loader's message;
// a row whose width is not the model's own parameter count is setup_failed
// naming the count; a table whose results could exceed the budget is
// ErrInvalidRequest from the worker before any row runs, distinguishable from the
// daemon's pre-dispatch bound; a ragged table and an impossible isolation floor
// never reach a container; no module image is ErrUnsupported.
func TestDockerRunModule(t *testing.T) {
	d := testDocker()
	d.ModuleImage = simProjectImage
	requireModuleImage(t, d)
	ctx := context.Background()

	rows := sweepRows(simRows, 0.1, 5.0, 2.0, 0.0)
	res, err := d.RunModule(ctx, ModuleRequest{Model: "vanderpol", Rows: rows, EndTime: simVanDerPolTEnd, Step: 0.01})
	if err != nil {
		t.Fatalf("RunModule: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("outcome = %s (%s); stderr=%q", res.Outcome, res.Detail, res.Stderr)
	}
	t.Logf("worker: %s", strings.TrimSpace(res.Stdout))
	if res.Width != 2 || len(res.Runs) != simRows {
		t.Fatalf("width %d, %d runs; want 2, %d", res.Width, len(res.Runs), simRows)
	}
	assertSweepArtifact(t, "RunModule vanderpol (re-encoded)", reencodeRuns(t, res, simVanDerPolTEnd*100), simRows, simVanDerPolTEnd, 2, simVanDerPolSHA256)

	// Lorenz, the model of our own: three outputs, 50 rows of 60 s. Chaos is why it
	// is here: a one-ulp difference anywhere in the arithmetic (a fused multiply-add
	// the AOT compiler contracted, a libm call) grows e-fold every 1.3 s and would
	// miss the checksum by the size of the attractor, not by a rounding tolerance.
	// The 60 s end time is also the regression for the shim's step guard: an
	// earlier shim stopped on the accumulated t, which lands 3.4e-12 short of 60
	// after 6,000 additions of 0.01, and asked the FMU for a step past the stop
	// time, which it refused (every row failed with sim_run -5).
	res, err = d.RunModule(ctx, ModuleRequest{Model: "lorenz", Rows: sweepRows(simLorenzRows, 20, 40, 10, 8.0/3.0), EndTime: simLorenzTEnd, Step: 0.01})
	if err != nil {
		t.Fatalf("RunModule lorenz: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("lorenz outcome = %s (%s); stderr=%q", res.Outcome, res.Detail, res.Stderr)
	}
	if res.Width != 3 || len(res.Runs) != simLorenzRows {
		t.Fatalf("lorenz width %d, %d runs; want 3, %d", res.Width, len(res.Runs), simLorenzRows)
	}
	assertSweepArtifact(t, "RunModule lorenz (re-encoded)", reencodeRuns(t, res, simLorenzTEnd*100), simLorenzRows, simLorenzTEnd, 3, simLorenzSHA256)

	// A model the image does not carry: the loader refuses, request-attributable.
	res, err = d.RunModule(ctx, ModuleRequest{Model: "nosuchmodel", Rows: rows[:2], EndTime: 1, Step: 0.01})
	if err != nil {
		t.Fatalf("unknown model: unexpected error %v", err)
	}
	if res.Outcome != ProjectOutcomeSetupFailed || !strings.Contains(res.Detail, "load failed") {
		t.Fatalf("unknown model: outcome = %s (%s), want setup_failed with the loader's message", res.Outcome, res.Detail)
	}

	// The model's own parameter count governs the row width.
	res, err = d.RunModule(ctx, ModuleRequest{Model: "vanderpol", Rows: [][]float64{{1, 2}}, EndTime: 1, Step: 0.01})
	if err != nil {
		t.Fatalf("narrow row: unexpected error %v", err)
	}
	if res.Outcome != ProjectOutcomeSetupFailed || !strings.Contains(res.Detail, "expected 3 values") {
		t.Fatalf("narrow row: outcome = %s (%s), want setup_failed naming the model's parameter count", res.Outcome, res.Detail)
	}

	// 300 rows of 2002 steps pass the daemon's width-1 bound (4.8 MB) and fail
	// the worker's exact one at width 2 (9.6 MB): refused before any row ran,
	// and the message is the worker's (no "at least").
	_, err = d.RunModule(ctx, ModuleRequest{Model: "vanderpol", Rows: sweepRows(300, 0.1, 5.0, 2.0, 0.0), EndTime: simVanDerPolTEnd, Step: 0.01})
	if !errors.Is(err, ErrInvalidRequest) || !strings.Contains(err.Error(), "byte budget") || strings.Contains(err.Error(), "at least") {
		t.Fatalf("over-budget table: err = %v, want the worker's ErrInvalidRequest refusal", err)
	}

	// Pre-dispatch refusals never launch a container.
	if _, err := d.RunModule(ctx, ModuleRequest{Model: "vanderpol", Rows: [][]float64{{1, 2, 3}, {1}}, EndTime: 1, Step: 0.01}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ragged table: err = %v, want ErrInvalidRequest", err)
	}
	if _, err := d.RunModule(ctx, ModuleRequest{Model: "vanderpol", Rows: rows[:1], EndTime: 1, Step: 0.01, MinimumIsolation: IsolationVM}); !errors.Is(err, ErrInsufficientIsolation) {
		t.Fatalf("vm floor on docker: err = %v, want ErrInsufficientIsolation", err)
	}
	plain := testDocker()
	if plain.SupportsModules() {
		t.Fatal("SupportsModules true with no module image")
	}
	if _, err := plain.RunModule(ctx, ModuleRequest{Model: "vanderpol", Rows: rows[:1], EndTime: 1, Step: 0.01}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("no module image: err = %v, want ErrUnsupported", err)
	}
}
