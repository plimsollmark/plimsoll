package sandbox

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"testing"
)

// A buck converter controller written in C, compiled to WebAssembly inside the
// sandbox and judged against /models/buck.wasm (examples/wasm-buck), under the same
// shared shim as the cart-pole controller.
//
// Proven here:
//   - the compile is reproducible: two runs produce the same controller.wasm, and
//     its SHA-256 is the one recorded in examples/wasm-buck/fingerprints.json;
//   - every scenario's trajectory has one fingerprint across the two runs, the one
//     recorded in the fixture;
//   - the JavaScript law the C is a port of (reference.js), run through the same
//     judge, gives the same four fingerprints: the two trajectories are identical to
//     the bit. Unlike the cart-pole port, which calls cos, this law calls no library
//     function, and -ffp-contract=off keeps every multiply and add separate, so each
//     operation is the same IEEE 754 double operation in both languages;
//   - the controller regulates: no overvoltage (6 V) or overcurrent (10 A) at any
//     tick, and at least the fixture's floor (0.6) of the ticks from 2 ms on within
//     0.1 V of 5 V.

const wasmBuckDir = "../examples/wasm-buck/"

// wasmBuckWidth is the buck plant's observation count: output voltage and inductor
// current. The judge appends the duty cycle.
const wasmBuckWidth = 2

type wasmBuckFixture struct {
	Build                string  `json:"build"`
	ControllerWasmSHA256 string  `json:"controller_wasm_sha256"`
	Plant                string  `json:"plant"`
	TickS                float64 `json:"tick_s"`
	TEndS                float64 `json:"t_end_s"`
	MinScore             float64 `json:"min_score"`
	Scenarios            []struct {
		ID          string    `json:"id"`
		Params      []float64 `json:"params"`
		Fingerprint string    `json:"fingerprint"`
	} `json:"scenarios"`
}

func readWasmBuckFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(wasmBuckDir + name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return string(raw)
}

func (f wasmBuckFixture) judged() wasmJudged {
	j := wasmJudged{Plant: f.Plant, TickS: f.TickS, TEndS: f.TEndS, Width: wasmBuckWidth}
	for _, s := range f.Scenarios {
		j.Scenarios = append(j.Scenarios, wasmScenario{ID: s.ID, Params: s.Params})
	}
	return j
}

// buckRegulationScore is envs/buck-converter's verifier, restated: the fraction of
// ticks from 2 ms on with the output within 0.1 V of 5 V, and zero with a reason if
// the output ever exceeds 6 V or the inductor current 10 A in magnitude. The
// trajectory is the judge's record: per tick v, i, then the duty cycle, as
// little-endian float64.
func buckRegulationScore(traj []byte, tickS float64) (score float64, failure string) {
	stride := wasmBuckWidth + 1
	n := len(traj) / 8 / stride
	at := func(k, col int) float64 {
		return math.Float64frombits(binary.LittleEndian.Uint64(traj[(k*stride+col)*8:]))
	}
	from := int(math.Round(0.002 / tickS))
	inBand, counted := 0, 0
	for k := 0; k < n; k++ {
		v, i := at(k, 0), at(k, 1)
		if math.Abs(i) > 10 {
			return 0, "overcurrent"
		}
		if v > 6 {
			return 0, "overvoltage"
		}
		if k >= from {
			counted++
			if math.Abs(v-5) <= 0.1 {
				inBand++
			}
		}
	}
	if inBand == 0 {
		return 0, "never_regulated"
	}
	return float64(inBand) / float64(counted), ""
}

func TestDockerWasmBuckControllerMatchesItsJavaScriptLaw(t *testing.T) {
	d := testDocker()
	d.ProjectImage = wasmCCProjectImage
	requireProjectImage(t, d)
	var f wasmBuckFixture
	if err := json.Unmarshal([]byte(readWasmBuckFile(t, "fingerprints.json")), &f); err != nil {
		t.Fatalf("fingerprints.json: %v", err)
	}
	if f.Build == "" || len(f.ControllerWasmSHA256) != 64 || f.Plant == "" || len(f.Scenarios) == 0 || f.TickS <= 0 || f.TEndS <= 0 {
		t.Fatalf("fingerprints.json is incomplete: %+v", f)
	}
	j := f.judged()
	cFiles := []File{
		{Path: "controller.c", Content: readWasmBuckFile(t, "controller/controller.c")},
		{Path: "controller.js", Content: readWasmShim(t)},
	}
	wasm1, first := runWasmJudged(t, d, j, cFiles, f.Build, "controller.js")
	wasm2, second := runWasmJudged(t, d, j, cFiles, f.Build, "controller.js")
	_, js := runWasmJudged(t, d, j, []File{{Path: "reference.js", Content: readWasmBuckFile(t, "controller/reference.js")}}, "", "reference.js")

	sum1, sum2 := sha256.Sum256(wasm1), sha256.Sum256(wasm2)
	if sum1 != sum2 {
		t.Fatalf("two compiles of the same source differ: %x and %x", sum1, sum2)
	}
	if got := hex.EncodeToString(sum1[:]); got != f.ControllerWasmSHA256 {
		t.Fatalf("controller.wasm hashes to %s, fixture records %s (a changed source, flag or toolchain)", got, f.ControllerWasmSHA256)
	}
	t.Logf("controller.wasm: %d bytes, %x, identical across two compiles", len(wasm1), sum1)

	for _, s := range f.Scenarios {
		a, b, r := first[s.ID], second[s.ID], js[s.ID]
		if a.fingerprint != b.fingerprint {
			t.Errorf("%s: two runs gave two fingerprints: %s and %s", s.ID, a.fingerprint, b.fingerprint)
			continue
		}
		if a.fingerprint != s.Fingerprint {
			t.Errorf("%s: fingerprint %s, fixture records %s", s.ID, a.fingerprint, s.Fingerprint)
		}
		if r.fingerprint != a.fingerprint {
			t.Errorf("%s: the JavaScript law gave %s, the C port %s; the port is not bit-exact", s.ID, r.fingerprint, a.fingerprint)
		}
		score, failure := buckRegulationScore(a.trajectory, f.TickS)
		if failure != "" || score < f.MinScore {
			t.Errorf("%s: score %.4f, failure %q; want at least %.2f", s.ID, score, failure, f.MinScore)
			continue
		}
		t.Logf("%s %v: %s = JavaScript, score %.4f", s.ID, s.Params, a.fingerprint[:16], score)
	}
}
