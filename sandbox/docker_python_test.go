package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

// pythonProjectImage is the tag `make docker-images` gives docker/python.Dockerfile.
const pythonProjectImage = "plimsoll/sandbox-python:latest"

// TestDockerProjectPython proves that a runtime is image content, not a provider
// feature: the Python image built from docker/python.Dockerfile runs a NumPy/SciPy
// project through the unchanged project API, and the run keeps every lockdown a
// Node project gets. The numeric checks are tight (1e-9 on float64 for a
// well-conditioned 3x3 system and an exact 4-point DFT) because a wrong or
// mislinked library would pass anything looser. The trailing `pip install` step
// documents the no-install rule from docs/guest-dependencies.md: it must fail,
// whether because the image ships no pip or because the run has no network and a
// read-only root. Skips without the image; fails under SANDBOX_TEST_REQUIRE_DOCKER=1.
func TestDockerProjectPython(t *testing.T) {
	d := testDocker()
	d.ProjectImage = pythonProjectImage
	requireProjectImage(t, d)

	// A x = b with A symmetric positive definite and x = [1, 2, 3] exactly, so the
	// expected solution has no rounding in it; the DFT of [1, 2, 3, 4] is exact too.
	const mainPy = `import json
import os
import numpy as np
import scipy
import scipy.linalg

A = np.array([[4.0, 1.0, 0.0], [1.0, 3.0, 1.0], [0.0, 1.0, 2.0]])
b = np.array([6.0, 10.0, 8.0])
x = scipy.linalg.solve(A, b, assume_a="sym")
X = np.fft.fft(np.array([1.0, 2.0, 3.0, 4.0]))

np.save("out.npy", x)
with open("result.json", "w") as f:
    json.dump({
        "x": x.tolist(),
        "fft_re": X.real.tolist(),
        "fft_im": X.imag.tolist(),
        "openblas_threads": os.environ.get("OPENBLAS_NUM_THREADS"),
        "numpy": np.__version__,
        "scipy": scipy.__version__,
    }, f)
print("numpy", np.__version__, "scipy", scipy.__version__)
`
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:     []File{{Path: "main.py", Content: mainPy}},
		Steps:     []string{"python3 main.py", "python3 -m pip install requests"},
		Artifacts: []string{"out.npy", "result.json"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("outcome = %s (%s), want completed", res.Outcome, res.Detail)
	}
	if len(res.Steps) != 2 {
		t.Fatalf("ran %d steps, want 2: %+v", len(res.Steps), res.Steps)
	}
	if run := res.Steps[0]; run.ExitCode != 0 {
		t.Fatalf("python3 main.py exit = %d, stdout=%q stderr=%q", run.ExitCode, run.Stdout, run.Stderr)
	}
	t.Logf("python step stdout: %s", strings.TrimSpace(res.Steps[0].Stdout))
	if pip := res.Steps[1]; pip.ExitCode == 0 {
		t.Fatalf("pip install succeeded inside a run; the no-install rule is broken: stdout=%q", pip.Stdout)
	} else {
		t.Logf("pip install refused as required (exit %d): %s", pip.ExitCode, strings.TrimSpace(pip.Stderr))
	}

	got := map[string][]byte{}
	for _, a := range res.Artifacts {
		got[a.Path] = a.Content
	}
	if len(got) != 2 {
		t.Fatalf("captured %d artifacts, want out.npy and result.json: %v", len(got), got)
	}

	wantX := []float64{1, 2, 3}
	if x, err := decodeNpyFloat64(got["out.npy"]); err != nil {
		t.Errorf("out.npy: %v", err)
	} else {
		assertClose(t, "out.npy", x, wantX)
	}

	var r struct {
		X              []float64 `json:"x"`
		FFTRe          []float64 `json:"fft_re"`
		FFTIm          []float64 `json:"fft_im"`
		OpenBLASThread string    `json:"openblas_threads"`
		NumPy          string    `json:"numpy"`
		SciPy          string    `json:"scipy"`
	}
	if err := json.Unmarshal(got["result.json"], &r); err != nil {
		t.Fatalf("result.json: %v: %q", err, got["result.json"])
	}
	assertClose(t, "result.json x", r.X, wantX)
	assertClose(t, "fft real", r.FFTRe, []float64{10, -2, -2, -2})
	assertClose(t, "fft imag", r.FFTIm, []float64{0, 2, 0, -2})
	if r.OpenBLASThread != "1" {
		t.Errorf("OPENBLAS_NUM_THREADS seen by the step = %q, want \"1\" (the image's ENV must reach every step)", r.OpenBLASThread)
	}
	if r.NumPy == "" || r.SciPy == "" {
		t.Errorf("versions missing from result.json: numpy=%q scipy=%q", r.NumPy, r.SciPy)
	}
}

// assertClose fails unless got and want have the same length and every element is
// within 1e-9, the tolerance the plan fixes for float64 on a well-conditioned system.
func assertClose(t *testing.T, what string, got, want []float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", what, got, want)
		return
	}
	for i := range want {
		if math.Abs(got[i]-want[i]) > 1e-9 {
			t.Errorf("%s[%d] = %.17g, want %.17g (tolerance 1e-9)", what, i, got[i], want[i])
		}
	}
}

// decodeNpyFloat64 reads a one-dimensional little-endian float64 array from the
// .npy format (versions 1.0 to 3.0): magic, version, header length, an ASCII dict
// header, then raw data. Written here rather than trusting the JSON twin so the
// artifact NumPy itself serialized is what the test checks.
func decodeNpyFloat64(b []byte) ([]float64, error) {
	magic := []byte("\x93NUMPY")
	if !bytes.HasPrefix(b, magic) || len(b) < 10 {
		return nil, fmt.Errorf("not an .npy file (first bytes %q)", b[:min(len(b), 8)])
	}
	major := b[6]
	var headerLen, off int
	switch major {
	case 1:
		headerLen, off = int(binary.LittleEndian.Uint16(b[8:10])), 10
	case 2, 3:
		if len(b) < 12 {
			return nil, fmt.Errorf("truncated v%d header", major)
		}
		headerLen, off = int(binary.LittleEndian.Uint32(b[8:12])), 12
	default:
		return nil, fmt.Errorf("unsupported .npy major version %d", major)
	}
	if len(b) < off+headerLen {
		return nil, fmt.Errorf("header length %d exceeds file", headerLen)
	}
	header := string(b[off : off+headerLen])
	if !strings.Contains(header, "'descr': '<f8'") || !strings.Contains(header, "'fortran_order': False") {
		return nil, fmt.Errorf("header is not little-endian float64 C-order: %s", strings.TrimSpace(header))
	}
	data := b[off+headerLen:]
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("data length %d is not a multiple of 8", len(data))
	}
	out := make([]float64, len(data)/8)
	for i := range out {
		out[i] = math.Float64frombits(binary.LittleEndian.Uint64(data[i*8:]))
	}
	return out, nil
}
