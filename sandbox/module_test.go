package sandbox

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"
)

func validModuleRequest() ModuleRequest {
	return ModuleRequest{Model: "vanderpol", Rows: [][]float64{{1, 2, 0}, {2, 2, 0}}, EndTime: 20, Step: 0.01}
}

func TestValidateModuleRequest(t *testing.T) {
	if err := ValidateModuleRequest(validModuleRequest()); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	tooManyRows := make([][]float64, MaxModuleRows+1)
	for i := range tooManyRows {
		tooManyRows[i] = []float64{1}
	}
	wide := make([]float64, MaxModuleRowWidth+1)
	cases := []struct {
		name   string
		mutate func(*ModuleRequest)
		want   string
	}{
		{"empty model", func(r *ModuleRequest) { r.Model = "" }, "model must match"},
		{"path in model", func(r *ModuleRequest) { r.Model = "../etc/passwd" }, "model must match"},
		{"slash in model", func(r *ModuleRequest) { r.Model = "a/b" }, "model must match"},
		{"leading dot", func(r *ModuleRequest) { r.Model = ".hidden" }, "model must match"},
		{"model too long", func(r *ModuleRequest) { r.Model = strings.Repeat("a", 65) }, "model must match"},
		{"no rows", func(r *ModuleRequest) { r.Rows = nil }, "at least one row"},
		{"too many rows", func(r *ModuleRequest) { r.Rows = tooManyRows }, "too many rows"},
		{"empty row", func(r *ModuleRequest) { r.Rows = [][]float64{{}} }, "1 to 64 values"},
		{"row too wide", func(r *ModuleRequest) { r.Rows = [][]float64{wide} }, "1 to 64 values"},
		{"ragged rows", func(r *ModuleRequest) { r.Rows = [][]float64{{1, 2, 3}, {1, 2}} }, "row 1 has 2 values, row 0 has 3"},
		{"nan value", func(r *ModuleRequest) { r.Rows[1][2] = math.NaN() }, "row 1 value 2 is not finite"},
		{"inf value", func(r *ModuleRequest) { r.Rows[0][0] = math.Inf(1) }, "row 0 value 0 is not finite"},
		{"zero end", func(r *ModuleRequest) { r.EndTime = 0 }, "end_time must be positive"},
		{"negative end", func(r *ModuleRequest) { r.EndTime = -1 }, "end_time must be positive"},
		{"nan end", func(r *ModuleRequest) { r.EndTime = math.NaN() }, "end_time must be positive"},
		{"zero step", func(r *ModuleRequest) { r.Step = 0 }, "step must be positive"},
		{"inf step", func(r *ModuleRequest) { r.Step = math.Inf(1) }, "step must be positive"},
		{"too many steps", func(r *ModuleRequest) { r.EndTime, r.Step = 1e6, 1e-3 }, "exceeds 1000000 steps"},
		{"results over budget", func(r *ModuleRequest) {
			// 600 rows of 2002 steps at one output per step is 9.6 MB, over 8 MiB
			// with the width the daemon cannot know; the worker would refuse too.
			r.Rows = make([][]float64, 600)
			for i := range r.Rows {
				r.Rows[i] = []float64{1, 2, 0}
			}
		}, "over the 8388608 byte budget"},
		{"bad isolation", func(r *ModuleRequest) { r.MinimumIsolation = IsolationClass(99) }, "minimum isolation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validModuleRequest()
			tc.mutate(&r)
			err := ValidateModuleRequest(r)
			if err == nil {
				t.Fatalf("accepted; want an error containing %q", tc.want)
			}
			if !errors.Is(err, ErrInvalidRequest) && tc.name != "bad isolation" {
				t.Errorf("error %v is not ErrInvalidRequest", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestModuleRequestMaxSteps(t *testing.T) {
	r := ModuleRequest{EndTime: 20, Step: 0.01}
	// The worker computes (int32_t)(t_end / h) + 2; 20/0.01 is 2000 in float64.
	if got := r.MaxSteps(); got != 2002 {
		t.Fatalf("MaxSteps = %d, want 2002", got)
	}
}

// encodeModuleResults builds a worker record for the decoder tests, so a change to
// either side's layout fails here rather than in a docker run.
func encodeModuleResults(runs []ModuleRun, width, params int) []byte {
	b := []byte("PLSM")
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(runs)))
	b = binary.LittleEndian.AppendUint32(b, uint32(width))
	b = binary.LittleEndian.AppendUint32(b, uint32(params))
	for _, r := range runs {
		b = binary.LittleEndian.AppendUint32(b, uint32(r.Status))
		for _, v := range r.Outputs {
			b = binary.LittleEndian.AppendUint64(b, math.Float64bits(v))
		}
	}
	return b
}

func TestDecodeModuleResults(t *testing.T) {
	want := []ModuleRun{
		{Status: 2, Outputs: []float64{1, 2, 3, 4}},
		{Status: -3},
		{Status: 0},
		{Status: 1, Outputs: []float64{math.Pi, -0}},
	}
	rec := encodeModuleResults(want, 2, 3)
	runs, width, err := DecodeModuleResults(rec, 4, 3)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if width != 2 || len(runs) != 4 {
		t.Fatalf("width %d, %d runs; want 2, 4", width, len(runs))
	}
	for i := range want {
		if runs[i].Status != want[i].Status || len(runs[i].Outputs) != len(want[i].Outputs) {
			t.Fatalf("run %d = %+v, want %+v", i, runs[i], want[i])
		}
		for k := range want[i].Outputs {
			if math.Float64bits(runs[i].Outputs[k]) != math.Float64bits(want[i].Outputs[k]) {
				t.Fatalf("run %d output %d = %v, want %v (bit-exact)", i, k, runs[i].Outputs[k], want[i].Outputs[k])
			}
		}
	}

	bad := []struct {
		name string
		rec  []byte
		rows int
		want string
	}{
		{"short", rec[:10], 4, "shorter than its header"},
		{"magic", append([]byte("XXXX"), rec[4:]...), 4, "magic"},
		{"version", func() []byte { c := append([]byte(nil), rec...); c[4] = 2; return c }(), 4, "version 2"},
		{"row count", rec, 5, "describes 4 rows"},
		{"zero width", func() []byte { c := append([]byte(nil), rec...); c[12] = 0; return c }(), 4, "width 0"},
		{"truncated outputs", rec[:len(rec)-8], 4, "ends inside row 3's outputs"},
		{"truncated status", rec[:moduleResultHeader+2], 4, "ends inside row 0's status"},
		{"trailing", append(append([]byte(nil), rec...), 0), 4, "1 trailing bytes"},
		{"huge status", func() []byte {
			c := append([]byte(nil), rec...)
			binary.LittleEndian.PutUint32(c[moduleResultHeader:], math.MaxInt32)
			return c
		}(), 4, "ends inside row 0's outputs"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := DecodeModuleResults(tc.rec, tc.rows, 3)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
	if _, _, err := DecodeModuleResults(rec, 4, 2); err == nil || !strings.Contains(err.Error(), "of 3 params, the request had 4 rows of 2") {
		t.Fatalf("params mismatch not refused: %v", err)
	}
}
