package quantise_test

import (
	"math"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/quantise"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// staircase builds a sweep of one parameter whose results only change when the
// value crosses a multiple of tread, which is what an internal fixed step does
// to a parameter that only enters the model at its own instants.
func staircase(t *testing.T, lo, step, tread float64, n int) ([][]float64, []sandbox.ModuleRun) {
	t.Helper()
	rows := make([][]float64, n)
	runs := make([]sandbox.ModuleRun, n)
	for i := range rows {
		v := lo + float64(i)*step
		rows[i] = []float64{1.5, v, 0.25}
		// One output per step; the value is constant across a tread.
		level := math.Floor(v/tread + 1e-9)
		runs[i] = sandbox.ModuleRun{Status: 3, Outputs: []float64{level, level * 2, level * 3}}
	}
	return rows, runs
}

func TestTreadIsMeasuredInTheSweptParametersUnits(t *testing.T) {
	// Swept ten times finer than the tread, which is the case that wastes runs.
	rows, runs := staircase(t, 0.0, 0.001, 0.01, 61)
	found := quantise.Analyze(rows, runs)
	if len(found) != 1 {
		t.Fatalf("want one finding, got %d", len(found))
	}
	f := found[0]
	if f.Column != 1 {
		t.Errorf("swept column: got %d want 1", f.Column)
	}
	if !f.Quantised() {
		t.Error("a sweep ten times finer than the tread must report as quantised")
	}
	if got, want := f.Rows, 61; got != want {
		t.Errorf("rows: got %d want %d", got, want)
	}
	// 61 samples over 0.060 at a tread of 0.01 cross six edges, so seven levels.
	if got, want := f.Distinct, 7; got != want {
		t.Errorf("distinct results: got %d want %d", got, want)
	}
	if got, want := f.Repeated, 54; got != want {
		t.Errorf("repeated results: got %d want %d", got, want)
	}
	const tol = 1e-9
	if math.Abs(f.TreadMin-0.01) > tol || math.Abs(f.TreadMax-0.01) > tol {
		t.Errorf("tread: got [%g, %g] want 0.01 both", f.TreadMin, f.TreadMax)
	}
	if math.Abs(f.Sampled-0.001) > tol {
		t.Errorf("sampled spacing: got %g want 0.001", f.Sampled)
	}
	if math.Abs(f.Span-0.060) > tol {
		t.Errorf("span: got %g want 0.06", f.Span)
	}
}

func TestAResolvedSweepProducesNoFinding(t *testing.T) {
	// Swept coarser than the tread: every row is a different answer, so there
	// is nothing to warn about and silence is the right output.
	rows, runs := staircase(t, 0.0, 0.05, 0.01, 10)
	if found := quantise.Analyze(rows, runs); len(found) != 0 {
		t.Fatalf("want no finding when every row differs, got %+v", found)
	}
}

func TestWholeSweepInsideOneTread(t *testing.T) {
	// The worst case: every row succeeds, every number looks fine, and the
	// results carry no information about the parameter at all.
	rows, runs := staircase(t, 0.0, 0.0005, 1.0, 12)
	found := quantise.Analyze(rows, runs)
	if len(found) != 1 {
		t.Fatalf("want one finding, got %d", len(found))
	}
	f := found[0]
	if !f.WholeSweepInOneTread() {
		t.Errorf("want the whole-sweep case, got distinct=%d rows=%d", f.Distinct, f.Rows)
	}
	if f.TreadMin != 0 || f.TreadMax != 0 {
		t.Errorf("no edge was crossed so no tread can be measured: got [%g, %g]", f.TreadMin, f.TreadMax)
	}
	if got, want := f.Repeated, 11; got != want {
		t.Errorf("repeated: got %d want %d", got, want)
	}
}

func TestTwoVaryingColumnsAreNotAttributed(t *testing.T) {
	rows := [][]float64{{0, 0}, {0.001, 1}, {0.002, 2}, {0.003, 3}}
	runs := []sandbox.ModuleRun{
		{Status: 1, Outputs: []float64{5}}, {Status: 1, Outputs: []float64{5}},
		{Status: 1, Outputs: []float64{5}}, {Status: 1, Outputs: []float64{5}},
	}
	if found := quantise.Analyze(rows, runs); len(found) != 0 {
		t.Fatalf("a repeat cannot be attributed to either column: got %+v", found)
	}
}

func TestFailedRowsAreSkippedNotCountedAsRepeats(t *testing.T) {
	rows := [][]float64{{0.0}, {0.001}, {0.002}, {0.003}}
	runs := []sandbox.ModuleRun{
		{Status: 1, Outputs: []float64{1}},
		{Status: -7}, // the model refused this row
		{Status: 1, Outputs: []float64{1}},
		{Status: 1, Outputs: []float64{2}},
	}
	found := quantise.Analyze(rows, runs)
	if len(found) != 1 {
		t.Fatalf("want one finding, got %d", len(found))
	}
	if got, want := found[0].Rows, 3; got != want {
		t.Errorf("only completed rows take part: got %d want %d", got, want)
	}
	if got, want := found[0].Repeated, 1; got != want {
		t.Errorf("repeated: got %d want %d", got, want)
	}
}

func TestRowOrderDoesNotChangeTheMeasurement(t *testing.T) {
	rows, runs := staircase(t, 0.0, 0.001, 0.01, 41)
	ordered := quantise.Analyze(rows, runs)
	// Reverse the table: a caller may submit rows in any order.
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
		runs[i], runs[j] = runs[j], runs[i]
	}
	reversed := quantise.Analyze(rows, runs)
	if len(ordered) != 1 || len(reversed) != 1 {
		t.Fatalf("want one finding each, got %d and %d", len(ordered), len(reversed))
	}
	if ordered[0] != reversed[0] {
		t.Errorf("measurement depends on row order:\n ordered %+v\nreversed %+v", ordered[0], reversed[0])
	}
}

func TestOneUlpCountsAsAChange(t *testing.T) {
	// The project treats trajectories as bit-identical or different everywhere
	// else, and this detector must not quietly widen that.
	base := 1.25
	rows := [][]float64{{0.0}, {0.001}, {0.002}}
	runs := []sandbox.ModuleRun{
		{Status: 1, Outputs: []float64{base}},
		{Status: 1, Outputs: []float64{math.Float64frombits(math.Float64bits(base) + 1)}},
		{Status: 1, Outputs: []float64{base}},
	}
	if found := quantise.Analyze(rows, runs); len(found) != 0 {
		t.Fatalf("a one-ulp difference is a difference: got %+v", found)
	}
}

func TestDegenerateInputsReportNothing(t *testing.T) {
	runs := []sandbox.ModuleRun{{Status: 1, Outputs: []float64{1}}}
	for name, tc := range map[string]struct {
		rows [][]float64
		runs []sandbox.ModuleRun
	}{
		"single row":        {[][]float64{{0.5}}, runs},
		"no rows":           {nil, nil},
		"misaligned runs":   {[][]float64{{0.5}, {0.6}}, runs},
		"zero-width rows":   {[][]float64{{}, {}}, []sandbox.ModuleRun{{Status: 1}, {Status: 1}}},
		"no varying column": {[][]float64{{0.5}, {0.5}}, []sandbox.ModuleRun{{Status: 1, Outputs: []float64{1}}, {Status: 1, Outputs: []float64{1}}}},
	} {
		if found := quantise.Analyze(tc.rows, tc.runs); len(found) != 0 {
			t.Errorf("%s: want no finding, got %+v", name, found)
		}
	}
}

func TestAResultThatComesBackIsCountedOnce(t *testing.T) {
	// A, A, B, A: the fourth row returns the first answer. Counting changes
	// between neighbours would call that three distinct results; there are two.
	rows := [][]float64{{0.0}, {0.001}, {0.002}, {0.003}}
	runs := []sandbox.ModuleRun{
		{Status: 1, Outputs: []float64{1}}, {Status: 1, Outputs: []float64{1}},
		{Status: 1, Outputs: []float64{2}}, {Status: 1, Outputs: []float64{1}},
	}
	found := quantise.Analyze(rows, runs)
	if len(found) != 1 {
		t.Fatalf("want one finding, got %d", len(found))
	}
	f := found[0]
	if f.Distinct != 2 || f.Repeated != 2 || f.Flat != 1 {
		t.Errorf("want distinct=2 repeated=2 flat=1, got distinct=%d repeated=%d flat=%d", f.Distinct, f.Repeated, f.Flat)
	}
}

func TestARepeatWithoutAFlatNeighbourIsNotATread(t *testing.T) {
	// A, B, A: the parameter changed the result and then changed it back. That
	// is a repeat, not coarse resolution, and reporting it as a tread would be
	// a claim about the model the data does not support.
	rows := [][]float64{{0.0}, {0.001}, {0.002}}
	runs := []sandbox.ModuleRun{
		{Status: 1, Outputs: []float64{1}}, {Status: 1, Outputs: []float64{2}}, {Status: 1, Outputs: []float64{1}},
	}
	if found := quantise.Analyze(rows, runs); len(found) != 0 {
		t.Fatalf("no neighbours agree, so no tread: got %+v", found)
	}
}

func TestARepeatedParameterValueIsDeterminismNotATread(t *testing.T) {
	// The caller submitted 0.001 twice. Getting the same answer twice is the
	// model being deterministic, and every other neighbour differs.
	rows := [][]float64{{0.0}, {0.001}, {0.001}, {0.002}}
	runs := []sandbox.ModuleRun{
		{Status: 1, Outputs: []float64{1}}, {Status: 1, Outputs: []float64{2}},
		{Status: 1, Outputs: []float64{2}}, {Status: 1, Outputs: []float64{3}},
	}
	if found := quantise.Analyze(rows, runs); len(found) != 0 {
		t.Fatalf("a duplicated input is not a tread: got %+v", found)
	}
}

func TestOneInputTwoAnswersReportsNothing(t *testing.T) {
	rows := [][]float64{{0.0}, {0.0}, {0.001}, {0.002}}
	runs := []sandbox.ModuleRun{
		{Status: 1, Outputs: []float64{1}}, {Status: 1, Outputs: []float64{9}},
		{Status: 1, Outputs: []float64{1}}, {Status: 1, Outputs: []float64{1}},
	}
	if found := quantise.Analyze(rows, runs); len(found) != 0 {
		t.Fatalf("a non-deterministic run supports no tread claim: got %+v", found)
	}
}
