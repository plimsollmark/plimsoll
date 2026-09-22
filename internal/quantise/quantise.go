// Package quantise reports the resolution at which a module run's swept
// parameter was actually resolved, which is not always the resolution the
// caller asked for.
//
// A compiled physical model subdivides the communication step with an internal
// step of its own, so a parameter that only enters the model at those internal
// instants moves in discrete treads. Two exports of one model can tread a
// decade apart: measured on CoupledClutches, one vendor at 1e-2 and another at
// 1e-3. A caller sweeping finer than the tread pays for simulations that return
// a result it already has, and a caller differentiating across one gets exactly
// zero. Neither failure announces itself: every row succeeds and every number
// looks reasonable.
//
// This is post-dispatch analysis over results plimsoll already computed, in the
// same sense as the efficiency advisor: it runs no model, changes no result, and
// cannot fail a run. It sees parameter values and output bits, which the caller
// supplied and plimsoll already holds, and derives nothing else.
package quantise

import (
	"encoding/binary"
	"math"
	"sort"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Finding describes one swept parameter column whose results are quantised.
// Tread spacings are in the swept parameter's own units, so they are directly
// comparable with the step the caller asked for.
type Finding struct {
	// Column is the index into each parameter row that varied.
	Column int
	// Rows is how many distinct parameter values completed (a value submitted
	// twice counts once), and Distinct how many different output vectors they
	// produced, counted over the whole sweep. Repeated is Rows-Distinct: the
	// simulations that returned a result some other row already had, wherever
	// in the sweep that row sat.
	Rows     int
	Distinct int
	Repeated int
	// Flat counts neighbouring samples, in swept order, that returned the same
	// result. It is the tread evidence: a repeat between non-neighbours (A, B,
	// A) is a repeat but not a tread, since the parameter did change the result
	// in between. A repeat is evidence of coarse resolution, never proof of its
	// cause: a model that is genuinely insensitive to the parameter over the
	// swept range produces the same pattern.
	Flat int
	// Sampled is the finest gap the caller swept at, Span the full swept range.
	Sampled float64
	Span    float64
	// TreadMin and TreadMax bound the measured spacing between changes. Both
	// are zero when Distinct is 1, where no spacing can be measured and the
	// tread is only known to exceed Span.
	TreadMin, TreadMax float64
}

// Quantised reports whether the column resolved more coarsely than it was
// swept: at least one pair of neighbouring samples returned the same result.
// A column with no such pair produces no finding.
func (f Finding) Quantised() bool { return f.Flat > 0 }

// WholeSweepInOneTread reports the worst case: every row returned the same
// result, so the sweep never left one tread and its results carry no
// information about the parameter at all.
func (f Finding) WholeSweepInOneTread() bool { return f.Distinct == 1 && f.Rows > 1 }

// Analyze measures the treads in one module run's results. It returns nothing
// unless exactly one parameter column varies across the rows: with two varying
// at once a repeated result cannot be attributed to either, and guessing would
// be worse than silence.
//
// runs must be positionally aligned with rows, which is the contract
// sandbox.ModuleResult.Runs already carries. Rows that did not complete are
// skipped rather than treated as a repeat. Rows that repeat a parameter value
// collapse to one sample, since the same input returning the same output is
// determinism, not a tread; if they disagree the run is not deterministic and
// nothing is reported.
func Analyze(rows [][]float64, runs []sandbox.ModuleRun) []Finding {
	if len(rows) < 2 || len(runs) != len(rows) {
		return nil
	}
	column, ok := soleVaryingColumn(rows)
	if !ok {
		return nil
	}
	// Only completed rows carry outputs to compare. A failed row is not
	// evidence of a tread in either direction.
	type sample struct {
		value float64
		bits  []uint64
	}
	samples := make([]sample, 0, len(rows))
	for i, run := range runs {
		if run.Status <= 0 || run.Outputs == nil {
			continue
		}
		samples = append(samples, sample{value: rows[i][column], bits: outputBits(run.Outputs)})
	}
	sort.SliceStable(samples, func(a, b int) bool { return samples[a].value < samples[b].value })
	// Collapse repeated parameter values. Sorting put them next to each other.
	unique := samples[:0]
	for _, s := range samples {
		if n := len(unique); n > 0 && math.Float64bits(unique[n-1].value) == math.Float64bits(s.value) {
			if !sameBits(unique[n-1].bits, s.bits) {
				return nil // one input, two answers: not deterministic, so no tread claim
			}
			continue
		}
		unique = append(unique, s)
	}
	samples = unique
	if len(samples) < 2 {
		return nil
	}

	// Walk in swept order. A change between adjacent samples ends a tread; the
	// distance between consecutive changes is one tread's width. Distinct is
	// counted over the whole sweep, not from the changes, so a result that
	// comes back after a different one (A, B, A) is one result, not two.
	seen := map[string]struct{}{key(samples[0].bits): {}}
	flat := 0
	var changes []float64
	finest := math.Inf(1)
	for i := 1; i < len(samples); i++ {
		if gap := samples[i].value - samples[i-1].value; gap > 0 && gap < finest {
			finest = gap
		}
		seen[key(samples[i].bits)] = struct{}{}
		if sameBits(samples[i].bits, samples[i-1].bits) {
			flat++
			continue
		}
		// The edge sits between the two samples that straddle it; the midpoint
		// is the least wrong single number for it at this sampling.
		changes = append(changes, (samples[i].value+samples[i-1].value)/2)
	}
	if flat == 0 {
		return nil // no two neighbours agree: resolved at this sampling
	}
	f := Finding{
		Column:   column,
		Rows:     len(samples),
		Distinct: len(seen),
		Repeated: len(samples) - len(seen),
		Flat:     flat,
		Span:     samples[len(samples)-1].value - samples[0].value,
	}
	if !math.IsInf(finest, 1) {
		f.Sampled = finest
	}
	// Two edges bound one whole tread. One edge bounds none: it says only that
	// the tread is wider than nothing, which is not a measurement.
	for i := 1; i < len(changes); i++ {
		w := changes[i] - changes[i-1]
		if f.TreadMin == 0 || w < f.TreadMin {
			f.TreadMin = w
		}
		if w > f.TreadMax {
			f.TreadMax = w
		}
	}
	return []Finding{f}
}

// soleVaryingColumn returns the single column that varies across rows. Rows of
// unequal width, no varying column, or more than one all report not-ok.
func soleVaryingColumn(rows [][]float64) (int, bool) {
	width := len(rows[0])
	if width == 0 {
		return 0, false
	}
	found, count := 0, 0
	for c := 0; c < width; c++ {
		varies := false
		for _, row := range rows {
			if len(row) != width {
				return 0, false
			}
			if math.Float64bits(row[c]) != math.Float64bits(rows[0][c]) {
				varies = true
			}
		}
		if varies {
			found, count = c, count+1
		}
	}
	return found, count == 1
}

// outputBits compares trajectories the way the rest of this project compares
// them: by the bits, so a one-ulp difference is a difference and NaN matches
// NaN rather than failing every comparison.
func outputBits(out []float64) []uint64 {
	bits := make([]uint64, len(out))
	for i, v := range out {
		bits[i] = math.Float64bits(v)
	}
	return bits
}

// key is a map key for one output vector, exact to the bit.
func key(bits []uint64) string {
	b := make([]byte, 8*len(bits))
	for i, v := range bits {
		binary.LittleEndian.PutUint64(b[8*i:], v)
	}
	return string(b)
}

func sameBits(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
