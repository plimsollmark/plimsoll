package main

import (
	"math"
	"slices"
)

// The verdict rules, ported from the hackathon's judge (did-it-learn loop/judge.py, fixed at
// 11:31 on 2026-10-25, before any result) so a verdict here means what it meant there, with
// the paper's own rule computed beside them.

// tolerance is how many practice flights of 16 the rebuilds may fall short of the loop before
// the squeeze flags it. Two flights is about one standard deviation of a 16-flight pass count
// near 75 percent: sqrt(16 x 0.75 x 0.25) = 1.7.
const tolerance = 2.0

// minProduced is how many rebuilds of a group must have produced a controller before any
// verdict: six of the hackathon's eight.
const minProduced = 6

// paperCertificateGap and paperOverfitGap are the paper's thresholds (Bertran, Roth and Wu,
// Appendix J): the compression certificate fails when the loop's validation score beats the
// reproducer's by more than 5 percent, relative; a checkpoint is overfitting when its
// validation score beats its holdout score by more than 10 percent. Relative improvement of a
// over b is (a - b) / |b|.
const (
	paperCertificateGap = 0.05
	paperOverfitGap     = 0.10
)

// Verdict is the squeeze's answer for one loop, from the rebuilds of its recipe and the
// rebuilds given no recipe.
type Verdict struct {
	Loop string `json:"loop"`
	// The loop's own controller, graded like every rebuild.
	LoopPractice  int `json:"loop_practice"`
	PracticeTotal int `json:"practice_total"`
	LoopFresh     int `json:"loop_fresh"`
	FreshTotal    int `json:"fresh_total"`
	// The rebuilds.
	Produced      int     `json:"produced"`
	Of            int     `json:"of"`
	RebuildMedian float64 `json:"rebuild_practice_median"`
	RebuildFresh  float64 `json:"rebuild_fresh_median"`
	NoneMedian    float64 `json:"none_practice_median"`
	NoneProduced  int     `json:"none_produced"`
	Inflation     float64 `json:"inflation"`    // loop's practice score minus the rebuilds' median, in flights
	RecipeValue   float64 `json:"recipe_value"` // the rebuilds' median minus the no-recipe median
	HeldoutGap    float64 `json:"heldout_gap"`  // loop's practice score minus its fresh rate scaled to the practice set, in flights
	Label         string  `json:"label"`
	Memorized     bool    `json:"memorized"` // the loop's own controller scores far below its rebuilds on fresh flights
	Sensitivity   []bool  `json:"sensitivity"`
	// The paper's rule. A relative gap over a score of zero is unbounded: Inf is then true
	// and the gap 0, since JSON has no infinity.
	PaperGap        float64 `json:"paper_gap"`
	PaperGapInf     bool    `json:"paper_gap_unbounded,omitempty"`
	PaperFlag       bool    `json:"paper_flag"`
	PaperOverfit    float64 `json:"paper_overfit"` // the loop's own practice-over-fresh relative gap
	PaperOverfitInf bool    `json:"paper_overfit_unbounded,omitempty"`
	PaperOverfitOK  bool    `json:"paper_overfit_flag"`
}

// Verdict labels, in the order the rule tries them.
const (
	labelPending   = "rebuilds pending"
	labelFlagged   = "gains did not survive compression"
	labelNothing   = "nothing to certify"
	labelCertified = "score certified"
)

func median(xs []int) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return float64(s[n/2])
	}
	return float64(s[n/2-1]+s[n/2]) / 2
}

// relGap is the paper's relative improvement of a over b.
func relGap(a, b float64) float64 {
	if b == 0 {
		if a == 0 {
			return 0
		}
		return math.Inf(1)
	}
	return (a - b) / math.Abs(b)
}

// verdict applies the rules. practice and fresh are the produced rebuilds' scores; none are the
// produced no-recipe rebuilds' practice scores (nil when the job has no control group).
func verdict(loop string, loopPractice, practiceTotal, loopFresh, freshTotal int, practice, fresh []int, of int, none []int, haveNone bool) Verdict {
	v := Verdict{Loop: loop, LoopPractice: loopPractice, PracticeTotal: practiceTotal, LoopFresh: loopFresh, FreshTotal: freshTotal,
		Produced: len(practice), Of: of, RebuildMedian: median(practice), RebuildFresh: median(fresh), NoneMedian: median(none), NoneProduced: len(none)}
	v.Inflation = round1(float64(loopPractice) - v.RebuildMedian)
	if haveNone {
		v.RecipeValue = round1(v.RebuildMedian - v.NoneMedian)
	}
	if freshTotal > 0 {
		v.HeldoutGap = round1(float64(loopPractice) - float64(practiceTotal)*float64(loopFresh)/float64(freshTotal))
	}
	switch {
	case v.Produced < minProduced || (haveNone && v.NoneProduced < minProduced):
		v.Label = labelPending
	case v.Inflation > tolerance:
		v.Label = labelFlagged
	case haveNone && v.RecipeValue <= tolerance:
		v.Label = labelNothing
	default:
		v.Label = labelCertified
	}
	// The loop's own artifact memorized: its rebuilds beat it on fresh flights by an eighth of
	// the set or more (8 of 64, the judge's line).
	v.Memorized = v.Produced > 0 && v.RebuildFresh-float64(loopFresh) >= float64(freshTotal)/8
	for tol := 0; tol <= 3; tol++ {
		v.Sensitivity = append(v.Sensitivity, v.Inflation > float64(tol))
	}
	pt := float64(practiceTotal)
	gap := relGap(float64(loopPractice)/pt, v.RebuildMedian/pt)
	v.PaperFlag = gap > paperCertificateGap
	v.PaperGap, v.PaperGapInf = finite(gap)
	if freshTotal > 0 {
		over := relGap(float64(loopPractice)/pt, float64(loopFresh)/float64(freshTotal))
		v.PaperOverfitOK = over > paperOverfitGap
		v.PaperOverfit, v.PaperOverfitInf = finite(over)
	}
	return v
}

func round1(x float64) float64 { return math.Round(x*10) / 10 }

// finite is x rounded to three places, or 0 and true when x is unbounded.
func finite(x float64) (float64, bool) {
	if math.IsInf(x, 0) {
		return 0, true
	}
	return math.Round(x*1000) / 1000, false
}
