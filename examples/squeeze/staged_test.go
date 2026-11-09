package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const stagedPublished = "../../docs/examples/squeeze-recipe"

// The resampling draws exactly what CPython's random.Random draws for the same seed, so the
// page's intervals are the registered rule's script's own. The expected values were printed by
// Python 3.12: random.Random(seed).getrandbits(32), and random.Random(20261106).choice over
// range(16) ten times, then range(8) five times.
func TestPyRandomMatchesCPython(t *testing.T) {
	for _, c := range []struct {
		seed uint64
		want []uint32
	}{
		{20261106, []uint32{2786169488, 207578373, 379423095}},
		{0, []uint32{3626764237, 1654615998}},
		{1<<40 + 5, []uint32{2166296868, 2220160828}},
	} {
		r := newPyRandom(c.seed)
		for i, w := range c.want {
			if got := r.uint32(); got != w {
				t.Errorf("seed %d, draw %d: %d, want %d", c.seed, i, got, w)
			}
		}
	}
	r := newPyRandom(20261106)
	var got []int
	for range 10 {
		got = append(got, r.below(16))
	}
	for range 5 {
		got = append(got, r.below(8))
	}
	if fmt.Sprint(got) != "[1 2 4 7 0 10 12 8 0 0 1 3 4 2 2]" {
		t.Errorf("choices: %v", got)
	}
}

// fsum and round4 are Python's math.fsum and round(x, 4), whose results the rule compares.
func TestFsumAndRound4AreCPythons(t *testing.T) {
	tenths := make([]float64, 10)
	for i := range tenths {
		tenths[i] = 0.1
	}
	if got := fsum(tenths); got != 1.0 {
		t.Errorf("fsum of ten 0.1s: %v, want 1 (a plain sum gives 0.9999999999999999)", got)
	}
	if got := fsum([]float64{1e100, 1.0, -1e100, 1e-100, 1e50, -1.0, -1e50}); got != 1e-100 {
		t.Errorf("fsum of Python's documented example: %v, want 1e-100", got)
	}
	for x, want := range map[float64]float64{0.03125: 0.0312, 0.0771484375: 0.0771, 0.064453125: 0.0645, -0.0146484375: -0.0146, 0: 0} {
		if got := round4(x); got != want {
			t.Errorf("round4(%v) = %v, want %v", x, got, want)
		}
	}
	// lo = (1-level)/2 in float64, as Python computes it: at 90% it is 0.04999999999999999, so of
	// 10,000 sorted values the rule's script reads indexes 499 and 9499, and at 95% indexes 250
	// and 9749 (Python printed both pairs).
	sorted := make([]float64, 10000)
	for i := range sorted {
		sorted[i] = float64(i)
	}
	if q90, q95 := quantiles(sorted, 0.90), quantiles(sorted, 0.95); q90 != [2]float64{499, 9499} || q95 != [2]float64{250, 9749} {
		t.Errorf("quantiles of 10,000: at 90%% %v, at 95%% %v", q90, q95)
	}
	if q := quantiles([]float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 0.90); q != [2]float64{0, 8} {
		t.Errorf("quantiles at 90%% of ten: %v, want [0 8] as Python reads them", q)
	}
}

// The rule's four outcomes, each from the differences that decide it, in the order it tries them.
func TestStagedRuleDecidesEachOutcome(t *testing.T) {
	rule := Rule{Primary: [2]string{"scrambled", "recipe"}, Margins: RuleMargins{Landed: 0.1, Words: 1}}
	d := func(lo95, hi95, lo90, hi90 float64) Delta {
		return Delta{Interval95: [2]float64{lo95, hi95}, Interval90: [2]float64{lo90, hi90}}
	}
	none, small, up, upTiny := d(-0.5, 0.5, -0.4, 0.4), d(-0.05, 0.05, -0.04, 0.04), d(0.1, 3, 0.2, 2.5), d(0.00004, 0.2, 0.01, 0.1)
	se := func(read bool, rs, rn, sn [2]Delta) *StagedEvidence {
		return &StagedEvidence{LandedRead: read, Pairs: []PairEvidence{
			{Name: "recipe minus scrambled", Landed: rs[0], Words: rs[1]},
			{Name: "recipe minus none", Landed: rn[0], Words: rn[1]},
			{Name: "scrambled minus none", Landed: sn[0], Words: sn[1]}}}
	}
	for _, c := range []struct {
		name string
		se   *StagedEvidence
		want string
	}{
		{"words in order", se(false, [2]Delta{none, up}, [2]Delta{none, none}, [2]Delta{none, none}), outcomeOrder},
		{"landings in order, read", se(true, [2]Delta{up, small}, [2]Delta{none, small}, [2]Delta{none, small}), outcomeOrder},
		{"landings in order, withheld", se(false, [2]Delta{up, small}, [2]Delta{none, small}, [2]Delta{none, small}), outcomeNoneSee},
		{"a lower end that rounds to zero is not above it", se(true, [2]Delta{upTiny, none}, [2]Delta{none, none}, [2]Delta{none, none}), outcomeUnclear},
		{"words taken up, order unseen", se(false, [2]Delta{none, none}, [2]Delta{none, up}, [2]Delta{none, up}), outcomeWords},
		{"nothing moved", se(true, [2]Delta{small, small}, [2]Delta{none, small}, [2]Delta{none, none}), outcomeNoneSee},
		{"anything else", se(true, [2]Delta{none, none}, [2]Delta{none, none}, [2]Delta{none, none}), outcomeUnclear},
	} {
		if got, err := decide(rule, c.se); err != nil || got != c.want {
			t.Errorf("%s: %q (%v), want %q", c.name, got, err, c.want)
		}
	}
}

// The published page verifies, and its numbers are the registered rule's script's own: the
// values below are what private tooling printed from the same agents (each rounded to four
// places), before this page existed.
func TestStagedPagePublishedVerifies(t *testing.T) {
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStaged(stagedPublished, job); err != nil {
		t.Fatalf("%v; run go run ./examples/squeeze -job examples/squeeze/jobs/recipe-scramble-easy.json -staged -render -out docs/examples/squeeze-recipe", err)
	}
	page, err := os.ReadFile(filepath.Join(stagedPublished, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	checkUniqueIDs(t, page)
	exp, err := readExperiment(stagedPublished)
	if err != nil {
		t.Fatal(err)
	}
	stages, err := readStages(stagedPublished, job, exp)
	if err != nil {
		t.Fatal(err)
	}
	se, err := stagedEvidence(exp, job, stages)
	if err != nil {
		t.Fatal(err)
	}
	var arms []string
	for _, g := range se.Groups {
		arms = append(arms, fmt.Sprintf("%s %d %v %v", g.ID, g.Agents, round4(g.Landed), g.Words))
	}
	if got := strings.Join(arms, "; "); got != "recipe 16 0.8799 0; scrambled 16 0.8027 0; none 8 0.8555 0.125" {
		t.Errorf("groups: %s", got)
	}
	r4 := func(iv [2]float64) [2]float64 { return [2]float64{round4(iv[0]), round4(iv[1])} }
	var pairs []string
	for _, p := range se.Pairs {
		pairs = append(pairs, fmt.Sprintf("%s: landed %v %v %v, words %v %v %v", p.Name, round4(p.Landed.Difference), r4(p.Landed.Interval95), r4(p.Landed.Interval90),
			round4(p.Words.Difference), r4(p.Words.Interval95), r4(p.Words.Interval90)))
	}
	want := []string{
		"recipe minus scrambled: landed 0.0771 [0.0283 0.126] [0.0361 0.1182], words 0 [0 0] [0 0]",
		"recipe minus none: landed 0.0244 [-0.0146 0.0645] [-0.0088 0.0586], words -0.125 [-0.375 0] [-0.375 0]",
		"scrambled minus none: landed -0.0527 [-0.1104 0.0059] [-0.1016 -0.0039], words -0.125 [-0.375 0] [-0.375 0]",
	}
	if strings.Join(pairs, "\n") != strings.Join(want, "\n") {
		t.Errorf("pairs:\n%s\nwant:\n%s", strings.Join(pairs, "\n"), strings.Join(want, "\n"))
	}
	if se.Outcome != outcomeOrder || !se.LandedRead {
		t.Errorf("outcome %s, landings read %v", se.Outcome, se.LandedRead)
	}
	if math.Abs(se.Cost.TotalUSD-6.2519) > 1e-9 || se.Cost.Calls != 478 {
		t.Errorf("cost %+v", se.Cost)
	}
	if !strings.Contains(string(page), `href="https://plimsollmark.github.io/plimsoll/"`) {
		t.Error("the page lost its link home")
	}
}

// What the page says is held to the evidence: a claim the evidence does not bear stops the
// render, and a changed rule or a changed number refuses -verify.
func TestStagedPageRefusesWhatTheFilesDoNotSay(t *testing.T) {
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	exp, err := readExperiment(stagedPublished)
	if err != nil {
		t.Fatal(err)
	}
	stages, err := readStages(stagedPublished, job, exp)
	if err != nil {
		t.Fatal(err)
	}
	se, err := stagedEvidence(exp, job, stages)
	if err != nil {
		t.Fatal(err)
	}
	other := *se
	other.Outcome = outcomeUnclear
	if _, err := renderStagedPage(exp, job, &other, stages); err == nil || !strings.Contains(err.Error(), "the page says") {
		t.Errorf("a page whose outcome the prose contradicts rendered: %v", err)
	}

	// A copy of the page whose rule resamples with another seed: its intervals move, and the
	// published evidence.json no longer matches.
	dir := t.TempDir()
	copyTree(t, stagedPublished, dir)
	raw, err := os.ReadFile(filepath.Join(dir, experimentName))
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(raw), `"seed": 20261106`, `"seed": 20261107`, 1)
	if changed == string(raw) {
		t.Fatal("experiment.json no longer names the seed this test changes")
	}
	if err := os.WriteFile(filepath.Join(dir, experimentName), []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyStaged(dir, job); err == nil || !strings.Contains(err.Error(), "evidence.json") {
		t.Errorf("a changed resampling seed verified: %v", err)
	}
	renamed := strings.Replace(string(raw), `"name": "WORDS ONLY"`, `"name": "PLAN FOLLOWED"`, 1)
	if err := os.WriteFile(filepath.Join(dir, experimentName), []byte(renamed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyStaged(dir, job); err == nil || !strings.Contains(err.Error(), "decides between") {
		t.Errorf("a rule with an outcome this program does not decide verified: %v", err)
	}
}

// An agent's answer is escaped before its markdown is kept: nothing a model wrote becomes markup.
func TestAnswersAreEscaped(t *testing.T) {
	got := string(mdBlock("**Used:** <script>alert(1)</script> `x<y`\n\n- a <b>list</b> item"))
	want := "<p><b>Used:</b> &lt;script&gt;alert(1)&lt;/script&gt; <code>x&lt;y</code></p><ul><li>a &lt;b&gt;list&lt;/b&gt; item</li></ul>"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// stagedCopy copies the published page into a temporary directory, lets edit change one stage's
// transcripts, and writes them back.
func stagedCopy(t *testing.T, stage string, edit func([]Transcript) []Transcript) string {
	t.Helper()
	dir := t.TempDir()
	copyTree(t, stagedPublished, dir)
	sd := filepath.Join(dir, stagesDir, stage)
	ts, err := readTranscripts(sd)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTranscripts(filepath.Join(sd, transcriptsName), edit(ts)); err != nil {
		t.Fatal(err)
	}
	return dir
}

// renderThenVerify is what someone hiding an edit would do: render the edited copy again, so its
// evidence.json, agents.json and page agree with it, then verify.
func renderThenVerify(dir string, job *Job) error {
	if err := renderStaged(dir, job); err != nil {
		return err
	}
	return verifyStaged(dir, job)
}

// squeeze-recipe-17: an agent whose transcript is left out is refused, even with its run.json entry
// removed too and the page rendered again, since the signed bundle still grades it and its group
// falls short of the stage's build size.
func TestStagedRefusesAMissingTranscript(t *testing.T) {
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := stagedCopy(t, "recipe", func(ts []Transcript) []Transcript {
		return slices.DeleteFunc(ts, func(x Transcript) bool { return x.Group == "recipe" && x.N == 12 })
	})
	if err := renderThenVerify(dir, job); err == nil || !strings.Contains(err.Error(), "easy.recipe.12") {
		t.Errorf("a page with easy.recipe.12's transcript removed: %v", err)
	}
	runPath := filepath.Join(dir, stagesDir, "recipe", "run.json")
	raw, err := os.ReadFile(runPath)
	if err != nil {
		t.Fatal(err)
	}
	var rf map[string]any
	if err := json.Unmarshal(raw, &rf); err != nil {
		t.Fatal(err)
	}
	built := rf["built"].([]any)
	kept := slices.DeleteFunc(slices.Clone(built), func(b any) bool {
		m := b.(map[string]any)
		return m["group"] == "recipe" && m["n"] == 12.0
	})
	if len(kept) != len(built)-1 {
		t.Fatal("run.json has no easy.recipe.12 entry to remove")
	}
	rf["built"] = kept
	out, err := json.MarshalIndent(rf, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runPath, out, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := renderThenVerify(dir, job); err == nil || !strings.Contains(err.Error(), "easy.recipe.12") {
		t.Errorf("a page with easy.recipe.12's transcript and run.json entry removed: %v", err)
	}
}

// squeeze-recipe-18: a transcript whose controller text was edited, its declared digest kept, is
// refused: the text read for the words measure and the generator checks must be the graded one.
func TestStagedRefusesAnEditedControllerText(t *testing.T) {
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := stagedCopy(t, "recipe", func(ts []Transcript) []Transcript {
		for i := range ts {
			if ts[i].Group == "recipe" && ts[i].N == 3 {
				ts[i].Controller += "\nconst jitter = Math.random();\n"
			}
		}
		return ts
	})
	if err := renderThenVerify(dir, job); err == nil || !strings.Contains(err.Error(), "easy.recipe.3") || !strings.Contains(err.Error(), "controller text") {
		t.Errorf("a page with easy.recipe.3's controller text edited, its digest kept: %v", err)
	}
}

// squeeze-recipe-23: a transcript whose session differs from the design's for its group (another
// brief, another system prompt, another after-session question, another recipe) is refused, each
// on its own, even with the page rendered again.
func TestStagedRefusesASessionOutsideTheDesign(t *testing.T) {
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		edit func(*Transcript)
		want string
	}{
		{"brief", func(x *Transcript) {
			x.Prompt = strings.Replace(x.Prompt, "Build controller.js following the recipe.", "Ignore the recipe.", 1)
		}, "brief"},
		{"system prompt", func(x *Transcript) { x.System += " Take your time." }, "system prompt"},
		{"question", func(x *Transcript) { x.Question = afterQuestion("") }, "after-session question"},
		{"recipe", func(x *Transcript) { x.Recipe = job.Courses[0].Loops[0].Recipe }, "recipe"},
	} {
		dir := stagedCopy(t, "recipe", func(ts []Transcript) []Transcript {
			for i := range ts {
				if ts[i].Group == "scrambled" && ts[i].N == 5 {
					c.edit(&ts[i])
				}
			}
			return ts
		})
		if err := renderThenVerify(dir, job); err == nil || !strings.Contains(err.Error(), "easy.scrambled.5") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s changed in easy.scrambled.5's transcript: %v", c.name, err)
		}
	}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// publishedPage builds the page's view of the published files, as both templates see it.
func publishedPage(t *testing.T) stagedPage {
	t.Helper()
	job, err := loadJob(filepath.Join("jobs", "recipe-scramble-easy.json"))
	if err != nil {
		t.Fatal(err)
	}
	exp, err := readExperiment(stagedPublished)
	if err != nil {
		t.Fatal(err)
	}
	stages, err := readStages(stagedPublished, job, exp)
	if err != nil {
		t.Fatal(err)
	}
	se, err := stagedEvidence(exp, job, stages)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newStagedPage(exp, job, se, stages)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The method page is written and checked beside index.html: it links home, uses no ID twice,
// labels its one unregistered number exploratory, and names nobody.
func TestMethodPagePublished(t *testing.T) {
	page, err := os.ReadFile(filepath.Join(stagedPublished, methodPage))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, m := range regexp.MustCompile(`\sid="([^"]+)"`).FindAllSubmatch(page, -1) {
		seen[string(m[1])]++
	}
	if len(seen) < 8 {
		t.Fatalf("found only %d IDs on the method page; the pattern no longer matches it", len(seen))
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("the method page uses the ID %q %d times", id, n)
		}
	}
	for _, want := range []string{`href="https://plimsollmark.github.io/plimsoll/"`, "EXPLORATORY", `href="index.html"`} {
		if !strings.Contains(string(page), want) {
			t.Errorf("the method page lacks %q", want)
		}
	}
	index, err := os.ReadFile(filepath.Join(stagedPublished, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), `href="method.html"`) {
		t.Error("the results page does not link the method page")
	}
	for _, page := range [][]byte{page, index} {
		for _, no := range []string{"interval95\">", "prefers-color-scheme"} {
			if strings.Contains(string(page), no) {
				t.Errorf("a page holds %q", no)
			}
		}
	}
}

// The recipe strips are the honest recipe cut at its semicolons, one strip an item, and every
// scrambled word is tagged with the item it came from, so the figure can be read back to the
// recipe word for word.
func TestRecipeStripsAndScrambledWords(t *testing.T) {
	p := publishedPage(t)
	strips, err := p.HonestStrips()
	if err != nil {
		t.Fatal(err)
	}
	items, _ := courseItems(p.Course)
	if len(strips) != len(items.Items) {
		t.Fatalf("%d strips, %d items", len(strips), len(items.Items))
	}
	r, _ := p.Group("recipe")
	var joined []string
	for i, s := range strips {
		if s.Item != i+1 {
			t.Errorf("strip %d is numbered %d", i, s.Item)
		}
		joined = append(joined, s.Text)
	}
	if strings.Join(joined, " ") != r.Recipe {
		t.Errorf("the strips do not join back into the recipe: %q", strings.Join(joined, " "))
	}
	words, err := p.ScrambledWords()
	if err != nil {
		t.Fatal(err)
	}
	s, _ := p.Group("scrambled")
	var back []string
	perItem := map[int]int{}
	for _, w := range words {
		back = append(back, w.Word)
		perItem[w.Item]++
	}
	if strings.Join(back, " ") != s.Recipe {
		t.Errorf("the tagged words do not join back into the scrambled recipe")
	}
	for _, st := range strips {
		if perItem[st.Item] != len(strings.Fields(st.Text)) {
			t.Errorf("item %d has %d words in the recipe and %d tagged in the scrambled one", st.Item, len(strings.Fields(st.Text)), perItem[st.Item])
		}
	}
}

// The flight grid draws every agent and every sealed flight, each row's runs land exactly the
// agent's score, and the column counts sum to the landings of the whole run.
func TestFlightGridMatchesTheScores(t *testing.T) {
	p := publishedPage(t)
	g, err := p.Grid()
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Rows) != len(p.Ev.Agents) || len(g.Columns) != p.Ev.FreshCount {
		t.Fatalf("%d rows and %d columns for %d agents and %d flights", len(g.Rows), len(g.Columns), len(p.Ev.Agents), p.Ev.FreshCount)
	}
	total, byColumn := 0, 0
	for _, r := range g.Rows {
		w := 0.0
		for _, run := range r.Runs {
			w += run.W
		}
		if int(w/g.CellW+0.5) != r.Agent.Fresh {
			t.Errorf("%s: runs cover %.0f cells, score %d", r.Agent.ID, w/g.CellW, r.Agent.Fresh)
		}
		total += r.Agent.Fresh
	}
	for _, c := range g.Columns {
		byColumn += c.Landed
	}
	if total != byColumn {
		t.Errorf("rows land %d flights, columns %d", total, byColumn)
	}
	fly, err := p.Flights()
	if err != nil {
		t.Fatal(err)
	}
	if len(fly.Tracks) != 3 || len(fly.Geo.Gates) != 3 || fly.Geo.Opening != 60 {
		t.Errorf("flights: %d tracks, %d gates, opening %v cm", len(fly.Tracks), len(fly.Geo.Gates), fly.Geo.Opening)
	}
}

// The exact permutation count agrees with enumerating every deal on small pools.
func TestPermutationCountMatchesEnumeration(t *testing.T) {
	cases := []struct{ treat, base []int }{
		{[]int{60, 58, 57, 55}, []int{52, 50, 58, 44, 49}},
		{[]int{1, 1, 1}, []int{0, 0, 0, 1}},
		{[]int{64, 64}, []int{64, 64, 64}},
		{[]int{5, 9, 2, 7, 7}, []int{3, 8, 1, 6}},
	}
	for _, c := range cases {
		extreme, total, observed := permutationCount(c.treat, c.base)
		pool := append(append([]int{}, c.treat...), c.base...)
		m, P := len(c.treat), len(pool)
		S, T := 0, 0
		for _, x := range pool {
			S += x
		}
		for _, x := range c.treat {
			T += x
		}
		d0 := abs(T*P - S*m)
		wantExtreme, wantTotal := 0, 0
		for mask := 0; mask < 1<<P; mask++ {
			if popcount(mask) != m {
				continue
			}
			wantTotal++
			sum := 0
			for i := 0; i < P; i++ {
				if mask&(1<<i) != 0 {
					sum += pool[i]
				}
			}
			if abs(sum*P-S*m) >= d0 {
				wantExtreme++
			}
		}
		if extreme != wantExtreme || total != wantTotal {
			t.Errorf("%v vs %v: %d of %d deals, enumeration %d of %d", c.treat, c.base, extreme, total, wantExtreme, wantTotal)
		}
		if want := float64(T)/float64(m) - float64(S-T)/float64(len(c.base)); math.Abs(observed-want) > 1e-12 {
			t.Errorf("observed %v, want %v", observed, want)
		}
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func popcount(x int) int {
	n := 0
	for ; x != 0; x &= x - 1 {
		n++
	}
	return n
}

// The method page's practice-budget sentence and the course figure's caption are written from
// the data: the agents at the fly-call cap are the ones the evidence says, and the caption
// says all landed only when every recorded flight did (squeeze-recipe-31 and -33).
func TestPracticeCapAndCourseCaptionAreComputed(t *testing.T) {
	p := publishedPage(t)
	capped := p.FlyCapped()
	for _, a := range p.Ev.Agents {
		at := false
		for _, c := range capped {
			at = at || c.ID == a.ID
		}
		if at != (a.FlyCalls >= p.Job.Rebuild.FlyCalls) {
			t.Errorf("agent %s: at the cap %v, fly calls %d of %d", a.ID, at, a.FlyCalls, p.Job.Rebuild.FlyCalls)
		}
	}
	if len(capped) == 0 {
		t.Error("no agent at the fly-call cap: the sentence about the cap has nothing to say")
	}
	page, err := os.ReadFile(filepath.Join(stagedPublished, "method.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range capped {
		if !strings.Contains(string(page), "<code>"+a.ID+"</code>") {
			t.Errorf("the method page does not name %s, which used every fly call", a.ID)
		}
	}
	fig, err := p.Flights()
	if err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(filepath.Join(stagedPublished, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Contains(string(index), "of these landed; what differs"); got != fig.AllLanded() {
		t.Errorf("caption says all landed: %v; every recorded flight landed: %v", got, fig.AllLanded())
	}
	fig.Tracks[0].Landed = false
	if fig.AllLanded() {
		t.Error("AllLanded stays true when a recorded flight failed")
	}
}
