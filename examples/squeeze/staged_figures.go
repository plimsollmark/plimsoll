package main

// The staged page's pictures, and the method page beside it. Everything here is drawn from the
// stages' files through the template: the groups and what each was handed, the course with one
// recorded flight a group, the recipe cut into its items beside the scrambled words, every fresh
// flight of every agent, and the one exploratory number the method page states (an exact
// permutation test, labeled there as not registered).

import (
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed method.html
var methodTemplate string

//go:embed staged.css
var stagedCSS string

// CSS is the style sheet both pages share.
func (p stagedPage) CSS() template.CSS { return template.CSS(stagedCSS) }

// ScrambleSeed is the seed the scrambled recipe's words were shuffled with.
func (p stagedPage) ScrambleSeed() uint64 { return scrambleSeed }

// seq is 0 to n-1, for drawing one mark an agent.
func seq(n int) []int {
	out := make([]int, max(n, 0))
	for i := range out {
		out[i] = i
	}
	return out
}

// --- the recipe cut into its items -----------------------------------------------------------

// RecipeStrip is one item of the honest recipe: its number, from 1, and its words as written.
type RecipeStrip struct {
	Item int
	Text string
}

// TaggedWord is one word of the scrambled recipe and the item of the honest recipe it came from.
type TaggedWord struct {
	Word string
	Item int
}

// honestWords tags each word of the honest recipe with its item: items are separated by a word
// ending in a semicolon, and the count must be the course's item count.
func (p stagedPage) honestWords() ([]TaggedWord, error) {
	g, err := p.Group("recipe")
	if err != nil {
		return nil, err
	}
	l, ok := courseItems(p.Course)
	if !ok {
		return nil, errors.New("the course lists no recipe items")
	}
	var out []TaggedWord
	item := 1
	for _, w := range strings.Fields(g.Recipe) {
		out = append(out, TaggedWord{Word: w, Item: item})
		if strings.HasSuffix(w, ";") {
			item++
		}
	}
	if item != len(l.Items) {
		return nil, fmt.Errorf("the recipe has %d items separated by semicolons; the course lists %d", item, len(l.Items))
	}
	return out, nil
}

// HonestStrips is the honest recipe cut at its semicolons: one strip an item, numbered.
func (p stagedPage) HonestStrips() ([]RecipeStrip, error) {
	words, err := p.honestWords()
	if err != nil {
		return nil, err
	}
	var out []RecipeStrip
	for _, w := range words {
		if len(out) == 0 || out[len(out)-1].Item != w.Item {
			out = append(out, RecipeStrip{Item: w.Item})
		}
		s := &out[len(out)-1]
		if s.Text != "" {
			s.Text += " "
		}
		s.Text += w.Word
	}
	return out, nil
}

// ScrambledWords is the scrambled recipe word by word, each tagged with the honest item it came
// from: the same words, so every word finds exactly one unused honest word spelled the same.
func (p stagedPage) ScrambledWords() ([]TaggedWord, error) {
	honest, err := p.honestWords()
	if err != nil {
		return nil, err
	}
	g, err := p.Group("scrambled")
	if err != nil {
		return nil, err
	}
	used := make([]bool, len(honest))
	var out []TaggedWord
	for _, w := range strings.Fields(g.Recipe) {
		found := false
		for i, h := range honest {
			if !used[i] && h.Word == w {
				used[i], found = true, true
				out = append(out, TaggedWord{Word: w, Item: h.Item})
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("the scrambled recipe's word %q is not a word of the honest recipe", w)
		}
	}
	if len(out) != len(honest) {
		return nil, fmt.Errorf("the scrambled recipe has %d words, the honest one %d", len(out), len(honest))
	}
	return out, nil
}

// --- the course, and one recorded flight a group ---------------------------------------------

// courseGeometry is the course's fixed geometry in centimeters, read from the course file the
// grading runs fly, so the picture cannot drift from the simulator.
type courseGeometry struct {
	Takeoff, Pad [3]float64
	Gates        [][3]float64
	Opening      float64
	MinX, MaxX   float64
	MinZ, MaxZ   float64
	Height       float64
}

var (
	geomTakeoff = regexp.MustCompile(`TAKEOFF = v\(([-\d.]+), ([-\d.]+), ([-\d.]+)\)`)
	geomPad     = regexp.MustCompile(`PAD = Object\.freeze\(\{ centre: v\(([-\d.]+), ([-\d.]+), ([-\d.]+)\)`)
	geomGate    = regexp.MustCompile(`centre: v\(([-\d.]+), ([-\d.]+), ([-\d.]+)\), normal`)
	geomOpening = regexp.MustCompile(`gateOpening: ([\d.]+)`)
	geomRoom    = regexp.MustCompile(`room: Object\.freeze\(\{ minX: ([-\d.]+), maxX: ([-\d.]+), minZ: ([-\d.]+), maxZ: ([-\d.]+), height: ([-\d.]+) \}\)`)
)

func courseGeometryOf(course string) (courseGeometry, error) {
	src, err := courseFS.ReadFile("course/task-" + course + ".mjs")
	if err != nil {
		return courseGeometry{}, err
	}
	s := string(src)
	cm := func(m string) float64 {
		f, _ := strconv.ParseFloat(m, 64)
		return math.Round(f * 100)
	}
	v := func(m []string) [3]float64 { return [3]float64{cm(m[1]), cm(m[2]), cm(m[3])} }
	t, pd, op, rm := geomTakeoff.FindStringSubmatch(s), geomPad.FindStringSubmatch(s), geomOpening.FindStringSubmatch(s), geomRoom.FindStringSubmatch(s)
	gates := geomGate.FindAllStringSubmatch(s, -1)
	if t == nil || pd == nil || op == nil || rm == nil || len(gates) == 0 {
		return courseGeometry{}, fmt.Errorf("course %s: its file no longer states the geometry this page draws", course)
	}
	g := courseGeometry{Takeoff: v(t), Pad: v(pd), Opening: cm(op[1]), MinX: cm(rm[1]), MaxX: cm(rm[2]), MinZ: cm(rm[3]), MaxZ: cm(rm[4]), Height: cm(rm[5])}
	for _, m := range gates {
		g.Gates = append(g.Gates, v(m))
	}
	return g, nil
}

// TrackPath is one recorded flight drawn: its path from above and from the side.
type TrackPath struct {
	Group   string
	Seed    uint32
	Landed  bool
	End     string
	Seconds float64
	Top     string // SVG path data, the room from above (x and z)
	Side    string // the room from the side (x and height)
	TopX    float64
	TopY    float64
	SideX   float64
	SideY   float64
}

// FlightFigure is the course from above and from the side, with one recorded fresh flight a
// group. S is the top view's size; the side view is S wide and SideH tall; M the margin.
type FlightFigure struct {
	Geo     courseGeometry
	S, M    float64
	SideH   float64
	scale   float64
	Tracks  []TrackPath
	GridXZ  []float64 // grid lines, in centimeters from the room's center
	GridY   []float64
	Opening float64
}

// TX, TZ and TY place a centimeter on the drawing: x and z in the top view, x and height in the
// side view.
func (f FlightFigure) TX(cm float64) float64 { return round1(f.M + (cm-f.Geo.MinX)*f.scale) }
func (f FlightFigure) TZ(cm float64) float64 { return round1(f.M + (cm-f.Geo.MinZ)*f.scale) }
func (f FlightFigure) TY(cm float64) float64 { return round1(f.SideH - f.M - cm*f.scale) }

// Half is half the gate opening, in centimeters.
func (f FlightFigure) Half() float64 { return f.Geo.Opening / 2 }

// PadR is the landing pad's drawn radius.
func (f FlightFigure) PadR() float64 { return round1(15 * f.scale * 6) }

// Flights draws the course and every stage's recorded fresh flight, one a group, built by the
// course's groups in order. Every recorded flight must be the same sealed flight (the same seed),
// so the picture compares the three controllers on one flight.
func (p stagedPage) Flights() (*FlightFigure, error) {
	geo, err := courseGeometryOf(p.Course.ID)
	if err != nil {
		return nil, err
	}
	f := &FlightFigure{Geo: geo, S: 440, M: 34, Opening: geo.Opening}
	f.scale = (f.S - 2*f.M) / (geo.MaxX - geo.MinX)
	f.SideH = 2*f.M + geo.Height*f.scale
	for c := -200.0; c <= 200; c += 100 {
		f.GridXZ = append(f.GridXZ, c)
	}
	for h := 100.0; h < geo.Height; h += 100 {
		f.GridY = append(f.GridY, h)
	}
	tracks := map[string]Track{}
	for _, st := range p.stages {
		for _, c := range st.ev.Courses {
			if c.ID != p.Course.ID {
				continue
			}
			for _, t := range c.Tracks {
				if t.Set != "fresh" {
					continue
				}
				if _, dup := tracks[t.Who]; dup {
					return nil, fmt.Errorf("group %s has two recorded fresh flights", t.Who)
				}
				tracks[t.Who] = t
			}
		}
	}
	var seed uint32
	for _, g := range p.Course.Groups {
		t, ok := tracks[g.ID]
		if !ok {
			return nil, fmt.Errorf("group %s has no recorded fresh flight", g.ID)
		}
		if seed == 0 {
			seed = t.Seed
		}
		if t.Seed != seed {
			return nil, fmt.Errorf("group %s's recorded flight is seed %d; the first group's is %d", g.ID, t.Seed, seed)
		}
		if len(t.XYZ) == 0 {
			return nil, fmt.Errorf("group %s's recorded flight has no positions", g.ID)
		}
		tp := TrackPath{Group: g.ID, Seed: t.Seed, Landed: t.Success, End: t.End, Seconds: t.Seconds}
		var top, side strings.Builder
		for i, xyz := range t.XYZ {
			cmd := "L"
			if i == 0 {
				cmd = "M"
			}
			x, y, z := float64(xyz[0]), float64(xyz[1]), float64(xyz[2])
			fmt.Fprintf(&top, "%s%.1f %.1f", cmd, f.TX(x), f.TZ(z))
			fmt.Fprintf(&side, "%s%.1f %.1f", cmd, f.TX(x), f.TY(y))
			tp.TopX, tp.TopY, tp.SideX, tp.SideY = f.TX(x), f.TZ(z), f.TX(x), f.TY(y)
		}
		tp.Top, tp.Side = top.String(), side.String()
		f.Tracks = append(f.Tracks, tp)
	}
	return f, nil
}

// --- every fresh flight of every agent -------------------------------------------------------

// GridRun is a run of consecutive landed flights in one agent's row.
type GridRun struct {
	X, W float64
}

// GridRow is one agent's fresh flights: its landed runs, drawn over a background of not landed.
type GridRow struct {
	Agent AgentScore
	Y     float64
	Runs  []GridRun
	Tip   string
}

// GridColumn is one sealed flight: how many controllers landed it.
type GridColumn struct {
	Flight int // from 1, in the sealed set's order
	Seed   uint32
	Landed int
	X, H   float64
	Tip    string
}

// GridBand is one group's rows.
type GridBand struct {
	Group  string
	Y0, Y1 float64
}

// FlightGrid is every agent's every fresh flight, a row an agent and a column a sealed flight,
// grouped by group and ordered within a group by landings.
type FlightGrid struct {
	Rows                []GridRow
	Columns             []GridColumn
	Bands               []GridBand
	CellW, CellH        float64
	Left, Right         float64 // room for the row labels and the scores
	Top                 float64 // room for the column bars
	BarH                float64
	W, H                float64
	Agents              int
	HardestFlight       GridColumn // the flight fewest controllers landed
	EasiestLanded       int        // controllers that landed the most-landed flight
	FlightsLandedByAll  int
	FlightsLandedByNone int
	FlightsBelowHalf    int
}

// Grid draws the flight grid from each agent's fresh_bits.
func (p stagedPage) Grid() (*FlightGrid, error) {
	n := p.Ev.FreshCount
	g := &FlightGrid{CellW: 10, CellH: 7, Left: 86, Right: 56, Top: 48, BarH: 36, Agents: len(p.Ev.Agents)}
	g.W = g.Left + float64(n)*g.CellW + g.Right
	landedBy := make([]int, n)
	y := g.Top
	for _, grp := range p.Course.Groups {
		agents := p.GroupAgents(grp.ID)
		if len(agents) == 0 {
			continue
		}
		sort.SliceStable(agents, func(i, j int) bool { return agents[i].Fresh > agents[j].Fresh })
		band := GridBand{Group: grp.ID, Y0: y}
		for _, a := range agents {
			if len(a.FreshBits) != n {
				return nil, fmt.Errorf("agent %s has %d fresh flight bits; the sealed set has %d flights", a.ID, len(a.FreshBits), n)
			}
			row := GridRow{Agent: a, Y: y, Tip: fmt.Sprintf("%s: %d of %d fresh flights landed, %d of %d practice", a.ID, a.Fresh, a.FreshTotal, a.Practice, a.PracticeTotal)}
			landed := 0
			for i := 0; i < n; {
				if a.FreshBits[i] != '1' {
					i++
					continue
				}
				j := i
				for j < n && a.FreshBits[j] == '1' {
					landedBy[j]++
					landed++
					j++
				}
				row.Runs = append(row.Runs, GridRun{X: g.Left + float64(i)*g.CellW, W: float64(j-i) * g.CellW})
				i = j
			}
			if landed != a.Fresh {
				return nil, fmt.Errorf("agent %s's fresh flight bits land %d flights; its score is %d", a.ID, landed, a.Fresh)
			}
			g.Rows = append(g.Rows, row)
			y += g.CellH
		}
		band.Y1 = y
		g.Bands = append(g.Bands, band)
		y += 8
	}
	g.H = y + 2
	seeds := p.freshSeeds
	if len(seeds) != n {
		return nil, fmt.Errorf("the sealed set lists %d seeds; the page states %d fresh flights", len(seeds), n)
	}
	hardest := -1
	for i := 0; i < n; i++ {
		c := GridColumn{Flight: i + 1, Seed: seeds[i], Landed: landedBy[i], X: g.Left + float64(i)*g.CellW}
		c.H = round1(g.BarH * float64(c.Landed) / float64(max(g.Agents, 1)))
		c.Tip = fmt.Sprintf("Flight %d of %d (seed %d): landed by %d of %d controllers", c.Flight, n, c.Seed, c.Landed, g.Agents)
		g.Columns = append(g.Columns, c)
		if hardest < 0 || c.Landed < g.Columns[hardest].Landed {
			hardest = i
		}
		g.EasiestLanded = max(g.EasiestLanded, c.Landed)
		switch {
		case c.Landed == g.Agents:
			g.FlightsLandedByAll++
		case c.Landed == 0:
			g.FlightsLandedByNone++
		}
		if 2*c.Landed < g.Agents {
			g.FlightsBelowHalf++
		}
	}
	g.HardestFlight = g.Columns[hardest]
	return g, nil
}

// --- the exploratory permutation test the method page states ---------------------------------

// PermTest is an exact permutation (shuffle) test of one pair's difference in mean fresh flights
// landed: of every way to deal the pooled agents into two groups of the observed sizes, the share
// whose difference is at least as far from zero as the observed one. It is not part of the
// registered rule; the method page labels it exploratory.
type PermTest struct {
	Pair     string
	Treat    string
	Base     string
	M, N     int     // agents in the treatment and base groups
	Observed float64 // the observed difference, in fresh flights (treatment mean minus base mean)
	Extreme  int     // deals at least as far from zero
	Total    int     // all deals: N+M choose M
	P        float64 // two-sided
}

// Permutation runs the exact test for a pair by name, counting deals with a dynamic program over
// subset size and summed landings (scores are whole flights of the same total).
func (p stagedPage) Permutation(name string) (PermTest, error) {
	pe, err := p.Pair(name)
	if err != nil {
		return PermTest{}, err
	}
	var treat, base []int
	for _, a := range p.Ev.Agents {
		if a.FreshTotal != p.Ev.FreshCount {
			return PermTest{}, fmt.Errorf("agent %s was graded on %d fresh flights, the set has %d", a.ID, a.FreshTotal, p.Ev.FreshCount)
		}
		switch a.Group {
		case pe.Treat:
			treat = append(treat, a.Fresh)
		case pe.Base:
			base = append(base, a.Fresh)
		}
	}
	t := PermTest{Pair: pe.Name, Treat: pe.Treat, Base: pe.Base, M: len(treat), N: len(base)}
	t.Extreme, t.Total, t.Observed = permutationCount(treat, base)
	t.P = float64(t.Extreme) / float64(t.Total)
	return t, nil
}

// permutationCount counts, over every M-subset of the pooled scores, those whose difference of
// means is at least as far from zero as the observed one, and returns the count, the number of
// subsets and the observed difference of means. With pool size P and treatment size M, a subset's
// difference of means is (sum*P - S*M)/(M*N) for S the pool's sum, so comparing sum*P - S*M to the
// observed value compares the differences exactly, in integers.
func permutationCount(treat, base []int) (extreme, total int, observed float64) {
	m, n := len(treat), len(base)
	pool := append(append([]int{}, treat...), base...)
	P := m + n
	S, T := 0, 0
	for _, x := range pool {
		S += x
	}
	for _, x := range treat {
		T += x
	}
	d0 := T*P - S*m
	if d0 < 0 {
		d0 = -d0
	}
	// ways[k][s]: subsets of size k summing to s, over the items seen so far.
	ways := make([][]int, m+1)
	for k := range ways {
		ways[k] = make([]int, S+1)
	}
	ways[0][0] = 1
	for _, x := range pool {
		for k := min(m, len(pool)); k >= 1; k-- {
			for s := S; s >= x; s-- {
				ways[k][s] += ways[k-1][s-x]
			}
		}
	}
	for s, w := range ways[m] {
		total += w
		d := s*P - S*m
		if d < 0 {
			d = -d
		}
		if d >= d0 {
			extreme += w
		}
	}
	observed = float64(T)/float64(m) - float64(S-T)/float64(n)
	return extreme, total, observed
}
