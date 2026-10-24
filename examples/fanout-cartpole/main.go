// Command fanout-cartpole grades a batch of cart-pole controllers by fanning the trials out
// to every sandbox it is given and fanning the answers in to one signed scoreboard: each
// candidate controller (a linear state-feedback law with its own pair of gains) tried from
// several starting angles, every trial run twice, in two different rooms (a room is one daemon
// serving one provider at one isolation tier). It is the shape of one batch of grading in
// training or testing a controller writer: many attempts, each tried, each recorded.
//
// The trial program (trial.js) uses only +, -, *, / and comparison on doubles, which IEEE 754
// rounds as specified, and fixed polynomials for sine and cosine, so conforming engines should print
// the same bytes for a trial. The candidates are a grid of gains made by hand, stable and
// unstable alike; no model wrote them.
//
//	go run ./examples/fanout-cartpole -daemons tmp/fanout/daemons.json   # run, then render
//	go run ./examples/fanout-cartpole                                     # render from the published files
//	go run ./examples/fanout-cartpole -verify                             # check them; writes nothing
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/examples/internal/fanjob"
)

//go:embed trial.js
var trialSource string

//go:embed page.html
var pageSource string

// batchFile is the batch: the gains each candidate takes (every angle gain with every spin
// gain), the starting angles each is tried from, and the rooms it may run in.
type batchFile struct {
	KP     []float64     `json:"kp"`     // force per radian of lean
	KD     []float64     `json:"kd"`     // force per radian per second of spin
	Theta0 []float64     `json:"theta0"` // starting angles, radians from upright
	Rooms  []fanjob.Room `json:"rooms"`
}

// The cart's position and speed gains, the same for every candidate (the accepted controller's).
const kx, kv = 1, 1

func main() {
	dir := flag.String("dir", filepath.Join("docs", "examples", "fanout-cartpole"), "the published files: rooms.json in, everything else out")
	daemons := flag.String("daemons", "", "run the batch on these daemons first (a JSON file of room id to url, token_file, concurrency)")
	verify := flag.Bool("verify", false, "check the published files and write nothing")
	flag.Parse()
	if err := realMain(*dir, *daemons, *verify); err != nil {
		fmt.Fprintln(os.Stderr, "fanout-cartpole:", err)
		os.Exit(1)
	}
}

func realMain(dir, daemonsPath string, verify bool) error {
	var bf batchFile
	if err := fanjob.ReadJSON(filepath.Join(dir, "rooms.json"), &bf); err != nil {
		return err
	}
	if err := bf.check(); err != nil {
		return err
	}
	if daemonsPath != "" {
		if verify {
			return errors.New("-verify checks published files; it does not run")
		}
		var ds map[string]fanjob.Daemon
		if err := fanjob.ReadJSON(daemonsPath, &ds); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
		defer cancel()
		if err := fanjob.RunAndPublish(ctx, dir, bf.Rooms, ds, bf); err != nil {
			return err
		}
	}
	m, err := load(dir, bf)
	if err != nil {
		return err
	}
	page, err := render(m)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "index.html")
	if verify {
		got, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, page) {
			return errors.New("index.html is not what the signed bundle renders")
		}
		fmt.Printf("verified: the bundle checks under harness.pub and the page is what it renders\n")
		fmt.Printf("result: %d signed runs, %d of %d trials agree, %d rooms ran\n", m.Runs, m.Agreed, m.Trials, m.RoomsRun)
		return nil
	}
	if err := os.WriteFile(path, page, 0o644); err != nil {
		return err
	}
	fmt.Printf("page: %d signed runs, %d of %d trials agree; %s\n", m.Runs, m.Agreed, m.Trials, path)
	return nil
}

func (bf batchFile) check() error {
	if len(bf.KP) < 1 || len(bf.KD) < 1 || len(bf.Theta0) < 1 || len(bf.KP)*len(bf.KD)*len(bf.Theta0) > 1024 {
		return errors.New("rooms.json: kp, kd and theta0 need at least one value each and at most 1024 trials in all")
	}
	return fanjob.CheckRooms(bf.Rooms)
}

// The job: one piece per trial, [candidate, starting angle], candidates in rows of spin gains.

func (batchFile) Prefix() string { return "cartpole" }

func (bf batchFile) Pieces() [][2]int {
	var out [][2]int
	for c := range len(bf.KP) * len(bf.KD) {
		for s := range bf.Theta0 {
			out = append(out, [2]int{c, s})
		}
	}
	return out
}

func (bf batchFile) gains(c int) (kp, kd float64) { return bf.KP[c/len(bf.KD)], bf.KD[c%len(bf.KD)] }

func (bf batchFile) Program(p [2]int) string {
	kp, kd := bf.gains(p[0])
	return strings.NewReplacer("__C__", strconv.Itoa(p[0]), "__S__", strconv.Itoa(p[1]),
		"__KP__", num(kp), "__KD__", num(kd), "__KX__", num(kx), "__KV__", num(kv), "__THETA0__", num(bf.Theta0[p[1]])).Replace(trialSource)
}

func num(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// model is everything the page shows, recomputed from the published files.
type model struct {
	Rooms      []roomView
	Cands      []candView
	Perfect    int // candidates balanced from every starting angle
	KP, KD     []string
	Theta0     []string
	Trials     int
	Runs       int
	RoomsRun   int
	Agreed     int
	Tiers      int
	TwoEngines int // agreed trials whose two runs used different JavaScript engines
	WithCloud  int // agreed trials with a run in a cloud room
	Clouds     int
	Upright    int // agreed trials that ended balanced
	Issues     []issue
	Failures   []fanjob.Failure
	NotRun     map[string]string
	Started    time.Time
	Ended      time.Time
	Harness    string
}

type roomView struct {
	fanjob.RoomRun
	Color string
}

// candView is one candidate controller on the scoreboard.
type candView struct {
	C       int
	KP, KD  string
	Upright int // starting angles it ended balanced from
	Steps   int // steps the pole stayed up, summed over its starting angles
	Agreed  int // of its trials, how many had two matching answers
	Fill    string
	Ink     string
}

type issue struct {
	C, S   int
	Reason string
}

type trialAnswer struct {
	Trial   []int  `json:"trial"`
	Steps   int    `json:"steps"`
	Upright bool   `json:"upright"`
	Hash    string `json:"hash"`
}

func load(dir string, bf batchFile) (*model, error) {
	l, err := fanjob.Load(dir, bf.Rooms, bf)
	if err != nil {
		return nil, err
	}
	m := &model{Runs: l.Runs, Tiers: l.Tiers, Clouds: l.Clouds, Failures: l.Failures, NotRun: l.NotRun,
		Started: l.Started, Ended: l.Ended, Harness: l.Harness, Trials: len(l.Pieces)}
	for _, v := range bf.KP {
		m.KP = append(m.KP, num(v))
	}
	for _, v := range bf.KD {
		m.KD = append(m.KD, num(v))
	}
	for _, v := range bf.Theta0 {
		m.Theta0 = append(m.Theta0, num(v))
	}
	engine, cloud := map[string]string{}, map[string]bool{}
	for _, r := range l.Rooms {
		m.Rooms = append(m.Rooms, roomView{RoomRun: r, Color: fanjob.TierColor[r.Tier]})
		engine[r.ID], cloud[r.ID] = r.Engine, r.Cloud
		if r.Runs > 0 {
			m.RoomsRun++
		}
	}
	m.Cands = make([]candView, len(bf.KP)*len(bf.KD))
	for c := range m.Cands {
		kp, kd := bf.gains(c)
		m.Cands[c] = candView{C: c, KP: num(kp), KD: num(kd)}
	}
	for _, p := range l.Pieces {
		c, s := p.P[0], p.P[1]
		reason := p.Disagreement()
		var a trialAnswer
		if reason == "" {
			if err := decodeStrict(p.Outputs[0], &a); err != nil || len(a.Trial) != 2 || a.Trial[0] != c || a.Trial[1] != s || a.Steps < 1 || a.Steps > 500 {
				reason = "the answer is not this trial's"
			}
		}
		if reason != "" {
			m.Issues = append(m.Issues, issue{C: c, S: s, Reason: reason})
			continue
		}
		m.Agreed++
		cv := &m.Cands[c]
		cv.Agreed++
		cv.Steps += a.Steps
		if a.Upright {
			cv.Upright++
			m.Upright++
		}
		if engine[p.Rooms[0]] != engine[p.Rooms[1]] {
			m.TwoEngines++
		}
		if cloud[p.Rooms[0]] || cloud[p.Rooms[1]] {
			m.WithCloud++
		}
	}
	for i := range m.Cands {
		m.Cands[i].Fill, m.Cands[i].Ink = scoreColor(m.Cands[i].Upright, len(bf.Theta0))
	}
	for _, c := range m.Cands {
		if c.Upright == len(bf.Theta0) {
			m.Perfect++
		}
	}
	return m, nil
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// scoreRamp is one teal ramp, light to dark as more starting angles end balanced (a
// sequential scale, distinct from the blue of the isolation tiers); the ink keeps contrast.
var scoreRamp = []string{"#eef3f2", "#cfe6e1", "#9bcfc5", "#5aa898", "#24715f"}

func scoreColor(up, of int) (fill, ink string) {
	i := up * (len(scoreRamp) - 1) / max(1, of)
	ink = "#1a1f29"
	if i >= 3 {
		ink = "#ffffff"
	}
	return scoreRamp[i], ink
}

// board is the scoreboard: one square per candidate, spin gain across, angle gain down.
func board(m *model) template.HTML {
	const cell, left, top = 64, 70, 44
	cols, rows := len(m.KD), len(m.KP)
	w, h := left+cols*cell+8, top+rows*cell+8
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-label="How many starting angles each candidate controller ended balanced from">`, w, h)
	fmt.Fprintf(&b, `<text x="%d" y="14" text-anchor="middle" font-size="13" fill="#4a5160">spin gain kd (newtons per radian per second)</text>`, left+cols*cell/2)
	for j, kd := range m.KD {
		fmt.Fprintf(&b, `<text x="%d" y="34" text-anchor="middle" font-size="13" fill="#4a5160">%s</text>`, left+j*cell+cell/2, kd)
	}
	fmt.Fprintf(&b, `<text transform="translate(14 %d) rotate(-90)" text-anchor="middle" font-size="13" fill="#4a5160">angle gain kp (N per radian)</text>`, top+rows*cell/2)
	for i, kp := range m.KP {
		fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="end" font-size="13" fill="#4a5160">%s</text>`, left-8, top+i*cell+cell/2+4, kp)
	}
	for _, c := range m.Cands {
		i, j := c.C/cols, c.C%cols
		x, y := left+j*cell, top+i*cell
		title := fmt.Sprintf("kp %s, kd %s: balanced from %d of %d starting angles; the pole stayed up %d steps in all", c.KP, c.KD, c.Upright, len(m.Theta0), c.Steps)
		if c.Agreed < len(m.Theta0) {
			title += fmt.Sprintf("; only %d of its %d trials had two matching answers", c.Agreed, len(m.Theta0))
		}
		fmt.Fprintf(&b, `<g><title>%s</title><rect x="%d" y="%d" width="%d" height="%d" rx="6" fill="%s"/>`, template.HTMLEscapeString(title), x+2, y+2, cell-4, cell-4, c.Fill)
		fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="middle" font-size="15" font-weight="600" fill="%s">%d/%d</text>`, x+cell/2, y+cell/2+5, c.Ink, c.Upright, len(m.Theta0))
		if c.Agreed < len(m.Theta0) {
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="6" fill="none" stroke="#e34948" stroke-width="2.5"/>`, x+2, y+2, cell-4, cell-4)
		}
		b.WriteString(`</g>`)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func render(m *model) ([]byte, error) {
	fns := template.FuncMap{
		"usd":     func(f float64) string { return fmt.Sprintf("$%.4f", f) },
		"seconds": func(ms int64) string { return strconv.FormatFloat(float64(ms)/1000, 'f', 2, 64) + " s" },
		"minutes": func(a, b time.Time) string {
			d := b.Sub(a).Round(time.Second)
			return fmt.Sprintf("%d min %d s", int(d.Minutes()), int(d.Seconds())%60)
		},
		"date": func(t time.Time) string { return t.Format("2006-01-02 15:04 UTC") },
	}
	t, err := template.New("page").Funcs(fns).Parse(pageSource)
	if err != nil {
		return nil, err
	}
	total := 0.0
	for _, r := range m.Rooms {
		total += r.Cost
	}
	var b bytes.Buffer
	err = t.Execute(&b, struct {
		*model
		Board     template.HTML
		Cost      float64
		NCands    int
		Ramp      []string
		TierColor map[string]string
		TierOrder []string
	}{m, board(m), total, len(m.Cands), scoreRamp, fanjob.TierColor, []string{"process", "container", "kernel", "vm"}})
	return b.Bytes(), err
}
