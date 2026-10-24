// Command fanout sends one job to every sandbox it is given and fans the answers in to one
// signed page: a picture of the Mandelbrot set cut into tiles, every tile computed twice, in
// two different rooms (a room is one daemon serving one provider at one isolation tier).
//
// The tile program (tile.js) uses only addition, multiplication and comparison on doubles,
// whose rounding JavaScript specifies, so conforming engines should print the same bytes for a tile:
// node in a container or a microVM, QuickJS in the wasm provider. Two rooms that disagree on
// a tile mean something is wrong, and the page says so.
//
// Each room is one plimsolld, reached through package placement as one pool. Every call is
// signed by a harness key made for the run into docs/examples/fanout/bundle.jsonl, and the
// page is rendered from the bundle and its unsigned run metadata: each signed request holds its tile's code, which
// says which tile it is, and each signed record states the provider and tier that ran it,
// which says which room it was. rooms.json says what each room is; run.json holds the run's
// start and end and any call that returned no record.
//
//	go run ./examples/fanout -daemons tmp/fanout/daemons.json   # run, then render
//	go run ./examples/fanout                                     # render from the published files
//	go run ./examples/fanout -verify                             # check them; writes nothing
//
// A daemons file maps a room's id to {"url", "token_file", "concurrency"}, or to {"skip": reason}. A room with no
// daemon, or whose daemon does not state the provider and tier rooms.json gives it, does
// not take part, and the page says why. The run's private key is never written.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/examples/internal/fanjob"
)

//go:embed tile.js
var tileSource string

//go:embed page.html
var pageSource string

// roomsFile is the job's size and the rooms it may run in.
type roomsFile struct {
	Grid  int           `json:"grid"` // tiles per side
	Size  int           `json:"size"` // pixels per tile side
	Rooms []fanjob.Room `json:"rooms"`
}

func main() {
	dir := flag.String("dir", filepath.Join("docs", "examples", "fanout"), "the published files: rooms.json in, everything else out")
	daemons := flag.String("daemons", "", "run the job on these daemons first (a JSON file of room id to url, token_file, concurrency)")
	verify := flag.Bool("verify", false, "check the published files and write nothing")
	flag.Parse()
	if err := realMain(*dir, *daemons, *verify); err != nil {
		fmt.Fprintln(os.Stderr, "fanout:", err)
		os.Exit(1)
	}
}

func realMain(dir, daemonsPath string, verify bool) error {
	var rf roomsFile
	if err := fanjob.ReadJSON(filepath.Join(dir, "rooms.json"), &rf); err != nil {
		return err
	}
	if err := rf.check(); err != nil {
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
		if err := fanjob.RunAndPublish(ctx, dir, rf.Rooms, ds, rf.job()); err != nil {
			return err
		}
	}
	m, err := load(dir, rf)
	if err != nil {
		return err
	}
	page, pic, err := render(m)
	if err != nil {
		return err
	}
	if verify {
		for name, want := range map[string][]byte{"index.html": page, "picture.png": pic} {
			got, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				return fmt.Errorf("%s is not what the signed bundle renders", name)
			}
		}
		fmt.Printf("verified: the bundle checks under harness.pub and the page and picture are what it renders\n")
		fmt.Printf("result: %d signed runs, %d of %d tiles agree, %d rooms ran\n", m.Runs, m.Agreed, len(m.Tiles), len(m.Rooms)-len(m.NotRun))
		return nil
	}
	for name, b := range map[string][]byte{"index.html": page, "picture.png": pic} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("page: %d signed runs, %d of %d tiles agree; %s\n", m.Runs, m.Agreed, len(m.Tiles), filepath.Join(dir, "index.html"))
	return nil
}

func (rf roomsFile) check() error {
	if rf.Grid < 1 || rf.Grid > 64 || rf.Size < 1 || rf.Size > 128 {
		return fmt.Errorf("rooms.json: grid %d and size %d must be 1 to 64 and 1 to 128", rf.Grid, rf.Size)
	}
	return fanjob.CheckRooms(rf.Rooms)
}

// mandelbrot is the job: one piece per tile, in rows, each tile's program its own snippet.
type mandelbrot struct{ grid, size int }

func (rf roomsFile) job() mandelbrot { return mandelbrot{rf.Grid, rf.Size} }

func (mandelbrot) Prefix() string { return "fanout" }

func (j mandelbrot) Pieces() [][2]int {
	out := make([][2]int, j.grid*j.grid)
	for i := range out {
		out[i] = [2]int{i % j.grid, i / j.grid}
	}
	return out
}

func (j mandelbrot) Program(p [2]int) string { return tileCode(j.grid, j.size, p[0], p[1]) }

// tileCode is the program for one tile; the published run is grid 16, size 32.
func tileCode(grid, size, tx, ty int) string {
	return strings.NewReplacer("__GRID__", strconv.Itoa(grid), "__SIZE__", strconv.Itoa(size),
		"__TX__", strconv.Itoa(tx), "__TY__", strconv.Itoa(ty)).Replace(tileSource)
}

// model is everything the page shows, recomputed from the published files.
type model struct {
	Grid, Size int
	Rooms      []roomView
	NotRun     map[string]string
	Tiles      []tileView
	Runs       int
	Agreed     int
	Tiers      int
	TwoEngines int // agreed tiles whose two runs used different JavaScript engines
	WithCloud  int // agreed tiles with a run in a cloud room
	Clouds     int // cloud rooms that ran
	Failures   []fanjob.Failure
	Started    time.Time
	Ended      time.Time
	Harness    string // the harness key's ID
	counts     [][]byte
}

type roomView struct {
	fanjob.RoomRun
	Color string
}

type tileView struct {
	X, Y   int
	Rooms  []string // in bundle order
	Ms     []int64
	Agree  bool
	Reason string // why it does not agree, when it does not
}

// load reads the published run through the engine, which verifies and attributes it, and
// then checks each tile: its two copies agree byte for byte and the answer is its tile's.
func load(dir string, rf roomsFile) (*model, error) {
	l, err := fanjob.Load(dir, rf.Rooms, rf.job())
	if err != nil {
		return nil, err
	}
	m := &model{Grid: rf.Grid, Size: rf.Size, NotRun: l.NotRun, Failures: l.Failures, Started: l.Started, Ended: l.Ended,
		Harness: l.Harness, Runs: l.Runs, Tiers: l.Tiers, Clouds: l.Clouds,
		Tiles: make([]tileView, len(l.Pieces)), counts: make([][]byte, len(l.Pieces))}
	engine, cloud := map[string]string{}, map[string]bool{}
	for _, r := range l.Rooms {
		m.Rooms = append(m.Rooms, roomView{RoomRun: r, Color: fanjob.TierColor[r.Tier]})
		engine[r.ID], cloud[r.ID] = r.Engine, r.Cloud
	}
	for i, p := range l.Pieces {
		t := &m.Tiles[i]
		t.X, t.Y, t.Rooms, t.Ms = p.P[0], p.P[1], p.Rooms, p.Ms
		if t.Reason = p.Disagreement(); t.Reason != "" {
			continue
		}
		c, err := parseTile(p.Outputs[0], t.X, t.Y, rf.Size)
		if err != nil {
			t.Reason = err.Error()
			continue
		}
		t.Agree, m.counts[i] = true, c
		m.Agreed++
		if engine[t.Rooms[0]] != engine[t.Rooms[1]] {
			m.TwoEngines++
		}
		if cloud[t.Rooms[0]] || cloud[t.Rooms[1]] {
			m.WithCloud++
		}
	}
	return m, nil
}

func parseTile(out []byte, tx, ty, size int) ([]byte, error) {
	var got struct {
		Tile   []int  `json:"tile"`
		Counts string `json:"counts"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		return nil, errors.New("the answer is not the tile's JSON")
	}
	if len(got.Tile) != 2 || got.Tile[0] != tx || got.Tile[1] != ty {
		return nil, errors.New("the answer names another tile")
	}
	c, err := hex.DecodeString(got.Counts)
	if err != nil || len(c) != size*size {
		return nil, errors.New("the answer's counts are malformed")
	}
	return c, nil
}

// picture paints the agreed tiles; a tile without agreement is left a flat red.
func picture(m *model) ([]byte, error) {
	w := m.Grid * m.Size
	img := image.NewRGBA(image.Rect(0, 0, w, w))
	for i, t := range m.Tiles {
		for j := 0; j < m.Size; j++ {
			for k := 0; k < m.Size; k++ {
				c := color.RGBA{0xe3, 0x49, 0x48, 0xff}
				if t.Agree {
					c = shade(m.counts[i][j*m.Size+k])
				}
				img.SetRGBA(t.X*m.Size+k, t.Y*m.Size+j, c)
			}
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// shade maps an iteration count to a colour: the set itself near black, the outside from
// the page's background through orange, darker the longer a point took to escape.
func shade(n byte) color.RGBA {
	if n == 255 {
		return color.RGBA{0x1a, 0x1f, 0x29, 0xff}
	}
	t := math.Sqrt(float64(n) / 64)
	if t > 1 {
		t = 1
	}
	lerp := func(a, b uint8) uint8 { return uint8(math.Round(float64(a) + (float64(b)-float64(a))*t)) }
	return color.RGBA{lerp(0xfa, 0xb3), lerp(0xf7, 0x40), lerp(0xf2, 0x0b), 0xff}
}

// tileMap is the grid of where each tile ran: each square split corner to corner, the
// upper triangle the first run's room, the lower the second's, coloured by tier.
func tileMap(m *model) template.HTML {
	const cell = 24
	side := m.Grid * cell
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-label="Where each tile's two runs happened, coloured by isolation tier">`, side, side)
	color := map[string]string{}
	label := map[string]string{}
	for _, r := range m.Rooms {
		color[r.ID], label[r.ID] = r.Color, r.Label
	}
	for _, t := range m.Tiles {
		x, y := t.X*cell, t.Y*cell
		title := fmt.Sprintf("tile %d,%d", t.X, t.Y)
		for i, id := range t.Rooms {
			title += fmt.Sprintf("; run %d: %s, %d ms", i+1, label[id], t.Ms[i])
		}
		if !t.Agree {
			title += "; " + t.Reason
		}
		fmt.Fprintf(&b, `<g class="t" data-rooms="%s"><title>%s</title>`, template.HTMLEscapeString(strings.Join(t.Rooms, " ")), template.HTMLEscapeString(title))
		a, c := "#e5e7eb", "#e5e7eb"
		if len(t.Rooms) > 0 {
			a = color[t.Rooms[0]]
		}
		if len(t.Rooms) > 1 {
			c = color[t.Rooms[1]]
		}
		fmt.Fprintf(&b, `<path d="M%d %dh%dL%d %dz" fill="%s"/>`, x+1, y+1, cell-2, x+1, y+cell-1, a)
		fmt.Fprintf(&b, `<path d="M%d %dv%dh-%dz" fill="%s"/>`, x+cell-1, y+1, cell-2, cell-2, c)
		if !t.Agree {
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" fill="none" stroke="#e34948" stroke-width="2"/>`, x+1, y+1, cell-2, cell-2)
		}
		b.WriteString(`</g>`)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func render(m *model) (page, pic []byte, err error) {
	pic, err = picture(m)
	if err != nil {
		return nil, nil, err
	}
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
		return nil, nil, err
	}
	total := 0.0
	ran := 0
	for _, r := range m.Rooms {
		total += r.Cost
		if r.Runs > 0 {
			ran++
		}
	}
	var b bytes.Buffer
	err = t.Execute(&b, struct {
		*model
		Map         template.HTML
		Cost        float64
		RoomsRun    int
		Pixels      int
		TierColor   map[string]string
		TierOrder   []string
		Disagreeing []tileView
	}{m, tileMap(m), total, ran, m.Grid * m.Size, fanjob.TierColor, []string{"process", "container", "kernel", "vm"}, slices.DeleteFunc(slices.Clone(m.Tiles), func(t tileView) bool { return t.Agree })})
	return b.Bytes(), pic, err
}
