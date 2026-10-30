package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
)

// RunFile is the run's own account of what the bundle cannot hold, written beside it unsigned:
// when the run started and ended, the fresh set's commitment as it was printed before any
// controller flew, the model and what it spent, each built rebuild's summary, the imported
// rebuilds that had no controller, and calls that came back without a record.
type RunFile struct {
	Job         string    `json:"job"`
	Started     time.Time `json:"started"`
	Sealed      time.Time `json:"sealed"`
	Ended       time.Time `json:"ended"`
	FreshSHA256 string    `json:"fresh_sha256"`
	// FreshGiven is true when the fresh set was an earlier run's, given with -fresh, not drawn
	// by this run: other runs have flown it.
	FreshGiven bool      `json:"fresh_given,omitempty"`
	Model      string    `json:"model,omitempty"`
	ModelBase  string    `json:"model_base,omitempty"`
	Usage      usage     `json:"usage"`
	Built      []Built   `json:"built"`
	Missing    []Missing `json:"missing"`
	Failures   []string  `json:"failures"`
}

// Missing is an imported rebuild that left no controller, as the hackathon recorded it.
type Missing struct {
	Course string `json:"course"`
	Group  string `json:"group"`
	N      int    `json:"n"`
	Why    string `json:"why"`
}

// live is one run against a daemon.
type live struct {
	job        *Job
	importRoot string
	daemon     string // the daemon's base URL
	token      string // its token, or "" for an open daemon
	model      *chat  // nil when the job builds nothing
	parallel   int
	given      givenFresh // the fresh set to fly, or none to draw one
	remote     *client.Remote
}

// unit is one controller to grade, and where it came from.
type unit struct {
	course string
	who    string // a group's ID, or the loop's ID for a loop's own controller
	n      string // the rebuild's number, or "loop"
	src    []byte
}

func (u unit) trace(purpose string) string {
	return fmt.Sprintf("sq.%s.%s.%s.%s", u.course, u.who, u.n, purpose)
}

// run makes the rebuilds, grades every controller and records the page's flights, signing
// every call into dir/bundle.jsonl with a key made for the run. dir is a staging directory.
func (l *live) run(ctx context.Context, dir string) error {
	privPEM, pubPEM, err := attest.GenerateKey()
	if err != nil {
		return err
	}
	key, err := attest.ParsePrivateKey(privPEM)
	if err != nil {
		return err
	}
	bundle, err := os.Create(filepath.Join(dir, "bundle.jsonl"))
	if err != nil {
		return err
	}
	defer bundle.Close()
	harness := attest.NewHarness(attest.NewSigner(key), bundle)
	opts := []client.Option{client.WithRecorder(harness)}
	if l.token != "" {
		opts = append(opts, client.WithToken(l.token))
	}
	if l.remote, err = client.New(l.daemon, opts...); err != nil {
		return err
	}

	rf := RunFile{Job: l.job.Name, Started: time.Now().UTC().Truncate(time.Second), Built: []Built{}, Missing: []Missing{}, Failures: []string{}}
	avoid := map[uint32]bool{}
	for _, c := range l.job.Courses {
		for _, s := range c.Practice {
			avoid[s] = true
		}
		for _, s := range smokeSeeds(c.ID) {
			avoid[s] = true
		}
	}
	var fresh SealedSet
	var freshFile []byte
	if l.given.path != "" {
		if fresh, freshFile, err = loadFresh(l.given, l.job.Fresh, avoid); err != nil {
			return err
		}
		rf.FreshGiven = true
	} else {
		if fresh, err = sealFresh(l.job.Fresh, avoid); err != nil {
			return err
		}
		freshFile = fresh.encode()
	}
	rf.FreshSHA256 = digest(freshFile)
	rf.Sealed = time.Now().UTC().Truncate(time.Second)
	if err := os.WriteFile(filepath.Join(dir, "fresh.json"), freshFile, 0o644); err != nil {
		return err
	}
	given := ""
	if rf.FreshGiven {
		given = " (given: an earlier run's set)"
	}
	fmt.Printf("sealed    | %d fresh flights, SHA-256 %s%s\n", len(fresh.Seeds), rf.FreshSHA256, given)
	for _, s := range fresh.Seeds {
		avoid[s] = true
	}

	var mu sync.Mutex
	var units []unit
	// Rebuilds: built here by the caller's model, or imported.
	for _, c := range l.job.Courses {
		for _, g := range c.Groups {
			recipe := ""
			if g.From != "" {
				lp, _ := c.loop(g.From)
				recipe = lp.Recipe
			}
			for i, path := range g.Import {
				src, err := os.ReadFile(filepath.Join(l.importRoot, path))
				if err != nil {
					rf.Missing = append(rf.Missing, Missing{Course: c.ID, Group: g.ID, N: i, Why: "no controller at " + path})
					continue
				}
				units = append(units, unit{course: c.ID, who: g.ID, n: strconv.Itoa(i), src: src})
			}
			var wg sync.WaitGroup
			sem := make(chan struct{}, l.parallel)
			for k := range g.Build {
				n := len(g.Import) + k
				spec := rebuildSpec{Course: c.ID, Group: g.ID, N: n, Recipe: recipe, Turns: l.job.Rebuild.Turns, FlightsPerFly: l.job.Rebuild.FlightsPerFly, Avoid: avoid}
				wg.Add(1)
				go func() {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					src, b, err := buildOne(ctx, l.model, l.remote, spec)
					mu.Lock()
					defer mu.Unlock()
					if err != nil {
						b.Problem = err.Error()
						rf.Failures = append(rf.Failures, spec.trace("build")+": "+err.Error())
					}
					rf.Built = append(rf.Built, b)
					fmt.Printf("rebuild   | %s: %d turns, %d fly calls, controller %v\n", spec.trace("build"), b.Turns, b.FlyCalls, src != nil)
					if src == nil {
						rf.Missing = append(rf.Missing, Missing{Course: c.ID, Group: g.ID, N: n, Why: "the rebuild left no controller.js"})
						return
					}
					units = append(units, unit{course: c.ID, who: g.ID, n: strconv.Itoa(n), src: src})
				}()
			}
			wg.Wait()
		}
		for _, lp := range c.Loops {
			if lp.Artifact == "" {
				continue
			}
			src, err := os.ReadFile(filepath.Join(l.importRoot, lp.Artifact))
			if err != nil {
				return fmt.Errorf("loop %s on the %s course: %w", lp.ID, c.ID, err)
			}
			units = append(units, unit{course: c.ID, who: lp.ID, n: "loop", src: src})
		}
	}
	slices.SortStableFunc(units, func(a, b unit) int { return compareUnits(a.course, a.who, a.n, b.course, b.who, b.n) })

	// Grading: two runs per controller, one for each sealed set, each in a sandbox of its own.
	practice := map[string][]byte{}
	for _, c := range l.job.Courses {
		practice[c.ID] = practiceSet(c).encode()
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, l.parallel)
	done := 0
	for _, u := range units {
		for _, set := range []string{"practice", "fresh"} {
			file := freshFile
			if set == "practice" {
				file = practice[u.course]
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				req, err := gradeRequest(u.course, u.src, set, file)
				if err == nil {
					err = again(ctx, func() error {
						_, err := l.remote.RunProject(client.NewTraceContext(ctx, u.trace(set)), req)
						return err
					})
				}
				mu.Lock()
				defer mu.Unlock()
				done++
				if err != nil {
					rf.Failures = append(rf.Failures, u.trace(set)+": "+err.Error())
					fmt.Printf("grade     | %s: %v\n", u.trace(set), err)
				}
				if done%16 == 0 || done == 2*len(units) {
					fmt.Printf("grade     | %d of %d grading runs\n", done, 2*len(units))
				}
			}()
		}
	}
	wg.Wait()

	// The page's flights: each loop's controller on the first practice flight and the first
	// fresh flight, and the first controller of each group on the first fresh flight.
	for _, c := range l.job.Courses {
		groupDone := map[string]bool{}
		for _, u := range units {
			if u.course != c.ID {
				continue
			}
			seeds := []uint32{c.Practice[0], fresh.Seeds[0]}
			if u.n != "loop" {
				if groupDone[u.who] {
					continue
				}
				groupDone[u.who] = true
				seeds = []uint32{fresh.Seeds[0]}
			}
			req, err := tracksRequest(c.ID, u.src, seeds)
			if err == nil {
				err = again(ctx, func() error {
					_, err := l.remote.RunProject(client.NewTraceContext(ctx, u.trace("tracks")), req)
					return err
				})
			}
			if err != nil {
				rf.Failures = append(rf.Failures, u.trace("tracks")+": "+err.Error())
			}
		}
	}

	if err := harness.Checkpoint(); err != nil {
		return err
	}
	if err := bundle.Sync(); err != nil {
		return err
	}
	rf.Ended = time.Now().UTC().Truncate(time.Second)
	if l.model != nil {
		rf.Model, rf.ModelBase, rf.Usage = l.model.model, l.model.base, l.model.used()
	}
	slices.SortFunc(rf.Built, func(a, b Built) int {
		return compareUnits(a.Course, a.Group, strconv.Itoa(a.N), b.Course, b.Group, strconv.Itoa(b.N))
	})
	slices.SortFunc(rf.Missing, func(a, b Missing) int {
		return compareUnits(a.Course, a.Group, strconv.Itoa(a.N), b.Course, b.Group, strconv.Itoa(b.N))
	})
	slices.Sort(rf.Failures)
	if err := os.WriteFile(filepath.Join(dir, "harness.pub"), pubPEM, 0o644); err != nil {
		return err
	}
	if len(rf.Failures) > 0 {
		fmt.Printf("failures  | %d calls came back without a record; run.json lists them\n", len(rf.Failures))
	}
	return writeJSON(filepath.Join(dir, "run.json"), rf)
}

// againTries and againWait bound how a grading or recording run is tried again after an
// error that came back without a record: on a loaded machine the docker provider's readiness
// check can outlast a run's wait for it (2026-10-27, at a load average of 65 on 24 cores: 67 of
// 96 grading runs lost, 47 to "docker preflight is already in progress"). Trying such a run again is safe even if it ran: it holds
// no state, and only an answered run, with its record, enters the bundle.
const (
	againTries = 6
	againWait  = 15 * time.Second
)

func again(ctx context.Context, send func() error) error {
	var err error
	for try := 1; try <= againTries; try++ {
		if err = send(); err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if try < againTries {
			select {
			case <-time.After(time.Duration(try) * againWait):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return err
}

// compareUnits orders controllers by course, then who, then number, loops first.
func compareUnits(c1, w1, n1, c2, w2, n2 string) int {
	if c1 != c2 {
		if c1 < c2 {
			return -1
		}
		return 1
	}
	if w1 != w2 {
		if w1 < w2 {
			return -1
		}
		return 1
	}
	if n1 == n2 {
		return 0
	}
	if n1 == "loop" {
		return -1
	}
	if n2 == "loop" {
		return 1
	}
	a, _ := strconv.Atoi(n1)
	b, _ := strconv.Atoi(n2)
	return a - b
}

// publish moves the staged files into dir, replacing what was there.
func publish(staging, dir string, names []string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, n := range names {
		if err := os.Rename(filepath.Join(staging, n), filepath.Join(dir, n)); err != nil {
			return err
		}
	}
	return nil
}

var errNoModel = errors.New("this job builds rebuilds with a model; give the model's key in the environment variable -key-env names (nothing is spent without one)")
