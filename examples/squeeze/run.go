package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
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
	// FreshGiven is true when the fresh set was given with -fresh, not drawn by this run: an
	// earlier run's, which other runs have flown, or one drawn before the run with -seal.
	FreshGiven bool   `json:"fresh_given,omitempty"`
	Model      string `json:"model,omitempty"`
	ModelBase  string `json:"model_base,omitempty"`
	// API is the model's API (chat or messages), and DesignSHA256 the digest of the design
	// document (-design) the run was made under: its job, prompts, tools and request settings.
	API          string `json:"api,omitempty"`
	DesignSHA256 string `json:"design_sha256,omitempty"`
	// Groups are the groups this run built, when it built only some (-groups), and Build how
	// many of each, when the run was given a size (-build).
	Groups []string `json:"groups,omitempty"`
	Build  int      `json:"build,omitempty"`
	// Regrade names the agents a regrade (-regrade) graded again; empty for a run.
	Regrade []string `json:"regrade,omitempty"`
	// Harness is the code that ran: its commit, and whether the checkout's code was the commit's.
	Harness Tree `json:"harness"`
	// GradingSeconds is the wall time from the first grading run's start to the last one's end:
	// what grading cost on this host at this run's hour, for comparing stages run apart.
	GradingSeconds float64   `json:"grading_seconds,omitempty"`
	Usage          usage     `json:"usage"`
	Built          []Built   `json:"built"`
	Missing        []Missing `json:"missing"`
	Failures       []string  `json:"failures"`
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
	daemon     string     // the daemon's base URL
	token      string     // its token, or "" for an open daemon
	model      agentModel // nil when the job builds nothing
	api        string     // the model's API, for run.json
	design     string     // the design document's digest, for run.json
	groups     []string   // build only these groups, or every group
	build      int        // with groups: this many of each, or 0 for the job's
	parallel   int
	given      givenFresh // the fresh set to fly, or none to draw one
	tree       Tree       // the harness's own code as the run found it
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
	harness, bundle, pubPEM, err := l.connect(dir)
	if err != nil {
		return err
	}
	defer bundle.Close()

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
		given = " (given with -fresh: not drawn by this run)"
	}
	fmt.Printf("sealed    | %d fresh flights, SHA-256 %s%s\n", len(fresh.Seeds), rf.FreshSHA256, given)
	for _, s := range fresh.Seeds {
		avoid[s] = true
	}

	var mu sync.Mutex
	var units []unit
	var transcripts []Transcript
	// Each transcript is saved the moment its rebuild ends, one JSON line synced to disk, so a run
	// killed later (out of memory, the machine) keeps every agent it paid for; transcripts.jsonl.gz
	// is written from them, in order, once the run is whole.
	var partial *os.File
	if l.job.builds() > 0 {
		if partial, err = os.Create(filepath.Join(dir, partialTranscripts)); err != nil {
			return err
		}
		defer partial.Close()
	}
	for _, c := range l.job.Courses {
		// Imported rebuilds: made elsewhere, graded here.
		for _, g := range c.Groups {
			for i, path := range g.Import {
				src, err := os.ReadFile(filepath.Join(l.importRoot, path))
				if err != nil {
					rf.Missing = append(rf.Missing, Missing{Course: c.ID, Group: g.ID, N: i, Why: "no controller at " + path})
					continue
				}
				units = append(units, unit{course: c.ID, who: g.ID, n: strconv.Itoa(i), src: src})
			}
		}
		// Built rebuilds, started in turn across the groups (each group's first, then each
		// group's second, ...), so a run the budget stops part way has stopped every group alike.
		var specs []rebuildSpec
		size := func(g Group) int {
			if l.build > 0 && slices.Contains(l.groups, g.ID) {
				return l.build
			}
			return g.Build
		}
		most := 0
		for _, g := range c.Groups {
			most = max(most, size(g))
		}
		for k := range most {
			for _, g := range c.Groups {
				if k < size(g) && (len(l.groups) == 0 || slices.Contains(l.groups, g.ID)) {
					r := l.job.Rebuild
					specs = append(specs, rebuildSpec{Course: c.ID, Group: g.ID, N: len(g.Import) + k, Recipe: c.recipeFor(g), Scrambled: g.Scramble,
						Turns: r.Turns, FlightsPerFly: r.FlightsPerFly, FlyCalls: r.FlyCalls, AskAfter: r.AskAfter, Avoid: avoid})
				}
			}
		}
		var wg sync.WaitGroup
		sem := make(chan struct{}, l.parallel)
		for _, spec := range specs {
			sem <- struct{}{} // taken here, so rebuilds start in the order above
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				src, b, tr, err := buildOne(ctx, l.model, l.remote, spec)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					b.Problem = err.Error()
					rf.Failures = append(rf.Failures, spec.trace("build")+": "+err.Error())
				}
				rf.Built = append(rf.Built, b)
				transcripts = append(transcripts, tr)
				if err := appendTranscript(partial, tr); err != nil {
					rf.Failures = append(rf.Failures, spec.trace("build")+": the transcript was not saved as it ended: "+err.Error())
				}
				fmt.Printf("rebuild   | %s: %d turns, %d fly calls, ended %s, controller %v\n", spec.trace("build"), b.Turns, b.FlyCalls, b.Ended, src != nil)
				if src == nil {
					rf.Missing = append(rf.Missing, Missing{Course: c.ID, Group: spec.Group, N: spec.N, Why: "the rebuild left no controller.js"})
					return
				}
				units = append(units, unit{course: c.ID, who: spec.Group, n: strconv.Itoa(spec.N), src: src})
			}()
		}
		wg.Wait()
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
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("the run was stopped before grading: %w", err)
	}
	slices.SortStableFunc(units, func(a, b unit) int { return compareUnits(a.course, a.who, a.n, b.course, b.who, b.n) })

	l.grade(ctx, units, fresh, freshFile, &rf)

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
		rf.Model, rf.ModelBase = l.model.label()
		rf.Usage, rf.API = l.model.used(), l.api
	}
	rf.DesignSHA256, rf.Groups, rf.Build, rf.Harness = l.design, l.groups, l.build, l.tree
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
	if l.job.builds() > 0 {
		slices.SortFunc(transcripts, func(a, b Transcript) int {
			return compareUnits(a.Course, a.Group, strconv.Itoa(a.N), b.Course, b.Group, strconv.Itoa(b.N))
		})
		if err := writeTranscripts(filepath.Join(dir, transcriptsName), transcripts); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(dir, "run.json"), rf)
}

// connect makes the run's key (never written) and dir/bundle.jsonl, and a client that signs every
// call into it; it returns the harness, the open bundle and the public key.
func (l *live) connect(dir string) (*attest.Harness, *os.File, []byte, error) {
	privPEM, pubPEM, err := attest.GenerateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := attest.ParsePrivateKey(privPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	bundle, err := os.Create(filepath.Join(dir, "bundle.jsonl"))
	if err != nil {
		return nil, nil, nil, err
	}
	harness := attest.NewHarness(attest.NewSigner(key), bundle)
	opts := []client.Option{client.WithRecorder(harness)}
	if l.token != "" {
		opts = append(opts, client.WithToken(l.token))
	}
	if l.remote, err = client.New(l.daemon, opts...); err != nil {
		bundle.Close()
		return nil, nil, nil, err
	}
	return harness, bundle, pubPEM, nil
}

// grade grades each controller on each sealed set, in runs of at most gradeChunk flights, each run
// in a sandbox of its own, and records in rf the runs that came back without a record and how long
// grading took.
func (l *live) grade(ctx context.Context, units []unit, fresh SealedSet, freshFile []byte, rf *RunFile) {
	parts := map[string][]setPart{"fresh": setParts("fresh", fresh, freshFile)}
	for _, c := range l.job.Courses {
		ps := practiceSet(c)
		parts[c.ID+"/practice"] = setParts("practice", ps, ps.encode())
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, l.parallel)
	done, total := 0, 0
	for _, u := range units {
		total += len(parts[u.course+"/practice"]) + len(parts["fresh"])
	}
	started := time.Now()
	for _, u := range units {
		for _, set := range []string{u.course + "/practice", "fresh"} {
			for _, part := range parts[set] {
				name := strings.SplitN(part.purpose, "-", 2)[0] // practice or fresh: the file's name in the run
				wg.Add(1)
				go func() {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					req, err := gradeRequest(u.course, u.src, name, part.file)
					if err == nil {
						err = again(ctx, func() error {
							_, err := l.remote.RunProject(client.NewTraceContext(ctx, u.trace(part.purpose)), req)
							return err
						})
					}
					mu.Lock()
					defer mu.Unlock()
					done++
					if err != nil {
						rf.Failures = append(rf.Failures, u.trace(part.purpose)+": "+err.Error())
						fmt.Printf("grade     | %s: %v\n", u.trace(part.purpose), err)
					}
					if done%16 == 0 || done == total {
						fmt.Printf("grade     | %d of %d grading runs\n", done, total)
					}
				}()
			}
		}
	}
	wg.Wait()
	rf.GradingSeconds = round1(time.Since(started).Seconds())
}

// transcriptsName is the file of every built rebuild's conversation, one JSON line each.
const transcriptsName = "transcripts.jsonl.gz"

// partialTranscripts is the same, a line appended as each rebuild ends: what a run that did not
// finish leaves in its kept staging directory.
const partialTranscripts = "transcripts.partial.jsonl"

func appendTranscript(f *os.File, t Transcript) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(t); err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		return err
	}
	return f.Sync()
}

func writeTranscripts(path string, ts []Transcript) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	for _, t := range ts {
		if err := enc.Encode(t); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// readTranscripts reads the transcripts a run wrote, or none if it built nothing.
func readTranscripts(dir string) ([]Transcript, error) {
	f, err := os.Open(filepath.Join(dir, transcriptsName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(zr)
	var ts []Transcript
	for {
		var t Transcript
		if err := dec.Decode(&t); errors.Is(err, io.EOF) {
			return ts, nil
		} else if err != nil {
			return nil, fmt.Errorf("%s: %w", transcriptsName, err)
		}
		ts = append(ts, t)
	}
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

// capacityWait, capacityWaitMax and capacityPatience bound how whenFree waits for the daemon.
var (
	capacityWait     = 2 * time.Second
	capacityWaitMax  = 15 * time.Second
	capacityPatience = 3 * time.Minute
)

// whenFree sends a call again while the daemon refuses it at capacity. Only a refusal marked
// not dispatched for capacity is sent again: nothing ran, so a call into a session (a cell, the
// hand-in read) is as safe to resend as a stateless one. Any other error comes back as it came,
// and so does the refusal once capacityPatience has passed. Without it, the docker run with the
// stand-in model of 2026-11-07 lost 5 of its 8 agents to "rate limit: 30 runs/min per caller",
// each ended by its first refused call.
func whenFree[T any](ctx context.Context, what string, send func() (T, error)) (T, error) {
	wait, give := capacityWait, time.Now().Add(capacityPatience)
	for {
		v, err := send()
		var nd *sandbox.NotDispatchedError
		if err == nil || !errors.As(err, &nd) || nd.Reason != sandbox.RefusalCapacity || time.Now().Add(wait).After(give) {
			return v, err
		}
		fmt.Printf("wait      | %s: at capacity, sent again in %s\n", what, wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}
		if wait *= 2; wait > capacityWaitMax {
			wait = capacityWaitMax
		}
	}
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

// errNotPaid is a building run refused because its model is off this machine and -paid was not given.
var errNotPaid = errors.New("this job's model calls go to a base off this machine, which spends the key's money: give -paid to allow it")
