package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// -regrade DIR grades again, with no model call, the controllers of a building run's agents whose
// grading failed (agents.json grade_problem: a grading run that came back with no record, a run
// whose time ran out), on the run's own sealed sets, signed by a key made for the regrade into
// DIR/regrades/<time>/. The agents' spend is sunk, so a failed grading costs grading runs, not an
// agent. agents.json then takes each such controller's grading from the latest regrade that
// graded it whole (regraded names which), and -verify checks every regrade as it checks the run.

const regradesDir = "regrades"

// regrade is one regrade's directory under regradesDir and the evidence its bundle states.
type regrade struct {
	name string
	ev   *Evidence
}

// readRegrades are dir's regrades in name order (a regrade's name is its time). Each must be of
// this job, on the run's own fresh set, grading runs alone, every one holding exactly its set, and
// its leak scan clean.
func readRegrades(dir string, job *Job, fresh string) ([]regrade, error) {
	names, err := os.ReadDir(filepath.Join(dir, regradesDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []regrade
	for _, n := range names {
		sub := filepath.Join(dir, regradesDir, n.Name())
		if !n.IsDir() || !runName.MatchString(n.Name()) {
			return nil, fmt.Errorf("%s: not a regrade's directory", sub)
		}
		var rf RunFile
		if err := readJSON(filepath.Join(sub, "run.json"), &rf); err != nil {
			return nil, err
		}
		if rf.Job != job.Name || rf.FreshSHA256 != fresh || len(rf.Regrade) == 0 {
			return nil, fmt.Errorf("%s is not a regrade of this run (job %q, fresh set %s)", sub, rf.Job, rf.FreshSHA256)
		}
		ev, err := deriveRun(sub, job)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sub, err)
		}
		if ev.Scan.SessionCalls > 0 || ev.Scan.PracticeRuns > 0 || !ev.Scan.SetsHeld || len(ev.Scan.Hits) > 0 {
			return nil, fmt.Errorf("%s: a regrade holds grading runs alone, each with exactly its set, and nothing the leak scan finds", sub)
		}
		out = append(out, regrade{name: n.Name(), ev: ev})
	}
	return out, nil
}

// applyRegrades gives each record whose grading failed the grading of the latest regrade that
// graded the same controller whole: a valid grading, or one the course's validator refused.
func applyRegrades(recs []AgentRecord, regs []regrade) {
	for i := range recs {
		r := &recs[i]
		if r.GradeProblem == "" || r.Controller == "" {
			continue
		}
		for j := len(regs) - 1; j >= 0; j-- {
			g := findRebuild(regs[j].ev, r.Course, r.Group, r.N)
			invalid := g != nil && !g.Valid && strings.HasPrefix(g.Problem, problemInvalid)
			if g == nil || g.SHA256 != r.Controller || !(g.Valid || invalid) {
				continue
			}
			r.Graded, r.Valid, r.Invalid, r.Records, r.GradeProblem, r.Regraded = true, g.Valid, invalid, g.Records, "", regs[j].name
			r.Fresh, r.FreshTotal, r.Practice, r.PracticeOf = g.Fresh, g.FreshTotal, g.Practice, g.PracticeTotal
			break
		}
	}
}

// regradePublished grades again the controllers of dir's agents whose grading failed, into a new
// regrade under dir, then writes agents.json again.
func regradePublished(ctx context.Context, dir string, job *Job, daemonURL, runtime, image string, parallel int) error {
	if job.builds() == 0 {
		return errors.New("-regrade is for a building run's agents (agents.json); a run of imported controllers is graded again with -fresh")
	}
	ev, err := derive(dir, job)
	if err != nil {
		return err
	}
	agents, err := agentRecords(dir, job, ev)
	if err != nil {
		return err
	}
	ts, err := readTranscripts(dir)
	if err != nil {
		return err
	}
	controller := map[string][]byte{}
	for _, t := range ts {
		controller[fmt.Sprintf("%s.%s.%d", t.Course, t.Group, t.N)] = []byte(t.Controller)
	}
	var units []unit
	var ids []string
	for _, a := range agents {
		if a.GradeProblem == "" || a.Controller == "" {
			continue
		}
		src := controller[a.ID]
		if digest(src) != a.Controller {
			return fmt.Errorf("%s: the transcript's controller is not the one agents.json names", a.ID)
		}
		units = append(units, unit{course: a.Course, who: a.Group, n: strconv.Itoa(a.N), src: src})
		ids = append(ids, a.ID)
	}
	if len(units) == 0 {
		fmt.Printf("regrade   | every agent's controller in %s is graded; nothing to grade again\n", dir)
		return nil
	}
	var parent RunFile
	if err := readJSON(filepath.Join(dir, "run.json"), &parent); err != nil {
		return err
	}
	freshFile, err := os.ReadFile(filepath.Join(dir, "fresh.json"))
	if err != nil {
		return err
	}
	if digest(freshFile) != parent.FreshSHA256 {
		return errors.New("fresh.json is not the set run.json committed to")
	}
	var fresh SealedSet
	if err := json.Unmarshal(freshFile, &fresh); err != nil {
		return err
	}
	l := &live{job: job, parallel: parallel, daemon: daemonURL, token: os.Getenv("PLIMSOLL_TOKEN"), tree: harnessTree()}
	if daemonURL == "" {
		base, token, stop, err := startDaemon(ctx, runtime, image, parallel, false)
		if err != nil {
			return err
		}
		defer stop()
		l.daemon, l.token = base, token
	}
	staging, err := os.MkdirTemp(dir, "regrade.staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	harness, bundle, pubPEM, err := l.connect(staging)
	if err != nil {
		return err
	}
	defer bundle.Close()
	fmt.Printf("regrade   | %d controllers of %s whose grading failed: %s\n", len(units), dir, strings.Join(ids, ", "))
	rf := RunFile{Job: job.Name, Started: time.Now().UTC().Truncate(time.Second), Sealed: parent.Sealed, FreshSHA256: parent.FreshSHA256,
		FreshGiven: true, Regrade: ids, Harness: l.tree, Built: []Built{}, Missing: []Missing{}, Failures: []string{}}
	l.grade(ctx, units, fresh, freshFile, &rf)
	if err := harness.Checkpoint(); err != nil {
		return err
	}
	if err := bundle.Sync(); err != nil {
		return err
	}
	rf.Ended = time.Now().UTC().Truncate(time.Second)
	slices.Sort(rf.Failures)
	for name, b := range map[string][]byte{"harness.pub": pubPEM, "fresh.json": freshFile} {
		if err := os.WriteFile(filepath.Join(staging, name), b, 0o644); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(staging, "run.json"), rf); err != nil {
		return err
	}
	if err := compressBundle(staging); err != nil {
		return err
	}
	name := strings.ToLower(time.Now().UTC().Format("20060102t150405z"))
	if err := publish(staging, filepath.Join(dir, regradesDir, name), []string{bundleName, "harness.pub", "fresh.json", "run.json"}); err != nil {
		return err
	}
	if err := writePage(dir, job); err != nil {
		return err
	}
	if len(rf.Failures) > 0 {
		return fmt.Errorf("%w: the regrade %s lost %d grading runs (its run.json lists them); regrade again", errIncomplete, name, len(rf.Failures))
	}
	fmt.Printf("regraded  | %s\n", filepath.Join(dir, regradesDir, name))
	return nil
}
