package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// assemble reads every configuration's raw output from the work directory, rechecks each
// record log with the Go checker beside the Python client's answer, and gathers what the
// page states.
func assemble(ctx context.Context, c config, files map[string]string, cs census) (*evidence, error) {
	ev := &evidence{
		Scripted: true,
		Image:    agentImage,
		Baseline: baselineImage,
		Task:     pinned{Repo: strings.TrimPrefix(primeRepo, "https://github.com/"), Commit: primeCommit, Path: primePath, Files: files},
		Census:   cs,
	}
	// The logs of an earlier run go only once this run's have all been produced.
	if err := os.RemoveAll(filepath.Join(c.out, "records")); err != nil {
		return nil, err
	}
	versions, err := exec.CommandContext(ctx, c.python, "-I", "-c",
		"import importlib.metadata as m, platform; print(m.version('verifiers')); print(platform.python_version())").Output()
	if err != nil {
		return nil, fmt.Errorf("reading the verifiers version: %w", err)
	}
	v := strings.Fields(string(versions))
	if len(v) != 2 {
		return nil, fmt.Errorf("reading the verifiers version: %q", versions)
	}
	ev.Verifiers, ev.Python = v[0], v[1]
	pin, err := os.ReadFile(filepath.Join(c.repo, "clients", "python", "frameworks", "verifiers", "requirements.in"))
	if err != nil {
		return nil, err
	}
	ev.Pin = strings.TrimSpace(string(pin))
	if ev.ImageID, err = imageID(ctx, agentImage); err != nil {
		return nil, err
	}
	if ev.BaseID, err = imageID(ctx, baselineImage); err != nil {
		return nil, err
	}

	// vf-validate, per docker runtime.
	for _, rt := range []string{"runc", "runsc"} {
		dir := filepath.Join(c.work, "validate-"+rt)
		if !fileExists(dir) {
			continue
		}
		results, err := filepath.Glob(filepath.Join(dir, "out", "*", "results.jsonl"))
		if err != nil || len(results) != 1 {
			return nil, fmt.Errorf("%s: want one results.jsonl, found %v", dir, results)
		}
		var row struct {
			Valid bool     `json:"valid"`
			Gold  checkRow `json:"gold"`
			Noop  checkRow `json:"noop"`
		}
		raw, err := os.ReadFile(results[0])
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(bytes.TrimSpace(raw), &row); err != nil {
			return nil, fmt.Errorf("%s: %w", results[0], err)
		}
		pyLine, err := lastJSONLine(filepath.Join(dir, "check.log"))
		if err != nil {
			return nil, err
		}
		log, err := c.addLog(ev, filepath.Join(dir, "out", "records.jsonl"), "validate-"+rt, floorOf(rt), pyLine)
		if err != nil {
			return nil, err
		}
		ev.Validate = append(ev.Validate, validation{DockerRuntime: rt, Floor: floorOf(rt), Valid: row.Valid, Gold: row.Gold, Untouched: row.Noop, Log: log})
	}

	// The uuid_ctf attempts.
	home, _ := os.UserHomeDir()
	traces := map[string]*trace{}
	for _, p := range attemptPlan(fileExists(filepath.Join(c.work, "uuid-gold-runsc"))) {
		dir := filepath.Join(c.work, p.name)
		var s summary
		if err := readJSON(filepath.Join(dir, "summary.json"), &s); err != nil {
			return nil, err
		}
		if len(s.Rollouts) != 1 {
			return nil, fmt.Errorf("%s: %d rollouts, want 1", p.name, len(s.Rollouts))
		}
		r := s.Rollouts[0]
		a := attempt{Name: p.name, Task: s.Task, Policy: s.Policy, Harness: s.Harness, Runtime: s.Runtime,
			Reward: r.Reward, Rewards: r.Rewards, Metrics: r.Metrics, Stop: r.Stop, Error: errorLine(r.Errors, home),
			Seconds: r.Seconds, ModelTurns: r.ModelTurns, ToolResults: r.ToolResults}
		if r.Total != nil {
			a.Total = *r.Total
		}
		if s.DockerRuntime != nil {
			a.DockerRuntime = *s.DockerRuntime
		}
		if s.Floor != nil {
			a.Floor = *s.Floor
		}
		t, err := readTrace(filepath.Join(dir, "runs"))
		switch {
		case err == nil:
			traces[p.name] = t
			a.Session = t.Agent.Runtime.ID
		case !p.mayFail:
			return nil, err
		}
		if s.Runtime == "plimsoll" {
			log, err := c.addLog(ev, filepath.Join(dir, "records.jsonl"), p.name, a.Floor, s.RecordLog)
			if err != nil {
				return nil, err
			}
			a.Log = log
			_, calls, err := checkRecordFile(filepath.Join(c.out, log), a.Floor)
			if err != nil {
				return nil, err
			}
			var agent []phaseCall
			for _, call := range calls {
				pc := phaseCall{chainCall: call, Phase: "unknown"}
				if t != nil {
					pc.Phase = t.phaseOf(call.Started)
					if call.Session != t.Agent.Runtime.ID {
						return nil, fmt.Errorf("%s: a record names session %.12s, the trace's runtime is %.12s", p.name, call.Session, t.Agent.Runtime.ID)
					}
				}
				if pc.Phase == "agent" {
					agent = append(agent, pc)
				}
				a.Chain = append(a.Chain, pc)
			}
			if t != nil {
				a.Tools = t.toolCalls(agent)
			}
		}
		ev.Attempts = append(ev.Attempts, a)
	}
	if a, b := traces["uuid-gold-runc"], traces["uuid-gold-docker"]; a != nil && b != nil {
		ev.Same = compareTranscripts(a, b)
	}

	// Each runtime call, timed.
	if callsPath := filepath.Join(c.work, "calls", "calls.json"); fileExists(callsPath) {
		var raw map[string]json.RawMessage
		if err := readJSON(callsPath, &raw); err != nil {
			return nil, err
		}
		ev.Calls = callCosts{Rows: map[string]opCosts{}}
		_ = json.Unmarshal(raw["rounds"], &ev.Calls.Rounds)
		_ = json.Unmarshal(raw["calls_per_round"], &ev.Calls.Calls)
		for _, row := range []string{"docker", "plimsoll-runc", "plimsoll-runsc"} {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw[row], &m); err != nil {
				return nil, fmt.Errorf("calls.json %s: %w", row, err)
			}
			costs := opCosts{}
			for _, op := range []string{"start", "run_true", "write_1k", "read_1k", "teardown"} {
				var s stat
				if err := json.Unmarshal(m[op], &s); err != nil {
					return nil, fmt.Errorf("calls.json %s %s: %w", row, op, err)
				}
				costs[op] = s
			}
			ev.Calls.Rows[row] = costs
			if row != "docker" {
				rt := strings.TrimPrefix(row, "plimsoll-")
				if _, err := c.addLog(ev, filepath.Join(c.work, "calls", row, "records.jsonl"), "calls-"+rt, floorOf(rt), m["record_log"]); err != nil {
					return nil, err
				}
			}
		}
	}
	if ev.Date == "" {
		return nil, errors.New("no record in any log, so no run date")
	}
	return ev, nil
}

// addLog copies a record log beside the page as records/<name>.jsonl, rechecks it with the
// Go checker and requires the Python client's answer to be the same.
func (c config) addLog(ev *evidence, src, name, floor string, pyAnswer json.RawMessage) (string, error) {
	rel := "records/" + name + ".jsonl"
	if err := os.MkdirAll(filepath.Join(c.out, "records"), 0o755); err != nil {
		return "", err
	}
	if err := copyFile(filepath.Join(c.out, filepath.FromSlash(rel)), src); err != nil {
		return "", err
	}
	goCheck, calls, err := checkRecordFile(filepath.Join(c.out, filepath.FromSlash(rel)), floor)
	if err != nil {
		return "", err
	}
	// The run's date is the first record's, so assembling later keeps it.
	for _, call := range calls {
		if d := time.UnixMilli(call.Started).UTC().Format("2006-01-02"); ev.Date == "" || d < ev.Date {
			ev.Date = d
		}
	}
	var py pyCheck
	if err := json.Unmarshal(pyAnswer, &py); err != nil {
		return "", fmt.Errorf("%s: the Python check's answer: %w", name, err)
	}
	if py.Error != "" {
		return "", fmt.Errorf("%s: the Python check refused the log: %s", name, py.Error)
	}
	if !reflect.DeepEqual(py.logCheck(), goCheck) {
		return "", fmt.Errorf("%s: the Python check says %+v, the Go check %+v", name, py.logCheck(), goCheck)
	}
	ev.Logs = append(ev.Logs, publishedLog{File: rel, Floor: floor, Python: py.logCheck(), Go: goCheck})
	return rel, nil
}

func imageID(ctx context.Context, image string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect", "-f", "{{.Id}}", image).Output()
	if err != nil {
		return "", fmt.Errorf("docker image inspect %s: %w", image, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// publish writes evidence.json and the page beside the record logs, refusing evidence
// that holds anything of the machine that ran it.
func publish(c config, ev *evidence) error {
	raw, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := noLocalPaths(raw, c.repo); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.out, "evidence.json"), raw, 0o644); err != nil {
		return err
	}
	page, err := render(ev)
	if err != nil {
		return err
	}
	if err := noLocalPaths(page, c.repo); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.out, "index.html"), page, 0o644)
}

// noLocalPaths refuses bytes holding the home directory, the repository's path or the
// account name: published evidence must not locate the machine.
func noLocalPaths(b []byte, repo string) error {
	home, _ := os.UserHomeDir()
	for _, s := range []string{home, repo, os.Getenv("USER")} {
		if len(s) > 2 && bytes.Contains(b, []byte(s)) {
			return fmt.Errorf("the published output would hold %q, a path or name of this machine", s)
		}
	}
	return nil
}

func loadEvidence(dir string) (*evidence, error) {
	var ev evidence
	raw, err := os.ReadFile(filepath.Join(dir, "evidence.json"))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return nil, fmt.Errorf("evidence.json: %w", err)
	}
	return &ev, nil
}

// verifyPublished checks the published directory offline: each record log rechecks with
// the Go checker and gives the counts evidence.json states for both checkers, every
// attempt's chain is the log's, the census holds together, and index.html is exactly what
// evidence.json renders.
func verifyPublished(dir string) error {
	ev, err := loadEvidence(dir)
	if err != nil {
		return err
	}
	if len(ev.Logs) == 0 {
		return errors.New("evidence.json lists no record logs")
	}
	for _, l := range ev.Logs {
		got, _, err := checkRecordFile(filepath.Join(dir, filepath.FromSlash(l.File)), l.Floor)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, l.Go) || !reflect.DeepEqual(got, l.Python) {
			return fmt.Errorf("%s rechecks to %+v; evidence.json states %+v (Go) and %+v (Python)", l.File, got, l.Go, l.Python)
		}
	}
	for _, a := range ev.Attempts {
		if a.Log == "" {
			continue
		}
		_, calls, err := checkRecordFile(filepath.Join(dir, filepath.FromSlash(a.Log)), a.Floor)
		if err != nil {
			return err
		}
		if len(calls) != len(a.Chain) {
			return fmt.Errorf("%s: the log holds %d records, the evidence draws %d", a.Name, len(calls), len(a.Chain))
		}
		for i, call := range calls {
			if call != a.Chain[i].chainCall {
				return fmt.Errorf("%s: record %d of the evidence is not the log's", a.Name, i+1)
			}
		}
	}
	cs := ev.Census
	for _, n := range []int{cs.Image, cs.Internet, cs.Fetch, cs.Logs, cs.Tests, cs.App, cs.Runnable} {
		if n < 0 || n > cs.Tasks {
			return fmt.Errorf("the census counts %d of %d tasks", n, cs.Tasks)
		}
	}
	page, err := render(ev)
	if err != nil {
		return err
	}
	published, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		return err
	}
	if !bytes.Equal(page, published) {
		return errors.New("index.html is not what evidence.json renders: run go run ./examples/verifiers -render")
	}
	return nil
}

// renderPublished rewrites index.html from the published evidence.json.
func renderPublished(dir string) error {
	ev, err := loadEvidence(dir)
	if err != nil {
		return err
	}
	page, err := render(ev)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "index.html"), page, 0o644)
}
