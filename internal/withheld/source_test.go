package withheld

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// harnessPy is a harness file as a hackathon ships one: the simulator, its scoring and
// its hidden cases, with a license header and imports any file might share.
const harnessPy = `"""Plant simulator for the flight task: one step of the hidden dynamics."""
import numpy as np

# Copyright 2026 The Harness Authors. Licensed under the Apache License 2.0.
# You may not use this file except in compliance with the License.

DRAG_COEFFICIENT = 0.3172
GRAVITY_MPS2 = 9.80665
WIND_GUST_TABLE = [0.12, 0.37, 0.05, 0.44, 0.29, 0.08]


def wind_at(t, seed):
    rng = np.random.default_rng(seed + int(t * 1000))
    gust = WIND_GUST_TABLE[int(t * 7) % len(WIND_GUST_TABLE)]
    return gust * rng.standard_normal()


def step(state, u, dt, seed):
    pos, vel = state
    accel = u - DRAG_COEFFICIENT * vel * abs(vel) - GRAVITY_MPS2
    accel += wind_at(pos, seed)
    vel_next = vel + dt * accel
    pos_next = pos + dt * vel_next
    return np.array([pos_next, vel_next])


def score(trajectory, target):
    errors = [abs(p - target) for p, _ in trajectory]
    settled = next((i for i, e in enumerate(errors) if e < 0.05), len(errors))
    return 100.0 - 0.5 * settled - 10.0 * max(errors[-20:])


def hidden_case(n):
    seeds = [731904, 552018, 100001, 993377]
    return {"seed": seeds[n % len(seeds)], "target": 12.5 + 2.5 * (n % 3)}
`

// controllerPy is an agent's own code for the same task: nothing of the harness.
const controllerPy = `import numpy as np


class Controller:
    def __init__(self, kp=2.0, ki=0.4, kd=0.9):
        self.kp, self.ki, self.kd = kp, ki, kd
        self.integral = 0.0
        self.previous_error = None

    def act(self, observation, target, dt):
        position, velocity = observation
        error = target - position
        self.integral = np.clip(self.integral + error * dt, -50.0, 50.0)
        derivative = 0.0 if self.previous_error is None else (error - self.previous_error) / dt
        self.previous_error = error
        return self.kp * error + self.ki * self.integral + self.kd * derivative - 0.1 * velocity
`

// sourceEntry is a source entry for content as the builder makes one: its distinctive
// lines, and DefaultMinLines of them to find it.
func sourceOf(content, label string, mode Mode) map[string]any {
	digests := SourceDigests([]byte(content))
	lines := make([]string, len(digests))
	for i, d := range digests {
		lines[i] = hex.EncodeToString(d[:])
	}
	m := map[string]any{"kind": "source", "lines": lines, "min_lines": DefaultMinLines(len(lines)), "label": label}
	if mode != "" {
		m["mode"] = mode
	}
	return m
}

func TestSourceLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"    return state + dt * (u - 0.3 * state)\n", "returnstate+dt*(u-0.3*state)"},
		{"\treturn state+dt*(u-0.3*state)\r\n", "returnstate+dt*(u-0.3*state)"},
		{`    "    pos_next = pos + dt * vel_next\n",` + "\n", "pos_next=pos+dt*vel_next"},
		{`    'pos_next = pos + dt * vel_next\n',`, "pos_next=pos+dt*vel_next"},
		{`print("done")`, `print("done")`},
		{`x = "a",`, `x="a`},
	} {
		if got := string(SourceLine(nil, []byte(tc.in))); got != tc.want {
			t.Errorf("SourceLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, line := range []string{"# Copyright 2026 The Harness Authors. Licensed", "// a comment that is long enough to count", " * a block comment's continuation line here", "-- a SQL comment, long enough to be counted", "x = 1"} {
		if Distinctive(SourceLine(nil, []byte(line))) {
			t.Errorf("%q is distinctive", line)
		}
	}
}

// A harness file is found however it ships: edited, reformatted, bundled with other
// code, as a notebook's cells, inside a string, inside an archive, inside a data: URI.
func TestSourceEntriesFindChangedCopies(t *testing.T) {
	n := len(SourceDigests([]byte(harnessPy)))
	if n < 2*MinSourceLines {
		t.Fatalf("the harness has %d distinctive lines; the test wants at least %d", n, 2*MinSourceLines)
	}
	set := setOf(t, ModeRefuse, nil, sourceOf(harnessPy, "harness/sim.py", ""))
	reformatted := strings.NewReplacer("    ", "\t", " = ", "=", " * ", "*", " + ", "+", "\n", "\r\n").Replace(harnessPy)
	edited := strings.NewReplacer("def step(", "def advance(", "GRAVITY_MPS2 = 9.80665", "GRAVITY_MPS2 = 9.81",
		"    return gust * rng.standard_normal()\n", "    noise = rng.standard_normal()\n    return gust * noise  # damped\n").Replace(harnessPy)
	var cells []string
	for line := range strings.Lines(harnessPy) {
		cells = append(cells, line)
	}
	notebook, err := json.MarshalIndent(map[string]any{"cells": []any{map[string]any{"cell_type": "code", "source": cells}}}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	quoted, err := json.Marshal(harnessPy)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, text string }{
		{"as it is", harnessPy},
		{"reindented and respaced, CRLF", reformatted},
		{"a function renamed, a constant changed, a line split", edited},
		{"bundled after other code", strings.Repeat(controllerPy, 3) + harnessPy},
		{"a notebook's cells", string(notebook)},
		{"inside a string", "const HARNESS = " + string(quoted) + ";\n"},
		{"inside a .tar.gz", base64Lines(gzipOf(tarOf(member{"vendor/plant.py", harnessPy})))},
		{"a data: URI", "data:text/x-python;base64," + base64.StdEncoding.EncodeToString([]byte(harnessPy))},
	} {
		if got := scanText(t, set, tc.text); !reflect.DeepEqual(got, []string{"harness/sim.py"}) {
			t.Errorf("%s: found %v", tc.name, got)
		}
	}
}

// A set of source entries alone reads each stored archive member as a file of its own:
// read as part of the whole archive, a member's first line follows its header with no
// newline between them, so the line is not one of the entry's, and a file of exactly
// min_lines distinctive lines would be one short (the 2026-10-29 public-source scan,
// finding 1: the member checks ran only when the set held a file entry).
func TestSourceOnlySetReadsStoredMembers(t *testing.T) {
	var exact strings.Builder
	for i := range MinSourceLines {
		fmt.Fprintf(&exact, "HIDDEN_CASE_%d_TARGET_ALTITUDE_METERS = %d.%03d\n", i, 40+i*7, 113*i)
	}
	src := exact.String()
	if n := len(SourceDigests([]byte(src))); n != MinSourceLines || DefaultMinLines(n) != n {
		t.Fatalf("the file has %d distinctive lines and needs %d; the test wants exactly %d of %d", n, DefaultMinLines(n), MinSourceLines, MinSourceLines)
	}
	m := member{"cases.py", src}
	for _, mode := range []Mode{ModeAudit, ModeRefuse} {
		set := setOf(t, mode, nil, sourceOf(src, "harness/cases.py", ""))
		for _, tc := range []struct{ name, text string }{
			{"as it is", src},
			{"a tar of text", string(tarOf(member{"README", "notes\n"}, m))},
			{"a tar, base64", base64Lines(tarOf(m))},
			{"a .tar.gz", base64Lines(gzipOf(tarOf(m)))},
			{"a stored zip, sizes in its local header", base64Lines(rawZip(nil, false, m))},
			{"a stored zip, data descriptors", base64Lines(zipOf(zip.Store, m))},
			{"a stored zip cut short", base64Lines(beforeDirectory(zipOf(zip.Store, m)))},
			{"a deflated zip", base64Lines(zipOf(zip.Deflate, m))},
		} {
			if got := scanText(t, set, tc.text); !reflect.DeepEqual(got, []string{"harness/cases.py"}) {
				t.Errorf("%s, %s: found %v", mode, tc.name, got)
			}
		}
	}
}

// A file holding fewer than min_lines of the entry's lines is not a find: a few copied
// lines, the comments and imports any file shares, an agent's own code for the task.
func TestSourceEntriesNeedEnoughLines(t *testing.T) {
	entry := sourceOf(harnessPy, "harness/sim.py", "")
	set := setOf(t, ModeRefuse, nil, entry)
	min := entry["min_lines"].(int)
	var distinctive []string
	for line := range strings.Lines(harnessPy) {
		if Distinctive(SourceLine(nil, []byte(line))) {
			distinctive = append(distinctive, line)
		}
	}
	header := "import numpy as np\n\n# Copyright 2026 The Harness Authors. Licensed under the Apache License 2.0.\n# You may not use this file except in compliance with the License.\n"
	for _, tc := range []struct {
		name, text string
		want       []string
	}{
		{"one line short", controllerPy + strings.Join(distinctive[:min-1], ""), nil},
		{"one line short, one of them ten times", controllerPy + strings.Join(distinctive[:min-1], "") + strings.Repeat(distinctive[0], 10), nil},
		{"just enough", controllerPy + strings.Join(distinctive[:min], ""), []string{"harness/sim.py"}},
		{"the license header and imports", header + controllerPy, nil},
		{"the agent's own controller", controllerPy, nil},
	} {
		if got := scanText(t, set, tc.text); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: found %v, want %v", tc.name, got, tc.want)
		}
	}
	// Counts are per file: lines split across two files of one call are neither's find.
	res, err := set.Scan(context.Background(), []Part{
		{Where: "files[0].content", Data: []byte(strings.Join(distinctive[:min-1], "")), Whole: true},
		{Where: "files[1].content", Data: []byte(strings.Join(distinctive[min-1:min+1], "")), Whole: true},
	})
	if err != nil || len(res.Found) > 0 {
		t.Fatalf("lines in two files: found %v, %v", labels(res.Found), err)
	}
}

func TestParseSourceEntries(t *testing.T) {
	good := sourceOf(harnessPy, "h", "")
	lines := good["lines"].([]string)
	for name, mutate := range map[string]func(m map[string]any){
		"too few lines":      func(m map[string]any) { m["lines"], m["min_lines"] = lines[:MinSourceLines-1], MinSourceLines },
		"min_lines too low":  func(m map[string]any) { m["min_lines"] = MinSourceLines - 1 },
		"min_lines too high": func(m map[string]any) { m["min_lines"] = len(lines) + 1 },
		"a sha256":           func(m map[string]any) { m["sha256"] = fileHex([]byte("x")) },
		"a length":           func(m map[string]any) { m["length"] = 6 },
		"a line twice":       func(m map[string]any) { m["lines"] = append([]string{lines[0]}, lines...) },
		"a bad digest":       func(m map[string]any) { m["lines"] = append([]string{"XYZ"}, lines[1:]...) },
	} {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		mutate(m)
		raw, _ := json.Marshal(map[string]any{"version": Version, "mode": ModeRefuse, "entries": []any{m}})
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	f := file("x\n", "f", "")
	f["lines"] = lines
	raw, _ := json.Marshal(map[string]any{"version": Version, "mode": ModeRefuse, "entries": []any{f}})
	if _, err := Parse(raw); err == nil {
		t.Error("a file entry with lines parsed")
	}
	// Two entries may share lines (two harness files with a common block); each counts
	// its own.
	setOf(t, ModeRefuse, nil, good, sourceOf(harnessPy+"\nEXTRA_CONSTANT_FOR_THE_SECOND_FILE = 42\n", "h2", ""))
}

// Over this module's own code, source entries made from some files find nothing in
// the others, and no two files share as much as the builder's third: the threshold
// keeps a codebase's common lines (imports, error checks, helper calls) from making a
// find. The test states the most any file shared with another.
func TestSourceEntriesInOrdinaryCode(t *testing.T) {
	var files []string
	for _, pattern := range []string{"*.go", "../rpc/*.go", "../../sandbox/*.go", "../../record/*.go", "../../attest/*.go"} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range m {
			if !strings.HasSuffix(f, "_test.go") {
				files = append(files, f)
			}
		}
	}
	type src struct {
		name  string
		lines map[[32]byte]bool
	}
	var srcs []src
	contents := map[string][]byte{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		contents[f] = data
		if ds := SourceDigests(data); len(ds) >= MinSourceLines {
			s := src{name: f, lines: map[[32]byte]bool{}}
			for _, d := range ds {
				s.lines[d] = true
			}
			srcs = append(srcs, s)
		}
	}
	// closest is the most shared lines as a fraction of what a find needs.
	worst, worstPair, closest, closestPair := 0.0, "", 0.0, ""
	for _, a := range srcs {
		need := DefaultMinLines(len(a.lines))
		for _, b := range srcs {
			if a.name == b.name {
				continue
			}
			shared := 0
			for d := range a.lines {
				if b.lines[d] {
					shared++
				}
			}
			pair := fmt.Sprintf("%d of %s's %d lines in %s", shared, a.name, len(a.lines), b.name)
			if frac := float64(shared) / float64(len(a.lines)); frac > worst {
				worst, worstPair = frac, pair
			}
			if frac := float64(shared) / float64(need); frac > closest {
				closest, closestPair = frac, pair
			}
			if shared >= need {
				t.Errorf("a find in ordinary code: %s", pair)
			}
		}
	}
	t.Logf("%d files with %d or more distinctive lines: the most one shared with another was %.0f%% (%s); the closest to a find, %.0f%% of the lines one needs (%s)",
		len(srcs), MinSourceLines, 100*worst, worstPair, 100*closest, closestPair)
	// The same through the scan: entries from this package's files, every other file scanned.
	var entries []map[string]any
	for _, f := range []string{"withheld.go", "views.go", "archive.go", "source.go"} {
		entries = append(entries, sourceOf(string(contents[f]), f, ""))
	}
	set := setOf(t, ModeRefuse, nil, entries...)
	var parts []Part
	for i, f := range files {
		if filepath.Dir(f) != "." {
			parts = append(parts, Part{Where: fmt.Sprintf("files[%d].content", i), Data: contents[f], Whole: true})
		}
	}
	res, err := set.Scan(context.Background(), parts)
	if err != nil || len(res.Found) > 0 || len(res.Incomplete) > 0 {
		t.Fatalf("found %v, incomplete %v, %v", labels(res.Found), res.Incomplete, err)
	}
}

// The scan's cost for source entries: the most a call carries of ordinary source,
// against 20 entries made from this module's files.
func BenchmarkScanSource(b *testing.B) {
	var entries []map[string]any
	for _, f := range []string{"withheld.go", "views.go", "archive.go", "source.go", "../rpc/withheld.go", "../rpc/pipeline.go",
		"../rpc/sessions.go", "../rpc/sandbox_service.go", "../../sandbox/sandbox.go", "../../sandbox/docker.go",
		"../../sandbox/e2b.go", "../../sandbox/wasm.go", "../../sandbox/broker.go", "../../sandbox/capability.go",
		"../../sandbox/factory.go", "../../sandbox/validation.go", "../../sandbox/module.go", "../../sandbox/session.go",
		"../../record/record.go", "../../attest/attest.go"} {
		data, err := os.ReadFile(f)
		if err != nil {
			b.Fatal(err)
		}
		entries = append(entries, sourceOf(string(data), strings.ReplaceAll(strings.TrimLeft(f, "./"), "../", ""), ""))
	}
	set := setOf(b, ModeAudit, nil, entries...)
	data := ordinaryText(4<<20 + 20*16<<10 + 100*1<<10)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		set.Scan(context.Background(), []Part{{Where: "files[0].content", Data: data, Whole: true}})
	}
}
