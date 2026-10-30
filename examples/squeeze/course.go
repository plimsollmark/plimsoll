package main

import (
	"embed"
	"fmt"
	"strconv"
	"strings"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The drone courses, ported from the did-it-learn hackathon entry. The simulator, the task
// file, the host and the fly runner reach practice and grading runs only; a rebuild's sandbox
// gets the course's API text and the baseline controller, never the simulator (the entry's
// mistake 1: with the simulator's seed-to-flight generator in every sandbox, agents rebuilt the
// answers for any seed they could guess).
//
//go:embed course/sim.mjs course/host.mjs course/fly.mjs course/task-easy.mjs course/task-hard.mjs course/API-easy.md course/API-hard.md course/baselines/stabilizer.js
var courseFS embed.FS

// cpuBudgetSeconds is the controller's CPU time per flight, from loading its code to landing; the
// runtime's own start, before any controller code runs, is not counted (course/sim.mjs).
// The README and the page say why this number.
const cpuBudgetSeconds = 5

// courseIDs are the courses there are files for.
var courseIDs = map[string]string{
	"easy": "a quadcopter that flies three gates and lands softly on a pad within 25 seconds, in gusty wind",
	"hard": "a quadcopter that flies three narrow gates and lands softly on a pad within 15 seconds, in strong gusty wind",
}

func courseFile(name string) string {
	b, err := courseFS.ReadFile("course/" + name)
	if err != nil {
		panic(err) // embedded: a missing file is a build mistake
	}
	return string(b)
}

// simulatorFiles are the files a practice or grading run flies a controller with.
func simulatorFiles(course string) ([]sandbox.File, error) {
	if _, ok := courseIDs[course]; !ok {
		return nil, fmt.Errorf("no course %q (easy or hard)", course)
	}
	return []sandbox.File{
		{Path: "sim.mjs", Content: courseFile("sim.mjs")},
		{Path: "host.mjs", Content: courseFile("host.mjs")},
		{Path: "fly.mjs", Content: courseFile("fly.mjs")},
		{Path: "task.mjs", Content: courseFile("task-" + course + ".mjs")},
	}, nil
}

// rebuildFiles are what a rebuild's sandbox starts with besides the brief.
func rebuildFiles(course string) []sandbox.File {
	return []sandbox.File{
		{Path: "API.md", Content: courseFile("API-" + course + ".md")},
		{Path: "baselines/stabilizer.js", Content: courseFile("baselines/stabilizer.js")},
	}
}

// smokeSeeds are the course's four smoke flights, read from its task file so there is one copy.
func smokeSeeds(course string) []uint32 {
	src := courseFile("task-" + course + ".mjs")
	_, rest, ok := strings.Cut(src, "export const SMOKE = Object.freeze([")
	if !ok {
		panic("task-" + course + ".mjs has no SMOKE list")
	}
	list, _, _ := strings.Cut(rest, "]")
	var out []uint32
	for _, f := range strings.Split(list, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 32)
		if err != nil {
			panic(err)
		}
		out = append(out, uint32(n))
	}
	return out
}

// flyStep is the command that flies controller.js on one cases file and prints the result.
func flyStep(cases string) string {
	return fmt.Sprintf("node fly.mjs controller.js %s --cpu-budget %d", cases, cpuBudgetSeconds)
}
