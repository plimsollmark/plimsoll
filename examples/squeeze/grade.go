package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Flight is one flight as fly.mjs reports it.
type Flight struct {
	Seed             uint32  `json:"seed"`
	Success          bool    `json:"success"`
	Reason           string  `json:"reason"`
	GatesPassed      int     `json:"gatesPassed"`
	LandingError     float64 `json:"landingError"`
	SimulatedSeconds float64 `json:"simulatedSeconds"`
	CPUSeconds       float64 `json:"cpuSeconds"`
	StartCPUSeconds  float64 `json:"startCpuSeconds"`
}

// FlightSet is fly.mjs's answer for one cases file.
type FlightSet struct {
	Valid   bool     `json:"valid"`
	Error   string   `json:"error,omitempty"`
	Passed  int      `json:"passed"`
	Total   int      `json:"total"`
	Results []Flight `json:"results"`
}

// gradeTimeout is a grading run's whole budget: the docker provider's ceiling. Each set is graded
// in a run of its own because 80 flights in one run outlasted it under gVisor on a loaded machine
// (2026-10-27: a median of 114 s, 3 of 31 runs cut off); the page states the times measured.
const gradeTimeout = 120 * time.Second

// gradeRequest is one controller's grading run on one sealed set: a fresh sandbox holding the
// course, the controller and that set's file, named set+".json". The controller runs in a child
// process allowed to read only its own source and the host, so the set beside it is out of its
// reach; and no run holds both sets.
func gradeRequest(course string, controller []byte, set string, file []byte) (sandbox.ProjectRequest, error) {
	files, err := simulatorFiles(course)
	if err != nil {
		return sandbox.ProjectRequest{}, err
	}
	files = append(files,
		sandbox.File{Path: "controller.js", Content: string(controller)},
		sandbox.File{Path: set + ".json", Content: string(file)},
	)
	return sandbox.ProjectRequest{Files: files, Steps: []string{flyStep(set + ".json")}, Timeout: gradeTimeout, MinimumIsolation: sandbox.IsolationContainer}, nil
}

// flyRequest flies a rebuild's controller on the seeds it asked for, in a sandbox of its own:
// the practice tool. It holds no sealed set.
func flyRequest(course string, controller []byte, seeds []uint32) (sandbox.ProjectRequest, error) {
	files, err := simulatorFiles(course)
	if err != nil {
		return sandbox.ProjectRequest{}, err
	}
	cases := SealedSet{Name: "practice-tool", Seeds: seeds}.encode()
	files = append(files, sandbox.File{Path: "controller.js", Content: string(controller)}, sandbox.File{Path: "cases.json", Content: string(cases)})
	return sandbox.ProjectRequest{Files: files, Steps: []string{flyStep("cases.json")}, Timeout: gradeTimeout, MinimumIsolation: sandbox.IsolationContainer}, nil
}

// tracksFPS is the poses a second a recorded flight keeps for the page: enough to draw the
// path through a 0.6 m gate at the drone's 1 to 2 m/s, and a tenth the size of the 30 the
// hackathon's viewer used.
const tracksFPS = 10

// tracksRequest records the flights of one controller on the given seeds, for the page's
// flight pictures.
func tracksRequest(course string, controller []byte, seeds []uint32) (sandbox.ProjectRequest, error) {
	files, err := simulatorFiles(course)
	if err != nil {
		return sandbox.ProjectRequest{}, err
	}
	cases := SealedSet{Name: "tracks", Seeds: seeds}.encode()
	files = append(files, sandbox.File{Path: "controller.js", Content: string(controller)}, sandbox.File{Path: "cases.json", Content: string(cases)})
	var artifacts []string
	for _, s := range seeds {
		artifacts = append(artifacts, "tracks/seed-"+strconv.FormatUint(uint64(s), 10)+".json")
	}
	step := flyStep("cases.json") + " --record tracks --fps " + strconv.Itoa(tracksFPS)
	return sandbox.ProjectRequest{Files: files, Steps: []string{step}, Artifacts: artifacts, Timeout: gradeTimeout, MinimumIsolation: sandbox.IsolationContainer}, nil
}

// parseFlights reads one step's answer. A step that printed nothing parseable (the run timed
// out, the sandbox failed) is reported as such, never as zero passed flights.
func parseFlights(stdout []byte) (FlightSet, error) {
	var fs FlightSet
	line := strings.TrimSpace(string(stdout))
	if line == "" {
		return fs, fmt.Errorf("the step printed nothing")
	}
	if err := json.Unmarshal([]byte(line), &fs); err != nil {
		return fs, fmt.Errorf("the step's output is not fly.mjs's JSON: %w", err)
	}
	if fs.Valid && fs.Total != len(fs.Results) {
		return fs, fmt.Errorf("the step reports %d flights and lists %d", fs.Total, len(fs.Results))
	}
	return fs, nil
}

// readSet reads a grading run's answer: the flights of its one set, or why there are none (the
// run timed out, the sandbox failed). A controller that fails validation is a valid answer.
func readSet(resp *plimsollv1.ProjectResult) (FlightSet, string) {
	steps := resp.GetSteps()
	if len(steps) == 0 {
		return FlightSet{}, "no step ran (" + resp.GetOutcome().String() + ")"
	}
	fs, err := parseFlights(steps[0].GetStdout())
	if err != nil {
		if steps[0].GetTimedOut() {
			return FlightSet{}, "the run's time ran out"
		}
		return FlightSet{}, err.Error()
	}
	return fs, ""
}
