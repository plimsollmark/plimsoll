// Command wasm-buck judges a buck converter controller written in C: the project run
// compiles it to WebAssembly inside the sandbox, then runs it against the buck
// plant, which is WebAssembly too, under the same shim as examples/wasm-controller.
// See README.md for what this proves and what it does not.
//
// It builds the docker provider in process with sandbox.Build, the factory plimsolld
// uses, with plimsoll/sandbox-wasm-cc as the project image and the shipped seccomp
// profile, proves it with EnsureReady, and sends three project runs: the C build
// twice (the compile and every trajectory must repeat) and reference.js, the
// JavaScript law the C is a port of. All three must give the recorded fingerprint in
// every scenario.
//
//	make docker-images && go run ./examples/wasm-buck
//
// Needs docker. Writes docs/examples/wasm-buck/index.html (override with -out).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/plimsollmark/plimsoll/examples/internal/wasmshim"
	"github.com/plimsollmark/plimsoll/sandbox"
)

//go:embed controller/controller.c
var controllerC string

//go:embed controller/reference.js
var referenceJS string

//go:embed fingerprints.json
var fixtureJSON []byte

//go:embed page.html
var pageTemplate string

// width is the plant's observation count: output voltage and inductor current. The
// judge appends the duty cycle to each tick of its record.
const width = 2

// fixture is fingerprints.json: the build step, the plant, the scenarios, and the
// fingerprint a run of the built image recorded for each. One fingerprint per
// scenario, because the C port and the JavaScript law give the same one.
type fixture struct {
	Build                string   `json:"build"`
	ControllerWasmSHA256 string   `json:"controller_wasm_sha256"`
	Plant                string   `json:"plant"`
	Parameters           []string `json:"parameters"`
	TickS                float64  `json:"tick_s"`
	TEndS                float64  `json:"t_end_s"`
	MinScore             float64  `json:"min_score"`
	Scenarios            []struct {
		ID          string     `json:"id"`
		Params      [3]float64 `json:"params"`
		Fingerprint string     `json:"fingerprint"`
	} `json:"scenarios"`
}

// judged is one scenario of one run.
type judged struct {
	fingerprint string
	trajectory  []byte
}

// result is one project run.
type result struct {
	wasmSHA256 string
	wasmBytes  int
	scenarios  map[string]judged
	isolation  string
	buildMs    int64
	judgeMs    int64
}

func main() {
	out := flag.String("out", filepath.Join("docs", "examples", "wasm-buck", "index.html"), "page to write")
	image := flag.String("image", "plimsoll/sandbox-wasm-cc:latest", "project image carrying the C toolchain, the plant and the judge")
	flag.Parse()
	if err := realMain(*out, *image); err != nil {
		fmt.Fprintln(os.Stderr, "wasm-buck:", err)
		os.Exit(1)
	}
}

func realMain(out, image string) error {
	var fx fixture
	if err := json.Unmarshal(fixtureJSON, &fx); err != nil {
		return fmt.Errorf("fingerprints.json: %w", err)
	}
	if len(fx.Scenarios) == 0 {
		return errors.New("fingerprints.json has no scenarios")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	env := map[string]string{
		"SANDBOX_PROVIDER":             "docker",
		"SANDBOX_DOCKER_PROJECT_IMAGE": image,
		"SANDBOX_DOCKER_SECCOMP":       filepath.Join("docker", "seccomp.json"),
	}
	p, err := sandbox.Build(func(k string) string { return env[k] })
	if err != nil {
		return fmt.Errorf("build the docker provider: %w", err)
	}
	if err := p.EnsureReady(ctx); err != nil {
		return fmt.Errorf("docker provider not ready (run from the repository root after make docker-images): %w", err)
	}
	fmt.Printf("build     | %s\n", fx.Build)

	cFiles := []sandbox.File{{Path: "controller.c", Content: controllerC}, {Path: "controller.js", Content: wasmshim.Source}}
	var runs []result
	for i := 1; i <= 2; i++ {
		r, err := judge(ctx, p.Sandbox, fx, cFiles, fx.Build, "controller.js")
		if err != nil {
			return fmt.Errorf("C run %d: %w", i, err)
		}
		fmt.Printf("run %d     | controller.wasm %d bytes, sha256 %s  (compile %d ms, judging %d ms, %s tier)\n", i, r.wasmBytes, r.wasmSHA256[:16], r.buildMs, r.judgeMs, r.isolation)
		runs = append(runs, r)
	}
	js, err := judge(ctx, p.Sandbox, fx, []sandbox.File{{Path: "reference.js", Content: referenceJS}}, "", "reference.js")
	if err != nil {
		return fmt.Errorf("JavaScript run: %w", err)
	}

	var problems []string
	if runs[0].wasmSHA256 != runs[1].wasmSHA256 {
		problems = append(problems, "the two compiles produced different modules")
	}
	if runs[0].wasmSHA256 != fx.ControllerWasmSHA256 {
		problems = append(problems, fmt.Sprintf("controller.wasm is %s, fingerprints.json records %s", runs[0].wasmSHA256, fx.ControllerWasmSHA256))
	}
	var rows []scenarioRow
	for _, s := range fx.Scenarios {
		a, b, j := runs[0].scenarios[s.ID], runs[1].scenarios[s.ID], js.scenarios[s.ID]
		for _, c := range []struct{ name, got string }{{"C run 1", a.fingerprint}, {"C run 2", b.fingerprint}, {"JavaScript", j.fingerprint}} {
			if c.got != s.Fingerprint {
				problems = append(problems, fmt.Sprintf("%s: %s fingerprint %s, fingerprints.json records %s", s.ID, c.name, c.got, s.Fingerprint))
			}
		}
		sc := score(a.trajectory, fx.TickS)
		if sc.Failure != "" || sc.Score < fx.MinScore {
			problems = append(problems, fmt.Sprintf("%s: score %.3f, failure %q, floor %.2f", s.ID, sc.Score, sc.Failure, fx.MinScore))
		}
		row := scenarioRow{
			ID: s.ID, InputV: s.Params[0], LoadOhm: s.Params[1], StepMs: round(s.Params[2] * 1000),
			Score: round(sc.Score), MaxV: round(sc.MaxV), MaxI: round(sc.MaxI),
			Fingerprint: a.fingerprint, SecondRun: b.fingerprint, JavaScript: j.fingerprint,
			Identical: bytes.Equal(a.trajectory, j.trajectory),
		}
		fmt.Printf("%-10s| %2s V in, %s ohm halving at %s ms  %s  C = C = JavaScript: %t  score %.3f, peak %.3f V, %.3f A\n",
			s.ID, num(s.Params[0]), num(s.Params[1]), num(row.StepMs), a.fingerprint[:16], row.Identical && a.fingerprint == b.fingerprint, sc.Score, sc.MaxV, sc.MaxI)
		rows = append(rows, row)
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	fmt.Println("verdict   | the compile is reproducible, the C port's trajectory is the JavaScript law's to the bit in every scenario, and it regulates within every limit")

	page, err := render(fx, runs, rows, runs[0].scenarios[fx.Scenarios[0].ID].trajectory)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(out, page, 0o644); err != nil {
		return err
	}
	fmt.Printf("page      | %s (%d bytes)\n", out, len(page))
	return nil
}

func num(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func round(v float64) float64 { return math.Round(v*1e6) / 1e6 }

// judge sends one project run: an optional compile, then one judge step per
// scenario, each running controller (a file of the run) as the controller process.
func judge(ctx context.Context, sb sandbox.Sandbox, fx fixture, files []sandbox.File, build, controller string) (result, error) {
	var steps, artifacts []string
	if build != "" {
		steps = append(steps, build)
		artifacts = append(artifacts, "controller.wasm")
	}
	judgeFrom := len(steps)
	for _, s := range fx.Scenarios {
		steps = append(steps, fmt.Sprintf("node --no-warnings /oracle/judge.mjs %s %s %s %s %s %s %s %s.bin",
			controller, fx.Plant, num(s.Params[0]), num(s.Params[1]), num(s.Params[2]), num(fx.TickS), num(fx.TEndS), s.ID))
		artifacts = append(artifacts, s.ID+".bin")
	}
	res, err := sb.RunProject(ctx, sandbox.ProjectRequest{
		Files:     files,
		Steps:     steps,
		Artifacts: artifacts,
		Timeout:   90 * time.Second,
	})
	if err != nil {
		return result{}, err
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != len(steps) {
		return result{}, fmt.Errorf("outcome %s (%s), %d of %d steps ran: %+v", res.Outcome, res.Detail, len(res.Steps), len(steps), res.Steps)
	}
	for _, st := range res.Steps {
		if st.ExitCode != 0 {
			return result{}, fmt.Errorf("step %q exited %d: %s", st.Command, st.ExitCode, strings.TrimSpace(st.Stderr))
		}
	}
	byPath := map[string][]byte{}
	for _, a := range res.Artifacts {
		byPath[a.Path] = a.Content
	}
	r := result{scenarios: map[string]judged{}, isolation: res.Isolation.String()}
	if build != "" {
		wasm := byPath["controller.wasm"]
		if len(wasm) == 0 {
			return result{}, errors.New("no controller.wasm came back")
		}
		sum := sha256.Sum256(wasm)
		r.wasmSHA256, r.wasmBytes, r.buildMs = hex.EncodeToString(sum[:]), len(wasm), res.Steps[0].Duration.Milliseconds()
	}
	ticks := int(math.Round(fx.TEndS / fx.TickS))
	for i, s := range fx.Scenarios {
		step := res.Steps[judgeFrom+i]
		r.judgeMs += step.Duration.Milliseconds()
		var v struct {
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(step.Stdout)), &v); err != nil {
			return result{}, fmt.Errorf("%s: judge stdout %q: %w", s.ID, step.Stdout, err)
		}
		traj := byPath[s.ID+".bin"]
		if len(traj) != ticks*(width+1)*8 {
			return result{}, fmt.Errorf("%s: trajectory is %d bytes, want %d ticks of %d doubles", s.ID, len(traj), ticks, width+1)
		}
		ts := sha256.Sum256(traj)
		fp := hex.EncodeToString(ts[:])
		if fp != v.Fingerprint {
			return result{}, fmt.Errorf("%s: the judge printed %s but the artifact hashes to %s", s.ID, v.Fingerprint, fp)
		}
		r.scenarios[s.ID] = judged{fingerprint: fp, trajectory: traj}
	}
	return r, nil
}

// at reads column col of tick k from a judge record: per tick v, i, duty as
// little-endian float64.
func at(traj []byte, k, col int) float64 {
	return math.Float64frombits(binary.LittleEndian.Uint64(traj[(k*(width+1)+col)*8:]))
}

type verdict struct {
	Score   float64
	Failure string
	MaxV    float64
	MaxI    float64
}

// score is the buck environment's verifier, restated: the fraction of ticks from
// 2 ms on with the output within 0.1 V of 5 V, and zero with a reason if the output
// ever exceeds 6 V or the inductor current 10 A in magnitude.
func score(traj []byte, tickS float64) verdict {
	n := len(traj) / 8 / (width + 1)
	from := int(math.Round(0.002 / tickS))
	v := verdict{MaxV: math.Inf(-1)}
	inBand, counted := 0, 0
	for k := 0; k < n; k++ {
		volts, amps := at(traj, k, 0), at(traj, k, 1)
		v.MaxV = math.Max(v.MaxV, volts)
		v.MaxI = math.Max(v.MaxI, math.Abs(amps))
		if v.Failure == "" && math.Abs(amps) > 10 {
			v.Failure = "overcurrent"
		}
		if v.Failure == "" && volts > 6 {
			v.Failure = "overvoltage"
		}
		if k >= from {
			counted++
			if math.Abs(volts-5) <= 0.1 {
				inBand++
			}
		}
	}
	if v.Failure == "" && inBand == 0 {
		v.Failure = "never_regulated"
	}
	if v.Failure == "" {
		v.Score = float64(inBand) / float64(counted)
	}
	return v
}

// scenarioRow is one scenario as the page shows it and embeds it.
type scenarioRow struct {
	ID          string  `json:"id"`
	InputV      float64 `json:"input_v"`
	LoadOhm     float64 `json:"load_ohm"`
	StepMs      float64 `json:"step_ms"`
	Score       float64 `json:"score"`
	MaxV        float64 `json:"max_v"`
	MaxI        float64 `json:"max_abs_i"`
	Fingerprint string  `json:"fingerprint"`
	SecondRun   string  `json:"second_run"`
	JavaScript  string  `json:"javascript"`
	Identical   bool    `json:"identical_to_javascript"`
}

// trace is the replayed scenario, column by column, for the chart; each value is
// shortest-round-trip, so the page holds the record's exact doubles.
type trace struct {
	TickS float64   `json:"tick_s"`
	V     []float64 `json:"v"`
	I     []float64 `json:"i"`
	Duty  []float64 `json:"duty"`
}

// sample is one row of the page's table view: the replayed trace every millisecond.
type sample struct {
	Ms   string
	V    string
	I    string
	Duty string
}

func render(fx fixture, runs []result, rows []scenarioRow, replay []byte) ([]byte, error) {
	n := len(replay) / 8 / (width + 1)
	tr := trace{TickS: fx.TickS}
	for k := 0; k < n; k++ {
		tr.V = append(tr.V, at(replay, k, 0))
		tr.I = append(tr.I, at(replay, k, 1))
		tr.Duty = append(tr.Duty, at(replay, k, 2))
	}
	var samples []sample
	every := int(math.Round(0.001 / fx.TickS))
	for k := 0; k < n; k += every {
		samples = append(samples, sample{
			Ms: num(round(float64(k) * fx.TickS * 1000)), V: strconv.FormatFloat(tr.V[k], 'f', 4, 64),
			I: strconv.FormatFloat(tr.I[k], 'f', 4, 64), Duty: strconv.FormatFloat(tr.Duty[k], 'f', 4, 64),
		})
	}
	data := struct {
		Wasm      map[string]any `json:"wasm"`
		Scenarios []scenarioRow  `json:"scenarios"`
		Replay    string         `json:"replay"`
		Trace     trace          `json:"trace"`
	}{
		Wasm:      map[string]any{"sha256": runs[0].wasmSHA256, "bytes": runs[0].wasmBytes, "second_run": runs[1].wasmSHA256, "build": fx.Build},
		Scenarios: rows,
		Replay:    rows[0].ID,
		Trace:     tr,
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	minScore, maxScore := rows[0].Score, rows[0].Score
	peakV, peakI := 0.0, 0.0
	for _, r := range rows {
		minScore, maxScore = math.Min(minScore, r.Score), math.Max(maxScore, r.Score)
		peakV, peakI = math.Max(peakV, r.MaxV), math.Max(peakI, r.MaxI)
	}
	t, err := template.New("page").Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = t.Execute(&b, map[string]any{
		"Date":        time.Now().Format("2006-01-02"),
		"Isolation":   runs[0].isolation,
		"Build":       html.EscapeString(fx.Build),
		"WasmSHA256":  runs[0].wasmSHA256,
		"WasmBytes":   runs[0].wasmBytes,
		"BuildMs":     runs[0].buildMs,
		"Count":       len(rows),
		"MinScore":    strconv.FormatFloat(minScore, 'f', 3, 64),
		"MaxScore":    strconv.FormatFloat(maxScore, 'f', 3, 64),
		"Floor":       num(fx.MinScore),
		"PeakV":       strconv.FormatFloat(peakV, 'f', 2, 64),
		"PeakI":       strconv.FormatFloat(peakI, 'f', 2, 64),
		"Rows":        rows,
		"Replay":      rows[0],
		"Samples":     samples,
		"Source":      html.EscapeString(controllerC),
		"Reference":   html.EscapeString(referenceJS),
		"Data":        string(raw),
		"Description": fmt.Sprintf("A buck converter controller in C, compiled to WebAssembly in plimsoll's sandbox and judged on a simulated power supply: identical to its JavaScript law in all %d scenarios.", len(rows)),
	})
	return b.Bytes(), err
}
