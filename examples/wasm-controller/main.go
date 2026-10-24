// Command wasm-controller runs and scores a controller written in C: the project run
// compiles it to WebAssembly inside the sandbox, then runs it against the
// cart-pole plant, which is WebAssembly too. See README.md for what this proves
// and what it does not.
//
// It builds plimsolld from this checkout, starts it on loopback with the docker
// provider and plimsoll/sandbox-wasm-cc as the project image, and sends ordinary
// project runs through the official client. The C run's files are controller.c and
// controller.js (the Node shim the runner spawns as the controller process, shared
// with the other C example from examples/internal/wasmshim); its
// first step compiles controller.c with the image's wasi-sdk, and one step per
// swing-up scenario runs /oracle/judge.mjs against /models/cartpole.wasm. Each
// trajectory comes back as an artifact and is hashed here, scored, and compared.
//
// Four runs: the C build twice (the compile and every trajectory must repeat), the
// same C built so that cos is Node's Math.cos, and reference.js, the JavaScript law
// the C is a port of. The last two must agree on every fingerprint; where the first
// parts from them, the page shows the tick and the two pole-angle traces.
//
//	make docker-images && go run ./examples/wasm-controller
//
// Needs docker. Writes docs/examples/wasm-controller/index.html (override with -out).
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

	"github.com/plimsollmark/plimsoll/examples/internal/daemonproc"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/examples/internal/grade"
	"github.com/plimsollmark/plimsoll/examples/internal/wasmshim"
	"github.com/plimsollmark/plimsoll/record"
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

const (
	width = 4   // x, v, theta, omega; the runner appends the force
	track = 2.4 // metres either side of centre; leaving it scores zero
	// uprightCos is the score's upright test: cos theta above it.
	uprightCos = 0.98
)

var columns = [width + 1]string{"x", "v", "theta", "omega", "force"}

// fixture is fingerprints.json: the build steps, the scenarios, and what a run of
// the built image recorded for each.
type fixture struct {
	Build                string  `json:"build"`
	MathCosBuild         string  `json:"math_cos_build"`
	ControllerWasmSHA256 string  `json:"controller_wasm_sha256"`
	TickS                float64 `json:"tick_s"`
	TEndS                float64 `json:"t_end_s"`
	MinScore             float64 `json:"min_score"`
	Scenarios            []struct {
		ID                 string     `json:"id"`
		Params             [3]float64 `json:"params"`
		Fingerprint        string     `json:"fingerprint"`
		MathCosFingerprint string     `json:"math_cos_fingerprint"`
	} `json:"scenarios"`
}

// judged is one scenario of one run: the trajectory's fingerprint and its exact bytes.
type judged struct {
	fingerprint string
	trajectory  []byte
}

// verdict is the line the swing-up environment's grader prints: docker/sim/graders/
// cartpole-swingup.mjs, shipped in the simulation image the project image is built on
// and run by grade.Run in a run of its own. failure is null on a pass, and t_up, when
// the final upright stretch began, is null when there was none.
type verdict struct {
	Score   float64  `json:"score"`
	Failure *string  `json:"failure"`
	TUp     *float64 `json:"t_up"`
}

// result is one project run: the compiled module's hash (when the run compiled
// one), each scenario's fingerprint, record and score, and the evidence the run reported.
type result struct {
	wasmSHA256 string
	wasmBytes  int
	scenarios  map[string]judged
	isolation  string
	buildMs    int64
	judgeMs    int64
}

func main() {
	out := flag.String("out", filepath.Join("docs", "examples", "wasm-controller", "index.html"), "page to write")
	image := flag.String("image", "plimsoll/sandbox-wasm-cc:latest", "project image carrying the C toolchain, the plant and the runner")
	flag.Parse()
	if err := realMain(*out, *image); err != nil {
		fmt.Fprintln(os.Stderr, "wasm-controller:", err)
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
	// The shim with one change: the module may import env.host_cos, bound to V8's
	// Math.cos. The fixture's math_cos_build compiles controller.c with
	// -Dcos=host_cos, so that module's cos is the JavaScript one.
	// sandbox/docker_wasm_controller_test.go derives the same shim the same way.
	mathCos, err := wasmshim.WithImports("{ env: { host_cos: Math.cos } }")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "plimsoll-wasm-controller-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	binary, err := daemonproc.Build(ctx, dir)
	if err != nil {
		return err
	}
	token, clientsPath, err := daemonproc.ClientsFile(dir, "wasm-controller")
	if err != nil {
		return err
	}
	env := []string{"SANDBOX_PROVIDER=docker", "SANDBOX_DOCKER_PROJECT_IMAGE=" + image, "PLIMSOLL_CLIENTS_FILE=" + clientsPath}
	// The shipped syscall allowlist, when this runs from the checkout: the compiler, the
	// runner and the controller process must all work under the profile a deployment uses.
	if abs, err := filepath.Abs(filepath.Join("docker", "seccomp.json")); err == nil {
		if _, err := os.Stat(abs); err == nil && os.Getenv("SANDBOX_DOCKER_SECCOMP") == "" {
			env = append(env, "SANDBOX_DOCKER_SECCOMP="+abs)
		}
	}
	// 90 s: the docker provider's startup smoke test launches containers. The daemon's
	// log is kept, and shown only if it never becomes ready.
	var audit bytes.Buffer
	daemon, err := daemonproc.Start(ctx, binary, daemonproc.Options{Env: env, Ready: 90 * time.Second, Log: &audit})
	if err != nil {
		return fmt.Errorf("%w\n%s", err, audit.String())
	}
	defer func() { _ = daemon.Stop(5 * time.Second) }()
	baseURL := daemon.BaseURL

	remote, err := client.New(baseURL, client.WithToken(token))
	if err != nil {
		return err
	}
	info, err := remote.Describe(ctx)
	if err != nil {
		return fmt.Errorf("describe: %w", err)
	}
	fmt.Printf("daemon    | provider=%s isolation=%s protocol=%d\n", info.Sandbox, info.Isolation, info.Protocol)
	fmt.Printf("build     | %s\n", fx.Build)

	cFiles := []sandbox.File{{Path: "controller.c", Content: controllerC}, {Path: "controller.js", Content: wasmshim.Source}}
	var runs []result
	for i := 1; i <= 2; i++ {
		r, err := judge(ctx, remote, fx, cFiles, fx.Build, "controller.js")
		if err != nil {
			return fmt.Errorf("C run %d: %w", i, err)
		}
		fmt.Printf("run %d     | controller.wasm %d bytes, sha256 %s  (compile %d ms, trials %d ms, %s tier)\n", i, r.wasmBytes, r.wasmSHA256[:16], r.buildMs, r.judgeMs, r.isolation)
		runs = append(runs, r)
	}
	hostCos, err := judge(ctx, remote, fx, []sandbox.File{{Path: "controller.c", Content: controllerC}, {Path: "controller.js", Content: mathCos}}, fx.MathCosBuild, "controller.js")
	if err != nil {
		return fmt.Errorf("C run with Math.cos: %w", err)
	}
	fmt.Printf("math.cos  | %s\n", fx.MathCosBuild)
	js, err := judge(ctx, remote, fx, []sandbox.File{{Path: "reference.js", Content: referenceJS}}, "", "reference.js")
	if err != nil {
		return fmt.Errorf("JavaScript run: %w", err)
	}

	// The scores are the environment's own grader's, in a run of its own after the
	// runs that made the trajectories; its record binds each score to the trajectory
	// it read.
	var trajs []grade.Trajectory
	for _, s := range fx.Scenarios {
		trajs = append(trajs, grade.Trajectory{ID: s.ID, Bytes: runs[0].scenarios[s.ID].trajectory})
	}
	graded, err := grade.Run(ctx, remote, "cartpole-swingup", fx.TickS, trajs)
	if err != nil {
		return err
	}
	if graded.Result.Record == nil {
		return errors.New("the grading run came back without a run record")
	}
	graderRecord := record.Digest(*graded.Result.Record)
	fmt.Printf("grader    | /oracle/graders/cartpole-swingup.mjs, in a run of its own, run record %s\n", graderRecord)

	var problems []string
	if runs[0].wasmSHA256 != runs[1].wasmSHA256 {
		problems = append(problems, "the two compiles produced different modules")
	}
	if runs[0].wasmSHA256 != fx.ControllerWasmSHA256 {
		problems = append(problems, fmt.Sprintf("controller.wasm is %s, fingerprints.json records %s", runs[0].wasmSHA256, fx.ControllerWasmSHA256))
	}
	var rows []scenarioRow
	for _, s := range fx.Scenarios {
		a, b := runs[0].scenarios[s.ID], runs[1].scenarios[s.ID]
		hc, j := hostCos.scenarios[s.ID], js.scenarios[s.ID]
		same := "run 1 = run 2"
		if a.fingerprint != b.fingerprint {
			same = "RUNS DIFFER"
			problems = append(problems, s.ID+": the two runs gave different fingerprints")
		}
		recorded := "= recorded"
		if a.fingerprint != s.Fingerprint {
			recorded = "NOT recorded"
			problems = append(problems, fmt.Sprintf("%s: fingerprint %s, fingerprints.json records %s", s.ID, a.fingerprint, s.Fingerprint))
		}
		if hc.fingerprint != j.fingerprint {
			problems = append(problems, fmt.Sprintf("%s: the C built against Math.cos gave %s, the JavaScript law %s; cos is not the whole difference", s.ID, hc.fingerprint, j.fingerprint))
		}
		if hc.fingerprint != s.MathCosFingerprint {
			problems = append(problems, fmt.Sprintf("%s: Math.cos fingerprint %s, fingerprints.json records %s", s.ID, hc.fingerprint, s.MathCosFingerprint))
		}
		var v verdict
		if err := json.Unmarshal(graded.Lines[s.ID], &v); err != nil {
			return fmt.Errorf("%s: the grader printed %s: %w", s.ID, graded.Lines[s.ID], err)
		}
		var held string
		if v.Failure != nil || v.TUp == nil || v.Score < fx.MinScore {
			failure := "none"
			if v.Failure != nil {
				failure = *v.Failure
			}
			held = fmt.Sprintf("FAILED (%s, score %.3f, floor %.2f)", failure, v.Score, fx.MinScore)
			problems = append(problems, s.ID+": "+held)
			v.TUp = new(float64)
		} else {
			held = fmt.Sprintf("upright from %.2f s, score %.3f", *v.TUp, v.Score)
		}
		row := scenarioRow{
			ID: s.ID, Theta0: s.Params[0], HalfLength: s.Params[1], CartMass: s.Params[2],
			Score: round(v.Score), UprightFrom: round(*v.TUp),
			Fingerprint: a.fingerprint, SecondRun: b.fingerprint, MathCos: hc.fingerprint, JavaScript: j.fingerprint,
		}
		row.VsJS = compare(a.trajectory, j.trajectory)
		fmt.Printf("%-10s| theta0 %-7s cart %-4s kg  %s  %s, %s  %s  %s\n", s.ID, num(s.Params[0]), num(s.Params[2]), a.fingerprint[:16], same, recorded, held, row.VsJS)
		rows = append(rows, row)
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}

	// The page replays the first scenario and compares it with the JavaScript law,
	// so that scenario must actually differ from it.
	if len(rows[0].VsJS.Rows) == 0 {
		return fmt.Errorf("%s: the C build and the JavaScript law are identical; the page has no difference to show", rows[0].ID)
	}
	fmt.Println("verdict   | the compile is reproducible, every trajectory has one fingerprint, the pole is up and held in every scenario, and cos is the whole difference from the JavaScript law")

	page, err := render(fx, runs, js, rows, info.Isolation.String(), graderRecord)
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

// judge sends one project run: an optional compile, then one runner step per
// scenario, each running controller (a file of the run) as the controller process.
func judge(ctx context.Context, remote *client.Remote, fx fixture, files []sandbox.File, build, controller string) (result, error) {
	var steps, artifacts []string
	if build != "" {
		steps = append(steps, build)
		artifacts = append(artifacts, "controller.wasm")
	}
	judgeFrom := len(steps)
	files = append([]sandbox.File(nil), files...)
	for _, s := range fx.Scenarios {
		// The runner reads the scenario from a file and deletes it before the controller
		// starts; these scenarios are public, so all four files go up front.
		files = append(files, sandbox.File{Path: s.ID + ".scenario",
			Content: num(s.Params[0]) + " " + num(s.Params[1]) + " " + num(s.Params[2]) + "\n"})
		steps = append(steps, fmt.Sprintf("node --no-warnings /oracle/judge.mjs %s /models/cartpole.wasm %s.scenario %s %s %s.bin",
			controller, s.ID, num(fx.TickS), num(fx.TEndS), s.ID))
		artifacts = append(artifacts, s.ID+".bin")
	}
	res, err := remote.RunProject(ctx, sandbox.ProjectRequest{
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
			return result{}, fmt.Errorf("%s: runner stdout %q: %w", s.ID, step.Stdout, err)
		}
		traj := byPath[s.ID+".bin"]
		if len(traj) != ticks*(width+1)*8 {
			return result{}, fmt.Errorf("%s: trajectory is %d bytes, want %d ticks of %d doubles", s.ID, len(traj), ticks, width+1)
		}
		ts := sha256.Sum256(traj)
		fp := hex.EncodeToString(ts[:])
		if fp != v.Fingerprint {
			return result{}, fmt.Errorf("%s: the runner printed %s but the artifact hashes to %s", s.ID, v.Fingerprint, fp)
		}
		r.scenarios[s.ID] = judged{fingerprint: fp, trajectory: traj}
	}
	return r, nil
}

// at reads column col of tick k from a runner record: per tick x, v, theta, omega,
// force as little-endian float64.
func at(traj []byte, k, col int) float64 {
	return math.Float64frombits(binary.LittleEndian.Uint64(traj[(k*(width+1)+col)*8:]))
}

// rowDiff is one tick at which two records are not byte-identical: which columns
// differ, the angle the C record holds there, and the two forces printed exactly
// (shortest round-trip decimals).
type rowDiff struct {
	Tick    int      `json:"tick"`
	Columns []string `json:"columns"`
	Theta   string   `json:"theta"`
	ForceC  string   `json:"force_c"`
	ForceJS string   `json:"force_js"`
	ULPs    uint64   `json:"ulps"` // how many representable doubles apart the two forces are
}

// comparison is everything that differs between the C build's record of one
// scenario and the JavaScript law's, read from the two records.
type comparison struct {
	Rows []rowDiff `json:"rows"`
	// StateTick is the first tick at which any state column (x, v, theta, omega)
	// differs; nil when the state is byte-identical at every tick.
	StateTick *int `json:"state_tick"`
	// MaxThetaDelta is the largest |theta_C - theta_JS| over the run.
	MaxThetaDelta float64 `json:"max_theta_delta"`
}

func compare(c, js []byte) comparison {
	cmp := comparison{Rows: []rowDiff{}} // an empty list on the page, not null
	n := len(c) / 8 / (width + 1)
	for k := 0; k < n; k++ {
		var cols []string
		for col := 0; col <= width; col++ {
			if math.Float64bits(at(c, k, col)) != math.Float64bits(at(js, k, col)) {
				cols = append(cols, columns[col])
				if col < width && cmp.StateTick == nil {
					t := k
					cmp.StateTick = &t
				}
			}
		}
		if d := math.Abs(at(c, k, 2) - at(js, k, 2)); d > cmp.MaxThetaDelta {
			cmp.MaxThetaDelta = d
		}
		if cols != nil {
			fc, fj := at(c, k, width), at(js, k, width)
			cmp.Rows = append(cmp.Rows, rowDiff{Tick: k, Columns: cols, Theta: num(at(c, k, 2)), ForceC: num(fc), ForceJS: num(fj), ULPs: ulps(fc, fj)})
		}
	}
	return cmp
}

// ulps is the number of representable doubles between a and b.
func ulps(a, b float64) uint64 {
	ordered := func(f float64) int64 {
		i := int64(math.Float64bits(f))
		if i < 0 {
			i = math.MinInt64 - i
		}
		return i
	}
	d := ordered(a) - ordered(b)
	if d < 0 {
		d = -d
	}
	return uint64(d)
}

func (c comparison) String() string {
	if len(c.Rows) == 0 {
		return "= JavaScript"
	}
	ticks := make([]string, len(c.Rows))
	for i, r := range c.Rows {
		ticks[i] = fmt.Sprintf("%d (%s)", r.Tick, strings.Join(r.Columns, ", "))
	}
	state := "state identical at every tick"
	if c.StateTick != nil {
		state = fmt.Sprintf("state differs from tick %d", *c.StateTick)
	}
	return fmt.Sprintf("JavaScript differs at tick %s; %s", strings.Join(ticks, ", "), state)
}

func round(v float64) float64 { return math.Round(v*1e6) / 1e6 }

// scenarioRow is one line of the page's table.
type scenarioRow struct {
	ID          string     `json:"id"`
	Theta0      float64    `json:"theta0"`
	HalfLength  float64    `json:"half_length"`
	CartMass    float64    `json:"cart_mass"`
	Score       float64    `json:"score"`
	UprightFrom float64    `json:"upright_from"`
	Fingerprint string     `json:"fingerprint"`
	SecondRun   string     `json:"second_run"`
	MathCos     string     `json:"math_cos"`
	JavaScript  string     `json:"javascript"`
	VsJS        comparison `json:"vs_javascript"`
}

// replay is the two records of one scenario, rounded for display; the
// fingerprints are of the exact bytes.
type replay struct {
	X       []float64 `json:"x"`
	Theta   []float64 `json:"theta"`
	Force   []float64 `json:"force"`
	ThetaJS []float64 `json:"theta_js"`
}

func decode(c, js []byte) replay {
	var r replay
	n := len(c) / 8 / (width + 1)
	for k := 0; k < n; k++ {
		r.X = append(r.X, round(at(c, k, 0)))
		r.Theta = append(r.Theta, round(at(c, k, 2)))
		r.Force = append(r.Force, round(at(c, k, width)))
		r.ThetaJS = append(r.ThetaJS, round(at(js, k, 2)))
	}
	return r
}

func render(fx fixture, runs []result, js result, rows []scenarioRow, isolation, graderRecord string) ([]byte, error) {
	s1 := fx.Scenarios[0]
	data, err := json.Marshal(map[string]any{
		"h": fx.TickS, "t_end": fx.TEndS, "track": track, "min_score": fx.MinScore, "upright_cos": uprightCos,
		"scenario":  rows[0],
		"replay":    decode(runs[0].scenarios[s1.ID].trajectory, js.scenarios[s1.ID].trajectory),
		"scenarios": rows,
		"wasm": map[string]any{
			"sha256": runs[0].wasmSHA256, "second_sha256": runs[1].wasmSHA256, "bytes": runs[0].wasmBytes,
			"compile_ms": runs[0].buildMs,
		},
	})
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("page").Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	identical := 0
	for _, r := range rows {
		if len(r.VsJS.Rows) == 0 {
			identical++
		}
	}
	cmp := rows[0].VsJS
	state := "the cart and pole are bit-identical at every tick"
	if cmp.StateTick != nil {
		state = fmt.Sprintf("the state parts from tick %d", *cmp.StateTick)
	}
	description := fmt.Sprintf("A cart-pole swing-up controller written in C, compiled to WebAssembly inside a sandbox run and checked by the fingerprint of its trajectory. "+
		"The compile and every trajectory repeat exactly. Against the JavaScript law it was ported from, %d of %d scenarios match to the last bit. "+
		"On %s the records differ in %d of %d rows, first at tick %d, because cos differs in the last bit; %s.",
		identical, len(rows), s1.ID, len(cmp.Rows), len(runs[0].scenarios[s1.ID].trajectory)/8/(width+1), cmp.Rows[0].Tick, state)
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]any{
		"Data":         string(data),
		"Description":  html.EscapeString(description),
		"ControllerC":  html.EscapeString(controllerC),
		"ReferenceJS":  html.EscapeString(referenceJS),
		"Build":        html.EscapeString(fx.Build),
		"MathCosBuild": html.EscapeString(fx.MathCosBuild),
		"Isolation":    html.EscapeString(isolation),
		"Date":         time.Now().Format("2006-01-02"),
		"TickMs":       num(fx.TickS * 1000),
		"TEnd":         num(fx.TEndS),
		"GraderRecord": graderRecord,
	})
	return buf.Bytes(), err
}
