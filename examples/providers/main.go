// Command providers runs the physics oracle's run on every sandbox provider this
// machine can reach and writes a page comparing them: the same controller, the same
// judge, the same plant, and the fingerprint of the trajectory from each provider.
//
// The run is the one examples/oracle publishes: its accepted controller
// (examples/oracle/controllers/accepted.js), its judge (docker/sim/oracle/run.mjs)
// and the cart-pole plant, started 0.2 rad from upright for 20 s. Here the judge and
// the plant travel as ordinary project files instead of image content, so any
// provider whose image has Node 20 or later can run it: the plant is sent base64
// encoded and a first step decodes it. Each provider is built by sandbox.Build, the
// factory plimsolld uses, from an environment of its own, must pass EnsureReady (its
// preflight and startup smoke test) before its run counts, and is then driven
// directly.
//
//	make docker-images && go run ./examples/providers
//
// Needs docker. E2B runs when E2B_API_KEY is set (a paid service; one run costs a
// fraction of a cent). Docker Cloud Sandboxes runs when DOCKER_SBX_TOKEN,
// DOCKER_SBX_USERNAME, SANDBOX_DOCKERCLOUD_API_URL and SANDBOX_DOCKERCLOUD_IMAGE are
// set (billed per second). gVisor runs when docker has the runsc runtime. Providers
// without their configuration are listed on the page as not run, with the reason.
// Writes docs/examples/providers/index.html (override with -out).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

//go:embed page.html
var pageTemplate string

// publishedFingerprint is the accepted controller's fingerprint as published on the
// oracle page (docs/examples/oracle/index.html). Every provider is checked against it.
const publishedFingerprint = "63cfd676924a3896127d60c97333677f3b3c804dd764dba001121f6c234a937f"

const decodeSource = `import { readFileSync, writeFileSync } from 'node:fs';
writeFileSync('cartpole.wasm', Buffer.from(readFileSync('cartpole.b64', 'utf8'), 'base64'));
`

var steps = []string{
	"node --version",
	"node decode.mjs",
	"node --no-warnings run.mjs controller.js cartpole.wasm 0.2 20 trajectory.bin",
}

type target struct {
	Key, Name, Where string
	Env              map[string]string
	Skip             string // non-empty: not run, and why
}

type row struct {
	Name, Where, Tier, Node, Fingerprint, Skip, Error string
	Matches                                           bool
	DurationMs                                        int64
}

type verdict struct {
	Fingerprint string   `json:"fingerprint"`
	FellAt      *float64 `json:"fell_at"`
	FinalX      float64  `json:"final_x"`
}

func main() {
	out := flag.String("out", filepath.Join("docs", "examples", "providers", "index.html"), "page to write")
	simImage := flag.String("sim-image", "plimsoll/sandbox-sim:latest", "image to read the cart-pole plant from")
	flag.Parse()
	if err := realMain(*out, *simImage); err != nil {
		fmt.Fprintln(os.Stderr, "providers:", err)
		os.Exit(1)
	}
}

func realMain(out, simImage string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	controller, err := os.ReadFile(filepath.Join("examples", "oracle", "controllers", "accepted.js"))
	if err != nil {
		return fmt.Errorf("run from the repository root: %w", err)
	}
	judgeSrc, err := os.ReadFile(filepath.Join("docker", "sim", "oracle", "run.mjs"))
	if err != nil {
		return err
	}
	plant, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", simImage, "/models/cartpole.wasm").Output()
	if err != nil {
		return fmt.Errorf("read the plant from %s (make docker-images): %w", simImage, err)
	}
	plantSum := sha256.Sum256(plant)
	files := []sandbox.File{
		// Marks controller.js as an ES module. Node 22 detects module syntax in a .js
		// file on its own; Node 20 (E2B's default template, 20.9 when this was
		// written) does not and fails on the first import.
		{Path: "package.json", Content: `{"type": "module"}` + "\n"},
		{Path: "controller.js", Content: string(controller)},
		{Path: "run.mjs", Content: string(judgeSrc)},
		{Path: "decode.mjs", Content: decodeSource},
		{Path: "cartpole.b64", Content: base64.StdEncoding.EncodeToString(plant)},
	}

	var rows []row
	var trajectory []byte
	for _, t := range targets() {
		r := row{Name: t.Name, Where: t.Where, Skip: t.Skip}
		if t.Skip == "" {
			traj, err := runOn(ctx, t, files, &r)
			if err != nil {
				r.Error = err.Error()
			} else if trajectory == nil {
				trajectory = traj
			}
		}
		status := r.Skip
		if status == "" {
			status = r.Error
		}
		if status == "" {
			status = fmt.Sprintf("%s tier, node %s, %s, matches published: %v", r.Tier, r.Node, r.Fingerprint[:16], r.Matches)
		}
		fmt.Printf("%-24s| %s\n", t.Name, status)
		rows = append(rows, r)
	}
	if trajectory == nil {
		return errors.New("no provider completed the run")
	}
	for _, r := range rows {
		if r.Error == "" && r.Skip == "" && !r.Matches {
			return fmt.Errorf("%s produced %s, not the published %s", r.Name, r.Fingerprint, publishedFingerprint)
		}
	}
	page, err := render(rows, trajectory, hex.EncodeToString(plantSum[:]))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(out, page, 0o644); err != nil {
		return err
	}
	fmt.Printf("page                    | %s (%d bytes)\n", out, len(page))
	return nil
}

// targets lists every provider, with the environment that builds it or the reason
// it is not run on this machine.
func targets() []target {
	docker := map[string]string{
		"SANDBOX_PROVIDER":             "docker",
		"SANDBOX_DOCKER_PROJECT_IMAGE": "plimsoll/sandbox:latest",
		"SANDBOX_DOCKER_SECCOMP":       filepath.Join("docker", "seccomp.json"),
	}
	gvisor := map[string]string{"SANDBOX_DOCKER_RUNTIME": "runsc"}
	for k, v := range docker {
		gvisor[k] = v
	}
	ts := []target{
		{Key: "docker", Name: "Docker, locked down (runc)", Where: "this machine", Env: docker},
		{Key: "gvisor", Name: "Docker with gVisor (runsc)", Where: "this machine", Env: gvisor},
		{Key: "e2b", Name: "E2B Firecracker microVM", Where: "E2B's cloud", Env: map[string]string{
			"SANDBOX_PROVIDER": "e2b", "E2B_API_KEY": os.Getenv("E2B_API_KEY"), "E2B_TEMPLATE": os.Getenv("E2B_TEMPLATE")}},
		{Key: "dockercloud", Name: "Docker Cloud Sandboxes", Where: "Docker's cloud", Env: map[string]string{
			"SANDBOX_PROVIDER":             "dockercloud",
			"DOCKER_SBX_TOKEN":             os.Getenv("DOCKER_SBX_TOKEN"),
			"DOCKER_SBX_USERNAME":          os.Getenv("DOCKER_SBX_USERNAME"),
			"SANDBOX_DOCKERCLOUD_API_URL":  os.Getenv("SANDBOX_DOCKERCLOUD_API_URL"),
			"SANDBOX_DOCKERCLOUD_AUTH_URL": os.Getenv("SANDBOX_DOCKERCLOUD_AUTH_URL"),
			"SANDBOX_DOCKERCLOUD_IMAGE":    os.Getenv("SANDBOX_DOCKERCLOUD_IMAGE"),
			"SANDBOX_CPUS":                 "1",
			"SANDBOX_MEMORY_MB":            "2048",
		}},
		{Key: "wasm", Name: "WebAssembly (in-process QuickJS)", Where: "inside the daemon",
			Skip: "snippets only: the process tier runs no multi-file projects, so it cannot host the judge"},
	}
	for i := range ts {
		switch ts[i].Key {
		case "gvisor":
			if !dockerHasRuntime("runsc") {
				ts[i].Skip = "docker on the machine that wrote this page has no runsc runtime (docker/install-gvisor.sh installs it, as root)"
			}
		case "e2b":
			if ts[i].Env["E2B_API_KEY"] == "" {
				ts[i].Skip = "E2B_API_KEY was not set"
			}
		case "dockercloud":
			if ts[i].Env["DOCKER_SBX_TOKEN"] == "" || ts[i].Env["SANDBOX_DOCKERCLOUD_IMAGE"] == "" {
				ts[i].Skip = "Docker Cloud credentials or image were not set"
			}
		}
	}
	return ts
}

func dockerHasRuntime(name string) bool {
	out, err := exec.Command("docker", "info", "--format", "{{json .Runtimes}}").Output()
	if err != nil {
		return false
	}
	var rt map[string]any
	return json.Unmarshal(out, &rt) == nil && rt[name] != nil
}

// runOn builds one provider from its own environment, proves it ready, and runs the
// oracle run on it. The environment never falls back to the process environment,
// so one provider's settings cannot leak into another's.
func runOn(ctx context.Context, t target, files []sandbox.File, r *row) ([]byte, error) {
	p, err := sandbox.Build(func(k string) string { return t.Env[k] })
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	if err := p.EnsureReady(ctx); err != nil {
		return nil, fmt.Errorf("not ready: %w", err)
	}
	res, err := p.Sandbox.RunProject(ctx, sandbox.ProjectRequest{
		Files: files, Steps: steps, Artifacts: []string{"trajectory.bin"}, Timeout: 90 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("run: %w", err)
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != len(steps) || len(res.Artifacts) != 1 {
		detail := ""
		for _, st := range res.Steps {
			detail += fmt.Sprintf("; %q exit %d stderr %q", st.Command, st.ExitCode, strings.TrimSpace(st.Stderr))
		}
		return nil, fmt.Errorf("the judge did not complete: outcome %s (%s), %d of %d steps, %d artifacts%s",
			res.Outcome, res.Detail, len(res.Steps), len(steps), len(res.Artifacts), detail)
	}
	for _, s := range res.Steps {
		if s.ExitCode != 0 {
			return nil, fmt.Errorf("step %q exited %d: %s", s.Command, s.ExitCode, strings.TrimSpace(s.Stderr))
		}
		r.DurationMs += s.Duration.Milliseconds()
	}
	var v verdict
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Steps[2].Stdout)), &v); err != nil {
		return nil, fmt.Errorf("judge stdout %q: %w", res.Steps[2].Stdout, err)
	}
	sum := sha256.Sum256(res.Artifacts[0].Content)
	r.Fingerprint = hex.EncodeToString(sum[:])
	if r.Fingerprint != v.Fingerprint {
		return nil, fmt.Errorf("the judge printed %s but the artifact hashes to %s", v.Fingerprint, r.Fingerprint)
	}
	r.Tier = res.Isolation.String()
	r.Node = strings.TrimSpace(res.Steps[0].Stdout)
	r.Matches = r.Fingerprint == publishedFingerprint
	return res.Artifacts[0].Content, nil
}

// decode reads the judge's record: per tick x, v, theta, omega, force as float64.
func decode(b []byte) (x, theta, force []float64, err error) {
	const width = 5
	if len(b)%(8*width) != 0 {
		return nil, nil, nil, fmt.Errorf("trajectory of %d bytes is not whole ticks", len(b))
	}
	for i := 0; i < len(b); i += 8 * width {
		f := func(j int) float64 {
			var u uint64
			for k := 7; k >= 0; k-- {
				u = u<<8 | uint64(b[i+8*j+k])
			}
			return math.Round(math.Float64frombits(u)*1e6) / 1e6
		}
		x, theta, force = append(x, f(0)), append(theta, f(2)), append(force, f(4))
	}
	return x, theta, force, nil
}

func render(rows []row, trajectory []byte, plantSum string) ([]byte, error) {
	x, theta, force, err := decode(trajectory)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(map[string]any{"h": 0.01, "ticks": len(x), "x": x, "theta": theta, "force": force})
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("page").Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]any{
		"Rows": rows, "Published": publishedFingerprint, "PlantSum": plantSum,
		"Date": time.Now().UTC().Format("2006-01-02"), "Data": template.JS(data),
	})
	return buf.Bytes(), err
}
