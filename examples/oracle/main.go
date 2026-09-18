// Command oracle is the physics oracle demo (docs/architecture/oracle-demo-plan.md):
// an agent writes a controller, plimsoll runs it against a compiled cart-pole
// plant, and the trajectory's fingerprint is the acceptance test.
//
// It builds plimsolld from this checkout, starts it on loopback with the docker
// provider and the module image as the project image (so the image's judge,
// /oracle/run.mjs, and its plant, /models/cartpole.wasm, are what run), then sends
// three ordinary project runs through the official client: the accepted controller
// twice and the agent's draft once. Each run's only file is the controller; the
// judge runs it as a separate process, records every 10 ms tick, and the artifact
// it writes is hashed here. The page it renders replays the recorded trajectories.
//
//	make docker-images && go run ./examples/oracle
//
// Needs docker. Writes docs/examples/oracle/index.html (override with -out).
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

//go:embed page.html
var pageTemplate string

//go:embed controllers/accepted.js
var acceptedSource string

//go:embed controllers/draft.js
var draftSource string

const (
	ticks = 2000 // 20 s at 10 ms
	width = 4    // x, v, theta, omega; the judge appends the force
	step  = "node --no-warnings /oracle/run.mjs controller.js"
)

// verdict is the judge's one stdout line.
type verdict struct {
	Fingerprint string   `json:"fingerprint"`
	Ticks       int      `json:"ticks"`
	FellAt      *float64 `json:"fell_at"`
	FinalX      float64  `json:"final_x"`
	FinalTheta  float64  `json:"final_theta"`
}

// run is one judged controller: what the judge said, what the artifact hashed to,
// and the trajectory decoded for the page.
type run struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	FellAt      *float64  `json:"fell_at"`
	FinalX      float64   `json:"final_x"`
	FinalTheta  float64   `json:"final_theta"`
	X           []float64 `json:"x"`
	Theta       []float64 `json:"theta"`
	Force       []float64 `json:"force"`
	Isolation   string    `json:"isolation"`
	DurationMs  int64     `json:"duration_ms"`
}

func main() {
	out := flag.String("out", filepath.Join("docs", "examples", "oracle", "index.html"), "page to write")
	image := flag.String("image", "plimsoll/sandbox-sim:latest", "module image carrying the plant and the judge")
	flag.Parse()
	if err := realMain(*out, *image); err != nil {
		fmt.Fprintln(os.Stderr, "oracle:", err)
		os.Exit(1)
	}
}

func realMain(out, image string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "plimsoll-oracle-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	binary, err := buildDaemon(ctx, dir)
	if err != nil {
		return err
	}
	token, clientsPath, err := writeClients(dir, "oracle")
	if err != nil {
		return err
	}
	addr, err := freeAddr()
	if err != nil {
		return err
	}
	var audit bytes.Buffer
	daemon, err := startDaemon(ctx, binary, addr, clientsPath, image, &audit)
	if err != nil {
		return err
	}
	defer stop(daemon)
	baseURL := "http://" + addr
	if err := waitForReady(ctx, baseURL); err != nil {
		return fmt.Errorf("daemon never became ready: %w\n%s", err, audit.String())
	}

	remote, err := client.New(baseURL, client.WithToken(token))
	if err != nil {
		return err
	}
	info, err := remote.Describe(ctx)
	if err != nil {
		return fmt.Errorf("describe: %w", err)
	}
	fmt.Printf("daemon    | provider=%s isolation=%s protocol=%d\n", info.Sandbox, info.Isolation, info.Protocol)

	accepted1, err := judge(ctx, remote, "accepted, run 1", acceptedSource)
	if err != nil {
		return err
	}
	accepted2, err := judge(ctx, remote, "accepted, run 2", acceptedSource)
	if err != nil {
		return err
	}
	draft, err := judge(ctx, remote, "draft", draftSource)
	if err != nil {
		return err
	}
	for _, r := range []run{accepted1, accepted2, draft} {
		fell := "balanced for 20 s"
		if r.FellAt != nil {
			fell = fmt.Sprintf("fell at %.2f s", *r.FellAt)
		}
		fmt.Printf("%-16s| %s  %s  final x %+.4f m, theta %+.2e rad  (%s tier, %d ms)\n", r.Name, r.Fingerprint[:16], fell, r.FinalX, r.FinalTheta, r.Isolation, r.DurationMs)
	}
	if accepted1.Fingerprint != accepted2.Fingerprint {
		return fmt.Errorf("the accepted controller gave two fingerprints: %s and %s", accepted1.Fingerprint, accepted2.Fingerprint)
	}
	if draft.Fingerprint == accepted1.Fingerprint {
		return errors.New("the draft controller matched the accepted fingerprint")
	}
	divergeAt := firstDifference(accepted1, draft)
	fmt.Printf("verdict   | run 1 = run 2 (identical); draft differs from tick %d (t = %.2f s)\n", divergeAt, float64(divergeAt)*0.01)

	page, err := render(accepted1, accepted2, draft, divergeAt, info.Isolation.String())
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

// judge sends one controller through the project API and hashes the artifact.
func judge(ctx context.Context, remote *client.Remote, name, source string) (run, error) {
	res, err := remote.RunProject(ctx, sandbox.ProjectRequest{
		Files:     []sandbox.File{{Path: "controller.js", Content: source}},
		Steps:     []string{step},
		Artifacts: []string{"trajectory.bin"},
		Timeout:   60 * time.Second,
	})
	if err != nil {
		return run{}, fmt.Errorf("%s: %w", name, err)
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		return run{}, fmt.Errorf("%s: the judge did not complete: outcome %s (%s), steps %+v", name, res.Outcome, res.Detail, res.Steps)
	}
	if len(res.Artifacts) != 1 {
		return run{}, fmt.Errorf("%s: %d artifacts, want the trajectory", name, len(res.Artifacts))
	}
	var v verdict
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Steps[0].Stdout)), &v); err != nil {
		return run{}, fmt.Errorf("%s: judge stdout %q: %w", name, res.Steps[0].Stdout, err)
	}
	sum := sha256.Sum256(res.Artifacts[0].Content)
	r := run{Name: name, Fingerprint: hex.EncodeToString(sum[:]), FellAt: v.FellAt, FinalX: v.FinalX, FinalTheta: v.FinalTheta,
		Isolation: res.Isolation.String(), DurationMs: sumDurations(res.Steps)}
	if r.Fingerprint != v.Fingerprint {
		return run{}, fmt.Errorf("%s: the judge printed %s but the artifact hashes to %s", name, v.Fingerprint, r.Fingerprint)
	}
	r.X, r.Theta, r.Force, err = decode(res.Artifacts[0].Content)
	if err != nil {
		return run{}, fmt.Errorf("%s: %w", name, err)
	}
	return r, nil
}

func sumDurations(steps []sandbox.StepResult) int64 {
	var ms int64
	for _, s := range steps {
		ms += s.Duration.Milliseconds()
	}
	return ms
}

// decode reads the judge's record: per tick x, v, theta, omega, force as
// little-endian float64. The page keeps x, theta and the force, rounded for
// display; the fingerprint is of the exact bytes.
func decode(b []byte) (x, theta, force []float64, err error) {
	per := (width + 1) * 8
	if len(b) != ticks*per {
		return nil, nil, nil, fmt.Errorf("trajectory is %d bytes, want %d", len(b), ticks*per)
	}
	for k := 0; k < ticks; k++ {
		row := b[k*per:]
		f := func(i int) float64 { return math.Float64frombits(binary.LittleEndian.Uint64(row[8*i:])) }
		x = append(x, round(f(0)))
		theta = append(theta, round(f(2)))
		force = append(force, round(f(4)))
	}
	return x, theta, force, nil
}

func round(v float64) float64 { return math.Round(v*1e6) / 1e6 }

// firstDifference is the first tick at which two runs' recorded states differ.
func firstDifference(a, b run) int {
	for k := range a.X {
		if a.X[k] != b.X[k] || a.Theta[k] != b.Theta[k] {
			return k
		}
	}
	return len(a.X)
}

func render(accepted1, accepted2, draft run, divergeAt int, isolation string) ([]byte, error) {
	data, err := json.Marshal(map[string]any{
		"h": 0.01, "ticks": ticks,
		"accepted": accepted1, "draft": draft,
		"accepted_second_fingerprint": accepted2.Fingerprint,
		"diverge_tick": divergeAt,
	})
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("page").Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]any{
		"Data":           string(data),
		"AcceptedSource": html.EscapeString(acceptedSource),
		"DraftSource":    html.EscapeString(draftSource),
		"Isolation":      html.EscapeString(isolation),
		"Date":           time.Now().Format("2006-01-02"),
	})
	return buf.Bytes(), err
}

// --- the loopback daemon ----------------------------------------------------------

func buildDaemon(ctx context.Context, dir string) (string, error) {
	binary := filepath.Join(dir, "plimsolld")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/plimsolld")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build plimsolld (run this from the repository root): %w", err)
	}
	return binary, nil
}

func writeClients(dir, callerID string) (token, path string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	path = filepath.Join(dir, "clients.json")
	body := fmt.Sprintf(`{"clients":[{"id":%q,"token_sha256":%q,"scopes":["code:run"]}]}`, callerID, hex.EncodeToString(sum[:]))
	return token, path, os.WriteFile(path, []byte(body), 0o600)
}

func freeAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

func startDaemon(ctx context.Context, binary, addr, clientsPath, image string, sink io.Writer) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, binary)
	env := append(os.Environ(),
		"SANDBOX_PROVIDER=docker",
		"SANDBOX_DOCKER_PROJECT_IMAGE="+image,
		"PLIMSOLL_ADDR="+addr,
		"PLIMSOLL_CLIENTS_FILE="+clientsPath,
	)
	// The shipped syscall allowlist, when this runs from the checkout: the judge
	// and its child process must work under the same profile a deployment uses.
	if abs, err := filepath.Abs(filepath.Join("docker", "seccomp.json")); err == nil {
		if _, err := os.Stat(abs); err == nil && os.Getenv("SANDBOX_DOCKER_SECCOMP") == "" {
			env = append(env, "SANDBOX_DOCKER_SECCOMP="+abs)
		}
	}
	cmd.Env = env
	cmd.Stdout = io.MultiWriter(os.Stderr, sink)
	cmd.Stderr = io.MultiWriter(os.Stderr, sink)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start plimsolld: %w", err)
	}
	return cmd, nil
}

func stop(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

func waitForReady(ctx context.Context, baseURL string) error {
	deadline := time.Now().Add(90 * time.Second) // the docker provider's startup smoke test launches containers
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/readyz", nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("timed out waiting for /readyz")
}
