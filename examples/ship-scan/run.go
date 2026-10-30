package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/examples/internal/daemonproc"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// simPy is the toy harness's simulator: what a grader keeps and an agent must never
// read, since the hidden cases can be worked out from it. 28 of its lines are
// distinctive (docs/ship-scan.md, "Source entries"), so its source entry needs 10.
const simPy = `"""Plant simulator for the hover task: the grader's copy, never the agent's."""
import math
import random

DRAG_COEFFICIENT = 0.4127
GRAVITY_MPS2 = 9.80665
ROTOR_LAG_SECONDS = 0.0815
GUST_TABLE = [0.18, 0.41, 0.07, 0.33, 0.26, 0.12, 0.38]


def gust_at(time_seconds, seed):
    rng = random.Random(seed * 7919 + int(time_seconds * 1000))
    base = GUST_TABLE[int(time_seconds * 5) % len(GUST_TABLE)]
    return base * rng.gauss(0.0, 1.0)


def rotor_response(command, previous_thrust, dt):
    blend = dt / (ROTOR_LAG_SECONDS + dt)
    return previous_thrust + blend * (command - previous_thrust)


def step(state, command, dt, seed):
    altitude, climb_rate, thrust, time_seconds = state
    thrust = rotor_response(command, thrust, dt)
    accel = thrust - GRAVITY_MPS2 - DRAG_COEFFICIENT * climb_rate * abs(climb_rate)
    accel += gust_at(time_seconds, seed)
    climb_rate_next = climb_rate + dt * accel
    altitude_next = max(0.0, altitude + dt * climb_rate_next)
    return (altitude_next, climb_rate_next, thrust, time_seconds + dt)


def score(trajectory, target_altitude):
    errors = [abs(point[0] - target_altitude) for point in trajectory]
    settled = [err for err in errors[len(errors) // 2:] if err < 0.25]
    return len(settled) / max(1, len(errors) - len(errors) // 2)


def fly(controller, seed, target_altitude=10.0, steps=400, dt=0.02):
    state = (0.0, 0.0, 0.0, 0.0)
    trajectory = []
    for _ in range(steps):
        command = controller(state[0], state[1], target_altitude)
        state = step(state, command, dt, seed)
        trajectory.append(state)
    return score(trajectory, target_altitude)
`

// cleanJS is an agent's controller that carries nothing withheld: a PD loop on a toy
// plant of its own.
const cleanJS = `// A PD controller on the agent's own toy plant, 200 steps.
let altitude = 0, climb = 0;
const target = 10, kp = 0.8, kd = 1.6, dt = 0.05;
for (let i = 0; i < 200; i++) {
  const thrust = kp * (target - altitude) - kd * climb;
  climb += dt * (thrust - 0.3 * climb);
  altitude += dt * climb;
}
console.log("final altitude " + altitude.toFixed(3) + " (target 10)");
`

// agentJS is an agent's controller tuned on a hidden seed it should never have had:
// the seed rides in its code. %s is the seed.
const agentJS = `// The agent's controller, tuned on the one case it was shown by mistake.
const TUNED_ON = %s;
const gain = 0.8 + (TUNED_ON %% 7) / 100;
console.log("gain " + gain.toFixed(2));
`

// buildLine is the set's build command as a reader types it, in the work directory.
var buildArgs = []string{"build", "-mode", "refuse", "-file", "harness/", "-source", "harness/", "-source-mode", "refuse",
	"-values", "seeds.txt", "-values-mode", "audit"}

func runAndPublish(ctx context.Context, out string) error {
	work, err := filepath.Abs(filepath.Join("tmp", "ship-scan-run"))
	if err != nil {
		return err
	}
	if _, err := os.Stat("go.mod"); err != nil {
		return errors.New("run it from the root of a plimsoll checkout: it builds plimsolld and plimsoll-withheld from source")
	}
	if err := os.RemoveAll(work); err != nil {
		return err
	}
	// The seeds live only in the work directory, and it goes when the run ends: the page
	// says they were deleted.
	defer func() { _ = os.RemoveAll(work) }()
	ev, secrets, ex, err := run(ctx, work)
	if err != nil {
		return err
	}
	if err := checkEvidence(ev, ex); err != nil {
		return fmt.Errorf("the run does not show what the page claims: %w", err)
	}
	return publish(out, ev, ex, secrets)
}

// exchange is the set file the daemon loaded, the clean call's request and response as
// the client checked them, and the audit-mode call's response.
type exchange struct {
	set          []byte
	request      []byte
	response     []byte
	seedResponse []byte
}

// run writes the harness and its seeds, builds the set as a reader would, starts the
// daemon, sends the five calls and the offline scans, and returns the evidence and the
// secrets the published files must never hold.
func run(ctx context.Context, work string) (*Evidence, []string, *exchange, error) {
	seeds := make([]string, 3)
	for i := range seeds {
		n, err := rand.Int(rand.Reader, big.NewInt(9_000_000_000))
		if err != nil {
			return nil, nil, nil, err
		}
		seeds[i] = n.Add(n, big.NewInt(1_000_000_000)).String()
	}
	secrets := append(append([]string(nil), seeds...), distinctiveLines(simPy)...)
	if err := os.MkdirAll(filepath.Join(work, "harness"), 0o755); err != nil {
		return nil, nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(work, "harness", "sim.py"), []byte(simPy), 0o644); err != nil {
		return nil, nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(work, "seeds.txt"), []byte(strings.Join(seeds, "\n")+"\n"), 0o644); err != nil {
		return nil, nil, nil, err
	}

	tool := filepath.Join(work, "bin", "plimsoll-withheld")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", tool, "./cmd/plimsoll-withheld").CombinedOutput(); err != nil {
		return nil, nil, nil, fmt.Errorf("build plimsoll-withheld: %v: %s", err, out)
	}
	setPath := filepath.Join(work, "withheld.json")
	set, code, err := runTool(ctx, work, tool, buildArgs...)
	if err != nil || code != 0 {
		return nil, nil, nil, fmt.Errorf("plimsoll-withheld build exited %d: %v", code, err)
	}
	if err := os.WriteFile(setPath, set, 0o644); err != nil {
		return nil, nil, nil, err
	}
	sum := sha256.Sum256(set)
	ev := &Evidence{
		Commit:    commit(ctx),
		Provider:  "wasm",
		SetSHA256: hex.EncodeToString(sum[:]),
		Build:     Command{Line: "plimsoll-withheld " + strings.Join(buildArgs, " ") + " > withheld.json", Exit: code},
	}
	if ev.Entries, err = setEntries(set); err != nil {
		return nil, nil, nil, err
	}
	fmt.Printf("set       | %d entries, SHA-256 %s\n", len(ev.Entries), ev.SetSHA256)

	binary, err := daemonproc.Build(ctx, work)
	if err != nil {
		return nil, nil, nil, err
	}
	token, clients, err := daemonproc.ClientsFile(work, "agent")
	if err != nil {
		return nil, nil, nil, err
	}
	log := &lineSink{}
	daemon, err := daemonproc.Start(ctx, binary, daemonproc.Options{Env: []string{
		"SANDBOX_PROVIDER=wasm",
		"PLIMSOLL_CLIENTS_FILE=" + clients,
		"PLIMSOLL_WITHHELD_FILE=" + setPath,
	}, Ready: 30 * time.Second, Log: log})
	if err != nil {
		return nil, nil, nil, err
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = daemon.Stop(5 * time.Second)
		}
	}()
	rec := &recorder{byTrace: map[string]*recorded{}}
	remote, err := client.New(daemon.BaseURL, client.WithToken(token), client.WithInsecureHTTP(), client.WithRecorder(rec))
	if err != nil {
		return nil, nil, nil, err
	}
	desc, err := remote.Describe(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	ev.Isolation = desc.Isolation.String()

	archive, err := tarGzBase64("vendor/plant.py", simPy)
	if err != nil {
		return nil, nil, nil, err
	}
	edited := strings.NewReplacer("def step(", "def advance(", "step(state, command, dt, seed)", "advance(state, command, dt, seed)", "    ", "\t").Replace(simPy)
	project := func(path, content string) func(context.Context) (Answer, error) {
		return func(ctx context.Context) (Answer, error) {
			res, err := remote.RunProject(ctx, sandbox.ProjectRequest{Files: []sandbox.File{{Path: path, Content: content}},
				Steps: []string{"python3 " + path}, Timeout: 10 * time.Second})
			if err != nil {
				return Answer{}, err
			}
			a := Answer{Ran: true}
			if n := len(res.Steps); n > 0 {
				a.ExitCode, a.Stdout = res.Steps[n-1].ExitCode, res.Steps[n-1].Stdout
			}
			return a, nil
		}
	}
	snippet := func(code string) func(context.Context) (Answer, error) {
		return func(ctx context.Context) (Answer, error) {
			res, err := remote.RunJavaScript(ctx, sandbox.Request{Code: code, Timeout: 10 * time.Second})
			if err != nil {
				return Answer{}, err
			}
			return Answer{Ran: true, ExitCode: res.ExitCode, Stdout: string(res.Stdout)}, nil
		}
	}
	calls := []struct {
		Call
		send func(context.Context) (Answer, error)
	}{
		{Call{Name: "clean", Kind: "javascript", Expect: expectRuns,
			Title: "A clean controller",
			Sent:  "An agent's controller as a JavaScript snippet (a PD loop: it steers by how far it is from the target and how fast it is moving): nothing in it is withheld."}, snippet(cleanJS)},
		{Call{Name: "harness-file", Kind: "project", Expect: expectRefused,
			Title: "The harness's simulator, shipped as a helper file",
			Sent:  "A project whose one file, helpers/sim.py, is the harness's simulator byte for byte: the harness developer's mistake."}, project("helpers/sim.py", simPy)},
		{Call{Name: "harness-edited", Kind: "project", Expect: expectRefused,
			Title: "The simulator, edited",
			Sent:  "The same simulator with its step function renamed and every indent turned into a tab, so its file entry no longer matches; its source entry does."}, project("helpers/plant.py", edited)},
		{Call{Name: "harness-archive", Kind: "project", Expect: expectRefused,
			Title: "The simulator, packed in an archive",
			Sent:  "The simulator inside a .tar.gz, sent as base64 text in deps.tar.gz.b64, as a step that runs base64 -d would unpack it."}, project("deps.tar.gz.b64", archive)},
		{Call{Name: "seed-in-code", Kind: "javascript", Expect: expectRunsLogged,
			Title: "A hidden seed in the agent's own code",
			Sent:  "An agent's snippet with a hidden seed written into it as a constant: the seed reached the agent somehow, and its code carries it."}, snippet(fmt.Sprintf(agentJS, seeds[1]))},
	}
	for i := range calls {
		c := calls[i].Call
		c.TraceID = "ship-scan-" + c.Name
		answer, err := calls[i].send(client.NewTraceContext(ctx, c.TraceID))
		if err != nil {
			answer, err = refusal(err)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("%s: %w", c.Name, err)
			}
		}
		c.Answer = answer
		if r := rec.byTrace[c.TraceID]; r != nil {
			c.Record = &Record{Version: r.record.Version, RequestSHA256: r.record.RequestSHA256, ResultSHA256: r.record.ResultSHA256}
			if c.Name == "clean" {
				c.Record.Published = true
			} else {
				c.Record.Why = "Its request holds a hidden seed, so it is not published; its response is, and -verify recomputes the result digest from it and checks the answer shown here."
			}
		}
		fmt.Printf("call      | %-16s %s\n", c.Name, summary(answer))
		ev.Calls = append(ev.Calls, c)
	}
	// The daemon's lines are complete once it has stopped.
	stopped = true
	if err := daemon.Stop(5 * time.Second); err != nil {
		return nil, nil, nil, fmt.Errorf("stop the daemon: %w", err)
	}
	lines, err := log.lines()
	if err != nil {
		return nil, nil, nil, err
	}
	for i := range ev.Calls {
		for _, l := range lines {
			if l.TraceID == ev.Calls[i].TraceID {
				ev.Calls[i].Log = append(ev.Calls[i].Log, l)
			}
		}
	}
	// The raw lines, whole, are checked for the secrets too: the allowlist is a second
	// guard, not the only one.
	if err := noSecrets("the daemon's log", log.raw(), secrets); err != nil {
		return nil, nil, nil, err
	}

	ex := &exchange{set: set}
	if r := rec.byTrace["ship-scan-clean"]; r != nil {
		ex.request, ex.response = r.request, r.response
	}
	if r := rec.byTrace["ship-scan-seed-in-code"]; r != nil {
		ex.seedResponse = r.response
	}

	// The offline half: the same set over folders, before anything is sent.
	if err := writeFiles(filepath.Join(work, "outbox"), map[string]string{"helpers/plant.py": edited, "agent.js": fmt.Sprintf(agentJS, seeds[1])}); err != nil {
		return nil, nil, nil, err
	}
	if err := writeFiles(filepath.Join(work, "clean"), map[string]string{"controller.js": cleanJS}); err != nil {
		return nil, nil, nil, err
	}
	for _, dir := range []string{"outbox/", "clean/"} {
		args := []string{"scan", "-set", "withheld.json", dir}
		printed, code, err := runTool(ctx, work, tool, args...)
		if err != nil {
			return nil, nil, nil, err
		}
		ev.Offline = append(ev.Offline, Command{Line: "plimsoll-withheld " + strings.Join(args, " "), Exit: code, Output: splitLines(printed)})
	}
	return ev, secrets, ex, nil
}

// refusal turns a call's error into what the caller was told, when it is a refusal
// marked not dispatched; any other error is the run's failure.
func refusal(err error) (Answer, error) {
	mark, ok := sandbox.NotDispatchedReason(err)
	if !ok {
		return Answer{}, err
	}
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return Answer{}, err
	}
	return Answer{Code: ce.Code().String(), Mark: mark.String(), Message: ce.Message()}, nil
}

func summary(a Answer) string {
	if a.Ran {
		return fmt.Sprintf("ran, exit %d: %s", a.ExitCode, strings.TrimSpace(a.Stdout))
	}
	return fmt.Sprintf("refused (%s, %s): %s", a.Code, a.Mark, a.Message)
}

// recorded is one exchange the client checked, as the Recorder received it.
type recorded struct {
	record   *sandbox.RunRecord
	request  []byte
	response []byte
}

type recorder struct {
	mu      sync.Mutex
	byTrace map[string]*recorded
}

func (r *recorder) Record(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) error {
	rec, err := recordCheck(req, resp)
	if err != nil {
		return err
	}
	opts := protojson.MarshalOptions{Multiline: true, Indent: "  "}
	reqJSON, err := opts.Marshal(req)
	if err != nil {
		return err
	}
	respJSON, err := opts.Marshal(resp)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byTrace[req.GetTraceId()] = &recorded{record: rec, request: append(reqJSON, '\n'), response: append(respJSON, '\n')}
	return nil
}

// lineSink keeps the daemon's log.
type lineSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lineSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lineSink) raw() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return bytes.Clone(l.buf.Bytes())
}

// lines decodes every JSON line into the allowlisted fields.
func (l *lineSink) lines() ([]LogLine, error) {
	var out []LogLine
	sc := bufio.NewScanner(bytes.NewReader(l.raw()))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if !bytes.HasPrefix(sc.Bytes(), []byte("{")) {
			continue
		}
		var line LogLine
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			return nil, fmt.Errorf("a daemon log line: %w", err)
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func runTool(ctx context.Context, dir, tool string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.Bytes(), exit.ExitCode(), nil
	}
	if err != nil {
		return nil, -1, fmt.Errorf("%s: %v: %s", filepath.Base(tool), err, stderr.Bytes())
	}
	return stdout.Bytes(), 0, nil
}

// setEntries lists the set's entries without their digests.
func setEntries(set []byte) ([]SetEntry, error) {
	var parsed struct {
		Mode    string `json:"mode"`
		Entries []struct {
			Kind  string `json:"kind"`
			Label string `json:"label"`
			Mode  string `json:"mode"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(set, &parsed); err != nil {
		return nil, fmt.Errorf("withheld.json: %w", err)
	}
	var out []SetEntry
	for _, e := range parsed.Entries {
		mode := e.Mode
		if mode == "" {
			mode = parsed.Mode
		}
		out = append(out, SetEntry{Kind: e.Kind, Label: e.Label, Mode: mode})
	}
	return out, nil
}

func tarGzBase64(name, content string) (string, error) {
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}); err != nil {
		return "", err
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		return "", err
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	var gb bytes.Buffer
	gw := gzip.NewWriter(&gb)
	if _, err := gw.Write(tb.Bytes()); err != nil {
		return "", err
	}
	if err := gw.Close(); err != nil {
		return "", err
	}
	enc := base64.StdEncoding.EncodeToString(gb.Bytes())
	var wrapped strings.Builder
	for len(enc) > 76 {
		wrapped.WriteString(enc[:76] + "\n")
		enc = enc[76:]
	}
	wrapped.WriteString(enc + "\n")
	return wrapped.String(), nil
}

func writeFiles(dir string, files map[string]string) error {
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func splitLines(b []byte) []string {
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// distinctiveLines are the simulator's lines a source entry holds, as written: none may
// appear in what is published.
func distinctiveLines(src string) []string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		if t := strings.TrimSpace(line); len(t) >= 24 && !strings.HasPrefix(t, "#") {
			out = append(out, t)
		}
	}
	return out
}

func commit(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}
