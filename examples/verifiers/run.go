package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/examples/internal/daemonproc"
)

// The outside sources, pinned. The run refuses a checkout at any other commit, and for
// the task's package any file that differs from the bytes read before pinning: its
// evaluator-side code runs in the evaluator's own Python, as verifiers runs every
// taskset's.
const (
	primeRepo   = "https://github.com/PrimeIntellect-ai/prime-envs"
	primeCommit = "e221a6514f2e8317af7922649a0d528aea5d087f"
	primePath   = "environments/reasoning/uuid_ctf"
	benchRepo   = "https://github.com/harbor-framework/terminal-bench-2"
	benchCommit = "2fd12b88aafdd04a52c298e3940bcb189f9766d6"

	// The session image: plimsoll's Python image plus bash and a /workspace link to the
	// session's work directory (clients/python/frameworks/verifiers/attempt/agent.Dockerfile).
	agentImage = "plimsoll-wip/verifiers-agent:dev"
	// verifiers' own docker runtime's default image, for the baseline.
	baselineImage = "python:3.11-slim"
	baseImage     = "plimsoll/sandbox-python:latest"
)

// primeFiles is every file of the task's package, by SHA-256, as read on 2026-10-27: it
// imports only the standard library and verifiers, builds its corpus in memory, and its
// only file system and exec text is inside strings that become files in the sandbox.
var primeFiles = map[string]string{
	"README.md":            "f1e2e0fff9a62c1a37982af7d337945e70bec13f3d943a88dd41237d5fd6be5a",
	"pyproject.toml":       "b7adf8fdad4ca96a3e337d378a700ae49c55a77d84241929e8a8574a177e8591",
	"uuid_ctf/__init__.py": "f685dbc0245a548fe88e4c9ba613ee0acaf49d32bdc0540b6c3f6784a9736d1a",
	"uuid_ctf/taskset.py":  "c288d09395a75534364abc62fec62592668f2b2674cb66efdd362cd2d667441b",
}

// config is where the run reads and writes.
type config struct {
	repo   string // the repository root (absolute)
	python string // the verifiers environment's interpreter
	prime  string // a prime-envs checkout, fetched at primeCommit if absent
	bench  string // a terminal-bench-2 checkout, fetched at benchCommit if absent
	work   string // scratch: every configuration's raw output (never published)
	out    string // the page's directory
	runsc  bool   // run the gVisor configurations
}

// runAll runs every configuration fresh, then writes the page and its evidence.
func runAll(ctx context.Context, c config) error {
	if err := preflight(ctx, c); err != nil {
		return err
	}
	if err := os.RemoveAll(c.work); err != nil {
		return err
	}
	if err := os.MkdirAll(c.work, 0o755); err != nil {
		return err
	}
	step("fetching the outside sources at their pinned commits")
	if err := fetchPinned(ctx, c.prime, primeRepo, primeCommit); err != nil {
		return err
	}
	files, err := checkTaskFiles(filepath.Join(c.prime, primePath))
	if err != nil {
		return err
	}
	if err := fetchPinned(ctx, c.bench, benchRepo, benchCommit); err != nil {
		return err
	}

	step("building plimsolld and the session image")
	binary, err := daemonproc.Build(ctx, c.work)
	if err != nil {
		return err
	}
	dockerfile := filepath.Join(c.repo, "clients", "python", "frameworks", "verifiers", "attempt", "agent.Dockerfile")
	if err := runQuiet(ctx, filepath.Join(c.work, "image.log"), "docker", "build", "-t", agentImage, "-f", dockerfile, filepath.Dir(dockerfile)); err != nil {
		return err
	}
	if exec.CommandContext(ctx, "docker", "image", "inspect", baselineImage).Run() != nil {
		if err := runQuiet(ctx, filepath.Join(c.work, "pull.log"), "docker", "pull", baselineImage); err != nil {
			return err
		}
	}

	runtimes := []string{"runc"}
	if c.runsc {
		runtimes = append(runtimes, "runsc")
	}
	for _, rt := range runtimes {
		step("vf-validate plimsoll-sum on plimsoll, " + rt)
		if err := validate(ctx, c, binary, rt); err != nil {
			return err
		}
	}
	taskset := filepath.Join(c.prime, primePath)
	for _, a := range attemptPlan(c.runsc) {
		step("vf-eval uuid_ctf: " + a.label)
		args := append([]string{"--task", "uuid-ctf", "--taskset-path", taskset, "--out", filepath.Join(c.work, a.name)}, a.args...)
		if a.serve {
			args = append(args, "--serve", binary)
		}
		err := python(ctx, c, filepath.Join(c.work, a.name+".log"), nil, "frameworks.verifiers.attempt.run_attempt", args...)
		if err != nil && !(a.mayFail && fileExists(filepath.Join(c.work, a.name, "summary.json"))) {
			return fmt.Errorf("%s: %w", a.name, err)
		}
	}
	if c.runsc {
		step("timing each runtime call (verifiers' docker runtime, plimsoll runc, plimsoll gVisor)")
		if err := python(ctx, c, filepath.Join(c.work, "calls.log"), nil, "frameworks.verifiers.attempt.measure_calls",
			"--serve", binary, "--out", filepath.Join(c.work, "calls")); err != nil {
			return err
		}
	}

	return assembleAndPublish(ctx, c, files)
}

// assembleAndPublish reads Terminal-Bench 2, gathers the evidence from the raw output in
// the work directory, and writes the page. -assemble runs it alone over the last run's
// output, starting nothing.
func assembleAndPublish(ctx context.Context, c config, files map[string]string) error {
	if files == nil {
		if err := fetchPinned(ctx, c.prime, primeRepo, primeCommit); err != nil {
			return err
		}
		var err error
		if files, err = checkTaskFiles(filepath.Join(c.prime, primePath)); err != nil {
			return err
		}
		if err := fetchPinned(ctx, c.bench, benchRepo, benchCommit); err != nil {
			return err
		}
	}
	step("reading Terminal-Bench 2 as data")
	cs, err := takeCensus(c.bench, strings.TrimPrefix(benchRepo, "https://github.com/"), benchCommit)
	if err != nil {
		return err
	}
	step("rechecking every record log and writing the page")
	ev, err := assemble(ctx, c, files, cs)
	if err != nil {
		return err
	}
	return publish(c, ev)
}

// plannedAttempt is one vf-eval configuration of uuid_ctf.
type plannedAttempt struct {
	name, label string
	args        []string
	serve       bool
	mayFail     bool // expected to end in verifiers' error, reported rather than raised
}

func attemptPlan(runsc bool) []plannedAttempt {
	p := []plannedAttempt{
		{name: "uuid-gold-runc", label: "plimsoll-bash on plimsoll (runc), the solving policy", args: []string{"--runtime", "plimsoll", "--policy", "gold"}, serve: true},
		{name: "uuid-wrong-runc", label: "plimsoll-bash on plimsoll (runc), the wrong-answer policy", args: []string{"--runtime", "plimsoll", "--policy", "wrong"}, serve: true},
	}
	if runsc {
		p = append(p, plannedAttempt{name: "uuid-gold-runsc", label: "plimsoll-bash on plimsoll (gVisor), the solving policy", args: []string{"--runtime", "plimsoll", "--policy", "gold", "--docker-runtime", "runsc"}, serve: true})
	}
	return append(p,
		plannedAttempt{name: "uuid-shipped-runc", label: "verifiers' shipped bash harness on plimsoll (runc)", args: []string{"--runtime", "plimsoll", "--policy", "gold", "--shipped-harness"}, serve: true, mayFail: true},
		plannedAttempt{name: "uuid-gold-docker", label: "verifiers' shipped bash harness on verifiers' docker runtime (the baseline)", args: []string{"--runtime", "docker", "--policy", "gold", "--shipped-harness"}},
	)
}

func preflight(ctx context.Context, c config) error {
	if _, err := os.Stat(c.python); err != nil {
		return fmt.Errorf("no verifiers environment at %s: run make py-frameworks PY_FRAMEWORKS=verifiers", c.python)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("docker is not on PATH")
	}
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", baseImage).Run(); err != nil {
		return fmt.Errorf("image %s is not present: run make docker-images", baseImage)
	}
	if c.runsc {
		out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .Runtimes}}").Output()
		if err != nil || !bytes.Contains(out, []byte(`"runsc"`)) {
			return errors.New("docker has no runsc runtime (gVisor); install it, or pass -runsc=false for the runc configurations alone")
		}
	}
	return nil
}

// validate serves a daemon and runs the docker suite's own check of plimsoll-sum
// (frameworks/verifiers/docker_check.py) against it.
func validate(ctx context.Context, c config, binary, rt string) error {
	dir := filepath.Join(c.work, "validate-"+rt)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	log, err := os.Create(filepath.Join(dir, "plimsolld.log"))
	if err != nil {
		return err
	}
	defer log.Close()
	runtime := ""
	if rt == "runsc" {
		runtime = "runsc"
	}
	d, err := daemonproc.Start(ctx, binary, daemonproc.Options{
		Env: []string{"SANDBOX_PROVIDER=docker", "SANDBOX_DOCKER_RUNTIME=" + runtime, "SANDBOX_DOCKER_PROJECT_IMAGE=" + agentImage,
			"SANDBOX_MAX_SESSIONS=4", "SANDBOX_RATE_PER_MIN=600", "PLIMSOLL_TOKEN=" + token, "PLIMSOLL_CLIENTS_FILE="},
		Ready: 5 * time.Minute,
		Log:   log,
	})
	if err != nil {
		return err
	}
	defer d.Stop(60 * time.Second)
	return python(ctx, c, filepath.Join(dir, "check.log"), []string{
		"PLIMSOLL_DOCKER_SESSIONS_URL=" + d.BaseURL, "PLIMSOLL_DOCKER_FLOOR=" + floorOf(rt),
		"PLIMSOLL_VERIFIERS_OUT=" + filepath.Join(dir, "out"), "PLIMSOLL_DOCKER_REQUIRED=1", "PLIMSOLL_TOKEN=" + token,
	}, "unittest", "frameworks.verifiers.docker_check", "-v")
}

func floorOf(rt string) string {
	if rt == "runsc" {
		return "kernel"
	}
	return "container"
}

// python runs a module of the verifiers environment from clients/python with only the
// variables a run needs, never this process's others.
func python(ctx context.Context, c config, logPath string, extra []string, module string, args ...string) error {
	env := []string{"PYTHONPATH=src", "PYTHONDONTWRITEBYTECODE=1"}
	for _, name := range []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "DOCKER_HOST"} {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	cmd := exec.CommandContext(ctx, c.python, append([]string{"-B", "-m", module}, args...)...)
	cmd.Dir = filepath.Join(c.repo, "clients", "python")
	cmd.Env = append(env, extra...)
	return runLogged(cmd, logPath)
}

func runQuiet(ctx context.Context, logPath, name string, args ...string) error {
	return runLogged(exec.CommandContext(ctx, name, args...), logPath)
}

// runLogged runs cmd with its output in logPath, and on failure names the log and shows
// its last lines.
func runLogged(cmd *exec.Cmd, logPath string) error {
	log, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Run(); err != nil {
		tail, _ := os.ReadFile(logPath)
		if len(tail) > 3000 {
			tail = tail[len(tail)-3000:]
		}
		return fmt.Errorf("%s: %w (log %s):\n%s", filepath.Base(cmd.Path), err, logPath, tail)
	}
	return nil
}

// fetchPinned makes dir a checkout of repo at commit, fetching only that commit when dir
// does not exist, and refuses a checkout at any other commit or with local changes.
func fetchPinned(ctx context.Context, dir, repo, commit string) error {
	git := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
		}
		return out, nil
	}
	if !fileExists(filepath.Join(dir, ".git")) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", repo}, {"fetch", "-q", "--depth", "1", "origin", commit}, {"checkout", "-q", "--detach", "FETCH_HEAD"}} {
			if _, err := git(args...); err != nil {
				return err
			}
		}
	}
	head, err := git("rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if got := strings.TrimSpace(string(head)); got != commit {
		return fmt.Errorf("%s is at %s, not the pinned %s", dir, got, commit)
	}
	status, err := git("status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(status)) > 0 {
		return fmt.Errorf("%s has local changes or untracked files:\n%s", dir, status)
	}
	return nil
}

// checkTaskFiles requires the task's package to be exactly primeFiles.
func checkTaskFiles(dir string) (map[string]string, error) {
	got := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		sum := sha256.Sum256(raw)
		got[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		return nil, err
	}
	var bad []string
	for name, want := range primeFiles {
		if got[name] != want {
			bad = append(bad, fmt.Sprintf("%s: %s, pinned %s", name, orNone(got[name]), want))
		}
	}
	for name := range got {
		if _, ok := primeFiles[name]; !ok {
			bad = append(bad, name+": not among the pinned files")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return nil, fmt.Errorf("the task's package at %s is not the one pinned:\n  %s", dir, strings.Join(bad, "\n  "))
	}
	return got, nil
}

func orNone(s string) string {
	if s == "" {
		return "missing"
	}
	return s
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func step(s string) { fmt.Fprintf(os.Stderr, "verifiers: %s\n", s) }

// lastJSONLine is the last line of a file that parses as a JSON object.
func lastJSONLine(path string) (json.RawMessage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var last json.RawMessage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) > 0 && line[0] == '{' && json.Valid(line) {
			last = append(json.RawMessage(nil), line...)
		}
	}
	if last == nil {
		return nil, fmt.Errorf("%s: no JSON line", path)
	}
	return last, sc.Err()
}

func copyFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
