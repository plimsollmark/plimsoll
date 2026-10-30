package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/examples/internal/daemonproc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

var (
	//go:embed guest/report.py
	guestReport string
	//go:embed guest/openai_main.py
	guestOpenAI string
	//go:embed guest/anthropic_main.py
	guestAnthropic string
	//go:embed guest/plain_main.py
	guestPlain string
)

const (
	imageTag  = "plimsoll-wip/sdk-grants:dev"
	baseImage = "plimsoll/sandbox-python:latest"
	caller    = "sdk-grants-example"
)

// dummyKeys are the placeholder keys the profiles put in the guest's environment: both
// libraries refuse to start without one, and the broker never forwards it.
var dummyKeys = map[string]string{"openai": "dummy-openai-key-in-the-sandbox", "anthropic": "dummy-anthropic-key-in-the-sandbox"}

type config struct {
	repo, work, out string
	build           bool
}

// guestRun is one run the program makes: the profile it selects ("" for none) and its
// program.
type guestRun struct {
	name, profile, main string
}

// guestSteps is every guest run's one step.
var guestSteps = []string{"python3 main.py"}

var guestRuns = []guestRun{
	{"openai", "openai", guestOpenAI},
	{"anthropic", "anthropic", guestAnthropic},
	{"plain", "", guestPlain},
}

// grantsFile is the profiles the daemon serves: one per API, each pointing at its stub
// listener, with the local address and a dummy key in sdk_env. The OpenAI profile raises
// its Files route for an 8 MiB multipart upload; the Anthropic profile passes the one
// header the Claude API requires that the library sends itself.
func grantsFile(urls map[string]string) map[string]any {
	return map[string]any{"profiles": map[string]any{
		"openai": map[string]any{
			"base_url":                urls["openai"],
			"allow":                   []string{"POST /v1/chat/completions", "POST /v1/files"},
			"sdk_env":                 map[string]string{"OPENAI_BASE_URL": "{origin}/v1", "OPENAI_API_KEY": dummyKeys["openai"]},
			"route_max_request_bytes": map[string]int64{"POST /v1/files": 16 << 20},
			"route_content_types":     map[string][]string{"POST /v1/files": {"multipart/form-data"}},
			"max_request_bytes":       64 << 20,
			"allowed_callers":         []string{caller},
			"token":                   map[string]string{"type": "static", "env": "STUB_OPENAI_KEY"},
		},
		"anthropic": map[string]any{
			"base_url":        urls["anthropic"],
			"allow":           []string{"POST /v1/messages"},
			"pass_headers":    []string{"anthropic-version"},
			"sdk_env":         map[string]string{"ANTHROPIC_BASE_URL": "{origin}", "ANTHROPIC_API_KEY": dummyKeys["anthropic"]},
			"allowed_callers": []string{caller},
			"token":           map[string]string{"type": "static", "env": "STUB_ANTHROPIC_KEY"},
		},
	}}
}

func runAll(ctx context.Context, c config) error {
	if err := os.RemoveAll(c.work); err != nil {
		return err
	}
	if err := os.MkdirAll(c.work, 0o700); err != nil {
		return err
	}
	if c.build {
		fmt.Println("image     | building", imageTag)
		cmd := exec.CommandContext(ctx, "docker", "build", "-q", "-f", filepath.Join(c.repo, "examples", "sdk-grants", "sdk.Dockerfile"), "-t", imageTag, filepath.Join(c.repo, "examples", "sdk-grants"))
		cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build %s: %w", imageTag, err)
		}
	}
	var obs observations
	var err error
	obs.Date = time.Now().UTC().Format("2006-01-02")
	if obs.Commit, err = gitHead(ctx, c.repo); err != nil {
		return err
	}
	obs.Image = imageFacts{Tag: imageTag, Base: baseImage}
	if obs.Image.ID, err = imageID(ctx, imageTag); err != nil {
		return err
	}
	if obs.Image.BaseID, err = imageID(ctx, baseImage); err != nil {
		return err
	}
	if obs.Pins, err = readPins(filepath.Join(c.repo, "examples", "sdk-grants", "requirements.txt")); err != nil {
		return err
	}

	// The keys the daemon holds for the two stub APIs: random values made for this run,
	// which open nothing but the stub.
	obs.Keys = map[string]string{}
	for _, api := range []string{"openai", "anthropic"} {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		obs.Keys[api] = "stub-" + api + "-key-held-by-the-daemon-" + hex.EncodeToString(b)
	}
	st, err := startStub([]string{dummyKeys["openai"], dummyKeys["anthropic"], obs.Keys["openai"], obs.Keys["anthropic"]})
	if err != nil {
		return err
	}
	defer st.close()
	grantsRaw, err := json.MarshalIndent(grantsFile(st.urls), "", "  ")
	if err != nil {
		return err
	}
	grantsRaw = append(grantsRaw, '\n')
	grantsPath := filepath.Join(c.work, fileGrants)
	if err := os.WriteFile(grantsPath, grantsRaw, 0o600); err != nil {
		return err
	}

	binary, err := daemonproc.Build(ctx, c.work)
	if err != nil {
		return err
	}
	token, clients, err := daemonproc.ClientsFile(c.work, caller)
	if err != nil {
		return err
	}
	logPath := filepath.Join(c.work, "plimsolld.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	defaultProfile := filepath.Join(c.repo, "docker", "seccomp.json")
	d, err := daemonproc.Start(ctx, binary, daemonproc.Options{Env: []string{
		"SANDBOX_PROVIDER=docker",
		"SANDBOX_DOCKER_PROJECT_IMAGE=" + imageTag,
		"SANDBOX_DOCKER_SECCOMP=" + defaultProfile,
		"SANDBOX_DOCKER_SECCOMP_SDK=derived",
		"PLIMSOLL_GRANTS_FILE=" + grantsPath,
		"PLIMSOLL_CLIENTS_FILE=" + clients,
		"STUB_OPENAI_KEY=" + obs.Keys["openai"],
		"STUB_ANTHROPIC_KEY=" + obs.Keys["anthropic"],
	}, Ready: 3 * time.Minute, Log: logFile, Metrics: true})
	if err != nil {
		return err
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = d.Stop(time.Minute)
		}
	}()

	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	signer := attest.NewSigner(key)
	var bundle bytes.Buffer
	harness := attest.NewHarness(signer, &bundle)
	info, err := mustRemote(d.BaseURL, token, "", harness).Describe(ctx)
	if err != nil {
		return err
	}
	obs.Daemon = daemonFacts{Provider: info.Sandbox, Isolation: info.Isolation.String(), Policy: info.Environments.Policy, Protocol: info.Protocol}
	fmt.Printf("daemon    | %s at the %s tier; policy %s\n", info.Sandbox, info.Isolation, info.Environments.Policy)

	for _, g := range guestRuns {
		remote := mustRemote(d.BaseURL, token, g.profile, harness)
		trace := "sdk-grants-" + g.name
		t0 := time.Now()
		res, err := remote.RunProject(client.NewTraceContext(ctx, trace), sandbox.ProjectRequest{
			Files:            []sandbox.File{{Path: "main.py", Content: g.main}, {Path: "report.py", Content: guestReport}},
			Steps:            guestSteps,
			Timeout:          2 * time.Minute,
			MinimumIsolation: sandbox.IsolationContainer,
		})
		if err != nil {
			return fmt.Errorf("run %s: %w", g.name, err)
		}
		if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
			var stderr string
			if len(res.Steps) > 0 {
				stderr = res.Steps[len(res.Steps)-1].Stderr
			}
			return fmt.Errorf("run %s: outcome %s (%s)\n%s", g.name, res.Outcome, res.Detail, stderr)
		}
		if res.Record == nil {
			return fmt.Errorf("run %s: no record", g.name)
		}
		obs.Runs = append(obs.Runs, runFacts{Name: g.name, Profile: g.profile, TraceID: trace, Record: res.Record.SHA256})
		fmt.Printf("run       | %-9s %s in %d ms, record %s, policy %s\n", g.name, res.Outcome, time.Since(t0).Milliseconds(), res.Record.SHA256[:16], res.Record.Policy)
	}
	if err := harness.Checkpoint(); err != nil {
		return err
	}
	if obs.Metrics, err = scrapeMetrics(ctx, d.MetricsURL); err != nil {
		return err
	}
	// The daemon pinned both profiles into its private directory, each named by its
	// digest; read the variant from there while it runs (it removes the directory when it
	// stops), so what is published is the bytes docker applied.
	defaultID, variantID, err := splitPolicy(obs.Daemon.Policy)
	if err != nil {
		return err
	}
	variantRaw, err := pinnedProfile(variantID)
	if err != nil {
		return err
	}
	defaultRaw, err := os.ReadFile(defaultProfile)
	if err != nil {
		return err
	}
	if id := "seccomp:sha256:" + sha256Hex(defaultRaw); id != defaultID {
		return fmt.Errorf("docker/seccomp.json is %s but the daemon states %s", id, defaultID)
	}
	stopped = true
	if err := d.Stop(time.Minute); err != nil {
		return err
	}
	_ = logFile.Sync()
	audits, err := readAudit(logPath)
	if err != nil {
		return err
	}
	for i := range obs.Runs {
		a, ok := audits[obs.Runs[i].TraceID]
		if !ok {
			return fmt.Errorf("the daemon's log has no audit line for %s", obs.Runs[i].TraceID)
		}
		obs.Runs[i].Audit = a
	}

	stubLog, err := jsonLines(st.requests())
	if err != nil {
		return err
	}
	_, pubPEM, err := publicPEM(pub)
	if err != nil {
		return err
	}
	raw := map[string][]byte{
		fileBundle: bundle.Bytes(), filePub: pubPEM, fileStub: stubLog, fileGrants: grantsRaw,
		fileDefault: defaultRaw, fileVariant: variantRaw,
	}
	obs.Files = map[string]string{}
	for _, name := range hashedFiles {
		obs.Files[name] = sha256Hex(raw[name])
	}
	subjects := make([]attest.Subject, len(obs.Runs))
	for i, r := range obs.Runs {
		subjects[i] = attest.Subject{Name: "plimsoll run record", Digest: map[string]string{"sha256": r.Record}}
	}
	env, err := signer.SignStatement(observationsType, subjects, obs)
	if err != nil {
		return err
	}
	if raw[fileObserved], err = json.MarshalIndent(env, "", "  "); err != nil {
		return err
	}
	raw[fileObserved] = append(raw[fileObserved], '\n')
	if err := os.MkdirAll(c.out, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := noLocalPaths(raw[name], c.repo); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(c.out, name), raw[name], 0o644); err != nil {
			return err
		}
	}
	ev, err := derive(c.out)
	if err != nil {
		return fmt.Errorf("deriving the page from what was just written: %w", err)
	}
	if err := publish(c.out, ev, c.repo); err != nil {
		return err
	}
	for _, ch := range ev.Checks {
		mark := "ok  "
		if !ch.Pass {
			mark = "FAIL"
		}
		fmt.Printf("check     | %s %s: %s\n", mark, ch.ID, ch.Detail)
	}
	fmt.Printf("page      | wrote %s and the files beside it\n", filepath.Join(c.out, filePage))
	for _, ch := range ev.Checks {
		if !ch.Pass {
			return fmt.Errorf("a check the page states failed: %s (%s); the page was written so the evidence can be read", ch.ID, ch.Detail)
		}
	}
	return nil
}

func mustRemote(baseURL, token, profile string, rec client.Recorder) *client.Remote {
	opts := []client.Option{client.WithToken(token), client.WithRecorder(rec)}
	if profile != "" {
		opts = append(opts, client.WithProjectGrantProfile(profile))
	}
	r, err := client.New(baseURL, opts...)
	if err != nil {
		panic(err) // a loopback URL the daemon chose; New refuses only a malformed one
	}
	return r
}

func gitHead(ctx context.Context, repo string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func imageID(ctx context.Context, image string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", image).Output()
	if err != nil {
		return "", fmt.Errorf("docker image inspect %s (run make docker-images first): %w", image, err)
	}
	return strings.TrimSpace(string(out)), nil
}

var pinLine = regexp.MustCompile(`^([A-Za-z0-9._-]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})$`)

// readPins reads requirements.txt: one pinned requirement per line, each with its hash.
func readPins(path string) ([]pin, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pins []pin
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := pinLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("%s: %q is not name==version --hash=sha256:<hex>", path, line)
		}
		pins = append(pins, pin{Name: m[1], Version: m[2], SHA256: m[3]})
	}
	return pins, nil
}

// splitPolicy reads Describe's policy, "seccomp:sha256:<default> sdk_env:seccomp:sha256:<variant>".
func splitPolicy(policy string) (defaultID, variantID string, err error) {
	parts := strings.Fields(policy)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "seccomp:sha256:") || !strings.HasPrefix(parts[1], "sdk_env:seccomp:sha256:") {
		return "", "", fmt.Errorf("the daemon's policy %q names no default profile and sdk_env variant by digest", policy)
	}
	return parts[0], strings.TrimPrefix(parts[1], "sdk_env:"), nil
}

// pinnedProfile finds the copy of a profile the daemon pinned, by the digest that names
// it, in a plimsoll docker private directory, and checks its bytes are that digest.
func pinnedProfile(id string) ([]byte, error) {
	digest := strings.TrimPrefix(id, "seccomp:sha256:")
	matches, _ := filepath.Glob(filepath.Join(os.TempDir(), "plimsoll-docker-config-*", "seccomp", digest+".json"))
	for _, m := range matches {
		raw, err := os.ReadFile(m)
		if err == nil && sha256Hex(raw) == digest {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("no pinned copy of %s found under %s", id, os.TempDir())
}

// readAudit reads the daemon's JSON log and returns each run's audit line by trace id.
func readAudit(path string) (map[string]auditLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]auditLine{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var line struct {
			auditLine
			TraceID string `json:"trace_id"`
			Op      string `json:"op"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil || line.TraceID == "" || line.Op == "" {
			continue
		}
		out[line.TraceID] = line.auditLine
	}
	return out, sc.Err()
}

var metricLine = regexp.MustCompile(`^(plimsoll_host_calls_total|plimsoll_host_call_latency_seconds_sum)\{profile="([^"]*)",method="([^"]*)",route="([^"]*)"\} (\S+)$`)

// scrapeMetrics reads the daemon's host-call series: a count and a latency sum per
// profile, method and route template.
func scrapeMetrics(ctx context.Context, url string) ([]metricSeries, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /metrics: %s", resp.Status)
	}
	byKey := map[[3]string]*metricSeries{}
	var keys [][3]string
	for _, line := range strings.Split(string(body), "\n") {
		m := metricLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		k := [3]string{m[2], m[3], m[4]}
		s := byKey[k]
		if s == nil {
			s = &metricSeries{Profile: m[2], Method: m[3], Route: m[4]}
			byKey[k] = s
			keys = append(keys, k)
		}
		v, err := strconv.ParseFloat(m[5], 64)
		if err != nil {
			return nil, fmt.Errorf("metrics line %q: %w", line, err)
		}
		if m[1] == "plimsoll_host_calls_total" {
			s.Count = int(v)
		} else {
			s.SumSec = v
		}
	}
	out := make([]metricSeries, 0, len(keys))
	for _, k := range keys {
		out = append(out, *byKey[k])
	}
	if len(out) == 0 {
		return nil, errors.New("the daemon's /metrics has no host-call series")
	}
	return out, nil
}

func jsonLines[T any](items []T) ([]byte, error) {
	var b bytes.Buffer
	for _, it := range items {
		line, err := json.Marshal(it)
		if err != nil {
			return nil, err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func publicPEM(pub ed25519.PublicKey) (string, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", nil, err
	}
	return attest.KeyID(pub), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
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
