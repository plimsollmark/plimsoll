package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/examples/internal/daemonproc"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The -live run: the same libraries against the real APIs, beside the stub run and sharing
// nothing with its claims. It spends money, so no test or gate reaches it: only main passes
// realAPIs, and the plumbing test passes the stub's addresses and canary keys.
//
// Without a server-side log it can show less than the stub run can, and the page says so. It
// shows that the API answered, that a stream arrived in pieces, that the broker refused a route
// off the allow list, and that the key is not in the sandbox. It cannot show what the API
// received.
var (
	//go:embed guest/live_scan.py
	guestLiveScan string
	//go:embed guest/live_openai_main.py
	guestLiveOpenAI string
	//go:embed guest/live_anthropic_main.py
	guestLiveAnthropic string
)

const (
	liveDir             = "live"
	fileLive            = "live.json"
	liveObservationType = "https://plimsollmark.github.io/plimsoll/examples/sdk-grants/live/observations/v1"

	// liveBudgetUSD caps the run's spend: a few short answers cost cents, so a quarter dollar leaves headroom and stops a loop.
	liveBudgetUSD = 0.25
	// liveMaxTokens is each answer's hard limit, and guest code sets it (a test holds it to this).
	liveMaxTokens = 64
	// liveInputTokens bounds one call's input: the fixed prompt is under 30 bytes, and this
	// leaves room for the chat template a provider wraps round it.
	liveInputTokens = 100
	// liveStreamSpanMs is the least spread a stream must arrive over to count as arriving in
	// pieces. A stream handed over in one block is only as spread as the library's parsing:
	// 66 pieces took the OpenAI library 2.4 to 3.3 ms (measured 2026-10-30, 20 runs, an
	// in-memory transport). 20 ms is about seven times that.
	liveStreamSpanMs = 20
)

// liveAPI is one API of the run. A chat route gets two calls (plain and streamed); each
// refused call stops at the broker and costs nothing.
type liveAPI struct {
	Name, Vendor, BaseURL, KeyEnv, Model, Route string
	SDKEnv                                      map[string]string
	PassHeaders                                 []string
	Main                                        string
	Calls                                       int
	PriceIn, PriceOut                           float64 // USD per million tokens, list price, read 2026-10-30
}

// realAPIs are the only place the paid hosts are named. Prices: Nebius's public catalog
// (tokenfactory.nebius.com/api/public/models_info) and Anthropic's pricing page.
var realAPIs = []liveAPI{
	{Name: "openai", Vendor: "Nebius Token Factory", BaseURL: "https://api.tokenfactory.nebius.com", KeyEnv: "NEBIUS_API_KEY",
		Model: "nvidia/Nemotron-3_5-Lightning", Route: "POST /v1/chat/completions",
		SDKEnv: map[string]string{"OPENAI_BASE_URL": "{origin}/v1", "OPENAI_API_KEY": dummyKeys["openai"]},
		Main:   guestLiveOpenAI, Calls: 2, PriceIn: 0.06, PriceOut: 0.24},
	{Name: "anthropic", Vendor: "Anthropic", BaseURL: "https://api.anthropic.com", KeyEnv: "ANTHROPIC_API_KEY",
		Model: "claude-haiku-5-5", Route: "POST /v1/messages", PassHeaders: []string{"anthropic-version"},
		SDKEnv: map[string]string{"ANTHROPIC_BASE_URL": "{origin}", "ANTHROPIC_API_KEY": dummyKeys["anthropic"]},
		Main:   guestLiveAnthropic, Calls: 2, PriceIn: 0.10, PriceOut: 0.50},
}

// liveWorstCase is the run's dearest possible cost: every call at its input bound and at its
// full output limit. Retries are off in the guest and the broker caps each route at Calls.
func liveWorstCase(apis []liveAPI) float64 {
	total := 0.0
	for _, a := range apis {
		total += float64(a.Calls) * (liveInputTokens*a.PriceIn + liveMaxTokens*a.PriceOut) / 1e6
	}
	return total
}

// checkLiveBudget refuses a run whose calls could pass the budget.
func checkLiveBudget(apis []liveAPI) error {
	if worst := liveWorstCase(apis); worst > liveBudgetUSD {
		return fmt.Errorf("these calls could cost $%.6f at list price, over the $%.2f budget: nothing started", worst, liveBudgetUSD)
	}
	return nil
}

// liveGrants is the profiles the daemon serves for the run: the key's variable name, never its
// value, and a cap on each paid route the broker enforces whatever the guest does.
func liveGrants(apis []liveAPI, workspace string) map[string]any {
	profiles := map[string]any{}
	for _, a := range apis {
		p := map[string]any{
			"base_url":        a.BaseURL,
			"allow":           []string{a.Route},
			"route_max_calls": map[string]int{a.Route: a.Calls},
			"sdk_env":         a.SDKEnv,
			"allowed_callers": []string{caller},
			"token":           map[string]string{"type": "static", "env": a.KeyEnv},
		}
		if len(a.PassHeaders) > 0 {
			p["pass_headers"] = a.PassHeaders
		}
		if workspace != "" && a.Name == "anthropic" {
			p["set_headers"] = map[string]string{"anthropic-workspace-id": workspace}
		}
		profiles[a.Name] = p
	}
	return map[string]any{"profiles": profiles}
}

// liveConfig is one live run. console is where progress goes: a test reads it for the canary.
type liveConfig struct {
	repo, work, out string
	build           bool
	apis            []liveAPI
	upstream        string // "real", or "stub" for the plumbing test
	workspace       string
	console         io.Writer
}

// keyDigest is how a key is named in anything written: its length and a salted digest. The
// salt keeps the digest from matching any other record of the same key.
type keyDigest struct {
	Name   string `json:"name"` // the profile
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
}

// scanSpec is scan.json, what the guest's scan and the page's recheck work from.
type scanSpec struct {
	Salt string      `json:"salt"`
	Keys []keyDigest `json:"keys"`
}

func saltedDigest(salt, key []byte) string {
	h := sha256.New()
	h.Write(salt)
	h.Write(key)
	return hex.EncodeToString(h.Sum(nil))
}

// scanWindows counts the windows of data that hash to any key of spec, without the key: every
// offset for every key length, so a reader of the published files can run it too.
func scanWindows(data []byte, spec scanSpec) (hits, windows int, err error) {
	salt, err := hex.DecodeString(spec.Salt)
	if err != nil {
		return 0, 0, fmt.Errorf("the scan's salt: %w", err)
	}
	h := sha256.New()
	var sum [sha256.Size]byte
	for _, k := range spec.Keys {
		want, err := hex.DecodeString(k.SHA256)
		if err != nil {
			return 0, 0, fmt.Errorf("key digest %s: %w", k.Name, err)
		}
		for i := 0; i+k.Length <= len(data); i++ {
			h.Reset()
			h.Write(salt)
			h.Write(data[i : i+k.Length])
			windows++
			if bytes.Equal(h.Sum(sum[:0]), want) {
				hits++
			}
		}
	}
	return hits, windows, nil
}

// runLive is the whole of a live run. It reads the keys from this process's environment and
// hands them to the daemon the same way, and only the daemon's broker uses them. It publishes
// nothing unless every check holds; on failure the raw files stay in the work directory.
func runLive(ctx context.Context, c liveConfig) error {
	if err := checkLiveBudget(c.apis); err != nil {
		return err
	}
	keys := map[string]string{}
	daemonEnv := []string{
		"SANDBOX_PROVIDER=docker",
		"SANDBOX_DOCKER_PROJECT_IMAGE=" + imageTag,
		"SANDBOX_DOCKER_SECCOMP=" + filepath.Join(c.repo, "docker", "seccomp.json"),
		"SANDBOX_DOCKER_SECCOMP_SDK=derived",
	}
	for _, a := range c.apis {
		key := os.Getenv(a.KeyEnv)
		if key == "" {
			return fmt.Errorf("%s is not set: nothing started", a.KeyEnv)
		}
		keys[a.Name] = key
		daemonEnv = append(daemonEnv, a.KeyEnv+"="+key)
		// Only the daemon needs it, and it gets it by name below. Every other child (go build,
		// docker, git) inherits this process's environment.
		if err := os.Unsetenv(a.KeyEnv); err != nil {
			return err
		}
	}
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return err
	}
	spec := scanSpec{Salt: hex.EncodeToString(saltBytes)}
	for _, a := range c.apis {
		spec.Keys = append(spec.Keys, keyDigest{Name: a.Name, Length: len(keys[a.Name]), SHA256: saltedDigest(saltBytes, []byte(keys[a.Name]))})
	}
	specRaw, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(c.work); err != nil {
		return err
	}
	if err := os.MkdirAll(c.work, 0o700); err != nil {
		return err
	}
	if c.build {
		fmt.Fprintln(c.console, "image     | building", imageTag)
		cmd := exec.CommandContext(ctx, "docker", "build", "-q", "-f", filepath.Join(c.repo, "examples", "sdk-grants", "sdk.Dockerfile"), "-t", imageTag, filepath.Join(c.repo, "examples", "sdk-grants"))
		cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build %s: %w", imageTag, err)
		}
	}
	obs := liveObservations{Date: time.Now().UTC().Format("2006-01-02"), Upstream: c.upstream, Scan: spec, Budget: liveBudgetUSD, WorstCase: liveWorstCase(c.apis)}
	for _, a := range c.apis {
		obs.APIs = append(obs.APIs, liveAPIFacts{Name: a.Name, Vendor: a.Vendor, Model: a.Model, Route: a.Route, PriceIn: a.PriceIn, PriceOut: a.PriceOut})
	}
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
	grantsRaw, err := json.MarshalIndent(liveGrants(c.apis, c.workspace), "", "  ")
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
	d, err := daemonproc.Start(ctx, binary, daemonproc.Options{
		Env: append(daemonEnv, "PLIMSOLL_GRANTS_FILE="+grantsPath, "PLIMSOLL_CLIENTS_FILE="+clients), Ready: 3 * time.Minute, Log: logFile, Metrics: true})
	if err != nil {
		return err
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = d.Stop(time.Minute)
		}
	}()
	pub, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	signer := attest.NewSigner(signKey)
	var bundle bytes.Buffer
	harness := attest.NewHarness(signer, &bundle)
	info, err := mustRemote(d.BaseURL, token, "", harness).Describe(ctx)
	if err != nil {
		return err
	}
	obs.Daemon = daemonFacts{Provider: info.Sandbox, Isolation: info.Isolation.String(), Policy: info.Environments.Policy, Protocol: info.Protocol}
	fmt.Fprintf(c.console, "daemon    | %s at the %s tier\n", info.Sandbox, info.Isolation)
	for _, a := range c.apis {
		trace := "sdk-grants-live-" + a.Name
		t0 := time.Now()
		res, err := mustRemote(d.BaseURL, token, a.Name, harness).RunProject(client.NewTraceContext(ctx, trace), sandbox.ProjectRequest{
			Files:            liveGuestFiles(a, string(specRaw)),
			Steps:            guestSteps,
			Timeout:          3 * time.Minute,
			MinimumIsolation: sandbox.IsolationContainer,
		})
		if err != nil {
			return fmt.Errorf("run %s: %w", a.Name, err)
		}
		if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
			detail := res.Detail
			if len(res.Steps) > 0 {
				detail += " " + lastLines(res.Steps[len(res.Steps)-1].Stderr, 12)
			}
			return fmt.Errorf("run %s: outcome %s (%s)", a.Name, res.Outcome, scrubKeys(detail, keys))
		}
		if res.Record == nil {
			return fmt.Errorf("run %s: no record", a.Name)
		}
		obs.Runs = append(obs.Runs, runFacts{Name: a.Name, Profile: a.Name, TraceID: trace, Record: res.Record.SHA256})
		fmt.Fprintf(c.console, "run       | %-9s %s in %d ms, record %s\n", a.Name, res.Outcome, time.Since(t0).Milliseconds(), res.Record.SHA256[:16])
	}
	if err := harness.Checkpoint(); err != nil {
		return err
	}
	if obs.Metrics, err = scrapeMetrics(ctx, d.MetricsURL); err != nil {
		return err
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
	_, pubPEM, err := publicPEM(pub)
	if err != nil {
		return err
	}
	obs.Files = map[string]string{fileGrants: sha256Hex(grantsRaw)}
	subjects := make([]attest.Subject, len(obs.Runs))
	for i, r := range obs.Runs {
		subjects[i] = attest.Subject{Name: "plimsoll run record", Digest: map[string]string{"sha256": r.Record}}
	}
	env, err := signer.SignStatement(liveObservationType, subjects, obs)
	if err != nil {
		return err
	}
	envRaw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	staged := filepath.Join(c.work, "staged", liveDir)
	if err := os.MkdirAll(staged, 0o755); err != nil {
		return err
	}
	raw := map[string][]byte{fileBundle: bundle.Bytes(), filePub: pubPEM, fileObserved: append(envRaw, '\n'), fileGrants: grantsRaw}
	for _, name := range sortedKeys(raw) {
		if err := noLocalPaths(raw[name], c.repo); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(staged, name), raw[name], 0o644); err != nil {
			return err
		}
	}
	lr, err := deriveLive(filepath.Dir(staged))
	if err != nil {
		return fmt.Errorf("deriving the results from what was just written: %w", err)
	}
	rawLive, err := marshalLive(lr)
	if err != nil {
		return err
	}
	if err := noLocalPaths(rawLive, c.repo); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(staged, fileLive), rawLive, 0o644); err != nil {
		return err
	}
	// The key itself, while this process has it, in everything this run wrote. Names only.
	for name, key := range keys {
		if hits, err := filesHolding(c.work, key); err != nil {
			return err
		} else if len(hits) != 0 {
			return fmt.Errorf("THE %s KEY IS IN %v: rotate it; nothing was published", name, hits)
		}
	}
	for _, ch := range lr.Checks {
		mark := "ok  "
		if !ch.Pass {
			mark = "FAIL"
		}
		fmt.Fprintf(c.console, "check     | %s %s: %s\n", mark, ch.ID, ch.Detail)
	}
	for _, ch := range lr.Checks {
		if !ch.Pass {
			return fmt.Errorf("a live check failed: %s (%s); nothing was published, and the raw files are in %s", ch.ID, ch.Detail, staged)
		}
	}
	dest := filepath.Join(c.out, liveDir)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	for _, name := range append(sortedKeys(raw), fileLive) {
		if err := copyFileBytes(filepath.Join(staged, name), filepath.Join(dest, name)); err != nil {
			return err
		}
	}
	fmt.Fprintf(c.console, "live      | wrote %s\n", dest)
	if c.upstream != "real" {
		return nil
	}
	return renderPublished(c.out)
}

func liveGuestFiles(a liveAPI, spec string) []sandbox.File {
	return []sandbox.File{{Path: "main.py", Content: a.Main}, {Path: "report.py", Content: guestReport},
		{Path: "live_scan.py", Content: guestLiveScan}, {Path: "scan.json", Content: spec}}
}

// lastLines keeps the end of a guest's stderr, enough to say why a run failed.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// scrubKeys removes a key from text about to be shown: a run's failure text is the guest's and
// the API's, and an error page could quote what it was sent.
func scrubKeys(s string, keys map[string]string) string {
	for _, k := range keys {
		s = strings.ReplaceAll(s, k, "[key removed]")
	}
	return s
}

// filesHolding names every file under root holding needle.
func filesHolding(root, needle string) ([]string, error) {
	var hits []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(needle)) {
			rel, _ := filepath.Rel(root, p)
			hits = append(hits, rel)
		}
		return nil
	})
	return hits, err
}

func copyFileBytes(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

// liveObservations is the predicate of the harness's signed statement about a live run.
type liveObservations struct {
	Date      string            `json:"date"`
	Commit    string            `json:"commit"`
	Upstream  string            `json:"upstream"` // "real", or "stub" in the plumbing test
	Daemon    daemonFacts       `json:"daemon"`
	Image     imageFacts        `json:"image"`
	Pins      []pin             `json:"pins"`
	Scan      scanSpec          `json:"scan"`
	Budget    float64           `json:"budget_usd"`
	WorstCase float64           `json:"worst_case_usd"`
	APIs      []liveAPIFacts    `json:"apis"`
	Files     map[string]string `json:"files"`
	Runs      []runFacts        `json:"runs"`
	Metrics   []metricSeries    `json:"metrics"`
}

// liveAPIFacts is what the run was told about an API, signed with it, so a later change of
// list price or model does not rewrite this run's arithmetic.
type liveAPIFacts struct {
	Name     string  `json:"name"`
	Vendor   string  `json:"vendor"`
	Model    string  `json:"model"`
	Route    string  `json:"route"`
	PriceIn  float64 `json:"price_in_per_million"`
	PriceOut float64 `json:"price_out_per_million"`
}

// liveResults is everything the page's live section states, derived from the raw files beside
// it. -verify derives it again and requires the same bytes.
type liveResults struct {
	Upstream  string        `json:"upstream"`
	Date      string        `json:"date"`
	Commit    string        `json:"commit"`
	KeyID     string        `json:"key_id"`
	Daemon    daemonFacts   `json:"daemon"`
	Image     imageFacts    `json:"image"`
	Budget    float64       `json:"budget_usd"`
	WorstCase float64       `json:"worst_case_usd"`
	CostUSD   float64       `json:"cost_usd"` // the usage the APIs reported, at list price
	Scan      scanSpec      `json:"scan"`
	APIs      []liveAPIView `json:"apis"`
	Checks    []check       `json:"checks"`
	Files     []fileView    `json:"files"`
}

// liveAPIView is one API's run.
type liveAPIView struct {
	Profile     string         `json:"profile"`
	Vendor      string         `json:"vendor"`
	BaseURL     string         `json:"base_url"`
	Model       string         `json:"model"`
	Library     string         `json:"library"` // name and version, as the guest imported it
	Route       string         `json:"route"`
	PassHeaders []string       `json:"pass_headers,omitempty"`
	TokenEnv    string         `json:"token_env"`
	PriceIn     float64        `json:"price_in_per_million"`
	PriceOut    float64        `json:"price_out_per_million"`
	Record      recordView     `json:"record"`
	Audit       auditLine      `json:"audit"`
	Metrics     []metricSeries `json:"metrics"`
	Calls       []liveCallView `json:"calls"`
	Scan        liveGuestScan  `json:"guest_scan"`
	OutputScan  liveOutputScan `json:"output_scan"`
	Input       int            `json:"input_tokens"`
	Output      int            `json:"output_tokens"`
	CostUSD     float64        `json:"cost_usd"`
}

// liveCallView is one call as the guest's library reported it.
type liveCallView struct {
	Name        string  `json:"name"`
	Title       string  `json:"title"`
	Status      int     `json:"status"`
	Model       string  `json:"model,omitempty"` // the model the API named in its answer
	Answer      string  `json:"answer,omitempty"`
	Finish      string  `json:"finish,omitempty"`
	Input       int     `json:"input_tokens,omitempty"`
	Output      int     `json:"output_tokens,omitempty"`
	UsageGiven  bool    `json:"usage_given"`
	Pieces      int     `json:"pieces,omitempty"`
	Span        float64 `json:"first_to_last_ms,omitempty"`
	LargestGap  float64 `json:"largest_gap_ms,omitempty"`
	ContentType string  `json:"content_type,omitempty"`
	Error       string  `json:"error,omitempty"`
	ShouldRetry string  `json:"x_should_retry,omitempty"`
	Body        string  `json:"body,omitempty"`
}

// liveGuestScan is the guest's own scan of its environment, processes and files.
type liveGuestScan struct {
	Bytes   int      `json:"bytes"`
	Windows int      `json:"windows"`
	Places  int      `json:"places"`
	Hits    []string `json:"hits"`
	Stopped bool     `json:"stopped_at_limit"`
}

// liveOutputScan is this program's scan of what the run sent and answered.
type liveOutputScan struct {
	Bytes   int `json:"bytes"`
	Windows int `json:"windows"`
	Hits    int `json:"hits"`
}

// liveGuestDoc is what a live guest printed.
type liveGuestDoc struct {
	SDKs      map[string]string `json:"sdks"`
	Sockets   map[string]string `json:"sockets"`
	Processes []struct {
		Error string `json:"error"`
	} `json:"processes"`
	Calls struct {
		Plain   liveGuestCall `json:"plain"`
		Stream  liveGuestCall `json:"stream"`
		Refused liveGuestCall `json:"refused"`
		Scan    liveGuestScan `json:"key_scan"`
	} `json:"calls"`
}

type liveGuestCall struct {
	Status      int     `json:"status"`
	Model       string  `json:"model"`
	Answer      string  `json:"answer"`
	Finish      string  `json:"finish"`
	Input       *int    `json:"input_tokens"`
	Output      *int    `json:"output_tokens"`
	ContentType string  `json:"content_type"`
	StartedMs   float64 `json:"started_ms"`
	Error       *string `json:"error"`
	ShouldRetry string  `json:"x_should_retry"`
	Body        string  `json:"body"`
	Pieces      []struct {
		AtMs float64 `json:"at_ms"`
	} `json:"pieces"`
}

// checkLiveGuestCode: the signed request carries this program's guest code byte for byte. The
// page's claims are that code's report, so a run of other code must not derive.
func checkLiveGuestCode(a liveAPI, spec string, req *plimsollv1.RunRequest) error {
	want := map[string]string{}
	for _, f := range liveGuestFiles(a, spec) {
		want[f.Path] = f.Content
	}
	files := req.GetProject().GetFiles()
	if len(files) != len(want) {
		return fmt.Errorf("the signed request carries %d files; this program sends %d", len(files), len(want))
	}
	for _, f := range files {
		if w, ok := want[f.GetPath()]; !ok || f.GetContent() != w {
			return fmt.Errorf("the signed request's %s is not this program's guest code", f.GetPath())
		}
	}
	if steps := req.GetProject().GetSteps(); !slices.Equal(steps, guestSteps) {
		return fmt.Errorf("the signed request's steps are %q; this program's are %q", steps, guestSteps)
	}
	return nil
}

func callOf(g liveGuestCall, name, title string) liveCallView {
	cv := liveCallView{Name: name, Title: title, Status: g.Status, Model: g.Model, Answer: g.Answer, Finish: g.Finish, ContentType: g.ContentType, ShouldRetry: g.ShouldRetry, Body: g.Body}
	if g.Error != nil {
		cv.Error = *g.Error
	}
	if g.Input != nil && g.Output != nil {
		cv.Input, cv.Output, cv.UsageGiven = *g.Input, *g.Output, true
	}
	cv.Pieces = len(g.Pieces)
	for i, p := range g.Pieces {
		if i > 0 {
			gap := p.AtMs - g.Pieces[i-1].AtMs
			if gap > cv.LargestGap {
				cv.LargestGap = gap
			}
		}
	}
	if cv.Pieces > 1 {
		cv.Span = g.Pieces[cv.Pieces-1].AtMs - g.Pieces[0].AtMs
	}
	return cv
}

// deriveLive reads the raw files of a live run in dir/live, checks the signatures that bind
// them, and computes what the section states.
func deriveLive(dir string) (*liveResults, error) {
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, liveDir, name)) }
	pubPEM, err := read(filePub)
	if err != nil {
		return nil, err
	}
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filePub, err)
	}
	v := attest.NewVerifier(pub)
	bundleRaw, err := read(fileBundle)
	if err != nil {
		return nil, err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(bundleRaw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileBundle, err)
	}
	rep, err := attest.VerifyBundle(entries, v)
	if err != nil {
		return nil, fmt.Errorf("%s does not verify: %w", fileBundle, err)
	}
	type call struct {
		rec  sandbox.RunRecord
		req  *plimsollv1.RunRequest
		resp *plimsollv1.RunResponse
		raw  [][]byte
	}
	calls := map[string]call{}
	for _, e := range entries {
		if len(e.Request) == 0 {
			continue
		}
		rec, err := v.Verify(e.Envelope)
		if err != nil {
			return nil, err
		}
		req, resp, err := e.Messages()
		if err != nil {
			return nil, err
		}
		calls[rec.SHA256] = call{rec: rec, req: req, resp: resp, raw: [][]byte{e.Request, e.Response}}
	}
	envRaw, err := read(fileObserved)
	if err != nil {
		return nil, err
	}
	var env attest.Envelope
	if err := json.Unmarshal(envRaw, &env); err != nil {
		return nil, fmt.Errorf("%s: %w", fileObserved, err)
	}
	var obs liveObservations
	subjects, err := v.OpenStatement(env, liveObservationType, &obs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileObserved, err)
	}
	if len(subjects) != len(obs.Runs) || rep.Runs != len(obs.Runs) || len(calls) != len(obs.Runs) {
		return nil, fmt.Errorf("the statement names %d records for %d runs; the bundle holds %d runs", len(subjects), len(obs.Runs), rep.Runs)
	}
	grants, err := read(fileGrants)
	if err != nil {
		return nil, err
	}
	if got := sha256Hex(grants); got != obs.Files[fileGrants] {
		return nil, fmt.Errorf("%s has SHA-256 %s; the signed statement names %s", fileGrants, got, obs.Files[fileGrants])
	}
	profiles, err := readProfiles(grants)
	if err != nil {
		return nil, err
	}
	byProfile := map[string]profileView{}
	for _, p := range profiles {
		byProfile[p.Name] = p
	}
	specRaw, err := json.Marshal(obs.Scan)
	if err != nil {
		return nil, err
	}
	lr := &liveResults{Upstream: obs.Upstream, Date: obs.Date, Commit: obs.Commit, KeyID: attest.KeyID(pub), Daemon: obs.Daemon, Image: obs.Image,
		Budget: obs.Budget, WorstCase: obs.WorstCase, Scan: obs.Scan}
	for _, name := range []string{fileBundle, filePub, fileObserved, fileGrants} {
		b, err := read(name)
		if err != nil {
			return nil, err
		}
		lr.Files = append(lr.Files, fileView{Name: name, Bytes: len(b), SHA256: sha256Hex(b)})
	}
	for i, r := range obs.Runs {
		if subjects[i].Digest["sha256"] != r.Record {
			return nil, fmt.Errorf("the statement's subject %d is not run %s's record", i+1, r.Name)
		}
		c, ok := calls[r.Record]
		if !ok {
			return nil, fmt.Errorf("run %s's record %s is not in the bundle", r.Name, r.Record)
		}
		var api *liveAPI
		for j := range realAPIs {
			if realAPIs[j].Name == r.Name {
				api = &realAPIs[j]
			}
		}
		if api == nil {
			return nil, fmt.Errorf("no live API is named %q", r.Name)
		}
		if obs.Upstream == "real" && byProfile[r.Name].BaseURL != api.BaseURL {
			return nil, fmt.Errorf("run %s went to %s, not %s, and calls itself real", r.Name, byProfile[r.Name].BaseURL, api.BaseURL)
		}
		if err := checkLiveGuestCode(*api, string(specRaw), c.req); err != nil {
			return nil, fmt.Errorf("run %s: %w", r.Name, err)
		}
		var facts liveAPIFacts
		for _, f := range obs.APIs {
			if f.Name == r.Name {
				facts = f
			}
		}
		if facts.Name == "" {
			return nil, fmt.Errorf("the statement names no API for run %s", r.Name)
		}
		view, err := deriveLiveRun(facts, r, c.rec, c.resp, c.raw, byProfile[r.Name], obs)
		if err != nil {
			return nil, fmt.Errorf("run %s: %w", r.Name, err)
		}
		lr.APIs = append(lr.APIs, view)
		lr.CostUSD += view.CostUSD
	}
	lr.CostUSD = round6(lr.CostUSD)
	lr.Checks = liveChecks(lr, rep, obs)
	return lr, nil
}

func round6(v float64) float64 {
	return float64(int64(v*1e6+0.5)) / 1e6
}

func deriveLiveRun(a liveAPIFacts, rf runFacts, rec sandbox.RunRecord, resp *plimsollv1.RunResponse, stored [][]byte, prof profileView, obs liveObservations) (liveAPIView, error) {
	v := liveAPIView{Profile: a.Name, Vendor: a.Vendor, BaseURL: prof.BaseURL, Model: a.Model, Route: a.Route, PassHeaders: prof.PassHeaders, TokenEnv: prof.TokenEnv,
		PriceIn: a.PriceIn, PriceOut: a.PriceOut, Audit: rf.Audit,
		Record: recordView{SHA256: rec.SHA256, Request: rec.RequestSHA256, Result: rec.ResultSHA256, Provider: rec.Provider,
			Isolation: rec.Isolation, Environment: rec.Environment, Policy: rec.Policy, StartedMs: rec.Started.UnixMilli(), EndedMs: rec.Ended.UnixMilli()}}
	pr := resp.GetProject()
	if pr == nil || len(pr.GetSteps()) != 1 {
		return v, errors.New("the stored answer is not a one-step project result")
	}
	step := pr.GetSteps()[0]
	var g liveGuestDoc
	if err := json.Unmarshal(bytes.TrimSpace(step.GetStdout()), &g); err != nil {
		return v, fmt.Errorf("the guest's output is not its JSON report: %w", err)
	}
	for name, version := range g.SDKs {
		v.Library = name + " " + version
	}
	v.Scan = g.Calls.Scan
	if v.Scan.Hits == nil {
		v.Scan.Hits = []string{}
	}
	v.Calls = []liveCallView{
		callOf(g.Calls.Plain, "plain", "A plain call"),
		callOf(g.Calls.Stream, "stream", "The same call, streamed"),
		callOf(g.Calls.Refused, "refused", "A route the profile does not allow"),
	}
	for _, c := range v.Calls[:2] {
		if c.UsageGiven {
			v.Input += c.Input
			v.Output += c.Output
		} else {
			// A call with no usage is counted at its limits, so the cost is never low.
			v.Input += liveInputTokens
			v.Output += liveMaxTokens
		}
	}
	v.CostUSD = round6((float64(v.Input)*a.PriceIn + float64(v.Output)*a.PriceOut) / 1e6)
	for _, m := range obs.Metrics {
		if m.Profile == a.Name {
			v.Metrics = append(v.Metrics, m)
		}
	}
	// Everything the run sent and answered: the stored messages, and the output as text, in
	// case the wire form encodes it.
	for _, b := range append(append([][]byte{}, stored...), step.GetStdout(), step.GetStderr()) {
		hits, windows, err := scanWindows(b, obs.Scan)
		if err != nil {
			return v, err
		}
		v.OutputScan.Hits += hits
		v.OutputScan.Windows += windows
		v.OutputScan.Bytes += len(b)
	}
	return v, nil
}

func liveChecks(lr *liveResults, rep attest.Report, obs liveObservations) []check {
	var out []check
	add := func(id, says string, pass bool, detail string, args ...any) {
		out = append(out, check{ID: id, Says: says, Pass: pass, Detail: fmt.Sprintf(detail, args...)})
	}
	add("records", "Each run's record is signed by the harness and checks against the request and answer stored with it.",
		rep.Runs == len(lr.APIs) && len(lr.APIs) > 0, "%d runs verified", rep.Runs)
	outputHits, guestHits, windows, guestWindows, stopped := 0, 0, 0, 0, false
	for _, a := range lr.APIs {
		outputHits += a.OutputScan.Hits
		windows += a.OutputScan.Windows
		guestHits += len(a.Scan.Hits)
		guestWindows += a.Scan.Windows
		stopped = stopped || a.Scan.Stopped
	}
	add("key-not-in-output", "Neither key's bytes appear in what either run was sent or answered, its output included.",
		outputHits == 0 && windows > 0, "%d matches in %d windows", outputHits, windows)
	add("key-not-in-sandbox", "Neither key's bytes appear in any process environment or command line the guest could read, or in its files.",
		guestHits == 0 && guestWindows > 0 && !stopped, "%d matches in %d windows; stopped at its size limit: %v", guestHits, guestWindows, stopped)
	answered, streamed, refused := true, true, true
	var answerDetail, streamDetail, refusedDetail []string
	for _, a := range lr.APIs {
		plain, stream, ref := a.Calls[0], a.Calls[1], a.Calls[2]
		answered = answered && plain.Status == 200 && plain.UsageGiven && plain.Output > 0
		answerDetail = append(answerDetail, fmt.Sprintf("%s: status %d, %d output tokens", a.Vendor, plain.Status, plain.Output))
		streamed = streamed && stream.Status == 200 && strings.HasPrefix(stream.ContentType, "text/event-stream") && stream.Pieces >= 2 && stream.Span >= liveStreamSpanMs
		streamDetail = append(streamDetail, fmt.Sprintf("%s: %d pieces over %.0f ms", a.Vendor, stream.Pieces, stream.Span))
		refused = refused && ref.Status == 403 && ref.ShouldRetry == "false" && a.Audit.HostCallsDenied == 1 && a.Audit.HostCalls == 2
		refusedDetail = append(refusedDetail, fmt.Sprintf("%s: status %d, %d allowed and %d denied on the audit line", a.Vendor, ref.Status, a.Audit.HostCalls, a.Audit.HostCallsDenied))
	}
	add("api-answered", "Each API answered its plain call, and reported the tokens it used.", answered && len(lr.APIs) > 0, "%s", strings.Join(answerDetail, "; "))
	add("stream", fmt.Sprintf("Each streamed answer reached the guest's library in pieces over at least %d ms; one handed over in a single block takes about 3 ms.", liveStreamSpanMs),
		streamed && len(lr.APIs) > 0, "%s", strings.Join(streamDetail, "; "))
	add("refusal", "The call to a route the profile does not allow was refused by the broker and marked not to retry: the daemon's audit line counts two calls that went on and one it denied.",
		refused && len(lr.APIs) > 0, "%s", strings.Join(refusedDetail, "; "))
	add("cost", "The tokens the APIs reported, at list price, came in under the budget.", lr.CostUSD <= lr.Budget, "$%.6f of $%.2f; at most $%.6f by arithmetic before the run", lr.CostUSD, lr.Budget, lr.WorstCase)
	pins := map[string]string{}
	for _, p := range obs.Pins {
		pins[p.Name] = p.Version
	}
	pinned := true
	var libs []string
	for _, a := range lr.APIs {
		name, version, _ := strings.Cut(a.Library, " ")
		pinned = pinned && version != "" && pins[name] == version
		libs = append(libs, a.Library)
	}
	add("versions", "The guest imported the pinned versions of both libraries.", pinned && len(lr.APIs) > 0, "%s", strings.Join(libs, ", "))
	return out
}

func marshalLive(lr *liveResults) ([]byte, error) {
	raw, err := json.MarshalIndent(lr, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// loadLive reads the live results beside the page, or nil if there are none. The page and
// -verify refuse results that are not a real run's: a stub run must never read as one.
func loadLive(dir string) (*liveResults, error) {
	path := filepath.Join(dir, liveDir, fileLive)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var lr liveResults
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lr); err != nil {
		return nil, fmt.Errorf("%s: %w", fileLive, err)
	}
	if lr.Upstream != "real" {
		return nil, fmt.Errorf("%s says its upstream was %q: only a real run belongs beside the page", fileLive, lr.Upstream)
	}
	return &lr, nil
}

// verifyLive checks the live files, if any: they derive to the stated results byte for byte,
// every check holds, and no published file holds a window of either key.
func verifyLive(dir string, lr *liveResults) error {
	if lr == nil {
		return nil
	}
	got, err := deriveLive(dir)
	if err != nil {
		return err
	}
	derived, err := marshalLive(got)
	if err != nil {
		return err
	}
	stated, err := os.ReadFile(filepath.Join(dir, liveDir, fileLive))
	if err != nil {
		return err
	}
	if !bytes.Equal(derived, stated) {
		return fmt.Errorf("%s is not what the live files give", fileLive)
	}
	for _, c := range got.Checks {
		if !c.Pass {
			return fmt.Errorf("the live check %q does not hold: %s", c.ID, c.Detail)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, liveDir))
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, liveDir, name))
		if err != nil {
			return err
		}
		hits, _, err := scanWindows(b, got.Scan)
		if err != nil {
			return err
		}
		if hits != 0 {
			return fmt.Errorf("%s holds a key: %d windows match its digest", name, hits)
		}
	}
	return nil
}
