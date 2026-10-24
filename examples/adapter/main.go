// Command adapter is the vendor adapter example: the loop a platform needs when an
// AI writes the code that integrates a vendor's device API.
//
// A fictional fleet vendor's OpenAPI document goes in. From it, specgen derives the
// grant's allow list, the typed client the sandbox injects and the description an
// agent is shown. plimsolld, built from this checkout and started on loopback with the
// docker provider, runs the platform's harness with an adapter against a simulated
// vendor API: the first adapter over eight scenarios, a boundary probe, the rewritten
// second adapter over the same eight, and ten adapters broken on purpose. Every run
// reaches the vendor only through the grant, under a credential minted for that run.
//
// The harness only reports. The verdict is made here, on the host, by package qualify,
// from the plan the run was sent and the vendor's ledger, and signed as a
// qualification statement bound to the run's record; the attest harness signs the
// records themselves. The page it writes shows all of it with the numbers from this
// run.
//
//	make docker-images && go run ./examples/adapter
//
// Needs docker. Writes docs/examples/adapter/index.html, bundle.jsonl,
// qualification.jsonl and harness.pub (override the page path with -out).
// SANDBOX_DOCKER_RUNTIME=runsc runs it under gVisor.
//
//	go run ./examples/adapter -verify docs/examples/adapter
//
// checks published files offline: the bundle, then every statement against it, each
// verdict rebuilt from its evidence. It starts nothing.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/examples/adapter/fleetsim"
	"github.com/plimsollmark/plimsoll/examples/adapter/qualify"
	"github.com/plimsollmark/plimsoll/examples/internal/daemonproc"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/auditline"
	"github.com/plimsollmark/plimsoll/internal/specgen"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const (
	callerID  = "example-client"
	profile   = "fleet"
	secretEnv = "FLEET_JWT_SECRET"
	audience  = "fleet-vendor"

	pageURL   = "https://plimsollmark.github.io/plimsoll/examples/adapter/index.html"
	repoURL   = "https://github.com/plimsollmark/plimsoll"
	sourceURL = repoURL + "/tree/main/examples/adapter"
	homeURL   = "https://plimsollmark.github.io/plimsoll/"
)

//go:embed page.html
var pageTemplate string

func main() {
	out := flag.String("out", filepath.Join("docs", "examples", "adapter", "index.html"), "where to write the page; the bundle and key go beside it")
	check := flag.String("verify", "", "verify the published bundle.jsonl, qualification.jsonl and harness.pub in this directory, and run nothing")
	flag.Parse()
	if *check != "" {
		n, err := verifyDir(*check)
		if err != nil {
			fmt.Fprintln(os.Stderr, "adapter: verify:", err)
			os.Exit(1)
		}
		fmt.Printf("verified: %d run records and %d qualification statements, every verdict rebuilt from its evidence\n", n, n)
		return
	}
	if err := run(context.Background(), *out); err != nil {
		fmt.Fprintln(os.Stderr, "adapter:", err)
		os.Exit(1)
	}
}

type opRow struct {
	Method, Path, ID, Summary string
	Granted                   bool
	Badge, Label              string // ok "granted" or off "catalog only"
}

type scenarioRun struct {
	N          int
	Group      string // first, probe, second or broken
	Title      string
	Vendor     string // what the vendor did
	Scenario   string
	Adapter    string
	Step       string
	WantFail   []string // the rules this run must fail; nil means it must pass
	Measured   bool     // a trial run: no expectation, its result is what was measured
	Plan       qualify.Plan
	Report     *qualify.Report
	Probe      *qualify.ProbeReport
	Ledger     []fleetsim.Order
	Events     []fleetsim.Event // what the vendor did, in order: the floor replays it
	Rules      []ruleCell
	Pass       bool
	Verdict    string // one line
	Badge      string // ok or no, the page's badge class
	Label      string // passed, failed, or caught for a broken adapter
	Calls      string // the brokered-call cell: served, shed, denied
	Orders     [3]int // the vendor's ledger per robot, r1 r2 r3
	R2Class    string // "chip bad" when r2 holds two orders
	AdviceTxt  string // the finding cell, or ""
	PollsTxt   string // status reads, or ""
	Millis     int64
	Audit      auditline.Run
	Vendor2    []string // the vendor's own counts by route template
	Refused    int
	Advice     []sandbox.AdviceFinding
	Record     string
	Request    string
	Result     string
	Isolation  string
	Credential string // the run's credential ID, shortened
	statement  attest.Envelope
}

// trialView is one independent agent's adapter as the page shows it.
type trialView struct {
	Name, Dir    string
	Lines        int
	Passed, Runs int
	Badge, Label string
	Cells        []trialCell
	Notes        []string // why each failed run failed
}

type trialCell struct{ Scenario, Badge, Label string }

// ruleCell is one rule's outcome as the page shows it.
type ruleCell struct {
	Name, Says, Detail string
	Held               bool
	Mark, Class, Badge string // the cell's symbol and class, and the badge class
}

type check struct {
	What, Short, Verdict, Detail string
	Pass                         bool
	Badge                        string // ok or no, the page's badge class
}

type pageData struct {
	Date, Provider, Tier, Runtime, Environment, Software, Policy string
	SpecTitle, SpecVersion                                       string
	Operations                                                   []opRow
	Allow, Catalog                                               []string
	BatchOf, HealthCheck, Description, Preamble                  string
	Contract, PromptHead                                         string
	InventoryV1, InventoryV2, DispatchV2                         string
	Runs                                                         []scenarioRun
	Scenarios                                                    []scenarioChoice
	Finding                                                      sandbox.AdviceFinding
	HasFinding                                                   bool
	V1Calls, V2Calls                                             int
	Probe                                                        qualify.ProbeReport
	KeyID                                                        string
	Checks                                                       []check
	Passed, Failed, Total                                        int
	AdapterRules                                                 []qualify.Rule
	Matrix                                                       []scenarioRun
	Credentials, CredentialLife                                  int
	FirstFailed, BrokenCaught, TrialPassed, TrialRuns            int
	RunLost1, RunDrop1, RunErr1, RunLost2, RunDrop2, RunErr2     int
	RunProbe                                                     int
	ProbeRuleCells                                               []ruleCell
	Trial                                                        []trialView
	FloorJSON                                                    template.JS
	PageURL, SourceURL, HomeURL, RepoURL                         string
}

// scenarioChoice is one scenario button on the floor, in fleetsim.ScenarioOrder.
type scenarioChoice struct{ Name, Title string }

func run(ctx context.Context, out string) error {
	workDir, err := os.MkdirTemp("", "plimsoll-adapter-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	// 1. The vendor's document, and the three artifacts generated from it.
	specBytes, err := os.ReadFile(filepath.Join("examples", "adapter", "vendor", "fleet.openapi.json"))
	if err != nil {
		return fmt.Errorf("read the vendor spec (run this from the repository root): %w", err)
	}
	gen, err := specgen.Generate(specBytes, specgen.Options{Global: "fleet"})
	if err != nil {
		return fmt.Errorf("specgen: %w", err)
	}
	var allow []string
	for _, r := range gen.Allow {
		if r.Method == "DELETE" || strings.HasSuffix(r.Path, "/firmware") {
			continue
		}
		allow = append(allow, r.Method+" "+r.Path)
	}
	catalog := gen.AllowStrings()
	fmt.Printf("spec      | %s v%s: %d operations; %d granted, %d catalog only\n", gen.Title, gen.Version, len(catalog), len(allow), len(catalog)-len(allow))
	ops, err := operationRows(specBytes, allow)
	if err != nil {
		return err
	}

	files, texts, err := readInputs(runPlan())
	if err != nil {
		return err
	}

	// 2. The simulated vendor, on loopback, and the profile that reaches it. The
	// profile mints a JWT per run; the vendor verifies each one and records its ID.
	secret, err := randomHex(24)
	if err != nil {
		return err
	}
	sim := fleetsim.New(fleetsim.HS256([]byte(secret), audience))
	upstream := httptest.NewServer(sim)
	defer upstream.Close()

	grantsDir := filepath.Join(workDir, "grants")
	if err := os.MkdirAll(grantsDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(grantsDir, "preamble.js"), []byte(gen.Preamble), 0o600); err != nil {
		return err
	}
	grantsPath, err := writeGrantsFile(grantsDir, upstream.URL, allow, catalog, gen.BatchOf, gen.HealthCheck)
	if err != nil {
		return err
	}
	clientToken, clientsPath, err := daemonproc.ClientsFile(workDir, callerID)
	if err != nil {
		return err
	}
	fmt.Printf("profile   | %q grants %d routes, declares %s, health %s, advice=caller, a JWT per run\n", profile, len(allow), describeBatch(gen.BatchOf), gen.HealthCheck)

	// 3. The daemon, built from this checkout, docker provider.
	binary, err := daemonproc.Build(ctx, workDir)
	if err != nil {
		return err
	}
	// The daemon's log is captured so each run's audit line can be read back.
	sink := &lineSink{}
	env := []string{"SANDBOX_PROVIDER=docker", "PLIMSOLL_CLIENTS_FILE=" + clientsPath,
		"PLIMSOLL_GRANTS_FILE=" + grantsPath, secretEnv + "=" + secret}
	if abs, err := filepath.Abs(filepath.Join("docker", "seccomp.json")); err == nil {
		if _, err := os.Stat(abs); err == nil && os.Getenv("SANDBOX_DOCKER_SECCOMP") == "" {
			env = append(env, "SANDBOX_DOCKER_SECCOMP="+abs)
		}
	}
	daemon, err := daemonproc.Start(ctx, binary, daemonproc.Options{Env: env, Ready: 3 * time.Minute, Log: sink})
	if err != nil {
		return fmt.Errorf("%w (is docker running, with the images from `make docker-images`?)\n--- daemon log ---\n%s", err, sink.tail(40))
	}
	defer func() { _ = daemon.Stop(10 * time.Second) }()

	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var bundle bytes.Buffer
	harness := attest.NewHarness(attest.NewSigner(key), &bundle)
	remote, err := client.New(daemon.BaseURL, client.WithToken(clientToken), client.WithProjectGrantProfile(profile), client.WithRecorder(harness))
	if err != nil {
		return err
	}
	info, err := remote.Describe(ctx)
	if err != nil {
		return err
	}
	if !info.SupportsProjectGrants {
		return errors.New("the daemon states no project grants")
	}
	fmt.Printf("daemon    | %s at the %s tier, project environment %s\n", info.Sandbox, info.Isolation, orNone(info.Environments.Project.Identity))

	data := pageData{
		Date: time.Now().UTC().Format("2006-01-02"), Provider: info.Sandbox, Tier: info.Isolation.String(),
		Runtime: runtimeName(), Environment: orNone(info.Environments.Project.Identity),
		Software: orNone(info.Environments.Project.SoftwareIdentity), Policy: orNone(info.Environments.Policy),
		SpecTitle: gen.Title, SpecVersion: gen.Version, Operations: ops, Allow: allow, Catalog: catalog,
		BatchOf: describeBatch(gen.BatchOf), HealthCheck: gen.HealthCheck, Description: gen.Description, Preamble: gen.Preamble,
		Contract: contractBlock(texts["CONTRACT.md"]), PromptHead: promptHead(texts["PROMPT.md"]),
		InventoryV1: inventoryOf(texts["adapter-v1.js"]), InventoryV2: inventoryOf(texts["adapter-v2.js"]),
		DispatchV2: functionOf(texts["adapter-v2.js"], "dispatch"),
		KeyID:      attest.KeyID(pub), PageURL: pageURL, SourceURL: sourceURL, HomeURL: homeURL, RepoURL: repoURL,
		AdapterRules: qualify.AdapterRules,
	}

	// 4. The runs.
	plan := runPlan()
	credentials := map[string]int{}
	for i := range plan {
		r := &plan[i]
		r.N = i + 1
		r.Vendor = fleetsim.Scenarios[r.Scenario].Says
		r.Plan = qualify.NewPlan(r.N)
		if r.Group == "probe" {
			r.Step = "node probe.js " + upstream.URL
			r.Vendor = "nothing special: the probe is what tries things"
		} else {
			r.Step = "node harness.js " + r.Scenario + " " + r.Adapter
		}
		planJSON, err := json.Marshal(r.Plan)
		if err != nil {
			return err
		}
		runFiles := append(append([]sandbox.File(nil), files...), sandbox.File{Path: "plan.json", Content: string(planJSON)})
		sim.Reset(r.Scenario)
		mark := sink.mark()
		t0 := time.Now()
		res, err := remote.RunProject(client.NewTraceContext(ctx, fmt.Sprintf("adapter-run-%d", r.N)), sandbox.ProjectRequest{
			Files: runFiles, Steps: []string{r.Step}, Timeout: 90 * time.Second, MinimumIsolation: sandbox.IsolationContainer,
		})
		if err != nil {
			return fmt.Errorf("run %d: %w", r.N, err)
		}
		r.Millis = time.Since(t0).Milliseconds()
		if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Record == nil {
			return fmt.Errorf("run %d: outcome %v (%s)", r.N, res.Outcome, res.Detail)
		}
		r.Isolation = res.Isolation.String()
		r.Audit = sink.auditSince(mark)
		r.Vendor2 = fleetsim.SortedCounts(sim.Counts())
		r.Refused = sim.Refused()
		if r.Refused > 0 {
			r.Vendor2 = append(r.Vendor2, fmt.Sprintf("503 answered: %d", r.Refused))
		}
		r.Calls = fmt.Sprintf("%d served", r.Audit.HostCalls)
		if r.Audit.HostCallsShed > 0 {
			r.Calls += fmt.Sprintf(", %d shed", r.Audit.HostCallsShed)
		}
		if r.Audit.HostCallsDenied > 0 {
			r.Calls += fmt.Sprintf(", %d denied", r.Audit.HostCallsDenied)
		}
		switch len(res.Advice) {
		case 0:
			r.AdviceTxt = "no finding"
		case 1:
			r.AdviceTxt = "1 finding, agent-fixable"
		default:
			r.AdviceTxt = fmt.Sprintf("%d findings, agent-fixable", len(res.Advice))
		}
		orders := sim.Orders()
		r.Orders = [3]int{orders["r1"], orders["r2"], orders["r3"]}
		r.R2Class = "chip"
		if orders["r2"] > 1 {
			r.R2Class = "chip bad"
		}
		r.Advice = res.Advice
		r.Record, r.Request, r.Result = res.Record.SHA256, res.Record.RequestSHA256, res.Record.ResultSHA256
		if sim.Unauthorized() != 0 || len(sim.Reached()) != 0 || sim.Illegal() != 0 {
			return fmt.Errorf("run %d: the vendor saw %d unauthenticated request(s), %v on catalog-only routes, %d illegal transitions", r.N, sim.Unauthorized(), sim.Reached(), sim.Illegal())
		}

		// The run's credential: one, minted for this run alone, for this caller, living
		// no longer than the run's budget plus the minter's five seconds of grace.
		creds := sim.Credentials()
		for _, c := range creds {
			if prev, dup := credentials[c.ID]; dup {
				return fmt.Errorf("run %d reused run %d's credential", r.N, prev)
			}
			credentials[c.ID] = r.N
			if c.Subject != callerID || c.LifetimeSeconds > 95 {
				return fmt.Errorf("run %d: credential for %q living %d s", r.N, c.Subject, c.LifetimeSeconds)
			}
			data.CredentialLife = int(c.LifetimeSeconds)
			r.Credential = c.ID
			if len(r.Credential) > 8 {
				r.Credential = r.Credential[:8]
			}
		}
		if len(creds) > 1 || (len(creds) == 0 && r.Group != "probe") {
			return fmt.Errorf("run %d: the vendor saw %d credentials", r.N, len(creds))
		}

		// The evidence, the verdict made from it, and the statement that signs both.
		stdout := string(res.Steps[0].Stdout)
		ev := qualify.Evidence{
			Kind: qualify.KindAdapter, Scenario: sim.Scenario(), Plan: r.Plan, Ledger: sim.Ledger(), Robots: sim.Robots(), Reads: sim.Reads(), Told: sim.Told(),
			Vendor:      qualify.VendorCounts{CatalogOnly: sim.Reached(), Unauthorized: sim.Unauthorized()},
			Credentials: creds, BrokerDenied: r.Audit.HostCallsDenied, ExitCode: res.Steps[0].ExitCode,
		}
		adapterPath := r.Adapter
		if r.Group == "probe" {
			// The probe places no order, so its evidence carries no plan.
			ev.Kind, ev.Probe, ev.Plan, adapterPath = qualify.KindProbe, qualify.ReadProbe(stdout), qualify.Plan{}, "probe.js"
			if ev.Probe == nil {
				return fmt.Errorf("run %d: no probe report (stdout %q, stderr %q)", r.N, stdout, res.Steps[0].Stderr)
			}
			r.Probe = ev.Probe
			data.Probe = *ev.Probe
			r.PollsTxt = "no missions"
		} else {
			ev.Report = qualify.ReadReport(stdout)
			if ev.Report == nil {
				return fmt.Errorf("run %d: no report (stdout %q, stderr %q)", r.N, stdout, res.Steps[0].Stderr)
			}
			r.Report = ev.Report
			r.PollsTxt = fmt.Sprintf("%d status reads", ev.Report.Polls)
		}
		r.Ledger = ev.Ledger
		events, lost := sim.Events()
		if lost > 0 {
			return fmt.Errorf("run %d: the vendor's event log overflowed by %d", r.N, lost)
		}
		r.Events = events
		outcomes, pass := qualify.Evaluate(ev)
		r.Pass = pass
		r.Rules, r.Verdict = ruleCells(ev.Kind, outcomes)
		pred := qualify.Predicate{
			Run: r.N, Simulator: fleetsim.Version,
			Adapter:  qualify.FileDigest{Path: adapterPath, SHA256: qualify.Digest(contentOf(runFiles, adapterPath))},
			Evidence: ev, Rules: outcomes, Verdict: qualify.Verdict(pass),
		}
		if ev.Kind == qualify.KindAdapter {
			pred.Harness = qualify.Digest(contentOf(runFiles, "harness.js"))
		}
		if r.statement, err = qualify.Sign(key, res.Record.SHA256, pred); err != nil {
			return err
		}
		var failed []string
		for _, o := range outcomes {
			if !o.Held {
				failed = append(failed, o.Rule)
			}
		}
		if !r.Measured && !slices.Equal(failed, r.WantFail) {
			return fmt.Errorf("run %d (%s): failed rules %v, want %v: %s", r.N, r.Title, failed, r.WantFail, r.Verdict)
		}
		fmt.Printf("run %-2d    | %s: %s (%d host calls, %d shed, %d denied, %d finding(s), %d ms)\n", r.N, r.Title, r.Verdict, r.Audit.HostCalls, r.Audit.HostCallsShed, r.Audit.HostCallsDenied, len(r.Advice), r.Millis)
	}

	// 5. What the story depends on, checked rather than asserted. Each run's failed
	// rules were checked against WantFail above.
	byTitle := func(group, scenario string) *scenarioRun {
		for i := range plan {
			if plan[i].Group == group && plan[i].Scenario == scenario {
				return &plan[i]
			}
		}
		return nil
	}
	first, overload, probe, second := byTitle("first", fleetsim.ScenarioNominal), byTitle("first", fleetsim.ScenarioOverload), byTitle("probe", fleetsim.ScenarioNominal), byTitle("second", fleetsim.ScenarioNominal)
	if len(first.Advice) != 1 || first.Advice[0].SuggestedRoute != "/robots" || first.Advice[0].SuggestedMethod != "GET" {
		return fmt.Errorf("the first adapter's nominal run should carry one finding naming GET /robots, got %+v", first.Advice)
	}
	data.Finding, data.HasFinding = first.Advice[0], true
	if len(second.Advice) != 0 {
		return fmt.Errorf("the second adapter's run should carry no finding, got %+v", second.Advice)
	}
	data.V1Calls, data.V2Calls = first.Audit.HostCalls, second.Audit.HostCalls
	if data.V2Calls >= data.V1Calls {
		return fmt.Errorf("the second adapter made %d calls against the first's %d", data.V2Calls, data.V1Calls)
	}
	if overload.Audit.HostCallsShed == 0 || overload.Refused != fleetsim.DegradedRequests || overload.Report.Retries == 0 {
		return fmt.Errorf("overload: shed %d, vendor refused %d, adapter retries %d", overload.Audit.HostCallsShed, overload.Refused, overload.Report.Retries)
	}
	if probe.Audit.HostCallsDenied != 1 {
		return fmt.Errorf("probe: the broker denied %d, want 1", probe.Audit.HostCallsDenied)
	}
	data.Credentials = len(credentials)
	data.RunLost1, data.RunDrop1 = byTitle("first", fleetsim.ScenarioLostAck).N, byTitle("first", fleetsim.ScenarioDropped).N
	data.RunLost2, data.RunDrop2 = byTitle("second", fleetsim.ScenarioLostAck).N, byTitle("second", fleetsim.ScenarioDropped).N
	data.RunErr1, data.RunErr2 = byTitle("first", fleetsim.ScenarioServerError).N, byTitle("second", fleetsim.ScenarioServerError).N
	data.RunProbe, data.ProbeRuleCells = probe.N, probe.Rules
	for i := range plan {
		r := &plan[i]
		if !r.Pass && r.Group == "first" {
			data.FirstFailed++
		}
		if !r.Pass && r.Group == "broken" {
			data.BrokenCaught++
		}
		switch {
		case r.Pass:
			data.Passed++
			r.Badge, r.Label = "ok", "passed"
		case r.Group == "broken":
			data.Failed++
			r.Badge, r.Label = "no", "caught"
		case r.Group == "trial":
			data.Failed++
			r.Badge, r.Label = "no", "failed"
		default:
			data.Failed++
			r.Badge, r.Label = "no", "failed"
		}
		data.Total++
		if r.Group != "probe" {
			data.Matrix = append(data.Matrix, *r)
		}
	}
	for _, m := range trialModels {
		v := trialView{Name: m.name, Dir: m.dir, Lines: strings.Count(contentOf(files, "trial/"+m.dir+".js"), "\n")}
		for _, r := range plan {
			if r.Adapter != "trial/"+m.dir+".js" {
				continue
			}
			v.Runs++
			c := trialCell{Scenario: scenarioTitles[r.Scenario], Badge: r.Badge, Label: "passed"}
			if r.Pass {
				v.Passed++
			} else {
				c.Label = "failed"
				v.Notes = append(v.Notes, scenarioTitles[r.Scenario]+", run "+fmt.Sprint(r.N)+": "+r.Verdict)
			}
			v.Cells = append(v.Cells, c)
		}
		if v.Runs == 0 {
			continue
		}
		data.TrialPassed, data.TrialRuns = data.TrialPassed+v.Passed, data.TrialRuns+v.Runs
		v.Badge, v.Label = "ok", fmt.Sprintf("%d of %d passed", v.Passed, v.Runs)
		if v.Passed != v.Runs {
			v.Badge = "no"
		}
		data.Trial = append(data.Trial, v)
	}
	data.Runs = plan
	for _, sc := range fleetsim.ScenarioOrder {
		data.Scenarios = append(data.Scenarios, scenarioChoice{Name: sc, Title: scenarioTitles[sc]})
	}
	floor, err := floorJSON(plan)
	if err != nil {
		return err
	}
	data.FloorJSON = floor

	// 6. The evidence: the bundle of run records and the qualification statements, each
	// verified as written and refused when changed.
	if err := harness.Checkpoint(); err != nil {
		return err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(bundle.Bytes()))
	if err != nil {
		return err
	}
	if len(entries) != len(plan)+1 {
		return fmt.Errorf("the bundle holds %d entries for %d runs and a checkpoint", len(entries), len(plan))
	}
	var statements []attest.Envelope
	for _, r := range plan {
		statements = append(statements, r.statement)
	}
	checks, err := evidenceChecks(pub, key, entries, statements, plan)
	if err != nil {
		return err
	}
	data.Checks = checks
	fmt.Printf("records   | %d signed, plus the checkpoint; %d qualification statements; %d checks as expected\n", len(entries)-1, len(statements), len(checks))

	// 7. The page, the bundle and the key.
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.jsonl"), bundle.Bytes(), 0o644); err != nil {
		return err
	}
	var qual bytes.Buffer
	for _, st := range statements {
		b, err := json.Marshal(st)
		if err != nil {
			return err
		}
		qual.Write(append(b, '\n'))
	}
	if err := os.WriteFile(filepath.Join(dir, "qualification.jsonl"), qual.Bytes(), 0o644); err != nil {
		return err
	}
	pubPEM, err := publicPEM(pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "harness.pub"), pubPEM, 0o644); err != nil {
		return err
	}
	tmpl, err := template.New("page").Parse(pageTemplate)
	if err != nil {
		return err
	}
	var page bytes.Buffer
	if err := tmpl.Execute(&page, data); err != nil {
		return err
	}
	if err := os.WriteFile(out, page.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("page      | %s\n", out)
	return nil
}

// floorJSON is what the page's floor replay needs: the fleet's starting poses (the
// simulated vendor's), the targets the plan sends (qualify's, so the two cannot drift),
// the fault step, and each run's measured outcome.
func floorJSON(runs []scenarioRun) (template.JS, error) {
	targets := map[string]fleetsim.Pose{}
	for _, c := range qualify.NewPlan(0).Commands {
		if !c.Cancel {
			targets[c.Robot] = c.Target
		}
	}
	type runOut struct {
		N        int                       `json:"n"`
		Group    string                    `json:"group"`
		Scenario string                    `json:"scenario"`
		Adapter  string                    `json:"adapter"`
		Title    string                    `json:"title"`
		Label    string                    `json:"label"`
		Badge    string                    `json:"badge"`
		Verdict  string                    `json:"verdict"`
		Calls    string                    `json:"calls"`
		Polls    int                       `json:"polls"`
		Retries  int                       `json:"retries"`
		Orders   map[string]int            `json:"orders"`
		Events   []fleetsim.Event          `json:"events,omitempty"`
		Stopped  map[string]*fleetsim.Pose `json:"stopped,omitempty"`
	}
	var outs []runOut
	for _, r := range runs {
		o := runOut{N: r.N, Group: r.Group, Scenario: r.Scenario, Adapter: r.Adapter, Title: r.Title, Label: r.Label, Badge: r.Badge, Verdict: r.Verdict,
			Calls: r.Calls, Orders: map[string]int{"r1": r.Orders[0], "r2": r.Orders[1], "r3": r.Orders[2]}}
		if r.Report != nil {
			o.Polls, o.Retries = r.Report.Polls, r.Report.Retries
		}
		if r.Group != "probe" && r.Group != "broken" {
			// The replay's events, and where the signed ledger says each order stopped, so
			// the page can show the two agree.
			o.Events, o.Stopped = r.Events, map[string]*fleetsim.Pose{}
			for _, ord := range r.Ledger {
				o.Stopped[ord.ID] = ord.StoppedAt
			}
		}
		outs = append(outs, o)
	}
	planned := map[string]int{}
	for _, c := range qualify.NewPlan(0).Commands {
		planned[c.Robot]++
	}
	b, err := json.Marshal(map[string]any{"start": fleetsim.StartPoses, "targets": targets, "planned": planned, "faultAt": fleetsim.FaultAtStep, "degraded": fleetsim.DegradedRequests, "titles": scenarioTitles, "runs": outs})
	if err != nil {
		return "", err
	}
	return template.JS(b), nil
}

// trialModels are the independent trial's agents (examples/adapter/trial): each one's
// final adapter runs over every scenario when its final.js is present.
var trialModels = []struct{ dir, name string }{{"haiku", "Claude Haiku"}, {"sonnet", "Claude Sonnet"}, {"opus", "Claude Opus"}}

// runPlan is the runs, in order: the first adapter over every scenario, the probe, the
// second adapter over every scenario, and ten adapters broken on purpose. WantFail is
// the rules each must fail, checked after the run; nil means every rule must hold.
// scenarioTitles names each scenario in plain words.
var scenarioTitles = map[string]string{
	fleetsim.ScenarioNominal: "nominal", fleetsim.ScenarioFault: "a fault", fleetsim.ScenarioOverload: "an overloaded vendor",
	fleetsim.ScenarioLostAck: "a lost answer", fleetsim.ScenarioDropped: "a dropped connection",
	fleetsim.ScenarioServerError: "a server error after accepting", fleetsim.ScenarioRefused: "a refused order",
	fleetsim.ScenarioSilent: "a vendor that never answers",
}

func runPlan() []scenarioRun {
	titles := scenarioTitles
	firstFails := map[string][]string{
		fleetsim.ScenarioLostAck:     {"one_order_per_command"},
		fleetsim.ScenarioDropped:     {"kept_the_shapes", "ended_as_it_should", "report_is_true"},
		fleetsim.ScenarioServerError: {"kept_the_shapes", "ended_as_it_should", "report_is_true"},
		// It throws the vendor's 409 on as it came, with no code: not the contract's refused.
		fleetsim.ScenarioRefused: {"kept_the_shapes", "report_is_true"},
		// It throws the vendor's 504 on as it came, with no code: not the contract's
		// unresolved. Its inventory reads each robot after the list, and throws on r2's.
		fleetsim.ScenarioSilent: {"kept_the_shapes", "inventory_is_true", "report_is_true"},
	}
	var runs []scenarioRun
	for _, sc := range fleetsim.ScenarioOrder {
		runs = append(runs, scenarioRun{Group: "first", Title: "The first adapter, " + titles[sc], Scenario: sc, Adapter: "adapter-v1.js", WantFail: firstFails[sc]})
	}
	runs = append(runs, scenarioRun{Group: "probe", Title: "The boundary probe", Scenario: fleetsim.ScenarioNominal, Adapter: "probe.js"})
	for _, sc := range fleetsim.ScenarioOrder {
		runs = append(runs, scenarioRun{Group: "second", Title: "The second adapter, " + titles[sc], Scenario: sc, Adapter: "adapter-v2.js"})
	}
	for _, m := range trialModels {
		if _, err := os.Stat(filepath.Join("examples", "adapter", "trial", m.dir, "final.js")); err != nil {
			continue
		}
		for _, sc := range fleetsim.ScenarioOrder {
			runs = append(runs, scenarioRun{Group: "trial", Title: m.name + "'s adapter, " + titles[sc], Scenario: sc, Adapter: "trial/" + m.dir + ".js", Measured: true})
		}
	}
	return append(runs,
		scenarioRun{Group: "broken", Title: "Broken on purpose: every order sent to (0, 0)", Scenario: fleetsim.ScenarioNominal, Adapter: "broken/wrong-target.js", WantFail: []string{"right_robot_and_target", "robot_at_target"}},
		scenarioRun{Group: "broken", Title: "Broken on purpose: r1's orders sent to r3", Scenario: fleetsim.ScenarioNominal, Adapter: "broken/wrong-robot.js", WantFail: []string{"right_robot_and_target"}},
		scenarioRun{Group: "broken", Title: "Broken on purpose: a failure reported as done", Scenario: fleetsim.ScenarioFault, Adapter: "broken/false-success.js", WantFail: []string{"report_is_true"}},
		scenarioRun{Group: "broken", Title: "Broken on purpose: a cancel that sends nothing", Scenario: fleetsim.ScenarioNominal, Adapter: "broken/no-cancel.js", WantFail: []string{"ended_as_it_should"}},
		scenarioRun{Group: "broken", Title: "Broken on purpose: a wait that reports no state", Scenario: fleetsim.ScenarioNominal, Adapter: "broken/no-state.js", WantFail: []string{"kept_the_shapes"}},
		scenarioRun{Group: "broken", Title: "Broken on purpose: an empty inventory", Scenario: fleetsim.ScenarioNominal, Adapter: "broken/empty-inventory.js", WantFail: []string{"inventory_is_true"}},
		scenarioRun{Group: "broken", Title: "Broken on purpose: an invented robot", Scenario: fleetsim.ScenarioNominal, Adapter: "broken/invented-robot.js", WantFail: []string{"kept_the_shapes", "inventory_is_true"}},
		scenarioRun{Group: "broken", Title: "Broken on purpose: a wait that throws after the mission ends", Scenario: fleetsim.ScenarioNominal, Adapter: "broken/throwing-wait.js", WantFail: []string{"kept_the_shapes"}},
		scenarioRun{Group: "broken", Title: "Broken on purpose: reads past the budget, one read reported", Scenario: fleetsim.ScenarioNominal, Adapter: "broken/undercounted-reads.js", WantFail: []string{"kept_the_shapes", "report_is_true"}},
		scenarioRun{Group: "broken", Title: "Broken on purpose: an order the vendor never answered, reported as refused", Scenario: fleetsim.ScenarioSilent, Adapter: "broken/unanswered-as-refused.js", WantFail: []string{"report_is_true"}},
	)
}

// ruleCells is a run's outcomes as the page shows them, and its verdict in one line.
func ruleCells(kind string, outcomes []qualify.Outcome) ([]ruleCell, string) {
	rules := qualify.AdapterRules
	if kind == qualify.KindProbe {
		rules = qualify.ProbeRules
	}
	byID := map[string]qualify.Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	var cells []ruleCell
	var broke []string
	for _, o := range outcomes {
		rl := byID[o.Rule]
		c := ruleCell{Name: rl.Name, Says: rl.Says, Detail: o.Detail, Held: o.Held, Mark: "✓", Class: "held", Badge: "ok"}
		if !o.Held {
			c.Mark, c.Class, c.Badge = "✗", "broke", "no"
			broke = append(broke, rl.Name+": "+o.Detail)
		}
		cells = append(cells, c)
	}
	if len(broke) == 0 {
		return cells, "every rule held"
	}
	return cells, strings.Join(broke, "; ")
}

func contentOf(files []sandbox.File, path string) string {
	for _, f := range files {
		if f.Path == path {
			return f.Content
		}
	}
	return ""
}

// evidenceChecks verifies the bundle and the statements as written, then refuses
// four changed copies: an edited run output, an edited ledger with the signature kept,
// a verdict re-signed that does not follow from its ledger, and a verdict re-signed
// onto another run's record. Any check that does not come out as expected is an error.
func evidenceChecks(pub ed25519.PublicKey, key ed25519.PrivateKey, entries []attest.Entry, statements []attest.Envelope, plan []scenarioRun) ([]check, error) {
	v := attest.NewVerifier(pub)
	var checks []check
	add := func(short, what string, wantOK bool, err error, okDetail string) {
		c := check{What: what, Short: short, Pass: err == nil, Verdict: "verified", Badge: "ok", Detail: okDetail}
		if err != nil {
			c.Verdict, c.Badge, c.Detail = "refused", "no", err.Error()
		}
		if c.Pass != wantOK {
			c.Detail = "UNEXPECTED: " + c.Detail
		}
		checks = append(checks, c)
	}
	index := func(group, scenario string) int {
		for i, r := range plan {
			if r.Group == group && r.Scenario == scenario {
				return i
			}
		}
		return -1
	}
	lost1, lost2 := index("first", fleetsim.ScenarioLostAck), index("second", fleetsim.ScenarioLostAck)

	_, err := attest.VerifyBundle(entries, v)
	add("records as written", "The run records as the harness wrote them", true, err,
		fmt.Sprintf("%d entries: %d run records, each signed with both digests recomputed, and the closing checkpoint", len(entries), len(entries)-1))
	edited, err := editStepOutput(entries, 0, `"completed":true`, `"completed":false`)
	if err != nil {
		return nil, err
	}
	_, err = attest.VerifyBundle(edited, v)
	add("a run's output changed", "The run records with run 1's output changed from completed:true to completed:false", false, err, "")

	_, err = qualify.Verify(pub, statements, entries)
	add("verdicts as written", "The qualification statements as written", true, err,
		fmt.Sprintf("%d statements: each bound to its run's record; its adapter, plan and report matched to that run's signed request and output; its verdict rebuilt from its evidence", len(statements)))

	tampered := func(i int, env attest.Envelope) []attest.Envelope {
		out := append([]attest.Envelope(nil), statements...)
		out[i] = env
		return out
	}
	oneOrder, err := qualify.Rewrite(statements[lost1], func(p *qualify.Predicate) {
		var kept []fleetsim.Order
		seen := false
		for _, o := range p.Evidence.Ledger {
			if o.Robot == "r2" {
				if seen {
					continue
				}
				seen = true
			}
			kept = append(kept, o)
		}
		p.Evidence.Ledger = kept
		outcomes, pass := qualify.Evaluate(p.Evidence)
		p.Rules, p.Verdict = outcomes, qualify.Verdict(pass)
	})
	if err != nil {
		return nil, err
	}
	_, err = qualify.Verify(pub, tampered(lost1, oneOrder), entries)
	add("a ledger edited", fmt.Sprintf("Run %d's statement with its ledger edited to one order for r2 and its verdict to pass, signature kept", lost1+1), false, err, "")

	subject, pred, err := qualify.Subject(statements[lost1])
	if err != nil {
		return nil, err
	}
	pred.Verdict = "pass"
	for i := range pred.Rules {
		pred.Rules[i].Held, pred.Rules[i].Detail = true, ""
	}
	forged, err := qualify.Sign(key, subject, pred)
	if err != nil {
		return nil, err
	}
	_, err = qualify.Verify(pub, tampered(lost1, forged), entries)
	add("a verdict re-signed", fmt.Sprintf("Run %d's statement re-signed with the right key, its verdict changed to pass over the same ledger", lost1+1), false, err, "")

	_, pred, _ = qualify.Subject(statements[lost1])
	pred.Run = lost2 + 1
	moved, err := qualify.Sign(key, plan[lost2].Record, pred)
	if err != nil {
		return nil, err
	}
	_, err = qualify.Verify(pub, tampered(lost2, moved), entries)
	add("a verdict moved", fmt.Sprintf("Run %d's failing verdict re-signed onto run %d's record, the second adapter's", lost1+1, lost2+1), false, err, "")

	for _, c := range checks {
		if strings.HasPrefix(c.Detail, "UNEXPECTED") {
			return checks, fmt.Errorf("the evidence checks did not come out as expected: %s: %s", c.What, c.Detail)
		}
	}
	return checks, nil
}

// verifyDir checks a published directory offline and returns how many runs it holds.
func verifyDir(dir string) (int, error) {
	pubPEM, err := os.ReadFile(filepath.Join(dir, "harness.pub"))
	if err != nil {
		return 0, err
	}
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		return 0, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "bundle.jsonl"))
	if err != nil {
		return 0, err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	if _, err := attest.VerifyBundle(entries, attest.NewVerifier(pub)); err != nil {
		return 0, err
	}
	qual, err := os.ReadFile(filepath.Join(dir, "qualification.jsonl"))
	if err != nil {
		return 0, err
	}
	statements, err := qualify.ReadStatements(qual)
	if err != nil {
		return 0, err
	}
	verified, err := qualify.Verify(pub, statements, entries)
	return len(verified), err
}

// readInputs loads the files every run carries (plan.json is added per run) and the two
// texts the page quotes. What is carried is declared by the runs themselves: the harness, each
// run's adapter, and the second adapter, which the adapters broken on purpose build on. Each
// is opened through a handle confined to the example's directory (os.Root refuses a path or a
// link, a parent directory's included, that leads out of it) and must be a regular file, so
// nothing beside the declared files can enter a published bundle.
func readInputs(runs []scenarioRun) ([]sandbox.File, map[string]string, error) {
	root, err := os.OpenRoot(filepath.Join("examples", "adapter"))
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	names := map[string]bool{"harness.js": true, "adapter-v2.js": true}
	for _, r := range runs {
		names[r.Adapter] = true
	}
	carried := make([]string, 0, len(names))
	for n := range names {
		if n != "harness.js" {
			carried = append(carried, n)
		}
	}
	sort.Strings(carried)
	carried = append([]string{"harness.js"}, carried...)
	texts := map[string]string{}
	var files []sandbox.File
	read := func(name, path string, carry bool) error {
		f, err := root.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("examples/adapter/%s: not a regular file", path)
		}
		b, err := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
		if err != nil {
			return err
		}
		if len(b) > maxInputBytes {
			return fmt.Errorf("examples/adapter/%s: over %d bytes", path, maxInputBytes)
		}
		texts[name] = string(b)
		if carry {
			files = append(files, sandbox.File{Path: name, Content: string(b)})
		}
		return nil
	}
	for _, name := range carried {
		path, ok := sourceOf(name)
		if !ok {
			return nil, nil, fmt.Errorf("a run names %q, which is not an adapter this example knows", name)
		}
		if err := read(name, path, true); err != nil {
			return nil, nil, err
		}
	}
	for name, path := range map[string]string{"CONTRACT.md": filepath.Join("contract", "CONTRACT.md"), "PROMPT.md": filepath.Join("adapter", "PROMPT.md")} {
		if err := read(name, path, false); err != nil {
			return nil, nil, err
		}
	}
	return files, texts, nil
}

// maxInputBytes caps one carried file: the largest, an adapter, is a few kilobytes.
const maxInputBytes = 1 << 20

// sourceOf is the source path, within examples/adapter, of a carried file's name: the harness,
// the two adapters and the probe, one adapter broken on purpose, or a trial agent's final adapter.
func sourceOf(name string) (string, bool) {
	switch {
	case name == "harness.js":
		return filepath.Join("contract", name), true
	case name == "adapter-v1.js" || name == "adapter-v2.js" || name == "probe.js":
		return filepath.Join("adapter", name), true
	case strings.HasPrefix(name, "broken/") && strings.HasSuffix(name, ".js") && !strings.ContainsAny(name[len("broken/"):], `/\`):
		return filepath.Join("adapter", "broken", name[len("broken/"):]), true
	case strings.HasPrefix(name, "trial/") && strings.HasSuffix(name, ".js"):
		dir := strings.TrimSuffix(name[len("trial/"):], ".js")
		for _, m := range trialModels {
			if m.dir == dir {
				return filepath.Join("trial", dir, "final.js"), true
			}
		}
	}
	return "", false
}

// operationRows reads the operations off the document for the page's table, marking
// the ones the profile grants.
func operationRows(spec []byte, allow []string) ([]opRow, error) {
	var doc struct {
		Paths map[string]map[string]struct {
			ID      string `json:"operationId"`
			Summary string `json:"summary"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(spec, &doc); err != nil {
		return nil, err
	}
	granted := map[string]bool{}
	for _, a := range allow {
		granted[a] = true
	}
	var rows []opRow
	for path, methods := range doc.Paths {
		for method, op := range methods {
			m := strings.ToUpper(method)
			template := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(path, "*")
			row := opRow{Method: m, Path: path, ID: op.ID, Summary: op.Summary, Granted: granted[m+" "+template], Badge: "off", Label: "catalog only"}
			if row.Granted {
				row.Badge, row.Label = "ok", "granted"
			}
			rows = append(rows, row)
		}
	}
	// A stable order: by path, then method, the order specgen uses.
	for i := range rows {
		for j := i + 1; j < len(rows); j++ {
			if rows[j].Path < rows[i].Path || (rows[j].Path == rows[i].Path && rows[j].Method < rows[i].Method) {
				rows[i], rows[j] = rows[j], rows[i]
			}
		}
	}
	return rows, nil
}

func describeBatch(b map[string][]string) string {
	var parts []string
	for k, v := range b {
		parts = append(parts, k+" = "+strings.Join(v, ", "))
	}
	return strings.Join(parts, "; ")
}

// contractBlock returns the JavaScript block of CONTRACT.md.
func contractBlock(md string) string {
	start := strings.Index(md, "```js\n")
	if start < 0 {
		return md
	}
	rest := md[start+len("```js\n"):]
	end := strings.Index(rest, "```")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// promptHead returns the instruction paragraph of PROMPT.md, after its separator.
func promptHead(md string) string {
	i := strings.Index(md, "\n---\n")
	if i < 0 {
		return md
	}
	rest := strings.TrimSpace(md[i+5:])
	if j := strings.Index(rest, "\n\n## "); j > 0 {
		rest = rest[:j]
	}
	return rest
}

// inventoryOf returns the adapter's inventory() function, the one line of difference.
func inventoryOf(src string) string { return functionOf(src, "inventory") }

// functionOf returns the adapter's method name, from its first line to its closing brace.
func functionOf(src, name string) string {
	i := strings.Index(src, "  async "+name+"(")
	if i < 0 {
		return ""
	}
	rest := src[i:]
	j := strings.Index(rest, "\n  },\n")
	if j < 0 {
		return rest
	}
	return rest[:j+len("\n  },")]
}

// editStepOutput returns a copy of entries whose i-th stored response has old
// replaced by new in its first step's stdout: what a tampered copy looks like.
func editStepOutput(entries []attest.Entry, i int, old, new string) ([]attest.Entry, error) {
	out := append([]attest.Entry(nil), entries...)
	resp := &plimsollv1.RunResponse{}
	if err := proto.Unmarshal(out[i].Response, resp); err != nil {
		return nil, err
	}
	steps := resp.GetProject().GetSteps()
	if len(steps) == 0 {
		return nil, errors.New("the entry is not a project run")
	}
	if !strings.Contains(string(steps[0].GetStdout()), old) {
		return nil, fmt.Errorf("run %d's output does not contain %q", i+1, old)
	}
	steps[0].Stdout = []byte(strings.Replace(string(steps[0].GetStdout()), old, new, 1))
	b, err := proto.Marshal(resp)
	if err != nil {
		return nil, err
	}
	out[i].Response = b
	return out, nil
}

func publicPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func runtimeName() string {
	if r := os.Getenv("SANDBOX_DOCKER_RUNTIME"); r != "" {
		return r
	}
	return "runc"
}

func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// writeGrantsFile writes the one-profile grants file beside preamble.js. Everything
// the spec carries is generated; base_url, the credential, the callers and the advice
// setting are operator policy. The credential is a JWT the daemon mints for each run
// (HS256, this vendor as its audience, the caller as its subject), living no longer
// than the run's budget plus five seconds; the vendor verifies it.
func writeGrantsFile(dir, baseURL string, allow, catalog []string, batchOf map[string][]string, health string) (string, error) {
	p := map[string]any{
		"base_url":         baseURL,
		"allow":            allow,
		"catalog":          catalog,
		"batch_of":         batchOf,
		"health_check":     health,
		"global":           "fleet",
		"preamble_file":    "preamble.js",
		"token":            map[string]any{"type": "jwt", "secret_env": secretEnv, "audience": audience, "ttl_sec": 120},
		"allowed_callers":  []string{callerID},
		"advice":           "caller",
		"advice_retention": "detailed",
	}
	body, err := json.MarshalIndent(map[string]any{"profiles": map[string]any{profile: p}}, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "grants.json")
	return path, os.WriteFile(path, body, 0o600)
}

// lineSink collects the daemon's log so a run's audit line can be found after it.
type lineSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lineSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lineSink) mark() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Len()
}

// auditSince returns the last run's audit line written after mark (auditline).
func (l *lineSink) auditSince(mark int) auditline.Run {
	l.mu.Lock()
	text := l.buf.String()[mark:]
	l.mu.Unlock()
	var found auditline.Run
	for _, line := range strings.Split(text, "\n") {
		if run, ok := auditline.Decode([]byte(line)); ok {
			found = run
		}
	}
	return found
}

func (l *lineSink) tail(n int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines := strings.Split(strings.TrimRight(l.buf.String(), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
