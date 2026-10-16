package sandbox_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/examples/adapter/fleetsim"
	"github.com/plimsollmark/plimsoll/examples/adapter/qualify"
	"github.com/plimsollmark/plimsoll/examples/adapter/trial/practice"
	"github.com/plimsollmark/plimsoll/internal/specgen"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The vendor adapter example (examples/adapter) through the provider directly: the
// platform's harness runs an adapter against the simulated vendor API, which the run
// reaches only through a grant generated from the vendor's OpenAPI document, and the
// verdict is made from the plan and the vendor's ledger by examples/adapter/qualify.
// The daemon path (advice, minted credentials, signed records and statements, the
// page) is the example program's; this test holds the part that must not drift: which
// rules each adapter breaks in each scenario, the first and second adapters' call
// counts, the overload scenario's shedding, the second adapter never taking an order
// that is not its command's, and the boundary probe's refusals.

// adapterGrant builds the grant the example's profile carries (practice.Grant), and checks
// the spec's batch extension the profile also declares.
func adapterGrant(t *testing.T, baseURL, token string) *sandbox.HostAPIGrant {
	t.Helper()
	spec, err := os.ReadFile("../examples/adapter/vendor/fleet.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	gen, err := specgen.Generate(spec, specgen.Options{Global: "fleet"})
	if err != nil {
		t.Fatalf("specgen: %v", err)
	}
	if gen.BatchOf["GET /robots"] == nil {
		t.Fatalf("the spec's batch extension was not picked up: %v", gen.BatchOf)
	}
	grant, err := practice.Grant(spec, baseURL, sandbox.StaticToken(token))
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func adapterFiles(t *testing.T) []sandbox.File {
	t.Helper()
	var files []sandbox.File
	broken, err := filepath.Glob("../examples/adapter/adapter/broken/*.js")
	if err != nil || len(broken) == 0 {
		t.Fatalf("no adapters broken on purpose: %v", err)
	}
	names := []string{"contract/harness.js", "adapter/adapter-v1.js", "adapter/adapter-v2.js", "adapter/probe.js"}
	for _, p := range broken {
		names = append(names, "adapter/broken/"+filepath.Base(p))
	}
	for _, name := range names {
		b, err := os.ReadFile("../examples/adapter/" + name)
		if err != nil {
			t.Fatal(err)
		}
		path := strings.TrimPrefix(strings.TrimPrefix(name, "contract/"), "adapter/")
		files = append(files, sandbox.File{Path: path, Content: string(b)})
	}
	return files
}

func routeCount(tr *sandbox.CallTrace, method, route string) int {
	n := 0
	if tr == nil {
		return 0
	}
	for _, c := range tr.Calls {
		if c.Method == method && c.Route == route {
			n++
		}
	}
	return n
}

// adapterRun is one harness run and the verdict qualify makes of it.
type adapterRun struct {
	res    sandbox.ProjectResult
	ev     qualify.Evidence
	failed []string
}

func TestDockerAdapterExample(t *testing.T) {
	t.Parallel()
	d := sessionDocker(t)

	const token = "fleet-vendor-bearer-for-this-test-only"
	sim := fleetsim.New(fleetsim.Static(token))
	upstream := httptest.NewServer(sim)
	defer upstream.Close()
	grant := adapterGrant(t, upstream.URL, token)
	files := adapterFiles(t)
	n := 0

	// run runs the harness with adapter under scenario; before, when set, runs on the
	// vendor after its reset and before the run.
	run := func(t *testing.T, scenario, adapter string, before func()) adapterRun {
		t.Helper()
		n++
		plan := qualify.NewPlan(n)
		planJSON, _ := json.Marshal(plan)
		sim.Reset(scenario)
		if before != nil {
			before()
		}
		res, err := d.RunProject(context.Background(), sandbox.ProjectRequest{
			Files:   append(slices.Clone(files), sandbox.File{Path: "plan.json", Content: string(planJSON)}),
			Steps:   []string{"node harness.js " + scenario + " " + adapter},
			Grant:   grant,
			Timeout: 90 * time.Second,
		})
		if err != nil {
			t.Fatalf("RunProject: %v", err)
		}
		if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 {
			t.Fatalf("outcome %v (%s), %d steps", res.Outcome, res.Detail, len(res.Steps))
		}
		ev := qualify.Evidence{Kind: qualify.KindAdapter, Scenario: sim.Scenario(), Plan: plan, Ledger: sim.Ledger(), Robots: sim.Robots(), Reads: sim.Reads(), Told: sim.Told(),
			Report: qualify.ReadReport(res.Steps[0].Stdout), ExitCode: res.Steps[0].ExitCode}
		if ev.Report == nil {
			t.Fatalf("no report line; stdout %q stderr %q", res.Steps[0].Stdout, res.Steps[0].Stderr)
		}
		if n := sim.Unauthorized(); n != 0 {
			t.Errorf("the vendor saw %d request(s) without the bearer", n)
		}
		if reached := sim.Reached(); len(reached) != 0 {
			t.Errorf("a catalog-only route was reached: %v", reached)
		}
		if n := sim.Illegal(); n != 0 {
			t.Errorf("the vendor was asked for %d illegal transitions", n)
		}
		outcomes, _ := qualify.Evaluate(ev)
		var failed []string
		for _, o := range outcomes {
			if !o.Held {
				failed = append(failed, o.Rule)
				t.Logf("%s: %s", o.Rule, o.Detail)
			}
		}
		return adapterRun{res: res, ev: ev, failed: failed}
	}

	// Which rules each adapter breaks in each scenario. The first adapter retries a
	// create blindly (two orders after a lost answer) and gives up on a dropped
	// connection while the vendor holds the order; the second passes everything; each
	// adapter broken on purpose breaks the rule it was broken for.
	matrix := []struct {
		scenario, adapter string
		fails             []string
	}{
		{fleetsim.ScenarioNominal, "adapter-v1.js", nil},
		{fleetsim.ScenarioFault, "adapter-v1.js", nil},
		{fleetsim.ScenarioLostAck, "adapter-v1.js", []string{"one_order_per_command"}},
		{fleetsim.ScenarioDropped, "adapter-v1.js", []string{"kept_the_shapes", "ended_as_it_should", "report_is_true"}},
		{fleetsim.ScenarioServerError, "adapter-v1.js", []string{"kept_the_shapes", "ended_as_it_should", "report_is_true"}},
		{fleetsim.ScenarioRefused, "adapter-v1.js", []string{"kept_the_shapes", "report_is_true"}},
		{fleetsim.ScenarioSilent, "adapter-v1.js", []string{"kept_the_shapes", "inventory_is_true", "report_is_true"}},
		{fleetsim.ScenarioFault, "adapter-v2.js", nil},
		{fleetsim.ScenarioLostAck, "adapter-v2.js", nil},
		{fleetsim.ScenarioDropped, "adapter-v2.js", nil},
		{fleetsim.ScenarioServerError, "adapter-v2.js", nil},
		{fleetsim.ScenarioRefused, "adapter-v2.js", nil},
		{fleetsim.ScenarioSilent, "adapter-v2.js", nil},
		{fleetsim.ScenarioNominal, "broken/wrong-target.js", []string{"right_robot_and_target", "robot_at_target"}},
		{fleetsim.ScenarioNominal, "broken/wrong-robot.js", []string{"right_robot_and_target"}},
		{fleetsim.ScenarioFault, "broken/false-success.js", []string{"report_is_true"}},
		{fleetsim.ScenarioNominal, "broken/no-cancel.js", []string{"ended_as_it_should"}},
		{fleetsim.ScenarioNominal, "broken/no-state.js", []string{"kept_the_shapes"}},
		{fleetsim.ScenarioNominal, "broken/empty-inventory.js", []string{"inventory_is_true"}},
		{fleetsim.ScenarioNominal, "broken/invented-robot.js", []string{"kept_the_shapes", "inventory_is_true"}},
		{fleetsim.ScenarioNominal, "broken/throwing-wait.js", []string{"kept_the_shapes"}},
		{fleetsim.ScenarioNominal, "broken/undercounted-reads.js", []string{"kept_the_shapes", "report_is_true"}},
		{fleetsim.ScenarioSilent, "broken/unanswered-as-refused.js", []string{"report_is_true"}},
	}
	for _, m := range matrix {
		t.Run(m.adapter+" "+m.scenario, func(t *testing.T) {
			if r := run(t, m.scenario, m.adapter, nil); !slices.Equal(r.failed, m.fails) {
				t.Errorf("failed rules %v, want %v", r.failed, m.fails)
			}
		})
	}
	// The silent scenario: v2 sends c2's create with its command ID until its attempts run
	// out, every one answered 504, then reports unresolved; the vendor holds one order.
	t.Run("adapter-v2.js silent: unresolved after its attempts", func(t *testing.T) {
		r := run(t, fleetsim.ScenarioSilent, "adapter-v2.js", nil)
		if len(r.failed) != 0 {
			t.Errorf("failed rules %v", r.failed)
		}
		if c := r.ev.Report.Commands[1]; c.Code != "unresolved" || c.Mission != "" {
			t.Errorf("c2 reported mission %q, code %q; want unresolved", c.Mission, c.Code)
		}
		if got := sim.Counts()["POST /robots/*/missions"]; got != 3+40 {
			t.Errorf("the vendor saw %d creates, want 43 (c1, c3 and c4 once, c2 40 times)", got)
		}
		if got := sim.Unanswered(); got != 39 {
			t.Errorf("the vendor answered %d requests 504 after the first, want 39", got)
		}
		if n := sim.Orders()["r2"]; n != 1 {
			t.Errorf("r2 holds %d orders, want 1", n)
		}
	})
	t.Run("adapter-v1.js nominal: one read per robot", func(t *testing.T) {
		r := run(t, fleetsim.ScenarioNominal, "adapter-v1.js", nil)
		if len(r.failed) != 0 {
			t.Errorf("failed rules %v", r.failed)
		}
		// Two inventory calls, before and after: the list, then one read per robot, each time.
		if got := routeCount(r.res.CallTrace, "GET", "/robots/*"); got != 6 {
			t.Errorf("v1 read GET /robots/* %d times, want 6 (one per robot after each list)", got)
		}
		if got := sim.Counts()["GET /robots/*"]; got != 6 {
			t.Errorf("the vendor counted %d GET /robots/*, want 6", got)
		}
		if r.res.CallTrace.Denied != 0 || r.res.CallTrace.Shed != 0 {
			t.Errorf("nominal run: denied %d shed %d, want 0 0", r.res.CallTrace.Denied, r.res.CallTrace.Shed)
		}
	})
	t.Run("adapter-v2.js nominal: the batch route", func(t *testing.T) {
		r := run(t, fleetsim.ScenarioNominal, "adapter-v2.js", nil)
		if len(r.failed) != 0 {
			t.Errorf("failed rules %v", r.failed)
		}
		if got := routeCount(r.res.CallTrace, "GET", "/robots/*"); got != 0 {
			t.Errorf("v2 read GET /robots/* %d times, want 0", got)
		}
		if got := routeCount(r.res.CallTrace, "GET", "/robots"); got != 2 {
			t.Errorf("v2 read GET /robots %d times, want 2 (one per inventory)", got)
		}
	})
	for _, adapter := range []string{"adapter-v1.js", "adapter-v2.js"} {
		t.Run(adapter+" overload: the breaker sheds", func(t *testing.T) {
			r := run(t, fleetsim.ScenarioOverload, adapter, nil)
			if len(r.failed) != 0 {
				t.Errorf("failed rules %v", r.failed)
			}
			if r.ev.Report.Retries == 0 {
				t.Error("the adapter reports no retry")
			}
			if sim.Refused() != fleetsim.DegradedRequests {
				t.Errorf("the vendor refused %d requests, want %d", sim.Refused(), fleetsim.DegradedRequests)
			}
			if r.res.CallTrace.Shed == 0 {
				t.Error("the broker shed nothing: the breaker never opened")
			}
			if r.res.CallTrace.Denied != 0 {
				t.Errorf("denied %d, want 0: shedding is not a policy denial", r.res.CallTrace.Denied)
			}
		})
	}
	// The review's second reproduction: an order someone else placed on r2 is already
	// running. The second adapter's create for r2 must come back with its own order,
	// queued behind it, never the order that was there.
	t.Run("adapter-v2.js never takes another command's order", func(t *testing.T) {
		r := run(t, fleetsim.ScenarioOverload, "adapter-v2.js", func() {
			body, _ := json.Marshal(map[string]any{"target": map[string]float64{"x": 10, "y": 50}, "command_id": "operator-0001"})
			req, _ := http.NewRequest("POST", upstream.URL+"/robots/r2/missions", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil || resp.StatusCode != http.StatusCreated {
				t.Fatalf("placing the operator's order: %v %v", resp, err)
			}
			resp.Body.Close()
		})
		c2 := r.ev.Plan.Commands[1]
		var mine []string
		for _, o := range r.ev.Ledger {
			if o.CommandID == c2.ID {
				mine = append(mine, o.ID)
			}
		}
		got := r.ev.Report.Commands[1]
		if len(mine) != 1 || got.Mission != mine[0] || got.Mission == "m1" {
			t.Errorf("%s: the adapter reported %q; the ledger's orders for it: %v (m1 is the operator's)", c2.ID, got.Mission, mine)
		}
		if n := sim.Orders()["r2"]; n != 2 {
			t.Errorf("r2 holds %d orders, want 2: the operator's and the command's", n)
		}
	})
	// The follow-up review's probe: wait's read budget covers failed reads. A client that
	// always answers 503, a budget of one read: one call, not one plus every retry.
	t.Run("adapter-v2.js wait keeps its read budget", func(t *testing.T) {
		v2, err := os.ReadFile("../examples/adapter/adapter/adapter-v2.js")
		if err != nil {
			t.Fatal(err)
		}
		probe := `let calls = 0;
globalThis.fleet = { getMission: async () => { calls++; throw new Error("host api 503: busy"); } };
const a = require("./adapter-v2.js");
(async () => {
  const out = {};
  for (const n of [0, 1, 3]) {
    calls = 0;
    const w = await a.wait("m1", { maxPolls: n });
    out[n] = { calls, polls: w.polls, state: w.state };
  }
  console.log("BUDGET " + JSON.stringify(out));
})();`
		res, err := d.RunProject(context.Background(), sandbox.ProjectRequest{
			Files:   []sandbox.File{{Path: "adapter-v2.js", Content: string(v2)}, {Path: "probe.js", Content: probe}},
			Steps:   []string{"node probe.js"},
			Timeout: 30 * time.Second,
		})
		if err != nil || len(res.Steps) != 1 {
			t.Fatalf("RunProject: %v %+v", err, res)
		}
		line := qualify.ParseLine(res.Steps[0].Stdout, "BUDGET ")
		var got map[string]struct {
			Calls, Polls int
			State        string
		}
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("probe: %v: %q %q", err, res.Steps[0].Stdout, res.Steps[0].Stderr)
		}
		for n, want := range map[string]int{"0": 0, "1": 1, "3": 3} {
			if g := got[n]; g.Calls != want || g.Polls != want || g.State != "timeout" {
				t.Errorf("maxPolls %s: %d calls, %d polls, state %q; want %d, %d, timeout", n, g.Calls, g.Polls, g.State, want, want)
			}
		}
	})
	t.Run("boundary probe", func(t *testing.T) {
		sim.Reset(fleetsim.ScenarioNominal)
		res, err := d.RunProject(context.Background(), sandbox.ProjectRequest{
			Files:   files,
			Steps:   []string{"node probe.js " + upstream.URL},
			Grant:   grant,
			Timeout: 60 * time.Second,
		})
		if err != nil {
			t.Fatalf("RunProject: %v", err)
		}
		if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
			t.Fatalf("outcome %v (%s), steps %+v", res.Outcome, res.Detail, res.Steps)
		}
		p := qualify.ReadProbe(res.Steps[0].Stdout)
		if p == nil {
			t.Fatalf("no probe report: %q (stderr %q)", res.Steps[0].Stdout, res.Steps[0].Stderr)
		}
		ev := qualify.Evidence{Kind: qualify.KindProbe, Scenario: sim.Scenario(), Probe: p, Ledger: sim.Ledger(),
			Vendor:       qualify.VendorCounts{CatalogOnly: sim.Reached(), Unauthorized: sim.Unauthorized()},
			BrokerDenied: res.CallTrace.Denied}
		outcomes, pass := qualify.Evaluate(ev)
		if !pass {
			t.Errorf("probe rules: %+v (the client's refusal never reaches the broker, so exactly one denial)", outcomes)
		}
	})
}

// The trial's development scenario runs an agent's adapter in the sandbox, never on the
// host (a security scan of 2026-10-16 found the helper running it under the host's node,
// with the operator's environment): the passing adapter passes, a broken one fails, and an
// adapter reading the environment and the host's files finds neither the operator's
// variables nor the host's home.
func TestDockerPracticeRunsTheAdapterInTheSandbox(t *testing.T) {
	// Not parallel: it sets a variable in this process's environment.
	d := sessionDocker(t)
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile("../examples/adapter/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	spec, harness := []byte(read("vendor/fleet.openapi.json")), read("contract/harness.js")
	ctx := context.Background()
	good, err := practice.Run(ctx, d, spec, harness, read("adapter/adapter-v2.js"))
	if err != nil || !good.Pass || !strings.HasSuffix(good.Text, "Verdict in this scenario: pass.\n") {
		t.Fatalf("the passing adapter: %v\n%s", err, good.Text)
	}
	bad, err := practice.Run(ctx, d, spec, harness, read("adapter/broken/false-success.js"))
	if err != nil || bad.Pass || !strings.Contains(bad.Text, "BROKEN: ") {
		t.Fatalf("a broken adapter: %v\n%s", err, bad.Text)
	}
	const canary = "PRACTICE_CANARY_7f3a"
	t.Setenv("PLIMSOLL_PRACTICE_CANARY", canary)
	home, _ := os.UserHomeDir()
	snoop := `const fs = require("fs");
let home = "unreadable"; try { home = fs.readdirSync(` + "`" + home + "`" + `).join(","); } catch (e) { home = "unreadable: " + e.code; }
console.error("ENV " + JSON.stringify(process.env) + " HOME " + home);
` + read("adapter/adapter-v2.js")
	seen, err := practice.Run(ctx, d, spec, harness, snoop)
	if err != nil || !seen.Pass {
		t.Fatalf("the snooping adapter: %v\n%s", err, seen.Text)
	}
	if strings.Contains(seen.Text, canary) || !strings.Contains(seen.Text, "HOME unreadable") {
		t.Fatalf("the adapter saw the operator's environment or home:\n%s", seen.Text)
	}
}
