// Package practice is the independent trial's development scenario: what each agent could
// try its adapter in, once per round. Run takes the adapter through the platform's harness
// against fleetsim (nominal only) in the sandbox it is given, under the grant the example's
// profile states, and returns exactly the text the agent is shown. An adapter is
// agent-written, so it runs only in a sandbox, never as a host process.
package practice

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/examples/adapter/fleetsim"
	"github.com/plimsollmark/plimsoll/examples/adapter/qualify"
	"github.com/plimsollmark/plimsoll/internal/specgen"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Grant is the grant the example's profile carries: the routes generated from the vendor's
// document minus the two catalog-only operations (a DELETE and the firmware route), the
// generated fleet client, and the health route for the broker's breaker.
func Grant(spec []byte, baseURL string, minter sandbox.TokenMinter) (*sandbox.HostAPIGrant, error) {
	gen, err := specgen.Generate(spec, specgen.Options{Global: "fleet"})
	if err != nil {
		return nil, fmt.Errorf("specgen: %w", err)
	}
	var allow []sandbox.HostRoute
	for _, r := range gen.Allow {
		if r.Method == "DELETE" || strings.HasSuffix(r.Path, "/firmware") {
			continue
		}
		allow = append(allow, r)
	}
	if len(allow) != 6 || gen.HealthCheck != "GET /health" {
		return nil, fmt.Errorf("the vendor's document gives %d routes and health %q; the profile grants 6 and GET /health", len(allow), gen.HealthCheck)
	}
	return &sandbox.HostAPIGrant{
		BaseURL:     baseURL,
		Allow:       allow,
		Global:      "fleet",
		Minter:      minter,
		Preamble:    gen.Preamble,
		HealthCheck: &sandbox.HostRoute{Method: "GET", Path: "/health"},
	}, nil
}

// Result is what one practice run told the agent, and its verdict.
type Result struct {
	Text string
	Pass bool
}

// Run runs adapter (its source) through harness (examples/adapter/contract/harness.js)
// in sb, against a fleetsim on loopback reached through the broker.
func Run(ctx context.Context, sb sandbox.Sandbox, spec []byte, harness, adapter string) (Result, error) {
	const token = "practice-token"
	sim := fleetsim.New(fleetsim.Static(token))
	sim.Reset(fleetsim.ScenarioNominal)
	srv := httptest.NewServer(sim)
	defer srv.Close()
	grant, err := Grant(spec, srv.URL, sandbox.StaticToken(token))
	if err != nil {
		return Result{}, err
	}
	plan := qualify.NewPlan(1)
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return Result{}, err
	}
	res, err := sb.RunProject(ctx, sandbox.ProjectRequest{
		Files: []sandbox.File{
			{Path: "harness.js", Content: harness},
			{Path: "adapter.js", Content: adapter},
			{Path: "plan.json", Content: string(planJSON)},
		},
		Steps:   []string{"node harness.js nominal adapter.js"},
		Timeout: 90 * time.Second,
		Grant:   grant,
		// The floor the example's judged runs state.
		MinimumIsolation: sandbox.IsolationContainer,
	})
	if err != nil {
		return Result{}, err
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 {
		return Result{}, fmt.Errorf("the practice run did not complete: %v, %s", res.Outcome, res.Detail)
	}
	step := res.Steps[0]
	ev := qualify.Evidence{Kind: qualify.KindAdapter, Scenario: sim.Scenario(), Plan: plan, Ledger: sim.Ledger(), Robots: sim.Robots(), Reads: sim.Reads(), Told: sim.Told(), Report: qualify.ReadReport(step.Stdout), ExitCode: step.ExitCode}
	outcomes, pass := qualify.Evaluate(ev)
	var b strings.Builder
	b.WriteString("Development scenario (nominal: three idle robots, every order can complete). The harness ran these commands: ")
	for _, c := range plan.Commands {
		s := fmt.Sprintf("%s: %s to (%g, %g)", c.ID, c.Robot, c.Target.X, c.Target.Y)
		if c.Cancel {
			s += ", cancelled as soon as placed"
		}
		b.WriteString(s + "; ")
	}
	fmt.Fprintf(&b, "\n\nThe harness exited %d and printed:\n%s\n", step.ExitCode, strings.TrimSpace(qualify.ParseLine(step.Stdout, "ADAPTER-REPORT ")))
	if e := strings.TrimSpace(step.Stderr); e != "" {
		if len(e) > 1500 {
			e = e[:1500] + "..."
		}
		fmt.Fprintf(&b, "\nIts stderr:\n%s\n", e)
	}
	b.WriteString("\nThe rules, from the vendor's ledger:\n")
	for _, o := range outcomes {
		mark := "held"
		if !o.Held {
			mark = "BROKEN: " + o.Detail
		}
		fmt.Fprintf(&b, "- %s: %s\n", o.Rule, mark)
	}
	fmt.Fprintf(&b, "\nVerdict in this scenario: %s.\n", map[bool]string{true: "pass", false: "fail"}[pass])
	return Result{Text: b.String(), Pass: pass}, nil
}
