package qualify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/adapter/fleetsim"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func done(id, robot, cmd string, t fleetsim.Pose) fleetsim.Order {
	return fleetsim.Order{ID: id, Robot: robot, CommandID: cmd, Target: t, Status: "done", History: []string{"queued", "running", "done"}, StoppedAt: &t}
}

// good is a clean run of plan p: one order per command, each done where it should be,
// the cancelled one cancelled, and a report that says so.
func good(p Plan, s fleetsim.Scenario) Evidence {
	e := Evidence{Kind: KindAdapter, Scenario: s, Plan: p, Report: &Report{Completed: true}}
	for _, id := range []string{"r1", "r2", "r3"} {
		status := "idle"
		if id == s.FaultRobot {
			status = "fault"
		}
		e.Robots = append(e.Robots, fleetsim.RobotState{ID: id, Status: status, Battery: 90})
	}
	inv := func() InventoryCall {
		var list []map[string]any
		for _, r := range e.Robots {
			list = append(list, map[string]any{"id": r.ID, "status": r.Status, "battery": r.Battery})
		}
		b, _ := json.Marshal(list)
		return InventoryCall{Returned: b}
	}
	e.Report.Inventories = []InventoryCall{inv(), inv()}
	for i, c := range p.Commands {
		o := done(fmt.Sprintf("m%d", i+1), c.Robot, c.ID, c.Target)
		if want := Expected(c, s); want != "done" {
			o.Status, o.History = want, []string{"queued", "running", want}
		}
		e.Ledger = append(e.Ledger, o)
		waited, _ := json.Marshal(map[string]any{"state": o.Status, "polls": 3})
		e.Report.Commands = append(e.Report.Commands, ReportedCommand{ID: c.ID, Robot: c.Robot, Mission: o.ID, Dispatched: json.RawMessage(`"` + o.ID + `"`),
			State: o.Status, Polls: 3, MaxPolls: 40, Waited: waited})
	}
	return e
}

func failed(t *testing.T, e Evidence) []string {
	t.Helper()
	outcomes, pass := Evaluate(e)
	var out []string
	for _, o := range outcomes {
		if !o.Held {
			out = append(out, o.Rule)
		}
	}
	if pass != (len(out) == 0) {
		t.Fatalf("pass %v with failed rules %v", pass, out)
	}
	return out
}

func TestRules(t *testing.T) {
	p := NewPlan(1)
	nominal, fault := fleetsim.Scenarios[fleetsim.ScenarioNominal], fleetsim.Scenarios[fleetsim.ScenarioFault]
	if got := failed(t, good(p, nominal)); got != nil {
		t.Fatalf("a clean run failed %v", got)
	}
	if got := failed(t, good(p, fault)); got != nil {
		t.Fatalf("a clean fault run failed %v", got)
	}
	cases := map[string]struct {
		scenario fleetsim.Scenario
		edit     func(e *Evidence)
		want     []string
	}{
		"a second order for one command, no command IDs": {nominal, func(e *Evidence) {
			for i := range e.Ledger {
				e.Ledger[i].CommandID = ""
			}
			e.Ledger = append(e.Ledger, done("m9", "r2", "", fleetsim.Pose{X: 10, Y: 4}))
		}, []string{"one_order_per_command"}},
		"an order sent to the wrong target": {nominal, func(e *Evidence) {
			e.Ledger[0].Target = fleetsim.Pose{}
			e.Ledger[0].StoppedAt = &fleetsim.Pose{}
		}, []string{"right_robot_and_target", "robot_at_target"}},
		"an order sent to the wrong robot": {nominal, func(e *Evidence) { e.Ledger[0].Robot = "r3" }, []string{"right_robot_and_target"}},
		"an order no command asked for": {nominal, func(e *Evidence) {
			e.Ledger = append(e.Ledger, done("m9", "r2", "someone-else", fleetsim.Pose{X: 1, Y: 1}))
		}, []string{"right_robot_and_target"}},
		"a command that became no order": {nominal, func(e *Evidence) {
			e.Ledger = e.Ledger[1:]
			e.Report.Commands[0].Mission, e.Report.Commands[0].State, e.Report.Commands[0].Error, e.Report.Commands[0].Code = "", "", "refused", "refused"
		}, []string{"one_order_per_command"}},
		"a failure reported as done": {fault, func(e *Evidence) { e.Report.Commands[1].State = "done" }, []string{"report_is_true"}},
		"a cancel that did nothing": {nominal, func(e *Evidence) {
			e.Ledger[3].Status, e.Ledger[3].History, e.Ledger[3].StoppedAt = "running", []string{"queued", "running"}, nil
			e.Report.Commands[3].State = "timeout"
		}, []string{"ended_as_it_should"}},
		"an error reported for an order the vendor holds": {nominal, func(e *Evidence) {
			e.Ledger[1].Status, e.Ledger[1].StoppedAt = "running", nil
			e.Report.Commands[1] = ReportedCommand{ID: e.Plan.Commands[1].ID, Error: "host api 502: host api unavailable"}
		}, []string{"kept_the_shapes", "ended_as_it_should", "report_is_true"}},
		"an honest unresolved for an order the vendor holds": {nominal, func(e *Evidence) {
			e.Ledger[1].Status, e.Ledger[1].StoppedAt = "running", nil
			e.Report.Commands[1] = ReportedCommand{ID: e.Plan.Commands[1].ID, Error: "no answer", Code: "unresolved"}
		}, []string{"ended_as_it_should"}},
		"another command's mission reported": {nominal, func(e *Evidence) { e.Report.Commands[1].Mission = "m1" }, []string{"report_is_true"}},
		"a done order that stopped short":    {nominal, func(e *Evidence) { e.Ledger[2].StoppedAt = &fleetsim.Pose{X: 0, Y: 14} }, []string{"robot_at_target"}},
		"a harness that did not finish":      {nominal, func(e *Evidence) { e.ExitCode, e.Report.Completed = 1, false }, []string{"ran_to_the_end"}},
		"no report at all":                   {nominal, func(e *Evidence) { e.Report = nil }, []string{"ran_to_the_end", "kept_the_shapes", "report_is_true"}},
		// The follow-up review's three reproductions, and the other obligations.
		"a wait with no state": {nominal, func(e *Evidence) {
			for i := range e.Report.Commands {
				e.Report.Commands[i].Waited, e.Report.Commands[i].State = json.RawMessage(`{"polls":1}`), ""
			}
		}, []string{"kept_the_shapes"}},
		"an empty inventory": {nominal, func(e *Evidence) {
			e.Report.Inventories = []InventoryCall{{Returned: json.RawMessage(`[]`)}, {Returned: json.RawMessage(`[]`)}}
		}, []string{"inventory_is_true"}},
		"an invented robot": {nominal, func(e *Evidence) {
			e.Report.Inventories[1].Returned = json.RawMessage(`[{"id":"imaginary","status":"banana","battery":-50}]`)
		}, []string{"kept_the_shapes", "inventory_is_true"}},
		"a last inventory that disagrees with the vendor": {fault, func(e *Evidence) {
			e.Report.Inventories[1].Returned = json.RawMessage(`[{"id":"r1","status":"idle","battery":90},{"id":"r2","status":"idle","battery":90},{"id":"r3","status":"idle","battery":90}]`)
		}, []string{"inventory_is_true"}},
		"more reads than the budget": {nominal, func(e *Evidence) {
			e.Report.Commands[0].Waited = json.RawMessage(`{"state":"done","polls":41}`)
		}, []string{"kept_the_shapes"}},
		"an error with no contract code": {nominal, func(e *Evidence) {
			e.Ledger = e.Ledger[1:]
			e.Report.Commands[0] = ReportedCommand{ID: e.Plan.Commands[0].ID, Error: "boom", Code: "oops"}
		}, []string{"kept_the_shapes", "one_order_per_command"}},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			e := good(p, c.scenario)
			c.edit(&e)
			if got := failed(t, e); !slices.Equal(got, c.want) {
				t.Errorf("failed %v, want %v", got, c.want)
			}
		})
	}
}

func TestProbeRules(t *testing.T) {
	p := &ProbeReport{ThroughClient: "host api call not permitted by sandbox capability: DELETE /robots/r1", BypassClient: "403 forbidden", Direct: "failed: fetch failed"}
	e := Evidence{Kind: KindProbe, Scenario: fleetsim.Scenarios[fleetsim.ScenarioNominal], Probe: p, BrokerDenied: 1}
	if got := failed(t, e); got != nil {
		t.Fatalf("a clean probe failed %v", got)
	}
	e.BrokerDenied, e.Vendor.CatalogOnly = 0, map[string]int{"DELETE /robots/*": 1}
	if got := failed(t, e); !slices.Equal(got, []string{"refused_by_broker", "vendor_saw_nothing"}) {
		t.Fatalf("failed %v", got)
	}
}

// signedRuns builds a bundle of n adapter runs signed by key, as the example writes
// one: each run's request carries its adapter, harness.js and plan.json, and its
// response prints the report. It returns the bundle and one statement per run.
func signedRuns(t *testing.T, key ed25519.PrivateKey, n int) ([]attest.Entry, []attest.Envelope, []Predicate) {
	t.Helper()
	var buf bytes.Buffer
	h := attest.NewHarness(attest.NewSigner(key), &buf)
	var preds []Predicate
	var subjects []string
	for i := 1; i <= n; i++ {
		s := fleetsim.Scenarios[fleetsim.ScenarioOrder[(i-1)%len(fleetsim.ScenarioOrder)]]
		e := good(NewPlan(i), s)
		e.Credentials = []fleetsim.Credential{{ID: fmt.Sprintf("jti-%d", i)}}
		e.Report.Scenario, e.Report.Adapter = s.Name, "adapter-v2.js"
		planJSON, _ := json.Marshal(e.Plan)
		reportJSON, _ := json.Marshal(e.Report)
		files := []*plimsollv1.ProjectFile{{Path: "harness.js", Content: "// harness"}, {Path: "adapter-v2.js", Content: "// adapter"}, {Path: "plan.json", Content: string(planJSON)}}
		step := "node harness.js " + s.Name + " adapter-v2.js"
		req := &plimsollv1.RunRequest{Protocol: 3, Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{Files: files, Steps: []string{step}}}}
		resp := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "container", Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{
			Steps: []*plimsollv1.StepResult{{Command: step, Stdout: []byte("noise\nADAPTER-REPORT " + string(reportJSON) + "\n")}}}}}
		resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req), Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000100)}, resp)
		if err := h.Record(req, resp); err != nil {
			t.Fatal(err)
		}
		outcomes, pass := Evaluate(e)
		preds = append(preds, Predicate{Run: i, Simulator: fleetsim.Version, Adapter: FileDigest{Path: "adapter-v2.js", SHA256: Digest("// adapter")},
			Harness: Digest("// harness"), Evidence: e, Rules: outcomes, Verdict: Verdict(pass)})
		subjects = append(subjects, resp.Record.GetRecordSha256())
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	entries, err := attest.ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var envs []attest.Envelope
	for i, p := range preds {
		env, err := Sign(key, subjects[i], p)
		if err != nil {
			t.Fatal(err)
		}
		envs = append(envs, env)
	}
	return entries, envs, preds
}

func TestStatementsVerifyAndRefuseChanges(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	entries, envs, preds := signedRuns(t, key, 3)
	if _, err := attest.VerifyBundle(entries, attest.NewVerifier(pub)); err != nil {
		t.Fatal(err)
	}
	if got, err := Verify(pub, envs, entries); err != nil || len(got) != 3 {
		t.Fatalf("as written: %d verified, %v", len(got), err)
	}
	resign := func(i int, edit func(*Predicate)) []attest.Envelope {
		p := preds[i]
		b, _ := json.Marshal(p)
		var c Predicate
		_ = json.Unmarshal(b, &c)
		edit(&c)
		subject, _, _ := Subject(envs[i])
		env, err := Sign(key, subject, c)
		if err != nil {
			t.Fatal(err)
		}
		out := slices.Clone(envs)
		out[i] = env
		return out
	}
	kept, _ := Rewrite(envs[0], func(p *Predicate) { p.Evidence.Ledger = p.Evidence.Ledger[1:] })
	_, strangerKey, _ := ed25519.GenerateKey(rand.Reader)
	stranger, _ := Sign(strangerKey, "", preds[0])
	for label, c := range map[string]struct {
		envs []attest.Envelope
		want string
	}{
		"an edited ledger, signature kept": {append([]attest.Envelope{kept}, envs[1:]...), "signature"},
		"signed by another key":            {append([]attest.Envelope{stranger}, envs[1:]...), "not one signature by this key"},
		"a verdict that does not follow": {resign(0, func(p *Predicate) {
			p.Evidence.Ledger = append(p.Evidence.Ledger, done("m9", "r2", "", fleetsim.Pose{X: 10, Y: 4}))
		}), "does not follow"},
		"a scenario that is not the simulator's": {resign(0, func(p *Predicate) { p.Evidence.Scenario.FaultRobot = "r1" }), "the scenario is not"},
		"a report the run did not print":         {resign(0, func(p *Predicate) { p.Evidence.Report.Retries = 7 }), "not the one the run printed"},
		"a plan the run was not sent": {resign(0, func(p *Predicate) {
			p.Evidence.Plan = NewPlan(2)
			p.Rules, _ = Evaluate(p.Evidence)
		}), "plan.json"},
		"an adapter the run did not carry": {resign(0, func(p *Predicate) { p.Adapter.SHA256 = Digest("// another adapter") }), "did not carry"},
		"a statement moved to another run": {resign(0, func(p *Predicate) { p.Run = 2 }), "is not run 2's record"},
		"an exit code the run did not end with": {resign(0, func(p *Predicate) {
			p.Evidence.ExitCode = 1
			p.Rules, _ = Evaluate(p.Evidence)
			p.Verdict = "fail"
		}), "exited 0"},
		"a credential two runs shared": {resign(1, func(p *Predicate) { p.Evidence.Credentials[0].ID = "jti-1" }), "also served run 1"},
		"a run without a statement":    {envs[:2], "2 statements for 3 runs"},
	} {
		t.Run(label, func(t *testing.T) {
			_, err := Verify(pub, c.envs, entries)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

// One statement and the one line it speaks for prove each other without the bundle:
// the line's own link places it, and the statement must name that place and that
// record. The checks across runs stay Verify's.
func TestVerifyOneNeedsOnlyTheLine(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	entries, envs, preds := signedRuns(t, key, 3)
	for i := range preds {
		got, err := VerifyOne(pub, envs[i], entries[i])
		if err != nil {
			t.Fatalf("statement %d alone: %v", i+1, err)
		}
		if subject, _, _ := Subject(envs[i]); got.Record != subject || got.Predicate.Run != i+1 {
			t.Fatalf("statement %d alone: %+v", i+1, got)
		}
	}
	if _, err := VerifyOne(pub, envs[0], entries[1]); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("statement 1 against line 2: %v", err)
	}
	moved := preds[0]
	moved.Run = 2
	subject, _, _ := Subject(envs[0])
	env, err := Sign(key, subject, moved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOne(pub, env, entries[1]); err == nil || !strings.Contains(err.Error(), "is not run 2's record") {
		t.Fatalf("a statement moved onto line 2: %v", err)
	}
	unlinked := entries[0]
	unlinked.Link = nil
	if _, err := VerifyOne(pub, envs[0], unlinked); err == nil || !strings.Contains(err.Error(), "the run's line") {
		t.Fatalf("a line without its link: %v", err)
	}
	if _, err := VerifyOne(pub, envs[0], entries[3]); err == nil {
		t.Fatal("the checkpoint was taken for a run")
	}
}
