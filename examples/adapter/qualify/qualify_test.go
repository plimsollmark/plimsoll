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
// the cancelled one cancelled, the one the vendor went silent about still running and
// reported unresolved, and a report that says so.
func good(p Plan, s fleetsim.Scenario) Evidence {
	e := Evidence{Kind: KindAdapter, Scenario: s, Plan: p, Report: &Report{Completed: true}, Reads: map[string]int{}}
	for _, id := range []string{"r1", "r2", "r3"} {
		status := "idle"
		if id == s.FaultRobot || id == s.OutOfService {
			status = "fault"
		}
		if id == s.Silent {
			status = "moving"
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
		if Expected(c, s) == Refused {
			e.Report.Commands = append(e.Report.Commands, ReportedCommand{ID: c.ID, Robot: c.Robot, Error: "command " + c.ID + " was not placed: host api 409", Code: Refused})
			continue
		}
		o := done(fmt.Sprintf("m%d", i+1), c.Robot, c.ID, c.Target)
		if Expected(c, s) == Unresolved {
			o.Status, o.History, o.StoppedAt = "running", []string{"queued", "running"}, nil
			e.Ledger = append(e.Ledger, o)
			e.Report.Commands = append(e.Report.Commands, ReportedCommand{ID: c.ID, Robot: c.Robot, Error: "command " + c.ID + ": no answer; the vendor may or may not hold the order", Code: Unresolved})
			continue
		}
		if want := Expected(c, s); want != "done" {
			o.Status, o.History = want, []string{"queued", "running", want}
		}
		e.Ledger = append(e.Ledger, o)
		e.Reads[o.ID] = 3
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
	refused := fleetsim.Scenarios[fleetsim.ScenarioRefused]
	if got := failed(t, good(p, refused)); got != nil {
		t.Fatalf("a clean refused run failed %v", got)
	}
	silent := fleetsim.Scenarios[fleetsim.ScenarioSilent]
	if got := failed(t, good(p, silent)); got != nil {
		t.Fatalf("a clean silent run failed %v", got)
	}
	// The silent order's true mission, found some other way, with a wait that ran out:
	// as honest as unresolved.
	trueMission := func(e *Evidence) {
		e.Reads["m2"] = 40
		e.Report.Commands[1] = ReportedCommand{ID: e.Plan.Commands[1].ID, Robot: "r2", Mission: "m2", Dispatched: json.RawMessage(`"m2"`),
			State: "timeout", Polls: 40, MaxPolls: 40, Waited: json.RawMessage(`{"state":"timeout","polls":40}`)}
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
		"a failure reported as done":                  {fault, func(e *Evidence) { e.Report.Commands[1].State = "done" }, []string{"report_is_true"}},
		"a refusal reported without the refused code": {refused, func(e *Evidence) { e.Report.Commands[2].Code = "" }, []string{"kept_the_shapes", "report_is_true"}},
		"a refusal reported as unresolved":            {refused, func(e *Evidence) { e.Report.Commands[2].Code = "unresolved" }, []string{"report_is_true"}},
		"a refused robot shown idle": {refused, func(e *Evidence) {
			b, _ := json.Marshal([]map[string]any{{"id": "r1", "status": "idle", "battery": 90}, {"id": "r2", "status": "idle", "battery": 90}, {"id": "r3", "status": "idle", "battery": 90}})
			e.Report.Inventories[1].Returned = b
		}, []string{"inventory_is_true"}},
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
		// A review of 15 October 2026 found these three false passes.
		"a wait that threw after the mission ended": {nominal, func(e *Evidence) {
			c := &e.Report.Commands[0]
			c.Waited, c.State, c.Polls, c.Error = nil, "", 0, "wait failed after the mission ended"
		}, []string{"kept_the_shapes"}},
		"fewer reads reported than the vendor served": {nominal, func(e *Evidence) { e.Reads["m1"] = 20 }, []string{"report_is_true"}},
		"more reads at the vendor than the budget, reported": {nominal, func(e *Evidence) {
			e.Reads["m1"], e.Report.Commands[0].Polls, e.Report.Commands[0].Waited = 41, 41, json.RawMessage(`{"state":"done","polls":41}`)
		}, []string{"kept_the_shapes"}},
		"the cancelled command's budget is the platform's, not the report's": {nominal, func(e *Evidence) {
			e.Reads["m4"], e.Report.Commands[3].Polls, e.Report.Commands[3].Waited = 6, 6, json.RawMessage(`{"state":"cancelled","polls":6}`)
		}, []string{"kept_the_shapes"}},
		"a null battery": {nominal, func(e *Evidence) {
			e.Report.Inventories[0].Returned = json.RawMessage(`[{"id":"r1","status":"idle","battery":null},{"id":"r2","status":"idle","battery":90},{"id":"r3","status":"idle","battery":90}]`)
		}, []string{"kept_the_shapes"}},
		// The silent scenario: the order exists, nothing about it is answered.
		"an unanswered order reported as refused":       {silent, func(e *Evidence) { e.Report.Commands[1].Code = Refused }, []string{"report_is_true"}},
		"an unanswered order reported with no code":     {silent, func(e *Evidence) { e.Report.Commands[1].Code = "" }, []string{"kept_the_shapes", "report_is_true"}},
		"an unanswered order's true mission, timed out": {silent, trueMission, nil},
		"an unanswered order under an invented mission": {silent, func(e *Evidence) {
			trueMission(e)
			e.Report.Commands[1].Mission = "m7"
		}, []string{"report_is_true"}},
		"an unanswered order reported done": {silent, func(e *Evidence) {
			trueMission(e)
			e.Report.Commands[1].State, e.Report.Commands[1].Waited = "done", json.RawMessage(`{"state":"done","polls":40}`)
		}, []string{"report_is_true"}},
		// The night review's two reproductions.
		"an unresolved report that read past the budget": {silent, func(e *Evidence) { e.Reads["m2"] = 41 }, []string{"kept_the_shapes"}},
		"an honest timeout on an order that ended later": {nominal, func(e *Evidence) {
			c := &e.Report.Commands[0]
			c.State, c.Polls, c.Waited = "timeout", 40, json.RawMessage(`{"state":"timeout","polls":40}`)
		}, nil},
		"a timeout after the vendor answered that it ended": {nominal, func(e *Evidence) {
			c := &e.Report.Commands[0]
			c.State, c.Polls, c.Waited = "timeout", 40, json.RawMessage(`{"state":"timeout","polls":40}`)
			e.Told = map[string]int{"m1": 1}
		}, []string{"report_is_true"}},
		"an unanswered order placed twice": {silent, func(e *Evidence) {
			e.Ledger = append(e.Ledger, fleetsim.Order{ID: "m9", Robot: "r2", CommandID: e.Plan.Commands[1].ID, Target: e.Plan.Commands[1].Target, Status: "queued", History: []string{"queued"}})
		}, []string{"one_order_per_command"}},
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

// fixture is a bundle of signed runs as the example writes one, with the requirements
// file every run's request carried.
type fixture struct {
	entries []attest.Entry
	envs    []attest.Envelope
	preds   []Predicate
	reqs    Requirements
	reqData []byte
}

// signedRuns builds a bundle of n adapter runs signed by key, as the example writes
// one: each run's request carries its adapter, harness.js, plan.json and the shipped
// requirements file, and its response prints the report. With probe, a boundary probe
// run follows them. It returns the bundle and one statement per run, each adapter
// statement pinning the requirements file with a verdict per requirement.
func signedRuns(t *testing.T, key ed25519.PrivateKey, n int, probe bool) fixture {
	t.Helper()
	return signedRunsWith(t, key, n, probe, nil)
}

// signedRunsWith is signedRuns with each run's files passed through edit first, when
// edit is not nil: a request the example would never send.
func signedRunsWith(t *testing.T, key ed25519.PrivateKey, n int, probe bool, edit func(run int, files []*plimsollv1.ProjectFile) []*plimsollv1.ProjectFile) fixture {
	t.Helper()
	reqData, reqs := shippedRequirementsFile(t)
	var buf bytes.Buffer
	h := attest.NewHarness(attest.NewSigner(key), &buf)
	var preds []Predicate
	var subjects []string
	record := func(i int, files []*plimsollv1.ProjectFile, step, stdout string) string {
		if edit != nil {
			files = edit(i, files)
		}
		req := &plimsollv1.RunRequest{Protocol: 3, Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{Files: files, Steps: []string{step}}}}
		resp := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "container", Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{
			Steps: []*plimsollv1.StepResult{{Command: step, Stdout: []byte(stdout)}}}}}
		resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req), Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000100)}, resp)
		if err := h.Record(req, resp); err != nil {
			t.Fatal(err)
		}
		return resp.Record.GetRecordSha256()
	}
	for i := 1; i <= n; i++ {
		s := fleetsim.Scenarios[fleetsim.ScenarioOrder[(i-1)%len(fleetsim.ScenarioOrder)]]
		e := good(NewPlan(i), s)
		e.Credentials = []fleetsim.Credential{{ID: fmt.Sprintf("jti-%d", i)}}
		e.Report.Scenario, e.Report.Adapter = s.Name, "adapter-v2.js"
		planJSON, _ := json.Marshal(e.Plan)
		reportJSON, _ := json.Marshal(e.Report)
		files := []*plimsollv1.ProjectFile{{Path: "harness.js", Content: "// harness"}, {Path: "adapter-v2.js", Content: "// adapter"},
			{Path: RequirementsPath, Content: string(reqData)}, {Path: "plan.json", Content: string(planJSON)}}
		subjects = append(subjects, record(i, files, "node harness.js "+s.Name+" adapter-v2.js", "noise\nADAPTER-REPORT "+string(reportJSON)+"\n"))
		outcomes, pass := Evaluate(e)
		verdicts, err := Judge(reqs, outcomes)
		if err != nil {
			t.Fatal(err)
		}
		preds = append(preds, Predicate{Run: i, Simulator: fleetsim.Version, Adapter: FileDigest{Path: "adapter-v2.js", SHA256: Digest("// adapter")},
			Harness: Digest("// harness"), Requirements: &FileDigest{Path: RequirementsPath, SHA256: reqs.SHA256()},
			Evidence: e, Rules: outcomes, RequirementVerdicts: verdicts, Verdict: Verdict(pass)})
	}
	if probe {
		p := &ProbeReport{ThroughClient: "host api call not permitted by sandbox capability: DELETE /robots/r1", BypassClient: "403 forbidden", Direct: "failed: fetch failed"}
		e := Evidence{Kind: KindProbe, Scenario: fleetsim.Scenarios[fleetsim.ScenarioNominal], Probe: p, BrokerDenied: 1}
		probeJSON, _ := json.Marshal(p)
		files := []*plimsollv1.ProjectFile{{Path: "harness.js", Content: "// harness"}, {Path: "probe.js", Content: "// probe"}, {Path: RequirementsPath, Content: string(reqData)}}
		subjects = append(subjects, record(n+1, files, "node probe.js http://127.0.0.1:1", "PROBE "+string(probeJSON)+"\n"))
		outcomes, pass := Evaluate(e)
		preds = append(preds, Predicate{Run: n + 1, Simulator: fleetsim.Version, Adapter: FileDigest{Path: "probe.js", SHA256: Digest("// probe")},
			Evidence: e, Rules: outcomes, Verdict: Verdict(pass)})
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
	return fixture{entries: entries, envs: envs, preds: preds, reqs: reqs, reqData: reqData}
}

// resign returns f's statements with statement i's predicate changed by edit and signed
// again with key: what a holder of the signing key can make.
func (f fixture) resign(t *testing.T, key ed25519.PrivateKey, i int, edit func(*Predicate)) []attest.Envelope {
	t.Helper()
	b, _ := json.Marshal(f.preds[i])
	var c Predicate
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	edit(&c)
	subject, _, _ := Subject(f.envs[i])
	env, err := Sign(key, subject, c)
	if err != nil {
		t.Fatal(err)
	}
	out := slices.Clone(f.envs)
	out[i] = env
	return out
}

// oneWordChanged is the shipped requirements file with one word of REQ-004 changed, read
// as a holder would read a reworded copy.
func oneWordChanged(t *testing.T, data []byte) Requirements {
	t.Helper()
	changed := bytes.Replace(data, []byte("exactly one order"), []byte("at most one order"), 1)
	if bytes.Equal(changed, data) {
		t.Fatal("the shipped file no longer says \"exactly one order\"")
	}
	r, err := ReadRequirements(changed)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestStatementsVerifyAndRefuseChanges(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f := signedRuns(t, key, 3, true)
	entries, envs, preds := f.entries, f.envs, f.preds
	if _, err := attest.VerifyBundle(entries, attest.NewVerifier(pub)); err != nil {
		t.Fatal(err)
	}
	if got, err := Verify(pub, f.reqs, envs, entries); err != nil || len(got) != 4 {
		t.Fatalf("as written: %d verified, %v", len(got), err)
	}
	resign := func(i int, edit func(*Predicate)) []attest.Envelope { return f.resign(t, key, i, edit) }
	kept, _ := Rewrite(envs[0], func(p *Predicate) { p.Evidence.Ledger = p.Evidence.Ledger[1:] })
	_, strangerKey, _ := ed25519.GenerateKey(rand.Reader)
	subject, _, err := Subject(envs[0])
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := Sign(strangerKey, subject, preds[0])
	if err != nil {
		t.Fatal(err)
	}
	// A version 1 statement: the same predicate under the old type, signed with the key.
	v1, err := attest.NewSigner(key).SignStatement("https://plimsollmark.github.io/plimsoll/examples/adapter/qualification/v1",
		[]attest.Subject{{Name: attest.SubjectName, Digest: map[string]string{"sha256": subject}}}, preds[0])
	if err != nil {
		t.Fatal(err)
	}
	reworded := oneWordChanged(t, f.reqData)
	for label, c := range map[string]struct {
		envs []attest.Envelope
		reqs Requirements
		want string
	}{
		"an edited ledger, signature kept": {envs: append([]attest.Envelope{kept}, envs[1:]...), want: "signature"},
		"signed by another key":            {envs: append([]attest.Envelope{stranger}, envs[1:]...), want: "no valid signature from this key"},
		"a version 1 statement":            {envs: append([]attest.Envelope{v1}, envs[1:]...), want: "predicate type"},
		"a verdict that does not follow": {envs: resign(0, func(p *Predicate) {
			p.Evidence.Ledger = append(p.Evidence.Ledger, done("m9", "r2", "", fleetsim.Pose{X: 10, Y: 4}))
		}), want: "does not follow"},
		"a scenario that is not the simulator's": {envs: resign(0, func(p *Predicate) { p.Evidence.Scenario.FaultRobot = "r1" }), want: "the scenario is not"},
		"a report the run did not print":         {envs: resign(0, func(p *Predicate) { p.Evidence.Report.Retries = 7 }), want: "not the one the run printed"},
		"a plan the run was not sent": {envs: resign(0, func(p *Predicate) {
			p.Evidence.Plan = NewPlan(2)
			p.Rules, _ = Evaluate(p.Evidence)
		}), want: "plan.json"},
		"an adapter the run did not carry": {envs: resign(0, func(p *Predicate) { p.Adapter.SHA256 = Digest("// another adapter") }), want: "did not carry"},
		"a statement moved to another run": {envs: resign(0, func(p *Predicate) { p.Run = 2 }), want: "is not run 2's record"},
		"an exit code the run did not end with": {envs: resign(0, func(p *Predicate) {
			p.Evidence.ExitCode = 1
			p.Rules, _ = Evaluate(p.Evidence)
			p.Verdict = "fail"
		}), want: "exited 0"},
		"a credential two runs shared": {envs: resign(1, func(p *Predicate) { p.Evidence.Credentials[0].ID = "jti-1" }), want: "also served run 1"},
		"a run without a statement":    {envs: envs[:3], want: "3 statements for 4 runs"},

		// The pin. The statements as written, against a requirements file with one word
		// of REQ-004 changed: every adapter statement names the file it was judged
		// against, and this is not it.
		"a requirements file reworded after the run": {envs: envs, reqs: reworded, want: "judged against requirements " + short(f.reqs.SHA256()) + ", and this requirements file is " + short(reworded.SHA256())},
		// Re-signed with REQ-004 held over a ledger holding two orders for one command:
		// the rules (rebuilt) say one_order_per_command did not hold, so REQ-004 cannot.
		"REQ-004 flipped to held over two orders": {envs: resign(0, func(p *Predicate) {
			extra := p.Evidence.Ledger[0]
			extra.ID = "m9"
			p.Evidence.Ledger = append(p.Evidence.Ledger, extra)
			p.Rules, _ = Evaluate(p.Evidence)
			p.Verdict = "fail"
			for i := range p.RequirementVerdicts {
				if p.RequirementVerdicts[i].ID == "REQ-004" {
					p.RequirementVerdicts[i].Status, p.RequirementVerdicts[i].Failed = Held, nil
				}
			}
		}), want: "requirement verdicts do not follow"},
		"a requirement verdict dropped": {envs: resign(0, func(p *Predicate) { p.RequirementVerdicts = p.RequirementVerdicts[1:] }), want: "requirement verdicts do not follow"},
		"no requirement verdicts":       {envs: resign(0, func(p *Predicate) { p.RequirementVerdicts = nil }), want: "requirement verdicts do not follow"},
		"no pin":                        {envs: resign(0, func(p *Predicate) { p.Requirements = nil }), want: "pins no requirements file"},
		// Re-signed to pin the reworded file and verified against it: the pin agrees
		// with the holder's file, but the run's signed request carried the other one.
		"a pin the request did not carry": {envs: resign(0, func(p *Predicate) {
			p.Requirements.SHA256 = reworded.SHA256()
		}), reqs: reworded, want: "the request did not carry " + RequirementsPath},
		"a pin naming another file of the request": {envs: resign(0, func(p *Predicate) { p.Requirements.Path = "harness.js" }), want: "the request did not carry harness.js"},
		"the probe pinning requirements": {envs: resign(3, func(p *Predicate) {
			p.Requirements = &FileDigest{Path: RequirementsPath, SHA256: f.reqs.SHA256()}
		}), want: "the probe decides no requirement"},
		"the probe carrying requirement verdicts": {envs: resign(3, func(p *Predicate) {
			p.RequirementVerdicts = preds[0].RequirementVerdicts
		}), want: "the probe decides no requirement"},
		"no requirements file given": {envs: envs, reqs: Requirements{}, want: "no requirements file"},
	} {
		t.Run(label, func(t *testing.T) {
			reqs := c.reqs
			if reqs.SHA256() == "" && label != "no requirements file given" {
				reqs = f.reqs
			}
			_, err := Verify(pub, reqs, c.envs, entries)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

// A request that carries the requirements file twice leaves no single file for the pin
// to name; the daemon refuses one, and so does the verifier.
func TestARepeatedFileIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f := signedRunsWith(t, key, 1, false, func(_ int, files []*plimsollv1.ProjectFile) []*plimsollv1.ProjectFile {
		return append(files, &plimsollv1.ProjectFile{Path: RequirementsPath, Content: "{}"})
	})
	if _, err := Verify(pub, f.reqs, f.envs, f.entries); err == nil || !strings.Contains(err.Error(), "carries "+RequirementsPath+" twice") {
		t.Fatalf("got %v", err)
	}
	if _, err := CarriedRequirements(f.entries[0]); err == nil || !strings.Contains(err.Error(), "2 copies") {
		t.Fatalf("carried requirements: %v", err)
	}
}

// A holder with no requirements file of its own reads the copy a run carried; the
// statements verify against it, and the pin names it.
func TestCarriedRequirements(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f := signedRuns(t, key, 2, true)
	for i, e := range f.entries[:3] {
		r, err := CarriedRequirements(e)
		if err != nil || r.SHA256() != f.reqs.SHA256() {
			t.Fatalf("run %d: %s, %v", i+1, r.SHA256(), err)
		}
	}
	if _, err := CarriedRequirements(f.entries[3]); err == nil {
		t.Fatal("the checkpoint carried a requirements file")
	}
	r, _ := CarriedRequirements(f.entries[0])
	if _, err := Verify(pub, r, f.envs, f.entries); err != nil {
		t.Fatal(err)
	}
	none := signedRunsWith(t, key, 1, false, func(_ int, files []*plimsollv1.ProjectFile) []*plimsollv1.ProjectFile {
		return slices.DeleteFunc(files, func(f *plimsollv1.ProjectFile) bool { return f.GetPath() == RequirementsPath })
	})
	if _, err := CarriedRequirements(none.entries[0]); err == nil || !strings.Contains(err.Error(), "0 copies") {
		t.Fatalf("a run without the file: %v", err)
	}
	// And its statement, which pins the file, does not verify: the request did not carry it.
	if _, err := Verify(pub, f.reqs, none.envs, none.entries); err == nil || !strings.Contains(err.Error(), "the request did not carry "+RequirementsPath) {
		t.Fatalf("a pinned file the request did not carry: %v", err)
	}
}

// One statement and the one line it speaks for prove each other without the bundle:
// the line's own link places it, and the statement must name that place and that
// record. The checks across runs stay Verify's.
func TestVerifyOneNeedsOnlyTheLine(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f := signedRuns(t, key, 3, true)
	entries, envs, preds := f.entries, f.envs, f.preds
	for i := range preds {
		got, err := VerifyOne(pub, f.reqs, envs[i], entries[i])
		if err != nil {
			t.Fatalf("statement %d alone: %v", i+1, err)
		}
		if subject, _, _ := Subject(envs[i]); got.Record != subject || got.Predicate.Run != i+1 {
			t.Fatalf("statement %d alone: %+v", i+1, got)
		}
	}
	if _, err := VerifyOne(pub, f.reqs, envs[0], entries[1]); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("statement 1 against line 2: %v", err)
	}
	moved := preds[0]
	moved.Run = 2
	subject, _, _ := Subject(envs[0])
	env, err := Sign(key, subject, moved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOne(pub, f.reqs, env, entries[1]); err == nil || !strings.Contains(err.Error(), "is not run 2's record") {
		t.Fatalf("a statement moved onto line 2: %v", err)
	}
	unlinked := entries[0]
	unlinked.Link = nil
	if _, err := VerifyOne(pub, f.reqs, envs[0], unlinked); err == nil || !strings.Contains(err.Error(), "the run's line") {
		t.Fatalf("a line without its link: %v", err)
	}
	if _, err := VerifyOne(pub, f.reqs, envs[0], entries[4]); err == nil {
		t.Fatal("the checkpoint was taken for a run")
	}
	if _, err := VerifyOne(pub, oneWordChanged(t, f.reqData), envs[0], entries[0]); err == nil || !strings.Contains(err.Error(), "judged against requirements") {
		t.Fatalf("one statement against a reworded file: %v", err)
	}
	if _, err := VerifyOne(pub, Requirements{}, envs[0], entries[0]); err == nil || !strings.Contains(err.Error(), "no requirements file") {
		t.Fatalf("no requirements file: %v", err)
	}
}
