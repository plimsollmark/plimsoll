package rpc

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// fanOutTrace builds a metadata-only CallTrace that trips the fan-out detector two
// ways, one finding per route group:
//   - GET /v1/lights/* hit 8 times, with a collection sibling (GET /v1/lights) in
//     the profile's Allow -> a fan-out the router can suggest a batch for
//     (agent-fixable).
//   - GET /v1/sensors/* hit 8 times, with NO sibling in Allow -> a fan-out the router
//     cannot fix (API-change, operator-only).
//
// Every call is delivered with a 200, and response sizes are all distinct so the
// repeated-read detector stays quiet — keeping the finding set deterministic for the
// assertions.
func fanOutTrace() *sandbox.CallTrace {
	var calls []sandbox.CallRow
	seq := 0
	add := func(route string) {
		seq++
		calls = append(calls, sandbox.CallRow{
			Seq: seq, Method: "GET", Route: route, Status: 200, Delivered: true,
			ReqBytes: 0, RespBytes: 100 + seq, Latency: time.Millisecond,
		})
	}
	for i := 0; i < 8; i++ {
		add("/v1/lights/*")
	}
	for i := 0; i < 8; i++ {
		add("/v1/sensors/*")
	}
	return &sandbox.CallTrace{Calls: calls}
}

// adviceService wires a fake sandbox whose JS result carries fanOutTrace() to a
// grants registry with one profile per advice mode (all otherwise identical), so a
// test can drive the same run under off/operator/caller by picking the profile.
func adviceService(t *testing.T, logw *bytes.Buffer) *SandboxService {
	t.Helper()
	t.Setenv("HUE_TOKEN", "tok")
	base := `"base_url":"https://h","allow":["GET /v1/lights/*","GET /v1/lights","GET /v1/sensors/*"],"allowed_callers":["mcp-a"],"token":{"type":"static","env":"HUE_TOKEN"}`
	// catalog exposes GET /v1/sensors — the batch sibling for the sensors fan-out that the
	// allow list omits — so a p-catalog profile can name the ungranted route to add.
	catalog := `,"catalog":["GET /v1/lights/*","GET /v1/lights","GET /v1/sensors/*","GET /v1/sensors"]`
	// p-operator/p-caller keep detailed retention so the Phase 4 per-finding assertions
	// hold; p-agg and p-caller-quiet exercise the Phase 5 retention gate (aggregate-only
	// and the default none, which stays silent in the audit log).
	body := `{"profiles":{
	  "p-off":{` + base + `},
	  "p-operator":{` + base + `,"advice":"operator","advice_retention":"detailed"},
	  "p-caller":{` + base + `,"advice":"caller","advice_retention":"detailed"},
	  "p-agg":{` + base + `,"advice":"operator","advice_retention":"aggregate"},
	  "p-caller-quiet":{` + base + `,"advice":"caller"},
	  "p-catalog":{` + base + catalog + `,"advice":"operator","advice_retention":"detailed"},
	  "p-catalog-caller":{` + base + catalog + `,"advice":"caller","advice_retention":"detailed"}
	}}`
	path := filepath.Join(t.TempDir(), "grants.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := grants.Load(path)
	if err != nil {
		t.Fatalf("load grants: %v", err)
	}
	fake := &fakeSandbox{
		jsResult: sandbox.Result{
			Stdout:    "sum=42",
			Stderr:    "warn",
			ExitCode:  0,
			Sandbox:   "fake",
			Isolation: sandbox.IsolationVM,
			Duration:  5 * time.Millisecond,
			CallTrace: fanOutTrace(),
		},
		// A project run brokers through the same core, so it carries the same trace and
		// must route advice identically to the snippet path.
		projResult: sandbox.ProjectResult{
			Sandbox:   "fake",
			Isolation: sandbox.IsolationVM,
			Outcome:   sandbox.ProjectOutcomeCompleted,
			Steps: []sandbox.StepResult{{
				Command: "node main.mjs", Stdout: "sum=42", Stderr: "warn", ExitCode: 0, Duration: 5 * time.Millisecond,
			}},
			CallTrace: fanOutTrace(),
		},
	}
	svc := NewSandboxService(fake)
	svc.Grants = reg
	if logw != nil {
		svc.Logger = slog.New(slog.NewJSONHandler(logw, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return svc
}

func runWithProfile(t *testing.T, svc *SandboxService, profile string) *plimsollv1.RunResponse {
	t.Helper()
	resp, err := svc.Run(authenticatedContext("mcp-a"), jsGrantReq("host.get('/v1/lights/1')", profile))
	if err != nil {
		t.Fatalf("run %s: %v", profile, err)
	}
	return resp.Msg
}

func runProjectWithProfile(t *testing.T, svc *SandboxService, profile string) *plimsollv1.RunResponse {
	t.Helper()
	resp, err := svc.Run(authenticatedContext("mcp-a"), projectReq(&plimsollv1.ProjectRun{
		Files:        []*plimsollv1.ProjectFile{{Path: "main.mjs", Content: "await host.get('/v1/lights/1')"}},
		Steps:        []string{"node main.mjs"},
		GrantProfile: profile,
	}))
	if err != nil {
		t.Fatalf("run project %s: %v", profile, err)
	}
	return resp.Msg
}

// TestProjectAdviceMirrorsSnippet proves the Phase-2 follow-up: a project run routes
// advice exactly like a snippet — off computes nothing, operator withholds from the
// caller, caller returns only the agent-fixable subset — and advice never changes the
// run (byte-identical steps/outcome across all three modes).
func TestProjectAdviceMirrorsSnippet(t *testing.T) {
	svc := adviceService(t, nil)
	off := runProjectWithProfile(t, svc, "p-off")
	operator := runProjectWithProfile(t, svc, "p-operator")
	caller := runProjectWithProfile(t, svc, "p-caller")

	// Execution is byte-identical across modes; only advice differs.
	for _, got := range []*plimsollv1.RunResponse{operator, caller} {
		if got.GetProject().GetOutcome() != off.GetProject().GetOutcome() || len(got.GetProject().GetSteps()) != len(off.GetProject().GetSteps()) {
			t.Fatalf("advice changed the project run:\n off=%+v\n got=%+v", off, got)
		}
		for i, st := range got.GetProject().GetSteps() {
			o := off.GetProject().GetSteps()[i]
			if !bytes.Equal(st.GetStdout(), o.GetStdout()) || !bytes.Equal(st.GetStderr(), o.GetStderr()) ||
				st.GetExitCode() != o.GetExitCode() || st.GetDurationMs() != o.GetDurationMs() {
				t.Fatalf("advice changed step %d:\n off=%+v\n got=%+v", i, o, st)
			}
		}
	}

	if len(off.GetProject().GetAdvice()) != 0 {
		t.Errorf("off mode returned advice: %+v", off.GetProject().GetAdvice())
	}
	if len(operator.GetProject().GetAdvice()) != 0 {
		t.Errorf("operator mode leaked advice to the caller: %+v", operator.GetProject().GetAdvice())
	}
	if len(caller.GetProject().GetAdvice()) == 0 {
		t.Fatal("caller mode returned no advice")
	}
	// Same router split as the snippet path: caller findings are agent-fixable only.
	for _, f := range caller.GetProject().GetAdvice() {
		if f.GetSuggestedRoute() == "" || f.GetSuggestedMethod() == "" {
			t.Errorf("caller finding is not agent-fixable (no suggested route): %+v", f)
		}
	}
}

// TestAdviceNonBlockingByteIdenticalExecution is the roadmap's non-blocking proof:
// the same run under off, operator, and caller advice produces byte-identical
// execution output — only the advisory `advice` field differs. Advice is evidence
// attached post-dispatch; it never changes the run.
func TestAdviceNonBlockingByteIdenticalExecution(t *testing.T) {
	svc := adviceService(t, nil)
	off := runWithProfile(t, svc, "p-off")
	operator := runWithProfile(t, svc, "p-operator")
	caller := runWithProfile(t, svc, "p-caller")

	// Every execution field is identical across the three modes.
	for _, got := range []*plimsollv1.RunResponse{operator, caller} {
		if !bytes.Equal(got.GetJavascript().GetStdout(), off.GetJavascript().GetStdout()) ||
			!bytes.Equal(got.GetJavascript().GetStderr(), off.GetJavascript().GetStderr()) ||
			got.GetJavascript().GetExitCode() != off.GetJavascript().GetExitCode() ||
			got.GetJavascript().GetTimedOut() != off.GetJavascript().GetTimedOut() ||
			got.GetDurationMs() != off.GetDurationMs() ||
			got.GetSandbox() != off.GetSandbox() ||
			got.GetIsolation() != off.GetIsolation() ||
			got.GetJavascript().GetStdoutTruncated() != off.GetJavascript().GetStdoutTruncated() ||
			got.GetJavascript().GetStderrTruncated() != off.GetJavascript().GetStderrTruncated() {
			t.Fatalf("advice changed execution output:\n off=%+v\n got=%+v", off, got)
		}
	}

	// Only caller mode surfaces advice to the caller.
	if len(off.GetJavascript().GetAdvice()) != 0 {
		t.Errorf("off mode returned advice: %+v", off.GetJavascript().GetAdvice())
	}
	if len(operator.GetJavascript().GetAdvice()) != 0 {
		t.Errorf("operator mode leaked advice to the caller: %+v", operator.GetJavascript().GetAdvice())
	}
	if len(caller.GetJavascript().GetAdvice()) == 0 {
		t.Error("caller mode returned no advice")
	}
}

// TestAdviceCallerReturnsOnlyAgentFixable proves the router split: caller mode
// returns only findings the profile can already fix with a better route, and the
// operator surface (audit) records strictly more (the API-change findings held back).
func TestAdviceCallerReturnsOnlyAgentFixable(t *testing.T) {
	var logbuf bytes.Buffer
	svc := adviceService(t, &logbuf)
	msg := runWithProfile(t, svc, "p-caller")

	adv := msg.GetJavascript().GetAdvice()
	if len(adv) == 0 {
		t.Fatal("caller advice is empty")
	}
	for _, f := range adv {
		if f.GetSuggestedRoute() == "" || f.GetSuggestedMethod() == "" {
			t.Errorf("caller finding is not agent-fixable (no suggested route): %+v", f)
		}
	}
	// The lights fan-out is the agent-fixable one; its suggestion is the collection.
	first := adv[0]
	if first.GetPattern() != "fan_out" || first.GetRoute() != "/v1/lights/*" ||
		first.GetSuggestedRoute() != "/v1/lights" || first.GetSuggestedMethod() != "GET" {
		t.Errorf("unexpected agent-fixable finding: %+v", first)
	}
	if first.GetDetail() == "" || first.GetExtraCalls() != 7 {
		t.Errorf("finding cost/detail wrong: detail=%q extra_calls=%d", first.GetDetail(), first.GetExtraCalls())
	}

	// The operator surface saw more than the caller got: the sensors fan-out is
	// API-change (no suggestion), so it is withheld from the caller but still counted
	// on the audit line.
	entry := lastCodeRunLog(t, &logbuf)
	findings := int(entry["advice_findings"].(float64))
	agentFixable := int(entry["advice_agent_fixable"].(float64))
	if entry["advice"] != "caller" {
		t.Errorf("audit advice mode = %v, want caller", entry["advice"])
	}
	if agentFixable != len(adv) {
		t.Errorf("advice_agent_fixable=%d but caller got %d findings", agentFixable, len(adv))
	}
	if findings <= agentFixable {
		t.Errorf("expected the operator surface to see more findings (%d) than the caller (%d)", findings, agentFixable)
	}
}

// TestAdviceAuditCarriesFindingsAndCosts proves the Phase 4 audit extension: the
// operator surface records the per-run pattern summary — aggregate costs plus one
// structured detail record per finding — all metadata only (route templates, verbs,
// labels, numbers), and the advice/waste metrics observe the same findings.
func TestAdviceAuditCarriesFindingsAndCosts(t *testing.T) {
	var logbuf bytes.Buffer
	svc := adviceService(t, &logbuf)
	runWithProfile(t, svc, "p-operator")

	entry := lastCodeRunLog(t, &logbuf)
	findings := int(entry["advice_findings"].(float64))
	if findings != 2 {
		t.Fatalf("expected exactly 2 findings (one fan-out per route group), got %d", findings)
	}
	// The totals sum disjoint route groups: two fan-outs of 8 calls each are 7+7 extra
	// calls, never inflated by a second finding over the same rows.
	if got := entry["advice_extra_calls"].(float64); got != 14 {
		t.Errorf("advice_extra_calls = %v, want 14", got)
	}
	if _, ok := entry["advice_bytes_moved"]; !ok {
		t.Error("advice_bytes_moved missing")
	}
	if _, ok := entry["advice_added_latency_ms"]; !ok {
		t.Error("advice_added_latency_ms missing")
	}

	// The structured per-finding detail list matches the finding count and carries the
	// trusted metadata the HTML report reads.
	details, ok := entry["advice_finding_details"].([]any)
	if !ok || len(details) != findings {
		t.Fatalf("advice_finding_details = %v (want %d records)", entry["advice_finding_details"], findings)
	}
	var sawAgentFixable, sawAPIChange bool
	for _, d := range details {
		m := d.(map[string]any)
		for _, key := range []string{"pattern", "severity", "remedy", "method", "route", "detail"} {
			if s, _ := m[key].(string); s == "" {
				t.Errorf("finding detail missing %q: %+v", key, m)
			}
		}
		if m["agent_fixable"].(bool) {
			sawAgentFixable = true
			if m["suggested_route"].(string) == "" {
				t.Errorf("agent-fixable finding has no suggested_route: %+v", m)
			}
		} else {
			sawAPIChange = true
		}
	}
	if !sawAgentFixable || !sawAPIChange {
		t.Errorf("expected both an agent-fixable and an API-change finding (fixable=%v api=%v)", sawAgentFixable, sawAPIChange)
	}

	// The advice/waste metrics observed the same findings.
	snap := svc.AdviceStats()
	if len(snap) == 0 {
		t.Fatal("AdviceStats recorded nothing")
	}
	var total uint64
	for _, s := range snap {
		total += s.Count
	}
	if int(total) != findings {
		t.Errorf("advice metrics counted %d findings, audit line %d", total, findings)
	}
}

// TestAdviceRetentionGatesAuditLog proves the Phase 5 retention gate. The knob governs
// only the durable audit-log record and is orthogonal to the advice audience:
//
//   - aggregate retention writes the per-run totals but no per-finding, per-route
//     records (advice_finding_details is absent);
//   - the default (none) writes nothing to the audit log even though advice is on — yet
//     the caller still gets its wire hint and /metrics still observes the findings,
//     because retention gates the log alone.
func TestAdviceRetentionGatesAuditLog(t *testing.T) {
	// Aggregate: totals present, per-finding detail withheld.
	var aggBuf bytes.Buffer
	aggSvc := adviceService(t, &aggBuf)
	runWithProfile(t, aggSvc, "p-agg")
	agg := lastCodeRunLog(t, &aggBuf)
	if agg["advice_retention"] != "aggregate" {
		t.Errorf("advice_retention = %v, want aggregate", agg["advice_retention"])
	}
	if int(agg["advice_findings"].(float64)) < 2 {
		t.Errorf("aggregate retention dropped the finding count: %v", agg["advice_findings"])
	}
	if _, present := agg["advice_finding_details"]; present {
		t.Errorf("aggregate retention leaked per-finding details: %v", agg["advice_finding_details"])
	}

	// Default none: caller mode, so the wire hint is returned and /metrics observes the
	// findings, but the audit log carries no advice_* record of them.
	var quietBuf bytes.Buffer
	quietSvc := adviceService(t, &quietBuf)
	msg := runWithProfile(t, quietSvc, "p-caller-quiet")
	if len(msg.GetJavascript().GetAdvice()) == 0 {
		t.Fatal("retention none suppressed the caller wire hint (it should gate only the log)")
	}
	if len(quietSvc.AdviceStats()) == 0 {
		t.Error("retention none suppressed /metrics folding (it should gate only the log)")
	}
	quiet := lastCodeRunLog(t, &quietBuf)
	for _, k := range []string{"advice", "advice_retention", "advice_findings", "advice_finding_details"} {
		if _, present := quiet[k]; present {
			t.Errorf("retention none wrote %q to the audit log: %v", k, quiet[k])
		}
	}
}

// TestAdviceOperatorWithholdsFromCaller confirms operator mode computes findings for
// the audit/log surface but returns nothing in the run result.
func TestAdviceOperatorWithholdsFromCaller(t *testing.T) {
	var logbuf bytes.Buffer
	svc := adviceService(t, &logbuf)
	msg := runWithProfile(t, svc, "p-operator")

	if len(msg.GetJavascript().GetAdvice()) != 0 {
		t.Fatalf("operator mode returned advice to the caller: %+v", msg.GetJavascript().GetAdvice())
	}
	entry := lastCodeRunLog(t, &logbuf)
	if entry["advice"] != "operator" {
		t.Errorf("audit advice mode = %v, want operator", entry["advice"])
	}
	if int(entry["advice_findings"].(float64)) < 1 {
		t.Error("operator mode recorded no findings on the audit line")
	}
}

// TestAdviceOffComputesNothing confirms the default: no advice field on the audit
// line and none in the result.
func TestAdviceOffComputesNothing(t *testing.T) {
	var logbuf bytes.Buffer
	svc := adviceService(t, &logbuf)
	msg := runWithProfile(t, svc, "p-off")

	if len(msg.GetJavascript().GetAdvice()) != 0 {
		t.Errorf("off mode returned advice: %+v", msg.GetJavascript().GetAdvice())
	}
	entry := lastCodeRunLog(t, &logbuf)
	if _, present := entry["advice"]; present {
		t.Errorf("off mode emitted an advice audit attr: %v", entry["advice"])
	}
}

// TestAdviceCatalogNamesUngrantedRoute proves the specgen->Prospector follow-on: when a
// fan-out's batch route is not granted but the profile's endpoint catalog shows the API
// exposes it, the operator surface names the concrete route to grant (grant_route), and
// that operator action never leaks to the caller.
func TestAdviceCatalogNamesUngrantedRoute(t *testing.T) {
	var logbuf bytes.Buffer
	svc := adviceService(t, &logbuf)
	runWithProfile(t, svc, "p-catalog")

	entry := lastCodeRunLog(t, &logbuf)
	if got := int(entry["advice_ungranted_routes"].(float64)); got < 1 {
		t.Fatalf("advice_ungranted_routes = %d, want >=1", got)
	}
	details, ok := entry["advice_finding_details"].([]any)
	if !ok {
		t.Fatalf("advice_finding_details missing: %v", entry["advice_finding_details"])
	}
	var named bool
	for _, d := range details {
		m := d.(map[string]any)
		if m["route"] == "/v1/sensors/*" {
			if m["grant_route"] != "/v1/sensors" || m["grant_route_method"] != "GET" {
				t.Errorf("sensors fan-out did not name the ungranted batch route: %+v", m)
			}
			if m["agent_fixable"].(bool) {
				t.Errorf("ungranted-route finding must not be agent_fixable: %+v", m)
			}
			named = true
		}
	}
	if !named {
		t.Fatalf("no finding named the ungranted route for /v1/sensors/*: %+v", details)
	}

	// The operator action never reaches the caller: caller mode returns only the granted
	// lights fan-out, and no caller finding carries a grant_route (that field is not on
	// the caller wire at all).
	callerMsg := runWithProfile(t, svc, "p-catalog-caller")
	for _, f := range callerMsg.GetJavascript().GetAdvice() {
		if f.GetRoute() == "/v1/sensors/*" {
			t.Errorf("ungranted sensors route leaked to the caller: %+v", f)
		}
		if f.GetSuggestedRoute() == "" {
			t.Errorf("caller finding is not agent-fixable: %+v", f)
		}
	}
}

// lastCodeRunLog parses the most recent "code run" JSON audit line into a map.
func lastCodeRunLog(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var entry map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		if m["msg"] == "code run" {
			entry = m
		}
	}
	if entry == nil {
		t.Fatalf("no \"code run\" audit line found in:\n%s", buf.String())
	}
	return entry
}
