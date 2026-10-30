package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/auditline"
	"github.com/plimsollmark/plimsoll/internal/withheld"
	"github.com/plimsollmark/plimsoll/protocol"
)

// The hackathon's two leaks, replayed against the real daemon (main() in a child
// process, the wasm provider, callers from a clients file, the set from
// PLIMSOLL_WITHHELD_FILE): the harness's source shipped as a caller's code, and a
// practice seed inside an example URL. The source is refused before dispatch, the seed
// is named to the operator alone, and the judge, which the set exempts, runs the
// source. A malformed set stops the daemon before it listens.
func TestDaemonShipScanReplaysTheHackathon(t *testing.T) {
	const (
		harness      = "function step(state, u, dt) { return state + dt * (u - 0.3 * state); }\nconsole.log(step(1, 0, 0.1));\n"
		practiceSeed = "731904"
		agentToken   = "agent-0123456789abcdef0123456789abcdef"
		judgeToken   = "judge-0123456789abcdef0123456789abcdef"
	)
	dir := t.TempDir()
	hexOf := func(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
	valueHex := func(v string) string { d := withheld.ValueDigest([]byte(v)); return hex.EncodeToString(d[:]) }
	file := withheld.FileDigest([]byte(harness))
	set, err := json.Marshal(map[string]any{"version": withheld.Version, "mode": "refuse", "exempt_callers": []string{"judge"}, "entries": []map[string]any{
		{"kind": "file", "sha256": hex.EncodeToString(file[:]), "label": "harness/sim.js"},
		{"kind": "value", "sha256": valueHex(practiceSeed), "length": len(practiceSeed), "label": "seeds.txt:2", "mode": "audit"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	clients, err := json.Marshal(map[string]any{"clients": []map[string]any{
		{"id": "agent-harness", "token_sha256": hexOf([]byte(agentToken)), "scopes": []string{"code:run"}},
		{"id": "judge", "token_sha256": hexOf([]byte(judgeToken)), "scopes": []string{"code:run"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	setPath, clientsPath := filepath.Join(dir, "withheld.json"), filepath.Join(dir, "clients.json")
	for path, raw := range map[string][]byte{setPath: set, clientsPath: clients} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{"SANDBOX_PROVIDER=wasm", "PLIMSOLL_ADDR=127.0.0.1:0", "PLIMSOLL_METRICS_ADDR=off", "PLIMSOLL_CLIENTS_FILE=" + clientsPath}
	d := startDaemon(t, append(env, "PLIMSOLL_WITHHELD_FILE="+setPath), 60*time.Second)
	client := plimsollv1connect.NewSandboxServiceClient(http.DefaultClient, "http://"+d.addr)
	run := func(token string, payload *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		payload.Protocol = protocol.Number
		// The wasm provider's ceiling, not its 5-second default: under the race detector in
		// a full gate a first QuickJS run took longer than 5 seconds twice on 2026-10-27,
		// and the audit-mode call came back timed out with no output.
		payload.TimeoutMs = 30000
		req := connect.NewRequest(payload)
		req.Header().Set("Authorization", "Bearer "+token)
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		resp, err := client.Run(ctx, req)
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}
	snippet := func(code string) *plimsollv1.RunRequest {
		return &plimsollv1.RunRequest{Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: code}}}
	}
	notDispatched := func(err error) (plimsollv1.NotDispatchedReason, bool) {
		var ce *connect.Error
		if !errors.As(err, &ce) {
			return 0, false
		}
		for _, detail := range ce.Details() {
			if v, derr := detail.Value(); derr == nil {
				if nd, ok := v.(*plimsollv1.NotDispatched); ok {
					return nd.GetReason(), true
				}
			}
		}
		return 0, false
	}

	// The harness's source as the agent's code, with Windows line endings: refused,
	// not dispatched, naming the entry and never the content.
	_, err = run(agentToken, snippet(strings.ReplaceAll(harness, "\n", "\r\n")))
	if reason, marked := notDispatched(err); connect.CodeOf(err) != connect.CodePermissionDenied || !marked ||
		reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION || !strings.Contains(err.Error(), "harness/sim.js (code)") ||
		strings.Contains(err.Error(), "function step") {
		t.Fatalf("the harness's source from the agent: %v", err)
	}
	// The same source as a project's helper file, under another name: refused by the
	// scan, before the provider is asked (the wasm provider runs no project).
	_, err = run(agentToken, &plimsollv1.RunRequest{Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
		Files: []*plimsollv1.ProjectFile{{Path: "helpers/model.js", Content: harness}}, Steps: []string{"node helpers/model.js"}}}})
	if connect.CodeOf(err) != connect.CodePermissionDenied || !strings.Contains(err.Error(), "harness/sim.js (files[0].content)") {
		t.Fatalf("the harness's source as a project file: %v", err)
	}
	// The practice seed in an example URL: the call runs, and nothing in its answer
	// says the seed was found.
	resp, err := run(agentToken, snippet(`const example = "viewer.html?seed=`+practiceSeed+`&case=2"; console.log("flown")`))
	if err != nil {
		t.Fatalf("the audit-mode call: %v", err)
	}
	if js := resp.GetJavascript(); !strings.Contains(string(js.GetStdout()), "flown") {
		t.Fatalf("the audit-mode call's output: %q (exit %d, timed out %v, stderr %q)", js.GetStdout(), js.GetExitCode(), js.GetTimedOut(), js.GetStderr())
	}
	if wire, _ := json.Marshal(resp); strings.Contains(string(wire), "seeds.txt") || strings.Contains(string(wire), "withheld") {
		t.Errorf("the answer states the find: %s", wire)
	}
	// The judge runs the harness's source.
	resp, err = run(judgeToken, snippet(harness))
	if err != nil || !strings.Contains(string(resp.GetJavascript().GetStdout()), "0.9") {
		t.Fatalf("the exempt judge: %v, %q", err, resp.GetJavascript().GetStdout())
	}
	d.stop(t, 30*time.Second)

	logs := d.logText()
	runs, err := auditline.Parse(strings.NewReader(logs))
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].Caller != "agent-harness" || runs[0].WithheldScan != "scanned" || strings.Join(runs[0].WithheldFound, ",") != "seeds.txt:2" ||
		runs[1].Caller != "judge" || runs[1].WithheldScan != "exempt" || runs[1].WithheldSet != hexOf(set) {
		t.Errorf("run lines: %+v", runs)
	}
	for _, want := range []string{`"msg":"withheld set loaded: every call's payload is scanned for it"`, `"msg":"withheld material refused"`, `"msg":"withheld material found"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("the daemon's log lacks %s", want)
		}
	}
	for _, leak := range []string{practiceSeed, "function step", "helpers/model.js", "viewer.html"} {
		if strings.Contains(logs, leak) {
			t.Errorf("the daemon's log repeats %q", leak)
		}
	}

	// A set with a typo in it stops the daemon before it serves anything.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(strings.Replace(string(set), `"mode":"refuse"`, `"mode":"refuze"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = append([]string{"PLIMSOLLD_RUN_MAIN=1", "PLIMSOLL_WITHHELD_FILE=" + bad}, env...)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "failed to load the withheld set") || strings.Contains(string(out), "plimsolld listening") {
		t.Fatalf("a malformed set: %v\n%s", err, out)
	}
}
