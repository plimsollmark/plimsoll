// Command devscenario is the independent trial's development scenario: what each agent
// could try its adapter in, once per round. It runs one adapter through the platform's
// harness against fleetsim (nominal only) under the host's node, with a stand-in for
// the broker socket (the six granted routes, the broker's error shapes) and the real
// generated client, and prints exactly what the agent is shown. It is not the sandbox:
// the trial's adapters are judged through plimsolld by the example program.
//
//	go run ./examples/adapter/trial/devscenario ADAPTER.js
package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/plimsollmark/plimsoll/examples/adapter/fleetsim"
	"github.com/plimsollmark/plimsoll/examples/adapter/qualify"
	"github.com/plimsollmark/plimsoll/internal/specgen"
)

const client = `
const allow = [["GET","/health"],["GET","/missions/*"],["POST","/missions/*/cancel"],["GET","/robots"],["GET","/robots/*"],["POST","/robots/*/missions"]];
function allowed(m, p) { const s = p.split("/"); return allow.some(([am, ap]) => { const t = ap.split("/"); return am === m && t.length === s.length && t.every((x, i) => x === "*" ? s[i] !== "" : x === s[i]); }); }
async function call(method, path, body) {
  method = String(method).toUpperCase();
  if (!allowed(method, path)) throw new Error("host api call not permitted by sandbox capability: " + method + " " + path);
  let r;
  try { r = await fetch(process.env.VENDOR_URL + path, { method, headers: { Authorization: "Bearer dev-token", "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }); }
  catch (e) { throw new Error("host api 502: host api unavailable"); }
  const text = await r.text();
  if (!r.ok) throw new Error("host api " + r.status + ": " + text);
  try { return JSON.parse(text); } catch { return text; }
}
globalThis.fleet = { call, get: (p) => call("GET", p), put: (p, b) => call("PUT", p, b), post: (p, b) => call("POST", p, b), patch: (p, b) => call("PATCH", p, b), del: (p) => call("DELETE", p) };
require("./preamble.js");
`

func main() {
	root := "."
	adapter := os.Args[1]
	spec, _ := os.ReadFile(filepath.Join(root, "examples/adapter/vendor/fleet.openapi.json"))
	gen, err := specgen.Generate(spec, specgen.Options{Global: "fleet"})
	if err != nil {
		panic(err)
	}
	dir, _ := os.MkdirTemp("", "trialdev-*")
	defer os.RemoveAll(dir)
	harness, _ := os.ReadFile(filepath.Join(root, "examples/adapter/contract/harness.js"))
	src, err := os.ReadFile(adapter)
	if err != nil {
		panic(err)
	}
	plan := qualify.NewPlan(1)
	planJSON, _ := json.Marshal(plan)
	for name, body := range map[string][]byte{"harness.js": harness, "adapter.js": src, "plan.json": planJSON, "preamble.js": []byte(gen.Preamble), "client.cjs": []byte(client)} {
		os.WriteFile(filepath.Join(dir, name), body, 0o600)
	}
	sim := fleetsim.New(fleetsim.Static("dev-token"))
	sim.Reset(fleetsim.ScenarioNominal)
	srv := httptest.NewServer(sim)
	defer srv.Close()
	cmd := exec.Command("node", "-r", "./client.cjs", "harness.js", "nominal", "adapter.js")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "VENDOR_URL="+srv.URL)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, _ := cmd.Output()
	code := cmd.ProcessState.ExitCode()
	ev := qualify.Evidence{Kind: qualify.KindAdapter, Scenario: sim.Scenario(), Plan: plan, Ledger: sim.Ledger(), Robots: sim.Robots(), Report: qualify.ReadReport(string(out)), ExitCode: code}
	outcomes, pass := qualify.Evaluate(ev)
	fmt.Printf("Development scenario (nominal: three idle robots, every order can complete). The harness ran these commands: ")
	for _, c := range plan.Commands {
		s := fmt.Sprintf("%s: %s to (%g, %g)", c.ID, c.Robot, c.Target.X, c.Target.Y)
		if c.Cancel {
			s += ", cancelled as soon as placed"
		}
		fmt.Print(s, "; ")
	}
	fmt.Printf("\n\nThe harness exited %d and printed:\n%s\n", code, strings.TrimSpace(qualify.ParseLine(string(out), "ADAPTER-REPORT ")))
	if e := strings.TrimSpace(stderr.String()); e != "" {
		if len(e) > 1500 {
			e = e[:1500] + "..."
		}
		fmt.Printf("\nIts stderr:\n%s\n", e)
	}
	fmt.Printf("\nThe rules, from the vendor's ledger:\n")
	for _, o := range outcomes {
		mark := "held"
		if !o.Held {
			mark = "BROKEN: " + o.Detail
		}
		fmt.Printf("- %s: %s\n", o.Rule, mark)
	}
	fmt.Printf("\nVerdict in this scenario: %s.\n", map[bool]string{true: "pass", false: "fail"}[pass])
}
