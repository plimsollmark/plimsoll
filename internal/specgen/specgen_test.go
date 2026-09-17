package specgen

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/sandbox"
)

var update = flag.Bool("update", false, "rewrite the golden artifacts under testdata/golden")

// TestGenerateGolden drives the representative smart-home spec end to end and asserts
// the three artifacts match committed golden files. Run `go test -run Golden -update`
// to regenerate them after an intentional change, then eyeball the diff.
func TestGenerateGolden(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("testdata", "smart-home.openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Global "home" mirrors a consumer that exposes its client as a domain-specific
	// `home.*` surface.
	res, err := Generate(spec, Options{Global: "home"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// The spec marks /status with x-plimsoll-health-check, which is the only way an
	// operation becomes the backpressure probe.
	if res.HealthCheck != "GET /status" {
		t.Errorf("HealthCheck = %q, want %q (note %q)", res.HealthCheck, "GET /status", res.HealthNote)
	}

	artifacts := map[string]string{
		"allow.txt":       strings.Join(res.AllowStrings(), "\n") + "\n",
		"preamble.js":     res.Preamble,
		"description.txt": res.Description,
	}
	for name, got := range artifacts {
		path := filepath.Join("testdata", "golden", name)
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read golden %s (run -update to create): %v", name, err)
		}
		if got != string(want) {
			t.Errorf("%s mismatch (run -update to accept):\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
		}
	}
}

// TestGenerateDeterministic proves generation is byte-stable across runs (the whole
// point of committing the artifacts and diffing them in review).
func TestGenerateDeterministic(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("testdata", "smart-home.openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := Generate(spec, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(spec, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Preamble != b.Preamble || a.Description != b.Description || len(a.Allow) != len(b.Allow) {
		t.Fatal("generation is not deterministic")
	}
}

// TestDerivedAllowMatchesBroker checks the derived routes are exactly the deduped
// segment-wise templates the broker enforces: path params become "*", and two paths
// that collapse to the same template share one allow entry.
func TestDerivedAllowMatchesBroker(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("testdata", "smart-home.openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Generate(spec, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, s := range res.AllowStrings() {
		got[s] = true
	}
	want := []string{
		"GET /lights",
		"POST /lights",
		"GET /lights/*",
		"PUT /lights/*",
		"PATCH /lights/*",
		"DELETE /lights/*",
		"GET /rooms/*/lights",
		"GET /scenes",
		"GET /status",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing allow route %q; got %v", w, res.AllowStrings())
		}
	}
	if len(res.AllowStrings()) != len(want) {
		t.Errorf("allow has %d routes, want %d: %v", len(res.AllowStrings()), len(want), res.AllowStrings())
	}
	// The broker now enforces PATCH, so it is a first-class allow route, not skipped.
	if !got["PATCH /lights/*"] {
		t.Error("PATCH /lights/* should be a derived allow route")
	}
	// This spec declares only enforceable verbs, so nothing is skipped.
	if len(res.Skipped) != 0 {
		t.Errorf("expected no skipped ops, got %+v", res.Skipped)
	}
}

// TestUnsupportedVerbsReported checks that a verb the broker cannot enforce
// (HEAD/OPTIONS/TRACE) is reported as skipped rather than silently dropped or emitted
// as an allow route the grant validator would reject.
func TestUnsupportedVerbsReported(t *testing.T) {
	spec := `{"openapi":"3.1.0","info":{"title":"t"},"paths":{"/lights":{
		"get":{"operationId":"listLights"},
		"options":{"operationId":"preflightLights"}
	}}}`
	res, err := Generate([]byte(spec), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.AllowStrings() {
		if strings.HasPrefix(s, "OPTIONS ") {
			t.Errorf("emitted an OPTIONS allow route the grant validator rejects: %q", s)
		}
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Method != "OPTIONS" || res.Skipped[0].Path != "/lights" {
		t.Fatalf("OPTIONS op not reported as skipped: %+v", res.Skipped)
	}
	if strings.Contains(res.Preamble, "preflightLights") {
		t.Error("preamble includes the unenforceable OPTIONS operation")
	}
}

// TestPreambleIsSafe asserts the generated SDK cannot leak a credential or smuggle a
// route: it attaches to globalThis[global] (never a bare credential), interpolates path
// params raw so a hostile arg hits the client/broker gate (never encodeURIComponent,
// which would percent-encode and be rejected — but also never a template literal that
// hides a "/"), and references only the generic client verbs.
func TestPreambleIsSafe(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("testdata", "smart-home.openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Generate(spec, Options{Global: "home"})
	if err != nil {
		t.Fatal(err)
	}
	p := res.Preamble
	if !strings.Contains(p, `globalThis["home"]`) {
		t.Errorf("preamble does not attach to the named global:\n%s", p)
	}
	if strings.Contains(p, "encodeURIComponent") {
		t.Errorf("preamble percent-encodes params, which the client gate rejects:\n%s", p)
	}
	if strings.Contains(p, "Bearer") || strings.Contains(p, "token") || strings.Contains(p, "Authorization") {
		t.Errorf("preamble references a credential:\n%s", p)
	}
	// A path param builds the concrete path by string concatenation.
	if !strings.Contains(p, `h["getLight"] = (id) => h.get("/lights/" + id)`) {
		t.Errorf("preamble getLight is not the expected raw-interpolation form:\n%s", p)
	}
	// PATCH is enforceable, so its operation is a first-class method that sends a body.
	if !strings.Contains(p, `h["updateLight"] = (id, body) => h.patch("/lights/" + id, body)`) {
		t.Errorf("preamble updateLight is not the expected PATCH form:\n%s", p)
	}
	// A bodyless verb takes no body arg; a body verb does.
	if !strings.Contains(p, `h["listLights"] = () => h.get("/lights")`) {
		t.Errorf("preamble listLights signature wrong:\n%s", p)
	}
	if !strings.Contains(p, `h["createLight"] = (body) => h.post("/lights", body)`) {
		t.Errorf("preamble createLight signature wrong:\n%s", p)
	}
}

// TestGeneratedProfileLoads proves the whole pipeline is real, not illustrative: the
// generated allow list + preamble + health check assemble into a grants profile that
// grants.Load accepts, and the loaded grant carries exactly the derived routes, typed SDK,
// and recovery probe.
// This is what makes the docs/examples/specgen worked example trustworthy — a consumer
// really can generate the fields and delete the hand-written ones. It also proves the full
// derived surface (now including PATCH) is one grants.Load accepts.
func TestGeneratedProfileLoads(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("testdata", "smart-home.openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Generate(spec, Options{Global: "home"})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "preamble.js"), []byte(res.Preamble), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := map[string]any{
		"profiles": map[string]any{
			"smart-home": map[string]any{
				"base_url":        "https://home.internal",
				"allowed_callers": []string{"mcp-home"},
				"scopes":          []string{"home:control"},
				"token":           map[string]any{"type": "jwt", "secret_env": "SMART_HOME_JWT_SECRET", "audience": "home"},
				"allow":           res.AllowStrings(), // <- generated
				"preamble_file":   "preamble.js",      // <- generated
				"health_check":    res.HealthCheck,    // <- generated
			},
		},
	}
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	grantsPath := filepath.Join(dir, "grants.json")
	if err := os.WriteFile(grantsPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SMART_HOME_JWT_SECRET", strings.Repeat("k", 32)) // HS256 needs >= 32 bytes

	reg, err := grants.Load(grantsPath)
	if err != nil {
		t.Fatalf("generated profile failed to load: %v", err)
	}
	p, ok := reg.Get("smart-home")
	if !ok {
		t.Fatal("profile smart-home not registered")
	}
	grant := p.Grant()
	if len(grant.Allow) != len(res.Allow) {
		t.Errorf("loaded grant has %d routes, generated %d", len(grant.Allow), len(res.Allow))
	}
	if !strings.Contains(grant.Preamble, `globalThis["home"]`) {
		t.Errorf("loaded grant preamble is not the generated SDK:\n%s", grant.Preamble)
	}
	// The generated health_check line loads into a live backpressure probe route.
	if grant.HealthCheck == nil {
		t.Fatal("loaded grant has no health_check probe; generated " + res.HealthCheck)
	}
	if got := grant.HealthCheck.Method + " " + grant.HealthCheck.Path; got != res.HealthCheck {
		t.Errorf("loaded health_check = %q, generated %q", got, res.HealthCheck)
	}
}

// TestHealthRouteDetection covers deriving the backpressure health_check from the spec.
// Only an explicit x-plimsoll-health-check marker designates one: the endpoint-name
// heuristic was deleted on 2026-09-17 because a name is not evidence of what an endpoint
// measures, and the probe's answer is what lets the breaker resume traffic. Every
// health-sounding name below must therefore come back with no route and a note.
func TestHealthRouteDetection(t *testing.T) {
	op := func(id string) string { return `{"operationId":"` + id + `"}` }
	spec := func(paths string) string {
		return `{"openapi":"3.1.0","info":{"title":"t"},"paths":{` + paths + `}}`
	}
	cases := []struct {
		name       string
		spec       string
		wantHealth string
	}{
		{
			name: "a health-sounding name is not a probe",
			spec: spec(`"/lights":{"get":` + op("l") + `},"/status":{"get":` + op("s") + `}`),
		},
		{
			name: "neither is a conventional readiness path",
			spec: spec(`"/livez":{"get":` + op("a") + `},"/readyz":{"get":` + op("b") + `}`),
		},
		{
			name: "nor a nested healthz",
			spec: spec(`"/v1/healthz":{"get":` + op("h") + `}`),
		},
		{
			name: "no health-named route",
			spec: spec(`"/lights":{"get":` + op("l") + `}`),
		},
		{
			name:       "explicit marker on a non-standard name",
			spec:       spec(`"/probe":{"get":{"operationId":"p","x-plimsoll-health-check":true}}`),
			wantHealth: "GET /probe",
		},
		{
			name:       "explicit marker is what selects, not the neighbouring /capacity",
			spec:       spec(`"/capacity":{"get":` + op("c") + `},"/beat":{"get":{"operationId":"b","x-plimsoll-health-check":true}}`),
			wantHealth: "GET /beat",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Generate([]byte(tc.spec), Options{})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if res.HealthCheck != tc.wantHealth {
				t.Errorf("HealthCheck = %q, want %q", res.HealthCheck, tc.wantHealth)
			}
			// The absence of a probe is always explained, and a resolved one never is.
			if (res.HealthNote != "") != (tc.wantHealth == "") {
				t.Errorf("HealthNote = %q with HealthCheck = %q", res.HealthNote, res.HealthCheck)
			}
		})
	}
}

// TestHealthRouteMarkerErrors proves an explicit x-plimsoll-health-check that cannot be
// a probe fails closed at generation, rather than yielding a silently-dropped or invalid
// health route.
func TestHealthRouteMarkerErrors(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want string
	}{
		{
			"marker on a non-GET verb",
			`{"openapi":"3.1.0","info":{"title":"t"},"paths":{"/x":{"post":{"operationId":"x","x-plimsoll-health-check":true}}}}`,
			"must be GET",
		},
		{
			"marker on a parameterized path",
			`{"openapi":"3.1.0","info":{"title":"t"},"paths":{"/x/{id}":{"get":{"operationId":"x","x-plimsoll-health-check":true}}}}`,
			"concrete path",
		},
		{
			"two markers",
			`{"openapi":"3.1.0","info":{"title":"t"},"paths":{"/a":{"get":{"operationId":"a","x-plimsoll-health-check":true}},"/b":{"get":{"operationId":"b","x-plimsoll-health-check":true}}}}`,
			"mark exactly one",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Generate([]byte(tc.spec), Options{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestGenerateErrors(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want string
	}{
		{"bad json", `{`, "invalid JSON"},
		{"wrong version", `{"openapi":"2.0","paths":{"/x":{"get":{"operationId":"x"}}}}`, "unsupported openapi version"},
		{"no paths", `{"openapi":"3.1.0","paths":{}}`, "no paths"},
		{"missing operationId", `{"openapi":"3.1.0","paths":{"/x":{"get":{}}}}`, "no operationId"},
		{"partial-segment param", `{"openapi":"3.1.0","paths":{"/files/{name}.json":{"get":{"operationId":"g"}}}}`, "whole segment"},
		{"empty param", `{"openapi":"3.1.0","paths":{"/x/{}":{"get":{"operationId":"g"}}}}`, "empty {} parameter"},
		{"duplicate method name", `{"openapi":"3.1.0","paths":{"/a":{"get":{"operationId":"do-it"}},"/b":{"get":{"operationId":"do.it"}}}}`, "collides"},
		{"no supported ops", `{"openapi":"3.1.0","paths":{"/x":{"head":{"operationId":"h"}}}}`, "no supported operations"},
		// A method named after one of the injected client's own verbs would replace the
		// primitive its body calls, so the SDK would recurse into itself on first use.
		{"operationId shadows the client", `{"openapi":"3.1.0","paths":{"/x":{"get":{"operationId":"get"}}}}`, "injected client's own methods"},
		{"operationId shadows after sanitizing", `{"openapi":"3.1.0","paths":{"/x":{"delete":{"operationId":"del"}}}}`, "injected client's own methods"},
		// $ref is not resolved, and a path item that parses to nothing would otherwise
		// disappear from the generated surface without a word.
		{"path item $ref", `{"openapi":"3.1.0","paths":{"/x":{"$ref":"#/components/pathItems/X"}}}`, "specgen resolves no references"},
		{"parameter $ref", `{"openapi":"3.1.0","paths":{"/x":{"get":{"operationId":"g","parameters":[{"$ref":"#/components/parameters/Page"}]}}}}`, "specgen resolves no references"},
		{"unknown parameter location", `{"openapi":"3.1.0","paths":{"/x":{"get":{"operationId":"g","parameters":[{"name":"p","in":"body"}]}}}}`, "unsupported location"},
		// A marked probe that cannot actually be called is operator error, not a route to
		// emit and discover at the first 503.
		{"health marker on an uncallable op", `{"openapi":"3.1.0","paths":{"/probe":{"get":{"operationId":"p","x-plimsoll-health-check":true,"parameters":[{"name":"q","in":"query","required":true}]}}}}`, "x-plimsoll-health-check"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Generate([]byte(tc.spec), Options{})
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// hazardSpec is a spec built entirely from shapes that a real OpenAPI document is
// allowed to contain and that each broke the generated JavaScript before 2026-09-17:
// a POST that declares no requestBody, a path parameter named after the preamble's own
// client binding, one that is not a valid identifier, one that is a reserved word, and
// two that sanitize to the same name.
const hazardSpec = `{
  "openapi": "3.1.0",
  "info": {"title": "Hazards", "version": "1.0"},
  "paths": {
    "/events": {"post": {"operationId": "trigger", "summary": "Fire an event with no body."}},
    "/things/{h}": {"get": {"operationId": "getThingForH"}},
    "/items/{item-id}": {"get": {"operationId": "getItem"}},
    "/nodes/{default}": {"delete": {"operationId": "deleteNode"}},
    "/pairs/{a-b}/{a.b}": {"get": {"operationId": "getPair"}},
    "/docs/{id}": {"put": {"operationId": "putDoc", "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}}}
  }
}`

// fakeHostClient stands in for the injected generic client (sandbox/capability.go): the
// same six methods, returning what they were asked to send instead of sending it. The
// preamble binds to whatever is on the global, so a generated method that shadowed or
// overwrote one of these would be visible in the recorded output.
const fakeHostClient = `
globalThis.out = [];
globalThis.host = {
  call: (m, p, b) => ({ method: m, path: p, hasBody: b !== undefined }),
  get: (p) => ({ method: "GET", path: p, hasBody: false }),
  put: (p, b) => ({ method: "PUT", path: p, hasBody: b !== undefined }),
  post: (p, b) => ({ method: "POST", path: p, hasBody: b !== undefined }),
  patch: (p, b) => ({ method: "PATCH", path: p, hasBody: b !== undefined }),
  del: (p) => ({ method: "DELETE", path: p, hasBody: false }),
};
globalThis.record = function (id, fn) {
  var row = { id: id };
  try {
    var got = fn();
    row.method = got.method; row.path = got.path; row.hasBody = got.hasBody;
  } catch (e) {
    row.error = String(e);
  }
  out.push(row);
};
`

// TestGeneratedPreambleExecutes runs the generated SDK in the embedded QuickJS engine
// and calls every method it defines. This is the test that a string-matching assertion
// cannot replace: a preamble that does not parse, references an argument it never bound,
// or shadows the client it calls is textually plausible and fails here. Each hazard in
// hazardSpec produced exactly one of those before the generator was fixed.
func TestGeneratedPreambleExecutes(t *testing.T) {
	res, err := Generate([]byte(hazardSpec), Options{Global: "host"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.Operations) != 6 {
		t.Fatalf("generated %d operations, want 6", len(res.Operations))
	}

	var code strings.Builder
	code.WriteString(fakeHostClient)
	code.WriteString(res.Preamble)
	want := map[string]struct {
		method, path string
		hasBody      bool
	}{}
	for _, op := range res.Operations {
		// Call each method with a distinct dummy per path parameter, so a mis-ordered or
		// mis-bound argument lands in the wrong path segment rather than going unnoticed.
		args := make([]string, 0, len(op.Params)+1)
		path := op.Path
		for i, p := range op.Params {
			val := fmt.Sprintf("arg%d", i)
			args = append(args, strconv.Quote(val))
			// op.Params is deconflicted, so substitute positionally on the template.
			open := strings.IndexByte(path, '{')
			closeIdx := strings.IndexByte(path, '}')
			if open < 0 || closeIdx < open {
				t.Fatalf("%s %s: parameter %q has no template slot", op.Method, op.Path, p)
			}
			path = path[:open] + val + path[closeIdx+1:]
		}
		if op.HasBody {
			args = append(args, `{"k":1}`)
		}
		want[op.ID] = struct {
			method, path string
			hasBody      bool
		}{op.Method, path, op.HasBody}
		fmt.Fprintf(&code, "record(%q, () => host[%q](%s));\n", op.ID, op.ID, strings.Join(args, ", "))
	}
	code.WriteString("console.log(JSON.stringify(out));\n")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run, err := sandbox.DefaultWasm().RunJavaScript(ctx, sandbox.Request{Code: code.String(), Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("run generated preamble: %v", err)
	}
	if run.ExitCode != 0 {
		t.Fatalf("generated preamble exited %d\nstderr: %s\nstdout: %s", run.ExitCode, run.Stderr, run.Stdout)
	}

	var got []struct {
		ID      string `json:"id"`
		Method  string `json:"method"`
		Path    string `json:"path"`
		HasBody bool   `json:"hasBody"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(run.Stdout)), &got); err != nil {
		t.Fatalf("parse run output %q: %v", run.Stdout, err)
	}
	if len(got) != len(want) {
		t.Fatalf("called %d methods, generated %d", len(got), len(want))
	}
	for _, g := range got {
		w, ok := want[g.ID]
		if !ok {
			t.Errorf("unexpected method %q in output", g.ID)
			continue
		}
		if g.Error != "" {
			t.Errorf("%s threw: %s", g.ID, g.Error)
			continue
		}
		if g.Method != w.method || g.Path != w.path || g.HasBody != w.hasBody {
			t.Errorf("%s called %s %s (body %v), want %s %s (body %v)", g.ID, g.Method, g.Path, g.HasBody, w.method, w.path, w.hasBody)
		}
	}
}

// TestBodylessBodyVerbPassesNoBodyArgument pins the emitted form for a POST/PUT/PATCH
// with no requestBody: no body parameter and no body argument. Passing one anyway is a
// ReferenceError the first time an agent calls the method.
func TestBodylessBodyVerbPassesNoBodyArgument(t *testing.T) {
	res, err := Generate([]byte(hazardSpec), Options{Global: "host"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Preamble, `h["trigger"] = () => h.post("/events");`) {
		t.Errorf("bodyless POST is not emitted without a body argument:\n%s", res.Preamble)
	}
	if !strings.Contains(res.Description, "host.trigger()  ->  POST /events") {
		t.Errorf("description advertises a body argument the method does not take:\n%s", res.Description)
	}
}

// TestPathParamsAreDeconflicted proves the emitted argument names are derived from the
// spec but never trusted as identifiers: the client binding, invalid characters,
// reserved words, and two names that sanitize alike all come out as distinct, legal
// bindings that shadow nothing the method body needs.
func TestPathParamsAreDeconflicted(t *testing.T) {
	res, err := Generate([]byte(hazardSpec), Options{Global: "host"})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string][]string{}
	for _, op := range res.Operations {
		byID[op.ID] = op.Params
	}
	cases := map[string][]string{
		"getThingForH": {"h_"},          // "h" is the preamble's client binding
		"getItem":      {"item_id"},     // "-" is not an identifier character
		"deleteNode":   {"default_"},    // a reserved word cannot be a binding
		"getPair":      {"a_b", "a_b_"}, // both sanitize to a_b; the second is renamed
	}
	for id, want := range cases {
		got := byID[id]
		if len(got) != len(want) {
			t.Errorf("%s params = %v, want %v", id, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s params = %v, want %v", id, got, want)
				break
			}
		}
	}
}

// TestQueryParametersReported covers the two honest outcomes for a parameter a brokered
// call cannot send. A REQUIRED one makes the operation impossible, so it is skipped with
// a reason; an optional one narrows the generated method, so it is generated with a
// warning. Neither may pass silently: the emitted allow list would otherwise describe a
// surface the agent can never reach.
func TestQueryParametersReported(t *testing.T) {
	spec := `{"openapi":"3.1.0","info":{"title":"t"},"paths":{
	  "/search":{"get":{"operationId":"search","parameters":[{"name":"q","in":"query","required":true}]}},
	  "/feed":{"get":{"operationId":"feed","parameters":[{"name":"page","in":"query"}]}},
	  "/admin":{"get":{"operationId":"admin","parameters":[{"name":"X-Tenant","in":"header","required":true}]}}
	}}`
	res, err := Generate([]byte(spec), Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.Operations) != 1 || res.Operations[0].ID != "feed" {
		t.Fatalf("generated %+v, want only the optional-parameter operation", res.Operations)
	}
	for _, r := range res.AllowStrings() {
		if strings.Contains(r, "/search") || strings.Contains(r, "/admin") {
			t.Errorf("allow list grants %q for an operation that cannot be called", r)
		}
	}
	if len(res.Skipped) != 2 {
		t.Fatalf("skipped %+v, want the required query and header operations", res.Skipped)
	}
	for _, s := range res.Skipped {
		if !strings.Contains(s.Reason, "requires") {
			t.Errorf("skip reason for %s %s does not say what is missing: %q", s.Method, s.Path, s.Reason)
		}
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "/feed") {
		t.Errorf("warnings = %v, want one naming GET /feed", res.Warnings)
	}
}
