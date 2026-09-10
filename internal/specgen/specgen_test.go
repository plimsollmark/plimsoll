package specgen

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/grants"
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

	// The spec's /status endpoint is auto-detected as the backpressure health route by
	// the well-known-name heuristic (no x-plimsoll-health-check marker needed).
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

// TestHealthRouteDetection covers deriving the backpressure health_check from the spec:
// the well-known-name heuristic (including recovery-priority ranking and tie ambiguity)
// and the explicit x-plimsoll-health-check override.
func TestHealthRouteDetection(t *testing.T) {
	op := func(id string) string { return `{"operationId":"` + id + `"}` }
	spec := func(paths string) string {
		return `{"openapi":"3.1.0","info":{"title":"t"},"paths":{` + paths + `}}`
	}
	cases := []struct {
		name       string
		spec       string
		wantHealth string
		wantNote   bool // expect a non-empty HealthNote (ambiguous)
	}{
		{
			name:       "single well-known name",
			spec:       spec(`"/lights":{"get":` + op("l") + `},"/status":{"get":` + op("s") + `}`),
			wantHealth: "GET /status",
		},
		{
			name:       "nested path uses last segment",
			spec:       spec(`"/v1/healthz":{"get":` + op("h") + `}`),
			wantHealth: "GET /v1/healthz",
		},
		{
			name:       "readiness outranks liveness for recovery",
			spec:       spec(`"/livez":{"get":` + op("a") + `},"/readyz":{"get":` + op("b") + `}`),
			wantHealth: "GET /readyz",
		},
		{
			name:       "capacity outranks health",
			spec:       spec(`"/health":{"get":` + op("a") + `},"/capacity":{"get":` + op("b") + `}`),
			wantHealth: "GET /capacity",
		},
		{
			name:       "status is a capacity signal and outranks health",
			spec:       spec(`"/healthz":{"get":` + op("a") + `},"/status":{"get":` + op("b") + `}`),
			wantHealth: "GET /status",
		},
		{
			name:       "same-rank tie is ambiguous, none picked",
			spec:       spec(`"/ready":{"get":` + op("a") + `},"/readyz":{"get":` + op("b") + `}`),
			wantHealth: "",
			wantNote:   true,
		},
		{
			name:       "a path param disqualifies a health-named route",
			spec:       spec(`"/status/{id}":{"get":{"operationId":"s","parameters":[{"name":"id","in":"path"}]}}`),
			wantHealth: "",
		},
		{
			name:       "no health-named route",
			spec:       spec(`"/lights":{"get":` + op("l") + `}`),
			wantHealth: "",
		},
		{
			name:       "explicit marker on a non-standard name",
			spec:       spec(`"/probe":{"get":{"operationId":"p","x-plimsoll-health-check":true}}`),
			wantHealth: "GET /probe",
		},
		{
			name:       "explicit marker overrides a higher-ranked heuristic match",
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
			if (res.HealthNote != "") != tc.wantNote {
				t.Errorf("HealthNote = %q, wantNote = %v", res.HealthNote, tc.wantNote)
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
