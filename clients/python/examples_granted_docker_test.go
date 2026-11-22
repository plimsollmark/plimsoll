package python

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/internal/specgen"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The granted examples: each code tool built with a grant the application chose (the
// five Python kits' *_grant.py, the TypeScript executeCode core's examples/granted.ts,
// the MCP server's mcp_grant.py), run as a newcomer would run them against a daemon on
// the docker provider serving one profile, "lights", behind a token, and a stand-in for
// the lights API on this host that answers only the credential the daemon holds. Nothing
// calls a model service or a real API, and nothing is paid for.
//
// What each must show: the model was told of the API (the description specgen wrote for
// the profile); an allowed route answered, in JavaScript and in Python; a route the
// profile does not list was refused inside the run; the route's call budget answered 429.
// And the credential canary: the planted key is in no program's output (the tool's
// answers, the labels a kit hands the application, its log lines), in no line of the
// daemon's log, and never in any process's environment; the daemon's log holds call
// counts, not the paths, arguments or answers of the calls.

const (
	grantedKeyEnv   = "PLIMSOLL_EXAMPLES_LIGHTS_KEY"
	grantedCanary   = "CANARY-lights-key-5d81e"
	grantedToken    = "examples-granted-token"
	grantedCaller   = "examples"
	grantedLightsV1 = `{"openapi":"3.1.0","info":{"title":"Lights","version":"1"},"servers":[{"url":"https://lights.example"}],"paths":{
"/v1/lights/{id}":{"get":{"operationId":"getLight","summary":"One light.","parameters":[{"name":"id","in":"path","required":true}]}},
"/v1/lights/{id}/on":{"post":{"operationId":"lightOn","summary":"Turn a light on.","parameters":[{"name":"id","in":"path","required":true}],"requestBody":{"content":{"application/json":{}}}}},
"/v1/doors/{id}":{"get":{"operationId":"getDoor","parameters":[{"name":"id","in":"path","required":true}]}}}}`
)

type grantedVerifier struct{}

func (grantedVerifier) VerifyToken(_ context.Context, token string) (rpc.Principal, bool, error) {
	if token != grantedToken {
		return rpc.Principal{}, false, nil
	}
	return rpc.Principal{UserID: grantedCaller, Scopes: []string{rpc.ScopeCodeRun}}, true, nil
}

// lockedLog is the daemon's log, written by its handlers concurrently.
type lockedLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// lightsStub is the stand-in for the lights API: it answers only the daemon's credential.
type lightsStub struct {
	mu    sync.Mutex
	calls []string
	auth  []string
}

func (s *lightsStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.calls = append(s.calls, r.Method+" "+r.URL.Path)
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	s.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+grantedCanary {
		http.Error(w, `{"error":"no key"}`, http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "GET" && len(parts) == 3 && parts[1] == "lights":
		_ = json.NewEncoder(w).Encode(map[string]any{"id": parts[2], "on": false})
	case r.Method == "POST" && len(parts) == 4 && parts[1] == "lights" && parts[3] == "on":
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": parts[2], "on": true, "level": in["level"]})
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func runGrantedExamples(t *testing.T, d *sandbox.DockerSandbox, floor string) {
	stub := &lightsStub{}
	api := httptest.NewServer(stub)
	t.Cleanup(api.Close)

	// The application's description, as an operator would make it: specgen over the
	// API's document, narrowed to the routes the profile grants.
	only := []sandbox.HostRoute{{Method: "GET", Path: "/v1/lights/*"}, {Method: "POST", Path: "/v1/lights/*/on"}}
	gen, err := specgen.Generate([]byte(grantedLightsV1), specgen.Options{Only: only})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	description := filepath.Join(dir, "description.txt")
	if err := os.WriteFile(description, []byte(gen.Description), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, _ := json.Marshal(map[string]any{"profiles": map[string]any{"lights": map[string]any{
		"base_url": api.URL, "allow": gen.AllowStrings(), "route_max_calls": map[string]int{"POST /v1/lights/*/on": 1},
		"allowed_callers": []string{grantedCaller}, "token": map[string]string{"type": "static", "env": grantedKeyEnv},
	}}})
	grantsFile := filepath.Join(dir, "grants.json")
	if err := os.WriteFile(grantsFile, profile, 0o600); err != nil {
		t.Fatal(err)
	}
	// The key reaches the daemon's registry only: the programs' environment is built
	// without it (environ), and the test fails if any output holds it.
	if err := os.Setenv(grantedKeyEnv, grantedCanary); err != nil {
		t.Fatal(err)
	}
	reg, err := grants.Load(grantsFile)
	_ = os.Unsetenv(grantedKeyEnv)
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedLog{}
	svc := rpc.NewSandboxService(d)
	svc.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc.Grants = reg
	svc.Sessions = rpc.SessionConfig{MaxSessions: 2, Lifetime: 10 * time.Minute, IdleTimeout: 5 * time.Minute}
	url := clientsuite.Serve(t, svc, grantedVerifier{}, nil)

	mcpBin := filepath.Join(dir, "plimsoll-mcp")
	if out, err := exec.Command("go", "build", "-C", filepath.Join("..", "mcp"), "-o", mcpBin, "./cmd/plimsoll-mcp").CombinedOutput(); err != nil {
		t.Fatalf("building plimsoll-mcp: %v\n%s", err, out)
	}
	python := func(env string) string {
		p, _ := filepath.Abs(filepath.Join("..", "..", "tmp", "py-frameworks", env, "bin", "python"))
		return p
	}
	// Every program prints what its tool gave; these hold in every one.
	js := []string{"the model is told of: Lights (v1).", `kitchen`, "second POST 429"}
	examples := []struct {
		name string
		argv []string
		dir  string
		want []string
	}{
		{"crewai_grant", []string{python("crewai"), "-B", "examples/crewai_grant.py"}, "", append(js, "doors refused", "'id': 'hall'", "doors refused 403")},
		{"agno_grant", []string{python("agno"), "-B", "examples/agno_grant.py"}, "", append(js, "doors refused", "'id': 'hall'", "doors refused 403")},
		{"langchain_grant", []string{python("deepagents"), "-B", "examples/langchain_grant.py"}, "", append(js, "doors refused", "'id': 'hall'", "doors refused 403")},
		{"agent_framework_grant", []string{python("agent_framework"), "-B", "examples/agent_framework_grant.py"}, "",
			append(js, "doors refused", "'id': 'hall'", "doors refused 403", "labels {'plimsoll_dispatched': 'yes'")},
		{"pydantic_ai_grant", []string{python("pydantic_ai"), "-B", "examples/pydantic_ai_grant.py"}, "",
			append(js, "doors refused", "'id': 'hall'", "doors refused 403", "labels {'plimsoll_dispatched': 'yes'")},
		{"mcp_grant", []string{python("openai_agents"), "-B", "examples/mcp_grant.py"}, "",
			append(js, "doors refused", "'id': 'hall'", "in a kept sandbox -> 'undefined'", `run_code carries grant profile "lights"`)},
		{"typescript_granted", []string{"node", "examples/granted.ts"}, filepath.Join("..", "typescript"),
			[]string{"languages that can call the API here: javascript, python", "second POST 429", "was: { id: 'kitchen', on: false }", "{'id': 'hall', 'on': False}"}},
	}
	for _, argv := range [][]string{{python("crewai")}, {"node"}} {
		if _, err := exec.LookPath(argv[0]); err != nil {
			t.Fatalf("%s: %v", argv[0], err)
		}
	}
	outputs := map[string]string{}
	var mu sync.Mutex
	t.Run("examples", func(t *testing.T) {
		for _, ex := range examples {
			t.Run(ex.name, func(t *testing.T) {
				t.Parallel()
				cmd := exec.Command(ex.argv[0], ex.argv[1:]...)
				cmd.Dir = ex.dir
				cmd.Env = append(environ(grantedKeyEnv),
					"PLIMSOLL_URL="+url, "PLIMSOLL_TOKEN="+grantedToken, "PLIMSOLL_MIN_ISOLATION="+floor,
					"PLIMSOLL_GRANT_PROFILE=lights", "PLIMSOLL_GRANT_DESCRIPTION_FILE="+description, "PLIMSOLL_MCP="+mcpBin,
					"PYTHONPATH="+strings.Join([]string{"src", filepath.Join("crewai-plimsoll", "src")}, string(os.PathListSeparator)),
					"PYTHONDONTWRITEBYTECODE=1", "HOME="+t.TempDir(),
					"CREWAI_DISABLE_TELEMETRY=true", "OTEL_SDK_DISABLED=true", "CREWAI_TRACING_ENABLED=false",
				)
				out, err := cmd.CombinedOutput()
				t.Logf("%s", out)
				mu.Lock()
				outputs[ex.name] = string(out)
				mu.Unlock()
				if err != nil {
					t.Fatalf("%v: %v", ex.argv, err)
				}
				for _, w := range ex.want {
					if !strings.Contains(string(out), w) {
						t.Errorf("%s printed no %q", ex.name, w)
					}
				}
			})
		}
	})

	// The credential canary and the telemetry, once every program has ended.
	for name, out := range outputs {
		if strings.Contains(out, grantedCanary) {
			t.Errorf("%s: the planted key is in the program's output", name)
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "labels") && (strings.Contains(line, "kitchen") || strings.Contains(line, "/v1/") || strings.Contains(line, "hall")) {
				t.Errorf("%s: a label holds a path or an answer: %s", name, line)
			}
		}
	}
	daemon := logs.String()
	if strings.Contains(daemon, grantedCanary) {
		t.Error("the planted key is in the daemon's log")
	}
	for _, leak := range []string{"kitchen", "/v1/lights/hall"} {
		if strings.Contains(daemon, leak) {
			t.Errorf("the daemon's log holds %q, a call's path or argument", leak)
		}
	}
	if !strings.Contains(daemon, "host_calls=") {
		t.Error("the daemon's log counts no host calls: the granted runs reached no broker")
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	for i, a := range stub.auth {
		if a != "Bearer "+grantedCanary {
			t.Errorf("call %s reached the API with Authorization %q, not the daemon's key", stub.calls[i], a)
		}
	}
	for _, c := range stub.calls {
		if strings.Contains(c, "/doors/") {
			t.Errorf("a route the profile does not list reached the API: %s", c)
		}
	}
}

// environ is this process's environment without the variables named.
func environ(drop ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		keep := true
		for _, d := range drop {
			keep = keep && name != d
		}
		if keep {
			out = append(out, kv)
		}
	}
	return out
}
