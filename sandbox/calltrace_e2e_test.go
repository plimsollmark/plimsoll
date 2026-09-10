package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestDockerRunPopulatesCallTrace closes the Phase-0 e2e gap: the traceSnapshot()
// seam was previously only unit-covered (calltrace_test.go drives the broker over a
// bare socket, no container). This drives a REAL container whose granted JS makes
// several brokered host.* calls and asserts the run's Result carries the bounded,
// metadata-only CallTrace: the matched route TEMPLATES (never the raw ids), the count
// per template, a broker-side denial counted with no row, and neither the injected
// credential nor a raw path anywhere in the serialized trace.
func TestDockerRunPopulatesCallTrace(t *testing.T) {
	requireSnippetImage(t, testDocker())

	var mu sync.Mutex
	var gotPaths, gotAuth []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPaths = append(gotPaths, r.URL.Path)
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	const token = "s3cr3t-e2e-bearer"
	grant := &HostAPIGrant{
		BaseURL: upstream.URL,
		Allow: []HostRoute{
			{Method: "GET", Path: "/items/*"},
			{Method: "GET", Path: "/items"},
		},
		Minter: StaticToken(token),
	}

	// Three per-item reads (fan-out shape) + one collection read go through the
	// injected host client. The fifth call bypasses that client and dials the mounted
	// socket directly at a forbidden route, so the AUTHORITATIVE host-side broker (not
	// just the cooperative client gate) must deny and count it. An async IIFE keeps
	// this valid whether node treats stdin as a module or a script.
	code := `(async () => {
  for (const p of ["/items/1", "/items/2", "/items/3", "/items"]) {
    await host.get(p);
  }
  const http = (await import("node:http")).default;
  const denied = await new Promise((resolve) => {
    const req = http.request({ socketPath: process.env.HOST_API_SOCKET, path: "/secret/keys", method: "GET" }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", () => resolve(0));
    req.end();
  });
  console.log("denied-status", denied);
})().catch((e) => { console.error("guest error", e && e.message); process.exit(1); });`

	res, err := testDocker().RunJavaScript(context.Background(), Request{Code: code, Grant: grant})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0 (stdout %q, stderr %q)", res.ExitCode, res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "denied-status 403") {
		t.Errorf("stdout = %q, want the guest to have seen the broker's 403 on the forbidden route", res.Stdout)
	}

	// The run really reached upstream with the broker-injected token, and the forbidden
	// route never got there.
	mu.Lock()
	paths, auths := append([]string(nil), gotPaths...), append([]string(nil), gotAuth...)
	mu.Unlock()
	for _, want := range []string{"/items/1", "/items/2", "/items/3", "/items"} {
		if !contains(paths, want) {
			t.Errorf("upstream did not receive %q; saw %v", want, paths)
		}
	}
	if contains(paths, "/secret/keys") {
		t.Errorf("forbidden route reached upstream: %v", paths)
	}
	for _, a := range auths {
		if a != "Bearer "+token {
			t.Errorf("upstream Authorization = %q, want the broker-injected bearer", a)
		}
	}

	// The trace is populated end to end, with TEMPLATES not raw ids.
	tr := res.CallTrace
	if tr == nil {
		t.Fatal("res.CallTrace is nil; the container's brokered calls did not reach the run result")
	}
	if len(tr.Calls) != 4 {
		t.Fatalf("recorded %d calls, want 4 (stderr %q): %+v", len(tr.Calls), res.Stderr, tr.Calls)
	}
	if tr.Denied != 1 {
		t.Errorf("Denied = %d, want 1 (the forbidden direct-socket call)", tr.Denied)
	}
	byRoute := map[string]int{}
	for _, c := range tr.Calls {
		if c.Method != "GET" || c.Status != 200 {
			t.Errorf("row = %+v, want GET/200", c)
		}
		byRoute[c.Route]++
	}
	if byRoute["/items/*"] != 3 || byRoute["/items"] != 1 {
		t.Errorf("route counts = %v, want /items/* x3 and /items x1", byRoute)
	}

	// The whole serialized trace must carry no raw per-item path, no forbidden path,
	// and no credential.
	js, err := json.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal trace: %v", err)
	}
	for _, leak := range []string{"/items/1", "/items/2", "/items/3", "/secret", "keys", token} {
		if strings.Contains(string(js), leak) {
			t.Errorf("trace leaked %q: %s", leak, js)
		}
	}
}

// TestDockerProjectGrantPreloadsHostClient is the Sluice Phase 2 e2e: a REAL project
// container run carrying a grant must reach the host API from an ordinary project step
// through the preloaded host.* global (node --import), over the same brokered socket the
// snippet path uses — proving project files get the identical global contract without an
// import, the credential stays host-side, and the run's ProjectResult carries the
// metadata-only CallTrace.
func TestDockerProjectGrantPreloadsHostClient(t *testing.T) {
	d := testDocker()
	requireProjectImage(t, d)

	var mu sync.Mutex
	var gotPaths, gotAuth []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPaths = append(gotPaths, r.URL.Path)
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	const token = "s3cr3t-project-bearer"
	grant := &HostAPIGrant{
		BaseURL: upstream.URL,
		Allow: []HostRoute{
			{Method: "GET", Path: "/items/*"},
			{Method: "POST", Path: "/items"},
		},
		Minter: StaticToken(token),
	}

	// A .mjs step uses the `host` global directly (no import), then a .ts step run via
	// tsx does too — proving the --import preload reaches both plain node and the tsx
	// loader child. Each writes a marker so we can assert the global resolved.
	reader := `const a = await host.get("/items/42");
const b = await host.post("/items", { name: "x" });
console.log("READER-OK", JSON.stringify(a), JSON.stringify(b));`
	tsReader := `(async () => {
  const r: any = await (globalThis as any).host.get("/items/7");
  console.log("TS-OK", JSON.stringify(r));
})().catch((e) => { console.error(e && e.message); process.exit(1); });`

	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{
			{Path: "reader.mjs", Content: reader},
			{Path: "reader.ts", Content: tsReader},
		},
		Steps: []string{"node reader.mjs", "tsx reader.ts"},
		Grant: grant,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("outcome = %v (detail %q, steps %+v), want completed", res.Outcome, res.Detail, res.Steps)
	}
	if len(res.Steps) != 2 {
		t.Fatalf("ran %d steps, want 2: %+v", len(res.Steps), res.Steps)
	}
	for i, want := range []string{"READER-OK", "TS-OK"} {
		s := res.Steps[i]
		if s.ExitCode != 0 {
			t.Fatalf("step %d exit = %d, want 0 (stdout %q, stderr %q)", i, s.ExitCode, s.Stdout, s.Stderr)
		}
		if !strings.Contains(s.Stdout, want) {
			t.Errorf("step %d stdout = %q, want %q (the preloaded host global resolved)", i, s.Stdout, want)
		}
	}

	// The steps really reached upstream with the broker-injected bearer, from inside a
	// project container that never held the token.
	mu.Lock()
	paths, auths := append([]string(nil), gotPaths...), append([]string(nil), gotAuth...)
	mu.Unlock()
	for _, want := range []string{"/items/42", "/items", "/items/7"} {
		if !contains(paths, want) {
			t.Errorf("upstream did not receive %q; saw %v", want, paths)
		}
	}
	for _, a := range auths {
		if a != "Bearer "+token {
			t.Errorf("upstream Authorization = %q, want the broker-injected bearer", a)
		}
	}

	// The project result carries the metadata-only trace with route TEMPLATES, and it
	// leaks neither the raw per-item id nor the credential.
	tr := res.CallTrace
	if tr == nil {
		t.Fatal("res.CallTrace is nil; the project's brokered calls did not reach the result")
	}
	byRoute := map[string]int{}
	for _, c := range tr.Calls {
		byRoute[c.Route]++
	}
	if byRoute["/items/*"] != 2 || byRoute["/items"] != 1 {
		t.Errorf("route counts = %v, want /items/* x2 and /items x1", byRoute)
	}
	js, err := json.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal trace: %v", err)
	}
	for _, leak := range []string{"/items/42", "/items/7", token} {
		if strings.Contains(string(js), leak) {
			t.Errorf("trace leaked %q: %s", leak, js)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
