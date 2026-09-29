package openshell

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// liveSecret is the credential the live grant tests' upstream expects. The guest
// must never be able to read it.
const liveSecret = "plimsoll-live-grant-secret-7d1f"

// liveUpstream is a host API on this machine: it answers GET /items/<id> with the id
// and whether the request carried the grant's credential, and counts its calls.
func liveUpstream(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"path": r.URL.Path, "authorized": r.Header.Get("Authorization") == "Bearer "+liveSecret})
	}))
	t.Cleanup(up.Close)
	return up, &calls
}

func liveGrant(base string) *sandbox.HostAPIGrant {
	return &sandbox.HostAPIGrant{
		BaseURL: base,
		Allow:   []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}},
		Minter:  sandbox.StaticToken(liveSecret),
	}
}

// TestOpenShellGrantLive: a granted snippet reaches the host API through the relay and
// the broker, with the credential added host-side; a route the grant omits is refused
// by the broker even when the guest bypasses the injected client; eight concurrent
// calls succeed (more than one gateway session token's three connections); and the
// credential appears nowhere the guest can read.
func TestOpenShellGrantLive(t *testing.T) {
	p := liveProvider(t, nil)
	up, calls := liveUpstream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	run := func(code string) sandbox.Result {
		t.Helper()
		start := time.Now()
		res, err := p.RunJavaScript(ctx, sandbox.Request{Code: code, Grant: liveGrant(up.URL), Timeout: 25 * time.Second})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		t.Logf("run took %v: exit %d, stdout %q, stderr %q", time.Since(start).Round(time.Millisecond), res.ExitCode, res.Stdout, res.Stderr)
		return res
	}

	res := run(`(async () => { console.log(JSON.stringify(await host.get("/items/42"))); })()`)
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, `"path":"/items/42"`) || !strings.Contains(res.Stdout, `"authorized":true`) {
		t.Fatalf("a granted call: %+v", res)
	}
	if res.CallTrace == nil || len(res.CallTrace.Calls) != 1 || res.CallTrace.Calls[0].Status != 200 {
		t.Fatalf("trace: %+v", res.CallTrace)
	}

	// The guest skips the injected client and asks the socket for a route the grant
	// does not list: the broker refuses it, and nothing reaches the upstream.
	before := calls.Load()
	res = run(`const http = require("http");
http.request({ socketPath: process.env.HOST_API_SOCKET, path: "/admin/keys", method: "GET" }, (r) => {
  let b = ""; r.on("data", (c) => (b += c)); r.on("end", () => console.log("status " + r.statusCode + " " + b.trim()));
}).end();`)
	if !strings.Contains(res.Stdout, "status 403") || calls.Load() != before {
		t.Fatalf("an ungranted route: %+v (upstream calls %d -> %d)", res, before, calls.Load())
	}

	res = run(`(async () => {
  const got = await Promise.all([1,2,3,4,5,6,7,8].map((i) => host.get("/items/" + i)));
  console.log(got.filter((r) => r.authorized).length + " of " + got.length);
})()`)
	if strings.TrimSpace(res.Stdout) != "8 of 8" {
		t.Fatalf("eight concurrent calls: %+v", res)
	}

	res = run(`const fs = require("fs"); const hits = [];
const look = (where, text) => { if (text.includes(` + "`" + liveSecret + "`" + `)) hits.push(where); };
look("env", JSON.stringify(process.env));
for (const d of fs.readdirSync("/proc")) {
  if (!/^[0-9]+$/.test(d)) continue;
  for (const f of ["environ", "cmdline"]) { try { look("/proc/" + d + "/" + f, fs.readFileSync("/proc/" + d + "/" + f, "latin1")); } catch {} }
}
const walk = (dir) => { for (const n of fs.readdirSync(dir)) { const p = dir + "/" + n; let st; try { st = fs.lstatSync(p); } catch { continue; }
  if (st.isDirectory()) walk(p); else if (st.isFile() && st.size < 1 << 20) { try { look(p, fs.readFileSync(p, "latin1")); } catch {} } } };
walk("/tmp");
console.log(hits.length ? "found in " + hits.join(", ") : "not found");`)
	if strings.TrimSpace(res.Stdout) != "not found" {
		t.Fatalf("the credential is readable in the sandbox: %+v", res)
	}
}

// TestOpenShellGrantProjectLive: a project step reaches the host API through the same
// relay, with the client preloaded into the step's node process.
func TestOpenShellGrantProjectLive(t *testing.T) {
	p := liveProvider(t, nil)
	up, _ := liveUpstream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := p.RunProject(ctx, sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "main.js", Content: `host.get("/items/7").then((r) => console.log(JSON.stringify(r)));`}},
		Steps: []string{"node main.js"},
		Grant: liveGrant(up.URL),
	})
	if err != nil || res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 {
		t.Fatalf("project: %+v, %v", res, err)
	}
	if !strings.Contains(res.Steps[0].Stdout, `"path":"/items/7"`) || !strings.Contains(res.Steps[0].Stdout, `"authorized":true`) {
		t.Fatalf("the step's call: %+v", res.Steps[0])
	}
	if res.CallTrace == nil || len(res.CallTrace.Calls) != 1 {
		t.Fatalf("trace: %+v", res.CallTrace)
	}
}

// TestOpenShellGrantSessionLive: a session call with a grant reaches the API, and its
// relay is gone before the next call (the sweep ends it like any leftover process).
func TestOpenShellGrantSessionLive(t *testing.T) {
	p := liveProvider(t, nil)
	up, _ := liveUpstream(t)
	s := openLive(t, p, sandbox.SessionOptions{Lifetime: 2 * time.Minute})
	res, err := s.RunJavaScript(context.Background(), sandbox.Request{
		Code:  `(async () => { console.log(JSON.stringify(await host.get("/items/9"))); })()`,
		Grant: liveGrant(up.URL),
	})
	if err != nil || !strings.Contains(res.Stdout, `"authorized":true`) {
		t.Fatalf("a granted session call: %+v, %v", res, err)
	}
	if got := js(t, s, `const fs=require("fs");let n=0;for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d))continue;
let c="";try{c=fs.readFileSync("/proc/"+d+"/cmdline","latin1")}catch{continue}if(c.includes("createServer"))n++}console.log(n)`); got != "0" {
		t.Fatalf("the relay outlived its call: %s processes", got)
	}
}
