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
	"time"
)

// sdkUpstream is a stand-in for a vendor's API that records what each request carried,
// so a test can say what a standard client's request looked like after the broker.
type sdkUpstream struct {
	mu   sync.Mutex
	seen []http.Header
	path []string
}

func newSDKUpstream(t *testing.T) (*httptest.Server, *sdkUpstream) {
	t.Helper()
	u := &sdkUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.seen = append(u.seen, r.Header.Clone())
		u.path = append(u.path, r.URL.RequestURI())
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "chatcmpl-1", "echo": string(body), "object": "chat.completion"})
	}))
	t.Cleanup(srv.Close)
	return srv, u
}

// sdkStyleGrant is a profile shaped for a chat API behind a standard client: the
// loopback base URL and a dummy key in the guest's environment, the API's version header
// passed through, one route allowed.
func sdkStyleGrant(baseURL, token string) *HostAPIGrant {
	return &HostAPIGrant{
		BaseURL:     baseURL,
		Allow:       []HostRoute{{Method: "POST", Path: "/v1/chat/completions"}},
		Minter:      StaticToken(token),
		PassHeaders: []string{"anthropic-version"},
		SDKEnv:      map[string]string{"OPENAI_BASE_URL": "{origin}/v1", "OPENAI_API_KEY": "plimsoll-grant"},
	}
}

// pythonSDKClient is a Python program that sends exactly what the OpenAI and Anthropic
// client libraries send (their header set, the dummy key from the environment, the
// base URL from the environment), with nothing but the standard library: the shape of
// an SDK call, without the SDK, since the image carries none. It then tries a call the
// broker must refuse and prints what it got back.
const pythonSDKClient = `import json, os, sys, urllib.request, urllib.error
base = os.environ["OPENAI_BASE_URL"]
key = os.environ["OPENAI_API_KEY"]
headers = {
    "Authorization": "Bearer " + key,
    "x-api-key": key,
    "anthropic-version": "2026-10-21",
    "anthropic-beta": "not-listed",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "OpenAI/Python 2.0.0",
    "X-Stainless-Lang": "python",
    "X-Stainless-Package-Version": "2.0.0",
    "X-Stainless-OS": "Linux",
    "X-Stainless-Arch": "x64",
    "X-Stainless-Runtime": "CPython",
    "X-Stainless-Runtime-Version": sys.version.split()[0],
    "X-Stainless-Async": "false",
    "x-stainless-retry-count": "0",
    "x-stainless-read-timeout": "600",
}
body = json.dumps({"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]}).encode()
req = urllib.request.Request(base + "/chat/completions", data=body, headers=headers, method="POST")
with urllib.request.urlopen(req, timeout=20) as resp:
    answer = json.loads(resp.read())
print("ANSWER", answer["id"], answer["object"])
# A refused call: a query string is not a route. The broker answers itself and says so.
req = urllib.request.Request(base + "/chat/completions?stream=true", data=body, headers=headers, method="POST")
try:
    urllib.request.urlopen(req, timeout=20)
    print("REFUSAL missing")
except urllib.error.HTTPError as e:
    print("REFUSAL", e.code, e.headers.get("X-Should-Retry"))
`

// TestDockerProjectGrantServesAStandardClientAtLoopback: a Python step in the project
// image, using only the standard library, reaches the API through the base URL and key the
// profile put in its environment, as the OpenAI or Anthropic client library would; the API
// sees the broker's credential and the one passed header, none of the client's telemetry
// or its dummy key; a refused call comes back marked not to retry.
func TestDockerProjectGrantServesAStandardClientAtLoopback(t *testing.T) {
	t.Parallel()
	d := testDocker()
	d.ProjectImage = pythonProjectImage
	requireProjectImage(t, d)
	shippedSeccomp(t, d)
	upstream, seen := newSDKUpstream(t)
	const token = "minted-for-this-run"
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:   []File{{Path: "main.py", Content: pythonSDKClient}},
		Steps:   []string{"python3 main.py"},
		Grant:   sdkStyleGrant(upstream.URL, token),
		Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("outcome %v (%s): %+v", res.Outcome, res.Detail, res.Steps)
	}
	out := res.Steps[0].Stdout
	if !strings.Contains(out, "ANSWER chatcmpl-1 chat.completion") {
		t.Fatalf("stdout = %q, want the API's answer", out)
	}
	if !strings.Contains(out, "REFUSAL 403 false") {
		t.Fatalf("stdout = %q, want the refused call as 403 with X-Should-Retry false", out)
	}
	assertSDKRequestSeen(t, seen, token)
}

// nodeSDKClient is the snippet form: Node's fetch, the same header set, the same two calls.
const nodeSDKClient = `const base = process.env.OPENAI_BASE_URL, key = process.env.OPENAI_API_KEY;
const headers = { "authorization": "Bearer " + key, "x-api-key": key, "anthropic-version": "2026-10-21", "anthropic-beta": "not-listed",
  "accept": "application/json", "content-type": "application/json", "user-agent": "OpenAI/JS 6.0.0",
  "x-stainless-lang": "js", "x-stainless-package-version": "6.0.0", "x-stainless-os": "Linux", "x-stainless-arch": "x64",
  "x-stainless-runtime": "node", "x-stainless-runtime-version": process.version, "x-stainless-retry-count": "0", "x-stainless-timeout": "600" };
const body = JSON.stringify({ model: "gpt-x", messages: [{ role: "user", content: "hi" }] });
const r = await fetch(base + "/chat/completions", { method: "POST", headers, body });
const a = await r.json();
console.log("ANSWER", a.id, a.object);
const d = await fetch(base + "/chat/completions?stream=true", { method: "POST", headers, body });
console.log("REFUSAL", d.status, d.headers.get("x-should-retry"));
`

// TestDockerSnippetGrantServesAStandardClientAtLoopback is the snippet form of the test
// above: the forwarder runs inside the guest's own node process, so fetch reaches the
// broker through the loopback base URL the profile named.
func TestDockerSnippetGrantServesAStandardClientAtLoopback(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireDocker(t)
	shippedSeccomp(t, d)
	upstream, seen := newSDKUpstream(t)
	const token = "minted-for-this-run"
	res, err := d.RunJavaScript(context.Background(), Request{Code: nodeSDKClient, Grant: sdkStyleGrant(upstream.URL, token), Timeout: 60 * time.Second})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: stdout %q stderr %q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "ANSWER chatcmpl-1 chat.completion") || !strings.Contains(res.Stdout, "REFUSAL 403 false") {
		t.Fatalf("stdout = %q", res.Stdout)
	}
	assertSDKRequestSeen(t, seen, token)
}

// assertSDKRequestSeen checks the one request that reached the stand-in API: the broker's
// credential, the passed version header, and none of the client's own headers.
func assertSDKRequestSeen(t *testing.T, u *sdkUpstream, token string) {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.seen) != 1 || u.path[0] != "/v1/chat/completions" {
		t.Fatalf("upstream saw %d requests at %v, want one at /v1/chat/completions", len(u.seen), u.path)
	}
	h := u.seen[0]
	if got := h.Get("Authorization"); got != "Bearer "+token {
		t.Errorf("Authorization = %q, want the broker's credential", got)
	}
	if got := h.Get("anthropic-version"); got != "2026-10-21" {
		t.Errorf("anthropic-version = %q, want the client's, passed through", got)
	}
	for _, name := range []string{"X-Api-Key", "Anthropic-Beta", "X-Stainless-Lang", "X-Stainless-Package-Version", "X-Stainless-Runtime", "X-Stainless-Retry-Count", "X-Stainless-Read-Timeout", "X-Stainless-Timeout", "Cookie"} {
		if vals, present := h[http.CanonicalHeaderKey(name)]; present {
			t.Errorf("%s reached the API: %q", name, vals)
		}
	}
	if ua := h.Get("User-Agent"); strings.HasPrefix(ua, "OpenAI/") {
		t.Errorf("the client's User-Agent reached the API: %q", ua)
	}
}
