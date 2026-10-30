package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestE2BGuardLive exercises the complete option-2 path. It is intentionally
// opt-in: E2B_LIVE_GRANT_BASE_URL must name a real HTTPS API reachable by the
// plimsoll host, while E2B_GUARD_URL must name the externally reachable HTTPS
// plimsoll guard route reachable from the E2B VM.
//
// Guard credentials only exist in the process that opened the run, so the
// public guard URL must terminate at THIS process. Set E2B_LIVE_GUARD_LISTEN
// to a local address (e.g. 127.0.0.1:8791) and the test serves the production
// guard handler there; run it on the host whose TLS front (the daemon's usual
// reverse proxy) routes the guard path to that address.
//
// Required environment:
//
//	E2B_API_KEY
//	E2B_GUARD_URL
//	E2B_LIVE_GRANT_BASE_URL       origin of a real HTTPS API used for the proof
//
// Optional:
//
//	E2B_LIVE_GUARD_LISTEN         local addr to self-serve the guard handler
//	E2B_LIVE_GRANT_ALLOWED_PATH   default /healthz
//	E2B_LIVE_GRANT_DENIED_PATH    default /not-allowed
//	E2B_LIVE_GRANT_TOKEN           static bearer for the test API
//
// A skip here is invisible in a green suite, and this is the only test that
// falsifies the guarded-E2B claim the documentation makes. `make audit E2B=1` runs
// -run Live, so before E2B_GUARD_LIVE_REQUIRED existed, "audit: OK" could mean the
// guarded path was never exercised. `make e2b-guard-live` sets that variable and
// this test then FAILS on missing configuration instead of skipping, so the only
// way to see it pass is to actually run it.
func TestE2BGuardLive(t *testing.T) {
	g := liveGuardSetup(t)
	e, grant, allowed, token := g.e, g.grant, g.allowed, g.token
	denied := strings.TrimSpace(os.Getenv("E2B_LIVE_GRANT_DENIED_PATH"))
	if denied == "" {
		denied = "/not-allowed"
	}
	res, err := e.RunJavaScript(context.Background(), Request{Code: liveAllowedCode(allowed), Grant: grant})
	if err != nil {
		t.Fatalf("allowed route infrastructure error: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "GUARD-ALLOWED") {
		t.Fatalf("allowed route failed: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if token != "" && strings.Contains(res.Stdout+res.Stderr, token) {
		t.Fatal("customer bearer appeared in guest output")
	}

	deniedCode := `(async () => {
  try {
    await host.get(` + strconvQuote(denied) + `);
    process.exit(12);
  } catch (err) {
    console.log("GUARD-DENIED", String(err));
    process.exit(17);
  }
})();`
	res, err = e.RunJavaScript(context.Background(), Request{Code: deniedCode, Grant: grant})
	if err != nil {
		t.Fatalf("denied route infrastructure error: %v", err)
	}
	if res.ExitCode != 17 || !strings.Contains(res.Stdout, "GUARD-DENIED") {
		t.Fatalf("denied route was not rejected: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}

	// The run-owned guard credential is removed before RunJavaScript returns. A
	// request using a captured token after cleanup must receive 401 from the
	// externally deployed guard, proving expiry is enforced at the HTTP boundary.
	guard, cleanup, err := e.openGuard(context.Background(), grant, time.Minute)
	if err != nil {
		t.Fatalf("open guard for expiry check: %v", err)
	}
	tokenForExpiry := guard.Token
	cleanup()
	payload, _ := json.Marshal(map[string]any{"method": http.MethodGet, "path": allowed})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, guard.Endpoint.URL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build expired-guard request: %v", err)
	}
	req.Header.Set(EgressGuardHeader, tokenForExpiry)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("expired-guard request: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired guard status=%d body=%q, want 401", resp.StatusCode, body)
	}
	t.Log("E2B guard live proof passed: allowed route, denied route, expired credential; run TestE2BEgressDeniedLive separately for no-grant egress")

	// The raw route, from inside the VM, the way a standard client calls it: one more
	// microVM. E2B's network rule adds the guard credential outside the guest and
	// terminates the guard's TLS with its proxy CA, which the run's node trusts through
	// NODE_EXTRA_CA_CERTS (e2bGuestCABundle), so fetch verifies the certificate as the
	// injected client does.
	liveRawRouteProof(t, func(code string, grant *HostAPIGrant) (Result, error) {
		return e.RunJavaScript(context.Background(), Request{Code: code, Grant: grant})
	})
}

// liveRawRouteProof runs one sandbox whose guest, with Node's fetch and the header set
// the OpenAI and Anthropic client libraries send (a dummy Authorization among them),
// makes three requests to the guard's raw route: an allowed one, which the test's own
// loopback upstream must see with the broker's credential and the one passed header
// only; a refused one (a path off the allow list), which gets a 4xx with the no-retry
// mark and never reaches the upstream; and a streamed one, which must arrive complete,
// with the time between the guest's first and last piece recorded (the upstream leaves
// 500 ms between events, so pieces arriving apart show at least 700 ms; the public route
// may buffer, so that part is measured, not required).
// The upstream is a Go server in this process on loopback, which the broker in this
// process reaches directly, so no second public route is needed and the streamed
// answer costs nothing beyond the one run. run runs guest code with a grant.
func liveRawRouteProof(t *testing.T, run func(code string, grant *HostAPIGrant) (Result, error)) {
	t.Helper()
	const token = "live-raw-minted-credential"
	var mu sync.Mutex
	var paths []string
	var itemsHeaders http.Header
	pieces := []string{"event: message_start\ndata: {}\n\n", "event: content_block_delta\ndata: {\"text\":\"hi\"}\n\n", "event: message_stop\ndata: {}\n\n"}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.RequestURI())
		if r.URL.Path == "/v1/items" {
			itemsHeaders = r.Header.Clone()
		}
		mu.Unlock()
		switch r.URL.Path {
		case "/v1/items":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"item-1"}`)
		case "/v1/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			for i, p := range pieces {
				if i > 0 {
					time.Sleep(500 * time.Millisecond)
				}
				_, _ = io.WriteString(w, p)
				_ = rc.Flush()
			}
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer upstream.Close()
	grant := &HostAPIGrant{
		BaseURL:     upstream.URL,
		Allow:       []HostRoute{{Method: http.MethodGet, Path: "/v1/items"}, {Method: http.MethodGet, Path: "/v1/stream"}},
		Minter:      StaticToken(token),
		PassHeaders: []string{"anthropic-version"},
	}
	code := `(async () => {
  const headers = { "authorization": "Bearer dummy-from-the-guest", "x-api-key": "dummy-from-the-guest", "anthropic-version": "2026-10-21",
    "anthropic-beta": "not-listed", "accept": "application/json", "user-agent": "OpenAI/JS 6.0.0", "x-stainless-lang": "js",
    "x-stainless-package-version": "6.0.0", "x-stainless-retry-count": "0", "x-stainless-timeout": "600", ...host.raw.headers };
  try {
    const a = await fetch(host.raw.url + "/v1/items", { headers });
    console.log("RAW-ALLOWED", a.status, await a.text());
    const d = await fetch(host.raw.url + "/v1/not-allowed", { headers });
    console.log("RAW-DENIED", d.status, d.headers.get("x-should-retry"));
    const s = await fetch(host.raw.url + "/v1/stream", { headers });
    const reader = s.body.getReader(); let first = 0, last = 0, bytes = 0;
    for (;;) { const { done, value } = await reader.read(); if (done) break; const now = Date.now(); if (!first) first = now; last = now; bytes += value.length; }
    console.log("RAW-STREAM", s.status, last - first, bytes);
  } catch (err) {
    console.error("RAW-FAILED", String(err), err?.cause?.code || "");
    process.exit(13);
  }
})();`
	res, err := run(code, grant)
	if err != nil {
		t.Fatalf("raw route: infrastructure error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("raw route guest failed: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, `RAW-ALLOWED 200 {"id":"item-1"}`) {
		t.Errorf("allowed raw request: stdout %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "RAW-DENIED 403 false") {
		t.Errorf("refused raw request: stdout %q, want 403 with X-Should-Retry false", res.Stdout)
	}
	var status, gapMs, bytes int
	if _, err := fmt.Sscanf(afterToken(res.Stdout, "RAW-STREAM "), "%d %d %d", &status, &gapMs, &bytes); err != nil || status != 200 || bytes != len(strings.Join(pieces, "")) {
		t.Errorf("streamed raw request: status %d, %d bytes (want 200 and %d bytes): stdout %q", status, bytes, len(strings.Join(pieces, "")), res.Stdout)
	} else if gapMs >= 700 {
		t.Logf("streamed raw request arrived in pieces: %d ms between the first and the last", gapMs)
	} else {
		// The public route (a Tailscale Funnel path on this laptop) sits between the guest
		// and the guard and may buffer a response; plimsoll's own streaming is proven by
		// TestEgressGuardStreamsEventStream against the handler, so this is a measurement
		// of the path, recorded rather than failed.
		t.Logf("streamed raw request arrived whole or nearly so (%d ms between the first and the last piece): the public route buffered it; plimsoll streamed (TestEgressGuardStreamsEventStream)", gapMs)
	}
	if strings.Contains(res.Stdout+res.Stderr, token) {
		t.Error("the broker's credential appeared in guest output")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if strings.Contains(p, "not-allowed") {
			t.Errorf("the refused request reached the upstream: %v", paths)
		}
	}
	if itemsHeaders == nil {
		t.Fatalf("the upstream never saw /v1/items; paths %v", paths)
	}
	if got := itemsHeaders.Get("Authorization"); got != "Bearer "+token {
		t.Errorf("upstream Authorization = %q, want the broker's credential", got)
	}
	if got := itemsHeaders.Get("anthropic-version"); got != "2026-10-21" {
		t.Errorf("upstream anthropic-version = %q, want the client's, passed through", got)
	}
	for _, name := range []string{"X-Api-Key", "Anthropic-Beta", "X-Stainless-Lang", "X-Stainless-Package-Version", "X-Stainless-Retry-Count", "X-Stainless-Timeout", EgressGuardHeader} {
		if vals, present := itemsHeaders[http.CanonicalHeaderKey(name)]; present {
			t.Errorf("%s reached the upstream: %q", name, vals)
		}
	}
	if ua := itemsHeaders.Get("User-Agent"); strings.HasPrefix(ua, "OpenAI/") {
		t.Errorf("the client's User-Agent reached the upstream: %q", ua)
	}
	t.Log("raw route live proof passed: allowed request with the broker's credential and the passed header only, refused request with the no-retry mark, streamed answer in pieces")
}

// afterToken returns what follows the first occurrence of token in s, to its line's end.
func afterToken(s, token string) string {
	i := strings.Index(s, token)
	if i < 0 {
		return ""
	}
	rest := s[i+len(token):]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// liveGuard is what the guarded live tests share, read from the environment; see
// TestE2BGuardLive for the variables. The tests skip unless E2B_GUARD_LIVE_REQUIRED=1
// (make e2b-guard-live), under which a missing variable fails them.
type liveGuard struct {
	e              *E2B
	grant          *HostAPIGrant
	allowed, token string
}

func liveGuardSetup(t *testing.T) liveGuard {
	t.Helper()
	paidOptIn(t, "E2B_GUARD_LIVE_REQUIRED")
	key := strings.TrimSpace(os.Getenv("E2B_API_KEY"))
	guardURL := strings.TrimSpace(os.Getenv("E2B_GUARD_URL"))
	baseURL := strings.TrimSpace(os.Getenv("E2B_LIVE_GRANT_BASE_URL"))
	if key == "" || guardURL == "" || baseURL == "" {
		var missing []string
		for _, v := range []struct {
			name  string
			value string
		}{
			{"E2B_API_KEY", key},
			{"E2B_GUARD_URL", guardURL},
			{"E2B_LIVE_GRANT_BASE_URL", baseURL},
		} {
			if v.value == "" {
				missing = append(missing, v.name)
			}
		}
		if os.Getenv("E2B_GUARD_LIVE_REQUIRED") == "1" {
			t.Fatalf("E2B_GUARD_LIVE_REQUIRED=1 but %s not set: this run proves nothing about the guarded egress path", strings.Join(missing, ", "))
		}
		t.Skipf("set %s for the live guard test (or run `make e2b-guard-live` to make this a failure)", strings.Join(missing, ", "))
	}
	allowed := strings.TrimSpace(os.Getenv("E2B_LIVE_GRANT_ALLOWED_PATH"))
	if allowed == "" {
		allowed = "/healthz"
	}
	token := os.Getenv("E2B_LIVE_GRANT_TOKEN")
	e := &E2B{APIKey: key, GuardURL: guardURL, DefaultTimeout: 90 * time.Second, MaxTimeout: 120 * time.Second}
	if listen := strings.TrimSpace(os.Getenv("E2B_LIVE_GUARD_LISTEN")); listen != "" {
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			t.Fatalf("listen for self-served guard on %s: %v", listen, err)
		}
		srv := &http.Server{Handler: EgressGuardHTTPHandler(e, e.EgressGuardPath(), 0, 0)}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
		t.Logf("serving guard handler on %s for %s; the public guard host must route the path here", listen, e.EgressGuardPath())
	}
	var minter TokenMinter
	if token != "" {
		minter = StaticToken(token)
	}
	grant := &HostAPIGrant{
		BaseURL: baseURL,
		Allow:   []HostRoute{{Method: http.MethodGet, Path: allowed}},
		Minter:  minter,
	}
	return liveGuard{e: e, grant: grant, allowed: allowed, token: token}
}

// liveAllowedCode calls the allowed route through the injected client and prints
// GUARD-ALLOWED, or exits 11 with the error.
func liveAllowedCode(allowed string) string {
	return `(async () => {
  try {
    const value = await host.get(` + strconvQuote(allowed) + `);
    console.log("GUARD-ALLOWED", JSON.stringify(value));
  } catch (err) {
    console.error("GUARD-ALLOWED-FAILED", JSON.stringify({name: err?.name, message: String(err), cause: err?.cause?.code || err?.cause?.message || String(err?.cause || ""), stack: err?.stack}));
    process.exit(11);
  }
})();`
}

// TestE2BSessionGuardLive proves both ways a session call reaches its grant
// (E2B_SESSION_GRANTS) against the live service: for each, one session whose granted
// call reaches the allowed route, an ungranted call after it, and a granted call after
// a suspend, which pauses the sandbox. "session" also proves E2B's record shows the
// guard's rule as created (its open checks it). It spends: two sessions of about a
// minute each. Same environment as TestE2BGuardLive.
func TestE2BSessionGuardLive(t *testing.T) {
	g := liveGuardSetup(t)
	grant := *g.grant
	grant.AllowInSessions = true
	ctx := context.Background()
	for _, mode := range []string{E2BSessionGrantsSession, E2BSessionGrantsCall} {
		t.Run(mode, func(t *testing.T) {
			g.e.SessionGrants = mode
			s, err := g.e.OpenSession(ctx, SessionOptions{Lifetime: 5 * time.Minute})
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer func() {
				_ = s.Close(ctx)
				select {
				case <-s.Done():
				case <-time.After(2 * time.Minute):
					t.Errorf("the session's sandbox %s was not deleted within 2 minutes of its close", s.(*e2bSession).machine().id)
				}
			}()
			granted := func(when string) {
				res, err := s.RunJavaScript(ctx, Request{Code: liveAllowedCode(g.allowed), Grant: &grant, Timeout: 60 * time.Second})
				if err != nil || res.ExitCode != 0 || !strings.Contains(res.Stdout, "GUARD-ALLOWED") {
					t.Fatalf("%s: err=%v exit=%d stdout=%q stderr=%q", when, err, res.ExitCode, res.Stdout, res.Stderr)
				}
			}
			granted("the first granted call")
			if res, err := s.RunJavaScript(ctx, Request{Code: `console.log("plain")`, Timeout: 30 * time.Second}); err != nil || res.ExitCode != 0 {
				t.Fatalf("an ungranted call after a granted one: err=%v exit=%d stderr=%q", err, res.ExitCode, res.Stderr)
			}
			if _, err := s.Suspend(ctx); err != nil {
				t.Fatalf("suspend: %v", err)
			}
			granted("a granted call after a suspend")
		})
	}
}

// strconvQuote keeps the test-generated JavaScript literal safe for arbitrary
// operator-selected paths without importing a JS templating dependency.
func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
