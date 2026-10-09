package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
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
