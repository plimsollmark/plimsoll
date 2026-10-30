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

// TestDockerCloudGuardLive is the end-to-end proof of a Docker Cloud host-API grant,
// as TestE2BGuardLive is for E2B: one Micro sandbox on the Connect API runs a snippet
// whose granted route reaches the upstream through this process's guard, a second
// whose ungranted route is refused, and then a captured guard credential is refused
// after its run closed. It spends (two sandboxes for a few seconds each, well under a
// cent at the $0.07-an-hour Micro list price) and runs only through
// `make dockercloud-guard-live`, which sets both opt-ins below.
//
// Guard credentials live only in the process that opened the run, so the public
// guard URL must end at THIS process: DOCKERCLOUD_LIVE_GUARD_LISTEN is a local address
// the test serves the production guard handler on, and the public HTTPS route (a
// Tailscale Funnel path on this laptop) must forward the guard path there.
//
// Required, besides dockerCloudLive's variables (the Connect API, so
// SANDBOX_DOCKERCLOUD_API_URL too; REST refuses grants):
//
//	SANDBOX_DOCKERCLOUD_GUARD_URL     the public HTTPS guard URL, path included
//	DOCKERCLOUD_LIVE_GUARD_LISTEN     local address the guard handler is served on
//	DOCKERCLOUD_LIVE_GRANT_BASE_URL   origin of the upstream the grant reaches
//
// Optional: DOCKERCLOUD_LIVE_GRANT_ALLOWED_PATH (default /healthz) and
// DOCKERCLOUD_LIVE_GRANT_DENIED_PATH (default /not-allowed).
func TestDockerCloudGuardLive(t *testing.T) {
	paidOptIn(t, "DOCKERCLOUD_GUARD_LIVE_REQUIRED")
	d := dockerCloudLive(t)
	if d.rest() {
		t.Fatal("host-API grants run on the Connect API only: set SANDBOX_DOCKERCLOUD_API=connect and SANDBOX_DOCKERCLOUD_API_URL")
	}
	guardURL := strings.TrimSpace(os.Getenv("SANDBOX_DOCKERCLOUD_GUARD_URL"))
	listen := strings.TrimSpace(os.Getenv("DOCKERCLOUD_LIVE_GUARD_LISTEN"))
	baseURL := strings.TrimSpace(os.Getenv("DOCKERCLOUD_LIVE_GRANT_BASE_URL"))
	if guardURL == "" || listen == "" || baseURL == "" {
		t.Fatal("make dockercloud-guard-live needs SANDBOX_DOCKERCLOUD_GUARD_URL, DOCKERCLOUD_LIVE_GUARD_LISTEN and DOCKERCLOUD_LIVE_GRANT_BASE_URL: without them this run proves nothing about the guarded path")
	}
	allowed := envOr("DOCKERCLOUD_LIVE_GRANT_ALLOWED_PATH", "/healthz")
	denied := envOr("DOCKERCLOUD_LIVE_GRANT_DENIED_PATH", "/not-allowed")
	d.GuardURL = guardURL

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatalf("listen for the guard on %s: %v (another process may hold the port: check it before routing a public path here)", listen, err)
	}
	srv := &http.Server{Handler: EgressGuardHTTPHandler(d, d.EgressGuardPath(), 0, 0), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	t.Logf("serving the guard handler on %s for %s; the public route must forward that path here", listen, d.EgressGuardPath())

	grant := &HostAPIGrant{BaseURL: baseURL, Allow: []HostRoute{{Method: http.MethodGet, Path: allowed}}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	res, err := d.RunJavaScript(ctx, Request{Code: liveAllowedCode(allowed), Grant: grant})
	if err != nil {
		t.Fatalf("allowed route: infrastructure error: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "GUARD-ALLOWED") {
		t.Fatalf("allowed route failed: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if res.Isolation != IsolationVM {
		t.Fatalf("isolation %q, want vm", res.Isolation)
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
	res, err = d.RunJavaScript(ctx, Request{Code: deniedCode, Grant: grant})
	if err != nil {
		t.Fatalf("denied route: infrastructure error: %v", err)
	}
	if res.ExitCode != 17 || !strings.Contains(res.Stdout, "GUARD-DENIED") {
		t.Fatalf("denied route was not refused: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}

	// A run's guard credential dies with its run: one captured after the close gets
	// 401 at the public route, which proves expiry at the HTTP boundary a guest reaches.
	guard, cleanup, err := d.openGuard(ctx, grant, time.Minute)
	if err != nil {
		t.Fatalf("open a guard for the expiry check: %v", err)
	}
	captured := guard.token
	cleanup()
	payload, _ := json.Marshal(map[string]any{"method": http.MethodGet, "path": allowed})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, guardURL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build the expired-credential request: %v", err)
	}
	req.Header.Set(EgressGuardHeader, captured)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("expired-credential request: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired credential: status %d body %q, want 401", resp.StatusCode, body)
	}
	t.Log("Docker Cloud guard live proof passed: allowed route, denied route, expired credential")

	// The raw route from inside the VM, as a standard client calls it: one more Micro
	// sandbox. Docker's proxy injects no credential for the guard, so the guest adds the
	// run's guard credential itself, from host.raw.headers, as a client library would
	// through its default headers.
	liveRawRouteProof(t, func(code string, grant *HostAPIGrant) (Result, error) {
		return d.RunJavaScript(ctx, Request{Code: code, Grant: grant})
	})
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
