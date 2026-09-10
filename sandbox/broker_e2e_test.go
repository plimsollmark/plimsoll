package sandbox

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestDockerBrokerEnforcesAllowlistOverSocket drives real HTTP requests through the
// docker broker's unix socket — the security-critical glue the pure routeAllowed
// unit tests do NOT cover: the handler gate, the reverse-proxy forwarding, and the
// host-side token injection. It needs no docker daemon (the broker is a plain HTTP
// server on a unix socket) so it runs everywhere.
//
// If the `if !grant.routeAllowed(...)` gate at startDockerBroker were removed or
// inverted, or the Director stopped overwriting Authorization, this test fails.
func TestDockerBrokerEnforcesAllowlistOverSocket(t *testing.T) {
	var upstreamHits int32
	var gotAuth atomic.Value // string
	var gotHost atomic.Value
	var gotForwarded atomic.Value
	gotAuth.Store("")
	gotHost.Store("")
	gotForwarded.Store("")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		gotAuth.Store(r.Header.Get("Authorization"))
		gotHost.Store(r.Host)
		gotForwarded.Store(r.Header.Get("Forwarded") + r.Header.Get("X-Forwarded-For"))
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: sampleAllow}
	b, err := startDockerBroker(grant, "tok-123")
	if err != nil {
		t.Fatalf("startDockerBroker: %v", err)
	}
	defer b.Close()

	// A client that dials the broker over its unix socket, exactly as the container's
	// bind-mounted HOST_API_SOCKET does.
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", b.sock)
		},
	}}
	do := func(method, path, auth string) (int, int32) {
		before := atomic.LoadInt32(&upstreamHits)
		req, err := http.NewRequest(method, "http://unix"+path, nil)
		if err != nil {
			t.Fatalf("new request %s %s: %v", method, path, err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		req.Host = "attacker.invalid"
		req.Header.Set("Forwarded", "for=attacker")
		req.Header.Set("X-Forwarded-For", "attacker")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do %s %s: %v", method, path, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode, atomic.LoadInt32(&upstreamHits) - before
	}

	t.Run("allowed route reaches upstream with injected token", func(t *testing.T) {
		// Send a spoofed Authorization; the broker must overwrite it with the minted one.
		status, forwarded := do(http.MethodGet, "/v1/lights", "Bearer evil-spoof")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if forwarded != 1 {
			t.Fatalf("upstream hit %d times, want 1", forwarded)
		}
		if got := gotAuth.Load().(string); got != "Bearer tok-123" {
			t.Fatalf("upstream saw Authorization %q, want the broker-injected %q (client spoof must be overwritten)", got, "Bearer tok-123")
		}
		if got, want := gotHost.Load().(string), strings.TrimPrefix(upstream.URL, "http://"); got != want {
			t.Fatalf("upstream Host = %q, want target host %q", got, want)
		}
		if got := gotForwarded.Load().(string); got != "" {
			t.Fatalf("spoofed forwarding headers reached upstream: %q", got)
		}
	})

	t.Run("denied route is rejected at the gate, never forwarded", func(t *testing.T) {
		for _, path := range []string{
			"/v1/code/run",           // not in the allowlist
			"/v1/lights/abc/color",   // path not allowed
			"/v1/lights/x%2f..%2fon", // encoded traversal — must die at the HTTP layer too
		} {
			status, forwarded := do(http.MethodPut, path, "")
			if status != http.StatusForbidden {
				t.Errorf("PUT %s: status = %d, want 403", path, status)
			}
			if forwarded != 0 {
				t.Errorf("PUT %s: forwarded to upstream %d times, want 0 (gate must block before proxy)", path, forwarded)
			}
		}
	})
}

// TestDockerBrokerEmptyAllowlistDeniesOverSocket confirms the off-by-default posture
// holds at the HTTP layer, not just in the routeAllowed predicate: with no Allow
// entries, every request is 403 and nothing reaches upstream.
func TestDockerBrokerEmptyAllowlistDeniesOverSocket(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
	}))
	defer upstream.Close()

	b, err := startDockerBroker(&HostAPIGrant{BaseURL: upstream.URL}, "tok")
	if err != nil {
		t.Fatalf("startDockerBroker: %v", err)
	}
	defer b.Close()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", b.sock)
		},
	}}
	resp, err := client.Get("http://unix/v1/lights")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (empty allowlist denies all)", resp.StatusCode)
	}
	if atomic.LoadInt32(&upstreamHits) != 0 {
		t.Fatalf("upstream was hit %d times under an empty allowlist, want 0", upstreamHits)
	}
}

// sanity: containerSocketPath is an absolute in-container path (mount target).
func TestContainerSocketPathIsAbsolute(t *testing.T) {
	if !strings.HasPrefix(containerSocketPath, "/") {
		t.Fatalf("containerSocketPath = %q, want an absolute path", containerSocketPath)
	}
}
