package sandbox

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func brokerSocketClient(t *testing.T, sock string) *http.Client {
	t.Helper()
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

// TestDockerBrokerEnforcesPerRunCallBudget verifies the broker's per-run call
// counter: a run gets exactly maxHostCallsPerRun brokered calls (allowed or
// denied), after which every further call is shed with 429 and nothing more
// reaches the upstream. A capability must not be usable as a host-API flood.
func TestDockerBrokerEnforcesPerRunCallBudget(t *testing.T) {
	var upstreamHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	b, err := startDockerBroker(&HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/ping"}}}, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	client := brokerSocketClient(t, b.sock)

	for i := 0; i < maxHostCallsPerRun; i++ {
		resp, err := client.Get("http://unix/ping")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d status = %d before the budget was spent", i, resp.StatusCode)
		}
	}
	resp, err := client.Get("http://unix/ping")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("call %d status = %d, want 429 (budget exhausted)", maxHostCallsPerRun+1, resp.StatusCode)
	}
	if upstreamHits != maxHostCallsPerRun {
		t.Fatalf("upstream hits = %d, want exactly %d", upstreamHits, maxHostCallsPerRun)
	}
}

// TestDockerBrokerCapsDeclaredResponseSize verifies a response whose declared
// Content-Length exceeds the per-call byte budget never streams into the
// sandbox: the broker aborts it as a bad gateway.
func TestDockerBrokerCapsDeclaredResponseSize(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(maxHostResponseBytes+1))
		_, _ = w.Write(make([]byte, maxHostResponseBytes+1))
	}))
	defer upstream.Close()

	b, err := startDockerBroker(&HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/big"}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	resp, err := brokerSocketClient(t, b.sock).Get("http://unix/big")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for an over-budget declared response", resp.StatusCode)
	}
}

// TestDockerBrokerCutsUndeclaredResponseStream verifies a chunked (no declared
// length) over-budget response is cut off mid-copy rather than relayed without
// bound: the sandbox must never receive more than the per-call byte budget.
func TestDockerBrokerCutsUndeclaredResponseStream(t *testing.T) {
	const total = maxHostResponseBytes * 3
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, _ := w.(http.Flusher)
		chunk := make([]byte, 64<<10)
		for written := 0; written < total; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if f != nil {
				f.Flush()
			}
		}
	}))
	defer upstream.Close()

	b, err := startDockerBroker(&HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/stream"}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	resp, err := brokerSocketClient(t, b.sock).Get("http://unix/stream")
	if err != nil {
		// The broker may abort the response before headers complete; that is a
		// valid containment outcome.
		if !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "reset") {
			t.Fatalf("unexpected transport error: %v", err)
		}
		return
	}
	defer resp.Body.Close()
	received, _ := io.Copy(io.Discard, resp.Body)
	if received > maxHostResponseBytes {
		t.Fatalf("sandbox received %d bytes, above the %d byte budget", received, maxHostResponseBytes)
	}
}
