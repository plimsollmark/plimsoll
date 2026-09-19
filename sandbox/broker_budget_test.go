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
// counter: a run gets exactly DefaultMaxHostCalls brokered calls (allowed or
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

	for i := 0; i < DefaultMaxHostCalls; i++ {
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
		t.Fatalf("call %d status = %d, want 429 (budget exhausted)", DefaultMaxHostCalls+1, resp.StatusCode)
	}
	if upstreamHits != DefaultMaxHostCalls {
		t.Fatalf("upstream hits = %d, want exactly %d", upstreamHits, DefaultMaxHostCalls)
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

// TestBrokerHonoursAGrantsOwnCallBudget covers the per-profile budget: a grant that
// names one gets exactly that many brokered calls, above or below the default. The low
// value is the one worth testing behaviourally, because it exercises the same counter
// without 6,000 round trips.
func TestBrokerHonoursAGrantsOwnCallBudget(t *testing.T) {
	var upstreamHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	const budget = 5
	b, err := startDockerBroker(&HostAPIGrant{
		BaseURL:  upstream.URL,
		Allow:    []HostRoute{{Method: "GET", Path: "/ping"}},
		MaxCalls: budget,
	}, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	client := brokerSocketClient(t, b.sock)

	for i := 0; i < budget; i++ {
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
		t.Fatalf("call %d status = %d, want 429 once the grant's budget is spent", budget+1, resp.StatusCode)
	}
	if upstreamHits != budget {
		t.Fatalf("upstream hits = %d, want exactly %d", upstreamHits, budget)
	}
}

// TestGrantCallBudgetBounds pins the accessor and its validation: zero means the
// default, the ceiling is enforced, and a negative value is refused. Without the
// ceiling a profile could hand one run an unbounded number of upstream requests.
func TestGrantCallBudgetBounds(t *testing.T) {
	var nilGrant *HostAPIGrant
	if got := nilGrant.CallBudget(); got != DefaultMaxHostCalls {
		t.Errorf("nil grant CallBudget() = %d, want %d", got, DefaultMaxHostCalls)
	}
	for _, tc := range []struct {
		max  int
		want int
	}{{0, DefaultMaxHostCalls}, {1, 1}, {MaxHostCallsCeiling, MaxHostCallsCeiling}} {
		g := &HostAPIGrant{MaxCalls: tc.max}
		if got := g.CallBudget(); got != tc.want {
			t.Errorf("MaxCalls %d: CallBudget() = %d, want %d", tc.max, got, tc.want)
		}
	}
	valid := func(max int) error {
		g := &HostAPIGrant{
			BaseURL:  "https://api.internal",
			Allow:    []HostRoute{{Method: "GET", Path: "/v1/ping"}},
			Minter:   StaticToken("tok"),
			MaxCalls: max,
		}
		return g.Validate()
	}
	if err := valid(MaxHostCallsCeiling); err != nil {
		t.Errorf("MaxCalls at the ceiling was refused: %v", err)
	}
	for _, bad := range []int{-1, MaxHostCallsCeiling + 1} {
		if err := valid(bad); err == nil {
			t.Errorf("MaxCalls %d was accepted; want a refusal", bad)
		}
	}
}

// TestTraceCapDoesNotFollowARaisedBudget is the decision this cap encodes: the trace is
// bounded evidence, not a ledger. A grant may allow far more calls than the trace keeps
// rows for, and the overflow has to show up as Dropped so a finding reports "at least".
func TestTraceCapDoesNotFollowARaisedBudget(t *testing.T) {
	if maxTraceRows != DefaultMaxHostCalls {
		t.Fatalf("maxTraceRows = %d, want the default budget %d regardless of any grant", maxTraceRows, DefaultMaxHostCalls)
	}
	if MaxHostCallsCeiling <= maxTraceRows {
		t.Fatal("the ceiling no longer exceeds the trace cap, so this decision is moot and the comment is wrong")
	}
	trace := newCallTrace()
	for i := 0; i < maxTraceRows+3; i++ {
		trace.record(CallRow{Method: "GET", Route: "/v1/ping", Status: 200, Delivered: true})
	}
	snap := trace.snapshot()
	if len(snap.Calls) != maxTraceRows || snap.Dropped != 3 {
		t.Fatalf("kept %d rows and dropped %d, want %d and 3", len(snap.Calls), snap.Dropped, maxTraceRows)
	}
}
