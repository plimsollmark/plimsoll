package sandbox

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// jsonResp is a small helper for the backpressure tests: an upstream response with a
// status, optional Retry-After, and a JSON body.
func jsonResp(status int, retryAfter, body string) *http.Response {
	h := http.Header{"Content-Type": {"application/json"}}
	if retryAfter != "" {
		h.Set("Retry-After", retryAfter)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}

// TestBrokerShedsAfterUpstreamBackpressure proves the reactive breaker: once the upstream
// answers 429/503, the broker sheds subsequent permitted calls (fails fast) instead of
// forwarding them, and records the shed distinctly from a policy denial.
func TestBrokerShedsAfterUpstreamBackpressure(t *testing.T) {
	var upstream int
	core, err := newBrokerSession(&HostAPIGrant{
		BaseURL: "https://api.internal",
		Allow:   []HostRoute{{Method: "GET", Path: "/work"}},
	}, "", brokerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		upstream++
		return jsonResp(http.StatusServiceUnavailable, "10", `{"error":"overloaded"}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	// First call reaches the upstream and gets the real 503, which trips the breaker.
	first := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/work"})
	if first.Status != http.StatusServiceUnavailable || upstream != 1 {
		t.Fatalf("first call status=%d upstream=%d, want a forwarded 503", first.Status, upstream)
	}
	// Every later call in the run is shed without touching the struggling upstream.
	for i := 0; i < 3; i++ {
		got := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/work"})
		if got.Status != http.StatusServiceUnavailable || !strings.Contains(string(got.Body), "shedding load") {
			t.Fatalf("shed call %d = %+v, want a fast shed", i, got)
		}
	}
	if upstream != 1 {
		t.Fatalf("upstream hit %d times; sheds must not forward", upstream)
	}
	trace := core.traceSnapshot()
	if trace == nil || trace.Shed != 3 || len(trace.Calls) != 1 || trace.Denied != 0 {
		t.Fatalf("trace = %+v, want one recorded call and three sheds (no denials)", trace)
	}
}

// TestBrokerHealthProbeClosesBreakerOnRecovery proves the declared health_check route
// lets a shedding run recover mid-run: while the breaker is open after an upstream 503,
// an elected caller probes the health route, and a 2xx closes the breaker so the call
// proceeds upstream.
func TestBrokerHealthProbeClosesBreakerOnRecovery(t *testing.T) {
	var workHits, healthHits int
	core, err := newBrokerSession(&HostAPIGrant{
		BaseURL:     "https://api.internal",
		Allow:       []HostRoute{{Method: "GET", Path: "/work"}},
		HealthCheck: &HostRoute{Method: "GET", Path: "/health"},
	}, "tok", brokerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/health":
			healthHits++
			return jsonResp(http.StatusOK, "", `{"ok":true}`), nil
		default:
			workHits++
			if workHits == 1 {
				return jsonResp(http.StatusServiceUnavailable, "5", `{"error":"overloaded"}`), nil
			}
			return jsonResp(http.StatusOK, "", `{"ok":true}`), nil
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	// First call trips the breaker (503: the service reports itself degraded).
	if got := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/work"}); got.Status != http.StatusServiceUnavailable {
		t.Fatalf("first call status=%d, want the forwarded 503", got.Status)
	}
	// Second call is elected to probe; the probe returns 200, so the breaker closes and
	// the call proceeds upstream (which is healthy now).
	second := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/work"})
	if second.Status != http.StatusOK {
		t.Fatalf("recovered call status=%d body=%q, want 200", second.Status, second.Body)
	}
	if healthHits != 1 {
		t.Fatalf("health probe hit %d times, want exactly one", healthHits)
	}
	trace := core.traceSnapshot()
	// Two forwarded work calls (429 then 200) are recorded; the health probe is broker
	// overhead and must NOT appear in the trace, and nothing was shed.
	if trace == nil || len(trace.Calls) != 2 || trace.Shed != 0 {
		t.Fatalf("trace = %+v, want two recorded work calls, no shed, no probe row", trace)
	}
	for _, c := range trace.Calls {
		if c.Route == "/health" {
			t.Fatal("health probe leaked into the metadata trace")
		}
	}
}

// TestBrokerHealthProbeKeepsSheddingWhileDegraded proves a still-degraded probe does not
// reopen the gate: the elected caller probes, gets a non-2xx, and the call is shed.
func TestBrokerHealthProbeKeepsSheddingWhileDegraded(t *testing.T) {
	var healthHits int
	core, err := newBrokerSession(&HostAPIGrant{
		BaseURL:     "https://api.internal",
		Allow:       []HostRoute{{Method: "GET", Path: "/work"}},
		HealthCheck: &HostRoute{Method: "GET", Path: "/health"},
	}, "tok", brokerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/health" {
			healthHits++
			return jsonResp(http.StatusServiceUnavailable, "", `{"ok":false}`), nil
		}
		return jsonResp(http.StatusServiceUnavailable, "20", `{"error":"overloaded"}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	if got := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/work"}); got.Status != http.StatusServiceUnavailable {
		t.Fatalf("first call status=%d, want the forwarded 503", got.Status)
	}
	shed := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/work"})
	if shed.Status != http.StatusServiceUnavailable || !strings.Contains(string(shed.Body), "shedding load") {
		t.Fatalf("degraded-probe call = %+v, want a shed", shed)
	}
	if healthHits != 1 {
		t.Fatalf("health probe hit %d times, want exactly one", healthHits)
	}
	if trace := core.traceSnapshot(); trace == nil || trace.Shed != 1 {
		t.Fatalf("trace = %+v, want one shed", trace)
	}
}

// TestHealthCheckGrantValidation locks down the health_check contract: a broker-operated
// probe must be a concrete GET route, since the broker sends it as an exact URL.
func TestHealthCheckGrantValidation(t *testing.T) {
	base := func(hc *HostRoute) *HostAPIGrant {
		return &HostAPIGrant{
			BaseURL:     "https://api.internal",
			Allow:       []HostRoute{{Method: "GET", Path: "/work"}},
			HealthCheck: hc,
		}
	}
	cases := []struct {
		name string
		hc   *HostRoute
		want string
	}{
		{"good", &HostRoute{Method: "GET", Path: "/health"}, ""},
		{"not get", &HostRoute{Method: "POST", Path: "/health"}, "must be a GET route"},
		{"wildcard", &HostRoute{Method: "GET", Path: "/health/*"}, "must be concrete"},
		{"relative", &HostRoute{Method: "GET", Path: "health"}, "absolute"},
		{"traversal", &HostRoute{Method: "GET", Path: "/../secrets"}, "traversal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := base(tc.hc).Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestBrokerDoesNotProbeAfterRateLimit is the counterpart to the recovery test, and the
// reason the trip carries its cause. A 429 says this caller has spent its allowance; the
// health route reports whether the SERVICE can serve, which is a different question and
// is answered 200 by a perfectly healthy API that is still rate-limiting. Probing here
// would reopen the gate and push the run's traffic straight back into the limiter that
// just asked it to back off, so a quota window is waited out with no probe at all.
func TestBrokerDoesNotProbeAfterRateLimit(t *testing.T) {
	var workHits, healthHits int
	core, err := newBrokerSession(&HostAPIGrant{
		BaseURL:     "https://api.internal",
		Allow:       []HostRoute{{Method: "GET", Path: "/work"}},
		HealthCheck: &HostRoute{Method: "GET", Path: "/health"},
	}, "tok", brokerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/health" {
			healthHits++
			return jsonResp(http.StatusOK, "", `{"ok":true}`), nil // the service is fine
		}
		workHits++
		return jsonResp(http.StatusTooManyRequests, "5", `{"error":"slow down"}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	if got := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/work"}); got.Status != http.StatusTooManyRequests {
		t.Fatalf("first call status=%d, want the forwarded 429", got.Status)
	}
	for i := 0; i < 3; i++ {
		got := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/work"})
		if got.Status != http.StatusServiceUnavailable || !strings.Contains(string(got.Body), "shedding load") {
			t.Fatalf("call %d after 429 = %+v, want a shed", i, got)
		}
	}
	if healthHits != 0 {
		t.Fatalf("health probed %d times after a 429; a healthy service does not prove a quota reset", healthHits)
	}
	if workHits != 1 {
		t.Fatalf("upstream hit %d times, want 1: the rate limiter must not be re-entered", workHits)
	}
}

// TestBrokerQuotaTripSuppressesProbingForTheWholeWindow proves the suppression is a
// property of the open window, not of one call: a later 503 that extends a window opened
// by a 429 must not turn probing back on, since nothing has shown the rate limit cleared.
func TestBrokerQuotaTripSuppressesProbingForTheWholeWindow(t *testing.T) {
	var br breaker
	now := time.Now()
	br.open(now, 30*time.Second, true) // 429
	br.open(now, 30*time.Second, false)
	if shedding, elected := br.gate(now.Add(time.Second), true); !shedding || elected {
		t.Fatalf("gate = (%v, %v), want shedding with no probe", shedding, elected)
	}

	// Once the window lapses, the next trip starts clean and is probeable again.
	if shedding, _ := br.gate(now.Add(time.Minute), true); shedding {
		t.Fatal("breaker still shedding after its window lapsed")
	}
	br.open(now.Add(time.Minute), 30*time.Second, false) // 503
	if shedding, elected := br.gate(now.Add(time.Minute+time.Second), true); !shedding || !elected {
		t.Fatalf("gate = (%v, %v), want shedding with an elected prober", shedding, elected)
	}
}
