package sandbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// jobsAPI counts the requests that reach it.
func jobsAPI(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(api.Close)
	return api.URL, &hits
}

func cappedGrant(base string, caps map[HostRoute]int, allow ...HostRoute) *HostAPIGrant {
	return &HostAPIGrant{BaseURL: base, Allow: allow, RouteMaxCalls: caps, Minter: StaticToken("t"), AllowInSessions: true}
}

// calls makes n POSTs to target through a fresh broker core for grant, as one granted
// call of a run or a session does, and returns their statuses.
func calls(t *testing.T, grant *HostAPIGrant, routes *RouteBudget, target string, n int) []int {
	t.Helper()
	core, err := brokerSessionForGrant(context.Background(), grant, time.Minute, routes)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	var out []int
	for range n {
		out = append(out, core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: target}).Status)
	}
	return out
}

// A session's granted calls each get a broker core of their own, so a cap held in the
// core started over with every call: a cap of two jobs gave six over three calls (the
// 8 October round-2 review). Given the session's budget, the cap spans the calls.
func TestRouteCapSpansTheSessionsCalls(t *testing.T) {
	base, hits := jobsAPI(t)
	submit := HostRoute{Method: "POST", Path: "/v2/ep1/run"}
	grant := cappedGrant(base, map[HostRoute]int{submit: 2}, submit)

	session := NewRouteBudget()
	for range 3 {
		calls(t, grant, session, "/v2/ep1/run", 3)
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("three calls of one session reached the API %d times, want the cap's 2", n)
	}

	// Runs keep a budget each.
	hits.Store(0)
	for range 3 {
		calls(t, grant, nil, "/v2/ep1/run", 3)
	}
	if n := hits.Load(); n != 6 {
		t.Fatalf("three runs reached the API %d times, want 2 each", n)
	}
}

// Two grants that cap the same route of the same API draw on one count in a session.
func TestRouteCapIsSharedByGrantsOfTheSameRoute(t *testing.T) {
	base, hits := jobsAPI(t)
	submit := HostRoute{Method: "POST", Path: "/v2/ep1/run"}
	status := HostRoute{Method: "get", Path: "/v2/ep1/status/*"}
	a := cappedGrant(base, map[HostRoute]int{submit: 2}, submit)
	b := cappedGrant(base, map[HostRoute]int{submit: 2}, status, submit)
	session := NewRouteBudget()
	calls(t, a, session, "/v2/ep1/run", 2)
	if got := calls(t, b, session, "/v2/ep1/run", 1); got[0] != http.StatusTooManyRequests {
		t.Fatalf("the second grant's call after the first spent the cap: %v, want 429", got)
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("the API was reached %d times, want 2", n)
	}
}

// A case variant of a capped route that only an uncapped entry matches as written
// still counts against the cap: an upstream that routes without regard to case serves
// it as the capped route.
func TestRouteCapCountsCaseVariants(t *testing.T) {
	base, hits := jobsAPI(t)
	submit := HostRoute{Method: "POST", Path: "/v2/ep1/run"}
	grant := cappedGrant(base, map[HostRoute]int{submit: 1}, HostRoute{Method: "POST", Path: "/v2/EP1/run"}, submit)
	core, err := brokerSessionForGrant(context.Background(), grant, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	for _, c := range []struct {
		target string
		status int
	}{{"/v2/ep1/run", 200}, {"/v2/EP1/run", 429}, {"/v2/Ep1/run", http.StatusForbidden}} {
		if got := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: c.target}).Status; got != c.status {
			t.Fatalf("%s = %d, want %d", c.target, got, c.status)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("the API was reached %d times, want 1", n)
	}
}

// Every constructor a session's granted call goes through keeps the budget it is given:
// the guard registry (E2B's per-call rule), E2B's session rule, and the GrantBroker that
// OpenShell uses.
func TestSessionGrantPathsUseTheSessionsBudget(t *testing.T) {
	base, _ := jobsAPI(t)
	submit := HostRoute{Method: "POST", Path: "/v2/ep1/run"}
	grant := cappedGrant(base, map[HostRoute]int{submit: 1}, submit)
	session := NewRouteBudget()

	var g guardRegistry
	_, core, cleanup, err := g.open(context.Background(), grant, time.Minute, session)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if core.routes != session {
		t.Error("the guard registry's core does not charge the session's budget")
	}

	gb, err := NewGrantBroker(context.Background(), grant, time.Minute, session)
	if err != nil {
		t.Fatal(err)
	}
	defer gb.Close()
	if gb.core.routes != session {
		t.Error("the GrantBroker's core does not charge the session's budget")
	}

	slot := &grantSlot{}
	rule := &e2bSessionRule{slot: slot, unregister: func() {}}
	core, release, err := rule.lend(context.Background(), &e2bSession{routes: session}, grant, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	defer core.Close()
	if core.routes != session {
		t.Error("E2B's session rule's core does not charge the session's budget")
	}
}

// Two spellings of one route that calls match without regard to case are one count:
// the round-3 review found the shared count still keyed by the spelling, so a profile
// spelling "/v2/EP1/run" and another "/v2/ep1/run" each allowed a call against a cap of
// one. Within one grant, two such entries charge the call once, against the tighter cap.
func TestRouteCapCountsSpellingsOfOneRouteOnce(t *testing.T) {
	base, hits := jobsAPI(t)
	lower := HostRoute{Method: "POST", Path: "/v2/ep1/run"}
	upper := HostRoute{Method: "POST", Path: "/v2/EP1/run"}
	a := cappedGrant(base, map[HostRoute]int{lower: 1}, lower)
	b := cappedGrant(base, map[HostRoute]int{upper: 1}, upper)
	session := NewRouteBudget()
	calls(t, a, session, "/v2/ep1/run", 1)
	if got := calls(t, b, session, "/v2/EP1/run", 1); got[0] != http.StatusTooManyRequests {
		t.Fatalf("the second profile's call after the first spent the cap: %v, want 429", got)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("the API was reached %d times, want 1", n)
	}

	hits.Store(0)
	both := cappedGrant(base, map[HostRoute]int{lower: 2, upper: 3}, lower, upper)
	if got := calls(t, both, nil, "/v2/ep1/run", 3); got[0] != 200 || got[1] != 200 || got[2] != http.StatusTooManyRequests {
		t.Fatalf("one grant with both spellings capped 2 and 3: %v, want two calls then 429 (charged once, the tighter cap)", got)
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("the API was reached %d times, want 2", n)
	}
}

// Two profiles may write the same origin either way: with the port its scheme implies
// or without it. Both reach the same API, so a session's cap on a route counts their
// calls together (round-4 review, 2026-10-08).
func TestRouteCapsSpanBothSpellingsOfAnOrigin(t *testing.T) {
	route := HostRoute{Method: "POST", Path: "/v2/ep1/run"}
	caps := map[HostRoute]int{route: 1}
	session := NewRouteBudget()
	if !session.charge("https://api.example", []HostRoute{route}, caps) {
		t.Fatal("the first call was refused")
	}
	for _, origin := range []string{"https://api.example:443", "https://API.example", "https://api.example", "https://api.example:0443", "https://api.example."} {
		if session.charge(origin, []HostRoute{route}, caps) {
			t.Fatalf("a second call through %q was admitted; want the cap of one to span every spelling of the origin", origin)
		}
	}
	// An IPv6 literal keeps its brackets, so its two spellings key alike too.
	six := NewRouteBudget()
	if !six.charge("https://[2001:db8::1]", []HostRoute{route}, caps) {
		t.Fatal("the first call to an IPv6 origin was refused")
	}
	for _, origin := range []string{"https://[2001:db8::1]:443", "https://[2001:DB8::1]", "https://[2001:db8:0:0:0:0:0:1]", "https://[2001:db8::1]:0443"} {
		if six.charge(origin, []HostRoute{route}, caps) {
			t.Fatalf("a second call through %q was admitted; want the cap of one to span every spelling of the origin", origin)
		}
	}
	// A different origin keeps its own count, port or no port.
	if !session.charge("https://other.example:8443", []HostRoute{route}, caps) {
		t.Fatal("another origin's first call was refused")
	}
	if !session.charge("http://api.example", []HostRoute{route}, caps) {
		t.Fatal("another scheme's first call was refused")
	}
}

// The key is exact about what it normalizes: a different port or a different host is
// another origin, and an origin it cannot parse is keyed as written.
func TestCanonicalOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.example":         "https://api.example",
		"HTTPS://API.Example:443":     "https://api.example",
		"https://api.example.:0443":   "https://api.example",
		"https://api.example:8443":    "https://api.example:8443",
		"http://api.example:80":       "http://api.example",
		"http://api.example:443":      "http://api.example:443",
		"https://[2001:db8:0::1]:443": "https://[2001:db8::1]",
		"https://[::ffff:192.0.2.1]":  "https://192.0.2.1",
		"https://192.0.2.1:0443":      "https://192.0.2.1",
		"https://api.example:99999":   "https://api.example:99999",
	} {
		if got := canonicalOrigin(in); got != want {
			t.Errorf("canonicalOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}
