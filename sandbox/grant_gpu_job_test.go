package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// gpuJobAPI stands in for a GPU job service shaped like RunPod's serverless API: POST
// /v2/{endpoint}/run queues a job, GET /v2/{endpoint}/status/{id} reports it in
// progress once and then completed with its output. It counts the jobs started.
type gpuJobAPI struct {
	mu     sync.Mutex
	jobs   map[string]int // job ID -> status reads so far
	inputs map[string]float64
}

func (a *gpuJobAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v2/ep1/run":
		var req struct {
			Input struct {
				N float64 `json:"n"`
			} `json:"input"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, `{"error":"bad input"}`, http.StatusBadRequest)
			return
		}
		id := fmt.Sprintf("job-%d", len(a.jobs)+1)
		a.jobs[id], a.inputs[id] = 0, req.Input.N
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "IN_QUEUE"})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/ep1/status/"):
		id := strings.TrimPrefix(r.URL.Path, "/v2/ep1/status/")
		reads, ok := a.jobs[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		a.jobs[id] = reads + 1
		if reads == 0 {
			_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "IN_PROGRESS"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "status": "COMPLETED", "output": map[string]float64{"square": a.inputs[id] * a.inputs[id]}})
	default:
		http.NotFound(w, r)
	}
}

// Agent code reaches a GPU job service through a grant: it starts jobs, polls them to
// completion and reads their output, while the route that starts a job, the one that
// spends, refuses past its cap and another endpoint of the account is refused outright.
func TestGrantGPUJobRouteCap(t *testing.T) {
	t.Parallel()
	api := &gpuJobAPI{jobs: map[string]int{}, inputs: map[string]float64{}}
	upstream := httptest.NewServer(api)
	defer upstream.Close()
	submit := HostRoute{Method: "POST", Path: "/v2/ep1/run"}
	grant := &HostAPIGrant{
		BaseURL:       upstream.URL,
		Allow:         []HostRoute{submit, {Method: "GET", Path: "/v2/ep1/status/*"}},
		Minter:        StaticToken("gpu-key"),
		RouteMaxCalls: map[HostRoute]int{submit: 2},
	}
	code := `(async () => {
  for (const n of [3, 4]) {
    const job = await host.post("/v2/ep1/run", {input: {n}});
    let s = job;
    while (s.status !== "COMPLETED") s = await host.get("/v2/ep1/status/" + job.id);
    console.log("job", job.id, s.output.square);
  }
  await host.post("/v2/ep1/run", {input: {n: 5}}).then(() => console.log("third: started"), e => console.log("third:", e.message));
  await host.get("/v2/ep2/status/job-1").then(() => console.log("other: reached"), e => console.log("other:", e.message));
})();`
	res, err := testWasm().RunJavaScript(context.Background(), Request{Code: code, Grant: grant})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	for _, want := range []string{"job job-1 9", "job job-2 16", "third: host api 429", "other: host api call not permitted"} {
		if !strings.Contains(res.Stdout, want) {
			t.Fatalf("stdout lacks %q: exit %d stdout=%q stderr=%q", want, res.ExitCode, res.Stdout, res.Stderr)
		}
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.jobs) != 2 {
		t.Fatalf("the service started %d jobs, want the cap's 2", len(api.jobs))
	}
}

// RouteMaxCalls names only entries of Allow, each with a positive cap, and a clone
// does not share it.
func TestGrantRouteMaxCallsValidation(t *testing.T) {
	submit := HostRoute{Method: "POST", Path: "/v2/ep1/run"}
	grant := func(caps map[HostRoute]int) *HostAPIGrant {
		return &HostAPIGrant{BaseURL: "https://api.example.com", Allow: []HostRoute{submit}, Minter: StaticToken("t"), RouteMaxCalls: caps}
	}
	if err := grant(map[HostRoute]int{submit: 1}).Validate(); err != nil {
		t.Fatalf("a cap on an allowed route: %v", err)
	}
	for name, caps := range map[string]map[HostRoute]int{
		"not in Allow":     {{Method: "POST", Path: "/v2/ep2/run"}: 1},
		"another case":     {{Method: "post", Path: "/v2/ep1/run"}: 1},
		"zero":             {submit: 0},
		"past the ceiling": {submit: MaxHostCallsCeiling + 1},
	} {
		if grant(caps).Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	g := grant(map[HostRoute]int{submit: 1})
	c := g.Clone()
	c.RouteMaxCalls[submit] = 5
	if !maps.Equal(g.RouteMaxCalls, map[HostRoute]int{submit: 1}) {
		t.Fatal("a clone shares RouteMaxCalls with its original")
	}
}

// A cap compares segments as written, while an upstream may serve "ep1.json", "0123" or
// "ep1." as "ep1" or "123". So a grant is refused when another entry of the same method
// matches a capped entry's calls with a "*" where the capped entry has a fixed segment
// (the 9 October scan, F2 and F3): a call spelled for the wildcard alone would reach the
// capped route uncounted. Entries that cannot carry such a call stay accepted.
func TestGrantRefusesAWildcardAroundACap(t *testing.T) {
	r := func(method, path string) HostRoute { return HostRoute{Method: method, Path: path} }
	ep1 := r("POST", "/v2/ep1/run")
	cases := []struct {
		name   string
		allow  []HostRoute
		caps   map[HostRoute]int
		refuse bool
	}{
		{"an uncapped wildcard over the capped segment", []HostRoute{ep1, r("POST", "/v2/*/run")}, map[HostRoute]int{ep1: 2}, true},
		{"its method spelled in lower case", []HostRoute{ep1, r("post", "/v2/*/run")}, map[HostRoute]int{ep1: 2}, true},
		{"a wildcard over another fixed segment", []HostRoute{ep1, r("POST", "/*/ep1/run")}, map[HostRoute]int{ep1: 2}, true},
		{"fixed segments equal but for case", []HostRoute{ep1, r("POST", "/V2/*/run")}, map[HostRoute]int{ep1: 2}, true},
		{"a wider route with a cap of its own", []HostRoute{ep1, r("POST", "/v2/*/run")}, map[HostRoute]int{ep1: 2, r("POST", "/v2/*/run"): 100}, true},
		{"crossing wildcards, each capped", []HostRoute{r("POST", "/a/*/c"), r("POST", "/a/b/*")}, map[HostRoute]int{r("POST", "/a/*/c"): 1, r("POST", "/a/b/*"): 2}, true},
		{"the wider route capped, the narrower not", []HostRoute{ep1, r("POST", "/v2/*/run")}, map[HostRoute]int{r("POST", "/v2/*/run"): 2}, false},
		{"another method", []HostRoute{ep1, r("GET", "/v2/*/run")}, map[HostRoute]int{ep1: 2}, false},
		{"another number of segments", []HostRoute{ep1, r("POST", "/v2/*")}, map[HostRoute]int{ep1: 2}, false},
		{"a fixed segment that differs", []HostRoute{ep1, r("POST", "/v3/*/run")}, map[HostRoute]int{ep1: 2}, false},
		{"a case variant of the capped route", []HostRoute{ep1, r("POST", "/v2/EP1/run")}, map[HostRoute]int{ep1: 2}, false},
	}
	for _, tc := range cases {
		g := &HostAPIGrant{BaseURL: "https://api.example.com", Allow: tc.allow, Minter: StaticToken("t"), RouteMaxCalls: tc.caps}
		err := g.Validate()
		if tc.refuse && err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
		if !tc.refuse && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// A route cap holds whatever order allow is written in. The 8 October security review
// found that the broker charged only the first entry a call matched, so an uncapped
// entry written before a capped one let calls through. Each case runs with allow in
// both orders, and the concurrent case shows that calls arriving together cannot
// share a cap's last call. (A wildcard that widens a capped entry's fixed segment is
// refused by Validate, TestGrantRefusesAWildcardAroundACap, so the overlaps left are a
// capped wildcard over narrower entries and spellings of one route.)
func TestRouteCapHoldsWhateverEntryMatchesFirst(t *testing.T) {
	t.Parallel()
	type call struct {
		target string
		status int
	}
	cases := map[string]struct {
		allow []HostRoute
		caps  map[HostRoute]int
		calls []call
	}{
		"a capped wildcard beside an exact route it covers": {
			allow: []HostRoute{{Method: "POST", Path: "/v2/*/run"}, {Method: "POST", Path: "/v2/ep1/run"}},
			caps:  map[HostRoute]int{{Method: "POST", Path: "/v2/*/run"}: 2},
			calls: []call{{"/v2/ep1/run", 200}, {"/v2/ep2/run", 200}, {"/v2/ep1/run", 429}, {"/v2/ep3/run", 429}},
		},
		"two spellings of one route, each capped": {
			allow: []HostRoute{{Method: "POST", Path: "/a/*/c"}, {Method: "POST", Path: "/A/*/c"}},
			caps:  map[HostRoute]int{{Method: "POST", Path: "/a/*/c"}: 1, {Method: "POST", Path: "/A/*/c"}: 3},
			// Either spelling spends from both caps, so the tighter one decides.
			calls: []call{{"/a/b/c", 200}, {"/A/x/c", 429}, {"/a/y/c", 429}},
		},
	}
	for name, tc := range cases {
		for _, reversed := range []bool{false, true} {
			allow := slices.Clone(tc.allow)
			if reversed {
				slices.Reverse(allow)
			}
			t.Run(fmt.Sprintf("%s/reversed=%v", name, reversed), func(t *testing.T) {
				reached := 0
				core, err := newBrokerSession(&HostAPIGrant{
					BaseURL: "https://api.internal", Allow: allow, RouteMaxCalls: tc.caps,
				}, "", brokerRoundTripFunc(func(*http.Request) (*http.Response, error) {
					reached++
					return jsonResp(http.StatusOK, "", `{}`), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				defer core.Close()
				want := 0
				for i, c := range tc.calls {
					got := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: c.target})
					if got.Status != c.status {
						t.Fatalf("call %d to %s = %d, want %d", i, c.target, got.Status, c.status)
					}
					if c.status == 200 {
						want++
					}
				}
				if reached != want {
					t.Fatalf("the API was reached %d times, want %d", reached, want)
				}
			})
		}
	}

	t.Run("concurrent calls", func(t *testing.T) {
		for _, reversed := range []bool{false, true} {
			allow := []HostRoute{{Method: "POST", Path: "/v2/*/run"}, {Method: "POST", Path: "/v2/ep1/run"}}
			if reversed {
				slices.Reverse(allow)
			}
			var reached atomic.Int64
			core, err := newBrokerSession(&HostAPIGrant{
				BaseURL: "https://api.internal", Allow: allow,
				RouteMaxCalls: map[HostRoute]int{{Method: "POST", Path: "/v2/*/run"}: 5},
			}, "", brokerRoundTripFunc(func(*http.Request) (*http.Response, error) {
				reached.Add(1)
				return jsonResp(http.StatusOK, "", `{}`), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for range maxHostConcurrent {
				wg.Go(func() { core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v2/ep1/run"}) })
			}
			wg.Wait()
			core.Close()
			if n := reached.Load(); n != 5 {
				t.Fatalf("reversed=%v: %d concurrent calls reached the API %d times, want the cap's 5", reversed, maxHostConcurrent, n)
			}
		}
	})
}
