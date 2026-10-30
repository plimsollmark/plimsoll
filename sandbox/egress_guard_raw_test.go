package sandbox

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestEgressGuardRawRouteCarriesAStandardClientsRequest: on the guard's raw route a
// standard client's request (its path under the route's prefix, its headers, its JSON
// body) reaches the broker core as the guest sent it: the route is matched on the
// remaining target, the grant's pass list decides the headers, the credential is the
// broker's, and the upstream's answer comes back bare.
func TestEgressGuardRawRouteCarriesAStandardClientsRequest(t *testing.T) {
	t.Parallel()
	var seen http.Header
	var seenPath, seenBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		seenPath = r.URL.RequestURI()
		b, _ := io.ReadAll(r.Body)
		seenBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"msg_1"}`)
	}))
	defer upstream.Close()
	reg := &guardRegistry{}
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "POST", Path: "/v1/messages"}}, Minter: StaticToken("minted"), PassHeaders: []string{"anthropic-version"}}
	token, _, cleanup, err := reg.open(context.Background(), grant, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	h := EgressGuardHTTPHandler(&registryGuard{reg: reg}, "/v1/e2b/guard", 0, 0)
	// A client sends an origin-form target; a proxy in front of the guard may send the
	// absolute form. Both name the same route.
	for _, target := range []string{"/v1/e2b/guard/raw/v1/messages", "https://guard.example/v1/e2b/guard/raw/v1/messages"} {
		seen, seenPath, seenBody = nil, "", ""
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"model":"x"}`))
		for name, vals := range sdkRequestHeaders() {
			if name == "Content-Length" || name == "Transfer-Encoding" || name == "Host" {
				continue // the test request's own framing; a real client's are consistent with its body
			}
			req.Header[http.CanonicalHeaderKey(name)] = vals
		}
		req.Header.Set(EgressGuardHeader, token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated || rec.Header().Get(brokerNoRetryHeader) != "" || rec.Body.String() != `{"id":"msg_1"}` {
			t.Fatalf("%s: answer = %d %q %q, want the upstream's 201 bare", target, rec.Code, rec.Header().Get(brokerNoRetryHeader), rec.Body.String())
		}
		if seenPath != "/v1/messages" || seenBody != `{"model":"x"}` {
			t.Errorf("%s: upstream saw %s %q", target, seenPath, seenBody)
		}
		if got := seen.Get("Authorization"); got != "Bearer minted" {
			t.Errorf("%s: Authorization = %q", target, got)
		}
		if got := seen.Get("anthropic-version"); got != "2026-10-21" {
			t.Errorf("%s: anthropic-version = %q", target, got)
		}
		for _, name := range []string{"X-Api-Key", "Anthropic-Beta", "X-Stainless-Lang", EgressGuardHeader, "Cookie", "X-Forwarded-For"} {
			if _, present := seen[http.CanonicalHeaderKey(name)]; present {
				t.Errorf("%s: %s reached the upstream", target, name)
			}
		}
	}
}

func TestRequestTarget(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"/v1/x":                          "/v1/x",
		"/v1/x?y=1":                      "/v1/x?y=1",
		"https://guard.example/v1/x":     "/v1/x",
		"https://guard.example/v1/x?y":   "/v1/x?y",
		"http://guard.example":           "http://guard.example",
		"guard.example:443":              "guard.example:443",
		"*":                              "*",
		"//evil.example/v1/x":            "//evil.example/v1/x",
		"https://guard.example//v1/x":    "//v1/x",
		"https://a@guard.example/v1/x":   "/v1/x",
		"https://guard.example:443/v1/x": "/v1/x",
	} {
		if got := requestTarget(in); got != want {
			t.Errorf("requestTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEgressGuardRawRouteRefusesWhatIsNotTheRoute: everything around the raw route is
// refused before the upstream: a path that is not under the prefix, a target the core
// would not approve (a query, a traversal, an encoded byte), a body over the request cap,
// an unknown credential; each answer carries the no-retry mark.
func TestEgressGuardRawRouteRefusesWhatIsNotTheRoute(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer upstream.Close()
	reg := &guardRegistry{}
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/messages"}, {Method: "POST", Path: "/v1/messages"}}}
	token, _, cleanup, err := reg.open(context.Background(), grant, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	h := EgressGuardHTTPHandler(&registryGuard{reg: reg}, "/v1/e2b/guard", 0, 0)
	for _, tc := range []struct {
		method, target, tok string
		body                string
		length              int64
		want                int
	}{
		{"GET", "/v1/e2b/guard/raw", token, "", 0, http.StatusNotFound},
		{"GET", "/v1/e2b/guard/rawx/v1/messages", token, "", 0, http.StatusNotFound},
		{"GET", "/v1/e2b/guard/raw//v1/messages", token, "", 0, http.StatusForbidden},
		{"GET", "/v1/e2b/guard/raw/v1/messages/", token, "", 0, http.StatusForbidden},
		{"GET", "/v1/e2b/guard/raw/v1/messages?stream=true", token, "", 0, http.StatusForbidden},
		{"GET", "/v1/e2b/guard/raw/../v1/messages", token, "", 0, http.StatusForbidden},
		{"GET", "/v1/e2b/guard/raw/v1/%6dessages", token, "", 0, http.StatusForbidden},
		{"DELETE", "/v1/e2b/guard/raw/v1/messages", token, "", 0, http.StatusForbidden},
		{"GET", "/v1/e2b/guard/raw/v1/messages", "crg_unknown", "", 0, http.StatusUnauthorized},
		{"POST", "/v1/e2b/guard/raw/v1/messages", token, "x", maxHostRequestBytes + 1, http.StatusRequestEntityTooLarge},
	} {
		req := httptest.NewRequest(tc.method, "https://guard.example"+tc.target, strings.NewReader(tc.body))
		if tc.length != 0 {
			req.ContentLength = tc.length
		}
		req.Header.Set(EgressGuardHeader, tc.tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want || rec.Header().Get(brokerNoRetryHeader) != "false" {
			t.Errorf("%s %s: %d %q, want %d and the no-retry mark", tc.method, tc.target, rec.Code, rec.Header().Get(brokerNoRetryHeader), tc.want)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("upstream reached %d times", n)
	}
	req := httptest.NewRequest(http.MethodGet, "https://guard.example/v1/e2b/guard/raw/v1/messages", nil)
	req.Header.Set(EgressGuardHeader, token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("the plain route: %d, upstream hits %d", rec.Code, hits.Load())
	}
}
