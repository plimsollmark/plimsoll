package sandbox

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// sdkRequestHeaders is the header set the OpenAI and Anthropic client libraries send on a
// create call (their Stainless base clients, read 2026-10-28), with a dummy credential in
// the two places a client puts one. A broker that lets any of these through except the
// listed API headers leaks the guest's telemetry, or worse its own say over
// authentication, to the operator's API.
func sdkRequestHeaders() map[string][]string {
	return map[string][]string{
		"Authorization":               {"Bearer dummy-key-from-the-guest"},
		"X-Api-Key":                   {"dummy-from-the-guest"},
		"Anthropic-Version":           {"2026-10-21"},
		"Anthropic-Beta":              {"files-api-2026-10-21"},
		"Openai-Beta":                 {"assistants=v2"},
		"Openai-Organization":         {"org-guest"},
		"Accept":                      {"application/json"},
		"Accept-Encoding":             {"br, gzip"},
		"Content-Type":                {"text/plain"},
		"Content-Length":              {"99999"},
		"Host":                        {"evil.example"},
		"User-Agent":                  {"OpenAI/Python 2.0.0"},
		"X-Stainless-Lang":            {"python"},
		"X-Stainless-Package-Version": {"2.0.0"},
		"X-Stainless-Retry-Count":     {"0"},
		"X-Stainless-Read-Timeout":    {"600"},
		"Cookie":                      {"session=guest"},
		"Transfer-Encoding":           {"chunked"},
		"X-Forwarded-For":             {"guest"},
		EgressGuardHeader:             {"crg_guest"},
	}
}

// TestBrokerCoreForwardsOnlyPassListedHeaders: a grant that lists anthropic-version and
// OpenAI-Organization gets exactly those from a standard client's request, in the grant's
// spelling; the dummy credentials, the telemetry, the connection headers and the
// unlisted API header never reach the upstream, and the broker's own credential and
// body type stand.
func TestBrokerCoreForwardsOnlyPassListedHeaders(t *testing.T) {
	t.Parallel()
	var seen http.Header
	transport := brokerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = req.Header.Clone()
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	grant := &HostAPIGrant{
		BaseURL:     "https://api.internal",
		Allow:       []HostRoute{{Method: "POST", Path: "/v1/messages"}},
		PassHeaders: []string{"anthropic-version", "OpenAI-Organization"},
	}
	core, err := newBrokerSession(grant, "broker-token", transport)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v1/messages", Headers: sdkRequestHeaders(), Body: strings.NewReader(`{"model":"x"}`)})
	if resp.Status != http.StatusOK || resp.FromBroker {
		t.Fatalf("response = %+v", resp)
	}
	if got := seen.Get("Authorization"); got != "Bearer broker-token" {
		t.Errorf("Authorization = %q, want the broker's credential", got)
	}
	if got := seen.Get("anthropic-version"); got != "2026-10-21" {
		t.Errorf("anthropic-version = %q, want the guest's", got)
	}
	if got := seen.Get("OpenAI-Organization"); got != "org-guest" {
		t.Errorf("OpenAI-Organization = %q, want the guest's", got)
	}
	if got := seen.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want the broker's", got)
	}
	for _, name := range []string{"X-Api-Key", "Anthropic-Beta", "Openai-Beta", "Cookie", "X-Stainless-Lang", "X-Stainless-Package-Version",
		"X-Stainless-Retry-Count", "X-Stainless-Read-Timeout", "X-Forwarded-For", EgressGuardHeader, "Transfer-Encoding"} {
		if _, present := seen[http.CanonicalHeaderKey(name)]; present {
			t.Errorf("%s reached the upstream: %q", name, seen.Values(name))
		}
	}
	if got := seen.Get("User-Agent"); got == "OpenAI/Python 2.0.0" {
		t.Errorf("the guest's User-Agent reached the upstream")
	}
	if got := seen.Get("Accept-Encoding"); strings.Contains(got, "br") {
		t.Errorf("the guest's Accept-Encoding reached the upstream: %q", got)
	}
}

// TestBrokerCoreSetsTheGrantsOwnHeaders: a header the grant sets reaches the upstream
// with the grant's value whatever the guest sent under that name, in any case, and a
// passed header beside it still comes from the guest. The choice of workspace or project
// the run's credential acts in stays the operator's.
func TestBrokerCoreSetsTheGrantsOwnHeaders(t *testing.T) {
	t.Parallel()
	var seen http.Header
	transport := brokerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = req.Header.Clone()
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	grant := &HostAPIGrant{
		BaseURL:     "https://api.internal",
		Allow:       []HostRoute{{Method: "POST", Path: "/v1/messages"}},
		PassHeaders: []string{"anthropic-version"},
		SetHeaders:  map[string]string{"anthropic-workspace-id": "wrkspc_operator", "OpenAI-Project": "proj_operator"},
	}
	if err := grant.Validate(); err != nil {
		t.Fatal(err)
	}
	core, err := newBrokerSession(grant, "broker-token", transport)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	headers := sdkRequestHeaders()
	headers["Anthropic-Workspace-Id"] = []string{"wrkspc_guest"}
	headers["openai-project"] = []string{"proj_guest"}
	resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v1/messages", Headers: headers, Body: strings.NewReader(`{"model":"x"}`)})
	if resp.Status != http.StatusOK || resp.FromBroker {
		t.Fatalf("response = %+v", resp)
	}
	for name, want := range map[string]string{"anthropic-workspace-id": "wrkspc_operator", "OpenAI-Project": "proj_operator", "anthropic-version": "2026-10-21", "Authorization": "Bearer broker-token"} {
		if got := seen.Values(name); len(got) != 1 || got[0] != want {
			t.Errorf("%s = %q, want only %q", name, got, want)
		}
	}
	// A call that sends none of them gets the grant's values too.
	resp = core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v1/messages", Body: strings.NewReader(`{"model":"x"}`)})
	if resp.Status != http.StatusOK || seen.Get("anthropic-workspace-id") != "wrkspc_operator" || seen.Get("OpenAI-Project") != "proj_operator" {
		t.Fatalf("a call with no headers: status %d, workspace %q, project %q", resp.Status, seen.Get("anthropic-workspace-id"), seen.Get("OpenAI-Project"))
	}
}

// TestHostAPIGrantValidateSetHeaders: a grant may set an ordinary API header, never one
// the broker, the transport or an API key owns, never with a value that is not a plain
// field value, and never one it also passes from the guest.
func TestHostAPIGrantValidateSetHeaders(t *testing.T) {
	t.Parallel()
	base := func(set map[string]string, pass ...string) *HostAPIGrant {
		return &HostAPIGrant{BaseURL: "https://api.internal", Allow: []HostRoute{{Method: "GET", Path: "/v1/models"}}, PassHeaders: pass, SetHeaders: set}
	}
	for _, name := range []string{"Authorization", "Cookie", "Host", "Content-Type", "Content-Length", "Transfer-Encoding", "X-Forwarded-For",
		EgressGuardHeader, "x-plimsoll-anything", "X-Api-Key", "x-goog-api-key", "Api-Key", "Ocp-Apim-Subscription-Key", "", "bad name", "name:"} {
		if err := base(map[string]string{name: "v"}).Validate(); err == nil {
			t.Errorf("Validate accepted SetHeaders name %q", name)
		}
	}
	for _, value := range []string{"", "a\nb", "a\rb", "caf\u00e9", " padded", "padded\t", strings.Repeat("x", maxPassHeaderValueBytes+1)} {
		if err := base(map[string]string{"anthropic-workspace-id": value}).Validate(); err == nil {
			t.Errorf("Validate accepted SetHeaders value %q", value)
		}
	}
	if err := base(map[string]string{"openai-project": "proj_1"}, "OpenAI-Project").Validate(); err == nil || !strings.Contains(err.Error(), "one owner") {
		t.Errorf("a header both passed and set: %v", err)
	}
	if err := base(map[string]string{"OpenAI-Project": "proj_1", "openai-project": "proj_2"}).Validate(); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a header set twice by case: %v", err)
	}
	if err := base(map[string]string{"anthropic-workspace-id": "wrkspc_01", "OpenAI-Organization": "org-1", "OpenAI-Project": "proj_1", "anthropic-version": "2023-06-01"},
		"anthropic-beta").Validate(); err != nil {
		t.Errorf("Validate refused ordinary set headers: %v", err)
	}
}

// TestBrokerCoreDropsHostilePassedValues: a listed header whose value could split the
// request or carry bytes the guest did not send as text is dropped whole, never cleaned.
func TestBrokerCoreDropsHostilePassedValues(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		value string
		want  bool
	}{
		"plain":      {"2026-10-21", true},
		"with tab":   {"a\tb", true},
		"crlf":       {"2026-10-21\r\nX-Injected: yes", false},
		"lf":         {"a\nb", false},
		"nul":        {"a\x00b", false},
		"del":        {"a\x7fb", false},
		"non-ascii":  {"café", false},
		"over cap":   {strings.Repeat("a", maxPassHeaderValueBytes+1), false},
		"at cap":     {strings.Repeat("a", maxPassHeaderValueBytes), true},
		"empty":      {"", true},
		"only space": {" ", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var seen http.Header
			transport := brokerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				seen = req.Header.Clone()
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(``))}, nil
			})
			grant := &HostAPIGrant{BaseURL: "https://api.internal", Allow: []HostRoute{{Method: "GET", Path: "/v1/models"}}, PassHeaders: []string{"anthropic-version"}}
			core, err := newBrokerSession(grant, "t", transport)
			if err != nil {
				t.Fatal(err)
			}
			defer core.Close()
			core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/v1/models", Headers: map[string][]string{"Anthropic-Version": {tc.value, "second value ignored"}}})
			vals, present := seen["Anthropic-Version"]
			if present != tc.want {
				t.Fatalf("forwarded = %v (%q), want %v", present, vals, tc.want)
			}
			if present && (len(vals) != 1 || vals[0] != tc.value) {
				t.Fatalf("forwarded %q, want exactly the first value %q", vals, tc.value)
			}
		})
	}
}

func TestHostAPIGrantValidatePassHeaders(t *testing.T) {
	t.Parallel()
	base := func(names ...string) *HostAPIGrant {
		return &HostAPIGrant{BaseURL: "https://api.internal", Allow: []HostRoute{{Method: "GET", Path: "/v1/models"}}, PassHeaders: names}
	}
	for _, name := range []string{"Authorization", "proxy-authorization", "Cookie", "Host", "Content-Length", "content-type", "Transfer-Encoding",
		"Connection", "Upgrade", "TE", "Trailer", "Keep-Alive", "Expect", "Forwarded", "Via", "Accept-Encoding", "X-Forwarded-For", "x-forwarded-host",
		EgressGuardHeader, "x-plimsoll-anything", "Proxy-Connection", "", "bad name", "anthropic version", "name:", "étiquette",
		// An API key header: the guest's own key would ride beside the broker's credential.
		"X-Api-Key", "x-goog-api-key", "Api-Key", "Ocp-Apim-Subscription-Key"} {
		if err := base(name).Validate(); err == nil {
			t.Errorf("Validate accepted PassHeaders entry %q", name)
		}
	}
	if err := base("Anthropic-Version", "anthropic-version").Validate(); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate by case: %v", err)
	}
	if err := base("anthropic-version", "anthropic-beta", "OpenAI-Beta", "OpenAI-Organization", "Accept", "Idempotency-Key").Validate(); err != nil {
		t.Errorf("Validate refused ordinary API headers: %v", err)
	}
}

func TestHostAPIGrantValidateSDKEnvAndRendersIt(t *testing.T) {
	t.Parallel()
	base := func(env map[string]string) *HostAPIGrant {
		return &HostAPIGrant{BaseURL: "https://api.internal", Allow: []HostRoute{{Method: "GET", Path: "/v1/models"}}, SDKEnv: env}
	}
	for _, name := range []string{"PATH", "HOME", "HOSTNAME", "NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "LD_PRELOAD", "LD_LIBRARY_PATH", "GLIBC_TUNABLES",
		"LOCPATH", "NLSPATH", "GCONV_PATH", HostAPISocketEnv, HostAPIListenEnv, "PLIMSOLL_RUNNER_PID", "PLIMSOLL_X", "openai_base_url", "1KEY", "KEY-NAME", "KEY NAME", "", "KÉY"} {
		if err := base(map[string]string{name: "x"}).Validate(); err == nil {
			t.Errorf("Validate accepted SDKEnv name %q", name)
		}
	}
	for _, value := range []string{"a\nb", "a\rb", "a\x00b", "a\x1bb", strings.Repeat("v", maxSDKEnvValueBytes+1)} {
		if err := base(map[string]string{"OPENAI_API_KEY": value}).Validate(); err == nil {
			t.Errorf("Validate accepted SDKEnv value %q", value)
		}
	}
	g := base(map[string]string{"OPENAI_BASE_URL": "{origin}/v1", "OPENAI_API_KEY": "plimsoll-grant", "ANTHROPIC_BASE_URL": "{origin}"})
	if err := g.Validate(); err != nil {
		t.Fatalf("Validate refused a plain SDKEnv: %v", err)
	}
	got := g.sdkEnv("http://127.0.0.1:8471")
	want := []string{"ANTHROPIC_BASE_URL=http://127.0.0.1:8471", "OPENAI_API_KEY=plimsoll-grant", "OPENAI_BASE_URL=http://127.0.0.1:8471/v1"}
	if !slices.Equal(got, want) {
		t.Fatalf("sdkEnv = %q, want %q", got, want)
	}
	if (&HostAPIGrant{}).sdkEnv("http://x") != nil || (*HostAPIGrant)(nil).sdkEnv("http://x") != nil {
		t.Fatal("an empty or nil grant renders an environment")
	}
	// Clone keeps the two new fields independent of the original.
	c := g.Clone()
	c.PassHeaders = append(c.PassHeaders, "x")
	c.SDKEnv["OPENAI_API_KEY"] = "changed"
	if len(g.PassHeaders) != 0 || g.SDKEnv["OPENAI_API_KEY"] != "plimsoll-grant" {
		t.Fatal("Clone shares PassHeaders or SDKEnv with the original")
	}
}

// rawSocketRequest writes one raw HTTP/1.1 request over the broker's socket and returns
// the status line and headers, so a target no client library would form (absolute-form,
// a CONNECT authority, the asterisk) reaches the server as written.
func rawSocketRequest(t *testing.T, sock, requestLine string, extra ...string) (status string, header http.Header) {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial socket: %v", err)
	}
	defer conn.Close()
	msg := requestLine + "\r\nHost: api.internal\r\n"
	for _, h := range extra {
		msg += h + "\r\n"
	}
	msg += "\r\n"
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response to %q: %v", requestLine, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Status, resp.Header
}

// TestBrokerSocketRefusesTargetsThatNameAnOrigin: on the socket a standard client speaks
// to, a request that names its own destination (an absolute-form target, a CONNECT
// authority, the server-wide asterisk) is refused before the upstream, with the no-retry
// header, so the local address is not a proxy to anywhere.
func TestBrokerSocketRefusesTargetsThatNameAnOrigin(t *testing.T) {
	t.Parallel()
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/items"}, {Method: "POST", Path: "/v1/items"}}}
	b, err := startDockerBroker(grant, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, line := range []string{
		"GET http://evil.example/v1/items HTTP/1.1",
		"GET " + upstream.URL + "/v1/items HTTP/1.1",
		"CONNECT api.internal:443 HTTP/1.1",
		"GET //evil.example/v1/items HTTP/1.1",
		"GET /v1/items?x=1 HTTP/1.1",
		"GET /v1/items#frag HTTP/1.1",
	} {
		status, header := rawSocketRequest(t, b.sock, line)
		if !strings.HasPrefix(status, "403") && !strings.HasPrefix(status, "400") {
			t.Errorf("%q: status %q, want a refusal", line, status)
		}
		if strings.HasPrefix(status, "403") && header.Get(brokerNoRetryHeader) != "false" {
			t.Errorf("%q: %s = %q, want false", line, brokerNoRetryHeader, header.Get(brokerNoRetryHeader))
		}
	}
	// "OPTIONS *" is answered by Go's server itself (200, no body) before any handler
	// runs; it reaches neither the broker nor the upstream.
	if status, _ := rawSocketRequest(t, b.sock, "OPTIONS * HTTP/1.1"); !strings.HasPrefix(status, "200") {
		t.Errorf("OPTIONS *: status %q, want Go's own 200", status)
	}
	if n := upstreamHits.Load(); n != 0 {
		t.Fatalf("upstream reached %d times by refused targets", n)
	}
	status, header := rawSocketRequest(t, b.sock, "GET /v1/items HTTP/1.1")
	if !strings.HasPrefix(status, "200") || header.Get(brokerNoRetryHeader) != "" {
		t.Fatalf("plain target: %q with %s=%q, want 200 and no retry header", status, brokerNoRetryHeader, header.Get(brokerNoRetryHeader))
	}
}

// TestBrokerSocketNoRetryHeaderMarksOnlyTheBrokersOwnAnswers: the upstream's 429 reaches
// the client bare (its retry policy toward the API is its own), the shed that follows
// and every refusal carry X-Should-Retry: false.
func TestBrokerSocketNoRetryHeaderMarksOnlyTheBrokersOwnAnswers(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"slow down"}`)
	}))
	defer upstream.Close()
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/items"}}}
	b, err := startDockerBroker(grant, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	status, header := rawSocketRequest(t, b.sock, "GET /v1/items HTTP/1.1")
	if !strings.HasPrefix(status, "429") || header.Get(brokerNoRetryHeader) != "" {
		t.Fatalf("upstream 429: %q with %s=%q, want the bare upstream answer", status, brokerNoRetryHeader, header.Get(brokerNoRetryHeader))
	}
	status, header = rawSocketRequest(t, b.sock, "GET /v1/items HTTP/1.1")
	if !strings.HasPrefix(status, "503") || header.Get(brokerNoRetryHeader) != "false" {
		t.Fatalf("shed: %q with %s=%q, want 503 and false", status, brokerNoRetryHeader, header.Get(brokerNoRetryHeader))
	}
	status, header = rawSocketRequest(t, b.sock, "DELETE /v1/items HTTP/1.1")
	if !strings.HasPrefix(status, "403") || header.Get(brokerNoRetryHeader) != "false" {
		t.Fatalf("refused route: %q with %s=%q, want 403 and false", status, brokerNoRetryHeader, header.Get(brokerNoRetryHeader))
	}
}

// TestEgressGuardNoRetryHeaderMarksGuardAnswers: the guard's HTTP framing carries the
// same mark for its own refusals (an unknown credential, a refused route through the
// registry) and never for an upstream's answer.
func TestEgressGuardNoRetryHeaderMarksGuardAnswers(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer upstream.Close()
	reg := &guardRegistry{}
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/items"}}}
	token, _, cleanup, err := reg.open(context.Background(), grant, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	guard := &registryGuard{reg: reg}
	h := EgressGuardHTTPHandler(guard, "/v1/e2b/guard", 0, 0)
	do := func(tok, envelope string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "https://guard.example/v1/e2b/guard", strings.NewReader(envelope))
		req.Header.Set(EgressGuardHeader, tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := do("crg_unknown", `{"method":"GET","path":"/v1/items"}`); rec.Code != http.StatusUnauthorized || rec.Header().Get(brokerNoRetryHeader) != "false" {
		t.Fatalf("unknown credential: %d %q", rec.Code, rec.Header().Get(brokerNoRetryHeader))
	}
	if rec := do(token, `{"method":"DELETE","path":"/v1/items"}`); rec.Code != http.StatusForbidden || rec.Header().Get(brokerNoRetryHeader) != "false" {
		t.Fatalf("refused route: %d %q", rec.Code, rec.Header().Get(brokerNoRetryHeader))
	}
	if rec := do(token, `{"method":"GET","path":"/v1/items"}`); rec.Code != http.StatusTooManyRequests || rec.Header().Get(brokerNoRetryHeader) != "" {
		t.Fatalf("upstream 429: %d %q, want bare", rec.Code, rec.Header().Get(brokerNoRetryHeader))
	}
}

// registryGuard serves a guardRegistry as an EgressGuardCapable, as the VM providers do.
type registryGuard struct{ reg *guardRegistry }

func (g *registryGuard) EgressGuardPath() string                 { return "/v1/e2b/guard" }
func (g *registryGuard) EgressGuardKnownToken(token string) bool { return g.reg.lookup(token) != nil }
func (g *registryGuard) EgressGuardCall(ctx context.Context, token string, call GuardRequest) EgressGuardResponse {
	return g.reg.call(ctx, token, call)
}
