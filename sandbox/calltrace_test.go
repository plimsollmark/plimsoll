package sandbox

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// brokerClient dials the broker's unix socket the way the container would.
func brokerClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
}

// TestBrokerTraceRecordsTemplateNotRawPath is the core redaction proof: an allowed
// brokered call is recorded with the matched route TEMPLATE ("/items/*"), never the
// raw request path ("/items/42"), and the credential never appears in the trace.
func TestBrokerTraceRecordsTemplateNotRawPath(t *testing.T) {
	var gotAuth, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	const token = "s3cr3t-bearer-token"
	grant := &HostAPIGrant{
		BaseURL: upstream.URL,
		Allow:   []HostRoute{{Method: "GET", Path: "/items/*"}},
	}
	b, err := startDockerBroker(grant, token)
	if err != nil {
		t.Fatalf("startDockerBroker: %v", err)
	}
	defer b.Close()

	resp, err := brokerClient(b.sock).Get("http://broker/items/42")
	if err != nil {
		t.Fatalf("GET /items/42: %v", err)
	}
	resp.Body.Close()

	// The broker really injected the credential and forwarded the raw path upstream.
	if gotAuth != "Bearer "+token {
		t.Errorf("upstream Authorization = %q, want Bearer %s", gotAuth, token)
	}
	if gotPath != "/items/42" {
		t.Errorf("upstream path = %q, want /items/42", gotPath)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	trace := b.traceSnapshot()
	if trace == nil || len(trace.Calls) != 1 {
		t.Fatalf("trace = %+v, want exactly one call", trace)
	}
	row := trace.Calls[0]
	if row.Route != "/items/*" {
		t.Errorf("row.Route = %q, want the template /items/*", row.Route)
	}
	if row.Method != "GET" || row.Status != 200 || row.Seq != 1 || !row.Delivered {
		t.Errorf("row = %+v, want GET/200/seq1/delivered", row)
	}
	if row.RespBytes != len(`{"ok":true}`) {
		t.Errorf("row.RespBytes = %d, want %d", row.RespBytes, len(`{"ok":true}`))
	}

	// The whole serialized trace must contain neither the raw path nor the token.
	js, err := json.Marshal(trace)
	if err != nil {
		t.Fatalf("marshal trace: %v", err)
	}
	if s := string(js); strings.Contains(s, "/items/42") || strings.Contains(s, token) {
		t.Errorf("trace leaked a raw path or credential: %s", s)
	}
}

// TestBrokerTraceCountsDeniedWithoutPath proves a denied call is counted but records
// no row and no path, since a denied call matched no template.
func TestBrokerTraceCountsDeniedWithoutPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	grant := &HostAPIGrant{
		BaseURL: upstream.URL,
		Allow:   []HostRoute{{Method: "GET", Path: "/items/*"}},
	}
	b, err := startDockerBroker(grant, "tok")
	if err != nil {
		t.Fatalf("startDockerBroker: %v", err)
	}
	defer b.Close()

	resp, err := brokerClient(b.sock).Get("http://broker/secret/hunter2")
	if err != nil {
		t.Fatalf("GET /secret/hunter2: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}

	trace := b.traceSnapshot()
	if trace == nil || trace.Denied != 1 || len(trace.Calls) != 0 {
		t.Fatalf("trace = %+v, want Denied=1 and no rows", trace)
	}
	js, _ := json.Marshal(trace)
	if strings.Contains(string(js), "hunter2") || strings.Contains(string(js), "/secret") {
		t.Errorf("denied call leaked its path into the trace: %s", js)
	}
}

func TestCallTraceCapOverflow(t *testing.T) {
	tr := newCallTrace()
	const extra = 5
	for i := 0; i < maxTraceRows+extra; i++ {
		tr.record(CallRow{Method: "GET", Route: "/x"})
	}
	snap := tr.snapshot()
	if len(snap.Calls) != maxTraceRows {
		t.Errorf("kept %d rows, want the cap %d", len(snap.Calls), maxTraceRows)
	}
	if snap.Dropped != extra {
		t.Errorf("Dropped = %d, want %d", snap.Dropped, extra)
	}
	if snap.Calls[0].Seq != 1 || snap.Calls[maxTraceRows-1].Seq != maxTraceRows {
		t.Errorf("Seq not monotonic 1..%d: first=%d last=%d",
			maxTraceRows, snap.Calls[0].Seq, snap.Calls[maxTraceRows-1].Seq)
	}
}

func TestCallTraceEmptyAndNilSafe(t *testing.T) {
	if newCallTrace().snapshot() != nil {
		t.Error("empty trace should snapshot to nil so a grant-free run stays unchanged")
	}
	var nilTrace *callTrace
	nilTrace.record(CallRow{Method: "GET", Route: "/x"}) // must not panic
	nilTrace.recordDenied()                              // must not panic
	if nilTrace.snapshot() != nil {
		t.Error("nil trace should snapshot to nil")
	}
}

func TestMatchRouteReturnsTemplate(t *testing.T) {
	grant := &HostAPIGrant{Allow: []HostRoute{
		{Method: "GET", Path: "/items/*"},
		{Method: "POST", Path: "/orders"},
	}}
	r, ok := grant.matchRoute("GET", "/items/42")
	if !ok || r.Path != "/items/*" || r.Method != "GET" {
		t.Errorf("matchRoute(GET,/items/42) = %+v,%v; want the /items/* template", r, ok)
	}
	if _, ok := grant.matchRoute("POST", "/items/42"); ok {
		t.Error("method mismatch should not match")
	}
	if _, ok := grant.matchRoute("GET", "/nope"); ok {
		t.Error("unlisted path should not match")
	}
	if _, ok := grant.matchRoute("GET", "/items/../secret"); ok {
		t.Error("traversal must be rejected")
	}
}
