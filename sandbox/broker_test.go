package sandbox

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// recordingMinter captures the MintScope it was called with.
type recordingMinter struct{ last MintScope }

func (m *recordingMinter) Mint(_ context.Context, s MintScope) (MintedToken, error) {
	m.last = s
	return MintedToken{Value: "tok-for-" + s.Subject}, nil
}

type subjectBoundRecordingMinter struct{ called bool }

func (*subjectBoundRecordingMinter) RequiresSubject() bool { return true }
func (m *subjectBoundRecordingMinter) Mint(context.Context, MintScope) (MintedToken, error) {
	m.called = true
	return MintedToken{Value: "must-not-mint"}, nil
}

// TestCredentialThreadsSubjectAndScope verifies the caller subject (from ctx) and
// the grant's scopes/TTL reach the minter — the basis of per-session token minting.
func TestCredentialThreadsSubjectAndScope(t *testing.T) {
	rm := &recordingMinter{}
	g := &HostAPIGrant{BaseURL: "https://x", Allow: sampleAllow, Scopes: []string{"a:read"}, Minter: rm}
	ctx := WithSubject(context.Background(), "user:z")
	tok, err := g.credential(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if rm.last.Subject != "user:z" {
		t.Errorf("subject = %q, want user:z", rm.last.Subject)
	}
	if len(rm.last.Scopes) != 1 || rm.last.Scopes[0] != "a:read" {
		t.Errorf("scopes = %v, want [a:read]", rm.last.Scopes)
	}
	if rm.last.TTL != 30*time.Second {
		t.Errorf("ttl = %v, want 30s", rm.last.TTL)
	}
	if tok != "tok-for-user:z" {
		t.Errorf("token = %q", tok)
	}
}

func TestCredentialCentrallyRejectsAnonymousSubjectBoundMinter(t *testing.T) {
	for _, subject := range []string{"", "  ", "alice\nadmin"} {
		m := &subjectBoundRecordingMinter{}
		g := &HostAPIGrant{BaseURL: "https://x", Minter: m}
		ctx := WithSubject(context.Background(), subject)
		if _, err := g.credential(ctx, time.Minute); err == nil || !strings.Contains(err.Error(), "stable authenticated subject") {
			t.Fatalf("subject %q credential error = %v", subject, err)
		}
		if m.called {
			t.Fatalf("subject %q reached subject-bound minter", subject)
		}
	}
}

func TestHostAPIGrantValidateRejectsAmbiguousBaseURLAndScopeTokens(t *testing.T) {
	invalidURLs := []string{
		"ftp://host.internal",
		"http://host.internal",
		"https://user:pass@host.internal",
		"https://host.internal/api",
		"https://host.internal?tenant=x",
		"https://host.internal#fragment",
	}
	for _, baseURL := range invalidURLs {
		if err := (&HostAPIGrant{BaseURL: baseURL}).Validate(); err == nil {
			t.Errorf("Validate(%q) succeeded, want rejection", baseURL)
		}
	}
	for _, scopes := range [][]string{{"safe code:run"}, {" safe"}, {""}} {
		if err := (&HostAPIGrant{BaseURL: "https://host.internal", Scopes: scopes}).Validate(); err == nil {
			t.Errorf("Validate scopes %q succeeded, want rejection", scopes)
		}
	}
	if err := (&HostAPIGrant{BaseURL: "https://host.internal:8443", Scopes: []string{"safe:read"}}).Validate(); err != nil {
		t.Fatalf("canonical origin rejected: %v", err)
	}
	if err := (&HostAPIGrant{BaseURL: "http://127.0.0.1:8080"}).Validate(); err != nil {
		t.Fatalf("loopback development origin rejected: %v", err)
	}
}

func TestHostAPIGrantValidateRejectsUnsafeRoutes(t *testing.T) {
	for _, route := range []HostRoute{
		{Method: "TRACE", Path: "/v1/echo"},
		{Method: " GET", Path: "/v1/x"},
		{Method: "GET", Path: "relative"},
		{Method: "GET", Path: "/v1//x"},
		{Method: "GET", Path: "/v1/../admin"},
		{Method: "GET", Path: "/v1/a*b"},
		{Method: "GET", Path: "/v1/%61"},
		{Method: "GET", Path: "/v1/x?admin=1"},
		{Method: "GET", Path: "/v1\\admin"},
		{Method: "GET", Path: "/v1/has space"},
		{Method: "GET", Path: "/v1/café"},
		{Method: "GET", Path: "/v1/x;jsessionid=1"},
		{Method: "GET", Path: "/v1/.../x"},
	} {
		grant := &HostAPIGrant{BaseURL: "https://host.internal", Allow: []HostRoute{route}}
		if err := grant.Validate(); err == nil {
			t.Errorf("Validate(%+v) succeeded, want rejection", route)
		}
	}
	valid := &HostAPIGrant{BaseURL: "https://host.internal", Allow: []HostRoute{{Method: "get", Path: "/v1/things/*"}}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid case-insensitive route rejected: %v", err)
	}
}

func TestCredentialRejectsInvalidMintedToken(t *testing.T) {
	for _, token := range []string{"", " token", "token with-space", "token\nheader", "tök"} {
		grant := &HostAPIGrant{BaseURL: "https://host.internal", Minter: StaticToken(token)}
		if _, err := grant.credential(context.Background(), time.Second); err == nil {
			t.Errorf("credential accepted invalid token %q", token)
		}
	}
}

func TestHostNetPreambleQuotesGlobalName(t *testing.T) {
	out := hostNetPreamble(`x"];globalThis.pwned=true;//`, nil)
	if !strings.Contains(out, `globalThis["x\"];globalThis.pwned=true;//"]`) {
		t.Fatalf("global name was not JSON-quoted: %s", out[:200])
	}
	if strings.Contains(out, "globalThis.x\"]") {
		t.Fatal("global name was interpolated as executable JavaScript")
	}
}

// A representative injected allowlist (what an embedder like control would set).
// The bridge itself knows none of these — they are data on the grant.
var sampleAllow = []HostRoute{
	{http.MethodGet, "/v1/health"},
	{http.MethodGet, "/v1/lights"},
	{http.MethodGet, "/v1/rooms"},
	{http.MethodPut, "/v1/lights/*/on"},
	{http.MethodPut, "/v1/lights/*/brightness"},
	{http.MethodPut, "/v1/scenes/*/recall"},
}

func TestHostAPIRouteAllowlist(t *testing.T) {
	g := &HostAPIGrant{Allow: sampleAllow}

	allow := []struct{ m, p string }{
		{http.MethodGet, "/v1/health"},
		{http.MethodGet, "/v1/lights"},
		{http.MethodGet, "/v1/rooms"},
		{http.MethodPut, "/v1/lights/abc/on"},
		{http.MethodPut, "/v1/lights/abc/brightness"},
		{http.MethodPut, "/v1/scenes/xyz/recall"},
		{"get", "/v1/lights"}, // method match is case-insensitive
	}
	deny := []struct{ m, p string }{
		{http.MethodPost, "/v1/code/run"},          // not in the allowlist
		{http.MethodGet, "/v1/audit-events"},       // outside the allowed surface
		{http.MethodPut, "/v1/lights/abc/color"},   // path not allowed
		{http.MethodPut, "/v1/lights/abc/../../x"}, // traversal
		{http.MethodGet, "/v2/lights"},             // wrong prefix
		{http.MethodDelete, "/v1/lights/abc/on"},   // wrong method
		{http.MethodGet, "/v1/lights/abc"},         // GET on a non-listed path
		{http.MethodPut, "/v1/lights/on"},          // wildcard needs a segment
		{http.MethodPut, "/v1/lights/a/b/on"},      // too many segments
		{http.MethodPut, "/v1/lights/a\\b/on"},     // target-dependent path separator
		{http.MethodPut, "/v1/lights/a\nb/on"},     // control character in wildcard
		{http.MethodPut, "/v1/lights/..;/on"},      // Tomcat/Spring read "..;" as ".."
		{http.MethodPut, "/v1/lights/abc;x=1/on"},  // path parameter an upstream strips
		{http.MethodPut, "/v1/lights/.../on"},      // all-dot segment
	}
	for _, c := range allow {
		if !g.routeAllowed(c.m, c.p) {
			t.Errorf("routeAllowed(%s %s) = false, want true", c.m, c.p)
		}
	}
	for _, c := range deny {
		if g.routeAllowed(c.m, c.p) {
			t.Errorf("routeAllowed(%s %s) = true, want false", c.m, c.p)
		}
	}
}

// TestHostAPIRouteAllowlistRejectsEncodedTraversal guards the percent-encoding
// bypass: routeAllowed must reject paths that decode to a different (allowlist-
// escaping) path on the wire. %2f decodes to "/" (smuggling extra segments past
// the "*" wildcard) and %2e%2e decodes to ".." (traversal). All must be denied.
func TestHostAPIRouteAllowlistRejectsEncodedTraversal(t *testing.T) {
	g := &HostAPIGrant{Allow: sampleAllow}
	deny := []string{
		"/v1/lights/x%2f..%2f..%2fadmin/on", // %2f smuggles ../../admin past the wildcard
		"/v1/lights/%2e%2e/on",              // %2e%2e decodes to ".."
		"/v1/lights/%2E%2E/on",              // uppercase hex variant
		"/v1/lights/abc%2fon",               // %2f folds two segments into the wildcard
		"/v1/lights/%2fon",                  // leading encoded slash
		"/v1/lights/%zz/on",                 // invalid percent-escape -> decode error -> deny
	}
	for _, p := range deny {
		if g.routeAllowed(http.MethodPut, p) {
			t.Errorf("routeAllowed(PUT %s) = true, want deny (encoding bypass)", p)
		}
	}
	// The legitimate decoded form is still allowed.
	if !g.routeAllowed(http.MethodPut, "/v1/lights/abc/on") {
		t.Error("routeAllowed(PUT /v1/lights/abc/on) = false, want allow")
	}
}

// TestHostAPIRouteAllowlistRejectsQueryAndFragment guards a bypass: a "?" or "#" in
// the path is matched here as part of a segment but stripped by net/http on the
// wire, so the approved route differs from the one hit. Both must be denied.
func TestHostAPIRouteAllowlistRejectsQueryAndFragment(t *testing.T) {
	g := &HostAPIGrant{Allow: sampleAllow}
	for _, p := range []string{
		"/v1/lights/x?/on", // wire path becomes /v1/lights/x (query "/on")
		"/v1/lights/x#/on", // fragment smuggling
		"/v1/lights/abc/on?evil=1",
	} {
		if g.routeAllowed(http.MethodPut, p) {
			t.Errorf("routeAllowed(PUT %s) = true, want deny (query/fragment)", p)
		}
	}
}

// An empty allowlist denies everything (off by default).
func TestHostAPIEmptyAllowlistDeniesAll(t *testing.T) {
	g := &HostAPIGrant{} // no Allow
	for _, c := range []struct{ m, p string }{
		{http.MethodGet, "/v1/health"},
		{http.MethodGet, "/v1/lights"},
		{http.MethodPut, "/v1/lights/abc/on"},
	} {
		if g.routeAllowed(c.m, c.p) {
			t.Errorf("empty allowlist permitted %s %s; want deny-by-default", c.m, c.p)
		}
	}
}
