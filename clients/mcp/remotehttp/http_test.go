package remotehttp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
	"github.com/plimsollmark/plimsoll/sandbox"
	"golang.org/x/net/netutil"
)

func TestRemoteConfigurationRefusesUnsafeStartup(t *testing.T) {
	base := Config{Listen: "127.0.0.1:8750", PublicURL: testOrigin, StateDir: filepath.Join(t.TempDir(), "state"), Daemon: server.Config{Token: "dedicated", MinimumIsolation: sandbox.IsolationKernel, SigningKeyFile: "key", ReceiptsDir: "receipts"}}
	for _, change := range []func(*Config){func(c *Config) { c.Listen = "0.0.0.0:8750" }, func(c *Config) { c.Listen = "localhost:8750" }, func(c *Config) { c.Listen = "127.0.0.1:0" }, func(c *Config) { c.Listen = "127.0.0.1:65536" }, func(c *Config) { c.PublicURL = "http://mcp.example.test" }, func(c *Config) { c.PublicURL = testOrigin + "/mcp" }, func(c *Config) { c.PublicURL = "https://user@mcp.example.test" }, func(c *Config) { c.PublicURL = testOrigin + "?" }, func(c *Config) { c.PublicURL = "https://127.0.0.1" }, func(c *Config) { c.PublicURL = testOrigin + ":443" }, func(c *Config) { c.PublicURL = testOrigin + ":0" }, func(c *Config) { c.PublicURL = testOrigin + ":08443" }, func(c *Config) { c.VisitorHeader = "X-Forwarded-For: 1" }, func(c *Config) { c.VisitorHeader = "Authorization" }, func(c *Config) { c.StateDir = "relative" }, func(c *Config) { c.Daemon.Token = "" }, func(c *Config) { c.Daemon.MinimumIsolation = sandbox.IsolationContainer }, func(c *Config) { c.Daemon.InsecureHTTP = true }, func(c *Config) { c.Daemon.ReceiptsDir = "" }, func(c *Config) { c.Daemon.MaxSandboxes = 1 }} {
		cfg := base
		change(&cfg)
		if cfg.validate() == nil {
			t.Fatal("unsafe remote configuration accepted")
		}
	}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	withPort := base
	withPort.PublicURL = testOrigin + ":8443"
	if err := withPort.validate(); err != nil {
		t.Fatalf("a non-default HTTPS port was refused: %v", err)
	}
	if _, err := New(base); err == nil {
		t.Fatal("startup accepted an unenrolled owner")
	}
	f := newFixture(t)
	if err := f.e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg := f.cfg
	cfg.Daemon.Token = "incorrect"
	if _, err := New(cfg); err == nil {
		t.Fatal("startup accepted a refused daemon credential")
	}
	cfg = f.cfg
	// Make even the anonymous probe authenticated to prove startup rejects it.
	cfg.Daemon.HTTPClient = &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		clone.Header.Set("Authorization", "Bearer "+testDaemonToken)
		return http.DefaultTransport.RoundTrip(clone)
	})}
	if _, err := New(cfg); err == nil {
		t.Fatal("startup accepted a daemon admitting anonymous requests")
	}
}

func TestDedicatedHTTPRouteHostOriginAndDiscoveryPolicy(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/", "/metrics", "/debug/pprof/", "/oauth/authorize/", "/mcp/", "//mcp", "/a/../mcp", "/%6dcp", "/mcp%2f", "/owner/enable", "/plimsoll.v1.SandboxService/Run", "/state.json", "/audit.jsonl"} {
		requireStatus(t, request(f.e, "GET", path, nil, browser{}), 404)
	}
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "mcp.example.test"
		r.Header.Set("Forwarded", "host=attacker.example;proto=http")
		r.Header.Set("X-Forwarded-Host", "attacker.example")
		w := httptest.NewRecorder()
		f.e.ServeHTTP(w, r)
		requireStatus(t, w, 200)
		if strings.Contains(w.Body.String(), "attacker") || !strings.Contains(w.Body.String(), testOrigin) {
			t.Fatal("discovery trusted forwarded input")
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatal("unsafe discovery headers")
		}
	}
	requireStatus(t, request(f.e, "POST", "/.well-known/oauth-protected-resource", nil, browser{}), 405)
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Host = "attacker.example"
	w := httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	requireStatus(t, w, 403)
	r.Host = "mcp.example.test"
	r.Header.Set("Origin", "null")
	w = httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	requireStatus(t, w, 403)
	r.Header.Set("Origin", "https://claude.ai")
	r.Header.Add("Origin", testOrigin)
	w = httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	requireStatus(t, w, 403)
	r.Header.Del("Origin")
	r.Header.Set("X-HTTP-Method-Override", "GET")
	w = httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	requireStatus(t, w, 404)
	requireStatus(t, request(f.e, "GET", "/mcp?access_token=not-accepted", nil, browser{}), 400)
	for _, method := range []string{"POST", "GET", "DELETE"} {
		w = request(f.e, method, "/mcp", nil, browser{})
		requireStatus(t, w, 401)
		if !strings.Contains(w.Header().Get("WWW-Authenticate"), testOrigin+"/.well-known/oauth-protected-resource") {
			t.Fatal("missing OAuth discovery challenge")
		}
	}
}

func TestClientMetadataHasBoundedExactPolicy(t *testing.T) {
	resolver := newResolver()
	var calls atomic.Int32
	good := `{"client_id":"https://chatgpt.com/oauth/client.json","client_name":"ChatGPT","redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_methods_supported":["none","private_key_jwt"]}`
	resolver.fetch = func(context.Context, string) ([]byte, error) { calls.Add(1); return []byte(good), nil }
	c, err := resolver.resolve(context.Background(), chatgptMetadata)
	if err != nil || c.Redirects[0] != chatgptRedirect {
		t.Fatal("verified hosted metadata rejected")
	}
	if _, err = resolver.resolve(context.Background(), chatgptMetadata); err != nil || calls.Load() != 1 {
		t.Fatal("metadata cache did not retain its bounded entry")
	}
	for _, id := range []string{"http://chatgpt.com/oauth/client.json", "https://chatgpt.com.evil.test/oauth/client.json", "https://user@chatgpt.com/oauth/client.json", chatgptMetadata + "?x=1", "https://127.0.0.1/client.json", "https://claude.ai/api/oauth/mcp-oauth-client-metadata"} {
		if _, err = resolver.resolve(context.Background(), id); err == nil {
			t.Fatal("unapproved metadata address accepted")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("unapproved address triggered a fetch")
	}
	for _, bad := range []string{strings.Replace(good, `"client_id":"https://chatgpt.com/oauth/client.json"`, `"client_id":"https://attacker.test/client.json"`, 1), strings.ReplaceAll(good, chatgptRedirect, chatgptRedirect+"?x=1"), strings.Replace(good, `["none","private_key_jwt"]`, `["private_key_jwt"]`, 1), `null`, `{`, good + good} {
		r := newResolver()
		r.fetch = func(context.Context, string) ([]byte, error) { return []byte(bad), nil }
		if _, err = r.resolve(context.Background(), chatgptMetadata); err == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	for _, address := range []string{"127.0.0.1", "::1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.0.2.1", "198.18.0.1", "2001:db8::1", "::ffff:192.168.1.1", "fd00::1", "fe80::1", "0.0.0.0"} {
		if publicIP(net.ParseIP(address)) {
			t.Fatalf("non-public metadata destination %s accepted", address)
		}
	}
	if !publicIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("public IP refused")
	}
}

func TestRegistrationRejectsCallbackNearMissesAndBoundsStorage(t *testing.T) {
	f := newFixture(t)
	for _, redirect := range []string{chatgptRedirect + "/", chatgptRedirect + "?x=1", strings.Replace(chatgptRedirect, "chatgpt.com", "chatgpt.com.evil.test", 1), strings.Replace(chatgptRedirect, "https://", "https://attacker@", 1), "http://localhost:1234/callback", "https://claude.ai/api/mcp/auth_callback#fragment"} {
		r := request(f.e, "POST", "/oauth/register", map[string]any{"redirect_uris": []string{redirect}}, browser{})
		requireStatus(t, r, 400)
	}
	r := request(f.e, "POST", "/oauth/register", map[string]any{"redirect_uris": []string{claudeRedirect}, "logo_uri": "http://169.254.169.254/no-fetch", "unrecognized_extension": "ignored"}, browser{})
	requireStatus(t, r, 201)
	// Fill the durable boundary directly, then exercise the real public refusal.
	err := f.e.state.update(func(d *stateData) error {
		for len(d.Clients) < maxClients {
			id := randomID("client_")
			d.Clients[id] = clientRecord{ID: id, Redirects: []string{claudeRedirect}}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r = request(f.e, "POST", "/oauth/register", map[string]any{"redirect_uris": []string{chatgptRedirect}}, browser{})
	requireStatus(t, r, 503)
}

func TestHTTPAdmissionLimitsAndFailClosedAudit(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	verifier := strings.Repeat("b", 43)
	b := authorizeBrowser(t, f.e, id, verifier)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), verifier)
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	r.Host = "mcp.example.test"
	r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	r.ContentLength = mcpBodyLimit + 1
	w := httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	requireStatus(t, w, 413)
	r.ContentLength = 2
	if !f.e.bodyBudget.TryAcquire(64 << 20) {
		t.Fatal("could not hold body budget")
	}
	w = httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	requireStatus(t, w, 429)
	f.e.bodyBudget.Release(64 << 20)
	f.e.audit.mu.Lock()
	f.e.audit.failed = true
	f.e.audit.mu.Unlock()
	w = httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	requireStatus(t, w, 503)
	requireStatus(t, request(f.e, "POST", "/mcp", nil, browser{}), 503) // Audit failure takes precedence.
}

func TestDisableOwnerRecoveryAndOfflineRestart(t *testing.T) {
	f := newFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.e.cfg.Listen = listener.Addr().String()
	_ = listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.e.Run(ctx) }()
	defer cancel()
	socket := filepath.Join(f.cfg.StateDir, "control.sock")
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err = os.Lstat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("local control listener did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err = checkSocket(socket); err != nil {
		t.Fatal(err)
	}
	status, err := Operator(context.Background(), f.cfg.StateDir, "disable")
	if err != nil || !status.Disabled || !status.CleanupComplete {
		t.Fatal("running local disable failed")
	}
	status, err = Operator(context.Background(), f.cfg.StateDir, "enroll")
	if err != nil || status.EnrollmentCode == "" || status.EnrollmentURL != testOrigin+"/owner/enroll" {
		t.Fatal("local enrollment authorization failed")
	}
	status, err = Operator(context.Background(), f.cfg.StateDir, "enable")
	if err != nil || status.Disabled {
		t.Fatal("running local enable failed")
	}
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP shutdown did not finish")
	}
	status, err = Operator(context.Background(), f.cfg.StateDir, "disable")
	if err != nil || !status.Disabled {
		t.Fatal("offline disable failed")
	}
	if _, err = Operator(context.Background(), f.cfg.StateDir, "enable"); err == nil {
		t.Fatal("offline enable bypassed daemon verification")
	}
	status, err = Operator(context.Background(), f.cfg.StateDir, "reset-owner")
	if err != nil || !status.Disabled || status.Passkeys != 0 {
		t.Fatal("owner recovery retained owner credentials")
	}
	if _, err = New(f.cfg); err == nil {
		t.Fatal("normal restart admitted a recovered owner without enrollment")
	}
}

func TestExpiredGrantClosesItsSandboxes(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("c", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	cs := connectMCP(t, f.e, pair.AccessToken)
	out, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "open_sandbox", Arguments: map[string]any{}})
	if err != nil || out.IsError {
		data, _ := json.Marshal(out)
		t.Fatalf("could not open sandbox: %v, %s", err, data)
	}
	future := time.Now().Add(idleLifetime + time.Hour)
	f.e.state.mu.Lock()
	f.e.state.now = func() time.Time { return future }
	f.e.state.mu.Unlock()
	f.e.expire(context.Background())
	if _, err = f.e.state.access(pair.AccessToken, f.e.resource()); err == nil {
		t.Fatal("idle authority remained valid")
	}
	f.e.mu.Lock()
	n := len(f.e.grantLimits)
	f.e.mu.Unlock()
	if n != 0 {
		t.Fatal("expired grant retained its admission bucket")
	}
}

func TestAuditRotationAndStorageFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	if err := privateDir(dir); err != nil {
		t.Fatal(err)
	}
	a, err := openAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A security line, then three times the tool stream's cap in tool lines: the tool
	// stream rotates, and the security line is still there (hunt-security-26).
	a.event("token_issued", strings.Repeat("g", 45), strings.Repeat("d", 64))
	for i := 0; i < 18000; i++ {
		a.event("checked_record", strings.Repeat("g", 45), strings.Repeat("a", 64))
	}
	if !a.healthy() {
		t.Fatal("rotation failed")
	}
	for _, name := range []string{"tools.jsonl", "tools.previous.jsonl", "audit.jsonl"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Size() > 1<<20 || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s exceeded its byte or permission boundary: %v", name, err)
		}
	}
	security, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil || !strings.Contains(string(security), `"event":"token_issued"`) || strings.Contains(string(security), "checked_record") {
		t.Fatalf("after 3 MiB of tool lines the security file holds: %.200s (%v)", security, err)
	}
	if err = a.security.file.Close(); err != nil {
		t.Fatal(err)
	}
	a.event("disk_failure", "", "")
	if a.healthy() {
		t.Fatal("audit write failure did not poison admission")
	}
	_ = a.close()
}

// An anonymous flood must not starve what a connected client needs to recover
// from an expired token: the 401 challenge, the metadata, and the token endpoint.
func TestAnonymousFloodCannotStarveRefreshOrChallenge(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("f", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	for range 500 {
		requireStatus(t, request(f.e, "GET", "/.well-known/oauth-authorization-server", nil, browser{}), 200)
		requireStatus(t, request(f.e, "POST", "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {randomID("r_")[:45]}}, browser{}), 400)
		requireStatus(t, request(f.e, "POST", "/oauth/authorize", url.Values{"tx": {"forged"}, "csrf": {"x"}, "decision": {"approve"}}, browser{}), 403)
	}
	for _, method := range []string{"GET", "POST"} {
		requireStatus(t, request(f.e, method, "/mcp", nil, browser{}), 401)
	}
	requireStatus(t, request(f.e, "OPTIONS", "/mcp", nil, browser{}), 204)
	requireStatus(t, request(f.e, "GET", "/.well-known/oauth-protected-resource/mcp", nil, browser{}), 200)
	// Anonymous approvals store nothing, so a flood of them cannot crowd out
	// the owner's next approval.
	marked := func() int {
		f.e.marks.mu.Lock()
		defer f.e.marks.mu.Unlock()
		return len(f.e.marks.entries)
	}
	before := marked()
	for range 200 {
		authorizeBrowser(t, f.e, id, strings.Repeat("g", 43))
	}
	if n := marked(); n != before {
		t.Fatalf("anonymous approvals added %d entries", n-before)
	}
	owner := authorizeBrowser(t, f.e, id, v)
	login(t, f, owner)
	approveCode(t, f.e, owner)
	r := request(f.e, "POST", "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {pair.RefreshToken}, "scope": {"offline_access code:run"}}, browser{})
	requireStatus(t, r, 200)
	// Refused attempts were audited up to the refusal budget, then counted.
	raw, err := os.ReadFile(filepath.Join(f.cfg.StateDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), "consent_refused"); n == 0 || n > 31 {
		t.Fatalf("%d refusal events written for 500 refusals", n)
	}
}

func TestChunkedPublicBodiesAreBounded(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(strings.Repeat(" ", 8193)))
	r.Host = "mcp.example.test"
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = -1
	w := httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	requireStatus(t, w, 400)
}

func TestDisableGenerationInvalidatesDelayedApproval(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	b := authorizeBrowser(t, f.e, id, strings.Repeat("d", 43))
	if _, err := f.e.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.e.Enable(); err != nil {
		t.Fatal(err)
	}
	// The approval was sealed before the disable; its generation is now stale.
	requireStatus(t, request(f.e, "POST", "/owner/login/options", input(b), b), 403)
}

func TestRepeatedRegistrationCannotExhaustPermanentClientRows(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	for i := 0; i < 50; i++ {
		if got := clientID(t, f.e); got != id {
			t.Fatal("same public callback set allocated another client identity")
		}
	}
	f.e.state.mu.Lock()
	n := len(f.e.state.data.Clients)
	f.e.state.mu.Unlock()
	if n != 1 {
		t.Fatal("anonymous registration grew the registry")
	}
}

func TestHTTPRefreshRotationAndLateReuseRevokeTheFamily(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("r", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	first := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	rotate := func(token, resource string) *httptest.ResponseRecorder {
		return request(f.e, "POST", "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {token}, "resource": {resource}}, browser{})
	}
	requireStatus(t, rotate(first.RefreshToken, "https://wrong.example/mcp"), 400)
	current := first
	for i := 0; i < 2; i++ {
		r := rotate(current.RefreshToken, f.e.resource())
		requireStatus(t, r, 200)
		if err := json.Unmarshal(r.Body.Bytes(), &current); err != nil {
			t.Fatal(err)
		}
	}
	requireStatus(t, rotate(first.RefreshToken, f.e.resource()), 400)
	if _, err := f.e.state.access(current.AccessToken, f.e.resource()); err == nil {
		t.Fatal("late refresh reuse left current access valid")
	}
	requireStatus(t, rotate(current.RefreshToken, f.e.resource()), 400)
}

func TestAuthorizationCanBeVerifiedWithExecutionDisabled(t *testing.T) {
	f := newFixture(t)
	f.e.cfg.ExecutionEnabled = false
	id := clientID(t, f.e)
	v := strings.Repeat("e", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_code","arguments":{"code":"must not run"}}}`))
	r.Host = "mcp.example.test"
	r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	requireStatus(t, w, 503)
	requireStatus(t, request(f.e, "POST", "/mcp", nil, browser{}), 401)
	if f.e.status().ExecutionEnabled {
		t.Fatal("status reported execution enabled during authorization-only verification")
	}
}

// A fault on this side must not tell the client to discard a valid refresh token.
func TestTokenEndpointAnswersServerFaultsAsUnavailable(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("u", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {pair.RefreshToken}}
	f.e.audit.mu.Lock()
	f.e.audit.failed = true
	f.e.audit.mu.Unlock()
	requireStatus(t, request(f.e, "POST", "/oauth/token", refresh, browser{}), 503)
	f.e.audit.mu.Lock()
	f.e.audit.failed = false
	f.e.audit.mu.Unlock()
	f.e.state.write = func([]byte) error { return errors.New("disk full") }
	requireStatus(t, request(f.e, "POST", "/oauth/token", refresh, browser{}), 503)
	requireStatus(t, request(f.e, "POST", "/oauth/token", refresh, browser{}), 503)
}

// A refresh that meets the tool server stopping is answered 503 and leaves the grant
// as it was, so the client's retry with the credential it sent can succeed; it once
// revoked the grant, and the owner had to approve the app again (hunt-security-28).
// The retry is shown to succeed after the restart too: the engine is closed and a new
// one opened on the same state, as a restarted process is, and the earlier refresh
// credential refreshes there, and the credentials it returns work. The store accepts
// that earlier credential only for refreshGrace after the rotation (store.refresh's
// retry rule); past it, presenting it is reuse, which
// TestARefreshRetriedPastTheGraceAfterARestartRevokesTheGrant measures.
func TestARefreshThatMeetsAStoppingToolServerKeepsTheGrant(t *testing.T) {
	f, id, refresh := refreshMeetsAStoppingToolServer(t)
	activeGrants := func(e *Engine) int {
		e.state.mu.Lock()
		defer e.state.mu.Unlock()
		active := 0
		for _, g := range e.state.data.Grants {
			if activeGrant(&e.state.data, g, e.state.now()) {
				active++
			}
		}
		return active
	}
	if active := activeGrants(f.e); active != 1 {
		t.Fatalf("%d active grants after a refresh met the stopping tool server, want 1", active)
	}
	restarted := restart(t, f)
	if active := activeGrants(restarted); active != 1 {
		t.Fatalf("%d active grants after the restart, want 1", active)
	}
	r := request(restarted, "POST", "/oauth/token", refresh, browser{})
	requireStatus(t, r, 200)
	var pair tokenPair
	if err := json.Unmarshal(r.Body.Bytes(), &pair); err != nil || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("the earlier credential's refresh after the restart: %v, %s", err, r.Body.String())
	}
	cs := connectMCP(t, restarted, pair.AccessToken)
	if _, err := cs.ListTools(context.Background(), nil); err != nil {
		t.Fatalf("the access token the restarted engine issued: %v", err)
	}
	next := url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {pair.RefreshToken}, "resource": {restarted.resource()}}
	requireStatus(t, request(restarted, "POST", "/oauth/token", next, browser{}), 200)
}

// The limit of the test above, measured: the store accepts a rotated refresh credential
// again only for refreshGrace (30 seconds) after its rotation, so a client that retries
// with it after a restart that took longer presents a used credential, which
// store.refresh treats as reuse and answers by revoking the grant. The owner then
// approves the app again. Recorded as part of hunt-security-28.
func TestARefreshRetriedPastTheGraceAfterARestartRevokesTheGrant(t *testing.T) {
	f, _, refresh := refreshMeetsAStoppingToolServer(t)
	restarted := restart(t, f)
	later := time.Now().Add(refreshGrace + time.Second)
	restarted.state.mu.Lock()
	restarted.state.now = func() time.Time { return later }
	restarted.state.mu.Unlock()
	requireStatus(t, request(restarted, "POST", "/oauth/token", refresh, browser{}), 400)
	restarted.state.mu.Lock()
	defer restarted.state.mu.Unlock()
	for _, g := range restarted.state.data.Grants {
		if activeGrant(&restarted.state.data, g, later) {
			t.Fatalf("grant %s is still active after its rotated credential was presented past the grace", g.ID)
		}
	}
}

// refreshMeetsAStoppingToolServer issues a grant, stops the tool server, and refreshes
// twice with the grant's refresh credential (the refresh, then its retry), each answered
// 503. It returns the fixture, the client id and that refresh request.
func refreshMeetsAStoppingToolServer(t *testing.T) (*fixture, string, url.Values) {
	t.Helper()
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("s", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	f.e.tools.Shutdown()
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {pair.RefreshToken}, "resource": {f.e.resource()}}
	for range 2 { // the refresh, then its retry with the same credential
		r := request(f.e, "POST", "/oauth/token", refresh, browser{})
		requireStatus(t, r, 503)
		if !strings.Contains(r.Body.String(), "temporarily_unavailable") {
			t.Fatalf("the refresh's answer: %s", r.Body.String())
		}
	}
	return f, id, refresh
}

// restart closes the fixture's engine and opens a new one on the same state directory
// and configuration, as a restarted process does.
func restart(t *testing.T, f *fixture) *Engine {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.e.Close(ctx); err != nil {
		t.Fatal(err)
	}
	e, err := New(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Enable(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return e
}

// A grant the store pruned before the expiry sweep ran still has a workspace,
// and disable must cancel it.
func TestDisableCancelsWorkspacesTheStoreAlreadyPruned(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("p", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	cs := connectMCP(t, f.e, pair.AccessToken)
	if out, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "open_sandbox", Arguments: map[string]any{}}); err != nil || out.IsError {
		t.Fatalf("could not open sandbox: %v", err)
	}
	future := time.Now().Add(idleLifetime + time.Hour)
	f.e.state.mu.Lock()
	f.e.state.now = func() time.Time { return future }
	f.e.state.mu.Unlock()
	if err := f.e.state.update(func(*stateData) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(f.e.tools.Grants()) != 1 {
		t.Fatal("the workspace was not registered")
	}
	complete, err := f.e.Disable(context.Background())
	if err != nil || !complete {
		t.Fatalf("disable: complete %v, %v", complete, err)
	}
	if g := f.e.tools.Grants(); len(g) != 0 {
		t.Fatalf("disable left workspaces %v", g)
	}
}

// A tool request without a declared length holds budget for what it sends.
func TestChunkedToolBodyHoldsOnlyWhatItSends(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("k", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	if !f.e.bodyBudget.TryAcquire(63 << 20) {
		t.Fatal("could not hold body budget")
	}
	defer f.e.bodyBudget.Release(63 << 20)
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Host = "mcp.example.test"
	r.ContentLength = -1
	r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	if w.Code == 429 || w.Code == 413 {
		t.Fatalf("a small chunked body was refused with %d", w.Code)
	}
}

// Meters of grants the store no longer holds never refuse a new grant.
func TestStaleGrantMetersMakeRoom(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("m", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	f.e.mu.Lock()
	for i := range maxMeters {
		f.e.grantLimits[fmt.Sprint("gone_", i)] = &grantRate{}
	}
	f.e.mu.Unlock()
	grant, err := f.e.state.lookupRefresh(pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.e.takeCall(grant); !ok {
		t.Fatal("stale meters refused a live grant")
	}
}

// The visitor key: the proxy's last address, an IPv6 address by its /64, an
// IPv4-mapped address as IPv4, and one shared key for anything unreadable.
func TestVisitorKeys(t *testing.T) {
	e := &Engine{cfg: Config{VisitorHeader: "X-Forwarded-For"}}
	key := func(values ...string) string {
		r := httptest.NewRequest("POST", "/oauth/token", nil)
		for _, v := range values {
			r.Header.Add("X-Forwarded-For", v)
		}
		return e.visitor(r)
	}
	for _, c := range []struct{ got, want string }{
		{key("198.51.100.1, 203.0.113.9"), "203.0.113.9"},
		{key("198.51.100.1", "203.0.113.9"), "203.0.113.9"},
		{key("::ffff:203.0.113.9"), "203.0.113.9"},
		{key("2001:db8:1:2::5"), key("2001:db8:1:2:ffff::1")},
		{key("2001:db8:1:2::5"), "2001:db8:1:2::/64"},
		{key(), "unknown"},
		{key("not an address"), "unknown"},
	} {
		if c.got != c.want {
			t.Errorf("visitor key %q, want %q", c.got, c.want)
		}
	}
	if (&Engine{}).visitor(httptest.NewRequest("GET", "/", nil)) != "" {
		t.Error("without a configured header every visitor must share the total")
	}
	if key("2001:db8:1:2::5") == key("2001:db8:1:3::5") {
		t.Error("different /64 blocks share a key")
	}
}

// Slow anonymous bodies take places only from their own lane: one visitor holds at
// most its lane's share, a request past it is refused at once and its connection
// closes though the body never comes, another visitor still gets in, owner and
// registration lanes full of slow bodies leave a connected app's token refresh
// answering, a full token lane still leaves /mcp's challenge and a signed-in tool call
// answering, and every place comes back.
func TestSlowAnonymousBodiesCannotCrowdOutOthers(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("s", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	f.e.cfg.VisitorHeader = "X-Forwarded-For"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := f.e.HTTPServer()
	go func() { _ = srv.Serve(netutil.LimitListener(l, maxConnections)) }()
	t.Cleanup(func() { _ = srv.Close() })
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			_ = c.Close()
		}
	})
	// send writes a request's headers, declaring a body it never sends.
	send := func(path, visitor string) net.Conn {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: mcp.example.test\r\nX-Forwarded-For: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\n", path, visitor)
		return c
	}
	inLane := func(lane string) int {
		f.e.mu.Lock()
		defer f.e.mu.Unlock()
		return f.e.lanesInUse[lane]
	}
	waitFor := func(lane string, n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for inLane(lane) != n {
			if time.Now().After(deadline) {
				t.Fatalf("lane %s holds %d places, want %d", lane, inLane(lane), n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// answeredAtOnce reads the answer to a request whose body was never sent: the
	// status must come at once and the connection must close after it.
	answeredAtOnce := func(c net.Conn, want int) {
		t.Helper()
		start := time.Now()
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("status %d, want %d", resp.StatusCode, want)
		}
		if _, err = io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("the connection stayed open after the answer: %v", err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("answer and close took %s while the body was held back", d)
		}
		_ = c.Close()
	}
	post := func(path, visitor string, form url.Values, bearer string) *http.Response {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		} else {
			body = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
		}
		req, err := http.NewRequest("POST", "http://"+l.Addr().String()+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "mcp.example.test"
		req.Header.Set("X-Forwarded-For", visitor)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Authorization", "Bearer "+bearer)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	// One visitor holds at most its share of the token lane.
	for range lanes["recovery"].perVisitor {
		held = append(held, send("/oauth/token", "203.0.113.9"))
	}
	waitFor("recovery", lanes["recovery"].perVisitor)
	answeredAtOnce(send("/oauth/token", "203.0.113.9"), 429)
	// Fill the owner and registration lanes, one slow body per visitor.
	for i := range lanes["owner"].places {
		held = append(held, send("/owner/login/options", fmt.Sprintf("192.0.2.%d", i+1)))
	}
	for i := range lanes["other"].places {
		held = append(held, send("/oauth/register", fmt.Sprintf("198.51.100.%d", i+1)))
	}
	waitFor("owner", lanes["owner"].places)
	waitFor("other", lanes["other"].places)
	answeredAtOnce(send("/owner/login/options", "192.0.2.200"), 429)
	// The connected app still renews its access.
	resp := post("/oauth/token", "198.18.0.1", url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {pair.RefreshToken}}, "")
	var renewed tokenPair
	if err := json.NewDecoder(resp.Body).Decode(&renewed); err != nil || resp.StatusCode != 200 {
		t.Fatalf("a token refresh got %d (%v) while the other lanes were full", resp.StatusCode, err)
	}
	_ = resp.Body.Close()
	// A full token lane still leaves /mcp answering.
	for i := range lanes["recovery"].places - lanes["recovery"].perVisitor {
		held = append(held, send("/oauth/token", fmt.Sprintf("198.18.1.%d", i+1)))
	}
	waitFor("recovery", lanes["recovery"].places)
	answeredAtOnce(send("/oauth/token", "198.18.2.1"), 429)
	answeredAtOnce(send("/mcp", "198.18.2.2"), 401)
	resp = post("/mcp", "198.18.2.3", nil, renewed.AccessToken)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("a signed-in tool call got %d while every anonymous lane was full", resp.StatusCode)
	}
	requireStatus(t, request(f.e, "GET", "/.well-known/oauth-protected-resource/mcp", nil, browser{}), 200)
	// Places come back when the bodies end.
	for _, c := range held {
		_ = c.Close()
	}
	held = nil
	for _, name := range []string{"recovery", "owner", "other"} {
		waitFor(name, 0)
	}
	f.e.mu.Lock()
	n := len(f.e.visitors)
	f.e.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d visitor entries left behind", n)
	}
}

// One approved app holds at most half of the tool-call slots; another app's call
// still gets one, and the places come back.
func TestOneAppHoldsAtMostHalfTheToolSlots(t *testing.T) {
	e := newEngine(Config{}, nil)
	half := cap(e.requests) / 2
	var releases []func()
	for range half {
		release, ok := e.takeAppSlot("app_a")
		if !ok {
			t.Fatal("an app was refused a place within its half")
		}
		releases = append(releases, release)
	}
	if _, ok := e.takeAppSlot("app_a"); ok {
		t.Fatalf("one app took more than %d of %d tool-call slots", half, cap(e.requests))
	}
	release, ok := e.takeAppSlot("app_b")
	if !ok {
		t.Fatal("another app was refused while the first held its half")
	}
	release()
	for _, r := range releases {
		r()
	}
	if len(e.appCalls) != 0 {
		t.Fatalf("app places left behind: %v", e.appCalls)
	}
}

// A JSON-RPC batch is many calls charged as one: it is refused before the SDK sees it.
func TestBatchesAreRefused(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("b", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	batch := `  [{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(batch))
	r.Host = "mcp.example.test"
	r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-03-26")
	w := httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	if w.Code != 400 || strings.Contains(w.Body.String(), "tools") {
		t.Fatalf("a batch was answered %d: %.200s", w.Code, w.Body.String())
	}
}

// The remote transport's tool-call slots are the calls that run code the tool server holds
// at once, and a grant's burst is all of them: the transport's number is the server's own
// (hunt-quality-58: it was a second 16 that a comment said was the same).
func TestToolSlotsAreTheServersOutstandingCalls(t *testing.T) {
	if toolSlots != server.MaxOutstanding || grantBurst != server.MaxOutstanding || sharedBurst != 4*server.MaxOutstanding {
		t.Errorf("toolSlots %d, a grant's burst %d and the shared burst %d; want the server's %d calls, the same, and four times it",
			toolSlots, grantBurst, sharedBurst, server.MaxOutstanding)
	}
	if e := newFixture(t).e; cap(e.requests) != server.MaxOutstanding {
		t.Errorf("the engine serves %d tool requests at once, want the server's %d", cap(e.requests), server.MaxOutstanding)
	}
}

// A request refused before the MCP handler made no call, so the grant's meter gets its
// charge back, whichever refusal it was: more batches and over-budget bodies than the
// grant's whole burst leave its meter full (hunt-quality-46).
func TestARequestRefusedBeforeTheHandlerKeepsTheGrantsMeter(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("m", 43)
	b := authorizeBrowser(t, f.e, id, v)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), v)
	g, err := f.e.state.access(pair.AccessToken, f.e.resource())
	if err != nil {
		t.Fatal(err)
	}
	send := func(body string) int {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
		r.Host = "mcp.example.test"
		r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		f.e.ServeHTTP(w, r)
		return w.Code
	}
	meter := func() float64 {
		f.e.mu.Lock()
		defer f.e.mu.Unlock()
		return f.e.grantLimits[g.ID].calls.tokens
	}
	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`
	for i := range 2 * grantBurst {
		if code := send(batch); code != 400 {
			t.Fatalf("batch %d was answered %d, not refused as a batch", i, code)
		}
	}
	if left := meter(); left < grantBurst-0.5 {
		t.Errorf("after refused batches the grant's meter holds %.1f of %d", left, grantBurst)
	}
	if !f.e.bodyBudget.TryAcquire(mcpBodyBudget) {
		t.Fatal("could not hold the body budget")
	}
	for i := range 2 * grantBurst {
		if code := send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`); code != 429 {
			t.Fatalf("body %d was answered %d with the body budget held", i, code)
		}
	}
	f.e.bodyBudget.Release(mcpBodyBudget)
	if left := meter(); left < grantBurst-0.5 {
		t.Errorf("after bodies over the budget the grant's meter holds %.1f of %d", left, grantBurst)
	}
	// A request that reaches the handler is charged.
	if code := send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`); code == 429 || code == 400 {
		t.Fatalf("a ping was answered %d", code)
	}
	if left := meter(); left > grantBurst-0.5 {
		t.Errorf("a request the handler served was not charged: the meter holds %.1f", left)
	}
}

// A call its own grant's meter refuses takes nothing from the meter every grant shares;
// a call a later admission refuses gets its charge back.
func TestARefusedCallLeavesTheSharedAllowance(t *testing.T) {
	f := newFixture(t)
	for range 16 {
		if _, ok := f.e.takeCall("busy"); !ok {
			t.Fatal("the grant's burst was refused")
		}
	}
	for range 40 {
		if _, ok := f.e.takeCall("busy"); ok {
			t.Fatal("a call past the grant's burst was taken")
		}
	}
	f.e.mu.Lock()
	left := f.e.authenticated.tokens
	f.e.mu.Unlock()
	if left < 47 {
		t.Errorf("the shared allowance fell to %.1f; the refused calls drained it", left)
	}
	refund, ok := f.e.takeCall("other")
	if !ok {
		t.Fatal("another grant was refused")
	}
	refund()
	f.e.mu.Lock()
	after := f.e.authenticated.tokens
	f.e.mu.Unlock()
	if after < left-0.5 {
		t.Errorf("a refunded call kept its charge: %.1f then %.1f", left, after)
	}
}

// One approved app holds at most half the body budget, one body at the limit, so two of
// its padded requests cannot refuse another app's (a security scan of 2026-10-16).
func TestOneAppHoldsAtMostHalfTheBodyBudget(t *testing.T) {
	f := newFixture(t)
	// An app is its callback set: the second adds testRedirect to chatgptRedirect.
	token := func(redirects []string, verifierByte string) (string, string) {
		r := request(f.e, "POST", "/oauth/register", map[string]any{"redirect_uris": redirects, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}}, browser{})
		requireStatus(t, r, 201)
		var c struct {
			ID string `json:"client_id"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		id := c.ID
		v := strings.Repeat(verifierByte, 43)
		b := authorizeBrowser(t, f.e, id, v)
		login(t, f, b)
		return id, exchangeCode(t, f.e, id, approveCode(t, f.e, b), v).AccessToken
	}
	idA, tokenA := token([]string{chatgptRedirect}, "p")
	idB, tokenB := token([]string{chatgptRedirect, testRedirect}, "q")
	if idA == idB {
		t.Fatal("the two registrations are one app")
	}
	ping := func(access string) int {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		r.Host = "mcp.example.test"
		r.Header.Set("Authorization", "Bearer "+access)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		f.e.ServeHTTP(w, r)
		return w.Code
	}
	if code := ping(tokenB); code == 429 || code == 413 {
		t.Fatalf("app B alone: %d", code)
	}
	// App A's first padded request holds its half, as a body at mcpBodyLimit would.
	if !f.e.takeBody(digest(idA), mcpBodyLimit) {
		t.Fatal("an app could not hold one body at the limit")
	}
	if f.e.takeBody(digest(idA), 1<<20) {
		t.Fatal("an app held more than half the body budget")
	}
	if code := ping(tokenA); code != 429 {
		t.Fatalf("app A past its half: %d, want 429", code)
	}
	if code := ping(tokenB); code == 429 || code == 413 {
		t.Fatalf("app B was refused with %d while app A held its half", code)
	}
	// The refused and the finished requests gave back what they held.
	f.e.mu.Lock()
	held, apps := f.e.appBody[digest(idA)], len(f.e.appBody)
	f.e.mu.Unlock()
	if held != mcpBodyLimit || apps != 1 {
		t.Fatalf("app A holds %d (want %d) and %d apps hold body memory (want 1)", held, mcpBodyLimit, apps)
	}
}
