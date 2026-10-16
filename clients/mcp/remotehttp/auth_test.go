package remotehttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const testOrigin = "https://mcp.example.test"
const testDaemonToken = "test-only-dedicated-daemon-token"

type virtualKey struct {
	private *ecdsa.PrivateKey
	id      []byte
	counter uint32
}
type browser struct {
	tx, csrf string
	cookie   *http.Cookie
	extra    []*http.Cookie // other approvals' cookies the same browser holds
}
type fixture struct {
	e   *Engine
	cfg Config
	key *virtualKey
}

func requireStatus(t *testing.T, r *httptest.ResponseRecorder, status int) {
	t.Helper()
	if r.Code != status {
		t.Fatalf("HTTP %d, want %d: %s", r.Code, status, r.Body.String())
	}
}
func request(e *Engine, method, path string, body any, b browser) *httptest.ResponseRecorder {
	var reader io.Reader
	contentType := "application/json"
	switch v := body.(type) {
	case nil:
	case url.Values:
		reader = strings.NewReader(v.Encode())
		contentType = "application/x-www-form-urlencoded"
	case string:
		reader = strings.NewReader(v)
	default:
		data, _ := json.Marshal(v)
		reader = bytes.NewReader(data)
	}
	r := httptest.NewRequest(method, testOrigin+path, reader)
	r.RequestURI = r.URL.RequestURI()
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.Header.Set("Content-Type", contentType)
	if method == "POST" {
		r.Header.Set("Origin", testOrigin)
	}
	for _, c := range b.extra {
		r.AddCookie(c)
	}
	if b.cookie != nil {
		r.AddCookie(b.cookie)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w
}
func browserOf(t *testing.T, r *httptest.ResponseRecorder) browser {
	t.Helper()
	requireStatus(t, r, 200)
	capture := func(name string) string {
		m := regexp.MustCompile(name + `="([^"]+)"`).FindStringSubmatch(r.Body.String())
		if len(m) != 2 {
			t.Fatalf("missing browser %s", name)
		}
		return m[1]
	}
	cookies := r.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe approval cookie")
	}
	return browser{tx: capture("data-tx"), csrf: capture("data-csrf"), cookie: cookies[0]}
}
func input(b browser) map[string]any { return map[string]any{"tx": b.tx, "csrf": b.csrf} }

// challengeOf returns a ceremony's challenge and the sealed session the page
// sends back with the authenticator's answer.
func challengeOf(t *testing.T, r *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	requireStatus(t, r, 200)
	var value struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
		Session string `json:"session"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &value); err != nil || value.PublicKey.Challenge == "" || value.Session == "" {
		t.Fatal("missing authenticator challenge")
	}
	return value.PublicKey.Challenge, value.Session
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func newVirtualKey(t *testing.T) *virtualKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &virtualKey{private: key, id: id}
}
func (k *virtualKey) credential(t *testing.T, challenge, origin string, enroll bool, flags byte, ownerID []byte) map[string]any {
	t.Helper()
	kind := "webauthn.get"
	if enroll {
		kind = "webauthn.create"
	}
	clientData, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte("mcp.example.test"))
	authData := append([]byte{}, rp[:]...)
	authData = append(authData, flags)
	k.counter++
	authData = binary.BigEndian.AppendUint32(authData, k.counter)
	response := map[string]any{"clientDataJSON": b64(clientData)}
	if enroll {
		authData = append(authData, make([]byte, 16)...)
		authData = binary.BigEndian.AppendUint16(authData, uint16(len(k.id)))
		authData = append(authData, k.id...)
		key, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: k.private.X.FillBytes(make([]byte, 32)), -3: k.private.Y.FillBytes(make([]byte, 32))})
		authData = append(authData, key...)
		object, _ := cbor.Marshal(map[string]any{"fmt": "none", "authData": authData, "attStmt": map[string]any{}})
		response["attestationObject"] = b64(object)
		response["transports"] = []string{"internal"}
	} else {
		hashed := sha256.Sum256(clientData)
		message := append(append([]byte{}, authData...), hashed[:]...)
		sum := sha256.Sum256(message)
		sig, err := ecdsa.SignASN1(rand.Reader, k.private, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		response["authenticatorData"] = b64(authData)
		response["signature"] = b64(sig)
		response["userHandle"] = b64(ownerID)
	}
	return map[string]any{"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "response": response, "clientExtensionResults": map[string]any{}, "authenticatorAttachment": "platform"}
}
func enroll(t *testing.T, e *Engine, key *virtualKey) {
	t.Helper()
	code, err := e.EnrollmentCode()
	if err != nil {
		t.Fatal(err)
	}
	b := browserOf(t, request(e, "GET", "/owner/enroll", nil, browser{}))
	in := input(b)
	in["code"] = code
	challenge, session := challengeOf(t, request(e, "POST", "/owner/enroll/options", in, b))
	in = input(b)
	in["session"] = session
	in["credential"] = key.credential(t, challenge, testOrigin, true, 0x45, e.owner().id)
	requireStatus(t, request(e, "POST", "/owner/enroll/finish", in, b), 200)
	// A completed enrollment and its challenge are never reusable.
	requireStatus(t, request(e, "POST", "/owner/enroll/finish", in, b), 403)
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	cfg := Config{Listen: "127.0.0.1:8750", PublicURL: testOrigin, StateDir: filepath.Join(t.TempDir(), "state"), Enrollment: true}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	key := newVirtualKey(t)
	enroll(t, e, key)
	if err = e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 8, Tier: sandbox.IsolationKernel})
	upstream, _ := url.Parse(d.URL)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testDaemonToken {
			http.Error(w, "unauthorized", 401)
			return
		}
		next := r.Clone(r.Context())
		next.URL.Scheme = upstream.Scheme
		next.URL.Host = upstream.Host
		next.RequestURI = ""
		response, err := http.DefaultTransport.RoundTrip(next)
		if err != nil {
			http.Error(w, "bad gateway", 502)
			return
		}
		defer response.Body.Close()
		for k, values := range response.Header {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	t.Cleanup(proxy.Close)
	private, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	if err = os.WriteFile(keyFile, private, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Enrollment = false
	cfg.ExecutionEnabled = true
	cfg.Daemon = server.Config{URL: proxy.URL, Token: testDaemonToken, MinimumIsolation: sandbox.IsolationKernel, SigningKeyFile: keyFile, ReceiptsDir: filepath.Join(t.TempDir(), "receipts")}
	e, err = New(cfg)
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
	return &fixture{e, cfg, key}
}
func clientID(t *testing.T, e *Engine) string {
	t.Helper()
	r := request(e, "POST", "/oauth/register", map[string]any{"client_name": "Test <script> account", "redirect_uris": []string{chatgptRedirect}, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}}, browser{})
	requireStatus(t, r, 201)
	var c struct {
		ID string `json:"client_id"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c.ID
}
func authorizeBrowser(t *testing.T, e *Engine, id, verifier string) browser {
	t.Helper()
	q := url.Values{"client_id": {id}, "redirect_uri": {chatgptRedirect}, "response_type": {"code"}, "resource": {testOrigin + "/mcp"}, "scope": {"code:run offline_access"}, "state": {"opaque-owner-state"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	r := request(e, "GET", "/oauth/authorize?"+q.Encode(), nil, browser{})
	b := browserOf(t, r)
	if strings.Contains(r.Body.String(), "Test <script>") {
		t.Fatal("unescaped client identity")
	}
	if !strings.Contains(r.Header().Get("Content-Security-Policy"), "script-src 'nonce-") {
		t.Fatal("no script nonce")
	}
	return b
}
func login(t *testing.T, f *fixture, b browser) {
	t.Helper()
	c, session := challengeOf(t, request(f.e, "POST", "/owner/login/options", input(b), b))
	in := input(b)
	in["session"] = session
	in["credential"] = f.key.credential(t, c, testOrigin, false, 5, f.e.owner().id)
	requireStatus(t, request(f.e, "POST", "/owner/login/finish", in, b), 200)
}
func approveCode(t *testing.T, e *Engine, b browser) string {
	t.Helper()
	r := request(e, "POST", "/oauth/authorize", url.Values{"tx": {b.tx}, "csrf": {b.csrf}, "decision": {"approve"}}, b)
	requireStatus(t, r, 303)
	u, err := url.Parse(r.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != chatgptRedirect || u.Query().Get("iss") != testOrigin || u.Query().Get("state") != "opaque-owner-state" || u.Query().Get("code") == "" {
		t.Fatal("authorization response lost its binding")
	}
	return u.Query().Get("code")
}
func exchangeCode(t *testing.T, e *Engine, id, code, verifier string) tokenPair {
	t.Helper()
	r := request(e, "POST", "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {id}, "code": {code}, "redirect_uri": {chatgptRedirect}, "resource": {testOrigin + "/mcp"}, "code_verifier": {verifier}}, browser{})
	requireStatus(t, r, 200)
	var pair tokenPair
	if err := json.Unmarshal(r.Body.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	return pair
}
func connectMCP(t *testing.T, e *Engine, token string) *mcp.ClientSession {
	t.Helper()
	ts := httptest.NewTLSServer(e)
	t.Cleanup(ts.Close)
	transport := ts.Client().Transport
	httpClient := &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		clone.Host = "mcp.example.test"
		clone.Header.Set("Authorization", "Bearer "+token)
		return transport.RoundTrip(clone)
	})}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "remote-test", Version: "0"}, nil).Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp", HTTPClient: httpClient}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPasskeyConsentTokensAndRealHTTPTools(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	verifier := strings.Repeat("v", 43)
	b := authorizeBrowser(t, f.e, id, verifier)
	requireStatus(t, request(f.e, "POST", "/oauth/authorize", url.Values{"tx": {b.tx}, "csrf": {b.csrf}, "decision": {"approve"}}, b), 403)
	login(t, f, b)
	code := approveCode(t, f.e, b)
	pair := exchangeCode(t, f.e, id, code, verifier)
	requireStatus(t, request(f.e, "POST", "/oauth/authorize", url.Values{"tx": {b.tx}, "csrf": {b.csrf}, "decision": {"approve"}}, b), 403)
	cs := connectMCP(t, f.e, pair.AccessToken)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "run_code", Arguments: map[string]any{"code": "print('secret-code-marker')"}})
	if err != nil || result.IsError {
		t.Fatalf("checked tool call failed: %v", err)
	}
	out, _ := json.Marshal(result)
	if !bytes.Contains(out, []byte(`"stored"`)) {
		t.Fatal("HTTP tool omitted its signed receipt")
	}
	audit, err := os.ReadFile(filepath.Join(f.cfg.StateDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testDaemonToken, pair.AccessToken, pair.RefreshToken, code, "secret-code-marker", "opaque-owner-state"} {
		if bytes.Contains(audit, []byte(secret)) {
			t.Fatal("audit disclosed sensitive content")
		}
	}
	if !bytes.Contains(audit, []byte("checked_record")) {
		t.Fatal("missing audit correlation")
	}
	r := request(f.e, "POST", "/oauth/revoke", url.Values{"client_id": {id}, "token": {pair.RefreshToken}}, browser{})
	requireStatus(t, r, 200)
	_, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "server_info"})
	if err == nil {
		t.Fatal("revoked HTTP grant remained usable")
	}
}

func TestPasskeyRejectsForgeriesAndChallengeReplay(t *testing.T) {
	for _, kind := range []string{"origin", "challenge", "rp", "verification", "signature", "credential", "handle", "replay"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			id := clientID(t, f.e)
			b := authorizeBrowser(t, f.e, id, strings.Repeat("x", 43))
			c, session := challengeOf(t, request(f.e, "POST", "/owner/login/options", input(b), b))
			origin := testOrigin
			flags := byte(5)
			if kind == "origin" {
				origin = "https://attacker.example"
			}
			if kind == "challenge" {
				c = "wrong"
			}
			if kind == "verification" {
				flags = 1
			}
			credential := f.key.credential(t, c, origin, false, flags, f.e.owner().id)
			response := credential["response"].(map[string]any)
			switch kind {
			case "rp":
				data, _ := base64.RawURLEncoding.DecodeString(response["authenticatorData"].(string))
				data[0] ^= 255
				response["authenticatorData"] = b64(data)
			case "signature":
				response["signature"] = b64([]byte("forged"))
			case "credential":
				credential["id"] = b64([]byte("unknown"))
				credential["rawId"] = credential["id"]
			case "handle":
				response["userHandle"] = b64([]byte("other-owner"))
			}
			in := input(b)
			in["session"] = session
			in["credential"] = credential
			if kind == "replay" {
				requireStatus(t, request(f.e, "POST", "/owner/login/finish", in, b), 200)
			}
			requireStatus(t, request(f.e, "POST", "/owner/login/finish", in, b), 403)
			if kind != "replay" {
				requireStatus(t, request(f.e, "POST", "/oauth/authorize", url.Values{"tx": {b.tx}, "csrf": {b.csrf}, "decision": {"approve"}}, b), 403)
			}
		})
	}
}

func TestBrowserBindingAndSafeErrorRedirects(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	b := authorizeBrowser(t, f.e, id, strings.Repeat("x", 43))
	for _, kind := range []string{"origin", "cookie", "csrf"} {
		in := input(b)
		r := httptest.NewRequest("POST", testOrigin+"/owner/login/options", nil)
		r.RequestURI = r.URL.RequestURI()
		r.URL.Scheme = ""
		r.URL.Host = ""
		inBytes, _ := json.Marshal(in)
		r.Body = io.NopCloser(bytes.NewReader(inBytes))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", testOrigin)
		r.AddCookie(b.cookie)
		if kind == "origin" {
			r.Header.Set("Origin", "https://claude.ai")
		}
		if kind == "cookie" {
			r.Header.Del("Cookie")
		}
		if kind == "csrf" {
			r.Body = io.NopCloser(strings.NewReader(`{"tx":"` + b.tx + `","csrf":"wrong"}`))
		}
		w := httptest.NewRecorder()
		f.e.ServeHTTP(w, r)
		requireStatus(t, w, 403)
	}
	q := url.Values{"client_id": {id}, "redirect_uri": {chatgptRedirect + "?attack=1"}}
	r := request(f.e, "GET", "/oauth/authorize?"+q.Encode(), nil, browser{})
	requireStatus(t, r, 400)
	if r.Header().Get("Location") != "" {
		t.Fatal("redirected to unchecked callback")
	}
	q.Set("redirect_uri", chatgptRedirect)
	q.Set("state", "error-state")
	q.Set("scope", "unknown")
	r = request(f.e, "GET", "/oauth/authorize?"+q.Encode(), nil, browser{})
	requireStatus(t, r, 303)
	u, _ := url.Parse(r.Header().Get("Location"))
	if u.Query().Get("iss") != testOrigin || u.Query().Get("state") != "error-state" || u.Query().Get("error") != "invalid_scope" {
		t.Fatal("safe error lost issuer/state")
	}
}

// Two approvals open in one browser (two tabs, or a client reopening its popup)
// keep separate bindings, so the earlier one can still be approved.
func TestTwoApprovalsInOneBrowserKeepTheirBindings(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	v := strings.Repeat("t", 43)
	first := authorizeBrowser(t, f.e, id, v)
	second := authorizeBrowser(t, f.e, id, strings.Repeat("s", 43))
	if first.cookie.Name == second.cookie.Name {
		t.Fatal("two approvals share one cookie name")
	}
	first.extra = []*http.Cookie{second.cookie}
	login(t, f, first)
	exchangeCode(t, f.e, id, approveCode(t, f.e, first), v)
}

// A second enrollment excludes the enrolled passkey, so an authenticator that
// holds it refuses instead of silently replacing it.
func TestEnrollmentExcludesEnrolledPasskeys(t *testing.T) {
	f := newFixture(t)
	code, err := f.e.EnrollmentCode()
	if err != nil {
		t.Fatal(err)
	}
	b := browserOf(t, request(f.e, "GET", "/owner/enroll", nil, browser{}))
	in := input(b)
	in["code"] = code
	r := request(f.e, "POST", "/owner/enroll/options", in, b)
	requireStatus(t, r, 200)
	var options struct {
		PublicKey struct {
			Exclude []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	if err = json.Unmarshal(r.Body.Bytes(), &options); err != nil {
		t.Fatal(err)
	}
	if len(options.PublicKey.Exclude) != 1 || options.PublicKey.Exclude[0].ID != b64(f.key.id) {
		t.Fatalf("enrolled passkey not excluded: %+v", options.PublicKey.Exclude)
	}
}

// One approval yields one code: once approved, its page cannot verify again.
// Denying an approval after the passkey verified it is final: an approve carrying
// the same page, cookie and anti-forgery value issues no code, and no new sign-in
// reopens it. Denying an unverified approval stores nothing.
func TestDenialOfAVerifiedApprovalIsFinal(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	b := authorizeBrowser(t, f.e, id, strings.Repeat("n", 43))
	login(t, f, b)
	requireStatus(t, request(f.e, "POST", "/oauth/authorize", url.Values{"tx": {b.tx}, "csrf": {b.csrf}, "decision": {"deny"}}, b), 303)
	requireStatus(t, request(f.e, "POST", "/oauth/authorize", url.Values{"tx": {b.tx}, "csrf": {b.csrf}, "decision": {"approve"}}, b), 403)
	requireStatus(t, request(f.e, "POST", "/owner/login/options", input(b), b), 403)
	marked := func() int {
		f.e.marks.mu.Lock()
		defer f.e.marks.mu.Unlock()
		return len(f.e.marks.entries)
	}
	before := marked()
	anon := authorizeBrowser(t, f.e, id, strings.Repeat("m", 43))
	requireStatus(t, request(f.e, "POST", "/oauth/authorize", url.Values{"tx": {anon.tx}, "csrf": {anon.csrf}, "decision": {"deny"}}, anon), 303)
	if n := marked(); n != before {
		t.Fatalf("an unverified denial stored %d marks", n-before)
	}
}

func TestAnsweredApprovalCannotIssueASecondCode(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	b := authorizeBrowser(t, f.e, id, strings.Repeat("o", 43))
	login(t, f, b)
	approveCode(t, f.e, b)
	requireStatus(t, request(f.e, "POST", "/owner/login/options", input(b), b), 403)
	requireStatus(t, request(f.e, "POST", "/oauth/authorize", url.Values{"tx": {b.tx}, "csrf": {b.csrf}, "decision": {"approve"}}, b), 403)
}
