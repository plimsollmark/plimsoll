package sandbox_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Grants in E2B sessions over the stand-in. The stand-in has no network and no E2B
// proxy, so the test does the proxy's part: it reads the guard credential from the
// sandbox's network rule, as the proxy holds it, and calls the guard with it while a
// granted call runs, before it and after it. What only the live service shows (the
// proxy adding the header, the rule across a pause) is the live suite's.

const testGuardURL = "https://guard.example.test"

// grantUpstream is the host API a grant reaches: GET /v1/items answers 200.
func grantUpstream(t *testing.T) *sandbox.HostAPIGrant {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/items" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	t.Cleanup(up.Close)
	return &sandbox.HostAPIGrant{BaseURL: up.URL, Allow: []sandbox.HostRoute{{Method: "GET", Path: "/v1/items"}},
		Minter: sandbox.StaticToken("t"), AllowInSessions: true}
}

// guardToken is the credential the sandbox's network rule gives the guard's host, ""
// when it has no rule.
func (f *e2bFake) guardToken(t *testing.T, id string) string {
	t.Helper()
	f.mu.Lock()
	raw, err := json.Marshal(f.boxes[id].network)
	f.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var n struct {
		Rules map[string][]struct {
			Transform struct {
				Headers map[string]string `json:"headers"`
			} `json:"transform"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatal(err)
	}
	rules := n.Rules["guard.example.test"]
	if len(rules) != 1 {
		return ""
	}
	return rules[0].Transform.Headers[sandbox.EgressGuardHeader]
}

// grantedCall runs a granted snippet that waits 4 s, and meanwhile calls the guard as
// E2B's proxy would, with the credential the sandbox's rule holds. It returns the
// result, the credential and the guard's status (0 if it never answered 200).
func grantedCall(t *testing.T, f *e2bFake, e *sandbox.E2B, s sandbox.Session, grant *sandbox.HostAPIGrant) (sandbox.Result, string, int) {
	t.Helper()
	id := sandbox.E2BSessionSandbox(s)
	type outcome struct {
		res sandbox.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := s.RunJavaScript(context.Background(), sandbox.Request{Timeout: 20 * time.Second, Grant: grant,
			Code: `console.log(typeof host, process.env.NODE_EXTRA_CA_CERTS || "unset"); setTimeout(() => {}, 4000);`})
		done <- outcome{res, err}
	}()
	token, status := "", 0
	for status != http.StatusOK {
		select {
		case o := <-done:
			if o.err != nil {
				t.Fatalf("granted call: %v", o.err)
			}
			return o.res, token, status
		case <-time.After(100 * time.Millisecond):
		}
		if token = f.guardToken(t, id); token != "" {
			status = e.EgressGuardCall(context.Background(), token, "GET", "/v1/items", nil).Status
		}
	}
	o := <-done
	if o.err != nil {
		t.Fatalf("granted call: %v", o.err)
	}
	return o.res, token, status
}

// checkGranted checks what a granted call that reached the guard once returns.
func checkGranted(t *testing.T, res sandbox.Result, status int) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("the guard never served the call's grant (last status %d)", status)
	}
	if res.ExitCode != 0 || !strings.HasPrefix(string(res.Stdout), "object /etc/ssl/certs/ca-certificates.crt") {
		t.Fatalf("the granted call ran without the host SDK or the CA bundle: exit %d, stdout %q, stderr %q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if res.CallTrace.Len() != 1 {
		t.Fatalf("the call's trace holds %d calls, want the 1 the guard served", res.CallTrace.Len())
	}
}

// E2B_SESSION_GRANTS=session: the sandbox carries the guard's rule from its open, and
// its one credential reaches a grant only while a granted call runs.
func TestE2BSessionDockerGrantsSessionRule(t *testing.T) {
	f := newE2BFake(t)
	e := f.provider()
	e.GuardURL, e.SessionGrants = testGuardURL, sandbox.E2BSessionGrantsSession
	grant := grantUpstream(t)
	s := openE2B(t, e)
	id := sandbox.E2BSessionSandbox(s)
	token := f.guardToken(t, id)
	if token == "" {
		t.Fatal("the session's sandbox was created without the guard's rule")
	}
	if e.EgressGuardKnownToken(token) {
		t.Fatal("the guard serves the session's credential before any call")
	}
	res, during, status := grantedCall(t, f, e, s, grant)
	checkGranted(t, res, status)
	if during != token || f.guardToken(t, id) != token {
		t.Fatal("the session's credential changed during a call")
	}
	if e.EgressGuardKnownToken(token) {
		t.Fatal("the guard still serves the session's credential after the call")
	}
	// A project's steps preload the same SDK.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pr, err := s.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{`node -e 'console.log(typeof host)'`}, Timeout: 20 * time.Second, Grant: grant})
	if err != nil || len(pr.Steps) != 1 || strings.TrimSpace(string(pr.Steps[0].Stdout)) != "object" {
		t.Fatalf("granted project: %v %+v", err, pr)
	}
}

// E2B_SESSION_GRANTS=call: the sandbox is deny-all between calls; each granted call
// puts on a rule with a fresh credential and takes it off, and the next call's
// read-back still matches the open.
func TestE2BSessionDockerGrantsCallRule(t *testing.T) {
	f := newE2BFake(t)
	e := f.provider()
	e.GuardURL, e.SessionGrants = testGuardURL, sandbox.E2BSessionGrantsCall
	grant := grantUpstream(t)
	s := openE2B(t, e)
	id := sandbox.E2BSessionSandbox(s)
	if f.guardToken(t, id) != "" {
		t.Fatal("the session's sandbox was created with the guard's rule")
	}
	res, first, status := grantedCall(t, f, e, s, grant)
	checkGranted(t, res, status)
	if f.guardToken(t, id) != "" || e.EgressGuardKnownToken(first) {
		t.Fatal("the call's rule or credential outlived the call")
	}
	if r := e2bSnippet(t, s, `console.log("plain")`); r.ExitCode != 0 {
		t.Fatalf("an ungranted call after a granted one: %+v", r)
	}
	res, second, status := grantedCall(t, f, e, s, grant)
	checkGranted(t, res, status)
	if second == first {
		t.Fatal("two granted calls got the same credential")
	}
}
