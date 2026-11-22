package sandbox

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Two cases an outside critique of the tools-from-code design (2026-11-18) asked to be
// measured before plimsoll claims anything about where the credential goes: an approved
// route whose answer reflects the credential back (the broker withholds the answer), and
// an answer that redirects off the approved host (never followed). Both run the broker's
// own upstream transport against real listeners.

// TestBrokerWithholdsAnAnswerThatHoldsTheCredential: an allowed route that echoes what the
// broker attached never hands it to the guest, for each way a grant places the credential,
// in the body and in the Content-Type. The guest gets the broker's fixed error in place of
// the whole answer, with nothing of the upstream's in it (so no mark shows where a copy
// was); the row records the call as not delivered with CredentialMatched, and holds no
// credential itself; and the run's grant has ended, so the next call is refused. An answer
// with no copy in it is not touched (finding hunt-security-32).
func TestBrokerWithholdsAnAnswerThatHoldsTheCredential(t *testing.T) {
	t.Parallel()
	basic := base64.StdEncoding.EncodeToString([]byte("svc:" + plantedCredential))
	cases := []struct {
		name      string
		placement CredentialPlacement
		echo      func(r *http.Request) (contentType, body string)
		matched   bool
	}{
		{"bearer, the header echoed", CredentialPlacement{},
			func(r *http.Request) (string, string) {
				return "application/json", `{"you_sent":"` + r.Header.Get("Authorization") + `"}`
			}, true},
		{"a named header, echoed twice", CredentialPlacement{Kind: CredentialHeader, Header: "X-Api-Key"},
			func(r *http.Request) (string, string) {
				k := r.Header.Get("X-Api-Key")
				return "text/plain", k + " and " + k
			}, true},
		{"basic, the header echoed", CredentialPlacement{Kind: CredentialBasic, Username: "svc"},
			func(r *http.Request) (string, string) { return "text/plain", "got " + r.Header.Get("Authorization") }, true},
		{"basic, the decoded password echoed", CredentialPlacement{Kind: CredentialBasic, Username: "svc"},
			func(r *http.Request) (string, string) { return "text/plain", "user svc password " + plantedCredential }, true},
		{"the copy in the Content-Type", CredentialPlacement{},
			func(r *http.Request) (string, string) { return "text/plain; note=" + plantedCredential, "ok" }, true},
		{"no copy in the answer", CredentialPlacement{},
			func(r *http.Request) (string, string) { return "application/json", `{"ok":true,"note":"CANARY-cred"}` }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ct, body := tc.echo(r)
				w.Header().Set("Content-Type", ct)
				_, _ = io.WriteString(w, body)
			}))
			defer upstream.Close()
			g := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/debug/echo"}}, Minter: StaticToken(plantedCredential), CredentialPlacement: tc.placement}
			core, err := newBrokerSession(g, plantedCredential, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer core.Close()
			resp := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/debug/echo"})
			for _, leaked := range []string{plantedCredential, basic} {
				if strings.Contains(string(resp.Body), leaked) || strings.Contains(resp.ContentType, leaked) {
					t.Fatalf("the guest's answer holds the credential: %q, Content-Type %q", resp.Body, resp.ContentType)
				}
			}
			trace := core.traceSnapshot()
			if trace == nil || len(trace.Calls) != 1 {
				t.Fatalf("trace = %+v", trace)
			}
			row := trace.Calls[0]
			if strings.Contains(row.Route, plantedCredential) {
				t.Fatalf("the trace holds the credential: %+v", row)
			}
			if !tc.matched {
				_, body := tc.echo(nil)
				if resp.Status != http.StatusOK || string(resp.Body) != body || row.CredentialMatched || !row.Delivered {
					t.Fatalf("an answer with no copy: %d %q, row %+v; want it whole and delivered", resp.Status, resp.Body, row)
				}
				return
			}
			if resp.Status != http.StatusBadGateway || !strings.Contains(string(resp.Body), errCredentialMatched) {
				t.Fatalf("the guest got %d %q, want the broker's fixed error (502, %q)", resp.Status, resp.Body, errCredentialMatched)
			}
			if fixed := brokerError(http.StatusBadGateway, errCredentialMatched); string(resp.Body) != string(fixed.Body) || resp.ContentType != fixed.ContentType {
				t.Fatalf("the guest got %q (%s), want exactly the broker's own error %q (%s), nothing of the upstream's answer", resp.Body, resp.ContentType, fixed.Body, fixed.ContentType)
			}
			if !row.CredentialMatched || row.Delivered || row.RespBytes != 0 || row.Status != http.StatusOK {
				t.Fatalf("row = %+v, want CredentialMatched, not delivered, no bytes returned, the upstream's status", row)
			}
			if next := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/debug/echo"}); next.Status != http.StatusServiceUnavailable {
				t.Fatalf("the next call got %d %q, want 503: the run's grant has ended", next.Status, next.Body)
			}
		})
	}
}

// TestBrokerAnswersAGuessOfTheCredentialAsAnEvent (finding hunt-security-32): code under a
// grant whose route reflects what it sends posts a batch of guesses of the credential. A batch
// without it comes back as the API sent it, byte for byte, so a miss shows nothing; a batch
// with it gets the broker's fixed error, in which no guess appears, so the guest cannot read
// off which guess it was, and the grant has ended, so no second batch is tested in that run.
func TestBrokerAnswersAGuessOfTheCredentialAsAnEvent(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) // a create route that answers with the object it created
	}))
	defer upstream.Close()
	g := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "POST", Path: "/v1/items"}}, Minter: StaticToken(plantedCredential)}
	core, err := newBrokerSession(g, plantedCredential, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	guess := func(guesses ...string) brokerResponse {
		quoted := make([]string, len(guesses))
		for i, g := range guesses {
			quoted[i] = `"` + g + `"`
		}
		body := `{"c":[` + strings.Join(quoted, ",") + `]}`
		return core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v1/items",
			Headers: map[string][]string{"Content-Type": {"application/json"}}, Body: strings.NewReader(body), ContentLength: int64(len(body))})
	}
	misses := []string{"CANARY-cred-0000", "CANARY-cred-7f3a9d", "canary-cred-7f3a9c"}
	if resp := guess(misses...); resp.Status != http.StatusOK || string(resp.Body) != `{"c":["CANARY-cred-0000","CANARY-cred-7f3a9d","canary-cred-7f3a9c"]}` {
		t.Fatalf("a batch of misses: %d %q, want it back as sent", resp.Status, resp.Body)
	}
	resp := guess(append(misses, plantedCredential, "CANARY-cred-ffff")...)
	if resp.Status != http.StatusBadGateway || !strings.Contains(string(resp.Body), errCredentialMatched) {
		t.Fatalf("a batch holding the credential: %d %q, want the broker's fixed error", resp.Status, resp.Body)
	}
	for _, g := range append(misses, plantedCredential, "CANARY-cred-ffff", "REDACTED") {
		if strings.Contains(string(resp.Body), g) {
			t.Fatalf("the broker's error %q shows %q, so the guest could tell which guess matched", resp.Body, g)
		}
	}
	if next := guess(misses...); next.Status != http.StatusServiceUnavailable {
		t.Fatalf("a batch after the match got %d %q, want 503: the run's grant has ended", next.Status, next.Body)
	}
	trace := core.traceSnapshot()
	if len(trace.Calls) != 2 || trace.Calls[0].CredentialMatched || !trace.Calls[1].CredentialMatched || trace.Calls[1].Delivered {
		t.Fatalf("trace = %+v, want the miss delivered and the match recorded as CredentialMatched, not delivered", trace)
	}
}

// TestBrokerNeverFollowsARedirectOffTheApprovedHost: an allowed route that answers with
// a redirect to another host is not followed, so the credential is never sent there;
// the guest gets the redirect's status and body, without its Location, and the trace
// names the route as the guest asked for it.
func TestBrokerNeverFollowsARedirectOffTheApprovedHost(t *testing.T) {
	t.Parallel()
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		if strings.Contains(r.Header.Get("Authorization"), plantedCredential) {
			t.Errorf("the credential reached the other host")
		}
		_, _ = io.WriteString(w, `{"reached":"the other host"}`)
	}))
	defer other.Close()
	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/collect", code)
		}))
		g := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "POST", Path: "/v1/jobs"}}, Minter: StaticToken(plantedCredential)}
		core, err := newBrokerSession(g, plantedCredential, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v1/jobs", Body: strings.NewReader(`{}`)})
		core.Close()
		upstream.Close()
		if resp.Status != code {
			t.Errorf("redirect %d: the guest got status %d (%s), not the redirect itself", code, resp.Status, resp.Body)
		}
		if strings.Contains(string(resp.Body), "reached") || strings.Contains(string(resp.Body), plantedCredential) {
			t.Errorf("redirect %d: the guest's answer is %s", code, resp.Body)
		}
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("the broker followed a redirect off the approved host %d times", n)
	}
}
