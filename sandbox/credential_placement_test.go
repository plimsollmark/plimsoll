package sandbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

const plantedCredential = "CANARY-cred-7f3a9c"

func placementGrant(p CredentialPlacement, pass ...string) *HostAPIGrant {
	return &HostAPIGrant{
		BaseURL: "https://api.internal", Allow: []HostRoute{{Method: "POST", Path: "/v1/models"}},
		Minter: StaticToken(plantedCredential), CredentialPlacement: p, PassHeaders: pass,
	}
}

func okTransport(seen *http.Header) brokerRoundTripFunc {
	return func(req *http.Request) (*http.Response, error) {
		*seen = req.Header.Clone()
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	}
}

func callWith(t *testing.T, g *HostAPIGrant, tr http.RoundTripper, headers map[string][]string) brokerResponse {
	t.Helper()
	core, err := newBrokerSession(g, plantedCredential, tr)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	return core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v1/models", Headers: headers, Body: strings.NewReader(`{}`)})
}

// TestCredentialPlacementHeader: a named header carries the real token, the guest's own
// copy of that name (in any case) is dropped, and Authorization is not sent at all.
func TestCredentialPlacementHeader(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"x-goog-api-key", "api-key", "X-Custom-Token"} {
		var seen http.Header
		resp := callWith(t, placementGrant(CredentialPlacement{Kind: CredentialHeader, Header: name}), okTransport(&seen), map[string][]string{
			"Authorization": {"Bearer guest"}, strings.ToUpper(name): {"guest-key"}, name: {"guest-key-2"}, "X-Api-Key": {"guest-key-3"},
		})
		if resp.Status != http.StatusOK {
			t.Fatalf("%s: %+v", name, resp)
		}
		if got := seen.Values(name); len(got) != 1 || got[0] != plantedCredential {
			t.Errorf("%s = %q, want only the real credential", name, got)
		}
		if v := seen.Values("Authorization"); len(v) != 0 {
			t.Errorf("%s: Authorization reached the upstream: %q", name, v)
		}
		if v := seen.Values("X-Api-Key"); len(v) != 0 {
			t.Errorf("guest x-api-key reached the upstream: %q", v)
		}
	}
}

func TestCredentialPlacementBasic(t *testing.T) {
	t.Parallel()
	for _, user := range []string{"", "svc"} {
		var seen http.Header
		resp := callWith(t, placementGrant(CredentialPlacement{Kind: CredentialBasic, Username: user}), okTransport(&seen), map[string][]string{"Authorization": {"Bearer guest"}})
		if resp.Status != http.StatusOK {
			t.Fatalf("%+v", resp)
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+plantedCredential))
		if got := seen.Values("Authorization"); len(got) != 1 || got[0] != want {
			t.Errorf("user %q: Authorization = %q, want %q", user, got, want)
		}
		u, p, ok := (&http.Request{Header: seen}).BasicAuth()
		if !ok || u != user || p != plantedCredential {
			t.Errorf("BasicAuth = %q %q %v", u, p, ok)
		}
	}
}

func TestCredentialPlacementDefaultIsBearer(t *testing.T) {
	t.Parallel()
	var seen http.Header
	callWith(t, placementGrant(CredentialPlacement{}), okTransport(&seen), map[string][]string{"Authorization": {"Bearer guest"}})
	if got := seen.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+plantedCredential {
		t.Errorf("Authorization = %q", got)
	}
}

// TestCredentialPlacementHealthProbe: the second place the broker sets the credential, the
// host-side health probe, uses the same placement.
func TestCredentialPlacementHealthProbe(t *testing.T) {
	t.Parallel()
	var seen http.Header
	g := placementGrant(CredentialPlacement{Kind: CredentialHeader, Header: "x-goog-api-key"})
	g.HealthCheck = &HostRoute{Method: "GET", Path: "/health"}
	core, err := newBrokerSession(g, plantedCredential, okTransport(&seen))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	if healthy, _ := core.probeHealth(context.Background()); !healthy {
		t.Fatal("probe not healthy")
	}
	if got := seen.Get("x-goog-api-key"); got != plantedCredential || seen.Get("Authorization") != "" {
		t.Errorf("probe headers = %v", seen)
	}
}

// TestCredentialPlacementValidate: a bad placement fails closed at Validate.
func TestCredentialPlacementValidate(t *testing.T) {
	t.Parallel()
	bad := []CredentialPlacement{
		{Kind: "cookie"}, {Kind: CredentialHeader}, {Kind: CredentialHeader, Header: "bad name"}, {Kind: CredentialHeader, Header: "Authorization"},
		{Kind: CredentialHeader, Header: "Host"}, {Kind: CredentialHeader, Header: "Content-Type"}, {Kind: CredentialHeader, Header: "Content-Length"},
		{Kind: CredentialHeader, Header: "Cookie"}, {Kind: CredentialHeader, Header: "Transfer-Encoding"}, {Kind: CredentialHeader, Header: "X-Plimsoll-Guard"},
		{Kind: CredentialHeader, Header: "X-Forwarded-For"}, {Kind: CredentialHeader, Header: "x-k", Username: "u"},
		{Kind: CredentialBasic, Username: "a:b"}, {Kind: CredentialBasic, Username: "a b"}, {Kind: CredentialBasic, Username: "café"},
		{Kind: CredentialBasic, Header: "x-k"}, {Kind: CredentialBearer, Header: "x-k"}, {Username: "u"},
	}
	for _, p := range bad {
		if err := placementGrant(p).Validate(); err == nil {
			t.Errorf("Validate accepted %+v", p)
		}
	}
	noMinter := placementGrant(CredentialPlacement{Kind: CredentialBasic, Username: "u"})
	noMinter.Minter = nil
	if err := noMinter.Validate(); err == nil {
		t.Error("a non-bearer placement with no Minter was accepted")
	}
	if err := placementGrant(CredentialPlacement{Kind: CredentialHeader, Header: "X-Custom-Token"}, "x-custom-token").Validate(); err == nil {
		t.Error("custom credential header also in PassHeaders was accepted")
	}
	g := placementGrant(CredentialPlacement{Kind: CredentialHeader, Header: "X-Custom-Token"})
	g.SetHeaders = map[string]string{"x-custom-token": "v"}
	if err := g.Validate(); err == nil {
		t.Error("credential header also in SetHeaders was accepted")
	}
	// pass_headers and set_headers keep refusing key headers whatever the placement.
	for _, name := range providerKeyHeaders {
		g := placementGrant(CredentialPlacement{Kind: CredentialHeader, Header: name}, name)
		if err := g.Validate(); err == nil {
			t.Errorf("PassHeaders %s accepted beside placement %s", name, name)
		}
		g = placementGrant(CredentialPlacement{Kind: CredentialHeader, Header: name})
		g.SetHeaders = map[string]string{name: "k"}
		if err := g.Validate(); err == nil {
			t.Errorf("SetHeaders %s accepted beside placement %s", name, name)
		}
	}
	for _, ok := range []CredentialPlacement{{}, {Kind: CredentialBearer}, {Kind: CredentialHeader, Header: "x-goog-api-key"}, {Kind: CredentialHeader, Header: "api-key"},
		{Kind: CredentialHeader, Header: "ocp-apim-subscription-key"}, {Kind: CredentialBasic}, {Kind: CredentialBasic, Username: "svc"}} {
		if err := placementGrant(ok).Validate(); err != nil {
			t.Errorf("Validate refused %+v: %v", ok, err)
		}
	}
}

// TestCredentialCanary: a planted credential appears in no answer to the guest, no trace,
// no error and no log line, whatever the upstream does and wherever the credential goes.
func TestCredentialCanary(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	reply := func(code int, body string) brokerRoundTripFunc {
		return func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: code, Header: http.Header{"Retry-After": {"1"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
		}
	}
	transports := map[string]http.RoundTripper{
		"error": brokerRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") }),
		"500":   reply(500, "boom"),
		"503":   reply(503, "down"),
	}
	forms := []string{plantedCredential, base64.StdEncoding.EncodeToString([]byte("svc:" + plantedCredential))}
	for _, p := range []CredentialPlacement{{}, {Kind: CredentialHeader, Header: "x-goog-api-key"}, {Kind: CredentialBasic, Username: "svc"}} {
		for name, tr := range transports {
			core, err := newBrokerSession(placementGrant(p), plantedCredential, tr)
			if err != nil {
				t.Fatal(err)
			}
			var all strings.Builder
			for i := 0; i < 3; i++ {
				resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v1/models", Body: strings.NewReader(`{}`)})
				fmt.Fprintf(&all, "%d %s %s\n", resp.Status, resp.ContentType, resp.Body)
			}
			fmt.Fprintf(&all, "%+v %#v", core.traceSnapshot(), core.traceSnapshot())
			core.Close()
			for _, hay := range []string{all.String(), logs.String()} {
				for _, form := range forms {
					if strings.Contains(hay, form) {
						t.Errorf("placement %+v, upstream %s: credential form %q leaked", p, name, form)
					}
				}
			}
		}
	}
	// A credential the broker refuses is reported without its value.
	_, err := newBrokerSession(placementGrant(CredentialPlacement{Kind: CredentialHeader, Header: "x-goog-api-key"}), plantedCredential+" bad", nil)
	if err == nil || strings.Contains(err.Error(), plantedCredential) {
		t.Errorf("bad credential error = %v", err)
	}
}
