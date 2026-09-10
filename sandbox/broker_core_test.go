package sandbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type brokerRoundTripFunc func(*http.Request) (*http.Response, error)

func (f brokerRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestBrokerCoreOwnsAuthorizationAndExactWireTarget(t *testing.T) {
	var upstreamCalls int
	transport := brokerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamCalls++
		if req.Method != http.MethodPost || req.URL.String() != "https://api.internal/v1/items/42" || req.URL.RequestURI() != "/v1/items/42" {
			t.Errorf("wire request = %s %s (%s)", req.Method, req.URL.String(), req.URL.RequestURI())
		}
		if got := req.Header.Get("Authorization"); got != "Bearer broker-token" {
			t.Errorf("Authorization = %q, want broker credential", got)
		}
		if got := req.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		if got := req.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		body, _ := io.ReadAll(req.Body)
		if string(body) != `{"name":"lamp"}` {
			t.Errorf("body = %q", body)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"secret=x"}},
			Body:       io.NopCloser(strings.NewReader(`{"id":42}`)),
		}, nil
	})
	grant := &HostAPIGrant{
		BaseURL: "https://api.internal",
		Allow:   []HostRoute{{Method: "POST", Path: "/v1/items/*"}},
	}
	core, err := newBrokerSession(grant, "broker-token", transport)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	response := core.Call(context.Background(), brokerCall{
		Method:    "post",
		RawTarget: "/v1/items/42",
		Body:      strings.NewReader(`{"name":"lamp"}`),
	})
	if upstreamCalls != 1 || response.Status != http.StatusCreated || response.ContentType != "application/json" || string(response.Body) != `{"id":42}` {
		t.Fatalf("calls=%d response=%+v", upstreamCalls, response)
	}
	trace := core.traceSnapshot()
	if trace == nil || len(trace.Calls) != 1 || trace.Calls[0].Route != "/v1/items/*" {
		t.Fatalf("trace = %+v, want the route template", trace)
	}
}

func TestBrokerCoreRejectsEveryApproveWireMismatch(t *testing.T) {
	var upstreamCalls int
	transport := brokerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		upstreamCalls++
		return nil, errors.New("must not be reached")
	})
	core, err := newBrokerSession(&HostAPIGrant{
		BaseURL: "https://api.internal",
		Allow:   []HostRoute{{Method: "GET", Path: "/v1/items/*"}},
	}, "", transport)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	for _, target := range []string{
		"/v1/items/x?admin=1",
		"/v1/items/x#fragment",
		"/v1/items/%78",
		"/v1/items/%2e%2e",
		"/v1/items/../admin",
		"/v1/items//x",
		"/v1/items/a\\b",
		"/v1/items/has space",
		"/v1/items/café",
		"/v1/items/[x]",
	} {
		response := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: target})
		if response.Status != http.StatusForbidden {
			t.Errorf("target %q status = %d, want 403", target, response.Status)
		}
	}
	if upstreamCalls != 0 {
		t.Fatalf("mismatched targets reached the upstream %d times", upstreamCalls)
	}
	trace := core.traceSnapshot()
	if trace == nil || trace.Denied != 10 || len(trace.Calls) != 0 {
		t.Fatalf("trace = %+v, want ten redacted denials", trace)
	}
}

func TestBrokerCoreDoesNotFollowRedirects(t *testing.T) {
	var upstreamCalls int
	core, err := newBrokerSession(&HostAPIGrant{
		BaseURL: "https://api.internal",
		Allow:   []HostRoute{{Method: "GET", Path: "/v1/items"}},
	}, "token", brokerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		upstreamCalls++
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": {"https://attacker.invalid/steal"}},
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	response := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/v1/items"})
	if upstreamCalls != 1 || response.Status != http.StatusFound {
		t.Fatalf("calls=%d status=%d, want one RoundTrip and the un-followed 302", upstreamCalls, response.Status)
	}
}

func TestBrokerCoreFreezesGrantForRun(t *testing.T) {
	var paths []string
	grant := &HostAPIGrant{
		BaseURL: "https://api.internal",
		Allow:   []HostRoute{{Method: "GET", Path: "/allowed"}},
	}
	core, err := newBrokerSession(grant, "", brokerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	grant.Allow[0].Path = "/widened"
	if got := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/allowed"}).Status; got != http.StatusOK {
		t.Fatalf("original authority status = %d, want 200", got)
	}
	if got := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/widened"}).Status; got != http.StatusForbidden {
		t.Fatalf("mutated authority status = %d, want 403", got)
	}
	if len(paths) != 1 || paths[0] != "/allowed" {
		t.Fatalf("upstream paths = %v", paths)
	}
}

func TestBrokerCoreCapsResponseBeforeReturningItToAnyAdapter(t *testing.T) {
	core, err := newBrokerSession(&HostAPIGrant{
		BaseURL: "https://api.internal",
		Allow:   []HostRoute{{Method: "GET", Path: "/large"}},
	}, "", brokerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: maxHostResponseBytes + 1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("credential-like-body-must-not-pass")),
		}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	response := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/large"})
	if response.Status != http.StatusBadGateway || strings.Contains(string(response.Body), "credential-like") {
		t.Fatalf("over-cap response escaped core: %+v", response)
	}
}
