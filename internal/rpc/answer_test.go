package rpc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const testRequestID = "0123456789abcdef0123456789abcdef"

func answerTestServer(t *testing.T) string {
	t.Helper()
	svc := NewSandboxService(&fakeSandbox{jsResult: sandbox.Result{Stdout: "ok", Sandbox: "fake"}})
	path, h := NewHandler(svc, connect.WithReadMaxBytes(1024))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(BindAnswers(mux))
	t.Cleanup(srv.Close)
	return srv.URL
}

func post(t *testing.T, url, contentType, body string, ids ...string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connect-Protocol-Version", "1")
	for _, id := range ids {
		req.Header.Add(protocol.RequestIDHeader, id)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

func TestBindAnswersEchoesOnlyAWellFormedID(t *testing.T) {
	url := answerTestServer(t) + "/plimsoll.v1.SandboxService/Describe"
	for name, tc := range map[string]struct {
		ids  []string
		echo []string
	}{
		"one well-formed ID": {[]string{testRequestID}, []string{testRequestID}},
		"none":               {nil, nil},
		"upper case":         {[]string{strings.ToUpper(testRequestID)}, nil},
		"31 digits":          {[]string{testRequestID[1:]}, nil},
		"not hex":            {[]string{"g123456789abcdef0123456789abcdef"}, nil},
		"sent twice":         {[]string{testRequestID, testRequestID}, nil},
	} {
		resp := post(t, url, "application/json", "{}", tc.ids...)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", name, resp.StatusCode)
		}
		if got := resp.Header.Values(protocol.RequestIDHeader); strings.Join(got, ",") != strings.Join(tc.echo, ",") {
			t.Errorf("%s: echo %q, want %q", name, got, tc.echo)
		}
		if m := resp.Header.Get(protocol.NotDispatchedHeader); m != "" {
			t.Errorf("%s: a success is marked %q", name, m)
		}
	}
}

// What connect-go and net/http refuse before any procedure's handler runs is marked;
// what the handler refuses carries its own detail and no header.
func TestBindAnswersMarksRefusalsBeforeTheHandler(t *testing.T) {
	base := answerTestServer(t) + "/plimsoll.v1.SandboxService/"
	for name, tc := range map[string]struct {
		procedure, contentType, body string
		status                       int
		mark                         string
	}{
		"malformed body":           {"Run", "application/json", "{", http.StatusBadRequest, "request"},
		"body over the read cap":   {"Run", "application/json", `{"protocol":3,"javascript":{"code":"` + strings.Repeat("x", 2048) + `"}}`, http.StatusTooManyRequests, "request"},
		"unsupported content type": {"Run", "text/plain", "{}", http.StatusUnsupportedMediaType, "request"},
		"unknown procedure":        {"Nope", "application/json", "{}", http.StatusNotFound, "unsupported"},
		"refused by the handler":   {"Run", "application/json", `{"javascript":{"code":"1"}}`, http.StatusBadRequest, ""},
	} {
		resp := post(t, base+tc.procedure, tc.contentType, tc.body, testRequestID)
		if resp.StatusCode != tc.status {
			t.Errorf("%s: status %d, want %d", name, resp.StatusCode, tc.status)
		}
		if got := resp.Header.Get(protocol.NotDispatchedHeader); got != tc.mark {
			t.Errorf("%s: mark %q, want %q", name, got, tc.mark)
		}
		if got := resp.Header.Get(protocol.RequestIDHeader); got != testRequestID {
			t.Errorf("%s: echo %q", name, got)
		}
	}
}

// A server binds its whole listener and serves a NewHandler inside it: one echo, and a
// refusal written between the two (the HTTP middlewares') is marked.
func TestBindAnswersNests(t *testing.T) {
	svc := NewSandboxService(&fakeSandbox{})
	path, h := NewHandler(svc)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(BindAnswers(mux))
	t.Cleanup(srv.Close)
	resp := post(t, srv.URL+path+"Describe", "application/json", "{}", testRequestID)
	if got := resp.Header.Values(protocol.RequestIDHeader); len(got) != 1 || got[0] != testRequestID {
		t.Fatalf("echo %q, want one %s", got, testRequestID)
	}
	if got := resp.Header.Get(protocol.NotDispatchedHeader); got != "request" {
		t.Fatalf("the middleware's refusal is marked %q", got)
	}
}
