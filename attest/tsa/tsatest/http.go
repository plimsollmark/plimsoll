package tsatest

import (
	"github.com/plimsollmark/plimsoll/attest/tsa"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Definition is the authority as a requester pins it, at url.
func (a *Authority) Definition(url string) tsa.Authority {
	return tsa.Authority{Name: "tsatest", URL: url, RootSHA256: tsa.CertSHA256(a.Root)}
}

// Server serves Respond over HTTP until the test ends.
func (a *Authority) Server(t testing.TB) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := a.Respond(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(s.Close)
	return s
}
