// Package answertest serves the intermediary the official clients' answer binding is
// tested against (failure-injection review, finding 1): a proxy that forwards every
// request to the daemon, so the daemon runs it, and answers every request after the
// first with the first one's answer, headers and all. Only tests import it.
package answertest

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Replay starts the proxy in front of upstream (a base URL) and returns its URL.
func Replay(t testing.TB, upstream string) string {
	t.Helper()
	p := &replay{upstream: upstream}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv.URL
}

type replay struct {
	upstream string

	mu    sync.Mutex
	first *answer
}

type answer struct {
	status int
	header http.Header
	body   []byte
}

func (p *replay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, p.upstream+r.URL.Path, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req.Header = r.Header.Clone()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	p.mu.Lock()
	if p.first == nil {
		p.first = &answer{status: resp.StatusCode, header: resp.Header.Clone(), body: got}
	}
	ans := p.first
	p.mu.Unlock()
	for k, v := range ans.header {
		w.Header()[k] = v
	}
	w.WriteHeader(ans.status)
	_, _ = w.Write(ans.body)
}
