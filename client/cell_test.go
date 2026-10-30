package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// cellServer serves a daemon stating a pool of 2 over a provider with warm members
// waiting, and keeps every Run request that reaches it as sent.
func cellServer(t *testing.T, warm int) (*Remote, *sandboxtest.Pooled, func() []*plimsollv1.RunRequest) {
	t.Helper()
	p := sandboxtest.NewPooled(warm)
	svc := rpc.NewSandboxService(p)
	svc.Sessions = rpc.SessionConfig{MaxSessions: 4, Pool: 2, Lifetime: time.Minute, IdleTimeout: time.Minute}
	var mu sync.Mutex
	var sent []*plimsollv1.RunRequest
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasSuffix(req.URL.Path, "/Run") {
			body, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(strings.NewReader(string(body)))
			var m plimsollv1.RunRequest
			if err := protojson.Unmarshal(body, &m); err == nil {
				mu.Lock()
				sent = append(sent, &m)
				mu.Unlock()
			}
		}
		h.ServeHTTP(w, req)
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return newRemote(t, srv.URL, WithConnectOptions(connect.WithProtoJSON())), p, func() []*plimsollv1.RunRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]*plimsollv1.RunRequest(nil), sent...)
	}
}

var oneCell = sandbox.CellRequest{Language: sandbox.LanguagePython, Code: "6 * 7",
	Files: []sandbox.File{{Path: "in/a.csv", Content: "a"}}, MinimumIsolation: sandbox.IsolationContainer}

// RunCell with PreferWarm sends the flag on a Run cell and returns the member's answer,
// its record checked as a single run's.
func TestRunCellPreferWarm(t *testing.T) {
	r, p, sent := cellServer(t, 1)
	res, err := r.RunCell(context.Background(), oneCell, CellOptions{PreferWarm: true})
	if err != nil || !res.Warm || res.Stdout != "python 1: 6 * 7" || res.Stderr != "in/a.csv\n" {
		t.Fatalf("RunCell = %+v, %v; want the member's answer, warm", res, err)
	}
	if !res.InterpreterStarted || !res.InterpreterEnded {
		t.Fatalf("interpreter flags %v %v; want both", res.InterpreterStarted, res.InterpreterEnded)
	}
	if res.Record == nil || res.Record.Session != "" || res.Record.Sequence != 0 {
		t.Fatalf("record %+v; want a single run's", res.Record)
	}
	if reqs := sent(); len(reqs) != 1 || !reqs[0].GetPreferWarm() || reqs[0].GetCell().GetCode() != "6 * 7" {
		t.Fatalf("sent %v; want one Run cell with prefer_warm", reqs)
	}
	if len(p.FreshRuns()) != 0 {
		t.Fatal("a fresh run was made")
	}
}

// Without the flag, and with it on a miss, the cell runs fresh and the answer says so;
// the miss is no error.
func TestRunCellFresh(t *testing.T) {
	for _, tc := range []struct {
		name       string
		warm       int
		preferWarm bool
	}{{"no flag", 1, false}, {"none waiting", 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			r, p, sent := cellServer(t, tc.warm)
			res, err := r.RunCell(context.Background(), oneCell, CellOptions{PreferWarm: tc.preferWarm})
			if err != nil || res.Warm || res.Stdout != "fresh python: 6 * 7" || res.Record == nil {
				t.Fatalf("RunCell = %+v, %v; want the fresh answer", res, err)
			}
			if reqs := sent(); len(reqs) != 1 || reqs[0].GetPreferWarm() != tc.preferWarm {
				t.Fatalf("sent %v; want prefer_warm %v", reqs, tc.preferWarm)
			}
			if len(p.FreshRuns()) != 1 {
				t.Fatalf("%d fresh runs; want one", len(p.FreshRuns()))
			}
		})
	}
}
