package sandbox_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestDockerPreferWarmCell is the daemon's one-call path end to end on docker: plimsoll's
// RPC handler over the docker provider with a pool of 2, driven through the Go client,
// which checks every answer's record. A Run cell that prefers a pool member runs in one
// (warm), and the member is deleted after; the same cell without the flag runs in a
// sandbox made for it, through the runner, and answers byte for byte the same, for
// Python and JavaScript alike, files included.
func TestDockerPreferWarmCell(t *testing.T) {
	sandbox.HeavyDockerTest(t)
	d := pythonSessionDocker(t)
	before := sessionContainers(t)
	startPool(t, d, 2)
	// The pool returns once its first member is ready; the second follows. Both are
	// waited for, so each language's call finds one (a call that found none would run
	// fresh, which is right, but not what this test is about).
	var members []string
	for deadline := time.Now().Add(2 * time.Minute); len(members) < 2; time.Sleep(250 * time.Millisecond) {
		if members = sandbox.DockerPoolReady(d); time.Now().After(deadline) {
			t.Fatalf("the pool has %v ready; want two members", members)
		}
	}
	if made := newContainers(t, before); len(made) != 2 {
		t.Fatalf("the pool made %v; want its two members", made)
	}
	svc := rpc.NewSandboxService(d)
	svc.Logger = slog.New(slog.DiscardHandler)
	svc.Sessions = rpc.SessionConfig{MaxSessions: 4, Pool: 2, Lifetime: 10 * time.Minute, IdleTimeout: time.Minute}
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	r, err := client.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	files := []sandbox.File{{Path: "in/rows.txt", Content: "3\n4\n"}}
	for _, c := range []struct {
		lang sandbox.Language
		code string
	}{
		{sandbox.LanguagePython, "rows = [int(x) for x in open('in/rows.txt')]\nprint('rows', len(rows))\nsum(rows) * 6"},
		{sandbox.LanguageJavaScript, "const rows = require('fs').readFileSync('in/rows.txt', 'utf8').trim().split('\\n').map(Number);\nconsole.log('rows', rows.length);\nrows.reduce((a, b) => a + b, 0) * 6"},
	} {
		req := sandbox.CellRequest{Language: c.lang, Code: c.code, Files: files, MinimumIsolation: sandbox.IsolationContainer}
		start := time.Now()
		warm, err := r.RunCell(ctx, req, client.CellOptions{PreferWarm: true})
		took := time.Since(start)
		if err != nil || !warm.Warm || warm.ExitCode != 0 || warm.Stdout != "rows 2\n42\n" || warm.Record == nil {
			t.Fatalf("%s cell preferring a member: %+v, %v; want it warm, answering rows 2 and 42", c.lang, warm, err)
		}
		start = time.Now()
		fresh, err := r.RunCell(ctx, req, client.CellOptions{})
		freshTook := time.Since(start)
		if err != nil || fresh.Warm || fresh.Record == nil {
			t.Fatalf("%s cell without the flag: %+v, %v; want it fresh", c.lang, fresh, err)
		}
		if fresh.Stdout != warm.Stdout || fresh.Stderr != warm.Stderr || fresh.ExitCode != warm.ExitCode ||
			fresh.InterpreterStarted != warm.InterpreterStarted || fresh.InterpreterEnded != warm.InterpreterEnded {
			t.Fatalf("%s: the fresh answer %+v differs from the warm one %+v", c.lang, fresh, warm)
		}
		if fresh.Record.RequestSHA256 != warm.Record.RequestSHA256 {
			t.Fatalf("%s: the two requests digest differently, though prefer_warm is the only difference", c.lang)
		}
		t.Logf("%s cell: %v from a pool member, %v in a sandbox made for it", c.lang, took.Round(time.Millisecond), freshTook.Round(time.Millisecond))
	}
	// Both members ran a call each and are deleted; the pool makes their replacements.
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(250 * time.Millisecond) {
		now := sessionContainers(t)
		if !slices.Contains(now, members[0]) && !slices.Contains(now, members[1]) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the members %v were not deleted after their calls (containers now %v)", members, now)
		}
	}
}
