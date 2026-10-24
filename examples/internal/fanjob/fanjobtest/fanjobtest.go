// Package fanjobtest holds what the fan-out examples' tests share: the real WebAssembly
// engine under another provider name, so a test has two rooms a bundle can tell apart, and a
// daemon serving a sandbox in-process.
package fanjobtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Renamed is the real wasm engine under another provider name. Alter, when set, rewrites
// what a run printed after the engine ran it, as a sandbox that returned something other than
// what the program printed would.
type Renamed struct {
	*sandbox.WasmSandbox
	Provider string
	Alter    func(stdout string) string
}

// Name is the provider name the twin states.
func (r Renamed) Name() string { return r.Provider }

// RunJavaScript runs the snippet on the real engine and states the twin's provider.
func (r Renamed) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	res, err := r.WasmSandbox.RunJavaScript(ctx, req)
	res.Sandbox = r.Provider // the result names the provider that ran it, and the record takes it from there
	if err == nil && r.Alter != nil {
		res.Stdout = r.Alter(res.Stdout)
	}
	return res, err
}

// Serve starts a daemon for s on a test server and returns its URL.
func Serve(t *testing.T, s sandbox.Sandbox) string {
	t.Helper()
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(rpc.NewSandboxService(s), connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}
