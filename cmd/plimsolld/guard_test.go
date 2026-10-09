package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// guardedSandbox is a provider that serves an egress guard at path ("" serves none).
type guardedSandbox struct {
	countingSandbox
	path string
}

func (g *guardedSandbox) EgressGuardPath() string                 { return g.path }
func (g *guardedSandbox) EgressGuardKnownToken(token string) bool { return token == "run-token" }
func (g *guardedSandbox) EgressGuardCall(context.Context, string, string, string, []byte) sandbox.EgressGuardResponse {
	return sandbox.EgressGuardResponse{Status: http.StatusOK, Body: []byte("guarded")}
}

func TestGuardAddrWith(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		serves  bool
		want    string
		wantErr string
	}{
		{"", false, "", ""},
		{"", true, "", "is required"},
		{"127.0.0.1:8443", true, "127.0.0.1:8443", ""},
		{" :8443 ", true, ":8443", ""},
		{"8443", true, "", "must be host:port"},
		{":8443", false, "", "serves no egress guard"},
	} {
		got, err := guardAddrWith(envMap(map[string]string{"PLIMSOLL_GUARD_ADDR": tc.raw}), tc.serves)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q serves=%v: err %v, want one containing %q", tc.raw, tc.serves, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q serves=%v: %q, %v; want %q", tc.raw, tc.serves, got, err, tc.want)
		}
	}
}

func TestEgressGuardOf(t *testing.T) {
	if g, p := egressGuardOf(&countingSandbox{}); g != nil || p != "" {
		t.Errorf("a provider without a guard: %v %q", g, p)
	}
	if g, p := egressGuardOf(&guardedSandbox{}); g != nil || p != "" {
		t.Errorf("a guard provider without a guard URL: %v %q", g, p)
	}
	if g, p := egressGuardOf(&guardedSandbox{path: "/v1/e2b/guard"}); g == nil || p != "/v1/e2b/guard" {
		t.Errorf("a guard provider with a guard URL: %v %q", g, p)
	}
}

// The guard and the RPC procedures never share a listener: a granted guest's one
// permitted destination is the guard, so its listener answers the guard path and
// nothing else, and the RPC listener does not answer the guard path.
func TestGuardHasAListenerOfItsOwn(t *testing.T) {
	sb := &guardedSandbox{path: "/v1/e2b/guard"}
	guard, path := egressGuardOf(sb)
	verifier := tokenTable{"token-b-0123456789abcdef0123456789": {UserID: "b", Scopes: []string{rpc.ScopeCodeRun}}}
	rpcSrv := httptest.NewServer(rpcMux(rpc.NewSandboxService(sb), verifier, 1, sb))
	defer rpcSrv.Close()
	guardSrv := httptest.NewServer(guardHandler(guard, path, 1))
	defer guardSrv.Close()

	post := func(base, p, token string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, base+p, strings.NewReader(`{"method":"GET","path":"/v1/items"}`))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set(sandbox.EgressGuardHeader, token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	get := func(base, p string) int {
		t.Helper()
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := post(guardSrv.URL, path, "run-token"); got != http.StatusOK {
		t.Errorf("guard listener, guard path, live credential: %d, want 200", got)
	}
	if got := post(guardSrv.URL, path, "wrong"); got != http.StatusUnauthorized {
		t.Errorf("guard listener, guard path, unknown credential: %d, want 401", got)
	}
	for _, p := range []string{"/healthz", "/readyz", plimsollv1connect.SandboxServiceDescribeProcedure} {
		if got := get(guardSrv.URL, p); got != http.StatusNotFound {
			t.Errorf("guard listener GET %s: %d, want 404", p, got)
		}
	}
	if got := post(guardSrv.URL, plimsollv1connect.SandboxServiceRunProcedure, "run-token"); got != http.StatusNotFound {
		t.Errorf("guard listener POST the Run procedure: %d, want 404", got)
	}
	if got := post(rpcSrv.URL, path, "run-token"); got != http.StatusNotFound {
		t.Errorf("RPC listener, guard path, live credential: %d, want 404", got)
	}
	if got := get(rpcSrv.URL, "/healthz"); got != http.StatusOK {
		t.Errorf("RPC listener /healthz: %d, want 200", got)
	}
}

func TestSplitConnections(t *testing.T) {
	for _, tc := range []struct {
		n          int
		guard      bool
		rpc, gconn int
	}{
		// An unknown budget stays uncapped on both: a split into ones would let one
		// client hold each listener's only connection.
		{0, false, 0, 0},
		{0, true, 0, 0},
		{1, false, 1, 0},
		{1, true, 1, 1},
		{3, true, 2, 1},
		{1000, false, 1000, 0},
		{1000, true, 500, 500},
	} {
		if r, g := splitConnections(tc.n, tc.guard); r != tc.rpc || g != tc.gconn {
			t.Errorf("splitConnections(%d, %v) = %d, %d; want %d, %d", tc.n, tc.guard, r, g, tc.rpc, tc.gconn)
		}
	}
}

// "OPTIONS *" reaches the handler on every listener: Go's own answer to it reads the
// body first and replies 200, past the guard's checks, the auth middleware and
// unreadbody. Sent with a held-back body over a real socket.
func TestOptionsStarReachesTheHandler(t *testing.T) {
	sb := &guardedSandbox{path: "/v1/e2b/guard"}
	guard, path := egressGuardOf(sb)
	verifier := tokenTable{"token-b-0123456789abcdef0123456789": {UserID: "b", Scopes: []string{rpc.ScopeCodeRun}}}
	for name, h := range map[string]http.Handler{
		"guard": guardHandler(guard, path, 1),
		"rpc":   rpcMux(rpc.NewSandboxService(sb), verifier, 1, sb),
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := newHTTPServer(ln.Addr().String(), h, nil)
		go func() { _ = srv.Serve(ln) }()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(conn, "OPTIONS * HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{}")
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		_ = conn.Close()
		_ = srv.Close()
		if err != nil {
			t.Fatalf("%s listener: no answer to OPTIONS * while its body was held back: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode/100 != 4 {
			t.Fatalf("%s listener: OPTIONS * got %d, want a 4xx from the handler", name, resp.StatusCode)
		}
	}
}

// failingListener accepts nothing: its Accept fails at once with an error that is not
// temporary, which ends http.Server.Serve.
type failingListener struct{ net.Listener }

func (failingListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed for good") }

// A listener that fails is reported to the caller, which drains, rather than ending
// the process on the spot with runs in flight; a signal is reported as no failure.
func TestServeUntilReportsAFailedListener(t *testing.T) {
	healthy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	broken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ok := &http.Server{Handler: http.NotFoundHandler()}
	defer ok.Close()
	done := make(chan error, 1)
	go func() {
		done <- serveUntil(context.Background(), []served{{"rpc", ok, healthy}, {"egress guard", &http.Server{Handler: http.NotFoundHandler()}, failingListener{broken}}})
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "egress guard listener") {
			t.Fatalf("serveUntil = %v, want the guard listener's failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveUntil did not return when a listener failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: http.NotFoundHandler()}
	defer s.Close()
	go func() { done <- serveUntil(ctx, []served{{"rpc", s, l}}) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveUntil after the signal = %v, want nil", err)
	}
}

// exitDaemon runs the real main() in a child process with exactly env and returns its
// exit code and log once it exits, failing the test if it is still running after wait.
func exitDaemon(t *testing.T, env []string, wait time.Duration) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = append([]string{"PLIMSOLLD_RUN_MAIN=1"}, env...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the daemon was still running after %v; log:\n%s", wait, out)
	}
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	return code, string(out)
}

// Startup settles every local setting and binds every listener before the smoke test,
// which on a paid provider creates a billed microVM: a daemon restarting over a bad
// setting would otherwise pay for one each time. Each case uses the docker provider,
// whose smoke test starts real containers, and must fail naming its setting without
// the provider's readiness check having run.
func TestLocalSettingsFailBeforeTheSmokeTest(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	base := []string{"PATH=" + os.Getenv("PATH"), "SANDBOX_PROVIDER=docker", "PLIMSOLL_TOKEN=" + strings.Repeat("t", 32),
		"PLIMSOLL_ADDR=127.0.0.1:0", "PLIMSOLL_METRICS_ADDR=off"}
	for name, tc := range map[string]struct {
		env  []string
		want string
	}{
		"port out of range":      {[]string{"PLIMSOLL_ADDR=127.0.0.1:65536"}, "cannot listen"},
		"port taken":             {[]string{"PLIMSOLL_ADDR=" + taken.Addr().String()}, "cannot listen"},
		"metrics port taken":     {[]string{"PLIMSOLL_METRICS_ADDR=" + taken.Addr().String()}, "cannot listen for metrics"},
		"unreadable TLS keypair": {[]string{"PLIMSOLL_TLS_CERT=/nonexistent/cert.pem", "PLIMSOLL_TLS_KEY=/nonexistent/key.pem"}, "invalid TLS configuration"},
		"hardened, shared token": {[]string{"PLIMSOLL_HARDENED=1"}, "before the smoke test"},
		"bad clients file":       {[]string{"PLIMSOLL_CLIENTS_FILE=/nonexistent/clients.json"}, "PLIMSOLL_CLIENTS_FILE"},
	} {
		t.Run(name, func(t *testing.T) {
			env := append(slices.Clone(base), tc.env...)
			code, log := exitDaemon(t, env, 30*time.Second)
			if code == 0 || !strings.Contains(log, tc.want) {
				t.Fatalf("exit %d, want a failure naming %q; log:\n%s", code, tc.want, log)
			}
			if strings.Contains(log, "sandbox provider") {
				t.Fatalf("the provider's readiness check ran before the setting was refused; log:\n%s", log)
			}
		})
	}
}
