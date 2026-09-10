package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func TestHTTPServerUsesNativeBoundedH2C(t *testing.T) {
	srv := newHTTPServer(":0", http.NotFoundHandler(), nil)
	if srv.Protocols == nil || !srv.Protocols.HTTP1() || !srv.Protocols.UnencryptedHTTP2() {
		t.Fatalf("protocols = %v, want HTTP/1 + native unencrypted HTTP/2", srv.Protocols)
	}
	if srv.MaxHeaderBytes != 32<<10 {
		t.Fatalf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, 32<<10)
	}
}

type countingSandbox struct{ runs atomic.Int64 }

func (s *countingSandbox) Name() string                           { return "counting" }
func (s *countingSandbox) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationVM }
func (s *countingSandbox) RunJavaScript(_ context.Context, _ sandbox.Request) (sandbox.Result, error) {
	s.runs.Add(1)
	return sandbox.Result{Sandbox: s.Name(), Isolation: s.IsolationClass()}, nil
}
func (s *countingSandbox) RunProject(context.Context, sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	return sandbox.ProjectResult{}, sandbox.ErrUnsupported
}

func TestNativeHTTP1AndH2PriorKnowledgeEnforceMessageCaps(t *testing.T) {
	provider := &countingSandbox{}
	svc := rpc.NewSandboxService(provider)
	path, handler := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithReadMaxBytes(maxRequestBytes))
	mux := http.NewServeMux()
	mux.Handle(path, http.MaxBytesHandler(handler, maxRequestBytes))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(ln.Addr().String(), mux, nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	baseURL := "http://" + ln.Addr().String()

	h1 := plimsollv1connect.NewSandboxServiceClient(http.DefaultClient, baseURL)
	if _, err := h1.RunJavaScriptV2(context.Background(), connect.NewRequest(&plimsollv1.RunJavaScriptV2Request{Code: "1"})); err != nil {
		t.Fatalf("HTTP/1 Connect request failed: %v", err)
	}
	h2Transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	t.Cleanup(h2Transport.CloseIdleConnections)
	h2Client := &http.Client{Transport: h2Transport}
	h2c := plimsollv1connect.NewSandboxServiceClient(h2Client, baseURL)
	if _, err := h2c.RunJavaScriptV2(context.Background(), connect.NewRequest(&plimsollv1.RunJavaScriptV2Request{Code: "1"})); err != nil {
		t.Fatalf("HTTP/2 prior-knowledge Connect request failed: %v", err)
	}
	if got := provider.runs.Load(); got != 2 {
		t.Fatalf("normal requests dispatched %d runs, want 2", got)
	}

	oversized := strings.Repeat("x", maxRequestBytes+1)
	if _, err := h1.RunJavaScriptV2(context.Background(), connect.NewRequest(&plimsollv1.RunJavaScriptV2Request{Code: oversized})); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("oversized raw request code = %v, err=%v; want ResourceExhausted", connect.CodeOf(err), err)
	}
	gzipH2 := plimsollv1connect.NewSandboxServiceClient(h2Client, baseURL, connect.WithSendGzip())
	if _, err := gzipH2.RunJavaScriptV2(context.Background(), connect.NewRequest(&plimsollv1.RunJavaScriptV2Request{Code: oversized})); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("gzip-expanded request code = %v, err=%v; want ResourceExhausted", connect.CodeOf(err), err)
	}
	if got := provider.runs.Load(); got != 2 {
		t.Fatalf("oversized requests reached provider: runs=%d, want 2", got)
	}
}

// envMap returns a getenv func backed by a map, for testing config parsing without
// touching the process environment.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadLimiterConfigDefaults(t *testing.T) {
	lc, err := loadLimiterConfig(envMap(nil), "wasm", 0)
	if err != nil {
		t.Fatal(err)
	}
	if lc.MaxConcurrent != 8 || lc.PerKey != 4 || lc.RatePerMin != 30 || lc.Burst != 30 {
		t.Fatalf("defaults = %+v, want {8 4 30 30}", lc)
	}
}

func TestMinimumIsolationWithRejectsNone(t *testing.T) {
	if got, required, err := minimumIsolationWith(envMap(nil)); err != nil || required || got != sandbox.IsolationUnknown {
		t.Fatalf("empty minimum = %v required=%v err=%v, want unknown/false/nil", got, required, err)
	}
	for raw, want := range map[string]sandbox.IsolationClass{
		"process": sandbox.IsolationProcess, "container": sandbox.IsolationContainer,
		"kernel": sandbox.IsolationKernel, "vm": sandbox.IsolationVM,
	} {
		got, required, err := minimumIsolationWith(envMap(map[string]string{"SANDBOX_MIN_ISOLATION": raw}))
		if err != nil || !required || got != want {
			t.Errorf("%q = %v required=%v err=%v, want %v/true/nil", raw, got, required, err, want)
		}
	}
	for _, raw := range []string{"none", "unknown", "strong"} {
		if _, _, err := minimumIsolationWith(envMap(map[string]string{"SANDBOX_MIN_ISOLATION": raw})); err == nil {
			t.Errorf("SANDBOX_MIN_ISOLATION=%q was accepted", raw)
		}
	}
}

func TestLoadLimiterConfigExplicit(t *testing.T) {
	lc, err := loadLimiterConfig(envMap(map[string]string{
		"SANDBOX_MAX_CONCURRENT":     "16",
		"SANDBOX_PER_KEY_CONCURRENT": "3",
		"SANDBOX_RATE_PER_MIN":       "60",
		"SANDBOX_RATE_BURST":         "10",
	}), "docker", 0)
	if err != nil {
		t.Fatal(err)
	}
	if lc != (limiterConfig{16, 3, 60, 10}) {
		t.Fatalf("lc = %+v, want {16 3 60 10}", lc)
	}
}

func TestLoadLimiterConfigMemoryClamp(t *testing.T) {
	// 1 GiB total, 256 MiB per run -> at most 4 concurrent, clamping the requested 8.
	lc, err := loadLimiterConfig(envMap(map[string]string{
		"SANDBOX_MAX_CONCURRENT":  "8",
		"SANDBOX_TOTAL_MEMORY_MB": "1024",
	}), "docker", 256)
	if err != nil {
		t.Fatal(err)
	}
	if lc.MaxConcurrent != 4 {
		t.Fatalf("max_concurrent = %d, want it clamped to 4", lc.MaxConcurrent)
	}
	// e2b runners live off-host: the aggregate-memory clamp does not apply.
	lc, err = loadLimiterConfig(envMap(map[string]string{
		"SANDBOX_MAX_CONCURRENT":  "8",
		"SANDBOX_TOTAL_MEMORY_MB": "1024",
	}), "e2b", 256)
	if err != nil {
		t.Fatal(err)
	}
	if lc.MaxConcurrent != 8 {
		t.Fatalf("e2b max_concurrent = %d, want the clamp skipped (8)", lc.MaxConcurrent)
	}
}

func TestLoadLimiterConfigMemoryTooSmall(t *testing.T) {
	_, err := loadLimiterConfig(envMap(map[string]string{
		"SANDBOX_TOTAL_MEMORY_MB": "100",
	}), "docker", 256)
	if err == nil {
		t.Fatal("a total that cannot fit one run should error")
	}
}

func TestLoadLimiterConfigInvalidMaxConcurrent(t *testing.T) {
	if _, err := loadLimiterConfig(envMap(map[string]string{"SANDBOX_MAX_CONCURRENT": "9999"}), "wasm", 0); err == nil {
		t.Fatal("out-of-range max_concurrent should error")
	}
}

func TestLoadLimiterConfigUnparseableFailsClosed(t *testing.T) {
	if _, err := loadLimiterConfig(envMap(map[string]string{"SANDBOX_RATE_PER_MIN": "3O"}), "wasm", 0); err == nil {
		t.Fatal("unparseable rate silently became a default")
	}
	if _, err := loadLimiterConfig(envMap(map[string]string{"SANDBOX_TOTAL_MEMORY_MB": "-1"}), "wasm", 0); err == nil {
		t.Fatal("negative aggregate memory limit was silently disabled")
	}
}

func TestValidateLimiterConfig(t *testing.T) {
	valid := [][4]int{{1, 0, 0, 0}, {8, 4, 30, 30}, {1024, 1024, 1, 1}}
	for _, c := range valid {
		if err := validateLimiterConfig(c[0], c[1], c[2], c[3]); err != nil {
			t.Errorf("validateLimiterConfig%v: %v", c, err)
		}
	}
	invalid := [][4]int{{0, 0, 0, 0}, {1025, 0, 0, 0}, {8, 9, 0, 0}, {8, -1, 0, 0}, {8, 1, -1, 0}, {8, 1, 1, -1}}
	for _, c := range invalid {
		if err := validateLimiterConfig(c[0], c[1], c[2], c[3]); err == nil {
			t.Errorf("validateLimiterConfig%v succeeded, want error", c)
		}
	}
}
