package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestMain lets a test run the daemon's real main() in a child process: the test
// binary, started with PLIMSOLLD_RUN_MAIN=1 and no arguments, is the daemon.
func TestMain(m *testing.M) {
	if os.Getenv("PLIMSOLLD_RUN_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// daemon is a plimsolld child process: the test binary running main() (TestMain).
type daemon struct {
	cmd         *exec.Cmd
	addr        string        // the RPC listener's bound address
	metricsAddr string        // the metrics listener's, or "off"
	done        chan struct{} // closed when the child's stderr closes

	mu  sync.Mutex
	log []string
}

// startDaemon runs the real main() in a child process with exactly env (nothing from
// the caller's shell, so no provider or key leaks in) and waits up to wait for its
// listening line. The log is kept in memory, so a chatty daemon never blocks on a
// full pipe.
func startDaemon(t *testing.T, env []string, wait time.Duration) *daemon {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append([]string{"PLIMSOLLD_RUN_MAIN=1"}, env...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	d := &daemon{cmd: cmd, done: make(chan struct{})}
	type addrs struct{ rpc, metrics string }
	listening := make(chan addrs, 1)
	go func() {
		defer close(d.done)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			d.mu.Lock()
			d.log = append(d.log, sc.Text())
			d.mu.Unlock()
			var rec struct {
				Msg         string `json:"msg"`
				Addr        string `json:"addr"`
				MetricsAddr string `json:"metrics_addr"`
			}
			if json.Unmarshal(sc.Bytes(), &rec) == nil && rec.Msg == "plimsolld listening" {
				listening <- addrs{rec.Addr, rec.MetricsAddr}
			}
		}
	}()
	select {
	case a := <-listening:
		d.addr, d.metricsAddr = a.rpc, a.metrics
	case <-d.done:
		t.Fatalf("daemon exited before it listened:\n%s", d.logText())
	case <-time.After(wait):
		t.Fatalf("daemon did not report listening within %v:\n%s", wait, d.logText())
	}
	return d
}

func (d *daemon) logText() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.log, "\n")
}

// stop sends SIGTERM and requires a clean exit within wait.
func (d *daemon) stop(t *testing.T, wait time.Duration) {
	t.Helper()
	if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.done:
	case <-time.After(wait):
		t.Fatalf("daemon did not exit within %v of SIGTERM:\n%s", wait, d.logText())
	}
	if err := d.cmd.Wait(); err != nil {
		t.Fatalf("daemon did not exit cleanly on SIGTERM: %v\n%s", err, d.logText())
	}
}

// TestDaemonServesMetricsOnlyOnItsOwnListener runs the real main() (disabled
// provider, ephemeral loopback ports) and proves the wiring, not just the handlers:
// /metrics answers on PLIMSOLL_METRICS_ADDR and not on the RPC listener, the probes
// answer on the RPC listener and not on the metrics one, and SIGTERM stops both.
func TestDaemonServesMetricsOnlyOnItsOwnListener(t *testing.T) {
	d := startDaemon(t, []string{"PLIMSOLL_ADDR=127.0.0.1:0", "PLIMSOLL_METRICS_ADDR=127.0.0.1:0"}, 30*time.Second)
	client := &http.Client{Timeout: 10 * time.Second}
	get := func(url string) (int, string) {
		t.Helper()
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, _ := get("http://" + d.addr + "/healthz"); code != http.StatusOK {
		t.Errorf("RPC listener /healthz = %d, want 200", code)
	}
	if code, _ := get("http://" + d.addr + "/metrics"); code != http.StatusNotFound {
		t.Errorf("RPC listener /metrics = %d, want 404: metrics must not be served where callers connect", code)
	}
	if code, body := get("http://" + d.metricsAddr + "/metrics"); code != http.StatusOK || !strings.Contains(body, "plimsoll_runs_total 0") {
		t.Errorf("metrics listener /metrics = %d %q, want 200 with the run counter", code, body)
	}
	if code, _ := get("http://" + d.metricsAddr + "/healthz"); code != http.StatusNotFound {
		t.Errorf("metrics listener /healthz = %d, want 404", code)
	}
	d.stop(t, 30*time.Second)
}

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
func (s *countingSandbox) RunModule(context.Context, sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	return sandbox.ModuleResult{}, sandbox.ErrUnsupported
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
	if _, err := h1.Run(context.Background(), snippetRequest("1")); err != nil {
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
	if _, err := h2c.Run(context.Background(), snippetRequest("1")); err != nil {
		t.Fatalf("HTTP/2 prior-knowledge Connect request failed: %v", err)
	}
	if got := provider.runs.Load(); got != 2 {
		t.Fatalf("normal requests dispatched %d runs, want 2", got)
	}

	oversized := strings.Repeat("x", maxRequestBytes+1)
	if _, err := h1.Run(context.Background(), snippetRequest(oversized)); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("oversized raw request code = %v, err=%v; want ResourceExhausted", connect.CodeOf(err), err)
	}
	gzipH2 := plimsollv1connect.NewSandboxServiceClient(h2Client, baseURL, connect.WithSendGzip())
	if _, err := gzipH2.Run(context.Background(), snippetRequest(oversized)); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("gzip-expanded request code = %v, err=%v; want ResourceExhausted", connect.CodeOf(err), err)
	}
	if got := provider.runs.Load(); got != 2 {
		t.Fatalf("oversized requests reached provider: runs=%d, want 2", got)
	}
}

// snippetRequest is a protocol-stamped envelope around one snippet.
func snippetRequest(code string) *connect.Request[plimsollv1.RunRequest] {
	return connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number,
		Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: code}}})
}

// envMap returns a getenv func backed by a map, for testing config parsing without
// touching the process environment.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadLimiterConfigDefaults(t *testing.T) {
	lc, err := loadLimiterConfig(envMap(nil), "wasm", 0, 0)
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

// The session pool's waiting containers hold memory (each container's limit is one
// run's) and no concurrency slot, so the memory budget is charged for them first: with
// 1 GiB, 256 MiB a run and a pool of 2, two runs fit, not four. A pool that leaves no
// room for one run refuses to start. Before the fix the pool was not charged, so the
// budget did not bound what sandboxes hold.
func TestLoadLimiterConfigChargesTheSessionPool(t *testing.T) {
	env := envMap(map[string]string{"SANDBOX_MAX_CONCURRENT": "8", "SANDBOX_TOTAL_MEMORY_MB": "1024"})
	lc, err := loadLimiterConfig(env, "docker", 256, 2)
	if err != nil {
		t.Fatal(err)
	}
	if lc.MaxConcurrent != 2 {
		t.Fatalf("max_concurrent = %d with a pool of 2 in a budget of 4 runs; want 2", lc.MaxConcurrent)
	}
	if _, err := loadLimiterConfig(env, "docker", 256, 4); err == nil {
		t.Fatal("a pool holding the whole budget was accepted")
	}
	if lc, err := loadLimiterConfig(envMap(map[string]string{"SANDBOX_MAX_CONCURRENT": "8"}), "docker", 256, 2); err != nil || lc.MaxConcurrent != 8 {
		t.Fatalf("with no memory budget the pool changes nothing: %+v, %v", lc, err)
	}
}

func TestLoadLimiterConfigExplicit(t *testing.T) {
	lc, err := loadLimiterConfig(envMap(map[string]string{
		"SANDBOX_MAX_CONCURRENT":     "16",
		"SANDBOX_PER_KEY_CONCURRENT": "3",
		"SANDBOX_RATE_PER_MIN":       "60",
		"SANDBOX_RATE_BURST":         "10",
	}), "docker", 0, 0)
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
	}), "docker", 256, 0)
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
	}), "e2b", 256, 0)
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
	}), "docker", 256, 0)
	if err == nil {
		t.Fatal("a total that cannot fit one run should error")
	}
}

func TestLoadLimiterConfigInvalidMaxConcurrent(t *testing.T) {
	if _, err := loadLimiterConfig(envMap(map[string]string{"SANDBOX_MAX_CONCURRENT": "9999"}), "wasm", 0, 0); err == nil {
		t.Fatal("out-of-range max_concurrent should error")
	}
}

func TestLoadLimiterConfigUnparseableFailsClosed(t *testing.T) {
	if _, err := loadLimiterConfig(envMap(map[string]string{"SANDBOX_RATE_PER_MIN": "3O"}), "wasm", 0, 0); err == nil {
		t.Fatal("unparseable rate silently became a default")
	}
	if _, err := loadLimiterConfig(envMap(map[string]string{"SANDBOX_TOTAL_MEMORY_MB": "-1"}), "wasm", 0, 0); err == nil {
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
