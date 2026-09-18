package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	pathpkg "path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// E2B runs agent code in an E2B sandbox (Firecracker microVM) — the right
// isolation for hostile, arbitrary code at scale.
//
// Two planes (no official Go SDK, so both are spoken directly):
//   - Control plane: REST at https://api.e2b.app — create/kill sandboxes.
//   - Data plane: each sandbox's envd, reached at https://49983-<id>.e2b.app,
//     a ConnectRPC server. Commands run via process.Process/Start (a server
//     stream of stdout/stderr/end events); project files are written over envd's
//     HTTP /files endpoint. Sandboxes are created with secured access (secure:
//     true), so every envd request must carry the per-sandbox X-Access-Token —
//     the public envd URL alone grants nothing.
type E2B struct {
	APIKey   string
	Template string // default "base"
	// GuardURL is the absolute HTTPS endpoint exposed by the plimsoll daemon (or
	// another embedder) for brokered E2B host-API calls. E2B network rules allow
	// only this host and inject the per-run guard header outside the guest. Empty
	// disables E2B grants, preserving deny-all execution for unconfigured runs.
	GuardURL string

	// Overridable for tests; empty uses the real E2B endpoints.
	APIBase  string
	EnvdHost func(sandboxID string) string

	HTTP           *http.Client
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	MaxOutputBytes int
	ProjectDir     string // where project files are written; default /home/user/project

	// Maximum resources the chosen template may expose to one hostile run. E2B sizes
	// these at template level; the provider verifies the control plane's live
	// cpuCount/memoryMB/diskSizeMB after create. Zero = no requested cap.
	MaxMemoryMB int
	MaxVCPU     float64
	MaxDiskMB   int
	PidsLimit   int // unsupported by E2B; a non-zero value fails configuration

	// Orphan-reconciliation state. Every sandbox this provider creates is stamped
	// with control-plane metadata naming this exact provider instance, and its ID
	// is tracked while the run is in flight. ReconcileOrphans can then kill any
	// sandbox carrying our stamp that is no longer tracked — a leak from a
	// malformed create response or a failed teardown — without ever touching
	// sandboxes owned by other instances sharing the API key.
	mu         sync.Mutex
	instanceID string
	inflight   map[string]struct{}
	guardMu    sync.Mutex
	guards     map[[32]byte]*brokerSession
}

func (*E2B) Name() string { return "e2b" }

// SupportsProjects is true: project runs work against a toolchain-baked template
// (see e2b/README.md).
func (*E2B) SupportsProjects() bool { return true }

func (e *E2B) SupportsJavaScriptGrants() bool { return e.guardConfig() != nil }
func (e *E2B) SupportsProjectGrants() bool    { return e.guardConfig() != nil }

// IsolationClass is VM: each run gets a disposable Firecracker microVM, the
// strongest boundary offered here.
func (*E2B) IsolationClass() IsolationClass { return IsolationVM }

// Preflight validates E2B configuration. It deliberately does NOT call the E2B API,
// so this is configuration-readiness, not proof that the key/template/control plane
// is currently usable; Run verifies the live allocation after create.
func (e *E2B) Preflight(context.Context) error {
	if strings.TrimSpace(e.APIKey) == "" {
		return errors.New("E2B_API_KEY is not set")
	}
	if _, err := parseE2BGuardURL(e.GuardURL); err != nil {
		return err
	}
	return e.validateResourceConfig()
}

// e2bSmokeTimeout bounds the whole startup smoke: one microVM create (template
// cold starts can take tens of seconds), a short probe run, and teardown.
const e2bSmokeTimeout = 90 * time.Second

// The guard endpoint is reached from inside the VM, but the credential that
// authenticates it is injected by E2B's beta network transform outside the VM.
// It is therefore safe for the guest SDK to know only the endpoint URL.
type e2bGuardEndpoint struct {
	URL  string
	Host string
	Path string
}

type e2bGuardConfig struct {
	Endpoint *e2bGuardEndpoint
	Token    string
	Core     *brokerSession
}

func parseE2BGuardURL(raw string) (*e2bGuardEndpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("E2B_GUARD_URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	if port := u.Port(); port != "" && port != "443" {
		return nil, errors.New("E2B_GUARD_URL must use HTTPS port 443; E2B domain filtering does not cover other ports")
	}
	host := strings.ToLower(u.Hostname())
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(host, ".localhost") {
		return nil, errors.New("E2B_GUARD_URL must not point to a loopback hostname")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil, errors.New("E2B_GUARD_URL must not point to a loopback address")
	}
	p := u.EscapedPath()
	if p == "" || p == "/" {
		p = "/v1/e2b/guard"
	}
	// Keep the guest's literal target and the daemon route byte-identical. E2B
	// domain filtering cannot make a useful promise for encoded or non-canonical
	// paths, and the guard endpoint itself must not be ambiguous.
	if !strings.HasPrefix(p, "/") || pathpkg.Clean(p) != p || strings.ContainsAny(p, `\\%`) {
		return nil, errors.New("E2B_GUARD_URL path must be an absolute, canonical, unencoded path")
	}
	u.Path, u.RawPath = p, ""
	return &e2bGuardEndpoint{URL: u.String(), Host: host, Path: p}, nil
}

func (e *E2B) guardConfig() *e2bGuardEndpoint {
	cfg, err := parseE2BGuardURL(e.GuardURL)
	if err != nil {
		return nil
	}
	return cfg
}

func newE2BGuardToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("mint E2B guard token: %w", err)
	}
	return "crg_" + fmt.Sprintf("%x", raw[:]), nil
}

func (e *E2B) openGuard(ctx context.Context, grant *HostAPIGrant, timeout time.Duration) (*e2bGuardConfig, func(), error) {
	if grant == nil {
		return nil, func() {}, nil
	}
	endpoint, err := parseE2BGuardURL(e.GuardURL)
	if err != nil {
		return nil, func() {}, err
	}
	if endpoint == nil {
		return nil, func() {}, fmt.Errorf("%w: e2b host-API grants require E2B_GUARD_URL", ErrUnsupported)
	}
	core, err := brokerSessionForGrant(ctx, grant, timeout)
	if err != nil {
		return nil, func() {}, err
	}
	token, err := newE2BGuardToken()
	if err != nil {
		core.Close()
		return nil, func() {}, err
	}
	digest := sha256.Sum256([]byte(token))
	e.guardMu.Lock()
	if e.guards == nil {
		e.guards = make(map[[32]byte]*brokerSession)
	}
	e.guards[digest] = core
	e.guardMu.Unlock()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			e.guardMu.Lock()
			delete(e.guards, digest)
			e.guardMu.Unlock()
			core.Close()
		})
	}
	return &e2bGuardConfig{Endpoint: endpoint, Token: token, Core: core}, cleanup, nil
}

func (e *E2B) EgressGuardPath() string {
	if endpoint := e.guardConfig(); endpoint != nil {
		return endpoint.Path
	}
	return ""
}

// EgressGuardKnownToken is the pre-body admission check (see EgressGuardCapable).
// It does exactly what EgressGuardCall's own lookup does and nothing more, so it
// leaks no fact the authoritative path would not have returned anyway.
func (e *E2B) EgressGuardKnownToken(token string) bool {
	return e.guardSession(token) != nil
}

func (e *E2B) guardSession(token string) *brokerSession {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	digest := sha256.Sum256([]byte(token))
	e.guardMu.Lock()
	defer e.guardMu.Unlock()
	return e.guards[digest]
}

func (e *E2B) EgressGuardCall(ctx context.Context, token, method, rawTarget string, body []byte) EgressGuardResponse {
	if strings.TrimSpace(token) == "" {
		return EgressGuardResponse{Status: http.StatusUnauthorized, ContentType: "application/json", Body: []byte(`{"error":"missing egress guard credential"}`)}
	}
	core := e.guardSession(token)
	if core == nil {
		return EgressGuardResponse{Status: http.StatusUnauthorized, ContentType: "application/json", Body: []byte(`{"error":"unknown or expired egress guard credential"}`)}
	}
	resp := core.Call(ctx, brokerCall{Method: method, RawTarget: rawTarget, Body: bytes.NewReader(body)})
	return EgressGuardResponse{Status: resp.Status, ContentType: resp.ContentType, Body: resp.Body}
}

// e2bSmokeProbe runs inside the throwaway smoke microVM. It proves the pieces a
// real run depends on and reports them as one JSON object on stdout: the node
// runtime the template bakes (its absence would fail every snippet run), the
// working directory envd applied (the project-step contract), and — the security
// property unit tests cannot see — whether deny-all egress is actually in force
// on the live network, probed against both a raw IP (no DNS needed) and a DNS
// name. Each fetch gets a short abort timeout so dropped packets fail fast
// instead of hanging the smoke.
const e2bSmokeProbe = `(async () => {
  const egressOpen = [];
  for (const target of ["https://1.1.1.1", "https://example.com"]) {
    try {
      await fetch(target, { signal: AbortSignal.timeout(4000) });
      egressOpen.push(target);
    } catch {}
  }
  process.stdout.write(JSON.stringify({ node: process.version, cwd: process.cwd(), egressOpen }));
})();`

// SmokeTest proves the CONFIGURED E2B template supports this provider's contract
// by exercising one throwaway microVM end to end: secured create (both access
// tokens), live resource verification, multi-file staging into the project dir,
// and a probe executed through the exact project-step path (sh script → node).
// Preflight checks configuration only; this verifies behavior — a template
// missing its toolchain, an unreachable control plane, or an egress policy not
// actually in force fails startup here instead of failing (or silently
// weakening) the first hostile run. It creates one real, billable sandbox, so
// the daemon runs it once at startup — never on unauthenticated poll paths.
func (e *E2B) SmokeTest(ctx context.Context) error {
	if err := e.Preflight(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, e2bSmokeTimeout)
	defer cancel()
	vm, err := e.create(ctx, remainingBudget(ctx, e2bSmokeTimeout))
	if err != nil {
		return fmt.Errorf("e2b template smoke: create: %w", err)
	}
	defer e.kill(vm.id)
	if err := e.verifyResources(ctx, vm); err != nil {
		return fmt.Errorf("e2b template smoke: %w", err)
	}
	// Stage probe + step script in ONE multipart request and run the probe through
	// `sh <script>` with cwd set — byte-for-byte the mechanics RunProject uses, so
	// passing here means the template can actually serve project runs.
	dir := e.projectDir()
	const stepPath = "/tmp/plimsoll-smoke-step.sh"
	files := []File{
		{Path: pathpkg.Join(dir, "plimsoll-smoke.cjs"), Content: e2bSmokeProbe},
		{Path: stepPath, Content: "node plimsoll-smoke.cjs\n"},
	}
	if err := e.writeFiles(ctx, vm, files); err != nil {
		return fmt.Errorf("e2b template smoke: stage probe: %w", err)
	}
	out, err := e.runProcess(ctx, vm, "sh", []string{stepPath}, dir)
	if err != nil {
		return fmt.Errorf("e2b template smoke: run probe: %w", err)
	}
	if out.exitCode != 0 {
		// 127 here is the classic missing-toolchain signature (sh could not find node).
		return fmt.Errorf("e2b template smoke: probe exited %d on template %q (a template missing its toolchain cannot serve runs): %s",
			out.exitCode, e.template(), strings.TrimSpace(out.stderr))
	}
	var report struct {
		Node       string   `json:"node"`
		Cwd        string   `json:"cwd"`
		EgressOpen []string `json:"egressOpen"`
	}
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		return fmt.Errorf("e2b template smoke: unparseable probe report %q: %w", out.stdout, err)
	}
	if report.Node == "" {
		return errors.New("e2b template smoke: probe reported no node version")
	}
	if report.Cwd != dir {
		return fmt.Errorf("e2b template smoke: probe ran in %q, not the project dir %q — step cwd is not honored", report.Cwd, dir)
	}
	if len(report.EgressOpen) > 0 {
		return fmt.Errorf("e2b template smoke: egress is OPEN to %s — deny-all network policy is not in force", strings.Join(report.EgressOpen, ", "))
	}
	return nil
}

func (e *E2B) validateResourceConfig() error {
	if e.MaxMemoryMB < 0 || e.MaxVCPU < 0 || e.MaxDiskMB < 0 || e.PidsLimit < 0 || math.IsNaN(e.MaxVCPU) || math.IsInf(e.MaxVCPU, 0) {
		return errors.New("e2b resource caps must be finite and non-negative")
	}
	if e.MaxVCPU > 0 && math.Trunc(e.MaxVCPU) != e.MaxVCPU {
		return fmt.Errorf("e2b cannot enforce fractional SANDBOX_CPUS=%v; templates expose integral vCPU counts", e.MaxVCPU)
	}
	if e.PidsLimit > 0 {
		return errors.New("e2b cannot enforce SANDBOX_PIDS; leave it unset or choose docker")
	}
	return nil
}

func (e *E2B) apiBase() string {
	if e.APIBase != "" {
		return e.APIBase
	}
	return "https://api.e2b.app"
}

func (e *E2B) envdHost(id string) string {
	if e.EnvdHost != nil {
		return e.EnvdHost(id)
	}
	return "https://49983-" + id + ".e2b.app"
}

func (e *E2B) httpClient() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return http.DefaultClient
}

func (e *E2B) template() string {
	if strings.TrimSpace(e.Template) != "" {
		return e.Template
	}
	return "base"
}

func (e *E2B) projectDir() string {
	if e.ProjectDir != "" {
		return e.ProjectDir
	}
	return "/home/user/project"
}

func (e *E2B) maxOutput() int {
	if e.MaxOutputBytes > 0 {
		return e.MaxOutputBytes
	}
	return 64 << 10
}

func (e *E2B) clampTimeout(req time.Duration, def, max time.Duration) time.Duration {
	if req <= 0 {
		req = def
		if req <= 0 {
			req = 30 * time.Second
		}
	}
	if max <= 0 {
		max = 120 * time.Second
	}
	if req > max {
		req = max
	}
	return req
}

// e2bGuestCABundle points Node at the guest's OS trust-store bundle. A guarded
// E2B run reaches the guard over HTTPS that E2B's beta per-host network transform
// terminates with an internal proxy CA; that CA is installed in the guest OS
// trust store, but Node ships its own compiled-in CA bundle and does not read the
// OS store unless NODE_EXTRA_CA_CERTS points at it. Setting it lets brokered guard
// calls verify the proxy certificate WITHOUT disabling TLS verification (the newer
// --use-system-ca would too, but needs Node 22.15+, so the env var is used for
// template-version independence). Root cause and fix confirmed by E2B support.
const e2bGuestCABundle = "/etc/ssl/certs/ca-certificates.crt"

// RunJavaScript runs a single snippet from a staged CommonJS file.
func (e *E2B) RunJavaScript(ctx context.Context, req Request) (Result, error) {
	if err := ValidateRequest(req); err != nil {
		return Result{Sandbox: "e2b", Isolation: IsolationVM}, err
	}
	if err := CheckMinimumIsolation(e.IsolationClass(), req.MinimumIsolation); err != nil {
		return Result{Sandbox: e.Name(), Isolation: e.IsolationClass()}, err
	}
	if strings.TrimSpace(e.APIKey) == "" {
		return Result{Sandbox: "e2b"}, errors.New("E2B_API_KEY is not set")
	}
	if err := e.validateResourceConfig(); err != nil {
		return Result{Sandbox: "e2b", Isolation: IsolationVM}, err
	}
	timeout := e.clampTimeout(req.Timeout, e.DefaultTimeout, e.MaxTimeout)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	budget := remainingBudget(runCtx, timeout)
	guard, closeGuard, err := e.openGuard(runCtx, req.Grant, budget)
	if err != nil {
		return Result{Sandbox: "e2b", Isolation: IsolationVM}, err
	}
	defer closeGuard()

	vm, err := e.create(runCtx, budget, guard)
	if err != nil {
		return Result{Sandbox: "e2b"}, err
	}
	defer e.kill(vm.id) // cleanup is part of the run lifecycle and graceful drain
	if err := e.verifyResources(runCtx, vm); err != nil {
		return Result{Sandbox: "e2b", Isolation: IsolationVM}, err
	}

	// Do not pass agent code as one `node -e` argv element: Linux limits a single
	// argument to roughly 128 KiB while the public request limit is 256 KiB (and
	// the injected SDK adds more). Upload a file so every accepted snippet works.
	const snippetPath = "/tmp/plimsoll-snippet.cjs"
	code := req.Code
	if req.Grant != nil {
		code = withE2BHostSDK(code, req.Grant, guard.Endpoint.URL)
	}
	if err := e.writeFile(runCtx, vm, snippetPath, code); err != nil {
		return Result{Sandbox: "e2b", Isolation: IsolationVM}, fmt.Errorf("e2b write snippet: %w", err)
	}
	start := time.Now()
	// A guarded run reaches the guard over HTTPS terminated by E2B's proxy CA;
	// point Node at the guest OS trust store so it verifies (see e2bGuestCABundle).
	var runEnv map[string]string
	if req.Grant != nil {
		runEnv = map[string]string{"NODE_EXTRA_CA_CERTS": e2bGuestCABundle}
	}
	out, err := e.runProcessWithEnv(runCtx, vm, "node", []string{snippetPath}, "", runEnv)
	res := Result{
		Stdout:          out.stdout,
		Stderr:          out.stderr,
		StdoutTruncated: out.stdoutTruncated,
		StderrTruncated: out.stderrTruncated,
		ExitCode:        out.exitCode,
		Duration:        time.Since(start),
		Sandbox:         "e2b",
		Isolation:       IsolationVM,
	}
	if guard != nil {
		res.CallTrace = guard.Core.traceSnapshot()
	}
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			res.TimedOut = true
			res.ExitCode = 124
			return res, nil
		}
		return Result{Sandbox: "e2b"}, err
	}
	return res, nil
}

// RunModule is unsupported: the module worker image is a docker recipe, and no
// E2B template carries it. Same shape as the docker provider, later, if a
// template is built for it.
func (e *E2B) RunModule(_ context.Context, req ModuleRequest) (ModuleResult, error) {
	if err := ValidateModuleRequest(req); err != nil {
		return ModuleResult{Sandbox: "e2b", Isolation: IsolationVM}, err
	}
	if err := CheckMinimumIsolation(IsolationVM, req.MinimumIsolation); err != nil {
		return ModuleResult{Sandbox: "e2b", Isolation: IsolationVM}, err
	}
	return ModuleResult{Sandbox: "e2b", Isolation: IsolationVM}, ErrUnsupported
}

// RunProject writes the files then runs each step in order, stopping on failure.
func (e *E2B) RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error) {
	if err := ValidateProjectRequest(req); err != nil {
		return ProjectResult{Sandbox: "e2b", Isolation: IsolationVM}, err
	}
	if err := CheckMinimumIsolation(e.IsolationClass(), req.MinimumIsolation); err != nil {
		return ProjectResult{Sandbox: e.Name(), Isolation: e.IsolationClass()}, err
	}
	if strings.TrimSpace(e.APIKey) == "" {
		return ProjectResult{Sandbox: "e2b"}, errors.New("E2B_API_KEY is not set")
	}
	if err := e.validateResourceConfig(); err != nil {
		return ProjectResult{Sandbox: "e2b", Isolation: IsolationVM}, err
	}
	timeout := e.clampTimeout(req.Timeout, e.DefaultTimeout, e.MaxTimeout)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	budget := remainingBudget(runCtx, timeout)
	guard, closeGuard, err := e.openGuard(runCtx, req.Grant, budget)
	if err != nil {
		return ProjectResult{Sandbox: "e2b", Isolation: IsolationVM}, err
	}
	defer closeGuard()

	vm, err := e.create(runCtx, budget, guard)
	if err != nil {
		return ProjectResult{Sandbox: "e2b"}, err
	}
	defer e.kill(vm.id) // cleanup is part of the run lifecycle and graceful drain
	if err := e.verifyResources(runCtx, vm); err != nil {
		return ProjectResult{Sandbox: "e2b", Isolation: IsolationVM}, err
	}

	dir := e.projectDir()
	staged := make([]File, 0, len(req.Files))
	for _, f := range req.Files {
		// Defense in depth: the RPC layer already validates, but never write a path
		// that would escape the project dir even inside the disposable microVM.
		dest := pathpkg.Join(dir, f.Path)
		if dest != dir && !strings.HasPrefix(dest, dir+"/") {
			return ProjectResult{Sandbox: "e2b", Isolation: IsolationVM, Outcome: ProjectOutcomeSetupFailed, Detail: "illegal file path: " + f.Path}, nil
		}
		staged = append(staged, File{Path: dest, Content: f.Content})
	}
	if req.Grant != nil {
		staged = append(staged, File{Path: "/tmp/plimsoll-e2b-host.mjs", Content: hostE2BSDKModule(req.Grant, guard.Endpoint.URL)})
	}
	// One multipart round trip for the whole project, not one POST per file.
	if err := e.writeFiles(runCtx, vm, staged); err != nil {
		return ProjectResult{Sandbox: "e2b", Isolation: IsolationVM}, fmt.Errorf("could not write project files: %w", err)
	}

	res := ProjectResult{Sandbox: "e2b", Isolation: IsolationVM, Outcome: ProjectOutcomeCompleted}
	if guard != nil {
		res.CallTrace = guard.Core.traceSnapshot()
	}
	envs := map[string]string(nil)
	if req.Grant != nil {
		// NODE_OPTIONS preloads the host SDK; NODE_EXTRA_CA_CERTS lets the step's
		// node trust the E2B proxy CA for guard calls (see e2bGuestCABundle).
		envs = map[string]string{
			"NODE_OPTIONS":        "--import /tmp/plimsoll-e2b-host.mjs",
			"NODE_EXTRA_CA_CERTS": e2bGuestCABundle,
		}
	}
	for _, step := range req.Steps {
		// As with snippets, avoid `sh -c <huge command>` and its per-argument OS
		// limit. Reuse one VM-local script; the reported Command remains the caller's
		// original string.
		const stepPath = "/tmp/plimsoll-step.sh"
		if err := e.writeFile(runCtx, vm, stepPath, step); err != nil {
			return ProjectResult{Sandbox: "e2b", Isolation: IsolationVM}, fmt.Errorf("could not stage step: %w", err)
		}
		start := time.Now()
		out, err := e.runProcessWithEnv(runCtx, vm, "sh", []string{stepPath}, dir, envs)
		if err != nil {
			if runCtx.Err() == context.DeadlineExceeded {
				res.Steps = append(res.Steps, StepResult{Command: step, ExitCode: 124, TimedOut: true, Duration: time.Since(start)})
				res.Outcome, res.Detail = ProjectOutcomeTimedOut, "run exceeded the time budget"
				return res, nil
			}
			return ProjectResult{Sandbox: "e2b", Isolation: IsolationVM}, err
		}
		res.Steps = append(res.Steps, StepResult{
			Command:         step,
			Stdout:          out.stdout,
			Stderr:          out.stderr,
			StdoutTruncated: out.stdoutTruncated,
			StderrTruncated: out.stderrTruncated,
			ExitCode:        out.exitCode,
			Duration:        time.Since(start),
		})
		if guard != nil {
			res.CallTrace = guard.Core.traceSnapshot()
		}
		if out.exitCode != 0 {
			break
		}
	}

	// Capture requested artifacts (those that exist), even after a failed step.
	var total int64
	for _, p := range req.Artifacts {
		dest := pathpkg.Join(dir, p)
		if dest != dir && !strings.HasPrefix(dest, dir+"/") {
			continue
		}
		data, ok, err := e.readFile(runCtx, vm, dest)
		if err != nil {
			return ProjectResult{Sandbox: "e2b", Isolation: IsolationVM}, fmt.Errorf("read artifact %q: %w", p, err)
		}
		if !ok {
			continue
		}
		if total+int64(len(data)) > maxArtifactBytesTotal {
			res.ArtifactsTruncated = true
			break
		}
		total += int64(len(data))
		res.Artifacts = append(res.Artifacts, Artifact{Path: p, Content: data})
	}
	return res, nil
}

// maxArtifactBytesTotal bounds the total captured-artifact bytes per run.
const maxArtifactBytesTotal = 8 << 20

// remainingBudget folds an earlier caller deadline into all E2B-side lifetimes:
// the minted credential, VM TTL, and envd process timeout must never outlive the
// request context merely because the requested/provider timeout was larger.
func remainingBudget(ctx context.Context, fallback time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return time.Millisecond
		}
		if fallback <= 0 || remaining < fallback {
			return remaining
		}
	}
	return fallback
}

// readFile downloads a file from envd's HTTP /files endpoint. found=false is
// reserved for a 404; transport/auth/server failures remain infrastructure errors.
func (e *E2B) readFile(ctx context.Context, vm e2bVM, path string) ([]byte, bool, error) {
	q := url.Values{"path": {path}, "username": {"user"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.envdHost(vm.id)+"/files?"+q, nil)
	if err != nil {
		return nil, false, err
	}
	vm.authorize(req)
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, false, fmt.Errorf("envd files: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArtifactBytesTotal+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxArtifactBytesTotal {
		return nil, false, fmt.Errorf("artifact exceeds %d bytes", maxArtifactBytesTotal)
	}
	return data, true, nil
}

// ---- control plane (REST) ----

// e2bVM is a live sandbox handle: its ID plus the per-sandbox envd access token
// that secured access returns. Every data-plane (envd) request must present the
// token — without it the per-sandbox URL would be callable by anyone who learns
// the sandbox ID during its lifetime.
type e2bVM struct {
	id                 string
	accessToken        string
	trafficAccessToken string
}

// authorize stamps the envd access token onto a data-plane request.
func (vm e2bVM) authorize(req *http.Request) {
	req.Header.Set("X-Access-Token", vm.accessToken)
	if vm.trafficAccessToken != "" {
		req.Header.Set("e2b-traffic-access-token", vm.trafficAccessToken)
	}
}

// create starts a microVM. Per-run CPU/RAM/disk are NOT set here: E2B sizes those
// at the template level. Immediately after create, verifyResources reads the live
// allocation and rejects any configured maximum that is exceeded. The per-create
// timeout below caps VM lifetime and is the leak safety net.
func (e *E2B) create(ctx context.Context, timeout time.Duration, guard ...*e2bGuardConfig) (e2bVM, error) {
	create := map[string]any{
		"templateID": e.template(),
		// Give the sandbox a little longer than the run budget so a slow run is
		// killed by our context, not by the sandbox expiring underneath it. This
		// "timeout" is also the leak safety net: even if kill never lands, E2B
		// auto-reaps the microVM when it elapses.
		"timeout": int(timeout.Seconds()) + 10,
		// The instance stamp keys orphan reconciliation: ReconcileOrphans lists by
		// it and kills whatever this exact provider instance created but no longer
		// tracks, without touching other instances sharing the API key.
		"metadata": map[string]string{"sdk": "plimsoll", "instance": e.instance()},
		// Secured access: envd requires the per-sandbox access token on every
		// data-plane request, so the public https://49983-<id>.e2b.app URL is not an
		// open door to anyone who learns the sandbox ID while it lives.
		"secure": true,
	}
	network := map[string]any{
		"denyOut":            []string{"0.0.0.0/0"},
		"allowPublicTraffic": false,
	}
	if len(guard) > 0 && guard[0] != nil {
		cfg := guard[0]
		network["allowOut"] = []string{cfg.Endpoint.Host}
		// E2B's beta transform runs outside the guest network namespace. The VM
		// sees only the guard URL; the guard credential is never staged in code or
		// environment variables.
		network["rules"] = map[string]any{
			cfg.Endpoint.Host: []any{
				map[string]any{"transform": map[string]any{
					"headers": map[string]string{E2BGuardHeader: cfg.Token},
				}},
			},
		}
	}
	create["network"] = network
	body, _ := json.Marshal(create)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.apiBase()+"/sandboxes", bytes.NewReader(body))
	if err != nil {
		return e2bVM{}, err
	}
	req.Header.Set("X-API-Key", e.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return e2bVM{}, err
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		// Non-2xx: no billable microVM was created, so there is nothing to reap.
		return e2bVM{}, fmt.Errorf("e2b create sandbox: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	// Past this point the API returned success, so a microVM almost certainly EXISTS
	// and is billing. Every failure below must reap whatever we can identify (the
	// sandbox ID) instead of leaking it; when we cannot even parse an ID, say so
	// loudly so the leak is tracked rather than silent (the create "timeout" is the
	// last-resort backstop that eventually reaps it).
	var out struct {
		SandboxID          string `json:"sandboxID"`
		EnvdAccessToken    string `json:"envdAccessToken"`
		TrafficAccessToken string `json:"trafficAccessToken"`
	}
	unmarshalErr := json.Unmarshal(raw, &out)
	if out.SandboxID == "" {
		slog.Error("e2b create sandbox: 2xx response with no parseable sandbox ID; scheduling orphan reconciliation by instance stamp",
			"unmarshal_error", unmarshalErr, "read_error", readErr, "instance", e.instance())
		// The microVM exists and is billing even though its ID never reached us,
		// but it does carry our instance stamp. Reap it by reconciliation once the
		// grace window (which protects concurrent in-flight creates) has passed;
		// the create "timeout" remains the backstop if this process dies first.
		go func() {
			time.Sleep(e2bReconcileGrace + 5*time.Second)
			rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if n, err := e.ReconcileOrphans(rctx); err != nil {
				slog.Error("e2b: orphan reconciliation after malformed create response failed", "error", err)
			} else if n > 0 {
				slog.Warn("e2b: orphan reconciliation reaped leaked sandboxes", "count", n)
			}
		}()
		return e2bVM{}, errors.New("e2b create sandbox: unexpected response (no sandbox ID)")
	}
	e.trackVM(out.SandboxID)
	// We have an ID, so any remaining problem is recoverable: reap the VM before
	// returning the error. A short body read failure or malformed trailer means we
	// cannot trust the rest of the response, so distrust the whole handle.
	if unmarshalErr != nil || readErr != nil {
		e.kill(out.SandboxID)
		return e2bVM{}, fmt.Errorf("e2b create sandbox: malformed response (read=%v json=%v); reaped %s", readErr, unmarshalErr, out.SandboxID)
	}
	// Fail closed: with secure=true the API must return the envd access token. A
	// sandbox we could reach without one would be reachable by anyone — kill it
	// rather than run on an unauthenticated data plane.
	if out.EnvdAccessToken == "" {
		e.kill(out.SandboxID)
		return e2bVM{}, errors.New("e2b create sandbox: no envd access token in secure-mode response (template's envd too old for secured access?)")
	}
	if out.TrafficAccessToken == "" {
		e.kill(out.SandboxID)
		return e2bVM{}, errors.New("e2b create sandbox: no traffic access token with public traffic disabled")
	}
	return e2bVM{id: out.SandboxID, accessToken: out.EnvdAccessToken, trafficAccessToken: out.TrafficAccessToken}, nil
}

// verifyResources reads the live sandbox's template-level allocation from E2B's
// control plane and rejects a VM that exceeds the requested per-run maximum. A
// larger VM is not harmless: hostile code can consume everything the VM exposes.
func (e *E2B) verifyResources(ctx context.Context, vm e2bVM) error {
	if e.MaxMemoryMB <= 0 && e.MaxVCPU <= 0 && e.MaxDiskMB <= 0 {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.apiBase()+"/sandboxes/"+url.PathEscape(vm.id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", e.APIKey)
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("e2b verify resources: %w", err)
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return fmt.Errorf("e2b verify resources: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("e2b verify resources: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var got struct {
		MemoryMB   int  `json:"memoryMB"`
		CPUCount   int  `json:"cpuCount"`
		DiskSizeMB *int `json:"diskSizeMB"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		return fmt.Errorf("e2b verify resources: unparseable control-plane response: %w", err)
	}
	if e.MaxMemoryMB > 0 && (got.MemoryMB <= 0 || got.MemoryMB > e.MaxMemoryMB) {
		return fmt.Errorf("e2b template exceeds memory cap: microVM has %d MiB, maximum is %d", got.MemoryMB, e.MaxMemoryMB)
	}
	if e.MaxVCPU > 0 && (got.CPUCount <= 0 || float64(got.CPUCount) > e.MaxVCPU) {
		return fmt.Errorf("e2b template exceeds CPU cap: microVM has %d vCPU, maximum is %.0f", got.CPUCount, e.MaxVCPU)
	}
	if e.MaxDiskMB > 0 {
		if got.DiskSizeMB == nil {
			return errors.New("e2b verify resources: control-plane response omitted diskSizeMB")
		}
		if *got.DiskSizeMB < 0 || *got.DiskSizeMB > e.MaxDiskMB {
			return fmt.Errorf("e2b template exceeds disk cap: microVM has %d MiB, maximum is %d", *got.DiskSizeMB, e.MaxDiskMB)
		}
	}
	return nil
}

// kill removes the sandbox, retrying a few times before giving up. It uses its own
// context so it still runs after the request context is cancelled or timed out. A
// failed teardown is logged loudly because it leaks a billable, token-bearing
// microVM; ReconcileOrphans (and, failing that, the create "timeout") eventually
// reaps it. The ID is untracked unconditionally: after the run's lifecycle ends,
// anything still alive under our instance stamp IS an orphan by definition.
func (e *E2B) kill(id string) {
	defer e.untrackVM(id)
	const attempts = 3
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := e.deleteSandbox(ctx, id)
		cancel()
		if err == nil {
			return
		}
		if i == attempts-1 {
			slog.Error("e2b: failed to kill sandbox; orphan reconciliation or its create timeout will reap it",
				"sandbox", id, "attempts", attempts, "error", err)
			return
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
}

// ---- orphan reconciliation ----

// e2bReconcileGrace spares sandboxes younger than this from reconciliation. A
// concurrent create() has a window between the control plane creating the
// sandbox and the response being parsed (and the ID tracked); killing inside
// that window would tear down a legitimate in-flight run. Tracked IDs are
// spared regardless of age, so the grace only needs to out-wait that window.
const e2bReconcileGrace = 60 * time.Second

// instance lazily assigns this provider instance's random identity, stamped as
// control-plane metadata on every sandbox it creates.
func (e *E2B) instance() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.instanceID == "" {
		e.instanceID = randID()
	}
	return e.instanceID
}

func (e *E2B) trackVM(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inflight == nil {
		e.inflight = make(map[string]struct{})
	}
	e.inflight[id] = struct{}{}
}

func (e *E2B) untrackVM(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.inflight, id)
}

func (e *E2B) trackedVM(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.inflight[id]
	return ok
}

// ReconcileOrphans lists this provider instance's live sandboxes on the control
// plane (keyed by the metadata stamp create writes) and kills every one that is
// no longer tracked in flight and older than the create grace window. It closes
// the two leaks the per-run lifecycle cannot: a 2xx create response whose
// sandbox ID never reached us, and a teardown whose retries all failed. It never
// touches sandboxes created by other instances (even with the same API key),
// so a fleet can reconcile independently. Returns the number of sandboxes killed.
func (e *E2B) ReconcileOrphans(ctx context.Context) (int, error) {
	if strings.TrimSpace(e.APIKey) == "" {
		return 0, errors.New("E2B_API_KEY is not set")
	}
	listed, err := e.listInstanceSandboxes(ctx)
	if err != nil {
		return 0, err
	}
	killed := 0
	for _, sb := range listed {
		if e.trackedVM(sb.id) {
			continue
		}
		// Unparseable/missing startedAt: be conservative and leave it to the
		// create-timeout backstop rather than risk killing an in-flight create.
		if sb.startedAt.IsZero() || time.Since(sb.startedAt) < e2bReconcileGrace {
			continue
		}
		if err := e.deleteSandbox(ctx, sb.id); err != nil {
			slog.Error("e2b: failed to kill orphaned sandbox", "sandbox", sb.id, "error", err)
			continue
		}
		slog.Warn("e2b: killed orphaned sandbox", "sandbox", sb.id, "started_at", sb.startedAt)
		killed++
	}
	return killed, nil
}

type e2bListedSandbox struct {
	id        string
	startedAt time.Time
}

// listInstanceSandboxes returns the control plane's live sandboxes carrying this
// instance's metadata stamp. The server-side metadata filter is treated as an
// optimization only: every returned entry is re-checked locally so a filter
// regression can never widen the kill set to other instances' sandboxes.
func (e *E2B) listInstanceSandboxes(ctx context.Context) ([]e2bListedSandbox, error) {
	instance := e.instance()
	q := url.Values{"metadata": {url.Values{"instance": {instance}}.Encode()}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.apiBase()+"/sandboxes?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", e.APIKey)
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("e2b list sandboxes: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("e2b list sandboxes: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("e2b list sandboxes: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out []struct {
		SandboxID string            `json:"sandboxID"`
		StartedAt time.Time         `json:"startedAt"`
		Metadata  map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("e2b list sandboxes: unparseable response: %w", err)
	}
	listed := make([]e2bListedSandbox, 0, len(out))
	for _, sb := range out {
		if sb.SandboxID == "" || sb.Metadata["instance"] != instance {
			continue
		}
		listed = append(listed, e2bListedSandbox{id: sb.SandboxID, startedAt: sb.StartedAt})
	}
	return listed, nil
}

// deleteSandbox issues one DELETE. A 404 counts as success (already gone).
func (e *E2B) deleteSandbox(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, e.apiBase()+"/sandboxes/"+id, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", e.APIKey)
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("e2b kill sandbox %s: HTTP %d", id, resp.StatusCode)
	}
	return nil
}

// ---- data plane (envd) ----

// writeFile uploads one file via envd's HTTP /files endpoint. It is a thin wrapper
// over writeFiles so the snippet/step paths (single file) and the project path
// (many files) share one request builder.
func (e *E2B) writeFile(ctx context.Context, vm e2bVM, path, content string) error {
	return e.writeFiles(ctx, vm, []File{{Path: path, Content: content}})
}

// writeFiles uploads one or more files in a SINGLE envd /files multipart request,
// which creates parent directories as needed. Batching all of a project's files into
// one round trip (instead of one POST per file) cuts create-to-run latency and the
// number of authenticated envd calls. envd routes each part to the absolute path in
// its multipart filename; the single-file query form (?path=) is used only when
// exactly one file is sent, preserving the original behavior for snippets/steps.
func (e *E2B) writeFiles(ctx context.Context, vm e2bVM, files []File) error {
	if len(files) == 0 {
		return nil
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range files {
		part, err := mw.CreateFormFile("file", f.Path)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(part, f.Content); err != nil {
			return err
		}
	}
	_ = mw.Close()

	q := url.Values{"username": {"user"}}
	if len(files) == 1 {
		q.Set("path", files[0].Path)
	}
	reqURL := e.envdHost(vm.id) + "/files?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	vm.authorize(req)
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

type procOutput struct {
	stdout          string
	stderr          string
	stdoutTruncated bool
	stderrTruncated bool
	exitCode        int
}

// exitOutputFlooded is the exit code reported when a run is aborted because its
// output stream exceeded maxStreamTransferBytes — a user-run failure (a hostile
// or runaway flood), not infrastructure. 153 = 128+SIGXFSZ (the "file size limit
// exceeded" kill), by analogy with the 124 timeout convention.
const exitOutputFlooded = 153

// runProcess invokes process.Process/Start (Connect server-streaming) and
// aggregates the stdout/stderr/end events into a single result.
func (e *E2B) runProcess(ctx context.Context, vm e2bVM, cmd string, args []string, cwd string) (procOutput, error) {
	return e.runProcessWithEnv(ctx, vm, cmd, args, cwd, nil)
}

func (e *E2B) runProcessWithEnv(ctx context.Context, vm e2bVM, cmd string, args []string, cwd string, envs map[string]string) (procOutput, error) {
	startReq := map[string]any{
		"process": map[string]any{"cmd": cmd, "args": args},
		"stdin":   false,
	}
	if cwd != "" {
		startReq["process"].(map[string]any)["cwd"] = cwd
	}
	if len(envs) > 0 {
		startReq["process"].(map[string]any)["envs"] = envs
	}
	payload, _ := json.Marshal(startReq)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.envdHost(vm.id)+"/process.Process/Start", bytes.NewReader(connectEnvelope(payload)))
	if err != nil {
		return procOutput{}, err
	}
	req.Header.Set("Content-Type", "application/connect+json")
	req.Header.Set("Connect-Protocol-Version", "1")
	// envd intentionally detaches a process from the HTTP request context unless
	// this header is present. Propagate the remaining deadline so closing/timing
	// out the stream also has a server-side process kill backstop.
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		ms := (remaining + time.Millisecond - 1) / time.Millisecond // round up
		if ms < 1 {
			ms = 1
		}
		req.Header.Set("Connect-Timeout-Ms", strconv.FormatInt(int64(ms), 10))
	}
	vm.authorize(req)
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return procOutput{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return procOutput{}, fmt.Errorf("envd start: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out procOutput
	max := e.maxOutput()
	stdout := &cappedStream{max: max}
	stderr := &cappedStream{max: max}
	sawEnd := false
	err = readConnectStream(resp.Body, func(msg []byte) error {
		var ev procEvent
		if err := json.Unmarshal(msg, &ev); err != nil {
			return nil // ignore non-event frames
		}
		switch {
		case ev.Event.Data != nil:
			stdout.append(ev.Event.Data.Stdout)
			stderr.append(ev.Event.Data.Stderr)
		case ev.Event.End != nil:
			out.exitCode = ev.Event.End.ExitCode
			sawEnd = true
		}
		return nil
	})
	out.stdout = stdout.b.String()
	out.stderr = stderr.b.String()
	out.stdoutTruncated = stdout.dropped
	out.stderrTruncated = stderr.dropped
	if err != nil {
		// The guest flooding its own output past the transfer budget is a failed
		// USER run, not infrastructure: report it as a non-zero exit with truncated
		// output. The stream was aborted mid-flood, so both streams are marked
		// truncated and the guest's own exit status is unknowable.
		if errors.Is(err, errStreamOverBudget) {
			out.stdoutTruncated, out.stderrTruncated = true, true
			out.exitCode = exitOutputFlooded
			return out, nil
		}
		return out, err
	}
	// A stream that ends without an End event truncated mid-run: do NOT report the
	// default exit 0, which would falsely look like a clean success.
	if !sawEnd {
		return out, errors.New("envd stream ended before process completion")
	}
	return out, nil
}

// cappedStream accumulates at most max bytes, recording whether anything was
// dropped so truncation is reported out-of-band rather than as an in-band marker.
type cappedStream struct {
	b       strings.Builder
	max     int
	dropped bool
}

func (c *cappedStream) append(data []byte) {
	if len(data) == 0 {
		return
	}
	if c.b.Len() >= c.max {
		c.dropped = true
		return
	}
	if c.b.Len()+len(data) > c.max {
		data = data[:c.max-c.b.Len()]
		c.dropped = true
	}
	c.b.Write(data)
}

type procEvent struct {
	Event struct {
		Data *struct {
			Stdout []byte `json:"stdout"`
			Stderr []byte `json:"stderr"`
		} `json:"data"`
		End *struct {
			ExitCode int    `json:"exitCode"`
			Exited   bool   `json:"exited"`
			Status   string `json:"status"`
		} `json:"end"`
	} `json:"event"`
}

// connectEnvelope wraps a message in the Connect streaming framing:
// [flags:1][length:4 big-endian][payload].
func connectEnvelope(payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	return buf
}

// maxConnectFrameBytes caps a single Connect stream frame. The length prefix is
// server-controlled, so without this a malformed/hostile frame could trigger a
// multi-gigabyte allocation (OOM/DoS). envd's process output frames are small.
const maxConnectFrameBytes = 8 << 20

// maxStreamTransferBytes caps the TOTAL bytes read across a whole process stream.
// The per-frame cap bounds one allocation, but a hostile process can emit an endless
// series of in-bound frames; cappedStream stops STORING at maxOutput yet the reader
// would keep pulling and allocating frames until the deadline. Bounding cumulative
// transfer makes a flood deterministic: once the run has produced far more than any
// legitimate output, the stream is aborted rather than read indefinitely. Sized well
// above maxConnectFrameBytes and any sane maxOutput so real runs never reach it.
const maxStreamTransferBytes = 32 << 20

// errStreamOverBudget marks a stream aborted for exceeding maxStreamTransferBytes.
// runProcess classifies it as a failed user run (exitOutputFlooded), not an
// infrastructure error: the flood is the guest's own doing.
var errStreamOverBudget = errors.New("envd stream exceeded the transfer budget")

// readConnectStream decodes the Connect streaming response framing, invoking fn
// for each data message. The final frame (flags bit 0x2) is the end-of-stream
// trailer; if it carries an error, that error is returned. Total bytes transferred
// are bounded by maxStreamTransferBytes to cap a flooding process.
func readConnectStream(r io.Reader, fn func(msg []byte) error) error {
	header := make([]byte, 5)
	var total int64
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		flags := header[0]
		length := binary.BigEndian.Uint32(header[1:5])
		if length > maxConnectFrameBytes {
			return fmt.Errorf("envd stream frame too large: %d bytes", length)
		}
		total += int64(length)
		if total > maxStreamTransferBytes {
			return errStreamOverBudget
		}
		msg := make([]byte, length)
		if _, err := io.ReadFull(r, msg); err != nil {
			return err
		}
		if flags&0x2 != 0 { // end-of-stream
			var trailer struct {
				Error *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(msg, &trailer) == nil && trailer.Error != nil {
				return fmt.Errorf("envd error %s: %s", trailer.Error.Code, trailer.Error.Message)
			}
			return nil
		}
		if err := fn(msg); err != nil {
			return err
		}
	}
}
