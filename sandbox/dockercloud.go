package sandbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	pathpkg "path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DockerCloud runs agent code in a Docker Cloud Sandbox: a Docker-managed microVM
// created for one run and deleted when it ends.
//
// It is written against Docker's published contract, the protobuf API released as
// the Go module github.com/docker/sandboxes-api (v0.36.0, Apache-2.0). It passed
// its live suite against the real service on 2026-09-24. Where the service differs
// from the contract (the token exchange, the inline network policy, the reported
// image digest, the required CPU count) the code says so where it depends on it.
// "Assumption (live probe)" marks behavior the contract does not pin down; the live
// suite exercises it, but no document promises it.
//
// The contract is Connect RPC. This provider speaks it by hand, as JSON over
// net/http, rather than importing Docker's generated client: that client would add
// protovalidate and googleapis generated code to the module graph of a hostile-code
// TCB, for a surface of nine procedures. Unary calls are JSON POSTs; the file
// upload and download streams use Connect's enveloped framing in one request body.
//
// Two endpoints, one credential:
//   - Management (APIURL): docker.sbx.v1 sandbox, operation, capability and
//     network-policy services.
//   - Sandbox endpoint (SandboxCore.endpoint.uri, reported per sandbox):
//     docker.sbx.process.v1 and docker.sbx.files.v1.
//
// The contract has no separate endpoint credential in v1: SandboxEndpoint's
// credential_audience "is empty in v1; an empty value does not mean open access",
// PERMISSION_SANDBOXES_CREDENTIAL is "reserved for endpoint credentials", and the
// generated facade (gen/go/sbx/facade.go, NewSandboxClient) says "the endpoint takes
// the same credential as the management client". The cloud CloudCredentialService
// is unrelated: it exchanges a one-use Docker OIDC id_token for a Docker credential
// stored server-side and returns nothing. So the same bearer token authorizes both
// endpoints: the short-lived one exchanged from the personal access token (bearer),
// never the personal access token itself, which the service refuses.
//
// Bounds the API does not give are enforced here. ExecRequest has no timeout, no
// stdin and no output limit, and ExecResponse returns whole stdout and stderr, so
// every guest command runs under dcExecWrapper: `timeout -s KILL` inside the guest,
// each stream capped by `head -c` inside the guest, the host reading a bounded
// response, and the run's context deadline cancelling the call and deleting the
// sandbox as the backstop.
type DockerCloud struct {
	// Token is a Docker personal access token for automation (DOCKER_SBX_TOKEN).
	// It is read from the environment and never written anywhere. The sandbox API
	// does not accept it directly (verified live 2026-09-24: TOKEN_INVALID): it is
	// exchanged at AuthURL, with Username, for a short-lived bearer token.
	Token string
	// Username is the Docker account the token belongs to (DOCKER_SBX_USERNAME).
	Username string
	// AuthURL is Docker Hub's token exchange (SANDBOX_DOCKERCLOUD_AUTH_URL); default
	// dcDefaultAuthURL. It answers {"access_token": JWT}; the JWT lived 900 s when
	// verified live on 2026-09-24.
	AuthURL string
	// APIURL is the management endpoint (SANDBOX_DOCKERCLOUD_API_URL). There is no
	// default: Docker has not documented it. The only hint in the published module
	// is its Python README, which connects to "https://sandboxes.connect.docker.com/sbx"
	// (sandboxes-api v0.36.0, gen/python/README.md); it is an example, not a
	// documented contract, so the operator must state the URL.
	APIURL string
	// Image is the raw OCI image each sandbox boots (SANDBOX_DOCKERCLOUD_IMAGE),
	// normally the plimsoll toolchain image published to a registry the service
	// can pull.
	Image string
	// RequirePinnedImage refuses an Image that is not an @sha256: digest.
	RequirePinnedImage bool
	// GuardURL is the public HTTPS endpoint of this process's egress guard
	// (SANDBOX_DOCKERCLOUD_GUARD_URL). Set, it enables host-API grants: a grant run's
	// sandbox may reach this host on 443 and nothing else. Empty keeps grants
	// unsupported and every run deny-all.
	GuardURL string
	// PolicyURL is the base of Docker's per-sandbox network-policy REST endpoint
	// (SANDBOX_DOCKERCLOUD_POLICY_URL); default dcDefaultPolicyURL. It is NOT part
	// of Docker's published contract: it is the call the sbx CLI makes for
	// --allow-network, captured on 2026-09-24. Every grant run reads the effective
	// policy back through the published contract before any caller code runs, so
	// a change on Docker's side fails closed, never open.
	PolicyURL string

	HTTP *http.Client // nil = a client that never follows redirects

	authMu         sync.Mutex
	access         string
	accessExp      time.Time
	guards         guardRegistry // live per-run guard credentials (guard_registry.go)
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	MaxOutputBytes int    // per stream; default 64 KiB
	ProjectDir     string // default /tmp/plimsoll-project

	// The per-run envelope. CPU and memory are requested at create and verified
	// against the created sandbox. The contract has no disk or process-count
	// control, so a non-zero MaxDiskMB or PidsLimit fails configuration.
	MaxMemoryMB int
	MaxVCPU     float64
	MaxDiskMB   int
	PidsLimit   int

	// Orphan-reconciliation state. Every sandbox is named after this provider
	// instance, and the name is tracked BEFORE the create request is sent, so the
	// reconciler never races an in-flight create and needs no grace window.
	mu         sync.Mutex
	instanceID string
	inflight   map[string]struct{}
}

func (*DockerCloud) Name() string { return "dockercloud" }

// SupportsProjects is true: project runs use the configured toolchain image.
func (*DockerCloud) SupportsProjects() bool { return true }

// Host-API grants need a forced, authenticated channel out of the VM that keeps the
// credential host-side (E2B's guard). None exists for this provider yet, so grants
// are refused before any sandbox is created.
func (d *DockerCloud) SupportsJavaScriptGrants() bool { return d.guardConfig() != nil }
func (d *DockerCloud) SupportsProjectGrants() bool    { return d.guardConfig() != nil }

// IsolationClass is VM: each run gets a disposable Docker-managed microVM. As for
// every provider, the tier is configuration and provider evidence plus the startup
// smoke test, never runtime attestation.
func (*DockerCloud) IsolationClass() IsolationClass { return IsolationVM }

const (
	dcProcCreateSandbox   = "/docker.sbx.v1.SandboxService/CreateSandbox"
	dcProcGetSandbox      = "/docker.sbx.v1.SandboxService/GetSandbox"
	dcProcListSandboxes   = "/docker.sbx.v1.SandboxService/ListSandboxes"
	dcProcDeleteSandbox   = "/docker.sbx.v1.SandboxService/DeleteSandbox"
	dcProcGetCapabilities = "/docker.sbx.v1.CapabilityService/GetCapabilities"
	dcProcWaitOperation   = "/docker.sbx.v1.OperationService/WaitOperation"
	dcProcGetOperation    = "/docker.sbx.v1.OperationService/GetOperation"
	dcProcEffectivePolicy = "/docker.sbx.v1.NetworkPolicyService/GetEffectiveNetworkPolicy"
	dcProcExec            = "/docker.sbx.process.v1.ProcessService/Exec"
	dcProcUpload          = "/docker.sbx.files.v1.FileService/Upload"
	dcProcDownload        = "/docker.sbx.files.v1.FileService/Download"
)

const (
	// dcNamePrefix starts every sandbox name; the instance ID follows it, so the
	// reconciler can recognize this instance's sandboxes by name alone.
	dcNamePrefix = "plimsoll-"
	// dcTTLSlack is added to the run budget for the sandbox's own cloud TTL, so a
	// slow run is ended by our context, not by the sandbox expiring under it. The
	// TTL (with ON_TIMEOUT_DELETE) is the backstop if every delete fails.
	dcTTLSlack = 30 * time.Second
	// dcGuestMargin is how much earlier than the host deadline the in-guest
	// `timeout` fires, so a timed-out step returns its captured output before the
	// host gives up on the call.
	dcGuestMargin = 2 * time.Second
	// dcSmokeTimeout bounds the startup smoke: one create, a probe, teardown.
	dcSmokeTimeout = 120 * time.Second
	// dcMaxUnaryResponse caps a management response body.
	dcMaxUnaryResponse = 1 << 20
	// dcUploadChunk is the data-frame size for file uploads.
	dcUploadChunk = 512 << 10
	// dcMaxListPages bounds reconciliation's walk over ListSandboxes pages.
	dcMaxListPages = 50
)

// dcStartCmd keeps a raw image's sandbox alive without running its entrypoint.
// Assumption (live probe): cloud.start_cmd replaces the image's entrypoint and
// command, and a sandbox whose start command exits is no longer usable.
var dcStartCmd = []string{"tail", "-f", "/dev/null"}

// dcExecWrapper runs every guest command. Arguments: $1 the in-guest time limit in
// whole seconds, $2 the per-stream byte cap, then the argv to run.
//
//   - `timeout -s KILL` bounds the run inside the VM (the API has no timeout). KILL
//     cannot be trapped; both busybox and coreutils then exit 137.
//   - Each stream passes through `head -c` inside the VM, so the response carries
//     at most $2 bytes per stream. The host sets $2 to its cap plus one, so a
//     retained length above the cap is the truncation signal: no marker is ever
//     written into the output. A guest that keeps writing after head exits gets
//     SIGPIPE, so a flood ends as a failed user run.
//   - The exit status travels through a file because POSIX sh has no pipefail.
//
// It uses only POSIX sh, timeout, head and cat, which busybox provides. busybox
// `timeout` needs kill(2): where a syscall filter refuses it, the limit fails open,
// which is why SmokeTest proves a hung command is really killed. The host deadline
// (cancel the call, delete the sandbox) remains the backstop either way.
const dcExecWrapper = `t=$1; c=$2; shift 2
rc=/tmp/.plimsoll-rc.$$
rm -f "$rc"
{ { timeout -s KILL "$t" "$@"; echo "$?" >"$rc"; } 2>&1 1>&3 3>&- | head -c "$c" 1>&2; } 3>&1 | head -c "$c"
if [ -s "$rc" ]; then s=$(cat "$rc"); rm -f "$rc"; exit "$s"; fi
exit 125`

// ---- configuration ----

// validateConfig is the structural check shared by Build and Preflight. It does not
// call the API.
func (d *DockerCloud) validateConfig() error {
	if strings.TrimSpace(d.Token) == "" {
		return errors.New("DOCKER_SBX_TOKEN is not set")
	}
	if strings.TrimSpace(d.Username) == "" {
		return errors.New("DOCKER_SBX_USERNAME is not set (the Docker account the token belongs to)")
	}
	if _, err := parseDockerCloudURL(d.authURL(), "SANDBOX_DOCKERCLOUD_AUTH_URL"); err != nil {
		return err
	}
	if _, err := parseGuardURL(d.GuardURL, "SANDBOX_DOCKERCLOUD_GUARD_URL", dcGuardDefaultPath); err != nil {
		return err
	}
	if _, err := parseDockerCloudURL(d.policyURL(), "SANDBOX_DOCKERCLOUD_POLICY_URL"); err != nil {
		return err
	}
	if _, err := parseDockerCloudURL(d.APIURL, "SANDBOX_DOCKERCLOUD_API_URL"); err != nil {
		return err
	}
	image := strings.TrimSpace(d.Image)
	if image == "" {
		return errors.New("SANDBOX_DOCKERCLOUD_IMAGE is not set (the raw OCI image each sandbox boots)")
	}
	if d.RequirePinnedImage && !isDigestPinned(image) {
		return fmt.Errorf("SANDBOX_DOCKERCLOUD_IMAGE %q is not pinned to an immutable @sha256: digest (SANDBOX_REQUIRE_PINNED_IMAGES is on)", image)
	}
	return d.validateResourceConfig()
}

func (d *DockerCloud) validateResourceConfig() error {
	if d.MaxMemoryMB < 0 || d.MaxVCPU < 0 || d.MaxDiskMB < 0 || d.PidsLimit < 0 || math.IsNaN(d.MaxVCPU) || math.IsInf(d.MaxVCPU, 0) {
		return errors.New("dockercloud resource caps must be finite and non-negative")
	}
	if d.MaxVCPU > 0 && (math.Trunc(d.MaxVCPU) != d.MaxVCPU || d.MaxVCPU > math.MaxUint32) {
		return fmt.Errorf("dockercloud cannot enforce fractional SANDBOX_CPUS=%v; the API takes a whole CPU count", d.MaxVCPU)
	}
	if d.MaxDiskMB > 0 {
		return errors.New("dockercloud cannot enforce SANDBOX_DISK_MB; the API has no disk control, leave it unset or choose docker or e2b")
	}
	if d.PidsLimit > 0 {
		return errors.New("dockercloud cannot enforce SANDBOX_PIDS; leave it unset or choose docker")
	}
	return nil
}

// parseDockerCloudURL accepts an absolute HTTPS URL (HTTP only on loopback, for
// tests) with no credentials, query or fragment. The bearer token is sent to it,
// so cleartext off loopback is refused.
func parseDockerCloudURL(raw, what string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%s is not set (Docker has not documented a default; state it explicitly)", what)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("%s must be an absolute URL without credentials, query or fragment", what)
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("%s must use HTTPS off loopback (the bearer token is sent to it)", what)
		}
	default:
		return nil, fmt.Errorf("%s must be an http(s) URL", what)
	}
	return u, nil
}

func (d *DockerCloud) apiBase() string { return strings.TrimRight(strings.TrimSpace(d.APIURL), "/") }

func (d *DockerCloud) httpClient() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return dcDefaultClient
}

// dcDefaultClient never follows a redirect: a redirected request would carry the
// bearer token (or lose it) somewhere the operator did not configure.
var dcDefaultClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (d *DockerCloud) projectDir() string {
	if d.ProjectDir != "" {
		return d.ProjectDir
	}
	// /tmp is writable by any guest user, and Node's parent-directory walk from
	// here still reaches /node_modules, where derived toolchain images bake
	// third-party packages.
	return "/tmp/plimsoll-project"
}

func (d *DockerCloud) maxOutput() int {
	if d.MaxOutputBytes > 0 {
		return d.MaxOutputBytes
	}
	return 64 << 10
}

// Preflight validates configuration. It does not call the API, so it proves nothing
// about reachability or the token; SmokeTest does.
func (d *DockerCloud) Preflight(context.Context) error { return d.validateConfig() }

// ---- runs ----

// RunJavaScript runs one snippet with node from a staged CommonJS file.
func (d *DockerCloud) RunJavaScript(ctx context.Context, req Request) (Result, error) {
	fail := Result{Sandbox: d.Name(), Isolation: IsolationVM}
	if err := ValidateRequest(req); err != nil {
		return fail, err
	}
	if err := CheckMinimumIsolation(d.IsolationClass(), req.MinimumIsolation); err != nil {
		return fail, err
	}
	if err := d.validateConfig(); err != nil {
		return fail, err
	}
	timeout := clampRunTimeout(req.Timeout, d.DefaultTimeout, d.MaxTimeout)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	guard, closeGuard, err := d.openGuard(runCtx, req.Grant, timeout)
	if err != nil {
		return fail, err
	}
	defer closeGuard()

	vm, err := d.create(runCtx, remainingBudget(runCtx, timeout))
	if err != nil {
		return fail, d.deadlineAware(runCtx, err)
	}
	defer d.destroy(vm) // every exit path, including cancellation and panics
	if err := d.sealNetwork(runCtx, vm, guard); err != nil {
		return fail, d.deadlineAware(runCtx, err)
	}
	code := req.Code
	if guard != nil {
		code = withGuardHostSDK(code, req.Grant, guard.endpoint.URL, guard.token)
	}

	// Staged as a file, not a `node -e` argument: one argv element is limited to
	// about 128 KiB and an accepted snippet may be larger.
	const snippetPath = "/tmp/plimsoll-snippet.cjs"
	if err := d.upload(runCtx, vm, []File{{Path: snippetPath, Content: code}}); err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return Result{Sandbox: d.Name(), Isolation: IsolationVM, ExitCode: 124, TimedOut: true}, nil
		}
		return fail, fmt.Errorf("dockercloud write snippet: %w", err)
	}
	start := time.Now()
	out, err := d.execGuarded(runCtx, vm, []string{"node", snippetPath}, "")
	res := Result{
		Stdout:          out.stdout,
		Stderr:          out.stderr,
		StdoutTruncated: out.stdoutTruncated,
		StderrTruncated: out.stderrTruncated,
		ExitCode:        out.exitCode,
		TimedOut:        out.timedOut,
		Duration:        time.Since(start),
		Sandbox:         d.Name(),
		Isolation:       IsolationVM,
	}
	if guard != nil {
		res.CallTrace = guard.core.traceSnapshot()
	}
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			res.TimedOut, res.ExitCode = true, 124
			return res, nil
		}
		return fail, err
	}
	return res, nil
}

// RunModule is unsupported: the module worker image is a docker recipe.
func (d *DockerCloud) RunModule(_ context.Context, req ModuleRequest) (ModuleResult, error) {
	fail := ModuleResult{Sandbox: d.Name(), Isolation: IsolationVM}
	if err := ValidateModuleRequest(req); err != nil {
		return fail, err
	}
	if err := CheckMinimumIsolation(IsolationVM, req.MinimumIsolation); err != nil {
		return fail, err
	}
	return fail, ErrUnsupported
}

// RunProject writes the files, then runs each step in order, stopping on the first
// failure, and finally captures the requested artifacts that exist.
func (d *DockerCloud) RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error) {
	fail := ProjectResult{Sandbox: d.Name(), Isolation: IsolationVM}
	if err := ValidateProjectRequest(req); err != nil {
		return fail, err
	}
	if err := CheckMinimumIsolation(d.IsolationClass(), req.MinimumIsolation); err != nil {
		return fail, err
	}
	if err := d.validateConfig(); err != nil {
		return fail, err
	}
	timeout := clampRunTimeout(req.Timeout, d.DefaultTimeout, d.MaxTimeout)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	guard, closeGuard, err := d.openGuard(runCtx, req.Grant, timeout)
	if err != nil {
		return fail, err
	}
	defer closeGuard()

	dir := d.projectDir()
	staged := make([]File, 0, len(req.Files)+len(req.Steps))
	dirs := map[string]struct{}{dir: {}}
	for _, f := range req.Files {
		// Defense in depth: validation already refuses escaping paths, but never
		// write outside the project dir even inside the disposable microVM.
		dest := pathpkg.Join(dir, f.Path)
		if dest == dir || !strings.HasPrefix(dest, dir+"/") {
			return ProjectResult{Sandbox: d.Name(), Isolation: IsolationVM, Outcome: ProjectOutcomeSetupFailed, Detail: "illegal file path: " + f.Path}, nil
		}
		staged = append(staged, File{Path: dest, Content: f.Content})
		dirs[pathpkg.Dir(dest)] = struct{}{}
	}
	// Every step script is staged in the same upload, one file per step, so a run
	// costs one upload however many steps it has.
	stepPaths := make([]string, len(req.Steps))
	for i, step := range req.Steps {
		stepPaths[i] = fmt.Sprintf("/tmp/plimsoll-step-%d.sh", i)
		staged = append(staged, File{Path: stepPaths[i], Content: step})
	}

	// A grant preloads the guard client into every Node step, as on E2B: the same
	// host.* global for snippets and projects.
	var stepPrefix []string
	if guard != nil {
		staged = append(staged, File{Path: dcHostModulePath, Content: hostGuardSDKModule(req.Grant, guard.endpoint.URL, guard.token)})
		stepPrefix = []string{"env", "NODE_OPTIONS=--import " + dcHostModulePath}
	}

	vm, err := d.create(runCtx, remainingBudget(runCtx, timeout))
	if err != nil {
		return fail, d.deadlineAware(runCtx, err)
	}
	defer d.destroy(vm)
	if err := d.sealNetwork(runCtx, vm, guard); err != nil {
		return fail, d.deadlineAware(runCtx, err)
	}

	timedOut := func() ProjectResult {
		return ProjectResult{Sandbox: d.Name(), Isolation: IsolationVM, Outcome: ProjectOutcomeTimedOut, Detail: "run exceeded the time budget before its steps ran"}
	}
	if err := d.mkdirs(runCtx, vm, dirs); err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return timedOut(), nil
		}
		return fail, fmt.Errorf("could not create project directories: %w", err)
	}
	if err := d.upload(runCtx, vm, staged); err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return timedOut(), nil
		}
		return fail, fmt.Errorf("could not write project files: %w", err)
	}

	res := ProjectResult{Sandbox: d.Name(), Isolation: IsolationVM, Outcome: ProjectOutcomeCompleted}
	for i, step := range req.Steps {
		start := time.Now()
		out, err := d.execGuarded(runCtx, vm, append(append([]string(nil), stepPrefix...), "sh", stepPaths[i]), dir)
		if err != nil {
			if runCtx.Err() == context.DeadlineExceeded {
				res.Steps = append(res.Steps, StepResult{Command: step, ExitCode: 124, TimedOut: true, Duration: time.Since(start)})
				res.Outcome, res.Detail = ProjectOutcomeTimedOut, "run exceeded the time budget"
				return res, nil
			}
			return fail, err
		}
		res.Steps = append(res.Steps, StepResult{
			Command:         step,
			Stdout:          out.stdout,
			Stderr:          out.stderr,
			StdoutTruncated: out.stdoutTruncated,
			StderrTruncated: out.stderrTruncated,
			ExitCode:        out.exitCode,
			TimedOut:        out.timedOut,
			Duration:        time.Since(start),
		})
		if guard != nil {
			res.CallTrace = guard.core.traceSnapshot()
		}
		if out.timedOut {
			res.Outcome, res.Detail = ProjectOutcomeTimedOut, "step exceeded the time budget"
			return res, nil
		}
		if out.exitCode != 0 {
			break
		}
	}

	// Capture requested artifacts (those that exist), even after a failed step.
	var wanted []string
	for _, p := range req.Artifacts {
		dest := pathpkg.Join(dir, p)
		if dest != dir && strings.HasPrefix(dest, dir+"/") {
			wanted = append(wanted, dest)
		}
	}
	if len(wanted) > 0 {
		arts, truncated, err := d.download(runCtx, vm, wanted)
		if err != nil {
			if runCtx.Err() == context.DeadlineExceeded {
				res.Outcome, res.Detail = ProjectOutcomeTimedOut, "run exceeded the time budget while reading artifacts"
				return res, nil
			}
			return fail, fmt.Errorf("read artifacts: %w", err)
		}
		for _, a := range arts {
			res.Artifacts = append(res.Artifacts, Artifact{Path: strings.TrimPrefix(a.Path, dir+"/"), Content: a.Content})
		}
		res.ArtifactsTruncated = truncated
	}
	return res, nil
}

// deadlineAware keeps the caller's own deadline recognizable: a create that ran out
// of time is reported as context.DeadlineExceeded rather than as whatever transport
// error the cancelled request produced.
func (d *DockerCloud) deadlineAware(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("%w: %v", ctxErr, err)
	}
	return err
}

// clampRunTimeout applies a provider's default and ceiling to a requested budget.
func clampRunTimeout(req, def, max time.Duration) time.Duration {
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

// ---- guest execution ----

type dcExecOutput struct {
	stdout          string
	stderr          string
	stdoutTruncated bool
	stderrTruncated bool
	exitCode        int
	timedOut        bool
}

// execGuarded runs argv under dcExecWrapper with an in-guest time limit derived
// from the remaining run budget.
//
// A step is reported as timed out when the in-guest `timeout` killed it: exit 137
// (or 124) AND the call took at least the in-guest limit. The elapsed-time half
// cannot be forged by guest code (it would have to actually run that long), so a
// user program that merely exits 137 is not misread as a timeout.
func (d *DockerCloud) execGuarded(ctx context.Context, vm dcVM, argv []string, cwd string) (dcExecOutput, error) {
	limit := remainingBudget(ctx, clampRunTimeout(0, d.DefaultTimeout, d.MaxTimeout)) - dcGuestMargin
	secs := int(limit / time.Second)
	if secs < 1 {
		secs = 1
	}
	return d.execLimited(ctx, vm, argv, cwd, secs)
}

// execLimited is execGuarded with an explicit in-guest limit in whole seconds.
func (d *DockerCloud) execLimited(ctx context.Context, vm dcVM, argv []string, cwd string, secs int) (dcExecOutput, error) {
	max := d.maxOutput()
	cmd := append([]string{"sh", "-c", dcExecWrapper, "plimsoll-exec", strconv.Itoa(secs), strconv.Itoa(max + 1)}, argv...)
	start := time.Now()
	raw, flooded, err := d.exec(ctx, vm, cmd, cwd, dcExecResponseLimit(max+1))
	elapsed := time.Since(start)
	if err != nil {
		return dcExecOutput{}, err
	}
	if flooded {
		// The response outgrew what the in-guest caps allow, which only guest code
		// working around them can cause: a failed user run, never infrastructure.
		return dcExecOutput{stdoutTruncated: true, stderrTruncated: true, exitCode: exitOutputFlooded}, nil
	}
	out := dcExecOutput{exitCode: int(raw.ExitCode)}
	out.stdout, out.stdoutTruncated = capStream(raw.Stdout, max)
	out.stderr, out.stderrTruncated = capStream(raw.Stderr, max)
	if (out.exitCode == 137 || out.exitCode == 124) && elapsed >= time.Duration(secs)*time.Second {
		out.timedOut, out.exitCode = true, 124
	}
	return out, nil
}

func capStream(b []byte, max int) (string, bool) {
	if len(b) > max {
		return string(b[:max]), true
	}
	return string(b), false
}

// dcExecResponseLimit is the largest Exec response the wrapper's caps allow: both
// streams base64-encoded in JSON, plus room for the envelope.
func dcExecResponseLimit(perStream int) int64 {
	return 2*int64(base64.StdEncoding.EncodedLen(perStream)) + 64<<10
}

type dcExecResponse struct {
	ExitCode int32  `json:"exitCode"`
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
}

// exec calls ProcessService.Exec on the sandbox endpoint. flooded reports that the
// response body exceeded limit; the body is then discarded unread.
func (d *DockerCloud) exec(ctx context.Context, vm dcVM, cmd []string, cwd string, limit int64) (dcExecResponse, bool, error) {
	in := map[string]any{"cmd": cmd}
	if cwd != "" {
		in["workingDir"] = cwd
	}
	body, _ := json.Marshal(in)
	status, raw, over, err := d.post(ctx, vm.endpoint+dcProcExec, "application/json", body, limit)
	if err != nil {
		return dcExecResponse{}, false, err
	}
	if status != http.StatusOK {
		return dcExecResponse{}, false, dcErrorFrom(dcProcExec, status, raw)
	}
	if over {
		return dcExecResponse{}, true, nil
	}
	var out dcExecResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return dcExecResponse{}, false, fmt.Errorf("dockercloud exec: unparseable response: %w", err)
	}
	return out, false, nil
}

// mkdirs creates the project directories with one `mkdir -p` in the guest.
// Assumption (live probe): FileService.Upload does not create parent directories,
// so they are created explicitly rather than relied on.
func (d *DockerCloud) mkdirs(ctx context.Context, vm dcVM, dirs map[string]struct{}) error {
	list := make([]string, 0, len(dirs))
	for dir := range dirs {
		list = append(list, dir)
	}
	sort.Strings(list)
	out, flooded, err := d.exec(ctx, vm, append([]string{"mkdir", "-p", "--"}, list...), "", dcExecResponseLimit(4<<10))
	if err != nil {
		return err
	}
	if flooded || out.ExitCode != 0 {
		return fmt.Errorf("mkdir exited %d: %s", out.ExitCode, strings.TrimSpace(string(out.Stderr)))
	}
	return nil
}

// ---- file transfer (Connect client and server streams) ----

// upload writes files with one FileService.Upload client stream: per file a header
// frame, then its bytes in data frames.
// Assumption (live probe): a file is complete when the next header or the end of
// the stream arrives, and an empty file is a header with no data frame.
func (d *DockerCloud) upload(ctx context.Context, vm dcVM, files []File) error {
	if len(files) == 0 {
		return nil
	}
	var body bytes.Buffer
	for _, f := range files {
		frame, _ := json.Marshal(map[string]any{"header": map[string]any{"path": f.Path, "mode": 0o644}})
		body.Write(connectEnvelope(frame))
		content := []byte(f.Content)
		for off := 0; off < len(content); off += dcUploadChunk {
			end := min(off+dcUploadChunk, len(content))
			frame, _ := json.Marshal(map[string]any{"data": content[off:end]})
			body.Write(connectEnvelope(frame))
		}
	}
	resp, err := d.stream(ctx, vm.endpoint+dcProcUpload, body.Bytes())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var written uint32
	var got bool
	err = readConnectFrames(resp.Body, dcProcUpload, 1<<20, 1<<20, func(msg []byte) error {
		var out struct {
			FilesWritten uint32 `json:"filesWritten"`
		}
		if err := json.Unmarshal(msg, &out); err != nil {
			return fmt.Errorf("dockercloud upload: unparseable response: %w", err)
		}
		written, got = out.FilesWritten, true
		return nil
	})
	if err != nil {
		return err
	}
	if !got || int(written) != len(files) {
		return fmt.Errorf("dockercloud upload: server reported %d of %d files written", written, len(files))
	}
	return nil
}

// errArtifactBudget stops a download once the artifact budget is spent.
var errArtifactBudget = errors.New("artifact budget exhausted")

// download reads the given absolute paths with one FileService.Download server
// stream. A path the server answers with a per-file error is treated as absent.
// Assumption (live probe): a missing file produces a per-file error frame rather
// than failing the stream, and header paths echo the requested paths.
func (d *DockerCloud) download(ctx context.Context, vm dcVM, paths []string) ([]Artifact, bool, error) {
	req, _ := json.Marshal(map[string]any{"paths": paths})
	resp, err := d.stream(ctx, vm.endpoint+dcProcDownload, connectEnvelope(req))
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	requested := make(map[string]bool, len(paths))
	for _, p := range paths {
		requested[p] = true
	}
	var (
		arts    []Artifact
		current *Artifact
		total   int64
	)
	finish := func() {
		if current != nil {
			arts = append(arts, *current)
			current = nil
		}
	}
	// The transport budget is the decoded artifact budget in base64 plus room for
	// headers and per-file errors; the decoded budget below is what normally stops it.
	transport := int64(base64.StdEncoding.EncodedLen(maxArtifactBytesTotal)) + 2<<20
	err = readConnectFrames(resp.Body, dcProcDownload, 16<<20, transport, func(msg []byte) error {
		var frame struct {
			Header *struct {
				Path string `json:"path"`
			} `json:"header"`
			Data  []byte          `json:"data"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(msg, &frame); err != nil {
			return fmt.Errorf("dockercloud download: unparseable frame: %w", err)
		}
		switch {
		case frame.Header != nil:
			finish()
			if !requested[frame.Header.Path] {
				return fmt.Errorf("dockercloud download: server sent unrequested path %q", frame.Header.Path)
			}
			current = &Artifact{Path: frame.Header.Path}
		case frame.Error != nil:
			finish() // a per-file error: that path is absent
		case frame.Data != nil:
			if current == nil {
				return errors.New("dockercloud download: data frame before any header")
			}
			if total+int64(len(frame.Data)) > maxArtifactBytesTotal {
				current = nil // this artifact does not fit; drop it whole
				return errArtifactBudget
			}
			total += int64(len(frame.Data))
			current.Content = append(current.Content, frame.Data...)
		}
		return nil
	})
	if errors.Is(err, errArtifactBudget) {
		return arts, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	finish()
	return arts, false, nil
}

// readConnectFrames decodes a Connect streaming response. Every frame is bounded
// (maxFrame) and so is the stream (maxTotal). The end-of-stream frame is required:
// a body that ends without one was cut, and its content cannot be trusted as whole.
func readConnectFrames(r io.Reader, procedure string, maxFrame uint32, maxTotal int64, fn func(msg []byte) error) error {
	header := make([]byte, 5)
	var total int64
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if err == io.EOF {
				return fmt.Errorf("dockercloud %s: stream ended without an end-of-stream frame", procedure)
			}
			return err
		}
		flags := header[0]
		length := binary.BigEndian.Uint32(header[1:5])
		if length > maxFrame {
			return fmt.Errorf("dockercloud %s: stream frame of %d bytes exceeds %d", procedure, length, maxFrame)
		}
		total += int64(length)
		if total > maxTotal {
			return fmt.Errorf("dockercloud %s: stream exceeds %d bytes", procedure, maxTotal)
		}
		if flags&0x01 != 0 {
			return fmt.Errorf("dockercloud %s: compressed stream frame, which was not negotiated", procedure)
		}
		msg := make([]byte, length)
		if _, err := io.ReadFull(r, msg); err != nil {
			return err
		}
		if flags&0x02 != 0 {
			var end struct {
				Error *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if len(msg) > 0 {
				if err := json.Unmarshal(msg, &end); err != nil {
					return fmt.Errorf("dockercloud %s: unparseable end-of-stream frame: %w", procedure, err)
				}
			}
			if end.Error != nil {
				return &dcRPCError{Procedure: procedure, HTTPStatus: http.StatusOK, Code: end.Error.Code, Message: end.Error.Message}
			}
			return nil
		}
		if err := fn(msg); err != nil {
			return err
		}
	}
}

// ---- transport ----

// dcRPCError is a Connect error from either endpoint.
type dcRPCError struct {
	Procedure  string
	HTTPStatus int
	Code       string // Connect code: not_found, unimplemented, ...
	Message    string
}

func (e *dcRPCError) Error() string {
	return fmt.Sprintf("dockercloud %s: %s (HTTP %d): %s", e.Procedure, e.Code, e.HTTPStatus, e.Message)
}

func dcCodeIs(err error, code string) bool {
	var rpc *dcRPCError
	return errors.As(err, &rpc) && rpc.Code == code
}

// dcErrorFrom parses a unary Connect error body, falling back to the protocol's
// HTTP-status mapping when the body is not a Connect error (a proxy's page, say).
func dcErrorFrom(procedure string, status int, raw []byte) error {
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Code != "" {
		return &dcRPCError{Procedure: procedure, HTTPStatus: status, Code: body.Code, Message: truncateForError(body.Message)}
	}
	code := "unknown"
	switch status {
	case http.StatusBadRequest:
		code = "internal"
	case http.StatusUnauthorized:
		code = "unauthenticated"
	case http.StatusForbidden:
		code = "permission_denied"
	case http.StatusNotFound:
		code = "unimplemented"
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		code = "unavailable"
	}
	return &dcRPCError{Procedure: procedure, HTTPStatus: status, Code: code, Message: truncateForError(strings.TrimSpace(string(raw)))}
}

// dcCredentialPattern matches anything credential-shaped a vendor message could
// echo: a bearer header value, a JWT (the exchanged bearer is one), a Docker
// personal access token, a plimsoll guard credential.
var dcCredentialPattern = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*|dckr_pat_[A-Za-z0-9_-]+|crg_[0-9a-f]{16,}`)

// truncateForError bounds and scrubs vendor-controlled text before it enters an
// error or a log line: every such string in this file passes through here, so no
// credential the service might echo back reaches a caller or a log.
func truncateForError(s string) string {
	s = dcCredentialPattern.ReplaceAllString(s, "<redacted>")
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

// requestedSize is the CPU count and memory a create asks for: the operator's
// envelope, or the Micro size where it is unset.
func (d *DockerCloud) requestedSize() (uint32, int) {
	cpus, memMiB := uint32(d.MaxVCPU), d.MaxMemoryMB
	if cpus == 0 {
		cpus = dcDefaultCPUs
	}
	if memMiB == 0 {
		memMiB = dcDefaultMemoryMiB
	}
	return cpus, memMiB
}

// dcGuardDefaultPath is the guard route when SANDBOX_DOCKERCLOUD_GUARD_URL names no
// path.
const dcGuardDefaultPath = "/v1/dockercloud/guard"

// dcDefaultPolicyURL is where the sbx CLI (v0.45.1) sends
// `PUT /sandboxes/{id}/network-policy` for --allow-network. Undocumented; see
// DockerCloud.PolicyURL.
const dcDefaultPolicyURL = "https://api.sandboxes-cloud.docker.com/v1"

func (d *DockerCloud) policyURL() string {
	if u := strings.TrimSpace(d.PolicyURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	return dcDefaultPolicyURL
}

func (d *DockerCloud) guardConfig() *guardEndpoint {
	g, err := parseGuardURL(d.GuardURL, "SANDBOX_DOCKERCLOUD_GUARD_URL", dcGuardDefaultPath)
	if err != nil {
		return nil
	}
	return g
}

// EgressGuardPath, EgressGuardKnownToken and EgressGuardCall make dockercloud an
// EgressGuardCapable provider; plimsolld mounts the shared handler at the path.
func (d *DockerCloud) EgressGuardPath() string {
	if g := d.guardConfig(); g != nil {
		return g.Path
	}
	return ""
}

func (d *DockerCloud) EgressGuardKnownToken(token string) bool { return d.guards.lookup(token) != nil }

func (d *DockerCloud) EgressGuardCall(ctx context.Context, token, method, rawTarget string, body []byte) EgressGuardResponse {
	return d.guards.call(ctx, token, method, rawTarget, body)
}

// dcGuard is one grant run's guard: the endpoint the guest calls, the per-run
// credential it sends, and the broker session that enforces the grant.
type dcGuard struct {
	endpoint *guardEndpoint
	token    string
	core     *brokerSession
}

// allowRule is the single network rule a grant run's sandbox gets: the guard host
// on 443, nothing else.
func (g *dcGuard) allowRule() string { return g.endpoint.Host + ":443" }

// openGuard registers a per-run guard credential for a grant. A nil grant returns a
// nil guard (a deny-all run). Without a configured guard URL a grant is refused.
func (d *DockerCloud) openGuard(ctx context.Context, grant *HostAPIGrant, timeout time.Duration) (*dcGuard, func(), error) {
	if grant == nil {
		return nil, func() {}, nil
	}
	endpoint := d.guardConfig()
	if endpoint == nil {
		return nil, func() {}, fmt.Errorf("%w: dockercloud host-API grants require SANDBOX_DOCKERCLOUD_GUARD_URL", ErrUnsupported)
	}
	token, core, cleanup, err := d.guards.open(ctx, grant, timeout)
	if err != nil {
		return nil, func() {}, err
	}
	return &dcGuard{endpoint: endpoint, token: token, core: core}, cleanup, nil
}

// putNetworkPolicy applies a deny-all policy with exactly the given allow rules to
// one sandbox, through the undocumented REST call the sbx CLI uses (PolicyURL). The
// response must echo the same policy; the caller still verifies the effective
// policy through the published contract before running anything.
func (d *DockerCloud) putNetworkPolicy(ctx context.Context, vm dcVM, allow []string) error {
	body, err := json.Marshal(map[string]any{"mode": "deny-all", "allowNetworks": allow})
	if err != nil {
		return err
	}
	target := d.policyURL() + "/sandboxes/" + url.PathEscape(vm.id) + "/network-policy"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	tok, err := d.bearer(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("dockercloud set network policy: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("dockercloud set network policy: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dockercloud set network policy: HTTP %d: %s", resp.StatusCode, truncateForError(strings.TrimSpace(string(raw))))
	}
	var echo struct {
		Mode          string   `json:"mode"`
		AllowNetworks []string `json:"allowNetworks"`
	}
	if err := json.Unmarshal(raw, &echo); err != nil || echo.Mode != "deny-all" || !sameStrings(echo.AllowNetworks, allow) {
		return fmt.Errorf("dockercloud set network policy: service answered %s, not the requested policy", truncateForError(string(raw)))
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// dcDefaultCPUs and dcDefaultMemoryMiB are the Micro size, requested when the
// operator sets no envelope: the smallest and cheapest the service offers.
const (
	dcDefaultCPUs      = 1
	dcDefaultMemoryMiB = 2048
)

// dcDefaultAuthURL is Docker Hub's documented token endpoint: POST
// {"identifier", "secret"} and receive {"access_token"}.
const dcDefaultAuthURL = "https://hub.docker.com/v2/auth/token"

// dcAuthRefreshMargin renews the bearer token this long before it expires, so a
// call never starts with a token about to lapse.
const dcAuthRefreshMargin = 60 * time.Second

func (d *DockerCloud) authURL() string {
	if u := strings.TrimSpace(d.AuthURL); u != "" {
		return u
	}
	return dcDefaultAuthURL
}

// bearer returns a current short-lived access token, exchanging the personal
// access token when none is cached or the cached one is within the refresh margin.
// The JWT's exp claim is read only to schedule the refresh; it is never trusted
// for anything else. Neither token is logged or included in an error.
func (d *DockerCloud) bearer(ctx context.Context) (string, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	if d.access != "" && time.Until(d.accessExp) > dcAuthRefreshMargin {
		return d.access, nil
	}
	body, err := json.Marshal(map[string]string{"identifier": strings.TrimSpace(d.Username), "secret": strings.TrimSpace(d.Token)})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.authURL(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("dockercloud: token exchange: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("dockercloud: token exchange: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Classified like any Connect auth failure so callers treat it one way. The
		// response body is not echoed: it is the vendor's text about our credential.
		code := "unavailable"
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			code = "unauthenticated"
		}
		return "", &dcRPCError{Procedure: "token exchange", HTTPStatus: resp.StatusCode, Code: code,
			Message: fmt.Sprintf("token exchange refused: HTTP %d", resp.StatusCode)}
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("dockercloud: token exchange returned no access_token")
	}
	d.access, d.accessExp = out.AccessToken, dcJWTExpiry(out.AccessToken, time.Now())
	return d.access, nil
}

// dcJWTExpiry reads the exp claim of an unverified JWT for refresh scheduling. An
// unreadable token is treated as expiring in five minutes.
func dcJWTExpiry(token string, now time.Time) time.Time {
	fallback := now.Add(5 * time.Minute)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fallback
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return fallback
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp <= 0 {
		return fallback
	}
	return time.Unix(claims.Exp, 0)
}

// authorize stamps the bearer token and the Connect headers. The remaining
// deadline travels as Connect-Timeout-Ms so the server can stop work the client
// has already abandoned.
func (d *DockerCloud) authorize(ctx context.Context, req *http.Request, contentType string) error {
	tok, err := d.bearer(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connect-Protocol-Version", "1")
	if deadline, ok := ctx.Deadline(); ok {
		ms := (time.Until(deadline) + time.Millisecond - 1) / time.Millisecond
		if ms < 1 {
			ms = 1
		}
		req.Header.Set("Connect-Timeout-Ms", strconv.FormatInt(int64(ms), 10))
	}
	return nil
}

// post sends one request and reads at most limit bytes of the response. over
// reports that the body was longer than limit.
func (d *DockerCloud) post(ctx context.Context, target, contentType string, body []byte, limit int64) (status int, raw []byte, over bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, false, err
	}
	if err := d.authorize(ctx, req, contentType); err != nil {
		return 0, nil, false, err
	}
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return 0, nil, false, err
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.StatusCode, nil, false, err
	}
	if int64(len(raw)) > limit {
		return resp.StatusCode, nil, true, nil
	}
	return resp.StatusCode, raw, false, nil
}

// call is one unary management RPC with a JSON body.
func (d *DockerCloud) call(ctx context.Context, procedure string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	status, raw, over, err := d.post(ctx, d.apiBase()+procedure, "application/json", body, dcMaxUnaryResponse)
	if err != nil {
		return err
	}
	if over {
		return fmt.Errorf("dockercloud %s: response exceeds %d bytes", procedure, dcMaxUnaryResponse)
	}
	if status != http.StatusOK {
		return dcErrorFrom(procedure, status, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("dockercloud %s: unparseable response: %w", procedure, err)
	}
	return nil
}

// stream opens a Connect streaming call with a pre-framed request body.
func (d *DockerCloud) stream(ctx context.Context, target string, framed []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(framed))
	if err != nil {
		return nil, err
	}
	if err := d.authorize(ctx, req, "application/connect+json"); err != nil {
		return nil, err
	}
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, dcErrorFrom(target, resp.StatusCode, raw)
	}
	return resp, nil
}

// ---- protojson helpers ----

// protoEnum holds a protojson enum value. Conforming servers emit the value name,
// but the encoding also allows the number, so both are accepted.
type protoEnum string

func (p *protoEnum) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*p = protoEnum(s)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*p = protoEnum(strconv.FormatInt(n, 10))
	return nil
}

func (p protoEnum) is(name string, number int) bool {
	return string(p) == name || string(p) == strconv.Itoa(number)
}

// protoUint holds a protojson unsigned integer, which the encoding writes as a
// string for 64-bit fields and as a number for 32-bit ones.
type protoUint uint64

func (p *protoUint) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		n, err := strconv.ParseUint(s, 10, 64)
		*p = protoUint(n)
		return err
	}
	var n uint64
	err := json.Unmarshal(b, &n)
	*p = protoUint(n)
	return err
}

func protoDuration(d time.Duration) string {
	secs := int64(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return strconv.FormatInt(secs, 10) + "s"
}

// ---- lifecycle ----

// dcVM is a live sandbox handle. name is ours and known before create; id and
// endpoint come from the service.
type dcVM struct {
	name     string
	id       string
	endpoint string
}

// ref is the SandboxRef JSON for this sandbox: by id once known, else by name.
func (vm dcVM) ref() map[string]string {
	if vm.id != "" {
		return map[string]string{"id": vm.id}
	}
	return map[string]string{"name": vm.name}
}

type dcSandbox struct {
	Core struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Status    protoEnum `json:"status"`
		CreatedAt time.Time `json:"createdAt"`
		Resources *struct {
			Cpus      *protoUint `json:"cpus"`
			MemoryMib *protoUint `json:"memoryMib"`
		} `json:"resources"`
		Endpoint *struct {
			URI      string    `json:"uri"`
			Protocol protoEnum `json:"protocol"`
		} `json:"endpoint"`
	} `json:"core"`
	Cloud *struct {
		ImageDigest string `json:"imageDigest"`
	} `json:"cloud"`
}

func (s dcSandbox) running() bool {
	return s.Core.Status.is("SANDBOX_STATUS_RUNNING", 3) && s.Core.Endpoint != nil && s.Core.Endpoint.URI != ""
}

func (s dcSandbox) terminal() bool {
	return s.Core.Status.is("SANDBOX_STATUS_FAILED", 6) || s.Core.Status.is("SANDBOX_STATUS_STOPPED", 5) || s.Core.Status.is("SANDBOX_STATUS_STOPPING", 4)
}

type dcOperation struct {
	ID    string `json:"id"`
	Done  bool   `json:"done"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Response json.RawMessage `json:"response"`
}

func (d *DockerCloud) instance() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.instanceID == "" {
		d.instanceID = randID()
	}
	return d.instanceID
}

func (d *DockerCloud) namePrefix() string { return dcNamePrefix + d.instance() + "-" }

func (d *DockerCloud) track(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inflight == nil {
		d.inflight = make(map[string]struct{})
	}
	d.inflight[name] = struct{}{}
}

func (d *DockerCloud) untrack(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.inflight, name)
}

func (d *DockerCloud) tracked(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.inflight[name]
	return ok
}

// create starts a sandbox, waits for it to run, and verifies it. Deny-all egress
// comes from the account's cloud network policy, not from the request (see the
// comment in the body); every run reads the effective policy back before any
// guest code runs (verifyEgressDenied). On any failure after the request is sent it deletes
// the sandbox by name, since the service may have created it even when the answer
// never arrived.
func (d *DockerCloud) create(ctx context.Context, budget time.Duration) (dcVM, error) {
	vm := dcVM{name: d.namePrefix() + randID()}
	d.track(vm.name) // before the request, so the reconciler never races this create
	ok := false
	defer func() {
		if !ok {
			d.destroy(vm)
		}
	}()

	in := map[string]any{
		"name":      vm.name,
		"requestId": vm.name,
		// No inline networkPolicies. Verified live on 2026-09-24: a create carrying
		// {"mode": NETWORK_POLICY_MODE_DENY_ALL} fails with Connect code 13
		// "internal error", although capabilities report can_attach_policies. The
		// account's cloud policy default supplies deny-all instead (the operator runs
		// `sbx --cloud policy init deny-all` once); with it in force the effective
		// policy reads DENY_ALL and, from inside the guest, HTTP is unreachable, TLS
		// is refused, a TCP connection is reset on its first byte and UDP gets no
		// answer. verifyEgressDenied refuses any sandbox where that is not so.
		"cloud": map[string]any{
			"imageRef":   strings.TrimSpace(d.Image),
			"startCmd":   dcStartCmd,
			"timeout":    protoDuration(budget + dcTTLSlack),
			"onTimeout":  "ON_TIMEOUT_DELETE",
			"autoResume": false,
			// Pinned so the booted platform, and with it the manifest digest checked in
			// verifySandbox, cannot change under the operator.
			"platform": map[string]any{"os": "linux", "architecture": "amd64"},
		},
	}
	// The service refuses a raw-image create without cpus (verified live
	// 2026-09-24: "'cpus' is required when using 'imageRef'"), so an unset
	// SANDBOX_CPUS or SANDBOX_MEMORY_MB requests the smallest size, Micro.
	cpus, memMiB := d.requestedSize()
	in["resources"] = map[string]any{
		"cpus":      cpus,
		"memoryMib": strconv.Itoa(memMiB), // uint64: a string in protojson
	}

	var op dcOperation
	if err := d.call(ctx, dcProcCreateSandbox, in, &op); err != nil {
		return dcVM{}, fmt.Errorf("dockercloud create sandbox: %w", err)
	}
	op, err := d.waitOperation(ctx, op)
	if err != nil {
		return dcVM{}, fmt.Errorf("dockercloud create sandbox: %w", err)
	}
	if op.Error != nil {
		return dcVM{}, fmt.Errorf("dockercloud create sandbox: operation failed (code %d): %s", op.Error.Code, truncateForError(op.Error.Message))
	}
	var sb dcSandbox
	if len(op.Response) == 0 || json.Unmarshal(op.Response, &sb) != nil || !sb.running() {
		// The operation's response is a google.protobuf.Any; if it does not already
		// carry a running sandbox, read the sandbox itself.
		sb, err = d.waitRunning(ctx, vm)
		if err != nil {
			return dcVM{}, err
		}
	}
	vm.id = sb.Core.ID
	if vm.id == "" {
		return dcVM{}, errors.New("dockercloud create sandbox: running sandbox has no id")
	}
	if sb.Core.Name != "" && sb.Core.Name != vm.name {
		return dcVM{}, fmt.Errorf("dockercloud create sandbox: service reports name %q, requested %q", sb.Core.Name, vm.name)
	}
	if err := d.verifySandbox(sb); err != nil {
		return dcVM{}, err
	}
	vm.endpoint = strings.TrimRight(sb.Core.Endpoint.URI, "/")
	ok = true
	return vm, nil
}

// waitOperation blocks until op is done, using WaitOperation's server-side wait
// and falling back to polling GetOperation where it is not served.
func (d *DockerCloud) waitOperation(ctx context.Context, op dcOperation) (dcOperation, error) {
	poll := false
	for !op.Done {
		if op.ID == "" {
			return op, errors.New("operation is not done and has no id to wait on")
		}
		if err := ctx.Err(); err != nil {
			return op, err
		}
		var next dcOperation
		if !poll {
			wait := min(remainingBudget(ctx, 10*time.Second), 10*time.Second)
			err := d.call(ctx, dcProcWaitOperation, map[string]any{"id": op.ID, "timeout": protoDuration(wait)}, &next)
			if dcCodeIs(err, "unimplemented") {
				poll = true
				continue
			}
			if err != nil {
				return op, err
			}
		} else {
			if err := sleepCtx(ctx, 250*time.Millisecond); err != nil {
				return op, err
			}
			if err := d.call(ctx, dcProcGetOperation, map[string]any{"id": op.ID}, &next); err != nil {
				return op, err
			}
		}
		op = next
	}
	return op, nil
}

// waitRunning polls GetSandbox until the sandbox runs with an endpoint.
func (d *DockerCloud) waitRunning(ctx context.Context, vm dcVM) (dcSandbox, error) {
	for {
		var sb dcSandbox
		if err := d.call(ctx, dcProcGetSandbox, map[string]any{"sandbox": vm.ref()}, &sb); err != nil {
			return dcSandbox{}, fmt.Errorf("dockercloud get sandbox: %w", err)
		}
		if sb.running() {
			return sb, nil
		}
		if sb.terminal() {
			return dcSandbox{}, fmt.Errorf("dockercloud create sandbox: sandbox reached status %s instead of running", sb.Core.Status)
		}
		if err := sleepCtx(ctx, 250*time.Millisecond); err != nil {
			return dcSandbox{}, err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// verifySandbox checks what the service reports about a new sandbox before any
// guest code runs: an endpoint the token may be sent to, resources within the
// configured maximum, and (when the image is pinned) the digest it booted.
func (d *DockerCloud) verifySandbox(sb dcSandbox) error {
	ep := sb.Core.Endpoint
	if ep == nil || ep.URI == "" {
		return errors.New("dockercloud create sandbox: no sandbox endpoint reported")
	}
	// Assumption (live probe): the cloud reports protocol CONNECT (or leaves it
	// unset). A unix-socket endpoint is the local backend's and is refused.
	if ep.Protocol != "" && !ep.Protocol.is("SANDBOX_ENDPOINT_PROTOCOL_CONNECT", 1) {
		return fmt.Errorf("dockercloud create sandbox: endpoint protocol %s is not Connect over HTTP", ep.Protocol)
	}
	if _, err := parseDockerCloudURL(ep.URI, "sandbox endpoint"); err != nil {
		return fmt.Errorf("dockercloud create sandbox: %w", err)
	}
	// Checked against what was requested, including the Micro default when the
	// operator set no envelope: a sandbox that reports no size, or a larger one than
	// requested, is refused (it could bill, or hold, more than asked for).
	wantCPU, wantMiB := d.requestedSize()
	r := sb.Core.Resources
	if r == nil || r.Cpus == nil || r.MemoryMib == nil {
		return errors.New("dockercloud verify resources: sandbox reports no CPU or memory size")
	}
	if *r.Cpus == 0 || uint64(*r.Cpus) > uint64(wantCPU) {
		return fmt.Errorf("dockercloud sandbox exceeds CPU cap: reported %v, requested %d", derefUint(r.Cpus), wantCPU)
	}
	if *r.MemoryMib == 0 || uint64(*r.MemoryMib) > uint64(wantMiB) {
		return fmt.Errorf("dockercloud sandbox exceeds memory cap: reported %v MiB, requested %d", derefUint(r.MemoryMib), wantMiB)
	}
	if image := strings.TrimSpace(d.Image); isDigestPinned(image) {
		// A pinned image is a claim about what boots, so it needs evidence: a
		// sandbox that reports no booted digest is refused, not waved through.
		if sb.Cloud == nil || sb.Cloud.ImageDigest == "" {
			return errors.New("dockercloud sandbox reported no booted image digest; cannot prove the pinned image is the one running")
		}
		want := image[strings.LastIndex(image, "@")+1:]
		if !strings.EqualFold(sb.Cloud.ImageDigest, want) {
			// The cloud reports the platform manifest it booted, not a multi-platform
			// index (verified 2026-09-24: an index pin booted its linux/amd64 entry).
			return fmt.Errorf("dockercloud sandbox booted image digest %s, configured %s; pin the image's linux/amd64 manifest digest, not a multi-platform index", sb.Cloud.ImageDigest, want)
		}
	}
	return nil
}

func derefUint(p *protoUint) string {
	if p == nil {
		return "nothing"
	}
	return strconv.FormatUint(uint64(*p), 10)
}

// verifyEgressDenied reads the sandbox's effective network policy back from the
// service and refuses to run unless it is deny-all with nothing allowed. An older
// server drops inline policies silently (the contract's own warning on
// Capabilities.can_attach_policies), and a governance layer could add allow rules,
// so the request alone is not evidence.
func (d *DockerCloud) verifyEgressDenied(ctx context.Context, vm dcVM) error {
	return d.verifyEgress(ctx, vm, nil)
}

// dcHostModulePath is where a grant project run stages the guard client module.
const dcHostModulePath = "/tmp/plimsoll-dockercloud-host.mjs"

// sealNetwork makes the sandbox's network what the run is entitled to, and proves
// it before any caller code runs. A no-grant run must read back deny-all with
// nothing allowed. A grant run first gets exactly one rule, the guard's host:443
// (putNetworkPolicy), and must then read back exactly that. Until the rule is
// applied the sandbox is deny-all, so every failure here fails closed.
func (d *DockerCloud) sealNetwork(ctx context.Context, vm dcVM, guard *dcGuard) error {
	if guard == nil {
		return d.verifyEgressDenied(ctx, vm)
	}
	allow := []string{guard.allowRule()}
	if err := d.putNetworkPolicy(ctx, vm, allow); err != nil {
		return err
	}
	return d.verifyEgress(ctx, vm, allow)
}

// verifyEgress reads the sandbox's effective network policy back through the
// published contract and refuses the run unless it is deny-all with exactly the
// allowed networks: none for a no-grant run, the guard's host:443 for a grant run.
// An extra rule from any layer (kit, owner, org) refuses the run too.
func (d *DockerCloud) verifyEgress(ctx context.Context, vm dcVM, allowed []string) error {
	var pol struct {
		Mode          protoEnum `json:"mode"`
		AllowNetworks []struct {
			Network string `json:"network"`
		} `json:"allowNetworks"`
	}
	in := map[string]any{"target": map[string]any{"sandbox": map[string]string{"id": vm.id}}}
	if err := d.call(ctx, dcProcEffectivePolicy, in, &pol); err != nil {
		return fmt.Errorf("dockercloud verify egress policy: %w", err)
	}
	if !pol.Mode.is("NETWORK_POLICY_MODE_DENY_ALL", 2) {
		return fmt.Errorf("dockercloud verify egress policy: effective mode is %q, not deny-all", string(pol.Mode))
	}
	got := make([]string, 0, len(pol.AllowNetworks))
	for _, a := range pol.AllowNetworks {
		got = append(got, a.Network)
	}
	if !sameStrings(got, allowed) {
		if len(allowed) == 0 {
			return fmt.Errorf("dockercloud verify egress policy: %d allow rule(s) in force on a no-grant run", len(got))
		}
		return fmt.Errorf("dockercloud verify egress policy: allowed %v, want exactly %v", got, allowed)
	}
	return nil
}

// destroy deletes the sandbox, retrying, on its own context so it still runs after
// the run's context is cancelled or expired. A NOT_FOUND is success. The name is
// untracked whatever happens: once the run is over, anything still alive under
// this instance's name prefix is an orphan, and ReconcileOrphans (or the cloud TTL)
// reaps it.
func (d *DockerCloud) destroy(vm dcVM) {
	defer d.untrack(vm.name)
	const attempts = 3
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := d.deleteSandbox(ctx, vm.ref(), "delete-"+vm.name)
		cancel()
		if err == nil {
			return
		}
		if i == attempts-1 {
			slog.Error("dockercloud: failed to delete sandbox; orphan reconciliation or its cloud TTL will reap it",
				"sandbox", vm.name, "id", vm.id, "attempts", attempts, "error", err)
			return
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
}

func (d *DockerCloud) deleteSandbox(ctx context.Context, ref map[string]string, requestID string) error {
	// DeleteSandbox answers an Operation; an accepted request is not a completed
	// deletion. Wait for it, and treat a failed operation as a failed delete so
	// destroy retries and the reaper does not count the sandbox as gone.
	var op dcOperation
	err := d.call(ctx, dcProcDeleteSandbox, map[string]any{"sandbox": ref, "force": true, "requestId": requestID}, &op)
	if dcCodeIs(err, "not_found") {
		return nil
	}
	if err != nil {
		return err
	}
	op, err = d.waitOperation(ctx, op)
	if dcCodeIs(err, "not_found") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("dockercloud delete sandbox: %w", err)
	}
	if op.Error != nil {
		return fmt.Errorf("dockercloud delete sandbox: operation failed (code %d): %s", op.Error.Code, truncateForError(op.Error.Message))
	}
	return nil
}

// ReconcileOrphans deletes every sandbox named with this instance's prefix that no
// run is tracking: a create whose answer never arrived and whose delete-by-name
// also failed, or a teardown whose retries all failed. Names are tracked before a
// create is sent, so an in-flight run is never touched, and sandboxes of other
// instances (even under the same token) never match the prefix.
func (d *DockerCloud) ReconcileOrphans(ctx context.Context) (int, error) {
	if strings.TrimSpace(d.Token) == "" {
		return 0, errors.New("DOCKER_SBX_TOKEN is not set")
	}
	prefix := d.namePrefix()
	deleted := 0
	token := ""
	for page := 0; page < dcMaxListPages; page++ {
		in := map[string]any{"pageSize": 100}
		if token != "" {
			in["pageToken"] = token
		}
		var out struct {
			Sandboxes     []dcSandbox `json:"sandboxes"`
			NextPageToken string      `json:"nextPageToken"`
		}
		if err := d.call(ctx, dcProcListSandboxes, in, &out); err != nil {
			return deleted, fmt.Errorf("dockercloud list sandboxes: %w", err)
		}
		for _, sb := range out.Sandboxes {
			name := sb.Core.Name
			if !strings.HasPrefix(name, prefix) || d.tracked(name) {
				continue
			}
			ref := map[string]string{"name": name}
			if sb.Core.ID != "" {
				ref = map[string]string{"id": sb.Core.ID}
			}
			if err := d.deleteSandbox(ctx, ref, "reap-"+name); err != nil {
				slog.Error("dockercloud: failed to delete orphaned sandbox", "sandbox", name, "error", err)
				continue
			}
			slog.Warn("dockercloud: deleted orphaned sandbox", "sandbox", name, "created_at", sb.Core.CreatedAt)
			deleted++
		}
		if out.NextPageToken == "" {
			return deleted, nil
		}
		token = out.NextPageToken
	}
	return deleted, fmt.Errorf("dockercloud list sandboxes: more than %d pages", dcMaxListPages)
}

// ---- startup smoke test ----

// dockerCloudRequiredPermissions are the owner-scope permissions a run needs.
var dockerCloudRequiredPermissions = []struct {
	name   string
	number int
}{
	{"PERMISSION_SANDBOXES_READ", 1},
	{"PERMISSION_SANDBOXES_CREATE", 2},
	// PERMISSION_SANDBOXES_EXEC and the FILES permissions are not required: the
	// cloud does not list them for a Cloud Sandboxes token, yet serves exec on the
	// sandbox endpoint (verified live 2026-09-24). The exec and upload calls fail
	// loudly if a token really lacks them.
	{"PERMISSION_SANDBOXES_DELETE", 9},
	{"PERMISSION_NETWORK_POLICIES_READ", 18},
}

// checkCapabilities asks the backend what it serves this token: the permissions a
// run needs and the resource range. Egress is not checked here; it is read back
// per sandbox.
func (d *DockerCloud) checkCapabilities(ctx context.Context) error {
	var caps struct {
		Permissions []protoEnum `json:"permissions"`
		Resources   *struct {
			CPUMin       protoUint `json:"cpuMin"`
			CPUMax       protoUint `json:"cpuMax"`
			MemoryMibMin protoUint `json:"memoryMibMin"`
			MemoryMibMax protoUint `json:"memoryMibMax"`
		} `json:"resources"`
	}
	if err := d.call(ctx, dcProcGetCapabilities, map[string]any{}, &caps); err != nil {
		return fmt.Errorf("get capabilities: %w", err)
	}
	// An empty list is read as "not reported", not as "no permissions"; the create
	// and exec calls then fail loudly if the token really lacks them.
	if len(caps.Permissions) > 0 {
		var missing []string
		for _, want := range dockerCloudRequiredPermissions {
			found := false
			for _, have := range caps.Permissions {
				if have.is(want.name, want.number) {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, want.name)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("token lacks permissions: %s", strings.Join(missing, ", "))
		}
	}
	if r := caps.Resources; r != nil {
		if cpus := uint64(d.MaxVCPU); cpus > 0 && r.CPUMax > 0 && (cpus < uint64(r.CPUMin) || cpus > uint64(r.CPUMax)) {
			return fmt.Errorf("SANDBOX_CPUS=%d is outside the backend's range %d..%d", cpus, r.CPUMin, r.CPUMax)
		}
		if mem := uint64(d.MaxMemoryMB); mem > 0 && r.MemoryMibMax > 0 && (mem < uint64(r.MemoryMibMin) || mem > uint64(r.MemoryMibMax)) {
			return fmt.Errorf("SANDBOX_MEMORY_MB=%d is outside the backend's range %d..%d MiB", mem, r.MemoryMibMin, r.MemoryMibMax)
		}
	}
	return nil
}

// SmokeTest proves the configured account, image and endpoint serve this provider's
// contract by exercising one throwaway sandbox end to end: capabilities, create
// with the deny-all policy, the effective policy read back, directory creation and
// upload into the project dir, and a probe run through the exact project-step path
// (the exec wrapper around `sh <script>`), which reports the node runtime, the
// working directory and, from inside the guest, whether egress is really denied;
// then a hung command and a flood prove the in-guest time limit and output cap.
// It creates one billable sandbox, so the daemon runs it once at startup and never
// on a poll path.
func (d *DockerCloud) SmokeTest(ctx context.Context) error {
	if err := d.Preflight(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, dcSmokeTimeout)
	defer cancel()
	if err := d.checkCapabilities(ctx); err != nil {
		return fmt.Errorf("dockercloud smoke: %w", err)
	}
	vm, err := d.create(ctx, remainingBudget(ctx, dcSmokeTimeout))
	if err != nil {
		return fmt.Errorf("dockercloud smoke: %w", err)
	}
	defer d.destroy(vm)
	if err := d.verifyEgressDenied(ctx, vm); err != nil {
		return fmt.Errorf("dockercloud smoke: %w", err)
	}
	dir := d.projectDir()
	const stepPath = "/tmp/plimsoll-smoke-step.sh"
	if err := d.mkdirs(ctx, vm, map[string]struct{}{dir: {}}); err != nil {
		return fmt.Errorf("dockercloud smoke: create project dir: %w", err)
	}
	files := []File{
		{Path: pathpkg.Join(dir, "plimsoll-smoke.cjs"), Content: vmSmokeProbe},
		{Path: stepPath, Content: "node plimsoll-smoke.cjs\n"},
	}
	if err := d.upload(ctx, vm, files); err != nil {
		return fmt.Errorf("dockercloud smoke: stage probe: %w", err)
	}
	out, err := d.execGuarded(ctx, vm, []string{"sh", stepPath}, dir)
	if err != nil {
		return fmt.Errorf("dockercloud smoke: run probe: %w", err)
	}
	if out.exitCode != 0 {
		// 127 is the missing-tool signature: sh could not find node or timeout.
		return fmt.Errorf("dockercloud smoke: probe exited %d on image %q (an image missing node, timeout or head cannot serve runs): %s",
			out.exitCode, d.Image, strings.TrimSpace(out.stderr))
	}
	var report struct {
		Node       string   `json:"node"`
		Cwd        string   `json:"cwd"`
		EgressOpen []string `json:"egressOpen"`
	}
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		return fmt.Errorf("dockercloud smoke: unparseable probe report %q: %w", out.stdout, err)
	}
	if report.Node == "" {
		return errors.New("dockercloud smoke: probe reported no node version")
	}
	if report.Cwd != dir {
		return fmt.Errorf("dockercloud smoke: probe ran in %q, not the project dir %q; the step working directory is not honored", report.Cwd, dir)
	}
	if len(report.EgressOpen) > 0 {
		return fmt.Errorf("dockercloud smoke: egress is OPEN to %s; the deny-all network policy is not in force", strings.Join(report.EgressOpen, ", "))
	}

	// The bounds the API does not give must actually hold in this guest. busybox
	// `timeout` fails open when kill(2) is refused (its watcher reads the error as
	// "the process is gone"), so a hung command must really be killed at the limit,
	// and a flood must really be capped.
	hang, err := d.execLimited(ctx, vm, []string{"sleep", "30"}, "", 1)
	if err != nil {
		return fmt.Errorf("dockercloud smoke: time-limit probe: %w", err)
	}
	if !hang.timedOut {
		return fmt.Errorf("dockercloud smoke: the in-guest time limit is not in force (sleep exited %d instead of being killed at 1s)", hang.exitCode)
	}
	flood, err := d.execLimited(ctx, vm, []string{"yes"}, "", 10)
	if err != nil {
		return fmt.Errorf("dockercloud smoke: output-cap probe: %w", err)
	}
	if !flood.stdoutTruncated || flood.exitCode == 0 || len(flood.stdout) != d.maxOutput() {
		return fmt.Errorf("dockercloud smoke: the in-guest output cap is not in force (exit %d, %d bytes, truncated=%v)",
			flood.exitCode, len(flood.stdout), flood.stdoutTruncated)
	}
	return nil
}
