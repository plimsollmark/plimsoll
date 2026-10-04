package sandbox

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/lease"
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

	HTTP *http.Client // nil = a default client; redirects are never followed either way

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
	// instance, and the name is its lease key (sandbox/internal/lease).
	mu         sync.Mutex
	instanceID string
	leases     lease.Set
}

func (*DockerCloud) Name() string { return "dockercloud" }

// BillingTeardown is how long a run's microVM can outlive its deadline, being
// deleted: every run creates a microVM the operator pays for by the second
// (sandbox.Metered).
func (*DockerCloud) BillingTeardown() time.Duration { return meteredTeardown }

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

// httpClient never follows a redirect, whoever supplied the client: a redirected
// request would carry the bearer token (or lose it) somewhere the operator did not
// configure.
func (d *DockerCloud) httpClient() *http.Client { return withoutRedirects(d.HTTP) }

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

// admit is every check before a Docker Cloud call dispatches, in one order (review R4):
// the caller's isolation floor and software rule, then the provider's configuration.
// Every refusal is marked not dispatched; before, a missing token went out unmarked,
// as if the run might have happened.
func (d *DockerCloud) admit(floor IsolationClass, rule SoftwareRule) error {
	if err := CheckMinimumIsolation(d.IsolationClass(), floor); err != nil {
		return err
	}
	if err := rule.Check(""); err != nil {
		return err
	}
	if err := d.validateConfig(); err != nil {
		return NotDispatched(RefusalEnvironment, err)
	}
	return nil
}

// dcCredentialPattern matches anything credential-shaped a vendor message could
// echo: a bearer header value, a JWT (the exchanged bearer is one), a Docker
// personal access token, a plimsoll guard credential.
var dcCredentialPattern = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*|dckr_pat_[A-Za-z0-9_-]+|crg_[0-9a-f]{16,}|e2b_[A-Za-z0-9]{8,}`)

// truncateForError bounds and scrubs vendor- or guest-controlled text before it
// enters an error or a log line: every such string in every provider passes through
// here (dcRPCError through its Error method), so no credential a service might echo
// back reaches a caller or a log.
func truncateForError(s string) string {
	s = dcCredentialPattern.ReplaceAllString(s, "<redacted>")
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

// dcDefaultCPUs and dcDefaultMemoryMiB are the Micro size, requested when the
// operator sets no envelope: the smallest and cheapest the service offers.
const (
	dcDefaultCPUs      = 1
	dcDefaultMemoryMiB = 2048
)
