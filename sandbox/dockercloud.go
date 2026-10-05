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
// It was first written against Docker's pre-launch contract, the protobuf API released
// as the Go module github.com/docker/sandboxes-api (v0.36.0, Apache-2.0), and since
// 2026-10-04 can also speak the REST API Docker documents, as a backup until it covers
// grants, the booted image's identity and runs past 270 s; Connect stays the default.
// Both passed the live suite on 2026-10-04 (docs/dockercloud.md). Where the service differs
// from the contract (the token exchange, the inline network policy, the reported
// image digest, the required CPU count) the code says so where it depends on it.
// "Assumption (live probe)" marks behavior the contract does not pin down; the live
// suite exercises it, but no document promises it.
//
// Its calls to the service go through one transport (dcTransport,
// dockercloud_transport.go), which speaks one of Docker's APIs, chosen by the
// operator (API): Connect (dockercloud_connect.go) or REST (dockercloud_rest.go).
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
	// API is the Docker API this provider speaks (SANDBOX_DOCKERCLOUD_API): dcAPIConnect,
	// the pre-launch contract and the default, the only one with grants, the booted
	// image's identity and runs past 270 s; or dcAPIREST, the one Docker documents, kept
	// as the backup until it covers those. Empty is connect (both passed the live suite on
	// 2026-10-04). One API serves a provider for its whole life (dcTransport).
	API string
	// APIURL is the management endpoint (SANDBOX_DOCKERCLOUD_API_URL). For REST the
	// default is the base URL Docker documents (dcRESTDefaultURL). For Connect there
	// is no default: Docker has not documented it. The only hint in the published module
	// is its Python README, which connects to "https://sandboxes.connect.docker.com/sbx"
	// (sandboxes-api v0.36.0, gen/python/README.md); it is an example, not a
	// documented contract, so the operator must state the URL.
	APIURL string
	// Image is the raw OCI image each sandbox boots (SANDBOX_DOCKERCLOUD_IMAGE),
	// normally the plimsoll toolchain image published to a registry the service
	// can pull.
	Image string
	// StoreImage is an image in the account's own Docker Cloud Sandboxes image store
	// (SANDBOX_DOCKERCLOUD_STORE_IMAGE), named "<image id>@sha256:<manifest digest>",
	// instead of Image. The service boots it by ID with no registry pull, so the image
	// can stay private to the account with no registry credential; the digest is
	// required, and every sandbox's booted digest is checked against it. The image's
	// own size and start command apply (the service refuses either beside an image
	// ID), so it is created with plimsoll's start command, `tail -f /dev/null`.
	// Connect only. Verified live on 2026-10-05.
	StoreImage string
	// RequirePinnedImage refuses an Image that is not an @sha256: digest (a StoreImage
	// always carries one).
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

	// The REST transport's endpoint credentials, one per live sandbox (dcREST).
	restCredMu sync.Mutex
	restCreds  map[string]dcRESTCred

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
func (d *DockerCloud) SupportsJavaScriptGrants() bool { return d.grantsServed() }
func (d *DockerCloud) SupportsProjectGrants() bool    { return d.grantsServed() }

// grantsServed: a guard URL is configured and the API is one on which the guard's
// network rule has been shown to take effect (Connect, live 2026-09-24).
func (d *DockerCloud) grantsServed() bool { return d.guardConfig() != nil && !d.rest() }

// IsolationClass is VM: each run gets a disposable Docker-managed microVM. As for
// every provider, the tier is configuration and provider evidence plus the startup
// smoke test, never runtime attestation.
func (*DockerCloud) IsolationClass() IsolationClass { return IsolationVM }

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
	switch d.API {
	case "", dcAPIConnect, dcAPIREST:
	default:
		return fmt.Errorf("SANDBOX_DOCKERCLOUD_API=%q: want %s or %s", d.API, dcAPIConnect, dcAPIREST)
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
	if _, err := parseDockerCloudURL(d.apiURL(), "SANDBOX_DOCKERCLOUD_API_URL"); err != nil {
		return err
	}
	if d.rest() && strings.TrimSpace(d.GuardURL) != "" {
		return errors.New("dockercloud host-API grants cannot be verified on the REST API (it does not report a sandbox's policy once the guard's rule is on): unset SANDBOX_DOCKERCLOUD_GUARD_URL, or set SANDBOX_DOCKERCLOUD_API=connect")
	}
	if d.rest() && runCeiling(d.MaxTimeout) > dcRESTMaxRun {
		return fmt.Errorf("dockercloud on the REST API cannot run past %s (an exec ends with its endpoint credential); the configured ceiling is %s", dcRESTMaxRun, runCeiling(d.MaxTimeout))
	}
	image, store := strings.TrimSpace(d.Image), strings.TrimSpace(d.StoreImage)
	switch {
	case image != "" && store != "":
		return errors.New("SANDBOX_DOCKERCLOUD_IMAGE and SANDBOX_DOCKERCLOUD_STORE_IMAGE are both set; set one")
	case store != "":
		if _, _, err := parseStoreImage(store); err != nil {
			return err
		}
		if d.rest() {
			return errors.New("SANDBOX_DOCKERCLOUD_STORE_IMAGE needs SANDBOX_DOCKERCLOUD_API=connect: the REST API reports no booted digest, so a store image's digest could not be checked")
		}
		return d.validateResourceConfig()
	case image == "":
		return errors.New("SANDBOX_DOCKERCLOUD_IMAGE is not set (the raw OCI image each sandbox boots), nor SANDBOX_DOCKERCLOUD_STORE_IMAGE")
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

// parseStoreImage splits "<image id>@sha256:<64 hex>" into the store's image ID and the
// digest. An ID is what the store assigns (tmpl_ and 26 more letters and digits on
// 2026-10-05); any letters, digits, '_' and '-' up to 128 are accepted, since the ID
// is sent as a JSON string and never put in a URL or a host name.
func parseStoreImage(s string) (id, digest string, err error) {
	at := strings.Index(s, "@")
	if at <= 0 || !isDigestPinned(s) || strings.Count(s, "@") != 1 {
		return "", "", fmt.Errorf("SANDBOX_DOCKERCLOUD_STORE_IMAGE %q: want <image id>@sha256:<64 hex digits>", truncateForError(s))
	}
	id, digest = s[:at], strings.ToLower(s[at+1:])
	if len(id) > 128 {
		return "", "", fmt.Errorf("SANDBOX_DOCKERCLOUD_STORE_IMAGE: image ID longer than 128 characters")
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", "", fmt.Errorf("SANDBOX_DOCKERCLOUD_STORE_IMAGE %q: an image ID is letters, digits, '_' and '-'", truncateForError(s))
		}
	}
	return id, digest, nil
}

// imageName is the configured image as an operator wrote it, for messages.
func (d *DockerCloud) imageName() string {
	if s := strings.TrimSpace(d.StoreImage); s != "" {
		return "store image " + s
	}
	return strings.TrimSpace(d.Image)
}

// pinnedDigest is the digest every sandbox must report having booted: a store image's,
// always, or Image's when it is pinned.
func (d *DockerCloud) pinnedDigest() (string, bool) {
	if s := strings.TrimSpace(d.StoreImage); s != "" {
		_, digest, err := parseStoreImage(s)
		return digest, err == nil
	}
	if image := strings.TrimSpace(d.Image); isDigestPinned(image) {
		return image[strings.LastIndex(image, "@")+1:], true
	}
	return "", false
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

// The values of DockerCloud.API.
const (
	dcAPIConnect = "connect"
	dcAPIREST    = "rest"
)

// dcRESTDefaultURL is the REST API's base URL, as Docker documents it.
const dcRESTDefaultURL = "https://connect.docker.com/sandboxes"

// dcRESTMaxRun is the longest run the REST transport accepts: an exec is cut off when
// its endpoint credential expires, at most 300 s after the credential is minted
// (probe 2026-10-04: 299.6 s), and each exec mints its own just before it starts.
// The 30 s margin covers the run's own setup and the mint's round trip.
const dcRESTMaxRun = 270 * time.Second

// rest reports that this provider speaks the REST API; Connect is the default.
func (d *DockerCloud) rest() bool { return d.API == dcAPIREST }

// APIName is the Docker API this provider speaks: "rest" or "connect".
func (d *DockerCloud) APIName() string {
	if d.rest() {
		return dcAPIREST
	}
	return dcAPIConnect
}

// wire is the transport this provider's calls go through.
func (d *DockerCloud) wire() dcTransport {
	if d.rest() {
		return dcREST{d}
	}
	return dcConnect{d}
}

func (d *DockerCloud) apiURL() string {
	if u := strings.TrimSpace(d.APIURL); u != "" || !d.rest() {
		return u
	}
	return dcRESTDefaultURL
}

func (d *DockerCloud) apiBase() string { return strings.TrimRight(d.apiURL(), "/") }

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
