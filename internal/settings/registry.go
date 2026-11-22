package settings

// The table: every variable plimsolld reads, in its -h order. Written once from the -h
// text that was hand-kept in cmd/plimsolld until 2026-11-18 (P5 of
// private/reviews/refactor-and-assumptions-public-2026-11-18.md); edit it here.

const helpHead = `plimsolld serves the plimsoll SandboxService over Connect: cleartext
HTTP/2 ("h2c") and HTTP/1.1, or HTTP/1.1 and HTTP/2 over TLS when PLIMSOLL_TLS_CERT
is set.

Usage: plimsolld [-h]

The daemon takes no arguments. Configuration is by environment variable:

`

const helpFoot = `
Endpoints outside auth: GET /healthz (liveness) and GET /readyz (provider
readiness) on PLIMSOLL_ADDR, GET /metrics (Prometheus text: run, shed-load,
host-call and advice counters) on PLIMSOLL_METRICS_ADDR only, and the egress
guard (each call authenticated by its run's guard credential) on
PLIMSOLL_GUARD_ADDR only.
`

var (
	sectionDaemon       = section("Daemon", "", "")
	sectionProviders    = section("Providers", "", "\n")
	sectionAgentsandbox = section("agentsandbox", "agentsandbox", `
  SANDBOX_PROVIDER=agentsandbox
                             Kubernetes agent-sandbox (v1.0.7): one SandboxClaim per
                             run on a warm pool, deleted after. plimsolld runs in the
                             cluster, since it reaches each pod's sandboxd at the
                             pod's address. The tier is read from the runtime class's
                             handler (runsc and any declared below: kernel, runc:
                             container, kata, kata-clh and kata-clh-runtime-rs: vm;
                             anything else refused), proven by the startup smoke
                             test and checked again in every pod.
                             The class the smoke test ran on (its UID, handler,
                             overhead and scheduling) is the only one accepted after;
                             a class changed since is refused until a restart.
`)
	sectionLambdamicrovm = section("lambdamicrovm", "lambdamicrovm", `
  SANDBOX_PROVIDER=lambdamicrovm
                             AWS Lambda MicroVMs (Firecracker): one VM per run, billed
                             by the second, so the daily paid-seconds allowances apply.
                             Experimental: written from AWS's documentation and not yet
                             run against the live service. The guest has public
                             internet unless started on a customer VPC egress connector
                             with no route out; every run reads the VM back and probes
                             the guest's network before any code, and the smoke test
                             refuses startup if the guest reaches the internet or DNS,
                             or if node does not run a snippet and name its version.
                             Snippets and projects only: no grants, sessions or modules.
`)
	sectionOpenshell = section("openshell", "openshell", `
  SANDBOX_PROVIDER=openshell NVIDIA OpenShell sandboxes through a gateway: the
                             docker compute driver only, reported as container
                             isolation (hardened mode refuses it). Each run creates
                             a sandbox with no network and deletes it. All five are
                             required (the gateway uses mutual TLS):
`)
	sectionWslc = section("wslc", "wslc", `
  SANDBOX_PROVIDER=wslc
                             WSL containers (WSLC) on Windows, driven through WSL
                             interop from a plimsolld in a WSL distribution. Needs
                             WSL 3.0.5 or later. Microsoft states that WSL is not a
                             security sandbox for running untrusted code; hardened
                             mode refuses it in both modes.
                             In both, a run's container has no read-only root, no
                             seccomp choice or no-new-privileges, no process limit
                             and no user namespaces. The smoke test refuses startup
                             unless the probe container has loopback alone, no
                             capability, the guest uid, the memory limit, a seccomp
                             filter, no GPU device, no Windows folder and no writable
                             place but its four tmpfs mounts.
                             Snippets and projects only: no grants, sessions or modules.
                             Guide: docs/wslc.md.
`)
	sectionWithheldKnown = section("WithheldKnown", "", "")
	sectionLimits        = section("Limits", "", "\n")
)

// Daemon settings.
var (
	Addr = sectionDaemon.text(Meta{Name: "PLIMSOLL_ADDR", Default: "127.0.0.1:8746", Doc: `listen address for RPC and the health endpoints
(default 127.0.0.1:8746, this machine only). To
serve other hosts (a container, a pod, a server), set
it: 0.0.0.0:8746 or :8746 for every interface, or one
interface's address`})
	MetricsAddr = sectionDaemon.trimmed(Meta{Name: "PLIMSOLL_METRICS_ADDR", Doc: `listen address for GET /metrics, a listener of its
own (default 127.0.0.1:9464, this host only; the
host and port are OpenTelemetry's Prometheus exporter
defaults); off disables it. It has no authentication
and its labels name grant profiles and route
templates, so bind an address other hosts can reach
only behind a firewall rule that admits just the
scraper. It serves TLS when the daemon does`})
	GuardAddr = sectionDaemon.trimmed(Meta{Name: "PLIMSOLL_GUARD_ADDR", Doc: `listen address for the egress guard, a listener of
its own that serves the guard path and nothing else;
required when E2B_GUARD_URL or
SANDBOX_DOCKERCLOUD_GUARD_URL is set, refused
otherwise. Point the public guard URL at it. A guest's
one permitted destination is the guard, so it never
shares PLIMSOLL_ADDR, where the guest would also reach
the RPC procedures and the health endpoints. It
serves TLS when the daemon does`})
	LogFormat = sectionDaemon.trimmed(Meta{Name: "PLIMSOLL_LOG_FORMAT", Doc: `json (default) or text; the audit stream is a
machine-read record and prospector-report consumes
newline-delimited JSON. Use text only for eyeballing
a local run.`})
	ClientsFile = sectionDaemon.trimmed(Meta{Name: "PLIMSOLL_CLIENTS_FILE", Doc: `JSON caller registry for multi-client auth (each
caller its own principal; managed by plimsoll-clients);
takes precedence over PLIMSOLL_TOKEN. A file or
directory on its path that another user could change
is refused in hardened mode and warned about otherwise
(as for PLIMSOLL_GRANTS_FILE and PLIMSOLL_WITHHELD_FILE)`})
	Token = sectionDaemon.text(Meta{Name: "PLIMSOLL_TOKEN", Doc: `one shared bearer granting code:run to every caller
(at least 32 characters)`})
	Insecure = sectionDaemon.bool(Meta{Name: "PLIMSOLL_INSECURE", Doc: `=1 (or true) explicitly permits a real provider with
auth disabled (development only); any value but 0,
1, false or true refuses startup. Open mode serves
loopback only: it refuses to start unless
PLIMSOLL_ADDR binds a loopback address (the default
does; :8746 or 0.0.0.0:8746 is refused), and it
answers only requests addressed to localhost or a
loopback address`})
	TLSCert = sectionDaemon.trimmed(Meta{Name: "PLIMSOLL_TLS_CERT", Doc: `PEM certificate and key; when set the daemon serves
TLS (HTTP/1.1 + HTTP/2 via ALPN) instead of cleartext`})
	TLSKey   = sectionDaemon.trimmed(Meta{Name: "PLIMSOLL_TLS_KEY", DocWith: "PLIMSOLL_TLS_CERT"})
	Hardened = sectionDaemon.bool(Meta{Name: "PLIMSOLL_HARDENED", Doc: `=1 enforces the production policy at startup: vm or
verified kernel isolation, multi-client auth, TLS on
every non-loopback listener (RPC, metrics, guard),
pinned images (docker; dockercloud, or a store image,
with SANDBOX_DOCKERCLOUD_API=connect named) or an
explicit E2B template, no unconfined seccomp, an
explicit resource envelope plus (docker) the aggregate
budget, per-caller rate limiting with a burst of at
most one minute's rate, a per-caller concurrency cap
below SANDBOX_MAX_CONCURRENT, a per-caller session cap
with sessions on, and paid_seconds_per_day on every
caller of e2b or dockercloud, and callers, grants and
withheld files (and every directory on their paths)
owned by root or the daemon's user and not writable by
group or others. Every rule but isolation
is checked before the billed smoke test. Any violation
refuses to serve. Isolation is also held on every run:
kernel is a floor joined to each request's minimum, so
a provider that finds a weaker boundary later refuses
the run before code runs, and /readyz says not ready
while the provider's tier is below it.`})
	GrantsFile = sectionDaemon.trimmed(Meta{Name: "PLIMSOLL_GRANTS_FILE", Doc: `JSON file of named host-API capability profiles a
caller may select via grant_profile`})
	WithheldFile = sectionDaemon.trimmed(Meta{Name: "PLIMSOLL_WITHHELD_FILE", Doc: `JSON withheld set (built by plimsoll-withheld): digests
of what must never enter a sandbox, such as a
harness's source, hidden answers and held-out seeds.
Every call's payload, and the archives in it, is
scanned for it before admission; a find refuses the
call (not dispatched) or is named on the audit line
alone, by the entry's mode, and a set with a refuse
entry refuses a call whose archives pass the scan's
bounds. With the docker provider, each image it runs
is scanned for the set at startup too (about 12 s for
a 1 GB image), and a refuse-mode entry found in one
refuses to start. A malformed set refuses to start.
See docs/ship-scan.md`})
)

// Providers settings.
var (
	Provider     = sectionProviders.lower(Meta{Name: "SANDBOX_PROVIDER", Doc: `{providers} | (unset = disabled)`})
	MinIsolation = sectionProviders.lower(Meta{Name: "SANDBOX_MIN_ISOLATION", Doc: `refuse to start unless the provider meets this tier,
and refuse any run below it, not dispatched
(vm | kernel | container | process); unset = no floor`})
	DockerImage        = sectionProviders.text(Meta{Name: "SANDBOX_DOCKER_IMAGE", Doc: `snippet image (default node:22-alpine)`})
	DockerProjectImage = sectionProviders.text(Meta{Name: "SANDBOX_DOCKER_PROJECT_IMAGE", Doc: `project toolchain image (default plimsoll/sandbox:latest)`})
	DockerModuleImage  = sectionProviders.text(Meta{Name: "SANDBOX_DOCKER_MODULE_IMAGE", Doc: `simulation worker image for module runs (built by
make docker-images as plimsoll/sandbox-sim:latest);
unset = module runs unsupported`})
	DockerRuntime = sectionProviders.text(Meta{Name: "SANDBOX_DOCKER_RUNTIME", Doc: `runsc (gVisor) for the docker provider; "" = runc`})
	DockerSeccomp = sectionProviders.text(Meta{Name: "SANDBOX_DOCKER_SECCOMP", Doc: `seccomp profile path (or "unconfined") for docker; ""
keeps docker's built-in default. Set it to the shipped
audited profile (docker/seccomp.json) to also deny
ptrace, io_uring, keyctl and similar; see docs/seccomp.md`})
	DockerSeccompSDK = sectionProviders.text(Meta{Name: "SANDBOX_DOCKER_SECCOMP_SDK", Doc: `the profile a run gets instead of SANDBOX_DOCKER_SECCOMP
when its grant profile sets sdk_env (the local address a
standard client library reaches the broker through, which
needs IPv4 TCP sockets the default denies). "derived" makes
it from the default at startup (IPv4 TCP sockets and a few
socket options added, nothing else); a path names your own.
"" refuses such runs before dispatch when
SANDBOX_DOCKER_SECCOMP is a file. It needs
SANDBOX_DOCKER_SECCOMP, and never replaces it for any other
run; see docs/seccomp.md`})
	GuestUID = sectionProviders.trimmed(Meta{Name: "SANDBOX_GUEST_UID", Doc: `the uid (and gid) docker runs every guest as, default
61000, which no account uses; 1 to 65532, with
neither it nor it + 1 in a band systemd assigns
itself (60001-60513, 60578-60705, 61184-65519).
Preflight refuses one this host's /etc/passwd or
/etc/group has (it or one more, the session identity
check's)`})
	RequirePinnedImages = sectionProviders.bool(Meta{Name: "SANDBOX_REQUIRE_PINNED_IMAGES", Doc: `=1 to refuse mutable image tags (require
name@sha256:<64 lower-case hex digits>)`})
	E2BAPIKey   = sectionProviders.text(Meta{Name: "E2B_API_KEY", Doc: `E2B credentials and toolchain template`})
	E2BTemplate = sectionProviders.trimmed(Meta{Name: "E2B_TEMPLATE", DocWith: "E2B_API_KEY"})
	E2BGuardURL = sectionProviders.text(Meta{Name: "E2B_GUARD_URL", Doc: `absolute HTTPS egress-guard URL on port 443 whose host
is a name, never an IP address (E2B's network rule
refuses one); enables E2B grants (allowlist plus beta
header transform). It must reach this daemon's
PLIMSOLL_GUARD_ADDR`})
	E2BSessionGrants = sectionProviders.text(Meta{Name: "E2B_SESSION_GRANTS", Doc: `how a granted session call reaches the guard: unset
refuses it; session = one credential for the
session's life; call = a fresh one put on per call;
both passed against the live service on 2026-10-08.
Needs E2B_GUARD_URL`})
	DockerSBXToken = sectionProviders.text(Meta{Name: "DOCKER_SBX_TOKEN", Doc: `Docker Cloud Sandboxes personal access token for
dockercloud (read from the environment only); it is
exchanged for a short-lived bearer, never sent to
the sandbox API itself`})
	DockerSBXUsername  = sectionProviders.text(Meta{Name: "DOCKER_SBX_USERNAME", Doc: `the Docker account the token belongs to`})
	DockercloudAuthURL = sectionProviders.text(Meta{Name: "SANDBOX_DOCKERCLOUD_AUTH_URL", Doc: `token exchange endpoint; default
https://hub.docker.com/v2/auth/token`})
	DockercloudGuardURL = sectionProviders.text(Meta{Name: "SANDBOX_DOCKERCLOUD_GUARD_URL", Doc: `absolute HTTPS egress-guard endpoint on 443; enables
dockercloud grants (connect only). A grant run's sandbox may reach
only this host; the guest holds a per-run, guard-only
credential (Docker's proxy cannot inject one); served
on PLIMSOLL_GUARD_ADDR`})
	DockercloudPolicyURL = sectionProviders.text(Meta{Name: "SANDBOX_DOCKERCLOUD_POLICY_URL", Doc: `per-sandbox network-policy REST base; default
https://api.sandboxes-cloud.docker.com/v1. Not in
Docker's published contract (the sbx CLI's call);
every grant run verifies the result through it`})
	DockercloudAPI = sectionProviders.text(Meta{Name: "SANDBOX_DOCKERCLOUD_API", Doc: `which Docker API dockercloud speaks: connect (the
default; the pre-launch contract, the only one with
grants and image identity) or rest (the API Docker
documents, kept as a backup until it covers those);
both passed the live suite on 2026-10-04. rest states no image
identity (it reports no booted digest, so hardened
mode needs connect), caps a run at 270 s (an exec
ends with its 300 s endpoint credential) and cannot
verify grants, so it fails startup when
SANDBOX_DOCKERCLOUD_GUARD_URL is set`})
	DockercloudAPIURL = sectionProviders.text(Meta{Name: "SANDBOX_DOCKERCLOUD_API_URL", Doc: `Docker Cloud Sandboxes management endpoint. connect:
required, no default
(https://sandboxes.connect.docker.com/sbx answered on
2026-10-04); rest: default
https://connect.docker.com/sandboxes, the documented
base URL`})
	DockercloudImage = sectionProviders.text(Meta{Name: "SANDBOX_DOCKERCLOUD_IMAGE", Doc: `raw OCI image each dockercloud sandbox boots (the
toolchain image; must be @sha256: when
SANDBOX_REQUIRE_PINNED_IMAGES=1, and then the
linux/amd64 manifest digest). dockercloud honors
SANDBOX_MEMORY_MB and whole SANDBOX_CPUS, and requests
the Micro size (1 CPU, 2 GiB) when they are unset;
SANDBOX_PIDS and SANDBOX_DISK_MB fail startup. The
account's cloud network policy must default to
deny-all (sbx --cloud policy init deny-all); every run
verifies it. Verified live on 2026-09-24.`})
	DockercloudStoreImage = sectionProviders.trimmed(Meta{Name: "SANDBOX_DOCKERCLOUD_STORE_IMAGE", Doc: `instead of SANDBOX_DOCKERCLOUD_IMAGE: an image in the
account's own Cloud Sandboxes image store, as
<image id>@sha256:<digest>. Booted by ID with no
registry pull, so it can stay private to the account;
every sandbox's booted digest must equal the one given.
Its size and start command are the image's own (create
it with the start command tail -f /dev/null), so
SANDBOX_CPUS and SANDBOX_MEMORY_MB only cap them.
connect only. Verified live on 2026-10-05.`})
	DockerDefaultPlatform = sectionProviders.text(Meta{Name: "DOCKER_DEFAULT_PLATFORM", Doc: `the Docker platform image inspection and runs select
(for example linux/amd64)`})
	DockerHost = sectionProviders.trimmed(Meta{Name: "DOCKER_HOST", Doc: `the docker daemon the docker provider uses, resolved
once at startup; anything but a unix:// socket or an
absolute socket path (tcp://, ssh://) is refused: the
broker's socket and teardown need a local daemon`})
)

// agentsandbox settings.
var (
	AgentsandboxAPIServer = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_API_SERVER", Default: "https://kubernetes.default.svc", Doc: `the API server (default https://kubernetes.default.svc)`})
	AgentsandboxCAFile    = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_CA_FILE", Default: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", Doc: `its CA and a bearer token file, read at every request
(default: the pod's service account files under
/var/run/secrets/kubernetes.io/serviceaccount)`})
	AgentsandboxTokenFile     = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_TOKEN_FILE", Default: "/var/run/secrets/kubernetes.io/serviceaccount/token", DocWith: "SANDBOX_AGENTSANDBOX_CA_FILE"})
	AgentsandboxNamespace     = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_NAMESPACE", Doc: `the namespace of the pool, its template and every claim`})
	AgentsandboxWarmPool      = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_WARM_POOL", Doc: `the SandboxWarmPool each run claims from`})
	AgentsandboxRuntimeClass  = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_RUNTIME_CLASS", Doc: `the RuntimeClass the template's pods must name`})
	AgentsandboxRunscHandlers = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS", Doc: `a comma list of further handler names this operator
declares as gVisor (a containerd runtime of its own for
the runsc shim, such as one with a debug log). Each is
the kernel tier only, held to gVisor's boot line by the
smoke test and in every pod exactly as runsc is, so a
name that maps to another runtime is refused before
code runs. Each must be a DNS label; an empty entry, a
repeat, or a handler named above fails startup.
Hardened mode accepts it`})
	AgentsandboxImage = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_IMAGE", Doc: `the image the template's one container must run, as the
template writes it (@sha256: when
SANDBOX_REQUIRE_PINNED_IMAGES=1)`})
	AgentsandboxSandboxdTokenFile = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE", Doc: `a file holding the token sandboxd checks; the template
starts sandboxd with --auth-token-sha256 of it.
SANDBOX_MEMORY_MB and SANDBOX_CPUS must equal the
template's limits (default 256 MiB and 1 CPU);
SANDBOX_DISK_MB, when set, bounds the sum of its volumes'
size limits; SANDBOX_PIDS fails startup, because the
kubelet sets the process limit`})
	AgentsandboxSandboxdCAFile = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_SANDBOXD_CA_FILE", Doc: `the PEM certificate authority sandboxd's TLS
certificate must chain to, the deployment's own (the
system roots are never used); required. Each pod's
TLS terminator serves the certificate from the
Secret mounted at /etc/plimsoll/sandboxd-tls (mode
0400), in front of sandboxd on loopback, and nothing
is sent to a pod that does not prove it`})
	AgentsandboxSandboxdServerName = sectionAgentsandbox.text(Meta{Name: "SANDBOX_AGENTSANDBOX_SANDBOXD_SERVER_NAME", Doc: `the DNS name that certificate must carry (default
sandboxd.plimsoll.invalid)`})
	AgentsandboxEncryptedPodNetwork = sectionAgentsandbox.bool(Meta{Name: "SANDBOX_AGENTSANDBOX_ENCRYPTED_POD_NETWORK", Doc: `=1 states that the pod network between plimsolld and
the sandbox pods is authenticated and encrypted (a CNI
with WireGuard or IPsec, or a mesh with mutual TLS).
Every pod serves the same TLS certificate, so the
channel proves the peer is a plimsoll sandbox pod, not
which one; hardened mode requires the statement until
each pod has a key of its own`})
)

// lambdamicrovm settings.
var (
	LambdamicrovmAPIURL = sectionLambdamicrovm.trimmed(Meta{Name: "SANDBOX_LAMBDAMICROVM_API_URL", Doc: `the control plane's https URL (AWS documents none: required)`})
	AWSRegion           = sectionLambdamicrovm.trimmed(Meta{Name: "AWS_REGION", Doc: `the region`})
	AWSAccessKeyID      = sectionLambdamicrovm.trimmed(Meta{Name: "AWS_ACCESS_KEY_ID", Doc: `the credentials that sign control plane calls (environment
only; prefer short-lived)`})
	AWSSecretAccessKey           = sectionLambdamicrovm.trimmed(Meta{Name: "AWS_SECRET_ACCESS_KEY", DocWith: "AWS_ACCESS_KEY_ID"})
	AWSSessionToken              = sectionLambdamicrovm.trimmed(Meta{Name: "AWS_SESSION_TOKEN", DocWith: "AWS_ACCESS_KEY_ID"})
	LambdamicrovmSigningName     = sectionLambdamicrovm.trimmed(Meta{Name: "SANDBOX_LAMBDAMICROVM_SIGNING_NAME", Doc: `the SigV4 service name (default lambda, an assumption)`})
	LambdamicrovmImage           = sectionLambdamicrovm.trimmed(Meta{Name: "SANDBOX_LAMBDAMICROVM_IMAGE", Doc: `the image ARN and the version every run is held to`})
	LambdamicrovmImageVersion    = sectionLambdamicrovm.trimmed(Meta{Name: "SANDBOX_LAMBDAMICROVM_IMAGE_VERSION", DocWith: "SANDBOX_LAMBDAMICROVM_IMAGE"})
	LambdamicrovmEgressConnector = sectionLambdamicrovm.trimmed(Meta{Name: "SANDBOX_LAMBDAMICROVM_EGRESS_CONNECTOR", Doc: `a customer VPC egress connector ARN with a version number
(the internet connector and an unqualified ARN are
refused; the VPC must have no route out and no DNS)`})
	LambdamicrovmIngressConnector = sectionLambdamicrovm.trimmed(Meta{Name: "SANDBOX_LAMBDAMICROVM_INGRESS_CONNECTOR", Doc: `the ingress connector (default AWS's ALL_INGRESS; the
shell connector is refused)
SANDBOX_MEMORY_MB, SANDBOX_CPUS, SANDBOX_PIDS and
SANDBOX_DISK_MB fail startup: the image sets the size`})
)

// openshell settings.
var (
	OpenshellGatewayURL = sectionOpenshell.text(Meta{Name: "SANDBOX_OPENSHELL_GATEWAY_URL", Doc: `the gateway, https://host:port with no path`})
	OpenshellCAFile     = sectionOpenshell.text(Meta{Name: "SANDBOX_OPENSHELL_CA_FILE", Doc: `PEM CA the gateway's certificate must chain to`})
	OpenshellCertFile   = sectionOpenshell.text(Meta{Name: "SANDBOX_OPENSHELL_CERT_FILE", Doc: `PEM client certificate and key`})
	OpenshellKeyFile    = sectionOpenshell.text(Meta{Name: "SANDBOX_OPENSHELL_KEY_FILE", DocWith: "SANDBOX_OPENSHELL_CERT_FILE"})
	OpenshellImage      = sectionOpenshell.text(Meta{Name: "SANDBOX_OPENSHELL_IMAGE", Doc: `the image every sandbox boots; it must carry node, sh,
/usr/bin/env and the project runner,
/usr/local/libexec/plimsoll-helper (the native
helper of this release), as plimsoll/sandbox does
(@sha256: when SANDBOX_REQUIRE_PINNED_IMAGES=1). openshell
honors SANDBOX_MEMORY_MB and SANDBOX_CPUS (default 256
MiB and 1 CPU, since OpenShell's own default is no
limit). SANDBOX_DISK_MB mounts each run's /tmp, the
only writable directory, as a noexec tmpfs of that
size (never a session's, whose files a suspend would
discard); the gateway must set allow_driver_config =
true. Unset, /tmp is bounded only by the host's disk.
SANDBOX_PIDS fails startup,
because the gateway sets it for all its sandboxes`})
)

// wslc settings.
var (
	WSLCMode = sectionWslc.trimmed(Meta{Name: "SANDBOX_WSLC_MODE", Doc: `per-run (default) or shared.
per-run, tier container (vm with
SANDBOX_WSLC_ACCEPT_VM_TIER=1), always stated with its
qualification (Describe, every run's answer and its
record carry it as isolation_qualification, and the
startup log too): a
Hyper-V VM per run (one WSLC session per run), booted from
a fresh copy of a template disk plimsolld builds at
startup and deleted after the run; the VM wall is
Hyper-V's, and the Windows components around it (network
relay, shares, interop) run with the user's rights. Uses
wslc.exe's undocumented "system session enter",
powershell.exe (System32) and /usr/sbin/mkfs.ext4; about
0.9 GB of Windows memory per live run. Each per-run
plimsolld needs a run folder of its own: it ends only
sessions whose folder is under its run folder, and a
second process on the same folder refuses to start.
shared, chosen by setting it, tier container: every run is
a fresh container in the caller's default WSLC session VM
(one per Windows user and elevation), beside the others,
sharing its kernel and rootful dockerd. Weaker than docker
under runc. One run at a time: the process limit is counted
across the session VM, so a second run waits for its turn,
no longer than its own timeout, and is refused (not
dispatched, capacity) if the wait ends first.`})
	WSLCAcceptVMTier = sectionWslc.bool(Meta{Name: "SANDBOX_WSLC_ACCEPT_VM_TIER", Doc: `per-run only, off by default. Off (unset, 0 or false),
the per-run mode reports the container tier, because
Microsoft states that WSL is not a security sandbox for
running untrusted code: a vm or kernel floor (a
request's minimum_isolation, SANDBOX_MIN_ISOLATION,
placement) refuses it, not dispatched (isolation), and
SANDBOX_MIN_ISOLATION=vm or kernel refuses startup. On
(1 or true) is the operator accepting that statement:
the mode then reports vm, stated with the same
qualification plus that the operator set this. Letter
case and spaces around the value are ignored; any other
value refuses startup. gVisor does not change the tier.
In the shared mode any value refuses startup, 0
included: the setting means nothing there`})
	WSLCMaxSessions = sectionWslc.int(Meta{Name: "SANDBOX_WSLC_MAX_SESSIONS", Doc: `per-run only: the most runs in VMs of their own at once
(default 2, at most 16); a run past it is refused, not
dispatched, and a run waits while an ended one's VM is
still being torn down`})
	WSLCGvisor = sectionWslc.bool(Meta{Name: "SANDBOX_WSLC_GVISOR", Doc: `per-run only, off by default: 1 makes gVisor (runsc, the
systrap platform) the runtime inside every run's VM, an
added wall inside the Hyper-V VM. The tier does not
change (container, or vm with
SANDBOX_WSLC_ACCEPT_VM_TIER=1) and is stated with
gVisor's position added; hardened mode still refuses
the provider. The template carries runsc
(streamed in at startup and checked by SHA-512 inside
the VM). WSLC rewrites the docker settings at every VM
boot, so each run writes them again, reloads dockerd and
reads the default runtime back: a run whose VM does not
read runsc is refused (not dispatched, environment) and
is never started under runc. The smoke test then proves
gVisor from inside (its kernel string) and from the VM's
side (the container's runtime, a runsc process, the
memory limit and the Sentry's own filter). Each result
carries the policy gvisor:proven. Rests on three
behaviors Microsoft does not document: "system session
enter", "system session run" as root in the VM, and
dockerd rereading /etc/docker/daemon.json on SIGHUP.
The VM has no /dev/kvm, so systrap. Refused in the shared
mode`})
	WSLCRunscPath = sectionWslc.text(Meta{Name: "SANDBOX_WSLC_RUNSC_PATH", Doc: `with SANDBOX_WSLC_GVISOR=1: the runsc binary as this
distribution sees it (an absolute path; nothing is
downloaded). Needs SANDBOX_WSLC_RUNSC_SHA512`})
	WSLCRunscSHA512 = sectionWslc.trimmed(Meta{Name: "SANDBOX_WSLC_RUNSC_SHA512", Doc: `with SANDBOX_WSLC_GVISOR=1: the binary's SHA-512, 128
lowercase hex digits (a path without a digest, or a digest
that does not match, refuses startup)`})
	WSLCRunscHelpers = sectionWslc.text(Meta{Name: "SANDBOX_WSLC_RUNSC_HELPERS", Doc: `with SANDBOX_WSLC_GVISOR=1: the files runsc needs from the
gvisor-bin directory beside it, as NAME=SHA512 pairs
separated by commas (default none); each is sent and
checked, and the store must hold exactly this set`})
	WSLCRunRoot = sectionWslc.text(Meta{Name: "SANDBOX_WSLC_RUN_ROOT", Doc: `per-run only: the directory for the template and the run
disks, on a Windows drive as this distribution mounts it
(default the Windows user's %LOCALAPPDATA%\plimsoll-wslc);
only names plimsolld creates there are ever deleted. Every
run boots the template kept there, so startup refuses to
serve unless the root's owner and everyone who can write,
create or delete there (by Windows access list, inherited
rules included) is this Windows user, SYSTEM or
Administrators, or the list cannot be read. Every folder
above it, to the drive's own, is read too and refused when
anyone else could delete, rename or take it over, and so
are the built template's folder and disk file. The
template is not checked again between runs`})
	WSLCPath = sectionWslc.text(Meta{Name: "SANDBOX_WSLC_PATH", Doc: `wslc.exe as this distribution sees it (default
/mnt/c/Program Files/WSL/wslc.exe)`})
	WSLCImage = sectionWslc.text(Meta{Name: "SANDBOX_WSLC_IMAGE", Doc: `the image every run starts: plimsoll's sandbox image or
one built FROM it (required; with
SANDBOX_REQUIRE_PINNED_IMAGES=1, name@sha256:<digest>)`})
	WSLCNproc = sectionWslc.int(Meta{Name: "SANDBOX_WSLC_NPROC", Doc: `--ulimit nproc (default 256): processes of the guest uid
at once in the session VM (shared: one run at a time, so
one run's; per-run: in the run's own VM)
SANDBOX_MEMORY_MB, SANDBOX_CPUS and SANDBOX_DISK_MB size
each container; SANDBOX_PIDS fails startup`})
)

// WithheldKnown settings.
var (
	WithheldKnownFile = sectionWithheldKnown.trimmed(Meta{Name: "PLIMSOLL_WITHHELD_KNOWN_FILE", Doc: `JSON lists of unreadable image files, keyed by verified
content ID, path, reason and whole size. Create/update:
plimsoll-withheld known-unreadable -set SET -known FILE IMAGE
With a withheld set and docker, any unlisted unreadable
file refuses startup, including with audit-only sets.
Unset means none are known; malformed or missing FILE
refuses startup. Rebuilt images need new lists. Listing
unread bytes acknowledges a gap, not that they are clean.`})
)

// Limits settings.
var (
	MaxConcurrent     = sectionLimits.int(Meta{Name: "SANDBOX_MAX_CONCURRENT", Default: "8", Doc: `global max in-flight runs (default 8)`})
	PerKeyConcurrent  = sectionLimits.int(Meta{Name: "SANDBOX_PER_KEY_CONCURRENT", Doc: `max in-flight runs per caller (default max/2)`})
	RatePerMin        = sectionLimits.int(Meta{Name: "SANDBOX_RATE_PER_MIN", Default: "30", Doc: `per-caller runs per minute (default 30; 0 = disabled)`})
	RateBurst         = sectionLimits.int(Meta{Name: "SANDBOX_RATE_BURST", Doc: `per-caller token-bucket burst (default = rate)`})
	PaidSecondsPerDay = sectionLimits.int(Meta{Name: "SANDBOX_PAID_SECONDS_PER_DAY", Default: "0", Doc: `e2b and dockercloud, which bill by the second: the
daemon's allowance of microVM wall time per UTC day
(default 0: none); each caller's own is its
paid_seconds_per_day in PLIMSOLL_CLIENTS_FILE, both per
daemon. A run reserves its timeout plus the provider's
teardown bound (33 s) and is charged what it took. Kept
in memory: a restart forgets the day's spend`})
	TotalMemoryMB = sectionLimits.int(Meta{Name: "SANDBOX_TOTAL_MEMORY_MB", Default: "0", Doc: `aggregate host memory budget for runners; clamps
max-concurrent to total/per-run, less one run for
each SANDBOX_SESSION_POOL container, so concurrent
runs cannot oversubscribe the host (ignored for e2b
and dockercloud, whose runners live off-host)`})
	MemoryMB    = sectionLimits.count(Meta{Name: "SANDBOX_MEMORY_MB", Doc: `per-run resource envelope applied to the provider`})
	CPUs        = sectionLimits.amount(Meta{Name: "SANDBOX_CPUS", DocWith: "SANDBOX_MEMORY_MB"})
	Pids        = sectionLimits.count(Meta{Name: "SANDBOX_PIDS", DocWith: "SANDBOX_MEMORY_MB"})
	DiskMB      = sectionLimits.count(Meta{Name: "SANDBOX_DISK_MB", DocWith: "SANDBOX_MEMORY_MB"})
	MaxSessions = sectionLimits.int(Meta{Name: "SANDBOX_MAX_SESSIONS", Default: "0", Doc: `open sessions at once (default 0: sessions off). A
session keeps one sandbox for many calls: files
persist, processes do not, except the interpreters
it keeps for cells. Needs a provider with
sessions (docker with a project image, openshell
or e2b); startup fails otherwise, and when one real
session opened at startup does not keep what a
session promises. A running session
holds one concurrency slot; a suspended one holds
none, except on docker, where a suspend is a pause
that keeps the memory.`})
	MaxSessionsPerCaller = sectionLimits.int(Meta{Name: "SANDBOX_MAX_SESSIONS_PER_CALLER", Default: "0", Doc: `open sessions one caller may hold, suspended ones
included (default 0: no cap beyond
SANDBOX_MAX_SESSIONS; required in hardened mode
with sessions on)`})
	MaxSessionsPerOwner = sectionLimits.int(Meta{Name: "SANDBOX_MAX_SESSIONS_PER_OWNER", Default: "0", Doc: `open sessions one owner of a caller may hold (the
end user an OpenSession names; default 0: no
cap). At the cap an open closes that owner's least
recently used session with no call in progress;
its later calls are refused as replaced. Refused,
not dispatched, when every one is running a call.`})
	SessionPool = sectionLimits.int(Meta{Name: "SANDBOX_SESSION_POOL", Default: "0", Doc: `sandboxes kept ready for sessions (default 0: none;
at most SANDBOX_MAX_SESSIONS; docker and openshell;
startup fails for another provider). Each is
never used, has its interpreters already running,
goes to one session (or to one Run cell that asks
for one, prefer_warm) and is removed when it ends,
never reused; an idle one is replaced after 30m.
Each counts as one run against
SANDBOX_TOTAL_MEMORY_MB.`})
	SessionLifetime = sectionLimits.duration(Meta{Name: "SANDBOX_SESSION_LIFETIME", Default: "30m", Doc: `a session's absolute lifetime (default 30m, at most
12h); a request may ask for less`})
	SessionIdle = sectionLimits.duration(Meta{Name: "SANDBOX_SESSION_IDLE", Default: "5m", Doc: `suspend a session idle this long (default 5m; 0 =
never, refused with a provider billed by the
second; otherwise 1s to 12h); its files are kept and
the next call resumes it; a request may ask for less,
not under 1s. A session no request has named by its
first idle timeout (5m if it never suspends) is
closed instead (end unclaimed). On a provider billed by the second a
session's running time, open to suspend and resume
to suspend, draws on the paid allowances`})
	SessionDiskMB = sectionLimits.int(Meta{Name: "SANDBOX_SESSION_DISK_MB", Default: "1024", Doc: `end a session whose files exceed this after a call
(default 1024; 0 = no bound; at most 1048576);
measured after each call, not enforced during it`})
)
