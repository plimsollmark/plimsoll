// Command plimsolld serves the plimsoll SandboxService over Connect (h2c, so
// Connect, gRPC, and gRPC-Web clients all work). The execution provider is chosen
// by SANDBOX_PROVIDER (default: disabled; code execution is opt-in).
//
// Authenticated callers need the code:run scope. A real provider refuses to start
// without PLIMSOLL_TOKEN or PLIMSOLL_CLIENTS_FILE unless the operator explicitly
// acknowledges open development mode with PLIMSOLL_INSECURE=1.
//
// The daemon takes no arguments; every setting is an environment variable.
// `plimsolld -h` prints the full reference. That text is helpText (providers.go),
// built from the usage constants in this file, and a test requires every variable
// the package reads to appear in it, so the binary's own help cannot fall behind
// the code.
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/internal/clientconfig"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/internal/unreadbody"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// usageHead, usageProviders and usageLimits are what -h prints, around the two parts
// helpText generates: the SANDBOX_PROVIDER line and the daemon-built providers'
// sections. Together they are the daemon's configuration reference; keep every
// variable the package reads listed (TestUsageNamesEveryVariable enforces it).
const usageHead = `plimsolld serves the plimsoll SandboxService over Connect: cleartext
HTTP/2 ("h2c") and HTTP/1.1, or HTTP/1.1 and HTTP/2 over TLS when PLIMSOLL_TLS_CERT
is set.

Usage: plimsolld [-h]

The daemon takes no arguments. Configuration is by environment variable:

  PLIMSOLL_ADDR              listen address (default :8746, every interface;
                             set 127.0.0.1:8746 for a loopback-only daemon)
  PLIMSOLL_METRICS_ADDR      listen address for GET /metrics, a listener of its
                             own (default 127.0.0.1:9464, this host only; the
                             host and port are OpenTelemetry's Prometheus exporter
                             defaults); off disables it. It has no authentication
                             and its labels name grant profiles and route
                             templates, so bind an address other hosts can reach
                             only behind a firewall rule that admits just the
                             scraper. It serves TLS when the daemon does
  PLIMSOLL_GUARD_ADDR        listen address for the egress guard, a listener of
                             its own that serves the guard path and nothing else;
                             required when E2B_GUARD_URL or
                             SANDBOX_DOCKERCLOUD_GUARD_URL is set, refused
                             otherwise. Point the public guard URL at it. A guest's
                             one permitted destination is the guard, so it never
                             shares PLIMSOLL_ADDR, where the guest would also reach
                             the RPC procedures and the health endpoints. It
                             serves TLS when the daemon does
  PLIMSOLL_LOG_FORMAT       json (default) or text; the audit stream is a
                             machine-read record and prospector-report consumes
                             newline-delimited JSON. Use text only for eyeballing
                             a local run.
  PLIMSOLL_CLIENTS_FILE      JSON caller registry for multi-client auth (each
                             caller its own principal; managed by plimsoll-clients);
                             takes precedence over PLIMSOLL_TOKEN
  PLIMSOLL_TOKEN             one shared bearer granting code:run to every caller
                             (at least 32 characters)
  PLIMSOLL_INSECURE          =1 explicitly permits a real provider with auth
                             disabled (development only; never expose that listener)
  PLIMSOLL_TLS_CERT / PLIMSOLL_TLS_KEY
                             PEM certificate and key; when set the daemon serves
                             TLS (HTTP/1.1 + HTTP/2 via ALPN) instead of cleartext
  PLIMSOLL_HARDENED          =1 enforces the production policy at startup: vm or
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
                             caller of e2b or dockercloud. Every rule but isolation
                             is checked before the billed smoke test. Any violation
                             refuses to serve.
  PLIMSOLL_GRANTS_FILE       JSON file of named host-API capability profiles a
                             caller may select via grant_profile

`

const usageProviders = `  SANDBOX_MIN_ISOLATION      refuse to start unless the provider meets this tier
                             (vm | kernel | container | process); unset = no floor
  SANDBOX_DOCKER_IMAGE       snippet image (default node:22-alpine)
  SANDBOX_DOCKER_PROJECT_IMAGE
                             project toolchain image (default plimsoll/sandbox:latest)
  SANDBOX_DOCKER_MODULE_IMAGE
                             simulation worker image for module runs (built by
                             make docker-images as plimsoll/sandbox-sim:latest);
                             unset = module runs unsupported
  SANDBOX_DOCKER_RUNTIME     runsc (gVisor) for the docker provider; "" = runc
  SANDBOX_DOCKER_SECCOMP     seccomp profile path (or "unconfined") for docker; ""
                             keeps docker's built-in default. Set it to the shipped
                             audited profile (docker/seccomp.json) to also deny
                             ptrace, io_uring, keyctl and similar; see docs/seccomp.md
  SANDBOX_GUEST_UID          the uid (and gid) docker runs every guest as, default
                             61000, which no account uses; 1 to 65532, with
                             neither it nor it + 1 in a band systemd assigns
                             itself (60001-60513, 60578-60705, 61184-65519).
                             Preflight refuses one this host's /etc/passwd or
                             /etc/group has (it or one more, the session identity
                             check's)
  SANDBOX_REQUIRE_PINNED_IMAGES
                             =1 to refuse mutable image tags (require @sha256:)
  E2B_API_KEY / E2B_TEMPLATE E2B credentials and toolchain template
  E2B_GUARD_URL              absolute HTTPS egress-guard URL on port 443 whose host
                             is a name, never an IP address (E2B's network rule
                             refuses one); enables E2B grants (allowlist plus beta
                             header transform). It must reach this daemon's
                             PLIMSOLL_GUARD_ADDR
  E2B_SESSION_GRANTS         how a granted session call reaches the guard: unset
                             refuses it; session = one credential for the
                             session's life; call = a fresh one put on per call;
                             both passed against the live service on 2026-10-08.
                             Needs E2B_GUARD_URL
  DOCKER_SBX_TOKEN           Docker Cloud Sandboxes personal access token for
                             dockercloud (read from the environment only); it is
                             exchanged for a short-lived bearer, never sent to
                             the sandbox API itself
  DOCKER_SBX_USERNAME        the Docker account the token belongs to
  SANDBOX_DOCKERCLOUD_AUTH_URL
                             token exchange endpoint; default
                             https://hub.docker.com/v2/auth/token
  SANDBOX_DOCKERCLOUD_GUARD_URL
                             absolute HTTPS egress-guard endpoint on 443; enables
                             dockercloud grants (connect only). A grant run's sandbox may reach
                             only this host; the guest holds a per-run, guard-only
                             credential (Docker's proxy cannot inject one); served
                             on PLIMSOLL_GUARD_ADDR
  SANDBOX_DOCKERCLOUD_POLICY_URL
                             per-sandbox network-policy REST base; default
                             https://api.sandboxes-cloud.docker.com/v1. Not in
                             Docker's published contract (the sbx CLI's call);
                             every grant run verifies the result through it
  SANDBOX_DOCKERCLOUD_API    which Docker API dockercloud speaks: connect (the
                             default; the pre-launch contract, the only one with
                             grants and image identity) or rest (the API Docker
                             documents, kept as a backup until it covers those);
                             both passed the live suite on 2026-10-04. rest states no image
                             identity (it reports no booted digest, so hardened
                             mode needs connect), caps a run at 270 s (an exec
                             ends with its 300 s endpoint credential) and cannot
                             verify grants, so it fails startup when
                             SANDBOX_DOCKERCLOUD_GUARD_URL is set
  SANDBOX_DOCKERCLOUD_API_URL
                             Docker Cloud Sandboxes management endpoint. connect:
                             required, no default
                             (https://sandboxes.connect.docker.com/sbx answered on
                             2026-10-04); rest: default
                             https://connect.docker.com/sandboxes, the documented
                             base URL
  SANDBOX_DOCKERCLOUD_IMAGE  raw OCI image each dockercloud sandbox boots (the
                             toolchain image; must be @sha256: when
                             SANDBOX_REQUIRE_PINNED_IMAGES=1, and then the
                             linux/amd64 manifest digest). dockercloud honors
                             SANDBOX_MEMORY_MB and whole SANDBOX_CPUS, and requests
                             the Micro size (1 CPU, 2 GiB) when they are unset;
                             SANDBOX_PIDS and SANDBOX_DISK_MB fail startup. The
                             account's cloud network policy must default to
                             deny-all (sbx --cloud policy init deny-all); every run
                             verifies it. Verified live on 2026-09-24.
  SANDBOX_DOCKERCLOUD_STORE_IMAGE
                             instead of SANDBOX_DOCKERCLOUD_IMAGE: an image in the
                             account's own Cloud Sandboxes image store, as
                             <image id>@sha256:<digest>. Booted by ID with no
                             registry pull, so it can stay private to the account;
                             every sandbox's booted digest must equal the one given.
                             Its size and start command are the image's own (create
                             it with the start command tail -f /dev/null), so
                             SANDBOX_CPUS and SANDBOX_MEMORY_MB only cap them.
                             connect only. Verified live on 2026-10-05.
`

const usageLimits = `
  SANDBOX_MAX_CONCURRENT     global max in-flight runs (default 8)
  SANDBOX_PER_KEY_CONCURRENT max in-flight runs per caller (default max/2)
  SANDBOX_RATE_PER_MIN       per-caller runs per minute (default 30; 0 = disabled)
  SANDBOX_RATE_BURST         per-caller token-bucket burst (default = rate)
  SANDBOX_PAID_SECONDS_PER_DAY
                             e2b and dockercloud, which bill by the second: the
                             daemon's allowance of microVM wall time per UTC day
                             (default 0: none); each caller's own is its
                             paid_seconds_per_day in PLIMSOLL_CLIENTS_FILE, both per
                             daemon. A run reserves its timeout plus the provider's
                             teardown bound (33 s) and is charged what it took. Kept
                             in memory: a restart forgets the day's spend
  SANDBOX_TOTAL_MEMORY_MB    aggregate host memory budget for runners; clamps
                             max-concurrent to total/per-run, less one run for
                             each SANDBOX_SESSION_POOL container, so concurrent
                             runs cannot oversubscribe the host (ignored for e2b
                             and dockercloud, whose runners live off-host)
  SANDBOX_MEMORY_MB / SANDBOX_CPUS / SANDBOX_PIDS / SANDBOX_DISK_MB
                             per-run resource envelope applied to the provider
  SANDBOX_MAX_SESSIONS       open sessions at once (default 0: sessions off). A
                             session keeps one sandbox for many calls: files
                             persist, processes do not, except the interpreters
                             it keeps for cells. Needs a provider with
                             sessions (docker with a project image, openshell
                             or e2b); startup fails otherwise, and when one real
                             session opened at startup does not keep what a
                             session promises. A running session
                             holds one concurrency slot; a suspended one holds
                             none, except on docker, where a suspend is a pause
                             that keeps the memory.
  SANDBOX_MAX_SESSIONS_PER_CALLER
                             open sessions one caller may hold, suspended ones
                             included (default 0: no cap beyond
                             SANDBOX_MAX_SESSIONS; required in hardened mode
                             with sessions on)
  SANDBOX_MAX_SESSIONS_PER_OWNER
                             open sessions one owner of a caller may hold (the
                             end user an OpenSession names; default 0: no
                             cap). At the cap an open closes that owner's least
                             recently used session with no call in progress;
                             its later calls are refused as replaced. Refused,
                             not dispatched, when every one is running a call.
  SANDBOX_SESSION_POOL       sandboxes kept ready for sessions (default 0: none;
                             at most SANDBOX_MAX_SESSIONS; docker only). Each is
                             never used, has its interpreters already running,
                             goes to one session and is removed when it closes,
                             never reused; an idle one is replaced after 30m.
                             Each counts as one run against
                             SANDBOX_TOTAL_MEMORY_MB.
  SANDBOX_SESSION_LIFETIME   a session's absolute lifetime (default 30m, at most
                             12h); a request may ask for less
  SANDBOX_SESSION_IDLE       suspend a session idle this long (default 5m; 0 =
                             never, refused with a provider billed by the
                             second; otherwise 1s to 12h); its files are kept and
                             the next call resumes it; a request may ask for less,
                             not under 1s. A session no request has named by its
                             first idle timeout (5m if it never suspends) is
                             closed instead (end unclaimed). On a provider billed by the second a
                             session's running time, open to suspend and resume
                             to suspend, draws on the paid allowances
  SANDBOX_SESSION_DISK_MB    end a session whose files exceed this after a call
                             (default 1024; 0 = no bound; at most 1048576);
                             measured after each call, not enforced during it

Endpoints outside auth: GET /healthz (liveness) and GET /readyz (provider
readiness) on PLIMSOLL_ADDR, GET /metrics (Prometheus text: run, shed-load,
host-call and advice counters) on PLIMSOLL_METRICS_ADDR only, and the egress
guard (each call authenticated by its run's guard credential) on
PLIMSOLL_GUARD_ADDR only.
`

// parseArgs accepts only a help request. Any other argument is refused rather
// than ignored: a daemon that silently starts despite a misspelt flag leaves its
// operator believing a setting is in force when it is not.
func parseArgs(args []string) (help bool, err error) {
	switch {
	case len(args) == 0:
		return false, nil
	case len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help"):
		return true, nil
	default:
		return false, fmt.Errorf("unexpected argument %q: plimsolld takes no arguments; configuration is by environment variable", args[0])
	}
}

func main() {
	if help, err := parseArgs(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "plimsolld: %v\n\n%s", err, helpText())
		os.Exit(2)
	} else if help {
		fmt.Print(helpText())
		return
	}
	configureLogging(os.Getenv)
	for _, name := range unknownVariables(os.Environ(), helpText()) {
		// A misspelling, or a setting a newer plimsolld has: either way this daemon runs
		// without it, which an operator relying on it (a per-owner session cap, say)
		// would otherwise learn only from its effects.
		slog.Warn("unknown variable ignored: this plimsolld has no such setting", "name", name)
	}

	addr := getenv("PLIMSOLL_ADDR", ":8746")

	provider, err := buildProvider(os.Getenv)
	if err != nil {
		slog.Error("invalid sandbox configuration", "error", err)
		os.Exit(1)
	}
	sb, res := provider.Sandbox, provider.Resources

	// The egress guard's listener is settled before anything below can spend: a
	// missing address fails here, not after the smoke test has created a billed
	// microVM.
	guard, guardPath := egressGuardOf(sb)
	guardAddr, err := guardAddrWith(os.Getenv, guardPath != "")
	if err != nil {
		slog.Error("invalid egress guard listener", "error", err)
		os.Exit(1)
	}

	// A provider billed by the second: what is wrong with its allowances is refused
	// before the smoke test below creates a billed microVM.
	metered := sandbox.IsMetered(sb)
	paidPerDay, err := loadPaidConfig(os.Getenv, metered)
	if err != nil {
		slog.Error("invalid paid-provider configuration", "error", err)
		os.Exit(1)
	}

	// Everything local is settled before anything below can spend: the smoke test
	// creates a billed microVM on a paid provider, so a daemon restarting over a bad
	// setting would otherwise pay for one on every restart. Settings, the caller
	// registry, TLS, an early pass of the hardened policy and every listener's bind
	// come first; the checks that need the smoke test's evidence come after it.
	//
	// Fail closed if the operator required a minimum isolation tier the selected
	// provider cannot meet (e.g. SANDBOX_MIN_ISOLATION=vm but SANDBOX_PROVIDER=wasm):
	// the whole point of the service is bounding hostile code, so a silent downgrade
	// to a weaker boundary must be a startup error, not a surprise at runtime.
	want, requireMinimum, err := minimumIsolationWith(os.Getenv)
	if err != nil {
		slog.Error("SANDBOX_MIN_ISOLATION is not a valid tier", "error", err, "want", "vm|kernel|container|process")
		os.Exit(1)
	}

	// Resolve the effective limiter envelope (env parsing + aggregate-memory clamp +
	// validation) in one typed, unit-tested function so main() only wires the result.
	var poolSize int
	sc, err := loadSessionConfig(os.Getenv)
	if err == nil {
		poolSize, err = loadSessionPool(os.Getenv, sc)
	}
	if err != nil {
		slog.Error("invalid session configuration", "error", err)
		os.Exit(1)
	}
	// The session pool is charged against the memory budget, so it is read first.
	lc, err := loadLimiterConfig(os.Getenv, sb.Name(), res.MemoryMB, poolSize)
	if err != nil {
		slog.Error("invalid limiter configuration", "error", err)
		os.Exit(1)
	}
	maxConcurrent, perKey, ratePerMin, burst := lc.MaxConcurrent, lc.PerKey, lc.RatePerMin, lc.Burst
	// Session settings the provider cannot honor fail here too; the pool's start and
	// the session smoke test, which create sandboxes, come after the run smoke test.
	if sc.MaxSessions > 0 {
		sp, ok := sb.(sandbox.SessionProvider)
		if !ok || !sp.SupportsSessions() {
			slog.Error("SANDBOX_MAX_SESSIONS is set but the provider keeps no sessions", "provider", sb.Name())
			os.Exit(1)
		}
		// A session's sandbox bills for every second it is not suspended, which the paid
		// allowances charge (internal/rpc/spend.go); one that never suspended would bill
		// for its whole lifetime.
		if metered && sc.IdleTimeout == 0 {
			slog.Error("SANDBOX_SESSION_IDLE=0 (never suspend) with a provider billed by the second: an idle session would bill until its lifetime ends; set an idle timeout", "provider", sb.Name())
			os.Exit(1)
		}
		// The admission wrapper always has the method; a provider without a pool
		// answers ErrUnsupported through it.
		if _, ok := sb.(sandbox.SessionPool); poolSize > 0 && !ok {
			slog.Error("SANDBOX_SESSION_POOL is set but the provider keeps no session pool", "provider", sb.Name())
			os.Exit(1)
		}
	}

	gr, err := grants.LoadFromEnv()
	if err != nil {
		slog.Error("failed to load host-API grant profiles", "error", err)
		os.Exit(1)
	}
	if gr.Len() > 0 {
		gc, ok := sb.(sandbox.GrantCapable)
		if !ok || (!gc.SupportsJavaScriptGrants() && !gc.SupportsProjectGrants()) {
			slog.Error("grant profiles are configured but the selected provider supports no credential-safe grant path",
				"provider", sb.Name(), "profiles", gr.Len())
			os.Exit(1)
		}
		slog.Info("host-API grant profiles loaded", "count", gr.Len())
		for _, name := range gr.OpenToEveryCaller() {
			slog.Warn("grant profile is open to every authenticated caller (allowed_callers is \"*\")", "profile", name)
		}
	}

	var verifier rpc.TokenVerifier
	multiClientAuth := false
	var uncapped []string // callers without a daily allowance on a metered provider
	switch {
	case strings.TrimSpace(os.Getenv("PLIMSOLL_CLIENTS_FILE")) != "":
		// Multi-client: each caller authenticates as its own principal, so the
		// per-session token's `sub` is actually per client.
		fv, err := rpc.LoadClientsFromEnv()
		if err != nil {
			slog.Error("failed to load PLIMSOLL_CLIENTS_FILE", "error", err)
			os.Exit(1)
		}
		if fv == nil {
			slog.Error("PLIMSOLL_CLIENTS_FILE was set but no verifier was loaded")
			os.Exit(1)
		}
		verifier = fv
		multiClientAuth = true
		uncapped = fv.Uncapped()
		slog.Info("multi-client auth enabled", "clients", fv.Len())
	case os.Getenv("PLIMSOLL_TOKEN") != "":
		if err := clientconfig.CheckToken(os.Getenv("PLIMSOLL_TOKEN")); err != nil {
			slog.Error("PLIMSOLL_TOKEN is too short; refusing to serve", "error", err)
			os.Exit(1)
		}
		verifier = staticVerifier{token: os.Getenv("PLIMSOLL_TOKEN"), scopes: []string{rpc.ScopeCodeRun}}
	default:
		// Open dev mode. Harmless when the provider is Disabled (no code runs), but
		// serving a REAL provider with no auth means any unauthenticated caller can
		// run hostile code — the worst fail-open for this service. Refuse to start in
		// that combination unless the operator explicitly opts in, so a lost/forgotten
		// token can't silently become an open code-execution endpoint.
		if sb.Name() != "disabled" && os.Getenv("PLIMSOLL_INSECURE") != "1" {
			slog.Error("refusing to start: a real sandbox provider is enabled but PLIMSOLL_TOKEN is unset (auth DISABLED). Set PLIMSOLL_TOKEN (or PLIMSOLL_CLIENTS_FILE) to require auth, or set PLIMSOLL_INSECURE=1 to acknowledge open code execution",
				"provider", sb.Name())
			os.Exit(1)
		}
		slog.Warn("PLIMSOLL_TOKEN unset: auth DISABLED (open dev mode) — every caller may run code", "provider", sb.Name())
	}

	// TLS is resolved before the hardened policy so the policy can check the
	// transport that will actually serve, and a bad keypair fails at startup
	// rather than on the first handshake.
	tlsConf, err := tlsConfigFromEnv(os.Getenv)
	if err != nil {
		slog.Error("invalid TLS configuration", "error", err)
		os.Exit(1)
	}
	metricsAddr, err := metricsAddrWith(os.Getenv)
	if err != nil {
		slog.Error("invalid metrics listener", "error", err)
		os.Exit(1)
	}

	// Hardened mode: the deploy-time policy for serving hostile code in
	// production. Everything it checks is resolved evidence (the loaded verifier,
	// the effective limiter, the actual transport, and, after the smoke test, the
	// provider's proven isolation), so a pass means the properties are in force, not
	// merely configured. It runs twice: every rule but isolation now, before anything
	// spends, and all of them once the smoke test has proven the tier.
	hardened, err := sandbox.BoolFromEnv(os.Getenv, "PLIMSOLL_HARDENED")
	if err != nil {
		slog.Error("invalid PLIMSOLL_HARDENED", "error", err)
		os.Exit(1)
	}
	facts := hardenedFacts{
		Provider:        sb.Name(),
		Isolation:       sb.IsolationClass(),
		MultiClientAuth: multiClientAuth,
		TLS:             tlsConf != nil,
		Addr:            addr,
		MetricsAddr:     metricsAddr,
		GuardAddr:       guardAddr,
		MaxConcurrent:   maxConcurrent,
		RatePerMin:      ratePerMin,
		Burst:           burst,
		PerCaller:       perKey,
		Sessions:        sc,
		Metered:         metered,
		Uncapped:        uncapped,
	}
	// The isolation rule waits for the smoke test's evidence; every other rule is
	// checked now, so a violation costs nothing.
	facts.IsolationPending = true
	if hardened {
		if err := enforceHardenedPolicy(os.Getenv, facts); err != nil {
			slog.Error("hardened-mode policy violation; refusing to serve before the smoke test", "error", err)
			os.Exit(1)
		}
	}

	// Bind every listener now: an address that cannot be bound (taken, out of range,
	// the same as another listener's) fails before anything spends, and the log can
	// name the bound address (":0", an ephemeral port, is how the tests run the
	// daemon). Nothing is served until startup has finished; a connection made in
	// the meantime waits in the accept queue.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("cannot listen", "addr", addr, "error", err)
		os.Exit(1)
	}
	rpcConns, guardConns := connectionCaps(guardAddr != "")
	ln = limitConnections(ln, rpcConns)
	var guardLn net.Listener
	boundGuard := "none"
	if guardAddr != "" {
		guardLn, err = net.Listen("tcp", guardAddr)
		if err != nil {
			slog.Error("cannot listen for the egress guard; set PLIMSOLL_GUARD_ADDR to a free address", "addr", guardAddr, "error", err)
			os.Exit(1)
		}
		guardLn = limitConnections(guardLn, guardConns)
		boundGuard = guardLn.Addr().String()
	}
	var metricsLn net.Listener
	boundMetrics := "off"
	if metricsAddr != "" {
		metricsLn, err = net.Listen("tcp", metricsAddr)
		if err != nil {
			slog.Error("cannot listen for metrics; set PLIMSOLL_METRICS_ADDR to a free address, or off", "addr", metricsAddr, "error", err)
			os.Exit(1)
		}
		metricsLn = limitConnections(metricsLn, metricsMaxConnections)
		boundMetrics = metricsLn.Addr().String()
		if !loopbackAddr(boundMetrics) {
			slog.Warn("the metrics listener is reachable from other hosts and has no authentication; its labels name grant profiles and route templates, so admit only the scraper",
				"metrics_addr", boundMetrics)
		}
	}

	// Verify dependencies (Preflight) and prove the exact configured execution
	// stack enforces its promised bounds (SmokeTest, throwaway sandboxes) before
	// serving. The Docker provider reports the kernel tier only after Preflight has
	// verified that the pinned local daemon actually registers runsc under a runsc
	// executable path. Startup-only: smoke starts real sandboxes, so it must never
	// sit on the unauthenticated /readyz poll path.
	readyCtx, cancelReady := context.WithTimeout(context.Background(), 2*time.Minute)
	if err := provider.EnsureReady(readyCtx); err != nil {
		cancelReady()
		slog.Error("sandbox provider is not ready; refusing to serve", "provider", sb.Name(), "error", err)
		os.Exit(1)
	}
	cancelReady()
	slog.Info("sandbox provider ready", "provider", sb.Name())
	// The tier startup proved: the background loop below re-checks whenever the
	// current evidence falls below it.
	proven := sb.IsolationClass()

	// SANDBOX_MIN_ISOLATION, parsed before the smoke test, against what it proved.
	if requireMinimum {
		if !sb.IsolationClass().Meets(want) {
			slog.Error("provider does not meet the required isolation tier",
				"provider", sb.Name(), "provider_isolation", sb.IsolationClass().String(), "required", want.String())
			os.Exit(1)
		}
	}

	// The single most security-relevant fact is the boundary strength; make a weak
	// default loud. docker under runc is namespaces only, NOT a hostile-code boundary.
	if sb.Name() == "docker" && sb.IsolationClass() == sandbox.IsolationContainer {
		slog.Warn("docker provider is running under runc (shared host kernel) — this is NOT a hostile-code boundary; set SANDBOX_DOCKER_RUNTIME=runsc (gVisor) for a real boundary")
	}

	svc := rpc.NewSandboxService(sb)
	svc.Resources = res
	svc.Limiter = rpc.NewCodeLimiter(maxConcurrent, perKey, ratePerMin, burst)
	// A provider billed by the second draws each run on the caller's daily allowance
	// (paid_seconds_per_day in PLIMSOLL_CLIENTS_FILE) and on the daemon's.
	svc.Spend = rpc.NewSpendCap(paidPerDay)
	switch {
	case metered && paidPerDay == 0:
		slog.Warn("paid provider with no daemon-wide allowance (SANDBOX_PAID_SECONDS_PER_DAY): only the callers' own paid_seconds_per_day bound what runs cost")
	case metered:
		slog.Info("paid provider: runs draw on daily allowances in seconds, per daemon, UTC days, kept in memory (a restart forgets the day's spend)",
			"daemon_seconds_per_day", paidPerDay)
	}

	if sc.MaxSessions > 0 {
		sp := sb.(sandbox.SessionProvider) // checked before the smoke test
		// The pool starts first, so the session the smoke test opens is a claimed
		// member: the warm path is the one startup proves.
		if poolSize > 0 {
			poolCtx, cancelPool := context.WithTimeout(context.Background(), 3*time.Minute)
			err := sb.(sandbox.SessionPool).StartSessionPool(poolCtx, poolSize, sc.Lifetime)
			cancelPool()
			if err != nil {
				slog.Error("the session pool could not start; refusing to serve", "provider", sb.Name(), "error", err)
				os.Exit(1)
			}
		}
		// What only a session does (the sweep between calls, a suspend and its resume,
		// an interpreter kept across calls, a close) is proven here, by one real
		// session, as EnsureReady proved the provider's runs. Startup-only, like it.
		smokeCtx, cancelSmoke := context.WithTimeout(context.Background(), 2*time.Minute)
		err := sandbox.SessionSmokeTest(smokeCtx, sp, sandbox.SessionOptions{Lifetime: min(sc.Lifetime, 5*time.Minute), DiskBytes: sc.DiskBytes})
		cancelSmoke()
		if err != nil {
			slog.Error("sessions are not ready; refusing to serve", "provider", sb.Name(), "error", err)
			os.Exit(1)
		}
		slog.Info("sessions enabled", "max_sessions", sc.MaxSessions, "max_sessions_per_caller", sc.MaxPerCaller, "max_sessions_per_owner", sc.MaxPerOwner, "pool", poolSize,
			"lifetime", sc.Lifetime.String(), "idle", sc.IdleTimeout.String(), "disk_mb", sc.DiskBytes>>20)
		if sb.Name() == "docker" && sc.MaxSessions >= maxConcurrent {
			slog.Warn("SANDBOX_MAX_SESSIONS is at least SANDBOX_MAX_CONCURRENT: a paused docker session keeps its slot, so open sessions can leave no slot for single runs",
				"max_sessions", sc.MaxSessions, "max_concurrent", maxConcurrent)
		}
	}
	svc.Sessions = sc
	svc.Grants = gr

	if hardened {
		facts.Isolation, facts.IsolationPending = sb.IsolationClass(), false
		if err := enforceHardenedPolicy(os.Getenv, facts); err != nil {
			slog.Error("hardened-mode policy violation; refusing to serve", "error", err)
			os.Exit(1)
		}
		slog.Info("hardened mode: production policy verified and enforced")
	}

	srv := newHTTPServer(addr, rpcMux(svc, verifier, maxConcurrent, sb), tlsConf)
	var guardSrv *http.Server
	if guardLn != nil {
		guardSrv = newHTTPServer(guardAddr, guardHandler(guard, guardPath, maxConcurrent), tlsConf)
	}
	var metricsSrv *http.Server
	if metricsLn != nil {
		metricsSrv = newMetricsServer(metricsAddr, metricsHandler(svc), tlsConf)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Once a minute, in the background:
	//   - Reap execution resources that leaked past the per-run lifecycle (e.g. E2B
	//     microVMs whose create response was malformed or whose teardown retries all
	//     failed). The provider guarantees it never destroys a resource another run
	//     may still be using, so the loop is safe alongside in-flight runs.
	//   - Re-check isolation evidence that has lapsed below what startup proved. A
	//     provider whose tier fell (openshell to unknown after a failed gateway check,
	//     docker from kernel to container after a failed refresh) has every request
	//     whose floor is above the current tier refused before the provider is asked,
	//     so without this only a /readyz poll or a run with no floor would ever check
	//     again.
	rec, reconciles := sb.(sandbox.OrphanReconciler)
	pf, preflights := sb.(sandbox.Preflighter)
	if reconciles || preflights {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if c := sb.IsolationClass(); preflights && (c == sandbox.IsolationUnknown || c < proven) {
						pctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						if err := pf.Preflight(pctx); err != nil {
							slog.Warn("isolation evidence is below what startup proved; requests whose minimum isolation is above it are refused",
								"provider", sb.Name(), "isolation", sb.IsolationClass().String(), "proven", proven.String(), "error", err)
						}
						cancel()
					}
					if !reconciles {
						continue
					}
					rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					n, err := rec.ReconcileOrphans(rctx)
					cancel()
					switch {
					case err != nil:
						slog.Warn("orphan reconciliation failed", "provider", sb.Name(), "error", err)
					case n > 0:
						slog.Warn("orphan reconciliation reaped leaked sandboxes", "provider", sb.Name(), "count", n)
					}
				}
			}
		}()
	}

	{
		// Echo the EFFECTIVE (post-clamp) limiter and resource envelope so a
		// fat-fingered env var is visible in the logs rather than silently
		// defaulting. The resource envelope only applies to providers that enforce it
		// (docker/wasm); E2B sizes CPU/RAM/disk at the template level, so advertise
		// that instead of caps that are not in force.
		args := []any{
			"addr", ln.Addr().String(),
			"provider", sb.Name(),
			"isolation", sb.IsolationClass().String(),
			"auth", verifier != nil,
			"max_concurrent", maxConcurrent,
			"per_key_concurrent", perKey,
			"rate_per_min", ratePerMin,
			"rate_burst", burst,
		}
		switch sb.Name() {
		case "e2b":
			args = append(args,
				"resources", "template-managed; configured values are post-create maxima",
				"max_mem_mb", res.MemoryMB,
				"max_cpus", res.CPUs,
				"max_disk_mb", res.DiskMB,
				"pids", "unsupported (non-zero fails startup)",
			)
		case "dockercloud":
			if dc, ok := sb.(*sandbox.DockerCloud); ok {
				args = append(args, "api", dc.APIName())
			}
			args = append(args,
				"resources", "requested at create and verified after it; 0 = backend default",
				"max_mem_mb", res.MemoryMB,
				"max_cpus", res.CPUs,
				"disk_and_pids", "unsupported (non-zero fails startup)",
			)
		default:
			args = append(args, "mem_mb", res.MemoryMB, "cpus", res.CPUs, "pids", res.PidsLimit, "disk_mb", res.DiskMB)
		}
		args = append(args, "tls", tlsConf != nil, "metrics_addr", boundMetrics, "guard_addr", boundGuard, "max_connections", rpcConns)
		slog.Info("plimsolld listening", args...)
	}
	listeners := []served{{"rpc", srv, ln}}
	if guardSrv != nil {
		listeners = append(listeners, served{"egress guard", guardSrv, guardLn})
	}
	if metricsSrv != nil {
		listeners = append(listeners, served{"metrics", metricsSrv, metricsLn})
	}
	// A listener that fails ends the daemon through the same drain as a signal, so the
	// runs in flight finish and their sandboxes are deleted; exiting on the spot would
	// leave billed microVMs running until their own expiry.
	serveErr := serveUntil(ctx, listeners)
	stop() // restore default handling so a second signal force-quits the drain
	if serveErr != nil {
		slog.Error("a listener failed; draining in-flight runs before exiting", "error", serveErr)
	} else {
		slog.Info("shutdown signal received; draining in-flight runs")
	}
	// Drain rather than kill: in-flight runs finish on their own goroutines, so
	// their deferred cleanup (containers, e2b microVMs, temp dirs) actually runs
	// instead of leaking on an abrupt exit.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown timed out; forcing close", "error", err)
		_ = srv.Close()
	}
	// Runs are over; let the provider finish what they left behind (openshell deletes
	// each sandbox off the result path), within the same shutdown budget.
	if d, ok := sb.(sandbox.Drainer); ok {
		if err := d.Drain(shutdownCtx); err != nil {
			slog.Error("provider cleanup did not finish before shutdown; a later reconciliation reaps what is left", "provider", sb.Name(), "error", err)
		}
	}
	// The guard stays up through the drain, since a run still in flight makes its
	// host calls through it; metrics too, so a scraper can watch the in-flight gauge
	// fall. Once the runs are over neither has anything left to serve.
	if guardSrv != nil {
		_ = guardSrv.Close()
	}
	if metricsSrv != nil {
		_ = metricsSrv.Close()
	}
	slog.Info("plimsolld stopped")
	if serveErr != nil {
		os.Exit(1)
	}
}

// served is one listener and the server that serves it.
type served struct {
	name string
	srv  *http.Server
	ln   net.Listener
}

// serveUntil serves every listener until ctx ends or one of them fails, and returns
// that failure, or nil when ctx ended first. Either way the caller drains.
func serveUntil(ctx context.Context, listeners []served) error {
	failed := make(chan error, len(listeners))
	for _, l := range listeners {
		go func() {
			if err := serve(l.srv, l.ln); err != nil {
				failed <- fmt.Errorf("%s listener: %w", l.name, err)
			}
		}()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-failed:
		return err
	}
}

// serve runs srv on ln until the server is shut down, over TLS when it has a
// config. The keypair is already loaded into TLSConfig, so the paths are empty.
func serve(srv *http.Server, ln net.Listener) error {
	var err error
	if srv.TLSConfig != nil {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// metricsHandler serves /metrics and nothing else. It is mounted on its own
// listener (PLIMSOLL_METRICS_ADDR), never on the RPC one: the endpoint has no
// authentication, and its labels name grant profiles and route templates, which a
// caller who can reach the RPC port has no business reading.
func metricsHandler(svc *rpc.SandboxService) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		writeMetrics(w, svc)
	})
	return mux
}

// newMetricsServer is newHTTPServer with a scrape's time limits. A scrape renders
// counters already in memory and needs none of the RPC listener's six-minute
// write window; 10 s is Prometheus's default scrape timeout, after which the
// scraper has given up anyway.
func newMetricsServer(addr string, handler http.Handler, tlsConf *tls.Config) *http.Server {
	srv := newHTTPServer(addr, handler, tlsConf)
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	return srv
}

// readyzHandler re-runs the provider's bounded Preflight. Anyone can poll it, so it
// answers with a fixed body: a Preflight error can name DOCKER_HOST, image references
// or a gateway's own error text. The detail goes to the log, at most once per
// readyzLogEvery, so a poller cannot flood the log either.
func readyzHandler(sb sandbox.Sandbox) http.HandlerFunc {
	var mu sync.Mutex
	var logged time.Time
	return func(w http.ResponseWriter, r *http.Request) {
		if pf, ok := sb.(sandbox.Preflighter); ok {
			if err := pf.Preflight(r.Context()); err != nil {
				mu.Lock()
				if time.Since(logged) >= readyzLogEvery {
					logged = time.Now()
					slog.Warn("readiness check failed", "provider", sb.Name(), "error", err)
				}
				mu.Unlock()
				http.Error(w, "not ready", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	}
}

const readyzLogEvery = 30 * time.Second

// newHTTPServer configures the daemon's HTTP server. With a TLS config it serves
// HTTPS with HTTP/1.1 + HTTP/2 negotiated via ALPN; without one it enables Go's
// native cleartext HTTP/2 alongside HTTP/1.1. Do not replace the cleartext path
// with x/net/http2/h2c.NewHandler: that upgrade wrapper reads the first h2c
// request body entirely into memory before the handler runs, bypassing
// AuthenticateHTTP and Connect's request-size limit. Native protocol selection
// handles HTTP/2 prior knowledge without a pre-handler body read.
// Every handler is wrapped by unreadbody: an HTTP/1.x answer that does not read its
// request body (a refusal, a 404, a health check sent a body) closes the connection
// instead of first waiting for that body, which a slow client could hold back until
// the read timeout.
func newHTTPServer(addr string, handler http.Handler, tlsConf *tls.Config) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	if tlsConf != nil {
		protocols.SetHTTP2(true)
	} else {
		protocols.SetUnencryptedHTTP2(true)
	}
	return &http.Server{
		Addr:    addr,
		Handler: unreadbody.Handler(handler),
		// Without this, Go answers "OPTIONS *" itself, before the handler: it reads
		// the request's body first (up to 4 KiB, waiting for it) and replies 200, so
		// the guard's path check, the auth middleware and unreadbody never see it.
		DisableGeneralOptionsHandler: true,
		Protocols:                    protocols,
		TLSConfig:                    tlsConf,
		ReadHeaderTimeout:            5 * time.Second,
		ReadTimeout:                  30 * time.Second, // includes bounded request body; stops slow uploads
		WriteTimeout:                 6 * time.Minute,  // above the RPC hard ceiling + response write
		IdleTimeout:                  2 * time.Minute,
		MaxHeaderBytes:               32 << 10,
	}
}

// rpcMux is what the RPC listener serves: the SandboxService behind its pre-body
// checks, and the operational endpoints, every answer bound to its request
// (rpc.BindAnswers): the pre-body checks' refusals and a 404 included.
func rpcMux(svc *rpc.SandboxService, verifier rpc.TokenVerifier, maxConcurrent int, sb sandbox.Sandbox) http.Handler {
	mux := http.NewServeMux()
	path, handler := rpc.NewHandler(svc,
		// ReleaseDecodeSlot first: it gives back the decode slot guardRPC took, once
		// Connect has decoded the request and before anything runs.
		connect.WithInterceptors(rpc.ReleaseDecodeSlot(), rpc.AuthInterceptor(verifier)),
		// Bound the request body BEFORE it is decompressed/unmarshalled. Without
		// this, Connect's default ReadMaxBytes is 0 (unlimited), so the per-field
		// size checks in the service run only after a hostile multi-GB or
		// compression-bombed message is already buffered in memory. Every caller is
		// untrusted; this is the real DoS backstop. Headroom over the 4 MiB project
		// limit for proto framing and step/artifact metadata.
		connect.WithReadMaxBytes(maxRequestBytes),
	)
	// Reject bad credentials before Connect reads/decompresses the body, then cap
	// authenticated requests during decode before the run limiter is reachable.
	// LimitBody independently caps raw HTTP bytes; Connect's limit is per
	// decompressed message, so neither one substitutes for the other.
	mux.Handle(path, guardRPC(verifier, maxConcurrent, handler))
	// The egress guard is not here: it has a listener of its own (guardHandler).
	// Operational endpoints, registered OUTSIDE the auth interceptor so probes need
	// no token. Liveness is unconditional; readiness re-runs the provider's bounded
	// Preflight. Docker probes its pinned daemon/runtime; E2B's current Preflight
	// validates configuration only and does not prove API reachability. /metrics is
	// not here: it has a listener of its own (metricsHandler).
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", readyzHandler(sb))
	return rpc.BindAnswers(mux)
}

// egressGuardOf returns the provider's egress guard and the path it serves, or nil
// and "" when the provider serves none (one without a guard, or E2B and Docker Cloud
// without a guard URL).
func egressGuardOf(sb sandbox.Sandbox) (sandbox.EgressGuardCapable, string) {
	guard, ok := sb.(sandbox.EgressGuardCapable)
	if !ok {
		return nil, ""
	}
	path := guard.EgressGuardPath()
	if path == "" {
		return nil, ""
	}
	return guard, path
}

// guardHandler is everything the guard listener serves: the guard's one path, which
// answers 404 to any other path or method. A guest's one permitted destination is
// the guard, so the guard has a listener of its own: on the RPC listener a guest
// could also reach the RPC procedures, /healthz and /readyz. The guard URL is public
// by construction, so the handler authenticates on the per-run guard credential and
// bounds concurrent decode work before reading a body; its admission lives inside
// it, and the bound tracks live granted runs, since a guest awaits each host.* call
// rather than pipelining.
func guardHandler(guard sandbox.EgressGuardCapable, path string, maxConcurrent int) http.Handler {
	return sandbox.EgressGuardHTTPHandler(guard, path, maxConcurrent*2, 2)
}

// guardRPC wraps the Connect handler in the checks that run before Connect reads the
// body: credentials first, then the declared body size against the cap on raw request
// bytes, then a decode slot for the authenticated caller.
func guardRPC(verifier rpc.TokenVerifier, maxConcurrent int, handler http.Handler) http.Handler {
	return rpc.AuthenticateHTTP(verifier, rpc.LimitBody(maxRequestBytes, rpc.LimitHTTPConcurrency(maxConcurrent*2, handler)))
}

// writeMetrics renders a minimal Prometheus text exposition. It covers the biggest
// production blind spots: run throughput/errors, live saturation, and — the piece
// invisible in the logs — how often load was shed and why. No client_golang
// dependency; the surface is small and stable.
func writeMetrics(w http.ResponseWriter, svc *rpc.SandboxService) {
	total, failed := svc.RunCounts()
	var st rpc.Stats
	if svc.Limiter != nil {
		st = svc.Limiter.Stats()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP plimsoll_runs_total Runs dispatched to the provider.\n")
	fmt.Fprintf(w, "# TYPE plimsoll_runs_total counter\n")
	fmt.Fprintf(w, "plimsoll_runs_total %d\n", total)
	fmt.Fprintf(w, "# HELP plimsoll_runs_failed_total Runs that failed with an infrastructure error.\n")
	fmt.Fprintf(w, "# TYPE plimsoll_runs_failed_total counter\n")
	fmt.Fprintf(w, "plimsoll_runs_failed_total %d\n", failed)
	fmt.Fprintf(w, "# HELP plimsoll_inflight Runs currently holding a concurrency slot.\n")
	fmt.Fprintf(w, "# TYPE plimsoll_inflight gauge\n")
	fmt.Fprintf(w, "plimsoll_inflight %d\n", st.InFlight)
	fmt.Fprintf(w, "# HELP plimsoll_shed_total Runs rejected by the limiter, by reason.\n")
	fmt.Fprintf(w, "# TYPE plimsoll_shed_total counter\n")
	fmt.Fprintf(w, "plimsoll_shed_total{reason=\"at_capacity\"} %d\n", st.AtCapacity)
	fmt.Fprintf(w, "plimsoll_shed_total{reason=\"per_key\"} %d\n", st.PerKeyFull)
	fmt.Fprintf(w, "plimsoll_shed_total{reason=\"rate\"} %d\n", st.RateLimited)
	paidCaller, paidDaemon := svc.Spend.Refused()
	fmt.Fprintf(w, "plimsoll_shed_total{reason=\"paid_caller\"} %d\n", paidCaller)
	fmt.Fprintf(w, "plimsoll_shed_total{reason=\"paid_daemon\"} %d\n", paidDaemon)
	writeHostCallMetrics(w, svc.HostCallStats())
	writeAdviceMetrics(w, svc.AdviceStats())
}

// writeAdviceMetrics renders the Prospector Phase 4 advice counters, one series per
// (profile, pattern, severity, remedy, agent_fixable). Every label is operator-
// bounded metadata (a grant profile plus the fixed detector vocabulary and the
// router's agent-fixable split), so nothing here can leak a request value or inflate
// cardinality. The added-latency counter is the modelled latency beyond one call
// that the dashboard's bottleneck-attribution panel weighs against raw upstream
// latency; it is a model of the pattern's shape, not measured wall time lost.
func writeAdviceMetrics(w io.Writer, series []rpc.AdviceSeriesSnapshot) {
	if len(series) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP plimsoll_advice_findings_total Efficiency findings, by grant profile, pattern, severity, remedy, and whether the agent can fix it now.\n")
	fmt.Fprintf(w, "# TYPE plimsoll_advice_findings_total counter\n")
	for _, s := range series {
		fmt.Fprintf(w, "plimsoll_advice_findings_total{%s} %d\n", adviceLabels(s), s.Count)
	}
	fmt.Fprintf(w, "# HELP plimsoll_advice_extra_calls_total Calls beyond the ideal shape attributed to flagged patterns.\n")
	fmt.Fprintf(w, "# TYPE plimsoll_advice_extra_calls_total counter\n")
	for _, s := range series {
		fmt.Fprintf(w, "plimsoll_advice_extra_calls_total{%s} %d\n", adviceLabels(s), s.ExtraCalls)
	}
	fmt.Fprintf(w, "# HELP plimsoll_advice_added_latency_seconds_total Modelled upstream latency beyond one call, summed over the calls a pattern flagged (a model of the pattern's shape, not measured wall time lost).\n")
	fmt.Fprintf(w, "# TYPE plimsoll_advice_added_latency_seconds_total counter\n")
	for _, s := range series {
		fmt.Fprintf(w, "plimsoll_advice_added_latency_seconds_total{%s} %g\n", adviceLabels(s), s.AddedLatencySec)
	}
	fmt.Fprintf(w, "# HELP plimsoll_advice_bytes_moved_total Request+response bytes across the calls flagged by a pattern.\n")
	fmt.Fprintf(w, "# TYPE plimsoll_advice_bytes_moved_total counter\n")
	for _, s := range series {
		fmt.Fprintf(w, "plimsoll_advice_bytes_moved_total{%s} %d\n", adviceLabels(s), s.BytesMoved)
	}
}

// adviceLabels builds the label set for an advice series. Values are escaped per the
// Prometheus text format; agent_fixable is rendered as the string "true"/"false".
func adviceLabels(s rpc.AdviceSeriesSnapshot) string {
	return fmt.Sprintf(`profile="%s",pattern="%s",severity="%s",remedy="%s",agent_fixable="%t"`,
		escapeLabelValue(s.Profile), escapeLabelValue(s.Pattern),
		escapeLabelValue(s.Severity), escapeLabelValue(s.Remedy), s.AgentFixable)
}

// writeHostCallMetrics renders the Prospector host-API call counter and upstream-
// latency histogram, one series per (profile, method, route template). Labels are
// operator-bounded and metadata only: route is always a grant template, never a raw
// path, so nothing here can leak a request value or inflate cardinality.
func writeHostCallMetrics(w io.Writer, series []rpc.HostCallSeriesSnapshot) {
	if len(series) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP plimsoll_host_calls_total Brokered host-API calls, by grant profile, method, and route template.\n")
	fmt.Fprintf(w, "# TYPE plimsoll_host_calls_total counter\n")
	for _, s := range series {
		fmt.Fprintf(w, "plimsoll_host_calls_total{%s} %d\n", hostCallLabels(s, ""), s.Count)
	}
	fmt.Fprintf(w, "# HELP plimsoll_host_call_latency_seconds Upstream latency of brokered host-API calls.\n")
	fmt.Fprintf(w, "# TYPE plimsoll_host_call_latency_seconds histogram\n")
	bounds := rpc.HostCallLatencyBounds()
	for _, s := range series {
		for i, ub := range bounds {
			fmt.Fprintf(w, "plimsoll_host_call_latency_seconds_bucket{%s} %d\n",
				hostCallLabels(s, fmt.Sprintf("le=\"%g\"", ub)), s.CumulativeBuckets[i])
		}
		fmt.Fprintf(w, "plimsoll_host_call_latency_seconds_bucket{%s} %d\n",
			hostCallLabels(s, "le=\"+Inf\""), s.Count)
		fmt.Fprintf(w, "plimsoll_host_call_latency_seconds_sum{%s} %g\n", hostCallLabels(s, ""), s.SumSec)
		fmt.Fprintf(w, "plimsoll_host_call_latency_seconds_count{%s} %d\n", hostCallLabels(s, ""), s.Count)
	}
}

// hostCallLabels builds the label set for a host-call series, appending an optional
// extra label (le="..."). Values are escaped per the Prometheus text format.
func hostCallLabels(s rpc.HostCallSeriesSnapshot, extra string) string {
	labels := fmt.Sprintf(`profile="%s",method="%s",route="%s"`,
		escapeLabelValue(s.Profile), escapeLabelValue(s.Method), escapeLabelValue(s.Route))
	if extra != "" {
		labels += "," + extra
	}
	return labels
}

// escapeLabelValue escapes a Prometheus label value: backslash, double quote, and
// newline. The result is placed inside %q, which adds the surrounding quotes;
// pre-escaping keeps a template's own characters from breaking the exposition.
func escapeLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// maxRequestBytes caps an incoming RPC message at the transport layer. It sits
// above the 4 MiB project payload with headroom for proto
// framing and step/artifact metadata.
const maxRequestBytes = 8 << 20 // 8 MiB

// staticVerifier accepts a single shared bearer token (PLIMSOLL_TOKEN) and
// grants it a fixed scope set. It is the zero-infra auth option; swap in a
// DB/JWT-backed TokenVerifier for multi-tenant deployments.
type staticVerifier struct {
	token  string
	scopes []string
}

func (v staticVerifier) VerifyToken(_ context.Context, token string) (rpc.Principal, bool, error) {
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(v.token)) != 1 {
		return rpc.Principal{}, false, nil
	}
	return rpc.Principal{UserID: "static", Scopes: v.scopes}, true, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func atLeast1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func validateLimiterConfig(maxConcurrent, perKey, ratePerMin, burst int) error {
	if maxConcurrent < 1 || maxConcurrent > 1024 {
		return fmt.Errorf("max_concurrent=%d is outside [1,1024]", maxConcurrent)
	}
	if perKey < 0 || perKey > maxConcurrent {
		return fmt.Errorf("per_key_concurrent=%d must be between 0 and max_concurrent=%d", perKey, maxConcurrent)
	}
	if ratePerMin < 0 || burst < 0 {
		return fmt.Errorf("rate_per_min and rate_burst must be non-negative")
	}
	return nil
}

// unknownVariables lists the PLIMSOLL_ and SANDBOX_ variables in environ that the help
// text does not name. The help text names every variable the daemon reads
// (TestUsageNamesEveryVariable), so a name it lacks is one the daemon ignores.
func unknownVariables(environ []string, help string) []string {
	var out []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "PLIMSOLL_") && !strings.HasPrefix(name, "SANDBOX_") {
			continue
		}
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(help) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
