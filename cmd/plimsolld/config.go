package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// limiterConfig is the fully-resolved, validated admission-control envelope for the
// daemon: the effective values NewCodeLimiter is built from AFTER env parsing and the
// aggregate-memory clamp. Extracting it from main() makes the parsing/clamp/validate
// logic pure and unit-testable (no process env, no os.Exit) — main() only wires it.
type limiterConfig struct {
	MaxConcurrent int
	PerKey        int
	RatePerMin    int
	Burst         int
}

// minimumIsolationWith parses the daemon-wide startup floor. IsolationNone is
// not accepted: a configured security floor must require an actual execution
// boundary, while an empty value is the only way to request no floor.
func minimumIsolationWith(getenv func(string) string) (sandbox.IsolationClass, bool, error) {
	raw := strings.ToLower(strings.TrimSpace(getenv("SANDBOX_MIN_ISOLATION")))
	if raw == "" {
		return sandbox.IsolationUnknown, false, nil
	}
	want := sandbox.ParseIsolationClass(raw)
	if want < sandbox.IsolationProcess || want > sandbox.IsolationVM {
		return sandbox.IsolationUnknown, false, fmt.Errorf("SANDBOX_MIN_ISOLATION=%q must be one of process, container, kernel, or vm", raw)
	}
	return want, true, nil
}

// loadLimiterConfig resolves the limiter envelope from getenv (injectable for tests).
// providerName and perRunMemMB drive the SANDBOX_TOTAL_MEMORY_MB clamp: a count is not
// a resource budget, so when a total is set the max-concurrent is clamped so
// concurrent × per-run memory cannot oversubscribe the host (skipped for e2b and dockercloud, whose
// runners live off-host). The session pool's poolSize waiting containers are charged
// first: each holds memory (its container's limit is one run's) and no concurrency
// slot, and the pool refills what a session claims, so poolSize is always what waits.
// It returns a typed error instead of exiting, so callers decide how to fail.
func loadLimiterConfig(getenv func(string) string, providerName string, perRunMemMB, poolSize int) (limiterConfig, error) {
	maxConcurrent, err := envIntWith(getenv, "SANDBOX_MAX_CONCURRENT", 8)
	if err != nil {
		return limiterConfig{}, err
	}
	if err := validateLimiterConfig(maxConcurrent, 0, 0, 0); err != nil {
		return limiterConfig{}, fmt.Errorf("invalid SANDBOX_MAX_CONCURRENT: %w", err)
	}

	totalMB, err := envIntWith(getenv, "SANDBOX_TOTAL_MEMORY_MB", 0)
	if err != nil {
		return limiterConfig{}, err
	}
	if totalMB < 0 {
		return limiterConfig{}, fmt.Errorf("SANDBOX_TOTAL_MEMORY_MB=%d must be non-negative", totalMB)
	}
	if totalMB > 0 && providerName != "e2b" && providerName != "dockercloud" {
		perRun := perRunMemMB
		if perRun <= 0 {
			perRun = 256 // wasm and docker both default to 256 MiB per run
		}
		fit := totalMB/perRun - poolSize
		if fit < 1 {
			if poolSize > 0 {
				return limiterConfig{}, fmt.Errorf("SANDBOX_TOTAL_MEMORY_MB=%d cannot fit the session pool's %d waiting containers (%d MiB each) and one run", totalMB, poolSize, perRun)
			}
			return limiterConfig{}, fmt.Errorf("SANDBOX_TOTAL_MEMORY_MB=%d cannot fit even one %d MiB run", totalMB, perRun)
		}
		if fit < maxConcurrent {
			slog.Warn("clamping max concurrency to the aggregate memory budget",
				"total_mb", totalMB, "per_run_mb", perRun, "session_pool", poolSize,
				"max_concurrent_requested", maxConcurrent, "max_concurrent_effective", fit)
			maxConcurrent = fit
		}
	}

	perKey, err := envIntWith(getenv, "SANDBOX_PER_KEY_CONCURRENT", atLeast1(maxConcurrent/2))
	if err != nil {
		return limiterConfig{}, err
	}
	ratePerMin, err := envIntWith(getenv, "SANDBOX_RATE_PER_MIN", 30)
	if err != nil {
		return limiterConfig{}, err
	}
	burst, err := envIntWith(getenv, "SANDBOX_RATE_BURST", ratePerMin)
	if err != nil {
		return limiterConfig{}, err
	}
	if err := validateLimiterConfig(maxConcurrent, perKey, ratePerMin, burst); err != nil {
		return limiterConfig{}, err
	}
	return limiterConfig{MaxConcurrent: maxConcurrent, PerKey: perKey, RatePerMin: ratePerMin, Burst: burst}, nil
}

// tlsConfigFromEnv resolves the optional server certificate pair
// (PLIMSOLL_TLS_CERT / PLIMSOLL_TLS_KEY). Both-or-neither: a half-configured
// pair is a startup error, and an unloadable pair fails now rather than on the
// first handshake. nil means serve cleartext (h2c).
func tlsConfigFromEnv(getenv func(string) string) (*tls.Config, error) {
	cert := strings.TrimSpace(getenv("PLIMSOLL_TLS_CERT"))
	key := strings.TrimSpace(getenv("PLIMSOLL_TLS_KEY"))
	if cert == "" && key == "" {
		return nil, nil
	}
	if cert == "" || key == "" {
		return nil, errors.New("PLIMSOLL_TLS_CERT and PLIMSOLL_TLS_KEY must be set together")
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
}

// defaultMetricsAddr is where /metrics listens unless PLIMSOLL_METRICS_ADDR says
// otherwise: the loopback address and port 9464, OpenTelemetry's defaults for a
// Prometheus exporter (OTEL_EXPORTER_PROMETHEUS_HOST=localhost,
// OTEL_EXPORTER_PROMETHEUS_PORT=9464). Nothing off this host can read it until an
// operator binds another address.
const defaultMetricsAddr = "127.0.0.1:9464"

// metricsAddrWith resolves the metrics listener's address; "" means metrics are
// off. The endpoint has no authentication and its labels name grant profiles and
// route templates, so it never shares the RPC listener and defaults to loopback.
// The address is checked for a port here, so a bare "9464" fails naming the
// variable instead of as a listen error.
func metricsAddrWith(getenv func(string) string) (string, error) {
	raw := strings.TrimSpace(getenv("PLIMSOLL_METRICS_ADDR"))
	switch {
	case raw == "":
		return defaultMetricsAddr, nil
	case strings.EqualFold(raw, "off"):
		return "", nil
	}
	if _, _, err := net.SplitHostPort(raw); err != nil {
		return "", fmt.Errorf("PLIMSOLL_METRICS_ADDR=%q must be host:port or off: %w", raw, err)
	}
	return raw, nil
}

// guardAddrWith resolves the egress guard's listen address; "" means the daemon
// serves no guard. serves reports whether the provider has a guard to serve (E2B with
// E2B_GUARD_URL, Docker Cloud with SANDBOX_DOCKERCLOUD_GUARD_URL). The guard is a
// granted guest's one permitted destination, so it never shares the RPC listener,
// where the guest would also reach the RPC procedures and the health endpoints. There
// is no default: the guard must be reachable from the provider's VMs, and choosing an
// address another network can reach is the operator's decision, not plimsolld's. A
// value with no guard to serve is refused, so a set variable never does nothing.
func guardAddrWith(getenv func(string) string, serves bool) (string, error) {
	raw := strings.TrimSpace(getenv("PLIMSOLL_GUARD_ADDR"))
	switch {
	case serves && raw == "":
		return "", errors.New("PLIMSOLL_GUARD_ADDR is required: the provider serves the egress guard (its guard URL is set), and the guard has a listener of its own; set host:port and point the public guard URL at it")
	case !serves && raw != "":
		return "", fmt.Errorf("PLIMSOLL_GUARD_ADDR=%q is set but the provider serves no egress guard (only e2b with E2B_GUARD_URL and dockercloud with SANDBOX_DOCKERCLOUD_GUARD_URL do); unset it", raw)
	case !serves:
		return "", nil
	}
	if _, _, err := net.SplitHostPort(raw); err != nil {
		return "", fmt.Errorf("PLIMSOLL_GUARD_ADDR=%q must be host:port: %w", raw, err)
	}
	return raw, nil
}

// loopbackAddr reports whether a listen address can only be reached from this
// host. An empty host (":8746") binds every interface and is NOT loopback.
func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// hardenedFacts are the resolved runtime facts the hardened policy checks —
// evidence main() computed that is not directly readable from the environment.
type hardenedFacts struct {
	Provider        string                 // active provider name
	Isolation       sandbox.IsolationClass // post-EnsureReady evidence, not static config
	MultiClientAuth bool                   // PLIMSOLL_CLIENTS_FILE verifier loaded
	TLS             bool                   // serving TLS
	Addr            string                 // listen address
	MetricsAddr     string                 // metrics listen address; "" = metrics off
	GuardAddr       string                 // egress guard listen address; "" = no guard
	// IsolationPending skips the isolation rule: the early pass, before the smoke
	// test has produced the evidence it needs, checks every other rule.
	IsolationPending bool
	MaxConcurrent    int               // effective global concurrency cap
	RatePerMin       int               // effective per-caller rate limit
	Burst            int               // effective per-caller rate burst
	PerCaller        int               // effective per-caller concurrency cap; 0 = none
	Sessions         rpc.SessionConfig // the session settings in force
	// Metered: the provider bills by the second (sandbox.Metered); Uncapped names the
	// callers in PLIMSOLL_CLIENTS_FILE without a paid_seconds_per_day.
	Metered  bool
	Uncapped []string
}

// enforceHardenedPolicy is the production policy PLIMSOLL_HARDENED=1 turns on.
// The soft posture — warnings for runc, optional pinning, defaulted budgets — is
// fine for development, but a warning is not a production policy: in hardened
// mode every advertised production property must be verifiably in force or the
// daemon refuses to serve. All violations are reported at once (errors.Join) so
// the operator fixes the deployment in one pass instead of startup-loop whack-a-mole.
func enforceHardenedPolicy(getenv func(string) string, f hardenedFacts) error {
	var violations []error
	fail := func(format string, args ...any) {
		violations = append(violations, fmt.Errorf(format, args...))
	}

	// Boundary: only a hardware VM or a verified user-space kernel is a
	// hostile-code boundary. f.Isolation is post-EnsureReady evidence, so for
	// docker this is true only after the pinned daemon proved a runsc runtime.
	if !f.IsolationPending && f.Isolation != sandbox.IsolationVM && f.Isolation != sandbox.IsolationKernel {
		fail("provider %q reports isolation %q; hardened mode requires vm (e2b, dockercloud) or verified kernel (docker with SANDBOX_DOCKER_RUNTIME=runsc)",
			f.Provider, f.Isolation.String())
	}

	// Identity: a single shared token collapses every caller into one principal,
	// which defeats per-caller limits, grant ACLs, per-session minting, and audit.
	if !f.MultiClientAuth {
		fail("hardened mode requires multi-client auth: set PLIMSOLL_CLIENTS_FILE (a shared PLIMSOLL_TOKEN or open dev mode is not a production identity)")
	}
	if strings.TrimSpace(getenv("PLIMSOLL_INSECURE")) != "" {
		fail("PLIMSOLL_INSECURE must not be set in hardened mode")
	}

	// Transport: bearer tokens on cleartext are replayable by anyone on the path.
	// Exact-loopback listeners are exempt, mirroring the official client's policy.
	if !f.TLS && !loopbackAddr(f.Addr) {
		fail("hardened mode requires TLS on the non-loopback listener %q: set PLIMSOLL_TLS_CERT/PLIMSOLL_TLS_KEY or bind a loopback address", f.Addr)
	}
	// The metrics listener is the daemon's second listener and follows the same
	// rule. It carries no bearer, but its labels name grant profiles and route
	// templates, and TLS keeps them off the wire in the clear. TLS does not decide
	// who may scrape: the endpoint has no authentication, so off this host that is
	// the firewall's job.
	if f.MetricsAddr != "" && !f.TLS && !loopbackAddr(f.MetricsAddr) {
		fail("hardened mode requires TLS on the non-loopback metrics listener %q: set PLIMSOLL_TLS_CERT/PLIMSOLL_TLS_KEY, bind a loopback address, or set PLIMSOLL_METRICS_ADDR=off", f.MetricsAddr)
	}

	// The guard listener carries each granted call's host-API request and response
	// and the run's guard credential, so off this host it needs TLS too. A guard
	// behind a TLS-terminating proxy on this host binds loopback and is exempt.
	if f.GuardAddr != "" && !f.TLS && !loopbackAddr(f.GuardAddr) {
		fail("hardened mode requires TLS on the non-loopback egress guard listener %q: set PLIMSOLL_TLS_CERT/PLIMSOLL_TLS_KEY or bind a loopback address behind a TLS-terminating proxy", f.GuardAddr)
	}

	// Immutable execution surface, per provider.
	switch f.Provider {
	case "docker":
		pinned, err := sandbox.BoolFromEnv(getenv, "SANDBOX_REQUIRE_PINNED_IMAGES")
		if err != nil {
			violations = append(violations, err)
		} else if !pinned {
			fail("hardened mode requires SANDBOX_REQUIRE_PINNED_IMAGES=1 so every configured docker image is an immutable @sha256 digest (a mutable tag can be repushed under you)")
		}
		// The vm/kernel requirement above already forces runsc, whose user-space
		// kernel does its own syscall interception (the host seccomp profile is
		// deliberately not applied under runsc — see lockdownArgs). Only an operator
		// explicitly signaling seccomp-off intent is rejected here.
		if strings.TrimSpace(getenv("SANDBOX_DOCKER_SECCOMP")) == "unconfined" {
			fail("hardened mode forbids SANDBOX_DOCKER_SECCOMP=unconfined")
		}
	case "dockercloud":
		// The sandbox boots a raw OCI reference, so the same pinning rule as docker
		// applies: a mutable tag could be repushed under a running deployment.
		// A store image (SANDBOX_DOCKERCLOUD_STORE_IMAGE) always carries its digest,
		// checked against every sandbox's booted digest, so it needs no flag.
		pinned, err := sandbox.BoolFromEnv(getenv, "SANDBOX_REQUIRE_PINNED_IMAGES")
		if err != nil {
			violations = append(violations, err)
		} else if !pinned && strings.TrimSpace(getenv("SANDBOX_DOCKERCLOUD_STORE_IMAGE")) == "" {
			fail("hardened mode requires SANDBOX_REQUIRE_PINNED_IMAGES=1 so SANDBOX_DOCKERCLOUD_IMAGE is an immutable @sha256 digest")
		}
		// A pin is only evidence where the API reports the digest each sandbox
		// booted; the REST API, the default, reports none.
		if api := strings.TrimSpace(getenv("SANDBOX_DOCKERCLOUD_API")); api != "connect" {
			fail("hardened mode requires SANDBOX_DOCKERCLOUD_API=connect, named rather than left to the default: the REST API does not report which image a sandbox booted, so the pinned image cannot be proven")
		}
	case "e2b":
		// E2B offers no digest pinning; an explicit template (never the implicit
		// "base" default) is the strongest surface selection available. The startup
		// SmokeTest then proves that template behaves.
		if strings.TrimSpace(getenv("E2B_TEMPLATE")) == "" {
			fail("hardened mode requires an explicit E2B_TEMPLATE (the implicit \"base\" default is not a pinned execution surface)")
		}
	}
	dp, daemonBuilt := daemonProviders[f.Provider]
	if daemonBuilt && dp.pinnedImages {
		pinned, err := sandbox.BoolFromEnv(getenv, "SANDBOX_REQUIRE_PINNED_IMAGES")
		if err != nil {
			violations = append(violations, err)
		} else if !pinned {
			fail("hardened mode requires SANDBOX_REQUIRE_PINNED_IMAGES=1 so the %s image is an immutable @sha256 digest", f.Provider)
		}
	}

	// Explicit budgets: provider defaults are development conveniences. A hardened
	// deployment states its per-run envelope and (for on-host runners) the
	// aggregate memory budget so capacity is a decision, not an accident.
	required, ok := hardenedEnvelope[f.Provider]
	switch {
	case daemonBuilt:
		required = dp.hardenedEnvelope
	case !ok:
		required = hardenedEnvelopeDefault
	}
	var missing, nonPositive []string
	for _, key := range required {
		v := strings.TrimSpace(getenv(key))
		if v == "" {
			missing = append(missing, key)
			continue
		}
		// Zero means "provider default" or "no cap" to the factory, which is not an
		// operator's chosen envelope.
		if n, err := strconv.ParseFloat(v, 64); err != nil || !(n > 0) {
			nonPositive = append(nonPositive, key)
		}
	}
	if len(missing) > 0 {
		fail("hardened mode requires an explicit resource envelope: set %s", strings.Join(missing, ", "))
	}
	if len(nonPositive) > 0 {
		fail("hardened mode requires a positive resource envelope: %s must be greater than zero", strings.Join(nonPositive, ", "))
	}
	if f.RatePerMin <= 0 {
		fail("hardened mode requires per-caller rate limiting: SANDBOX_RATE_PER_MIN must be positive")
	} else if f.Burst > f.RatePerMin {
		// A burst larger than a minute's allowance lets one caller start more runs at
		// once than the rate admits in a minute, which is what the limit is for.
		fail("hardened mode requires SANDBOX_RATE_BURST (%d) to be at most SANDBOX_RATE_PER_MIN (%d), one minute's allowance", f.Burst, f.RatePerMin)
	}
	// A rate limit bounds what a caller starts, not what it holds: without a
	// concurrency cap one caller can hold every slot with long runs or running
	// sessions. A suspended session holds no slot, so the session cap below bounds
	// those.
	if f.PerCaller <= 0 {
		fail("hardened mode requires a per-caller concurrency cap: SANDBOX_PER_KEY_CONCURRENT must be positive")
	} else if f.PerCaller >= f.MaxConcurrent {
		// A cap equal to the global one lets one caller hold every slot.
		fail("hardened mode requires SANDBOX_PER_KEY_CONCURRENT (%d) to be below SANDBOX_MAX_CONCURRENT (%d), so one caller cannot hold every slot", f.PerCaller, f.MaxConcurrent)
	}
	// A suspended session holds no concurrency slot, so the cap above does not bound
	// how many sessions one caller keeps open.
	if f.Sessions.MaxSessions > 0 && f.Sessions.MaxPerCaller <= 0 {
		fail("hardened mode requires a per-caller session cap with sessions on: SANDBOX_MAX_SESSIONS_PER_CALLER must be positive")
	}
	// Every run on a metered provider is billed by the second, and a rate limit bounds
	// runs per minute, not seconds per day: each caller needs its own daily allowance.
	if f.Metered && len(f.Uncapped) > 0 {
		fail("hardened mode with a provider billed by the second requires a daily allowance on every caller: set paid_seconds_per_day (plimsoll-clients limit) for %s", strings.Join(f.Uncapped, ", "))
	}

	if len(violations) > 0 {
		return errors.Join(violations...)
	}
	return nil
}

// hardenedEnvelope is the resource envelope hardened mode requires of each provider
// sandbox.Build constructs: every dimension the provider enforces and none its
// configuration rejects, since a policy demanding a variable Build refuses could
// never be satisfied. A daemon-built provider brings its own (daemonProvider).
var hardenedEnvelope = map[string][]string{
	// docker enforces the whole envelope, and its runners share this host, so the
	// aggregate budget that clamps concurrency is required too.
	"docker": {"SANDBOX_MEMORY_MB", "SANDBOX_CPUS", "SANDBOX_DISK_MB", "SANDBOX_PIDS", "SANDBOX_TOTAL_MEMORY_MB"},
	// E2B cannot enforce a process limit, so Build rejects SANDBOX_PIDS there.
	"e2b": {"SANDBOX_MEMORY_MB", "SANDBOX_CPUS", "SANDBOX_DISK_MB"},
	// Docker Cloud Sandboxes expose no disk or process control.
	"dockercloud": {"SANDBOX_MEMORY_MB", "SANDBOX_CPUS"},
}

// hardenedEnvelopeDefault applies to a provider in neither table (wasm, disabled),
// which the isolation rule refuses anyway.
var hardenedEnvelopeDefault = []string{"SANDBOX_MEMORY_MB", "SANDBOX_CPUS", "SANDBOX_DISK_MB"}

// maxSessionLifetime bounds SANDBOX_SESSION_LIFETIME: a session's sandbox outlives a
// crashed daemon by its lifetime (plus the reaper's margin), so the setting is also
// how long an orphan can live. Twelve hours covers a working day of agent use.
const maxSessionLifetime = 12 * time.Hour

// loadSessionConfig reads the session settings. Sessions stay off unless
// SANDBOX_MAX_SESSIONS is positive; the other values are validated either way, so a
// typo fails startup instead of lying in wait. The defaults: a 30-minute lifetime,
// a 5-minute idle timeout, 1 GiB of files (sessions plan, assumptions to revise from
// use: room for a node_modules tree and a build's output, and an abandoned session
// frees its slot within minutes).
// maxSessionDiskMB bounds SANDBOX_SESSION_DISK_MB at 1 TiB: far beyond any disk a
// session's sandbox holds, and well inside the int64 the byte count is kept in (the
// shift to bytes wrapped to 0, "no bound", at 2^44).
const maxSessionDiskMB = 1 << 20

func loadSessionConfig(getenv func(string) string) (rpc.SessionConfig, error) {
	max, err := envIntWith(getenv, "SANDBOX_MAX_SESSIONS", 0)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	perCaller, err := envIntWith(getenv, "SANDBOX_MAX_SESSIONS_PER_CALLER", 0)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	perOwner, err := envIntWith(getenv, "SANDBOX_MAX_SESSIONS_PER_OWNER", 0)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	diskMB, err := envIntWith(getenv, "SANDBOX_SESSION_DISK_MB", 1024)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	lifetime, err := envDurationWith(getenv, "SANDBOX_SESSION_LIFETIME", 30*time.Minute)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	idle, err := envDurationWith(getenv, "SANDBOX_SESSION_IDLE", 5*time.Minute)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	switch {
	case max < 0:
		return rpc.SessionConfig{}, fmt.Errorf("SANDBOX_MAX_SESSIONS=%d must not be negative", max)
	case perCaller < 0:
		return rpc.SessionConfig{}, fmt.Errorf("SANDBOX_MAX_SESSIONS_PER_CALLER=%d must not be negative", perCaller)
	case perOwner < 0:
		return rpc.SessionConfig{}, fmt.Errorf("SANDBOX_MAX_SESSIONS_PER_OWNER=%d must not be negative", perOwner)
	case diskMB < 0:
		return rpc.SessionConfig{}, fmt.Errorf("SANDBOX_SESSION_DISK_MB=%d must not be negative", diskMB)
	case lifetime < time.Second || lifetime > maxSessionLifetime:
		return rpc.SessionConfig{}, fmt.Errorf("SANDBOX_SESSION_LIFETIME=%v must be between 1s and %v", lifetime, maxSessionLifetime)
	case diskMB > maxSessionDiskMB:
		return rpc.SessionConfig{}, fmt.Errorf("SANDBOX_SESSION_DISK_MB=%d must be at most %d (1 TiB)", diskMB, maxSessionDiskMB)
	case idle < 0 || (idle > 0 && idle < time.Second) || idle > maxSessionLifetime:
		return rpc.SessionConfig{}, fmt.Errorf("SANDBOX_SESSION_IDLE=%v must be 0 (never suspend) or between 1s and %v", idle, maxSessionLifetime)
	}
	return rpc.SessionConfig{MaxSessions: max, MaxPerCaller: perCaller, MaxPerOwner: perOwner, Lifetime: lifetime, IdleTimeout: idle, DiskBytes: int64(diskMB) << 20}, nil
}

// loadSessionPool reads SANDBOX_SESSION_POOL, the sandboxes kept ready for sessions:
// default 0, off, because each one is a running container holding host memory. It
// cannot exceed SANDBOX_MAX_SESSIONS (more could never all be claimed at once) and
// needs sessions on.
func loadSessionPool(getenv func(string) string, sc rpc.SessionConfig) (int, error) {
	n, err := envIntWith(getenv, "SANDBOX_SESSION_POOL", 0)
	switch {
	case err != nil:
		return 0, err
	case n < 0:
		return 0, fmt.Errorf("SANDBOX_SESSION_POOL=%d must not be negative", n)
	case n > 0 && sc.MaxSessions == 0:
		return 0, fmt.Errorf("SANDBOX_SESSION_POOL=%d needs sessions on (SANDBOX_MAX_SESSIONS)", n)
	case n > sc.MaxSessions:
		return 0, fmt.Errorf("SANDBOX_SESSION_POOL=%d must not exceed SANDBOX_MAX_SESSIONS=%d", n, sc.MaxSessions)
	}
	return n, nil
}

// envDurationWith reads a Go duration ("30m", "90s") the way envIntWith reads an int.
func envDurationWith(getenv func(string) string, key string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q must be a duration such as 30m or 90s", key, v)
	}
	return d, nil
}

// envIntWith reads an int env var through an injected getenv. A non-empty but
// unparseable value is a startup error: admission limits are safety settings, so a
// typo must never silently weaken or disable one.
func envIntWith(getenv func(string) string, key string, def int) (int, error) {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q must be an integer", key, v)
	}
	return n, nil
}

// loadPaidConfig reads SANDBOX_PAID_SECONDS_PER_DAY and checks what needs no running
// sandbox about a provider billed by the second (metered), so a misconfigured daemon
// is refused before its smoke test creates a billed microVM: the allowance set for a
// provider that does not bill (a setting that does nothing must not look applied),
// and sessions on one that does, which nothing meters.
func loadPaidConfig(getenv func(string) string, metered bool) (int64, error) {
	paid, err := envIntWith(getenv, "SANDBOX_PAID_SECONDS_PER_DAY", 0)
	if err != nil {
		return 0, err
	}
	if paid < 0 {
		return 0, fmt.Errorf("SANDBOX_PAID_SECONDS_PER_DAY=%d must not be negative", paid)
	}
	if paid > 0 && !metered {
		return 0, errors.New("SANDBOX_PAID_SECONDS_PER_DAY applies only to a provider billed by the second (e2b, dockercloud): leave it unset")
	}
	if metered {
		if n, err := envIntWith(getenv, "SANDBOX_MAX_SESSIONS", 0); err == nil && n > 0 {
			return 0, errors.New("SANDBOX_MAX_SESSIONS on a provider billed by the second: session calls draw on no allowance, so they are refused")
		}
	}
	return int64(paid), nil
}
