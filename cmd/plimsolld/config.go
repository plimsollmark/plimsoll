package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/internal/settings"
	"github.com/plimsollmark/plimsoll/record"
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
	raw := settings.MinIsolation.Get(getenv)
	if raw == "" {
		return sandbox.IsolationUnknown, false, nil
	}
	want := sandbox.ParseIsolationClass(raw)
	if want < sandbox.IsolationProcess || want > sandbox.IsolationVM {
		return sandbox.IsolationUnknown, false, fmt.Errorf("SANDBOX_MIN_ISOLATION=%q must be one of process, container, kernel, or vm", raw)
	}
	return want, true, nil
}

// operatorMinimumError is SANDBOX_MIN_ISOLATION (want, when required) against the tier the
// provider reports: nil when it is met or unset, else an error naming the provider and both
// tiers, with the provider's own qualification when it states one (the wslc per-run mode's
// names the setting that would raise its tier). plimsolld asks it before the provider's
// startup checks when tierKnownBeforeChecks, and again after them.
func operatorMinimumError(sb sandbox.Sandbox, want sandbox.IsolationClass, required bool) error {
	if !required || sb.IsolationClass().Meets(want) {
		return nil
	}
	err := fmt.Errorf("provider %q reports isolation %s, below SANDBOX_MIN_ISOLATION=%s", sb.Name(), sb.IsolationClass(), want)
	if q, ok := sb.(sandbox.Qualifier); ok && q.Qualification() != "" {
		err = fmt.Errorf("%w; it states: %s", err, q.Qualification())
	}
	return err
}

// qualificationError is nil when the provider states no qualification or one a run
// record can carry (record.ValidQualification), else an error saying why not. Every
// answer and its record state the sentence beside the tier, so the daemon serves none
// without it.
func qualificationError(sb sandbox.Sandbox) error {
	q, ok := sb.(sandbox.Qualifier)
	if !ok || record.ValidQualification(q.Qualification()) {
		return nil
	}
	return fmt.Errorf("provider %q states an isolation qualification of %d bytes that a run record cannot carry: at most %d bytes of UTF-8 with no control or bidirectional format character", sb.Name(), len(q.Qualification()), record.MaxQualificationBytes)
}

// tierKnownBeforeChecks reports whether the provider's tier is known from its configuration
// alone, so SANDBOX_MIN_ISOLATION can be held against it before its startup checks start
// any work: false only for a provider whose descriptor says its checks establish the tier
// (tierFromChecks: docker under runsc, agentsandbox, openshell).
func tierKnownBeforeChecks(sb sandbox.Sandbox) bool {
	f := providers[sb.Name()].tierFromChecks
	return f == nil || !f(sb)
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
	maxConcurrent, err := settings.MaxConcurrent.Get(getenv)
	if err != nil {
		return limiterConfig{}, err
	}
	if err := validateLimiterConfig(maxConcurrent, 0, 0, 0); err != nil {
		return limiterConfig{}, fmt.Errorf("invalid SANDBOX_MAX_CONCURRENT: %w", err)
	}

	totalMB, err := settings.TotalMemoryMB.Get(getenv)
	if err != nil {
		return limiterConfig{}, err
	}
	if totalMB < 0 {
		return limiterConfig{}, fmt.Errorf("SANDBOX_TOTAL_MEMORY_MB=%d must be non-negative", totalMB)
	}
	if totalMB > 0 && !providers[providerName].remoteMemory {
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

	perKey, err := settings.PerKeyConcurrent.GetOr(getenv, settings.PerKeyConcurrentDefault(maxConcurrent))
	if err != nil {
		return limiterConfig{}, err
	}
	ratePerMin, err := settings.RatePerMin.Get(getenv)
	if err != nil {
		return limiterConfig{}, err
	}
	burst, err := settings.RateBurst.GetOr(getenv, ratePerMin)
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
	cert := settings.TLSCert.Get(getenv)
	key := settings.TLSKey.Get(getenv)
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
	raw := settings.MetricsAddr.Get(getenv)
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
	raw := settings.GuardAddr.Get(getenv)
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

// loopbackAddr reports whether a bound listen address (a listener's Addr().String())
// can only be reached from this host: a literal loopback IP and a port. Every caller
// passes the address the listener bound, never the configured string, so a name is
// never accepted: "localhost" can resolve to an address other hosts reach, and an
// empty host (":8746") binds every interface (it reads back as "[::]:8746").
func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loopbackListener reports whether a bound listener can only be reached from this
// host, judged from the address the kernel bound (net.Listener.Addr), never from the
// configured name. plimsolld listens on TCP only; any other kind of address is not
// loopback, so a listener this function does not understand is refused, not served.
func loopbackListener(bound net.Addr) bool {
	tcp, ok := bound.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

// openModeBindError refuses open developer mode (a real provider, no token, no
// callers file, PLIMSOLL_INSECURE=1) on an RPC listener other hosts can reach. Open
// mode authenticates no one, so the loopback bind is its one boundary, and this is
// what enforces it: the Host check in rpc.AuthenticateHTTP answers a browser page's
// DNS rebinding and nothing else, since any program can write that header. It is
// judged from the bound address, so PLIMSOLL_ADDR=localhost:8746 passes only when it
// bound a loopback address, and ":8746" (every interface) is refused. The unset
// address, 127.0.0.1:8746, is loopback, so this is the second guard behind it.
func openModeBindError(bound net.Addr) error {
	if loopbackListener(bound) {
		return nil
	}
	return fmt.Errorf("open mode (PLIMSOLL_INSECURE=1 with no PLIMSOLL_TOKEN or PLIMSOLL_CLIENTS_FILE) serves loopback only, and the RPC listener bound %s, which other hosts can reach: set PLIMSOLL_ADDR=127.0.0.1:8746 (or [::1]:8746) to serve this host only, or set PLIMSOLL_TOKEN or PLIMSOLL_CLIENTS_FILE to require a credential", bound)
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
	// test has produced the evidence it needs, checks every other rule. It skips the
	// guest guard rule too, which waits for the same smoke test.
	IsolationPending bool
	// GuestGuard is what the provider states of plimsoll's guest guard after the smoke test
	// (sandbox.GuestGuarded): its policy word and whether the smoke test proved it in force.
	GuestGuard       string
	GuestGuardProven bool
	MaxConcurrent    int               // effective global concurrency cap
	RatePerMin       int               // effective per-caller rate limit
	Burst            int               // effective per-caller rate burst
	PerCaller        int               // effective per-caller concurrency cap; 0 = none
	Sessions         rpc.SessionConfig // the session settings in force
	// Metered: the provider bills by the second (sandbox.Metered); Uncapped names the
	// callers in PLIMSOLL_CLIENTS_FILE without a paid_seconds_per_day.
	Metered  bool
	Uncapped []string
	// LooseFiles names, one "SETTING: problems" each, the callers, grants and withheld
	// files a user other than the daemon's own or root could change (configfile), as
	// read from the descriptors the daemon opened.
	LooseFiles []string
}

// hardenedFloor is the weakest isolation hardened mode accepts: kernel, the weaker of
// its two allowed levels (vm and verified kernel). Startup checks the provider's proven
// tier against it, and the daemon holds every run to it as a floor (isolationFloor),
// because a provider can read its boundary again on each dispatch (agentsandbox reads its
// runtime class) and find a weaker one than startup proved.
const hardenedFloor = sandbox.IsolationKernel

// isolationFloor is the floor the daemon merges into every request's minimum
// (rpc.SandboxService.Floor): the stronger of hardenedFloor in hardened mode and the
// operator's SANDBOX_MIN_ISOLATION (configured; IsolationUnknown when unset), none when
// neither applies, so a daemon with neither dispatches exactly as before. The operator's
// minimum is checked at startup too, but a startup check alone holds nothing once a
// provider finds a weaker boundary on a later dispatch.
func isolationFloor(hardened bool, configured sandbox.IsolationClass) sandbox.IsolationClass {
	floor := configured
	if hardened {
		floor = max(floor, hardenedFloor)
	}
	return floor
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
	// docker this is true only after the pinned daemon proved a runsc runtime. The
	// same level is the floor the daemon then holds every run to (isolationFloor).
	if !f.IsolationPending && !f.Isolation.Meets(hardenedFloor) {
		fail("provider %q reports isolation %q; hardened mode requires vm (e2b, dockercloud, agentsandbox on a Kata runtime class) or verified kernel (docker with SANDBOX_DOCKER_RUNTIME=runsc, agentsandbox on a runsc runtime class)",
			f.Provider, f.Isolation.String())
	}

	// The guest guard: on a provider whose commands start behind it, the smoke test must have
	// proved its filter in force from a program started as the code is (docker's
	// smokeGuestGuard). Without it, code could make a namespace and a mount of its own under
	// gVisor, and a folder with no noexec mark in it.
	if desc := providers[f.Provider]; desc.guestGuard && !f.IsolationPending && !f.GuestGuardProven {
		fail("hardened mode requires plimsoll's guest guard proven in force on provider %q (the filter in front of every program plimsoll starts in a sandbox, which refuses the code namespaces, mounts, clone3 and tracing), and the startup smoke test did not prove it; restart so the smoke test runs, and read its error",
			f.Provider)
	}

	// Identity: a single shared token collapses every caller into one principal,
	// which defeats per-caller limits, grant ACLs, per-session minting, and audit.
	if !f.MultiClientAuth {
		fail("hardened mode requires multi-client auth: set PLIMSOLL_CLIENTS_FILE (a shared PLIMSOLL_TOKEN or open dev mode is not a production identity)")
	}
	if settings.Insecure.Set(getenv) {
		fail("PLIMSOLL_INSECURE must not be set in hardened mode")
	}

	// The files that decide who may call and what a run may reach: one another local user
	// can change hands that user a caller of their own at the next restart, so hardened
	// mode holds them to OpenSSH's rule for authorized_keys (internal/settings/configfile).
	for _, loose := range f.LooseFiles {
		fail("hardened mode refuses a file another user of this machine could change (%s): make the file and every directory named owned by root or the daemon's user, and remove their group and others write bits (chmod go-w)", loose)
	}

	// Transport: bearer tokens on cleartext are replayable by anyone on the path.
	// A listener that bound a loopback address is exempt, mirroring the official
	// client's policy; main passes the bound addresses, so a name is never exempt.
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

	// Immutable execution surface, per provider (providerDescriptor).
	desc := providers[f.Provider]
	if desc.hardened != nil {
		desc.hardened(getenv, fail, func(err error) { violations = append(violations, err) })
	}
	if desc.pinnedImages {
		pinned, err := settings.RequirePinnedImages.Get(getenv)
		if err != nil {
			violations = append(violations, err)
		} else if !pinned {
			fail("hardened mode requires SANDBOX_REQUIRE_PINNED_IMAGES=1 so the %s image is an immutable @sha256 digest", f.Provider)
		}
	}

	// Explicit budgets: provider defaults are development conveniences. A hardened
	// deployment states its per-run envelope and (for on-host runners) the
	// aggregate memory budget so capacity is a decision, not an accident.
	required := desc.hardenedEnvelope
	if required == nil {
		required = hardenedEnvelopeDefault
	}
	if desc.hardenedEnvelopeAt != nil && !f.IsolationPending {
		required = append(slices.Clone(required), desc.hardenedEnvelopeAt(f.Isolation)...)
	}
	var missing, nonPositive []string
	for _, size := range required {
		set, positive := size.Positive(getenv)
		name := settings.NameOf(size)
		if !set {
			missing = append(missing, name)
			continue
		}
		// Zero means "provider default" or "no cap" to the factory, which is not an
		// operator's chosen envelope.
		if !positive {
			nonPositive = append(nonPositive, name)
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
	if f.MaxConcurrent < 2 {
		// The two checks below cannot both pass at one slot, and their messages sent an
		// operator in a circle (review, 2026-10-26).
		fail("hardened mode requires SANDBOX_MAX_CONCURRENT of at least 2, so a per-caller cap can sit below it")
	} else if f.PerCaller <= 0 {
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
var hardenedEnvelopeFor = map[string][]settings.Size{
	// docker enforces the whole envelope, and its runners share this host, so the
	// aggregate budget that clamps concurrency is required too.
	"docker": {settings.MemoryMB, settings.CPUs, settings.DiskMB, settings.Pids, settings.TotalMemoryMB},
	// E2B cannot enforce a process limit, so Build rejects SANDBOX_PIDS there.
	"e2b": {settings.MemoryMB, settings.CPUs, settings.DiskMB},
	// Docker Cloud Sandboxes expose no disk or process control.
	"dockercloud": {settings.MemoryMB, settings.CPUs},
}

// hardenedEnvelopeDefault applies to a provider in neither table (wasm, disabled),
// which the isolation rule refuses anyway.
var hardenedEnvelopeDefault = []settings.Size{settings.MemoryMB, settings.CPUs, settings.DiskMB}

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
	max, err := settings.MaxSessions.Get(getenv)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	perCaller, err := settings.MaxSessionsPerCaller.Get(getenv)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	perOwner, err := settings.MaxSessionsPerOwner.Get(getenv)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	diskMB, err := settings.SessionDiskMB.Get(getenv)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	lifetime, err := settings.SessionLifetime.Get(getenv)
	if err != nil {
		return rpc.SessionConfig{}, err
	}
	idle, err := settings.SessionIdle.Get(getenv)
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
	n, err := settings.SessionPool.Get(getenv)
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

// loadPaidConfig reads SANDBOX_PAID_SECONDS_PER_DAY and checks what needs no running
// sandbox about a provider billed by the second (metered), so a misconfigured daemon
// is refused before its smoke test creates a billed microVM: the allowance set for a
// provider that does not bill (a setting that does nothing must not look applied), and
// sessions on one that does with no idle timeout, which the service refuses at every
// open since such a session would bill for its whole lifetime. Sessions on a metered
// provider draw on the allowance (internal/rpc sessionMeter: the open, each call, the
// idle time); this used to refuse them outright, from before they were metered
// (review, 2026-10-23).
func loadPaidConfig(getenv func(string) string, metered bool) (int64, error) {
	paid, err := settings.PaidSecondsPerDay.Get(getenv)
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
		n, err := settings.MaxSessions.Get(getenv)
		idle, ierr := settings.SessionIdle.Get(getenv)
		if err == nil && ierr == nil && n > 0 && idle == 0 {
			return 0, errors.New("SANDBOX_SESSION_IDLE=0 with sessions on a provider billed by the second: a session that never suspends bills for its whole lifetime, so every open would be refused; set an idle timeout")
		}
	}
	return int64(paid), nil
}
