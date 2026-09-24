package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

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
// runners live off-host). It returns a typed error instead of exiting, so callers
// decide how to fail.
func loadLimiterConfig(getenv func(string) string, providerName string, perRunMemMB int) (limiterConfig, error) {
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
		fit := totalMB / perRun
		if fit < 1 {
			return limiterConfig{}, fmt.Errorf("SANDBOX_TOTAL_MEMORY_MB=%d cannot fit even one %d MiB run", totalMB, perRun)
		}
		if fit < maxConcurrent {
			slog.Warn("clamping max concurrency to the aggregate memory budget",
				"total_mb", totalMB, "per_run_mb", perRun,
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

// strictBoolEnv parses an opt-in boolean env var; anything but 0/1/false/true
// (or empty = false) is a startup error, so a typo can never silently disable a
// safety opt-in.
func strictBoolEnv(getenv func(string) string, key string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(getenv(key))) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be one of 0, 1, false, or true", key)
	}
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
	RatePerMin      int                    // effective per-caller rate limit
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
	if f.Isolation != sandbox.IsolationVM && f.Isolation != sandbox.IsolationKernel {
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

	// Immutable execution surface, per provider.
	switch f.Provider {
	case "docker":
		pinned, err := strictBoolEnv(getenv, "SANDBOX_REQUIRE_PINNED_IMAGES")
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
		pinned, err := strictBoolEnv(getenv, "SANDBOX_REQUIRE_PINNED_IMAGES")
		if err != nil {
			violations = append(violations, err)
		} else if !pinned {
			fail("hardened mode requires SANDBOX_REQUIRE_PINNED_IMAGES=1 so SANDBOX_DOCKERCLOUD_IMAGE is an immutable @sha256 digest")
		}
	case "e2b":
		// E2B offers no digest pinning; an explicit template (never the implicit
		// "base" default) is the strongest surface selection available. The startup
		// SmokeTest then proves that template behaves.
		if strings.TrimSpace(getenv("E2B_TEMPLATE")) == "" {
			fail("hardened mode requires an explicit E2B_TEMPLATE (the implicit \"base\" default is not a pinned execution surface)")
		}
	}

	// Explicit budgets: provider defaults are development conveniences. A hardened
	// deployment states its per-run envelope and (for on-host runners) the
	// aggregate memory budget so capacity is a decision, not an accident.
	required := []string{"SANDBOX_MEMORY_MB", "SANDBOX_CPUS"}
	if f.Provider != "dockercloud" {
		// Docker Cloud Sandboxes expose no disk control, so Build rejects
		// SANDBOX_DISK_MB for dockercloud; requiring it would make hardened mode
		// unsatisfiable there.
		required = append(required, "SANDBOX_DISK_MB")
	}
	if f.Provider == "docker" {
		// E2B cannot enforce pids (Build rejects it there); docker can and must.
		required = append(required, "SANDBOX_PIDS", "SANDBOX_TOTAL_MEMORY_MB")
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
	}

	if len(violations) > 0 {
		return errors.Join(violations...)
	}
	return nil
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
