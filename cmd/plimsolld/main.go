// Command plimsolld serves the plimsoll SandboxService over Connect (h2c, so
// Connect, gRPC, and gRPC-Web clients all work). The execution provider is chosen
// by SANDBOX_PROVIDER (default: disabled; code execution is opt-in).
//
// Authenticated callers need the code:run scope. A real provider refuses to start
// without PLIMSOLL_TOKEN or PLIMSOLL_CLIENTS_FILE unless the operator explicitly
// acknowledges open development mode with PLIMSOLL_INSECURE=1.
//
// The daemon takes no arguments; every setting is an environment variable.
// `plimsolld -h` prints the full reference. That text is the usage constant in
// this file, and a test requires every variable the package reads to appear in it,
// so the binary's own help cannot fall behind the code.
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// usage is what -h prints. It is the daemon's configuration reference; keep every
// variable the package reads listed here (TestUsageNamesEveryVariable enforces it).
const usage = `plimsolld serves the plimsoll SandboxService over Connect (h2c).

Usage: plimsolld [-h]

The daemon takes no arguments. Configuration is by environment variable:

  PLIMSOLL_ADDR              listen address (default :8746, every interface;
                             set 127.0.0.1:8746 for a loopback-only daemon)
  PLIMSOLL_LOG_FORMAT        json (default) or text; the audit stream is a
                             machine-read record and prospector-report consumes
                             newline-delimited JSON. Use text only for eyeballing
                             a local run.
  PLIMSOLL_CLIENTS_FILE      JSON caller registry for multi-client auth (each
                             caller its own principal; managed by plimsoll-clients);
                             takes precedence over PLIMSOLL_TOKEN
  PLIMSOLL_TOKEN             one shared bearer granting code:run to every caller
  PLIMSOLL_INSECURE          =1 explicitly permits a real provider with auth
                             disabled (development only; never expose that listener)
  PLIMSOLL_TLS_CERT / PLIMSOLL_TLS_KEY
                             PEM certificate and key; when set the daemon serves
                             TLS (HTTP/1.1 + HTTP/2 via ALPN) instead of cleartext
  PLIMSOLL_HARDENED          =1 enforces the production policy at startup: vm or
                             verified kernel isolation, multi-client auth, TLS off
                             loopback, pinned images (docker, dockercloud) or an
                             explicit E2B template, no unconfined seccomp, an
                             explicit resource envelope
                             plus aggregate budget, and per-caller rate limiting.
                             Any violation refuses to serve.
  PLIMSOLL_GRANTS_FILE       JSON file of named host-API capability profiles a
                             caller may select via grant_profile

  SANDBOX_PROVIDER           wasm | docker | e2b | dockercloud | (unset = disabled)
  SANDBOX_MIN_ISOLATION      refuse to start unless the provider meets this tier
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
  SANDBOX_REQUIRE_PINNED_IMAGES
                             =1 to refuse mutable image tags (require @sha256:)
  E2B_API_KEY / E2B_TEMPLATE E2B credentials and toolchain template
  E2B_GUARD_URL              absolute HTTPS egress-guard endpoint; enables E2B
                             grants (allowlist plus beta header transform)
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
                             dockercloud grants. A grant run's sandbox may reach
                             only this host; the guest holds a per-run, guard-only
                             credential (Docker's proxy cannot inject one)
  SANDBOX_DOCKERCLOUD_POLICY_URL
                             per-sandbox network-policy REST base; default
                             https://api.sandboxes-cloud.docker.com/v1. Not in
                             Docker's published contract (the sbx CLI's call);
                             every grant run verifies the result through it
  SANDBOX_DOCKERCLOUD_API_URL
                             Docker Cloud Sandboxes management endpoint; required,
                             no default (https://sandboxes.connect.docker.com/sbx
                             answered on 2026-09-24)
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

  SANDBOX_MAX_CONCURRENT     global max in-flight runs (default 8)
  SANDBOX_PER_KEY_CONCURRENT max in-flight runs per caller (default max/2)
  SANDBOX_RATE_PER_MIN       per-caller runs per minute (default 30; 0 = disabled)
  SANDBOX_RATE_BURST         per-caller token-bucket burst (default = rate)
  SANDBOX_TOTAL_MEMORY_MB    aggregate host memory budget for runners; clamps
                             max-concurrent to total/per-run so concurrent runs
                             cannot oversubscribe the host (ignored for e2b and
                             dockercloud, whose runners live off-host)
  SANDBOX_MEMORY_MB / SANDBOX_CPUS / SANDBOX_PIDS / SANDBOX_DISK_MB
                             per-run resource envelope applied to the provider

Endpoints outside auth: GET /healthz (liveness), GET /readyz (provider readiness),
GET /metrics (Prometheus text: run and shed-load counters).
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
		fmt.Fprintf(os.Stderr, "plimsolld: %v\n\n%s", err, usage)
		os.Exit(2)
	} else if help {
		fmt.Print(usage)
		return
	}
	configureLogging(os.Getenv)

	addr := getenv("PLIMSOLL_ADDR", ":8746")

	provider, err := sandbox.Build(os.Getenv)
	if err != nil {
		slog.Error("invalid sandbox configuration", "error", err)
		os.Exit(1)
	}
	sb, res := provider.Sandbox, provider.Resources

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

	// Fail closed if the operator required a minimum isolation tier the selected
	// provider cannot meet (e.g. SANDBOX_MIN_ISOLATION=vm but SANDBOX_PROVIDER=wasm):
	// the whole point of the service is bounding hostile code, so a silent downgrade
	// to a weaker boundary must be a startup error, not a surprise at runtime.
	want, requireMinimum, err := minimumIsolationWith(os.Getenv)
	if err != nil {
		slog.Error("SANDBOX_MIN_ISOLATION is not a valid tier", "error", err, "want", "vm|kernel|container|process")
		os.Exit(1)
	}
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
	// Resolve the effective limiter envelope (env parsing + aggregate-memory clamp +
	// validation) in one typed, unit-tested function so main() only wires the result.
	lc, err := loadLimiterConfig(os.Getenv, sb.Name(), res.MemoryMB)
	if err != nil {
		slog.Error("invalid limiter configuration", "error", err)
		os.Exit(1)
	}
	maxConcurrent, perKey, ratePerMin, burst := lc.MaxConcurrent, lc.PerKey, lc.RatePerMin, lc.Burst
	svc.Limiter = rpc.NewCodeLimiter(maxConcurrent, perKey, ratePerMin, burst)

	gr, err := grants.LoadFromEnv()
	if err != nil {
		slog.Error("failed to load host-API grant profiles", "error", err)
		os.Exit(1)
	}
	svc.Grants = gr
	if gr.Len() > 0 {
		gc, ok := sb.(sandbox.GrantCapable)
		if !ok || (!gc.SupportsJavaScriptGrants() && !gc.SupportsProjectGrants()) {
			slog.Error("grant profiles are configured but the selected provider supports no credential-safe grant path",
				"provider", sb.Name(), "profiles", gr.Len())
			os.Exit(1)
		}
		slog.Info("host-API grant profiles loaded", "count", gr.Len())
	}

	var verifier rpc.TokenVerifier
	multiClientAuth := false
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
		slog.Info("multi-client auth enabled", "clients", fv.Len())
	case os.Getenv("PLIMSOLL_TOKEN") != "":
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

	// Hardened mode: the deploy-time policy for serving hostile code in
	// production. Everything it checks is already resolved evidence — provider
	// isolation post-EnsureReady, the loaded verifier, the effective limiter, the
	// actual transport — so a pass means the properties are in force, not merely
	// configured.
	hardened, err := strictBoolEnv(os.Getenv, "PLIMSOLL_HARDENED")
	if err != nil {
		slog.Error("invalid PLIMSOLL_HARDENED", "error", err)
		os.Exit(1)
	}
	if hardened {
		if err := enforceHardenedPolicy(os.Getenv, hardenedFacts{
			Provider:        sb.Name(),
			Isolation:       sb.IsolationClass(),
			MultiClientAuth: multiClientAuth,
			TLS:             tlsConf != nil,
			Addr:            addr,
			RatePerMin:      ratePerMin,
		}); err != nil {
			slog.Error("hardened-mode policy violation; refusing to serve", "error", err)
			os.Exit(1)
		}
		slog.Info("hardened mode: production policy verified and enforced")
	}

	mux := http.NewServeMux()
	path, handler := plimsollv1connect.NewSandboxServiceHandler(svc,
		connect.WithInterceptors(rpc.AuthInterceptor(verifier)),
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
	// MaxBytesHandler independently caps raw HTTP bytes; Connect's limit is per
	// decompressed message, so neither one substitutes for the other.
	rpcHandler := rpc.AuthenticateHTTP(verifier, rpc.LimitHTTPConcurrency(maxConcurrent*2, handler))
	mux.Handle(path, http.MaxBytesHandler(rpcHandler, maxRequestBytes))
	// The guard URL is public by construction (a microVM must reach it from
	// outside), so it gets the same treatment as the RPC path: it authenticates on
	// the per-run guard credential and bounds concurrent decode work before reading
	// a body. Its own admission lives inside the handler; the bound tracks live
	// granted runs, since a guest awaits each host.* call rather than pipelining.
	if guard, ok := sb.(sandbox.EgressGuardCapable); ok {
		if guardPath := guard.EgressGuardPath(); guardPath != "" {
			mux.Handle(guardPath, sandbox.EgressGuardHTTPHandler(guard, guardPath, maxConcurrent*2))
		}
	}

	// Operational endpoints, registered OUTSIDE the auth interceptor so probes and
	// scrapers need no token. Liveness is unconditional; readiness re-runs the
	// provider's bounded Preflight. Docker probes its pinned daemon/runtime; E2B's
	// current Preflight validates configuration only and does not prove API reachability.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if pf, ok := sb.(sandbox.Preflighter); ok {
			if err := pf.Preflight(r.Context()); err != nil {
				http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		writeMetrics(w, svc)
	})

	srv := newHTTPServer(addr, mux, tlsConf)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Reap execution resources that leaked past the per-run lifecycle (e.g. E2B
	// microVMs whose create response was malformed or whose teardown retries all
	// failed). The provider guarantees it only ever destroys resources this
	// instance created and no longer tracks, so the loop is safe alongside
	// in-flight runs.
	if rec, ok := sb.(sandbox.OrphanReconciler); ok {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
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

	go func() {
		// Echo the EFFECTIVE (post-clamp) limiter and resource envelope so a
		// fat-fingered env var is visible in the logs rather than silently
		// defaulting. The resource envelope only applies to providers that enforce it
		// (docker/wasm); E2B sizes CPU/RAM/disk at the template level, so advertise
		// that instead of caps that are not in force.
		args := []any{
			"addr", addr,
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
			args = append(args,
				"resources", "requested at create and verified after it; 0 = backend default",
				"max_mem_mb", res.MemoryMB,
				"max_cpus", res.CPUs,
				"disk_and_pids", "unsupported (non-zero fails startup)",
			)
		default:
			args = append(args, "mem_mb", res.MemoryMB, "cpus", res.CPUs, "pids", res.PidsLimit, "disk_mb", res.DiskMB)
		}
		args = append(args, "tls", tlsConf != nil)
		slog.Info("plimsolld listening", args...)
		serve := srv.ListenAndServe
		if tlsConf != nil {
			// The keypair is already loaded into TLSConfig; empty paths are correct.
			serve = func() error { return srv.ListenAndServeTLS("", "") }
		}
		if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	stop() // restore default handling so a second signal force-quits the drain
	slog.Info("shutdown signal received; draining in-flight runs")
	// Drain rather than kill: in-flight runs finish on their own goroutines, so
	// their deferred cleanup (containers, e2b microVMs, temp dirs) actually runs
	// instead of leaking on an abrupt exit.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown timed out; forcing close", "error", err)
		_ = srv.Close()
	}
	slog.Info("plimsolld stopped")
}

// newHTTPServer configures the daemon's HTTP server. With a TLS config it serves
// HTTPS with HTTP/1.1 + HTTP/2 negotiated via ALPN; without one it enables Go's
// native cleartext HTTP/2 alongside HTTP/1.1. Do not replace the cleartext path
// with x/net/http2/h2c.NewHandler: that upgrade wrapper reads the first h2c
// request body entirely into memory before the handler runs, bypassing
// AuthenticateHTTP and Connect's request-size limit. Native protocol selection
// handles HTTP/2 prior knowledge without a pre-handler body read.
func newHTTPServer(addr string, handler http.Handler, tlsConf *tls.Config) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	if tlsConf != nil {
		protocols.SetHTTP2(true)
	} else {
		protocols.SetUnencryptedHTTP2(true)
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		Protocols:         protocols,
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second, // includes bounded request body; stops slow uploads
		WriteTimeout:      6 * time.Minute,  // above the RPC hard ceiling + response write
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
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
