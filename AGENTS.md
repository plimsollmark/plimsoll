# plimsoll — agent guide

> **This file is the source of truth for *what this is*:** architecture, providers,
> invariants. It is vendor-neutral, and it is published with the repository, so it
> describes the component and nothing about any particular deployment of it.

Standalone code-execution sandbox service: the **one** place that runs untrusted,
agent-authored code with an explicitly reported isolation tier, callable over RPC.
Hostile production deployments require the verified kernel or VM tiers; the WASM
option is intentionally only process-tier.

- Go module `github.com/plimsollmark/plimsoll`. The go.mod **floor is 1.26.2** (so
  sibling consumers that `replace` this module build unchanged), but the **canonical
  build pins the 1.26.6 toolchain** (`toolchain go1.26.6`): `govulncheck ./...` is
  clean there, while earlier 1.26.x had stdlib advisories in the reverse-proxy and
  HTTP/2 paths this TCB actually calls. Build plimsolld with >= 1.26.6.
- Direct dependencies are Connect, protobuf, wazero, and `golang.org/x/net`;
  `x/sys` and `x/text` are indirect. Do not add dependencies casually: this is a
  hostile-code TCB.
- **`github.com/fastschema/qjs` is banned.** Its `MemoryLimit` is a no-op. Drive
  wazero directly with `WithMemoryLimitPages` for a real per-run memory cap.

## Layout
- [sandbox/](sandbox/) — the package (`package sandbox`). Deliberately
  **transport-agnostic**: no Connect/HTTP types, so the same providers back an
  RPC, a CLI, or a test.
  - [sandbox/sandbox.go](sandbox/sandbox.go) — the `Sandbox` interface and shared
    request/result types (`Request`, `ProjectRequest`, `Result`, `ProjectResult`,
    `HostAPIGrant`).
  - [sandbox/factory.go](sandbox/factory.go) — `Build()` checked provider selection
    (returns `Provider{Sandbox, Resources}` plus an explicit error; `EnsureReady`
    bundles Preflight + SmokeTest for local embedders).
  - [sandbox/wasm.go](sandbox/wasm.go) — in-process QuickJS/WASM provider.
  - [sandbox/docker.go](sandbox/docker.go) — locked-down `docker run` provider.
  - [sandbox/e2b.go](sandbox/e2b.go) — E2B Firecracker microVM provider.
  - [sandbox/disabled.go](sandbox/disabled.go) — refuses to execute (the default).
  - [sandbox/broker.go](sandbox/broker.go) — provider-neutral per-run host-API
    enforcement core (allowlist, credential injection, budgets, upstream HTTP,
    metadata trace); providers supply only framing adapters.
  - [sandbox/capability.go](sandbox/capability.go) — the generic injected host-API
    client and capability validation.
  - [sandbox/wasm/qjs-wasi.wasm](sandbox/wasm/) — embedded QuickJS-ng WASI build
    (`//go:embed`); MIT plus a minimal checked-in host-call shim. Rebuild from
    pinned inputs with [sandbox/wasm/build.sh](sandbox/wasm/build.sh).
- [cmd/plimsoll-clients/](cmd/plimsoll-clients/) — offline operator CLI over the
  caller registry the daemon loads from `PLIMSOLL_CLIENTS_FILE`; the shared format
  and validation live in [internal/clientconfig/](internal/clientconfig/). Usage:
  [docs/callers.md](docs/callers.md).
- [docker/](docker/) — build recipe for the project-run toolchain image:
  [docker/Dockerfile](docker/Dockerfile) (node + tsc/tsx/eslint, baked in so
  runtime needs no egress) and [docker/runner.mjs](docker/runner.mjs) (the
  in-sandbox multi-file project runner).
- [examples/](examples/) — four runnable programs: `minimal` (one snippet and the
  tier it ran behind), `grant` (the capability model, including a guest bypassing
  the injected client and being refused by the broker anyway, then the identical
  request succeeding under a separate per-run grant that lists it), `daemon` (the
  full service path with auth, `Describe`, and an isolation floor being refused),
  and `advisor` (the efficiency advisor over a loopback daemon: a per-item loop,
  the finding that names the granted collection route, the rewrite, and the API's
  own request count as the witness).
- [docs/trainers/](docs/trainers/) — dependency-free interactive lessons covering
  the execution model, architecture, providers, capabilities, operations,
  dependencies, MCP/agent integration, customer patterns, and product planning.
  The pricing lesson is a planning hypothesis, not a current commercial offer.

## The `Sandbox` interface
Every provider implements [sandbox/sandbox.go](sandbox/sandbox.go):
- `RunJavaScript(ctx, Request) (Result, error)` — run a JavaScript snippet (Node
  on Docker/E2B, QuickJS on WASM).
- `RunProject(ctx, ProjectRequest) (ProjectResult, error)` — write a multi-file
  project, then run build/lint/run steps in order (stop on first failure).
- `Name() string` — the provider id.

Result semantics: a non-zero `ExitCode` is a **normal result** (the user's code
failed), not a Go `error`. Returned errors cover typed pre-dispatch failures
(`ErrInvalidRequest`, `ErrUnsupported`, `ErrDisabled`, `ErrAtCapacity`), context
cancellation/deadline, and unmatched infrastructure failures. For projects,
per-step failures live in `Steps` and the top-level conclusion is the typed
`ProjectResult.Outcome` (`completed` / `setup_failed` / `timed_out` /
`protocol_error`, with human context in `Detail`) — a stable retry/status
classification. Output truncation is machine-readable everywhere: results carry
`StdoutTruncated`/`StderrTruncated` (and `ArtifactsTruncated`) flags and the
retained output is never annotated with in-band markers. On the wire,
stdout/stderr are protobuf `bytes`, so arbitrary guest bytes survive verbatim
instead of being lossily repaired into UTF-8. An E2B guest that floods its
output stream past the transfer budget is classified as a failed user run
(exit 153, both streams marked truncated), not an infrastructure error.

## Providers (`SANDBOX_PROVIDER`)
`Build(getenv)` selects one and fails closed: malformed safety configuration and
unrecognized provider names are explicit errors, and the default (unset) is
**Disabled**, so execution is opt-in and never on by accident.

| Value     | Provider | Isolation | Notes |
|-----------|----------|-----------|-------|
| `wasm`    | in-process QuickJS via wazero | process tier, lowest latency | JS snippets and snippet grants through a direct host function; no projects. An engine escape lands in plimsolld. |
| `docker`  | locked-down `docker run` | container under runc; kernel tier only after verified runsc Preflight | self-host/dev. Snippet and project JS grants both use a host-side Unix broker; a project preloads the same client into every step (`node --import`). Under runsc the runtime must be registered with `--host-uds=open` (the installer does) or the guest cannot reach the broker socket; the smoke test proves it can. |
| `e2b`     | E2B Firecracker microVM | hardware-virtualized VM | isolated snippets/projects; grants require `E2B_GUARD_URL` and use E2B `allowOut` + deny-all plus the beta per-host header transform to reach the guard, which delegates the shared broker. Secured envd + public-traffic token; no-grant egress denied. Sandboxes are stamped with a per-instance metadata ID; `ReconcileOrphans` (run periodically by the daemon) reaps stamped, untracked microVMs that leaked past a malformed create response or failed teardown. |
| unset     | Disabled | n/a | returns `ErrDisabled`; any other value fails `Build`. |

Relevant env: `SANDBOX_DOCKER_IMAGE`, `SANDBOX_DOCKER_PROJECT_IMAGE`,
`SANDBOX_DOCKER_RUNTIME` (`runsc` for a real gVisor boundary),
`SANDBOX_DOCKER_SECCOMP` (path to a syscall-filter profile; set it
to the shipped audited allowlist `docker/seccomp.json` to deny non-cap-gated attack
surface like `ptrace`/`io_uring`/`keyctl` — see [docs/seccomp.md](docs/seccomp.md)),
`SANDBOX_REQUIRE_PINNED_IMAGES` (`=1` to require both images to be
`@sha256:`-pinned),
`E2B_API_KEY`, `E2B_TEMPLATE`, `E2B_GUARD_URL` (the guard is **process-local**: a run's
guard credential lives only in the memory of the process that opened that run, so the
public guard URL must resolve to that same process — an ordinary load balancer across
replicas rejects valid guard calls as unknown credentials), `PLIMSOLL_GRANTS_FILE` (named host-API capability
profiles selectable via `grant_profile`), and dev-only `PLIMSOLL_INSECURE=1`
(explicitly permits a real provider without auth). Operational knobs: `SANDBOX_MIN_ISOLATION`
(refuse to start below a tier: `vm|kernel|container|process`), the per-run resource
envelope `SANDBOX_MEMORY_MB`/`SANDBOX_CPUS`/`SANDBOX_PIDS`/`SANDBOX_DISK_MB`
(for docker, `SANDBOX_DISK_MB` is the run's **aggregate** writable-storage budget:
`/tmp` + `/dev/shm` + `/work` must fit inside it, `/work` defaults to the
remainder, and every writable mount is a sized `noexec` tmpfs — images declaring
`VOLUME`s are rejected at Preflight because docker would auto-create unbounded
writable host volumes for them, and every run launches the content-addressed
image ID that Preflight actually inspected, so re-pointing a mutable tag cannot
smuggle an unverified image past that check), the
limiter `SANDBOX_MAX_CONCURRENT`/`SANDBOX_PER_KEY_CONCURRENT`/`SANDBOX_RATE_PER_MIN`/
`SANDBOX_RATE_BURST`, and the aggregate budget `SANDBOX_TOTAL_MEMORY_MB` (clamps
max-concurrent to total/per-run so concurrent runners cannot oversubscribe the host;
ignored for e2b, whose runners live off-host). Each provider reports its boundary via
`IsolationClass()` and in the RPC response `isolation` field, and the **`Describe`
RPC** reports the active provider, tier, project support, and operation-specific
grant support (via `ProjectCapable` / `GrantCapable`) so a gateway does not
hard-code claims. **A reported tier is configuration and provider evidence plus the
behavioral smoke tests below — never runtime attestation**, and any surface that
advertises a tier has to carry that qualification (README states it in full under the
provider table). It also advertises minimum-isolation protocol support; this is
discovery only. Execution uses only the versioned `RunJavaScriptV2` /
`RunProjectV2` procedures, so an old backend returns Unimplemented before code can
run rather than silently ignoring a new request field. The daemon serves `GET /healthz`, `/readyz`,
`/metrics` outside auth. `/readyz` re-runs the provider's bounded `Preflight`: for docker
that probes the pinned daemon and runtime, but for e2b it validates **configuration only**
and proves nothing about API reachability, key validity, or guard routability — the
behavioral proof is the one-shot startup `SmokeTest`, which creates a real billable
microVM and so must never run on an unauthenticated poll path. `Describe` reports current isolation evidence but only
structural/static operation support. Both real providers run a startup
**`SmokeTest`** (behavior, not just configuration) via `EnsureReady`, and neither
serves if it fails. For docker: one throwaway lockdown container per configured
image (launched by its Preflight-verified content ID), under the exact
runtime/seccomp combination, must prove from its own mount table that the root fs
is read-only and every writable mount is a tmpfs with the exact promised size +
`noexec`/`nosuid` — and, by attempting a real write at every mount point, that
the promised mounts are the **only** ones that accept writes at all (device-node
mounts like docker's `/dev/null`-masked proc paths are excluded: their writes
discard rather than persist); Preflight also requires both images to be present
(inspectable) on the pinned daemon. The first probe container also mounts a
throwaway host Unix socket exactly as a run mounts the per-run broker socket and
must reach it: whether a guest may connect to a host socket is a runtime property
(runsc needs `--host-uds=open`, which `docker/install-gvisor.sh` sets), and a runtime
that cannot broker grants must refuse to serve rather than fail every grant run.
Under runsc the first probe container also
reads one bounded line of `dmesg` and logs it (`DockerSandbox.RuntimeBanner`).
That line is diagnostic identity information for an operator's log and nothing
more: gVisor's own documentation says the banner is trivially forged, so it never
authorizes the kernel tier, never replaces the mount and write checks, and an
unreadable banner does not fail readiness. Under runc it is not attempted. For e2b: one throwaway microVM must
complete secured create (both access tokens), live resource verification,
multi-file staging into the project dir, and a probe run through the exact
project-step path (`sh` script → node) — proving the configured template bakes
the toolchain, honors the step cwd, and (checked live) actually denies egress.
`plimsolld -h` prints the full env list; the text is the `usage` constant in
[cmd/plimsolld/main.go](cmd/plimsolld/main.go), and a test fails if the package
reads a variable that text omits. The daemon refuses any other argument.

**Hardened mode (`PLIMSOLL_HARDENED=1`)** turns the soft production posture into
an enforced startup policy: a warning is not a policy. It refuses to serve unless
every advertised production property is verifiably in force — `vm` or verified
`kernel` isolation (post-`EnsureReady` evidence, so docker means proven runsc),
multi-client auth (`PLIMSOLL_CLIENTS_FILE`; a shared token or open dev mode is
rejected), TLS on any non-loopback listener, an immutable execution surface
(docker: `SANDBOX_REQUIRE_PINNED_IMAGES=1`, no `unconfined` seccomp; e2b: an
explicit `E2B_TEMPLATE`), an explicit per-run resource envelope plus aggregate
memory budget, and per-caller rate limiting. Every violation is reported at once
(one fix pass, not a startup loop). TLS itself is configured with
`PLIMSOLL_TLS_CERT`/`PLIMSOLL_TLS_KEY` (both-or-neither; loaded and validated
at startup); with them the daemon serves HTTP/1.1 + HTTP/2 over TLS instead of
cleartext h2c.

`Request.MinimumIsolation` / `ProjectRequest.MinimumIsolation` (wire field
`minimum_isolation`) are per-dispatch security floors. The RPC handler compares the
floor with current provider evidence immediately before admission and dispatch;
`ErrInsufficientIsolation` means no hostile code ran. `SANDBOX_MIN_ISOLATION` is
the daemon's operator-wide startup floor; it is not a substitute for a caller's
per-run requirement. Consumers such as Control also stamp it onto each request so
a stale `Describe` or readiness result cannot authorize a later downgrade. The
official client also checks returned evidence; a mismatch is
`ErrIsolationEvidenceMismatch`/DataLoss and means execution may already have
occurred, so it is never a safe automatic-retry signal.

## Capability model (`HostAPIGrant`)
A grant is a **per-run** capability: it rides on `Request.Grant` /
`ProjectRequest.Grant`, not on provider state, so authority is selected independently
for each dispatch. (Two runs may intentionally select the same profile or static
token.) Without one the run is **fully isolated (no network)**. A `HostAPIGrant` is
opt-in and **domain-agnostic**: it lets agent code call an HTTP host API via an
injected generic client (`host.get/put/post/del/call`).
It is **off by default twice over**: a nil grant means no network, and a grant with
an empty `Allow` list reaches nothing — the embedder injects the exact routes it
permits (`[]HostRoute`, with `*` wildcard segments). The shared broker accepts only
decoded, canonical paths whose Go HTTP request target is byte-identical to the
approved string; queries, traversal, percent encodings, and characters that would
be wire-encoded are rejected before upstream dispatch. An optional `Preamble` lets
an embedder layer a domain SDK on top of the generic client.

The `allow` list, the `Preamble`, and the model-facing tool description a gateway
shows the agent all describe the same surface and otherwise drift. The **spec-import
generator** ([internal/specgen](internal/specgen/), CLI
[cmd/plimsoll-specgen](cmd/plimsoll-specgen/)) derives all three from one OpenAPI
3.x document — path params become whole-segment `*` routes, operations become typed
`globalThis[global]` methods, summaries become the description. It is deterministic and
offline (no server fetch, no credential), and enforces its **supported subset at parse
time** rather than emitting a method that cannot run: it reports rather than drops verbs
the broker can't enforce (grants allow GET/PUT/POST/DELETE/PATCH; HEAD/OPTIONS/TRACE are
skipped with a warning) and operations requiring a query/header/cookie parameter (a
brokered call sends a literal path and no headers, so such an operation is unreachable),
warns when optional ones are dropped, and errors on a `$ref` path item or parameter rather
than letting it vanish from the surface. Generated argument names are sanitized and
deconflicted against the client binding and JS reserved words, a body argument is emitted
only when the operation declares a request body, and an `operationId` naming one of the
injected client's own methods (`get`/`put`/`post`/`patch`/`del`/`call`) is refused. The
generated SDK is **executed in QuickJS by the tests**, so a preamble that does not parse or
throws on its first call fails the build. `-emit catalog` gives the full route list for a
profile's `catalog` (see the advisory channel). It emits an optional concrete `health_check`
recovery probe only for the operation explicitly marked `x-plimsoll-health-check: true`;
`-emit health` outputs that profile line. Worked example:
[docs/examples/specgen](docs/examples/specgen/).

**Backpressure.** A grant's optional concrete `HealthCheck` GET route (profile
`health_check`) drives a per-run circuit breaker: an upstream 429/503 opens it for a
cooldown (honoring `Retry-After`, capped at 30s) and the broker *sheds* further permitted
calls (fast 503) rather than pile onto a struggling API. **The two statuses recover
differently, because the probe answers only one of their questions.** A 503 says the
service is degraded, which the health route can speak to: while shedding, one elected
caller per second probes it host-side and a 2xx closes the breaker early. A 429 says this
caller has spent its allowance, which a healthy service says nothing about, so that window
is never probed and is waited out — reopening it on a 200 would push the run's traffic
straight back into the limiter that asked it to back off. For the same reason specgen will
not guess a probe from an endpoint's name. The probe uses the run's credential but is
neither traced nor charged to the call budget. Sheds are counted in `CallTrace.Shed`
(distinct from a policy `Denied`) and surfaced as `host_calls_shed` on the audit line.

Grant `BaseURL`s are canonical origins only (scheme + host + optional port; no
userinfo/path/query/fragment), with HTTPS required off loopback, so every provider
authorizes and sends the same route without exposing a bearer on cleartext transport.
Each declared scope is exactly one whitespace-free token.

**Credential = minted per run.** The grant carries a `TokenMinter`, not a static
token: plimsoll calls `Mint` once per run with that run's scope, so prefer
short-lived, route-scoped tokens (an exfiltrated credential then dies almost
immediately). `StaticToken(value)` is the degenerate minter for host APIs without
real minting. `HostAPIGrant.Validate` rejects a grant whose declared `Scopes`
include `code:run` or `*`.

**Enforcement is shared; transports are narrow.** `brokerSession` owns the frozen
per-run grant, minted token, exact approve==wire check, proxy-free/no-redirect
upstream request, traffic budgets (max 256 calls, 1 MiB request, 4 MiB response),
and metadata-only trace. Docker JavaScript keeps `--network none` and frames calls
over a per-run Unix socket. WASM JavaScript uses a direct, quota-bounded wazero
host function; only `{method,path,body}` and the bounded response cross WASM linear
memory, while the credential remains in Go and never enters QuickJS. Both adapters
delegate authority to the same core. Docker **project** runs get grants too: the
runner preloads the same client module into every step process (`node --import`,
generated host-side from the grant), so project files reach the host API through the
identical `host.*` global over the same per-run socket, and the minted token never
enters the container. WASM project grants stay rejected (no project toolchain). E2B
grants **are supported when `E2B_GUARD_URL` is configured** and rejected
(`ErrUnsupported`) when it is not: the guard is the forced, authenticated channel that
keeps both the credential and route enforcement outside the hostile VM, and it
delegates to the same shared broker. `SupportsJavaScriptGrants` reports exactly that
condition rather than a constant. No-grant E2B runs deny egress and public traffic.

**Over RPC:** a caller selects a **named, server-side profile** via the
`grant_profile` request field; profiles are loaded from `PLIMSOLL_GRANTS_FILE`
(see [internal/grants](internal/grants/)). The registry is frozen after load:
`Profile.Grant()` returns a deep copy per dispatch, so nothing downstream can
mutate a loaded profile for later runs. The caller can only *select* a profile —
BaseURL, allowed routes, and the token all live server-side. A raw caller-supplied
grant is intentionally **not** accepted over the wire. Every profile also requires
an `allowed_callers` ACL of authenticated principal IDs; `code:run` alone does not
grant downstream capabilities. Each profile's `token` config
chooses how the credential is produced: `static` (one shared bearer from an env var)
or `jwt` (a fresh short-lived HS256 JWT minted per run with the calling principal as
`sub` and the profile's scopes as a `scope` claim — the per-session model; the RPC
layer stamps the principal via `sandbox.WithSubject`). Custom minters implement
`sandbox.TokenMinter`.
The Go client selects profiles per operation with
`client.WithJavaScriptGrantProfile` / `WithProjectGrantProfile`; passing a raw
`Request.Grant` to `client.Remote` fails instead of silently dropping authority.
`client.New` is checked: it returns `(*Remote, error)`, accepts only absolute
HTTP(S) URLs, and refuses non-loopback cleartext unless the caller explicitly opts
into development-only `client.WithInsecureHTTP()`.

## RPC server (`cmd/plimsolld`)
`plimsolld` serves the `plimsoll.v1.SandboxService` (see
[proto/plimsoll/v1/sandbox.proto](proto/plimsoll/v1/sandbox.proto)) over
Connect/h2c. Auth is **fail-closed** when configured (callers need the `code:run`
scope; see [internal/rpc/auth.go](internal/rpc/auth.go)). Verifier precedence:
`PLIMSOLL_CLIENTS_FILE` (multi-client — each caller is its own principal, a JSON
list of `{id, token_sha256, scopes}`; see
[docs/clients.example.json](docs/clients.example.json) and
[internal/rpc/clients.go](internal/rpc/clients.go)) → `PLIMSOLL_TOKEN` (one shared
token) → open dev mode (logs a warning). The multi-client verifier is what makes
per-session token minting real: each client's `id` becomes its `Principal.UserID`,
which the service stamps as the minted token's `sub`. Tokens are stored as SHA-256
hex, so the file holds no live secrets. The file is managed offline by
[cmd/plimsoll-clients](cmd/plimsoll-clients/) (`create`, `import`, `list`, `rotate`,
`revoke`), which shares its parser and validator with the verifier through
[internal/clientconfig](internal/clientconfig/), emits a generated token only on an
explicitly requested stdout, and stores fingerprints only; the daemon reads the file
once at startup, so every change needs a restart to take effect
([docs/callers.md](docs/callers.md)). Generated code lives in `gen/go` (regenerate
with `buf generate`; local plugins, no network).

Every run is **audit-logged** (`slog`): one structured line per RunJavaScript/
RunProject with the caller (principal UserID, never the token), code/file sizes,
`grant_profile`, provider, exit code, timed-out, and duration — never the code
contents. Raw HTTP bodies and decompressed Connect messages are independently
capped. HTTP middleware authenticates before Connect reads the body, bounds
concurrent decode work, and the server applies a whole-body read deadline. Go's
native unencrypted HTTP/2 supports prior-knowledge h2c; HTTP/1.1 Upgrade h2c is not
supported.

## Advisory channel (Prospector)
The efficiency advisor turns the capability broker into an API-usage coach. It is
**post-dispatch analysis over metadata plimsoll already holds**, never a new data
path into guest content. The pipeline:

1. **Data foundation.** The shared broker records a bounded, metadata-only
   `CallTrace` per run (`sandbox/calltrace.go`): the matched route *template* for
   each brokered `host.*` call plus verb, status, whether the broker delivered the
   response to the guest, byte counts, and latency. A call the broker refused to
   deliver (no upstream answer, an oversized or unreadable body) keeps its row and
   its upstream status, marked undelivered, so a capped 200 is never read as a
   successful call. `CallRow` has **no field** for a path, query, body, or credential,
   so none can enter the trace by construction. Attached to `Result.CallTrace`
   (snippets) and `ProjectResult.CallTrace` (projects); discarded after the response.
2. **Detectors.** `insights.Analyze(trace, allow)` ([internal/insights](internal/insights/))
   runs two deterministic detectors, fan-out/N+1 over a per-item route and repeated
   reads of one fixed route, each emitting a `Finding` (pattern/severity/cost/remedy).
   Both count only calls the broker delivered with a 2xx status: failed calls are
   named in the finding's sentence and never counted as records retrieved, and a
   trace that hit its row cap reports its count as "at least". Each finding stands on
   its own (method, route) group, so a run's findings never describe the same call
   twice and their costs sum without double counting. A finding's cost compares the
   measured pattern with an assumed ideal of one call, never a measured one:
   `ExtraCalls` is the successful count minus one (rigorous when a granted collection
   route is named and returns the same items), `AddedLatency` is summed round trips
   beyond one call (a model, not wall time lost), `BytesMoved` is the gross bytes the
   pattern moved (not a saving). The former aggregate-in-code and sequential-calls
   detectors were deleted on 2026-09-16: the trace holds no call start times, so it
   cannot tell serial calls from concurrent ones, and no guest content, so it cannot
   tell a client-side reduce from any other loop. A small router asks one question
   from the profile's `Allow` list, for a **GET** fan-out only: does the collection
   route already exist? If so the finding is **agent-fixable** (`Finding.Suggested`
   set) and states its condition, that the collection route must return the same
   items, which plimsoll does not verify. A write fan-out is never routed, granted or
   catalogued: a collection write's semantics cannot be read off its path, so it stays
   unrouted until an explicit operation relationship exists. When a profile also declares
   a `catalog` (its full endpoint list, e.g. `plimsoll-specgen -emit catalog`), a finding
   whose batch route the catalog exposes but the grant omits is annotated with the concrete
   route to add (`Finding.CatalogMatch`, audit `grant_route`) — an **operator action**,
   never returned to the caller, since the agent cannot call an ungranted route.
   **A finding is therefore one of three things, and the third is not a verdict:** a
   granted route covers it, the catalog names one the profile omits, or *neither is
   known*. Only in that third case does `insights.Prompt` render a paste-ready prompt for
   the customer's own AI, and it asks for the smallest change **or for a plain statement
   that none is warranted** — one run's trace cannot show that an API forces a pattern on
   every caller, the granted routes may be a subset of what the API offers, and a profile
   need not declare a catalog at all. For a read fan-out the prompt also offers a
   server-side aggregate as a conditional alternative, which is where the aggregate idea
   now lives. plimsoll emits text and **never calls an LLM itself**. The HTML report keeps
   the three classes distinct (`report.Class`) and carries the WIP notice the advisor
   example page carries.
3. **Routing by audience.** Per-profile `advice: off|operator|caller`
   (`grants.AdviceMode`) decides who can act: `off` computes nothing; `operator` keeps
   findings on operator surfaces; `caller` additionally returns the agent-fixable subset
   on the run result's `advice` field (`internal/rpc/advice.go`). The official Go
   client maps that field onto `sandbox.Result.Advice` and `ProjectResult.Advice`
   (`[]sandbox.AdviceFinding`, transport-independent: pattern, severity, remedy,
   route template, suggested route, and the cost numbers); direct in-process
   providers leave it nil, since advice is a service-side computation. Both `RunJavaScriptV2`
   and `RunProjectV2` compute and route advice the same way over their run's `CallTrace`.
   Findings with no granted route stay operator-only regardless.
4. **Retention of durable telemetry.** Per-profile `advice_retention: none|aggregate|detailed`
   (`grants.AdviceRetention`) gates only what reaches the **durable audit log**, orthogonal
   to the audience: `none` (default) writes nothing, `aggregate` writes per-run totals,
   `detailed` writes one metadata-only record per finding (`advice_finding_details`, the
   stream the [prospector-report](cmd/prospector-report) HTML renders). The caller wire
   hint and the bounded `/metrics` aggregates (labels only: profile/pattern/severity/remedy,
   no route templates) are governed by `advice` alone, not by retention. plimsoll is
   stateless: it stores nothing, so retention is about what it *emits*. Full rationale in
   [docs/advisory-privacy.md](docs/advisory-privacy.md).

## Build, vet, test
```sh
go build ./...
go vet ./...
go test ./...     # the e2b *live* tests skip without E2B_API_KEY
```
Some tests need a local docker daemon and the two images (`node:22-alpine` for
snippets, `plimsoll/sandbox:latest` for `RunProject`); `make docker-images` pulls
the first and builds the second. Without them those tests skip in an ordinary run
and fail under `make audit DOCKER=1`.

`make audit` is the single local gate: build, vet, race tests, golangci-lint,
`buf lint` plus a generated-code drift check, and `govulncheck`. The real
infrastructure suites are opt-in: `make audit DOCKER=1` adds the
docker/seccomp/broker/smoke tests, `make audit E2B=1` (with `E2B_API_KEY`) adds
the live E2B suite. `make help` lists individual targets.

One claim the gate does **not** make: `make audit E2B=1` runs `-run Live`, and
`TestE2BGuardLive` skips unless `E2B_GUARD_URL` and `E2B_LIVE_GRANT_BASE_URL` are
also set, so a green E2B suite does not mean the guarded-egress path was exercised.
`make e2b-guard-live` is that run, and it fails rather than skips when its
configuration is absent, so a pass can only come from actually proving the path.
Startup `SmokeTest` proves deny-all egress on a no-grant microVM; it does not create
a guarded VM, and it never proved "denied except for the guard".

The three tools the gate shells out to (buf, golangci-lint, govulncheck) are outside
the module, so they are pinned in [gate-tools.versions](gate-tools.versions) and the
gate's first step (`tools-check`) fails on a version mismatch. Otherwise "audit: OK"
means only that it passed under whatever happened to be on `PATH`, which is not the
claim this gate makes. `make tools` installs the pinned set; the codegen plugins are
pinned separately by go.mod `tool` directives.

**CI runs the gate as three Makefile targets, and each green check means exactly
what its target exercised.** [.github/workflows/audit.yml](.github/workflows/audit.yml)
has two jobs: `audit` runs plain `make audit` (build, vet, race tests, lint, buf
lint plus generated-code drift, govulncheck; no containers), and `audit-docker`
runs `make docker-images` then `make audit DOCKER=1`, the docker suite under runc
with the shipped seccomp profile. `DOCKER=1` is a request for proof: `docker-suite`
sets `SANDBOX_TEST_REQUIRE_DOCKER=1`, under which a missing daemon or image fails a
test instead of skipping it, and the target then fails on any `--- SKIP` line in
its own output. So a green `audit-docker` means the isolation suite ran: a container
came up read-only, every writable mount was a sized `noexec` tmpfs, the seccomp
profile loaded, and the broker refused what it was built to refuse. An ordinary
`go test ./...` on a machine without docker keeps its skips.
[.github/workflows/gvisor.yml](.github/workflows/gvisor.yml) is the kernel-tier
run: it installs the pinned gVisor bundle with `docker/install-gvisor.sh` and runs
the same suite with `SANDBOX_DOCKER_RUNTIME=runsc`. It is a separate workflow so a
runsc failure is attributable on its own and cannot mask the runc result.

What no CI run exercises is E2B. That suite is absent deliberately rather than
left unconfigured: it drives a live paid service and no automated run in this
project may spend, so **do not add an E2B key to repository secrets to "complete"
the gate.** Third-party actions are pinned by commit SHA rather than tag, for the
same reason the gate tools, the QuickJS artifact and the gVisor release are pinned:
a tag is mutable.

**The E2B key never lands on disk.** The live E2B suite reads `E2B_API_KEY` from
the environment and nothing writes it anywhere:

```sh
E2B_API_KEY="$KEY" make audit DOCKER=1 E2B=1   # full gate with the live suite
E2B_API_KEY="$KEY" go test ./sandbox -run Live # just the live provider tests
```

**Module identity.** The module path is `github.com/plimsollmark/plimsoll`. The
GitHub organization `plimsollmark` was registered on 2026-09-09, so the name cannot
be taken by someone else and used to serve a substitute module.

**Read that as a change of protection model, not a restatement.** The path used to
be a private module path under the RFC-reserved `.localhost` TLD,
which could never resolve publicly *by construction*: no registration, no
ownership, and nothing to keep renewed. The rename to a public path swapped that
structural guarantee for one that rests on holding an account. It is the right
trade for a module people are meant to `go get`, but it is a weaker kind of
guarantee, and it is only as good as the organization staying registered and its
owning account staying secure.

Consumers `require` tagged versions with no `replace`; day-to-day sibling
development uses an uncommitted workspace (`go work init . ../plimsoll`,
gitignored). A workspace build resolves the sibling working tree, not the pinned
version, so it proves nothing about the pin: verify with `GOWORK=off`.

Version resolution outside a workspace (`go mod tidy`/`go mod vendor`, Docker
builds) comes from `proxy.golang.org` and is checked against `sum.golang.org`,
like any other public module. There is nothing to configure. The `make modproxy`
target that publishes a local file-based GOPROXY still exists and is still how a
pre-publication tag would be served, but no released version needs it.

**Public releases start at v0.2.0, and the gap below it is deliberate.** Versions
v0.1.0 through v0.1.7 were tagged on this module before publication and resolve only
from a local file proxy; their trees are not this tree. A module version is global and
immutable, so those numbers are spent: reusing one publicly would mean a single
version string naming two different artifacts, and any consumer holding the older
hash would hit a checksum mismatch. The first public tag is therefore numbered above
the whole retired line rather than starting from v0.1.0.

**The `github.com/plimsollmark/*` checksum exemption is gone, and it is not coming
back.** While consumers still required a pre-publication v0.1.x, this module had to
be exempted from `sum.golang.org`: a checksum lookup for a version with no public tag
behind it returns `not found`, so enforcing verification then would have turned every
`go mod tidy` into a failure that described nothing real. That is why the exemption
existed and why it was always framed as temporary.

It was removed on 2026-09-10, once every consumer required v0.2.0. `sum.golang.org`
now holds v0.2.0 (transparency-log index 62818162) and verifies every later fetch
against the hash it recorded, which is the real replacement for what the old
`.localhost` module path used to give for free. **Do not re-add the exemption.**
Doing so would leave this TCB's own module as the one dependency in a consumer's
graph that nothing cross-checks, which is precisely backwards for a component whose
job is running hostile code. If a future pre-publication tag ever needs the file
proxy again, scope the exemption to that work and take it out with the tag.

**Supply chain.** Codegen plugins are pinned by go.mod `tool` directives
(`protoc-gen-go`, `protoc-gen-connect-go`) and run via `go tool`, so `buf generate`
is reproducible with no network. The embedded QuickJS artifact is pinned to
quickjs-ng **v0.15.1** by SHA-256, guarded by `TestEmbeddedQuickJSProvenance` (see
[sandbox/wasm/README.md](sandbox/wasm/README.md)). `docker/install-gvisor.sh` pins
a specific gVisor release and checksum rather than tracking `latest`.

## Invariants — do not regress
- **Safe factory/daemon default.** `Build` and `plimsolld` run no code unless
  `SANDBOX_PROVIDER` is set explicitly. Direct provider constructors are explicit
  execution opt-ins and must be wrapped/configured safely by their embedder. Never
  execute agent code as a native host process. WASM is explicitly
  in-process/process-tier and must not be described as an OS/VM boundary.
- Keep `sandbox` transport-agnostic — no Connect/HTTP types leak into it.
- No new third-party deps without cause; never reintroduce `fastschema/qjs`.
- Treat all executed code as hostile; preserve the network/filesystem/capability
  restrictions on every provider.
- **Advisory-as-evidence (non-authoritative).** Advice is computed post-dispatch over
  the already-final `Result`, so a run with advice is **byte-identical in execution** to
  one without. A finding is evidence attached to a run, like the isolation tier: it must
  never gate admission, change `ExitCode`/output/isolation, or slow the run. Keep every
  advisory addition on the post-dispatch side of the boundary.
- **Metadata-only telemetry.** The `CallTrace` and everything derived from it (findings,
  caller wire hints, audit records, `/metrics`) carry only route **templates**, counts,
  timings, and trusted labels — never a raw path, query, body, or credential. `CallRow`
  has no body/credential field by construction; findings and prompts are templated from
  trusted inputs only (route templates + numbers) and must never echo a guest-controlled
  string. Preserve this on every new advisory surface, and never let advisory code call
  an LLM. See [docs/advisory-privacy.md](docs/advisory-privacy.md).
- **The correlation id is the answer to "so you just record less".** Declining to keep
  the path and body is only defensible if the question they answer is still answerable
  somewhere. `trace_id` on the run request is an **opaque** join key the caller already
  uses in its own log (an upstream MCP proxy can carry such an id across its
  boundary); the daemon echoes it onto the run's audit line and does nothing else with
  it — never parsed, never routed on, never handed to the guest or sent upstream. The
  sensitive payload then exists in exactly ONE place, one layer up, instead of two.
  This is the difference between *"we record less"* and *"we record the part that is
  ours"*, and it is the honest form of the privacy claim.
  Because it is caller-controlled, it is also the one field that could smuggle a path
  into the stream that promises it holds none: `internal/rpc/trace.go` accepts only
  `[A-Za-z0-9._:-]{1,64}` and **drops a non-conforming id whole** (logging
  `trace_id_rejected`, never the value). Never widen that charset, never truncate
  instead of dropping — a truncated id looks joinable and joins to nothing.
- **No backward compatibility.** This is pre-1.0 with no locked-in external
  consumers: make clean breaking changes and **remove** compat shims (legacy
  fallbacks, deprecated aliases, nil-means-old-behavior branches). Delete old
  fields/functions rather than deprecating them; prefer the correct model over an
  additive, compatible one.
