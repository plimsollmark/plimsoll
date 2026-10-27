# plimsoll: agent guide

> **This file is the index for *what this is*:** identity, layout, the rules no change may
> break, and where each subsystem's documentation lives. It is vendor-neutral and it is
> published with the repository, so it describes the component and nothing about any
> particular deployment of it. A working copy may carry an `AGENTS.local.md` beside this
> file for what is true of that copy only; it never ships. If it exists, read it before
> starting.

Standalone code-execution sandbox service: the **one** place that runs untrusted,
agent-authored code with an explicitly reported isolation tier, callable over RPC.
Hostile production deployments require the verified kernel or VM tiers; the WASM
option is intentionally only process-tier.

- Go module `github.com/plimsollmark/plimsoll`. The **canonical build pins the 1.26.10
  toolchain** (`toolchain go1.26.10`) and `golang.org/x/net` v0.60.0: `govulncheck ./...` is
  clean there. 1.26.9 has GO-2026-6809 (crypto/x509 distrusting compromised intermediate
  certificates, published 2026-10-21), and 1.26.6 had eleven stdlib advisories published on
  2026-10-08, among them an HTTP/2 server crash and HTTP/2 memory exhaustion in paths this
  TCB calls. Build plimsolld with >= 1.26.10.
- Direct dependencies are Connect, protobuf, wazero, and `golang.org/x/net`;
  `x/sys` and `x/text` are indirect. Do not add dependencies casually: this is a
  hostile-code TCB.
- **`github.com/fastschema/qjs` is banned.** Its `MemoryLimit` is a no-op. Drive
  wazero directly with `WithMemoryLimitPages` for a real per-run memory cap.

## Where the detail is

Read the document for the subsystem you touch, not all of them.

| Topic | Document |
|---|---|
| Isolation tiers and what each provider's tier means | [docs/isolation-tiers.md](docs/isolation-tiers.md), [docs/gvisor.md](docs/gvisor.md), [docs/seccomp.md](docs/seccomp.md) |
| Sessions (one sandbox kept for many calls, cells, the pool, what a session gives up) | [docs/sessions.md](docs/sessions.md) |
| Run records and signing | [docs/run-records.md](docs/run-records.md) |
| Results, outcomes and the not-dispatched mark | [docs/run-results.md](docs/run-results.md) |
| Capability grants (the per-run host-API broker) | [docs/capability-grants.md](docs/capability-grants.md) |
| Hardened mode | [docs/hardened-mode.md](docs/hardened-mode.md) |
| Callers and tokens | [docs/callers.md](docs/callers.md) |
| Docker Cloud, OpenShell, Kubernetes agent-sandbox operator guides | [docs/dockercloud.md](docs/dockercloud.md), [docs/openshell.md](docs/openshell.md), [docs/agentsandbox.md](docs/agentsandbox.md) |
| Guest dependencies and images | [docs/guest-dependencies.md](docs/guest-dependencies.md), [docs/dependencies.md](docs/dependencies.md) |
| The efficiency advisor | [docs/efficiency-advisor.md](docs/efficiency-advisor.md) |
| Placement across daemons | [docs/placement.md](docs/placement.md) |
| Seams for embedders | [docs/seams.md](docs/seams.md) |
| Example programs and their pages | [docs/example-programs.md](docs/example-programs.md), `docs/examples/` |
| Releasing and module identity | [docs/releasing.md](docs/releasing.md) |
| Every environment variable | `plimsolld -h` (the text is `helpText` in [cmd/plimsolld/providers.go](cmd/plimsolld/providers.go); a test fails if the package reads a variable the text omits) |
| Limitations stated plainly | [docs/limitations.md](docs/limitations.md) |

## Layout

- [sandbox/](sandbox/): `package sandbox`, deliberately **transport-agnostic** (no
  Connect/HTTP types), so the same providers back an RPC, a CLI or a test.
  [sandbox.go](sandbox/sandbox.go) holds the `Sandbox` interface and the request and result
  types; [factory.go](sandbox/factory.go) `Build()` selects a provider and fails closed;
  [wasm.go](sandbox/wasm.go), the `docker*.go`, `e2b*.go` and `dockercloud*.go` files are the
  in-tree providers; [disabled.go](sandbox/disabled.go) refuses to execute (the default);
  [broker.go](sandbox/broker.go) and [capability.go](sandbox/capability.go) are the
  provider-neutral grant enforcement; [internal/sessionkit](sandbox/internal/sessionkit/)
  holds the programs every session provider sends into its sandbox; [sessiontest](sandbox/sessiontest/)
  is the conformance suite a session provider must pass; [wasm/qjs-wasi.wasm](sandbox/wasm/) is the
  embedded QuickJS build (pinned by SHA-256, rebuilt by `wasm/build.sh`).
- [sandbox/openshell/](sandbox/openshell/) and [sandbox/agentsandbox/](sandbox/agentsandbox/):
  the NVIDIA OpenShell and Kubernetes agent-sandbox providers, each its own package because
  its generated gRPC client registers protobuf names another SDK also registers; plimsolld
  builds them from [cmd/plimsolld/providers.go](cmd/plimsolld/providers.go), outside `Build`.
- [placement/](placement/), [record/](record/), [attest/](attest/): routing across daemons;
  the digests the daemon states on every run; the signing harness outside the daemon
  ([cmd/plimsoll-attest](cmd/plimsoll-attest/) is its CLI).
- [cmd/plimsolld](cmd/plimsolld/): the daemon. [cmd/plimsoll-clients](cmd/plimsoll-clients/):
  the offline caller registry CLI. [cmd/plimsoll-specgen](cmd/plimsoll-specgen/) over
  [internal/specgen](internal/specgen/): a grant's allow list, injected client and tool
  description derived from one OpenAPI document.
- [internal/rpc](internal/rpc/) (the Connect service, auth, admission, spend, advice routing),
  [internal/grants](internal/grants/) (named profiles from `PLIMSOLL_GRANTS_FILE`),
  [internal/insights](internal/insights/) (the advisor's detectors),
  [internal/clientconfig](internal/clientconfig/) (the callers file shared by daemon and CLI).
- [clients/python/](clients/python/), [clients/typescript/](clients/typescript/),
  [clients/mcp/](clients/mcp/): the Python and TypeScript clients, and the MCP server (its own
  Go module). Each makes the Go client's checks: protocol number, every run record recomputed,
  the isolation floor, a session's chain, the request ID's echo.
- [docker/](docker/): the image recipes (`Dockerfile`, `python.Dockerfile`, `sim.Dockerfile`,
  `wasm-cc.Dockerfile`, `agentsandbox.Dockerfile`), the in-sandbox project runner
  [runner.mjs](docker/runner.mjs), the runner guard [guard/runner.c](docker/guard/runner.c),
  the simulation worker [sim/](docker/sim/), the audited seccomp allowlist `seccomp.json`.
- [examples/](examples/): runnable examples (`minimal`, `grant`, `daemon`, `advisor`, `oracle`, `fanout`, `fanout-cartpole`,
  `wasm-controller`, `wasm-buck`, `providers`, `sessions`, `capsule`, `sbom`, `agentsandbox`,
  `adapter`, `trigger-chat`, `agent-session`); their pages are under `docs/examples/`.
  [docs/example-programs.md](docs/example-programs.md) says what each proves.
- [measurements/](measurements/): timing programs; the gate builds them and never runs them.
- [proto/](proto/) and `gen/go`: the service definition and generated code (`make generate`,
  never a bare `buf generate`).
- [docs/trainers/](docs/trainers/): dependency-free interactive lessons.

## The `Sandbox` interface, in brief

Every provider implements [sandbox/sandbox.go](sandbox/sandbox.go): `RunJavaScript` (a
snippet), `RunProject` (files, then build/lint/run steps, stop on first failure),
`RunModule` (a compiled simulator once per parameter row; docker only), `Name`. A provider
may add sessions (`sandbox.SessionProvider`: one sandbox for many calls, cells in a kept
interpreter, suspend and close); every session implementation passes
[sandbox/sessiontest](sandbox/sessiontest/) before it states sessions.

Result semantics that every change must keep:
- A non-zero `ExitCode` is a **normal result**, not a Go error.
- **Whether anything ran is a mark, not a code.** A refusal raised before any code was
  dispatched is a `sandbox.NotDispatchedError` with a reason (`request`, `permission`,
  `protocol`, `unsupported`, `isolation`, `environment`, `capacity`). The RPC layer builds
  every handler-side refusal through `refuse` and sends the mark as an error detail; an
  answer given before the handler is marked by the `Plimsoll-Not-Dispatched` header. **No
  mark means execution may have occurred**, so an unmarked error is never a safe retry.
- A mark counts only on an answer bound to its request: every client sends a fresh
  `Plimsoll-Request-Id` and believes nothing on an answer whose echo is missing or differs.
- `ProjectResult.Outcome` (`completed`, `setup_failed`, `timed_out`, `protocol_error`, `runner_failed`) is
  the stable classification; a timed-out step makes the run `timed_out` on every provider.
- Truncation is machine-readable (`StdoutTruncated`, `StderrTruncated`,
  `ArtifactsTruncated`), never an in-band marker; stdout and stderr are `bytes` on the wire.
- Every answered `Run` carries a **run record** (digests of request and result, the
  evidence, the times); the daemon holds no key; clients recompute both digests
  (`record.ErrMismatch` is DataLoss).
- The `protocol` number is the mixed-version gate: a request that omits it is refused
  before the payload is read. Bump `protocol.Number` when omitting a new request field would
  change what a daemon may execute, or when clients start requiring something of answers.

## Providers (`SANDBOX_PROVIDER`)

`Build(getenv)` selects one and fails closed: a malformed safety setting or an unknown name
is an error, and unset is **Disabled**. plimsolld builds `openshell` and `agentsandbox`
itself, outside `Build`.

| Value | Provider | Tier |
|---|---|---|
| `wasm` | in-process QuickJS via wazero | process (snippets only; an engine escape lands in plimsolld) |
| `docker` | locked-down `docker run` | container under runc; **kernel** only after verified runsc Preflight |
| `e2b` | E2B Firecracker microVM | vm (billed by the second) |
| `dockercloud` | Docker Cloud Sandboxes microVM | vm (billed by the second) |
| `openshell` | NVIDIA OpenShell through a gateway | container |
| `agentsandbox` | Kubernetes agent-sandbox pod from a warm pool | read from the runtime class: `kata-clh`, `kata-clh-runtime-rs`, `kata` vm; `runsc` kernel; `runc` container; anything else refused |
| unset | Disabled | none; any other value fails `Build` |

**A reported tier is configuration and provider evidence plus the behavioral startup
smoke test, never runtime attestation**, and every surface that advertises a tier carries
that qualification. Every provider whose boundary depends on the host or a remote service
runs a **`SmokeTest`** at startup (`EnsureReady`) and serves nothing if it fails; `/readyz`
re-runs the bounded `Preflight` (for e2b and dockercloud that is configuration only).
`Describe` reports the provider, tier, payload support, grant support, each payload kind's
environment and software identity, and the resource envelope. `minimum_isolation` on a
request is a per-dispatch floor checked immediately before admission;
`ErrInsufficientIsolation` means no hostile code ran. **Hardened mode**
(`PLIMSOLL_HARDENED=1`) refuses to serve unless every advertised production property is
in force ([docs/hardened-mode.md](docs/hardened-mode.md)).

## Capability model, RPC server and advisor, in brief

- A **grant** (`HostAPIGrant`) is per run and off by default twice over: a nil grant means
  no network, and an empty `Allow` list reaches nothing. The shared broker accepts only
  decoded, canonical paths byte-identical to an approved route; the credential is minted
  per run by a `TokenMinter` and never enters the sandbox. Over RPC a caller only selects a
  server-side profile (`grant_profile`); a raw grant is never accepted on the wire.
- `plimsolld` serves `plimsoll.v1.SandboxService` over Connect; auth is fail-closed when
  configured (`PLIMSOLL_CLIENTS_FILE`, then `PLIMSOLL_TOKEN`, then open dev mode with a
  warning). Every run is audit-logged with the principal, sizes, profile, provider, exit,
  duration, never the code (a run's outcome detail can carry the runner's own error text,
  which may name a caller's file: [docs/efficiency-advisor.md](docs/efficiency-advisor.md)).
  Internal faults reach a caller as `internal error <id>` only.
- The advisor is post-dispatch analysis over a metadata-only `CallTrace`; it never calls a
  model and never changes a run. [docs/efficiency-advisor.md](docs/efficiency-advisor.md).

## Build, vet, test

```sh
go build ./...
go vet ./...
go test ./...     # paid live tests skip unless their make target's flag is 1; a key alone runs nothing paid
```

`make audit` is the single local gate: build, vet, the nested modules' build and vet, race tests (`-short`: no docker),
golangci-lint, `buf lint` plus a generated-code drift check, and `govulncheck`. The real
infrastructure suites are opt-in: `make audit DOCKER=1` adds the docker, seccomp, broker and
smoke tests (it needs the five images `make docker-images` provides, and refuses an image
whose `io.plimsoll.inputs` label is not the current hash of `docker/`: after editing
`docker/`, rebuild); `E2B=1`, `DOCKERCLOUD=1`, `OPENSHELL=1` and `AGENTSANDBOX=1` add the
live suites, which fail rather than skip without their configuration. `make help` lists
the targets. Run the gate as a non-root user: root defeats the runner guard two tests
exercise. A working copy may append steps through an unpublished `local.mk`.

**The ordinary gate cannot spend.** Every test that creates a billable microVM skips
unless the flag only its make target sets is `1`; the `test`, `race` and `docker-suite`
targets run under `env -u E2B_API_KEY -u DOCKER_SBX_TOKEN`. A green `make audit E2B=1`
never means the guarded-egress path was exercised; `make e2b-guard-live` is that run.
**Credentials never land on disk.**

The three tools the gate shells out to are pinned in
[gate-tools.versions](gate-tools.versions); `make tools` installs them. Codegen plugins
are pinned by go.mod `tool` directives.

**CI** ([.github/workflows/](.github/workflows/)) runs `make audit`, `make clients-suite`,
`make capsule-suite`, `make sbom-suite`, `make mcp-suite` and `make docker-suite` under
runc, and the docker suite under runsc in a separate workflow. No CI run exercises E2B,
Docker Cloud or OpenShell: **never add an E2B key or a Docker token to repository
secrets.** Third-party actions are pinned by commit SHA.

**Module identity.** `github.com/plimsollmark/plimsoll` resolves from `proxy.golang.org`
and is verified by `sum.golang.org`. Public releases start at v0.2.0 (v0.1.0 to v0.1.7 are
spent tags: never reuse one). **Do not re-add a `GONOSUMDB` exemption for this module.**
[docs/releasing.md](docs/releasing.md).

## Invariants: do not regress

- **Safe factory/daemon default.** `Build` and `plimsolld` run no code unless
  `SANDBOX_PROVIDER` is set explicitly. Direct provider constructors are explicit
  execution opt-ins and must be wrapped/configured safely by their embedder. Never
  execute agent code as a native host process. WASM is explicitly
  in-process/process-tier and must not be described as an OS/VM boundary.
- Keep `sandbox` transport-agnostic: no Connect/HTTP types leak into it.
- No new third-party deps without cause; never reintroduce `fastschema/qjs`.
- Treat all executed code as hostile; preserve the network/filesystem/capability
  restrictions on every provider.
- **Environment variables are a channel into the sandbox; keep it closed.** The docker
  provider starts the CLI only through `dockerCommand` ([sandbox/docker_cli.go](sandbox/docker_cli.go)):
  PATH as its whole environment and an empty client config of its own (a fresh private
  temp directory, never a fixed path another local user could make first with a `proxies`
  entry; it holds a socket the process listens on, so `ReconcileOrphans` removes one a dead
  process left, as it does dead broker socket directories), so neither a daemon
  secret nor the host's client settings (a `proxies` entry puts proxy URLs, credentials
  included, into every container `docker run` starts) reach a container. An `-e` flag is
  built only by `dockerEnvFlag`, always `NAME=value`. No program of plimsoll's in a docker
  sandbox starts with the image's environment: the runner, the smoke probes, a session's
  main process, and in a session the sweep, process lister, identity check, relays and
  interpreter launcher start under `/usr/bin/env -i` with a fixed PATH
  (`sessionkit.ControlArgv`), and every container command is plimsoll's own
  (`--entrypoint`), never the image's.
  Guest-facing processes (a snippet's node, a project's steps, a cell's interpreter) get
  the image's environment, read from the verified image's config, handed to them
  explicitly (`guestArgv`, the plan's `env`), with HOME and HOSTNAME as docker sets them.
  An image variable that loads code (`NODE_OPTIONS`, a search path into `/work`) therefore
  reaches guest processes alone, where it can load only the guest's own code; it once
  made node run a guest-written file inside plimsoll's sweep. The one exception is the
  first process of each command, plimsoll's `/usr/bin/env`, whose dynamic loader and C
  library read the environment docker gives it before `-i` clears anything, so Preflight
  refuses an image that sets a variable they read at startup (any `LD_` name,
  `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`, `GCONV_PATH`). The startup smoke test runs a
  snippet exactly as runs do, since its start marker is written before node starts.
  `TestDockerCLIIsStartedOnlyThroughDockerCommand` fails the build on a new direct docker
  call, and `TestDockerImageEnvReachesOnlyGuestProcesses` proves the split with an image
  whose `NODE_OPTIONS` loads a hook from `/work`. On openshell, whose exec hands a fixed
  set of the gateway's variables and never the image's (measured on v0.1.2), the process
  lister, the sweep and both relays start under `sessionkit.ControlArgv` too.
- **Advisory-as-evidence (non-authoritative).** Advice is computed post-dispatch over
  the already-final `Result`, so a run with advice is **byte-identical in execution** to
  one without. A finding is evidence attached to a run, like the isolation tier: it must
  never gate admission, change `ExitCode`/output/isolation, or slow the run. Keep every
  advisory addition on the post-dispatch side of the boundary.
- **Metadata-only telemetry.** The `CallTrace` and everything derived from it (findings,
  caller wire hints, audit records, `/metrics`) carry only route **templates**, counts,
  timings, and trusted labels, never a raw path, query, body, or credential. `CallRow`
  has no body/credential field by construction; findings and prompts are templated from
  trusted inputs only (route templates + numbers) and must never echo a guest-controlled
  string. Preserve this on every new advisory surface, and never let advisory code call
  an LLM. See [docs/efficiency-advisor.md](docs/efficiency-advisor.md).
- **The correlation id is the answer to "so you just record less".** Declining to keep
  the path and body is only defensible if the question they answer is still answerable
  somewhere. `trace_id` on the run request is an **opaque** join key the caller already
  uses in its own log (an upstream MCP proxy can carry such an id across its
  boundary); the daemon echoes it onto the run's audit line and does nothing else with
  it: never parsed, never routed on, never handed to the guest or sent upstream. The
  sensitive payload then exists in exactly ONE place, one layer up, instead of two.
  This is the difference between *"we record less"* and *"we record the part that is
  ours"*, and it is the honest form of the privacy claim.
  Because it is caller-controlled, it is also the one field that could smuggle a path
  into the stream that promises it holds none: `internal/rpc/trace.go` accepts only
  `[A-Za-z0-9._:-]{1,64}` and **drops a non-conforming id whole** (logging
  `trace_id_rejected`, never the value). Never widen that charset, never truncate
  instead of dropping: a truncated id looks joinable and joins to nothing.
- **No backward compatibility, except in reading signed evidence.** This is pre-1.0
  with no locked-in external consumers: make clean breaking changes and **remove**
  compat shims (legacy fallbacks, deprecated aliases, nil-means-old-behavior branches).
  Delete old fields/functions rather than deprecating them; prefer the correct model
  over an additive, compatible one. The one exception: **a verifier of stored evidence
  reads every published run record version** (`record.published`), each frozen and
  pinned by what its own release produced (`record/testdata/published/`,
  `attest/testdata/published/`), because a record's value is that it can be checked
  later. Writers write the current version only, and a live answer must carry it. A
  published version is retired only by a dated, announced decision. Bundles from before
  links (v0.10.0 to v0.17.x) are not read whole: their records verify one line at a time
  (`plimsoll-attest verify-record`, `attest.VerifyCall`).
