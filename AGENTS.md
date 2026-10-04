# plimsoll — agent guide

> **This file is the source of truth for *what this is*:** architecture, providers,
> invariants. It is vendor-neutral, and it is published with the repository, so it
> describes the component and nothing about any particular deployment of it.
> A working copy may carry an `AGENTS.local.md` beside this file for what is true of
> that copy only; it never ships. If it exists, read it before starting.

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
  - [sandbox/docker.go](sandbox/docker.go) — locked-down `docker run` provider: its type,
    configuration and lockdown flags; [docker_preflight.go](sandbox/docker_preflight.go)
    (daemon and image verification), [docker_smoke.go](sandbox/docker_smoke.go) (the
    startup smoke test), [docker_run.go](sandbox/docker_run.go) (admission and the
    snippet, project and module runs), [docker_broker.go](sandbox/docker_broker.go) (the
    per-run grant socket), beside docker_cli.go, docker_session.go and docker_pool.go.
  - [sandbox/e2b.go](sandbox/e2b.go) — E2B Firecracker microVM provider.
  - [sandbox/dockercloud.go](sandbox/dockercloud.go): Docker Cloud Sandboxes
    microVM provider. Its wire calls go through one interface
    ([dockercloud_transport.go](sandbox/dockercloud_transport.go)) with two implementations:
    the REST API Docker documents, the default
    ([dockercloud_rest.go](sandbox/dockercloud_rest.go)), and Connect, Docker's pre-launch
    sandboxes-api v0.36.0, kept as the backup
    ([dockercloud_connect.go](sandbox/dockercloud_connect.go)), both verified against the
    live service on 2026-10-04; see
    [docs/dockercloud.md](docs/dockercloud.md). Its runs, exec, network guard, token
    exchange and sandbox lifecycle are in the other `dockercloud_*.go` files beside it.
  - [sandbox/openshell/](sandbox/openshell/openshell.go): NVIDIA OpenShell provider
    (the gateway's docker driver, container tier), in its own package because its
    generated gRPC client registers protobuf names OpenShell's Go SDK also registers.
    plimsolld builds it ([cmd/plimsolld/openshell.go](cmd/plimsolld/openshell.go));
    verified against a v0.1.2 gateway (2026-09-28).
  - [sandbox/disabled.go](sandbox/disabled.go) — refuses to execute (the default).
  - [sandbox/broker.go](sandbox/broker.go) — provider-neutral per-run host-API
    enforcement core (allowlist, credential injection, budgets, upstream HTTP,
    metadata trace); providers supply only framing adapters.
  - [sandbox/capability.go](sandbox/capability.go) — the generic injected host-API
    client and capability validation.
  - [sandbox/wasm/qjs-wasi.wasm](sandbox/wasm/) — embedded QuickJS-ng WASI build
    (`//go:embed`); MIT plus a minimal checked-in host-call shim. Rebuild from
    pinned inputs with [sandbox/wasm/build.sh](sandbox/wasm/build.sh).
- [placement/](placement/): the routing library for a caller with several daemons.
  It filters backends by what `Describe` states (payload
  kind, floor, grant capability, selected software identity; a session by the
  `session_environment` Describe states, since on docker it runs in the project image), ranks them by the caller's own
  comparison, sends with each backend's own credential, and retries on another backend
  only after a refusal marked not-dispatched with reason unsupported, isolation,
  environment or capacity. The daemon enforces software rules before dispatch;
  one daemon still serves one provider.
  [docs/placement.md](docs/placement.md).
- [record/](record/) and [attest/](attest/): run records. `record` computes the digests
  the daemon states on every run and the client checks; `attest` is the harness outside
  the daemon that signs checked records (DSSE around in-toto), verifies bundles and
  session chains, and replays; [cmd/plimsoll-attest](cmd/plimsoll-attest/) is its CLI.
  Spec: [docs/run-records.md](docs/run-records.md).
- [clients/python/](clients/python/): the Python client (distribution `plimsoll-client`,
  import `plimsoll_client`; standard library only, Python 3.10 or later). It speaks
  Connect's JSON protocol and makes the Go client's checks: the protocol number stated
  and compared, every run record recomputed, the isolation floor sent and the returned
  evidence checked, a session's chain followed, and the not-dispatched mark and session
  end restored from the error details; `Session.run_cell` for cells. `client_test.go`
  beside it serves the real RPC handler and runs the Python suite against it.
  [README](clients/python/README.md).
- [cmd/plimsoll-clients/](cmd/plimsoll-clients/) — offline operator CLI over the
  caller registry the daemon loads from `PLIMSOLL_CLIENTS_FILE`; the shared format
  and validation live in [internal/clientconfig/](internal/clientconfig/). Usage:
  [docs/callers.md](docs/callers.md).
- [docker/](docker/) — build recipe for the project-run toolchain image:
  [docker/Dockerfile](docker/Dockerfile) (node + tsc/tsx/eslint, baked in so
  runtime needs no egress), [docker/runner.mjs](docker/runner.mjs) (the
  in-sandbox multi-file project runner), and [docker/guard/runner.c](docker/guard/runner.c)
  (loaded into that runner before it reads the plan, making its descriptors and
  memory inaccessible to same-uid steps). Third-party packages for projects are baked
  into a derived image at `/node_modules` at build time, where Node's parent-directory
  walk from `/work` finds them; a run never installs anything
  ([docs/guest-dependencies.md](docs/guest-dependencies.md)). Other runtimes are
  the same recipe: [docker/python.Dockerfile](docker/python.Dockerfile) derives
  `plimsoll/sandbox-python` (python3, NumPy, SciPy, one BLAS thread) from the base
  image with no runner, API, or environment-variable change.
  [docker/sim.Dockerfile](docker/sim.Dockerfile) derives `plimsoll/sandbox-sim` on a
  glibc base: a WasmEdge AOT worker ([docker/sim/](docker/sim/)) plus two Reference
  FMUs and a Lorenz simulator of our own compiled to WebAssembly under `/models`, run through the unchanged project
  API and proven byte-identical to native by `sandbox/docker_sim_test.go`. The same
  image carries the Greedy fixture that proves the worker's per-instance memory cap
  (256 pages; a greedy row fails alone), and the physics oracle: a cart-pole simulator
  kept as WebAssembly at `/models/cartpole.wasm` behind a stepping shim, and the
  runner `/oracle/run.mjs` that runs a caller's controller as a separate process and
  fingerprints the trajectory (`sandbox/docker_oracle_test.go`). The generic trial runner
  `/oracle/judge.mjs` (any plant, the scenario chosen by data) takes each scenario from a
  file it deletes before the controller starts, never from a command line, and
  re-executes itself under the runner guard, proven by the runner's own same-uid probe,
  so a controller can read neither a hidden scenario parameter nor the runner's memory
  and descriptors (`sandbox/docker_judge_scenario_test.go`). `/oracle/run.mjs` is
  vendored unchanged and does not guard itself; its scenarios are public.
  [docker/wasm-cc.Dockerfile](docker/wasm-cc.Dockerfile) derives
  `plimsoll/sandbox-wasm-cc` from the sim image: the C half of wasi-sdk 27 (clang and
  a wasm32-wasip1 libc with libm), pinned by the same image digest the sim build
  uses, so a project step can compile C to a WebAssembly module with no network.
- [examples/](examples/) — ten runnable programs: `minimal` (one snippet and the
  tier it ran behind), `grant` (the capability model, including a guest bypassing
  the injected client and being refused by the broker anyway, then the identical
  request succeeding under a separate per-run grant that lists it), `daemon` (the
  full service path with auth, `Describe`, and an isolation floor being refused),
  `advisor` (the efficiency advisor over a loopback daemon: a per-item loop,
  the finding that names the declared, granted batch route, the rewrite, and the API's
  own request count as the witness), `oracle` (needs docker: an agent-written
  controller run against the module image's cart-pole simulator and checked by its
  trajectory fingerprint, through the ordinary project API; the page it writes replays the
  runs, and `sandbox/docker_oracle_test.go` asserts the fingerprints), and
  `wasm-controller` (needs docker: a swing-up controller in C compiled to
  WebAssembly by the run's first step in `plimsoll/sandbox-wasm-cc` and run on
  four scenarios by the generic trial runner `/oracle/judge.mjs` through the shared Node shim
  ([examples/internal/wasmshim](examples/internal/wasmshim/), which passes the module
  every observation and the tick index, with optional `control_count` and
  `control_output` exports for multiple commands, and gives
  the module no imports); the page it writes, `docs/examples/wasm-controller/index.html`, replays
  the swing-up and compares the record with `controller/reference.js` tick by tick;
  `sandbox/docker_wasm_controller_test.go` asserts a reproducible compile,
  one fingerprint per scenario, the score floor, and that the only difference from
  the JavaScript law is `cos`), `wasm-buck` (needs docker: the buck converter's
  average current-mode law in C under the same shim and runner; the law calls no
  library function, so `sandbox/docker_wasm_buck_test.go` requires the C trajectory
  to equal `controller/reference.js`'s byte for byte in all four scenarios, plus a
  reproducible compile and the regulation floor; the page it writes is
  `docs/examples/wasm-buck/index.html`), and `providers` (the oracle's run, with its runner and
  simulator sent as project files, on every provider the machine can reach, each built
  by the constructor plimsolld uses (`sandbox.Build`, or `openshell.FromEnv`) and proven
  by `EnsureReady`; the page it writes compares the
  fingerprints with the one the oracle page published; E2B and dockercloud rows need
  their credentials and are paid, and the openshell row needs a gateway), `sessions`
  (needs an OpenShell gateway: one session of five calls through plimsolld with the
  `attest` harness signing every record; the page it writes, `docs/examples/sessions/`,
  shows the chain and the verifier refusing a dropped call and a changed byte, with the
  bundle and public key beside it), and `capsule` (its own Go module, because the capsule
  emitter needs Go 1.27 and dependencies plimsoll does not take on: each call in the
  sessions bundle, once `attest` has accepted it, stated as an Agent Action Capsule under
  draft-mih-scitt-agent-action-capsule-05 and checked by that project's Go and Python
  verifiers; the page it writes is `docs/examples/capsule/`). The examples that run the daemon build it from source
  through [examples/internal/daemonproc](examples/internal/daemonproc/).
- [clients/typescript/](clients/typescript/): `@plimsollmark/client`, a dependency-free
  TypeScript client (Connect JSON over `fetch`) that keeps the Go client's checks: the
  protocol number, every run record recomputed (golden vectors shared with
  `record/record_test.go`), the isolation floor, a session's chain; `Session.runCell` for
  cells. `CodeSandboxes` keeps one sandbox per conversation key (a session where Describe
  states sessions, every call a cell in its Python or JavaScript interpreter, with the
  call's files written first; a fresh project per call otherwise, through a runner that
  prints the last expression the same way; always fresh without a key), and two add-ons
  give an agent an `executeCode` tool (`code`, `language`, `files`) on it: `/trigger` (Trigger.dev's code-sandbox recipe: warm in
  `onTurnStart`, dispose in `onChatSuspend`/`onComplete`; `chat.local` holds only the run
  id, never a session ID) and `/mastra` (keyed by thread and resource).
  `go test ./clients/typescript/` serves the real RPC handler and runs its node suites.
  [examples/trigger-chat](examples/trigger-chat/) is the Trigger.dev chat agent, tested
  through Trigger.dev's `mockChatAgent`.
- [docs/trainers/](docs/trainers/) — dependency-free interactive lessons covering
  the execution model, architecture, providers, dependencies, the API broker and
  its capacity signal, MCP/agent integration, customer patterns, and the efficiency
  advisor.

## The `Sandbox` interface
Every provider implements [sandbox/sandbox.go](sandbox/sandbox.go):
- `RunJavaScript(ctx, Request) (Result, error)` — run a JavaScript snippet (Node
  on Docker, E2B, Docker Cloud and OpenShell; QuickJS on WASM).
- `RunProject(ctx, ProjectRequest) (ProjectResult, error)` — write a multi-file
  project, then run build/lint/run steps in order (stop on first failure).
- `RunModule(ctx, ModuleRequest) (ModuleResult, error)` — run a compiled physical
  simulator baked into the provider's module image once per parameter row (docker only;
  see "Module runs" below).
- `Name() string` — the provider id.

**Sessions** (optional `sandbox.SessionProvider`, [docs/sessions.md](docs/sessions.md)):
one sandbox kept for many calls, files persisting, and of processes only the interpreters a
session keeps for its cells, as of the sweep after each call (an interpreter runs between
calls, so it can start a process the next sweep kills); surviving a call is optional.
`OpenSession`
returns a `sandbox.Session` (snippet, project and cell calls, serialized; `Suspend`, `Close`,
`Done`, `Err`), and a session's end is a typed `SessionEndedError`; a call on an ended
session is refused not-dispatched. `Err` is set as the session ends; `Done` closes only once
its sandbox is deleted, and capacity (the daemon's slot, `WithAdmission`'s reservation) is
given back on `Done`, since the sandbox holds its memory until then. A **cell** (`RunCell`, wire payload `cell`, only in a
session; `Run` refuses one, which exists there as the stored form a harness replays) runs
code in a Node or Python interpreter the session keeps alive, so state survives calls as in
a notebook; its files are written into the work directory first (a cell whose files cannot
all be written is refused not-dispatched, reason `request`, its interpreter untouched); it
carries no grant. The
interpreters, their launcher and the relay each provider keeps attached beside each
interpreter (one `docker exec` or one OpenShell exec stream held open, so a warm cell's code
reaches its interpreter without a new process) live in [sandbox/internal/sessionkit](sandbox/internal/sessionkit/) and travel in argv, so an image
needs only `node` (and `python3` for Python); the sweep keeps each live interpreter by PID,
start time and command line and kills its children; a deadline kills it. Code of a session can
write into a docker relay's or launcher's output while it starts, so nothing they print decides
a not-dispatched mark, a second send or what the sweep keeps: a cell is two steps (files and
the interpreter's connection, then the code), only the first can refuse it, every relay line
carries the cell's nonce, and on docker an identity is kept only once a check run as a second
uid (the guest's plus one) confirms it (a relay started by `docker exec`, so parent PID 0; the one
process with the interpreter's command line). Which languages an
image runs is found by each provider's smoke test (the interpreter starts and prints) and stated
on `PayloadEnvironment.languages`; with sessions on, the session smoke test then runs a cell that
keeps state in each, and refuses a stated language it has no check for. Every call of a session runs in one work directory
(docker `/work`, openshell `/tmp/work`), so a snippet finds what a project wrote. Every
implementation runs the conformance suite in [sandbox/sessiontest](sandbox/sessiontest/) and
states sessions only once it passes; openshell and docker do (their call boundaries:
[docs/openshell.md](docs/openshell.md#sessions), [docs/sessions.md](docs/sessions.md#docker)).
Both run the same in-sandbox programs between calls, the process lister and the sweep, from
[sandbox/internal/sessionkit](sandbox/internal/sessionkit/). A docker session is a run's
locked-down container from the project image kept alive under docker's init, every call a
`docker exec` into it; its idle suspend is `docker pause`, so `Suspend` reports the memory
still held and the daemon keeps the session's concurrency slot; its read-back before each
call compares the security-relevant `docker inspect` fields with open; its broker socket is
mounted at open and serves only the grant of the call in progress, to anything in the
container, code an earlier call left running included; an OpenShell session's granted call
starts its relay in the sandbox, reachable the same way. So a granted session call needs a
grant that allows sessions (`HostAPIGrant.AllowInSessions`, a profile's
`allow_in_sessions`), or both providers refuse it before dispatch
(`ErrGrantNotForSessions`, reason `permission`, `PermissionDenied` over RPC).
[docs/sessions.md](docs/sessions.md#what-a-session-gives-up) says what a session gives up.
Over RPC the procedures are `OpenSession`, `SessionRun` (its own request message, so a
daemon that predates sessions refuses it instead of dropping the ID) and `CloseSession`;
the daemon binds each 128-bit session ID to its principal (an unknown and a foreign ID are
the same NotFound), never logs it, serializes calls, chains their records, suspends an idle
session and gives back its concurrency slot, and keeps an ended session's final count
collectable for 10 minutes. Sessions are off unless `SANDBOX_MAX_SESSIONS` is positive.
On docker, `SANDBOX_SESSION_POOL` keeps never-used session containers ready
([sandbox/docker_pool.go](sandbox/docker_pool.go), the `sandbox.SessionPool` interface): a
member is created and read back as a session's container is, gets an interpreter and its
relay for a set of the stated languages (`sessionkit.Interpreters.Warm`, so the first cell
still reports its interpreter as new), and is handed to `OpenSession` only while it matches
the verified execution state and its relays are attached; it is never returned or reused.
`SessionOptions.Languages` (wire `languages`) is a latency hint, checked by
`sandbox.SessionLanguages` (an unknown name refused, an unstated one dropped): a claim takes
the member warming the most hinted languages. A pool of 4 or fewer (`poolSplitMinSize`)
warms every language in every member; a larger one divides its size across language sets by
a decaying weight of the hints it sees (no hint = every language; one open moves a set's
weight by at most a quarter member's worth). Claims and refills follow the split; rebalance only replaces members of sets holding under
a quarter of the weight, at most one a minute (`poolMoveInterval`) and only when a move is
worth more than 1.75 members (1 + `poolMoveMargin`); hints never add members. A
member's lifetime label covers 30 minutes of waiting plus `SANDBOX_SESSION_LIFETIME`, and a
member idle 30 minutes is replaced. With the pool on, the startup session smoke test runs
on a claimed member.

Result semantics: a non-zero `ExitCode` is a **normal result** (the user's code
failed), not a Go `error`. Returned errors cover typed pre-dispatch failures
(`ErrInvalidRequest`, `ErrUnsupported`, `ErrDisabled`, `ErrAtCapacity`), context
cancellation/deadline, and unmatched infrastructure failures. **Whether anything ran
is a mark, not a code:** a refusal raised before any code was dispatched is a
`sandbox.NotDispatchedError` carrying a `Refusal` reason (`request`, `permission`,
`protocol`, `unsupported`, `isolation`, `environment`, `capacity`; `sandbox.NotDispatchedReason(err)`
reads it). The sandbox package marks its validators, isolation checks, admission,
grant issuance (an invalid grant or a failed mint, reason `permission`) and
every `ErrUnsupported`/`ErrDisabled` site at the source; the RPC layer builds every
handler-side refusal through `refuse` (a test fails on a Connect error built anywhere
else) and sends the mark as the `plimsoll.v1.NotDispatched` error detail, which the
client restores into the same Go error. **No mark means execution may have occurred**
(the module worker's exit 4 is `ErrInvalidRequest` after its container ran, and stays
unmarked), so an unmarked error is never a safe automatic retry. For projects,
per-step failures live in `Steps` and the top-level conclusion is the typed
`ProjectResult.Outcome` (`completed` / `setup_failed` / `timed_out` /
`protocol_error`, with human context in `Detail`) — a stable retry/status
classification. `timed_out` covers both a run that exceeded its whole budget and
a step killed by its own step budget: a timed-out step sets `StepResult.TimedOut`
**and** makes the run's `Outcome` `timed_out`, on every provider and for both
`RunProject` and `RunModule`, so a caller keying on `Outcome` alone cannot read a
hung step as a clean run. Output truncation is machine-readable everywhere: results carry
`StdoutTruncated`/`StderrTruncated` (and `ArtifactsTruncated`) flags and the
retained output is never annotated with in-band markers. On the wire,
stdout/stderr are protobuf `bytes`, so arbitrary guest bytes survive verbatim
instead of being lossily repaired into UTF-8. An E2B guest that floods its
output stream past the transfer budget is classified as a failed user run
(exit 153, both streams marked truncated), not an infrastructure error. Nor can guest
code pass its own exit for docker's: a docker snippet or project runner, in a run or a
session call, starts through a shell under `env -i` that writes a per-call start marker to
stderr before node exists (stripped, with anything the docker CLI printed before it, from
the result). A call whose stderr holds the marker ran, and its exit is the guest's; one
without it is never a result, whatever docker exited with or printed (no list of docker's
wording decides it): almost always docker failed before plimsoll's command started, but a
broken attach stream can lose the marker of a call that did start, so the error is never
marked not dispatched. A docker CLI killed by a signal is an infrastructure error, never an
exit code. A run that reached its deadline timed out only if the marker is there; without
it, it is that same unmarked error. What ended a run is read when docker returns, before
its container's removal, which can outlast the deadline. A
session call whose exit may be docker's is also checked against the container: paused,
stopped, gone or unreadable ends the session. A docker session finds its container gone
by an ID-filtered listing, never by docker's wording, and a read-back docker cannot
answer refuses the call (not dispatched, reason `environment`). A project's runner keeps only artifacts
the kernel says it opened inside the work directory (`/proc/self/fd`), so a step left
running cannot swap a parent directory for a link between the check and the open.

## Providers (`SANDBOX_PROVIDER`)
`Build(getenv)` selects one and fails closed: malformed safety configuration and
unrecognized provider names are explicit errors, and the default (unset) is
**Disabled**, so execution is opt-in and never on by accident. plimsolld builds
`openshell` itself, outside `Build`, so a program that imports package sandbox never
links its generated protocol code: each such provider registers from its own file in
[cmd/plimsolld/providers.go](cmd/plimsolld/providers.go)'s table, with its `-h` section
and its hardened-mode envelope.

| Value     | Provider | Isolation | Notes |
|-----------|----------|-----------|-------|
| `wasm`    | in-process QuickJS via wazero | process tier, lowest latency | JS snippets and snippet grants through a direct host function; no projects. An engine escape lands in plimsolld. |
| `docker`  | locked-down `docker run` | container under runc; kernel tier only after verified runsc Preflight | self-host/dev. Snippet and project JS grants both use a host-side Unix broker; a project preloads the same client into every step (`node --import`). Under runsc the runtime must be registered with `--host-uds=open` (the installer does) or the guest cannot reach the broker socket; the smoke test proves it can. Every container declares its lifetime as a label (a run's is its deadline); a run whose `docker run` does not exit 0 has its container removed at once, and `ReconcileOrphans` removes any container past its lifetime plus 5 minutes that no open session or pool holds. |
| `e2b`     | E2B Firecracker microVM | hardware-virtualized VM | isolated snippets/projects; grants require `E2B_GUARD_URL` and use E2B `allowOut` + deny-all plus the beta per-host header transform to reach the guard, which delegates the shared broker. Secured envd + public-traffic token; no-grant egress denied. No redirect from envd or the control plane is followed (a followed one would carry the envd and traffic tokens, or the API key, wherever a guest answering on envd's port pointed it), with the default HTTP client or an embedder's. A sandbox ID that is not letters, digits and dashes is never put in envd's host name or a path, and a vendor's error body is cut to 512 bytes with credentials scrubbed before it enters an error. Sandboxes are stamped with a per-instance metadata ID and a lease key tracked from before the create request until the kill has finished ([sandbox/internal/lease](sandbox/internal/lease/), the rule E2B, Docker Cloud and OpenShell share); `ReconcileOrphans` (run periodically by the daemon) reaps stamped microVMs whose key is not tracked, at any age, so a slow create is never reaped and a leak from a malformed or lost create response or failed teardown waits for no clock. |
| `dockercloud` | Docker Cloud Sandboxes microVM | hardware-virtualized VM | speaks two APIs through one internal transport interface, chosen by `SANDBOX_DOCKERCLOUD_API` and never switched at run time, both through the live suite on 2026-10-04: `rest` (default), the API Docker documents since launch, which states no image identity (it reports no booted digest, so hardened mode requires `connect`), caps a run at 270 s (an exec ends with its 300 s endpoint credential, one cached per sandbox) and refuses grants, failing startup if a guard URL is set (after the guard's rule the REST API will not report the sandbox's policy, so the rule cannot be verified; a live tripwire watches for that to change); and `connect`, Docker's pre-launch sandboxes-api v0.36.0, now undocumented, kept as the backup, the only API with grants and image evidence. Each run boots a pinned linux/amd64 sandbox, refuses to run unless the read-back network policy is deny-all with exactly the entitled rules, wraps every exec in `timeout`/`head -c` (the API has neither bound), and deletes the sandbox on every exit path; `ReconcileOrphans` reaps untracked ones. Grants need `SANDBOX_DOCKERCLOUD_GUARD_URL` (`ErrUnsupported` otherwise); unlike E2B, the guest holds its own per-run guard credential, and the grant rule is applied through a REST call outside the published contract. Operator setup (token exchange, deny-all account policy, single-platform digest) and the full run and smoke-test sequence: [docs/dockercloud.md](docs/dockercloud.md). |
| `openshell` | NVIDIA OpenShell sandbox through a gateway | container (the gateway's docker driver; any other driver is refused) | built by plimsolld, not `Build`. Keeps sessions (a sweep of every non-own process after each call, `sleep` as the main process, a read-back before each call). Each run creates a sandbox with no network rules (the gateway's deny-all default) and `/tmp` as the only writable directory (a `noexec` tmpfs of `SANDBOX_DISK_MB` when that is set), reads it back and refuses any difference, runs the payload over the streamed exec (the deadline cancels the stream, which kills the command's process group; a `setsid` descendant lives until the delete), and deletes the sandbox off the result path, holding the run's capacity until the delete is through (`sandbox.HoldCapacity`; admitters wrap their release with `sandbox.WithCapacity`); `Drain` waits for those deletes at shutdown. Every sandbox declares its lifetime, so `ReconcileOrphans` also reaps what a crashed instance left behind, once that lifetime plus 5 minutes has passed. Grants keep the no-grant policy: a relay in the sandbox pairs the guest's socket connections with connections plimsoll dials in through `ForwardTcp` (session tokens revoked at the run's end), and plimsoll serves the shared broker on them. Module runs: `ErrUnsupported`. Operator setup, grants and the smoke test: [docs/openshell.md](docs/openshell.md). |
| unset     | Disabled | n/a | returns `ErrDisabled`; any other value fails `Build`. |

Relevant env: `SANDBOX_DOCKER_IMAGE`, `SANDBOX_DOCKER_PROJECT_IMAGE`,
`SANDBOX_DOCKER_MODULE_IMAGE` (the simulation worker image; unset = module runs
unsupported),
`SANDBOX_DOCKER_RUNTIME` (`runsc` for a real gVisor boundary),
`SANDBOX_DOCKER_SECCOMP` (path to a syscall-filter profile; set it
to the shipped audited allowlist `docker/seccomp.json` to deny non-cap-gated attack
surface like `ptrace`/`io_uring`/`keyctl` — see [docs/seccomp.md](docs/seccomp.md)),
`SANDBOX_GUEST_UID` (the uid and gid docker runs every guest as; default 61000, a uid no
account uses: below 65,536 so it starts under userns-remap and rootless docker, in the band
systemd leaves unused; Preflight refuses one, or the session identity check's uid + 1, that
this host's `/etc/passwd` or `/etc/group` has; under runc without remapping a container's
uid is the host's, so an escape lands as no account),
`SANDBOX_REQUIRE_PINNED_IMAGES` (`=1` to require both images to be
`@sha256:`-pinned),
`E2B_API_KEY`, `E2B_TEMPLATE`, `E2B_GUARD_URL` (the guard is **process-local**: a run's
guard credential lives only in the memory of the process that opened that run, so the
public guard URL must resolve to that same process — an ordinary load balancer across
replicas rejects valid guard calls as unknown credentials), `DOCKER_SBX_TOKEN` (a Docker
personal access token with the Cloud Sandboxes scope, read from the environment only),
`DOCKER_SBX_USERNAME` (the account it belongs to), `SANDBOX_DOCKERCLOUD_AUTH_URL`
(the token exchange; default Docker Hub's), `SANDBOX_DOCKERCLOUD_API` (`rest`, the default, or `connect`),
`SANDBOX_DOCKERCLOUD_API_URL`
(the management endpoint; for `connect` required, since Docker documents no default,
and `https://sandboxes.connect.docker.com/sbx` answered on 2026-10-04; for `rest` it
defaults to the documented `https://connect.docker.com/sandboxes`),
`SANDBOX_DOCKERCLOUD_IMAGE` (the raw OCI image each sandbox boots; `@sha256:` when
pinning is required; dockercloud honors `SANDBOX_MEMORY_MB` and whole `SANDBOX_CPUS`,
requested at create and verified after it, and rejects `SANDBOX_PIDS`/`SANDBOX_DISK_MB`),
`SANDBOX_OPENSHELL_GATEWAY_URL`, `SANDBOX_OPENSHELL_CA_FILE`, `SANDBOX_OPENSHELL_CERT_FILE`
and `SANDBOX_OPENSHELL_KEY_FILE` (the gateway and its mutual TLS files),
`SANDBOX_OPENSHELL_IMAGE` (must carry `node`, `sh`, `/usr/bin/env`, `/runner.mjs` and
`/usr/local/lib/plimsoll-runner-guard.so`; openshell honors
`SANDBOX_MEMORY_MB` and `SANDBOX_CPUS` (plus an equal amount of swap on a host with swap:
OpenShell sets no swap limit), rejects `SANDBOX_PIDS`, and with `SANDBOX_DISK_MB`
mounts a run's `/tmp` as a `noexec` tmpfs of that size through the sandbox's driver config,
which needs the gateway's `allow_driver_config = true`; never a session's),
`SANDBOX_MAX_SESSIONS` (open sessions at once; default 0, sessions off; startup fails when
set for a provider without sessions), `SANDBOX_MAX_SESSIONS_PER_CALLER` (open sessions one
principal may hold, suspended ones included; default 0, no cap beyond the daemon's; a
suspended session holds no concurrency slot, so the per-caller concurrency cap does not bound
them), `SANDBOX_SESSION_POOL` (docker only: never-used session containers kept ready,
each with an interpreter and relay already attached for every language the image runs;
default 0, at most `SANDBOX_MAX_SESSIONS`; one goes to one session and is removed at its
close, never reused; each is charged one run's memory against `SANDBOX_TOTAL_MEMORY_MB`, in
plimsolld's clamp and in `WithAdmission`; [docs/sessions.md](docs/sessions.md#docker)), `SANDBOX_SESSION_LIFETIME` (default 30m, at most
12h), `SANDBOX_SESSION_IDLE` (default 5m; 0 never suspends; otherwise 1s to 12h, and a
request may ask for less but not under 1s), `SANDBOX_SESSION_DISK_MB`
(default 1024; 0 disables the check and measures nothing; disk use is measured after each call,
on docker as the used space of the session's tmpfs mounts (`statfs`), on openshell by a walk
the session's code can hide files from;
exceeding the limit ends the session, but it is not enforced during the call; openshell's
`SANDBOX_DISK_MB` caps runs only, because docker discards a tmpfs when a suspend stops the
container),
`PLIMSOLL_GRANTS_FILE` (named host-API capability
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
smuggle an unverified image past that check; once the startup smoke test has run, only
the IDs it proved: a tag re-pointed later fails Preflight, so `/readyz`, and its runs are
refused, not dispatched, reason `environment`, until a restart proves the new content), the
limiter `SANDBOX_MAX_CONCURRENT`/`SANDBOX_PER_KEY_CONCURRENT`/`SANDBOX_RATE_PER_MIN`/
`SANDBOX_RATE_BURST`, and the aggregate budget `SANDBOX_TOTAL_MEMORY_MB` (clamps
max-concurrent to total/per-run so concurrent runners cannot oversubscribe the host;
ignored for e2b and dockercloud, whose runners live off-host), and for a provider billed by
the second (`sandbox.Metered`: e2b, dockercloud) the daily allowances in seconds of microVM
wall time, `SANDBOX_PAID_SECONDS_PER_DAY` for the daemon and `paid_seconds_per_day` per
caller in `PLIMSOLL_CLIENTS_FILE` (internal/rpc/spend.go: a run the provider supports
reserves its clamped timeout plus the provider's `BillingTeardown` before admission,
refused not dispatched, reason `capacity`, when either allowance would go over, and is
charged the wall time of the provider call, or its whole reservation when the provider
could not delete the microVM (`sandbox.TeardownGaveUp`: the delete gave up, or a create's
outcome is unknown: on E2B an error that does not prove the request never left, an answer
neither a success nor a 4xx refusal, or a success without a usable ID; on Docker Cloud an
answer that is not a refusal or an operation still running, unless the cleanup delete
removed the sandbox), since the microVM then bills until
the provider's own lifetime for it ends; UTC days, a run crossing midnight counted in the new
day for the part after it; per daemon, so placement's retry on
a capacity refusal lets a caller spend its allowance once per daemon; the counters live
in memory, so a restart forgets the day's spend; refusals are counted in
`plimsoll_shed_total`). Each provider reports its boundary via
`IsolationClass()` and in the RPC response `isolation` field, and the **`Describe`
RPC** reports the active provider, tier, project and module support, and
operation-specific grant support (via `ProjectCapable` / `ModuleCapable` /
`GrantCapable`) so a gateway does not
hard-code claims. It also states each payload kind's environment
(`sandbox.Describer`): an exact outer artifact identity such as Docker's verified
image index ID, a separate `SoftwareIdentity` for the selected platform manifest
when Docker can establish it (the containerd image store and Docker Engine >= 28.1,
whose `docker image inspect --platform` it uses; the classic store gives none, and the
containerd store on an older engine fails Preflight rather than run without one), and the provider's timeout ceiling. A tag or template
name is never an identity. The per-run resource envelope is also reported. A caller
can require one exact software identity or an explicit approved set through
`sandbox.SoftwareRule`. The daemon checks it before dispatch against the `Describe`
evidence it holds, which can be stale; each shipped provider checks it again against
the artifact it is about to launch (docker against the manifest it verified, the others
against the empty identity, so a required rule fails closed); and the client checks the
run record, which states the identity the run reported. The record check is the binding
one: a client that reads `software_identity` off the response and skips it has only the
daemon's word. A missing software identity fails a required rule. Other
providers leave it empty until they can establish their selected artifact.
**A reported tier is configuration and provider evidence plus the
behavioral smoke tests below — never runtime attestation**, and any surface that
advertises a tier has to carry that qualification (README states it in full under the
provider table). It also advertises minimum-isolation protocol support; this is
discovery only. Execution is one procedure, **`Run`**: an envelope (a `protocol`
number, the `minimum_isolation` floor, the software rule, the opaque `trace_id`, the timeout) around
exactly one payload (`javascript`, `project` or `module`), answered by an envelope
(provider, isolation evidence, duration) around a result of the same kind. The
protocol number is the mixed-version gate: protobuf drops fields a receiver does not
know, so a daemon that predates a security-relevant request field would execute a
request without it. A client states the number it speaks (`protocol.Number`, which
the official client stamps as `client.Protocol`) and a daemon serves exactly one: a
request that omits it is InvalidArgument and a request on another number is
Unimplemented, both before the payload is read. `Describe` reports the daemon's
number. Bump `protocol.Number` when a request field is added whose omission would
change what a daemon may execute; an informational field does not bump it. Every answered
`Run` carries a **run record** (`RunResponse.record`, package [record](record/)): SHA-256
digests of the request as sent and the result as returned, the evidence (provider, tier,
outer environment, selected software identity, caller's admission rule, verified
sandbox policy) and the daemon's start and end
times. The daemon only hashes and holds no key; the official client recomputes both
digests and returns a mismatch as `DataLoss` (`record.ErrMismatch`), and a harness outside
the daemon signs checked records. A session call that may have run but ended in an error (no
not-dispatched mark) is chained too: a version 3 record (no result digest, the error's Connect
code in `unanswered`) rides on the error as the `UnansweredCall` detail, the clients check and
keep it, and the session goes on. Encoding and field list: [docs/run-records.md](docs/run-records.md). The daemon serves `GET /healthz` and
`/readyz` outside auth on its RPC listener. `GET /metrics`, also outside auth, has a listener of its own,
`PLIMSOLL_METRICS_ADDR` (default `127.0.0.1:9464`: loopback and port 9464 are OpenTelemetry's Prometheus exporter
defaults; `off` disables it), because its labels name grant profiles and route templates, which a caller who can reach the RPC
port has no business reading. `/readyz` re-runs the provider's bounded `Preflight`: for docker
that probes the pinned daemon and runtime, but for e2b and dockercloud it validates **configuration only**
and proves nothing about API reachability, token or key validity, or guard routability — the
behavioral proof is the one-shot startup `SmokeTest`, which creates a real billable
microVM and so must never run on an unauthenticated poll path. A failing `/readyz` answers `not ready` and nothing
else (the error goes to the log, at most every 30 s), and a poll that hangs up cannot change the evidence: docker's
`Preflight` runs detached from its caller's cancellation, so only a real failure drops the tier, and plimsolld
re-runs `Preflight` every minute while the tier is below what startup proved. `Describe` reports current isolation evidence but only
structural/static operation support. Every provider whose boundary depends on the
host or a remote service (docker, e2b, dockercloud, openshell) runs a startup
**`SmokeTest`** (behavior, not just configuration) via `EnsureReady`, and none
serves if it fails. With sessions enabled, plimsolld then runs `sandbox.SessionSmokeTest`
on one real session (the sweep kills a process a call left, files survive calls and a
suspend, a cell's interpreter keeps state in every stated language and after a suspend keeps
it or says it is fresh, a call cannot open a running relay's pipes, a failing call is a
result with its exit code, close ends it), and a
failure refuses startup too. wasm has none, and its startup check is configuration only: its
boundary is wazero library code compiled into plimsolld (the per-run memory cap, no
network API), the same on every host, so the gate's tests (`TestWasmMemoryLimitEnforced`,
`TestWasmHasNoNetworkOrFS`) are its proof. For docker: one throwaway lockdown container per configured
image (launched by its Preflight-verified content ID), under the exact
runtime/seccomp combination, must prove from its own mount table that the root fs
is read-only and every writable mount is a tmpfs with the exact promised size +
`noexec`/`nosuid` — and, by attempting a real write at every mount point, that
the promised mounts are the **only** ones that accept writes at all (device-node
mounts like docker's `/dev/null`-masked proc paths are excluded: their writes
discard rather than persist), that loopback is its only network interface (what
`--network none` gives under runc and runsc alike; a structural check, so an offline
host cannot pass it by accident), and that its cgroup's `pids.max` is exactly the
configured process limit (a runtime can accept `--pids-limit` without applying it;
an unreadable value or a non-positive `PidsLimit` fails closed). Under runsc the guest
reads gVisor's emulated cgroup files, which say `max` whatever was set, while runsc
applies the limit to the whole sandbox's cgroup on the host, so the smoke test starts
one more lockdown container and reads `pids.max` from that host cgroup instead, located
through the PID docker reports and refused unless the cgroup path names the container
(the limit there also counts gVisor's own tasks: [docs/gvisor.md](docs/gvisor.md)). Preflight also requires both images to be present
(inspectable) on the pinned daemon. The first probe container also mounts a
throwaway host Unix socket exactly as a run mounts the per-run broker socket and
must reach it: whether a guest may connect to a host socket is a runtime property
(runsc needs `--host-uds=open`, which `docker/install-gvisor.sh` sets), and a runtime
that cannot broker grants must refuse to serve rather than fail every grant run.
For every project and module image, a second throwaway container runs its real
entrypoint; a project step must be unable to open the runner's plan descriptor,
report descriptor or memory, and the runner itself checks that before reading a
plan. A failure refuses startup.
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
For dockercloud: a capability check, then one throwaway sandbox proving deny-all
policy, file upload, the exec wrapper, the step cwd and in-guest egress denial
([docs/dockercloud.md](docs/dockercloud.md#startup-smoke-test)).
`plimsolld -h` prints the full env list; the text is `helpText` in
[cmd/plimsolld/providers.go](cmd/plimsolld/providers.go) (the usage constants in
main.go plus each daemon-built provider's section), and a test fails if the package
reads a variable that text omits. The daemon refuses any other argument.

**Hardened mode (`PLIMSOLL_HARDENED=1`)** turns the soft production posture into
an enforced startup policy: a warning is not a policy. It refuses to serve unless
every advertised production property is verifiably in force — `vm` or verified
`kernel` isolation (post-`EnsureReady` evidence, so docker means proven runsc),
multi-client auth (`PLIMSOLL_CLIENTS_FILE`; a shared token or open dev mode is
rejected), TLS on any non-loopback listener (the metrics listener included), an immutable execution surface
(docker: `SANDBOX_REQUIRE_PINNED_IMAGES=1`, no `unconfined` seccomp; e2b: an
explicit `E2B_TEMPLATE`; dockercloud: `SANDBOX_REQUIRE_PINNED_IMAGES=1`), an explicit
per-run resource envelope (memory and CPU only for dockercloud, which has no disk
control) plus, for docker, whose runners share the daemon's host, the aggregate memory budget, per-caller rate limiting with a burst no larger than a minute's rate, and a per-caller concurrency cap (`SANDBOX_PER_KEY_CONCURRENT` positive and below `SANDBOX_MAX_CONCURRENT`: a rate limit bounds what a caller starts, not the slots its long runs or running sessions hold), and with sessions on a per-caller session cap (`SANDBOX_MAX_SESSIONS_PER_CALLER` positive), and with a provider billed by the second a daily allowance on every caller (`paid_seconds_per_day`). Every violation is reported at once
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

## Module runs (the `module` payload)
A *module run* executes a compiled physical simulator once per parameter row. The
simulator is an AOT-compiled WebAssembly module (a source-form FMU or any C behind
`docker/sim/shim.c`) baked into the **module image** at `/models/<id>.so`; the
worker (`docker/sim/worker.c`, a C program on WasmEdge's C API, vendored from the
sister repository) loads it once and runs one fresh instance per row. Register a
simulator = build an image: an AOT module is machine code that must be mapped
executable, every writable mount is `noexec`, and the image root is the only place
it can load from. plimsoll supervises the worker as a process inside its container
tier and **never links the runtime**: the Go TCB stays pure Go, wazero keeps the
snippet tier.

The operation reuses the project machinery end to end (`DockerSandbox.runPlan`):
the parameter table is written into `/work` as text (shortest round-trip
decimals), one step runs `sim-worker --table` with the result budget on its command
line, and the results come back as one artifact in a versioned record (`"PLSM"`,
version, rows, width, params; then per row an int32 status and status × width
float64 outputs) that `sandbox.DecodeModuleResults` bounds-checks before anything
is trusted. The row width must equal the simulator's own `sim_run` parameter count and
the output width is the module's exported `sim_width()`; the worker reads both from
the module, so the daemon assumes no layout. It trusts neither beyond its buffers: a
width past 1,048,576 refuses the module, and a row whose `sim_run` claims more steps than
the worker allotted fails (status -110) instead of being copied. Over RPC every NaN of an output is sent as the quiet NaN with
no sign or payload (`0x7ff8000000000000`), the one Python's and JavaScript's NaN encode to,
so a JSON client's record check agrees whatever NaN the simulator produced. `ModuleResult.Outcome` reuses the
project outcome type: `completed` (every row has a status; a failed row is a
negative status, the table continues), `setup_failed` (the worker refused: unknown
simulator, a row of the wrong width), `timed_out`, `protocol_error` (an undecodable
record, a signal). **Results are never truncated.** `ValidateModuleRequest` refuses
pre-dispatch a table whose results could not fit the 8 MiB artifact budget even at
one output per step; the worker refuses with the true width before running any row
(exit 4, surfaced as `ErrInvalidRequest`); a worker that accepted a table and still
overran the budget is a protocol error, not a shorter answer. Limits:
`MaxModuleRows` 100,000, `MaxModuleRowWidth` 64, `MaxModuleSteps` 1,000,000, the
project timeout ceiling. Every row of a table is one instance in one process; a
caller shards a big table across calls, because WasmEdge instantiation contends
across threads in one process and not across processes.

`Describe` advertises `supports_module` (a module image is configured). The audit
line carries the request's `model` ID (validated to a filename stem), row count, row width,
step bound, outcome and duration, never a parameter value. `wasm`, `e2b`,
`dockercloud` and `openshell` return `ErrUnsupported`; the E2B shape would be the same
worker in a template, later.
What the test proves (`sandbox/docker_sim_test.go`, required mode in CI): 100
VanDerPol rows through `RunModule`, re-encoded, hash to the native C checksum, then
50 Lorenz rows of 60 s (three outputs, 6,000 steps each: chaos would turn a one-ulp
difference anywhere into a checksum miss), and every refusal above behaves as stated
under the shipped seccomp profile.

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
be wire-encoded are rejected before upstream dispatch, and so are `;` and all-dot
segments, which some upstream servers reinterpret after the match (`/a/..;/b`
reads as `/b` on Tomcat and Spring), and a `*` never binds a segment containing `:`
(`/items/a:setIamPolicy` is another operation on AIP-136 APIs). An optional `Preamble` lets
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
injected client's own methods (`get`/`put`/`post`/`patch`/`del`/`call`) or an `Object.prototype`
name (`__proto__`, `constructor`, ...) is refused. Each derived route is checked as a grant
checks it (`sandbox.ValidateHostRoute`, which `grants.Load` also applies to a profile's
`catalog`); a control character or line terminator in the title, version or a path is
refused, since they reach the preamble's comment and the description; a summary is folded
to one line. The
generated SDK is **executed in QuickJS by the tests**, so a preamble that does not parse or
throws on its first call fails the build. `-emit catalog` gives the full route list for a
profile's `catalog` (see the advisory channel). It emits an optional concrete `health_check`
recovery probe only for the operation explicitly marked `x-plimsoll-health-check: true`;
`-emit health` outputs that profile line. A collection GET marked
`x-plimsoll-batch-of: [operationId, ...]`, naming the per-item GETs one request to it
replaces, becomes the profile's `batch_of` (`-emit batch`; see the advisory channel); an
operationId that is unknown, ambiguous or names an operation a grant cannot express fails
generation, and the result passes `grants.ParseBatchOf`, the check `grants.Load` applies. Worked example:
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
upstream request, traffic budgets (256 calls by default, 1 MiB request, 4 MiB
response; a profile's `max_calls` raises the call budget for a workload that is a
loop by design, never past `MaxHostCallsCeiling` of 100,000, and the metadata trace
stays capped at the default 256 rows either way, counting the rest as `Dropped`;
16 calls in flight; 60 s per upstream call, headers and body),
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
The guard endpoint (E2B and dockercloud) admits per run before it reads a body: at most
16 of a run's requests in the handler and 2 holding one of the shared decode slots
(plimsolld sizes the pool at twice `SANDBOX_MAX_CONCURRENT`, so every live run keeps its
share), and an admitted body must arrive within 10 s. A run's grant ends with its code,
before the VM is killed or deleted: a call a detached guest process makes during the
teardown is refused, so the trace a run returns holds every call its grant served.

**Over RPC:** a caller selects a **named, server-side profile** via the
`grant_profile` request field; profiles are loaded from `PLIMSOLL_GRANTS_FILE`
(see [internal/grants](internal/grants/)). The registry is frozen after load:
`Profile.Grant()` returns a deep copy per dispatch, so nothing downstream can
mutate a loaded profile for later runs. The caller can only *select* a profile —
BaseURL, allowed routes, and the token all live server-side. A raw caller-supplied
grant is intentionally **not** accepted over the wire. Every profile also requires
an `allowed_callers` ACL of authenticated principal IDs; `code:run` alone does not
grant downstream capabilities. A profile serves calls inside a session only with
`allow_in_sessions: true`. Each profile's `token` config
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
list of `{id, token_sha256, scopes, paid_seconds_per_day}`, the last optional; see
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
with `make generate`, never a bare `buf generate`, whose `clean` step would empty
the tree before any vendored template runs; local plugins, no network).

Every run is **audit-logged** (`slog`): one structured line per RunJavaScript/
RunProject with the caller (principal UserID, never the token), code/file sizes,
`grant_profile`, provider, exit code, timed-out, and duration — never the code
contents. Raw HTTP bodies and decompressed Connect messages are independently
capped. HTTP middleware authenticates before Connect reads the body, bounds
concurrent decode work (a slot covers the body only, given back once it has been read,
and one caller holds at most half the slots), and the server applies a whole-body read
deadline. A session holds one call waiting for its turn; a further one is refused, not
dispatched, reason `capacity`. An internal fault reaches the caller as `internal error
<id>` only; its text (which can carry a vendor's response body or docker's stderr) goes
to the log under that ID, cut to 4 KiB. Refused credentials are counted and logged at
most every 30 s, never the token; a caller token (imported, or `PLIMSOLL_TOKEN`) is at
least 32 characters. Go's
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
   `ExtraCalls` is the successful count minus one (as rigorous as the operator's
   declaration when a declared, granted batch route is named), `AddedLatency` is summed
   round trips beyond one call (a model, not wall time lost), `BytesMoved` is the gross bytes the
   pattern moved (not a saving). Do not reintroduce the removed aggregate-in-code or
   sequential-calls detectors: the trace holds no call start times and no guest content,
   so it cannot support them (docs/efficiency-advisor.md). A small router names a batch
   route for a **GET** fan-out only, and says on what basis. A profile's `batch_of`
   (`{"GET /items": ["GET /items/*"]}`, or specgen's `x-plimsoll-batch-of`) is the
   operator's statement that one request to the batch route returns what the per-item
   calls did; plimsoll cannot check it, since pagination, returned fields and scope are
   outside the trace. A declared route the profile grants makes the finding
   **agent-fixable** (`Finding.Suggested`), the only route a finding ever hands the
   caller; a declared route it does not grant is the operator's one line to add
   (`Finding.GrantRoute`, audit `grant_route`). Without a declaration, the per-item
   route's collection (`/items` for `/items/*`), granted or listed in the profile's
   `catalog` (its full endpoint list, e.g. `plimsoll-specgen -emit catalog`), is a
   **candidate** (`Finding.Candidate`, audit `candidate_route`): operator-only, to check
   and then declare, because a path shape is no evidence that the route returns the same
   items. A write fan-out is never routed: `batch_of` refuses a write, and a collection
   write's semantics cannot be read off its path.
   **A finding is therefore one of four things, and the last is not a verdict:** a
   declared, granted route covers it; a declared route needs granting; a candidate needs
   checking; or *no route is known*. Only in that last case does `insights.Prompt` render
   a paste-ready prompt for the customer's own AI, and it asks for the smallest change
   **or for a plain statement that none is warranted** — one run's trace cannot show that
   an API forces a pattern on every caller, the granted routes may be a subset of what the
   API offers, and a profile need not declare a catalog at all. For a read fan-out the
   prompt also offers a server-side aggregate as a conditional alternative, which is
   where the aggregate idea now lives. plimsoll emits text and **never calls an LLM itself**. The HTML report keeps
   the four classes distinct (`report.Class`) and carries the WIP notice the advisor
   example page carries.
3. **Routing by audience.** Per-profile `advice: off|operator|caller`
   (`grants.AdviceMode`) decides who can act: `off` computes nothing; `operator` keeps
   findings on operator surfaces; `caller` additionally returns the agent-fixable subset
   on the run result's `advice` field (`internal/rpc/advice.go`). The official Go
   client maps that field onto `sandbox.Result.Advice` and `ProjectResult.Advice`
   (`[]sandbox.AdviceFinding`, transport-independent: pattern, severity, remedy,
   route template, suggested route, and the cost numbers); direct in-process
   providers leave it nil, since advice is a service-side computation. The `javascript`
   and `project` payload kinds compute and route advice the same way over their run's `CallTrace`.
   Findings with no declared, granted route stay operator-only regardless.
4. **Retention of durable telemetry.** Per-profile `advice_retention: none|aggregate|detailed`
   (`grants.AdviceRetention`) gates only what reaches the **durable audit log**, orthogonal
   to the audience: `none` (default) writes nothing, `aggregate` writes per-run totals,
   `detailed` writes one metadata-only record per finding (`advice_finding_details`, the
   stream the [prospector-report](cmd/prospector-report) HTML renders). The caller wire
   hint and the bounded `/metrics` aggregates (labels only: profile/pattern/severity/remedy,
   no route templates) are governed by `advice` alone, not by retention. plimsoll is
   stateless: it stores nothing, so retention is about what it *emits*. Full rationale in
   [docs/efficiency-advisor.md](docs/efficiency-advisor.md).

## Build, vet, test
```sh
go build ./...
go vet ./...
go test ./...     # the e2b and dockercloud *live* tests skip without their credentials
```
Some tests need a local docker daemon and the five images `make docker-images`
provides: `node:22-alpine` for snippets (pulled), and `plimsoll/sandbox:latest` for
`RunProject` plus the `-python`, `-sim` and `-wasm-cc` images derived from it (built).
Every docker test needs the images its sandbox is configured with, because Preflight
requires them all. Each image `make docker-images` builds carries a hash of its build
context (`docker/`, minus the literal paths in `docker/.dockerignore`) as the label
`io.plimsoll.inputs`, and `make docker-suite` refuses an image whose label is not the
current hash: after editing `docker/`, rebuild the images. Without them those tests skip in an ordinary run and fail under
`make audit DOCKER=1`. Only the docker suite runs them: `make audit`'s race pass and
`make test` run with `-short`, which the docker test helpers (`requireDocker`,
`sessionDocker`) read as skip, so a docker test reaches docker only through one of
them. The docker suite also covers the oracle's anti-forgery tests
and the gVisor installer's offline-bundle check (which needs `zstd`). Run the gate
as a non-root user: root defeats the runner guard two runnerwire tests exercise, so
they skip.

`make audit` is the single local gate: build, vet, race tests (`-short`: no docker), golangci-lint,
`buf lint` plus a generated-code drift check, and `govulncheck`. A working copy may append steps
of its own through an optional, unpublished `local.mk` (`EXTRA_AUDIT`). The real
infrastructure suites are opt-in: `make audit DOCKER=1` adds the
docker/seccomp/broker/smoke tests, `make audit E2B=1` (with `E2B_API_KEY`) adds
the live E2B suite, and `make audit DOCKERCLOUD=1` (with `DOCKER_SBX_TOKEN`,
`SANDBOX_DOCKERCLOUD_API_URL` and `SANDBOX_DOCKERCLOUD_IMAGE`) adds the live Docker
Cloud Sandboxes suite, which fails rather than skips when that configuration is
absent. `make audit OPENSHELL=1` (with a gateway and the `SANDBOX_OPENSHELL_*`
settings) adds the live OpenShell suite, the provider's tests plus a daemon test
against the gateway; it is free but needs a gateway, and it too fails rather than
skips. `make help` lists individual targets.

**The ordinary gate cannot spend.** A bare `go test ./...` with `E2B_API_KEY` or
`DOCKER_SBX_TOKEN` (plus its API URL) in the environment runs a live suite, which
creates billable microVMs. So the `test`, `race` and `docker-suite` targets run
under `env -u E2B_API_KEY -u DOCKER_SBX_TOKEN`; only `e2b-suite` and
`e2b-guard-live` see the E2B key, only `dockercloud-suite` sees the Docker token,
and each paid suite strips the other's credential. Prefer the make targets to a bare `go test ./...`
in any shell that may hold a key. Docker is deliberately *not* hidden from the
ordinary gate: those tests are free and local, and they are the isolation proof.

One claim the gate does **not** make: `make audit E2B=1` runs `-run 'E2B.*Live'`, and
`TestE2BGuardLive` skips unless `E2B_GUARD_URL` and `E2B_LIVE_GRANT_BASE_URL` are
also set, so a green E2B suite does not mean the guarded-egress path was exercised.
`make e2b-guard-live` is that run, and it fails rather than skips when its
configuration is absent, so a pass can only come from actually proving the path.
Startup `SmokeTest` proves deny-all egress on a no-grant microVM; it does not create
a guarded VM, and it never proved "denied except for the guard".
The same holds for the OpenShell disk cap: `TestDiskCapLive` asserts whichever outcome
the gateway gives, the cap enforced or startup refused for want of
`allow_driver_config`, and logs which. A green `make audit OPENSHELL=1` proves the cap
itself only against a gateway that allows driver configs.

The three tools the gate shells out to (buf, golangci-lint, govulncheck) are outside
the module, so they are pinned in [gate-tools.versions](gate-tools.versions) and the
gate's first step (`tools-check`) fails on a version mismatch. Otherwise "audit: OK"
means only that it passed under whatever happened to be on `PATH`, which is not the
claim this gate makes. `make tools` installs the pinned set; the codegen plugins are
pinned separately by go.mod `tool` directives.

**CI** ([.github/workflows/](.github/workflows/)) runs plain `make audit`, then
`make clients-suite` (both `npm ci` installs and the Python, TypeScript client,
add-on and Trigger.dev tests in required mode) and `make docker-suite` under runc.
The docker suite also runs under runsc in a separate workflow, so a runsc failure
cannot mask the runc result; what each green check proves is in
[CONTRIBUTING.md](CONTRIBUTING.md). The client and provider jobs run their required
suites without repeating the build, race tests, lint, generated-code check or
vulnerability scan.
`make docker-suite` is a request for proof: a missing daemon or image, or any
`--- SKIP` line, fails it. No CI run exercises E2B or Docker Cloud
Sandboxes, deliberately, because they spend: **never add an E2B key or a Docker token
to repository secrets.** No CI run exercises OpenShell either, because it needs a
gateway. Third-party actions are pinned by commit SHA, since a tag is
mutable.

**Credentials never land on disk.** `E2B_API_KEY` and `DOCKER_SBX_TOKEN` are read
from the environment by the provider and its live suite, and nothing writes them
anywhere (`E2B_API_KEY="$KEY" make audit DOCKER=1 E2B=1`).

**Module identity.** The module path is `github.com/plimsollmark/plimsoll`, resolved
from `proxy.golang.org` and verified by `sum.golang.org` like any public module.
Consumers `require` tagged versions with no `replace`; sibling development uses an
uncommitted workspace (`go work init . ../plimsoll`, gitignored), which resolves the
working tree and proves nothing about the pin, so verify with `GOWORK=off`. Public
releases start at v0.2.0 because v0.1.0 to v0.1.7 are spent pre-publication tags:
never reuse one. **Do not re-add a `GONOSUMDB` exemption for this module.** Why the
path, the gap and the exemption are what they are: [docs/releasing.md](docs/releasing.md).

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
  timings, and trusted labels — never a raw path, query, body, or credential. `CallRow`
  has no body/credential field by construction; findings and prompts are templated from
  trusted inputs only (route templates + numbers) and must never echo a guest-controlled
  string. Preserve this on every new advisory surface, and never let advisory code call
  an LLM. See [docs/efficiency-advisor.md](docs/efficiency-advisor.md).
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
