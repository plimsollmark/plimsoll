# plimsoll

A sandbox service for running untrusted, agent-authored code that **reports the
isolation boundary each run executed behind, and refuses the run when it is weaker
than the caller demanded**.

A Plimsoll line is the load limit painted on a ship's hull. It is mandatory, and it
is on the outside where anyone can check it. That is the idea here: the isolation
tier is a value the caller reads, asserts a floor against, and re-checks on the
response, not a sentence in a datasheet.

What backs that value is provider-specific startup evidence, described exactly under
[Isolation tiers](#isolation-tiers) below. Read the tier as evidence this daemon
collected, not as a remote attestation: no provider here cryptographically attests
the runtime implementation underneath it.

```go
res, err := provider.Sandbox.RunJavaScript(ctx, sandbox.Request{
    Code:             "console.log(6 * 7)",
    MinimumIsolation: sandbox.IsolationVM, // ErrInsufficientIsolation means nothing ran
})
// res.Isolation reports the boundary that actually ran.
```

## Status, plainly

- **Pre-1.0**, single author, no external users yet. Breaking changes land without a
  deprecation path, on purpose.
- **No third-party security audit has ever been performed**, and the author's own
  self-review ledgers are not published either. [SECURITY.md](SECURITY.md) says what
  exists, what it is worth, and what you can check yourself instead.
- **There is no CI.** The gate is `make audit`, run locally. See
  [CONTRIBUTING.md](CONTRIBUTING.md).

## The problem

Agent frameworks increasingly need to run model-authored code. The products that
offer this converge on one security sentence, "isolated per request, nothing
persists," because a single-runtime vendor has exactly one boundary to describe. None
of them let a caller ask which tier ran, assert a minimum before dispatch, or check
the answer afterwards.

Meanwhile the ecosystem ships safety claims that nothing checks. The founding example
for this project: a popular embeddable JavaScript sandbox advertised a `MemoryLimit`
that was a **no-op**. The library promised a limit it did not enforce, and nothing in
the type system or the docs revealed it.

plimsoll is the policy and attestation layer in front of a sandbox, not a sandbox
itself. Isolation is delegated to gVisor and Firecracker, which are better at it.

## Isolation tiers

Select a provider with `SANDBOX_PROVIDER`. **The default is Disabled**, so nothing
executes unless you opt in explicitly.

| `SANDBOX_PROVIDER` | Provider | Tier | Use it for |
|---|---|---|---|
| unset | Disabled | none | the default; returns `ErrDisabled` |
| `wasm` | in-process QuickJS via wazero | **process** | dev and low-latency snippets, **not hostile code** |
| `docker` | locked-down `docker run` | container, or **kernel** under verified gVisor `runsc` | self-hosted production |
| `e2b` | E2B Firecracker microVM | **VM** | hardware-virtualized isolation |

> **The WASM tier is in-process.** It is not an OS boundary and not a VM boundary. A
> QuickJS engine escape lands in the daemon process. It exists for latency and for
> development. Do not point it at genuinely hostile code.

Container tier under stock `runc` shares the host kernel. For hostile production
input, use `e2b`, or `docker` with `SANDBOX_DOCKER_RUNTIME=runsc`.

Both real providers run a startup **`SmokeTest`** that checks behavior rather than
configuration, and neither serves if it fails. The Docker smoke test launches a
throwaway container and proves, from its own mount table and by attempting a real
write at every mount point, that the root filesystem is read-only and that the
promised `noexec` tmpfs mounts are the only writable ones. The E2B smoke test
completes a real secured microVM create, stages files, runs a probe through the
actual project-step path, and checks live that egress is denied.

**Exactly what the kernel and VM tiers rest on**, since a security claim that is not
falsifiable is not worth reading. For `docker`, kernel tier requires that the daemon
this provider is actually connected to registers the configured OCI runtime, and
that `runsc` resolves there to an executable named `runsc`; runs then launch under
that runtime. That is daemon-registration evidence plus the behavioral smoke above.
It is not proof that the running kernel boundary is gVisor, and the code says so at
[docker.go](sandbox/docker.go) `Preflight`. For `e2b`, VM tier follows from provider
identity: E2B runs each sandbox in a Firecracker microVM, and plimsoll reports that
rather than measuring it. Its smoke test proves the microVM behaves as promised,
including denied egress, not that a hypervisor is present. Both are stronger than a
datasheet sentence and weaker than attestation; if your threat model needs the
latter, neither tier here supplies it.

## Asserting a floor

`MinimumIsolation` on a request is a per-dispatch security floor, compared against
current provider evidence immediately before admission. `ErrInsufficientIsolation`
means **no code ran**.

The client also checks the evidence that comes back. A mismatch is
`ErrIsolationEvidenceMismatch`, and it is deliberately not a safe retry signal:
execution may already have happened.

`SANDBOX_MIN_ISOLATION` is the operator-wide startup floor. It is not a substitute for
a caller asserting its own requirement, because a stale `Describe` response must never
be able to authorize a later downgrade.

## Capability grants

Without a grant, a run has **no network at all**. A grant is opt-in twice over: a nil
grant reaches nothing, and a grant with an empty allow list also reaches nothing.

A grant is **per-run**, not provider state, and it is domain-agnostic. It lets guest
code call an allowlisted HTTP API through an injected generic client
(`host.get/put/post/del/call`).

**The credential is minted per run and never enters the guest.** A grant carries a
`TokenMinter`, not a static token, so you can issue short-lived route-scoped
credentials that die almost immediately if exfiltrated. Enforcement lives in a shared
broker on the host side: Docker runs keep `--network none` and frame calls over a
per-run Unix socket, while WASM uses a direct wazero host function where only
`{method, path, body}` and a bounded response cross linear memory. In both cases the
token stays in Go.

The broker accepts only decoded, canonical paths that are byte-identical to an
approved route. Queries, traversal, and percent-encoding tricks are rejected before
anything is dispatched upstream.

Over RPC, a caller selects a **named server-side profile** by id. Raw caller-supplied
grants are intentionally not accepted over the wire, so base URL, routes, and
credential all stay server-side, and every profile carries an `allowed_callers` ACL.

## Telemetry is metadata-only by construction

Every brokered call is recorded in a `CallTrace` holding the matched route
**template**, verb, status, byte counts, and latency. `CallRow` has **no field** for a
path, query, body, or credential, so none can be captured by accident.

The honest form of that claim is the correlation id. `trace_id` on a request is an
opaque join key that gets echoed onto the audit line and is never parsed, routed on,
or sent upstream. The sensitive payload lives in exactly one place, one layer up, in
your own log. This is the difference between "we record less" and "we record the part
that is ours."

Because that field is caller-controlled, it is validated as `[A-Za-z0-9._:-]{1,64}`
and a non-conforming id is **dropped whole** rather than truncated. A truncated id
would look joinable and join to nothing.

Full rationale: [docs/advisory-privacy.md](docs/advisory-privacy.md).

## Hardened mode

`PLIMSOLL_HARDENED=1` turns the soft production posture into an enforced startup
policy, because a warning is not a policy. The daemon refuses to serve unless all of
the following are verifiably in force: VM or verified kernel isolation, multi-client
auth, TLS on any non-loopback listener, pinned images with no `unconfined` seccomp, an
explicit per-run resource envelope with an aggregate memory budget, and per-caller
rate limiting. Every violation is reported at once, so it is one fix pass rather than
a startup loop.

## Quick start

The module floor is Go 1.26.2, so consumers build unchanged. Build the daemon itself
with **1.26.6 or newer**, the toolchain this module pins: `govulncheck` is clean
there, while earlier 1.26.x carried stdlib advisories in the reverse-proxy and HTTP/2
paths this code actually calls.

Run something first. This needs no daemon, no docker, no credentials and no
network, because it selects the in-process WASM provider:

```sh
git clone https://github.com/plimsollmark/plimsoll && cd plimsoll
go run ./examples/minimal
```

```
provider   wasm
isolation  process
exit code  0
timed out  false
duration   312ms
stdout     {"Engineering":59000000,"Sales":20300000,"Operations":9800000}
```

That `isolation` line is the run's own evidence, not a claim by the example.
**`process` is not an OS boundary and is not a production posture for hostile
code** (see [Isolation tiers](#isolation-tiers)). The same snippet runs behind a
real kernel boundary once gVisor is installed:

```sh
SANDBOX_PROVIDER=docker SANDBOX_DOCKER_RUNTIME=runsc go run ./examples/minimal
```

The line then reads `isolation  kernel`, and nothing else about the program
changes. [examples/minimal/main.go](examples/minimal/main.go) is about forty
lines and comments each step.

To embed it:

```sh
go get github.com/plimsollmark/plimsoll
```

```go
provider, err := sandbox.Build(os.Getenv)   // errors rather than guessing
if err != nil { return err }
if err := provider.EnsureReady(ctx); err != nil { return err } // preflight + smoke test

result, err := provider.Sandbox.RunJavaScript(ctx, sandbox.Request{
    Code:    userCode,
    Timeout: 10 * time.Second,
})
// err means the run never happened. Code that merely failed returns
// result.ExitCode != 0, which is a normal result, not an error.
```

With `SANDBOX_PROVIDER` unset, `Build` selects the Disabled provider and runs
nothing. That is deliberate: execution is opt-in and cannot be switched on by
accident.

As a service:

```sh
SANDBOX_PROVIDER=docker \
SANDBOX_DOCKER_RUNTIME=runsc \
PLIMSOLL_CLIENTS_FILE=clients.json \
go run ./cmd/plimsolld
```

The daemon serves `plimsoll.v1.SandboxService` over Connect, plus `/healthz`,
`/readyz`, and `/metrics` outside auth. Auth is fail-closed once configured.

## What it does not do

Stated so you do not have to discover it in review:

- It does not implement an isolation boundary. gVisor and Firecracker do that.
- WASM supports snippets only, not multi-file projects, and WASM project grants are
  rejected outright.
- E2B grants require `E2B_GUARD_URL`; the forced, authenticated guard keeps
  credentials and route enforcement outside the hostile VM. Without a grant,
  E2B runs deny egress.
- There is no fleet-level gateway across instances. The control surface is per
  instance.
- There is no auto-patching supply chain. Images, the QuickJS artifact, gVisor, the
  codegen plugins, and the three tools the gate shells out to are pinned instead,
  which buys determinism and gives up automatic updates. One qualification, because
  "verified by digest" is not uniformly true: the gVisor installer pins the release
  on every architecture, but the checksum it compares against is recorded in this
  repository only for x86_64. Elsewhere it verifies the release bucket's own
  `.sha512`, which catches a corrupted transfer, not a compromised bucket.

## Examples

Three runnable programs, none needing docker, credentials or a daemon you start
yourself. Run them from the repository root.

| Command | What it shows |
|---|---|
| `go run ./examples/minimal` | One snippet, its result, and the isolation tier the run reports. |
| `go run ./examples/grant` | The capability model: a permitted route, a refused one, the same refusal when the guest bypasses the injected client, and a search for the credential that comes back empty. |
| `go run ./examples/daemon` | The service path: plimsolld started with a real multi-client auth file, called by the Go client, refusing an isolation floor it cannot meet and refusing a wrong bearer. |

`examples/grant` is the one to read if you only read one. It prints the run's
`CallTrace` after each step, which is the same metadata-only evidence the advisory
channel and the audit log are built from:

```
1. a route the grant lists
   guest | ok: Engineering 46600000
   trace | #1 GET /v1/employees/*/comp -> 200, 0B in 39B out, 1ms

3. the same forbidden route, bypassing the client
   guest | broker answered: 403 forbidden by sandbox capability allowlist
   trace | 0 call(s), 1 denied by policy, 0 shed for backpressure, 0 dropped
```

Note what the trace holds: the matched route *template*, never the path that was
requested. `CallRow` has no field for a path, query, body or credential, so none can
be recorded by accident.

## Documentation

- [AGENTS.md](AGENTS.md) is the architecture reference: providers, invariants, the
  full environment list.
- [docs/seccomp.md](docs/seccomp.md) and [docs/gvisor.md](docs/gvisor.md) cover the
  syscall filter and the kernel-tier boundary.
- [docs/advisory-privacy.md](docs/advisory-privacy.md) covers the advisory channel and
  why its telemetry cannot carry payloads.
- [docs/trainers/](docs/trainers/) are dependency-free interactive lessons on the
  execution model, providers, capabilities, and operations. Open any file directly or
  serve the directory.
- [docs/seams.md](docs/seams.md) maps the deliberate extension points.

## License

[Apache-2.0](LICENSE).
