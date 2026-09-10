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

The second thing it does is narrower and, for most callers, the more useful one:
**it lets agent-written code use your API without ever receiving your credential, your
base URL, or general network access.** The bearer is minted per run, stays in Go, and
is attached host-side only after the caller and the exact route have been authorized.
Code that ignores the injected client and calls out by hand does not get further,
because the broker rather than the client is what enforces the policy. See
[Capability grants](#capability-grants).

```go
res, err := provider.Sandbox.RunJavaScript(ctx, sandbox.Request{
    Code:             "console.log(6 * 7)",
    MinimumIsolation: sandbox.IsolationVM, // ErrInsufficientIsolation means nothing ran
})
// res.Isolation reports the boundary that actually ran.
```

## The workflow this is built for

Running agent-authored code costs something in every environment, and the cost is
wrong in both directions. A microVM per run is right for production and absurd for
the *inner loop*, meaning the edit-run-debug cycle a developer repeats hundreds of
times a day. But developing against a weak sandbox and deploying against a strong one
is how a weak sandbox reaches production.

Plimsoll's answer is that the tier is chosen by configuration and **demanded by each
request**, so the two decisions are made by different people at different times:

1. **Locally, run in-process.** `SANDBOX_PROVIDER=wasm` executes JavaScript on an
   embedded QuickJS build through wazero. No sandbox account, no API key, no docker
   daemon, no network, no per-run cost. It is process-tier isolation and the README
   says so everywhere: an engine escape lands in your own daemon.
2. **In production, demand the tier your threat model requires.** Every request
   carries `MinimumIsolation`, so the caller states its own floor rather than trusting
   whatever the operator configured.
3. **Then ship the configuration mistake.** A deploy still pointing at `wasm` while
   the caller demands `IsolationVM` is the failure this design exists to catch.
4. **The run is refused before dispatch.** The handler compares the floor against
   current provider evidence immediately before admission, and returns
   `ErrInsufficientIsolation`. **No submitted code ran.** The caller also re-checks the
   evidence on the response; a mismatch there is `ErrIsolationEvidenceMismatch`, which
   is a weaker guarantee and deliberately described as one, because by then execution
   may already have happened.

This is enforcement at runtime, expressed through a typed request field. Nothing in
the type system forces a production caller to ask for `IsolationVM`; what the design
gives you is that asking is one field, and that asking is checked before anything
executes rather than reported afterwards.

**What this workflow does not give you is a guarantee that code behaving locally
behaves in production**, and it would be dishonest to imply otherwise:

- The engines differ. `wasm` runs QuickJS; `docker` and `e2b` run Node. `fetch` is
  undefined under QuickJS and global under Node 22, and there is no npm. A snippet
  passing locally is not evidence it passes on a production tier.
- `RunProject` is unsupported on `wasm` and always returns `ErrUnsupported`, so
  multi-file projects cannot be exercised in-process at all.
- Grant support differs. `wasm` always supports JavaScript grants; `e2b` supports them
  only when `E2B_GUARD_URL` is configured, so a grant that works locally fails there
  until the guard is set up.

Treat the in-process tier as a fast way to iterate on your integration, not as a
staging environment. `Describe` reports what the active provider actually supports, so
a gateway can find these differences at startup instead of discovering them in
production.

## Status, plainly

- **Pre-1.0**, single author, no external users yet. Breaking changes land without a
  deprecation path, on purpose.
- **No third-party security audit has ever been performed**, and the author's own
  self-review ledgers are not published either. [SECURITY.md](SECURITY.md) says what
  exists, what it is worth, and what you can check yourself instead.
- **CI runs the gate, but not all of it.** The
  [audit workflow](.github/workflows/audit.yml) runs `make audit` on every push and
  pull request: build, vet, race tests, lint, `buf lint`, a generated-code drift
  check, and `govulncheck`. It does **not** run the docker, seccomp or E2B suites,
  which are opt-in (`DOCKER=1`, `E2B=1`) and are where the provider isolation claims
  are actually tested. A green check therefore proves strictly less than a local
  `make audit DOCKER=1 E2B=1`. The E2B suite drives a live paid service and is
  deliberately never wired to a runner. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Learn how it works

The [interactive lessons](https://plimsollmark.github.io/plimsoll/trainers/) are the
fastest way in if you would rather read than clone. They are plain HTML pages with no
build step, no dependencies and no network calls, covering the execution model,
architecture, the four providers, the capability model, operations, and integrating
with an agent or MCP server.

Start with **[Plain English](https://plimsollmark.github.io/plimsoll/trainers/plain-english.html)**
if you want the idea before the API, or
**[Quick start](https://plimsollmark.github.io/plimsoll/trainers/quick-start.html)**
if you want to run something.

They live in [docs/trainers/](docs/trainers/) and work offline: open any file from a
clone in a browser. GitHub shows `.html` files as source rather than rendering them,
which is why the links above point at the published copy instead.

## The problem

Agent frameworks increasingly need to run model-authored code. A single-runtime vendor
has exactly one boundary to describe, so the products that offer this converge on one
security sentence: "isolated per request, nothing persists."

Checked in September 2026 against the current documentation for E2B, Modal, Daytona,
Vercel Sandbox, Cloudflare and Northflank: none of them returns the isolation boundary a
run executed behind, and none refuses a run that would execute below a minimum the
caller stated. Modal comes closest, in the other direction: passing
`experimental_options={"vm_runtime": True}` to `Sandbox.create()` opts into a full VM
instead of the gVisor default, but nothing reports back which runtime served a given
call. Kubernetes RuntimeClass (`runtimeClassName: gvisor`) is the same shape one layer
down, a declaration in a pod spec rather than a per-request floor.

The case this is built for is the one Northflank documents plainly: it runs Kata
Containers where nested virtualization is available and gVisor where it is not. That is
a reasonable engineering decision, and it means the boundary your code ran behind is a
property of the host it landed on. The caller has no way to ask which it got.

If your service does report the tier and enforce a caller's floor, open an issue and
this section gets corrected.

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

## What comes back, and what it means

Most sandboxes flatten every bad outcome into one error, and the caller then cannot
tell a user's broken code from a refused request from a run that may have half
happened. That distinction is the difference between retrying safely and repeating
something with side effects.

**A non-zero exit code is a normal result, not a Go error.** The user's code failed;
nothing went wrong with the sandbox. Errors are reserved for pre-dispatch failures
(`ErrInvalidRequest`, `ErrUnsupported`, `ErrDisabled`, `ErrAtCapacity`), cancellation,
and unmatched infrastructure faults.

For projects, per-step failures live in `Steps` and the run's conclusion is a typed
`ProjectResult.Outcome`, which is a stable retry classification rather than a message
to regex:

| Outcome | What happened | Retryable |
|---|---|---|
| `completed` | every step ran; read `Steps` for pass or fail | no, the answer is in the result |
| `setup_failed` | staging the project never got as far as your code | yes, nothing of yours ran |
| `timed_out` | the run exceeded its deadline | with care; side effects may exist |
| `protocol_error` | the runner and the host disagreed | no, this is a bug to report |

Read the isolation errors the same way. `ErrInsufficientIsolation` means **no code
ran**. `ErrIsolationEvidenceMismatch` means execution **may already have happened**,
which is why it is never a safe automatic retry. `ErrAtCapacity` is the one that is
cleanly retryable with backoff, because admission refused the run before it started.

### Output comes back exactly as the guest wrote it

Guest output is `bytes` on the wire, not a string, so arbitrary bytes survive verbatim
instead of being lossily repaired into UTF-8. If your agent emits a binary blob, a lone
surrogate, or invalid UTF-8, you receive what it actually wrote.

**Truncation is a field, never a marker injected into your data.** Results carry
`StdoutTruncated`, `StderrTruncated` and `ArtifactsTruncated`, and the retained output
is not annotated in-band. Nothing appends `...[truncated]` into a stream you are about
to parse, so a run that produces JSON still produces parseable JSON right up to the
cut.

Flooding is classified as what it is. An E2B guest that pushes its output past the
transfer budget is a **failed user run** (exit 153, both streams flagged truncated),
not an infrastructure error, so it does not page anyone and it does not get retried as
though the platform failed.

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

### The policy and the tool description are generated from one source

Three things describe the same API surface, and in every hand-maintained setup they
drift apart:

- the **allow list**, which is what the broker enforces,
- the **preamble**, the JavaScript client the agent actually calls,
- the **tool description**, the text a gateway shows the model so it knows what exists.

When they disagree the failure is quiet and specific: the model is told about a route
the broker will refuse, or the client offers a method the policy never approved. You
find out at runtime, in an agent transcript.

[`plimsoll-specgen`](cmd/plimsoll-specgen) derives **all three from one OpenAPI 3.x
document**, so they cannot disagree. Path parameters become whole-segment `*` routes,
operations become typed methods on a global, and summaries become the description. It
is deterministic and fully offline: no server is contacted and no credential is
needed. It fails closed on ambiguous input, and it **reports rather than silently
drops** what it cannot express, so a verb the broker cannot enforce (`HEAD`,
`OPTIONS`, `TRACE`) is a warning rather than a gap you discover later.

```sh
plimsoll-specgen -emit grants   api.openapi.json   # the allow list and preamble
plimsoll-specgen -emit catalog  api.openapi.json   # every route, for operator advice
plimsoll-specgen -emit health   api.openapi.json   # the recovery probe, if derivable
```

Worked example, with the input document and every generated artifact side by side:
[docs/examples/specgen](docs/examples/specgen).

### The broker also protects the API from the agent

A sandbox usually protects your infrastructure from the agent's code. This one also
protects your upstream API from the agent's behaviour, which is a different failure:
**an agent loop that reacts to a 429 by trying again, faster.**

Nothing in a model's training makes it back off. So the broker does it host-side. When
an upstream returns 429 or 503, a **per-run circuit breaker** opens for a cooldown
that honours `Retry-After` (capped at 30s), and further permitted calls are *shed* with
a fast 503 rather than piled onto an API that has already asked for room. While
shedding, one elected caller per second probes the grant's declared `health_check`
route and closes the breaker early on a 2xx, so recovery does not wait out the full
cooldown or burn an expensive call to discover it.

The probe uses the run's credential but is neither traced nor charged to the call
budget. Sheds are counted separately from policy denials (`CallTrace.Shed` versus
`Denied`) and surface on the audit line as `host_calls_shed`, so "the agent was
throttled" and "the agent tried something it was not allowed to" never look alike.

**The scope is one run.** This is not fleet-wide overload protection and does not
coordinate across concurrent runs; it stops a single agent loop from hammering an
endpoint that is already struggling.

### Prior art, and what differs here

Keeping the credential out of the guest is not a new idea, and two funded platforms
ship a version of it. Vercel Sandbox's **credentials brokering** injects the credential
into egressing traffic host-side, so that "the secrets never enter the sandbox, so code
running inside it cannot exfiltrate them." Cloudflare's **Code Mode** holds the access
tokens in a supervisor outside the isolate and makes `fetch()` and `connect()` throw
inside it. Two teams building the same control independently is the best evidence
available that it is the right control.

Checked September 2026 against their current documentation, four things differ here:

- **Route granularity, and denial as the default.** Vercel states plainly that
  "Matchers never block traffic": access is decided per domain from the TLS SNI, and a
  request matching no rule still reaches that domain, simply without the credential
  attached. Restricting a domain to particular paths means routing it through a proxy
  you write and rejecting the rest there. plimsoll refuses anything that is not
  byte-identical to an approved route, and that refusal is the component rather than an
  integration point.
- **The credential is minted per run, not attached per sandbox.** Their documented
  examples interpolate a long-lived token from the operator's environment. A grant here
  carries a `TokenMinter` called once per run with that run's scopes and the calling
  principal as the subject.
- **No parallel path to bypass.** Vercel documents that traffic permitted by
  `subnets.allow` "bypasses SNI filtering, credentials brokering, and requests
  proxying", and that domain fronting is possible because matching reads the SNI alone.
  A plimsoll guest has no network at all outside the broker: Docker runs with
  `--network none`, and the WASM guest has a host function and no sockets.
- **Backpressure and generation.** Neither documents a circuit breaker or backoff on an
  upstream 429/503, and while generating a model-facing tool surface from OpenAPI is
  well populated, generating the *enforced* allow list from the same document is not
  something this project has found elsewhere.

**Where theirs is broader, and it is a real trade.** Vercel's firewall governs whatever
the sandbox runs, so package installs, `git`, and Postgres clients all work with a
credential attached at the boundary. plimsoll's broker serves JavaScript runs through
the injected client, and everything else in the guest has no egress whatsoever: the
project toolchain is baked into the image precisely because runtime has no network. If
your agent needs to `npm install` mid-run against a private registry, their model covers
that case and this one does not.

Vendor documentation changes; this comparison is dated for that reason. If it is wrong
or has gone stale, open an issue.

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

## The dependency list, and who checks the checkers

This runs hostile code, so every dependency is attack surface someone else controls.
There are **four direct dependencies**, and the whole list fits here:

```
connectrpc.com/connect      the RPC transport
google.golang.org/protobuf  the wire format
github.com/tetratelabs/wazero  the WebAssembly runtime
golang.org/x/net            HTTP/2
```

`golang.org/x/sys` and `golang.org/x/text` come along indirectly. That is the entire
graph. Adding to it is a decision, not a convenience.

**One library is banned by name, in the linter, with the reason attached.**
`github.com/fastschema/qjs` looked like the obvious way to embed a JavaScript engine,
and its `MemoryLimit` is a no-op: it accepts a limit and does not enforce one. In an
in-process sandbox an unenforced memory cap is a direct route to taking down the host.
So plimsoll drives wazero directly with `WithMemoryLimitPages` for a real per-run cap,
a `depguard` rule fails the build if the import returns, and a test asserts the same
thing independently of the linter. The generalisable part is not the library, it is
that a dependency claiming a safety property is not evidence that it has one.

The embedded QuickJS artifact is pinned to quickjs-ng v0.15.1 **by SHA-256** and
guarded by a provenance test, and `docker/install-gvisor.sh` pins a specific gVisor
release and checksum rather than tracking `latest`.

### The gate pins the tools that run the gate

`make audit` shells out to `buf`, `golangci-lint` and `govulncheck`. Those are not Go
dependencies, so nothing in `go.mod` pins them, and without something else doing it
every machine would run a different gate while reporting the same `audit: OK`.

So [gate-tools.versions](gate-tools.versions) pins all three, and `tools-check` is a
prerequisite of `audit`: **the gate refuses to run against anything else.** `make
tools` installs exactly the pinned set. This matters because the alternative is a
green check that means "it passed under whatever happened to be on this `PATH`", which
is not the claim the gate is making. The codegen plugins are pinned separately, by
go.mod `tool` directives, so `buf generate` is reproducible with no network.

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
- [The interactive lessons](https://plimsollmark.github.io/plimsoll/trainers/) cover
  the execution model, providers, capabilities, and operations. Source in
  [docs/trainers/](docs/trainers/); open any file from a clone to read them offline.
- [docs/seams.md](docs/seams.md) maps the deliberate extension points.

## License

[Apache-2.0](LICENSE).
