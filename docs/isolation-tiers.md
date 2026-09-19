# Isolation tiers, and asserting a floor

What problem the reported tier solves, what evidence each tier rests on, and how a caller demands one per request.

Part of the [plimsoll README](../README.md).

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

plimsoll is the policy and evidence layer in front of a sandbox, not a sandbox
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
[docker.go](../sandbox/docker.go) `Preflight`. For `e2b`, VM tier follows from provider
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
