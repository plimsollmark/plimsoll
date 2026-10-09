# Isolation tiers, and asserting a floor

An <dfn>*isolation tier*</dfn> is how strong the wall around a run is, reported as one of four levels, weakest first: `process`, `container`, `kernel`, `vm`. This page covers why plimsoll reports it, what evidence each tier rests on, and how a request demands a minimum.

Part of the [plimsoll README](../README.md).

## The problem

AI agent frameworks increasingly need to run code a model wrote. A vendor with one kind
of sandbox has one wall to describe, so the products that offer this all say the same
thing: "isolated per request, nothing persists."

In September 2026 we checked the current documentation of six hosted sandbox services:
<dfn>*E2B*</dfn> (which runs code in small virtual machines), Modal, Daytona, Vercel
Sandbox, Cloudflare and Northflank. None of them returns the wall a run actually got, and
none refuses a run that would get less than a minimum the caller stated. Modal comes
closest, from the other side: passing `experimental_options={"vm_runtime": True}` to
`Sandbox.create()` asks for a full virtual machine instead of its default,
<dfn>*gVisor*</dfn> (a layer that answers a container's requests to the kernel itself), but
nothing reports which of the two served a given call. Kubernetes <dfn>*RuntimeClass*</dfn>
(`runtimeClassName: gvisor`), the pod setting that picks which runtime runs a
pod, has the same shape one layer down: a declaration in a pod spec, not a minimum per
request.

The case plimsoll is built for is one Northflank documents plainly: it runs
<dfn>*Kata Containers*</dfn> (each container inside its own lightweight virtual machine)
where <dfn>*nested virtualization*</dfn> (a virtual machine inside another one) is
available, and gVisor where it is not. That is a reasonable engineering decision, and it
means the wall your code got depends on the machine it landed on. The caller has no way to
ask which it got.

If your service does report the tier and enforce a caller's minimum, open an issue and this
section will be corrected.

Safety claims that nothing checks are common. The example that started this project: a
popular embeddable JavaScript sandbox advertised a `MemoryLimit` that did **nothing**. The
library promised a limit it did not enforce, and nothing in its types or its docs revealed
that.

plimsoll is not a sandbox itself. It sits in front of one, decides which requests may run,
and reports the evidence. The walls come from gVisor and <dfn>*Firecracker*</dfn> (AWS's
open-source virtual machine monitor), which are better at building them.

## Isolation tiers

Pick the <dfn>*provider*</dfn>, the backend that runs the code, with `SANDBOX_PROVIDER`.
**The default is Disabled**, so nothing runs unless you opt in.

| `SANDBOX_PROVIDER` | Provider | Tier | Use it for |
|---|---|---|---|
| unset | Disabled | none | the default; returns `ErrDisabled` |
| `wasm` | <dfn>*QuickJS*</dfn>, a small JavaScript engine compiled to <dfn>*WebAssembly*</dfn> (a portable bytecode), run by <dfn>*wazero*</dfn>, a WebAssembly runtime written in Go, inside the daemon | **process** | development and fast snippets, **not hostile code** |
| `docker` | a locked-down `docker run` | container, or **kernel** under gVisor's runtime `runsc`, once verified | self-hosted production |
| `e2b` | an E2B <dfn>*microVM*</dfn>, a small virtual machine made for one run | **VM** | isolation by <dfn>*hardware virtualization*</dfn>, the processor's own separation between virtual machines |
| `dockercloud` | a microVM from <dfn>*Docker Cloud Sandboxes*</dfn>, Docker's hosted sandbox service | **VM** | the same, on Docker's machines |
| `openshell` | a sandbox from an <dfn>*OpenShell*</dfn> gateway (NVIDIA's agent sandbox runtime), created with docker | container | platforms that already run an OpenShell gateway; the same caveat as docker under `runc` |

> **The WASM tier runs inside the daemon.** It is neither an operating-system wall nor a
> virtual machine wall. An <dfn>*escape*</dfn>, a bug that lets code out of the QuickJS
> engine, lands inside the daemon process. It exists for speed and for development. Do not
> point it at hostile code.

The container tier, with docker's default runtime `runc`, shares the host's kernel. For
hostile code in production, use a VM provider (`e2b`, `dockercloud`), or `docker` with
`SANDBOX_DOCKER_RUNTIME=runsc`.

Every provider whose walls depend on the host or on a remote service runs a startup
**`SmokeTest`** that checks behaviour, not just configuration, and the daemon serves
nothing if it fails. The `wasm` provider has none: its walls are library code built into
plimsolld, the same on every host, so the project's own tests prove its memory cap and its
lack of any network API, and its startup check reads only its settings.

- The docker test starts a throwaway container. From the container's own list of mounted
  filesystems, and by trying a real write at every mount point, it proves that the root
  filesystem is read-only and that the only writable places are the promised
  <dfn>*tmpfs*</dfn> mounts (filesystems held in memory) marked `noexec` (a file written
  there cannot be started or loaded as a program by its path; code a run places in memory
  is not stopped by it, so `noexec` is a second layer, not the boundary). It lists the container's network interfaces and refuses to serve unless
  loopback is the only one, which is what having no network means inside a container.
  It also reads the container's process limit, `pids.max`, and refuses to serve
  unless it equals the configured limit, because a runtime can accept `--pids-limit`
  without applying it. Under gVisor the container sees an emulated copy of that file that
  always reads `max`, while gVisor applies the limit to the sandbox's <dfn>*cgroup*</dfn>
  on the host (the kernel's record of a group of processes' limits), so there the test reads
  the host's copy instead.
- The E2B test creates a real microVM with its access tokens, copies files into it, runs a
  test program through exactly the path a project step takes, and checks live that
  <dfn>*egress*</dfn>, traffic leaving the VM, is blocked.
- The Docker Cloud test checks the token's permissions, then one throwaway sandbox proves
  a network policy in force that blocks every connection, file upload, the command wrapper, the step's working
  directory and egress denial from inside
  ([dockercloud.md](dockercloud.md#startup-smoke-test)).

**Exactly what the kernel and vm tiers rest on**, because a security claim nobody could
prove wrong is not worth reading.

- For `docker`, the kernel tier requires that the docker daemon this provider is actually
  connected to has the configured <dfn>*OCI runtime*</dfn> (the program docker calls to
  start a container) registered, and that `runsc` there is a program named `runsc`; runs
  then start under that runtime. That is evidence from docker's registration plus the
  startup test above. It is not proof that the wall actually running is gVisor, and the
  code says so at [docker_preflight.go](../sandbox/docker_preflight.go) `Preflight`.
- For `e2b`, the vm tier follows from which provider it is: E2B runs each sandbox in a
  Firecracker microVM, and plimsoll reports that without measuring it. Its startup test
  proves the microVM behaves as promised, including blocked egress, not that a
  <dfn>*hypervisor*</dfn> (the program that runs virtual machines) is present.
- For `dockercloud`, the vm tier also follows from which provider it is: Docker Cloud
  Sandboxes runs each sandbox in a microVM, and its startup test proves the policy that
  blocks every connection and the blocked egress, not the hypervisor.

All three are stronger than a sentence in a datasheet and weaker than
<dfn>*attestation*</dfn>, cryptographic proof from the hardware of what software is
running. If your <dfn>*threat model*</dfn> (the attacks you must hold out against) needs
attestation, neither tier here supplies it.

For `openshell`, the container tier follows from the gateway's own report:
`GetGatewayInfo` must say it creates sandboxes with docker (its docker compute driver), and
any other driver is refused. The gateway does not say which OCI runtime its docker uses, so
plimsoll reports `container` even where that runtime is gVisor. Its startup test proves
from inside a sandbox that only `/tmp` accepts writes, that egress is refused, that the
requested limits are in the sandbox's cgroup, and that cancelling a command kills it
([openshell.md](openshell.md)).

## Asserting a floor

A request's `MinimumIsolation` is its <dfn>*floor*</dfn>: the weakest tier it will
accept. The daemon compares it with what its provider currently reports just before
<dfn>*admission*</dfn>, the capacity check right before a run starts.
`ErrInsufficientIsolation` means **no code ran**. The error is marked as refused before
<dfn>*dispatch*</dfn> (the handover to the provider), with the reason `isolation`, so a
caller can safely send the request to a stronger provider
([run results](run-results.md#did-anything-run-the-error-says-so)).

The official client also checks the tier that comes back. A mismatch is
`ErrIsolationEvidenceMismatch`, and it deliberately does not mean "safe to retry": the
code may already have run.

`SANDBOX_MIN_ISOLATION` is the operator's floor for the whole daemon, checked at startup.
It does not replace a caller's own floor on each request: a `Describe` answer the caller
read earlier can be out of date, and must never be what allows a weaker run later.
