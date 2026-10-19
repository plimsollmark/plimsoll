# The agent-sandbox provider

`SANDBOX_PROVIDER=agentsandbox` selects the `agentsandbox` <dfn>*provider*</dfn> (the backend
that actually runs the code): Kubernetes agent-sandbox, a Kubernetes project that keeps
sandboxes as <dfn>*pods*</dfn> (Kubernetes' unit of one or more containers run together)
with a warm pool of them ready to hand out
([Agent Sandbox (EXTERNAL · official docs ↗)](https://agent-sandbox.sigs.k8s.io/),
[kubernetes-sigs/agent-sandbox (EXTERNAL · source repo ↗)](https://github.com/kubernetes-sigs/agent-sandbox)).
Each snippet or project <dfn>*claims*</dfn> one sandbox from the pool (a SandboxClaim, the
object that asks for one), runs in it, and the claim is deleted after, which deletes the
pod. Snippets and projects only: no sessions, grants or module runs yet. The code is
[sandbox/agentsandbox](../sandbox/agentsandbox/agentsandbox.go), and plimsolld builds it in
[cmd/plimsolld/agentsandbox.go](../cmd/plimsolld/agentsandbox.go).

agent-sandbox lets a template name a <dfn>*runtime class*</dfn> (the Kubernetes object that
picks the program a node starts containers with), and that is its whole isolation story: it
does not check the class, and nothing in a sandbox's status says which one it got. So
plimsoll reads the tier, never takes it as configuration: the runtime class's handler
`runsc` (<dfn>*gVisor*</dfn>, a stand-in kernel that runs as an ordinary program) is the
`kernel` tier, `runc` (an ordinary container) the `container` tier, Kata Containers' Cloud
Hypervisor handlers `kata-clh` and `kata-clh-runtime-rs` and AKS Pod Sandboxing's `kata` (a
small virtual machine with its own Linux kernel per pod, [below](#kata-containers-the-vm-tier))
the `vm` tier, and any other handler is refused. The startup smoke test then holds each tier to what a guest can observe
(below), and every run holds its own pod to it again. As
for every provider, a reported tier is configuration and provider evidence plus that
behavioural test, never attestation.

## How it was built and verified

plimsoll talks to the Kubernetes API over plain HTTPS with a bearer token, with no Kubernetes
client library. It runs each command through sandboxd, the daemon agent-sandbox puts in every
sandbox's pod, over sandboxd's gRPC process service: its `.proto` files are copied at v1.0.7
under [third_party/agentsandbox](../third_party/agentsandbox/README.md) (Apache-2.0) and
spoken through connect-go, the RPC library plimsoll already uses. The package is separate
from package `sandbox` because the generated code registers the same protobuf names as
agent-sandbox's own Go SDK. plimsoll is an independent project, not affiliated with or
endorsed by the Kubernetes project.

`make agentsandbox-suite` (or `make audit AGENTSANDBOX=1`) runs the live suite against a
cluster: the provider's tests (snippets, the guest's identity, egress, a project with an
artifact, a hung snippet timed out, the startup smoke test, nothing left after a drain) and a
daemon test that starts plimsolld, serves a snippet, a refused isolation floor and a project
over RPC, then sends SIGTERM and requires the cluster to hold no claim of plimsoll's. It
passed on 2026-10-18 on a kind cluster (Kubernetes 1.37.0, containerd 2.3.4, agent-sandbox
v1.0.7) under both a gVisor runtime class and a runc one, and the same day under Kata
Containers 4.2.0 with Cloud Hypervisor, under both of Kata's runtimes. On that cluster a warm
pod answered a snippet in 50 to 250 ms from claim to result (160 to 360 ms under Kata), and
the daemon was ready, smoke test included, in about 3 seconds (about 4 under Kata). The docker suite also runs the scripts the smoke test sends
into a pod, in docker's locked-down container, so a broken script fails the ordinary gate.

[The evidence page (INTERNAL · example page →)](examples/agentsandbox/index.html) shows two
runs on that cluster through a hardened daemon under gVisor, signed and converted to CycloneDX
bills of materials, whose results are byte for byte those of the same requests on docker under
gVisor and on a Docker Cloud microVM, and five refusals, among them a node whose runsc handler
was remapped to runc under a running daemon.

## What the operator sets up

- **agent-sandbox v1.0.7 with its extensions** (the SandboxTemplate, SandboxWarmPool and
  SandboxClaim kinds), and a runtime class whose handler is `runsc` (gVisor), `runc`, or one
  of Kata's two Cloud Hypervisor handlers. Prefer gVisor or Kata: hardened mode accepts only
  the kernel and vm tiers.
- **plimsolld running in the cluster.** It reaches each pod's sandboxd at the pod's address,
  which only the cluster network routes; Kubernetes' port-forward does not reach a pod under
  gVisor. With no settings for them, the API server, its certificate authority and the token
  are the pod's own service account (`https://kubernetes.default.svc` and the files under
  `/var/run/secrets/kubernetes.io/serviceaccount`); the token file is read at every request,
  since Kubernetes rotates it in place. The service account needs, in the namespace: create,
  get, list and delete on `sandboxclaims`; get on `sandboxwarmpools`, `sandboxtemplates`,
  `sandboxes` and `pods`; list on `networkpolicies`; and, cluster-wide, get on
  `runtimeclasses`, and under Kata get on `nodes` (each run compares its pod's kernel with
  its node's). Nothing else.
- **An image with sandboxd and plimsoll's runner.**
  [docker/agentsandbox.Dockerfile](../docker/agentsandbox.Dockerfile) builds it from
  `plimsoll/sandbox`: sandboxd from the v1.0.7 commit at `/usr/local/bin/sandboxd`, and
  util-linux's `setpriv` at `/bin/setpriv`, which drops every command to the guest user.
  `SANDBOX_AGENTSANDBOX_IMAGE` names it exactly as the template writes it; with
  `SANDBOX_REQUIRE_PINNED_IMAGES=1` it must be pinned by `@sha256:`, and that digest is
  checked against each pod's image on every run.
- **A token for sandboxd.** A random string of 32 to 512 characters in a file named by
  `SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE`, never in the environment. The template starts
  sandboxd with `--auth-token-sha256=` and the token's SHA-256 in hex: sandboxd runs as root,
  and without a token, code in the pod could ask it on loopback to run a command as root.
- **A template and a warm pool**, named by `SANDBOX_AGENTSANDBOX_WARM_POOL` (the pool, which
  names its template) in `SANDBOX_AGENTSANDBOX_NAMESPACE`, whose pods plimsoll's read-back
  accepts:
  - the runtime class `SANDBOX_AGENTSANDBOX_RUNTIME_CLASS`, and under runc a seccomp profile
    (`RuntimeDefault` or `Localhost`; <dfn>*seccomp*</dfn> is the kernel feature that limits
    which requests a process may make to the kernel). None is required under gVisor or Kata,
    whose guests talk to a kernel of their own;
  - `automountServiceAccountToken: false`, no host network, process or IPC namespace, no
    shared process namespace, no init or ephemeral container, one container;
  - `dnsPolicy: None` with the one nameserver `127.0.0.1` and no search domain: Kubernetes'
    default writes the node's search domains into the pod;
  - the container: the image, `/usr/local/bin/sandboxd` as its command with the token
    digest and every argument in the `--name=value` form (sandboxd's flag parser stops at
    `--` or a bare word, and lets a flag without `=` take the next argument as its value,
    so any other form could make it read other flags than plimsoll checked),
    `allowPrivilegeEscalation: false`, a read-only root filesystem, all capabilities
    dropped but `SETUID` and `SETGID`, and memory and CPU limits equal to `SANDBOX_MEMORY_MB`
    and `SANDBOX_CPUS` (default 256 MiB and 1 CPU);
  - every volume an `emptyDir` with `medium: Memory` and a `sizeLimit`, mounted whole at a
    clean path, one of them `/work`. A disk-backed one is capped only when the kubelet's
    periodic eviction notices, so a run could fill the node's disk until then; with
    `SANDBOX_DISK_MB` set, the size limits must sum to no more than it. The guest mount table must show no mount strictly beneath any writable root,
    under every tier: a tmpfs root cannot bound a node-backed file mounted inside it, even
    when an image symlink hides the relationship from the API path check. Under Kata no volume
    keeps its size limit, so `SANDBOX_DISK_MB` fails startup there
    ([below](#kata-containers-the-vm-tier));
  - `terminationMessagePath` somewhere the guest cannot reach, such as
    `/root/termination-log`. The default, `/dev/termination-log`, is a file the kubelet
    mounts from the node's disk, writable by every user in the container (measured: 64 MiB
    written by the guest landed on the node). Every pod is held to it, outside `/tmp`,
    `/dev` and every volume, so a warm pod made from an older template is refused too.
  - a network policy (the template's own `networkPolicy` will do) that denies egress, and
    none in the namespace that allows any; ingress only to sandboxd's gRPC port, 9090, from
    where plimsolld runs.

  [An example template, pool and service account](agentsandbox-example.yaml) passes the
  read-back.

**A closed pod and container schema.** Both the template and each actual pod refuse unknown
pod-spec and container fields, including unknown fields inside decoded probes, mounts and
security contexts. Exec handlers in readiness, liveness and startup probes and in lifecycle
hooks are refused: Kubernetes would run them as sandboxd's root user, and a command could
name a file the guest wrote. TCP, HTTP and gRPC probes and HTTP or TCP lifecycle hooks are
allowed. Scheduling defaults, RuntimeClass overhead, node selectors and tolerations are
allowed because they affect placement and accounting rather than granting guest privileges.
Service-account names are allowed with token mounting disabled; resource requests, image
pull policy and termination-message policy do not relax the checked execution boundary.
Host ports are refused; sandboxd's explicit user and group must be root so it can drop each
command to the guest user. Environment injection, device mounts and other fields outside
the schema require review before they can be accepted.

**After startup, only the template the smoke test proved.** The read-back decodes the fields
it checks and no others, and the smoke test proves the rest (where the guest can write, what
it can reach) for one template. So once it passes, a template whose name or spec differs
from the one it ran on fails Preflight and readiness, and its runs are refused before
anything is claimed (reason `environment`), until a restart proves it, as a docker tag
re-pointed after startup is. The template is read again at most every 5 seconds.

**The proven network policy set.** Before the smoke test sends a command, plimsoll records
all policies in the namespace by name, UID (Kubernetes' identity for that object) and the
digest of the complete spec, including fields the semantic checker does not decode. Both
claimed pods and a final read must see that same set. Every later pod read-back refuses
an added, removed, replaced or changed policy before dispatch, reason `environment`; restart
plimsolld to prove a new set. Once observed, a difference remains a refusal even if the
original set is restored. Metadata-only edits and list ordering do not change the pin.
The whole namespace set is pinned, including policies that select other pods, because a
policy's selector can change which pods it affects. A recreated deny policy cannot borrow
its predecessor's proof while the network plugin is still applying it. Cluster-scoped
policies, network-plugin state and changes after the read-back remain outside this pin.
A per-run connection test could check enforcement again, at the cost of waiting for blocked
connections to time out; it is not implemented.

## What each run does

1. Reads the warm pool, its template and the runtime class, and refuses any difference from
   the above, or a template other than the one the smoke test proved. The tier is the
   handler's.
2. Creates a claim on the pool, labelled with this daemon instance, `plimsoll.run=1` and
   the run's lifetime, and with a shutdown time five minutes past the run's end, at which
   agent-sandbox deletes it even if plimsolld is gone. A claim is refused when the API
   server's clock is more than a minute from plimsolld's.
3. Reads the claimed pod back (the same checks, its image by digest, every network policy
   that selects it) before any code is sent.
4. Runs one command of its own in the pod, as the guest, before any of the run's code: the
   first line of the kernel log, which under the kernel tier must be gVisor's boot line and
   under Kata a Linux kernel's; the kernel's boot ID, which under Kata must differ from the
   one the pod's node reports, since a pod on the node's own kernel shares it; and the seccomp
   mode, which under runc must show a filter. A handler's name is configuration on
   each node, which the API does not show: live on kind, with a node's runsc handler remapped
   to runc after the smoke test had passed, a run was signed at the kernel tier on the host's
   kernel until this check was added. A pod that fails it is refused, not dispatched, reason
   `environment`. On kind it cost nothing measurable (a median of 75 ms per snippet with and
   without it).
5. Sends one command to sandboxd: the snippet to `node -`, or a project's plan to the
   runner, as the guest user (uid 61000, no capabilities, `no_new_privs`, under `env -i`).
   Every request that carries sandboxd's token is sent before the guest's code starts. The
   deadline is plimsoll's: when it passes, plimsoll cancels the stream, which makes sandboxd
   kill the command's process group; sandboxd itself bounds neither time nor output, so
   plimsoll keeps the first 1 MiB of each stream and flags the rest as dropped.
6. Returns the result, then deletes the claim in the foreground, so the pod is gone before
   the run gives back its capacity. A delete that exhausts its retry budget stays tracked
   as pending and keeps the capacity held. `ReconcileOrphans` retries it by name, with or
   without a deletion timestamp, including a claim no longer present in the namespace
   listing. Only confirmed absence releases the reservation. Concurrent reconciliation
   cannot take over a create, a live run or a deletion already in progress. Daemon shutdown
   waits for deletion, and `Drain` names remaining claims if its deadline expires.

## Startup smoke test

Before the provider serves, it claims two sandboxes as runs do and proves from inside what
the read-back cannot see:

- the guest runs as uid 61000 alone, with no capability, `no_new_privs`, only `PATH` and
  `HOME`, and the fixed resolver;
- a write attempted at every path the guest can reach (about 4,900 on the test cluster)
  succeeds only in the template's volumes and `/dev/shm`, and a file can be created nowhere
  else, except a message queue in `/dev/mqueue` (below);
- each volume refuses writes once its size limit is full; under Kata, where none does, every
  volume and `/dev/shm` is instead a tmpfs of the VM's own kernel, so in its memory;
- no connection leaves the pod: to the internet, the cloud metadata address, the API
  server's address and the node's kubelet, every attempt times out or is refused inside the
  pod;
- under the kernel tier, the guest's kernel log begins with gVisor's boot line (a handler
  named `runsc` is only a name in the node's configuration, and a host's own log can name
  gVisor too); under Kata, the log begins with a Linux kernel's boot and the boot ID is not
  the node's; under runc, a seccomp filter is in force on the guest. Every run repeats this
  check in its own pod (step 4 above), since the smoke test sees only the nodes its two pods
  landed on;
- a project step cannot open the runner's plan and report descriptors or memory, nor
  sandboxd's.

A failure refuses startup.

## Claims a crashed daemon leaves behind

Once a minute the daemon deletes its own claims that no run tracks, and any other instance's
once the API server's creation time plus the declared lifetime plus 5 minutes has passed. A
claim's own shutdown time deletes it anyway, at the same mark, if no plimsolld is left to.

## What it does not do, and what it leaves to the node

- **No sessions, grants or module runs.** They are refused before anything is claimed.
- **Memory.** Under gVisor the pod's limit caps memory in RAM only: on a node with swap a
  gVisor pod swaps past it under the kubelet's default swap setting, NoSwap (gVisor issue
  [google/gvisor#15756 (EXTERNAL · issue tracker ↗)](https://github.com/google/gvisor/issues/15756);
  measured on kind on 2026-10-18: a 128 MiB pod held 1024 MiB, 932 of it in swap, and was never
  killed, where runc killed the same pod at 112 MiB). Until gVisor fixes it, take swap from the
  pods' parent cgroup: `memory.swap.max=0` on the kubepods cgroup in the cgroupfs layout (the
  same pod was then killed at 96 MiB), or a `MemorySwapMax=0` drop-in on the kubepods slice
  under the systemd driver, which the issue's reporter confirmed. Either takes swap from every
  pod on the node. The volumes are tmpfs, so they count against that memory too. `/dev/shm` is outside the
  volumes' sum: under runc the runtime's own 64 MiB tmpfs, under gVisor bounded only by the
  pod's memory.
- **Message queues.** Under runc the guest can create POSIX message queues in its pod's own
  IPC namespace, freed with the pod. Their size is counted per user across the node (819,200
  bytes by default), so concurrent guests share one allowance: one can use it up and deny the
  others queues, never read theirs. The smoke test refuses a node whose allowance is
  unlimited or above 1 MiB.
- **Process count.** The kubelet sets it for every pod on a node (`podPidsLimit`), which the
  API does not show, so `SANDBOX_PIDS` fails startup.
- **Other runtimes.** Kata's QEMU handlers and any other handler are refused until plimsoll
  has tested them.
- **Policies outside the namespace.** The read-back sees Kubernetes NetworkPolicy objects
  only; a cluster-wide admin policy or a network plugin's own kinds can allow traffic too,
  which only the smoke test's connection attempts would catch.

## Kata Containers: the vm tier

[Kata Containers (EXTERNAL · official docs ↗)](https://kata-containers.github.io/kata-containers/installation/)
starts each pod inside a small virtual machine of its own, with its own Linux kernel, using the
CPU's hardware virtualization (KVM on Linux), so a node needs `/dev/kvm`, and on a cloud VM
nested virtualization. Its installer, kata-deploy, registers one runtime class per
<dfn>*shim*</dfn> (Kata's program for one hypervisor and runtime) with the handler named after
it. plimsoll treats two as the `vm` tier: `kata-clh` (Cloud Hypervisor on Kata's Go runtime)
and `kata-clh-runtime-rs` (Cloud Hypervisor on runtime-rs, the Rust runtime Kata recommends
since 4.0). Both were run with kata-deploy 4.2.0 on the kind cluster above, which runs on a
virtual machine with nested virtualization, and both pass the whole live suite. Kata's QEMU
shim never started a pod there (the guest agent did not answer within the shim's 10 seconds),
so its handlers stay refused. The third `vm` handler is `kata`, the one behind AKS Pod
Sandboxing's runtime class ([below](#on-aks-pod-sandboxing)).

How plimsoll holds a pod to the tier: before any of a run's code, the guest reads its kernel
log, whose first line must be a Linux kernel's boot line (gVisor's is not), and its kernel's
boot ID, a random identifier each boot, which must differ from the boot ID the pod's node
reports through the API: a pod that a node's Kata handler actually started under runc shares
the node's kernel, and so its boot ID. Measured on kind with the node's `kata-clh` handler
remapped to runc, every run was refused on both counts. As with gVisor's boot line, a node's
root could forge either, so this catches a node that runs something other than its handler
says, not a hostile node. It also assumes the kubelet reads the node kernel's own boot ID: a
kubelet inside systemd-nspawn reads one nspawn made for its container, which a runc pod on
that node would not share, so there the boot ID tells nothing.

What changes under Kata, measured on that cluster:

- **No volume keeps its size limit.** Kata mounts each memory-backed `emptyDir` as a tmpfs of
  the VM's own kernel: runtime-rs with no size (Linux's default, half the VM's memory), the Go
  runtime with the VM's whole memory; a guest wrote 100 MB into a volume limited to 32 MiB
  ([kata-containers#2438 (EXTERNAL · issue tracker ↗)](https://github.com/kata-containers/kata-containers/issues/2438)).
  The writes stay in the VM's memory, not in any file system of the node's (the VM's memory
  can still reach the node's swap, or the guest's own swap where Kata's configuration turns it
  on; plimsoll checks neither), so the smoke test checks that every writable mount is such a
  tmpfs instead of filling each one, and
  `SANDBOX_DISK_MB` fails startup: no disk budget can be promised. Hardened mode does not
  require it under Kata. A disk-backed `emptyDir` is a share of the node's own directory under
  Kata, so it stays refused.
- **Memory.** runtime-rs sizes the VM to the pod's limit (the guest saw 257 MiB for 256 MiB);
  the Go runtime boots a 2 GiB VM and applies the container's limit inside it. Both runtime
  classes add a fixed overhead per pod (130 MiB and 250 millicores, as kata-deploy 4.2.0
  writes them), which the scheduler counts outside the template's limits.
- **No seccomp in the guest.** Kata applies no seccomp profile inside the VM unless its
  configuration sets `disable_guest_seccomp = false`; the guest saw none with the template's
  `RuntimeDefault`. The boundary is the VM, so plimsoll requires none, as under gVisor, and
  states only the tier.
- **Start time.** A pod is ready in seconds, and the warm pool hides it; a snippet took 160 to
  360 ms from claim to result against 50 to 250 ms under gVisor.

### On AKS Pod Sandboxing

[AKS Pod Sandboxing (EXTERNAL · official docs ↗)](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing)
is Kata on Cloud Hypervisor over Microsoft's own hypervisor, on Azure Linux nodes. A node pool
created with `--workload-runtime KataVmIsolation` gets the runtime class `kata-vm-isolation`,
whose handler is `kata`; the class adds a fixed 600 MiB of memory per pod (`overhead`) and a
node selector for those nodes. Run on 2026-10-18 on one `Standard_D4s_v4` node (Kubernetes
1.36.4, containerd 2.3.4) with Cilium enforcing network policy, the whole live suite passed at
the `vm` tier, the provider's tests and the daemon's over RPC. What the guest saw:

- its own kernel, a build of the node's (`6.6.137.mshv1-1.azl3` inside, `6.6.137.mshv2-2.azl3`
  on the node), a Linux boot line readable as the guest's uid, and a boot ID other than the
  node's;
- 225 MiB of memory for a 256 MiB limit, so the VM is sized to the pod as under runtime-rs;
- each memory-backed volume and `/dev/shm` a tmpfs of the VM's kernel with no size (half the
  VM's memory), the root read-only, and no seccomp, the same as on kind;
- no connection out to any address the smoke test tries, the node's metadata service and its
  kubelet included.

The daemon was ready in 9.5 seconds, its smoke test included, and a snippet over RPC took 458
ms. Two things differ from kind. The overhead holds memory only, so a template's CPU limit is
counted whole against the node: with the system pods on that 4-vCPU node, a pool of two pods
at one CPU each left no room for the pod a run claims while another is deleted, and the run
timed out waiting for it; at 500 millicores (`SANDBOX_CPUS=0.5`) it passed. And the nodes are
managed, so the remap test above (a handler pointed at runc) cannot be repeated there; the
per-pod check is the same code either way.

## Each claimed pod keeps the tested filesystem boundary

The actual pod must match the checked template's volume sizes, mount paths,
termination-log path, entrypoint and security context. Scheduling fields, resource
requests and Kubernetes readiness defaults do not change that comparison. Every
accepted pod must use the first accepted pod's image digest, including both startup
smoke-test claims, so changing a mutable image tag requires a restart and new proof.

Before any submitted code, the same guest command that reads the kernel identity
also reads the complete mount table. No mount may sit below a writable root, even
when a path in the image resolves through a symbolic link. Under container and vm
isolation, each root must report a tmpfs, a filesystem held in memory. Under gVisor,
Kubernetes memory volumes appear as 9p shares, a filesystem-sharing protocol that
hides their backing type; their memory declaration and limits remain bound to the
template whose write limits the startup test proved. A malformed or truncated report refuses the run without dispatch.
These checks are provider evidence, never hardware attestation.
