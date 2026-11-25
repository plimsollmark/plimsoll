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
| `wslc` | a container from WSL containers (WSLC), the container engine Microsoft ships inside the Windows Subsystem for Linux, started through `wslc.exe` from a daemon in a WSL distribution | per-run mode, the default: container, or **VM** with the operator's opt-in. The per-run mode gives each run its own Hyper-V VM. It reports the `container` tier, because Microsoft states that WSL is not a security sandbox for running untrusted code; an operator who accepts that statement sets `SANDBOX_WSLC_ACCEPT_VM_TIER=1`, and it then reports `vm` with that statement attached. Shared mode, one virtual machine for every run: container | a Windows machine with nothing installed beyond WSL. <dfn>*Hardened mode*</dfn> (the daemon's strict production check, `PLIMSOLL_HARDENED=1`) refuses it in both modes; the shared mode is weaker than docker under `runc`, with five of its controls missing ([wslc.md](wslc.md#controls)) |

> **The WASM tier runs inside the daemon.** It is neither an operating-system wall nor a
> virtual machine wall. An <dfn>*escape*</dfn>, a bug that lets code out of the QuickJS
> engine, lands inside the daemon process. It exists for speed and for development. Do not
> point it at hostile code.

The container tier, with docker's default runtime `runc`, shares the host's kernel. For
hostile code in production, use a VM provider (`e2b`, `dockercloud`), or `docker` with
`SANDBOX_DOCKER_RUNTIME=runsc`. The `wslc` per-run mode is not one of them. The per-run
mode gives each run its own Hyper-V VM. It reports the `container` tier, because
Microsoft states that WSL is not a security sandbox for running untrusted code; an
operator who accepts that statement sets `SANDBOX_WSLC_ACCEPT_VM_TIER=1`, and it then
reports `vm` with that statement attached. By default, then, a request that requires `vm`
or `kernel` is refused before anything runs
([wslc.md](wslc.md#the-tier-and-why-hardened-mode-refuses-it)).

Every provider whose walls depend on the host or on a remote service runs a startup
**`SmokeTest`** that checks behaviour, not just configuration, and the daemon serves
nothing if it fails. The `wasm` provider has none: its walls are library code built into
plimsolld, the same on every host, so the project's own tests prove its memory cap and its
lack of any network API, and its startup check reads only its settings.

<!-- Generated from each provider's boundary declaration by `go test ./internal/boundary -run TestTierPageIsGenerated -update`: change a declaration, not this section. -->

Each provider declares, for every claim below, the steps of its startup test that prove it, or why its test does not check it ([internal/boundary](../internal/boundary/boundary.go) holds the list of claims). The test records each claim as its check passes, and the provider serves nothing when the record differs from the declaration, so this comparison says what the code proves, no more and no less. "Not checked" says nothing about whether the property holds, only that the startup test does not check it; each provider's list below says why.

**The wall around a run**

| Claim | `wasm` | `docker` | `e2b` | `dockercloud` | `openshell` | `agentsandbox` | `wslc` |
|---|---|---|---|---|---|---|---|
| Only the promised places accept a write; the root filesystem refuses one (`writable-places`) | not checked | proved | not checked | not checked | proved | proved | proved |
| Each place that accepts a write is held to a size bound (`writable-bounds`) | not checked | proved | proved, when `SANDBOX_DISK_MB` is set | not checked | proved, when `SANDBOX_DISK_MB` is set | proved | proved |
| The code sees no network interface but loopback (`loopback-only`) | not checked | proved | not checked | not checked | proved | not checked | proved |
| No connection the code tries to an outside address succeeds (`no-egress`) | not checked | not checked | proved | proved | proved | proved | proved |
| The <dfn>*guest*</dfn>, the code running inside the sandbox, runs as an unprivileged user of its own, with no other user or group (`guest-user`) | not checked | proved | not checked | not checked | not checked | proved | proved |
| The code holds no Linux capability (a power the kernel gives a process beyond its user's) (`no-capabilities`) | not checked | not checked | not checked | not checked | not checked | proved | proved |
| A <dfn>*seccomp*</dfn> filter (the kernel's filter on which requests a process may make) is in force on the code (`seccomp-filter`) | not checked | not checked | not checked | not checked | not checked | proved, at the container tier | proved |
| Every program plimsoll starts in the sandbox starts behind plimsoll's <dfn>*guest guard*</dfn>, a seccomp filter of plimsoll's own that refuses the code the requests that make a <dfn>*namespace*</dfn> (a private view of the system in which the code acts as administrator) or a mount of its own, and tracing (`guest-guard`) | not checked | proved | not checked | not checked | not checked | not checked | not checked |
| The configured limit on the number of processes is applied (`process-limit`) | not checked | proved | not checked | not checked | not checked | not checked | proved |
| The configured memory limit is applied (`memory-limit`) | not checked | not checked | proved, when `SANDBOX_MEMORY_MB` is set | proved | proved | not checked | proved |
| The configured CPU limit is applied (`cpu-limit`) | not checked | not checked | proved, when `SANDBOX_CPUS` is set | proved | proved | not checked | not checked |
| The code's resolver settings (which name server it asks) are plimsoll's own, with nothing of the host's (`fixed-resolver`) | not checked | proved | not checked | not checked | not checked | proved | proved |
| No environment variable reaches the code from outside its image and plimsoll's own runner (`closed-environment`) | not checked | not checked | not checked | not checked | not checked | proved | proved |
| The code cannot open plimsoll's own channel to the run: the runner's plan, its report and its memory, and any agent of the provider's beside it (`control-channel`) | not checked | proved | not checked | not checked | proved | proved | proved |
| No device or folder of the host machine reaches the code (`no-host-share`) | not checked | not checked | not checked | not checked | not checked | not checked | proved |
| From inside, the code sees the kernel the stated tier rests on (`tier-inside`) | not checked | not checked | not checked | not checked | not checked | proved, at the kernel and vm tiers | proved |

**The path every run takes**

| Claim | `wasm` | `docker` | `e2b` | `dockercloud` | `openshell` | `agentsandbox` | `wslc` |
|---|---|---|---|---|---|---|---|
| Before code runs, what the service set up for it (image, policy, limits, runtime) is read back and must be what was asked (`setup-read-back`) | not checked | proved | not checked | proved | proved | proved | proved |
| Code runs end to end through the path a run takes: files in, steps run, output and files back (`run-path`) | not checked | proved | proved | proved | proved | proved | proved |
| A command past its time limit is ended, with every process it started (`deadline-kill`) | not checked | not checked | not checked | proved | proved | not checked | not checked |
| Output past the cap is cut off, and the cut is reported (`output-cap`) | not checked | not checked | not checked | proved | not checked | not checked | not checked |
| A host socket handed to a run for its <dfn>*grant*</dfn> (its permission to call listed routes of one HTTP API) is reachable from inside it (`grant-socket`) | not checked | proved | not checked | not checked | not checked | not checked | not checked |
| The languages stated for runs are the ones that answered at startup (`languages`) | not checked | proved | proved | proved | proved | not checked | not checked |
| A run's sandbox is gone after the run (`teardown`) | not checked | not checked | not checked | not checked | not checked | not checked | proved, in the per-run mode |

**`wasm`**, [wasm.go](../sandbox/wasm.go). It has no startup test: its walls are library code built into plimsolld, the same on every host, so the project's own tests prove them, and its startup check reads only its settings. Its tier is process: an escape from the engine lands inside plimsolld.

- `writable-places`, not checked: no filesystem is opened to the engine, so there is no place to write (`TestWasmDefaultCannotReachHostResources`, `TestWasmHasNoNetworkOrFS`).
- `writable-bounds`, not checked: there is no place to write; the engine's memory is capped instead (see `memory-limit`).
- `loopback-only`, not checked: the engine has no network API at all, so there is no interface to list (`TestWasmHasNoNetworkOrFS`).
- `no-egress`, not checked: the engine has no network API at all (`TestWasmHasNoNetworkOrFS`).
- `guest-user`, not checked: the code runs inside plimsolld's own process, as plimsolld's user: the wall is the engine, not a user.
- `no-capabilities`, not checked: the code runs inside plimsolld's process, which holds what plimsolld holds; the engine gives the code no <dfn>*system call*</dfn> (a request a program makes to the kernel) through which to use it.
- `seccomp-filter`, not checked: no filter is set: the engine gives the code no system call, only WebAssembly's system interface with no directory opened and the host functions plimsolld defines.
- `guest-guard`, not checked: not applicable: the engine starts no program, so there is nothing for the guest guard to stand in front of.
- `process-limit`, not checked: the code cannot start a process: the engine runs it inside plimsolld's own process.
- `memory-limit`, not checked: wazero caps the engine's memory (`WithMemoryLimitPages`) the same way on every host (`TestWasmMemoryLimitEnforced`).
- `cpu-limit`, not checked: a configured CPU limit is refused (`TestWasmRejectsUnsupportedResourceDimensions`), and the run's time limit bounds it instead.
- `fixed-resolver`, not checked: the code has no network, so no resolver.
- `closed-environment`, not checked: the engine is given no environment variables (`TestWasmDefaultCannotReachHostResources` sets a secret in plimsolld's own environment and the code cannot read it).
- `control-channel`, not checked: there is no runner: plimsolld calls the engine directly and reads its output.
- `no-host-share`, not checked: no directory is opened to the engine and no device exists inside it (`TestWasmDefaultCannotReachHostResources`).
- `tier-inside`, not checked: the process tier promises no kernel of its own.
- `setup-read-back`, not checked: there is no service to read back: its startup check reports only whether the settings were valid, and the QuickJS build is embedded in plimsolld and checked against its SHA-256 (`TestEmbeddedQuickJSProvenance`).
- `run-path`, not checked: the engine is built into plimsolld, the same on every host, so the project's own tests run snippets through it.
- `deadline-kill`, not checked: wazero ends the run when its deadline passes (`WithCloseOnContextDone`, `TestWasmTimeout`).
- `output-cap`, not checked: plimsolld reads each stream through a capped buffer of its own.
- `grant-socket`, not checked: there is no socket: a grant reaches the engine through host functions plimsolld defines.
- `languages`, not checked: the engine runs JavaScript alone, and states nothing else.
- `teardown`, not checked: the engine's instance is closed when the run returns, inside plimsolld's process.

**`docker`**, [docker_smoke.go](../sandbox/docker_smoke.go). It starts throwaway containers under the exact lockdown a run gets, one for each configured image, and checks from inside what each can do; then it runs a snippet and a project's runner as runs do.

- `writable-places`, proved: a write to the root filesystem must fail, and a write is tried at every mount point: only the promised <dfn>*tmpfs*</dfn> mounts (filesystems held in memory) may accept one, `/tmp` and `/dev/shm`, and `/work` in a project image. That is what exists when code starts, and the code cannot add a place of its own later, under `runc` or gVisor: making one needs a user namespace of its own (a private view of the system in which it acts as administrator) and a mount in it, and the guest guard refuses both (see `guest-guard`, whose check is also this claim's); under `runc` the shipped seccomp profile refuses them too. (`smokeProbe`, `smokeGuestGuard`)
- `writable-bounds`, proved: in the container's own list of mounted filesystems, each promised mount must be a tmpfs of exactly its configured size, marked `noexec` (a file written there cannot be started or loaded as a program by its path; code a run places in memory is not stopped by it, so `noexec` is a second layer, not the wall; and since the guest guard refuses the code a folder of its own, under `runc` and gVisor alike, there is no unmarked folder for it to copy a program into) and `nosuid`. (`smokeProbe`)
- `loopback-only`, proved: the container's own list of network interfaces must be loopback alone, which is what having no network means inside a container. (`smokeProbe`)
- `no-egress`, not checked: with loopback the only interface (checked above), no packet has a way out, and the docker suite's tests try connections (`TestDockerRunHasNoEgress`).
- `guest-user`, proved: every user and group ID the kernel states for the test's process, and every supplementary group, must be the guest user's: a runtime could accept `--user` and run the code as someone else. (`smokeProbe`)
- `no-capabilities`, not checked: the lockdown passes `--cap-drop ALL` and `no-new-privileges` to docker.
- `seccomp-filter`, not checked: [Preflight](trainers/glossary.html#preflight), the provider's check of its configuration, checks each configured seccomp profile file, and under `runc` every container gets that profile or docker's default; under gVisor no host profile is applied, since gVisor filters requests in its own kernel. The guest guard's own filter, which the test does prove in force under both, is the `guest-guard` claim.
- `guest-guard`, proved: every command plimsoll starts in a container, the code's and plimsoll's own, starts behind the guest guard: a small program of plimsoll's, carried inside plimsolld and mounted read-only into each container (an operator's own image needs nothing added for it), that puts a seccomp filter on itself before anything else runs; every program started after it keeps the filter, and none can take it off. In a [session](trainers/glossary.html#session) the container's first process is the guest guard too, in place of docker's own init (`--init`), which docker started outside it: it stays as process 1 behind its own filter, starts the session's main process and collects every process that ends in the container, and a session does not open unless process 1 is that program. The filter refuses with "Operation not permitted" the requests that make a namespace (`unshare`, `clone` with a namespace flag, `setns`), that mount or change the root (`mount`, `umount2`, `pivot_root`, `chroot` and the newer mount calls), and tracing (`ptrace`, `process_vm_writev`), so a debugger or `strace` does not work in the sandbox; it answers `clone3` and every request numbered above the newest it was reviewed against with "Function not implemented", and ends a process that makes a request through the 32-bit or x32 entry. In each image the test starts a check program of plimsoll's exactly as a run starts the code, and requires the guest guard's answers, under `runc` and under gVisor alike: a request answered in a way only the guest guard's filter answers it, then a user namespace, `clone3`, tracing and a mount refused, then an ordinary request that works; in the image sessions run, it starts the check a second time in a session's shape, with the guest guard as process 1, and under gVisor it requires both processes' `Seccomp` lines in `/proc` to say a filter is on them. Not every one of those answers tells the guest guard from no guest guard: without it a mount is refused anyway (the code holds no capabilities), and under `runc` with the shipped profile so are tracing and a user namespace. What proves the filter is on the code's program is the first answer, which only the guest guard's filter gives, and under gVisor also the namespace and tracing answers, which gVisor without the guest guard allows; the ordinary request proves the filter does not refuse everything. That the filter refuses each request it names is proved by the guest guard's own bytes instead: the guest guard program is named by its SHA-256, [Preflight](trainers/glossary.html#preflight) compares the file every container mounts with the copy inside plimsolld, and plimsoll's tests hold the filter in those bytes to its table. Not covered: the test runs under the default seccomp profile only, never under the variant a run whose grant sets `sdk_env` gets ([seccomp.md](seccomp.md#the-second-profile-runs-whose-grant-sets-sdk_env)): under gVisor no host profile applies, and under `runc` the variant plimsoll derives changes only sockets, but an operator's own variant that ended a process for a request the guest guard makes, instead of refusing it, would be found at the first such run, which fails, not at startup; a machine type with no tested build of the guest guard (only x86-64 has one), where the provider refuses to serve, and a docker daemon, `DOCKER_DEFAULT_PLATFORM` or image for another machine than plimsolld's own, which Preflight refuses for the same reason; and code that puts a program in memory (`memfd_create`) and starts it from there, which no filter of this kind stops. The guest guard is a second layer in front of the code, not the sandbox's wall: the wall is the container under `runc`, or gVisor's kernel. (`smokeGuestGuard`)
- `process-limit`, proved: the container's `pids.max` must equal the configured limit, because a runtime can accept `--pids-limit` without applying it. Under gVisor the container sees an emulated copy of that file that always reads `max`, while gVisor applies the limit to the sandbox's <dfn>*cgroup*</dfn> (the kernel's record of a group of processes' limits) on the host, so there the test reads the host's copy instead, from a container it starts for that. (`smokeProbe`, `proveSandboxPidsLimit`)
- `memory-limit`, not checked: the lockdown passes `--memory`, with `--memory-swap` equal to it so there is no swap.
- `cpu-limit`, not checked: the lockdown passes `--cpus`.
- `fixed-resolver`, proved: the container's `/etc/resolv.conf` must be plimsoll's fixed file byte for byte, since docker writes the host's search domains and name servers there even with no network. (`smokeProbe`)
- `closed-environment`, not checked: plimsoll's own programs start under `env -i` with a fixed PATH, and code gets the verified image's environment and nothing else; a test with an image whose `NODE_OPTIONS` loads a hook holds that split (`TestDockerImageEnvReachesOnlyGuestProcesses`).
- `control-channel`, proved: in each project image the project runner, plimsoll's native helper at `/usr/local/libexec/plimsoll-helper`, must be a regular file, root's and writable by no one else, whose SHA-256 is that of the copy inside plimsolld (the hash is computed inside the image, so this proves the image is the one plimsoll built, not that a hostile image could not lie); the library `/usr/local/lib/plimsoll-runner-guard.so` must be a file, and a program started as a [session](trainers/glossary.html#session) starts its sweep, its quiesce and the relay of each [cell](trainers/glossary.html#cell), with that library loaded first to make it <dfn>*non-dumpable*</dfn> (no other program of the same user may open its descriptors or read its memory), must be listed by the kernel as no longer the guest user's (its `/proc/<pid>/environ` is root's) and its descriptors refused to a process of that user, since a loader that cannot find the library starts the program without it and without a word; and the runner is started as runs start it, and a project step's opens of the runner's plan and report descriptors and of its memory must be refused. (`smokeNativeHelper`, `smokeGuard`, `smokeRunner`)
- `no-host-share`, not checked: the lockdown mounts nothing of the host's but plimsoll's fixed resolver file and the guest guard program, both read-only, and, for a grant, the run's own socket to plimsolld.
- `tier-inside`, not checked: the kernel tier rests on Preflight's reading that the docker daemon registers `runsc` as a program named `runsc`. Under gVisor the test reads the first line of the kernel log, but only for the startup log, since a line like it is easy to forge.
- `setup-read-back`, proved: Preflight reads the one local docker daemon it is bound to: the configured runtime must be registered there, every configured image must be present by its content ID and declare no `VOLUME` (and, with `SANDBOX_REQUIRE_PINNED_IMAGES=1`, be <dfn>*pinned*</dfn>: named by its <dfn>*digest*</dfn>, a hash of its content that names exactly those bytes), and every configured seccomp profile must be a file that agrees with the others; the containers above start those exact content IDs. (`SmokeTest`)
- `run-path`, proved: a snippet must run as runs run it and print what it should, and in each project image the runner must complete a one-step project. (`smokeSnippet`, `smokeRunner`)
- `deadline-kill`, not checked: a run's teardown force-removes its container, which ends every process in it.
- `output-cap`, not checked: plimsolld reads each stream of a container through a capped buffer of its own.
- `grant-socket`, proved: the first container mounts a throwaway host Unix socket exactly as a grant's socket to plimsolld is mounted, and must reach it; gVisor refuses one unless registered with `--host-uds=open`. (`smokeProbe`)
- `languages`, proved: each interpreter is run once in the project image; node must answer, since a session's programs and the granted-run forwarder are node, and only the languages that answer are stated. (`probeLanguages`)
- `teardown`, not checked: every container is started with `--rm` and a label with its expiry, which the orphan sweep removes when a container outlives its run.

**`e2b`**, [e2b.go](../sandbox/e2b.go). It creates one real (billed) microVM, a small virtual machine made for one run, as a run does, stages files into it, runs a test program through exactly the path a project step takes, and checks live that <dfn>*egress*</dfn> (traffic leaving the VM) is blocked. It also keeps the template's node version: a session's own programs start with `--disable-sigusr1`, which node accepts from v22.14.0 (v23.7.0 in the 23 line, every release from 24), so on an older node a session is refused at its open while single runs, which start none of plimsoll's own node programs, are served. E2B's `base` template carried node v20.9.0 when a live check read it on 2026-11-20, and E2B removed that template's published recipe on 2026-10-13; plimsoll's recipe in `e2b/` builds one that serves sessions.

- `writable-places`, not checked: the wall is the microVM itself, not a read-only filesystem inside it.
- `writable-bounds`, proved: E2B's control plane must report the microVM's disk at or under the configured size: read back, not filled. Only when `SANDBOX_DISK_MB` is set. (`SmokeTest`)
- `loopback-only`, not checked: the microVM has a network interface, which E2B's <dfn>*deny-all*</dfn> policy (one that blocks every connection no rule allows) holds shut; the requests below test it.
- `no-egress`, proved: HTTPS and HTTP requests to a raw IPv4 address, an HTTPS request to a raw IPv6 address and one to a name must all fail. Only a request that gets an answer counts as egress, since E2B's proxy accepts every IPv4 connection under deny-all and then closes it without forwarding (measured 2026-10-24). A DNS question for example.com, sent in a UDP datagram to an outside IPv4 address, over TCP to that address's port 53, and to an outside resolver through node's own resolver, must get no answer either. Every reply counts as egress except a refusal (DNS code REFUSED or NOTIMP, with no answer): a "no such name" counts, so a name that resolves while every connection then fails is caught. A resolver on the internet never refuses example.com, so a refusal comes from the sandbox's own side and resolves nothing. The UDP and resolver questions passed against E2B on 2026-11-24; the TCP question was added the same day and has run only on a docker stand-in. (`SmokeTest`)
- `guest-user`, not checked: the wall is the microVM, and the test does not read which user a step runs as inside it.
- `no-capabilities`, not checked: the wall is the microVM, and the test reads nothing of the kernel's inside it.
- `seccomp-filter`, not checked: the wall is the microVM, and the test reads nothing of the kernel's inside it.
- `guest-guard`, not checked: not applied: the wall is the virtual machine, no `noexec` mark is stated to protect, and the service's own process interface starts each command, not a command line of plimsoll's.
- `process-limit`, not checked: E2B has no per-sandbox process limit, so `SANDBOX_PIDS` is refused.
- `memory-limit`, proved: the control plane must report the microVM's memory at or under the configured cap (the template sets it; the setting is a maximum): read back, not measured inside. Only when `SANDBOX_MEMORY_MB` is set. (`SmokeTest`)
- `cpu-limit`, proved: the control plane must report the microVM's virtual CPUs at or under the configured cap: read back, not measured inside. Only when `SANDBOX_CPUS` is set. (`SmokeTest`)
- `fixed-resolver`, not checked: the deny-all policy holds the network shut, and the request by name above must fail.
- `closed-environment`, not checked: E2B's agent in the microVM (envd) starts each command, and the test does not read the environment a command gets.
- `control-channel`, not checked: the channel to the microVM is E2B's agent in it (envd), reached with the sandbox's access tokens.
- `no-host-share`, not checked: the wall is the microVM, which shares no folder or device of plimsolld's host.
- `tier-inside`, not checked: the vm tier follows from which provider it is, since E2B runs each sandbox in a Firecracker microVM; the test proves the microVM behaves as promised, not that the program running the virtual machine is present.
- `setup-read-back`, not checked: E2B names a template by its name alone, never by a digest that could be read back, so hardened mode requires the name to be explicit; the resources are read back under the limits above.
- `run-path`, proved: the microVM is created as a run's is, with both access tokens (a secured create); a test program and a step script are staged in one upload, and the script runs it through exactly the path a project step takes, a shell running node, which must exit 0 in the project directory. (`SmokeTest`)
- `deadline-kill`, not checked: a run's microVM is killed when the run ends.
- `output-cap`, not checked: plimsolld caps each stream as it reads it.
- `grant-socket`, not checked: a grant reaches the microVM's code through plimsolld's <dfn>*egress guard*</dfn>, an HTTPS endpoint of the daemon's that is the only address the run may reach, not through a socket of the host's.
- `languages`, proved: JavaScript is stated because node ran the test program; each other language only when its interpreter answers a probe. (`SmokeTest`)
- `teardown`, not checked: the test's microVM is killed when the test ends, and the orphan sweep removes what a crashed daemon left.

**`dockercloud`**, [dockercloud_lifecycle.go](../sandbox/dockercloud_lifecycle.go). It checks the token's permissions, then creates one throwaway (billed) sandbox from Docker Cloud Sandboxes as a run does, reads its network policy back, and runs a test program, a hung command and a flood of output through the exact path a project step takes ([dockercloud.md](dockercloud.md#startup-smoke-test)).

- `writable-places`, not checked: the wall is the microVM itself, not a read-only filesystem inside it.
- `writable-bounds`, not checked: the service has no disk control, so `SANDBOX_DISK_MB` is refused.
- `loopback-only`, not checked: the microVM has a network interface, which the deny-all policy holds shut; the requests below test it.
- `no-egress`, proved: from inside, HTTPS and HTTP requests to a raw IPv4 address, an HTTPS request to a raw IPv6 address and one to a name must all fail, and the three DNS questions of the `e2b` entry above must get no reply but a refusal. Docker Cloud answers every DNS question on port 53, to any address, with REFUSED and no answer (measured 2026-11-24), so the question reaches Docker's side of the sandbox and nothing is resolved; what Docker's side does with the names it refuses cannot be seen from inside. The startup test with all three questions passed against Docker Cloud on 2026-11-24. (`SmokeTest`)
- `guest-user`, not checked: the wall is the microVM, and the test does not read which user a step runs as inside it.
- `no-capabilities`, not checked: the wall is the microVM, and the test reads nothing of the kernel's inside it.
- `seccomp-filter`, not checked: the wall is the microVM, and the test reads nothing of the kernel's inside it.
- `guest-guard`, not checked: not applied: the wall is the virtual machine, no `noexec` mark is stated to protect, and the service's own process interface starts each command, not a command line of plimsoll's.
- `process-limit`, not checked: the service has no process limit, so `SANDBOX_PIDS` is refused.
- `memory-limit`, proved: the service's account of the new sandbox must give its memory at or under what was requested (the smallest size when none is configured): read back, not measured inside. (`SmokeTest`)
- `cpu-limit`, proved: the service's account of the new sandbox must give its CPUs at or under what was requested: read back, not measured inside. (`SmokeTest`)
- `fixed-resolver`, not checked: the deny-all policy holds the network shut, and the request by name above must fail.
- `closed-environment`, not checked: the service starts each command, and the test does not read the environment a command gets.
- `control-channel`, not checked: the channel to the sandbox is the service's own endpoint for it, reached with the token.
- `no-host-share`, not checked: the wall is the microVM, which shares no folder or device of plimsolld's host.
- `tier-inside`, not checked: the vm tier follows from which provider it is, since Docker Cloud Sandboxes runs each sandbox in a microVM; the test proves the policy that blocks every connection and the blocked egress, not the program running the virtual machine.
- `setup-read-back`, proved: the token's permissions are checked first; the new sandbox's endpoint must be one the token may be sent to, and a pinned image must be the digest it booted (under the REST API, which reports none, the pinned reference the service recorded); and its effective network policy, read back, must be deny-all with nothing allowed. (`SmokeTest`)
- `run-path`, proved: the project directory is made, a test program and a step script are uploaded, and the script runs it through the exec wrapper around a shell, as a project step runs, which must exit 0 with a node version in the project directory. (`SmokeTest`)
- `deadline-kill`, proved: a hung step, in a step's own shape (an outer shell, then the script's), must really be ended at a 1 second limit: busybox's `timeout`, which the image's steps run under, fails open when the kernel refuses its kill. (`SmokeTest`)
- `output-cap`, proved: a flood of output must be cut at exactly the cap, with the cut reported and the command failed. (`SmokeTest`)
- `grant-socket`, not checked: a grant reaches the sandbox's code through plimsolld's egress guard, not through a socket of the host's.
- `languages`, proved: JavaScript is stated because node ran the test program; each other language only when its interpreter answers a probe. (`SmokeTest`)
- `teardown`, not checked: the test's sandbox is destroyed when the test ends, and the orphan sweep removes what a crashed daemon left.

**`openshell`**, [smoke.go](../sandbox/openshell/smoke.go). It creates one throwaway sandbox as a run does and checks from inside it the writes, the network and the limits; then it round-trips a project at the size ceiling through the runner and kills a hung command.

- `writable-places`, proved: a write is tried at every path the code can reach (each mount point, the standard top-level directories and every directory beneath them that can be listed, at least 100 paths): only `/tmp` and what lies beneath it may accept one, which shows Landlock (the kernel's path rules for a process) enforcing the policy. (`smokeProbe`)
- `writable-bounds`, proved: `/tmp` must be a tmpfs (a filesystem held in memory) of exactly the configured size, marked `noexec`, `nosuid` and `nodev`. Only when `SANDBOX_DISK_MB` is set. (`smokeProbe`)
- `loopback-only`, proved: the sandbox's list of network interfaces must be loopback alone. (`smokeProbe`)
- `no-egress`, proved: connections to two IPv4 and two IPv6 addresses, and an HTTPS request by name, must go unanswered or be refused inside the sandbox; a refusal or a TLS failure from outside counts as egress. (`smokeProbe`)
- `guest-user`, not checked: every command runs as the gateway's sandbox user, which plimsoll does not choose.
- `no-capabilities`, not checked: the gateway, not plimsoll, sets what its sandbox user holds.
- `seccomp-filter`, not checked: the gateway, not plimsoll, sets the sandbox's seccomp filter; plimsoll's policy requires Landlock, so a command fails where the kernel lacks it.
- `guest-guard`, not checked: not applied yet: the guest guard is built for the docker provider first, and this provider's commands do not start behind it.
- `process-limit`, not checked: the gateway sets one process limit for all of its sandboxes, so `SANDBOX_PIDS` is refused; the test reads the sandbox's `pids.max` only for the startup log.
- `memory-limit`, proved: the sandbox's own cgroup (the kernel's record of a group of processes' limits) must carry the requested memory limit, `memory.max`. (`smokeProbe`)
- `cpu-limit`, proved: the sandbox's own cgroup must carry the requested CPU quota, `cpu.max`. (`smokeProbe`)
- `fixed-resolver`, not checked: the policy has no network rules, so no name is resolved outside the sandbox; the test records what a name resolves to inside (an address the gateway makes up, not a real answer) only for the startup log.
- `closed-environment`, not checked: a v0.1.2 gateway hands every command a fixed set of variables of its own (HOME, PATH, its CA settings, `OPENSHELL_SANDBOX`, TERM, USER), never the image's (measured 2026-10-03), and plimsoll's own programs start under `env -i`.
- `control-channel`, proved: the project's step must be refused when it opens the runner's plan and report descriptors and its memory. (`smokeRunner`)
- `no-host-share`, not checked: the gateway decides what its docker driver mounts into a sandbox; the write sweep above would find a writable folder of the host's, not a read-only one.
- `tier-inside`, not checked: the container tier rests on the gateway's own report that it creates sandboxes with docker. The gateway does not say which runtime its docker uses, so plimsoll reports container even where that is gVisor.
- `setup-read-back`, proved: the gateway must report that it creates sandboxes with its docker compute driver (any other driver is refused), and the test's sandbox is created as a run's is, its policy and limits read back exactly. (`SmokeTest`)
- `run-path`, proved: a project at the 4 MiB size ceiling must round-trip through the runner by the project exec path, its plan on standard input, and the step's output file must have the length and SHA-256 the host computed. (`smokeRunner`)
- `deadline-kill`, proved: a command that never ends, and a second process it starts, must both be gone, as a second command counts them, once the first command's exec stream is cancelled: the mechanism behind every timeout. (`smokeKill`)
- `output-cap`, not checked: plimsolld caps each stream of a command as it reads it.
- `grant-socket`, not checked: a grant reaches the sandbox through a relay inside it that plimsolld connects over the gateway's exec stream, not through a socket mounted from the host.
- `languages`, proved: each interpreter is run once; node must answer, since snippets, the relays and a session's programs are node, and only the languages that answer are stated. (`smokeLanguages`)
- `teardown`, not checked: the test's sandbox is deleted when the test ends, and every sandbox carries a label with its lifetime, by which the orphan sweep removes one that outlives its run.

**`agentsandbox`**, [smoke.go](../sandbox/agentsandbox/smoke.go). It claims three sandboxes from the warm pool as every run claims them: in the first a snippet tests the wall from inside, and dials the second, which runs no code; in the third a project step tests the channels of the runner and of sandboxd (the agent in the pod that starts its processes); the pool, template, policies and runtime class must read the same before and after.

- `writable-places`, proved: a write is tried at every path the code can reach (at least 100 paths): it may succeed only beneath the template's emptyDir mounts and `/dev/shm`, nowhere else may it even create a file (message queues in `/dev/mqueue` excepted, while the guest's allowance for them is small and finite), no file outside them may open for append, and `/work` must accept writes. (`smokeBoundary`)
- `writable-bounds`, proved: below the vm tier each volume is filled until it refuses a write (ENOSPC) at its size limit; at the vm tier, where Kata keeps no size limit, each writable root must be a tmpfs (a filesystem held in memory) of the VM's own kernel, so it fills the VM's memory, never the node's disk; at every tier no mount may sit beneath a writable root, where the root's limit would not cover it. (`smokeBoundary`)
- `loopback-only`, not checked: a pod has a network interface of its own; the test records the interfaces it sees for the startup log, and the connection attempts below hold the pod's network shut.
- `no-egress`, proved: connections to public IPv4 and IPv6 addresses, the cloud metadata address, the API server, the node's kubelet and another sandbox pod's TLS terminator port must time out or be unreachable, never open or refused (a refusal is an answer, so the packet left the pod). The other sandbox is claimed for the test, and plimsolld reaches its terminator over TLS after the attempt, so the port was listening. (`smokeBoundary`)
- `guest-user`, proved: every user and group ID of the code must be the guest user's, with no supplementary group. (`smokeBoundary`)
- `no-capabilities`, proved: the code must hold no effective or permitted capability, and run with `no_new_privs`. (`smokeBoundary`)
- `seccomp-filter`, proved: the code's status must say seccomp mode 2, a filter in force (it proves a filter, not which one). Under gVisor the status is gVisor's own emulation, which says nothing of the host's filter, so the kernel tier is held to its kernel log instead (`tier-inside`). Only at the container tier. (`smokeBoundary`)
- `guest-guard`, not checked: not applied yet: the guest guard is built for the docker provider first, and this provider's commands do not start behind it.
- `process-limit`, not checked: a pod's process limit is the kubelet's on each node, which the API does not show, so `SANDBOX_PIDS` is refused.
- `memory-limit`, not checked: the read-back holds the template's container to the configured memory limit, and the kubelet applies it to the pod.
- `cpu-limit`, not checked: the read-back holds the template's container to the configured CPU limit, and the kubelet applies it to the pod.
- `fixed-resolver`, proved: the code's resolver settings must be the one loopback name server and nothing else. (`smokeBoundary`)
- `closed-environment`, proved: the code's environment must hold PATH and HOME alone. (`smokeBoundary`)
- `control-channel`, proved: from inside the pod, sandboxd must refuse a process start without its token and one with a wrong token (gRPC status 16, unauthenticated), the code's open of the TLS key must be refused for permission, and a cleartext start sent to the TLS terminator's port must get no gRPC status; and a project step must be refused when it opens the runner's plan and report descriptors and memory, and sandboxd's and pid 1's memory, environment and input. Before any project runs, the project runner at `/usr/local/libexec/plimsoll-helper` must be a regular file, root's and writable by no one else, whose SHA-256 is that of the copy inside plimsolld (read by the guest inside the image, so this proves the image is one built with that runner, not that a hostile image could not lie). (`smokeBoundary`, `smokeRunner`)
- `no-host-share`, not checked: the read-back refuses a template that shares the node's own network, process list or inter-process communication, or exposes a host port, and allows no volume but memory-backed emptyDir ones.
- `tier-inside`, proved: at the kernel tier the first line of the code's kernel log must be gVisor's own boot line exactly, and at the vm tier a Linux kernel's boot line: a runtime class's handler is only a name in the node's configuration. This is no proof from the hardware, but a handler that names one runtime and a guest that sees another kernel is refused. Every pod, the test's included, is also held at the vm tier to a boot ID that is not its node's. Only at the kernel and vm tiers. (`smokeBoundary`)
- `setup-read-back`, proved: Preflight reads the warm pool, its template (whose pod spec must pass every pod's checks) and the runtime class; the test binds the network policies over its sandboxes, and the class, before its three sandboxes, and requires them and the template to read the same after. (`SmokeTest`)
- `run-path`, proved: the boundary test runs as a snippet through the run path itself, and the runner test as a project whose one step must complete. (`smokeBoundary`, `smokeRunner`)
- `deadline-kill`, not checked: a run's sandbox is deleted when the run ends, which ends every process in its pod.
- `output-cap`, not checked: plimsolld caps each stream of a command as it reads it.
- `grant-socket`, not checked: grants are not supported yet.
- `languages`, not checked: the provider states no languages of its own, and the image's node, which the runner needs, runs both tests above.
- `teardown`, not checked: each sandbox is deleted after its run, and every claim carries this instance's label, by which the orphan sweep finds what a crashed daemon left.

**`wslc`**, [smoke.go](../sandbox/wslc/smoke.go). It inspects the image, then runs a boundary test as a runner step through exactly the path a run takes and checks what the container it got can do; in the per-run mode it does that in two fresh virtual machines, each torn down after ([wslc.md](wslc.md#startup-smoke-test-and-readiness)).

- `writable-places`, proved: a write is tried at every mount point and, walking the whole filesystem, at every folder and file the guest user looks able to write: only the four tmpfs mounts (`/tmp`, `/var/tmp`, `/dev/shm` and `/work`) may accept one, and the walk must not stop short. WSL containers cannot mount the root read-only, so this walk is what shows the guest user cannot write to it; a folder the guest user cannot list is not entered (the startup log counts them). (`checkBoundary`)
- `writable-bounds`, proved: each of the four must be a tmpfs (a filesystem held in memory) of its configured size, marked `noexec`, `nosuid` and `nodev`. (`checkBoundary`)
- `loopback-only`, proved: the container's list of network interfaces must be loopback alone. (`checkBoundary`)
- `no-egress`, proved: a TCP connection to two public addresses and the cloud metadata address must not connect. (`checkBoundary`)
- `guest-user`, proved: every user and group ID of the code must be the guest user's, with no other group. (`checkBoundary`)
- `no-capabilities`, proved: every capability set of the code, the bounding set included, must be empty. (`checkBoundary`)
- `seccomp-filter`, proved: the code's status must say seccomp mode 2, docker's default filter (WSL containers offer no choice of profile); with gVisor, whose own reading differs, every gVisor kernel process in the VM must run under a filter of its own instead. (`checkBoundary`)
- `guest-guard`, not checked: not applied yet: the guest guard is built for the docker provider first, and this provider's commands do not start behind it.
- `process-limit`, proved: the code's process limit (`--ulimit nproc`, `SANDBOX_WSLC_NPROC`), and its open-file and core-file limits, must be the configured ones. The process limit counts every process of the guest user in the VM, not one run's: WSL containers have no `--pids-limit`, so `SANDBOX_PIDS` fails startup. (`checkBoundary`)
- `memory-limit`, proved: the container's `memory.max` must be the configured limit; with gVisor, the limit on the cgroup that holds gVisor's processes, read in the VM. (`checkBoundary`)
- `cpu-limit`, not checked: `--cpus` is passed to WSL containers, and the test reads only the memory limit back.
- `fixed-resolver`, proved: the container's resolver settings may name no name server but loopback and no search domain (`--dns 127.0.0.1 --dns-search .`). (`checkBoundary`)
- `closed-environment`, proved: a step's environment may hold no variable but the image's and those the runner and a step's shell set. (`checkBoundary`)
- `control-channel`, proved: the project runner at `/usr/local/libexec/plimsoll-helper` must be a regular file, root's and writable by no one else, whose SHA-256 is that of the copy inside plimsolld (read by the test's step inside the image, so this proves the image is one built with that runner, not that a hostile image could not lie), and a step's open of the runner's memory must be refused. (`checkBoundary`)
- `no-host-share`, proved: the container's mount table may hold no 9p, virtiofs, drvfs, SMB or FUSE mount, the ways a Windows folder reaches Linux, and the container must lack the GPU device `/dev/dxg`, which every VM of WSL containers has. (`checkBoundary`)
- `tier-inside`, proved: the container's kernel release and boot ID must be those of the VM the test read; in the per-run mode that VM's boot ID must be one never seen before (not the other test VM's, the shared mode's VM's or the WSL distribution's), so each run lands in a virtual machine of its own. With gVisor in the VMs, the kernel and boot ID must be gVisor's own, and the VM must show the container running under `runsc`. Microsoft states that WSL is not a security sandbox for running untrusted code; that sentence goes with the tier. (`checkBoundary`)
- `setup-read-back`, proved: WSL must be at least the release whose `wslc` can drop capabilities, and the image must be a Linux image with a `sha256` ID, no `VOLUME`, its pinned digest among its repository digests and no environment variable the C library or loader reads at startup; in the per-run mode the run root must be this process's alone and writable by no one else, and so must the template's folder and disk file. (`SmokeTest`, `smokePerRun`)
- `run-path`, proved: the boundary test runs as a project step through the runner, which must send an authenticated report of a completed step. (`checkProbe`)
- `deadline-kill`, not checked: the runner ends a step at its time limit, and a run that does not end cleanly has its container force-removed (in the per-run mode its whole VM is torn down).
- `output-cap`, not checked: plimsolld caps each stream of a command as it reads it.
- `grant-socket`, not checked: grants are not offered by this provider.
- `languages`, not checked: the provider states JavaScript alone, the language of the runner's node, which runs the boundary test.
- `teardown`, proved: each of the two test VMs is torn down as a run's is, and its directory must be gone after; the shared mode's runs share one VM, which no run tears down. Only in the per-run mode. (`smokeSession`)

<!-- End of the generated section. -->

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
- For `wslc` in its per-run mode, the vm tier is stated only when the operator sets
  `SANDBOX_WSLC_ACCEPT_VM_TIER=1`, accepting Microsoft's statement below; without it the
  mode reports `container`. Where it is stated, it follows from how each run is started:
  in a virtual machine of its own, which WSL containers start for the run with Hyper-V
  and plimsolld deletes after it. Its startup test proves that its two boundary-test runs
  landed in two virtual machines never seen before (boot IDs that differ from each other,
  from the user's shared WSL containers machine and from the WSL distribution), and every
  run refuses a boot ID already seen; it does not prove the hypervisor. Microsoft states
  that WSL is not a security sandbox for running untrusted code; `Describe`, the startup
  log and `plimsolld -h` carry that sentence beside the tier, and hardened mode refuses
  the provider ([wslc.md](wslc.md#the-tier-and-why-hardened-mode-refuses-it)).

All four are stronger than a sentence in a datasheet and weaker than
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

A provider may also state a sentence that must stand beside its tier wherever the tier is
shown, for example a vendor's own statement about the wall under it. A caller reads it from
`Describe`, as `isolation_qualification` (`Info.IsolationQualification` in the Go client,
`isolation_qualification` in the Python client, `isolationQualification` in the TypeScript
client, and in the summary of the <dfn>*MCP*</dfn> (Model Context Protocol) server's
`server_info`); it is empty for a provider with none. Every run's answer states it too
(`RunResponse.isolation_qualification`), and so does the <dfn>*run record*</dfn> (the
daemon's statement of what it ran and where, which a program outside the daemon signs) from record version 5
and <dfn>*protocol number*</dfn> 6 (the version the daemon and its client must agree on): the
clients' results, the MCP server's run results and the bills of materials of
[examples/sbom](examples/sbom/index.html) state it beside the tier. Like the tier, it is
configuration and provider evidence, never runtime attestation.
Today only the `wslc` provider states one, and it does in both of its modes: each carries
Microsoft's statement about WSL; the shared mode's also says that its runs share one
virtual machine and are weaker than docker under `runc`; the per-run mode's also says
which tier it reports and the setting that changes it, and adds gVisor's position when
gVisor runs inside its virtual machines
([wslc.md](wslc.md#the-tier-and-why-hardened-mode-refuses-it)).

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

`SANDBOX_MIN_ISOLATION` is the operator's floor for the whole daemon, checked at startup and
held on every run. At startup it is checked before the provider's startup checks start
anything, for every provider whose configuration fixes its tier; docker under gVisor
(`runsc`), `agentsandbox` and `openshell` learn their tier from those checks, so they are
checked after them. On every run it is merged into each request's minimum, so a provider that finds a
weaker boundary after startup refuses the run, not dispatched, and `/readyz` reports not
ready.
It does not replace a caller's own floor on each request: a `Describe` answer the caller
read earlier can be out of date, and must never be what allows a weaker run later.
A daemon started with `PLIMSOLL_HARDENED=1` adds a floor of its own, `kernel`, which it
joins to every request's minimum, so there a caller that sets none is still refused a
weaker sandbox
([hardened-mode.md](hardened-mode.md#isolation-is-a-floor-on-every-run-not-only-a-startup-check)).
