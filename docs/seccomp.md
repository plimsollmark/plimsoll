# Audited seccomp profile for the docker sandbox

<dfn>*Seccomp*</dfn> is the Linux kernel feature that limits which
<dfn>*syscalls*</dfn> (requests to the kernel, such as opening a file or starting a
process) a process may make. `docker/seccomp.json` is a seccomp profile: a
**deny-by-default** allowlist of syscalls, built for the plimsoll workload, which is
the `node` runtime plus the TypeScript toolchain (`tsc`/`tsx`/`eslint`) and the child
processes the project runner spawns. It is opt-in: reference it with
`SANDBOX_DOCKER_SECCOMP=docker/seccomp.json` (an absolute path in production).
Leaving the variable empty keeps docker's built-in default profile, which does not keep
sockets to the families it names on a host with the 32-bit entry ([Architectures](#architectures)).
A copy of the profile made from a release up to v0.27.2 is refused at startup: copy it
again from this release ([Architectures](#architectures) says why).

```sh
SANDBOX_PROVIDER=docker \
SANDBOX_DOCKER_SECCOMP=/etc/plimsoll/seccomp.json \
plimsolld
```

The profile is skipped automatically under <dfn>*gVisor*</dfn>
(`SANDBOX_DOCKER_RUNTIME=runsc`), a stand-in kernel that runs as an ordinary program
and intercepts the container's syscalls itself. A host seccomp filter there is
redundant for guarding the host kernel and can conflict. The profile's refusals then do
not apply to the code, but those of the <dfn>*guest guard*</dfn>, plimsoll's own second filter, do: under both runtimes it refuses the code a
private view of the system of its own and folders mounted in it
([The guest guard](#the-guest-guard-a-second-filter-in-front-of-every-program)).

## Why ship one over docker's built-in default

The containers already run with `--cap-drop ALL --security-opt no-new-privileges`
(and state their own `--ulimit core=0`, `--ulimit nofile=4096:4096` and `--ipc private`
rather than inherit the docker daemon's: no core file, so code that crashes in the container never runs the
host's core-dump handler, and a fixed descriptor limit).
That removes every **capability-gated** syscall, one the kernel allows only to a
process holding a Linux capability (a slice of root's privileges): `mount`, `bpf`,
most of `ptrace`'s privileged modes, module loading, and so on. So what a custom
profile adds is precisely the syscalls that are **not** capability-gated: under
docker's default profile, an attacker inside the container, running as the same user
as its processes, can still reach them.

| Syscall(s) | Why denied |
|---|---|
| `ptrace`, `process_vm_readv`, `process_vm_writev` | Read or inject into the memory of other processes running as the same user; no capability required. |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | A large kernel interface with a history of exploits; node does not need it (and disables it by default). |
| `userfaultfd` | A standard building block for exploiting use-after-free bugs; available without privileges by default. |
| `perf_event_open` | A broad kernel interface, restricted by a kernel setting (a sysctl) rather than a capability. |
| `bpf` | Loads programs into the kernel; whether an unprivileged process may is a kernel setting (`kernel.unprivileged_bpf_disabled`), not a capability. |
| `keyctl`, `add_key`, `request_key` | Access to the kernel keyring (its key store), reachable without privileges. |
| `unshare`, `setns`, `CLONE_NEW*` clone flags, `clone3` | Create or enter <dfn>*namespaces*</dfn>, the kernel's separate views of files, processes and network that containers are built from: a lever for an <dfn>*escape*</dfn> from the sandbox or for gaining privileges. `clone` is allowed only when its flags carry none of them; `clone3` passes its flags in memory the filter cannot read, so it fails with `ENOSYS` and the C library falls back to `clone`. |
| `mount`, `umount2`, `pivot_root`, `chroot` | Change what the filesystem looks like to the process. |
| `name_to_handle_at`, `open_by_handle_at` | Open files by handle, bypassing path checks. |
| `modify_ldt` | Change the x86 local descriptor table (LDT), an exploitation aid the workload never uses. |
| `kexec_load`, `init_module`, `finit_module`, `reboot`, `swapon` | Host-level operations with no place in a sandbox. |
| `clock_settime`, `clock_adjtime`, `settimeofday`, `adjtimex` | Change the host's clock. |
| SysV IPC: `shmget`, `shmat`, `shmdt`, `shmctl`, `semget`, `semop`, `semtimedop`, `semctl`, `msgget`, `msgsnd`, `msgrcv`, `msgctl` | Old-style shared memory, semaphores and message queues between processes, unused by the workload. |
| `socket(AF_ALG, ...)` | Sockets into the Linux kernel's cryptography code; unnecessary for the workload and implicated in container privilege escalation. |
| `socketcall`, `ipc` | The 32-bit x86 entry's two multiplexers: one call each that performs every socket call or every SysV IPC call, with the real arguments in memory, where a filter cannot read them. On x86-64 and aarch64 the profile names no 32-bit architecture, so these, and every other call through a 32-bit or x32 entry, are killed ([Architectures](#architectures)). |

Every syscall not on the allowlist, made through the machine's native entry, fails with
`EPERM` (`defaultAction: SCMP_ACT_ERRNO`, `defaultErrnoRet: 1`). A call through any other
entry is not checked against the list at all: it kills the thread that made it.

## Notable allow-list decisions

- **`clone` is argument-filtered**: whether a call is allowed depends on its
  arguments. Threads and child processes are allowed, but a masked-equal check on the
  first argument (mask `0x7e020000`, the bits of the `CLONE_NEW*` flags `clone`
  accepts) rejects any `clone` carrying a `CLONE_NEW*` namespace flag. `clone3` is
  forced to fail with `ENOSYS` (errno 38, "not implemented") so the C library falls
  back to the filtered `clone` path. A seccomp filter sees only a call's argument
  values, and `clone3` passes its flags in a struct in memory, so it cannot be
  argument-filtered and denying it outright is the safe choice (musl and glibc both
  fall back cleanly).
- **`personality` is value-filtered** to `0` and `0xffffffff` (which only reads the
  current setting), blocking `READ_IMPLIES_EXEC` (which makes readable memory
  executable) and similar flags.
- **`socket` and `socketpair` are argument-filtered to `AF_UNIX`.** The host-API
  <dfn>*broker*</dfn>, the part of plimsoll outside the sandbox that makes API calls
  for a run's code, is reached over a bind-mounted Unix socket, and libuv (node's I/O
  library) uses Unix socketpairs internally. Other socket families, notably `AF_ALG`,
  are denied: `--network none` alone does not remove the kernel's socket families
  that never route over a network. The rule holds because the profile names only each
  machine's native architecture; through the 32-bit entry it did not, until 2026-11-19
  ([Architectures](#architectures)). The one kind of run that needs IPv4 sockets gets a
  second profile, never a wider default (the section below).
- **`memfd_create`, `inotify_*`, `timerfd_*`, `signalfd*`** are allowed: node/libuv
  use them for normal operation.
- **`kill` is allowed.** Each run has its own PID namespace, so `kill(2)` reaches
  only the run's own processes. Without it a process cannot stop a child it started:
  the physics runners (`docker/sim/oracle`) run an agent's <dfn>*controller*</dfn>, a
  program that decides at every <dfn>*tick*</dfn> (one fixed time step of a
  simulation) how to push the simulated system, and they SIGKILL a controller that
  misses its per-tick time to answer or lingers after the last tick. Before 2026-09-25
  the profile withheld it by omission, not decision, and those paths crashed under it
  with an unhandled `EPERM`; `TestDockerJudgesRefuseNonAnswers` exercises them.

- **`mknod` and `mknodat` are allowed for FIFOs only.** A <dfn>*session*</dfn>, one
  sandbox kept for many calls, can keep an interpreter alive between calls to run
  notebook-style code ([sessions.md](sessions.md#interpreters-state-between-calls)), and
  the interpreter writes its output to two FIFOs, named pipes that `mkfifo` creates through `mknodat`. A masked-equal check on the
  mode argument allows the call only when its file-type bits are those of a FIFO, so a
  device node and a regular file through `mknod` stay denied (a device node also needs
  `CAP_MKNOD`, which every run drops). A FIFO is the same kernel object `pipe2` makes,
  given a name. `TestDockerSeccompAllowsOnlyFIFOs` checks all three from inside a run,
  and `TestShippedSeccompProfileIsSaneAndTight` the filter itself.
- **`utime`, `utimes` and `futimesat` are allowed.** They are older forms of `utimensat`,
  which was already allowed: the kernel implements all four through the same code in
  `fs/utimes.c`, with the same ownership and write-permission checks, so they add no
  capability. Older C libraries still issue them. Before 2026-09-28 the profile withheld
  them by omission, and a program built on Ubuntu 20.04's C library failed with `EPERM`
  while setting the modification time of files it had just written to `/work`.
  `TestDockerLegacyTimestampSyscalls` makes each call from inside a run.

## The second profile: runs whose grant sets `sdk_env`

A second profile exists for one kind of run: a run whose <dfn>*grant*</dfn> (the
permission, attached to one run, for its code to call listed routes of one API) comes from
a profile that sets `sdk_env`, the local address a standard client library reaches the
broker through
([capability-grants.md](capability-grants.md#standard-client-libraries-in-any-language)).
That address is a forwarder listening on IPv4 loopback inside the container, which the
default profile's `AF_UNIX`-only rule denies. The variant is not a second file to copy:
with `SANDBOX_DOCKER_SECCOMP_SDK=derived` the daemon makes it from the configured default
at startup, so the two can never drift apart, and the derived bytes are what docker
applies (a copy named by their SHA-256, beside the default, see below). It is the default plus
exactly these rules, and `TestShippedSeccompSDKVariantDiffersFromDefaultByExactlyItsRules`
fails if the derivation changes anything else:

- **`socket(AF_INET, type, protocol)` is allowed only for TCP streams.** `type` is masked
  so that only `SOCK_NONBLOCK` and `SOCK_CLOEXEC` may be added to `SOCK_STREAM` (mask
  `0xfff7f7ff`, expected `1`), and `protocol` must be `0` or `IPPROTO_TCP` (`6`). UDP
  (`SOCK_DGRAM`), raw sockets, SCTP (protocol 132) and Multipath TCP (protocol 262) fail
  the type or protocol check; `AF_INET6` and every other family stay denied, and
  `socketpair` stays `AF_UNIX`-only.
- **`setsockopt` and `getsockopt` are no longer allowed whole.** The default allows them
  unfiltered; the variant takes them out of that list, because allow rules combine as a
  union, and allows only the options the forwarder and the client transports set, by
  level and name: `setsockopt` for `SO_REUSEADDR` (libuv sets it on every TCP listener),
  `SO_KEEPALIVE`, `TCP_NODELAY`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL` and `TCP_KEEPCNT` (node's
  HTTP agents and the client libraries keep connections alive without Nagle's delay);
  `getsockopt` for `SO_ERROR` (libuv reads a connect's result) and `SO_TYPE` (libuv
  classifies a child's standard input and output when they are a socketpair; measured:
  without it the project runner's own isolation check failed, since the check is a node
  child started by node). `TCP_ULP` (the
  option that attached the kernel TLS code behind CVE-2023-0461), the `SOL_TLS` options
  and the socket-filter options (`SO_ATTACH_FILTER`, `SO_ATTACH_BPF`,
  `SO_ATTACH_REUSEPORT_CBPF`, `SO_ATTACH_REUSEPORT_EBPF`) are refused, and
  `TestShippedSeccompSDKVariant` checks each of these allowances and refusals against the
  file itself.

What the variant adds, said plainly: hostile code in such a run gains IPv4 TCP socket
creation and the kernel code behind it (connection state, send and receive queues, timers,
loopback packet processing, the allowed options, the socket `ioctl` handlers that no
seccomp rule can tell apart from other `ioctl`s), all in the shared host kernel. Under
`--network none` the container has only its loopback interface and no capabilities, so
those sockets reach nothing outside the container and cannot be raw; but "only loopback"
describes connectivity, not kernel safety, and seccomp cannot read the address a connect
or bind points at, so it cannot hold the run's code to the forwarder's port. That is why the
variant exists at all instead of widening the default: a caller selects a
<dfn>*grant profile*</dfn> (a grant stored on the server under a name) it is authorized
for, and a profile that sets `sdk_env` authorizes this exposure for that run alone.

### Configuring the two, and how a run is matched to one

`SANDBOX_DOCKER_SECCOMP` is the profile every run gets. `SANDBOX_DOCKER_SECCOMP_SDK` is
the one a run gets instead when its grant sets `sdk_env`: `derived` makes it from the
default; a path names a variant of your own (for a default that is not the shipped
profile's shape, which the derivation refuses):

```sh
SANDBOX_PROVIDER=docker \
SANDBOX_DOCKER_SECCOMP=/etc/plimsoll/seccomp.json \
SANDBOX_DOCKER_SECCOMP_SDK=derived \
plimsolld
```

The rules, in the order they are applied (`dockerSeccomp.seccompFor` in
`sandbox/docker_seccomp.go`):

- Under gVisor (`runsc`) no host profile is applied to any run, and the run's record says
  `seccomp:skipped:runsc` rather than naming a profile that was not in force.
- A run whose grant does not set `sdk_env` (a plain grant, or none) gets
  `SANDBOX_DOCKER_SECCOMP`, always. It also gets no forwarder and no loopback address.
- A run whose grant sets `sdk_env` gets `SANDBOX_DOCKER_SECCOMP_SDK` when it is set. With
  docker's built-in profile or `unconfined` as the default (both already allow these
  sockets) it gets that default. With a profile file as the default and no variant named,
  it is **refused before anything starts**, marked as a run in which nothing ran, with
  reason `environment`: an operator's own profile is never replaced or widened on
  plimsoll's initiative.
- `SANDBOX_DOCKER_SECCOMP_SDK` needs `SANDBOX_DOCKER_SECCOMP` to be a file, and must be a
  file itself; <dfn>*Preflight*</dfn>, the check the docker backend makes of its own
  configuration before it serves anything, refuses the other combinations. A variant file of
  the operator's own must keep what the derived variant guarantees, or Preflight refuses it: deny by
  default, `socket` allowed only where a rule compares its address family, `socketcall`
  (the 32-bit entry point that hides `socket`'s arguments from a filter) not allowed at all,
  and no architecture listed under which that comparison would be written for `socketcall`
  without it ([Architectures](#architectures)).
  A rule is read under both spellings docker accepts, `names` and the older `name`, and one that
  sets both is refused, as docker refuses it.
  <dfn>*Hardened mode*</dfn>,
  the daemon setting that refuses to serve unless every production property is in force
  ([hardened-mode.md](hardened-mode.md)), forbids `unconfined` for either.

The choice is made for each run as it starts, from its grant, with nothing shared between
runs: two runs at once apply different profiles (`TestDockerSeccompProfileIsSelectedPerRun`). A grant with
`sdk_env` in a session (one sandbox kept for many calls) is refused as unsupported before
anything runs: a session's container applies one profile for its life,
and a later call could not change the profile of processes already running.

### What Describe and the run record say

Preflight reads each configured profile, computes the SHA-256 of its bytes and writes a copy
named by that hash into plimsoll's private directory; runs apply the copy, so what docker
enforced is exactly what the hash names, whatever happens to the operator's file afterwards.
`Describe` states the <dfn>*provider*</dfn>'s (the backend that runs the code) `policy` as
`seccomp:sha256:<hash of the default>`,
followed by ` sdk_env:seccomp:sha256:<hash of the variant>` when one is configured;
`seccomp:docker-default`, `seccomp:unconfined` and `seccomp:skipped:runsc` name the other
cases. Then comes the guest guard every command started behind,
` guest-guard:sha256:<hash of the guest guard program>`, under `runc` and gVisor alike (under gVisor, for
instance, `seccomp:skipped:runsc guest-guard:sha256:...`). Each run's record names the one profile
that run applied, then the guest guard, in its `policy` field ([run-records.md](run-records.md)), so a
record of an `sdk_env` run is told apart from any other by its hash, and every record says
which guest guard program stood in front of its code.

## The guest guard: a second filter in front of every program

The profile above is applied by docker, and only under `runc`. The guest guard is
a second seccomp filter, plimsoll's own, that stands in front of every program the docker
provider starts in a container, under `runc` and under gVisor alike: a small program carried
inside plimsolld, written at startup into plimsolld's private folder (named by the SHA-256 of
its bytes) and mounted read-only into each container, so an operator's own image needs nothing
added for it. Every command plimsoll starts in a container, the code's and plimsoll's own
alike, starts with it: the guest guard puts its filter on itself, checks that the filter answers, and
only then becomes the real program. Every program started after it keeps the filter, and no
program can take a filter off or loosen it (a filter the code adds can only refuse more).

In a [session](sessions.md#docker) the container's first process is the guest guard too. A
container's first process (process 1) has a job of its own: a process whose parent has ended is
handed to it, and it must collect each one that ends, or the ended processes pile up against the
container's process limit. Docker's own program for that job (`--init`) was started by docker,
outside the guest guard, so plimsoll no longer uses it: a session's container starts the guest
guard in its process-1 mode (`/.plimsoll-guest-guard --pid1 -- ...`), which puts its filter on
itself, starts the session's main process as its child, and then stays as process 1, behind its
own filter, collecting every process that ends in the container. It passes no signal on to any
process. It ends the container when its child ends, or on a signal recorded as coming from
outside the container (the one `docker stop` sends is one), and ignores every other signal it
takes. That is not a promise that code of the session cannot end or stall its own session
through process 1; it could always end it by ending the main process. Code of the session can
cause a signal recorded as from outside (the I/O signal of a descriptor it makes process 1 the
owner of, or the signal that follows a CPU limit it sets on process 1), which ends the session;
under gVisor it can stop process 1, which then collects nothing, or end it; and while it keeps
sending process 1 a stop signal, an outside `docker stop` waits its whole timeout (ten seconds
by default) before docker kills the container. plimsoll's own close removes the container
(`docker rm -f`), which does not wait. A session refuses to open unless its process 1 has
exactly that command line, and every `docker run` plimsoll writes says `--init=false`, so a
docker daemon whose own setting starts docker's init by default cannot put it in front of the
guest guard; plimsoll refuses a `docker run` that asks for docker's `--init` in any other form.

When the guest guard cannot start a command (its filter will not go on, or does not answer as
it should, or the program it was to start is missing), it starts nothing, writes one line on
the command's standard error (`plimsoll guest guard: STEP: errno N`) and exits with that step's
code, 120 to 124. At a session's open, before any code of the caller's exists, that refusal is
marked not <dfn>*dispatched*</dfn> (not handed to the provider to run, so safe to retry). For a fresh run and for a call in a session it is not: the run's own
code could write the same line and exit with the same code, and under `runc` it (or, in a
session, code left running by an earlier call) can open that standard error again and try to
take off it the start marker plimsoll writes first, so the answer is an error
without the mark, saying that whether the code ran is not known
([run-results.md](run-results.md#did-anything-run-the-error-says-so)).

What it refuses, the same on both runtimes (the one table it is built from is
`sandbox/internal/guestguard/refused.json`):

| Request | Answer | Why |
|---|---|---|
| `unshare`; `clone` with any flag that makes a namespace (a private view of the system, in which the code would act as administrator); `setns` | "Operation not permitted" | making or entering a namespace is the first step to mounting a folder of the code's own |
| `mount`, `umount2`, `pivot_root`, `chroot`, and the newer mount calls (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, `open_tree_attr`, `fchroot`) | "Operation not permitted" | they change what the filesystem looks like |
| `ptrace`, `process_vm_writev` | "Operation not permitted" | under gVisor a tracing parent can rewrite a request after the filter has looked at it (gVisor issue 16093, [EXTERNAL · source repo ↗](https://github.com/google/gvisor/issues/16093)) |
| `clone3`, and every request numbered above the newest one the table was reviewed against | "Function not implemented" | `clone3` passes its flags in memory, which a filter cannot read; C libraries and language runtimes then fall back to `clone`, which is checked. A newer request has not been reviewed |
| any request through the 32-bit or x32 entry ([Architectures](#architectures)) | the process is ended | the table is written for the machine's own numbers |

At startup, plimsolld's check of its own sandboxes (the startup smoke test, which starts
throwaway containers under a run's exact lockdown) proves it from inside, in each configured image: it starts a check program of plimsoll's the
way a run starts the code, and requires a request answered in a way only the guest guard's filter
answers it, then a request for a user namespace, `clone3`, a tracing request and a mount
refused as above, then an ordinary request that works. In the project image, which sessions
run, it does so a second time in a session's shape, with the guest guard as process 1 in its
process-1 mode and the check as its child. Under gVisor it also requires the line of
`/proc/1/status` and of the check's own status that says whether a seccomp filter is on the
process (`Seccomp: 2`) in both shapes: gVisor applies no host profile, so a 2 there can only be
the guest guard's filter, and process 1's says the container's first process is behind it (with
docker's `--init` as a session's process 1 the line read 0). Under `runc` the line reads 2 with
or without the guest guard, since docker's profile is a filter too, so there it is not required
and says nothing. If any answer differs, plimsolld serves nothing and says what the answer it
got means. The check program stops at its first answer, so
nothing at startup makes a namespace, with the guest guard or without it.

Not every one of those answers tells the guest guard from no guest guard. Without it, a mount
is refused anyway, since the code holds no capabilities (the kernel's grants of administrator
powers), and under `runc` with this profile so are tracing and a user namespace (measured
2026-11-20, as the unprivileged user a run's code runs as). What proves the filter is on a program started as the code is
started is the first answer, which only the guest guard's filter gives, and under gVisor also the
namespace and tracing answers, which gVisor without the guest guard allows; the ordinary request
proves the filter does not refuse everything. That the filter refuses each request in the table
above is proved by the guest guard's own bytes instead: the guest guard program is named by the SHA-256 of
its bytes, the provider's startup check of its configuration compares the file every container
mounts with the copy inside plimsolld and refuses to serve on any difference, and plimsoll's own
tests hold the filter inside those bytes to the table (`TestFilterMatchesTable`,
`TestProgramCarriesTheFilter`).

**What a caller loses.** No debugger works in the sandbox: `gdb`, `strace`, `ltrace`, `rr`,
`py-spy` and Go's `dlv` all need `ptrace`. Under `runc` with this profile they failed already;
under docker's built-in profile and under gVisor they worked before the guest guard and now get
"Operation not permitted". The `unshare` command and every program that builds a sandbox of its
own from namespaces (bubblewrap, rootless Podman or Buildah, nsjail, a browser's own sandbox)
fail the same way; under `runc` this profile refused them already. Three answers changed that a
program could notice: under `runc` with this profile, request number -1 and requests numbered
above the guest guard's newest now answer "Function not implemented" where the profile answered
"Operation not permitted" (when two filters both answer with an error, the one installed last
wins, and the guest guard is installed after docker's); under gVisor, `clone3` now answers "Function
not implemented" where it answered "Invalid argument"; and tracing, as above.

**What it does not cover.**

- Runs whose grant sets `sdk_env`, at startup. The startup check runs under the default profile
  only, never under the variant ([the second profile](#the-second-profile-runs-whose-grant-sets-sdk_env)).
  Under gVisor no host profile applies, and under `runc` the variant plimsoll derives changes only
  sockets; but an operator's own variant that ended a process for a request the guest guard makes,
  instead of refusing it, would be found at the first such run, which fails, not at startup.
- A machine type with no tested build of the guest guard. Only x86-64 has one; on another, the
  provider refuses to start rather than run code without the guest guard. The guest guard is
  built for plimsolld's own machine, so the provider's startup check of its configuration also
  refuses to serve when the docker daemon, `DOCKER_DEFAULT_PLATFORM` when it is set, or any
  configured image is for another platform than Linux on that machine (an arm64 image run under
  emulation on an x86-64 host, for one), and its error names both platforms.
- Code that puts a program in memory (`memfd_create`, an in-memory file) and starts it from
  there. No filter of this kind stops that, under either runtime ([limitations](limitations.md)).
- The other providers. <dfn>*E2B*</dfn> (a hosted service that runs each sandbox in a small virtual machine) and Docker Cloud (and any provider whose wall is a virtual machine)
  start each command through the service's own process interface and state no no-execute mark,
  so the guest guard is not applied there; the Kubernetes, WSL containers and <dfn>*OpenShell*</dfn> (NVIDIA's agent sandbox runtime) providers do
  not start their commands behind it yet. Each provider's `guest-guard` line in
  [isolation-tiers.md](isolation-tiers.md) says which.

The guest guard is a second layer in front of the code, not the sandbox's wall: the wall is the
container under `runc`, or gVisor's kernel. Every run's record names the guest guard by the SHA-256
of its program, beside the profile ([what Describe and each run's record say](#what-describe-and-the-run-record-say)),
and [hardened mode](hardened-mode.md) refuses to serve docker unless the startup test proved it.

## Architectures

A program on an x86-64 machine can ask the kernel for a system call through three
*entries*, the doors into the kernel: the native one; the 32-bit one (the
`int 0x80` instruction with the numbers of 32-bit x86, kept so 32-bit programs run); and
*x32*, a rarely used variant with 64-bit registers and 32-bit pointers. On an
aarch64 machine a 32-bit ARM program has an entry of its own. A seccomp filter says which
entries it covers, by architecture, and a call through an entry it does not name never
reaches its rules: the kernel stops it, and docker's runtime kills the thread that made it
with `SIGSYS`.

The profile's `archMap` names `x86_64` and `aarch64` with no sub-architectures, so on either
machine every call through any other entry is killed whole, whatever the call and its
arguments. Nothing plimsoll runs in a sandbox uses those entries: none of the five images the
docker provider runs (`node:22-alpine` and the four built from `docker/`) holds a 32-bit
program, and each image's startup smoke test passes under the profile and its derived variant
(measured 2026-11-19). The `*_time64`, `*64` and `*32` names in the allowlist are the 32-bit
forms of calls; on an x86-64 or aarch64 machine they name nothing.

**Until 2026-11-19 the socket rule did not hold on an x86-64 machine whose kernel has the
32-bit entry** (Linux built with `CONFIG_IA32_EMULATION` and not booted with
`ia32_emulation=false`; `grep IA32_EMULATION /boot/config-$(uname -r)` shows the first). Every release up to
and including v0.27.2 listed the 32-bit x86 and x32 sub-architectures under `x86_64`, and 32-bit
ARM under `aarch64`. The 32-bit x86 entry has `socketcall`, one call that performs `socket`,
`connect`, `setsockopt` and every other socket call, with the real arguments in memory, and
`ipc`, the same for SysV IPC. libseccomp, the library docker's runtime builds the filter with,
writes an allow rule on one of those calls a second time for that entry, for the multiplexer:
the comparison on the first argument becomes the multiplexer's call number, and the others are
applied to the multiplexer's own arguments, a pointer among them
([EXTERNAL · source repo ↗](https://github.com/seccomp/libseccomp/blob/v2.5.5/src/syscalls.c),
`abi_rule_add`; its manual page,
[EXTERNAL · official docs ↗](https://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html),
says rules added this way may be rewritten "due to architecture specifics (e.g. internal
rewriting of multiplexed syscalls, like socket and ipc functions on x86)"). So the rule
"`socket` only for `AF_UNIX`" became, for the 32-bit entry, "`socketcall` to make a socket, any
family". Measured from inside a sandbox on 2026-11-19 (docker 29.1.3 with <dfn>*runc*</dfn> 1.3.4, docker's
default runtime, which shares the machine's kernel; libseccomp 2.5.5;
kernel 6.18): a 32-bit `socketcall` made vsock, `AF_ALG`, netlink and IPv4 sockets, while the
32-bit `socket` call itself was refused. The profile's other argument rules (on `clone`,
`personality`, `mknod` and `mknodat`) held under every entry, since those calls are not
multiplexed, and SysV IPC stayed denied, since the profile allows none of it. Under gVisor
(`SANDBOX_DOCKER_RUNTIME=runsc`) no host profile is applied and gVisor's own kernel answers
every 32-bit and x32 call with `ENOSYS`, so runs under gVisor were not affected.

**Preflight refuses a profile whose rules an entry would void.** A profile file, the default
or the variant, that names an architecture whose entry multiplexes socket or SysV IPC calls
(32-bit x86 above all, and the POWER, IBM Z, 32-bit MIPS, SuperH and m68k ones) beside an allow
rule that compares an argument of one of those calls is refused before anything runs, with the
architecture named. A copy of the profile made from an earlier release is such a file.

What this does not cover:

- **Docker's built-in profile** (`SANDBOX_DOCKER_SECCOMP` unset) names the 32-bit
  sub-architectures and allows `socketcall` outright, so its own socket family rules do not
  hold through the 32-bit entry either: under docker 29.1.3 a native vsock socket is refused
  and a 32-bit `socketcall` for one succeeds, and its SysV IPC calls are reachable both ways
  (measured 2026-11-19). plimsoll cannot read docker's built-in profile to refuse it; set this
  profile when the socket rule matters.
- **A machine whose own architecture multiplexes** (32-bit x86, POWER, IBM Z): docker adds no
  architecture for a machine the `archMap` does not name, so the filter covers that machine's
  own entry, which has `socketcall`, and the socket rule does not hold there. plimsoll is built
  and measured for x86-64 and aarch64 machines.
- **aarch64 was not measured.** The 32-bit ARM entry of a 64-bit ARM kernel has no
  `socketcall` or `ipc` (Linux's table of its calls, `arch/arm64/tools/syscall_32.tbl`, lists
  neither; 32-bit ARM has them only in its old interface, which a 64-bit kernel does not
  offer), so the rule held there before as well, by reading rather than measurement. The
  profile names no 32-bit ARM now either, and the docker suite's probe is x86-64 machine code,
  so it skips on an aarch64 machine.

## How it was audited

Empirically, against the real workload on a live daemon:

- The full docker sandbox suite (`go test ./sandbox -run 'Docker|RunProject'`) is run
  with `SANDBOX_DOCKER_SECCOMP` pointed at the profile. Snippet runs, multi-file
  TypeScript compilation (`tsc`), `tsx` execution, artifact capture (binary file
  I/O), a project stopping at its first failing step, and the unix-socket broker all
  pass under it.
- `TestShippedSeccompProfileIsSaneAndTight` (no daemon needed) asserts the policy is
  deny-by-default and keeps the essential syscalls, and reads the denial table above
  from this file: every syscall named there must be withheld, `clone` must be allowed
  only under a mask covering every `CLONE_NEW*` flag it can carry, and sockets only for
  `AF_UNIX`. A row the test cannot interpret fails it, so the table and the test cannot
  drift apart.
- Rules checked against the file alone hold only for calls through the entries the
  profile names, which is how the 32-bit hole passed these checks. So
  `TestShippedSeccompProfilesListOnlyNativeArchitectures` holds the default and the derived
  variant to x86-64 and aarch64 with no sub-architecture, and
  `TestDockerSeccompKillsEveryNonNativeEntry`, in the docker suite, makes the calls from inside a
  sandbox: from a Python program (`sandbox/testdata/seccomp_entries.py`), a 32-bit
  `socketcall` for five socket families, the 32-bit `socket`, `ipc`, `shmget`, `clone`,
  `personality`, `mknod` and `mknodat`, and their x32 forms, under the default and the
  variant, each of which must be killed. It first runs the same calls under the profile
  with the old sub-architectures restored, to learn whether the kernel has the 32-bit entry
  (one without it faults before any filter runs, and the test says so rather than failing)
  and to prove the probe sees the hole.

To re-audit after changing node or toolchain versions, re-run:

```sh
SANDBOX_DOCKER_SECCOMP="$(pwd)/docker/seccomp.json" \
  go test ./sandbox -run 'Docker|RunProject' -count=1
```

A new syscall requirement shows up as an `EPERM`-driven failure; add the specific
syscall to the allowlist (never widen `defaultAction`).
