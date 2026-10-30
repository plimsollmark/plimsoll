# Audited seccomp profile for the docker sandbox

<dfn>*Seccomp*</dfn> is the Linux kernel feature that limits which
<dfn>*syscalls*</dfn> (requests to the kernel, such as opening a file or starting a
process) a process may make. `docker/seccomp.json` is a seccomp profile: a
**deny-by-default** allowlist of syscalls, built for the plimsoll workload, which is
the `node` runtime plus the TypeScript toolchain (`tsc`/`tsx`/`eslint`) and the child
processes the project runner spawns. It is opt-in: reference it with
`SANDBOX_DOCKER_SECCOMP=docker/seccomp.json` (an absolute path in production).
Leaving the variable empty keeps docker's built-in default profile.

```sh
SANDBOX_PROVIDER=docker \
SANDBOX_DOCKER_SECCOMP=/etc/plimsoll/seccomp.json \
plimsolld
```

The profile is skipped automatically under <dfn>*gVisor*</dfn>
(`SANDBOX_DOCKER_RUNTIME=runsc`), a stand-in kernel that runs as an ordinary program
and intercepts the container's syscalls itself. A host seccomp filter there is
redundant and can conflict.

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

Every syscall not on the allowlist fails with `EPERM` (`defaultAction:
SCMP_ACT_ERRNO`, `defaultErrnoRet: 1`).

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
  that never route over a network. The one kind of run that needs IPv4 sockets gets a
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
  default, `socket` allowed only where a rule compares its address family, and `socketcall`
  (the 32-bit entry point that hides `socket`'s arguments from a filter) not allowed at all.
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
cases. Each run's record names the one profile that run applied in its `policy` field
([run-records.md](run-records.md)), so a record of an `sdk_env` run is told apart from any
other by its hash.

## Architectures

The profile carries an `archMap` for `x86_64` (with the `x86`/`x32` sub-architectures)
and `aarch64` (with `arm`), so the 32-bit compatibility versions of syscalls resolve correctly. The
`*_time64`, `*64`, and `*32` syscall aliases are listed for musl/glibc on those
sub-architectures.

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

To re-audit after changing node or toolchain versions, re-run:

```sh
SANDBOX_DOCKER_SECCOMP="$(pwd)/docker/seccomp.json" \
  go test ./sandbox -run 'Docker|RunProject' -count=1
```

A new syscall requirement shows up as an `EPERM`-driven failure; add the specific
syscall to the allowlist (never widen `defaultAction`).
