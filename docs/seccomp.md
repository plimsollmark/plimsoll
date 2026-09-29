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

The containers already run with `--cap-drop ALL --security-opt no-new-privileges`.
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
  that never route over a network.
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

- **`utime`, `utimes` and `futimesat` are allowed.** They are older forms of `utimensat`,
  which was already allowed: the kernel implements all four through the same code in
  `fs/utimes.c`, with the same ownership and write-permission checks, so they add no
  capability. Older C libraries still issue them. Before 2026-09-28 the profile withheld
  them by omission, and a program built on Ubuntu 20.04's C library failed with `EPERM`
  while setting the modification time of files it had just written to `/work`.
  `TestDockerLegacyTimestampSyscalls` makes each call from inside a run.

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
