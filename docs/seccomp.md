# Audited seccomp profile for the docker sandbox

`docker/seccomp.json` is a **deny-by-default** syscall allowlist purpose-built for
the plimsoll workload: the `node` runtime plus the TypeScript toolchain
(`tsc`/`tsx`/`eslint`) and the child processes the project runner spawns. It is
opt-in — reference it with `SANDBOX_DOCKER_SECCOMP=docker/seccomp.json` (an absolute
path in production). Leaving the var empty keeps docker's built-in default profile.

```sh
SANDBOX_PROVIDER=docker \
SANDBOX_DOCKER_SECCOMP=/etc/plimsoll/seccomp.json \
plimsolld
```

The profile is skipped automatically under gVisor (`SANDBOX_DOCKER_RUNTIME=runsc`),
which intercepts syscalls in its own user-space kernel — a host seccomp filter there
is redundant and can conflict.

## Why ship one over docker's built-in default

The containers already run with `--cap-drop ALL --security-opt no-new-privileges`,
which removes every **capability-gated** syscall (`mount`, `bpf`, most of
`ptrace`'s privileged modes, module loading, etc.). So the marginal value of a
custom profile is precisely the syscalls that are **not** capability-gated — a
same-uid attacker inside the container can still reach them under docker's default:

| Syscall(s) | Why denied |
|---|---|
| `ptrace`, `process_vm_readv`/`writev` | Read/inject into other same-uid processes — no capability required. |
| `io_uring_setup`/`enter`/`register` | Large, historically exploit-rich kernel surface; node does not need it (and disables it by default). |
| `userfaultfd` | Classic use-after-free exploitation primitive; unprivileged by default. |
| `perf_event_open` | Broad kernel surface, gated by a sysctl rather than a capability. |
| `keyctl`, `add_key`, `request_key` | Kernel keyring access, reachable unprivileged. |
| `unshare`, `setns`, `CLONE_NEW*` clone flags | Namespace creation — an escape/priv-esc lever. |
| `mount`, `umount2`, `pivot_root`, `chroot` | Filesystem-view manipulation. |
| `name_to_handle_at`, `open_by_handle_at` | Open files by handle, bypassing path checks. |
| `modify_ldt` | x86 LDT manipulation — an exploitation aid the workload never uses. |
| `kexec_load`, `init_module`, `finit_module`, `reboot`, `swapon` | Host-level operations with no place in a sandbox. |
| `clock_settime`, `settimeofday`, `adjtimex` | Host clock mutation. |
| SysV IPC (`shmget`/`semget`/`msgget`) | Unused cross-process IPC surface. |
| `socket(AF_ALG, ...)` | Linux kernel crypto socket surface; unnecessary for the workload and implicated in container privilege escalation. |

Everything not on the allowlist returns `EPERM` (`defaultAction:
SCMP_ACT_ERRNO`, `defaultErrnoRet: 1`).

## Notable allow-list decisions

- **`clone` is argument-filtered.** Threads and child processes are allowed, but the
  masked-equal check on arg 0 (mask `0x7e020000`) rejects any `clone` carrying a
  `CLONE_NEW*` namespace flag. `clone3` is forced to `ENOSYS` (errno 38) so libc
  falls back to the filtered `clone` path — you cannot argument-filter `clone3`'s
  struct argument, so denying it outright is the safe choice (musl and glibc both
  fall back cleanly).
- **`personality` is value-filtered** to `0` and the read-only `0xffffffff`, blocking
  `READ_IMPLIES_EXEC` and friends.
- **`socket` and `socketpair` are argument-filtered to `AF_UNIX`.** The host-API
  broker is reached over a bind-mounted Unix socket and libuv uses Unix
  socketpairs internally. Other families, notably `AF_ALG`, are denied; `--network
  none` alone does not remove non-routable kernel socket families.
- **`memfd_create`, `inotify_*`, `timerfd_*`, `signalfd*`** are allowed: node/libuv
  use them for normal operation.

## Architectures

The profile carries an `archMap` for `x86_64` (with the `x86`/`x32` sub-architectures)
and `aarch64` (with `arm`), so 32-bit-compat syscall variants resolve correctly. The
`*_time64`, `*64`, and `*32` syscall aliases are listed for musl/glibc on those
sub-architectures.

## How it was audited

Empirically, against the real workload on a live daemon:

- The full docker sandbox suite (`go test ./sandbox -run 'Docker|RunProject'`) is run
  with `SANDBOX_DOCKER_SECCOMP` pointed at the profile — snippet runs, multi-file
  TypeScript compilation (`tsc`), `tsx` execution, artifact capture (binary file
  I/O), the failure-chain path, and the unix-socket broker all pass under it.
- `TestShippedSeccompProfileIsSaneAndTight` (no daemon needed) asserts the policy is
  deny-by-default, keeps the essential syscalls, and withholds every syscall in the
  denial table above — so an edit cannot silently loosen it.

To re-audit after changing node or toolchain versions, re-run:

```sh
SANDBOX_DOCKER_SECCOMP="$(pwd)/docker/seccomp.json" \
  go test ./sandbox -run 'Docker|RunProject' -count=1
```

A new syscall requirement shows up as an `EPERM`-driven failure; add the specific
syscall to the allowlist (never widen `defaultAction`).
