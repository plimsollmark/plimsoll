# gVisor (runsc) for the self-host sandbox

The `docker` <dfn>*provider*</dfn> (the backend that runs code in docker containers)
hands each container to an <dfn>*OCI runtime*</dfn>, the program that builds the walls
around it. Its default runtime is <dfn>*runc*</dfn>, which shares the host kernel: the
code in every container talks to the same kernel as the host. runc plus
<dfn>*namespaces*</dfn> (the kernel feature that gives each container its own view of
files, processes and network) is good hardening but is **not** a boundary against
deliberately hostile code: a kernel exploit <dfn>*escapes*</dfn> it, getting out of the
container.

For untrusted code written by AI agents on a self-hosted machine, run the container
under <dfn>*gVisor*</dfn>, an application kernel: a stand-in kernel that runs in user
space as an ordinary program. It intercepts <dfn>*syscalls*</dfn>, the requests a
program makes to the kernel, so the <dfn>*guest*</dfn> (the code in the container)
never talks to the host kernel directly. Docker starts a container under gVisor
through gVisor's runtime, <dfn>*runsc*</dfn>. (In production, the `e2b` provider gives
an even stronger hardware boundary. It runs each sandbox on <dfn>*E2B*</dfn>, a hosted
service, as a <dfn>*microVM*</dfn>, a small virtual machine made for one run, on
<dfn>*Firecracker*</dfn>, AWS's open-source virtual machine monitor.)

## Install

```sh
sudo ./docker/install-gvisor.sh
```

This downloads the **complete <dfn>*pinned*</dfn> bundle** recorded in
[gvisor.versions](../docker/gvisor.versions): one exact gVisor release, fixed by its
checksums. The bundle holds `runsc`, the containerd shim (the adapter containerd uses
to start runsc), and the helper programs in `gvisor-bin/`, which upstream calls
sidecars. For both x86_64 and aarch64, the downloaded bundle must match the SHA512
checksum committed in that file before anything is unpacked or run. The installer
then checks that every listed executable is present, that runsc reports the pinned
version, and that runsc's own check finds every sidecar. It installs the files together in
`/usr/local/bin`, registers runsc in `/etc/docker/daemon.json`, and restarts Docker.
Installing and restarting require root.

To check the current host's bundle without root or system changes:

```sh
./docker/install-gvisor.sh --verify-only
```

For an offline check or installation, add `--archive /path/to/gvisor-ARCH.tar.zstd`.
The same committed checksum is required for local archives. Verification uses
a throwaway Docker configuration under the checkout's ignored `tmp/` and deletes
it afterwards. `runsc install` is explicitly forbidden from downloading sidecars.
Verification does not launch a sandbox or prove isolation.

The bundle needs `curl` for downloads and `tar`, `zstd`, and `sha512sum` for
verification. Unsupported architectures fail before downloading anything.
There is no environment variable to pick a different release: an upgrade edits
`docker/gvisor.versions`, so the version, the checksums and the list of executables
are reviewed together.

### Maintaining the pin

The maintainer reviews the upstream release list before each plimsoll release
and immediately when a relevant security advisory arrives. That review covers
the gVisor bundle separately from updates to the GitHub Actions the CI uses.

1. Read the target release notes and its `SHA512SUMS` in the
   [EXTERNAL · source repo releases ↗](https://github.com/google/gvisor/releases).
2. Update the release, both architecture hashes, and executable list in
   `docker/gvisor.versions`. Inspect both archives; do not merely copy a version.
3. Run `--verify-only` on a native host for each supported architecture. Review
   the pinned release's install flags: this release uses
   `--download-sidecars=NEVER --require-sidecars=ALWAYS`, which upstream describes
   as transitional flags, and registers the runtime with `--host-uds=open` (see
   below); confirm the flag and its values still exist in `runsc flags`.
4. Run `make audit`, then install on a test host and run
   `SANDBOX_DOCKER_RUNTIME=runsc make audit DOCKER=1`. Record any architecture or
   runtime path that was not exercised before making a support claim.

Upstream's move to bundles that ship the sidecars, and its removal of the old
automatic downloads, are documented in [EXTERNAL · official installation docs ↗](https://gvisor.dev/docs/user_guide/install/).
The old pinned binary does not expire when the transitional downloader is removed.

## Host Unix sockets: why runsc is registered with `--host-uds=open`

When a run has a <dfn>*grant*</dfn>, permission to call listed routes of one of your
APIs, its code makes those calls through the <dfn>*broker*</dfn>, the part of plimsoll
outside the sandbox that makes the real call. The docker provider connects the two
over one Unix socket, created on the host per run and bind-mounted into the container
at `/run/host-api.sock`. Whether a guest may connect to a host socket is decided by
the runtime: runsc's `--host-uds` flag takes `none|open|create|all` and defaults to
`none`, under which the connect fails with `ECONNREFUSED` and every grant run fails
while the runtime otherwise works. The installer therefore registers the runtime with `--host-uds=open`, the
smallest value that allows the connect: `open` lets the sandbox use host sockets
that are mounted into it and does not let it create host sockets (`create`, `all`).
The only socket ever mounted is the per-run broker socket, so `open` exposes exactly
the channel the grant is meant to use.

This was found by the first hosted `gvisor` workflow run (2026-09-14): the banner
read (the startup check that logs gVisor's identity line from inside a container)
succeeded, and the three tests that make calls through a grant failed with
`ECONNREFUSED`. Since then the provider's startup `SmokeTest` mounts a throwaway host
socket into the first test container it starts, exactly as a run would, and requires
the guest to reach it. On a runtime that cannot carry grant calls, the provider
refuses to serve, naming the fix, instead of reporting ready.

Verify:

```sh
docker run --rm --runtime=runsc node:22-alpine node -e 'console.log("gvisor", 6*7)'
```

gVisor's platform is the mechanism it uses to intercept the guest's system calls.
The default platform is `systrap`, which does not require <dfn>*nested
virtualization*</dfn> (running a virtual machine inside another, which not every cloud
server allows). The KVM platform must be selected explicitly and requires `/dev/kvm`;
upstream no longer supports the old `ptrace` platform. See
[EXTERNAL · official platform docs ↗](https://gvisor.dev/docs/user_guide/platforms/).

## Use it

The runtime is selected with an environment variable (see `sandbox/factory.go`):

```sh
SANDBOX_PROVIDER=docker SANDBOX_DOCKER_RUNTIME=runsc <your binary>
```

or directly on the struct: `DockerSandbox{Runtime: "runsc", ...}`. An empty value
means docker's default runtime, runc.

Run the docker suite under gVisor:

```sh
SANDBOX_DOCKER_RUNTIME=runsc go test ./sandbox -run 'Docker|RunProject' -count=1
```

## Notes

- **The process limit covers the whole sandbox.** runsc applies `--pids-limit`
  (`SANDBOX_PIDS`) to the sandbox's <dfn>*cgroup*</dfn> on the host (the kernel
  feature that caps how many processes, and how much memory and CPU, a group of
  processes may use). That cgroup also holds gVisor's own tasks (about 30 when idle,
  measured with release 20260907.0) and about two host tasks per guest process. A
  guest therefore gets well under half the configured number: at `SANDBOX_PIDS=256` a
  guest held 112 single-threaded processes beside the two `node` processes of the
  runner and its step before a spawn failed (measured 2026-09-29, same release), where
  runc allowed 192 and more. `TestDockerGuestGetsItsProcessBudget` holds each runtime
  to a minimum below those numbers, so a release that raises the cost fails a test. At
  the limit a spawn fails with `ENOMEM`, not the `EAGAIN` runc gives, and in two of four
  measured runs at a limit of 256 the run instead ended with exit status 2 and no
  output. Size `SANDBOX_PIDS` with that overhead in mind. Inside the guest, `pids.max`
  is a file gVisor emulates and reads `max`, so the startup smoke test proves the limit
  on the host cgroup.
- gVisor adds work to every system call it intercepts, so its cost grows with how many
  a run makes. Measured through the docker provider on one machine (24 cores, Linux 6.6
  under WSL2, Docker 29.1.3, gVisor release-20260907.0, median of 20 runs, 2026-09-29):
  a one-line snippet took 453 ms under runsc against 399 ms under runc (14% more), and a
  one-file TypeScript project (compile with `tsc`, then run with `node`) took 4.1 s
  against 1.95 s (2.1 times as long). plimsoll's position is that the isolation is worth
  that cost for untrusted code.
- A successful bundle verification establishes that the files are the pinned release
  and that none is missing. The Docker tests after installation establish how the
  runtime behaves in the cases they exercise; neither check is a third-party security
  audit.
