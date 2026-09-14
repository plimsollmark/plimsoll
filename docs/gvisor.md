# gVisor (runsc) for the self-host sandbox

The `docker` provider's default OCI runtime is **runc**, which shares the host
kernel. runc + namespaces is good hardening but is **not** a boundary against
deliberately hostile code — a kernel exploit escapes it. For untrusted,
agent-authored code on a self-hosted box, run the container under **gVisor**
(`runsc`): an application kernel in user space that intercepts syscalls, so the
guest never talks to the host kernel directly. (In production, the E2B
Firecracker microVM provider gives an even stronger hardware boundary.)

## Install

```sh
sudo ./docker/install-gvisor.sh
```

This downloads the **complete pinned bundle** recorded in
[gvisor.versions](../docker/gvisor.versions): `runsc`, the containerd shim, and
the `gvisor-bin/` sidecars. Both x86_64 and aarch64 bundles must match a SHA512
committed in that manifest before extraction or execution. The installer checks
the executable set, version, and runtime sidecar check, installs the files together
in `/usr/local/bin`, registers runsc in `/etc/docker/daemon.json`, and restarts
Docker. Installing and restarting require root.

To check the current host's bundle without root or system changes:

```sh
./docker/install-gvisor.sh --verify-only
```

For an offline check or installation, add `--archive /path/to/gvisor-ARCH.tar.zstd`.
The same committed checksum is mandatory for local archives. Verification uses
a throwaway Docker configuration under the checkout's ignored `tmp/` and deletes
it afterwards. `runsc install` is explicitly forbidden from downloading sidecars.
Verification does not launch a sandbox or prove isolation.

The bundle needs `curl` for downloads and `tar`, `zstd`, and `sha512sum` for
verification. Unsupported architectures fail before downloading anything.
There is no environment override for the release: upgrades change the manifest
so the version, hashes, and executable set are reviewed together.

### Maintaining the pin

The maintainer reviews the upstream release list before each plimsoll release
and immediately when a relevant security advisory arrives. The pin review covers
the runtime bundle separately from GitHub Actions dependency updates.

1. Read the target release notes and its `SHA512SUMS` in the
   [EXTERNAL · source repo releases ↗](https://github.com/google/gvisor/releases).
2. Update the release, both architecture hashes, and executable list in
   `docker/gvisor.versions`. Inspect both archives; do not merely copy a version.
3. Run `--verify-only` on a native host for each supported architecture. Review
   the pinned release's install flags: this release uses
   `--download-sidecars=NEVER --require-sidecars=ALWAYS`, which upstream describes
   as transitional flags.
4. Run `make audit`, then install on a test host and run
   `SANDBOX_DOCKER_RUNTIME=runsc make audit DOCKER=1`. Record any architecture or
   runtime path that was not exercised before making a support claim.

Upstream's move to sidecar bundles and the removal of legacy auto-downloads are
documented in [EXTERNAL · official installation docs ↗](https://gvisor.dev/docs/user_guide/install/).
The old pinned binary does not expire when the transitional downloader is removed.

Verify:

```sh
docker run --rm --runtime=runsc node:22-alpine node -e 'console.log("gvisor", 6*7)'
```

The default platform is `systrap`, which does not require nested virtualization.
KVM is selected explicitly and requires `/dev/kvm`; upstream no longer supports
the old `ptrace` platform. See
[EXTERNAL · official platform docs ↗](https://gvisor.dev/docs/user_guide/platforms/).

## Use it

The runtime is selected via env (see `sandbox/factory.go`):

```sh
SANDBOX_PROVIDER=docker SANDBOX_DOCKER_RUNTIME=runsc <your binary>
```

or directly on the struct: `DockerSandbox{Runtime: "runsc", ...}`. Empty =
docker's default (runc).

Run the docker suite under gVisor:

```sh
SANDBOX_DOCKER_RUNTIME=runsc go test ./sandbox -run 'Docker|RunProject' -count=1
```

## Notes

- gVisor adds some syscall-interception overhead; for short snippet runs it is
  negligible, and the isolation is worth it for untrusted code.
- A successful bundle verification establishes artifact identity and completeness.
  The Docker tests after installation establish exercised runtime behavior;
  neither check is a third-party security audit.
