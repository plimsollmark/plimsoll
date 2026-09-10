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

This downloads a **pinned** `runsc` release (see `GVISOR_RELEASE` in the
script; on x86_64 the binary must also match the sha512 recorded in the
script, not just the bucket's own checksum file), installs it to
`/usr/local/bin`, registers it as a docker runtime in `/etc/docker/daemon.json`,
and restarts the daemon. (All three steps need root.) To upgrade, bump
`GVISOR_RELEASE` and the recorded sha512 together.

Verify:

```sh
docker run --rm --runtime=runsc node:22-alpine node -e 'console.log("gvisor", 6*7)'
```

If `runsc` runs unprivileged user namespaces are not available (older kernels),
gVisor falls back to the `ptrace` platform automatically; on hosts with
`/dev/kvm` it can use the faster `kvm` platform.

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
- This was smoke-tested rootless on a WSL2 kernel (ptrace platform) during
  bring-up; full docker-runtime integration requires the root install above.
