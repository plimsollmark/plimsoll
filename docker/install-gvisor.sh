#!/usr/bin/env bash
# Install gVisor (runsc) and register it as a docker runtime, so the self-host
# sandbox can run with SANDBOX_DOCKER_RUNTIME=runsc — a real user-space-kernel
# boundary around hostile code. Plain runc shares the host kernel and is NOT a
# hostile-code boundary; gVisor (or the E2B microVM provider) is.
#
# The release is PINNED (supply chain: runsc is the hostile-code boundary, so
# "whatever is latest today" is not an acceptable provenance). For x86_64 the
# expected sha512 is embedded below and the download must match it; for other
# architectures the bucket's .sha512 is verified and the pinned release still
# guarantees a known version, not a moving target. To upgrade: change
# GVISOR_RELEASE, refresh GVISOR_SHA512_X86_64 from
#   https://storage.googleapis.com/gvisor/releases/release/<release>/x86_64/runsc.sha512
# and re-run.
#
# Requires root: it writes /usr/local/bin/runsc and /etc/docker/daemon.json and
# restarts the docker daemon.
#
#   sudo ./docker/install-gvisor.sh
#
# Verify afterwards:
#   docker run --rm --runtime=runsc node:22-alpine node -e 'console.log("gvisor", 6*7)'
#   SANDBOX_DOCKER_RUNTIME=runsc go test ./sandbox -run 'Docker|RunProject' -count=1
set -euo pipefail

GVISOR_RELEASE="${GVISOR_RELEASE:-20260714.0}"
GVISOR_SHA512_X86_64="75c092fe87d84078f06ac40937cb5207fb5a1a92511b38b4790c915801555daadc59fef33de8db4dd92e1892a6de390c8a2e390a7a3bd0e2d3731d9ed6a3a6e8"

if [[ "${EUID}" -ne 0 ]]; then
  echo "must run as root (sudo $0)" >&2
  exit 1
fi

ARCH="$(uname -m)"
URL="https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/${ARCH}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "Downloading runsc ${GVISOR_RELEASE} (${ARCH}) …"
curl -fsSL "${URL}/runsc" -o "${TMP}/runsc"
curl -fsSL "${URL}/runsc.sha512" -o "${TMP}/runsc.sha512"
( cd "${TMP}" && sha512sum -c runsc.sha512 )

# Provenance, not just transport integrity: for x86_64 the binary must ALSO
# match the checksum recorded in this repository, so a compromised bucket
# cannot serve a different "verified" artifact under the pinned name.
if [[ "${ARCH}" == "x86_64" ]]; then
  echo "${GVISOR_SHA512_X86_64}  ${TMP}/runsc" | sha512sum -c -
else
  echo "NOTE: no repo-pinned checksum for ${ARCH}; verified against the bucket's .sha512 only." >&2
fi

install -m 0755 "${TMP}/runsc" /usr/local/bin/runsc
echo "Installed: $(/usr/local/bin/runsc --version | head -1)"

# Registers the "runsc" runtime in /etc/docker/daemon.json (idempotent).
/usr/local/bin/runsc install

# Reload the daemon so the new runtime is picked up.
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart docker
else
  echo "Restart the docker daemon manually to load the runsc runtime."
fi

echo "Done. runsc ${GVISOR_RELEASE} is registered as a docker runtime."
