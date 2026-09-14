#!/usr/bin/env bash
# Install the complete gVisor release recorded in gvisor.versions.
# --verify-only checks an extracted bundle without touching system paths.
# --archive FILE permits the same verification and installation fully offline.
set -euo pipefail

fail() { echo "gvisor: $*" >&2; exit 1; }
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_ONLY=0
ARCHIVE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify-only) VERIFY_ONLY=1; shift ;;
    --archive)
      [[ $# -ge 2 && -n "$2" ]] || fail "--archive requires a file"
      ARCHIVE="$2"; shift 2 ;;
    *) fail "usage: $0 [--verify-only] [--archive FILE]" ;;
  esac
done
if [[ "$VERIFY_ONLY" -eq 0 && "$EUID" -ne 0 ]]; then
  fail "installation needs root; use --verify-only to validate without installing"
fi

# Data, never sourced shell code. A version bump includes the whole executable set.
MANIFEST="$SCRIPT_DIR/gvisor.versions"
RELEASE="$(sed -n 's/^release=//p' "$MANIFEST")"
ARCH="$(uname -m)"
case "$ARCH" in x86_64|aarch64) ;; *) fail "unsupported architecture: $ARCH" ;; esac
EXPECTED="$(sed -n "s/^sha512_${ARCH}=//p" "$MANIFEST")"
[[ "$RELEASE" =~ ^[0-9]{8}\.[0-9]+$ ]] || fail "invalid pinned release"
[[ "$EXPECTED" =~ ^[0-9a-f]{128}$ ]] || fail "missing or invalid pinned SHA512 for $ARCH"
read -r -a EXECUTABLES <<< "$(sed -n 's/^executables=//p' "$MANIFEST")"
[[ ${#EXECUTABLES[@]} -ge 3 ]] || fail "missing complete executable manifest"
for entry in "${EXECUTABLES[@]}"; do
  [[ "$entry" =~ ^(gvisor-bin/)?[A-Za-z0-9_-]+$ ]] || fail "invalid executable path: $entry"
done

mkdir -p "$SCRIPT_DIR/../tmp"
# Under sudo the checkout belongs to the invoking user. A tmp/ created by root here
# would refuse every later unprivileged write into it (make docker-suite keeps its
# log and status there), which is how the first hosted runsc run went red after its
# tests had passed. Hand the directory back to the user who ran sudo.
if [[ "$EUID" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
  chown "$SUDO_UID:$SUDO_GID" "$SCRIPT_DIR/../tmp"
fi
STAGE="$(mktemp -d "$SCRIPT_DIR/../tmp/gvisor-install.XXXXXX")"
trap 'rm -rf -- "$STAGE"' EXIT
BUNDLE="$STAGE/gvisor.tar.zstd"
if [[ -n "$ARCHIVE" ]]; then
  cp -- "$ARCHIVE" "$BUNDLE"
else
  URL="https://github.com/google/gvisor/releases/download/release-${RELEASE}/gvisor-${ARCH}.tar.zstd"
  curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 300 "$URL" -o "$BUNDLE"
fi
# The committed digest covers runsc, the shim, and every sidecar together.
printf '%s  %s\n' "$EXPECTED" "$BUNDLE" | sha512sum -c -
mkdir "$STAGE/bin"
tar --zstd -xf "$BUNDLE" -C "$STAGE/bin"
for entry in "${EXECUTABLES[@]}"; do
  [[ -f "$STAGE/bin/$entry" && ! -L "$STAGE/bin/$entry" && -x "$STAGE/bin/$entry" ]] || \
    fail "bundle lacks executable $entry"
done
VERSION="$("$STAGE/bin/runsc" --version)"
[[ "${VERSION%%$'\n'*}" == "runsc version release-${RELEASE}" ]] || fail "bundle version differs from manifest"

# Exercise runsc's own sidecar completeness check against a throwaway config.
# These flags belong to the pinned release; review them when upgrading.
#
# Everything after "--" is a runtime flag written into daemon.json. --host-uds=open
# lets a sandbox connect to host Unix-domain sockets that are mounted into it and
# nothing more (no creating host sockets: that would be "create" or "all"). The
# docker provider brokers every host-API grant over exactly one such socket, mounted
# per run, and runsc's default of "none" refuses it with ECONNREFUSED. The provider's
# startup smoke test proves the socket is reachable and refuses to serve otherwise.
RUNTIME_FLAGS=(--host-uds=open)
"$STAGE/bin/runsc" install --download-sidecars=NEVER --require-sidecars=ALWAYS \
  --config_file="$STAGE/daemon.json" -- "${RUNTIME_FLAGS[@]}"
echo "Verified gVisor $RELEASE ($ARCH): complete bundle, committed SHA512, sidecars available, runtime flags ${RUNTIME_FLAGS[*]}."
if [[ "$VERIFY_ONLY" -eq 1 ]]; then
  exit 0
fi

install -d -m 0755 /usr/local/bin/gvisor-bin
for entry in "${EXECUTABLES[@]}"; do
  install -m 0755 "$STAGE/bin/$entry" "/usr/local/bin/$entry"
done
/usr/local/bin/runsc install --download-sidecars=NEVER --require-sidecars=ALWAYS -- "${RUNTIME_FLAGS[@]}"
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart docker
else
  echo "Restart the Docker daemon manually to load the runsc runtime."
fi
echo "Installed gVisor $RELEASE and registered the runsc Docker runtime."
