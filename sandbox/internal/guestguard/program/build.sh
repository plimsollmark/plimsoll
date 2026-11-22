#!/usr/bin/env bash
# Builds the guest guard (guard.c, with the generated ../guest_filter.h) for x86-64 and aarch64,
# statically against musl, inside a container image pinned by digest, twice in two folders, and
# refuses unless the two builds give the same bytes. Then installs the machines in INSTALLED as
# guard_<goarch> and writes guard.sha256 (inputs and outputs), which the package's tests check.
#
#     build.sh ZIG_TARBALL
#
# ZIG_TARBALL is Zig 0.17.1 for the machine running docker, from
# https://ziglang.org/download/0.17.1/ (zig-x86_64-linux-0.17.1.tar.xz or
# zig-aarch64-linux-0.17.1.tar.xz), checked against the SHA-256 below. Zig's C compiler (clang)
# carries musl's sources and the Linux kernel headers for every machine it targets, so one pinned
# download builds both machines from either, and nothing is fetched while building. Run it where
# docker is local; it uses an empty client config of its own, so no host client setting (a
# proxies entry) reaches the build container.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 ZIG_TARBALL" >&2
  exit 2
fi

readonly tarball="$(realpath "$1")"
readonly script_dir="$(cd "$(dirname "$0")" && pwd)"
readonly pkg_dir="$(cd "$script_dir/.." && pwd)"
readonly repo_root="$(cd "$script_dir/../../../.." && pwd)"
# alpine:3.21, by the digest of its multi-machine index: only its shell, tar and xz are used.
readonly image="alpine@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d"
readonly zig_version="0.17.1"
# Machines installed: aarch64 is built and compared but not installed until it has run under
# the package's docker tests on an aarch64 host.
readonly installed="amd64"

case "$(uname -m)" in
  x86_64) expected_zig_sha="3581863e3cbcfd0fce0efc682ce7e9e93da96668a977791d356a26d2a7e9b17a" zig_host="x86_64" ;;
  aarch64 | arm64) expected_zig_sha="a1546d5646eb184437918d6635ca6b762a0e889eac09cef720ee7a1ed3fe7795" zig_host="aarch64" ;;
  *) echo "build.sh: no Zig pinned for $(uname -m)" >&2; exit 1 ;;
esac
actual="$(sha256sum "$tarball" | cut -d ' ' -f 1)"
if [[ "$actual" != "$expected_zig_sha" ]]; then
  echo "zig tarball checksum mismatch: got $actual, want $expected_zig_sha" >&2
  exit 1
fi

mkdir -p "$repo_root/tmp"
build_root="$(mktemp -d "$repo_root/tmp/guestguard-build.XXXXXX")"
readonly build_root
trap 'rm -rf -- "$build_root"' EXIT
mkdir "$build_root/docker-config"

# build DIR: one whole build in DIR, mounted at its own path, so two builds differ in every
# path the compiler sees.
build() {
  local dir="$1"
  mkdir -p "$dir/src" "$dir/out"
  cp "$script_dir/guard.c" "$pkg_dir/guest_filter.h" "$dir/src/"
  docker --config "$build_root/docker-config" run --rm --network none \
    --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp:rw,size=64m \
    -v "$tarball:/zig.tar.xz:ro" -v "$dir:$dir" -w "$dir" \
    --entrypoint /usr/bin/env "$image" -i PATH=/usr/bin:/bin DIR="$dir" \
    ZIGDIR="zig-$zig_host-linux-$zig_version" sh -euc '
      tar -xJf /zig.tar.xz -C "$DIR"
      for t in x86_64:amd64 aarch64:arm64; do
        ZIG_GLOBAL_CACHE_DIR="$DIR/cache" ZIG_LOCAL_CACHE_DIR="$DIR/cache" \
          "$DIR/$ZIGDIR/zig" cc -target "${t%%:*}-linux-musl" -mcpu=baseline -static -Os -fno-sanitize=all \
          -Wall -Wextra -Werror -ffile-prefix-map="$DIR=/build" -Wl,--build-id=none -s \
          -o "$DIR/out/guard_${t##*:}" "$DIR/src/guard.c"
      done'
}

build "$build_root/first"
build "$build_root/a/second/build"
for goarch in amd64 arm64; do
  if ! cmp -s "$build_root/first/out/guard_$goarch" "$build_root/a/second/build/out/guard_$goarch"; then
    echo "build.sh: guard_$goarch differs between two builds" >&2
    exit 1
  fi
  echo "guard_$goarch: the same bytes from two builds: $(sha256sum "$build_root/first/out/guard_$goarch" | cut -d ' ' -f 1) ($(stat -c %s "$build_root/first/out/guard_$goarch") bytes)"
done

for goarch in $installed; do
  install -m 0644 "$build_root/first/out/guard_$goarch" "$script_dir/guard_$goarch"
done
# Paths are the package's (check with: cd sandbox/internal/guestguard && sha256sum -c program/guard.sha256).
(
  cd "$pkg_dir"
  sha256sum program/guard.c guest_filter.h program/build.sh $(for g in $installed; do echo "program/guard_$g"; done)
) > "$script_dir/guard.sha256"
cat "$script_dir/guard.sha256"
