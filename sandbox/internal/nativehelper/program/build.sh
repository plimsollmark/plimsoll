#!/usr/bin/env bash
# Builds the native helper (plimsoll-helper, this folder's Rust crate) for x86-64, statically
# against musl, inside a container image pinned by digest that carries the pinned toolchain,
# twice in two folders, and refuses unless the two builds give the same bytes. With HOST=1 it
# also builds once on this machine with rustup's toolchain of the same version (the one
# rust-toolchain.toml names) and refuses unless that gives the same bytes too. Then it installs
# the file as plimsoll-helper_amd64 and writes plimsoll-helper.sha256 (inputs and output), which
# the package's tests check.
#
#     build.sh            # the two container builds
#     HOST=1 build.sh     # and the host build
#
# The image must already be on this machine (docker pull rust@<digest below>, about 1 GB;
# take the docker lock exclusively for the pull). Nothing is fetched while building: the crate
# has no outside package and the container has no network. Run it where docker is local; it uses
# an empty client config of its own, so no host client setting (a proxies entry) reaches the
# build container.
set -euo pipefail

readonly script_dir="$(cd "$(dirname "$0")" && pwd)"
readonly repo_root="$(cd "$script_dir/../../../.." && pwd)"
# rust:1.99.1-alpine, by the digest of its multi-machine index (checked 2026-11-19); the
# toolchain inside is Rust 1.99.1, the version rust-toolchain.toml pins. The design review
# measured that the image's own newer toolchain (1.100.0 in rust:1-alpine) gives other bytes,
# so both are pinned.
readonly image="rust@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383"
readonly rust_version="1.99.1"
readonly target="x86_64-unknown-linux-musl"
# Machines installed: no plimsoll image is built for aarch64 yet (the design review's finding
# 9), so there is nothing to run an aarch64 helper under.
readonly installed="amd64"
# Every input of the build, relative to this folder; the pin lists each. The build copies the
# whole of src/ (copy_sources), so every file under it is an input, not only the .rs files: a
# file read by include_bytes! changes the bytes too (finding rust-native-helper-33). Anything
# under src/ that is neither a plain file nor a folder, or whose name the list below could not
# carry, is refused. sandbox/internal/nativehelper's TestBuildInputsAreEverySourceFile runs
# this line against a copy holding one more file.
odd="$(cd "$script_dir" && find src \( \( ! -type f ! -type d \) -o -name '*[!A-Za-z0-9._-]*' \) -print)"
if [[ -n "$odd" ]]; then
  echo "build.sh: under src/, only plain files and folders with plain names (A-Z a-z 0-9 . _ -): $odd" >&2
  exit 1
fi
readonly inputs="Cargo.toml Cargo.lock rust-toolchain.toml build.sh $(cd "$script_dir" && find src -type f | LC_ALL=C sort | tr '\n' ' ')"

mkdir -p "$repo_root/tmp"
build_root="$(mktemp -d "$repo_root/tmp/nativehelper-build.XXXXXX")"
readonly build_root
trap 'rm -rf -- "$build_root"' EXIT
mkdir "$build_root/docker-config"

# The flags that make the bytes: static musl, every path the compiler sees under DIR written
# as /build, no build ID. The profile in Cargo.toml does the rest (one codegen unit, LTO,
# stripped, abort on panic).
rustflags() {
  echo "-C target-feature=+crt-static --remap-path-prefix=$1=/build -C link-arg=-Wl,--build-id=none"
}

copy_sources() {
  local dir="$1"
  mkdir -p "$dir/src" "$dir/out"
  (cd "$script_dir" && cp Cargo.toml Cargo.lock rust-toolchain.toml "$dir/src/" && cp -r src "$dir/src/src")
}

# build_in_image DIR: one whole build in DIR, mounted at its own path, so two builds differ
# in every path the compiler sees.
build_in_image() {
  local dir="$1"
  copy_sources "$dir"
  docker --config "$build_root/docker-config" run --rm --network none \
    --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp:rw,exec,size=512m \
    -v "$dir:$dir" -w "$dir/src" \
    --entrypoint /usr/bin/env "$image" -i PATH=/usr/local/cargo/bin:/usr/bin:/bin \
    RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN="$rust_version" CARGO_HOME="$dir/cargo-home" \
    CARGO_TARGET_DIR="$dir/target" RUSTFLAGS="$(rustflags "$dir")" DIR="$dir" TARGET="$target" WANT="$rust_version" \
    sh -euc '
      v="$(rustc --version)"; echo "in the image: $v"
      case "$v" in "rustc $WANT "*) ;; *) echo "build.sh: the image carries $v, not $WANT" >&2; exit 1 ;; esac
      cargo build --offline --locked --release --target "$TARGET"
      cp "$DIR/target/$TARGET/release/plimsoll-helper" "$DIR/out/plimsoll-helper_amd64"'
}

build_on_host() {
  local dir="$1" bin="${RUSTUP_BIN:-$HOME/.cargo/bin}"
  copy_sources "$dir"
  (
    cd "$dir/src"
    echo "on the host: $(RUSTUP_TOOLCHAIN="$rust_version" "$bin/rustc" --version)"
    env -u RUSTC_WRAPPER PATH="$bin:/usr/bin:/bin" RUSTUP_TOOLCHAIN="$rust_version" CARGO_HOME="$dir/cargo-home" \
      CARGO_TARGET_DIR="$dir/target" RUSTFLAGS="$(rustflags "$dir")" "$bin/cargo" build --offline --locked --release --target "$target"
  )
  cp "$dir/target/$target/release/plimsoll-helper" "$dir/out/plimsoll-helper_amd64"
}

build_in_image "$build_root/first"
build_in_image "$build_root/a/second/build"
builds="$build_root/a/second/build"
if [[ "${HOST:-0}" == 1 ]]; then
  build_on_host "$build_root/host/third"
  builds="$builds $build_root/host/third"
fi
for b in $builds; do
  if ! cmp -s "$build_root/first/out/plimsoll-helper_amd64" "$b/out/plimsoll-helper_amd64"; then
    echo "build.sh: plimsoll-helper_amd64 differs between $build_root/first and $b" >&2
    sha256sum "$build_root/first/out/plimsoll-helper_amd64" "$b/out/plimsoll-helper_amd64" >&2
    exit 1
  fi
done
echo "plimsoll-helper_amd64: the same bytes from $((1 + $(wc -w <<<"$builds"))) builds: $(sha256sum "$build_root/first/out/plimsoll-helper_amd64" | cut -d ' ' -f 1) ($(stat -c %s "$build_root/first/out/plimsoll-helper_amd64") bytes)"

for goarch in $installed; do
  install -m 0644 "$build_root/first/out/plimsoll-helper_$goarch" "$script_dir/plimsoll-helper_$goarch"
done
# Paths are this folder's (check with: cd sandbox/internal/nativehelper/program && sha256sum -c plimsoll-helper.sha256).
(
  cd "$script_dir"
  # shellcheck disable=SC2086
  sha256sum $inputs $(for g in $installed; do echo "plimsoll-helper_$g"; done)
) > "$script_dir/plimsoll-helper.sha256"
cat "$script_dir/plimsoll-helper.sha256"
