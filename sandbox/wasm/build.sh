#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 QUICKJS_SOURCE_TARBALL WASI_SDK_DEB CMAKE_TARBALL" >&2
  exit 2
fi

readonly quickjs_archive="$(realpath "$1")"
readonly wasi_sdk_deb="$(realpath "$2")"
readonly cmake_archive="$(realpath "$3")"
readonly script_dir="$(cd "$(dirname "$0")" && pwd)"
readonly expected_source_sha="c4e813951b7c46845096a948e978c620b11ab4cf5fd622ca09c727ec31f42623"
readonly expected_wasi_sha="20a5b880814adc14b93f8b14a2230e75a6174a1b77493c50e8fc00d27dcfdcb2"
readonly expected_cmake_sha="5a1133ff103c71eb5120e2cc3de922733e7d8a26a98ae716397e8676adb367bf"

verify_sha() {
  local file="$1" expected="$2" label="$3" actual
  actual="$(sha256sum "$file" | cut -d ' ' -f 1)"
  if [[ "$actual" != "$expected" ]]; then
    echo "$label checksum mismatch: got $actual" >&2
    exit 1
  fi
}

verify_sha "$quickjs_archive" "$expected_source_sha" "quickjs source"
verify_sha "$wasi_sdk_deb" "$expected_wasi_sha" "wasi-sdk"
verify_sha "$cmake_archive" "$expected_cmake_sha" "cmake"

readonly build_root="$(mktemp -d)"
trap 'rm -rf -- "$build_root"' EXIT

tar -xzf "$quickjs_archive" -C "$build_root"
mkdir -p "$build_root/wasi-sdk" "$build_root/cmake"
dpkg-deb -x "$wasi_sdk_deb" "$build_root/wasi-sdk"
tar -xzf "$cmake_archive" -C "$build_root/cmake" --strip-components=1
readonly source_dir="$build_root/quickjs-0.15.1"
readonly wasi_sdk_root="$build_root/wasi-sdk/opt/wasi-sdk"
readonly cmake_bin="$build_root/cmake/bin/cmake"
# The checked-in notice is what satisfies MIT for the redistributed binary, so it has
# to be the notice from the source that built it. Its Go test can only prove the file
# has not changed since it was added; this is the one moment the upstream copy is on
# disk, so this is where the two are actually compared.
if ! cmp -s "$source_dir/LICENSE" "$script_dir/LICENSE.quickjs-ng"; then
  echo "LICENSE.quickjs-ng does not match the pinned source archive's LICENSE" >&2
  exit 1
fi

cp "$script_dir/coderunner-hostcall.c" "$source_dir/coderunner-hostcall.c"
patch --batch -p1 -d "$source_dir" < "$script_dir/quickjs-v0.15.1.patch"

export SOURCE_DATE_EPOCH=1759119141
"$cmake_bin" -S "$source_dir" -B "$build_root/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE="$wasi_sdk_root/share/cmake/wasi-sdk.cmake" \
  -DCMAKE_C_FLAGS="-ffile-prefix-map=$build_root=/build" \
  -DQJS_BUILD_WERROR=ON
"$cmake_bin" --build "$build_root/build" --target qjs_exe --parallel

install -m 0644 "$build_root/build/qjs" "$script_dir/qjs-wasi.wasm"
sha256sum "$script_dir/qjs-wasi.wasm"
