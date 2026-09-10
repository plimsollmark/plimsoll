# qjs-wasi.wasm

A WASI build of [QuickJS-ng](https://github.com/quickjs-ng/quickjs) (MIT;
[license notice](LICENSE.quickjs-ng)), embedded into plimsoll and executed by
wazero for the in-process `wasm` provider ([wasm.go](../wasm.go)).

This is a reproducible local build of QuickJS-ng v0.15.1 with one small
plimsoll-specific import. `coderunner-hostcall.c` exposes
`__coderunner_host_call` to JavaScript and imports the four-argument
`coderunner.host_call` WASM function supplied by Go. That ABI name is the
project's former name and is **deliberately frozen**: the pinned artifact below
imports it, so renaming it would require rebuilding and re-pinning the binary.
This file and `coderunner-hostcall.c` are the provenance record of the inputs
that produced the pinned hash, so neither is renamed. Only bounded guest request
and response buffers cross that ABI. The grant, route policy, bearer credential,
upstream HTTP client, quotas, and metadata trace remain in Go's shared broker
core; the credential is never copied into WASM memory or the QuickJS heap.

## Provenance (pinned)

| Input | Version / SHA-256 |
|---|---|
| QuickJS-ng source | **v0.15.1**; `c4e813951b7c46845096a948e978c620b11ab4cf5fd622ca09c727ec31f42623` |
| QuickJS-ng license notice | [LICENSE.quickjs-ng](LICENSE.quickjs-ng); `bfa580b50618373ca3debde48ea146aa2733e0fe99fd4d05b00d12cb98f9f822` |
| wasi-sdk build tool | **29.0** x86_64 Linux `.deb`; `20a5b880814adc14b93f8b14a2230e75a6174a1b77493c50e8fc00d27dcfdcb2` |
| CMake build tool | **3.31.6** x86_64 Linux tarball; `5a1133ff103c71eb5120e2cc3de922733e7d8a26a98ae716397e8676adb367bf` |
| Local changes | [coderunner-hostcall.c](coderunner-hostcall.c) and [quickjs-v0.15.1.patch](quickjs-v0.15.1.patch) |
| Resulting artifact | `qjs-wasi.wasm`; `f9258d318b05404d49f635191d2056c30d24ad75f2cb7f1190fdb98a76cd679e` |

`TestEmbeddedQuickJSProvenance` in [../wasm_test.go](../wasm_test.go) pins the
result checksum. The build was repeated from two fresh temporary directories and
produced the same checksum.

## Rebuilding

Download these exact inputs:

- <https://github.com/quickjs-ng/quickjs/archive/refs/tags/v0.15.1.tar.gz>
- <https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-29/wasi-sdk-29.0-x86_64-linux.deb>
- <https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-linux-x86_64.tar.gz>

Run the checked-in builder with the three downloaded files:

```sh
./build.sh /path/to/quickjs-v0.15.1.tar.gz \
  /path/to/wasi-sdk-29.0-x86_64-linux.deb \
  /path/to/cmake-3.31.6-linux-x86_64.tar.gz
```

The script independently verifies all three hashes, extracts the build tools into
one temporary directory, applies only the checked-in patch and shim, sets a fixed
source epoch and file-prefix map, builds with `QJS_BUILD_WERROR=ON`, and replaces
`qjs-wasi.wasm`. Update this document and the test pin together whenever any input
or local shim changes.

The build tools are regeneration-only dependencies. They are not linked into the
Go module, shipped with plimsoll, or needed at runtime. The artifact is invoked
as `qjs -e <code>` with stdout/stderr captured and no preopened filesystem,
environment, socket, or ambient network.
