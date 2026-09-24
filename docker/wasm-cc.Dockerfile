# C-to-WebAssembly project-run image, derived from the simulation image. A project
# run in this image can compile C source to a WebAssembly module inside the sandbox
# (a build step) and then run it (a later step), with no network at either point.
# examples/wasm-controller is the reason it exists: a cart-pole controller written
# in C, compiled here, and judged by /oracle/judge.mjs against /models/cartpole.wasm,
# both inherited unchanged from plimsoll/sandbox-sim.
#
# Built by `make docker-images` as plimsoll/sandbox-wasm-cc:latest; point a daemon at
# it with SANDBOX_DOCKER_PROJECT_IMAGE. Nothing about the run contract changes: the
# runner, ENTRYPOINT, USER node, read-only root, noexec writable mounts, --network
# none and the seccomp profile all come from the base. The compiler lives in the
# image root, which is the only place a run can execute a binary from; what it
# writes into /work is a .wasm file that Node loads as data, never a native program.
#
# The toolchain is wasi-sdk 27 (clang 20.1.8, wasi-libc 3f7eb4c7d6ed), taken from the
# same digest-pinned image docker/sim.Dockerfile compiles the plants with, so the
# plants and the controllers come out of one compiler. The tag is mutable, the
# digest is not; bump both files together. Its libm is wasi-libc's (musl's, which
# descends from fdlibm), linked into the module, so a controller that calls sin or
# cos imports nothing from the host and its arithmetic does not depend on the Node
# that runs it.
#
# Only the C half of the SDK is copied: clang, the wasm linker, the two LLVM shared
# libraries clang loads, clang's own headers and builtins, and the wasm32-wasip1
# sysroot without C++ headers, C++ libraries, shared-library variants or LTO
# bitcode. That is about 150 MB instead of the SDK's 422 MB. C++ would need those
# pieces back; nothing here uses it.
#
# The SDK binaries are glibc programs (they need GLIBC_2.29 at most), which is one
# more reason to derive from the Debian-based sim image rather than the Alpine base.

FROM ghcr.io/webassembly/wasi-sdk@sha256:a4924a72705af8d5c95b84439a212200795600eb4db8dd79f3d147f4cf2f407f AS sdk
RUN set -eu; \
    src=/opt/wasi-sdk; dst=/out/wasi-sdk; \
    mkdir -p "$dst/bin" "$dst/lib" "$dst/share/wasi-sysroot/include" "$dst/share/wasi-sysroot/lib"; \
    cp -a "$src/VERSION" "$dst/"; \
    cp -a "$src/bin/clang-20" "$src/bin/clang" "$src/bin/clang.cfg" "$src/bin/lld" "$src/bin/wasm-ld" "$dst/bin/"; \
    cp -a "$src"/lib/libLLVM.so.20.1-wasi-sdk "$src"/lib/libclang-cpp.so.20.1-wasi-sdk "$src/lib/clang" "$dst/lib/"; \
    cp -a "$src/share/wasi-sysroot/include/wasm32-wasip1" "$dst/share/wasi-sysroot/include/"; \
    rm -rf "$dst/share/wasi-sysroot/include/wasm32-wasip1/c++"; \
    cp -a "$src/share/wasi-sysroot/lib/wasm32-wasip1" "$dst/share/wasi-sysroot/lib/"; \
    cd "$dst/share/wasi-sysroot/lib/wasm32-wasip1"; \
    rm -rf libc++* *.so llvm-lto

FROM plimsoll/sandbox-sim:latest
COPY --from=sdk /out/wasi-sdk /opt/wasi-sdk
ENV PATH=/opt/wasi-sdk/bin:$PATH
# Fail the build, not the first run, if the trimmed SDK cannot compile and link a
# module that uses libm, or if that module imports anything from the host.
RUN set -eu; cd /tmp; \
    printf '#include <math.h>\n__attribute__((export_name("f"))) double f(double x) { return sin(x) + cos(x); }\n' > probe.c; \
    clang --target=wasm32-wasip1 -mexec-model=reactor -O2 -o probe.wasm probe.c; \
    node -e 'const m = new WebAssembly.Module(require("fs").readFileSync("probe.wasm")); const i = WebAssembly.Module.imports(m); if (i.length) { console.error("probe imports", i); process.exit(1); }'; \
    rm probe.c probe.wasm
