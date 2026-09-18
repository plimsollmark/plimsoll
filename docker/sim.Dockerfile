# Simulation worker image: compiled physical models as supervised WasmEdge workers,
# step 1 of docs/architecture/run-module-plan.md. Nothing here changes the project
# API: a step names the worker, the worker names a model baked into the image root,
# and the run keeps every lockdown a Node project gets (read-only root, noexec
# writable mounts, --network none, the seccomp profile). Built by `make docker-images`
# as plimsoll/sandbox-sim:latest; point a daemon at it with
# SANDBOX_DOCKER_PROJECT_IMAGE. Recipe and rationale: docs/guest-dependencies.md,
# "A compiled model is image content too".
#
# Register a model = build an image. A model is an AOT-compiled shared object and
# must be mapped executable; every writable mount of a run is noexec, so the image
# root is the only place a model can load from. sandbox/docker_sim_test.go proves
# both halves: /models/vanderpol.so runs 100 parameter sets byte-identical to a
# native C run of the same shim, and a byte-identical copy under /work refuses to
# load. /models/lorenz.so is a model of our own (sim/models/Lorenz): chaos turns
# any one-ulp difference in the arithmetic into a checksum miss, and its 60 s
# rows are the regression for the shim's step guard. /models/greedy.so is a test
# fixture (sim/models/Greedy) proving the worker's per-instance memory cap: a
# row that asks for more than 16 MiB fails alone with -7 while its neighbours
# complete.
#
# The physics oracle (docs/architecture/oracle-demo-plan.md) is two more files.
# /models/cartpole.wasm is the cart-pole plant (sim/models/CartPole) behind the
# stepping shim sim/shim_step.c, kept as WebAssembly rather than AOT-compiled
# because Node, not the worker, loads it. /oracle/run.mjs is the judge: a project
# step runs it with the caller's controller file, it loads the plant through
# Node's WASI support, runs the controller as a separate process, exchanges one
# line per tick, and writes the trajectory whose SHA-256 is the fingerprint.
#
# Four stages, every input pinned:
#   fetch  the WasmEdge release tarball (SHA-256 checked) and the Reference FMUs
#          source at a tag (commit checked), both from GitHub;
#   wasm   the wasi-sdk image, pinned by digest, compiles two Reference FMUs and
#          sim/models/Lorenz, each behind sim/shim.c, plus sim/models/CartPole
#          behind sim/shim_step.c and the Greedy fixture, into wasm32-wasi reactor
#          modules;
#   build  gcc links sim/worker.c against libwasmedge and `wasmedge compile`
#          AOT-compiles the modules to shared objects;
#   runtime node:22-bookworm-slim (the runner needs node; the WasmEdge binaries are
#          glibc, which rules out the Alpine base the other images share) carrying
#          libwasmedge, the worker, the models and runner.mjs, USER node, the same
#          entrypoint as every project image.
#
# The wasm bytes, and so the artifact checksums the test asserts, depend on the
# wasi-sdk digest, the Reference FMUs commit and shim.c; the machine code depends on
# the WasmEdge version. Bump any of them deliberately and regenerate the checksums
# from a native run (the sister repository's `make native` then `sha256sum`).

ARG WASMEDGE_VERSION=0.17.1
# From the SHA256SUM asset of the 0.17.1 release, manylinux_2_28 x86_64 tarball.
ARG WASMEDGE_SHA256=27a1abec072ddf45b40e2e81e33c1e5fe9b241f31fd1bbf0182f05097489a07a
ARG REF_FMUS_TAG=v0.0.41
# The commit the annotated tag v0.0.41 points to (Modelica Association, BSD-2).
ARG REF_FMUS_COMMIT=1258711a41e28b1c25e058abd04f6214beefa3cb

# ---- fetch: pinned inputs from the network, verified before use ----------------
FROM debian:bookworm-slim AS fetch
ARG WASMEDGE_VERSION
ARG WASMEDGE_SHA256
ARG REF_FMUS_TAG
ARG REF_FMUS_COMMIT
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/wasmedge.tar.gz \
      "https://github.com/WasmEdge/WasmEdge/releases/download/${WASMEDGE_VERSION}/WasmEdge-${WASMEDGE_VERSION}-manylinux_2_28_x86_64.tar.gz" \
 && echo "${WASMEDGE_SHA256}  /tmp/wasmedge.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/wasmedge \
 && tar -xzf /tmp/wasmedge.tar.gz -C /opt/wasmedge \
 && rm /tmp/wasmedge.tar.gz
RUN git clone --quiet --depth 1 --branch "${REF_FMUS_TAG}" \
      https://github.com/modelica/Reference-FMUs.git /src \
 && test "$(git -C /src rev-parse HEAD)" = "${REF_FMUS_COMMIT}" \
 && rm -rf /src/.git

# ---- wasm: three models as wasm32-wasi reactor modules --------------------------
# wasi-sdk 27, pinned by digest: the tag is mutable, the digest is not.
FROM ghcr.io/webassembly/wasi-sdk@sha256:a4924a72705af8d5c95b84439a212200795600eb4db8dd79f3d147f4cf2f407f AS wasm
COPY --from=fetch /src /src
COPY sim/shim.c sim/shim_step.c /build/
COPY sim/models /build/models
WORKDIR /build
# Same flags as the sister repository's Makefile: the shim exports alloc, sim_width
# and sim_run; BB selects BouncingBall, LORENZ selects models/Lorenz, the default
# is VanDerPol.
RUN /opt/wasi-sdk/bin/clang --target=wasm32-wasi -mexec-model=reactor -O2 \
      -DFMI_VERSION=3 -DDISABLE_PREFIX -I /src/include -I /src/VanDerPol \
      /src/src/fmi3Functions.c /src/src/cosimulation.c /src/VanDerPol/model.c shim.c \
      -o vanderpol.wasm \
 && /opt/wasi-sdk/bin/clang --target=wasm32-wasi -mexec-model=reactor -O2 \
      -DFMI_VERSION=3 -DDISABLE_PREFIX -DBB -I /src/include -I /src/BouncingBall \
      /src/src/fmi3Functions.c /src/src/cosimulation.c /src/BouncingBall/model.c shim.c \
      -o bouncingball.wasm \
 && /opt/wasi-sdk/bin/clang --target=wasm32-wasi -mexec-model=reactor -O2 \
      -DFMI_VERSION=3 -DDISABLE_PREFIX -DLORENZ -I /src/include -I /build/models/Lorenz \
      /src/src/fmi3Functions.c /src/src/cosimulation.c /build/models/Lorenz/model.c shim.c \
      -o lorenz.wasm \
 && /opt/wasi-sdk/bin/clang --target=wasm32-wasi -mexec-model=reactor -O2 \
      -DFMI_VERSION=3 -DDISABLE_PREFIX -I /src/include -I /build/models/CartPole \
      /src/src/fmi3Functions.c /src/src/cosimulation.c /build/models/CartPole/model.c shim_step.c \
      -o cartpole.wasm \
 && /opt/wasi-sdk/bin/clang --target=wasm32-wasi -mexec-model=reactor -O2 \
      /build/models/Greedy/greedy.c -o greedy.wasm

# ---- build: the worker binary and the AOT models --------------------------------
FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev libstdc++6 zlib1g libtinfo6 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /opt/wasmedge /opt/wasmedge
COPY --from=wasm /build/vanderpol.wasm /build/bouncingball.wasm /build/lorenz.wasm /build/greedy.wasm /build/
COPY sim/worker.c /build/worker.c
WORKDIR /build
RUN gcc -O2 worker.c -I /opt/wasmedge/include -L /opt/wasmedge/lib64 -lwasmedge -lpthread \
      -o sim-worker \
 && LD_LIBRARY_PATH=/opt/wasmedge/lib64 /opt/wasmedge/bin/wasmedge compile vanderpol.wasm vanderpol.so \
 && LD_LIBRARY_PATH=/opt/wasmedge/lib64 /opt/wasmedge/bin/wasmedge compile bouncingball.wasm bouncingball.so \
 && LD_LIBRARY_PATH=/opt/wasmedge/lib64 /opt/wasmedge/bin/wasmedge compile lorenz.wasm lorenz.so \
 && LD_LIBRARY_PATH=/opt/wasmedge/lib64 /opt/wasmedge/bin/wasmedge compile greedy.wasm greedy.so

# ---- runtime: the project image contract, plus the worker and the models --------
FROM node:22-bookworm-slim
# The real file only; ldconfig recreates the soname link libwasmedge.so.0 from it.
COPY --from=build /opt/wasmedge/lib64/libwasmedge.so.0.1.1 /usr/local/lib/
COPY --from=build /build/sim-worker /usr/local/bin/sim-worker
COPY --from=build /build/vanderpol.so /build/bouncingball.so /build/lorenz.so /build/greedy.so /models/
COPY --from=wasm /build/cartpole.wasm /models/cartpole.wasm
COPY sim/oracle/run.mjs /oracle/run.mjs
COPY runner.mjs /runner.mjs
# Fail the build, not the first run, if the worker's shared libraries are missing.
RUN ldconfig && ! ldd /usr/local/bin/sim-worker | grep 'not found'
USER node
ENTRYPOINT ["node", "/runner.mjs"]
