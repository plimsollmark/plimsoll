# Third-party packages in project runs

A run has no network. Docker runs launch with `--network none`, the WASM guest has no
sockets, and an E2B microVM denies egress except through the grant guard. So
`npm install` cannot happen inside a run, from a public registry or a private one,
and no grant changes that: the broker carries one allowlisted API origin with exact
routes and a 4 MiB response budget, which no package manager can work through.

Packages a project imports therefore come from the **project image**, and the
operator decides them **at image build time**. That is also the only place a
registry credential ever exists. This page is the recipe, with outputs pasted from a
real run. It covers project runs (`RunProject`); snippet runs use the separate
`SANDBOX_DOCKER_IMAGE` and the same derived-image approach applies, but the outputs
here are from projects.

## How a project finds a package

Project files are written to `/work`, a tmpfs, and every step runs with `/work` as its
working directory. Node resolves a bare import by walking up parent directories
looking for `node_modules`: `/work/node_modules`, then `/node_modules`. A package
installed at `/node_modules` in the image is therefore found by every project file,
for both `import` and `require`, with no `NODE_PATH` and no change to the runner.
TypeScript's node-style resolution walks the same directories.

## The recipe

Start from the shipped toolchain image and install from a lockfile at the filesystem
root, with lifecycle scripts disabled:

```dockerfile
FROM plimsoll/sandbox:latest
USER root
WORKDIR /
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev --no-fund --no-audit && npm cache clean --force
USER node
```

With a `package.json` declaring `left-pad` and its generated lockfile beside the
Dockerfile:

```sh
docker build -t my-org/plimsoll-sandbox:2026-09-17 .
```

Four choices in that file are load-bearing:

- **`npm ci` from a lockfile**, never `npm install`: the image contains exactly the
  versions and integrity hashes the lockfile names, and rebuilding yields the same
  tree.
- **`--ignore-scripts`**: install-time lifecycle scripts are code execution, and the
  image build is not the sandbox. Packages whose install step compiles native code
  will not work this way; prefer pure-JavaScript packages, or build such a package
  deliberately in its own `RUN` step where you can read what it does.
- **`WORKDIR /`** puts the tree at `/node_modules`, the one place every project file
  resolves.
- **`USER node`** restores the unprivileged user the runner expects; the daemon also
  enforces `--user` and drops capabilities at run time.

**A private registry** supplies its credential to the build only, through a BuildKit
secret mount, so it never lands in an image layer:

```dockerfile
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \
    npm ci --ignore-scripts --omit=dev --no-fund --no-audit && npm cache clean --force
```

```sh
docker build --secret id=npmrc,src=$HOME/.npmrc -t my-org/plimsoll-sandbox:2026-09-17 .
```

The `.npmrc` names the registry and its token. The plain form above is the one this
page exercised; the secret mount is Docker's documented mechanism for exactly this.

## Point the daemon at it

```sh
SANDBOX_PROVIDER=docker \
SANDBOX_DOCKER_PROJECT_IMAGE=my-org/plimsoll-sandbox:2026-09-17 \
...
```

Preflight inspects the image on the daemon's own docker (it must be present there),
rejects an image that declares a `VOLUME`, and every run launches the content-addressed
image ID that Preflight inspected, so re-pointing the tag later cannot change what
runs. In production set `SANDBOX_REQUIRE_PINNED_IMAGES=1` and name the image by
`@sha256:` digest; hardened mode requires it.

## What a project sees

Two projects, each one file, each one step (`node main.mjs`), run through a daemon
whose project image was built from the recipe above with `left-pad@1.3.0`:

```
import left-pad          outcome completed, isolation container
  step "node main.mjs" exit 0 stdout "00042\n" stderr ""
import not-in-the-image  outcome completed, isolation container
  step "node main.mjs" exit 1 stdout "" stderr "node:internal/modules/package_json_reader:314 ... Error [ERR_MODULE_NOT_FOUND]: ..."
```

The first is the package resolving from `/node_modules` with no network. The second is
what a missing package looks like: a **normal result**, `outcome: completed` with the
step's exit code 1 and Node's own error on stderr, not a Go error and not an
infrastructure fault. Nothing in plimsoll knows what the agent wanted to import; the
sandbox does not read guest output, so the operator learns it from the caller.

## Other runtimes: the same recipe

A runtime is image content too. plimsoll selects an image, never a package or an
interpreter, so a Python project needs no new provider, procedure, or environment
variable: a derived image that puts `python3` on `PATH`, and a step that names it.
[docker/python.Dockerfile](../docker/python.Dockerfile) is that image, built by
`make docker-images` as `plimsoll/sandbox-python:latest`:

```dockerfile
FROM plimsoll/sandbox:latest
USER root
RUN apk add --no-cache "python3~=3.14.7" "py3-numpy~=2.4.6" "py3-scipy~=1.17.1"
ENV OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
USER node
```

The base keeps the contract every project image inherits: the runner at
`/runner.mjs` as entrypoint, `USER node`, no `VOLUME`, a read-only root at run time.
Point a daemon at the image with `SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python:latest`
and a project whose step is `python3 main.py` runs through `RunProject` unchanged.

Three things in that file are load-bearing:

- **NumPy and SciPy live in the image root.** A native extension is a shared object
  that must be mapped executable, and the run's writable mounts (`/work`, `/tmp`,
  `/dev/shm`) are `noexec` tmpfs. The read-only image root is the only place a
  native library can load from, which is the same reason `/node_modules` is baked
  in. `sandbox/docker_python_test.go` proves the extensions load under the shipped
  seccomp profile: it solves a 3x3 system through SciPy's LAPACK binding and takes
  an FFT, and checks the values to 1e-9.
- **One BLAS thread.** Alpine's OpenBLAS sizes its thread pool from the host's core
  count, not the run's CPU quota, so without `OPENBLAS_NUM_THREADS=1` a run inside a
  1-CPU, 256-process cgroup would start a thread per host core. One thread also
  makes reductions repeat bit-for-bit across runs, which anything comparing results
  between runs needs. The image's `ENV` reaches every step process; the test
  checks that too.
- **No pip.** A run never installs anything, on any provider (see the limits
  below), and the image does not ship pip, so `python3 -m pip install` fails with
  "No module named pip" rather than reaching for a network the run does not have.
  The test runs that step and requires it to fail.

One caveat on the pins. The `node:22-alpine` base tag floats with Alpine's current
release, and `make docker-images` pulls it every time, so the three version pins
track whichever Alpine that tag currently carries. An `apk add` failure reading
"unable to select packages ... breaks: world[python3~3.x]" means the base moved;
the fix is a deliberate bump of the pins to what
`apk search -x python3 py3-numpy py3-scipy` reports inside `plimsoll/sandbox`. It
happened on the first build of the file, 2026-09-18, when the tag moved from Alpine
3.23 to 3.24 between the trial and the build.

### A compiled model is image content too

A physical model compiled to WebAssembly takes the same path as an interpreter or
a package: a file in the image root, named by a step.
[docker/sim.Dockerfile](../docker/sim.Dockerfile) is that recipe, built by
`make docker-images` as `plimsoll/sandbox-sim:latest`. The image ships:

- `/usr/local/bin/sim-worker`, a C program on WasmEdge's C API
  ([docker/sim/worker.c](../docker/sim/worker.c)). It loads one AOT-compiled
  module once, runs one fresh instance per parameter set, and writes one binary
  artifact: per run an int32 step count, then the module's own `sim_width()`
  float64 outputs per step (two for the Reference models, three for Lorenz).
- `/models/vanderpol.so` and `/models/bouncingball.so`: two Modelica Reference
  FMUs (FMI 3.0, C source, BSD-2) compiled to wasm32-wasi by wasi-sdk 27 behind a
  small shim ([docker/sim/shim.c](../docker/sim/shim.c)), then AOT-compiled by
  WasmEdge 0.17.1 into shared objects; and `/models/lorenz.so`, a Lorenz model
  of our own in the same style ([docker/sim/models/Lorenz](../docker/sim/models/Lorenz)),
  there because chaos turns any one-ulp arithmetic difference into a checksum miss.
  `/models/greedy.so` is a test fixture proving the worker caps every instance at
  256 pages (16 MiB): a row that asks for more fails alone.
- `/models/cartpole.wasm` and `/oracle/run.mjs`: the physics oracle. A cart-pole
  plant with the force as an input, kept as WebAssembly because Node, not the
  worker, loads it, and the judge that runs a caller's controller as a separate
  process against it and fingerprints the trajectory. `examples/oracle` is the
  demonstration; the page it writes replays the recorded runs.
- Seven more plants in the same form, each a `.wasm` file under `/models` that
  the judge (`/oracle/judge.mjs`) steps one tick at a time, with the controller in
  its own process. The sources are under [docker/sim/models](../docker/sim/models):
  - `shower.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/shower/index.html)): a mixing valve, a pipe modelled as a transport delay, and a
    shower head; a toilet flush drops the cold pressure mid-run. The controller
    sets the hot fraction and must not scald.
  - `buck.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/buck-converter/index.html)): an averaged synchronous buck converter; the controller sets the
    duty cycle and must hold the output voltage through a load step.
  - `ship.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/ship-heading/index.html)): a first-order Nomoto ship with a lagging, rate-limited rudder and
    wave forcing; the controller holds an ordered heading.
  - `blackhole.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/black-hole-orbit/index.html)): a probe on a Schwarzschild geodesic with two small
    thrusters, asked to hold a circular orbit inside the innermost stable one.
  - `rocket.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/twin-paradox-rocket/index.html)): the relativistic rocket equations in the ship's proper time;
    the controller has to arrive home when Earth's clock reads an ordered date.
  - `satclock.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/satellite-clock/index.html)): a navigation satellite's clock, which runs about 38.6
    microseconds a day fast from relativity, steered through a delayed
    measurement.
  - `slits.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/double-slit/index.html)): an aperture of sixteen phase-plate cells and a
    64-point screen; the controller sets all sixteen phases to produce a target
    pattern, and the plant also exports the exact output Jacobian.

  Each replay page runs two hand-written controllers against the plant on one
  scenario through the project API, a draft that fails and an accepted one that
  passes, and shows both trajectories and their fingerprints. Those controllers
  and their scoring programs are not published; a controller is the caller's.
  Cart-pole has the same page for its swing-up task
  ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/cartpole-swingup/index.html)).
- `libwasmedge`, the runner and `USER node`, on `node:22-bookworm-slim` rather than
  the Alpine base the other images share: WasmEdge's release binaries are glibc.

A step names the worker, a model and the sweep:

```sh
sim-worker /models/vanderpol.so 100 1 20 out.bin 0.1 5.0 2.0 0.0
#          model               N  threads t_end out  p0min p0max p1 p2
```

and `out.bin` comes back as an artifact. Three things in that file are load-bearing:

- **The model lives in the image root, for the same reason NumPy does.** An AOT
  model is machine code that WasmEdge loads with `dlopen`, so it must be mapped
  executable, and every writable mount of a run is `noexec`.
  `sandbox/docker_sim_test.go` proves both halves under the shipped seccomp
  profile: the sweeps run from `/models`, and a byte-identical copy of the model
  under `/work` is refused by the loader. Register a model = build an image, by
  design rather than as a workaround.
- **Bit-identity is the test, not a tolerance.** The test compares the SHA-256 of
  each sweep's artifact with a native C run of the same shim: 100 parameter sets
  of each Reference model, state events included, and 50 Lorenz rows of 60 s
  match to the byte. WebAssembly's
  floating-point semantics (no fused multiply-add outside relaxed SIMD, one
  rounding per operation) are what turn a numeric comparison into a checksum.
- **Every input is pinned.** The WasmEdge tarball by SHA-256 from the release's
  checksum file, the Reference FMUs by the commit behind the tag, the wasi-sdk
  image by digest. The wasm bytes, and so the checksums the test asserts, depend
  on the wasi-sdk digest, the Reference FMUs commit and the shim; the machine code
  depends on the WasmEdge version. Bump any of them deliberately and regenerate
  the checksums from a native run.

The same image also backs the typed operation. Point a daemon at it with
`SANDBOX_DOCKER_MODULE_IMAGE=plimsoll/sandbox-sim:latest` and a `Run` with a `module` payload takes a
model id and a parameter table (one row per instance) and returns every row's
status and outputs, decoded from the worker's versioned record; `Describe` then
reports `supports_module`. It is the project machinery with one step and one
artifact, so the same limits apply (8 MiB of results, the project timeout), and a
table whose results could not fit is refused before any row runs rather than
truncated. Nothing about the image changes between the two paths: the model id
`vanderpol` is `/models/vanderpol.so`, and adding a model is adding a line to this
recipe's `wasm` and `build` stages.

### A compiler is image content too

A compiler is one more program in the image root, named by a step.
[docker/wasm-cc.Dockerfile](../docker/wasm-cc.Dockerfile) derives
`plimsoll/sandbox-wasm-cc:latest` from the sim image, built by `make docker-images`,
and adds the C half of wasi-sdk 27 at `/opt/wasi-sdk` (on `PATH`): clang, the
WebAssembly linker, and a wasm32-wasip1 C library with its libm. It is taken from the
same digest-pinned wasi-sdk image the sim build compiles the plants with, and adds
about 150 MB. A project whose first step is

```sh
clang --target=wasm32-wasip1 -mexec-model=reactor -O2 -ffp-contract=off -o controller.wasm controller.c
```

gets a WebAssembly module in `/work` with no network, and a later step loads it with
Node. Two things make that work under the run's lockdown:

- **The compiler runs from the image root; its output is data.** clang and the linker
  are native programs, so they live in the read-only root like every other
  executable. What they write into the `noexec` `/work` is a `.wasm` file that Node
  reads and compiles in memory, never a native program the kernel would be asked to
  execute.
- **libm is compiled into the module.** A controller that calls `cos` links
  wasi-libc's implementation, so the module needs no host function for it and its
  arithmetic does not depend on the Node that runs it.
  [examples/wasm-controller](../examples/wasm-controller/) runs such a module with an
  empty import object, and its README explains why the result still differs, in the
  last bit, from a JavaScript program calling `Math.cos`.

## Limits, stated plainly

- No package installation during a run, ever, on any provider. An agent that must
  install arbitrary packages mid-run is the case general-purpose sandbox VMs cover
  and this component does not.
- The image root is read-only in a run. A package that writes beside itself at
  runtime fails with a normal non-zero exit; `/work` and `/tmp` are the writable
  places, and they are the run's sized `noexec` tmpfs mounts.
- Changing the dependency set means rebuilding, re-pinning and redeploying the
  image, and every caller of a daemon sees the same set.
- E2B: the template bakes the toolchain the same way (`e2b/e2b.Dockerfile`), and the
  recipe applies there; this page did not exercise that path.
