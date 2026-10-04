# Third-party packages in project runs

A run has no network, whichever <dfn>*provider*</dfn> (the backend that runs the code) it
uses:

- Docker runs launch with `--network none`.
- The `wasm` provider's <dfn>*guest*</dfn> (the code in the sandbox) has no sockets.
- An <dfn>*E2B*</dfn> <dfn>*microVM*</dfn> (E2B is a hosted service that runs each
  sandbox in a small virtual machine made for one run) denies <dfn>*egress*</dfn>, any
  connection out of it, except through the <dfn>*guard*</dfn>: the one plimsoll address a
  run with a <dfn>*grant*</dfn> (permission to call listed routes of one API) may reach.

So `npm install` cannot happen inside a run, from a public registry or a private one,
and no grant changes that. The <dfn>*broker*</dfn>, the part of plimsoll that makes a
grant's API calls, reaches one API address, only on the exact routes the grant lists,
with at most 4 MiB per response: no package manager can work through that.

Packages a project imports therefore come from the **project image**, and the
operator decides them **at image build time**. That is also the only place a
registry credential ever exists. This page is the recipe, with outputs pasted from a
real run. It covers project runs (`RunProject`); snippet runs use the separate
`SANDBOX_DOCKER_IMAGE`, and the same approach (build your own image on top of
plimsoll's) applies there, but the outputs here are from projects.

## How a project finds a package

Project files are written to `/work`, a <dfn>*tmpfs*</dfn> (a filesystem held in
memory, with a size limit), and every step runs with `/work` as its working directory.
Node resolves a bare import (a package name, such as `left-pad`, rather than a file path)
by walking up parent directories looking for `node_modules`: `/work/node_modules`, then
`/node_modules`. A package installed at `/node_modules` in the image is therefore found
by every project file, for both `import` and `require`, with no `NODE_PATH` and no
change to the runner. TypeScript's node-style resolution walks the same directories.

## The recipe

Start from the shipped toolchain image and install from a lockfile at the filesystem
root, with packages' lifecycle scripts (the commands a package can run when it is
installed) disabled:

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

Four choices in that file matter:

- **`npm ci` from a lockfile**, never `npm install`: the image contains exactly the
  versions and integrity hashes the lockfile names, and rebuilding yields the same
  tree.
- **`--ignore-scripts`**: install-time scripts run code, and the image build does not
  happen inside the sandbox. Packages whose install step compiles native code will not
  work this way; prefer pure-JavaScript packages, or build such a package deliberately
  in its own `RUN` step where you can read what it does.
- **`WORKDIR /`** puts the tree at `/node_modules`, the one place every project file
  resolves.
- **`USER node`** keeps the image's own default unprivileged. The daemon runs every
  guest as its own uid anyway (`--user`, default 61000, `SANDBOX_GUEST_UID`), which has no
  account in the image, and drops Linux capabilities (the kernel's separate root
  privileges) at run time. So a file only `node` can read is unreadable to a run, `HOME`
  is `/`, and `os.userInfo()` (and Python's `getpass.getuser()`) fails: give a package's
  files to everyone (`chmod -R a+rX`), or add a passwd line for the guest uid if a tool
  needs a user name.

**A private registry** supplies its credential to the build only, through a BuildKit
secret mount (a file docker makes available to one `RUN` step and never writes into the
image), so it never lands in an image layer:

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

<dfn>*Preflight*</dfn>, the configuration check the provider runs at startup and on each
readiness poll, inspects the image on the docker daemon plimsoll uses (the image must be
present there) and rejects an image that declares a `VOLUME`, because docker would
create an unbounded writable volume for it. Every run then launches the
<dfn>*content-addressed*</dfn> image ID that preflight inspected, an ID computed from the
image's own content, so pointing the tag at another image later cannot change what runs.
In production set `SANDBOX_REQUIRE_PINNED_IMAGES=1` and name the image by its `@sha256:`
<dfn>*digest*</dfn> (the SHA-256 hash of its content). <dfn>*Hardened mode*</dfn>, the
setting under which the daemon refuses to start unless every production safeguard is
configured, requires it.

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
step's exit code 1 and Node's own error on stderr, not a Go error and not a failure of
plimsoll itself. Nothing in plimsoll knows what the agent wanted to import; the sandbox
does not read guest output, so the operator learns it from the caller.

## Other runtimes: the same recipe

A runtime is image content too. plimsoll selects an image, never a package or an
interpreter, so a Python project needs no new provider, procedure, or environment
variable: a derived image that puts `python3` on `PATH`, and a step that names it.
[docker/python.Dockerfile](../docker/python.Dockerfile) is that image, built by
`make docker-images` as `plimsoll/sandbox-python:latest`:

```dockerfile
FROM plimsoll/sandbox:latest
USER root
RUN apk add --no-cache "python3~3.14" "py3-numpy~2.4" "py3-scipy~1.17"
ENV OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
USER node
```

The base image carries what every project image inherits: `/runner.mjs` and
`/usr/local/lib/plimsoll-runner-guard.so`, which the docker provider loads into
`node /runner.mjs` before the runner reads a plan, stopping a project step from reading
the runner's plan, its report or its memory. The provider starts the runner itself, with
none of the image's environment, and ignores the image's `ENTRYPOINT`; the image's `ENV`
(here the one BLAS thread) reaches the project's steps. `USER node`, no `VOLUME`, and a
read-only root at run time also apply, and an `ENV` that sets a dynamic-loader variable
(any `LD_` name, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH` or `GCONV_PATH`) is refused at startup.
Point a daemon at the image with `SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python:latest`
and a project whose step is `python3 main.py` runs through `RunProject` unchanged.

Three things in that file matter:

- **NumPy and SciPy live in the image root.** A native extension is compiled machine
  code (a shared object, `.so`) that must be mapped into memory as executable, and the
  run's writable mounts (`/work`, `/tmp`, `/dev/shm`) are `noexec` tmpfs, where nothing
  can be executed. The read-only image root is the only place a native library can load
  from, which is the same reason `/node_modules` is built into the image.
  `sandbox/docker_python_test.go` proves the extensions load under the shipped
  <dfn>*seccomp*</dfn> profile (seccomp is the Linux feature that limits which kernel
  requests a process may make; the profile lists the ones plimsoll's containers may use):
  it solves a 3x3 linear system through SciPy's LAPACK binding (the standard
  linear-algebra library) and takes a fast Fourier transform, and checks the values to
  1e-9.
- **One BLAS thread.** Alpine's OpenBLAS (the linear-algebra library NumPy calls) sizes
  its thread pool from the host's core count, not the run's CPU quota, so without
  `OPENBLAS_NUM_THREADS=1` a run inside a 1-CPU, 256-process <dfn>*cgroup*</dfn> (the
  kernel's cap on the memory, CPU and process count of a group of processes) would start
  a thread per host core. One thread also makes reductions (sums over many numbers, whose
  rounding depends on their order) repeat bit-for-bit across runs, which anything
  comparing results between runs needs. The image's `ENV` reaches every step process;
  the test checks that too.
- **No pip.** A run never installs anything, on any provider (see the limits
  below), and the image does not ship pip, so `python3 -m pip install` fails with
  "No module named pip" rather than reaching for a network the run does not have.
  The test runs that step and requires it to fail.

One caveat on the three version <dfn>*pins*</dfn> on the `apk add` line: `~3.14` fixes
each package's upstream minor version (3.14, 2.4, 1.17) and leaves patch releases and
Alpine's packaging revision free. A patch pin is not an option here, because Alpine keeps
only a package's current build in its index: pinned to 3.14.7, the image stopped building
the day Alpine shipped 3.14.8 (2026-10-01). What a run used is still exact, because the
image's identity is stated on every run. The `node:22-alpine` base tag moves with Alpine's
current release, and `make docker-images` pulls it every time, so the three pins track
whichever Alpine that tag currently carries. An `apk add` failure reading
"unable to select packages ... breaks: world[python3~3.x]" means the base moved;
the fix is a deliberate bump of the pins to what
`apk search -x python3 py3-numpy py3-scipy` reports inside `plimsoll/sandbox`. It
happened on the first build of the file, 2026-09-18, when the tag moved from Alpine
3.23 to 3.24 between the trial and the build.

<a id="a-compiled-model-is-image-content-too"></a>
### A compiled simulator is image content too

A physical simulator compiled to <dfn>*WebAssembly*</dfn> (a portable bytecode format
that runs inside a host program) takes the same path as an interpreter or a package: a
file in the image root, named by a step.
[docker/sim.Dockerfile](../docker/sim.Dockerfile) is that recipe, built by
`make docker-images` as `plimsoll/sandbox-sim:latest`. The image ships:

- `/usr/local/bin/sim-worker`, a C program built on the C API of WasmEdge (a WebAssembly
  runtime) ([docker/sim/worker.c](../docker/sim/worker.c)). It loads one module that was
  compiled ahead of time (AOT) to machine code, once, runs one fresh instance per
  parameter set, and writes one binary artifact (an output file returned with the
  result): per run an int32 step count, then the module's own `sim_width()` float64
  outputs per step (two for the Reference FMUs, three for Lorenz).
- `/models/vanderpol.so` and `/models/bouncingball.so`: two Modelica Reference FMUs (an
  FMU is a simulation model packaged to the FMI standard; these are FMI 3.0 models
  published as C source under BSD-2), compiled to wasm32-wasi by wasi-sdk 27 behind a
  small adapter ([docker/sim/shim.c](../docker/sim/shim.c)), then AOT-compiled by
  WasmEdge 0.17.1 into shared objects; and `/models/lorenz.so`, a simulator of our own
  for the Lorenz system in the same style ([docker/sim/models/Lorenz](../docker/sim/models/Lorenz)).
  Lorenz is there because it is chaotic, and chaos turns a difference in the last bit of
  any one arithmetic result into a checksum miss. `/models/greedy.so` is a test fixture
  proving the worker caps every instance at 256 WebAssembly memory pages (16 MiB): a row
  that asks for more fails alone.
- `/models/cartpole.wasm` and `/oracle/run.mjs`: the <dfn>*physics oracle*</dfn>, which
  tests a caller's program against a simulation. The first is a <dfn>*cart-pole*</dfn>
  simulator (a cart on a rail with a pole hinged on top) with the force on the cart as
  its input, kept as WebAssembly because Node, not the worker, loads it. The second is
  the runner: it runs a caller's <dfn>*controller*</dfn> (a program that reads the
  simulation's state at every step and decides how to push) as a separate process
  against the simulator, and <dfn>*fingerprints*</dfn> the <dfn>*trajectory*</dfn>: it
  takes the SHA-256 hash of the record of every state at every step, so equal
  fingerprints mean identical runs. `examples/oracle` is the demonstration; the page it
  writes replays the recorded runs.
- Seven more simulators in the same form, each a `.wasm` file under `/models` that
  the generic trial runner (`/oracle/judge.mjs`) steps one <dfn>*tick*</dfn> (one fixed time step) at
  a time, with the controller in its own process. The runner takes each scenario from a
  file it deletes before the controller starts and closes its own memory and open files to
  the controller, so a controller can neither read a hidden scenario parameter nor touch
  the plant or the record. The sources are under
  [docker/sim/models](../docker/sim/models):
  - `shower.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/shower/index.html)): a mixing valve, a pipe modelled as a transport delay (water takes a fixed time
    to travel it), and a shower head; a toilet flush drops the cold pressure mid-run. The
    controller sets the hot fraction and must not scald.
  - `buck.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/buck-converter/index.html)): a synchronous <dfn>*buck converter*</dfn> (a power-supply circuit that turns a
    higher DC voltage into a lower one by switching it on and off many times a second),
    modelled by its average over each switching cycle. The controller sets the duty cycle
    (the fraction of each cycle the switch is on) and must hold the output voltage through
    a load step, a sudden change in the current drawn.
  - `ship.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/ship-heading/index.html)): a ship turning by the first-order Nomoto model (the standard simplest model
    of how a ship answers its rudder), with a rudder that lags and can only move so fast,
    and waves pushing it; the controller holds an ordered heading.
  - `blackhole.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/black-hole-orbit/index.html)): a probe falling freely around a non-rotating black hole (on a
    Schwarzschild geodesic) with two small thrusters, asked to hold a circular orbit
    inside the innermost stable one, closer in than any orbit that holds without thrust.
  - `rocket.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/twin-paradox-rocket/index.html)): the relativistic rocket equations in the ship's proper time (the time the
    ship's own clock shows); the controller has to arrive home when Earth's clock reads
    an ordered date.
  - `satclock.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/satellite-clock/index.html)): a navigation satellite's clock, which runs about 38.6
    microseconds a day fast from relativity, steered through a delayed
    measurement.
  - `slits.wasm` ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/double-slit/index.html)): an aperture of sixteen phase-plate segments and a
    64-point screen; the controller sets all sixteen phases to produce a target
    pattern, and the simulator also exports the exact output Jacobian (how fast each
    output changes with each input).

  Each replay page runs two hand-written controllers against the simulator on one
  scenario through the project API, a draft that fails and an accepted one that
  passes, and shows both trajectories and their fingerprints. Those controllers
  and their scoring programs are not published; a controller is the caller's.
  Cart-pole has the same page for its swing-up task, swinging the pole up from hanging
  and balancing it
  ([replay page, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/examples/envs/cartpole-swingup/index.html)).
- `libwasmedge`, the runner and `USER node`, on `node:22-bookworm-slim` rather than
  the Alpine base the other images share: WasmEdge's release binaries are built against
  glibc, which Alpine does not use.

A step names the worker, a simulator and the sweep (the range of parameter values to
run):

```sh
sim-worker /models/vanderpol.so 100 1 20 out.bin 0.1 5.0 2.0 0.0
#          simulator           N  threads t_end out  p0min p0max p1 p2
```

and `out.bin` comes back as an artifact. Three things in that file matter:

- **The simulator lives in the image root, for the same reason NumPy does.** An AOT
  module is machine code that WasmEdge loads with `dlopen`, so it must be mapped
  executable, and every writable mount of a run is `noexec`.
  `sandbox/docker_sim_test.go` proves both halves under the shipped seccomp
  profile: the sweeps run from `/models`, and a byte-identical copy of the simulator
  under `/work` is refused by the loader. Registering a simulator means building an
  image, by design rather than as a workaround.
- **Bit-identity is the test, not a tolerance.** The test compares the SHA-256 of
  each sweep's artifact with a native C run of the same adapter code: 100 parameter
  sets of each Reference FMU, state events (the moments a model switches behaviour,
  such as the ball bouncing) included, and 50 Lorenz rows of 60 s match to the
  byte. WebAssembly's floating-point rules (one rounding per operation, and no fused
  multiply-add, which would skip the rounding between a multiply and an add, outside the
  optional relaxed SIMD instructions) are what turn a numeric comparison into a
  checksum.
- **Every input is pinned.** The WasmEdge tarball by SHA-256 from the release's
  checksum file, the Reference FMUs by the commit behind the tag, the wasi-sdk
  image by digest. The wasm bytes, and so the checksums the test asserts, depend
  on the wasi-sdk digest, the Reference FMUs commit and the shim; the machine code
  depends on the WasmEdge version. Bump any of them deliberately and regenerate
  the checksums from a native run.

The same image also backs a dedicated operation. Point a daemon at it with
`SANDBOX_DOCKER_MODULE_IMAGE=plimsoll/sandbox-sim:latest` and a `Run` with a `module`
payload takes a `model` ID and a parameter table (one row per instance) and returns
every row's status and outputs, decoded from the worker's versioned binary record;
`Describe`, the procedure that reports what a daemon offers, then reports
`supports_module`. It is the project machinery with one step and one artifact, so the
same limits apply (8 MiB of results, the project timeout), and a table whose results
could not fit is refused before any row runs rather than truncated. Nothing about the
image changes between the two paths: the `model` ID `vanderpol` is
`/models/vanderpol.so`, and adding a simulator is adding a line to this recipe's `wasm`
and `build` stages.

### A compiler is image content too

A compiler is one more program in the image root, named by a step.
[docker/wasm-cc.Dockerfile](../docker/wasm-cc.Dockerfile) derives
`plimsoll/sandbox-wasm-cc:latest` from the sim image, built by `make docker-images`,
and adds the C half of wasi-sdk 27 (the toolkit for compiling C to WebAssembly) at
`/opt/wasi-sdk` (on `PATH`): clang, the WebAssembly linker, and a wasm32-wasip1 C
library with its libm, the C math library. It is taken from the same digest-pinned
wasi-sdk image the sim build compiles the simulators with, and adds about 150 MB. A
project whose first step is

```sh
clang --target=wasm32-wasip1 -mexec-model=reactor -O2 -ffp-contract=off -o controller.wasm controller.c
```

gets a WebAssembly module in `/work` with no network, and a later step loads it with
Node. Two things make that work under the run's restrictions:

- **The compiler runs from the image root; its output is data.** clang and the linker
  are native programs, so they live in the read-only root like every other
  executable. What they write into the `noexec` `/work` is a `.wasm` file that Node
  reads and compiles in memory, never a native program the kernel would be asked to
  execute.
- **libm is compiled into the module.** A controller that calls `cos` links
  wasi-libc's implementation, so the module needs nothing from the program hosting it
  for that, and its arithmetic does not depend on the Node that runs it.
  [examples/wasm-controller](../examples/wasm-controller/) runs such a module with an
  empty import object (it gives the module nothing outside itself to call), and its
  README explains why the result still differs, in the last bit, from a JavaScript
  program calling `Math.cos`.

## Limits, stated plainly

- No package installation during a run, ever, on any provider. An agent that must
  install arbitrary packages mid-run is the case general-purpose sandbox virtual
  machines cover and plimsoll does not.
- The image root is read-only in a run. A package that writes beside itself at
  runtime fails with a normal non-zero exit; `/work` and `/tmp` are the writable
  places, and they are the run's sized `noexec` tmpfs mounts.
- Changing the dependency set means rebuilding, re-pinning and redeploying the
  image, and every caller of a daemon sees the same set.
- E2B: its template (the image E2B starts each sandbox from) builds in the toolchain the
  same way (`e2b/e2b.Dockerfile`), and the recipe applies there; this page did not
  exercise that path.
