# A controller in C, compiled to WebAssembly in the sandbox

A cart-pole swing-up controller written in C
([controller/controller.c](controller/controller.c)), sent as a file of an ordinary
project run, compiled to WebAssembly by the run's first step, and judged against the
cart-pole plant by the later steps. The plant (`/models/cartpole.wasm`) and the judge
(`/oracle/judge.mjs`) are the ones [examples/oracle](../oracle/) uses; what is new is
that the controller is no longer JavaScript.

```sh
make docker-images && go run ./examples/wasm-controller
```

Needs docker. `make docker-images` builds `plimsoll/sandbox-wasm-cc:latest` from
[docker/wasm-cc.Dockerfile](../../docker/wasm-cc.Dockerfile): the simulation image
plus a C-to-WebAssembly compiler (wasi-sdk 27, clang 20, pinned by image digest),
about 150 MB more.

## What the run does

One project run, two files, five steps:

| Step | What it is |
|---|---|
| `clang --target=wasm32-wasip1 -mexec-model=reactor -O2 -ffp-contract=off -Wall -Werror -o controller.wasm controller.c` | compiles the controller inside the sandbox, with `--network none` like every step |
| `node /oracle/judge.mjs controller.js /models/cartpole.wasm 3.14159 0.5 1 0.01 20 s1.bin` and three more | one per scenario: the pole starts hanging (about pi rad), the cart mass varies from 0.8 to 1.2 kg |

The judge spawns [controller/controller.js](controller/controller.js) as the
controller process, exactly as it would a controller written in JavaScript, so the
judge did not change. That file is a shim with no control arithmetic: it instantiates
`controller.wasm` once per episode and, for each line of state the judge sends, calls
the module's exported `double control(double x, double v, double theta, double omega,
int k)` and writes the result back. State between ticks lives in the module's
globals.

The module gets an empty import object. It cannot call the host for anything, not
WASI, not a clock, not `Math.cos`; a module that imports something is refused before
the first tick, with the import named. So `sin` and `cos` are wasi-libc's, compiled
into the module, and the whole closed loop (plant and controller) is WebAssembly.

The page the run writes, live: [a controller in C, judged by its trajectory](https://plimsollmark.github.io/plimsoll/examples/wasm-controller/index.html)
(source: [docs/examples/wasm-controller/index.html](../../docs/examples/wasm-controller/index.html)).
It replays scenario s1, shows the source, the four scenarios and their fingerprints,
and the comparison with the JavaScript law below, every number from the run.

The program sends that run twice, then the two comparison runs described under "Does
it reproduce the JavaScript controller bit for bit?", and prints, per scenario, the trajectory's
fingerprint (the SHA-256 of the judge's per-tick record), whether both runs agree,
whether it is the fingerprint recorded in [fingerprints.json](fingerprints.json), and
the swing-up score: 1 minus the time the final unbroken upright stretch began, over
20 s, and zero if the cart ever leaves the 2.4 m track.

```
s1  theta0 3.14159 cart 1    kg  e28dbdb6a0769585  run 1 = run 2, = recorded  upright from 2.41 s, score 0.879  JavaScript differs at tick 91 (force), 176 (force); state identical at every tick
s2  theta0 3       cart 1    kg  da4e1845a2bcdba0  run 1 = run 2, = recorded  upright from 2.16 s, score 0.892  JavaScript differs at tick 189 (force); state identical at every tick
s3  theta0 3.3     cart 1.2  kg  32e98c0545f135db  run 1 = run 2, = recorded  upright from 2.41 s, score 0.879  JavaScript differs at tick 159 (force), 224 (force); state identical at every tick
s4  theta0 3.14159 cart 0.8  kg  a9a6287641198364  run 1 = run 2, = recorded  upright from 1.05 s, score 0.948  = JavaScript
```

## What it proves

- **A program in a compiled language can be built and judged through the unchanged
  project API.** No daemon change, no new operation, no new environment variable: a
  derived image and two steps. The same recipe holds for any language whose
  compiler targets WebAssembly and fits in an image.
- **The compile is reproducible.** Two runs produce a byte-identical
  `controller.wasm`, and its SHA-256 is the one recorded in `fingerprints.json`.
- **Each trajectory has one fingerprint.** Both runs give the same fingerprint for
  every scenario, and it is the recorded one; the judge's printed fingerprint is the
  hash of the artifact that came back.
- **The controller works.** Upright within 2.5 s and held to 20 s in all four
  scenarios, scoring above the 0.85 floor.

[sandbox/docker_wasm_controller_test.go](../../sandbox/docker_wasm_controller_test.go)
asserts all of that under the shipped seccomp profile, and also that the shim refuses
a module that imports `cos` from the host.

## Does it reproduce the JavaScript controller bit for bit?

No, and the reason is one function. This controller is a line-for-line port of
[controller/reference.js](controller/reference.js), the same swing-up law in
JavaScript. Every expression keeps the
JavaScript operand order, and the build passes `-ffp-contract=off` so no multiply
and add are fused, so the only arithmetic that can differ is `cos`: here it is
wasi-libc's (musl's, descended from fdlibm), linked into the module; in the
JavaScript controller it is V8's `Math.cos`, a different implementation. The two
disagree in the last bit on about one input in a hundred (9,264 of a million angles
drawn uniformly from -1 to 7 rad). Along scenario s1 that shows up at two ticks, 91
and 176, where the C and JavaScript controllers return forces a few representable
doubles apart (2 and 14). The fingerprint hashes the forces as well as the state, so
s1, s2 and s3 differ from the JavaScript fingerprints and s4, where no force differs,
is identical.

What does not differ is the motion. In every scenario the recorded state (cart
position and velocity, pole angle and angular velocity) is bit-identical to the
JavaScript run at every tick, including the ticks after each differing force: the
judge hands the plant each force exactly as the controller wrote it, and a difference
that small is rounded away in the plant's next step. Two fingerprints, one swing.

The run proves `cos` is the whole difference: the same `controller.c`, built with
`-Dcos=host_cos` so that `cos` becomes an import bound to `Math.cos`, gives the
fingerprints `reference.js` gives in all four scenarios, and both are the
`math_cos_fingerprint` values in `fingerprints.json` (the docker test asserts the
same).

Which one is "right" is not the question a fingerprint answers. Both are
deterministic; they are different programs. The point of the all-WebAssembly loop is
that this fingerprint depends only on the module's bytes and the plant's, not on which
Node or which V8 runs them.

## What it does not prove

- **Not isolation beyond the run's tier.** The compiler, the judge and the controller
  run inside one project run, behind whatever tier the daemon reports (`container`
  under runc here). The module's empty import object keeps it from calling the host,
  but that is a property of this shim, not a sandbox boundary; the sandbox boundary
  is the tier.
- **Not that the fingerprint survives a toolchain bump.** The module's bytes depend on
  the wasi-sdk digest and the compile flags; change either and the recorded hashes
  change, deliberately.
- **Not other languages.** Only C is set up: the image carries the C half of wasi-sdk
  (no C++ headers or libraries). Rust or Zig would be another derived image.
- **Not a general agent loop.** Nothing here writes the controller; it is a fixed file.
  The example shows the judging path an agent-written C controller would take.
