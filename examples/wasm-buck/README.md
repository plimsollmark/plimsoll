# A buck converter controller in C, identical to its JavaScript law to the bit

A buck converter is the power supply that steps a higher voltage down to the one a
chip runs on, by switching its input on for a fraction of each cycle (the duty
cycle). The controller that picks that fraction is firmware, and firmware is usually
C. This example sends such a controller
([controller/controller.c](controller/controller.c)) as a file of an ordinary project
run, compiles it to WebAssembly in the run's first step, and judges it against the
buck plant (`/models/buck.wasm`) in the later steps. The plant, the judge
(`/oracle/judge.mjs`) and the shim are the ones the cart-pole C controller in
[examples/wasm-controller](../wasm-controller/) uses; only the controller and the
plant's name differ.

```sh
make docker-images && go run ./examples/wasm-buck
```

Needs docker and `plimsoll/sandbox-wasm-cc` (`make docker-images` builds it). Run it
from the repository root: it builds the docker provider in process with
`sandbox.Build`, the factory `plimsolld` uses, under the shipped seccomp profile
`docker/seccomp.json`, and proves it with `EnsureReady` before sending anything.

## What the run does

One project run, two files, five steps:

| Step | What it is |
|---|---|
| `clang --target=wasm32-wasip1 -mexec-model=reactor -O2 -ffp-contract=off -Wall -Werror -o controller.wasm controller.c` | compiles the controller inside the sandbox, with `--network none` like every step |
| `node /oracle/judge.mjs controller.js /models/buck.wasm 12 4 0.01 1e-05 0.02 s1.bin` and three more | one per scenario: 10 to 16 V in, a 2 to 8 ohm load that halves at an unknown moment, 2,000 ticks of 10 microseconds |

`controller.js` is the shared shim in
[examples/internal/wasmshim](../internal/wasmshim/controller.js). It has no control
arithmetic and knows nothing about the plant: it instantiates `controller.wasm` with
an empty import object and, for each line the judge sends, calls the module's
exported `control` with every value on the line and then the tick index, here
`double control(double v, double i, int k)`, and writes the duty cycle back.

The program sends that run twice, then runs [controller/reference.js](controller/reference.js),
the same law in JavaScript, through the same judge, and prints per scenario:

```
s1  12 V in, 4 ohm halving at 10 ms   9bcc0a3a963d1185  C = C = JavaScript: true  score 0.908, peak 5.062 V, 2.505 A
s2  10 V in, 8 ohm halving at 6 ms    ef91a39f0afe20aa  C = C = JavaScript: true  score 0.914, peak 5.104 V, 1.340 A
s3  16 V in, 2 ohm halving at 12 ms   b39ccc8ac760e1d8  C = C = JavaScript: true  score 0.888, peak 5.014 V, 5.000 A
s4  14 V in, 4 ohm halving at 15 ms   e040e81c7729ede8  C = C = JavaScript: true  score 0.908, peak 5.058 V, 2.504 A
```

The score is the fraction of ticks from 2 ms on with the output within 0.1 V of
5 V, and zero if the output ever exceeds 6 V or the inductor current 10 A. The floor
is 0.6, from the buck environment's acceptance rule. This controller ramps its
target over the first 3 ms, so in s1 the output first enters the band at 2.99 ms:
99 of the 1,800 judged ticks, 5.5 of the 9.2 points s1 loses. The other 67 ticks
are the dip when the load steps.

The page it writes, [a buck converter controller in C](https://plimsollmark.github.io/plimsoll/examples/wasm-buck/index.html)
(source: [docs/examples/wasm-buck/index.html](../../docs/examples/wasm-buck/index.html)),
charts scenario s1 tick by tick (output voltage, inductor current, duty cycle) and
shows the four scenarios, their fingerprints, and both sources.

## What it proves

- **The C port's trajectory is the JavaScript law's, byte for byte, in every
  scenario.** The C keeps every expression's operand order, the build passes
  `-ffp-contract=off` so no multiply and add are fused, and the law calls no library
  function. What remains is IEEE 754 double arithmetic, which both languages must
  compute identically. The cart-pole port differs from its JavaScript law only
  because it calls `cos`; this one has nothing that could differ.
- **The compile is reproducible.** Two runs produce the same 1,583-byte
  `controller.wasm`, and its SHA-256 is the one in [fingerprints.json](fingerprints.json).
- **The controller regulates.** No overvoltage or overcurrent in any scenario, and
  0.89 to 0.91 of the judged ticks within the band.

[sandbox/docker_wasm_buck_test.go](../../sandbox/docker_wasm_buck_test.go) asserts
all of that under the shipped seccomp profile.

## What it does not prove

- **Not firmware on a chip.** The C uses `double` and runs as WebAssembly. A
  microcontroller build would use its own number format, timer and analog-to-digital
  converter, and would be a different program with its own fingerprint.
- **Not a hardware converter.** The plant is an averaged model: the switching ripple
  is averaged out, so the run judges the control law, not the switching stage.
- **Not isolation beyond the run's tier.** The compiler, the judge and the controller
  run inside one project run, behind the tier the provider reports (`container` under
  runc here).
- **Not that the fingerprint survives a toolchain bump.** The module's bytes depend on
  the wasi-sdk digest and the compile flags. The trajectory would not change as long
  as the arithmetic stays unfused, but the recorded module hash would.
