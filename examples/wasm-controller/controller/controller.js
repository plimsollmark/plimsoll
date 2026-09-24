// The Node side of a WebAssembly controller. The judge (/oracle/judge.mjs) spawns
// this file as the controller process and speaks its line protocol: one line of
// state in, one number out, once per tick. This shim does no control arithmetic of
// its own. It instantiates controller.wasm (compiled from controller.c by the run's
// build step) once for the episode, parses each state line exactly as a JavaScript
// controller would, calls the module's exported control function, and writes the
// returned double back.
//
// The module gets an empty import object, so it cannot reach the host at all: no
// WASI, no clock, no file, no host math. A module that imports anything is refused
// before the judge's first tick, with the imports named. Its sin and cos are therefore the
// libm compiled into it, and the numbers it returns depend only on its own bytes
// and the inputs the judge sends.
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

// Everything the module may import. Empty: the controller is pure computation.
const provided = {};

const bytes = readFileSync(new URL('./controller.wasm', import.meta.url));
const module = new WebAssembly.Module(bytes);
const missing = WebAssembly.Module.imports(module).filter((i) => !(provided[i.module] && i.name in provided[i.module]));
if (missing.length > 0) {
  console.error('controller.wasm imports what this shim does not provide: ' +
    missing.map((i) => `${i.module}.${i.name} (${i.kind})`).join(', '));
  process.exit(1);
}
const { exports } = new WebAssembly.Instance(module, provided);
if (typeof exports.control !== 'function') {
  console.error('controller.wasm does not export a function named control');
  process.exit(1);
}
// A reactor module (clang -mexec-model=reactor) runs its constructors here.
if (typeof exports._initialize === 'function') exports._initialize();

let k = 0;
const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  // The state is everything before an optional '|' (the judge's --jac appendix).
  const [x, v, theta, omega] = line.split('|')[0].trim().split(' ').map(Number);
  const u = exports.control(x, v, theta, omega, k++);
  process.stdout.write(u + '\n');
});
