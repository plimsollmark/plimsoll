// Vendored from the plimsoll-sim repository at commit d3f9b28 (2026-09-18),
// unchanged below this header. The judge of the physics oracle, baked into
// plimsoll/sandbox-sim as /oracle/run.mjs; a project step names it and the
// caller's controller file.
// The judge. Loads a stepping plant compiled to WebAssembly, runs the caller's
// controller as a SEPARATE process, and closes the loop one 10 ms tick at a
// time: the state goes to the controller's stdin as one line, one number (the
// force) comes back on its stdout. Every tick's state and force are recorded and
// written to OUT after the controller has exited, so the controller can neither
// touch the plant's memory nor the record; it sees numbers and answers a number.
//
//   node run.mjs CONTROLLER.js [PLANT.wasm] [theta0] [t_end] [OUT]
//
// OUT is little-endian float64: per tick x, v, theta, omega, then the force.
// Stdout carries the SHA-256 of OUT (the fingerprint), the tick count, whether
// and when the pole fell (|theta| > pi/2), and the final cart position.
import { readFileSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { WASI } from 'node:wasi';

const [controller, plantPath = '/models/cartpole.wasm', theta0Arg = '0.2', tEndArg = '20', outPath = 'trajectory.bin'] = process.argv.slice(2);
if (!controller) { console.error('usage: node run.mjs CONTROLLER.js [PLANT.wasm] [theta0] [t_end] [OUT]'); process.exit(2); }
const h = 0.01, theta0 = Number(theta0Arg), tEnd = Number(tEndArg);
const ticks = Math.round(tEnd / h);

const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {} });
const { instance } = await WebAssembly.instantiate(readFileSync(plantPath), { wasi_snapshot_preview1: wasi.wasiImport });
wasi.initialize(instance);
const { alloc, sim_width, sim_init, sim_get, sim_step, sim_free, memory } = instance.exports;
const width = sim_width();
const ptr = alloc(8 * width);
const state = () => new Float64Array(memory.buffer, ptr, width).slice();
const rc = sim_init(theta0, 0.5, 1.0, h, tEnd);
if (rc < 0) { console.error(`plant refused to initialise: ${rc}`); process.exit(1); }

const child = spawn(process.execPath, ['--no-warnings', controller], { stdio: ['pipe', 'pipe', 'inherit'] });
const closed = new Promise((resolve) => child.on('close', resolve));
// A controller that exits while ticks remain can close its input before the judge
// sees its output end; the write error is the controller's failure (exit 3).
let feeding = true, fed = 0;
child.stdin.on('error', (err) => {
  if (!feeding) return;
  console.error(`controller closed its input at tick ${fed} (${err.code})`);
  process.exit(3);
});
const answers = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
const record = new Float64Array(ticks * (width + 1));
let fellAt = -1;
for (let k = 0; k < ticks; k++) {
  if (sim_get(ptr) < 0) { console.error(`plant state read failed at tick ${k}`); process.exit(1); }
  const s = state();
  child.stdin.write(s.join(' ') + '\n');
  const { value, done } = await answers.next();
  if (done) { console.error(`controller exited at tick ${k} without answering`); process.exit(3); }
  const text = value.trim();
  const u = text === '' ? NaN : Number(text); // a blank line is no answer, though Number('') is 0
  if (!Number.isFinite(u)) { console.error(`controller answered a non-number at tick ${k}`); process.exit(3); }
  record.set(s, k * (width + 1));
  record[k * (width + 1) + width] = u;
  if (fellAt < 0 && Math.abs(s[2]) > Math.PI / 2) fellAt = k * h;
  const step = sim_step(u, ptr);
  if (step < 0) { console.error(`plant step failed at tick ${k}: ${step}`); process.exit(1); }
  fed = k + 1;
  if (step === 0) break;
}
feeding = false;
child.stdin.end();
// Every tick is answered; a controller that does not exit once its input closes is
// killed after 2 s (the other judge's default answer budget) rather than holding the
// run until the sandbox's whole-run budget.
const linger = setTimeout(() => child.kill('SIGKILL'), 2000);
await closed;
clearTimeout(linger);
sim_free();

const bytes = Buffer.from(record.buffer);
writeFileSync(outPath, bytes);
const last = record.subarray((ticks - 1) * (width + 1), (ticks - 1) * (width + 1) + width);
console.log(JSON.stringify({
  fingerprint: createHash('sha256').update(bytes).digest('hex'),
  ticks, h, width, theta0,
  fell_at: fellAt < 0 ? null : fellAt,
  final_x: last[0], final_theta: last[2],
}));
