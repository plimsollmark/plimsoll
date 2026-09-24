// The generic judge of the control-design environments: /oracle/run.mjs with the
// plant and the scenario chosen by data. Loads a stepping plant compiled to
// WebAssembly (sim/shim_env.c, or a standalone module with the same exports),
// runs the caller's controller as a SEPARATE process, and closes the loop one tick
// at a time: the state goes to the controller's stdin as one line, the input
// comes back on its stdout as one line of numbers. Every tick's state and input
// are recorded and written to OUT after the controller has exited, so the
// controller can neither touch the plant's memory nor the record; it sees
// numbers and answers numbers. The judge knows nothing about any plant: what a
// good trajectory is belongs to the environment's verifier, which runs on the
// host and first checks that the artifact it received hashes to the fingerprint
// printed here.
//
//   node judge.mjs [--jac] CONTROLLER.js PLANT.wasm p0 p1 p2 h t_end [OUT]
//
// The plant says how many inputs it takes per tick (sim_nin, 1 if absent); the
// controller answers that many numbers per line, space separated. OUT is
// little-endian float64: per tick the state (sim_width values), then the inputs
// (sim_nin values). Stdout carries one JSON line: the SHA-256 of OUT (the
// fingerprint), the tick count, the tick, the width, the input count, the
// parameters and the final state.
//
// --jac is differentiable access for the controller. Before every tick the judge
// asks the plant for a Jacobian and appends it to the state line after a '|'. A
// plant with ODE states (sim_nx > 0) gives its linearization, "state n A(n*n)
// B(n*nin)"; a plant that exports sim_jac_out gives the derivative of its
// observations with respect to its inputs, "out width nin J(width*nin)". Either
// is also written per tick to jacobians.bin beside OUT. The plant restores its
// state exactly after any perturbation, so the trajectory and its fingerprint are
// the same with and without --jac for the same controller answers; the verdict
// line names the Jacobian file, its kind and its own SHA-256.
import { readFileSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { WASI } from 'node:wasi';

const args = process.argv.slice(2);
let jac = false, answerMs = 2000;
for (;;) {
  if (args[0] === '--jac') { jac = true; args.shift(); continue; }
  if (args[0] === '--answer-ms') { answerMs = Number(args[1]); args.splice(0, 2); continue; }
  break;
}
if (args.length < 7 || !(answerMs > 0)) {
  console.error('usage: node judge.mjs [--jac] [--answer-ms MS] CONTROLLER.js PLANT.wasm p0 p1 p2 h t_end [OUT]');
  process.exit(2);
}
const [controller, plantPath] = args;
const params = args.slice(2, 5).map(Number);
const h = Number(args[5]), tEnd = Number(args[6]);
const outPath = args[7] ?? 'trajectory.bin';
const jacPath = outPath.replace(/[^/]*$/, 'jacobians.bin');
if (![...params, h, tEnd].every(Number.isFinite) || h <= 0 || tEnd <= 0) {
  console.error('parameters, h and t_end must be finite numbers, h and t_end positive');
  process.exit(2);
}
const ticks = Math.round(tEnd / h);

const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {} });
const { instance } = await WebAssembly.instantiate(readFileSync(plantPath), { wasi_snapshot_preview1: wasi.wasiImport });
wasi.initialize(instance);
const ex = instance.exports;
const { alloc, sim_width, sim_init, sim_get, sim_free, memory } = ex;
const width = sim_width();
const nin = ex.sim_nin ? ex.sim_nin() : 1;
const ptr = alloc(8 * width);
const uPtr = alloc(8 * nin);
const state = () => new Float64Array(memory.buffer, ptr, width).slice();
const step = (u) => {
  if (nin === 1 && !ex.sim_step_n) return ex.sim_step(u[0], ptr);
  new Float64Array(memory.buffer, uPtr, nin).set(u);
  return ex.sim_step_n(uPtr, ptr);
};

let jacKind = null, jacLen = 0, jacPtrA = 0, jacPtrB = 0, nx = 0;
if (jac) {
  nx = ex.sim_nx ? ex.sim_nx() : 0;
  if (nx > 0 && ex.sim_jac) {
    jacKind = 'state'; jacLen = nx * nx + nx * nin;
    jacPtrA = alloc(8 * nx * nx); jacPtrB = alloc(8 * nx * nin);
  } else if (ex.sim_jac_out) {
    jacKind = 'out'; jacLen = width * nin;
    jacPtrA = alloc(8 * jacLen);
  } else {
    console.error('this plant offers no Jacobian');
    process.exit(2);
  }
}
const linearization = () => {
  if (jacKind === 'state') {
    const rc = ex.sim_jac(jacPtrA, jacPtrB);
    if (rc < 0) { console.error(`plant linearization failed: ${rc}`); process.exit(1); }
    return [...new Float64Array(memory.buffer, jacPtrA, nx * nx), ...new Float64Array(memory.buffer, jacPtrB, nx * nin)];
  }
  const rc = ex.sim_jac_out(jacPtrA);
  if (rc < 0) { console.error(`plant output Jacobian failed: ${rc}`); process.exit(1); }
  return [...new Float64Array(memory.buffer, jacPtrA, jacLen)];
};
const jacHeader = jacKind === 'state' ? `state ${nx}` : `out ${width} ${nin}`;

const rc = sim_init(params[0], params[1], params[2], h, tEnd);
if (rc < 0) { console.error(`plant refused to initialise: ${rc}`); process.exit(1); }

const child = spawn(process.execPath, ['--no-warnings', controller], { stdio: ['pipe', 'pipe', 'inherit'] });
const answers = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
const record = new Float64Array(ticks * (width + nin));
const jacRecord = jac ? new Float64Array(ticks * jacLen) : null;
let done_ticks = 0;
for (let k = 0; k < ticks; k++) {
  if (sim_get(ptr) < 0) { console.error(`plant state read failed at tick ${k}`); process.exit(1); }
  const s = state();
  let line = s.join(' ');
  if (jac) {
    const l = linearization();
    jacRecord.set(l, k * jacLen);
    line += ' | ' + jacHeader + ' ' + l.join(' ');
  }
  child.stdin.write(line + '\n');
  // A controller gets answerMs per tick (default 2 s; a real controller answers in
  // microseconds). One that never answers fails at the tick it missed, not at the
  // sandbox's whole-run budget, which the first training run spent ten minutes on.
  let timer;
  const late = new Promise((resolve) => { timer = setTimeout(() => resolve({ late: true }), answerMs); });
  const answer = await Promise.race([answers.next(), late]);
  clearTimeout(timer);
  if (answer.late) { console.error(`controller did not answer within ${answerMs} ms at tick ${k}`); child.kill('SIGKILL'); process.exit(3); }
  const { value, done } = answer;
  if (done) { console.error(`controller exited at tick ${k} without answering`); process.exit(3); }
  const u = value.trim().split(/\s+/).map(Number);
  if (u.length !== nin || !u.every(Number.isFinite)) { console.error(`controller answered ${u.length} value(s), not all numbers, at tick ${k}; the plant takes ${nin}`); process.exit(3); }
  record.set(s, k * (width + nin));
  record.set(u, k * (width + nin) + width);
  done_ticks = k + 1;
  const rcs = step(u);
  if (rcs < 0) { console.error(`plant step failed at tick ${k}: ${rcs}`); process.exit(1); }
  if (rcs === 0) break;
}
child.stdin.end();
await new Promise((resolve) => child.on('close', resolve));
sim_free();

const bytes = Buffer.from(record.buffer, 0, done_ticks * (width + nin) * 8);
writeFileSync(outPath, bytes);
const last = record.subarray((done_ticks - 1) * (width + nin), (done_ticks - 1) * (width + nin) + width);
const verdict = {
  fingerprint: createHash('sha256').update(bytes).digest('hex'),
  ticks: done_ticks, h, width, nin, params,
  final: Array.from(last),
};
if (jac) {
  const jb = Buffer.from(jacRecord.buffer, 0, done_ticks * jacLen * 8);
  writeFileSync(jacPath, jb);
  verdict.jacobians = { file: jacPath, kind: jacKind, nx, sha256: createHash('sha256').update(jb).digest('hex') };
}
console.log(JSON.stringify(verdict));
