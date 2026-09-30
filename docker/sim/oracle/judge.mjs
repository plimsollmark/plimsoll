// The generic trial runner of the control-design environments: /oracle/run.mjs with the
// plant and the scenario chosen by data. Loads a stepping plant compiled to
// WebAssembly (sim/shim_env.c, or a standalone module with the same exports),
// runs the caller's controller as a SEPARATE process, and closes the loop one tick
// at a time: the state goes to the controller's stdin as one line, the input
// comes back on its stdout as one line of numbers. Every tick's state and input
// are recorded and written to OUT after the controller has exited. The runner
// knows nothing about any plant: what a good trajectory is belongs to the
// environment's grader, which runs on the host and first checks that the artifact
// it received hashes to the fingerprint printed here.
//
//   node judge.mjs [--jac] [--answer-ms MS] CONTROLLER.js PLANT.wasm SCENARIO h t_end [OUT]
//
// SCENARIO is a file holding the plant's three scenario parameters (whitespace
// separated). The runner reads it and deletes it before the controller starts.
//
// What the controller cannot reach. It runs under this process's uid in the same
// container, so before doing anything else the runner re-executes itself in place
// with the image's runner guard preloaded (the library the project runner uses),
// which makes it non-dumpable: its memory and descriptors are then
// closed to same-uid processes whatever the host's ptrace (Yama) setting, and a
// same-uid probe must prove that before the scenario is read. The scenario never
// appears on a command line, which any process can read from /proc; it arrives in a
// file that is gone before the controller exists. So the controller sees the
// scenario only through the plant's behavior, and cannot read or write the plant,
// the record or the fingerprint in this process. Limits: a scenario file is hidden
// only from the controller of the run that deletes it, not from anything an earlier
// step of the same project runs, so a secret scenario needs a run of its own; and a
// controller that leaves a child behind can still rewrite OUT after it is written,
// which is why the grader checks the artifact against the printed fingerprint.
//
// The plant says how many inputs it takes per tick (sim_nin, 1 if absent); the
// controller answers that many numbers per line, space separated. OUT is
// little-endian float64: per tick the state (sim_width values), then the inputs
// (sim_nin values). Stdout carries one JSON line: the SHA-256 of OUT (the
// fingerprint), the tick count, the tick, the width, the input count, the
// parameters and the final state.
//
// --jac is differentiable access for the controller. Before every tick the runner
// asks the plant for a Jacobian and appends it to the state line after a '|'. A
// plant with ODE states (sim_nx > 0) gives its linearization, "state n A(n*n)
// B(n*nin)"; a plant that exports sim_jac_out gives the derivative of its
// observations with respect to its inputs, "out width nin J(width*nin)". Either
// is also written per tick to jacobians.bin beside OUT. The plant restores its
// state exactly after any perturbation, so the trajectory and its fingerprint are
// the same with and without --jac for the same controller answers; the run summary
// line names the Jacobian file, its kind and its own SHA-256.
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { WASI } from 'node:wasi';

const GUARD = '/usr/local/lib/plimsoll-runner-guard.so';
if (process.env.PLIMSOLL_JUDGE_GUARD !== GUARD) {
  // Same pid, new image: the guard's constructor runs before any of this code again.
  process.execve(process.execPath,
    [process.execPath, ...process.execArgv, fileURLToPath(import.meta.url), ...process.argv.slice(2)],
    { ...process.env, LD_PRELOAD: GUARD, PLIMSOLL_JUDGE_GUARD: GUARD });
}
// The guard stays in this process only; the controller and the probe start without it.
delete process.env.LD_PRELOAD;
delete process.env.PLIMSOLL_JUDGE_GUARD;
{
  // A loader can ignore a missing preload library, so prove the effect with the project
  // runner's own probe: a same-uid child must be refused this process's descriptors and
  // memory. (Its environment holds nothing the controller may not see.)
  const probe = `const fs=require("node:fs");const p="/proc/"+process.ppid;const out=[];
for(const [f,m] of [["/fd/0",fs.constants.O_RDONLY],["/fd/1",fs.constants.O_RDONLY],["/fd/1",fs.constants.O_WRONLY],["/mem",fs.constants.O_RDONLY]]){
try{fs.closeSync(fs.openSync(p+f,m));out.push("open");}catch(e){out.push(e.code||"unknown");}}
process.stdout.write(out.join(","));`;
  const r = spawnSync(process.execPath, ['-e', probe], { encoding: 'utf8', timeout: 5000, maxBuffer: 4096 });
  const codes = (r.stdout ?? '').split(',');
  if (r.error || r.status !== 0 || codes.length !== 4 || codes.some((c) => c !== 'EACCES' && c !== 'EPERM')) {
    console.error(`the trial runner could not prove it is closed to the controller (${r.stdout || r.error})`);
    process.exit(1);
  }
}

const args = process.argv.slice(2);
let jac = false, answerMs = 2000;
for (;;) {
  if (args[0] === '--jac') { jac = true; args.shift(); continue; }
  if (args[0] === '--answer-ms') { answerMs = Number(args[1]); args.splice(0, 2); continue; }
  break;
}
if (args.length < 5 || !(answerMs > 0)) {
  console.error('usage: node judge.mjs [--jac] [--answer-ms MS] CONTROLLER.js PLANT.wasm SCENARIO h t_end [OUT]');
  process.exit(2);
}
const [controller, plantPath, scenarioPath] = args;
let params;
try {
  params = readFileSync(scenarioPath, 'utf8').trim().split(/\s+/).map(Number);
  unlinkSync(scenarioPath);
} catch (e) {
  console.error(`scenario file ${scenarioPath}: ${e.code || e.message} (it must be a readable, deletable file)`);
  process.exit(2);
}
const h = Number(args[3]), tEnd = Number(args[4]);
const outPath = args[5] ?? 'trajectory.bin';
const jacPath = outPath.replace(/[^/]*$/, 'jacobians.bin');
if (params.length !== 3 || ![...params, h, tEnd].every(Number.isFinite) || h <= 0 || tEnd <= 0) {
  console.error('the scenario must hold three finite numbers, and h and t_end must be finite and positive');
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
const closed = new Promise((resolve) => child.on('close', resolve));
const answers = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
const record = new Float64Array(ticks * (width + nin));
const jacRecord = jac ? new Float64Array(ticks * jacLen) : null;
let done_ticks = 0;
// A controller that exits while ticks remain can close its input before the runner
// sees its output end. The next write then fails with EPIPE, which is the
// controller's failure (exit 3), not the runner's. Once every tick is fed, a write
// error no longer matters.
let feeding = true;
child.stdin.on('error', (err) => {
  if (!feeding) return;
  console.error(`controller closed its input at tick ${done_ticks} (${err.code})`);
  process.exit(3);
});
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
  // A blank line is no answer: ''.split(/\s+/) is [''], which Number reads as 0.
  const text = value.trim();
  const u = text === '' ? [] : text.split(/\s+/).map(Number);
  if (u.length !== nin || !u.every(Number.isFinite)) { console.error(`controller answered ${u.length} value(s), not all numbers, at tick ${k}; the plant takes ${nin}`); process.exit(3); }
  record.set(s, k * (width + nin));
  record.set(u, k * (width + nin) + width);
  done_ticks = k + 1;
  const rcs = step(u);
  if (rcs < 0) { console.error(`plant step failed at tick ${k}: ${rcs}`); process.exit(1); }
  if (rcs === 0) break;
}
feeding = false;
child.stdin.end();
// Every tick is answered, so the trajectory is complete. A controller that does not
// exit once its input closes gets one answer budget, then is killed, rather than
// holding the run until the sandbox's whole-run budget.
const linger = setTimeout(() => child.kill('SIGKILL'), answerMs);
await closed;
clearTimeout(linger);
sim_free();

const bytes = Buffer.from(record.buffer, 0, done_ticks * (width + nin) * 8);
writeFileSync(outPath, bytes);
const last = record.subarray((done_ticks - 1) * (width + nin), (done_ticks - 1) * (width + nin) + width);
const summary = {
  fingerprint: createHash('sha256').update(bytes).digest('hex'),
  ticks: done_ticks, h, width, nin, params,
  final: Array.from(last),
};
if (jac) {
  const jb = Buffer.from(jacRecord.buffer, 0, done_ticks * jacLen * 8);
  writeFileSync(jacPath, jb);
  summary.jacobians = { file: jacPath, kind: jacKind, nx, sha256: createHash('sha256').update(jb).digest('hex') };
}
console.log(JSON.stringify(summary));
