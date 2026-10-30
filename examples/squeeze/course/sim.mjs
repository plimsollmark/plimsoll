// Trusted simulation. No controller source is imported or executed in this process.
//
// Ported from the did-it-learn hackathon entry (github.com/carrollco/did-it-learn, tasks/drone/sim.mjs,
// 2026-10-25). The physics is unchanged. One rule changed, the entry's mistake 4: a controller step had
// 50 ms of wall-clock time, so a slow step failed a flight on a busy machine and passed it on an idle
// one (one rebuild scored 52 of 64, then 64 of 64). Here a flight has a budget of the controller
// process's own CPU time, read from /proc, from the moment the runtime has started and before any
// controller code runs: loading the controller and every step count, the runtime's own start does
// not, since it is the same for every controller and under gVisor on a loaded machine was measured
// at most of a second. The wall-clock limit per step is
// only a guard against a controller that hangs.
import { spawn } from 'node:child_process';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { TASK, TAKEOFF, GATES, PAD, random, trialParameters } from './task.mjs';

const FORBIDDEN = /import|require|process|globalThis|constructor|prototype|__proto__|eval|Function|Reflect|Proxy|fetch|Date|performance/;
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const norm = (v) => Math.hypot(v.x, v.y, v.z);
// Node 26 has --permission (and restricts the network too); Google's Managed Agents sandboxes run Node 22, which has
// --experimental-permission (files, child processes and workers restricted; network not). The child holds no secret.
const PERM = process.allowedNodeEnvironmentFlags.has('--permission') ? '--permission'
  : process.allowedNodeEnvironmentFlags.has('--experimental-permission') ? '--experimental-permission' : null;
const copy = (v) => ({ ...v });
const MOTOR_X = [-1, 1, 1, -1], MOTOR_Z = [-1, -1, 1, 1], SPIN = [1, -1, 1, -1];
// HANG_MS is the wall-clock guard on one step: long enough that no load makes an honest step trip it.
// CPU is checked every CPU_EVERY steps and once at the end of the flight.
const HANG_MS = 5000, CPU_EVERY = 10;
// STARTUP_MS bounds the controller's process start, which gVisor on a loaded machine slows the most.
const STARTUP_MS = 15000;

// cpuSeconds is the user plus system CPU time a process has used, from /proc/<pid>/stat (fields 14
// and 15, in clock ticks of 1/100 s, the fixed USER_HZ Linux reports there). The process name in
// field 2 may hold spaces, so the fields are counted after its closing parenthesis.
export function cpuSeconds(pid) {
  const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
  const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
  return (Number(fields[11]) + Number(fields[12])) / 100;
}

export function validateSource(path) {
  if (!PERM) throw new Error('this task requires Node with the permission model (Node 22 or later)');
  const absolute = realpathSync(path);
  if (!statSync(absolute).isFile()) throw new Error('controller must be a file');
  const source = readFileSync(absolute, 'utf8');
  if (Buffer.byteLength(source) > 256 * 1024) throw new Error('controller exceeds 256 KiB source limit');
  const token = source.match(FORBIDDEN)?.[0];
  if (token) throw new Error(`forbidden source token: ${token}`);
  return absolute;
}

class ControllerProcess {
  constructor(artifact) {
    const host = fileURLToPath(new URL('./host.mjs', import.meta.url));
    this.child = spawn(process.execPath, [PERM, `--allow-fs-read=${host}`, `--allow-fs-read=${artifact}`, '--max-old-space-size=48', host, artifact], {
      env: {}, stdio: ['pipe', 'pipe', 'pipe'], cwd: '/',
    });
    this.buffer = ''; this.stderr = ''; this.pending = null; this.dead = null;
    this.child.stderr.on('data', (chunk) => { this.stderr = (this.stderr + chunk).slice(-1200); });
    this.child.stdout.on('data', (chunk) => {
      this.buffer += chunk;
      if (this.buffer.length > 16384) return this.fail(new Error('controller output exceeds protocol limit'));
      let end;
      while ((end = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, end); this.buffer = this.buffer.slice(end + 1);
        if (!this.pending) return this.fail(new Error('unsolicited controller output'));
        const pending = this.pending; this.pending = null; clearTimeout(pending.timer);
        try { pending.resolve(JSON.parse(line)); }
        catch { pending.reject(new Error('malformed controller JSON')); }
      }
    });
    this.child.on('error', (error) => this.fail(error));
    this.child.on('exit', (code, signal) => this.fail(new Error(`controller exited (${signal || code})${this.stderr ? ': ' + this.stderr.slice(-180) : ''}`)));
    this.child.stdin.on('error', (error) => this.fail(error));
  }
  fail(error) {
    this.dead ||= error;
    if (this.pending) {
      clearTimeout(this.pending.timer); this.pending.reject(this.dead); this.pending = null;
    }
    this.child.kill('SIGKILL');
  }
  // message sends payload (when given) and waits for the child's next line.
  message(timeout, payload) {
    if (this.dead) return Promise.reject(this.dead);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail(new Error(payload?.obs ? `controller step exceeded ${HANG_MS} ms of wall time (a hang)` : `controller startup exceeded ${STARTUP_MS} ms`)), timeout);
      this.pending = { resolve, reject, timer };
      if (payload) this.child.stdin.write(JSON.stringify(payload) + '\n');
    });
  }
  // ready waits for the host to boot, reads the CPU time the runtime took to start (before any
  // controller code ran), then lets the host load the controller.
  async ready() {
    const booted = await this.message(STARTUP_MS);
    if (booted.booted !== true) throw new Error('controller host did not boot');
    this.startCpu = this.cpu() ?? 0;
    const message = await this.message(STARTUP_MS, { go: true });
    if (message.ready !== true) throw new Error('controller did not send ready');
  }
  async step(obs) {
    const response = await this.message(HANG_MS, { obs });
    if (response.error) throw new Error(`controller error: ${response.error}`);
    const action = response.action;
    if (!action || typeof action !== 'object' || Array.isArray(action) ||
      !['thrust', 'roll', 'pitch', 'yawRate'].every((k) => typeof action[k] === 'number' && Number.isFinite(action[k]))) {
      throw new Error('malformed action: four finite numbers required');
    }
    return { thrust: clamp(action.thrust, 0, 1), roll: clamp(action.roll, -0.6, 0.6),
      pitch: clamp(action.pitch, -0.6, 0.6), yawRate: clamp(action.yawRate, -2, 2) };
  }
  // cpu is the controller process's CPU time so far, or null once it has exited.
  cpu() { try { return cpuSeconds(this.child.pid); } catch { return null; } }
  // flightCpu is the CPU time since the runtime booted, or null once the process has exited.
  flightCpu() { const c = this.cpu(); return c === null ? null : c - (this.startCpu ?? 0); }
  close() { this.child.kill('SIGKILL'); }
}

export function initialState(parameters) {
  return {
    t: 0, pos: { x: TAKEOFF.x + parameters.offset.x, y: TASK.bodyHeight, z: TAKEOFF.z + parameters.offset.z },
    vel: { x: 0, y: 0, z: 0 }, att: { roll: 0, pitch: 0, yaw: 0 },
    rates: { roll: 0, pitch: 0, yaw: 0 }, motors: [0, 0, 0, 0], integral: { roll: 0, pitch: 0 },
    gateIndex: 0, landedFor: 0, airborne: false, reason: null,
  };
}

function observation(state, rng) {
  const noise = (n) => (rng() + rng() + rng() - 1.5) * n;
  const vector = (v, n) => Object.fromEntries(Object.entries(v).map(([key, value]) => [key, value + noise(n)]));
  return {
    t: +state.t.toFixed(4), pos: vector(state.pos, TASK.positionNoise), vel: vector(state.vel, TASK.velocityNoise),
    att: vector(state.att, TASK.attitudeNoise), rates: vector(state.rates, TASK.rateNoise),
    gateIndex: state.gateIndex,
    nextGate: state.gateIndex < GATES.length ? { centre: copy(GATES[state.gateIndex].centre), normal: copy(GATES[state.gateIndex].normal) } : null,
    pad: { centre: copy(PAD.centre) },
  };
}

function integrate(state, action, parameters, dt) {
  const old = copy(state.pos), { att, rates } = state;
  const inertia = TASK.inertia * parameters.mass / TASK.baseMass;
  const torque = {};
  for (const axis of ['roll', 'pitch']) {
    const error = action[axis] - att[axis];
    state.integral[axis] = clamp(state.integral[axis] + error * dt, -0.35, 0.35);
    torque[axis] = inertia * (65 * error - 13 * rates[axis] + 22 * state.integral[axis]);
  }
  torque.yaw = inertia * 8 * (action.yawRate - rates.yaw);
  for (let i = 0; i < 4; i++) {
    const desired = action.thrust * TASK.maxMotorThrust +
      torque.roll * MOTOR_Z[i] / (4 * TASK.arm) - torque.pitch * MOTOR_X[i] / (4 * TASK.arm) +
      torque.yaw * SPIN[i] / (4 * TASK.yawCoefficient);
    const target = clamp(desired, 0, TASK.maxMotorThrust) * (i === parameters.weakMotor ? 1 - parameters.weakness : 1);
    state.motors[i] += (target - state.motors[i]) * (1 - Math.exp(-dt / parameters.lag));
  }
  const sum = state.motors.reduce((a, b) => a + b, 0);
  const moment = (sign) => state.motors.reduce((a, f, i) => a + f * sign[i], 0);
  rates.roll += (TASK.arm * moment(MOTOR_Z) / inertia - 0.4 * rates.roll) * dt;
  rates.pitch += (-TASK.arm * moment(MOTOR_X) / inertia - 0.4 * rates.pitch) * dt;
  rates.yaw += (TASK.yawCoefficient * moment(SPIN) / inertia - 0.4 * rates.yaw) * dt;
  for (const axis of ['roll', 'pitch', 'yaw']) att[axis] += rates[axis] * dt;
  const bodyX = Math.sin(att.pitch) * Math.cos(att.roll), bodyZ = -Math.sin(att.roll);
  const direction = { x: Math.cos(att.yaw) * bodyX + Math.sin(att.yaw) * bodyZ,
    y: Math.cos(att.pitch) * Math.cos(att.roll), z: -Math.sin(att.yaw) * bodyX + Math.cos(att.yaw) * bodyZ };
  const wind = copy(parameters.baseWind);
  for (const gust of parameters.gusts) if (state.t >= gust.start && state.t < gust.start + gust.duration) {
    wind.x += gust.x; wind.y += gust.y; wind.z += gust.z;
  }
  for (const axis of ['x', 'y', 'z']) {
    const force = sum * direction[axis] + TASK.linearDrag * (wind[axis] - state.vel[axis]);
    state.vel[axis] += (force / parameters.mass - (axis === 'y' ? TASK.gravity : 0)) * dt;
    state.pos[axis] += state.vel[axis] * dt;
  }
  state.t += dt;
  if (state.pos.y > TASK.bodyHeight + 0.08) state.airborne = true;
  if (Math.max(Math.abs(att.roll), Math.abs(att.pitch)) > TASK.flipAngle) state.reason = 'flipped';
  if (Math.abs(state.pos.x) + TASK.bodyRadius >= TASK.room.maxX || Math.abs(state.pos.z) + TASK.bodyRadius >= TASK.room.maxZ || state.pos.y + TASK.bodyHeight >= TASK.room.height) {
    if (norm(state.vel) > TASK.contactCrashSpeed) state.reason = 'wall or ceiling crash';
    state.pos.x = clamp(state.pos.x, TASK.room.minX + TASK.bodyRadius, TASK.room.maxX - TASK.bodyRadius);
    state.pos.z = clamp(state.pos.z, TASK.room.minZ + TASK.bodyRadius, TASK.room.maxZ - TASK.bodyRadius);
    state.pos.y = Math.min(state.pos.y, TASK.room.height - TASK.bodyHeight);
    state.vel.x = 0; state.vel.z = 0; state.vel.y = Math.min(state.vel.y, 0);
  }
  if (state.pos.y <= TASK.bodyHeight) {
    if (state.airborne && (norm(state.vel) > TASK.contactCrashSpeed || Math.max(Math.abs(att.roll), Math.abs(att.pitch)) > TASK.landingTilt * 2)) state.reason = 'floor crash';
    state.pos.y = TASK.bodyHeight; state.vel.y = Math.max(0, state.vel.y);
    state.vel.x *= Math.exp(-12 * dt); state.vel.z *= Math.exp(-12 * dt);
  }
  // Sweep the entire body through each gate plane, rather than testing the centre only.
  for (let i = 0; i < GATES.length; i++) {
    const gate = GATES[i], x = gate.centre.x;
    if ((old.x < x && state.pos.x >= x) || (old.x > x && state.pos.x <= x)) {
      const fraction = (x - old.x) / (state.pos.x - old.x);
      const y = old.y + fraction * (state.pos.y - old.y), z = old.z + fraction * (state.pos.z - old.z);
      const dy = Math.abs(y - gate.centre.y), dz = Math.abs(z - gate.centre.z);
      const half = TASK.gateOpening / 2, outer = half + TASK.gateFrame;
      const fits = dy + TASK.bodyHeight <= half && dz + TASK.bodyRadius <= half;
      const overlapsFrame = dy <= outer + TASK.bodyHeight && dz <= outer + TASK.bodyRadius && !fits;
      if (overlapsFrame) state.reason = 'gate frame collision';
      if (i === state.gateIndex && old.x < x && state.pos.x >= x && fits) state.gateIndex++;
    }
  }
  const error = Math.hypot(state.pos.x - PAD.centre.x, state.pos.z - PAD.centre.z);
  if (state.gateIndex === GATES.length && error <= TASK.landingRadius && state.pos.y <= TASK.bodyHeight + 0.025 &&
      norm(state.vel) < TASK.landingSpeed && Math.max(Math.abs(att.roll), Math.abs(att.pitch)) < TASK.landingTilt) state.landedFor += dt;
  else state.landedFor = 0;
  if (state.landedFor >= TASK.landingHold && !state.reason) state.reason = 'landed';
}

const frame = (s) => ({ t: +s.t.toFixed(4), pos: copy(s.pos), att: copy(s.att), gateIndex: s.gateIndex });

// runTrial flies one seeded flight. cpuBudget is the controller process's CPU time allowed for
// loading the controller and flying, in seconds; fps is how many poses a second a recorded track
// keeps.
export async function runTrial(artifact, seed, { record = false, cpuBudget = 5, fps = 30 } = {}) {
  const parameters = trialParameters(seed), state = initialState(parameters), rng = random((seed ^ 0xa5a5a5a5) >>> 0);
  const controller = new ControllerProcess(artifact);
  const frames = record ? [frame(state)] : undefined;
  let nextFrame = 1 / fps, cpu = 0, startCpu = 0;
  const overBudget = () => {
    const used = controller.flightCpu();
    if (used !== null) cpu = used;
    if (cpu > cpuBudget) throw new Error(`controller used more than ${cpuBudget} s of CPU time`);
  };
  try {
    await controller.ready();
    startCpu = controller.startCpu;
    for (let step = 0; step < Math.round(TASK.duration / TASK.dt) && !state.reason; step++) {
      const action = await controller.step(observation(state, rng));
      if (step % CPU_EVERY === 0) overBudget();
      const previous = record ? frame(state) : null;
      for (let sub = 0; sub < TASK.substeps && !state.reason; sub++) integrate(state, action, parameters, TASK.dt / TASK.substeps);
      if (record && state.t + 1e-8 >= nextFrame) {
        const u = clamp((nextFrame - previous.t) / (state.t - previous.t), 0, 1);
        const interpolate = (a, b) => Object.fromEntries(Object.keys(a).map((axis) => [axis, a[axis] + u * (b[axis] - a[axis])]));
        frames.push({ t: +nextFrame.toFixed(4), pos: interpolate(previous.pos, state.pos), att: interpolate(previous.att, state.att),
          gateIndex: u < 1 ? previous.gateIndex : state.gateIndex });
        nextFrame += 1 / fps;
      }
    }
    const used = controller.flightCpu();
    if (used !== null) cpu = used;
    if (cpu > cpuBudget && (!state.reason || state.reason === 'landed')) state.reason = `controller used more than ${cpuBudget} s of CPU time`;
  } catch (error) { state.reason = error.message; }
  finally { controller.close(); }
  if (record && frames.at(-1).t !== +state.t.toFixed(4)) frames.push(frame(state));
  const result = {
    seed, success: state.reason === 'landed', reason: state.reason || 'time limit', gatesPassed: state.gateIndex,
    landingError: +Math.hypot(state.pos.x - PAD.centre.x, state.pos.z - PAD.centre.z).toFixed(4),
    simulatedSeconds: +state.t.toFixed(3), cpuSeconds: +cpu.toFixed(2), startCpuSeconds: +startCpu.toFixed(2),
  };
  return { result, track: record ? { version: TASK.version, fps, seed, result, frames } : undefined };
}
