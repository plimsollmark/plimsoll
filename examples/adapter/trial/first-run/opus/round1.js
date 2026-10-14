'use strict';

// Adapter for the Fleet Vendor API (v2.4.0). It reaches the vendor only through the
// injected `fleet` client and requires nothing.

const DEFAULT_MAX_POLLS = 50;
const CALL_TIMEOUT_MS = 10000; // a call with no answer by then is treated as a lost answer
const LOOKUP_TIMEOUT_MS = 5000;
const DISPATCH_BUDGET_MS = 30000; // how long dispatch keeps asking before it gives up
const READ_RETRIES = 20; // transient failures one read operation tolerates
const BACKOFF_START_MS = 250;
const BACKOFF_MAX_MS = 2000;
const POLL_START_MS = 100;
const POLL_MAX_MS = 500;
const CANCEL_ROUNDS = 3;
const COMMAND_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const ROBOT_STATUSES = new Set(['idle', 'moving', 'fault']);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const backoff = (n) => Math.min(BACKOFF_MAX_MS, BACKOFF_START_MS * 2 ** Math.min(n, 8));
const present = (v) => v !== undefined && v !== null && v !== '';
const idOf = (v) => (v && typeof v === 'object' ? v.id : v);

function client() {
  const f = typeof fleet !== 'undefined' ? fleet : globalThis.fleet; // eslint-disable-line no-undef
  if (!f) {
    const err = new Error('the fleet client is not available');
    err.notSent = true;
    throw err;
  }
  return f;
}

// A typed operation when the client has it, else the generic call on the same route.
function invoke(name, args, method, path, body) {
  const f = client();
  if (typeof f[name] === 'function') return f[name](...args);
  return body === undefined ? f.call(method, path) : f.call(method, path, body);
}

// Settles with the call, or rejects as a lost answer after ms. A late result of the call
// is ignored, never left as an unhandled rejection.
function withTimeout(start, ms) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      const err = new Error(`no answer within ${ms} ms`);
      err.noAnswer = true;
      reject(err);
    }, ms);
    let pending;
    try {
      pending = Promise.resolve(start());
    } catch (err) {
      pending = Promise.reject(err);
    }
    pending.then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

const messageOf = (err) => String((err && err.message) || err);
const brief = (err) => messageOf(err).slice(0, 300);
const notPermitted = (err) => /not permitted by sandbox capability/.test(messageOf(err));

function statusOf(err) {
  if (!err || err.noAnswer || err.notSent) return 0;
  if (Number.isInteger(err.status)) return err.status;
  const m = /host api (\d{3})\b/.exec(messageOf(err));
  return m ? Number(m[1]) : 0;
}

function fail(code, message, cause, extra) {
  const err = cause === undefined ? new Error(message) : new Error(message, { cause });
  err.code = code;
  return Object.assign(err, extra);
}

// What a failed create says about the order: 'refused' (definitely not taken), 'busy'
// (rate limited, not taken, worth asking again) or 'unknown' (it may have been taken).
function writeOutcome(err) {
  if ((err && err.notSent) || notPermitted(err)) return 'refused';
  const s = statusOf(err);
  if (s === 429) return 'busy';
  if (s >= 400 && s < 500 && s !== 408) return 'refused';
  return 'unknown';
}

function readRetriable(err) {
  if ((err && err.notSent) || notPermitted(err)) return false;
  const s = statusOf(err);
  return s === 0 || s === 408 || s === 429 || s >= 500;
}

async function readWithRetry(what, call) {
  for (let failures = 0; ; failures += 1) {
    try {
      return await withTimeout(call, CALL_TIMEOUT_MS);
    } catch (err) {
      const transient = readRetriable(err);
      if (!transient || failures >= READ_RETRIES) {
        throw fail(transient ? 'unavailable' : 'vendor', `${what}: ${brief(err)}`, err, { status: statusOf(err) });
      }
      await sleep(backoff(failures));
    }
  }
}

function hash53(str, seed) {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i += 1) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(14, '0');
}

// The vendor's idempotency key for a command: the platform's own id when the vendor accepts
// its form, else a stable digest of it, so a repeated dispatch of one command names one order.
function vendorCommandId(commandId) {
  if (!present(commandId)) {
    let s = 'adp-';
    for (let i = 0; i < 24; i += 1) s += Math.floor(Math.random() * 16).toString(16);
    return s;
  }
  const raw = String(commandId);
  if (COMMAND_ID_RE.test(raw)) return raw;
  return `cmd-${hash53(raw, 1)}${hash53(raw, 2)}`;
}

function attribute(answer, robotId, cid) {
  if (!answer || typeof answer !== 'object') return { missing: true };
  const missionId = present(answer.mission_id) ? answer.mission_id : answer.id;
  if (!present(missionId)) return { missing: true };
  if (present(answer.command_id) && String(answer.command_id) !== cid) return { foreign: true };
  const robot = idOf(answer.robot);
  if (present(robot) && String(robot) !== String(robotId)) return { foreign: true };
  return { ok: true, missionId };
}

// Best effort: the robot names its running mission, and that mission names its command.
async function missionOnRobot(robotId, cid) {
  try {
    const robot = await withTimeout(() => invoke('getRobot', [robotId], 'GET', `/robots/${robotId}`), LOOKUP_TIMEOUT_MS);
    const mid = idOf(robot && robot.mission);
    if (!present(mid)) return null;
    const m = await withTimeout(() => invoke('getMission', [mid], 'GET', `/missions/${mid}`), LOOKUP_TIMEOUT_MS);
    if (m && present(m.command_id) && String(m.command_id) === cid) return present(m.id) ? m.id : mid;
  } catch (_) {
    // the lookup is optional; its failure leaves the order unresolved
  }
  return null;
}

async function resolveOrThrow(ctx, cid, reason, cause) {
  const found = await missionOnRobot(ctx.robotId, cid);
  if (present(found)) return found;
  throw fail(
    'unresolved',
    `dispatch ${ctx.commandId}: cannot tell whether the vendor took the order (${reason})`,
    cause,
    { ...ctx, status: cause === undefined ? undefined : statusOf(cause) },
  );
}

function robotStatus(robot) {
  const s = String(robot.status == null ? '' : robot.status).toLowerCase();
  if (ROBOT_STATUSES.has(s)) return s;
  return present(idOf(robot.mission)) ? 'moving' : 'fault';
}

function batteryOf(v) {
  if (typeof v === 'number') return v;
  const n = Number(v);
  return present(v) && Number.isFinite(n) ? n : null;
}

function missionState(mission) {
  const s = String((mission && mission.status) || '').toLowerCase();
  if (s === 'done' || s === 'failed' || s === 'cancelled') return s;
  if (s === 'canceled') return 'cancelled';
  return null;
}

async function inventory() {
  const body = await readWithRetry('list robots', () => invoke('listRobots', [], 'GET', '/robots'));
  const robots = Array.isArray(body) ? body : body && Array.isArray(body.robots) ? body.robots : null;
  if (!robots) throw fail('vendor', 'list robots: the answer holds no robot list');
  return robots
    .filter((r) => r && present(r.id))
    .map((r) => ({ id: r.id, status: robotStatus(r), battery: batteryOf(r.battery) }));
}

async function dispatch(robotId, target, commandId) {
  const cid = vendorCommandId(commandId);
  const body = { target: { x: target && target.x, y: target && target.y }, command_id: cid };
  const path = `/robots/${robotId}/missions`;
  const ctx = { commandId, robotId };
  const deadline = Date.now() + DISPATCH_BUDGET_MS;
  let mayExist = false; // some attempt may have reached the vendor and created the order
  let last;
  for (let attempt = 0; ; attempt += 1) {
    const timeout = Math.max(1000, Math.min(CALL_TIMEOUT_MS, deadline - Date.now()));
    let answer;
    let threw = false;
    try {
      // Every attempt carries the same command_id, so a repeat can only return the original.
      answer = await withTimeout(() => invoke('createMission', [robotId, body], 'POST', path, body), timeout);
    } catch (err) {
      threw = true;
      last = err;
    }
    if (!threw) {
      const seen = attribute(answer, robotId, cid);
      if (seen.ok) return seen.missionId;
      if (seen.foreign) return resolveOrThrow(ctx, cid, 'the vendor answered with a mission of another command or robot');
      mayExist = true;
      last = new Error('the vendor accepted the request but named no mission');
    } else {
      const outcome = writeOutcome(last);
      if (outcome === 'refused') {
        if (mayExist) return resolveOrThrow(ctx, cid, `refused after an attempt that may have created it: ${brief(last)}`, last);
        throw fail('refused', `dispatch ${commandId}: the order was refused: ${brief(last)}`, last, { ...ctx, status: statusOf(last) });
      }
      if (outcome === 'unknown') mayExist = true;
    }
    const delay = backoff(attempt);
    if (Date.now() + delay >= deadline) break;
    await sleep(delay);
  }
  if (!mayExist) {
    throw fail('refused', `dispatch ${commandId}: the vendor kept declining the order as rate limited: ${brief(last)}`, last, { ...ctx, status: statusOf(last) });
  }
  return resolveOrThrow(ctx, cid, `no answer could be attributed: ${brief(last)}`, last);
}

async function wait(missionId, opts) {
  if (!present(missionId)) throw fail('invalid', 'wait: no mission id');
  const o = opts || {};
  const requested = o.maxPolls == null ? NaN : Number(o.maxPolls);
  const maxPolls = Number.isFinite(requested) && requested >= 0 ? Math.floor(requested) : DEFAULT_MAX_POLLS;
  const path = `/missions/${missionId}`;
  let polls = 0;
  let failures = 0;
  let pause = POLL_START_MS;
  while (polls < maxPolls) {
    let mission;
    try {
      mission = await withTimeout(() => invoke('getMission', [missionId], 'GET', path), CALL_TIMEOUT_MS);
    } catch (err) {
      const transient = readRetriable(err);
      if (!transient || failures >= READ_RETRIES) {
        throw fail(transient ? 'unavailable' : 'vendor', `wait for mission ${missionId}: ${brief(err)}`, err, {
          missionId,
          polls,
          status: statusOf(err),
        });
      }
      await sleep(backoff(failures));
      failures += 1;
      continue;
    }
    polls += 1;
    const state = missionState(mission); // a failed mission is reported, never retried
    if (state) return { state, polls };
    if (polls < maxPolls) {
      await sleep(pause);
      pause = Math.min(POLL_MAX_MS, Math.round(pause * 1.5));
    }
  }
  return { state: 'timeout', polls };
}

async function cancel(missionId) {
  if (!present(missionId)) throw fail('invalid', 'cancel: no mission id');
  const path = `/missions/${missionId}/cancel`;
  let mission = null;
  for (let round = 0; round < CANCEL_ROUNDS; round += 1) {
    // Cancelling is idempotent (a finished mission is unchanged), so a lost answer is re-sent.
    mission = await readWithRetry(`cancel mission ${missionId}`, () => invoke('cancelMission', [missionId], 'POST', path));
    const state = missionState(mission);
    if (state) return { state };
    await sleep(backoff(round));
  }
  return { state: String((mission && mission.status) || 'unknown').toLowerCase() };
}

module.exports = { inventory, dispatch, wait, cancel };
