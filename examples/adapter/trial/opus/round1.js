"use strict";

// Adapter for the Fleet Vendor API (v2.4.0). Every vendor call goes through the injected
// `fleet` client; nothing is imported.

const CALL_TIMEOUT_MS = 10000;
const BACKOFF_MS = 200;
const BACKOFF_MAX_MS = 2000;
const CALL_TRIES = 5;
const DISPATCH_TRIES = 8;
const DISPATCH_BUDGET_MS = 30000;
const CANCEL_ROUNDS = 3;
const DEFAULT_MAX_POLLS = 50;
const POLL_MIN_MS = 100;
const POLL_MAX_MS = 500;
const NOT_FOUND_TRIES = 3;

const ROBOT_STATUSES = new Set(["idle", "moving", "fault"]);
const TERMINAL = { done: "done", failed: "failed", cancelled: "cancelled", canceled: "cancelled" };
const COMMAND_ID = /^[A-Za-z0-9_-]{8,64}$/;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const backoff = (n) => Math.min(BACKOFF_MAX_MS, BACKOFF_MS * 2 ** (n - 1));

function codedError(code, message, cause) {
  const err = new Error(message, cause ? { cause } : undefined);
  err.code = code;
  return err;
}

function statusOf(err) {
  if (err && Number.isInteger(err.status)) return err.status;
  const match = /host api (\d{3})\b/.exec(String(err && err.message));
  return match ? Number(match[1]) : null;
}

// "lost": the call may or may not have reached the vendor; "busy": the vendor turned it away
// for now; "rejected": the vendor refused it; "denied": the sandbox never sent it.
function classify(err) {
  if (err && err.code === "timeout") return "lost";
  if (/not permitted/.test(String(err && err.message))) return "denied";
  const status = statusOf(err);
  if (status === 429) return "busy";
  if (status !== null && status >= 400 && status < 500 && status !== 408) return "rejected";
  return "lost";
}

// Rejects with a "timeout" error when the vendor never answers; the abandoned call's own
// outcome is swallowed so it cannot surface as an unhandled rejection.
function withTimeout(call, ms = CALL_TIMEOUT_MS) {
  const pending = Promise.resolve(call);
  pending.catch(() => {});
  let timer;
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => reject(codedError("timeout", `no answer from the vendor within ${ms} ms`)), ms);
  });
  return Promise.race([pending, expiry]).finally(() => clearTimeout(timer));
}

// For calls that are safe to repeat: reads and cancels.
async function withRetries(send, tries) {
  for (let attempt = 1; ; attempt++) {
    try {
      return await withTimeout(send());
    } catch (err) {
      const kind = classify(err);
      if ((kind !== "lost" && kind !== "busy") || attempt >= tries) throw err;
      await sleep(backoff(attempt));
    }
  }
}

// cyrb53, rendered as 11 base-36 digits.
function hash(str, seed) {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36).padStart(11, "0");
}

// The vendor only dedupes command ids of 8-64 [A-Za-z0-9_-]; anything else is mapped to a
// stable id of that form, so a repeated create still names the same order.
function vendorCommandId(commandId) {
  if (commandId == null || commandId === "") {
    return `adp-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
  }
  const raw = String(commandId);
  if (COMMAND_ID.test(raw)) return raw;
  return `cmd-${hash(raw, 1)}-${hash(raw, 2)}`;
}

// Best effort, read-only: the robot's running mission, if it is the one this command created.
async function findMission(robotId, cid) {
  try {
    const robot = await withRetries(() => fleet.getRobot(robotId), CALL_TRIES);
    if (!robot || robot.mission == null) return null;
    const mission = await withRetries(() => fleet.getMission(robot.mission), CALL_TRIES);
    return mission && mission.command_id === cid ? robot.mission : null;
  } catch {
    return null;
  }
}

function robotStatus(robot) {
  const status = String(robot.status || "").toLowerCase();
  if (ROBOT_STATUSES.has(status)) return status;
  if (status === "faulted" || status === "error") return "fault";
  return robot.mission ? "moving" : "idle";
}

function pollLimit(value) {
  const n = value == null ? NaN : Number(value);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : DEFAULT_MAX_POLLS;
}

module.exports = {
  async inventory() {
    const res = await withRetries(() => fleet.listRobots(), CALL_TRIES);
    const robots = Array.isArray(res) ? res : (res && res.robots) || [];
    return robots.map((robot) => ({ id: robot.id, status: robotStatus(robot), battery: robot.battery }));
  },

  async dispatch(robotId, target, commandId) {
    const cid = vendorCommandId(commandId);
    const body = { target: { x: target.x, y: target.y }, command_id: cid };
    const deadline = Date.now() + DISPATCH_BUDGET_MS;
    // Set once an attempt may have reached the vendor: from then on a refusal no longer proves
    // that no order exists, because the earlier attempt may have created it.
    let uncertain = false;
    let last;
    for (let attempt = 1; attempt <= DISPATCH_TRIES; attempt++) {
      if (attempt > 1) {
        if (Date.now() >= deadline) break;
        await sleep(backoff(attempt - 1));
      }
      try {
        // Every attempt carries the same command_id, so a repeat answers the original mission
        // instead of placing a second order.
        const created = await withTimeout(fleet.createMission(robotId, body));
        const missionId = created && (created.mission_id ?? created.id);
        if (missionId != null && (created.command_id == null || created.command_id === cid)) return missionId;
        last = new Error(`unexpected answer to create: ${JSON.stringify(created)}`);
        uncertain = true;
        break;
      } catch (err) {
        last = err;
        const kind = classify(err);
        if (kind === "rejected" || kind === "denied") {
          if (!uncertain) throw codedError("refused", `command ${commandId} refused: ${err.message}`, err);
          break;
        }
        if (kind === "lost") uncertain = true;
      }
    }
    if (!uncertain) {
      throw codedError("refused", `command ${commandId} turned away: ${last && last.message}`, last);
    }
    const found = await findMission(robotId, cid);
    if (found != null) return found;
    throw codedError(
      "unresolved",
      `cannot tell whether command ${commandId} became an order: ${last && last.message}`,
      last,
    );
  },

  async wait(missionId, opts) {
    const maxPolls = pollLimit(opts && opts.maxPolls);
    let polls = 0;
    let pause = POLL_MIN_MS;
    let missing = 0;
    while (polls < maxPolls) {
      if (polls > 0) {
        await sleep(pause);
        pause = Math.min(POLL_MAX_MS, Math.round(pause * 1.5));
      }
      polls++;
      let mission;
      try {
        mission = await withTimeout(fleet.getMission(missionId));
      } catch (err) {
        const kind = classify(err);
        if (kind === "lost" || kind === "busy") continue;
        // A mission only just created may not be readable yet.
        if (statusOf(err) === 404 && ++missing <= NOT_FOUND_TRIES) continue;
        throw err;
      }
      const state = TERMINAL[String(mission && mission.status).toLowerCase()];
      if (state) return { state, polls };
    }
    return { state: "timeout", polls };
  },

  async cancel(missionId) {
    for (let round = 1; ; round++) {
      // Cancelling is idempotent on the vendor: a finished or cancelled mission is left unchanged.
      const mission = await withRetries(() => fleet.cancelMission(missionId), CALL_TRIES);
      const status = mission && mission.status;
      if (status == null || TERMINAL[String(status).toLowerCase()]) return;
      if (round >= CANCEL_ROUNDS) {
        throw codedError("unresolved", `mission ${missionId} still ${status} after cancel`);
      }
      await sleep(backoff(round));
    }
  },
};
