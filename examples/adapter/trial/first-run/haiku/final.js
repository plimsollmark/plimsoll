"use strict";

// Retry limits and pauses. Only calls the vendor treats as safe to repeat are retried:
// reads, cancel, and a create carrying its command_id.
const POLL_MS = 250;
const RETRY_MS = 250;
const RETRY_LIMIT = 5;
const DISPATCH_ATTEMPTS = 4;
const DEFAULT_MAX_POLLS = 50;
const RETRYABLE = new Set([500, 502, 503, 504]);
const TERMINAL = { done: "done", failed: "failed", cancelled: "cancelled" };

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function statusOf(err) {
  const m = /^host api (\d{3}):/.exec(String(err && err.message));
  return m ? Number(m[1]) : null;
}

function notPermitted(err) {
  return String(err && err.message).startsWith("host api call not permitted");
}

function withCode(code, err) {
  const e = new Error(`${code}: ${err && err.message ? err.message : String(err)}`);
  e.code = code;
  return e;
}

// Repeats a call that answered 5xx, or no answer at all (reported as 502).
async function retrying(call, attempts = RETRY_LIMIT) {
  for (let i = 1; ; i++) {
    try {
      return await call();
    } catch (err) {
      if (!RETRYABLE.has(statusOf(err)) || i >= attempts) throw err;
      await pause(RETRY_MS * i);
    }
  }
}

module.exports = {
  async inventory() {
    const body = await retrying(() => fleet.listRobots());
    return body.robots.map((r) => ({ id: r.id, status: r.status, battery: r.battery }));
  },

  async dispatch(robotId, target, commandId) {
    let answer;
    for (let attempt = 1; ; attempt++) {
      try {
        answer = await fleet.createMission(robotId, { target, command_id: commandId });
        break;
      } catch (err) {
        if (notPermitted(err)) throw withCode("refused", err);
        const status = statusOf(err);
        if (status !== null && status >= 400 && status < 500) throw withCode("refused", err);
        if (attempt >= DISPATCH_ATTEMPTS) throw withCode("unresolved", err);
        // Safe to repeat: the same command_id answers the original mission, not a second order.
        await pause(RETRY_MS * attempt);
      }
    }
    if (!answer || typeof answer.mission_id !== "string" || answer.mission_id === "") {
      throw withCode("unresolved", new Error("create answered without a mission_id"));
    }
    return answer.mission_id;
  },

  async wait(missionId, opts) {
    const options = opts || {};
    const maxPolls = options.maxPolls ?? DEFAULT_MAX_POLLS;
    let polls = 0;
    while (polls < maxPolls) {
      const mission = await retrying(() => fleet.getMission(missionId));
      polls += 1;
      const state = TERMINAL[mission.status];
      if (state) return { state, polls };
      if (polls < maxPolls) await pause(POLL_MS);
    }
    return { state: "timeout", polls };
  },

  async cancel(missionId) {
    return retrying(() => fleet.cancelMission(missionId));
  },
};
