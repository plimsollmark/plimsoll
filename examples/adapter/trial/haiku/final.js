"use strict";

const MAX_ATTEMPTS = 4;
const RETRY_PAUSE_MS = 200;
const POLL_PAUSE_MS = 250;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function statusOf(err) {
  const m = /^host api (\d{3}):/.exec(err && err.message ? err.message : "");
  return m ? Number(m[1]) : null;
}

function isNotPermitted(err) {
  return /^host api call not permitted by sandbox capability:/.test(err && err.message ? err.message : "");
}

function withCode(code, message, cause) {
  const err = new Error(message, { cause });
  err.code = code;
  return err;
}

module.exports = {
  // Every robot the vendor knows, as [{ id, status, battery }].
  async inventory() {
    const { robots } = await fleet.listRobots();
    return robots.map((r) => ({ id: r.id, status: r.status, battery: r.battery }));
  },

  // Send robot `robotId` to target `{ x, y }` as command `commandId`. Every attempt
  // carries the same command_id, so the vendor answers with the original mission
  // instead of creating a second one.
  async dispatch(robotId, target, commandId) {
    const body = { target: { x: target.x, y: target.y }, command_id: commandId };
    let last = null;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      let res;
      try {
        res = await fleet.createMission(robotId, body);
      } catch (err) {
        const status = statusOf(err);
        // The vendor answered with a rejection, or the call never left the sandbox:
        // no order was accepted for this command.
        if (isNotPermitted(err) || (status !== null && status >= 400 && status < 500)) {
          throw withCode("refused", `dispatch ${commandId}: ${err.message}`, err);
        }
        last = err;
        await sleep(RETRY_PAUSE_MS * attempt);
        continue;
      }

      // The vendor accepted something, but not provably this command's order.
      if (!res || typeof res.mission_id !== "string" || res.command_id !== commandId || res.robot !== robotId) {
        throw withCode("unresolved", `dispatch ${commandId}: vendor answer does not match the order`);
      }
      return res.mission_id;
    }

    throw withCode("unresolved", `dispatch ${commandId}: no answer after ${MAX_ATTEMPTS} attempts`, last);
  },

  // Poll the mission until it ends. Every status read counts toward maxPolls,
  // including reads retried after a transient 502/503.
  async wait(missionId, opts = {}) {
    const maxPolls = opts.maxPolls ?? 50;
    let polls = 0;

    while (polls < maxPolls) {
      polls++;
      let mission;
      try {
        mission = await fleet.getMission(missionId);
      } catch (err) {
        const status = statusOf(err);
        if (status === 502 || status === 503) {
          await sleep(RETRY_PAUSE_MS);
          continue;
        }
        throw err;
      }

      switch (mission.status) {
        case "done":
        case "failed":
        case "cancelled":
          return { state: mission.status, polls };
        case "queued":
        case "running":
          break;
        default:
          throw new Error(`mission ${missionId}: unexpected status ${mission.status}`);
      }
      await sleep(POLL_PAUSE_MS);
    }

    return { state: "timeout", polls };
  },

  // Cancel the mission. Cancelling a finished mission leaves it unchanged, so
  // transient failures are retried.
  async cancel(missionId) {
    for (let attempt = 1; ; attempt++) {
      try {
        return await fleet.cancelMission(missionId);
      } catch (err) {
        const status = statusOf(err);
        if ((status === 502 || status === 503) && attempt < MAX_ATTEMPTS) {
          await sleep(RETRY_PAUSE_MS * attempt);
          continue;
        }
        throw err;
      }
    }
  },
};
