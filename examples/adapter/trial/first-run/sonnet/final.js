'use strict';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function statusOf(err) {
  const m = /^host api (\d{3})/.exec(String((err && err.message) || ''));
  return m ? Number(m[1]) : 0;
}

function transient(err) {
  const s = statusOf(err);
  return s === 502 || s === 503 || s === 504 || s === 429 || s === 408 || s === 500;
}

function coded(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

async function retrying(fn, attempts, pauseMs) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      last = err;
      if (!transient(err)) throw err;
      await sleep(pauseMs);
    }
  }
  throw last;
}

module.exports = {
  async inventory() {
    const res = await retrying(() => fleet.listRobots(), 5, 100);
    return (res.robots || []).map((r) => ({ id: r.id, status: r.status, battery: r.battery }));
  },

  async dispatch(robotId, target, commandId) {
    const body = { target: { x: target.x, y: target.y }, command_id: commandId };
    let res;
    try {
      // Repeating a create with the same command_id answers the original mission,
      // so retrying after a lost or failed answer never makes a second order.
      res = await retrying(() => fleet.createMission(robotId, body), 6, 150);
    } catch (err) {
      if (transient(err)) {
        throw coded('unresolved', 'vendor did not confirm command ' + commandId + ': ' + err.message);
      }
      throw coded('refused', 'vendor refused command ' + commandId + ': ' + err.message);
    }
    if (!res || !res.mission_id) {
      throw coded('unresolved', 'vendor answer for command ' + commandId + ' carried no mission');
    }
    if (res.command_id !== undefined && res.command_id !== commandId) {
      throw coded('unresolved', 'vendor answered a different command');
    }
    if (res.robot !== undefined && res.robot !== robotId) {
      throw coded('unresolved', 'vendor answered a mission for another robot');
    }
    return res.mission_id;
  },

  async wait(missionId, opts) {
    const maxPolls = opts && Number.isFinite(opts.maxPolls) ? opts.maxPolls : 50;
    let polls = 0;
    while (polls < maxPolls) {
      polls++;
      let m;
      try {
        m = await fleet.getMission(missionId);
      } catch (err) {
        if (transient(err)) {
          await sleep(100);
          continue;
        }
        throw err;
      }
      const st = m && m.status;
      if (st === 'done' || st === 'failed' || st === 'cancelled') {
        return { state: st, polls };
      }
      await sleep(100);
    }
    return { state: 'timeout', polls };
  },

  async cancel(missionId) {
    // Cancelling is idempotent, so a transient error is safe to retry.
    return retrying(() => fleet.cancelMission(missionId), 6, 150);
  },
};
