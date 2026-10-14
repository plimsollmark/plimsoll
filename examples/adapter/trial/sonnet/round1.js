'use strict';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function statusOf(err) {
  const m = /^host api (\d{3}):/.exec((err && err.message) || '');
  return m ? Number(m[1]) : null;
}

function isTransient(err) {
  const s = statusOf(err);
  return s === 502 || s === 503 || s === 504 || (s !== null && s >= 500);
}

function withTimeout(p, ms) {
  let t;
  const timer = new Promise((_, rej) => {
    t = setTimeout(() => rej(Object.assign(new Error('host api 502: timeout'), { timedOut: true })), ms);
  });
  return Promise.race([p, timer]).finally(() => clearTimeout(t));
}

// Map the platform's command id onto the vendor's allowed alphabet (8-64 of A-Za-z0-9-_),
// injectively, so distinct commands never share a vendor name.
function vendorCommandId(id) {
  const s = String(id);
  if (/^[A-Za-z0-9_-]{8,64}$/.test(s)) return s;
  let out = 'c_';
  for (const ch of s) {
    if (/[A-Za-z0-9_]/.test(ch)) out += ch;
    else out += '-' + ch.codePointAt(0).toString(16) + '-';
  }
  while (out.length < 8) out += '_';
  return out.slice(0, 64);
}

function fail(code, message) {
  return Object.assign(new Error(message), { code });
}

module.exports = {
  async inventory() {
    let lastErr;
    for (let i = 0; i < 5; i++) {
      try {
        const res = await fleet.listRobots();
        return (res.robots || []).map((r) => ({ id: r.id, status: r.status, battery: r.battery }));
      } catch (e) {
        lastErr = e;
        if (!isTransient(e)) throw e;
        await sleep(100);
      }
    }
    throw lastErr;
  },

  async dispatch(robotId, target, commandId) {
    const cid = vendorCommandId(commandId);
    const body = { target: { x: target.x, y: target.y }, command_id: cid };
    // Retrying with the same command_id is idempotent on the vendor: it answers with the
    // original mission, so it can never become a second order.
    for (let attempt = 0; attempt < 5; attempt++) {
      let res;
      try {
        res = await withTimeout(fleet.createMission(robotId, body), 8000);
      } catch (e) {
        const s = statusOf(e);
        if (e.timedOut || s === null ? !/not permitted/.test(e.message || '') : isTransient(e)) {
          await sleep(100 * (attempt + 1));
          continue;
        }
        if (s !== null && s >= 400 && s < 500) {
          throw fail('refused', `vendor refused order: ${e.message}`);
        }
        throw fail('refused', `dispatch failed: ${e.message}`);
      }
      if (!res || !res.mission_id) throw fail('unresolved', 'vendor answer had no mission id');
      if (res.command_id !== undefined && res.command_id !== cid) {
        throw fail('unresolved', 'vendor answered with a different command');
      }
      if (res.robot !== undefined && res.robot !== robotId) {
        throw fail('unresolved', 'vendor answered with a different robot');
      }
      return res.mission_id;
    }
    throw fail('unresolved', 'no usable answer from vendor; order state unknown');
  },

  async wait(missionId, opts) {
    const maxPolls = (opts && opts.maxPolls) || 50;
    let polls = 0;
    let errors = 0;
    while (polls < maxPolls) {
      let m;
      try {
        m = await fleet.getMission(missionId);
      } catch (e) {
        if (isTransient(e) && ++errors <= 30) {
          await sleep(50);
          continue;
        }
        throw e;
      }
      polls++;
      if (m.status === 'done' || m.status === 'failed' || m.status === 'cancelled') {
        return { state: m.status, polls };
      }
      if (polls < maxPolls) await sleep(50);
    }
    return { state: 'timeout', polls };
  },

  async cancel(missionId) {
    let lastErr;
    for (let i = 0; i < 5; i++) {
      try {
        return await fleet.cancelMission(missionId);
      } catch (e) {
        lastErr = e;
        if (!isTransient(e)) throw e;
        await sleep(100);
      }
    }
    throw lastErr;
  },
};
