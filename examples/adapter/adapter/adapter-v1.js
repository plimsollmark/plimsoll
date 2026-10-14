// Fleet vendor adapter, first version, written from PROMPT.md (the contract and the
// description generated from the vendor's OpenAPI document as they stood then) by the
// AI that built this example, in the same session, before the lost-acknowledgement
// scenario existed. It is not an independent agent's answer: its author also wrote the
// harness. Its code is unchanged since it was first committed; only this comment was
// corrected. Its inventory() lists the robots, then reads each one for its state: one
// request per robot. Its dispatch() predates the command ID and ignores it.
"use strict";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let retries = 0;

// The vendor answers 503 while it is degraded; wait a little and try again, a bounded
// number of times. Any other error is the caller's to see.
async function withRetry(fn) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (e) {
      const transient = /host api (503|429)/.test(String(e && e.message));
      if (!transient || attempt >= 40) throw e;
      retries++;
      await sleep(250);
    }
  }
}

module.exports = {
  async inventory() {
    const list = await withRetry(() => fleet.listRobots());
    const out = [];
    for (const summary of list.robots) {
      const robot = await withRetry(() => fleet.getRobot(summary.id));
      out.push({ id: robot.id, status: robot.status, battery: robot.battery });
    }
    return out;
  },

  async dispatch(robotId, target) {
    const mission = await withRetry(() => fleet.createMission(robotId, { target }));
    return mission.mission_id;
  },

  async wait(missionId, opts) {
    const maxPolls = (opts && opts.maxPolls) || 50;
    for (let polls = 1; polls <= maxPolls; polls++) {
      const mission = await withRetry(() => fleet.getMission(missionId));
      if (mission.status === "done" || mission.status === "failed" || mission.status === "cancelled") {
        return { state: mission.status, polls, retries };
      }
      await sleep(20);
    }
    return { state: "timeout", polls: maxPolls, retries };
  },

  async cancel(missionId) {
    await withRetry(() => fleet.cancelMission(missionId));
  },
};
