// Fleet vendor adapter, second version: two changes after the first was qualified.
// inventory() reads the list once, since the profile declares GET /robots the batch
// form of GET /robots/* (the advisor's finding). dispatch() names every order with the
// platform's command ID and, when the vendor's answer is an error or never comes, sends
// the same create again: the vendor answers a repeated command_id with the order it
// already has, so a retry cannot place a second order, and the mission returned is the
// one this command created. It never reads a robot's current mission to guess which
// order is its own.
//
// Two later repairs, after further testing: an error is a refusal only when it says so
// (an earlier version took a 500 as one, and reported "refused" for an order the vendor
// had accepted before answering 500); wait()'s maxPolls bounds every status read, failed
// ones included (an earlier version retried each read up to 40 times); and a status
// answer naming another mission is a failed read, never this mission's state.
"use strict";

const ATTEMPTS = 40; // calls one operation may make, retries included
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let retries = 0;

const statusOf = (e) => Number((String(e && e.message).match(/host api (\d{3})/) || [])[1] || 0);

// A definite refusal: the vendor said no (a 4xx other than 408 timeout and 429 too many
// requests), or the client never sent the call. Anything else (a 5xx, a 408 or 429, no
// answer at all) leaves the outcome unknown: the request may or may not have taken effect.
const refused = (e) => {
  const s = statusOf(e);
  return (s >= 400 && s < 500 && s !== 408 && s !== 429) || /not permitted by sandbox capability/.test(String(e && e.message));
};

const failure = (code, message) => Object.assign(new Error(message), { code });

// Reads and cancels are safe to repeat: try up to ATTEMPTS times while the outcome is unknown.
async function withRetry(fn) {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (e) {
      if (refused(e) || attempt >= ATTEMPTS) throw e;
      retries++;
      await sleep(250);
    }
  }
}

module.exports = {
  async inventory() {
    const list = await withRetry(() => fleet.listRobots());
    return list.robots.map((robot) => ({ id: robot.id, status: robot.status, battery: robot.battery }));
  },

  async dispatch(robotId, target, commandId) {
    for (let attempt = 1; ; attempt++) {
      try {
        const mission = await fleet.createMission(robotId, { target, command_id: commandId });
        return mission.mission_id;
      } catch (e) {
        if (refused(e)) throw failure("refused", "command " + commandId + " was not placed: " + e.message);
        if (attempt >= ATTEMPTS) throw failure("unresolved", "command " + commandId + ": no answer after " + attempt + " attempts; the vendor may or may not hold the order");
        retries++;
        await sleep(250);
      }
    }
  },

  // maxPolls is the number of status reads, failed ones included; 0 makes none.
  async wait(missionId, opts) {
    const maxPolls = opts && Number.isInteger(opts.maxPolls) && opts.maxPolls >= 0 ? opts.maxPolls : 50;
    let polls = 0;
    while (polls < maxPolls) {
      polls++;
      try {
        const mission = await fleet.getMission(missionId);
        if (!mission || mission.id !== missionId) {
          // An answer about another mission is no answer about this one: a failed read.
          retries++;
          if (polls < maxPolls) await sleep(250);
          continue;
        }
        if (mission.status === "done" || mission.status === "failed" || mission.status === "cancelled") {
          return { state: mission.status, polls, retries };
        }
        if (polls < maxPolls) await sleep(20);
      } catch (e) {
        if (refused(e)) throw e;
        retries++;
        if (polls < maxPolls) await sleep(250);
      }
    }
    return { state: "timeout", polls, retries };
  },

  async cancel(missionId) {
    await withRetry(() => fleet.cancelMission(missionId));
  },
};
