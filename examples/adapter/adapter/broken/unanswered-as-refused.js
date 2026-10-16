// Broken on purpose: the second adapter, except that a create the vendor never answers is
// given up after three tries and reported as refused, as if the vendor had said no.
"use strict";
const base = require("../adapter-v2.js");
module.exports = {
  ...base,
  async dispatch(robotId, target, commandId) {
    let last;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try { return (await fleet.createMission(robotId, { target, command_id: commandId })).mission_id; } catch (e) { last = e; }
    }
    throw Object.assign(new Error("command " + commandId + " was not placed: " + last.message), { code: "refused" });
  },
};
