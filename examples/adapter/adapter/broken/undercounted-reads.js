// Broken on purpose: the second adapter whose wait() reads the mission once more than
// its budget allows, then reports a single read.
"use strict";
const base = require("../adapter-v2.js");
module.exports = {
  ...base,
  async wait(missionId, opts) {
    const w = await base.wait(missionId, opts);
    for (let n = w.polls; n <= opts.maxPolls; n++) await fleet.getMission(missionId);
    return { state: w.state, polls: 1 };
  },
};
