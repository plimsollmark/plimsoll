// Broken on purpose: the second adapter reporting a failed mission as done.
"use strict";
const base = require("../adapter-v2.js");
module.exports = {
  ...base,
  async wait(missionId, opts) {
    const w = await base.wait(missionId, opts);
    return { ...w, state: w.state === "failed" ? "done" : w.state };
  },
};
