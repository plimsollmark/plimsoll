// Broken on purpose: the second adapter whose wait() follows the mission to its end,
// then throws instead of returning its state.
"use strict";
const base = require("../adapter-v2.js");
module.exports = { ...base, async wait(missionId, opts) { await base.wait(missionId, opts); throw new Error("wait failed after the mission ended"); } };
