// Broken on purpose: the second adapter whose wait() does the reads and then reports a
// count with no state.
"use strict";
const base = require("../adapter-v2.js");
module.exports = { ...base, async wait(missionId, opts) { const w = await base.wait(missionId, opts); return { polls: w.polls }; } };
