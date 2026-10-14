// Broken on purpose: the second adapter with r1's orders sent to r3. Every mission it
// reports exists and ends done.
"use strict";
const base = require("../adapter-v2.js");
module.exports = { ...base, dispatch: (robotId, target, commandId) => base.dispatch(robotId === "r1" ? "r3" : robotId, target, commandId) };
