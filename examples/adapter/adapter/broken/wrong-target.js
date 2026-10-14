// Broken on purpose: the second adapter with every order sent to (0, 0). Its report
// stays plausible: each mission ends done, at the target the vendor was given.
"use strict";
const base = require("../adapter-v2.js");
module.exports = { ...base, dispatch: (robotId, target, commandId) => base.dispatch(robotId, { x: 0, y: 0 }, commandId) };
