// Broken on purpose: the second adapter whose inventory() reports no robots.
"use strict";
const base = require("../adapter-v2.js");
module.exports = { ...base, async inventory() { return []; } };
