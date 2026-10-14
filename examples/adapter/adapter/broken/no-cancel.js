// Broken on purpose: the second adapter whose cancel() sends nothing.
"use strict";
const base = require("../adapter-v2.js");
module.exports = { ...base, async cancel() {} };
