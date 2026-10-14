// Broken on purpose: the second adapter whose inventory() reports a robot the vendor
// does not have, in a status the contract does not have.
"use strict";
const base = require("../adapter-v2.js");
module.exports = { ...base, async inventory() { return [{ id: "imaginary", status: "banana", battery: -50 }]; } };
