#!/usr/bin/env node
// Starts the plimsoll MCP server binary for this platform, from the package npm
// installed for it (an optional dependency selected by os and cpu), with this
// process's own stdin, stdout and stderr, so the MCP stream never passes through here.
"use strict";
const { spawn } = require("node:child_process");
const path = require("node:path");

const pkg = `@plimsollmark/mcp-${process.platform}-${process.arch}`;
const exe = process.platform === "win32" ? "plimsoll-mcp.exe" : "plimsoll-mcp";
let bin;
try {
  bin = path.join(path.dirname(require.resolve(`${pkg}/package.json`)), "bin", exe);
} catch {
  process.stderr.write(
    `plimsoll-mcp: no build for ${process.platform}-${process.arch}: ${pkg} is not installed. ` +
      "Builds exist for darwin-arm64, darwin-x64, linux-arm64, linux-x64 and win32-x64; elsewhere, build from source.\n",
  );
  process.exit(2);
}
const child = spawn(bin, process.argv.slice(2), { stdio: "inherit", windowsHide: true });
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => child.kill(signal));
}
child.on("error", (err) => {
  process.stderr.write(`plimsoll-mcp: ${err.message}\n`);
  process.exit(2);
});
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
