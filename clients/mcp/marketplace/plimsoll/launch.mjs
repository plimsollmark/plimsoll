#!/usr/bin/env node
// Starts the plugin's pinned plimsoll MCP server from the plugin's own data directory,
// never from the project Claude Code was started in. npx would look in the working
// directory's node_modules for a package of the same name and version before fetching
// one, and read that directory's .npmrc (which can name the shell npm runs commands
// with), so a project could put its own program in the server's place. Here npm runs with
// the plugin's data directory as its working directory and prefix, installs the exact
// pinned version there once with install scripts off, and the server's launcher is run by
// absolute path. Everything npm prints goes to stderr: stdout is the MCP stream.
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import path from "node:path";

const PACKAGE = "@plimsollmark/mcp";
const VERSION = "0.1.0";

const fail = (msg) => {
  process.stderr.write(`plimsoll plugin: ${msg}\n`);
  process.exit(2);
};

const data = process.env.CLAUDE_PLUGIN_DATA;
if (!data || !path.isAbsolute(data)) fail("CLAUDE_PLUGIN_DATA is not set to an absolute path; start the server through Claude Code's plugin");
const prefix = path.join(data, "npm");
mkdirSync(prefix, { recursive: true, mode: 0o700 });
const installed = path.join(prefix, "node_modules", ...PACKAGE.split("/"));

const version = () => {
  try {
    return JSON.parse(readFileSync(path.join(installed, "package.json"), "utf8")).version;
  } catch {
    return "";
  }
};

if (version() !== VERSION) {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const r = spawnSync(npm, ["install", "--prefix", prefix, "--save-exact", "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=error", `${PACKAGE}@${VERSION}`], {
    cwd: prefix,
    stdio: ["ignore", process.stderr, process.stderr],
    shell: process.platform === "win32", // npm.cmd needs a shell; every argument above is fixed
    windowsHide: true,
  });
  if (r.status !== 0 || version() !== VERSION) fail(`installing ${PACKAGE}@${VERSION} into ${prefix} failed`);
}

const child = spawn(process.execPath, [path.join(installed, "bin", "plimsoll-mcp.js"), ...process.argv.slice(2)], { cwd: prefix, stdio: "inherit", windowsHide: true });
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => child.kill(signal));
}
child.on("error", (err) => fail(err.message));
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
