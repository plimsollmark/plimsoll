// A session's JavaScript interpreter: one Node process that outlives the calls of
// a session, so what a cell defines is there for the next cell. It is started by
// the launcher in launch.sh with its stdout and stderr on two FIFOs, and runs one
// cell per connection to its control socket, in arrival order. The relay
// (relay.js) reads the FIFOs between the cell's start and end markers.
//
// Cells run as scripts in this process's global scope. Top-level let, const and
// class declarations are rewritten to var first (parsed with the acorn copy inside
// Node), so a later cell may declare a name again, as a notebook allows, and a cell
// that throws leaves no name stuck uninitialized. A cell with top-level await is
// wrapped by Node's own REPL transform, which keeps its declarations global. When
// Node's internals are not reachable, cells run unrewritten.
//
// Everything here sits inside one function, so none of the interpreter's own names
// is a global a cell could collide with.
(() => {
"use strict";
const fs = require("node:fs");
const net = require("node:net");
const util = require("node:util");
const vm = require("node:vm");

const dir = process.argv[1];
let acorn = null;
let topLevelAwait = null;
try {
  acorn = require("internal/deps/acorn/acorn/dist/acorn");
  topLevelAwait = require("internal/repl/await").processTopLevelAwait;
} catch {}

// Errors outside a cell (a timer, a rejected promise nobody awaited) are printed,
// never fatal: the interpreter's state belongs to the session.
process.on("uncaughtException", (e) => printError(e));
process.on("unhandledRejection", (e) => printError(e));

// printError prints an error as Node prints an uncaught one, without the frames of
// this interpreter below the cell.
function printError(e) {
  let text;
  if (e instanceof Error) {
    const lines = String(e.stack || e).split("\n");
    const cut = lines.findIndex((l) => /^\s+at .*(\(node:vm:|\[eval\])/.test(l));
    text = (cut < 0 ? lines : lines.slice(0, cut)).join("\n");
  } else {
    text = "Uncaught " + util.inspect(e);
  }
  try { process.stderr.write(text + "\n"); } catch {}
}

// rewrite turns top-level let/const into var and class declarations into var
// assignments, by offsets in the source, so everything else is untouched.
function rewrite(code) {
  if (!acorn) return code;
  let ast;
  try {
    ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "script", allowAwaitOutsideFunction: true, allowHashBang: true });
  } catch {
    return code; // the engine reports the syntax error itself
  }
  const edits = [];
  for (const node of ast.body) {
    if (node.type === "VariableDeclaration" && node.kind !== "var") {
      edits.push({ at: node.start, cut: node.kind.length, text: "var" });
    } else if (node.type === "ClassDeclaration" && node.id) {
      edits.push({ at: node.start, cut: 0, text: "var " + node.id.name + " = " });
      edits.push({ at: node.end, cut: 0, text: ";" });
    }
  }
  edits.sort((a, b) => b.at - a.at);
  let out = code;
  for (const e of edits) out = out.slice(0, e.at) + e.text + out.slice(e.at + e.cut);
  return out;
}

let cells = 0;

async function runCell(code) {
  cells++;
  const filename = "cell" + cells + ".js";
  const source = rewrite(code);
  let wrapped = null;
  if (topLevelAwait) {
    try { wrapped = topLevelAwait(source); } catch { wrapped = null; }
  }
  let value;
  if (wrapped) {
    const out = await vm.runInThisContext(wrapped, { filename, displayErrors: true });
    value = out === undefined ? undefined : out.value;
  } else {
    value = vm.runInThisContext(source, { filename, displayErrors: true });
    if (value instanceof Promise) value = await value;
  }
  if (value !== undefined) {
    globalThis._ = value;
    process.stdout.write(util.inspect(value, { depth: 4, maxArrayLength: 100, maxStringLength: 10000 }) + "\n");
  }
}

function marker(kind, nonce) {
  return Buffer.from("\0plimsoll-cell-" + kind + "-" + nonce + "\0");
}

function writeAll(fd, buf) {
  for (let off = 0; off < buf.length;) off += fs.writeSync(fd, buf, off);
}

let queue = Promise.resolve();
const server = net.createServer((conn) => {
  let input = "";
  let taken = false; // one cell per connection: later chunks never queue it again
  conn.setEncoding("utf8");
  conn.on("data", (chunk) => {
    if (taken) return;
    input += chunk;
    const nl = input.indexOf("\n");
    if (nl < 0) return;
    taken = true;
    const req = JSON.parse(input.slice(0, nl));
    queue = queue.then(async () => {
      writeAll(1, marker("start", req.nonce));
      writeAll(2, marker("start", req.nonce));
      let status = "ok";
      try {
        await runCell(req.code);
      } catch (e) {
        status = "error";
        printError(e);
      }
      try { writeAll(1, marker("end", req.nonce)); } catch {}
      try { writeAll(2, marker("end", req.nonce)); } catch {}
      conn.end(JSON.stringify({ status }) + "\n");
    });
  });
  conn.on("error", () => {});
});
server.listen(dir + "/ctl.sock", () => {
  fs.writeFileSync(dir + "/ready", String(process.pid));
});
})();
