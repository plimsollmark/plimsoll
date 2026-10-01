// A session interpreter's relay, so a cell costs a line on a pipe instead of a new
// process. The provider starts it once per interpreter as a
// long-lived command whose stdin and stdout it holds, and the sweep keeps it with
// the interpreter. Arguments: the interpreter's directory and the work directory.
//
// Its first line on stdout is {"ready":"pid:starttime:cmdline-hex"}, its identity.
// Then for each request line on stdin, {"nonce","code","files","outCap","errCap"}, it
// writes the files, hands the code to the interpreter over its control socket,
// streams what the interpreter writes between the cell's markers as {"o":b64} and
// {"e":b64} lines (at most outCap and errCap bytes), and ends with
// {"done":status,"ot":bool,"et":bool}: status 0 the code ran, 1 it
// raised, 3 a file could not be written, 75 no interpreter listening, 76 the
// interpreter ended during the cell), ot and et whether output was cut. Between cells
// it keeps reading the FIFOs and drops what it reads, so an interpreter writing
// between calls never fills them.
"use strict";
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");

const [dir, work] = process.argv.slice(1);

function send(frame) {
  process.stdout.write(JSON.stringify(frame) + "\n");
}

function identity() {
  const stat = fs.readFileSync("/proc/self/stat", "latin1");
  const start = stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19];
  const cmd = fs.readFileSync("/proc/self/cmdline").toString("hex");
  return process.pid + ":" + start + ":" + cmd;
}

let cell = null; // the cell in progress: markers, caps, counts, completion

// One FIFO, read for the relay's whole life. Bytes count only between the current
// cell's markers.
function stream(fifo, key) {
  const s = { pending: Buffer.alloc(0), copying: false, done: false };
  const fd = fs.openSync(fifo, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  const sock = new net.Socket({ fd, readable: true, writable: false });
  sock.on("data", (chunk) => {
    if (!cell || s.done) return;
    s.pending = Buffer.concat([s.pending, chunk]);
    if (!s.copying) {
      const i = s.pending.indexOf(cell.start);
      if (i < 0) {
        s.pending = s.pending.subarray(Math.max(0, s.pending.length - cell.start.length + 1));
        return;
      }
      s.copying = true;
      s.pending = s.pending.subarray(i + cell.start.length);
    }
    const j = s.pending.indexOf(cell.end);
    if (j >= 0) {
      emit(key, s.pending.subarray(0, j));
      s.pending = Buffer.alloc(0);
      s.done = true;
      cell.check();
      return;
    }
    const keep = cell.end.length - 1;
    if (s.pending.length > keep) {
      emit(key, s.pending.subarray(0, s.pending.length - keep));
      s.pending = s.pending.subarray(s.pending.length - keep);
    }
  });
  sock.on("error", () => {});
  return s;
}

function emit(key, buf) {
  if (buf.length === 0) return;
  const cap = key === "o" ? cell.outCap : cell.errCap;
  const room = Math.max(0, cap - cell.sent[key]);
  if (buf.length > room) cell.cut[key] = true;
  const take = buf.subarray(0, room);
  if (take.length === 0) return;
  cell.sent[key] += take.length;
  send({ [key]: take.toString("base64") });
}

const streams = { o: stream(path.join(dir, "out"), "o"), e: stream(path.join(dir, "err"), "e") };

function finish(status) {
  const c = cell;
  if (!c || c.finished) return;
  c.finished = true;
  clearTimeout(c.timer);
  cell = null;
  for (const s of Object.values(streams)) {
    s.pending = Buffer.alloc(0);
    s.copying = false;
    s.done = false;
  }
  send({ done: status, ot: c.cut.o, et: c.cut.e });
  next();
}

// A cell whose files cannot be written never reaches the interpreter.
function refuse() {
  send({ done: 3, ot: false, et: false });
  next();
}

function run(req) {
  for (const f of req.files || []) {
    const dest = path.resolve(work, f.path);
    if (dest === work || !dest.startsWith(work + "/")) return refuse();
    try {
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, f.content);
    } catch {
      return refuse();
    }
  }
  cell = {
    start: Buffer.from("\0plimsoll-cell-start-" + req.nonce + "\0"),
    end: Buffer.from("\0plimsoll-cell-end-" + req.nonce + "\0"),
    outCap: req.outCap > 0 ? req.outCap : Infinity,
    errCap: req.errCap > 0 ? req.errCap : Infinity,
    sent: { o: 0, e: 0 },
    cut: { o: false, e: false },
    status: null,
    finished: false,
    timer: null,
    // The cell is over once the interpreter replied and both end markers arrived,
    // or a moment after the reply if the code closed its own stdout or stderr.
    check() {
      if (this.status !== null && streams.o.done && streams.e.done) finish(this.status);
    },
  };
  const c = cell;
  let reply = "";
  let connected = false;
  const conn = net.connect(path.join(dir, "ctl.sock"));
  conn.setEncoding("utf8");
  conn.on("connect", () => {
    connected = true;
    conn.write(JSON.stringify({ nonce: req.nonce, code: req.code }) + "\n");
  });
  conn.on("data", (d) => {
    reply += d;
  });
  conn.on("error", () => {
    if (!connected && cell === c) finish(75);
  });
  conn.on("close", () => {
    if (cell !== c || !connected) return;
    let status = null;
    try {
      status = JSON.parse(reply).status;
    } catch {}
    c.status = status === "ok" ? 0 : status === "error" ? 1 : 76;
    c.timer = setTimeout(() => finish(c.status), 2000);
    c.check();
  });
}

// Requests arrive one at a time; the provider sends the next only after a done.
let input = "";
const queue = [];
function next() {
  if (cell || queue.length === 0) return;
  run(queue.shift());
}
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => {
  input += d;
  for (let nl = input.indexOf("\n"); nl >= 0; nl = input.indexOf("\n")) {
    const line = input.slice(0, nl);
    input = input.slice(nl + 1);
    if (line.trim()) queue.push(JSON.parse(line));
  }
  next();
});
process.stdin.on("end", () => process.exit(0));

send({ ready: identity() });
