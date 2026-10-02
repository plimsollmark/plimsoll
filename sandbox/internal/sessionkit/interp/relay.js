// A session interpreter's relay, so a cell costs a line on a pipe instead of a new
// process. The provider starts it once per interpreter as a
// long-lived command whose stdin and stdout it holds, and the sweep keeps it with
// the interpreter. Arguments: the interpreter's directory and the work directory.
//
// Its first line on stdout is {"ready":"pid:starttime:cmdline-hex"}, its identity.
// A cell then takes two request lines on stdin, and every frame the relay writes for
// it carries the request's nonce as "n":
//
//   - {"nonce","files"} prepares: it writes the files and connects to the
//     interpreter's control socket, then answers {"prepared":true}, or
//     {"done":3,"file":i,"errno":code} for a file it could not write, or {"done":75}
//     when no interpreter is listening. No code has been sent either way.
//   - {"nonce","code","outCap","errCap"} runs: it hands the code over the connection
//     the prepare opened, streams what the interpreter writes between the cell's
//     markers as {"o":b64} and {"e":b64} lines (at most outCap and errCap bytes, in
//     pieces of at most 48 KiB), and ends with {"done":status,"ot":bool,"et":bool}:
//     status 0 the code ran, 1 it raised, 76 the interpreter ended during the cell;
//     ot and et whether output was cut.
//
// The split is what lets the provider trust a refusal: code of the session can write
// frames into this relay's stdout, but a frame that says nothing ran can only arrive
// before the provider sent the code, and after that nothing a frame says makes the
// provider send it again. Between cells the relay keeps reading the FIFOs and drops
// what it reads, so an interpreter writing between calls never fills them.
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
let prepared = null; // {nonce, conn}: a prepared cell's connection, waiting for its code

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

// The provider bounds every frame it reads, so output goes out in pieces.
const piece = 48 << 10;

function emit(key, buf) {
  if (buf.length === 0) return;
  const cap = key === "o" ? cell.outCap : cell.errCap;
  const room = Math.max(0, cap - cell.sent[key]);
  if (buf.length > room) cell.cut[key] = true;
  const take = buf.subarray(0, room);
  if (take.length === 0) return;
  cell.sent[key] += take.length;
  for (let off = 0; off < take.length; off += piece) {
    send({ n: cell.nonce, [key]: take.subarray(off, off + piece).toString("base64") });
  }
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
  send({ n: c.nonce, done: status, ot: c.cut.o, et: c.cut.e });
  next();
}

// Lets go of a prepared connection whose code never came.
function unprepare() {
  if (prepared) prepared.conn.destroy();
  prepared = null;
}

// A cell whose files cannot be written never reaches the interpreter. The relay
// says which file (its index in the request) and the system's error code.
function refuse(nonce, file, errno) {
  send({ n: nonce, done: 3, ot: false, et: false, file, errno });
  next();
}

function prepare(req) {
  unprepare();
  const files = req.files || [];
  // Every destination is checked before any is written, so a refused path writes
  // nothing; a write that fails leaves the files before it written.
  const dests = [];
  for (const [i, f] of files.entries()) {
    const dest = path.resolve(work, f.path);
    if (dest === work || !dest.startsWith(work + "/")) return refuse(req.nonce, i, "EPATH");
    dests.push(dest);
  }
  // A link an earlier call left in the work directory is not followed out of it:
  // the parent must resolve inside, the file itself is opened without following a
  // link, and the kernel's name for what was opened must be inside too, before
  // anything is truncated or written.
  let workReal;
  try { workReal = fs.realpathSync(work); } catch (e) { return refuse(req.nonce, 0, "EIO"); }
  const inside = (p) => p.startsWith(workReal + "/");
  for (const [i, f] of files.entries()) {
    let fd = -1;
    try {
      fs.mkdirSync(path.dirname(dests[i]), { recursive: true });
      if (!inside(fs.realpathSync(path.dirname(dests[i])) + "/")) return refuse(req.nonce, i, "EPATH");
      fd = fs.openSync(dests[i], fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW, 0o644);
      if (!inside(fs.readlinkSync("/proc/self/fd/" + fd))) return refuse(req.nonce, i, "EPATH");
      fs.ftruncateSync(fd, 0);
      fs.writeFileSync(fd, f.content);
    } catch (e) {
      return refuse(req.nonce, i, typeof e?.code === "string" ? e.code : "EIO");
    } finally {
      if (fd >= 0) fs.closeSync(fd);
    }
  }
  const conn = net.connect(path.join(dir, "ctl.sock"));
  let connected = false;
  conn.on("connect", () => {
    connected = true;
    prepared = { nonce: req.nonce, conn };
    send({ n: req.nonce, prepared: true });
    next();
  });
  conn.on("error", () => {
    if (connected) return;
    send({ n: req.nonce, done: 75, ot: false, et: false });
    next();
  });
  // An interpreter that dies before the code arrives closes this connection; run
  // then answers at once instead of waiting for a close that already happened.
  conn.on("close", () => {
    if (prepared && prepared.conn === conn) prepared.closed = true;
  });
}

function run(req) {
  if (!prepared || prepared.nonce !== req.nonce) {
    // The provider sends code only after this relay prepared its cell; anything else
    // is answered as an interpreter that ended, which the provider never retries.
    unprepare();
    send({ n: req.nonce, done: 76, ot: false, et: false });
    return next();
  }
  const { conn, closed } = prepared;
  prepared = null;
  if (closed) {
    send({ n: req.nonce, done: 76, ot: false, et: false });
    return next();
  }
  cell = {
    nonce: req.nonce,
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
  conn.setEncoding("utf8");
  conn.write(JSON.stringify({ nonce: req.nonce, code: req.code }) + "\n");
  conn.on("data", (d) => {
    reply += d;
  });
  conn.on("close", () => {
    if (cell !== c) return;
    let status = null;
    try {
      status = JSON.parse(reply).status;
    } catch {}
    c.status = status === "ok" ? 0 : status === "error" ? 1 : 76;
    c.timer = setTimeout(() => finish(c.status), 2000);
    c.check();
  });
}

// Requests arrive one at a time; the provider sends the next only after an answer.
let input = "";
const queue = [];
let busy = false; // a prepare waiting for its connection
function next() {
  busy = false;
  if (cell || queue.length === 0) return;
  const req = queue.shift();
  if (typeof req.code === "string") return run(req);
  busy = true;
  prepare(req);
}
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => {
  input += d;
  for (let nl = input.indexOf("\n"); nl >= 0; nl = input.indexOf("\n")) {
    const line = input.slice(0, nl);
    input = input.slice(nl + 1);
    if (line.trim()) queue.push(JSON.parse(line));
  }
  if (!busy) next();
});
process.stdin.on("end", () => process.exit(0));

send({ ready: identity() });
