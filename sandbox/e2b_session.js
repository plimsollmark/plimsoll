// plimsoll's helper inside an E2B session's virtual machine (e2b_session.go). It starts
// under sessionkit.ControlArgv, so nothing of the machine's environment reaches it, and
// takes its mode as its first argument:
//
//   open <guest> <work> <stage>   as root, before any of the session's code: makes the
//     machine one where the guest uid cannot become root again, creates the work and
//     staging directories, proves the drop, and prints {"envd": <pid>}, the parent every
//     process envd starts has. Exit 2 with the reason on stderr refuses the session.
//   stage <file> <guest> <work> <dir>   as root: reads a call's files from <file>, in the
//     root-only staging directory, deletes it, becomes the guest (non-dumpable, so the
//     session's code cannot attach to it), and writes them: "work" files under <work>,
//     never following a link out of it, and "own" files into <dir>, a directory of the
//     call's own. Exit 3 with {"file": i, "errno": code} on stdout is a file it could not
//     write (i counts "work" files only).
//   artifacts <work> <max> <path>...   as the guest: prints {"artifacts": [{path, b64}],
//     "truncated": bool}, keeping only regular files the kernel says it opened inside
//     <work>, at most <max> bytes in all.
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const cp = require("node:child_process");

const [mode, ...args] = process.argv.slice(1);

function refuse(why) {
  process.stderr.write(why + "\n");
  process.exit(2);
}

// The drop every guest process gets: setpriv execs the command, so it keeps the PID.
function dropArgs(guest) {
  return ["--reuid=" + guest, "--regid=" + guest, "--clear-groups", "--no-new-privs", "--"];
}

// becomeGuest turns this root process into the guest, which also makes it non-dumpable.
function becomeGuest(guest) {
  process.setgroups([]);
  process.setgid(guest);
  process.setuid(guest);
  const owner = fs.statSync("/proc/" + process.pid + "/fd").uid;
  if (process.getuid() !== guest || process.getgid() !== guest || process.getgroups().some((g) => g !== guest) || owner !== 0) {
    process.stderr.write("could not become the guest, non-dumpable\n");
    process.exit(70);
  }
}

// Rewrites an account file, replacing the password field of every account whose field
// is empty with lock, through a new file renamed over the old one with its owner and mode.
function lockEmpty(file, lock) {
  let text;
  try {
    text = fs.readFileSync(file, "latin1");
  } catch (e) {
    if (e.code === "ENOENT") return;
    throw e;
  }
  let changed = false;
  const out = text.split("\n").map((line) => {
    const f = line.split(":");
    if (f.length < 2 || f[0] === "" || f[1] !== "") return line;
    f[1] = lock;
    changed = true;
    return f.join(":");
  });
  if (!changed) return;
  const st = fs.statSync(file);
  const tmp = file + ".plimsoll";
  fs.writeFileSync(tmp, out.join("\n"), { encoding: "latin1", mode: st.mode & 0o7777 });
  fs.chownSync(tmp, st.uid, st.gid);
  fs.chmodSync(tmp, st.mode & 0o7777);
  fs.renameSync(tmp, file);
}

function comm(pid) {
  try {
    return fs.readFileSync("/proc/" + pid + "/comm", "latin1").trim();
  } catch {
    return "";
  }
}

function pids() {
  return fs.readdirSync("/proc").filter((d) => /^[0-9]+$/.test(d));
}

// listening22 reports whether anything listens on TCP port 22 (state 0A, LISTEN).
function listening22() {
  for (const f of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    let text = "";
    try {
      text = fs.readFileSync(f, "latin1");
    } catch {
      continue;
    }
    for (const line of text.split("\n").slice(1)) {
      const cols = line.trim().split(/\s+/);
      if (cols.length > 3 && cols[1].endsWith(":0016") && cols[3] === "0A") return true;
    }
  }
  return false;
}

function dir(p, uid, gid, mode) {
  fs.mkdirSync(p, { recursive: true });
  const st = fs.lstatSync(p);
  if (!st.isDirectory()) refuse(p + " is not a directory");
  fs.chownSync(p, uid, gid);
  fs.chmodSync(p, mode);
}

function open([guestArg, work, stage]) {
  const guest = Number(guestArg);
  if (!Number.isInteger(guest) || guest <= 0) refuse("the guest uid is not a positive integer");
  if (process.getuid() !== 0) refuse("open runs as root");
  // The guest uid and gid must be no account's or group's: a process of an account
  // with that uid, or a file group-owned by that gid, would be the guest's to use.
  for (const [file, what] of [["/etc/passwd", "account"], ["/etc/group", "group"]]) {
    for (const line of fs.readFileSync(file, "latin1").split("\n")) {
      if (line.split(":")[2] === String(guest)) refuse("uid/gid " + guest + " is already an " + what + " here: " + line.split(":")[0]);
    }
  }
  // The template has no-password accounts (E2B's build runs passwd -d on root and user)
  // and an sshd that takes root and empty passwords: no-new-privs stops sudo and su, not
  // a login. Lock every empty password, then stop sshd for good.
  lockEmpty("/etc/shadow", "!");
  lockEmpty("/etc/passwd", "*");
  const units = ["ssh.service", "ssh.socket", "sshd.service", "sshd.socket"];
  for (const verb of ["mask", "stop"]) {
    try {
      cp.spawnSync("systemctl", [verb, ...units], { stdio: "ignore", timeout: 15000 });
    } catch {}
  }
  for (let round = 0; ; round++) {
    const left = pids().filter((p) => comm(p) === "sshd");
    if (left.length === 0) break;
    if (round > 50) refuse("sshd keeps running");
    for (const p of left) {
      try {
        process.kill(+p, "SIGKILL");
      } catch {}
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
  }
  if (listening22()) refuse("something still listens on port 22 after sshd was stopped");
  dir(work, guest, guest, 0o700);
  dir(stage, 0, 0, 0o700);
  // Prove the drop the session's code will run under, and that the known ways back to
  // root all fail from it: sudo and su (setuid, so no-new-privs leaves them powerless)
  // and an ssh login to root (nothing listens any more).
  const run = (argv, timeout) =>
    cp.spawnSync("setpriv", [...dropArgs(guest), ...argv], { encoding: "latin1", timeout, env: { PATH: process.env.PATH }, stdio: ["ignore", "pipe", "pipe"] });
  const proof = run([process.execPath, "-e", `process.stdout.write(require("fs").readFileSync("/proc/self/status","latin1"))`], 10000);
  if (proof.error || proof.status !== 0) refuse("setpriv could not start a process as the guest: " + (proof.error ? proof.error.message : proof.stderr));
  const field = (name) => (new RegExp("^" + name + ":[ \\t]*(.*)$", "m").exec(proof.stdout) || [])[1];
  const want = [guest, guest, guest, guest].join("\t");
  if (field("Uid") !== want || field("Gid") !== want) refuse("the drop left uid " + field("Uid") + " gid " + field("Gid"));
  if ((field("Groups") || "").trim() !== "") refuse("the drop left supplementary groups " + field("Groups"));
  if (field("NoNewPrivs") !== "1") refuse("the drop did not set no-new-privs");
  for (const [name, argv] of [
    ["sudo", ["sudo", "-n", "true"]],
    ["su", ["su", "-c", "true", "root"]],
    ["ssh", ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3", "root@127.0.0.1", "true"]],
  ]) {
    const r = run(argv, 10000);
    if (r.error && r.error.code === "ENOENT") continue; // not installed here
    if (!r.error && r.status === 0) refuse(name + " gave the guest root");
  }
  process.stdout.write(JSON.stringify({ envd: process.ppid }));
}

// writeInside writes content to rel under work as the guest, following no link out of
// work; it returns an errno-shaped code, or "" when it wrote.
function writeInside(work, workReal, rel, content) {
  const dest = path.resolve(work, rel);
  if (dest === work || !dest.startsWith(work + "/")) return "EPATH";
  const inside = (p) => p.startsWith(workReal + "/");
  let fd = -1;
  try {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    if (!inside(fs.realpathSync(path.dirname(dest)) + "/")) return "EPATH";
    // O_NONBLOCK: a fifo an earlier call left at this path would otherwise hold the
    // open until a reader came; opened, it fails the isFile check.
    fd = fs.openSync(dest, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o644);
    if (!inside(fs.readlinkSync("/proc/self/fd/" + fd))) return "EPATH";
    if (!fs.fstatSync(fd).isFile()) return "EFTYPE";
    fs.ftruncateSync(fd, 0);
    fs.writeFileSync(fd, content);
    return "";
  } catch (e) {
    return typeof e?.code === "string" ? e.code : "EIO";
  } finally {
    if (fd >= 0) fs.closeSync(fd);
  }
}

function stage([file, guestArg, work, own]) {
  const guest = Number(guestArg);
  if (!Number.isInteger(guest) || guest <= 0) process.exit(70);
  const spec = JSON.parse(fs.readFileSync(file, "latin1"));
  fs.unlinkSync(file);
  becomeGuest(guest);
  // The call's own directory: a fresh one under a parent that holds only the last
  // call's, which goes now.
  const parent = path.dirname(own);
  // Whatever the session's code put at the parent's path that is not a directory (a
  // link into the work directory) goes, so the cleanup below never follows it.
  let st = null;
  try {
    st = fs.lstatSync(parent);
  } catch {}
  if (st && !st.isDirectory()) fs.rmSync(parent, { force: true });
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  for (const old of fs.readdirSync(parent)) {
    if (path.join(parent, old) !== own) fs.rmSync(path.join(parent, old), { recursive: true, force: true });
  }
  fs.mkdirSync(own, { mode: 0o700 });
  for (const f of spec.own || []) {
    fs.writeFileSync(path.join(own, f.name), Buffer.from(f.b64, "base64"), { flag: fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, mode: 0o600 });
  }
  let workReal;
  try {
    workReal = fs.realpathSync(work);
  } catch {
    process.stdout.write(JSON.stringify({ file: 0, errno: "EIO" }));
    process.exit(3);
  }
  // Every destination is checked before any is written, so a refused path writes
  // nothing.
  for (const [i, f] of (spec.work || []).entries()) {
    const dest = path.resolve(work, f.path);
    if (dest === work || !dest.startsWith(work + "/")) {
      process.stdout.write(JSON.stringify({ file: i, errno: "EPATH" }));
      process.exit(3);
    }
  }
  for (const [i, f] of (spec.work || []).entries()) {
    const errno = writeInside(work, workReal, f.path, Buffer.from(f.b64, "base64"));
    if (errno !== "") {
      process.stdout.write(JSON.stringify({ file: i, errno }));
      process.exit(3);
    }
  }
}

function artifacts([work, maxArg, ...paths]) {
  const max = Number(maxArg);
  let workReal;
  try {
    workReal = fs.realpathSync(work);
  } catch {
    workReal = "";
  }
  const out = { artifacts: [], truncated: false };
  let total = 0;
  for (const rel of paths) {
    const dest = path.resolve(work, rel);
    if (workReal === "" || dest === work || !dest.startsWith(work + "/")) continue;
    let fd = -1;
    try {
      fd = fs.openSync(dest, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      if (!fs.readlinkSync("/proc/self/fd/" + fd).startsWith(workReal + "/")) continue;
      if (!fs.fstatSync(fd).isFile()) continue;
      const room = max - total;
      const buf = Buffer.alloc(room + 1);
      let n = 0;
      for (let r; n < buf.length && (r = fs.readSync(fd, buf, n, buf.length - n, null)) > 0; ) n += r;
      if (n > room) {
        out.truncated = true;
        break;
      }
      total += n;
      out.artifacts.push({ path: rel, b64: buf.subarray(0, n).toString("base64") });
    } catch {
      continue;
    } finally {
      if (fd >= 0) fs.closeSync(fd);
    }
  }
  process.stdout.write(JSON.stringify(out));
}

switch (mode) {
  case "open":
    open(args);
    break;
  case "stage":
    stage(args);
    break;
  case "artifacts":
    artifacts(args);
    break;
  default:
    process.exit(64);
}
