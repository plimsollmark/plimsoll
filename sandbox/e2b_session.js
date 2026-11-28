// plimsoll's helper inside an E2B session's virtual machine (e2b_session.go). It starts
// in / under sessionkit.ControlArgvClosed, so nothing of the machine's environment
// reaches it, and takes its mode as its first argument:
//
//   open <guest> <work> <stage> <helper>   as root, before any of the session's code:
//     makes the machine one where the guest uid cannot become root again (closing
//     /usr/local to it among the rest: closeUsrLocal), creates the work and staging
//     directories, makes the work directory a mount of its own (ownMount), proves the
//     drop, finds the programs every later start names by path (pin), checks what is at
//     the native helper's path (helperAt), and prints {"envd": <pid>, "bins": {name:
//     path}, "usrLocal": {entries, changed, ms}, "helper": "absent" | "present", "arch":
//     process.arch}: the parent every process envd starts has, those paths, what closing
//     /usr/local did, and whether the template holds a file at the helper's path. Exit 2
//     with the reason on stderr refuses the session; exit 24 (usrLocalExit) refuses it
//     because /usr/local could not be closed.
//   install <staged> <helper> <size>   as root, before any of the session's code: puts the
//     native helper the daemon uploaded to <staged> (in the root-only staging directory)
//     at <helper>, where nothing was (installHelper). Exit 2 with the reason on stderr
//     refuses the session.
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

// refuse ends the open with exit 2 and its reason as one line on standard error, the
// last line there: e2b_session.go (e2bSessionOpenRefused) reads that line alone as the
// refusal, so a reason that quotes another program's output stays one line.
function refuse(why) {
  process.stderr.write(String(why).replace(/\s+/g, " ").trim() + "\n");
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

// guestCanChange says why the guest (its uid and gid, no other group) could change the
// file or directory st describes, or "" when it cannot.
function guestCanChange(st, guest) {
  if (st.uid === guest) return "owned by the guest";
  if (st.mode & 0o002) return "writable by every user";
  if (st.gid === guest && st.mode & 0o020) return "writable by the guest's group";
  return "";
}

// untrusted walks p from / as exec does, following each link, and says why the guest
// could change what p names (a directory on the way, a directory that holds a link on
// the way, or the file itself), or "" when it cannot. A link's own mode means nothing;
// the directory holding it decides whether it can be replaced. want is "file" or "dir".
function untrusted(p, guest, want) {
  let parts = p.split("/").filter(Boolean);
  let cur = "/";
  let why = guestCanChange(fs.lstatSync("/"), guest);
  if (why) return "/ is " + why;
  for (let hops = 0; parts.length > 0; ) {
    const name = parts.shift();
    if (name === ".") continue;
    if (name === "..") {
      cur = path.dirname(cur);
      continue;
    }
    const next = path.join(cur, name);
    const st = fs.lstatSync(next);
    if (st.isSymbolicLink()) {
      if (++hops > 40) return next + " leads through too many links";
      const target = fs.readlinkSync(next);
      if (target.startsWith("/")) cur = "/";
      parts = target.split("/").filter(Boolean).concat(parts);
      continue;
    }
    why = guestCanChange(st, guest);
    if (why) return next + " is " + why;
    const last = parts.length === 0;
    if (!last && !st.isDirectory()) return next + " is not a directory";
    if (last && want === "file" && !st.isFile()) return next + " is not a regular file";
    if (last && want === "dir" && !st.isDirectory()) return next + " is not a directory";
    cur = next;
  }
  return "";
}

// The programs every later start of the session names by path. They are found here,
// once, through the control PATH (the root's system folders, without /usr/local, which
// E2B's template build leaves writable by every user: sessionkit.ControlPathClosed),
// before any of the session's code has run, so nothing the session writes can be what is found; and each
// is kept only when nothing on the way to it, links included, is the guest's to change,
// so a link into a folder the session writes is refused, not followed later.
// The open also closes /usr/local to the guest (closeUsrLocal), and /usr/local still
// stays off the control PATH: two walls for two questions. Closing it protects whatever
// else in the machine runs as root and looks there (E2B's own programs); keeping it off
// the PATH means plimsoll's own programs do not rest on that closing alone: a mistake in
// it, or the folder opened again later by something of the template's own that runs as
// root, would still not reach a program plimsoll starts.
// /usr/bin/env is the first program of every control command (sessionkit.ControlArgv)
// and /bin/sh is what envd starts every process through, so both are checked by those
// paths; python3 is pinned only where the machine has it.
const pinRequired = ["node", "sh", "setpriv", "mount"];
const pinOptional = ["python3"];
const pinFixed = ["/usr/bin/env", "/bin/sh"];

function pin(guest) {
  const dirs = (process.env.PATH || "").split(":");
  for (const d of dirs) {
    if (!d.startsWith("/")) refuse("the control PATH has the relative entry " + JSON.stringify(d));
    let why;
    try {
      why = untrusted(d, guest, "dir");
    } catch (e) {
      if (e.code === "ENOENT") continue; // a folder this machine does not have finds nothing
      throw e;
    }
    if (why) refuse("the control PATH folder " + d + " is not the root's own: " + why);
  }
  for (const p of pinFixed) {
    let why;
    try {
      why = untrusted(p, guest, "file");
    } catch (e) {
      why = e.code || "unreadable";
    }
    if (why) refuse(p + " is not the root's own: " + why);
  }
  const bins = {};
  for (const name of [...pinRequired, ...pinOptional]) {
    for (const d of dirs) {
      const p = d + "/" + name;
      try {
        if (!fs.statSync(p).isFile()) continue;
        fs.accessSync(p, fs.constants.X_OK);
      } catch {
        continue;
      }
      const why = untrusted(p, guest, "file");
      if (why) refuse("the machine's " + name + " at " + p + " is not the root's own: " + why);
      bins[name] = p;
      break;
    }
    if (!bins[name] && pinRequired.includes(name)) refuse("the machine has no " + name + " in its system folders (" + dirs.join(":") + ")");
  }
  return bins;
}

// The exit of an open refused because something under /usr/local stays the guest's to
// write (closeUsrLocal); e2b_session.go reads it as the template's fault: unsupported,
// not dispatched.
const usrLocalExit = 24;

function refuseUsrLocal(why) {
  process.stderr.write(why + "\n");
  process.exit(usrLocalExit);
}

// closeUsrLocal takes the write permission on /usr/local back from every user but each
// entry's owner, before any of the session's code runs, and then has the guest itself
// try every entry. E2B's template build ends with `chmod -R 777 /usr/local` (its
// finalize step, configure.sh, read 2026-11-20), so every file and folder there is
// writable by every user, the session's included, and E2B's own programs that run as
// root live in /usr/local/bin. Left open, the session's code could replace one of them,
// or put a program of its own where anything of root's looks a name up (the system's
// default search path starts with /usr/local), and run as root. This removes the write
// bits for the group and for other users from every file and folder there (the reverse
// of E2B's one line; owners stay as built, root on E2B). A link is never changed, since
// a mode change follows a link: the folder that holds a link decides whether it can be
// replaced, and that folder is closed here. Then the guest's check: a process dropped
// exactly as the session's code is (setpriv, no-new-privs) asks the kernel, for each
// entry and for every folder above /usr/local, whether it may write it (access W_OK,
// which also answers for access lists and read-only mounts). Any it may write refuses
// the open, so a template whose /usr/local cannot be closed (a file the guest's uid
// owns, a mount that ignores modes) never serves a session. A mode change that fails is
// not itself a refusal: a read-only folder stays closed without one; the guest's answer
// decides. Returns what it did, timed, for the open's report.
function closeUsrLocal(guest, bins) {
  const start = process.hrtime.bigint();
  let top;
  try {
    top = fs.realpathSync("/usr/local");
  } catch (e) {
    if (e.code === "ENOENT") return { entries: 0, changed: 0, ms: 0 }; // nothing there to close
    refuseUsrLocal("/usr/local could not be read: " + e.code);
  }
  const entries = [];
  const failed = new Map();
  let changed = 0;
  for (const stack = [top]; stack.length > 0; ) {
    const p = stack.pop();
    let st;
    try {
      st = fs.lstatSync(p);
    } catch (e) {
      refuseUsrLocal(JSON.stringify(p) + " under /usr/local could not be read: " + e.code);
    }
    if (st.isSymbolicLink()) continue;
    const mode = st.mode & 0o7777;
    if (mode & 0o022) {
      try {
        fs.chmodSync(p, mode & ~0o022);
        changed++;
      } catch (e) {
        failed.set(p, e.code || "error");
      }
    }
    entries.push(p);
    if (st.isDirectory()) {
      let names;
      try {
        names = fs.readdirSync(p);
      } catch (e) {
        refuseUsrLocal(JSON.stringify(p) + " under /usr/local could not be listed: " + e.code);
      }
      for (const n of names) stack.push(path.join(p, n));
    }
  }
  // The folders above it, and above the name /usr/local where that is a link: whoever
  // can write one could rename /usr/local itself away.
  for (const base of new Set([top, "/usr/local"])) {
    for (let d = path.dirname(base); ; d = path.dirname(d)) {
      entries.push(d);
      if (d === "/") break;
    }
  }
  const checker = `const fs = require("fs");
const open = [];
for (const p of JSON.parse(fs.readFileSync(0, "latin1"))) {
  try { fs.accessSync(p, fs.constants.W_OK); open.push(p); } catch {}
}
process.stdout.write(JSON.stringify({ open: open.slice(0, 3), count: open.length }));`;
  const r = cp.spawnSync(bins.setpriv, [...dropArgs(guest), process.execPath, "--disable-sigusr1", "-e", checker], {
    encoding: "latin1",
    timeout: 60000,
    env: { PATH: process.env.PATH },
    input: JSON.stringify(entries),
    maxBuffer: 1 << 20,
  });
  if (r.error || r.status !== 0) refuseUsrLocal("the guest's check of /usr/local could not run: " + (r.error ? r.error.message : (r.stderr || "").trim()));
  let answer;
  try {
    answer = JSON.parse(r.stdout);
  } catch {
    refuseUsrLocal("the guest's check of /usr/local answered " + JSON.stringify(r.stdout));
  }
  if (answer.count !== 0) {
    const first = answer.open[0];
    const how = failed.has(first) ? " (taking its write permission back failed: " + failed.get(first) + ")" : "";
    refuseUsrLocal("the session's user can still write " + answer.count + " file(s) or folder(s) under /usr/local after the open closed it, " + JSON.stringify(first) + " first" + how);
  }
  return { entries: entries.length, changed, ms: Number(process.hrtime.bigint() - start) / 1e6 };
}

// mountedAt says whether p is a mount point: a line of /proc/self/mountinfo whose fifth
// field, the mount point (with space, tab, newline and backslash written as octal escapes),
// is p.
function mountedAt(p) {
  const esc = mountEscape(p);
  return fs.readFileSync("/proc/self/mountinfo", "latin1").split("\n").some((line) => line.split(" ")[4] === esc);
}

// mountEscape writes p as /proc/self/mountinfo writes a path: space, tab, newline and
// backslash as octal escapes.
function mountEscape(p) {
  return p.replace(/[\\ \t\n]/g, (c) => "\\" + c.charCodeAt(0).toString(8).padStart(3, "0"));
}

// workAlias returns the mount point (as mountinfo writes it) of a mount through which the
// work folder's files can be reached other than through the work folder's own mount, or ""
// when there is none: a mount of the work mount's device whose root is the work mount's root
// or a folder above it, which shows the work folder at a path the work mount does not cover.
// Through such a mount a rename(2) of a folder the helper holds crosses no mount edge, so a
// process of the guest's could move it out of the work folder and a write would land outside
// it (review finding session-files-15). The mounts under the work mount (the one it sits on,
// and any earlier mount at the same path) show the folder at the work folder's own path,
// which the work mount covers, and are kept; so is a mount of a folder below the work mount's
// root, which shows only what is inside the work folder.
function workAlias(mountinfo, work) {
  const lines = mountinfo.split("\n").filter((l) => l !== "").map((l) => l.split(" "));
  const esc = mountEscape(work);
  const mine = lines.filter((f) => f[4] === esc).pop();
  if (!mine) return "";
  const [, , dev, root] = mine;
  const under = new Set();
  for (let at = mine; at && !under.has(at[0]); at = lines.find((f) => f[0] === at[1])) under.add(at[0]);
  const alias = lines.find((f) => {
    const [id, , d, r, point] = f;
    if (d !== dev || !(r === "/" || r === root || root.startsWith(r + "/"))) return false;
    const rel = r === "/" ? root : root.slice(r.length);
    const shown = point === "/" ? rel || "/" : point + (rel === "/" ? "" : rel);
    return !(under.has(id) && shown === esc);
  });
  return alias ? alias[4] : "";
}

// ownMount makes the work directory a mount of its own, a bind mount of itself, unless it
// is one already: the native helper's work scope refuses a work folder that is not one,
// since a folder of a call's path could otherwise be moved out of the work folder while
// the call holds it (docs/session-files.md, "The work folder must be a mount of its own");
// a rename out of a mount is refused by the kernel (EXDEV). The guest, with no capability,
// cannot unmount it. Measured 2026-11-27 on the stand-in's containers: /work a plain folder
// of the root file system, a rename out of it allowed; after the bind, refused with EXDEV.
// A mount edge proves nothing when the work folder's files are also under another mount of
// the same device (workAlias), so such a machine is refused too; on the stand-in there is
// none (TestE2BSessionDockerInstallsTheHelper), and on E2B's own templates it is not measured.
//
// The bind mount's 15 s: the mount is one system call, measured 2026-11-27 at 3 to 4 ms
// under runc and 10 to 20 ms under gVisor, as root in a container (on E2B's own machines it
// is not measured). One that has not returned by then is stuck, and the open refuses the
// machine instead of waiting out the session open's own deadline; it is the bound the open
// gives systemctl below.
function ownMount(work, bins) {
  if (!mountedAt(work)) {
    const r = cp.spawnSync(bins.mount, ["--bind", work, work], { encoding: "latin1", timeout: 15000, env: { PATH: process.env.PATH }, stdio: ["ignore", "pipe", "pipe"] });
    if (r.error || r.status !== 0) refuse("the work directory could not be made a mount of its own: " + (r.error ? r.error.message : (r.stderr || "").trim()));
    if (!mountedAt(work)) refuse("the work directory is not a mount of its own after its bind mount");
  }
  const alias = workAlias(fs.readFileSync("/proc/self/mountinfo", "latin1"), work);
  if (alias) refuse("the work directory's files are also under the mount at " + alias + ", where a folder a file call holds could be moved out of the work directory");
}

// helperFolder checks the folder that holds the native helper's path, making it (root's,
// mode 0755) when it is not there: a directory, not a link, the root's, not writable by
// its group or every user, and nothing on the way to it the guest's to change.
function helperFolder(helper, guest) {
  const parent = path.dirname(helper);
  try {
    fs.mkdirSync(parent, { mode: 0o755 });
  } catch (e) {
    if (e.code !== "EEXIST") refuse("the native helper's folder " + parent + " could not be made: " + e.code);
  }
  const st = fs.lstatSync(parent);
  if (!st.isDirectory()) refuse("the native helper's folder " + parent + " is not a directory");
  if (st.uid !== 0 || st.mode & 0o022) refuse("the native helper's folder " + parent + " is not the root's alone (uid " + st.uid + ", mode " + (st.mode & 0o7777).toString(8) + ")");
  const why = untrusted(parent, guest, "dir");
  if (why) refuse("the native helper's folder " + parent + " is not the root's own: " + why);
  return parent;
}

// helperAt says what is at the native helper's path: "absent", or "present" for a regular
// file of the root's that the guest may run, that no one but the root may read or change
// (mode 0711: its bytes are the daemon's to check, and a program its user cannot read is
// non-dumpable from its exec, review finding session-files-14). Anything else there (a
// link, a folder, a device, a file of another owner, that its group or every user may read
// or write, or a setuid one) refuses the session: the open never writes through or over what
// it did not put there.
function helperAt(helper, guest) {
  helperFolder(helper, guest);
  let st;
  try {
    st = fs.lstatSync(helper);
  } catch (e) {
    if (e.code === "ENOENT") return "absent";
    refuse("the native helper's path " + helper + " could not be read: " + e.code);
  }
  if (!st.isFile()) refuse("something other than a regular file is at the native helper's path " + helper);
  if (st.uid !== 0 || st.gid !== 0 || st.mode & 0o6066 || (st.mode & 0o001) !== 0o001) {
    refuse("the file at the native helper's path " + helper + " is not the root's alone, runnable by every user and readable by the root alone (uid " + st.uid + ", gid " + st.gid + ", mode " + (st.mode & 0o7777).toString(8) + ")");
  }
  const why = untrusted(helper, guest, "file");
  if (why) refuse("the native helper at " + helper + " is not the root's own: " + why);
  return "present";
}

// installHelper puts the native helper the daemon uploaded to staged (a file envd wrote
// as root in the root-only staging directory) at helper, where nothing may be: it checks
// the staged file (a regular file of the root's, of size bytes), copies it into a file of
// its own in the helper's folder (made with O_EXCL and O_NOFOLLOW, synced, mode 0711,
// the root's: the guest may run it and not read it, so it is non-dumpable from its exec), publishes that by a hard link, which refuses a name already there, removes
// both staged names, and checks the result's type, owner, mode and size. The daemon reads
// the bytes back through envd and checks their SHA-256 itself (e2b_session.go,
// installHelper), so nothing here is trusted for them.
function installHelper([staged, helper, sizeArg]) {
  if (process.getuid() !== 0) refuse("install runs as root");
  const size = Number(sizeArg);
  if (!Number.isInteger(size) || size <= 0) refuse("the helper's size is not a positive integer");
  const parent = path.dirname(helper);
  let st = fs.lstatSync(staged);
  if (!st.isFile() || st.uid !== 0 || st.size !== size) refuse("the uploaded native helper is not a regular file of the root's of " + size + " bytes");
  const bytes = fs.readFileSync(staged);
  fs.unlinkSync(staged);
  if (bytes.length !== size) refuse("the uploaded native helper changed while it was read");
  st = fs.lstatSync(parent);
  if (!st.isDirectory() || st.uid !== 0 || st.mode & 0o022) refuse("the native helper's folder " + parent + " is not the root's alone");
  try {
    fs.lstatSync(helper);
    refuse("something is at the native helper's path " + helper + " already");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  const temp = parent + "/.plimsoll-helper-" + process.pid + "-" + Date.now().toString(16);
  const fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o500);
  try {
    for (let off = 0; off < bytes.length; ) off += fs.writeSync(fd, bytes, off, bytes.length - off);
    fs.fchownSync(fd, 0, 0);
    fs.fchmodSync(fd, 0o711);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.linkSync(temp, helper);
  } catch (e) {
    fs.unlinkSync(temp);
    refuse("the native helper could not be published at " + helper + ": " + e.code);
  }
  fs.unlinkSync(temp);
  st = fs.lstatSync(helper);
  if (!st.isFile() || st.uid !== 0 || st.gid !== 0 || (st.mode & 0o7777) !== 0o711 || st.size !== size || st.nlink !== 1) {
    refuse("the native helper at " + helper + " is not what was installed");
  }
  process.stdout.write(JSON.stringify({ installed: helper }));
}

function open([guestArg, work, stage, helper]) {
  const guest = Number(guestArg);
  if (!Number.isInteger(guest) || guest <= 0) refuse("the guest uid is not a positive integer");
  if (process.getuid() !== 0) refuse("open runs as root");
  const bins = pin(guest);
  // The guest uid and gid must be no account's or group's: a process of an account
  // with that uid, or a file group-owned by that gid, would be the guest's to use.
  for (const [file, what] of [["/etc/passwd", "account"], ["/etc/group", "group"]]) {
    for (const line of fs.readFileSync(file, "latin1").split("\n")) {
      if (line.split(":")[2] === String(guest)) refuse("uid/gid " + guest + " is already an " + what + " here: " + line.split(":")[0]);
    }
  }
  const usrLocal = closeUsrLocal(guest, bins);
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
  ownMount(work, bins);
  dir(stage, 0, 0, 0o700);
  if (!helper || !helper.startsWith("/")) refuse("the native helper's path is not absolute");
  const helperState = helperAt(helper, guest);
  // Prove the drop the session's code will run under, and that the known ways back to
  // root all fail from it: sudo and su (setuid, so no-new-privs leaves them powerless)
  // and an ssh login to root (nothing listens any more).
  const run = (argv, timeout) =>
    cp.spawnSync(bins.setpriv, [...dropArgs(guest), ...argv], { encoding: "latin1", timeout, env: { PATH: process.env.PATH }, stdio: ["ignore", "pipe", "pipe"] });
  const proof = run([process.execPath, "--disable-sigusr1", "-e", `process.stdout.write(require("fs").readFileSync("/proc/self/status","latin1"))`], 10000);
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
  // envd's port answers inside the machine too, and plimsoll's own programs run as root
  // through it, so the guest, holding no access token, must be refused a process start
  // and a token reset at every address the machine has: loopback and each interface of
  // its own. envd answers 401 to any request without the token except its health and
  // signed file endpoints, and /init takes a token only when it matches the sandbox's or
  // the orchestrator's hash of it, a reset to none included (its auth.go and init.go, read
  // 2026-10-26). An address where nothing listens (connection refused) is one the guest
  // cannot reach envd at, so it passes; the fake envd of the docker-backed tests listens
  // on a Unix socket, so there every address is such. Anything else (an answer other than
  // a refusal, a timeout, another error) refuses the open (review, 2026-10-26).
  const envdProbe = `const http = require("http"), os = require("os");
const post = (host, path, body) => new Promise((resolve) => {
  const req = http.request({ host, port: 49983, path, method: "POST", headers: { "content-type": "application/json" }, timeout: 5000 },
    (res) => { res.resume(); res.on("end", () => resolve(String(res.statusCode))); });
  req.on("timeout", () => { req.destroy(); resolve("timeout"); });
  req.on("error", (e) => resolve(e.code || "error"));
  req.end(body);
});
(async () => {
  const hosts = ["127.0.0.1", ...Object.values(os.networkInterfaces()).flat().filter((i) => i && i.family === "IPv4" && !i.internal).map((i) => i.address)];
  const out = [];
  for (const host of hosts) {
    out.push(host, await post(host, "/process.Process/Start", JSON.stringify({ process: { cmd: "id" } })),
      await post(host, "/init", JSON.stringify({ accessToken: "plimsoll-open-probe" })), await post(host, "/init", "{}"));
  }
  process.stdout.write(out.join(" "));
})();`;
  const envdAnswer = run([process.execPath, "--disable-sigusr1", "-e", envdProbe], 60000);
  if (envdAnswer.error || envdAnswer.status !== 0) refuse("the envd check could not run: " + (envdAnswer.error ? envdAnswer.error.message : envdAnswer.stderr));
  const answers = (envdAnswer.stdout || "").trim().split(" ");
  if (answers.length < 4 || answers.length % 4 !== 0) refuse("the envd check answered " + JSON.stringify(envdAnswer.stdout));
  for (let i = 0; i < answers.length; i += 4) {
    const [host, startCode, resetCode, clearCode] = answers.slice(i, i + 4);
    if (startCode === "ECONNREFUSED") continue; // nothing listens there, so the guest reaches no envd at that address
    if (startCode !== "401") refuse("envd at " + host + " answered " + startCode + " to the guest's token-less process start; 401 is the proof");
    for (const [what, code] of [["reset", resetCode], ["clearing", clearCode]]) {
      if (!/^[45]\d\d$/.test(code)) refuse("envd at " + host + " answered " + code + " to the guest's token " + what + "; a refusal is the proof");
    }
  }
  process.stdout.write(JSON.stringify({ envd: process.ppid, bins, usrLocal, helper: helperState, arch: process.arch }));
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
      // A link is resolved first and followed only if it stays inside the work
      // directory, as the runner does; the real path is then opened without following
      // a final link, and the kernel's name for what was opened is checked again, since
      // a process the session left could swap a parent directory in between. A path
      // that does not resolve or open is skipped, as a missing file; a file opened and
      // then unreadable is not, as in the runner: the error ends the reader, and the
      // call is runner_failed (review, 2026-10-24).
      let real;
      try {
        real = fs.realpathSync(dest);
        if (!real.startsWith(workReal + "/")) continue;
        fd = fs.openSync(real, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        if (!fs.readlinkSync("/proc/self/fd/" + fd).startsWith(workReal + "/")) continue;
      } catch {
        continue;
      }
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
  case "install":
    installHelper(args);
    break;
  case "artifacts":
    artifacts(args);
    break;
  default:
    process.exit(64);
}
