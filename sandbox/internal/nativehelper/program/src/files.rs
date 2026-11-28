//! The file commands, `plimsoll-helper files SCOPE COMMAND ARG...` (or `files SCOPE -`, the same
//! words read from stdin, the form a daemon uses: see words_from_stdin): one generic interface to a
//! sandbox's files (stat, read, write, list with a glob, read a batch, make a folder, remove,
//! rename), the in-sandbox half of the daemon's file calls. The contract (scopes, commands,
//! framing, exit codes) is docs/session-files.md; this is its implementation, and a change to
//! anything a caller sees raises nativehelper.FilesVersion.
//!
//! What a command can reach. It runs as the guest's own user, started as the guest's own
//! process, and is a program of its own: it reads no plan, key, report or descriptor of the
//! project runner, and this module uses sys.rs's calls, errno.rs's error text and the glob
//! matcher below, nothing of the runner's report, its frame or its signing. Every open is the
//! kernel's check of the guest's own permissions, so a guest that starts the helper itself gets
//! nothing its own shell does not have. It makes itself non-dumpable before it opens anything,
//! so another process of the same user (a session's interpreter, which lives between calls)
//! cannot open its descriptors or its memory and change an answer.
//!
//! Scopes. `work`: a relative path from the working folder (the session's work folder, which
//! must be a mount of its own: root), parts separated by "/", none empty, "." or "..", at most
//! 4096 bytes; "." alone is the work folder. A path is resolved beneath the work folder by one
//! openat2 with RESOLVE_BENEATH (resolve): a link that stays inside is followed, one that would
//! leave is refused by the kernel's own resolution, so no check stands apart from the open it
//! guards. The work scope never crosses a mount (session-files-19): a mount below the work
//! folder (a template's bind of another folder at /work/shared) is another file system's
//! folder, which a process of the guest's could move out of the work folder while a call holds
//! it, since only the work mount's own edge stops such a move. The resolution adds
//! RESOLVE_NO_XDEV, and every name pinned and every folder a listing enters are held to the
//! work folder's mount by its mount id (within_work): a path across one answers 86, and a
//! recursive listing lists such a folder as one it could not enter. So the work scope needs a
//! kernel with openat2 whose statx states mount ids (Linux 5.8 or later, or gVisor): on any
//! other, root() refuses every work-scope command before a path is resolved (exit 1, ENOSYS
//! first on stderr), since a device tells apart no second mount of the work folder's own file
//! system and a walk part by part has no RESOLVE_NO_XDEV (session-files-23). `sandbox`: an absolute
//! path, resolved by the kernel as the guest's own shell resolves it, links and mounts
//! followed; "/" alone is the root. The sandbox's walls are the boundary there. In both, a
//! command that acts on a name (stat, remove, rename, a replace) acts on a link at the last
//! part itself, never its target; docs/session-files.md has the table.
//!
//! No open waits, and nothing but a regular file is opened for its content: a name is pinned
//! with O_PATH and classified by fstat first, and only a regular file is opened again, through
//! /proc/self/fd, so a FIFO or a device planted at a path is "neither a regular file nor a
//! folder" at once, never opened (session-files-8). Where /proc is not mounted, no file is
//! opened for its content at all: a name looked up again could hold a FIFO by then
//! (session-files-21).
//!
//! Exit codes: 0 done; 80 a symbolic link the scope does not follow (ELOOP); 81 nothing there
//! (ENOENT); 82 a folder where a file is meant (EISDIR); 83 not a folder where one is meant
//! (ENOTDIR); 84 something is there already (EEXIST); 85 neither a regular file nor a folder;
//! 86 permission denied (EACCES, EPERM), or in the work scope a path across a mount below the
//! work folder; 87 past a size cap, the helper's or the kernel's (EFBIG); 88 a folder that is not
//! empty (ENOTEMPTY); 89 no space left (ENOSPC, EDQUOT); 90 a read-only file system (EROFS); 91
//! a listing past one of its bounds (LIST_BOUNDS); 92 a write that failed after a change it
//! could not undo, so what the file holds is unknown; 2 a malformed command (stderr says what);
//! 1 any other failure (stderr: `CODE: description, call 'path'`). Nothing is written to stdout
//! unless the exit is 0.
//!
//! Framing: every answer is frames one after another, each a one-byte tag, the length of its
//! payload in decimal (no sign, no leading zero), ":", then exactly that many bytes. The last
//! frame, and only the last, is "." (the answer is whole) or "+" (it stopped at its budget: ask
//! again for the rest), and its payload is the decimal count of entries before it.

use crate::errno;
use crate::sys;
use std::ffi::{CStr, CString, OsStr, c_int};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::sync::OnceLock;

pub const LINK: i32 = 80;
pub const NOENT: i32 = 81;
pub const ISDIR: i32 = 82;
pub const NOTDIR: i32 = 83;
pub const EXIST: i32 = 84;
pub const NOTREG: i32 = 85;
pub const ACCES: i32 = 86;
pub const FBIG: i32 = 87;
pub const NOTEMPTY: i32 = 88;
pub const NOSPC: i32 = 89;
pub const ROFS: i32 = 90;
pub const TOOMANY: i32 = 91;
pub const UNKNOWN: i32 = 92;
const USAGE: i32 = 2;
const FAILED: i32 = 1;

/// Linux's PATH_MAX, the longest path a command takes.
const MAX_PATH: usize = 4096;
/// The most bytes one answer may take, and one read: the daemon reads the helper's output
/// itself, so this is the interface's cap, not the project runner's step output limit.
const MAX_BUDGET: usize = 8 << 20;
/// The least budget: room for the largest entry of a listing (a path of MAX_PATH bytes, its kind
/// and a 20-digit size: 4,130 bytes of frames) or a readmany error item (4,111), and the last
/// frame, rounded up to 8 KiB, so an answer that stops at its budget always holds an entry
/// (session-files-6).
const MIN_BUDGET: usize = 8192;
/// The most bytes one write carries.
const MAX_WRITE: usize = 4 << 20;
/// The most paths one readmany asks: enough for a store's search to read a large tree in few calls (each
/// call costs a process start); the budget, at most MAX_BUDGET, bounds what one answer carries.
const MAX_PATHS: usize = 16_384;
/// Room kept for the last frame: its tag, up to 2 length digits, ":", up to 20 count digits.
const END_ROOM: usize = 24;

// Linux's error numbers, the same on every machine (asm-generic/errno-base.h, errno.h).
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const ENXIO: i32 = 6;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EFBIG: i32 = 27;
const ENOSPC: i32 = 28;
const EROFS: i32 = 30;
const ENOTEMPTY: i32 = 39;
const ELOOP: i32 = 40;
const EXDEV: i32 = 18;
const EAGAIN: i32 = 11;
const ENOSYS: i32 = 38;
const EINVAL: i32 = 22;
const EOPNOTSUPP: i32 = 95;
const EDQUOT: i32 = 122;

/// Whether the scope is `sandbox` (links followed, paths absolute); set once in run.
static SANDBOX: OnceLock<bool> = OnceLock::new();

fn sandbox_scope() -> bool {
    SANDBOX.get().copied().unwrap_or(false)
}

/// openat's "the current folder".
const AT_FDCWD: RawFd = -100;

/// How a command ends when it does not end with 0.
#[derive(Debug)]
enum End {
    Code(i32),
    Failed(String),
    Usage(String),
}

type R<T> = Result<T, End>;

/// The exit code for an error the contract names, or None.
fn code_of(e: &io::Error) -> Option<i32> {
    Some(match e.raw_os_error()? {
        ELOOP => LINK,
        ENOENT => NOENT,
        EISDIR => ISDIR,
        ENOTDIR => NOTDIR,
        EEXIST => EXIST,
        ENXIO => NOTREG,
        EACCES | EPERM => ACCES,
        EFBIG => FBIG,
        ENOTEMPTY => NOTEMPTY,
        ENOSPC | EDQUOT => NOSPC,
        EROFS => ROFS,
        _ => return None,
    })
}

/// An error of a call: its code when the contract names one, else the failure's text.
fn failed(e: &io::Error, call: &str, path: &[u8]) -> End {
    code_of(e).map_or_else(|| End::Failed(errno::describe(e, call, &String::from_utf8_lossy(path))), End::Code)
}

fn usage(what: &str) -> End {
    End::Usage(format!("plimsoll-helper files: {what}"))
}

/// Runs one command and exits with its code; its stdout is written only on exit 0.
pub fn main(args: &[&OsStr]) -> ! {
    // First, before anything is opened: no other process of the guest's user may read this
    // one's memory or descriptors. Installed readable by root alone, the helper is already
    // non-dumpable from its exec (the kernel's rule for a program its user cannot read); this
    // call holds wherever it is not (a test's build, an operator's copy).
    if !sys::set_non_dumpable() {
        let _ = writeln!(io::stderr(), "plimsoll-helper files: cannot set non-dumpable state");
        std::process::exit(FAILED);
    }
    let mut out = Vec::new();
    let code = match run(args, &mut out) {
        Ok(()) => {
            let mut stdout = io::stdout().lock();
            if stdout.write_all(&out).and_then(|()| stdout.flush()).is_ok() { 0 } else { FAILED }
        }
        Err(End::Code(c)) => c,
        Err(End::Failed(text)) => {
            let _ = writeln!(io::stderr(), "{text}");
            FAILED
        }
        Err(End::Usage(text)) => {
            let _ = writeln!(io::stderr(), "{text}");
            USAGE
        }
    };
    std::process::exit(code)
}

const USAGE_TEXT: &str = "usage: files work|sandbox - (the words below on stdin) | files work|sandbox stat PATH | read PATH OFFSET LENGTH | \
                          write PATH replace|create-only|append 0|1 | mkdir PATH 0|1 | remove PATH 0|1 | \
                          rename FROM TO 0|1 | list DIR 0|1 BUDGET [MATCH] | readmany MAX BUDGET";

/// The most words `files SCOPE -` reads from stdin: a command and its arguments (`list` has
/// the most, five).
const MAX_WORDS: usize = 6;

/// The command's words for `files SCOPE -`, read from the start of stdin: their count in
/// decimal (no sign, no leading zero), ":", then each word ended by a NUL, each at most
/// MAX_PATH bytes. A daemon sends its words this way because an exec's arguments travel as
/// JSON or protobuf strings to the sandbox (docker exec, a gateway's exec), which replace a
/// byte that is not UTF-8, so a name that is not UTF-8 cannot be an argument; stdin carries
/// any byte. What follows the words is the command's own input, read as in the argv form.
fn words_from_stdin() -> R<Vec<Vec<u8>>> {
    use std::io::BufRead;
    let mut stdin = io::stdin().lock();
    let mut count = Vec::new();
    (&mut stdin).take(3).read_until(b':', &mut count).map_err(|e| failed(&e, "read", b"stdin"))?;
    if count.pop() != Some(b':') {
        return Err(usage("files SCOPE -: stdin starts with the count of words, then \":\""));
    }
    let n = number(&count, MAX_WORDS as u64)? as usize;
    if n == 0 {
        return Err(usage("files SCOPE -: at least the command's word"));
    }
    let mut words = Vec::with_capacity(n);
    for _ in 0..n {
        let mut w = Vec::new();
        (&mut stdin).take(MAX_PATH as u64 + 1).read_until(0, &mut w).map_err(|e| failed(&e, "read", b"stdin"))?;
        if w.pop() != Some(0) {
            return Err(usage(&format!("files SCOPE -: each word ends with a NUL and is at most {MAX_PATH} bytes")));
        }
        words.push(w);
    }
    Ok(words)
}

fn run(args: &[&OsStr], out: &mut Vec<u8>) -> R<()> {
    let a: Vec<&[u8]> = args.iter().map(|s| s.as_bytes()).collect();
    let Some((scope, rest)) = a.split_first() else { return Err(usage(USAGE_TEXT)) };
    let sandbox = match *scope {
        b"work" => false,
        b"sandbox" => true,
        _ => return Err(usage(USAGE_TEXT)),
    };
    let _ = SANDBOX.set(sandbox);
    if rest == [b"-"] {
        let words = words_from_stdin()?;
        let words: Vec<&[u8]> = words.iter().map(Vec::as_slice).collect();
        return command(&words, out);
    }
    command(rest, out)
}

/// Runs one command, given its words (the command, then its arguments).
fn command(rest: &[&[u8]], out: &mut Vec<u8>) -> R<()> {
    match rest {
        [b"stat", path] => stat(path, out),
        [b"read", path, offset, length] => {
            let length = number(length, MAX_BUDGET as u64)?;
            if length == 0 {
                return Err(usage("a read's LENGTH is 1 or more"));
            }
            read(path, number(offset, i64::MAX as u64)?, length, out)
        }
        [b"write", path, mode, parents] => write(path, write_mode(mode)?, flag01(parents)?, out),
        [b"mkdir", path, parents] => mkdir(path, flag01(parents)?),
        [b"remove", path, folder] => remove(path, flag01(folder)?),
        [b"rename", from, to, replace] => rename(from, to, flag01(replace)?),
        [b"list", dir, flag, budget] => list(dir, flag01(flag)?, budget_of(budget)?, None, out),
        [b"list", dir, flag, budget, pattern] => list(dir, flag01(flag)?, budget_of(budget)?, Some(pattern), out),
        [b"readmany", max, budget] => readmany(number(max, MAX_BUDGET as u64)?, budget_of(budget)?, out),
        _ => Err(usage(USAGE_TEXT)),
    }
}

/// A decimal number of at most `max`, with no sign and no leading zero.
fn number(s: &[u8], max: u64) -> R<u64> {
    let plain = !s.is_empty() && s.len() <= 20 && s.iter().all(u8::is_ascii_digit) && (s == b"0" || s[0] != b'0');
    let n = if plain { std::str::from_utf8(s).ok().and_then(|t| t.parse::<u64>().ok()) } else { None };
    match n {
        Some(n) if n <= max => Ok(n),
        _ => Err(usage(&format!("not a number from 0 to {max}: {:?}", String::from_utf8_lossy(s)))),
    }
}

fn flag01(s: &[u8]) -> R<bool> {
    match s {
        b"0" => Ok(false),
        b"1" => Ok(true),
        _ => Err(usage("a flag is 0 or 1")),
    }
}

fn budget_of(s: &[u8]) -> R<usize> {
    let n = number(s, MAX_BUDGET as u64)? as usize;
    if n < MIN_BUDGET {
        return Err(usage(&format!("a budget is {MIN_BUDGET} to {MAX_BUDGET} bytes")));
    }
    Ok(n)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteMode {
    Replace,
    CreateOnly,
    Append,
}

fn write_mode(s: &[u8]) -> R<WriteMode> {
    match s {
        b"replace" => Ok(WriteMode::Replace),
        b"create-only" => Ok(WriteMode::CreateOnly),
        b"append" => Ok(WriteMode::Append),
        _ => Err(usage("a write's mode is replace, create-only or append")),
    }
}

/// The parts of a path in the scope, each a C string. In the work scope a relative path ("."
/// alone is no part, where a folder is meant); in the sandbox scope an absolute one ("/" alone
/// is no part).
fn parts(p: &[u8], folder: bool) -> R<Vec<CString>> {
    let rel = if sandbox_scope() {
        if p.first() != Some(&b'/') || p.len() > MAX_PATH {
            return Err(usage(&format!(
                "not an absolute path of 1 to {MAX_PATH} bytes: {:?}",
                String::from_utf8_lossy(p)
            )));
        }
        if p == b"/" {
            return if folder { Ok(Vec::new()) } else { Err(usage("a file path is the root")) };
        }
        &p[1..]
    } else {
        if folder && p == b"." {
            return Ok(Vec::new());
        }
        if p.is_empty() || p.len() > MAX_PATH || p[0] == b'/' {
            return Err(usage(&format!(
                "not a relative path of 1 to {MAX_PATH} bytes: {:?}",
                String::from_utf8_lossy(p)
            )));
        }
        p
    };
    rel.split(|&c| c == b'/')
        .map(|part| {
            if part.is_empty() || part == b"." || part == b".." {
                return Err(usage(&format!("a path part is empty, . or ..: {:?}", String::from_utf8_lossy(p))));
            }
            CString::new(part).map_err(|_| usage("a path holds a NUL"))
        })
        .collect()
}

fn split_leaf(path: &[u8]) -> R<(Vec<CString>, CString)> {
    let mut p = parts(path, false)?;
    let leaf = p.pop().ok_or_else(|| usage("a file path is empty"))?;
    Ok((p, leaf))
}

/// Test hooks, compiled into a debug build alone (the one `cargo test` builds and runs); the
/// pinned helper is a release build, so its bytes hold none of them, which
/// sandbox/internal/nativehelper's TestPinnedHelperHoldsNoTestHooks checks. Each reads one
/// variable of the environment the test starts the helper with; a daemon starts the helper
/// with an empty one.
#[cfg(debug_assertions)]
mod hooks {
    /// PLIMSOLL_HELPER_TEST_PAUSE=POINT:FILE: at POINT the helper writes `note` to FILE and
    /// waits until FILE is gone (at most 20 s), so a test can change the folder between two
    /// steps of one call.
    pub fn pause(point: &str, note: &[u8]) {
        let Some(v) = std::env::var_os("PLIMSOLL_HELPER_TEST_PAUSE") else { return };
        let v = v.to_string_lossy().into_owned();
        let Some((p, file)) = v.split_once(':') else { return };
        if p != point || std::fs::write(file, note).is_err() {
            return;
        }
        let end = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::path::Path::new(file).exists() && std::time::Instant::now() < end {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    /// PLIMSOLL_HELPER_TEST_WORK_NOT_A_MOUNT=1: the work scope accepts a work folder that is
    /// not a mount of its own (a test's scratch folder cannot be one).
    pub fn work_need_not_be_a_mount() -> bool {
        std::env::var_os("PLIMSOLL_HELPER_TEST_WORK_NOT_A_MOUNT").is_some_and(|v| v == "1")
    }

    /// PLIMSOLL_HELPER_TEST_NO_MOUNT_ID=1: statx is read as a kernel before Linux 5.8 answers
    /// it, with no mount id stated, so a test can see the work scope refuse such a kernel.
    pub fn no_mount_id() -> bool {
        std::env::var_os("PLIMSOLL_HELPER_TEST_NO_MOUNT_ID").is_some_and(|v| v == "1")
    }

    /// PLIMSOLL_HELPER_TEST_OPENAT2_ENOSYS=1: the work folder's openat2 answers ENOSYS, as on a
    /// kernel before Linux 5.6 or under a seccomp profile that does not know the call, so a
    /// test can see the work scope refuse it.
    pub fn openat2_enosys() -> bool {
        std::env::var_os("PLIMSOLL_HELPER_TEST_OPENAT2_ENOSYS").is_some_and(|v| v == "1")
    }

    /// PLIMSOLL_HELPER_TEST_NO_TMPFILE=1: a write stages as on a file system without
    /// O_TMPFILE (gVisor's tmpfs), under a temporary name from the start.
    pub fn no_tmpfile() -> bool {
        std::env::var_os("PLIMSOLL_HELPER_TEST_NO_TMPFILE").is_some_and(|v| v == "1")
    }

    /// PLIMSOLL_HELPER_TEST_NO_LINK=1: an unnamed file cannot be linked (as with no /proc on a
    /// kernel that allows AT_EMPTY_PATH only with a capability), so a write stages again.
    pub fn no_link() -> bool {
        std::env::var_os("PLIMSOLL_HELPER_TEST_NO_LINK").is_some_and(|v| v == "1")
    }
}

#[cfg(not(debug_assertions))]
mod hooks {
    pub fn pause(_: &str, _: &[u8]) {}
    pub fn work_need_not_be_a_mount() -> bool {
        false
    }
    pub fn no_mount_id() -> bool {
        false
    }
    pub fn openat2_enosys() -> bool {
        false
    }
    pub fn no_tmpfile() -> bool {
        false
    }
    pub fn no_link() -> bool {
        false
    }
}

/// The folder paths start from: the work folder, or the root. In the work scope the work
/// folder must be a mount of its own (session-files-3): a folder the helper has opened can be
/// moved by another process while a call holds it, and only a mount's edge stops a move out
/// of the work folder (rename(2) across mounts is EXDEV), so no write of the call can land
/// outside it.
///
/// The work scope also needs a kernel that has openat2 (Linux 5.6) and whose statx states mount
/// ids (Linux 5.8; gVisor states them as well): resolve's RESOLVE_NO_XDEV and within_work's
/// mount id are what keep a call from crossing a mount below the work folder, and nothing else
/// tells a second mount of the work folder's own file system apart. On a kernel without either,
/// every work-scope command is refused here, before any path is resolved: exit 1 with ENOSYS
/// first on stderr (old_kernel), the contract's "any other failure", since the cause is the
/// machine's and not a path's (session-files-23).
///
/// The folder is opened O_PATH, as every folder on the way is (folder_at): a starting point,
/// never a folder read. A sandbox may forbid reading "/" itself and still allow what lies
/// beneath it (a Landlock policy that grants no read_dir on "/", as OpenShell's does), so an
/// O_RDONLY open here would refuse every call of the scope. A command that reads the root's
/// entries (a listing of "/" or of ".") opens it for reading then (readable), where such a
/// policy answers 86. In the work scope the work folder is opened by openat2 itself, so a
/// kernel without it answers before anything else is done.
fn root() -> R<OwnedFd> {
    let flags = sys::O_PATH | sys::O_DIRECTORY | sys::O_CLOEXEC;
    if sandbox_scope() {
        return sys::open_at(AT_FDCWD, c"/", flags, 0).map_err(|e| failed(&e, "open", b"/"));
    }
    let opened = if hooks::openat2_enosys() {
        Err(io::Error::from_raw_os_error(ENOSYS))
    } else {
        sys::open_at2(AT_FDCWD, c".", flags, 0)
    };
    let fd = match opened {
        Err(e) if e.raw_os_error() == Some(ENOSYS) => return Err(old_kernel("openat2", "this kernel has no openat2")),
        r => r.map_err(|e| failed(&e, "open", b"."))?,
    };
    let Some(here) = mount_id(&fd, c"") else { return Err(old_kernel("statx", NO_MOUNT_ID)) };
    let here = here.map_err(|e| failed(&e, "statx", b"."))?;
    if !hooks::work_need_not_be_a_mount() {
        own_mount(&fd, here)?;
    }
    if *WORK_MOUNT.get_or_init(|| here) != here {
        return Err(End::Failed("plimsoll-helper files: the work folder's mount changed within one call".into()));
    }
    Ok(fd)
}

const NO_MOUNT_ID: &str = "this kernel's statx states no mount id";

/// The work scope's refusal of a kernel that lacks what it needs (root): ENOSYS, the call that
/// showed it, and why, naming the kernel the scope needs.
fn old_kernel(call: &str, why: &str) -> End {
    End::Failed(errno::describe(
        &io::Error::from_raw_os_error(ENOSYS),
        call,
        &format!("the work scope needs Linux 5.8 or later, or gVisor: {why}"),
    ))
}

/// The mount id of `name` in `dir` (`name` empty: `dir` itself) as statx states it, not
/// following a link at the name; None where it states none (a kernel before Linux 5.8, which
/// root() refuses).
fn mount_id(dir: &OwnedFd, name: &CStr) -> Option<io::Result<u64>> {
    if hooks::no_mount_id() {
        return None;
    }
    sys::mount_id(dir.as_raw_fd(), name)
}

/// The mount an object is on: its mount id. A statx that states none after root() found one
/// stated fails closed (ENOSYS).
fn mount_of(fd: &OwnedFd) -> io::Result<u64> {
    mount_id(fd, c"").unwrap_or_else(|| Err(io::Error::from_raw_os_error(ENOSYS)))
}

/// The work folder's mount id, which root() states in the work scope before any path is resolved.
static WORK_MOUNT: OnceLock<u64> = OnceLock::new();

/// In the work scope, refuses an object `fd` holds (a pinned name, a folder on the way) that is
/// on another mount than the work folder (session-files-19), as beyond_mount; in the sandbox
/// scope, where the walls are the boundary, holds nothing back. Fails closed when the work
/// folder's mount is not stated.
fn within_work(fd: &OwnedFd) -> io::Result<()> {
    if sandbox_scope() {
        return Ok(());
    }
    let here = mount_of(fd)?;
    match WORK_MOUNT.get() {
        Some(work) if *work == here => Ok(()),
        _ => Err(beyond_mount()),
    }
}

/// What the work scope answers for a path across a mount below the work folder: 86, permission
/// denied (EACCES), the work scope's own refusal; the sandbox scope reaches it.
fn beyond_mount() -> io::Error {
    io::Error::from_raw_os_error(EACCES)
}

/// Refuses a work folder that is not a mount of its own: its mount id, `here`, is its parent's.
fn own_mount(work: &OwnedFd, here: u64) -> R<()> {
    let Some(up) = mount_id(work, c"..") else { return Err(old_kernel("statx", NO_MOUNT_ID)) };
    if here == up.map_err(|e| failed(&e, "statx", b".."))? {
        return Err(End::Failed(errno::describe(
            &io::Error::from_raw_os_error(EXDEV),
            "statx",
            "the work folder is not a mount of its own",
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Absent,
    Link,
    Folder,
    File,
    Other,
    /// A folder a recursive listing could not enter (no permission to read or search it): a
    /// listing's entry alone, never what a name is.
    Unreadable,
}

fn kind_of(m: &std::fs::Metadata) -> Kind {
    let t = m.file_type();
    if t.is_symlink() {
        Kind::Link
    } else if t.is_dir() {
        Kind::Folder
    } else if t.is_file() {
        Kind::File
    } else {
        Kind::Other
    }
}

/// The object at a name, pinned with O_PATH (which opens nothing: a FIFO or a device is not
/// opened by it) and its fstat. `follow` follows a link at the name; without it the link
/// itself is pinned. In the work scope the object must be on the work folder's mount
/// (within_work): a mount point at the name pins the mount's own root, which is refused.
fn pin_at(dir: RawFd, name: &CStr, follow: bool) -> io::Result<Option<(OwnedFd, std::fs::Metadata)>> {
    let flags = sys::O_PATH | sys::O_CLOEXEC | if follow { 0 } else { sys::O_NOFOLLOW };
    match sys::open_at(dir, name, flags, 0) {
        Err(e) if e.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
        Ok(fd) => {
            within_work(&fd)?;
            let m = File::from(fd.try_clone()?).metadata()?;
            Ok(Some((fd, m)))
        }
    }
}

/// What is at a name, by O_PATH and fstat: never opening the object itself (pin_at).
fn look_at(dir: RawFd, name: &CStr, follow: bool) -> io::Result<Option<std::fs::Metadata>> {
    Ok(pin_at(dir, name, follow)?.map(|(_, m)| m))
}

/// The parts joined by "/", one relative path.
fn joined(parts: &[CString]) -> CString {
    let mut b = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            b.push(b'/');
        }
        b.extend_from_slice(p.to_bytes());
    }
    CString::new(b).expect("parts hold no NUL")
}

/// Pins `parts` (at least one) from `root` with O_PATH and `flags` (O_DIRECTORY, O_NOFOLLOW or
/// neither: a resolution opens nothing for its content, reopen does that), by the scope's rule:
/// - the sandbox scope: one openat, resolved by the kernel as the guest's shell resolves it;
/// - the work scope: one openat2 with RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS and
///   RESOLVE_NO_XDEV, so a link that stays inside the work folder is followed, one that leaves
///   it (an absolute target, a ".." past the top, a /proc magic link) is refused as ELOOP, and
///   a part that is a mount below the work folder is refused as beyond_mount (86), the kernel
///   checking each step of the resolution itself (EAGAIN, when a rename raced it, is tried
///   again). root() has refused a kernel without openat2 before any call gets here.
///
/// A final link is followed unless `flags` holds O_NOFOLLOW (where O_PATH then pins the link).
fn resolve(root: &OwnedFd, parts: &[CString], flags: c_int) -> io::Result<OwnedFd> {
    let flags = sys::O_PATH | (flags & (sys::O_DIRECTORY | sys::O_NOFOLLOW)) | sys::O_CLOEXEC;
    let path = joined(parts);
    if sandbox_scope() {
        return sys::open_at(root.as_raw_fd(), &path, flags, 0);
    }
    let beneath = sys::RESOLVE_BENEATH | sys::RESOLVE_NO_MAGICLINKS;
    // Whether a try met a mount: the last answer when every try is used.
    let mut crossed = false;
    for _ in 0..16 {
        match sys::open_at2(root.as_raw_fd(), &path, flags, beneath | sys::RESOLVE_NO_XDEV) {
            Err(e) if e.raw_os_error() == Some(EAGAIN) => {}
            // EXDEV is both refusals: a step that would leave the work folder, and a mount
            // crossed. The path is resolved once more without RESOLVE_NO_XDEV (O_PATH:
            // nothing is opened, and what it pins is dropped): EXDEV again is the leaving
            // (80); an object on another mount is the mount (86). Anything else (an object
            // on the work mount, reached through a mount and back by a link, or an error
            // from beyond one) is a mount crossed, or a path another process changed
            // between the two resolutions, so both are tried again, and the answer once
            // every try is used is the mount: a race of the guest's then reads as 86, never
            // as a path followed.
            Err(e) if e.raw_os_error() == Some(EXDEV) => match sys::open_at2(root.as_raw_fd(), &path, flags, beneath) {
                Err(e) if e.raw_os_error() == Some(EXDEV) => return Err(io::Error::from_raw_os_error(ELOOP)),
                Ok(fd) if within_work(&fd).is_err() => return Err(beyond_mount()),
                _ => crossed = true,
            },
            // What it pins is held to the work folder's mount as well: a runtime that took
            // RESOLVE_NO_XDEV and did not keep it would fail closed here.
            Ok(fd) => return within_work(&fd).map(|()| fd),
            r => return r,
        }
    }
    Err(if crossed { beyond_mount() } else { io::Error::from_raw_os_error(EAGAIN) })
}

/// The folder at `parts` from `root` (the root itself for none), opened O_PATH by the scope's
/// rule (resolve): 81 nothing there, 83 not a folder, 80 a link that leaves the work folder.
fn folder_at(root: &OwnedFd, parts: &[CString]) -> io::Result<OwnedFd> {
    if parts.is_empty() {
        return root.try_clone();
    }
    resolve(root, parts, sys::O_PATH | sys::O_DIRECTORY)
}

/// folder_at, making each missing folder on the way (mode 0777 less the umask, as mkdir -p
/// makes it). A dangling link on the way is not made through: it is 81.
fn make_folders(root: &OwnedFd, parts: &[CString]) -> io::Result<OwnedFd> {
    let mut cur = root.try_clone()?;
    for k in 0..parts.len() {
        cur = match folder_at(root, &parts[..=k]) {
            Err(e) if e.raw_os_error() == Some(ENOENT) => {
                match sys::mkdir_at(cur.as_raw_fd(), &parts[k], 0o777) {
                    Ok(()) => {}
                    Err(e) if e.raw_os_error() == Some(EEXIST) => {}
                    Err(e) => return Err(e),
                }
                folder_at(root, &parts[..=k])?
            }
            r => r?,
        };
    }
    Ok(cur)
}

/// The folder at `parents`, as an answer's code.
fn parent(root: &OwnedFd, parents: &[CString], path: &[u8]) -> R<OwnedFd> {
    folder_at(root, parents).map_err(|e| failed(&e, "open", path))
}

/// A folder opened O_PATH, opened again for reading its entries.
fn readable(dir: &OwnedFd) -> io::Result<OwnedFd> {
    sys::open_at(dir.as_raw_fd(), c".", sys::O_DIRECTORY | sys::O_CLOEXEC, 0)
}

/// The object `pin` (an O_PATH descriptor) opened again with `flags` through /proc/self/fd, the
/// same object and never a name looked up again, so what fstat classified is what is opened;
/// it must then be that object (device and inode), or the answer is EAGAIN. Where /proc is not
/// mounted (ENOENT there: the link of a descriptor this process holds is always there when it
/// is) the call fails closed, exit 1 with ENOENT on /proc/self/fd: the name is never looked up
/// again, since by then it could hold a FIFO or a device, which the open would open before any
/// check saw it (session-files-21).
fn reopen(pin: &OwnedFd, flags: c_int, path: &[u8]) -> R<File> {
    let magic = format!("/proc/self/fd/{}", pin.as_raw_fd());
    let flags = flags | sys::O_NONBLOCK | sys::O_CLOEXEC;
    let f = match sys::open_at(AT_FDCWD, &CString::new(magic.as_str()).expect("no NUL"), flags, 0) {
        Ok(fd) => File::from(fd),
        Err(e) if e.raw_os_error() == Some(ENOENT) => {
            return Err(End::Failed(errno::describe(
                &e,
                "open",
                &format!("{magic} (no /proc: no file is opened by its name)"),
            )));
        }
        Err(e) => return Err(failed(&e, "open", path)),
    };
    let pinned = File::from(pin.try_clone().map_err(|e| failed(&e, "dup", path))?);
    let a = pinned.metadata().map_err(|e| failed(&e, "fstat", path))?;
    let b = f.metadata().map_err(|e| failed(&e, "fstat", path))?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err(failed(&io::Error::from_raw_os_error(EAGAIN), "open", path));
    }
    Ok(f)
}

/// The regular file at `parts` (a final link followed by the scope's rule), classified on an
/// O_PATH descriptor first and opened with `flags` only when it is a regular file, by reopen:
/// a FIFO or a device at the path is never opened (session-files-8). 82 a folder, 85 anything
/// else.
fn open_regular(root: &OwnedFd, parts: &[CString], flags: c_int, path: &[u8]) -> R<(File, std::fs::Metadata)> {
    let pin = resolve(root, parts, sys::O_PATH).map_err(|e| failed(&e, "open", path))?;
    let m = File::from(pin.try_clone().map_err(|e| failed(&e, "dup", path))?)
        .metadata()
        .map_err(|e| failed(&e, "fstat", path))?;
    match kind_of(&m) {
        Kind::File => {}
        Kind::Folder => return Err(End::Code(ISDIR)),
        _ => return Err(End::Code(NOTREG)),
    }
    let f = reopen(&pin, flags, path)?;
    let m = f.metadata().map_err(|e| failed(&e, "fstat", path))?;
    Ok((f, m))
}

/// An answer being framed within its budget.
struct Frames<'a> {
    out: &'a mut Vec<u8>,
    budget: usize,
    count: u64,
}

fn frame_len(n: usize) -> usize {
    1 + n.to_string().len() + 1 + n
}

impl Frames<'_> {
    fn new(out: &mut Vec<u8>, budget: usize) -> Frames<'_> {
        out.clear();
        Frames { out, budget, count: 0 }
    }

    fn push(&mut self, tag: u8, payload: &[u8]) {
        self.out.push(tag);
        self.out.extend_from_slice(payload.len().to_string().as_bytes());
        self.out.push(b':');
        self.out.extend_from_slice(payload);
    }

    /// One entry of `frames`, all its frames or none: false when they would pass the budget
    /// with room kept for the last frame.
    fn entry(&mut self, frames: &[(u8, &[u8])]) -> bool {
        let need: usize = frames.iter().map(|(_, p)| frame_len(p.len())).sum();
        if self.out.len() + need + END_ROOM > self.budget {
            return false;
        }
        for (tag, payload) in frames {
            self.push(*tag, payload);
        }
        self.count += 1;
        true
    }

    /// The last frame: "." when the answer is whole, "+" when it stopped at its budget.
    fn end(mut self, whole: bool) {
        let n = self.count.to_string();
        self.push(if whole { b'.' } else { b'+' }, n.as_bytes());
    }
}

/// An answer of one entry (each command bounds its own sizes).
fn one(out: &mut Vec<u8>, frames: &[(u8, &[u8])]) {
    let mut f = Frames::new(out, usize::MAX);
    f.entry(frames);
    f.end(true);
}

fn kind_tag(k: Kind) -> &'static [u8] {
    match k {
        Kind::Folder => b"d",
        Kind::File => b"f",
        Kind::Link => b"l",
        Kind::Unreadable => b"u",
        _ => b"o",
    }
}

/// `stat PATH`: "k" the kind (f, d, l, o), "s" the size, "m" the permission bits, "t" the
/// modification time in whole seconds since 1970 (0 for one before). The last part is never
/// followed, in either scope, so a link there is "l"; links before it are followed by the
/// scope's rule.
fn stat(path: &[u8], out: &mut Vec<u8>) -> R<()> {
    let root = root()?;
    let p = parts(path, true)?;
    let m = match p.split_last() {
        None => File::from(root.try_clone().map_err(|e| failed(&e, "dup", path))?)
            .metadata()
            .map_err(|e| failed(&e, "fstat", path))?,
        Some((leaf, parents)) => {
            let dir = parent(&root, parents, path)?;
            match look_at(dir.as_raw_fd(), leaf, false) {
                Ok(Some(m)) => m,
                Ok(None) => return Err(End::Code(NOENT)),
                Err(e) => return Err(failed(&e, "open", path)),
            }
        }
    };
    let k = kind_of(&m);
    let (size, mode, time) = (m.len().to_string(), (m.mode() & 0o7777).to_string(), m.mtime().max(0).to_string());
    one(out, &[(b'k', kind_tag(k)), (b's', size.as_bytes()), (b'm', mode.as_bytes()), (b't', time.as_bytes())]);
    Ok(())
}

/// `read PATH OFFSET LENGTH`: "s" the file's size at its open (size_at_open: no promise of the
/// length read, since the file can change while it is read), "b" up to LENGTH bytes from OFFSET
/// (fewer at its end, none past it). The bytes are read to LENGTH or the end, whatever the size at
/// open says: a file of the kernel's (procfs, sysfs) states size 0 and has content, which
/// `readmany` answered and `read` did not (review finding session-files-18).
fn read(path: &[u8], offset: u64, length: u64, out: &mut Vec<u8>) -> R<()> {
    let p = parts(path, false)?;
    let root = root()?;
    let (mut f, m) = open_regular(&root, &p, sys::O_RDONLY, path)?;
    let mut buf = Vec::new();
    f.seek(SeekFrom::Start(offset)).map_err(|e| failed(&e, "lseek", path))?;
    f.take(length).read_to_end(&mut buf).map_err(|e| failed(&e, "read", path))?;
    let size = m.len().to_string();
    one(out, &[(b's', size.as_bytes()), (b'b', &buf)]);
    Ok(())
}

/// Standard input, at most `max` bytes (87 past it).
fn read_stdin(max: usize) -> R<Vec<u8>> {
    let mut data = Vec::new();
    io::stdin().lock().take(max as u64 + 1).read_to_end(&mut data).map_err(|e| failed(&e, "read", b"stdin"))?;
    if data.len() > max {
        return Err(End::Code(FBIG));
    }
    Ok(data)
}

/// `write PATH replace|create-only|append 0|1`: stdin (at most 4 MiB) into the file; with 1 the
/// folders on the way are made (and stay, should the write then fail). Answers "n", the bytes
/// written. `replace` and `create-only` stage the content in a file of their own and publish
/// it whole (stage_and_publish); `append` adds to the end in place (append).
fn write(path: &[u8], mode: WriteMode, make_parents: bool, out: &mut Vec<u8>) -> R<()> {
    let (parents, leaf) = split_leaf(path)?;
    let content = read_stdin(MAX_WRITE)?;
    let root = root()?;
    let dir = if make_parents { make_folders(&root, &parents) } else { folder_at(&root, &parents) }
        .map_err(|e| failed(&e, "open", path))?;
    hooks::pause("parent", b"");
    if mode == WriteMode::Append {
        let mut all = parents;
        all.push(leaf.clone());
        append(&root, &all, &dir, &leaf, &content, path)?;
    } else {
        stage_and_publish(&dir, &leaf, mode, &content, path)?;
    }
    one(out, &[(b'n', content.len().to_string().as_bytes())]);
    Ok(())
}

/// `write PATH append`: opens the regular file at the path (a final link followed by the
/// scope's rule, open_regular), or makes it when nothing is at the name (O_CREAT with O_EXCL
/// and O_NOFOLLOW, so never through a link: a link to nothing is 81), and adds the content at
/// its end. Not atomic: a call left without an answer may have added any part. A write that
/// fails before its first byte answers its error (89 for no space), and nothing was added; one
/// that fails after it added a part answers 92: what the file holds is unknown, as after a call
/// left without an answer, and the part stays. It is never cut back (session-files-22): the
/// length the file had says nothing of whose bytes follow it, since another process of the
/// guest's may append its own between the part and any cut, and a cut would take those too.
fn append(root: &OwnedFd, all: &[CString], dir: &OwnedFd, leaf: &CStr, content: &[u8], path: &[u8]) -> R<()> {
    for _ in 0..8 {
        let f = match open_regular(root, all, sys::O_WRONLY | sys::O_APPEND, path) {
            Ok((f, _)) => f,
            Err(End::Code(NOENT)) => {
                let flags = sys::O_WRONLY
                    | sys::O_APPEND
                    | sys::O_CREAT
                    | sys::O_EXCL
                    | sys::O_NOFOLLOW
                    | sys::O_NONBLOCK
                    | sys::O_CLOEXEC;
                match sys::open_at(dir.as_raw_fd(), leaf, flags, 0o666) {
                    Ok(fd) => File::from(fd),
                    Err(e) if e.raw_os_error() == Some(EEXIST) => match look_at(dir.as_raw_fd(), leaf, false) {
                        Ok(Some(m)) if kind_of(&m) == Kind::Link => return Err(End::Code(NOENT)),
                        Ok(_) => continue,
                        Err(e) => return Err(failed(&e, "open", path)),
                    },
                    Err(e) => return Err(failed(&e, "open", path)),
                }
            }
            Err(e) => return Err(e),
        };
        return append_to(&f, content, path);
    }
    Err(failed(&io::Error::from_raw_os_error(EAGAIN), "open", path))
}

/// Adds `content` at the end of `f` (open O_APPEND); a failure after a part was added is 92,
/// never cut back (append).
fn append_to(f: &File, content: &[u8], path: &[u8]) -> R<()> {
    let mut written = 0usize;
    while written < content.len() {
        match (&*f).write(&content[written..]) {
            Ok(0) => return append_failed(written, &io::Error::from(io::ErrorKind::WriteZero), path),
            Ok(n) => written += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return append_failed(written, &e, path),
        }
    }
    Ok(())
}

/// A failed append's answer: its error when nothing was added, 92 once a part was.
fn append_failed(written: usize, e: &io::Error, path: &[u8]) -> R<()> {
    if written == 0 {
        return Err(failed(e, "write", path));
    }
    Err(End::Code(UNKNOWN))
}

/// A file being staged for a write: unnamed (O_TMPFILE, where the file system offers it), or
/// under a staging name in the target's folder.
struct Staged {
    file: File,
    name: Option<CString>,
}

/// `write PATH replace|create-only` (session-files-4): the content goes into a file of the
/// helper's own, made with O_TMPFILE where the file system offers it, so no name points at it
/// and no other process can open it while it is written and synced. create-only then links it
/// at the name (linkat, which refuses a name already there: 84), with no staging name at all;
/// replace links it at a staging name (`.plimsoll-write-`, the helper's process id in hex,
/// "-", 16 hex digits) and renames that over the name. Where O_TMPFILE is not offered (gVisor's
/// tmpfs answers EOPNOTSUPP, measured 2026-11-26) the file is made under the staging name from
/// the start. After the publish the name must hold the very file written (device and inode),
/// or the answer is 92: another process swapped the staging name, and what the name holds is
/// not known to be the content. A failed write removes its staging name; one a killed helper
/// left is removed by the next replace or create-only write into that folder
/// (remove_left_staging).
fn stage_and_publish(dir: &OwnedFd, leaf: &CStr, mode: WriteMode, content: &[u8], path: &[u8]) -> R<()> {
    // What is at the name now, pinned and classified without opening it: replace keeps a
    // regular file's permission bits and refuses one the guest may not write (the reopen for
    // writing is the kernel's check, as the shell's); a link at the name is replaced, never
    // written through, in both scopes; create-only refuses anything there (84).
    let keep_mode = match (mode, pin_at(dir.as_raw_fd(), leaf, false).map_err(|e| failed(&e, "open", path))?) {
        (_, None) => None,
        (WriteMode::CreateOnly, Some(_)) => return Err(End::Code(EXIST)),
        (_, Some((pin, m))) => match kind_of(&m) {
            Kind::Link => None,
            Kind::Folder => return Err(End::Code(ISDIR)),
            Kind::File => {
                reopen(&pin, sys::O_WRONLY, path)?;
                Some(m.mode() & 0o7777)
            }
            _ => return Err(End::Code(NOTREG)),
        },
    };
    remove_left_staging(dir);
    let mut named = hooks::no_tmpfile();
    loop {
        let mut staged = stage(dir, named, path)?;
        let done = fill_and_publish(dir, leaf, mode, &mut staged, keep_mode, content, path);
        if done.is_err()
            && let Some(name) = &staged.name
        {
            let _ = sys::unlink_at(dir.as_raw_fd(), name, 0);
        }
        match done {
            // The unnamed file could not be linked anywhere (no /proc, and a kernel that allows
            // AT_EMPTY_PATH only with a capability): stage again under a name.
            Err(End::Code(RESTAGE)) if !named => named = true,
            Err(End::Code(RESTAGE)) => return Err(failed(&io::Error::from_raw_os_error(ENOENT), "linkat", path)),
            r => return r,
        }
    }
}

/// fill_and_publish's word for an unnamed file it could not link (stage_and_publish stages again
/// under a name); never an exit code.
const RESTAGE: i32 = -1;

/// Whether a failed link of an unnamed file means it cannot be linked at all (rather than that
/// the name is taken, or the folder refuses it).
fn unlinkable(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(ENOENT | EPERM | EXDEV | EOPNOTSUPP | EINVAL))
}

/// A new staged file in `dir`: O_TMPFILE where offered (and `named` is false), else under a
/// staging name made with O_EXCL (another try on a name taken).
fn stage(dir: &OwnedFd, named: bool, path: &[u8]) -> R<Staged> {
    if !named {
        match sys::open_at(dir.as_raw_fd(), c".", sys::O_TMPFILE | sys::O_WRONLY | sys::O_CLOEXEC, 0o666) {
            Ok(fd) => return Ok(Staged { file: File::from(fd), name: None }),
            Err(e) if matches!(e.raw_os_error(), Some(EACCES | EPERM | ENOSPC | EDQUOT | EROFS)) => {
                return Err(failed(&e, "open", path));
            }
            // EOPNOTSUPP (a file system without O_TMPFILE), EISDIR or EINVAL (a kernel without
            // it): stage under a name.
            Err(_) => {}
        }
    }
    for _ in 0..16 {
        let name = staging_name();
        let flags = sys::O_WRONLY | sys::O_CREAT | sys::O_EXCL | sys::O_NOFOLLOW | sys::O_CLOEXEC;
        match sys::open_at(dir.as_raw_fd(), &name, flags, 0o666) {
            Ok(fd) => return Ok(Staged { file: File::from(fd), name: Some(name) }),
            Err(e) if e.raw_os_error() == Some(EEXIST) => {}
            Err(e) => return Err(failed(&e, "open", path)),
        }
    }
    Err(End::Code(EXIST))
}

/// The prefix of every staging name.
const STAGING: &[u8] = b".plimsoll-write-";

/// A staging name no other file is likely to have: STAGING, this process's id in hex, "-", 16
/// random hex digits.
fn staging_name() -> CString {
    let mut seed = [0u8; 8];
    if let Ok(mut r) = File::open("/dev/urandom") {
        let _ = r.read_exact(&mut seed);
    }
    let n = u64::from_le_bytes(seed)
        ^ std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
    let mut b = STAGING.to_vec();
    b.extend_from_slice(format!("{:x}-{n:016x}", std::process::id()).as_bytes());
    CString::new(b).expect("no NUL")
}

/// The most entries of a folder remove_left_staging reads; a larger folder is not tidied.
const TIDY_MAX_ENTRIES: usize = 65_536;

/// Removes the staging names in `dir` whose helper process is gone (a helper killed between
/// making its staging name and publishing it, which no cleanup of its own can follow), so a
/// killed write leaves nothing behind past the next replace or create-only write into that
/// folder. A name whose process id field does not parse, or whose process exists, is kept.
/// Only a folder of at most TIDY_MAX_ENTRIES entries is read, so the cost of a write stays
/// bounded; errors are ignored, since tidying is not the call's work.
fn remove_left_staging(dir: &OwnedFd) {
    let Ok(rd) = readable(dir) else { return };
    let bound = sys::FolderBound { entries: TIDY_MAX_ENTRIES, bytes: TIDY_MAX_ENTRIES * (256 + sys::ENTRY_OVERHEAD) };
    let Ok(Some(entries)) = sys::read_folder(rd, bound) else { return };
    for (name, _) in entries {
        let Some(rest) = name.strip_prefix(STAGING) else { continue };
        let Some((pid, _)) =
            rest.split_first().and_then(|_| rest.iter().position(|&c| c == b'-')).map(|i| rest.split_at(i))
        else {
            continue;
        };
        let Some(pid) = std::str::from_utf8(pid).ok().and_then(|s| i32::from_str_radix(s, 16).ok()) else { continue };
        if pid as u32 == std::process::id() || sys::process_exists(pid) {
            continue;
        }
        if let Ok(c) = CString::new(name) {
            let _ = sys::unlink_at(dir.as_raw_fd(), &c, 0);
        }
    }
}

/// Fills the staged file (permission bits, content, fsync), publishes it at `leaf`, and checks
/// that the name holds it (stage_and_publish).
fn fill_and_publish(
    dir: &OwnedFd,
    leaf: &CStr,
    mode: WriteMode,
    staged: &mut Staged,
    keep_mode: Option<u32>,
    content: &[u8],
    path: &[u8],
) -> R<()> {
    if let Some(bits) = keep_mode {
        staged
            .file
            .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(bits))
            .map_err(|e| failed(&e, "fchmod", path))?;
    }
    staged.file.write_all(content).map_err(|e| failed(&e, "write", path))?;
    staged.file.sync_all().map_err(|e| failed(&e, "fsync", path))?;
    let ours = staged.file.metadata().map_err(|e| failed(&e, "fstat", path))?;
    let d = dir.as_raw_fd();
    if staged.name.is_none() {
        if mode == WriteMode::CreateOnly {
            link_unnamed(&staged.file, d, leaf)
                .map_err(|e| if unlinkable(&e) { End::Code(RESTAGE) } else { failed(&e, "linkat", path) })?;
        } else {
            let mut linked = None;
            for _ in 0..16 {
                let name = staging_name();
                match link_unnamed(&staged.file, d, &name) {
                    Ok(()) => {
                        linked = Some(name);
                        break;
                    }
                    Err(e) if e.raw_os_error() == Some(EEXIST) => {}
                    Err(e) if unlinkable(&e) => return Err(End::Code(RESTAGE)),
                    Err(e) => return Err(failed(&e, "linkat", path)),
                }
            }
            staged.name = Some(linked.ok_or(End::Code(EXIST))?);
        }
    }
    if let Some(name) = &staged.name {
        hooks::pause("staged", name.to_bytes());
        let flags = if mode == WriteMode::CreateOnly { sys::RENAME_NOREPLACE } else { 0 };
        sys::rename_at(d, name, d, leaf, flags).map_err(|e| failed(&e, "rename", path))?;
        staged.name = None;
    }
    match look_at(d, leaf, false) {
        Ok(Some(m)) if (m.dev(), m.ino()) == (ours.dev(), ours.ino()) => Ok(()),
        _ => Err(End::Code(UNKNOWN)),
    }
}

/// Links the unnamed file `f` at `name` in `dir`: through /proc/self/fd (AT_SYMLINK_FOLLOW,
/// which needs no capability), else by AT_EMPTY_PATH where /proc is not there.
fn link_unnamed(f: &File, dir: RawFd, name: &CStr) -> io::Result<()> {
    if hooks::no_link() {
        return Err(io::Error::from_raw_os_error(ENOENT));
    }
    let magic = CString::new(format!("/proc/self/fd/{}", f.as_raw_fd())).expect("no NUL");
    match sys::link_at(AT_FDCWD, &magic, dir, name, sys::AT_SYMLINK_FOLLOW) {
        Err(e) if e.raw_os_error() == Some(ENOENT) => sys::link_at(f.as_raw_fd(), c"", dir, name, sys::AT_EMPTY_PATH),
        r => r,
    }
}

/// `mkdir PATH 0|1`: makes the folder (with 1, and those on the way); a folder already there
/// is done (a link to one inside the work folder too, by the scope's rule), anything else
/// there is 84 (a link to nothing included).
fn mkdir(path: &[u8], make_parents: bool) -> R<()> {
    let p = parts(path, false)?;
    let (last, parents) = p.split_last().ok_or_else(|| usage("a folder path is empty"))?;
    let root = root()?;
    let dir = if make_parents { make_folders(&root, parents) } else { folder_at(&root, parents) }
        .map_err(|e| failed(&e, "open", path))?;
    match sys::mkdir_at(dir.as_raw_fd(), last, 0o777) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(EEXIST) => match folder_at(&root, &p) {
            Ok(_) => Ok(()),
            Err(e) if matches!(e.raw_os_error(), Some(ENOTDIR | ENOENT)) => Err(End::Code(EXIST)),
            Err(e) => Err(failed(&e, "open", path)),
        },
        Err(e) => Err(failed(&e, "mkdir", path)),
    }
}

/// `remove PATH 0|1`: with 0 removes anything but a folder (82); with 1 an empty folder (83 for
/// anything else, 88 when it is not empty). A link at the last part is removed itself, never
/// its target, in both scopes.
fn remove(path: &[u8], is_folder: bool) -> R<()> {
    let (parents, leaf) = split_leaf(path)?;
    let root = root()?;
    let dir = parent(&root, &parents, path)?;
    let k = match look_at(dir.as_raw_fd(), &leaf, false) {
        Ok(m) => m.as_ref().map_or(Kind::Absent, kind_of),
        Err(e) => return Err(failed(&e, "open", path)),
    };
    match (k, is_folder) {
        (Kind::Absent, _) => return Err(End::Code(NOENT)),
        (Kind::Folder, false) => return Err(End::Code(ISDIR)),
        (Kind::Folder, true) | (_, false) => {}
        (_, true) => return Err(End::Code(NOTDIR)),
    }
    let flags = if is_folder { sys::AT_REMOVEDIR } else { 0 };
    sys::unlink_at(dir.as_raw_fd(), &leaf, flags).map_err(|e| match e.raw_os_error() {
        Some(EEXIST) => End::Code(NOTEMPTY),
        _ => failed(&e, if is_folder { "rmdir" } else { "unlink" }, path),
    })
}

/// `rename FROM TO 0|1`: moves FROM to TO; with 0 refuses a TO already there (84), atomically
/// (renameat2's RENAME_NOREPLACE). A link at either last part is moved or replaced itself,
/// never its target, in both scopes.
fn rename(from: &[u8], to: &[u8], replace: bool) -> R<()> {
    let (fp, fl) = split_leaf(from)?;
    let (tp, tl) = split_leaf(to)?;
    let root = root()?;
    let fd = parent(&root, &fp, from)?;
    let td = parent(&root, &tp, to)?;
    match look_at(fd.as_raw_fd(), &fl, false) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(End::Code(NOENT)),
        Err(e) => return Err(failed(&e, "open", from)),
    }
    // A mount point at TO (in the work scope, one below the work folder) is 86, as at FROM.
    look_at(td.as_raw_fd(), &tl, false).map_err(|e| failed(&e, "open", to))?;
    let flags = if replace { 0 } else { sys::RENAME_NOREPLACE };
    sys::rename_at(fd.as_raw_fd(), &fl, td.as_raw_fd(), &tl, flags).map_err(|e| failed(&e, "rename", from))
}

/// The kind and size of an entry: its listed type, then fstat of it opened O_PATH without
/// following it (a regular file's size needs it, and so does a type the file system does not
/// state). A listing never follows a link, in either scope.
fn entry_kind(dir: &OwnedFd, name: &[u8], dtype: u8) -> (Kind, u64) {
    match dtype {
        sys::DT_LNK => (Kind::Link, 0),
        sys::DT_DIR => (Kind::Folder, 0),
        sys::DT_REG | sys::DT_UNKNOWN => {
            let Ok(c) = CString::new(name) else { return (Kind::Other, 0) };
            match look_at(dir.as_raw_fd(), &c, false) {
                Ok(Some(m)) => {
                    let k = kind_of(&m);
                    (k, if k == Kind::File { m.len() } else { 0 })
                }
                _ => (Kind::Other, 0),
            }
        }
        _ => (Kind::Other, 0),
    }
}

/// What one `list` call may spend (session-files-5), each checked while it is spent, never
/// after: entries read from the folders it walks (cumulative), bytes of names held at once
/// (each folder on the walk's path holds its sorted entries), and how deep below DIR it goes
/// (each level holds a descriptor). Past any of them the call ends with 91, never a cut
/// answer; so does an entry whose path from DIR would be longer than MAX_PATH bytes, since
/// every path a listing answers must be accepted back as its cursor (session-files-6).
#[derive(Clone, Copy, Debug)]
struct WalkBounds {
    entries: usize,
    bytes: usize,
    depth: usize,
}

const LIST_BOUNDS: WalkBounds = WalkBounds { entries: 1_000_000, bytes: 64 << 20, depth: 512 };

/// One folder of a walk: its entries, sorted by name, the next to look at, the rest of the
/// cursor below it, and the bytes its entries hold.
struct Level<'c> {
    dir: OwnedFd,
    prefix: Vec<u8>,
    entries: sys::Entries,
    next: usize,
    after: Option<&'c [&'c [u8]]>,
    held: usize,
}

/// What a walk has left to spend.
struct Spend {
    entries: usize,
    bytes: usize,
}

/// The entries of the folder `dir` (O_PATH), sorted by name, taken from what is left: 91 past it.
fn entries(dir: &OwnedFd, left: &mut Spend) -> io::Result<Result<(sys::Entries, usize), End>> {
    entries_of(readable(dir)?, left)
}

/// The entries of the folder `rd`, opened for reading (readable), as entries says.
fn entries_of(rd: OwnedFd, left: &mut Spend) -> io::Result<Result<(sys::Entries, usize), End>> {
    let bound = sys::FolderBound { entries: left.entries, bytes: left.bytes };
    let Some(mut e) = sys::read_folder(rd, bound)? else { return Ok(Err(End::Code(TOOMANY))) };
    let held = e.iter().map(|(n, _)| n.len() + sys::ENTRY_OVERHEAD).sum::<usize>();
    left.entries -= e.len();
    left.bytes -= held;
    e.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    Ok(Ok((e, held)))
}

/// Lists the tree at `top` into the frames, depth first, with an explicit stack (one level per
/// folder open, each holding its own folder's entries alone): Ok(true) when it is whole,
/// Ok(false) once the frames are full (with at least one entry in them: every entry fits the
/// least budget), 91 past `bounds`. `cursor`, when given, is the path after which the listing
/// starts. A folder below the top that cannot be entered for want of permission (to read it or
/// to search it: readable opens "." from it, which needs both) is listed as "u", unreadable, and
/// not entered, so a listing that answers names every subtree it could not list rather than
/// leaving it out, and goes on (session-files-6 and the lead after it: a recursive listing of
/// the sandbox's "/" meets such folders at once). The kind is known before the entry is framed,
/// because the folder is opened for reading first. One that is gone, or no longer a folder, by
/// the time the walk opens it is a change made while it ran, and lists nothing.
fn walk_tree(
    frames: &mut Frames,
    recursive: bool,
    pattern: Option<&[&[u8]]>,
    top: OwnedFd,
    cursor: Option<&[&[u8]]>,
    bounds: WalkBounds,
) -> R<bool> {
    let mut left = Spend { entries: bounds.entries, bytes: bounds.bytes };
    let (first, held) = entries(&top, &mut left).map_err(|e| failed(&e, "open", b"."))??;
    let mut stack = vec![Level { dir: top, prefix: Vec::new(), entries: first, next: 0, after: cursor, held }];
    while let Some(level) = stack.last_mut() {
        if level.next == level.entries.len() {
            left.bytes += level.held;
            stack.pop();
            continue;
        }
        let k = level.next;
        level.next += 1;
        let (name, dtype) = (std::mem::take(&mut level.entries[k].0), level.entries[k].1);
        // Where the entry stands against the cursor: before it (skipped), the cursor itself
        // (listed already; a folder's entries still come after it), on the cursor's path (a
        // folder listed already, the rest of the cursor below it), or after it.
        let mut below: Option<&[&[u8]]> = None;
        let mut listed = false;
        if let Some(c) = level.after {
            match name.as_slice().cmp(c[0]) {
                std::cmp::Ordering::Less => continue,
                std::cmp::Ordering::Equal => {
                    listed = true;
                    if c.len() > 1 {
                        below = Some(&c[1..]);
                    }
                }
                std::cmp::Ordering::Greater => {}
            }
        }
        let (mut kind, size) = entry_kind(&level.dir, &name, dtype);
        // A folder the walk will enter is opened for reading now, before its entry is framed,
        // so a folder the guest may not enter is framed "u" (unreadable), never "d" with
        // nothing below it. None: not entered (a flat listing, not a folder, or gone meanwhile).
        let mut sub: Option<(OwnedFd, OwnedFd)> = None;
        if kind == Kind::Folder && recursive {
            let Ok(c) = CString::new(name.as_slice()) else { continue };
            let flags = sys::O_PATH | sys::O_DIRECTORY | sys::O_NOFOLLOW | sys::O_CLOEXEC;
            let mut path = level.prefix.clone();
            path.extend_from_slice(&name);
            match sys::open_at(level.dir.as_raw_fd(), &c, flags, 0) {
                Ok(pin) => {
                    // In the work scope a folder on another mount (a mount point below the work
                    // folder) is never entered: within_work refuses it as EACCES, so it is
                    // listed "u", a folder the listing could not enter (session-files-19).
                    let opened = within_work(&pin).and_then(|()| readable(&pin));
                    match opened {
                        Ok(rd) => sub = Some((pin, rd)),
                        Err(e) if matches!(e.raw_os_error(), Some(EACCES | EPERM)) => kind = Kind::Unreadable,
                        Err(e) if matches!(e.raw_os_error(), Some(ENOENT | ENOTDIR)) => {}
                        Err(e) => return Err(failed(&e, "open", &path)),
                    }
                }
                Err(e) if matches!(e.raw_os_error(), Some(ENOENT | ENOTDIR | ELOOP)) => {}
                Err(e) if matches!(e.raw_os_error(), Some(EACCES | EPERM)) => kind = Kind::Unreadable,
                Err(e) => return Err(failed(&e, "open", &path)),
            }
        }
        if below.is_some() && kind != Kind::Folder {
            // The cursor went below a folder that is now something else: it came before.
            continue;
        }
        if level.prefix.len() + name.len() > MAX_PATH {
            return Err(End::Code(TOOMANY));
        }
        let mut path = level.prefix.clone();
        path.extend_from_slice(&name);
        if !listed && pattern.is_none_or(|p| glob::matches(p, &path)) {
            let size = size.to_string();
            if !frames.entry(&[(b'p', &path), (b'k', kind_tag(kind)), (b's', size.as_bytes())]) {
                if frames.count == 0 {
                    // Not reached: MIN_BUDGET holds the largest entry.
                    return Err(End::Failed("plimsoll-helper files: an entry past the least budget".into()));
                }
                return Ok(false);
            }
        }
        if let Some((sub, rd)) = sub {
            let (found, held) = match entries_of(rd, &mut left) {
                Ok(r) => r?,
                Err(e) if matches!(e.raw_os_error(), Some(ENOENT | ENOTDIR)) => continue,
                Err(e) => return Err(failed(&e, "open", &path)),
            };
            if found.is_empty() {
                continue;
            }
            if stack.len() > bounds.depth {
                return Err(End::Code(TOOMANY));
            }
            path.push(b'/');
            stack.push(Level { dir: sub, prefix: path, entries: found, next: 0, after: below, held });
        }
    }
    Ok(true)
}

/// `list DIR 0|1 BUDGET [MATCH]`: per entry "p" its path from DIR, "k" its kind (f, d, l, o, and
/// in a recursive listing u, a folder it could not enter), "s" its size (a regular file's; 0 for
/// the rest); with 1, depth first into every folder below DIR, never through a link, each
/// folder's entries sorted by their bytes. With MATCH, only the entries whose path matches the
/// glob (the walk still goes everywhere). With a path on stdin (the last of an answer that
/// stopped at its budget), only those after it. DIR itself is resolved by the scope's rule (a
/// link to a folder inside the work folder is followed), and must be one the guest may read and
/// search (86 otherwise: the call's own folder).
fn list(dir: &[u8], recursive: bool, budget: usize, pattern: Option<&[u8]>, out: &mut Vec<u8>) -> R<()> {
    let after = read_stdin(MAX_PATH)?;
    let cursor: Option<Vec<&[u8]>> = if after.is_empty() {
        None
    } else {
        let c: Vec<&[u8]> = after.split(|&c| c == b'/').collect();
        if c.iter().any(|p| p.is_empty() || *p == b"." || *p == b".." || p.contains(&0)) {
            return Err(usage("a listing's cursor is a path of plain parts"));
        }
        Some(c)
    };
    if !recursive && cursor.as_ref().is_some_and(|c| c.len() > 1) {
        return Err(usage("a flat listing's cursor is one name"));
    }
    let glob: Option<Vec<&[u8]>> = match pattern {
        None => None,
        Some(p) => Some(glob::parse(p).map_err(|why| usage(&format!("a bad glob: {why}")))?),
    };
    let p = parts(dir, true)?;
    let root = root()?;
    let fd = folder_at(&root, &p).map_err(|e| failed(&e, "open", dir))?;
    // The top folder must be readable.
    drop(readable(&fd).map_err(|e| failed(&e, "open", dir))?);
    let mut frames = Frames::new(out, budget);
    let whole = walk_tree(&mut frames, recursive, glob.as_deref(), fd, cursor.as_deref(), LIST_BOUNDS)?;
    frames.end(whole);
    Ok(())
}

/// `readmany MAX BUDGET`, stdin at most 16,384 paths, each ended by a NUL: for each in order,
/// "p" the path, "s" its size as its open saw it, then "b" its bytes; or "p" the path, "s" 0,
/// then "e" the exit code that says why it was not read (87 for one past MAX bytes, or the
/// first item of an answer whose bytes would not fit its budget even alone, which no later call
/// of that budget could carry: read it with `read`); the count is the paths answered, and "+"
/// means the next did not fit the budget, never with a count of 0 (session-files-6). Each
/// file's bytes are what was read, never a size measured before: the size says nothing of the
/// bytes' length.
fn readmany(max: u64, budget: usize, out: &mut Vec<u8>) -> R<()> {
    let input = read_stdin(MAX_PATHS * (MAX_PATH + 1))?;
    if !input.is_empty() && input.last() != Some(&0) {
        return Err(usage("readmany: each path on stdin ends with a NUL"));
    }
    let paths: Vec<&[u8]> =
        if input.is_empty() { Vec::new() } else { input[..input.len() - 1].split(|&c| c == 0).collect() };
    if paths.len() > MAX_PATHS {
        return Err(usage(&format!("readmany: at most {MAX_PATHS} paths")));
    }
    let mut split = Vec::with_capacity(paths.len());
    for p in &paths {
        split.push(parts(p, false)?);
    }
    let root = root()?;
    let mut frames = Frames::new(out, budget);
    for (path, all) in paths.iter().zip(&split) {
        let got = read_whole(&root, all, max, path);
        let fit = match &got {
            Ok((size, bytes)) => frames.entry(&[(b'p', path), (b's', size.to_string().as_bytes()), (b'b', bytes)]),
            Err(code) => frames.entry(&[(b'p', path), (b's', b"0"), (b'e', code.to_string().as_bytes())]),
        };
        if !fit {
            if frames.count > 0 {
                frames.end(false);
                return Ok(());
            }
            // The first item does not fit alone: answered as too large for this budget (an
            // error item always fits the least budget).
            frames.entry(&[(b'p', path), (b's', b"0"), (b'e', FBIG.to_string().as_bytes())]);
        }
    }
    frames.end(true);
    Ok(())
}

/// The whole of a regular file of at most `max` bytes and its size as its open saw it, or the
/// exit code that says why not.
fn read_whole(root: &OwnedFd, all: &[CString], max: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i32> {
    let (f, m) = open_regular(root, all, sys::O_RDONLY, path).map_err(|e| match e {
        End::Code(c) => c,
        _ => FAILED,
    })?;
    if m.len() > max {
        return Err(FBIG);
    }
    let mut buf = Vec::with_capacity(m.len() as usize);
    f.take(max + 1).read_to_end(&mut buf).map_err(|e| code_of(&e).unwrap_or(FAILED))?;
    if buf.len() as u64 > max {
        return Err(FBIG);
    }
    Ok((m.len(), buf))
}

/// The glob a listing matches paths against: parts separated by "/"; within a part `*` is any
/// run of bytes, `?` one byte, `[...]` one byte of a set (ranges `a-z`, `!` or `^` first to
/// negate, `]` first to include it), `\` makes the next byte plain; a part that is exactly `**`
/// is zero or more whole parts. A leading dot is not special. The vectors every reader of this
/// rule checks itself against are sandbox/internal/nativehelper/testdata/glob-vectors.json.
pub mod glob {
    /// The pattern's parts; an error for an empty pattern, an empty part, a `**` inside a part,
    /// an unclosed set or a trailing backslash.
    pub fn parse(p: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
        if p.is_empty() {
            return Err("empty");
        }
        let parts: Vec<&[u8]> = p.split(|&c| c == b'/').collect();
        for part in &parts {
            if part.is_empty() {
                return Err("an empty part");
            }
            if *part != b"**" && part.windows(2).any(|w| w == b"**") {
                return Err("** is a whole part");
            }
            check_part(part)?;
        }
        Ok(parts)
    }

    fn check_part(p: &[u8]) -> Result<(), &'static str> {
        let mut i = 0;
        while i < p.len() {
            match p[i] {
                b'\\' => {
                    if i + 1 == p.len() {
                        return Err("a trailing backslash");
                    }
                    i += 2;
                }
                b'[' => i = set_end(p, i).ok_or("an unclosed [")? + 1,
                _ => i += 1,
            }
        }
        Ok(())
    }

    /// The index of the `]` closing the set that opens at `start`.
    fn set_end(p: &[u8], start: usize) -> Option<usize> {
        let mut i = start + 1;
        if i < p.len() && (p[i] == b'!' || p[i] == b'^') {
            i += 1;
        }
        if i < p.len() && p[i] == b']' {
            i += 1;
        }
        while i < p.len() {
            match p[i] {
                b']' => return Some(i),
                b'\\' => i += 2,
                _ => i += 1,
            }
        }
        None
    }

    /// The members of the set between `start` (its `[`) and `end` (its `]`), as inclusive byte
    /// ranges, and whether it is negated.
    fn set_ranges(p: &[u8], start: usize, end: usize) -> (Vec<(u8, u8)>, bool) {
        let mut i = start + 1;
        let negate = p[i] == b'!' || p[i] == b'^';
        if negate {
            i += 1;
        }
        // The members, each byte with its escape taken off.
        let mut bytes = Vec::new();
        while i < end {
            if p[i] == b'\\' && i + 1 < end {
                bytes.push((p[i + 1], true));
                i += 2;
            } else {
                bytes.push((p[i], false));
                i += 1;
            }
        }
        let mut ranges = Vec::new();
        let mut k = 0;
        while k < bytes.len() {
            if k + 2 < bytes.len() && bytes[k + 1] == (b'-', false) {
                ranges.push((bytes[k].0, bytes[k + 2].0));
                k += 3;
            } else {
                ranges.push((bytes[k].0, bytes[k].0));
                k += 1;
            }
        }
        (ranges, negate)
    }

    /// Whether one part of a name matches one part of a pattern: iterative, with one backtrack
    /// point for the last `*` seen.
    fn part_matches(p: &[u8], s: &[u8]) -> bool {
        let (mut pi, mut si) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        while si < s.len() {
            if pi < p.len() {
                let step = match p[pi] {
                    b'*' => {
                        star = Some((pi + 1, si));
                        pi += 1;
                        continue;
                    }
                    b'?' => Some(1),
                    b'[' => set_end(p, pi).and_then(|end| {
                        let (ranges, negate) = set_ranges(p, pi, end);
                        let hit = ranges.iter().any(|&(lo, hi)| lo <= s[si] && s[si] <= hi);
                        (hit != negate).then_some(end + 1 - pi)
                    }),
                    b'\\' if pi + 1 < p.len() => (p[pi + 1] == s[si]).then_some(2),
                    c => (c == s[si]).then_some(1),
                };
                if let Some(n) = step {
                    pi += n;
                    si += 1;
                    continue;
                }
            }
            match star {
                Some((sp, ss)) => {
                    pi = sp;
                    si = ss + 1;
                    star = Some((sp, ss + 1));
                }
                None => return false,
            }
        }
        p[pi..].iter().all(|&c| c == b'*')
    }

    /// Whether `path` (parts separated by "/") matches the parsed pattern, in steps bounded by
    /// the pattern's parts times the path's (session-files-5): the pattern is read as a machine
    /// whose states are its positions, all live states advanced together one path part at a
    /// time, so a pattern of many `**` is never tried partition by partition (which took time
    /// exponential in their number). Within one part, part_matches keeps one backtrack point, so
    /// it costs at most the part's length times the pattern part's.
    pub fn matches(pattern: &[&[u8]], path: &[u8]) -> bool {
        let n = pattern.len();
        let mut live = vec![false; n + 1];
        live[0] = true;
        close(pattern, &mut live);
        for s in path.split(|&c| c == b'/') {
            let mut next = vec![false; n + 1];
            for (i, p) in pattern.iter().enumerate() {
                if !live[i] {
                    continue;
                }
                if *p == b"**" {
                    next[i] = true;
                } else if part_matches(p, s) {
                    next[i + 1] = true;
                }
            }
            close(pattern, &mut next);
            if !next.contains(&true) {
                return false;
            }
            live = next;
        }
        live[n]
    }

    /// A live `**` may also match no part: the state after it is live too.
    fn close(pattern: &[&[u8]], live: &mut [bool]) {
        for (i, p) in pattern.iter().enumerate() {
            if live[i] && *p == b"**" {
                live[i + 1] = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Frames, glob, number, parts, sys};

    #[test]
    fn numbers_are_plain_decimal() {
        assert_eq!(number(b"0", 5).unwrap(), 0);
        assert_eq!(number(b"5", 5).unwrap(), 5);
        for bad in [&b""[..], b"6", b"05", b"-1", b"+1", b"1 ", b"0x1", b"99999999999999999999999"] {
            assert!(number(bad, 5).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn work_paths_are_relative_and_plain() {
        assert_eq!(parts(b".", true).unwrap().len(), 0);
        assert_eq!(parts(b"a/b", false).unwrap().len(), 2);
        for bad in [&b""[..], b".", b"/a", b"a//b", b"a/", b"a/./b", b"a/../b", b"..", b"../a"] {
            assert!(parts(bad, false).is_err(), "{bad:?}");
        }
        assert!(parts(&[b'a'; 4097], false).is_err());
    }

    /// The framing: each frame a tag, its length in decimal, ":", its bytes; an entry that
    /// would pass the budget is left out whole, and the last frame always fits.
    #[test]
    fn frames_keep_their_budget() {
        let mut out = Vec::new();
        let mut f = Frames::new(&mut out, 64);
        assert!(f.entry(&[(b'p', b"a\nb"), (b's', b"12")]));
        assert!(!f.entry(&[(b'p', &[b'x'; 40])]));
        f.end(false);
        assert_eq!(out, b"p3:a\nbs2:12+1:1");
        assert!(out.len() <= 64);
    }

    /// The glob rule against the shared vectors (testdata/glob-vectors.json), which every other
    /// reader of the rule checks itself against too.
    #[test]
    fn glob_matches_the_shared_vectors() {
        use crate::json::Value;
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/glob-vectors.json");
        let text = std::fs::read_to_string(path).unwrap();
        let v = crate::json::parse(&text).unwrap();
        let Some(Value::Array(cases)) = v.get("cases") else { panic!("no cases") };
        let mut n = 0;
        for c in cases {
            let pattern = c.get("pattern").and_then(Value::as_str).unwrap();
            if matches!(c.get("invalid"), Some(Value::Bool(true))) {
                assert!(glob::parse(pattern.as_bytes()).is_err(), "{pattern:?} parsed");
                n += 1;
                continue;
            }
            let parsed = glob::parse(pattern.as_bytes()).unwrap_or_else(|e| panic!("{pattern:?}: {e}"));
            for (key, want) in [("match", true), ("no_match", false)] {
                let Some(Value::Array(paths)) = c.get(key) else { continue };
                for p in paths {
                    let p = p.as_str().unwrap();
                    assert_eq!(glob::matches(&parsed, p.as_bytes()), want, "{pattern:?} against {p:?}");
                    n += 1;
                }
            }
        }
        assert!(n > 40, "{n} vectors");
    }

    /// These tests walk a scratch folder in the work scope (the scope's default here): its
    /// mount is the work folder's, as root() states it for a command.
    fn work_mount_of(top: &std::os::fd::OwnedFd) {
        let m = super::mount_of(top).unwrap();
        assert_eq!(*super::WORK_MOUNT.get_or_init(|| m), m, "the scratch folders are on one mount");
    }

    /// A walk that reads past its cap of entries ends with TOOMANY, not a cut answer.
    #[test]
    fn a_walk_past_its_cap_is_toomany() {
        use std::os::fd::OwnedFd;
        let dir = std::env::temp_dir().join(format!("plimsoll-helper-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        for i in 0..30 {
            std::fs::write(dir.join("sub").join(format!("f{i}")), b"").unwrap();
        }
        let walk = |cap: usize| {
            let mut out = Vec::new();
            let mut frames = Frames::new(&mut out, 1 << 20);
            let top = OwnedFd::from(std::fs::File::open(&dir).unwrap());
            work_mount_of(&top);
            let bounds = super::WalkBounds { entries: cap, ..super::LIST_BOUNDS };
            super::walk_tree(&mut frames, true, None, top, None, bounds).map(|_| ())
        };
        assert!(walk(100).is_ok());
        assert!(matches!(walk(10), Err(super::End::Code(super::TOOMANY))));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// session-files-5: a folder far larger than a call's bounds is never read whole: the walk
    /// stops taking entries at its bound, whether of entries or of bytes held, and ends with
    /// TOOMANY.
    #[test]
    fn a_huge_folder_is_never_read_whole() {
        use std::os::fd::OwnedFd;
        let dir = std::env::temp_dir().join(format!("plimsoll-helper-huge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..3000 {
            std::fs::write(dir.join(format!("{i:0>200}")), b"").unwrap();
        }
        for bounds in [
            super::WalkBounds { entries: 100, ..super::LIST_BOUNDS },
            super::WalkBounds { bytes: 100 * (200 + sys::ENTRY_OVERHEAD), ..super::LIST_BOUNDS },
        ] {
            sys::ENTRIES_TAKEN.with(|n| n.set(0));
            let mut out = Vec::new();
            let mut frames = Frames::new(&mut out, 1 << 20);
            let top = OwnedFd::from(std::fs::File::open(&dir).unwrap());
            work_mount_of(&top);
            let r = super::walk_tree(&mut frames, false, None, top, None, bounds);
            assert!(matches!(r, Err(super::End::Code(super::TOOMANY))), "{bounds:?}");
            let taken = sys::ENTRIES_TAKEN.with(std::cell::Cell::get);
            assert!(taken <= 100, "{bounds:?}: {taken} entries taken");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// session-files-5: a pattern of many `**` against a deep path that it does not match ends
    /// at once; tried partition by partition it would not end in a lifetime.
    #[test]
    fn an_adversarial_glob_is_matched_in_bounded_steps() {
        let pattern = format!("{}x", "**/".repeat(40));
        let path = format!("{}b", "a/".repeat(60));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let p = glob::parse(pattern.as_bytes()).unwrap();
            let _ = tx.send((glob::matches(&p, path.as_bytes()), glob::matches(&p, format!("{path}/x").as_bytes())));
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the match did not end in 10 s");
        assert_eq!(got, (false, true));
    }

    /// sys::read_folder reads names and types with the hand-declared struct dirent: the
    /// same names, and for each the same type, as the standard library reads.
    #[test]
    fn read_folder_matches_the_standard_library() {
        use std::os::fd::OwnedFd;
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("plimsoll-helper-dirent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("file"), b"x").unwrap();
        std::fs::create_dir(dir.join("folder")).unwrap();
        symlink("file", dir.join("link")).unwrap();
        std::fs::write(dir.join("n".repeat(255)), b"").unwrap();
        let fd = OwnedFd::from(std::fs::File::open(&dir).unwrap());
        let mut got = sys::read_folder(fd, sys::FolderBound { entries: 100, bytes: 1 << 20 }).unwrap().unwrap();
        got.sort();
        let mut want: Vec<(Vec<u8>, u8)> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let t = e.file_type().unwrap();
                let k = if t.is_symlink() {
                    crate::sys::DT_LNK
                } else if t.is_dir() {
                    crate::sys::DT_DIR
                } else {
                    crate::sys::DT_REG
                };
                (std::os::unix::ffi::OsStrExt::as_bytes(e.file_name().as_os_str()).to_vec(), k)
            })
            .collect();
        want.sort();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(got, want);
    }
}
