//! The system calls the standard library does not offer, declared by hand against the C
//! library the standard library already links (musl, statically), so the helper needs no
//! outside crate (the design review's finding 8). Each is used in one place and named after
//! the C function it is. The constants are Linux's: those that differ between machines
//! (O_NOFOLLOW, the system call number of rt_sigaction) are given per machine, x86-64 and
//! aarch64, and any other machine does not compile; the rest are the same on both. Every
//! one is held to Go's own tables for both machines by sandbox/internal/nativehelper's
//! TestSysConstantsMatchGo (finding rust-native-helper-27: O_NOFOLLOW was x86-64's value
//! for both, and on aarch64 that value is O_LARGEFILE).

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("plimsoll-helper's system constants are listed for x86_64 and aarch64 only (src/sys.rs)");

use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

pub const PR_GET_DUMPABLE: c_int = 3;
pub const PR_SET_DUMPABLE: c_int = 4;

pub const O_NONBLOCK: i32 = 0o4000;
#[cfg(target_arch = "x86_64")]
pub const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_arch = "aarch64")]
pub const O_NOFOLLOW: i32 = 0o100_000;
pub const O_CLOEXEC: c_int = 0o2_000_000;
// The file commands' opens (src/files.rs).
pub const O_RDONLY: c_int = 0;
pub const O_WRONLY: c_int = 0o1;
pub const O_CREAT: c_int = 0o100;
pub const O_EXCL: c_int = 0o200;
pub const O_APPEND: c_int = 0o2000;
#[cfg(target_arch = "x86_64")]
pub const O_DIRECTORY: c_int = 0o200_000;
#[cfg(target_arch = "aarch64")]
pub const O_DIRECTORY: c_int = 0o40_000;
/// The same on every Linux machine: Go's syscall package lists it for arm64 and not for
/// amd64, and its own exec_linux_test.go says the value is the same on both.
pub const O_PATH: c_int = 0o10_000_000;
pub const AT_REMOVEDIR: c_int = 0x200;
pub const DT_UNKNOWN: u8 = 0;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
/// renameat2's flag that refuses a name already there, atomically.
pub const RENAME_NOREPLACE: c_uint = 1;
#[cfg(target_arch = "x86_64")]
const SYS_RENAMEAT2: c_long = 316;
#[cfg(target_arch = "aarch64")]
const SYS_RENAMEAT2: c_long = 276;

/// O_TMPFILE as open(2) takes it (__O_TMPFILE with O_DIRECTORY): a file with no name, in the
/// folder given.
#[cfg(target_arch = "x86_64")]
pub const O_TMPFILE: c_int = 0o20_200_000;
#[cfg(target_arch = "aarch64")]
pub const O_TMPFILE: c_int = 0o20_040_000;
pub const AT_EMPTY_PATH: c_int = 0x1000;
pub const AT_SYMLINK_FOLLOW: c_int = 0x400;
pub const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
/// openat2's resolve flags: every part resolved beneath the folder given (a link or ".."
/// that would leave it is EXDEV), no /proc magic link followed, and no mount crossed (a
/// part that is a mount point, a bind mount included, is EXDEV too).
pub const RESOLVE_BENEATH: u64 = 0x8;
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x2;
pub const RESOLVE_NO_XDEV: u64 = 0x1;
/// statx's mask bit for the mount's id.
pub const STATX_MNT_ID: c_uint = 0x1000;
/// The same number on both machines (the generic table's).
const SYS_OPENAT2: c_long = 437;
#[cfg(target_arch = "x86_64")]
const SYS_STATX: c_long = 332;
#[cfg(target_arch = "aarch64")]
const SYS_STATX: c_long = 291;

#[cfg(target_arch = "x86_64")]
const SYS_RT_SIGACTION: c_long = 13;
#[cfg(target_arch = "aarch64")]
const SYS_RT_SIGACTION: c_long = 134;

const SIGKILL: c_int = 9;
const SIGSTOP: c_int = 19;
const SIGCHLD: c_int = 17;
/// The highest signal number (the kernel's _NSIG is 64 on both machines).
const SIGMAX: c_int = 64;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;
const SIG_SETMASK: c_int = 2;

pub const POLLIN: i16 = 0x1;

/// musl's sigset_t: 128 bytes.
#[repr(C)]
struct SigSet([c_ulong; 128 / size_of::<c_ulong>()]);

#[repr(C)]
pub struct PollFd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

/// The kernel's struct sigaction as rt_sigaction takes it, the same on x86-64 and aarch64
/// (both define SA_RESTORER): the handler, the flags, the restorer, a 64-bit mask.
#[repr(C)]
struct KernelSigaction {
    handler: usize,
    flags: c_ulong,
    restorer: usize,
    mask: u64,
}

unsafe extern "C" {
    fn prctl(option: c_int, ...) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn signal(sig: c_int, handler: usize) -> usize;
    fn sigprocmask(how: c_int, set: *const SigSet, old: *mut SigSet) -> c_int;
    #[link_name = "poll"]
    fn c_poll(fds: *mut PollFd, n: c_ulong, timeout: c_int) -> c_int;
    fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;
    #[link_name = "read"]
    fn c_read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    #[link_name = "write"]
    fn c_write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn getppid() -> c_int;
    fn __errno_location() -> *mut c_int;
    static mut environ: *const *const c_char;
    fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn mkdirat(dirfd: c_int, path: *const c_char, mode: c_uint) -> c_int;
    fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
    fn linkat(olddir: c_int, old: *const c_char, newdir: c_int, new: *const c_char, flags: c_int) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn fdopendir(fd: c_int) -> *mut c_void;
    fn readdir(dir: *mut c_void) -> *const Dirent;
    fn closedir(dir: *mut c_void) -> c_int;
}

/// musl's struct dirent, the same on x86-64 and aarch64 (and the same layout as the
/// kernel's linux_dirent64): the inode, the offset, the record length, the type, then the
/// name, NUL-terminated. store.rs's tests read a folder with it and compare the names and
/// types with the standard library's reading of the same folder.
#[repr(C)]
pub struct Dirent {
    ino: u64,
    off: i64,
    reclen: u16,
    kind: u8,
    name: [c_char; 256],
}

/// openat(2), `name` relative to the folder `dir`, with the mode a create takes (unused
/// without O_CREAT). The descriptor is owned, so it is closed when dropped.
pub fn open_at(dir: RawFd, name: &CStr, flags: c_int, mode: c_uint) -> io::Result<OwnedFd> {
    // SAFETY: name is a valid C string; openat reads it and returns a new descriptor or -1.
    let fd = unsafe { openat(dir, name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is the descriptor openat just returned, owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// mkdirat(2).
pub fn mkdir_at(dir: RawFd, name: &CStr, mode: c_uint) -> io::Result<()> {
    // SAFETY: name is a valid C string.
    if unsafe { mkdirat(dir, name.as_ptr(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// renameat2(2), by its system call (musl declares no wrapper for it).
pub fn rename_at(from_dir: RawFd, from: &CStr, to_dir: RawFd, to: &CStr, flags: c_uint) -> io::Result<()> {
    // SAFETY: both names are valid C strings; renameat2 reads them and writes nothing of ours.
    let r = unsafe {
        syscall(
            SYS_RENAMEAT2,
            c_long::from(from_dir),
            from.as_ptr(),
            c_long::from(to_dir),
            to.as_ptr(),
            c_long::from(flags),
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// unlinkat(2): a file, or with AT_REMOVEDIR an empty folder.
pub fn unlink_at(dir: RawFd, name: &CStr, flags: c_int) -> io::Result<()> {
    // SAFETY: name is a valid C string.
    if unsafe { unlinkat(dir, name.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The kernel's struct open_how, openat2's argument.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// openat2(2), by its system call (musl declares no wrapper for it): `path` relative to
/// `dir`, resolved under `resolve` (RESOLVE_*). ENOSYS on a kernel without it (before 5.6).
pub fn open_at2(dir: RawFd, path: &CStr, flags: c_int, resolve: u64) -> io::Result<OwnedFd> {
    let how = OpenHow { flags: u64::from(flags as u32), mode: 0, resolve };
    // SAFETY: path is a valid C string and how a valid open_how of the size given; openat2
    // reads both and returns a new descriptor or -1.
    let fd = unsafe { syscall(SYS_OPENAT2, c_long::from(dir), path.as_ptr(), &raw const how, size_of::<OpenHow>()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is the descriptor openat2 just returned, owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
}

/// The mount id of `name` in `dir` (`name` empty: `dir` itself) by statx(2), without following
/// a link at the name; None when the kernel states no mount id (before 5.8). Some(Err) on a
/// failed call.
pub fn mount_id(dir: RawFd, name: &CStr) -> Option<io::Result<u64>> {
    // struct statx is 256 bytes; stx_mask is its first u32 and stx_mnt_id the u64 at 144.
    let mut buf = [0u64; 32];
    let flags = AT_SYMLINK_NOFOLLOW | if name.is_empty() { AT_EMPTY_PATH } else { 0 };
    // SAFETY: name is a valid C string and buf has room for the 256 bytes statx writes.
    let r = unsafe {
        syscall(
            SYS_STATX,
            c_long::from(dir),
            name.as_ptr(),
            c_long::from(flags),
            c_long::from(STATX_MNT_ID),
            buf.as_mut_ptr(),
        )
    };
    if r != 0 {
        return Some(Err(io::Error::last_os_error()));
    }
    let mask = buf[0] as u32;
    if mask & STATX_MNT_ID == 0 {
        return None;
    }
    Some(Ok(buf[144 / 8]))
}

/// linkat(2).
pub fn link_at(olddir: RawFd, old: &CStr, newdir: RawFd, new: &CStr, flags: c_int) -> io::Result<()> {
    // SAFETY: both names are valid C strings.
    if unsafe { linkat(olddir, old.as_ptr(), newdir, new.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether a process `pid` exists in this process's pid namespace: kill(pid, 0) is anything
/// but ESRCH (EPERM is a process of another user's, which exists).
pub fn process_exists(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 sends nothing; kill only checks the process.
    let alive = unsafe { kill(pid, 0) } == 0;
    alive || io::Error::last_os_error().raw_os_error() != Some(3)
}

/// A folder's entries: each name and its type (DT_*).
pub type Entries = Vec<(Vec<u8>, u8)>;

/// The most of a folder read_folder holds: past either bound it stops reading and answers
/// None, so one folder of any size costs at most this much memory.
#[derive(Clone, Copy, Debug)]
pub struct FolderBound {
    pub entries: usize,
    pub bytes: usize,
}

/// Bytes held per entry beyond its name: the entry's own (the name's pointer, length and
/// capacity, and the type, padded).
pub const ENTRY_OVERHEAD: usize = size_of::<(Vec<u8>, u8)>();

#[cfg(test)]
thread_local! {
    /// The entries read_folder has taken on this thread (tests only).
    pub static ENTRIES_TAKEN: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Every entry of the folder `dir` (open for reading, and closed here) but `.` and `..`:
/// its name and its type (one of DT_*, DT_UNKNOWN where the file system states none), in
/// the folder's own order; None as soon as it would hold more than `bound` allows (the
/// entry past it is not kept), so a folder of any size is never read whole into memory.
pub fn read_folder(dir: OwnedFd, bound: FolderBound) -> io::Result<Option<Entries>> {
    // SAFETY: dir is a valid descriptor; on success fdopendir owns it and closedir closes it.
    let d = unsafe { fdopendir(dir.as_raw_fd()) };
    if d.is_null() {
        return Err(io::Error::last_os_error());
    }
    std::mem::forget(dir);
    let mut out = Vec::new();
    let mut held = 0usize;
    let result = loop {
        // SAFETY: errno is this thread's; readdir changes it only on an error.
        unsafe { *__errno_location() = 0 };
        // SAFETY: d is the open folder stream fdopendir returned.
        let e = unsafe { readdir(d) };
        if e.is_null() {
            // SAFETY: as above.
            let n = unsafe { *__errno_location() };
            break if n == 0 { Ok(true) } else { Err(io::Error::from_raw_os_error(n)) };
        }
        // SAFETY: e is the entry readdir returned, valid until the next call; its name is
        // NUL-terminated inside it.
        let (name, kind) = unsafe { (CStr::from_ptr((*e).name.as_ptr()), (*e).kind) };
        let name = name.to_bytes();
        if name != b"." && name != b".." {
            held += name.len() + ENTRY_OVERHEAD;
            if out.len() >= bound.entries || held > bound.bytes {
                break Ok(false);
            }
            #[cfg(test)]
            ENTRIES_TAKEN.with(|n| n.set(n.get() + 1));
            out.push((name.to_vec(), kind));
        }
    };
    // SAFETY: d is open and not used after this.
    unsafe { closedir(d) };
    result.map(|whole| whole.then_some(out))
}

/// Makes this process non-dumpable, so a process of the same user (every project step) can
/// open none of its /proc descriptors or its memory, whatever the host's Yama setting, and
/// reads the setting back. What docker/guard/runner.c does for the Node runner, as one call
/// at the top of the program instead of a library loaded through LD_PRELOAD.
pub fn set_non_dumpable() -> bool {
    // SAFETY: prctl with these options reads and writes no memory of ours.
    unsafe {
        prctl(PR_SET_DUMPABLE, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong) == 0
            && prctl(PR_GET_DUMPABLE) == 0
    }
}

/// Makes this process dumpable, for the runner's test-only argument alone (main.rs): a helper
/// installed readable by root alone is non-dumpable from its exec (the kernel's rule for a
/// program its user cannot read), so only this call makes the runner reachable again for the
/// test of its own refusal. Reads the setting back.
pub fn set_dumpable_for_test() -> bool {
    // SAFETY: prctl with these options reads and writes no memory of ours.
    unsafe {
        prctl(PR_SET_DUMPABLE, 1 as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong) == 0
            && prctl(PR_GET_DUMPABLE) == 1
    }
}

pub fn parent_pid() -> i32 {
    // SAFETY: getppid cannot fail and touches no memory.
    unsafe { getppid() }
}

/// Sets signal `sig`'s disposition to SIG_DFL or SIG_IGN with the kernel's own call, not
/// musl's signal(), which refuses 32 to 34 (the C library's own signals, which this
/// single-threaded program never uses). Async-signal-safe and allocation-free, so it may
/// run between fork and exec.
fn set_disposition(sig: c_int, disposition: usize) -> io::Result<()> {
    let act = KernelSigaction { handler: disposition, flags: 0, restorer: 0, mask: 0 };
    // SAFETY: act is a valid struct sigaction for the kernel; no old action is asked for;
    // the mask size is the kernel's 8 bytes. SIG_DFL and SIG_IGN need no restorer.
    let r = unsafe {
        syscall(
            SYS_RT_SIGACTION,
            c_long::from(sig),
            &raw const act,
            std::ptr::null_mut::<KernelSigaction>(),
            8 as c_long,
        )
    };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// The signals the runner ignores: every one a process may catch (1 to 64 but KILL and
/// STOP), except SIGCHLD, whose handler wakes the runner when a step ends
/// (child_exit_pipe).
pub fn ignored_by_runner(sig: c_int) -> bool {
    (1..=SIGMAX).contains(&sig) && sig != SIGKILL && sig != SIGSTOP && sig != SIGCHLD
}

/// Ignores every catchable signal but SIGCHLD (ignored_by_runner), so a step, which runs as
/// the runner's user and is handed its process number (PLIMSOLL_RUNNER_PID), cannot end the
/// runner with one and turn its own call into a protocol error (finding
/// rust-native-helper-28). Only SIGKILL and SIGSTOP remain, which no process can ignore. A
/// fault the kernel raises itself (SIGSEGV, SIGBUS, SIGILL, SIGFPE) still ends the runner,
/// since the kernel resets an ignored disposition before it delivers one, and an abort
/// still aborts (musl's abort resets SIGABRT before it raises it again). Every step and the
/// self-check child get each signal reset to its default (reset_signals_in_child).
pub fn ignore_signals() -> io::Result<()> {
    for n in 1..=SIGMAX {
        if ignored_by_runner(n) {
            set_disposition(n, SIG_IGN)?;
        }
    }
    Ok(())
}

/// Resets every signal 1 to 64 but KILL and STOP to its default action and unblocks every
/// signal, as Node's child-process library (libuv) does in a child before it starts the
/// program (libuv for 1 to 31; 32 to 64 here too, since the runner itself ignores them,
/// ignore_signals): a signal ignored by or above the runner is not ignored in a step (the
/// design review's finding 4; Rust's standard library resets only SIGPIPE). Rust's standard
/// library also empties the mask in the child; this empties it again on purpose, so a
/// step's mask does not rest on that (finding rust-native-helper-25: no case can see
/// either). Called between fork and exec, so it uses only async-signal-safe calls and
/// allocates nothing.
pub fn reset_signals_in_child() -> io::Result<()> {
    for n in 1..=SIGMAX {
        if n == SIGKILL || n == SIGSTOP {
            continue;
        }
        set_disposition(n, SIG_DFL)?;
    }
    let empty = SigSet([0; 128 / size_of::<c_ulong>()]);
    // SAFETY: empty is a valid, initialized sigset_t; no old set is asked for.
    if unsafe { sigprocmask(SIG_SETMASK, &raw const empty, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Points the C library's environment at `envp` (a null-terminated list of "NAME=value"
/// strings), so the `execvp` the standard library calls next passes it in this order and
/// searches its PATH, as Node does. The standard library would otherwise sort the
/// environment by name (the design review's finding 4). Called between fork and exec only.
///
/// # Safety
/// `envp` must point at a null-terminated array of C strings that stays valid until exec.
pub unsafe fn set_environ(envp: *const *const c_char) {
    // SAFETY: the caller's promise; in the child after fork no other thread exists.
    unsafe { environ = envp };
}

/// poll(2), retried on EINTR by the caller.
pub fn poll(fds: &mut [PollFd], timeout_ms: c_int) -> io::Result<usize> {
    // SAFETY: fds is a valid slice of pollfd for its length.
    let n = unsafe { c_poll(fds.as_mut_ptr(), fds.len() as c_ulong, timeout_ms) };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

/// The write end of the pipe the SIGCHLD handler writes to (-1 before it is made).
static CHILD_PIPE_W: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_sigchld(_: c_int) {
    let fd = CHILD_PIPE_W.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    // SAFETY: errno is this thread's; write is async-signal-safe; the byte is on the stack.
    unsafe {
        let saved = *__errno_location();
        let one = 1u8;
        let _ = c_write(fd, (&raw const one).cast(), 1);
        *__errno_location() = saved;
    }
}

/// Makes the pipe a child's exit wakes (a SIGCHLD handler writes one byte to it, and the
/// read end goes into the same poll as the step's output) and returns its read end. The
/// pipe covers a child that exits between the runner's check of it and its poll, which the
/// signal alone would miss; no case can hit that window on purpose (finding
/// rust-native-helper-25), and removing the handler altogether is caught by the suite. Both
/// ends are close-on-exec and non-blocking, so no step inherits them and a full pipe never
/// blocks the handler. Called once.
pub fn child_exit_pipe() -> io::Result<c_int> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds has room for the two descriptors pipe2 writes.
    if unsafe { pipe2(fds.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    CHILD_PIPE_W.store(fds[1], Ordering::Relaxed);
    // SAFETY: on_sigchld is an extern "C" fn(c_int) that only does async-signal-safe work.
    if unsafe { signal(SIGCHLD, on_sigchld as *const () as usize) } == usize::MAX {
        return Err(io::Error::last_os_error());
    }
    Ok(fds[0])
}

/// Empties the child-exit pipe (its read end is non-blocking).
pub fn drain(fd: c_int) {
    let mut buf = [0u8; 64];
    // SAFETY: buf is valid for its length.
    while unsafe { c_read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
}

#[cfg(test)]
mod tests {
    use super::ignored_by_runner;

    /// Finding rust-native-helper-28: the runner ignores 1 to 64 but KILL (9) and STOP (19),
    /// which it cannot, and CHLD (17), which wakes it.
    #[test]
    fn the_runner_ignores_every_catchable_signal_but_sigchld() {
        let kept: Vec<i32> = (0..=65).filter(|&n| !ignored_by_runner(n)).collect();
        assert_eq!(kept, [0, 9, 17, 19, 65]);
    }
}
