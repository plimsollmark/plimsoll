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

use std::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

pub const PR_GET_DUMPABLE: c_int = 3;
pub const PR_SET_DUMPABLE: c_int = 4;

pub const O_NONBLOCK: i32 = 0o4000;
#[cfg(target_arch = "x86_64")]
pub const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_arch = "aarch64")]
pub const O_NOFOLLOW: i32 = 0o100_000;
const O_CLOEXEC: c_int = 0o2_000_000;

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
