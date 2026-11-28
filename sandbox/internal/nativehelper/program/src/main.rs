//! plimsoll-helper: plimsoll's own program inside a docker sandbox, one static file with no
//! outside crate. Its modes:
//!
//!   run-project   the project runner (src/runner.rs), in place of docker/runner.mjs
//!   self-check    the child the runner starts to prove a process of its user cannot open
//!                 the runner's descriptors or memory; not for any other use
//!   files         the file commands (src/files.rs, docs/session-files.md): one generic
//!                 interface to a sandbox's work folder (stat, read, write, list, delete, mkdir,
//!                 rmdir, readmany), framed exactly, paged, each path part opened with
//!                 O_NOFOLLOW, as the guest's own user and with nothing of the runner
//!   identity      prints `inputs ` and the SHA-256 of this build's inputs (build.sh sets it
//!                 at compile time from the lines of the pin that name them), which a startup
//!                 check that cannot read the file's bytes compares with the pinned build's
//!
//! `run-project --test-only-stay-dumpable` makes the runner dumpable in place of the call that
//! makes it non-dumpable, so the runner equivalence suite can reach the runner's own refusal
//! (its self-check then fails, and it reports that and runs nothing). Skipping the call is not
//! enough where the helper is installed readable by root alone: the kernel makes such a
//! program non-dumpable from its exec. Nothing plimsoll starts in a daemon passes it; a test in
//! sandbox/internal/nativehelper holds that.

mod child;
mod errno;
mod files;
mod json;
mod out;
mod runner;
mod sha256;
mod sys;

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

/// The read end of the pipe a child's exit writes to (sys::child_exit_pipe).
pub static CHILD_EXITS: OnceLock<i32> = OnceLock::new();

const TEST_ONLY_STAY_DUMPABLE: &str = "--test-only-stay-dumpable";

/// The SHA-256 of this build's inputs: of the lines `sha256sum` writes for them, in the
/// pin's order (plimsoll-helper.sha256 without its last line, the built file's), which
/// build.sh computes before it builds and passes in as PLIMSOLL_HELPER_INPUTS. A build
/// made without it (cargo test, a by-hand cargo build) reports `none`, which no check
/// accepts. It names the build; it proves nothing against a program built to lie.
const BUILD_INPUTS: &str = match option_env!("PLIMSOLL_HELPER_INPUTS") {
    Some(s) => s,
    None => "none",
};

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let args: Vec<&OsStr> = args.iter().map(std::ffi::OsString::as_os_str).collect();
    match args.as_slice() {
        [mode] if mode.as_bytes() == b"run-project" => run_project(true),
        [mode, flag] if mode.as_bytes() == b"run-project" && flag.as_bytes() == TEST_ONLY_STAY_DUMPABLE.as_bytes() => {
            run_project(false)
        }
        [mode] if mode.as_bytes() == b"self-check" => self_check(),
        [mode] if mode.as_bytes() == b"identity" => identity(),
        [mode, rest @ ..] if mode.as_bytes() == b"files" => files::main(rest),
        _ => {
            let _ = std::io::stderr()
                .write_all(b"usage: plimsoll-helper run-project | self-check | identity | files COMMAND ARG...\n");
            std::process::exit(2);
        }
    }
}

fn run_project(guard: bool) -> ! {
    // First, before anything is read: the runner guard's job, as one call (its test-only
    // opposite without the guard).
    if !(if guard { sys::set_non_dumpable() } else { sys::set_dumpable_for_test() }) {
        let _ = std::io::stderr().write_all(b"plimsoll runner: cannot set its dumpable state\n");
        std::process::exit(125);
    }
    // Then no signal a step may send ends the runner (sys::ignore_signals).
    if sys::ignore_signals().is_err() {
        let _ = std::io::stderr().write_all(b"plimsoll runner: cannot ignore signals\n");
        std::process::exit(125);
    }
    let Ok(fd) = sys::child_exit_pipe() else {
        let _ = std::io::stderr().write_all(b"plimsoll runner: cannot watch for its children's exits\n");
        std::process::exit(125);
    };
    let _ = CHILD_EXITS.set(fd);
    runner::main()
}

/// What the self-check child opens under /proc/<parent>, in order, and whether for
/// writing: the parent's input, its output for reading and for writing, and its memory, as
/// today's runner's check does. runner::self_check_passes takes one answer for each.
pub const SELF_CHECKS: [(&str, bool); 4] = [("fd/0", false), ("fd/1", false), ("fd/1", true), ("mem", false)];

/// Prints `inputs ` and BUILD_INPUTS, one line, and exits 0.
fn identity() -> ! {
    let mut out = std::io::stdout();
    let ok = out.write_all(format!("inputs {BUILD_INPUTS}\n").as_bytes()).and_then(|()| out.flush()).is_ok();
    std::process::exit(i32::from(!ok))
}

/// Opens each of SELF_CHECKS of the parent, without waiting on a pipe, and prints what each
/// gave (`open` or the error's code), comma-separated.
fn self_check() -> ! {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    let p = format!("/proc/{}", sys::parent_pid());
    let codes: Vec<String> = SELF_CHECKS
        .iter()
        .map(|(rel, write)| {
            let mut o = OpenOptions::new();
            if *write {
                o.write(true);
            } else {
                o.read(true);
            }
            match o.custom_flags(sys::O_NONBLOCK).open(format!("{p}/{rel}")) {
                Ok(_) => "open".to_owned(),
                Err(e) => errno::code(&e),
            }
        })
        .collect();
    let _ = std::io::stdout().write_all(codes.join(",").as_bytes());
    let _ = std::io::stdout().flush();
    std::process::exit(0)
}
