//! Starting a program and collecting its output as Node's `spawnSync` does, for a step and
//! for the self-check alike: its input is `/dev/null` and its output and error are pipes
//! (the choice on the status page: Node gives sockets, so `> /dev/stdout` fails today), its
//! environment is passed in the order given (not sorted), and every signal is reset to its
//! default. It is waited for until it has exited AND both pipes are closed, so a background
//! program that keeps the output open keeps the step running (the design review's finding 3);
//! at the deadline, or when the output passes the transfer budget, the program is killed
//! with SIGKILL, the pipes are closed, and it is reaped. Its own children are never killed.

use crate::sys;
use std::ffi::{CString, OsStr, OsString, c_char};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Instant;

/// An environment in its order, a later set of a name keeping the name's place, as a
/// JavaScript object's keys do.
#[derive(Clone, Default)]
pub struct Env(Vec<(OsString, OsString)>);

impl Env {
    /// This process's environment, in order, without `drop`.
    pub fn inherited(drop: &str) -> Env {
        Env(std::env::vars_os().filter(|(k, _)| k.as_bytes() != drop.as_bytes()).collect())
    }

    pub fn get(&self, name: &str) -> Option<&OsStr> {
        self.0.iter().find(|(k, _)| k.as_bytes() == name.as_bytes()).map(|(_, v)| v.as_os_str())
    }

    pub fn set(&mut self, name: &OsStr, value: &OsStr) {
        match self.0.iter_mut().find(|(k, _)| k == name) {
            Some((_, v)) => value.clone_into(v),
            None => self.0.push((name.to_owned(), value.to_owned())),
        }
    }

    /// The environment as exec takes it. A name or value with a NUL cannot be passed and
    /// is an error (the plan's JSON cannot carry one into a name or value of its own).
    fn block(&self) -> io::Result<Vec<CString>> {
        self.0
            .iter()
            .map(|(k, v)| {
                let mut kv = k.as_bytes().to_vec();
                kv.push(b'=');
                kv.extend_from_slice(v.as_bytes());
                CString::new(kv).map_err(|_| io::Error::from_raw_os_error(22))
            })
            .collect()
    }
}

/// What one program did.
pub struct Outcome {
    /// The first `keep` bytes of each stream.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Every byte each stream carried, kept or not.
    pub stdout_len: usize,
    pub stderr_len: usize,
    /// Its exit, unless it could not be reaped (never in practice).
    pub status: Option<ExitStatus>,
    pub timed_out: bool,
    /// Its output passed the transfer budget and it was killed.
    pub flooded: bool,
}

pub struct Limits {
    /// Bytes kept per stream.
    pub keep: usize,
    /// Bytes both streams may carry together before the program is killed.
    pub transfer: usize,
    /// Milliseconds from the start until it is killed, or none.
    pub timeout_ms: Option<u64>,
}

/// Starts `program` with `args`, `env` and `cwd`, and collects it under `limits`. Err is a
/// program that could not be started (its error number, as the kernel gave it to exec).
pub fn run(program: &Path, args: &[&OsStr], env: &Env, cwd: Option<&Path>, limits: &Limits) -> io::Result<Outcome> {
    let started = Instant::now();
    let block = env.block()?;
    let mut ptrs: Vec<*const c_char> = block.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let envp = ptrs.as_ptr() as usize;
    let mut cmd = Command::new(program);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    // SAFETY: the closure runs in the child between fork and exec and only resets signal
    // dispositions and the mask and swaps the environment pointer, all async-signal-safe;
    // `block` and `ptrs` outlive the spawn in the parent, and the child has a copy of both.
    unsafe {
        cmd.pre_exec(move || {
            sys::reset_signals_in_child()?;
            sys::set_environ(envp as *const *const c_char);
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    drop(ptrs);
    drop(block);
    Ok(collect(child, started, limits))
}

fn collect(mut child: Child, started: Instant, limits: &Limits) -> Outcome {
    let mut out = Stream(child.stdout.take().map(|p| File::from(OwnedFd::from(p))));
    let mut err = Stream(child.stderr.take().map(|p| File::from(OwnedFd::from(p))));
    let mut o = Outcome {
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_len: 0,
        stderr_len: 0,
        status: None,
        timed_out: false,
        flooded: false,
    };
    let exits = crate::CHILD_EXITS.get().copied();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        if o.status.is_none()
            && let Ok(Some(s)) = child.try_wait()
        {
            o.status = Some(s);
        }
        if o.status.is_some() && !out.open() && !err.open() {
            break;
        }
        let wait = match limits.timeout_ms {
            None => -1,
            Some(ms) => {
                let spent = started.elapsed().as_millis();
                if spent >= u128::from(ms) {
                    o.timed_out = true;
                    break;
                }
                i32::try_from(u128::from(ms) - spent).unwrap_or(i32::MAX)
            }
        };
        let mut fds = Vec::with_capacity(3);
        for s in [&out, &err] {
            if let Some(fd) = s.fd() {
                fds.push(sys::PollFd { fd, events: sys::POLLIN, revents: 0 });
            }
        }
        if let Some(fd) = exits {
            fds.push(sys::PollFd { fd, events: sys::POLLIN, revents: 0 });
        }
        match sys::poll(&mut fds, wait) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // poll cannot fail on a valid list; treat it as a step that cannot be watched.
            Err(_) => {
                o.timed_out = limits.timeout_ms.is_some();
                break;
            }
        }
        if let Some(fd) = exits {
            sys::drain(fd);
        }
        for fd in fds.iter().filter(|p| p.revents != 0).map(|p| p.fd) {
            let (s, kept, len) = if Some(fd) == out.fd() {
                (&mut out, &mut o.stdout, &mut o.stdout_len)
            } else if Some(fd) == err.fd() {
                (&mut err, &mut o.stderr, &mut o.stderr_len)
            } else {
                continue;
            };
            match s.read(&mut buf) {
                Ok(0) => s.close(),
                Ok(n) => {
                    let room = limits.keep.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                    *len += n;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted || e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => s.close(),
            }
        }
        if o.stdout_len + o.stderr_len > limits.transfer {
            o.flooded = true;
            break;
        }
    }
    if o.timed_out || o.flooded {
        // Kill only a program not yet reaped (the standard library refuses to signal one it
        // has reaped, so a reused process number is never hit), then close the pipes, as Node
        // does: a background program holding them gets EPIPE, nothing more.
        let _ = child.kill();
        out.close();
        err.close();
    }
    if o.status.is_none() {
        o.status = child.wait().ok();
    }
    o
}

/// One of a program's output pipes, closed when it reaches its end.
struct Stream(Option<File>);

impl Stream {
    fn open(&self) -> bool {
        self.0.is_some()
    }
    fn fd(&self) -> Option<i32> {
        self.0.as_ref().map(AsRawFd::as_raw_fd)
    }
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.as_mut() {
            Some(r) => r.read(buf),
            None => Ok(0),
        }
    }
    fn close(&mut self) {
        self.0 = None;
    }
}

/// A step's exit code as the runner reports it: its own, or 128 plus the signal that
/// ended its shell, or -1 for none.
pub fn exit_code(status: Option<ExitStatus>) -> i64 {
    match status {
        Some(s) => match (s.code(), s.signal()) {
            (Some(c), _) => i64::from(c),
            (None, Some(sig)) => 128 + i64::from(sig),
            (None, None) => -1,
        },
        None => -1,
    }
}
