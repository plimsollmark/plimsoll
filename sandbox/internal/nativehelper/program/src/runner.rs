//! The project runner, `run-project`: what docker/runner.mjs does, held equal to it by the
//! runner equivalence suite (sandbox/docker_runner_equivalence_test.go). It reads a JSON
//! plan on its input, writes the project's files into the work directory, runs each step
//! (`sh -c`) in order under one deadline, stopping at the first failure, reads back the
//! files asked for, and writes one report frame signed with the plan's key (HMAC-SHA256).
//!
//! Where it differs from today's runner, each on purpose (the status page lists them, and
//! the suite holds this runner to each under PLIMSOLL_TEST_RUNNER_KIND=native): a step's
//! input is /dev/null and its output pipes, not sockets; error text starts with its code
//! but is not Node's wording; a step's command is cut at 16,384 bytes on a character
//! boundary, not 16,384 UTF-16 units; and an artifact is read to at most the size its budget
//! was checked against, so one that grows while it is read stays within 8 MiB.
//!
//! The key arrives on the input alone and is never put in the environment, the command
//! line, a file or the output. Before the plan is read this process is non-dumpable (main)
//! and proves, by a child of its own user, that a step cannot open its descriptors or its
//! memory (`self_check`).

use crate::child::{self, Env, Limits};
use crate::errno;
use crate::json::{self, Value};
use crate::out;
use crate::sha256;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Opens the report frame on stdout; must match runnerwire.Marker.
const MARKER: &str = "<<<PLIMSOLL_REPORT_V3>>>";
/// Each of a step's streams keeps its first MAX_STEP_OUTPUT bytes and is flagged cut past
/// it (sandbox.ProjectStepOutputCap).
const MAX_STEP_OUTPUT: usize = 1 << 20;
/// Both streams together may carry this much before the step is killed and reported as
/// flooded (the E2B transport's budget, shared as Node's spawnSync maxBuffer is).
const MAX_STEP_TRANSFER: usize = 32 << 20;
/// 128 + SIGXFSZ, as the exec-based providers report a flooded step.
const EXIT_OUTPUT_FLOODED: i64 = 153;
/// Total bytes across all artifacts.
const MAX_ARTIFACT_BYTES: u64 = 8 << 20;
/// Encoded step metadata and output across the run.
const MAX_STEPS_JSON: usize = 3 << 20;
/// The host reads at most 16 MiB; the report keeps room for its framing.
const MAX_RESULT_JSON: usize = 15 << 20;
/// A reported command keeps at most this many bytes.
const MAX_COMMAND_BYTES: usize = 16 << 10;
/// The written host client module (outside the work directory, so never an artifact).
const HOST_SDK_PATH: &str = "/tmp/plimsoll-host.mjs";

const ISOLATION_UNPROVEN: &str = "runner descriptor and memory isolation could not be proven";
const OVER_BUDGET: &str = "sandbox result exceeds the encoded response budget";

/// One step as the report carries it, field for field in Node's order.
struct Step {
    command: String,
    stdout_b64: String,
    stderr_b64: String,
    stdout_cut: bool,
    stderr_cut: bool,
    exit_code: i64,
    timed_out: bool,
    duration_ms: i64,
}

impl Step {
    fn encode(&self, o: &mut String) {
        o.push_str("{\"command\":");
        out::string(o, &self.command);
        o.push_str(",\"stdoutBase64\":\"");
        o.push_str(&self.stdout_b64);
        o.push_str("\",\"stderrBase64\":\"");
        o.push_str(&self.stderr_b64);
        o.push_str("\",\"stdoutTruncated\":");
        out::boolean(o, self.stdout_cut);
        o.push_str(",\"stderrTruncated\":");
        out::boolean(o, self.stderr_cut);
        let _ = write!(o, ",\"exitCode\":{},\"timedOut\":", self.exit_code);
        out::boolean(o, self.timed_out);
        let _ = write!(o, ",\"durationMs\":{}}}", self.duration_ms);
    }

    fn encoded_len(&self) -> usize {
        let mut s = String::new();
        self.encode(&mut s);
        s.len()
    }
}

fn encode_steps(o: &mut String, steps: &[Step]) {
    o.push('[');
    for (i, s) in steps.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        s.encode(o);
    }
    o.push(']');
}

/// The length of `{"steps":[...]}` for steps of these encoded lengths.
fn steps_json_len(lens: &[usize]) -> usize {
    "{\"steps\":[]}".len() + lens.iter().sum::<usize>() + lens.len().saturating_sub(1)
}

struct Artifact {
    path: String,
    content_b64: String,
}

/// What the run ends with: the steps and artifacts, or an error (with the steps so far
/// when any step began).
enum Report {
    Done { steps: Vec<Step>, artifacts: Vec<Artifact>, cut: bool },
    Failed { error: String, began: Option<Vec<Step>> },
}

struct Run {
    key: Option<Vec<u8>>,
    began: bool,
    steps: Vec<Step>,
    /// Each step's encoded length, for the budget across steps.
    lens: Vec<usize>,
    origin: Instant,
}

/// Runs the project runner to its report and exits 0, as Node's does whatever happened.
pub fn main() -> ! {
    let mut run = Run { key: None, began: false, steps: Vec::new(), lens: Vec::new(), origin: Instant::now() };
    let report = match run.project() {
        Ok((artifacts, cut)) => Report::Done { steps: std::mem::take(&mut run.steps), artifacts, cut },
        Err(error) => {
            let began = run.began.then(|| std::mem::take(&mut run.steps));
            Report::Failed { error, began }
        }
    };
    emit(&report, run.key.as_deref());
    std::process::exit(0)
}

/// Node's `path.resolve(base, p)`: `p` itself if absolute, else `base/p`, then `.` and `..`
/// and empty segments resolved (`..` stops at the root) and any trailing slash dropped.
fn resolve(base: &str, p: &str) -> String {
    let joined = if p.starts_with('/') { p.to_owned() } else { format!("{base}/{p}") };
    let mut parts: Vec<&str> = Vec::new();
    for seg in joined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

fn within(path: &str, root: &str) -> bool {
    path == root || path.strip_prefix(root).is_some_and(|rest| rest.starts_with('/'))
}

/// The work directory: PLIMSOLL_WORK or /work, made absolute against the current one.
fn work_dir() -> String {
    let raw = std::env::var("PLIMSOLL_WORK").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/work".to_owned());
    if raw.starts_with('/') {
        resolve("/", &raw)
    } else {
        let cwd = std::env::current_dir().map_or_else(|_| "/".to_owned(), |d| d.to_string_lossy().into_owned());
        resolve(&cwd, &raw)
    }
}

/// Node's `Buffer.from(text, "hex")`: pairs of hex digits up to the first pair that is not
/// one (an odd last digit is dropped).
fn hex_prefix(text: &str) -> Vec<u8> {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::new();
    for pair in text.as_bytes().as_chunks::<2>().0 {
        match (digit(pair[0]), digit(pair[1])) {
            (Some(h), Some(l)) => out.push(h << 4 | l),
            _ => break,
        }
    }
    out
}

/// A list member of the plan (`plan.x ?? []`): absent or null is empty.
fn list<'a>(plan: &'a Value, key: &str) -> Result<&'a [Value], String> {
    match plan.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) => Ok(a),
        Some(v) => Err(format!("plan {key} is {}, not a list", v.kind())),
    }
}

/// A string member (`x ?? ""`): absent or null is empty.
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(s)) => Ok(s),
        Some(other) => Err(format!("plan {key} is {}, not a string", other.kind())),
    }
}

/// Writes `content` to `path` the way the runner writes every file: a link there is
/// refused (O_NOFOLLOW), a fifo there is not waited on (O_NONBLOCK), and anything that is
/// not then a regular file is refused. In a session the work directory holds what earlier
/// calls left.
fn write_owned(path: &str, content: &[u8], label: &str) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(crate::sys::O_NOFOLLOW | crate::sys::O_NONBLOCK)
        .open(path)
        .map_err(|e| errno::describe(&e, "open", path))?;
    match f.metadata() {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Err(format!("not a regular file: {label}")),
        Err(e) => return Err(errno::describe(&e, "fstat", path)),
    }
    f.write_all(content).map_err(|e| errno::describe(&e, "write", path))
}

impl Run {
    fn now_ms(&self) -> f64 {
        self.origin.elapsed().as_secs_f64() * 1000.0
    }

    fn project(&mut self) -> Result<(Vec<Artifact>, bool), String> {
        let mut env = Env::inherited("LD_PRELOAD");
        self_check(&env)?;
        let mut raw = Vec::new();
        io::stdin().lock().read_to_end(&mut raw).map_err(|e| errno::describe(&e, "read", "stdin"))?;
        let plan = json::parse_bytes(&raw).map_err(|e| format!("the plan is not JSON: {e}"))?;
        drop(raw);
        // The key, taken before anything else runs.
        let key = hex_prefix(plan.get("reportKey").and_then(Value::as_str).unwrap_or(""));
        if key.len() != 32 {
            return Err("plan carries no report key".to_owned());
        }
        self.key = Some(key);

        let work = work_dir();
        for f in list(&plan, "files")? {
            let path = text(f, "path")?;
            let dest = resolve(&work, path);
            if !within(&dest, &work) {
                return Err(format!("illegal file path: {path}"));
            }
            let parent = resolve(&dest, "..");
            fs::create_dir_all(&parent).map_err(|e| errno::describe(&e, "mkdir", &parent))?;
            write_owned(&dest, text(f, "content")?.as_bytes(), path)?;
        }

        // Steps start with this process's environment (PATH, HOME, HOSTNAME from the start
        // script; the guard's LD_PRELOAD dropped) and the plan's entries over it, then
        // PLIMSOLL_RUNNER_PID, and NODE_OPTIONS with the host client's import when a grant
        // carries one.
        if let Some(Value::Array(entries)) = plan.get("env") {
            for entry in entries {
                let Some((name, value)) = entry.as_str().and_then(|s| s.split_once('=')).filter(|(n, _)| !n.is_empty())
                else {
                    return Err("plan env entry is not NAME=value".to_owned());
                };
                env.set(OsStr::new(name), OsStr::new(value));
            }
        }
        env.set(OsStr::new("PLIMSOLL_RUNNER_PID"), OsStr::new(&std::process::id().to_string()));
        if let Some(sdk) = plan.get("hostSDK").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            write_owned(HOST_SDK_PATH, sdk.as_bytes(), HOST_SDK_PATH)?;
            let preload = format!("--import=file://{HOST_SDK_PATH}");
            let options = match env.get("NODE_OPTIONS").filter(|v| !v.is_empty()) {
                Some(v) => {
                    let mut s = v.to_owned();
                    s.push(" ");
                    s.push(&preload);
                    s
                }
                None => OsString::from(preload),
            };
            env.set(OsStr::new("NODE_OPTIONS"), &options);
        }

        // One deadline for every step, fixed before the first, on the monotonic clock: each
        // step gets what is left of the run's budget. A step reached with nothing left still
        // starts, with a millisecond, and is reported timed out.
        let budget = match plan.get("budgetMs") {
            Some(Value::Number(n)) => n.parse::<f64>().ok().filter(|b| b.is_finite() && *b > 0.0),
            _ => None,
        };
        let deadline = budget.map(|b| self.now_ms() + b);
        for command in list(&plan, "steps")? {
            self.began = true;
            let Value::String(command) = command else {
                return Err(format!("a step is {}, not a string", command.kind()));
            };
            let (step, stdout, stderr, stop) = self.run_step(command, deadline, &env, &work);
            self.lens.push(step.encoded_len());
            self.steps.push(step);
            self.cap_encoded_steps(&stdout, &stderr);
            if stop {
                break;
            }
        }

        // Read back the artifacts even if a step failed, so partial output still returns.
        capture_artifacts(&work, list(&plan, "artifacts")?)
    }

    /// Runs one step (`sh -c command` in the work directory, with what is left of the run's
    /// deadline) and returns it as reported, the bytes kept of its two streams, and whether
    /// the plan stops after it.
    fn run_step(&self, command: &str, deadline: Option<f64>, env: &Env, work: &str) -> (Step, Vec<u8>, Vec<u8>, bool) {
        let start = self.now_ms();
        let timeout_ms = deadline.map(|d| (d - start).ceil().max(1.0) as u64);
        let limits = Limits { keep: MAX_STEP_OUTPUT, transfer: MAX_STEP_TRANSFER, timeout_ms };
        let args = [OsStr::new("-c"), OsStr::new(command)];
        let ran = child::run(Path::new("sh"), &args, env, Some(Path::new(work)), &limits);
        let duration_ms = (self.now_ms() - start).round() as i64;
        let mut step = Step {
            command: cut_command(command),
            stdout_b64: String::new(),
            stderr_b64: String::new(),
            stdout_cut: false,
            stderr_cut: false,
            exit_code: -1,
            timed_out: false,
            duration_ms,
        };
        let (stdout, stderr, stop) = match ran {
            Ok(o) => {
                step.exit_code = if o.timed_out {
                    124
                } else if o.flooded {
                    EXIT_OUTPUT_FLOODED
                } else {
                    child::exit_code(o.status)
                };
                step.timed_out = o.timed_out;
                step.stdout_cut = o.flooded || o.stdout_len > MAX_STEP_OUTPUT;
                step.stderr_cut = o.flooded || o.stderr_len > MAX_STEP_OUTPUT;
                // A timed-out step, or one reported with an exit other than 0, ends the plan,
                // as on every exec-based provider. The reported exit, not the shell's: a
                // flooded step whose shell had already exited 0 (a program it left in the
                // background passed the budget) reports 153 and once ran on (release-97).
                let stop = o.timed_out || step.exit_code != 0;
                (o.stdout, o.stderr, stop)
            }
            // A step that could not be started reports exit -1 and the start error as its
            // stderr, in the same words as today's runner (they name the code).
            Err(e) => (Vec::new(), format!("spawnSync sh {}", errno::code(&e)).into_bytes(), true),
        };
        step.stdout_b64 = out::base64(&stdout);
        step.stderr_b64 = out::base64(&stderr);
        (step, stdout, stderr, stop)
    }

    /// Keeps every step's encoded output within MAX_STEPS_JSON together: when the last
    /// step passes it, its command and outcome stay and its stdout, then its stderr, keep
    /// as many whole base64 groups (3 bytes, 4 characters) as the room left holds; a stream
    /// cut here is flagged. Exactly the runner.mjs computation, on the same encoding.
    fn cap_encoded_steps(&mut self, stdout: &[u8], stderr: &[u8]) {
        if steps_json_len(&self.lens) <= MAX_STEPS_JSON {
            return;
        }
        let last = self.steps.len() - 1;
        let step = &mut self.steps[last];
        step.stdout_b64.clear();
        step.stderr_b64.clear();
        self.lens[last] = step.encoded_len();
        let mut size = steps_json_len(&self.lens);
        for (raw, is_out) in [(stdout, true), (stderr, false)] {
            let room = MAX_STEPS_JSON.saturating_sub(size);
            let kept = &raw[..raw.len().min(room / 4 * 3)];
            let b64 = out::base64(kept);
            size += b64.len();
            if is_out {
                step.stdout_cut |= kept.len() < raw.len();
                step.stdout_b64 = b64;
            } else {
                step.stderr_cut |= kept.len() < raw.len();
                step.stderr_b64 = b64;
            }
        }
        self.lens[last] = step.encoded_len();
    }
}

/// A command as reported: at most MAX_COMMAND_BYTES bytes, cut on a character boundary.
fn cut_command(command: &str) -> String {
    let mut n = command.len().min(MAX_COMMAND_BYTES);
    while !command.is_char_boundary(n) {
        n -= 1;
    }
    command[..n].to_owned()
}

/// Proves, before the plan is read, that a process of this process's user (as every step
/// is) cannot open this process's input, its output for reading or writing, or its memory:
/// a child of its own (this program's `self-check` mode) tries each and reports what the
/// kernel answered; anything but EACCES or EPERM for all four is a refusal.
fn self_check(env: &Env) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|_| ISOLATION_UNPROVEN.to_owned())?;
    let limits = Limits { keep: 4096, transfer: 4096, timeout_ms: Some(5000) };
    let o =
        child::run(&exe, &[OsStr::new("self-check")], env, None, &limits).map_err(|_| ISOLATION_UNPROVEN.to_owned())?;
    let finished = !o.timed_out && !o.flooded && o.status.and_then(|s| s.code()) == Some(0);
    if self_check_passes(finished, &o.stdout) { Ok(()) } else { Err(ISOLATION_UNPROVEN.to_owned()) }
}

/// The self-check's verdict on what its child printed: the child finished (exit 0, in time,
/// within its output), and gave one answer for each of crate::SELF_CHECKS, each EACCES or
/// EPERM. On a real kernel the four answers come all refused or all open, by the one
/// non-dumpable flag, so no case reaches a single part alone; the unit tests below change
/// each part alone (finding rust-native-helper-23).
fn self_check_passes(finished: bool, stdout: &[u8]) -> bool {
    let codes: Vec<&[u8]> = stdout.split(|&b| b == b',').collect();
    finished && codes.len() == crate::SELF_CHECKS.len() && codes.iter().all(|c| *c == b"EACCES" || *c == b"EPERM")
}

/// Reads each requested file under the work directory, in the request's order, within
/// MAX_ARTIFACT_BYTES together; the first one that would pass the budget ends the reading
/// and is reported as a cut. A path is resolved through any links and must still lie in the
/// work directory; the file is opened without following a final link and without waiting
/// on a fifo; the kernel is asked what was opened (a step left running can swap a parent
/// directory for a link between the resolution and the open), and only a regular file inside
/// the work directory is read, to at most the size its budget was checked against.
fn capture_artifacts(work: &str, paths: &[Value]) -> Result<(Vec<Artifact>, bool), String> {
    let mut out = Vec::new();
    let mut total: u64 = 0;
    let Ok(work_real) = fs::canonicalize(work) else { return Ok((out, false)) };
    let work_real = work_real.as_os_str().as_bytes().to_vec();
    let mut prefix = work_real.clone();
    prefix.push(b'/');
    for p in paths {
        let Value::String(p) = p else {
            return Err(format!("an artifact path is {}, not a string", p.kind()));
        };
        let dest = resolve(work, p);
        if !within(&dest, work) {
            continue;
        }
        let Ok(real) = fs::canonicalize(&dest) else { continue };
        let real_b = real.as_os_str().as_bytes();
        if real_b != work_real.as_slice() && !real_b.starts_with(&prefix) {
            continue;
        }
        let Ok(f) =
            OpenOptions::new().read(true).custom_flags(crate::sys::O_NOFOLLOW | crate::sys::O_NONBLOCK).open(&real)
        else {
            continue;
        };
        let Ok(opened) = fs::read_link(PathBuf::from(format!("/proc/self/fd/{}", f.as_raw_fd()))) else { continue };
        if !opened.as_os_str().as_bytes().starts_with(&prefix) {
            continue;
        }
        let Ok(info) = f.metadata() else { continue };
        if !info.is_file() {
            continue;
        }
        if total + info.len() > MAX_ARTIFACT_BYTES {
            return Ok((out, true));
        }
        let mut buf = Vec::new();
        // At most the size checked: a file that grows while it is read stays in budget.
        if f.take(info.len()).read_to_end(&mut buf).is_err() {
            continue;
        }
        total += buf.len() as u64;
        out.push(Artifact { path: p.clone(), content_b64: out::base64(&buf) });
    }
    Ok((out, false))
}

/// Writes the report as one frame on stdout:
/// `\n<MARKER> <body length> <hex HMAC-SHA256 of the body>\n<body>`. Without a key the MAC is
/// 64 zeros, so the host sees a report arrive and classifies it as a protocol error.
fn emit(report: &Report, key: Option<&[u8]>) {
    let body = encode_report(report);
    let mac = key.map_or_else(|| "0".repeat(64), |k| sha256::hex(&sha256::hmac(k, body.as_bytes())));
    let mut frame = format!("\n{MARKER} {} {mac}\n", body.len()).into_bytes();
    frame.extend_from_slice(body.as_bytes());
    // SAFETY: descriptor 1 is this process's stdout for its whole life; ManuallyDrop keeps
    // it open after the write.
    let mut stdout = ManuallyDrop::new(unsafe { File::from_raw_fd(1) });
    let _ = stdout.write_all(&frame);
}

/// The report's JSON, within MAX_RESULT_JSON: artifacts are dropped from the end while it
/// is over (and the drop is flagged); if it is still over, an error that keeps whether any
/// step began replaces it.
fn encode_report(report: &Report) -> String {
    let mut o = String::new();
    let ran = match report {
        Report::Done { steps, artifacts, cut } => {
            let mut s = String::new();
            encode_steps(&mut s, steps);
            let arts: Vec<String> = artifacts
                .iter()
                .map(|a| {
                    let mut e = String::from("{\"path\":");
                    out::string(&mut e, &a.path);
                    e.push_str(",\"content\":\"");
                    e.push_str(&a.content_b64);
                    e.push_str("\"}");
                    e
                })
                .collect();
            let mut keep = arts.len();
            let mut cut = *cut;
            let size = |keep: usize, cut: bool| {
                "{\"steps\":,\"artifacts\":[],\"artifactsTruncated\":}".len()
                    + s.len()
                    + arts[..keep].iter().map(String::len).sum::<usize>()
                    + keep.saturating_sub(1)
                    + if cut { 4 } else { 5 }
            };
            while size(keep, cut) > MAX_RESULT_JSON && keep > 0 {
                keep -= 1;
                cut = true;
            }
            if size(keep, cut) <= MAX_RESULT_JSON {
                o.push_str("{\"steps\":");
                o.push_str(&s);
                o.push_str(",\"artifacts\":[");
                o.push_str(&arts[..keep].join(","));
                o.push_str("],\"artifactsTruncated\":");
                out::boolean(&mut o, cut);
                o.push('}');
                return o;
            }
            !steps.is_empty()
        }
        Report::Failed { error, began } => {
            o.push_str("{\"error\":");
            out::string(&mut o, error);
            if let Some(steps) = began {
                o.push_str(",\"stepsBegan\":true,\"steps\":");
                encode_steps(&mut o, steps);
            }
            o.push('}');
            if o.len() <= MAX_RESULT_JSON {
                return o;
            }
            began.is_some()
        }
    };
    let mut o = String::from("{\"error\":");
    out::string(&mut o, OVER_BUDGET);
    if ran {
        o.push_str(",\"stepsBegan\":true");
    }
    o.push('}');
    o
}

#[cfg(test)]
mod tests {
    use super::{cut_command, hex_prefix, resolve, self_check_passes, steps_json_len, within, write_owned};

    #[test]
    fn resolve_as_node() {
        assert_eq!(resolve("/work", ""), "/work");
        assert_eq!(resolve("/work", "a/b.txt"), "/work/a/b.txt");
        assert_eq!(resolve("/work", "../x"), "/x");
        assert_eq!(resolve("/work", "/etc/hostname"), "/etc/hostname");
        assert_eq!(resolve("/work", "./a//b/../c/"), "/work/a/c");
        assert_eq!(resolve("/work", "../../.."), "/");
        assert_eq!(resolve("/work", "."), "/work");
        assert_eq!(resolve("/work/a.txt", ".."), "/work");
        assert!(within("/work", "/work") && within("/work/a", "/work"));
        assert!(!within("/workx", "/work") && !within("/x", "/work"));
    }

    #[test]
    fn hex_as_buffer_from() {
        assert_eq!(hex_prefix("00ff"), vec![0, 255]);
        assert_eq!(hex_prefix("abc"), vec![0xab]);
        assert_eq!(hex_prefix("ab zz cd"), vec![0xab]);
        assert_eq!(hex_prefix("AbCd"), vec![0xab, 0xcd]);
        assert_eq!(hex_prefix(""), Vec::<u8>::new());
    }

    #[test]
    fn command_cut_on_a_character() {
        let s = format!(": {}\u{1f600}", "a".repeat(16381));
        assert_eq!(cut_command(&s).len(), 16383);
        assert_eq!(cut_command("short"), "short");
        let exact = "b".repeat(16384);
        assert_eq!(cut_command(&exact), exact);
    }

    /// Finding rust-native-helper-23: each part of the self-check's verdict, changed alone,
    /// refuses.
    #[test]
    fn self_check_refuses_each_part_alone() {
        assert!(self_check_passes(true, b"EACCES,EACCES,EACCES,EACCES"));
        assert!(self_check_passes(true, b"EPERM,EACCES,EPERM,EACCES"));
        // The child did not finish (a non-zero exit, the deadline, a flood).
        assert!(!self_check_passes(false, b"EACCES,EACCES,EACCES,EACCES"));
        // Not one answer per check: three, five, none.
        assert!(!self_check_passes(true, b"EACCES,EACCES,EACCES"));
        assert!(!self_check_passes(true, b"EACCES,EACCES,EACCES,EACCES,EACCES"));
        assert!(!self_check_passes(true, b""));
        // Each answer opened, or failed otherwise, alone.
        for i in 0..4 {
            for other in ["open", "ENOENT", "", "EACCES "] {
                let mut codes = ["EACCES"; 4];
                codes[i] = other;
                assert!(!self_check_passes(true, codes.join(",").as_bytes()), "answer {i} as {other:?}");
            }
        }
    }

    /// The four things the child opens: input, output for reading, output for writing, memory.
    #[test]
    fn self_checks_are_the_four() {
        assert_eq!(crate::SELF_CHECKS, [("fd/0", false), ("fd/1", false), ("fd/1", true), ("mem", false)]);
    }

    /// Finding rust-native-helper-17's first layer: a written file that opens as anything but a
    /// regular file is refused (a character device here; a step cannot make one in /work).
    #[test]
    fn write_owned_refuses_what_is_not_a_regular_file() {
        let err = write_owned("/dev/null", b"x", "dev-null").unwrap_err();
        assert_eq!(err, "not a regular file: dev-null");
    }

    /// Finding rust-native-helper-27: O_NOFOLLOW is this machine's (the kernel refuses a final
    /// link with ELOOP), and a written file is refused through a link.
    #[test]
    fn nofollow_is_this_machines() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!("plimsoll-helper-nofollow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, b"t").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = std::fs::OpenOptions::new().read(true).custom_flags(crate::sys::O_NOFOLLOW).open(&link).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(40), "O_NOFOLLOW {:#o} did not refuse a final link", crate::sys::O_NOFOLLOW);
        assert!(write_owned(link.to_str().unwrap(), b"x", "link").unwrap_err().contains("ELOOP"));
        assert_eq!(std::fs::read(&target).unwrap(), b"t");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn steps_length() {
        assert_eq!(steps_json_len(&[]), "{\"steps\":[]}".len());
        assert_eq!(steps_json_len(&[3, 4]), "{\"steps\":[aaa,bbbb]}".len());
    }
}
