//! The file commands (src/files.rs, docs/session-files.md) run as a program, the way a session
//! starts them: each command in a scratch work folder, its exit code and its answer by its
//! framing. sandbox/docker_files_test.go drives the same commands inside a real container
//! under runc and gVisor.

use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const HELPER: &str = env!("CARGO_BIN_EXE_plimsoll-helper");
const NOT_A_MOUNT: &str = "PLIMSOLL_HELPER_TEST_WORK_NOT_A_MOUNT";

/// One entry of an answer: its frames, each a tag and a payload.
type Entry = Vec<(u8, Vec<u8>)>;

struct Work(PathBuf);

impl Work {
    fn new(name: &str) -> Work {
        let p = std::env::temp_dir().join(format!("plimsoll-files-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("work")).unwrap();
        std::fs::create_dir_all(p.join("outside")).unwrap();
        std::fs::write(p.join("outside/secret"), b"not yours\n").unwrap();
        Work(p)
    }

    fn root(&self) -> PathBuf {
        self.0.join("work")
    }

    fn put(&self, rel: &str, data: &[u8]) {
        let p = self.root().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    /// Runs `files work ARGS` with `stdin` in the work folder: its exit code and stdout.
    fn run(&self, args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>) {
        self.run_in("work", args, stdin)
    }

    /// Runs `files SCOPE ARGS` with `stdin` in the work folder.
    fn run_in(&self, scope: &str, args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>) {
        let mut child = Command::new(HELPER)
            .args(["files", scope])
            .args(args)
            .current_dir(self.root())
            // A scratch folder is not a mount of its own (the work scope's rule, which
            // an_unmounted_work_folder_is_refused checks); this debug build's test hook lets it be.
            .env(NOT_A_MOUNT, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // A command that refuses its input stops reading it: a broken pipe here is its answer.
        let _ = child.stdin.take().unwrap().write_all(stdin);
        let out = child.wait_with_output().unwrap();
        let code = out.status.code().unwrap();
        if code != 0 {
            assert!(out.stdout.is_empty(), "{args:?}: exit {code} with stdout {:?}", out.stdout);
        }
        (code, out.stdout)
    }

    /// run, with more variables in the helper's environment.
    fn run_env(&self, args: &[&str], stdin: &[u8], envs: &[(&str, &str)]) -> (i32, Vec<u8>) {
        let envs: Vec<(&str, String)> = envs.iter().map(|(k, v)| (*k, (*v).to_string())).collect();
        let out = spawn(self, args, stdin, &envs, false).wait_with_output().unwrap();
        (out.status.code().unwrap(), out.stdout)
    }

    fn frames_in(&self, scope: &str, args: &[&str], stdin: &[u8], group: usize) -> (Vec<Entry>, bool) {
        let (code, out) = self.run_in(scope, args, stdin);
        assert_eq!(code, 0, "{scope} {args:?}");
        parse(&out, group)
    }

    fn code(&self, args: &[&str], stdin: &[u8]) -> i32 {
        self.run(args, stdin).0
    }

    /// The answer of a command that must succeed, as its entries of `group` frames, and
    /// whether it is whole.
    fn frames(&self, args: &[&str], stdin: &[u8], group: usize) -> (Vec<Entry>, bool) {
        let (code, out) = self.run(args, stdin);
        assert_eq!(code, 0, "{args:?}");
        parse(&out, group)
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = Command::new("chmod").args(["-R", "u+rwx"]).arg(&self.0).status();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Parses the framing strictly: a tag, a decimal length with no leading zero, ":", the bytes;
/// the last frame "." or "+" and the count of entries of `group` frames before it.
fn parse(out: &[u8], group: usize) -> (Vec<Entry>, bool) {
    let mut frames = Vec::new();
    let mut i = 0;
    while i < out.len() {
        let colon = i + 1 + out[i + 1..].iter().position(|&c| c == b':').expect("a length");
        let digits = std::str::from_utf8(&out[i + 1..colon]).unwrap();
        assert!(digits == "0" || !digits.starts_with('0'), "leading zero in {digits}");
        let n: usize = digits.parse().unwrap();
        frames.push((out[i], out[colon + 1..colon + 1 + n].to_vec()));
        i = colon + 1 + n;
    }
    let (tag, count) = frames.pop().expect("an end frame");
    assert!(tag == b'.' || tag == b'+');
    let count: usize = std::str::from_utf8(&count).unwrap().parse().unwrap();
    assert_eq!(count * group, frames.len());
    assert!(frames.iter().all(|(t, _)| *t != b'.' && *t != b'+'));
    (frames.chunks(group).map(<[_]>::to_vec).collect(), tag == b'.')
}

fn payloads(entry: &[(u8, Vec<u8>)]) -> Vec<(char, String)> {
    entry.iter().map(|(t, p)| (*t as char, String::from_utf8_lossy(p).into_owned())).collect()
}

/// session-files-18: a file of the kernel's states size 0 at its open and has content. `read`
/// answers that content (from its offset, to its length) as `readmany` does, and keeps the size
/// it saw at open. /proc/self/status is the helper's own, so both start with its name.
#[test]
fn read_answers_a_procfs_file_whose_size_at_open_is_zero() {
    let w = Work::new("procfs");
    let (e, _) = w.frames_in("sandbox", &["read", "/proc/self/status", "0", "65536"], b"", 2);
    let p = payloads(&e[0]);
    assert_eq!(p[0], ('s', "0".into()), "procfs states size 0 at open");
    assert!(p[1].1.starts_with("Name:\tplimsoll-helpe"), "read answered {:?}", p[1].1);
    let (e, _) = w.frames_in("sandbox", &["read", "/proc/self/status", "6", "8"], b"", 2);
    assert_eq!(payloads(&e[0]), [('s', "0".into()), ('b', "plimsoll".into())]);
    let (e, _) = w.frames_in("sandbox", &["readmany", "65536", "65536"], b"/proc/self/status\0", 3);
    let p = payloads(&e[0]);
    assert_eq!(p[1], ('s', "0".into()));
    assert!(p[2].1.starts_with("Name:\tplimsoll-helpe"), "readmany answered {:?}", p[2].1);
}

#[test]
fn write_read_stat_and_their_modes() {
    let w = Work::new("write");
    assert_eq!(w.code(&["write", "notes/a.txt", "create-only", "1"], b"one\n"), 0);
    assert_eq!(w.code(&["write", "notes/a.txt", "create-only", "1"], b"again\n"), 84);
    assert_eq!(w.code(&["write", "notes/a.txt", "append", "1"], b"two\n"), 0);
    let (e, _) = w.frames(&["read", "notes/a.txt", "0", "100"], b"", 2);
    assert_eq!(payloads(&e[0]), [('s', "8".into()), ('b', "one\ntwo\n".into())]);
    assert_eq!(w.code(&["write", "notes/a.txt", "replace", "1"], b"three\n"), 0);
    let (e, _) = w.frames(&["read", "notes/a.txt", "2", "3"], b"", 2);
    assert_eq!(payloads(&e[0]), [('s', "6".into()), ('b', "ree".into())]);
    let (e, _) = w.frames(&["read", "notes/a.txt", "50", "3"], b"", 2);
    assert_eq!(payloads(&e[0])[1], ('b', String::new()));
    let (e, _) = w.frames(&["stat", "notes/a.txt"], b"", 4);
    let p = payloads(&e[0]);
    assert_eq!((p[0].clone(), p[1].clone()), (('k', "f".into()), ('s', "6".into())));
    assert_eq!((p[2].0, p[3].0), ('m', 't'));
    let (e, _) = w.frames(&["stat", "."], b"", 4);
    assert_eq!(payloads(&e[0])[0], ('k', "d".into()));
    assert_eq!(std::fs::read(w.root().join("notes/a.txt")).unwrap(), b"three\n");
}

#[test]
fn each_error_is_its_code() {
    let w = Work::new("errors");
    w.put("dir/inside", b"x");
    w.put("file", b"x");
    assert_eq!(w.code(&["stat", "nothing"], b""), 81);
    assert_eq!(w.code(&["read", "dir", "0", "1"], b""), 82);
    assert_eq!(w.code(&["remove", "dir", "0"], b""), 82);
    assert_eq!(w.code(&["read", "file/below", "0", "1"], b""), 83);
    assert_eq!(w.code(&["write", "file/below", "create-only", "1"], b"x"), 83);
    assert_eq!(w.code(&["remove", "file", "1"], b""), 83);
    assert_eq!(w.code(&["list", "file", "0", "8192"], b""), 83);
    assert_eq!(w.code(&["mkdir", "file", "1"], b""), 84);
    assert_eq!(w.code(&["remove", "dir", "1"], b""), 88);
    assert_eq!(w.code(&["list", "nothing", "0", "8192"], b""), 81);
    assert!(Command::new("mkfifo").arg(w.root().join("pipe")).status().unwrap().success());
    assert_eq!(w.code(&["read", "pipe", "0", "1"], b""), 85);
    assert_eq!(w.code(&["write", "pipe", "replace", "1"], b"x"), 85);
    for bad in ["../outside/secret", "/etc/passwd", "a/../b", "./a", "a//b", "", "a/"] {
        assert_eq!(w.code(&["read", bad, "0", "1"], b""), 2, "{bad:?}");
    }
    for bad in [
        &["read", "file", "01", "1"][..],
        &["read", "file", "0", "-1"],
        &["write", "file", "overwrite", "1"],
        &["list", ".", "2", "8192"],
        &["list", ".", "0", "8191"],
        &["list", ".", "0", "8388609"],
        &["readmany", "1", "8192"],
        &["nope"],
    ] {
        let stdin: &[u8] = if bad[0] == "readmany" { b"file" } else { b"" };
        assert_eq!(w.code(bad, stdin), 2, "{bad:?}");
    }
    assert_eq!(w.code(&["remove", "file", "0"], b""), 0);
    assert_eq!(w.code(&["remove", "file", "0"], b""), 81);
    assert_eq!(w.code(&["mkdir", "made/deep", "1"], b""), 0);
    assert_eq!(w.code(&["mkdir", "made/deep", "1"], b""), 0);
    assert_eq!(w.code(&["remove", "made/deep", "1"], b""), 0);
    assert_eq!(w.code(&["remove", "made/deep", "1"], b""), 81);
}

/// Run as a non-root user, as the gate is: root writes through any mode.
#[test]
fn permission_denied_is_86() {
    if Command::new("id").arg("-u").output().unwrap().stdout == b"0\n" {
        return;
    }
    let w = Work::new("perm");
    w.put("ro.txt", b"keep");
    w.put("locked/inside", b"keep");
    std::fs::set_permissions(w.root().join("ro.txt"), PermissionsExt::from_mode(0o444)).unwrap();
    std::fs::set_permissions(w.root().join("locked"), PermissionsExt::from_mode(0o555)).unwrap();
    assert_eq!(w.code(&["write", "ro.txt", "replace", "1"], b"x"), 86);
    assert_eq!(w.code(&["write", "locked/new", "create-only", "1"], b"x"), 86);
    assert_eq!(w.code(&["remove", "locked/inside", "0"], b""), 86);
    std::fs::set_permissions(w.root().join("locked"), PermissionsExt::from_mode(0o000)).unwrap();
    assert_eq!(w.code(&["read", "locked/inside", "0", "1"], b""), 86);
    assert_eq!(w.code(&["list", "locked", "0", "8192"], b""), 86);
    std::fs::set_permissions(w.root().join("locked"), PermissionsExt::from_mode(0o755)).unwrap();
    assert_eq!(std::fs::read(w.root().join("ro.txt")).unwrap(), b"keep");
}

/// session-files-10, the table in docs/session-files.md ("Links, per operation"): in the work
/// scope a link that stays inside the work folder is followed (an ancestor link, a final link
/// a read or an append opens, a ".." inside the work folder), one that leaves it is refused
/// (80: an absolute target, a ".." past the top, the root), a dangling one is nothing there
/// (81) where a command follows it; stat, remove, rename and a replace act on a final link
/// itself, never its target. A listing names links and goes into none of them.
#[test]
fn links_inside_the_work_folder_are_followed_and_links_leaving_it_refused() {
    let w = Work::new("links");
    let outside = w.0.join("outside");
    w.put("real/file", b"inside");
    w.put("venv/bin/python3.12", b"python");
    w.put("node_modules/x/cli.js", b"cli");
    std::fs::create_dir_all(w.root().join("node_modules/.bin")).unwrap();
    std::fs::create_dir_all(w.root().join("a/b")).unwrap();
    symlink(&outside, w.root().join("out")).unwrap();
    symlink("real", w.root().join("inner")).unwrap();
    symlink("real/file", w.root().join("flink")).unwrap();
    symlink("real", w.root().join("dlink")).unwrap();
    symlink("nothing", w.root().join("dangling")).unwrap();
    symlink("python3.12", w.root().join("venv/bin/python")).unwrap();
    symlink("../x/cli.js", w.root().join("node_modules/.bin/x")).unwrap();
    symlink("../../../outside/secret", w.root().join("a/b/up")).unwrap();
    symlink("/", w.root().join("a/b/root")).unwrap();
    let read = |p: &str| {
        let (code, out) = w.run(&["read", p, "0", "100"], b"");
        (code, if code == 0 { payloads(&parse(&out, 2).0[0])[1].1.clone() } else { String::new() })
    };
    let kind = |p: &str| {
        let (code, out) = w.run(&["stat", p], b"");
        if code == 0 { payloads(&parse(&out, 4).0[0])[0].1.clone() } else { code.to_string() }
    };
    // Followed: links that stay inside.
    assert_eq!(read("inner/file"), (0, "inside".into()));
    assert_eq!(read("flink"), (0, "inside".into()));
    assert_eq!(read("venv/bin/python"), (0, "python".into()));
    assert_eq!(read("node_modules/.bin/x"), (0, "cli".into()));
    assert_eq!(read("dlink"), (82, String::new()));
    let (e, _) = w.frames(&["readmany", "100", "8192"], b"venv/bin/python\0out/secret\0dangling\0", 3);
    let items: Vec<_> = e.iter().map(|en| payloads(en)[2].clone()).collect();
    assert_eq!(items, [('b', "python".into()), ('e', "80".into()), ('e', "81".into())]);
    // Refused: links that leave, wherever they are on the path; dangling: nothing there.
    for p in ["out/secret", "out", "a/b/up", "a/b/root/etc/passwd"] {
        assert_eq!(read(p).0, 80, "{p}");
        assert_eq!(w.code(&["write", p, "append", "0"], b"x"), 80, "{p}");
    }
    assert_eq!(read("dangling").0, 81);
    // stat: links before the last part followed by the rule, the last part never.
    assert_eq!(kind("inner/file"), "f");
    for p in ["flink", "dlink", "out", "dangling", "a/b/root"] {
        assert_eq!(kind(p), "l", "{p}");
    }
    assert_eq!(kind("out/secret"), "80");
    assert_eq!(kind("."), "d");
    // write: a replace puts a file at a final link's name, never through it; create-only finds
    // something there; an append goes through a link that stays inside; a dangling link is not
    // made through.
    assert_eq!(w.code(&["write", "flink", "create-only", "0"], b"x"), 84);
    assert_eq!(w.code(&["write", "dangling", "create-only", "0"], b"x"), 84);
    assert_eq!(w.code(&["write", "dangling", "append", "0"], b"x"), 81);
    assert_eq!(w.code(&["write", "flink", "append", "0"], b"+"), 0);
    assert_eq!(std::fs::read(w.root().join("real/file")).unwrap(), b"inside+");
    assert_eq!(w.code(&["write", "inner/new", "replace", "0"], b"made"), 0);
    assert_eq!(std::fs::read(w.root().join("real/new")).unwrap(), b"made");
    assert_eq!(w.code(&["write", "out/planted", "create-only", "1"], b"x"), 80);
    assert_eq!(w.code(&["write", "out", "replace", "0"], b"a file now"), 0);
    assert!(std::fs::symlink_metadata(w.root().join("out")).unwrap().is_file());
    symlink(&outside, w.root().join("out2")).unwrap();
    // mkdir: a link to a folder inside is a folder already there; one leaving is refused; a
    // dangling one is something there.
    assert_eq!(w.code(&["mkdir", "dlink", "0"], b""), 0);
    assert_eq!(w.code(&["mkdir", "inner/made", "0"], b""), 0);
    assert!(w.root().join("real/made").is_dir());
    assert_eq!(w.code(&["mkdir", "out2/made", "1"], b""), 80);
    assert_eq!(w.code(&["mkdir", "dangling", "1"], b""), 84);
    // list: the folder named followed by the rule; the walk goes into no link.
    let (e, whole) = w.frames(&["list", "inner", "0", "8192"], b"", 3);
    assert!(whole && e.iter().any(|en| en[0].1 == b"file"));
    assert_eq!(w.code(&["list", "out2", "1", "8192"], b""), 80);
    let (e, whole) = w.frames(&["list", ".", "1", "65536"], b"", 3);
    let listed: Vec<(String, String)> =
        e.iter().map(|en| (payloads(en)[0].1.clone(), payloads(en)[1].1.clone())).collect();
    assert!(whole);
    assert!(listed.contains(&("out2".into(), "l".into())) && listed.contains(&("a/b/root".into(), "l".into())));
    assert!(
        !listed.iter().any(|(p, _)| p.starts_with("out2/") || p.starts_with("inner/") || p.starts_with("a/b/root/"))
    );
    // remove and rename act on the link itself.
    assert_eq!(w.code(&["remove", "flink", "1"], b""), 83);
    assert_eq!(w.code(&["remove", "flink", "0"], b""), 0);
    assert_eq!(std::fs::read(w.root().join("real/file")).unwrap(), b"inside+");
    assert_eq!(w.code(&["rename", "out2", "moved", "0"], b""), 0);
    assert!(std::fs::symlink_metadata(w.root().join("moved")).unwrap().file_type().is_symlink());
    assert_eq!(w.code(&["remove", "dangling", "0"], b""), 0);
    assert_eq!(w.code(&["remove", "moved", "0"], b""), 0);
    // The root names the work folder where a folder is meant, and nothing acts on it.
    for args in [
        &["read", ".", "0", "1"][..],
        &["remove", ".", "1"],
        &["rename", ".", "x", "0"],
        &["write", ".", "replace", "0"],
    ] {
        assert_eq!(w.code(args, b""), 2, "{args:?}");
    }
    let names: Vec<String> =
        std::fs::read_dir(&outside).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names, ["secret"]);
    assert_eq!(std::fs::read(outside.join("secret")).unwrap(), b"not yours\n");
}

/// The race the scripts left open: a folder on the path swapped for a link out while the
/// file under it is read. openat2 resolves the whole path beneath the work folder, so the read
/// gets the file, a refusal or nothing there, and never the file outside.
#[test]
fn a_folder_swapped_for_a_link_mid_read_is_never_followed() {
    let w = Work::new("race");
    w.put("real/secret", b"inside\n");
    let stop = Arc::new(AtomicBool::new(false));
    let (root, outside, flag) = (w.root(), w.0.join("outside"), stop.clone());
    let flipper = std::thread::spawn(move || {
        let (real, swap) = (root.join("real"), root.join("d"));
        while !flag.load(Ordering::Relaxed) {
            let _ = std::fs::rename(&real, &swap);
            let _ = std::fs::rename(&swap, &real);
            let _ = symlink(&outside, &swap);
            let _ = std::fs::remove_file(&swap);
        }
    });
    let mut codes = std::collections::BTreeSet::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let (code, out) = w.run(&["read", "d/secret", "0", "100"], b"");
        assert!(!out.windows(9).any(|x| x == b"not yours"), "a read followed the link out");
        codes.insert(code);
    }
    stop.store(true, Ordering::Relaxed);
    flipper.join().unwrap();
    assert!(codes.iter().all(|c| [0, 80, 81].contains(c)), "{codes:?}");
    assert!(codes.contains(&80), "the link was never met: {codes:?}");
}

#[test]
fn names_holding_any_byte_are_framed_exactly() {
    let w = Work::new("names");
    let names = ["two\nlines", "p3:abc", "a\n  1 total", ".9:x", "plain"];
    for n in names {
        w.put(n, n.as_bytes());
    }
    let (e, whole) = w.frames(&["list", ".", "0", "8192"], b"", 3);
    let mut got: Vec<String> = e.iter().map(|en| payloads(en)[0].1.clone()).collect();
    got.sort();
    let mut want: Vec<String> = names.iter().map(|s| (*s).to_string()).collect();
    want.sort();
    assert!(whole);
    assert_eq!(got, want);
    let stdin: Vec<u8> = names.iter().flat_map(|n| n.bytes().chain([0])).collect();
    let (e, _) = w.frames(&["readmany", "100", "8192"], &stdin, 3);
    for (en, n) in e.iter().zip(names) {
        assert_eq!(payloads(en), [('p', n.into()), ('s', n.len().to_string()), ('b', n.into())]);
    }
}

#[test]
fn a_listing_pages_at_its_budget_with_nothing_missed_or_repeated() {
    let w = Work::new("pages");
    for d in 0..5 {
        for f in 0..80 {
            w.put(&format!("d{d}/{f:0>120}.txt"), b"");
        }
    }
    let mut paths = Vec::new();
    let mut after = Vec::new();
    let mut pages = 0;
    loop {
        let (e, whole) = w.frames(&["list", ".", "1", "8192"], &after, 3);
        pages += 1;
        paths.extend(e.iter().map(|en| en[0].1.clone()));
        if whole {
            break;
        }
        assert_ne!(e.len(), 0);
        after.clone_from(&e.last().unwrap()[0].1);
    }
    let unique: std::collections::BTreeSet<_> = paths.iter().collect();
    assert_eq!((paths.len(), unique.len()), (405, 405));
    assert!(pages > 5, "{pages} pages");
    // Flat listing pages too, by name.
    let (e, whole) = w.frames(&["list", "d0", "0", "8192"], b"", 3);
    assert!(!whole);
    let last = e.last().unwrap()[0].1.clone();
    let (rest, _) = w.frames(&["list", "d0", "0", "65536"], &last, 3);
    assert_eq!(e.len() + rest.len(), 80);
}

#[test]
fn readmany_frames_what_it_read_and_stops_at_its_budget() {
    let w = Work::new("many");
    w.put("r1", b"abc");
    w.put("r2", &[b'x'; 9000]);
    symlink(w.0.join("outside/secret"), w.root().join("lk")).unwrap();
    let (e, whole) = w.frames(&["readmany", "100", "8192"], b"r1\0lk\0none\0r2\0", 3);
    assert!(whole);
    let codes: Vec<_> = e.iter().map(|en| (payloads(en)[1].clone(), payloads(en)[2].clone())).collect();
    assert_eq!(
        codes,
        [
            (('s', "3".into()), ('b', "abc".into())),
            (('s', "0".into()), ('e', "80".into())),
            (('s', "0".into()), ('e', "81".into())),
            (('s', "0".into()), ('e', "87".into()))
        ]
    );
    let (e, whole) = w.frames(&["readmany", "10000", "8192"], b"r1\0r2\0", 3);
    assert!(!whole);
    assert_eq!(e.len(), 1);
    // session-files-6: an answer that stops at its budget always holds an item. A first item
    // whose bytes cannot fit the budget even alone is answered as too large for it (87), so
    // asking again with the rest makes progress, rather than "+" with nothing.
    let (e, whole) = w.frames(&["readmany", "10000", "8192"], b"r2\0r1\0", 3);
    assert!(whole);
    assert_eq!(payloads(&e[0])[2], ('e', "87".into()));
    assert_eq!(payloads(&e[1])[2], ('b', "abc".into()));
    let (e, whole) = w.frames(&["readmany", "1000", "8192"], b"", 3);
    assert!(whole && e.is_empty());
}

#[test]
fn a_tree_past_one_steps_output_lists_whole_in_pages() {
    // 60,000 names of 16 bytes: past one step's output (1 MiB) in one answer.
    let w = Work::new("big");
    for d in 0..60 {
        let dir = w.root().join(format!("d{d:02}"));
        std::fs::create_dir(&dir).unwrap();
        for f in 0..1000 {
            std::fs::File::create(dir.join(format!("file{f:04}.txt"))).unwrap();
        }
    }
    let (mut files, mut after, mut pages) = (0, Vec::new(), 0);
    loop {
        let (e, whole) = w.frames(&["list", ".", "1", "1048576"], &after, 3);
        pages += 1;
        files += e.iter().filter(|en| en[1].1 == b"f").count();
        if whole {
            break;
        }
        after.clone_from(&e.last().unwrap()[0].1);
    }
    assert_eq!(files, 60_000);
    assert!(pages >= 2, "{pages}");
}

#[test]
fn writes_and_folders_make_parents_only_when_asked() {
    let w = Work::new("parents");
    assert_eq!(w.code(&["write", "a/b/c.txt", "replace", "0"], b"x"), 81);
    assert_eq!(w.code(&["mkdir", "a/b", "0"], b""), 81);
    assert_eq!(w.code(&["mkdir", "a", "0"], b""), 0);
    assert_eq!(w.code(&["write", "a/c.txt", "replace", "0"], b"x"), 0);
    let (e, _) = w.frames(&["write", "a/d.txt", "append", "0"], b"hello", 1);
    assert_eq!(payloads(&e[0]), [('n', "5".into())]);
    // 4 MiB is the most one write carries.
    assert_eq!(w.code(&["write", "big", "replace", "0"], &vec![b'x'; (4 << 20) + 1]), 87);
    assert!(!w.root().join("big").exists());
    assert_eq!(w.code(&["write", "big", "replace", "0"], &vec![b'x'; 4 << 20]), 0);
    // Reads take up to 8 MiB at a time, from any offset.
    let (e, _) = w.frames(&["read", "big", "4194300", "8388608"], b"", 2);
    assert_eq!(payloads(&e[0]), [('s', "4194304".into()), ('b', "xxxx".into())]);
    assert_eq!(w.code(&["read", "big", "0", "8388609"], b""), 2);
    assert_eq!(w.code(&["read", "big", "0", "0"], b""), 2);
}

#[test]
fn rename_replaces_only_when_asked_and_moves_a_link_itself() {
    let w = Work::new("rename");
    w.put("a", b"one");
    w.put("b", b"two");
    assert_eq!(w.code(&["rename", "a", "b", "0"], b""), 84);
    assert_eq!(std::fs::read(w.root().join("b")).unwrap(), b"two");
    assert_eq!(w.code(&["rename", "a", "c", "0"], b""), 0);
    assert_eq!(w.code(&["rename", "c", "b", "1"], b""), 0);
    assert_eq!(std::fs::read(w.root().join("b")).unwrap(), b"one");
    assert_eq!(w.code(&["rename", "nothing", "x", "0"], b""), 81);
    symlink(w.0.join("outside"), w.root().join("out")).unwrap();
    assert_eq!(w.code(&["rename", "b", "out/b", "1"], b""), 80);
    // A link at either last part is moved or replaced itself, never its target.
    assert_eq!(w.code(&["rename", "out", "moved", "0"], b""), 0);
    assert_eq!(w.code(&["rename", "b", "moved", "0"], b""), 84);
    assert_eq!(w.code(&["rename", "b", "moved", "1"], b""), 0);
    assert!(std::fs::symlink_metadata(w.root().join("moved")).unwrap().is_file());
    assert_eq!(std::fs::read_dir(w.0.join("outside")).unwrap().count(), 1);
    assert_eq!(w.code(&["rename", "b", "dir/b", "0"], b""), 81);
}

#[test]
fn a_glob_lists_only_its_matches() {
    let w = Work::new("glob");
    for p in ["a.py", "src/b.py", "src/deep/c.py", "src/deep/c.txt", ".hidden/d.py", "node_modules/x/e.py"] {
        w.put(p, b"");
    }
    let listed = |pattern: &str| -> Vec<String> {
        let (e, whole) = w.frames(&["list", ".", "1", "65536", pattern], b"", 3);
        assert!(whole);
        e.iter().map(|en| payloads(en)[0].1.clone()).collect()
    };
    assert_eq!(listed("**/*.py"), [".hidden/d.py", "a.py", "node_modules/x/e.py", "src/b.py", "src/deep/c.py"]);
    assert_eq!(listed("src/*"), ["src/b.py", "src/deep"]);
    assert_eq!(listed("*.py"), ["a.py"]);
    assert_eq!(w.code(&["list", ".", "1", "65536", "a**"], b""), 2);
    // A glob with a cursor pages the matches.
    let (rest, whole) = w.frames(&["list", ".", "1", "65536", "**/*.py"], b"a.py", 3);
    assert!(whole);
    let rest: Vec<String> = rest.iter().map(|en| payloads(en)[0].1.clone()).collect();
    assert_eq!(rest, ["node_modules/x/e.py", "src/b.py", "src/deep/c.py"]);
}

#[test]
fn the_sandbox_scope_takes_absolute_paths_and_follows_links() {
    let w = Work::new("scope");
    w.put("real/file", b"inside");
    symlink(w.root().join("real"), w.root().join("alias")).unwrap();
    let abs = |rel: &str| w.root().join(rel).to_string_lossy().into_owned();
    let (e, _) = w.frames_in("sandbox", &["read", &abs("alias/file"), "0", "100"], b"", 2);
    assert_eq!(payloads(&e[0])[1], ('b', "inside".into()));
    // stat does not follow the last part, so a link is "l" there.
    let (e, _) = w.frames_in("sandbox", &["stat", &abs("alias")], b"", 4);
    assert_eq!(payloads(&e[0])[0], ('k', "l".into()));
    assert_eq!(w.run_in("sandbox", &["read", "real/file", "0", "1"], b"").0, 2, "a relative path in the sandbox scope");
    assert_eq!(
        w.run_in("work", &["read", &abs("real/file"), "0", "1"], b"").0,
        2,
        "an absolute path in the work scope"
    );
    assert_eq!(w.run_in("nowhere", &["read", "real/file", "0", "1"], b"").0, 2);
    // remove takes the link itself away, never its target.
    assert_eq!(w.run_in("sandbox", &["remove", &abs("alias"), "0"], b"").0, 0);
    assert!(w.root().join("real/file").exists());
}

/// No open waits: a FIFO planted where a file is read or written answers 85 at once.
#[test]
fn a_planted_pipe_answers_at_once() {
    let w = Work::new("pipe");
    assert!(Command::new("mkfifo").arg(w.root().join("p")).status().unwrap().success());
    let start = std::time::Instant::now();
    assert_eq!(w.code(&["read", "p", "0", "10"], b""), 85);
    assert_eq!(w.code(&["write", "p", "replace", "0"], b"x"), 85);
    assert_eq!(w.code(&["write", "p", "append", "0"], b"x"), 85);
    assert_eq!(w.frames(&["readmany", "10", "8192"], b"p\0", 3).0[0][2], (b'e', b"85".to_vec()));
    assert!(start.elapsed() < std::time::Duration::from_secs(5), "{:?}", start.elapsed());
}

/// The helper makes itself non-dumpable before it opens anything: while it waits on its
/// input, a process of the same user cannot read its /proc files.
#[test]
fn the_helper_is_non_dumpable_while_it_runs() {
    let w = Work::new("dumpable");
    let mut child = Command::new(HELPER)
        .args(["files", "work", "write", "x", "replace", "0"])
        .current_dir(w.root())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    // Until the helper has run its first line, its /proc files are the user's: wait for it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut refused = false;
    while std::time::Instant::now() < deadline {
        if let Err(e) = std::fs::read(format!("/proc/{pid}/environ")) {
            refused = e.kind() == std::io::ErrorKind::PermissionDenied;
            if refused {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    drop(child.stdin.take());
    child.wait().unwrap();
    if Command::new("id").arg("-u").output().unwrap().stdout == b"0\n" {
        return; // root reads any process's files
    }
    assert!(refused, "the helper's /proc/{pid}/environ stayed readable to its own user");
}

/// The work scope confines names, not inodes: a hard link the guest made in the work folder to
/// a file elsewhere reads as that file, and only when the guest may read it (Linux refuses a
/// hard link to a file the guest does not own while fs.protected_hardlinks is 1, its default).
#[test]
fn a_hard_link_reads_only_what_the_guest_can_read() {
    if Command::new("id").arg("-u").output().unwrap().stdout == b"0\n" {
        return; // root reads any file
    }
    let w = Work::new("hardlink");
    let outside = w.0.join("outside");
    std::fs::write(outside.join("closed"), b"closed\n").unwrap();
    std::fs::set_permissions(outside.join("closed"), PermissionsExt::from_mode(0o000)).unwrap();
    std::fs::hard_link(outside.join("closed"), w.root().join("closed")).unwrap();
    std::fs::hard_link(outside.join("secret"), w.root().join("open")).unwrap();
    assert_eq!(w.code(&["read", "closed", "0", "100"], b""), 86);
    let (e, _) = w.frames(&["read", "open", "0", "100"], b"", 2);
    assert_eq!(payloads(&e[0])[1], ('b', "not yours\n".into()));
    // A link to a file of root's is refused by the kernel itself, before any command.
    assert!(std::fs::hard_link("/etc/shadow", w.root().join("shadow")).is_err());
}

/// replace and create-only write a whole new file under a temporary name and rename it into
/// place: the file is all of the new content or as it was, its permission bits are kept, and
/// no temporary file is left behind, after a success or a refusal.
#[test]
fn replace_is_whole_or_nothing_and_leaves_nothing_behind() {
    let w = Work::new("atomic");
    w.put("f", b"old");
    std::fs::set_permissions(w.root().join("f"), PermissionsExt::from_mode(0o640)).unwrap();
    let (e, _) = w.frames(&["write", "f", "replace", "0"], b"new content", 1);
    assert_eq!(payloads(&e[0]), [('n', "11".into())]);
    assert_eq!(std::fs::read(w.root().join("f")).unwrap(), b"new content");
    let mode = std::fs::metadata(w.root().join("f")).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o640);
    assert_eq!(w.code(&["write", "f", "create-only", "0"], b"again"), 84);
    assert_eq!(w.code(&["write", "g", "create-only", "0"], b"fresh"), 0);
    if Command::new("id").arg("-u").output().unwrap().stdout != b"0\n" {
        std::fs::set_permissions(w.root().join("f"), PermissionsExt::from_mode(0o440)).unwrap();
        assert_eq!(w.code(&["write", "f", "replace", "0"], b"refused"), 86);
        assert_eq!(std::fs::read(w.root().join("f")).unwrap(), b"new content");
    }
    let left: Vec<String> = std::fs::read_dir(w.root())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".plimsoll-write-"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// `files SCOPE -` runs `words` read from stdin (their count, ":", each ended by a NUL), then
/// `input` as the command's own stdin: the form a daemon uses, since an exec's arguments reach a
/// sandbox as UTF-8 strings and a name need not be UTF-8.
fn stdin_form(w: &Work, words: &[&[u8]], input: &[u8]) -> (i32, Vec<u8>) {
    let mut stdin = format!("{}:", words.len()).into_bytes();
    for word in words {
        stdin.extend_from_slice(word);
        stdin.push(0);
    }
    stdin.extend_from_slice(input);
    w.run(&["-"], &stdin)
}

#[test]
fn the_stdin_form_carries_names_that_are_not_utf8() {
    let w = Work::new("stdin-form");
    let name: &[u8] = b"d\xff\n/f\xfe\x01";
    let (code, out) = stdin_form(&w, &[b"write", name, b"create-only", b"1"], b"bytes\n");
    assert_eq!(code, 0);
    assert_eq!(parse(&out, 1).0[0], [(b'n', b"6".to_vec())]);
    let (code, out) = stdin_form(&w, &[b"read", name, b"0", b"100"], b"");
    assert_eq!(code, 0);
    assert_eq!(parse(&out, 2).0[0], [(b's', b"6".to_vec()), (b'b', b"bytes\n".to_vec())]);
    // A listing's cursor and readmany's paths follow the words, as stdin does in the argv form.
    let (code, out) = stdin_form(&w, &[b"list", b".", b"1", b"8192"], b"");
    assert_eq!(code, 0);
    let (entries, whole) = parse(&out, 3);
    assert!(whole);
    assert_eq!(entries.iter().map(|e| e[0].1.clone()).collect::<Vec<_>>(), [b"d\xff\n".to_vec(), name.to_vec()]);
    let (code, out) = stdin_form(&w, &[b"list", b".", b"1", b"8192"], b"d\xff\n");
    assert_eq!(code, 0);
    assert_eq!(parse(&out, 3).0.len(), 1);
    let mut paths = name.to_vec();
    paths.push(0);
    let (code, out) = stdin_form(&w, &[b"readmany", b"100", b"8192"], &paths);
    assert_eq!(code, 0);
    assert_eq!(parse(&out, 3).0[0][1..], [(b's', b"6".to_vec()), (b'b', b"bytes\n".to_vec())]);
    let (code, _) = stdin_form(&w, &[b"rename", name, b"d\xff\n/g\x80", b"0"], b"");
    assert_eq!(code, 0);
    let moved = w.root().join(std::ffi::OsStr::from_bytes(b"d\xff\n/g\x80"));
    assert_eq!(std::fs::read(moved).unwrap(), b"bytes\n");
}

#[test]
fn a_malformed_stdin_form_is_a_malformed_command() {
    let w = Work::new("stdin-bad");
    for bad in [&b""[..], b"stat\0", b"0:", b"01:stat\0.\0", b"7:stat\0.\0.\0.\0.\0.\0.\0", b"2:stat\0.", b"x:stat\0"] {
        assert_eq!(w.run(&["-"], bad).0, 2, "{bad:?}");
    }
    let mut long = b"2:stat\0".to_vec();
    long.extend(std::iter::repeat_n(b'a', 4097));
    long.push(0);
    assert_eq!(w.run(&["-"], &long).0, 2);
    // The words are a command's, checked as the argv form checks them.
    assert_eq!(stdin_form(&w, &[b"read", b"../x", b"0", b"1"], b"").0, 2);
    assert_eq!(stdin_form(&w, &[b"stat", b"missing"], b"").0, 81);
}

/// Starts `files work ARGS` in the work folder with `envs` (and the not-a-mount hook unless
/// `mount_rule` keeps the work scope's rule), writes `stdin` and closes it.
fn spawn(w: &Work, args: &[&str], stdin: &[u8], envs: &[(&str, String)], mount_rule: bool) -> std::process::Child {
    let mut c = Command::new(HELPER);
    c.args(["files", "work"]).args(args).current_dir(w.root());
    if !mount_rule {
        c.env(NOT_A_MOUNT, "1");
    }
    for (k, v) in envs {
        c.env(k, v);
    }
    let mut child = c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child
}

/// Waits until `marker` exists (the helper paused there) or the child has exited: true when
/// it paused.
fn paused(child: &mut std::process::Child, marker: &std::path::Path) -> bool {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < end {
        if marker.exists() {
            return true;
        }
        if child.try_wait().unwrap().is_some() {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    panic!("the helper neither paused nor exited");
}

/// session-files-3: a folder the helper opened can be moved by another process while the call
/// holds it, and a write through it then lands wherever the folder went. Only a mount's edge
/// stops a move out of the work folder (rename across mounts is EXDEV), so the work scope
/// refuses a work folder that is not a mount of its own, before it opens anything below it.
/// The race is driven here: the helper pauses once it holds the parent, the test moves an
/// ancestor out of the work folder, then lets it go on.
#[test]
fn an_ancestor_moved_out_mid_call_never_takes_a_write_outside() {
    let w = Work::new("ancestor");
    w.put("a/b/keep", b"");
    let marker = w.0.join("marker");
    let pause = ("PLIMSOLL_HELPER_TEST_PAUSE", format!("parent:{}", marker.display()));
    let mut child = spawn(&w, &["write", "a/b/f", "replace", "0"], b"written", &[pause], true);
    if paused(&mut child, &marker) {
        std::fs::rename(w.root().join("a"), w.0.join("outside/a")).unwrap();
        std::fs::remove_file(&marker).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(!w.0.join("outside/a/b/f").exists(), "the write landed outside the work folder");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.starts_with(b"EXDEV: "), "{:?}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(w.code(&["stat", "a/b/keep"], b""), 0);
}

/// session-files-3, the other half: a work folder that is a mount of its own is accepted, and
/// the move the race above needs is refused by the kernel there. Run in a user and mount
/// namespace of its own (unshare), where a tmpfs can be mounted without privilege; skipped
/// where unprivileged namespaces are off.
#[test]
fn a_work_folder_that_is_its_own_mount_is_accepted_and_holds_its_folders() {
    let w = Work::new("mounted");
    let script = format!(
        "set -e; mount -t tmpfs none {work}; cd {work}; mkdir -p a/b; \
         printf data | {helper} files work write a/b/f replace 0 >/dev/null; \
         if {helper} files sandbox rename {work}/a {outside}/a 0 2>/dev/null; then echo moved; else echo refused; fi; \
         cat a/b/f",
        work = w.root().display(),
        outside = w.0.join("outside").display(),
        helper = HELPER,
    );
    let Ok(out) = Command::new("unshare").args(["-U", "-r", "-m", "sh", "-c", &script]).output() else {
        return;
    };
    if !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("unshare") {
        return; // no unprivileged namespaces here
    }
    assert_eq!(String::from_utf8_lossy(&out.stdout), "refused\ndata", "{}", String::from_utf8_lossy(&out.stderr));
}

/// session-files-4: the staging name of a replace is swapped by another process for a file of
/// its own between the staging and the rename (the helper pauses there). The helper must not
/// report success for content it did not write: the name then holds another file, and the
/// answer is 92 (what the file holds is unknown), with no count. Run on both staging paths:
/// O_TMPFILE (named only for the moment before the rename) and a staging name from the start
/// (where the file system has no O_TMPFILE, as gVisor's tmpfs).
#[test]
fn a_swapped_staging_file_is_never_reported_as_written() {
    for no_tmpfile in [false, true] {
        let w = Work::new(if no_tmpfile { "swap-named" } else { "swap-tmpfile" });
        w.put("f", b"old");
        let marker = w.0.join("marker");
        let mut envs = vec![("PLIMSOLL_HELPER_TEST_PAUSE", format!("staged:{}", marker.display()))];
        if no_tmpfile {
            envs.push(("PLIMSOLL_HELPER_TEST_NO_TMPFILE", "1".into()));
        }
        let mut child = spawn(&w, &["write", "f", "replace", "0"], b"the helper's", &envs, false);
        assert!(paused(&mut child, &marker), "no_tmpfile {no_tmpfile}: the helper never staged");
        let name = String::from_utf8(std::fs::read(&marker).unwrap()).unwrap();
        assert!(name.starts_with(".plimsoll-write-"), "{name:?}");
        std::fs::remove_file(w.root().join(&name)).unwrap();
        std::fs::write(w.root().join(&name), b"the guest's").unwrap();
        std::fs::remove_file(&marker).unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(92), "no_tmpfile {no_tmpfile}: {:?}", out.stdout);
        assert_eq!(out.stdout, b"");
    }
}

/// session-files-7: a replace killed after it made its staging name (the helper pauses there and
/// is killed, which no cleanup of its own can follow) leaves that name, and the next replace or
/// create-only write into the folder removes it, since its helper is gone. A staging name of a
/// helper still running is kept.
#[test]
fn a_killed_replace_leaves_nothing_past_the_next_write() {
    let w = Work::new("killed");
    let marker = w.0.join("marker");
    let envs = [
        ("PLIMSOLL_HELPER_TEST_PAUSE", format!("staged:{}", marker.display())),
        ("PLIMSOLL_HELPER_TEST_NO_TMPFILE", "1".into()),
    ];
    let mut child = spawn(&w, &["write", "f", "replace", "0"], b"cut", &envs, false);
    assert!(paused(&mut child, &marker));
    child.kill().unwrap();
    child.wait().unwrap();
    let staged = || -> Vec<String> {
        std::fs::read_dir(w.root())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".plimsoll-write-"))
            .collect()
    };
    assert_eq!(staged().len(), 1, "the kill left no staging name to tidy");
    // A live helper's staging name (this test's own process id) is kept.
    let live = format!(".plimsoll-write-{:x}-0000000000000000", std::process::id());
    std::fs::write(w.root().join(&live), b"").unwrap();
    assert_eq!(w.code(&["write", "g", "replace", "0"], b"next"), 0);
    assert_eq!(staged(), [live]);
    assert!(!w.root().join("f").exists());
}

/// Runs `script` with sh in a user and mount namespace of its own (unshare), where a tmpfs or a
/// bind can be mounted without privilege: its stdout, or None where unprivileged namespaces are
/// off (the script's first line of output must then be missing: each script echoes "ready"
/// once its mounts are made).
fn in_namespace(script: &str) -> Option<String> {
    let out = Command::new("unshare").args(["-U", "-r", "-m", "sh", "-c", script]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if !text.starts_with("ready\n") {
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("unshare"),
            "the namespace script failed before its mounts: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None; // no unprivileged namespaces here
    }
    Some(text["ready\n".len()..].to_string())
}

/// A write past the kernel's file size limit (RLIMIT_FSIZE, with SIGXFSZ ignored so the write
/// answers EFBIG instead of the signal ending the helper) is 87, the contract's past a size cap,
/// as the helper's own caps are; the file named is left as it was and no staging name stays.
#[test]
fn a_write_past_the_kernels_file_size_limit_is_87() {
    let w = Work::new("fsize");
    w.put("f", b"old");
    for (name, mode) in [("f", "replace"), ("new", "create-only")] {
        // ulimit -f counts 512-byte blocks in sh: 1 is 512 bytes.
        let script = "ulimit -f 1 && trap '' XFSZ && exec \"$0\" files work write \"$1\" \"$2\" 0";
        let mut child = Command::new("sh")
            .args(["-c", script, HELPER, name, mode])
            .current_dir(w.root())
            .env(NOT_A_MOUNT, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(&vec![b'x'; 100_000]);
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(87), "{mode}: {}", String::from_utf8_lossy(&out.stderr));
    }
    assert_eq!(std::fs::read(w.root().join("f")).unwrap(), b"old");
    let names: Vec<String> =
        std::fs::read_dir(w.root()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names, ["f"], "no staging name and no new file stays");
}

/// session-files-22: an append that runs out of space after it added a part answers 92 (what the
/// file holds is unknown) and is never cut back, since the length the file had is no proof that
/// the bytes after it are the call's own: another process's append may follow the part at any
/// moment, and a cut would take it too. One that runs out before its first byte answers 89 and
/// added nothing. Run on a 64 KiB tmpfs mounted in a user and mount namespace of its own (skipped
/// where those are off).
#[test]
fn an_append_that_runs_out_of_space_is_never_cut_back() {
    let w = Work::new("nospace");
    let script = format!(
        "set -e; mount -t tmpfs -o size=64k none {work}; cd {work}; head -c 40000 /dev/zero > f; echo ready; set +e; \
         head -c 100000 /dev/zero | {helper} files work write f append 0 >/dev/null; echo \"partial $? $(wc -c < f)\"; \
         head -c 100000 /dev/zero >> f 2>/dev/null; full=$(wc -c < f); \
         printf x | {helper} files work write f append 0 >/dev/null; echo \"full $? $(test $(wc -c < f) = $full && echo kept)\"",
        work = w.root().display(),
        helper = HELPER,
    );
    let Some(text) = in_namespace(&script) else { return };
    let words: Vec<&str> = text.split_whitespace().collect();
    assert_eq!(words.len(), 6, "{text}");
    assert_eq!(&words[..2], ["partial", "92"], "{text}");
    let size: u64 = words[2].parse().unwrap();
    assert!(size > 40_000 && size < 140_000, "the part added was cut back, or more was added: {text}");
    assert_eq!(&words[3..], ["full", "89", "kept"], "{text}");
}

/// session-files-21: where /proc is not mounted the helper cannot open a file by its descriptor,
/// and it opens none by its name instead (a name looked up again could hold a FIFO by then): a
/// read, a replace of a file that is there and an append fail closed (exit 1, ENOENT on
/// /proc/self/fd), the file as it was; a FIFO is still classified first (85). An empty tmpfs is
/// mounted over /proc in a user and mount namespace of the test's own (skipped where those are
/// off).
#[test]
fn without_proc_no_file_is_opened_by_its_name() {
    let w = Work::new("noproc");
    let script = format!(
        "set -e; mount -t tmpfs none {work}; cd {work}; printf data > f; mkfifo p; mount -t tmpfs none /proc; \
         test ! -e /proc/self; echo ready; set +e; \
         {helper} files work read f 0 10 2>err; echo \"read $? $(head -c 6 err)\"; \
         printf new | {helper} files work write f replace 0 2>err; echo \"replace $? $(head -c 6 err)\"; \
         printf new | {helper} files work write f append 0 2>err; echo \"append $? $(head -c 6 err)\"; \
         {helper} files work read p 0 1; echo \"fifo $?\"; \
         grep -q /proc/self/fd err && echo named; cat f",
        work = w.root().display(),
        helper = HELPER,
    );
    let Some(text) = in_namespace(&script) else { return };
    assert_eq!(
        text, "read 1 ENOENT\nreplace 1 ENOENT\nappend 1 ENOENT\nfifo 85\nnamed\ndata",
        "each call must fail closed, the file unchanged"
    );
}

/// session-files-19: a mount below the work folder (here a bind of an outside folder at
/// work/shared, and of an outside file at work/fm, as a template could make) is never crossed by
/// the work scope: a folder the helper held there could be moved out of the work folder by a
/// process of the guest's (a rename within the outside file system crosses no edge of the work
/// mount), and a write through it would land outside. Every command answers 86 for a path across
/// it, through openat2's RESOLVE_NO_XDEV, a link inside that points into it included; a
/// recursive listing lists the mount's folder as one it could not enter (u) and goes on;
/// nothing outside is written, made or removed. The sandbox scope still reaches it. Run in a
/// user and mount namespace of the test's own (skipped where those are off).
#[test]
fn the_work_scope_never_crosses_a_mount_below_the_work_folder() {
    use std::fmt::Write as _;
    let w = Work::new("xdev");
    std::fs::create_dir_all(w.0.join("outside/sub/dir")).unwrap();
    std::fs::write(w.0.join("outside/sub/dir/x"), b"outside\n").unwrap();
    std::fs::write(w.0.join("outside/file"), b"outside file\n").unwrap();
    let calls = [
        ("stat", "stat shared"),
        ("stat-below", "stat shared/dir"),
        ("read", "read shared/dir/x 0 10"),
        // Nothing there beyond the mount: the resolution without RESOLVE_NO_XDEV answers
        // ENOENT, and every try ends so, so the answer is the mount's.
        ("read-missing", "read shared/none 0 10"),
        ("write", "write shared/dir/f replace 0"),
        ("create", "write shared/new create-only 0"),
        ("append", "write shared/dir/x append 0"),
        ("parents", "write shared/made/f replace 1"),
        ("mkdir", "mkdir shared/m 0"),
        ("remove", "remove shared/dir/x 0"),
        ("remove-mount", "remove shared 1"),
        ("rename-out", "rename shared/dir/x moved 0"),
        ("rename-in", "rename a shared/a 0"),
        ("rename-over", "rename a fm 1"),
        ("list", "list shared 0 8192"),
        ("file-read", "read fm 0 10"),
        ("file-stat", "stat fm"),
        ("file-replace", "write fm replace 0"),
        ("file-append", "write fm append 0"),
    ];
    let mut script = format!(
        "set -e; mount -t tmpfs none {work}; cd {work}; mkdir shared; : > fm; printf a > a; \
         mount --bind {outside}/sub shared; mount --bind {outside}/file fm; echo ready; set +e; ",
        work = w.root().display(),
        outside = w.0.join("outside").display(),
    );
    for (name, args) in calls {
        let _ = write!(script, "printf x | {HELPER} files work {args} >/dev/null 2>&1; echo \"{name} $?\"; ");
    }
    let _ = write!(
        script,
        "{HELPER} files work list . 1 8192 </dev/null | tr -c '[:print:]' ' '; echo; \
         {HELPER} files work list . 0 8192 </dev/null | tr -c '[:print:]' ' '; echo; \
         printf 'shared/dir/x\\0' | {HELPER} files work readmany 100 8192 | tr -c '[:print:]' ' '; echo; \
         ln -s shared/dir inner; {HELPER} files work read inner/x 0 10 >/dev/null 2>&1; echo \"inner $?\"; \
         ln -s shared/../a back; {HELPER} files work read back 0 10 >/dev/null 2>&1; echo \"back $?\"; \
         {HELPER} files sandbox read {work}/shared/dir/x 0 10 >/dev/null; echo \"sandbox $?\"; \
         (cd {outside}/sub && ls -A . dir) | tr '\\n' ' '; echo; cat {outside}/file; cat a",
        work = w.root().display(),
        outside = w.0.join("outside").display(),
    );
    let Some(text) = in_namespace(&script) else { return };
    let mut lines = text.lines();
    for (name, _) in calls {
        assert_eq!(lines.next(), Some(format!("{name} 86").as_str()), "{text}");
    }
    // The recursive listing: a, fm (a file mount: its kind is not read across it), shared
    // as a folder it could not enter, and nothing from below it.
    assert_eq!(lines.next(), Some("p1:ak1:fs1:1p2:fmk1:os1:0p6:sharedk1:us1:0.1:3"), "{text}");
    // The flat listing names the mount point's folder as the folder it is in the work folder.
    assert_eq!(lines.next(), Some("p1:ak1:fs1:1p2:fmk1:os1:0p6:sharedk1:ds1:0.1:3"), "{text}");
    assert_eq!(lines.next(), Some("p12:shared/dir/xs1:0e2:86.1:1"), "{text}");
    // A link inside into the mount: 86, the mount's.
    assert_eq!(lines.next(), Some("inner 86"), "{text}");
    // A link through the mount and back to a file of the work folder: the resolution crossed
    // a mount (86, every try ending on the work mount).
    assert_eq!(lines.next(), Some("back 86"), "{text}");
    assert_eq!(lines.next(), Some("sandbox 0"), "the sandbox scope: {text}");
    assert_eq!(lines.next(), Some(".: dir  dir: x "), "something was written, made or removed outside: {text}");
    assert_eq!(lines.next(), Some("outside file"), "{text}");
    assert_eq!(lines.next(), Some("a"), "{text}");
}

/// session-files-8: a FIFO at a path is classified on an O_PATH descriptor and never opened, for
/// reading or for writing, by any command. inotify reports every open of the FIFO (an O_PATH
/// pin is no open of the file), so the test watches for one while each command meets it.
#[test]
fn a_fifo_is_never_opened() {
    unsafe extern "C" {
        fn inotify_init1(flags: i32) -> i32;
        fn inotify_add_watch(fd: i32, path: *const std::ffi::c_char, mask: u32) -> i32;
        fn read(fd: i32, buf: *mut std::ffi::c_void, n: usize) -> isize;
    }
    const IN_OPEN: u32 = 0x20;
    const IN_NONBLOCK: i32 = 0o4000;
    let w = Work::new("fifo");
    let fifo = w.root().join("p");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    symlink("p", w.root().join("lp")).unwrap();
    // SAFETY: plain system calls on a path and a buffer of this test's own.
    let fd = unsafe { inotify_init1(IN_NONBLOCK) };
    assert!(fd >= 0);
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert!(unsafe { inotify_add_watch(fd, c.as_ptr(), IN_OPEN) } >= 0);
    for args in [
        &["read", "p", "0", "10"][..],
        &["read", "lp", "0", "10"],
        &["write", "p", "replace", "0"],
        &["write", "p", "append", "0"],
        &["write", "lp", "append", "0"],
    ] {
        assert_eq!(w.code(args, b"x"), 85, "{args:?}");
        let mut buf = [0u8; 4096];
        let n = unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        assert!(n <= 0, "{args:?} opened the FIFO");
    }
    let (e, _) = w.frames(&["readmany", "10", "8192"], b"p\0lp\0", 3);
    assert!(e.iter().all(|en| en[2] == (b'e', b"85".to_vec())));
    let mut buf = [0u8; 4096];
    assert!(unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) } <= 0, "readmany opened the FIFO");
}

/// session-files-6: every path a listing answers is accepted back as its cursor, an answer that
/// stops at its budget always holds an entry, and a tree whose paths from the folder listed
/// would pass 4,096 bytes (folders of 200-byte names, 25 deep) ends with 91 at that point,
/// never with a path no cursor could carry.
#[test]
fn every_listed_path_is_a_cursor_and_every_page_progresses() {
    unsafe extern "C" {
        fn mkdirat(dir: i32, path: *const std::ffi::c_char, mode: u32) -> i32;
        fn openat(dir: i32, path: *const std::ffi::c_char, flags: i32, ...) -> i32;
        fn close(fd: i32) -> i32;
    }
    let w = Work::new("deep");
    // Made folder by folder from the one before (mkdirat, openat): the whole path is past
    // PATH_MAX, so no absolute path names the deepest.
    let top = std::ffi::CString::new(w.root().as_os_str().as_bytes()).unwrap();
    // SAFETY: plain system calls on names and descriptors of this test's own.
    let mut dir = unsafe { openat(-100, top.as_ptr(), 0o200_000) };
    assert!(dir >= 0);
    for i in 0..25 {
        let d = std::ffi::CString::new(format!("{i:0>200}")).unwrap();
        let f = std::ffi::CString::new(format!("{:0>200}", "f")).unwrap();
        unsafe {
            assert_eq!(mkdirat(dir, d.as_ptr(), 0o755), 0);
            let next = openat(dir, d.as_ptr(), 0o200_000);
            assert!(next >= 0);
            close(dir);
            dir = next;
            let fd = openat(dir, f.as_ptr(), 0o100 | 0o1, 0o644);
            assert!(fd >= 0);
            close(fd);
        }
    }
    unsafe { close(dir) };
    let mut after = Vec::new();
    let mut seen = 0;
    let code = loop {
        let (code, out) = w.run(&["list", ".", "1", "8192"], &after);
        if code != 0 {
            break code;
        }
        let (e, whole) = parse(&out, 3);
        seen += e.len();
        if whole {
            break 0;
        }
        assert!(!e.is_empty(), "a page that stopped at its budget with no entry");
        after.clone_from(&e.last().unwrap()[0].1);
        assert!(after.len() <= 4096);
    };
    assert_eq!(code, 91);
    assert!(seen >= 20, "{seen}: every folder whose path fits 4,096 bytes, then 91");
}

/// session-files-6: a recursive listing that meets a folder it may not enter names it "u"
/// (unreadable) and goes on, rather than answering as if that folder were empty or ending the
/// whole listing (a recursive listing of the sandbox's "/" meets such folders at once). A folder
/// the guest may read but not search, or search but not read, is as unreadable; a flat listing
/// enters nothing, so it names them "d"; and a listing of such a folder itself is 86.
#[test]
fn an_unreadable_folder_in_a_listing_is_reported() {
    if Command::new("id").arg("-u").output().unwrap().stdout == b"0\n" {
        return; // root enters any folder
    }
    let w = Work::new("unreadable");
    w.put("a/x", b"");
    w.put("noread/b", b"");
    w.put("nosearch/c", b"");
    w.put("shut/d", b"");
    w.put("z", b"zz");
    for (name, mode) in [("noread", 0o311), ("nosearch", 0o644), ("shut", 0o000)] {
        std::fs::set_permissions(w.root().join(name), PermissionsExt::from_mode(mode)).unwrap();
    }
    let (e, whole) = w.frames(&["list", ".", "1", "8192"], b"", 3);
    let got: Vec<(String, String)> = e
        .iter()
        .map(|e| (String::from_utf8_lossy(&e[0].1).into_owned(), String::from_utf8_lossy(&e[1].1).into_owned()))
        .collect();
    let want = [("a", "d"), ("a/x", "f"), ("noread", "u"), ("nosearch", "u"), ("shut", "u"), ("z", "f")];
    assert!(whole, "{got:?}");
    assert_eq!(got, want.iter().map(|(p, k)| (p.to_string(), k.to_string())).collect::<Vec<_>>());
    // Paged one entry at a time, the cursor at an unreadable folder goes on after it.
    let (first, _) = w.frames(&["list", ".", "1", "8192"], b"noread", 3);
    assert_eq!(first[0][0].1, b"nosearch");
    assert_eq!(first[0][1].1, b"u");
    let (e, whole) = w.frames(&["list", ".", "0", "8192"], b"", 3);
    assert!(whole && e.len() == 5 && e.iter().filter(|e| e[1].1 == b"d").count() == 4);
    for dir in ["noread", "nosearch", "shut"] {
        assert_eq!(w.code(&["list", dir, "0", "8192"], b""), 86, "{dir}");
        assert_eq!(w.code(&["list", dir, "1", "8192"], b""), 86, "{dir}");
    }
    for name in ["noread", "nosearch", "shut"] {
        std::fs::set_permissions(w.root().join(name), PermissionsExt::from_mode(0o755)).unwrap();
    }
}

/// session-files-3: a scratch folder is not a mount of its own, so the work scope refuses it
/// (exit 1, EXDEV) for every command, before anything below it is opened.
#[test]
fn an_unmounted_work_folder_is_refused() {
    let w = Work::new("unmounted");
    w.put("f", b"x");
    let out = spawn(&w, &["stat", "f"], b"", &[], true).wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.starts_with(b"EXDEV: "), "{:?}", String::from_utf8_lossy(&out.stderr));
    let out = Command::new(HELPER).args(["files", "sandbox", "stat", "/"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "the sandbox scope has no such rule");
}

/// session-files-23 (D101 A): the work scope needs a kernel whose statx states mount ids (Linux
/// 5.8) and that has openat2 (Linux 5.6), since nothing else tells a second mount of the work
/// folder's own file system apart. On a kernel without either (this debug build's hooks answer
/// as one does) every work-scope command exits 1 with ENOSYS first on stderr and the cause named,
/// before any path is resolved and before the work folder's own mount is checked: nothing is
/// read, written, made, moved or removed. The sandbox scope still answers.
#[test]
fn a_kernel_without_mount_ids_or_openat2_is_refused_by_the_work_scope() {
    let w = Work::new("oldkernel");
    w.put("f", b"x");
    let calls: [&[&str]; 8] = [
        &["stat", "f"],
        &["read", "f", "0", "1"],
        &["write", "new", "replace", "0"],
        &["mkdir", "made", "0"],
        &["remove", "f", "0"],
        &["rename", "f", "g", "0"],
        &["list", ".", "1", "8192"],
        &["readmany", "10", "8192"],
    ];
    for (hook, call, why) in [
        ("PLIMSOLL_HELPER_TEST_NO_MOUNT_ID", "statx", "states no mount id"),
        ("PLIMSOLL_HELPER_TEST_OPENAT2_ENOSYS", "openat2", "has no openat2"),
    ] {
        for mount_rule in [true, false] {
            for args in calls {
                // readmany's paths and a write's bytes come on stdin; a listing reads none.
                let stdin: &[u8] = match args[0] {
                    "readmany" => b"f\0",
                    "write" => b"y",
                    _ => b"",
                };
                let out = spawn(&w, args, stdin, &[(hook, "1".to_string())], mount_rule).wait_with_output().unwrap();
                let err = String::from_utf8_lossy(&out.stderr);
                assert_eq!(out.status.code(), Some(1), "{hook} {args:?}: {err}");
                assert!(out.stdout.is_empty(), "{hook} {args:?}");
                assert!(err.starts_with("ENOSYS: "), "{hook} {args:?}: {err}");
                assert!(
                    err.contains(&format!("{call} '")) && err.contains("Linux 5.8") && err.contains(why),
                    "{hook}: {err}"
                );
            }
        }
        let out = Command::new(HELPER).args(["files", "sandbox", "stat", "/"]).env(hook, "1").output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{hook}: the sandbox scope has no such rule");
    }
    let mut names: Vec<String> =
        std::fs::read_dir(w.root()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["f"], "nothing was made, moved or removed");
    assert_eq!(std::fs::read(w.root().join("f")).unwrap(), b"x");
}

/// session-files-4: where an unnamed file cannot be linked (this debug build's hook), a replace
/// and a create-only write stage again under a name and still publish whole, leaving no staging
/// name.
#[test]
fn a_write_whose_unnamed_file_cannot_be_linked_stages_again_under_a_name() {
    let w = Work::new("restage");
    w.put("f", b"old");
    let hook = [("PLIMSOLL_HELPER_TEST_NO_LINK", "1")];
    assert_eq!(w.run_env(&["write", "f", "replace", "0"], b"new", &hook).0, 0);
    assert_eq!(w.run_env(&["write", "g", "create-only", "0"], b"fresh", &hook).0, 0);
    assert_eq!(w.run_env(&["write", "g", "create-only", "0"], b"again", &hook).0, 84);
    assert_eq!(std::fs::read(w.root().join("f")).unwrap(), b"new");
    assert_eq!(std::fs::read(w.root().join("g")).unwrap(), b"fresh");
    let left = std::fs::read_dir(w.root())
        .unwrap()
        .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with(".plimsoll-write-"));
    assert_eq!(left.count(), 0);
}

/// readmany takes at most 16,384 paths (so a store's search reads a large tree in few calls): at the
/// cap every path is answered, in order; one past it is a malformed command (2).
#[test]
fn readmany_takes_paths_up_to_its_cap_and_refuses_one_past_it() {
    const CAP: usize = 16_384;
    let w = Work::new("readmany-cap");
    w.put("f0", b"zero");
    w.put("f16383", b"last");
    let input = |n: usize| -> Vec<u8> {
        let mut b = Vec::new();
        for i in 0..n {
            b.extend_from_slice(format!("f{i}").as_bytes());
            b.push(0);
        }
        b
    };
    let (e, whole) = w.frames(&["readmany", "100", "8388608"], &input(CAP), 3);
    assert!(whole);
    assert_eq!(e.len(), CAP);
    assert_eq!(payloads(&e[0])[2], ('b', "zero".into()));
    assert_eq!(payloads(&e[1])[2], ('e', "81".into()));
    assert_eq!(payloads(&e[CAP - 1])[0], ('p', "f16383".into()));
    assert_eq!(payloads(&e[CAP - 1])[2], ('b', "last".into()));
    assert_eq!(w.code(&["readmany", "100", "8388608"], &input(CAP + 1)), 2);
}

/// A Landlock ruleset (the kernel's own access control for an unprivileged process, the one
/// OpenShell confines its sandboxes with), declared by hand as src/sys.rs declares its calls: the
/// crate takes no outside package. The system call numbers are the same on every machine.
mod landlock {
    use std::ffi::{c_int, c_long};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::Command;

    unsafe extern "C" {
        fn syscall(n: c_long, ...) -> c_long;
        fn prctl(option: c_int, ...) -> c_int;
    }

    const CREATE_RULESET: c_long = 444;
    const ADD_RULE: c_long = 445;
    const RESTRICT_SELF: c_long = 446;
    const RULE_PATH_BENEATH: c_long = 1;
    const PR_SET_NO_NEW_PRIVS: c_int = 38;

    pub const EXECUTE: u64 = 1 << 0;
    pub const READ_FILE: u64 = 1 << 2;
    /// Every file system right of the first Landlock version (EXECUTE to MAKE_SYM).
    pub const ALL: u64 = (1 << 13) - 1;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C, packed)]
    struct PathBeneath {
        allowed_access: u64,
        parent_fd: i32,
    }

    /// A ruleset that handles ALL and grants each path's rights beneath it, nothing elsewhere;
    /// None where the kernel has no Landlock (the test is then skipped).
    pub fn ruleset(rules: &[(&Path, u64)]) -> Option<OwnedFd> {
        let attr = RulesetAttr { handled_access_fs: ALL };
        // SAFETY: attr is a valid landlock_ruleset_attr of the size given; the call returns a
        // new descriptor or -1.
        let fd = unsafe { syscall(CREATE_RULESET, &raw const attr, size_of::<RulesetAttr>(), 0u32) };
        if fd < 0 {
            eprintln!("no Landlock here ({}): skipped", io::Error::last_os_error());
            return None;
        }
        // SAFETY: fd is the descriptor the call just returned, owned by nothing else.
        let set = unsafe { OwnedFd::from_raw_fd(fd as c_int) };
        for (path, allowed) in rules {
            let dir = std::fs::File::open(path).unwrap();
            let rule = PathBeneath { allowed_access: *allowed, parent_fd: dir.as_raw_fd() };
            // SAFETY: rule is a valid landlock_path_beneath_attr and set a ruleset descriptor.
            let r = unsafe { syscall(ADD_RULE, set.as_raw_fd(), RULE_PATH_BENEATH, &raw const rule, 0u32) };
            assert_eq!(r, 0, "add a rule for {}: {}", path.display(), io::Error::last_os_error());
        }
        Some(set)
    }

    /// Confines the command's process by `set` before it starts the program.
    pub fn confine(cmd: &mut Command, set: &OwnedFd) {
        let fd = set.as_raw_fd();
        // SAFETY: the closure, run in the child before it starts the program, makes two system
        // calls and allocates nothing.
        unsafe {
            cmd.pre_exec(move || {
                if prctl(PR_SET_NO_NEW_PRIVS, 1 as c_long, 0 as c_long, 0 as c_long, 0 as c_long) != 0
                    || syscall(RESTRICT_SELF, fd, 0u32) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

/// Runs `files SCOPE ARGS` with `stdin` in the work folder, confined by the Landlock ruleset
/// `set`: its exit code and stdout.
fn run_confined(w: &Work, set: &std::os::fd::OwnedFd, scope: &str, args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>) {
    let mut c = Command::new(HELPER);
    c.args(["files", scope]).args(args).current_dir(w.root()).env(NOT_A_MOUNT, "1");
    landlock::confine(&mut c, set);
    let mut child = c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let out = child.wait_with_output().unwrap();
    let code = out.status.code().unwrap();
    if code != 0 {
        assert!(out.stdout.is_empty(), "{args:?}: exit {code} with stdout {:?}", out.stdout);
    }
    (code, out.stdout)
}

/// The sandbox scope where "/" itself may not be read but what lies beneath it may, as
/// OpenShell's Landlock policy has it (it grants no read_dir on "/"): the scope's root is a
/// starting point opened O_PATH, never a folder read, so a stat, a write and a read beneath it
/// answer, a stat of "/" answers, and only a listing of "/" itself is refused (86). Measured on
/// OpenShell v0.1.2 on 2026-11-27, where an O_RDONLY root refused every call; this is the same
/// confinement by a Landlock ruleset of the test's own (the kernel's, not a stand-in): every
/// right granted beneath the scratch folder alone, and elsewhere only reading files and
/// starting programs, so the helper can start.
#[test]
fn the_sandbox_scope_answers_where_the_root_cannot_be_read() {
    let w = Work::new("landlock-root");
    w.put("f", b"there");
    let anywhere = landlock::READ_FILE | landlock::EXECUTE;
    let Some(set) = landlock::ruleset(&[(std::path::Path::new("/"), anywhere), (&w.0, landlock::ALL)]) else {
        return;
    };
    let abs = |rel: &str| w.root().join(rel).to_string_lossy().into_owned();
    let run = |args: &[&str], stdin: &[u8]| run_confined(&w, &set, "sandbox", args, stdin);
    // The confinement holds: "/" cannot be listed, at either depth.
    assert_eq!(run(&["list", "/", "0", "8192"], b"").0, 86);
    assert_eq!(run(&["list", "/", "1", "8192"], b"").0, 86);
    // And everything beneath it that the policy grants answers.
    let (code, out) = run(&["stat", &abs("f")], b"");
    assert_eq!(code, 0, "stat beneath an unreadable root");
    assert_eq!(payloads(&parse(&out, 4).0[0])[..2], [('k', "f".into()), ('s', "5".into())]);
    let (code, out) = run(&["stat", "/"], b"");
    assert_eq!(code, 0, "stat of the unreadable root itself");
    assert_eq!(payloads(&parse(&out, 4).0[0])[0], ('k', "d".into()));
    assert_eq!(run(&["write", &abs("new/g"), "replace", "1"], b"written").0, 0);
    assert_eq!(std::fs::read(w.root().join("new/g")).unwrap(), b"written");
    assert_eq!(run(&["write", &abs("g2"), "create-only", "0"], b"two").0, 0);
    assert_eq!(run(&["write", &abs("g2"), "append", "0"], b"+").0, 0);
    assert_eq!(std::fs::read(w.root().join("g2")).unwrap(), b"two+");
    let (code, out) = run(&["read", &abs("new/g"), "0", "100"], b"");
    assert_eq!(code, 0);
    assert_eq!(payloads(&parse(&out, 2).0[0])[1], ('b', "written".into()));
    let mut paths = abs("f").into_bytes();
    paths.push(0);
    let (code, out) = run(&["readmany", "100", "8192"], &paths);
    assert_eq!(code, 0);
    assert_eq!(payloads(&parse(&out, 3).0[0])[2], ('b', "there".into()));
    let (code, out) = run(&["list", &w.root().to_string_lossy(), "1", "8192"], b"");
    assert_eq!(code, 0, "a folder the policy lets the guest read lists");
    assert_eq!(parse(&out, 3).0.len(), 4, "f, g2, new, new/g");
    assert_eq!(run(&["mkdir", &abs("d/e"), "1"], b"").0, 0);
    assert_eq!(run(&["rename", &abs("g2"), &abs("g3"), "0"], b"").0, 0);
    assert_eq!(run(&["remove", &abs("g3"), "0"], b"").0, 0);
    assert!(!w.root().join("g3").exists());
}

/// The work scope's root the same way: a work folder the guest may not read, holding a folder
/// it may, answers calls beneath it and refuses (86) only a listing of the work folder itself.
#[test]
fn the_work_scope_answers_where_the_work_folder_cannot_be_read() {
    let w = Work::new("landlock-work");
    w.put("inner/f", b"there");
    let inner = w.root().join("inner");
    let anywhere = landlock::READ_FILE | landlock::EXECUTE;
    let Some(set) = landlock::ruleset(&[(std::path::Path::new("/"), anywhere), (&inner, landlock::ALL)]) else {
        return;
    };
    let run = |args: &[&str], stdin: &[u8]| run_confined(&w, &set, "work", args, stdin);
    assert_eq!(run(&["list", ".", "0", "8192"], b"").0, 86);
    let (code, out) = run(&["stat", "inner/f"], b"");
    assert_eq!(code, 0, "stat beneath an unreadable work folder");
    assert_eq!(payloads(&parse(&out, 4).0[0])[0], ('k', "f".into()));
    assert_eq!(run(&["stat", "."], b"").0, 0);
    assert_eq!(run(&["write", "inner/g", "replace", "0"], b"written").0, 0);
    assert_eq!(std::fs::read(inner.join("g")).unwrap(), b"written");
    let (code, out) = run(&["read", "inner/f", "0", "100"], b"");
    assert_eq!(code, 0);
    assert_eq!(payloads(&parse(&out, 2).0[0])[1], ('b', "there".into()));
    assert_eq!(run(&["list", "inner", "0", "8192"], b"").0, 0);
}
