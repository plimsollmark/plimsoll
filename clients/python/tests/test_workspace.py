"""The agent workspace against a fake session: what it sends (file calls for files, fixed
steps for commands, the model's text only in files), what it refuses, and how it reads
results. The real thing runs in docker_workspace_check.py, which client_test.go runs when
docker is there."""

from __future__ import annotations

import base64
import errno
import json
import os
import shlex
import subprocess
import tempfile
import unittest
from typing import Any, Callable, Dict, List, Optional, Tuple

from plimsoll_client import CancelHandle, ExecOutcome, Workspace, WorkspacePathError, WorkspaceTooLargeError
from plimsoll_client.errors import RequestCanceledError
from plimsoll_client import files as fs
from plimsoll_client import workspace as ws
from plimsoll_client.types import Artifact, ProjectResult, SessionSummary, StepResult
from tests._files_fake import MemoryFiles, glob_match, glob_refused
from tests._files_fake import result as files_result

ROOT = "/work"
MAX = ws.MAX_READ_BYTES
HERE = os.path.dirname(os.path.abspath(__file__))


def result(
    *,
    exit_code: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    artifacts: Optional[Dict[str, bytes]] = None,
    timed_out: bool = False,
    outcome: str = "completed",
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
    steps: Optional[List[StepResult]] = None,
) -> ProjectResult:
    if steps is None:
        steps = [
            StepResult(
                command="",
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=timed_out,
                duration_ms=1,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )
        ]
    return ProjectResult(
        provider="fake",
        isolation="container",
        environment="",
        software_identity="",
        duration_ms=1,
        record=None,
        outcome=outcome,
        detail="",
        steps=tuple(steps),
        artifacts=tuple(Artifact(p, c) for p, c in (artifacts or {}).items()),
        artifacts_truncated=False,
        advice=(),
    )


def run_argv(files: Dict[str, str]) -> List[str]:
    """The program a run call starts: the words after `exec` in its script."""
    words = shlex.split(files[ws.STATE_DIR + "/run"], posix=True)
    return words[words.index("exec") + 1 :]


class FakeSession:
    """Records every project call and every file call. A project call answers the queued
    results, else what ``on_run`` makes of a run call's program, else a completed call whose
    requested artifacts come from ``artifacts``. A file call goes to ``mem``, a tree in
    memory answered as the helper answers."""

    def __init__(self) -> None:
        self.calls: List[Tuple[Dict[str, str], List[str], List[str], Optional[float]]] = []
        self.kwargs: List[Dict[str, Any]] = []
        self.file_kwargs: List[Dict[str, Any]] = []
        self.replies: List[ProjectResult] = []
        self.artifacts: Dict[str, bytes] = {ws.STATE_DIR + "/cwd": (ROOT + "\n").encode()}
        self.on_run: Optional[Callable[[List[str]], ProjectResult]] = None
        self.mem = MemoryFiles(ROOT)
        self.work_dir = ROOT
        self.closed = False

    def run_project(self, files: Any, steps: List[str], artifacts: List[str] = (), *, timeout: Optional[float] = None, **kw: Any) -> ProjectResult:
        self.calls.append((dict(files or {}), list(steps), list(artifacts), timeout))
        self.kwargs.append(kw)
        if self.replies:
            return self.replies.pop(0)
        if self.on_run is not None and steps == [ws._RUN_STEP]:
            return self.on_run(run_argv(files))
        return result(artifacts={a: self.artifacts[a] for a in artifacts if a in self.artifacts})

    def run_files(self, op: fs.FilesOperation, **kw: Any) -> fs.FilesResult:
        self.file_kwargs.append(kw)
        return self.mem.run_files(op)

    def close(self) -> SessionSummary:
        self.closed = True
        return SessionSummary(session="fake", calls=len(self.calls), last_record_sha256="", end="closed")

    @property
    def last(self) -> Tuple[Dict[str, str], List[str], List[str], Optional[float]]:
        return self.calls[-1]

    @property
    def ops(self) -> List[fs.FilesOperation]:
        return self.mem.calls


class ExecTests(unittest.TestCase):
    def test_command_travels_as_a_file_and_the_step_is_fixed(self) -> None:
        s = FakeSession()
        s.replies.append(result(stdout=b"hi\n", artifacts={ws.STATE_DIR + "/cwd": b"/work/src\n"}))
        out = Workspace(s).exec("cd src && echo hi")
        files, steps, artifacts, timeout = s.last
        self.assertEqual(files, {ws.STATE_DIR + "/cmd": "cd src && echo hi"})
        self.assertEqual(steps, [ws._EXEC_STEP])
        self.assertNotIn("echo hi", steps[0])
        self.assertEqual(artifacts, [ws.STATE_DIR + "/cwd"])
        self.assertEqual(timeout, 120.0)
        self.assertIsInstance(out, ExecOutcome)
        self.assertEqual(out.stdout, b"hi\n")
        self.assertEqual(out.stdout_text, "hi\n")
        self.assertEqual(out.exit_code, 0)
        self.assertEqual(out.cwd, "/work/src")
        self.assertEqual(out.result.outcome, "completed")

    def test_the_exec_step_keeps_its_own_names_out_of_the_saved_environment(self) -> None:
        self.assertIn("grep -Ev '^export (PWD|OLDPWD|__plimsoll_)'", ws._EXEC_STEP)
        self.assertTrue(ws._EXEC_STEP.startswith('__plimsoll_s="$PWD/.plimsoll-shell"'))

    def test_nonzero_exit_and_timeout_are_outcomes(self) -> None:
        s = FakeSession()
        s.replies.append(result(exit_code=3, stderr=b"no\n"))
        out = Workspace(s).exec("false")
        self.assertEqual((out.exit_code, out.stderr, out.timed_out), (3, b"no\n", False))
        s.replies.append(result(exit_code=124, timed_out=True, outcome="timed_out"))
        out = Workspace(s).exec("sleep 99", timeout=1)
        self.assertTrue(out.timed_out)
        self.assertEqual(s.last[3], 1.0)

    def test_the_root_is_the_opens_and_costs_no_call(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        self.assertEqual(w.root, ROOT)
        self.assertEqual((s.calls, s.ops), ([], []))
        # A session whose open stated none is asked once, by a program: no shell text.
        s.work_dir = ""
        s.replies.append(result(stdout=b"/home/user\n"))
        w = Workspace(s)
        self.assertEqual((w.root, w.root), ("/home/user", "/home/user"))
        self.assertEqual(len(s.calls), 1)
        self.assertEqual(run_argv(s.last[0]), ["pwd"])
        s.replies.append(result(stdout=b"not a path\n"))
        with self.assertRaises(RuntimeError):
            Workspace(s).root
        s.replies.append(result(steps=[]))  # a daemon that answers no step's report
        with self.assertRaises(ws.WorkspaceCallError):
            Workspace(s).root
        self.assertEqual(s.ops, [])

    def test_a_timeout_past_the_ceiling_is_clamped(self) -> None:
        s = FakeSession()
        w = Workspace(s, timeout=10, max_timeout=30)
        w.exec("true", timeout=300)
        self.assertEqual(s.last[3], 30.0)
        s.mem.put("f", b"x")
        w.read("f")
        self.assertEqual(s.file_kwargs[-1]["timeout"], 10.0)

    def test_refusals(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        with self.assertRaises(ValueError):
            w.exec("echo \x00")
        with self.assertRaises(TypeError):
            w.exec(b"ls")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            Workspace(s, timeout=0)
        self.assertEqual(s.calls, [])

    def test_an_answer_without_a_usable_result_is_an_error_that_keeps_the_answer(self) -> None:
        # The answer was checked like any other (its tier, its record), so an adapter can
        # still state what the daemon said about the call.
        for outcome, steps, said in (("setup_failed", [], "did not run"), ("runner_failed", [], "may have run"),
                                     ("protocol_error", None, "may have run"), ("completed", [], "may have run")):
            with self.subTest(outcome=outcome):
                s = FakeSession()
                answer = result(outcome=outcome, steps=steps)
                s.replies.append(answer)
                with self.assertRaises(ws.WorkspaceCallError) as caught:
                    Workspace(s).exec("true")
                self.assertIsInstance(caught.exception, RuntimeError)
                self.assertIs(caught.exception.result, answer)
                self.assertIn(said, str(caught.exception))


class PathTests(unittest.TestCase):
    def test_resolve(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        self.assertEqual(w.resolve("a/b.txt"), "a/b.txt")
        self.assertEqual(w.resolve("./a/../b"), "b")
        self.assertEqual(w.resolve("."), ".")
        self.assertEqual(w.resolve(ROOT + "/x/y"), "x/y")
        self.assertEqual(w.resolve(ROOT), ".")
        self.assertEqual((s.calls, s.ops), ([], []))
        for bad in ("", "../x", "a/../../x", "/etc/passwd", ROOT + "x/y", "a\nb", "a\\b", "a\x01b"):
            with self.assertRaises(WorkspacePathError, msg=bad):
                w.resolve(bad)
        with self.assertRaises(WorkspacePathError):
            w.read(".")
        with self.assertRaises(WorkspacePathError):
            w.write(ws.STATE_DIR + "/cmd", "x")
        with self.assertRaises(WorkspacePathError):
            w.read(ws.STATE_DIR)
        with self.assertRaises(WorkspacePathError):
            w.remove(ws.STATE_DIR + "/env")
        self.assertEqual(s.ops, [])

    def test_a_double_slash_is_resolved_as_the_sandbox_reads_it(self) -> None:
        # Finding release-47 (candidate d): resolve("/work//etc/passwd") returned
        # "/etc/passwd", an absolute path naming another file, from the method that promises
        # one relative to the work directory; the sandbox reads it as /work/etc/passwd.
        w = Workspace(FakeSession())
        self.assertEqual(w.resolve(ROOT + "//etc/passwd"), "etc/passwd")
        self.assertEqual(w.resolve(ROOT + "/a//b"), "a/b")
        self.assertEqual(w.resolve(ROOT + "/"), ".")
        for bad in (ROOT + "//../etc", ROOT + "/a/../../etc", "//etc/passwd"):
            with self.assertRaises(WorkspacePathError, msg=bad):
                w.resolve(bad)

    def test_a_name_a_listing_returned_as_bytes_is_named_back_by_them(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        s.mem.put("caf\udce9.txt", b"latin-1 name")  # the byte 0xe9, not UTF-8
        [entry] = list(w.list())
        self.assertEqual(entry.path, b"caf\xe9.txt")
        self.assertEqual(w.read(entry.path), b"latin-1 name")
        self.assertEqual(w.read(os.fsdecode(entry.path)), b"latin-1 name")
        self.assertEqual(s.ops[-1].path, b"caf\xe9.txt")


class FileTests(unittest.TestCase):
    def test_read_is_one_file_call(self) -> None:
        s = FakeSession()
        s.mem.put("a.txt", b"hello world")
        w = Workspace(s)
        self.assertEqual(w.read("a.txt", max_bytes=5), b"hello")
        self.assertEqual(s.ops[-1], fs.FilesRead(b"a.txt", offset=0, max_bytes=5, scope="work"))
        self.assertEqual(w.read("a.txt", max_bytes=5, offset=6), b"world")
        self.assertEqual(w.read("a.txt", offset=99), b"")
        self.assertEqual(s.calls, [])
        for bad in ({"max_bytes": MAX + 1}, {"max_bytes": 0}, {"offset": -1}, {"max_bytes": True}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                w.read("a.txt", **bad)  # type: ignore[arg-type]

    def test_each_error_is_the_python_error_it_names(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        s.mem.put("dir/f", b"x")
        s.mem.put("secret", b"x")
        s.mem.unreadable.add(s.mem.abs("secret"))
        s.mem.link("out", "/etc")
        s.mem.link("inside", "dir/f")
        with self.assertRaises(FileNotFoundError) as caught:
            w.read("missing")
        self.assertEqual((caught.exception.errno, caught.exception.filename), (errno.ENOENT, "missing"))
        with self.assertRaises(IsADirectoryError):
            w.read("dir")
        with self.assertRaises(PermissionError):
            w.read("secret")
        with self.assertRaises(NotADirectoryError):
            w.read("dir/f/x")
        with self.assertRaises(WorkspacePathError):
            w.read("out/passwd")  # a link that leaves the work directory
        self.assertEqual(w.read("inside"), b"x")  # one that stays inside is followed
        for error, cls, code in (("not_regular", OSError, errno.ENXIO), ("no_space", OSError, errno.ENOSPC),
                                 ("read_only", OSError, errno.EROFS), ("too_large", OSError, errno.EFBIG),
                                 ("other", OSError, errno.EIO), ("scan_limit", WorkspaceTooLargeError, None)):
            with self.subTest(error=error):
                s.mem.fail["FilesRead"] = [files_result(error=error, errno="EIO" if error == "other" else "")]
                with self.assertRaises(cls) as caught:
                    w.read("dir/f")
                if code is not None:
                    self.assertEqual(caught.exception.errno, code)
        # An "other" error's errno is read by its name, and only a name for a number: an answer
        # naming another attribute of the errno module is EIO, an OSError still.
        for name, code in (("ENOSPC", errno.ENOSPC), ("errorcode", errno.EIO), ("__doc__", errno.EIO), ("EBOGUS", errno.EIO), ("", errno.EIO)):
            with self.subTest(errno_name=name):
                s.mem.fail["FilesRead"] = [files_result(error="other", errno=name)]
                with self.assertRaises(OSError) as caught:
                    w.read("dir/f")
                self.assertEqual((type(caught.exception), caught.exception.errno), (OSError, code))

    def test_a_call_that_timed_out_or_got_no_answer_is_an_error_and_is_not_repeated(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        s.mem.fail["FilesWrite"] = [files_result(outcome="timed_out")]
        with self.assertRaises(TimeoutError):
            w.write("f", b"x")
        self.assertEqual(len(s.ops), 1)
        for outcome in ("runner_failed", "protocol_error"):
            answer = files_result(outcome=outcome)
            s.mem.fail["FilesWrite"] = [answer]
            with self.subTest(outcome=outcome), self.assertRaises(ws.WorkspaceCallError) as caught:
                w.write("f", b"x")
            self.assertIs(caught.exception.result, answer)
            self.assertIn("may have run", str(caught.exception))
        self.assertEqual(len(s.ops), 3)
        self.assertIsNone(s.mem.get("f"))

    def test_write_is_one_replace_that_makes_the_folders(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        w.write("src/x.py", "print('é')\n")
        self.assertEqual(s.ops, [fs.FilesWrite(b"src/x.py", "print('é')\n".encode(), mode="replace", make_parents=True, scope="work")])
        self.assertEqual(s.mem.get("src/x.py"), "print('é')\n".encode())
        w.write("nul", "a\x00b")  # text with a NUL is bytes like any other now
        self.assertEqual(s.mem.get("nul"), b"a\x00b")
        w.write("empty", b"")
        self.assertEqual(s.mem.get("empty"), b"")
        self.assertEqual(s.calls, [])
        with self.assertRaises(TypeError):
            w.write("x", 3)  # type: ignore[arg-type]

    def test_a_write_past_4_mib_is_a_replace_then_appends(self) -> None:
        s = FakeSession()
        data = bytes(range(256)) * ((2 * ws.MAX_WRITE_BYTES + 5) // 256 + 1)  # three pieces
        Workspace(s).write("blob.bin", data)
        self.assertEqual([(o.mode, o.make_parents) for o in s.ops], [("replace", True), ("append", False), ("append", False)])
        self.assertTrue(all(len(o.content) <= ws.MAX_WRITE_BYTES for o in s.ops))
        self.assertEqual(b"".join(o.content for o in s.ops), data)
        self.assertEqual(s.mem.get("blob.bin"), data)

    def test_a_write_that_fails_partway_leaves_its_first_pieces_and_sends_nothing_after(self) -> None:
        s = FakeSession()
        data = b"a" * ws.MAX_WRITE_BYTES + b"b" * ws.MAX_WRITE_BYTES + b"c"
        real = s.mem.run_files
        sent: List[fs.FilesWrite] = []

        def second_fails(op, **kw):
            sent.append(op)
            if len(sent) == 2:
                return files_result(error="no_space", errno="ENOSPC")
            return real(op)

        s.mem.run_files = second_fails  # type: ignore[method-assign]
        with self.assertRaises(OSError) as caught:
            Workspace(s).write("blob", data)
        self.assertEqual(caught.exception.errno, errno.ENOSPC)
        self.assertEqual(len(sent), 2)  # the third piece is not sent
        self.assertEqual(s.mem.get("blob"), b"a" * ws.MAX_WRITE_BYTES)

    def test_a_write_answered_with_another_count_is_an_error(self) -> None:
        s = FakeSession()
        s.mem.fail["FilesWrite"] = [files_result("write", fs.FilesWriteAnswer(written=1))]
        with self.assertRaises(OSError):
            Workspace(s).write("f", b"xyz")

    def test_edit(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        s.mem.put("f", b"a b a")
        with self.assertRaises(ValueError):
            w.edit("f", "a", "c")
        self.assertEqual(w.edit("f", "a", "c", replace_all=True), 2)
        self.assertEqual(s.mem.get("f"), b"c b c")
        self.assertEqual(w.edit("f", "b", "d"), 1)
        self.assertEqual(s.mem.get("f"), b"c d c")
        with self.assertRaises(ValueError):
            w.edit("f", "z", "d")
        s.mem.put("bin", b"\xff\xfe")
        with self.assertRaises(ValueError):
            w.edit("bin", "a", "b")
        with self.assertRaises(ValueError):
            w.edit("f", "", "b")
        # A file past one read is refused, not cut to its first 8 MiB and written back.
        s.mem.fail["FilesRead"] = [files_result("read", fs.FilesReadAnswer(content=b"a" * MAX, size_at_open=MAX + 1))]
        with self.assertRaises(WorkspaceTooLargeError):
            w.edit("f", "a", "b")
        self.assertEqual(s.mem.get("f"), b"c d c")

    def test_stat_list_read_many_make_dir_remove_rename(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        s.mem.put("d/a.txt", b"aa")
        s.mem.put("d/e/b.txt", b"b")
        s.mem.link("d/l", "a.txt")
        st = w.stat("d/a.txt")
        self.assertEqual((st.type, st.size), ("file", 2))
        self.assertEqual(w.stat(".").type, "dir")
        self.assertEqual(w.stat("d/l").type, "link")
        self.assertEqual([(e.path, e.type) for e in w.list("d")], [(b"a.txt", "file"), (b"e", "dir"), (b"l", "link")])
        self.assertEqual([e.path for e in w.list("d", recursive=True)], [b"a.txt", b"e", b"e/b.txt", b"l"])
        self.assertEqual([e.path for e in w.list("d", recursive=True, match="**/*.txt")], [b"a.txt", b"e/b.txt"])
        items = w.read_many(["d/a.txt", "nope", "d/e/b.txt"])
        self.assertEqual([(i.error, i.content) for i in items], [("none", b"aa"), ("not_found", b""), ("none", b"b")])
        w.make_dir("n/m", parents=True)
        self.assertEqual(w.stat("n/m").type, "dir")
        with self.assertRaises(FileExistsError):
            w.make_dir("d/a.txt")
        w.rename("d/a.txt", "d/c.txt")
        self.assertEqual(s.mem.get("d/c.txt"), b"aa")
        with self.assertRaises(FileExistsError):
            w.rename("d/c.txt", "d/e/b.txt")
        w.rename("d/c.txt", "d/e/b.txt", replace=True)
        w.remove("d/l")
        self.assertIsNone(s.mem.links.get(s.mem.abs("d/l")))
        with self.assertRaises(IsADirectoryError):
            w.remove("n/m")
        w.remove("n/m", dir=True)
        with self.assertRaises(OSError) as caught:
            w.remove("d", dir=True)
        self.assertEqual(caught.exception.errno, errno.ENOTEMPTY)
        with self.assertRaises(FileNotFoundError):
            list(w.list("nope"))
        self.assertEqual(s.calls, [])

    def test_a_listing_is_read_page_by_page_and_leaves_the_state_out(self) -> None:
        s = FakeSession()
        s.mem.page = 2
        for n in ("a", "b", "c", "d", "e"):
            s.mem.put(n)
        s.mem.put(ws.STATE_DIR + "/cmd")
        self.assertEqual([e.path for e in Workspace(s).list(recursive=True)], [b"a", b"b", b"c", b"d", b"e"])
        lists = [o for o in s.ops if isinstance(o, fs.FilesList)]
        self.assertEqual([o.after for o in lists], [b"", b".plimsoll-shell/cmd", b"b", b"d"])

    def test_a_listing_page_with_more_and_no_entry_is_a_call_error(self) -> None:
        # Such a page names no cursor to ask again from: the workspace's own error, never an
        # IndexError reading the last entry of none (the pre-scan clients review, 2026-11-27).
        s = FakeSession()
        s.mem.fail["FilesList"] = [files_result("list", fs.FilesListAnswer(entries=(), more=True))]
        with self.assertRaises(ws.WorkspaceCallError):
            list(Workspace(s).list())

    def test_read_many_asks_again_for_what_did_not_fit(self) -> None:
        s = FakeSession()
        s.mem.page = 2
        for n in "abcde":
            s.mem.put(n, n.encode())
        items = Workspace(s).read_many(list("abcde"))
        self.assertEqual([i.content for i in items], [b"a", b"b", b"c", b"d", b"e"])
        self.assertEqual([len(o.paths) for o in s.ops], [5, 3, 1])
        self.assertEqual(Workspace(s).read_many([]), [])
        s.mem.fail["FilesReadMany"] = [files_result("read_many", fs.FilesReadManyAnswer(items=(), more=True))]
        with self.assertRaises(ws.WorkspaceCallError):
            Workspace(s).read_many(["a"])

    def test_read_many_keeps_each_call_inside_the_daemons_request_cap(self) -> None:
        # A call names at most 16,384 paths (the helper's cap) and 4 MiB of their bytes: paths
        # travel in base64 under the daemon's 8 MiB request cap, so 16,384 long paths in one
        # call would be refused.
        s = FakeSession()
        s.mem.page = 1 << 20  # every page whole: the bounds alone split the calls
        names = [f"f{i}" for i in range(ws._READ_MANY_PATHS + 1)]
        s.mem.put(names[-1], b"last")
        items = Workspace(s).read_many(names)
        self.assertEqual([len(o.paths) for o in s.ops], [ws._READ_MANY_PATHS, 1])
        self.assertEqual((len(items), items[-1].content, items[0].error), (len(names), b"last", "not_found"))

        s = FakeSession()
        s.mem.page = 1 << 20
        long = ["d" * 3000 + f"/{i:05}" for i in range(1500)]
        s.mem.put(long[-1], b"end")
        items = Workspace(s).read_many(long)
        counts = [len(o.paths) for o in s.ops]
        self.assertEqual(sum(counts), len(long))
        self.assertGreater(len(counts), 1)
        for o in s.ops:
            sent = sum(len(fs.path_bytes(p)) for p in o.paths)
            self.assertLessEqual(sent, ws._READ_MANY_PATH_BYTES)
            if o is not s.ops[-1]:
                self.assertGreater(sent + len(long[0]), ws._READ_MANY_PATH_BYTES)  # filled, not cut early
        self.assertEqual(items[-1].content, b"end")


class WholeReadTests(unittest.TestCase):
    """read_pieces and read_whole: a file of any size, never a cut or spliced copy."""

    def piece(self, content: bytes, size: int) -> fs.FilesResult:
        return files_result("read", fs.FilesReadAnswer(content=content, size_at_open=size))

    def test_a_file_of_one_piece_is_one_call(self) -> None:
        s = FakeSession()
        s.mem.put("f.txt", b"small")
        self.assertEqual(Workspace(s).read_whole("f.txt"), b"small")
        self.assertEqual(len(s.ops), 1)
        s.mem.put("empty", b"")
        self.assertEqual(list(Workspace(s).read_pieces("empty")), [])
        s.mem.put("exact", b"a" * MAX)
        self.assertEqual(len(Workspace(s).read_whole("exact")), MAX)
        self.assertEqual(len(s.ops), 3)  # one each: the size the read states says it is whole

    def test_a_longer_file_is_read_in_pieces_by_the_size_its_first_read_states(self) -> None:
        s = FakeSession()
        data = b"a" * MAX + b"bcd"
        s.mem.put("-f.bin", data)  # a dash-led name is just a name (finding release-42)
        self.assertEqual(list(Workspace(s).read_pieces("-f.bin")), [b"a" * MAX, b"bcd"])
        self.assertEqual([(o.offset, o.max_bytes) for o in s.ops], [(0, MAX), (MAX, 3)])
        self.assertEqual(s.calls, [])  # no size call: each read states it

    def test_a_file_longer_than_the_limit_is_refused_on_its_first_answer(self) -> None:
        # Finding release-46: a whole read had no limit, and a sandbox can make a file of
        # any size for nothing (a sparse one), so the caller's process held all of it.
        s = FakeSession()
        s.mem.fail["FilesRead"] = [self.piece(b"a" * MAX, ws.MAX_WHOLE_BYTES + 1)]
        pieces = Workspace(s).read_pieces("f.bin")
        with self.assertRaises(WorkspaceTooLargeError) as caught:
            next(pieces)  # refused before anything is yielded
        self.assertIn(str(ws.MAX_WHOLE_BYTES + 1), str(caught.exception))
        self.assertEqual(len(s.ops), 1)
        s.mem.put("f.txt", b"abc")
        with self.assertRaises(WorkspaceTooLargeError):
            Workspace(s).read_whole("f.txt", limit=2)
        for bad in (-1, 1.5, True, "8"):
            with self.subTest(limit=bad), self.assertRaises(ValueError):
                Workspace(FakeSession()).read_whole("f.txt", limit=bad)  # type: ignore[arg-type]

    def test_the_limit_is_the_callers_to_lift(self) -> None:
        s = FakeSession()
        big = ws.MAX_WHOLE_BYTES + 1
        s.mem.fail["FilesRead"] = [self.piece(b"a" * MAX, big), self.piece(b"b", big)]
        pieces = Workspace(s).read_pieces("f.bin", limit=None)
        self.assertEqual(next(pieces), b"a" * MAX)
        self.assertEqual(next(pieces), b"b")  # read on, past 64 MiB, as asked
        pieces.close()

    def test_a_head_of_any_length_is_read_in_pieces_and_checked(self) -> None:
        s = FakeSession()
        s.mem.put("f.bin", b"a" * MAX + b"bcdefg")
        self.assertEqual(Workspace(s).read_head("f.bin", MAX + 3), b"a" * MAX + b"bcd")
        self.assertEqual(s.ops[-1].max_bytes, 3)  # exactly what the head still needs
        s.mem.put("f.txt", b"abc")
        self.assertEqual(Workspace(s).read_head("f.txt", 2), b"ab")
        self.assertEqual(s.ops[-1].max_bytes, 2)
        s.mem.fail["FilesRead"] = [self.piece(b"a" * MAX, MAX + 100), self.piece(b"", MAX + 100)]
        with self.assertRaises(ws.WorkspaceChangedError):
            Workspace(s).read_head("f.bin", MAX + 3)  # shrank between its pieces
        with self.assertRaises(ValueError):
            Workspace(FakeSession()).read_head("f.txt", 0)
        # A sparse file past the whole-read limit: a head of it reads only the head.
        s.mem.fail["FilesRead"] = [self.piece(b"\0" * MAX, ws.MAX_WHOLE_BYTES + 1), self.piece(b"\0" * 3, ws.MAX_WHOLE_BYTES + 1)]
        self.assertEqual(Workspace(s).read_head("sparse", MAX + 3), bytes(MAX + 3))

    def test_a_file_that_changed_while_read_is_an_error(self) -> None:
        size = MAX + 3
        for name, rest in (("grew between pieces", [self.piece(b"bcd", size + 5)]),
                           ("shrank", [self.piece(b"", size - 2)]),
                           ("cut", [self.piece(b"", size)]),
                           ("removed", [files_result(error="not_found", errno="ENOENT")])):
            s = FakeSession()
            s.mem.fail["FilesRead"] = [self.piece(b"a" * MAX, size)] + rest
            with self.subTest(change=name), self.assertRaises(ws.WorkspaceChangedError) as caught:
                Workspace(s).read_whole("f.bin")
            self.assertIsInstance(caught.exception, OSError)
            self.assertIn("changed while it was read", str(caught.exception))
        # More bytes than its own open counted: it grew while the one read was made.
        s = FakeSession()
        s.mem.fail["FilesRead"] = [self.piece(b"abcdef", 3)]
        with self.assertRaises(ws.WorkspaceChangedError):
            list(Workspace(s).read_pieces("f"))

    def test_a_kernel_file_that_states_size_zero_is_read_to_its_end(self) -> None:
        # The helper reads such a file to its end whatever its open states (file contract 6),
        # as procfs answers /proc/self/status: size 0, content all the same.
        status = b"Name:\tplimsoll-helpe\nUid:\t1000\t1000\t1000\t1000\n"
        s = FakeSession()
        s.mem.fail["FilesRead"] = [self.piece(status, 0)]
        self.assertEqual(Workspace(s).read_whole("status"), status)
        self.assertEqual(len(s.ops), 1)  # a short piece is the end
        # One longer than a call: read on from where it got until a piece comes back short.
        s = FakeSession()
        s.mem.fail["FilesRead"] = [self.piece(b"a" * MAX, 0), self.piece(b"bc", 0)]
        self.assertEqual(list(Workspace(s).read_pieces("k")), [b"a" * MAX, b"bc"])
        self.assertEqual([(o.offset, o.max_bytes) for o in s.ops], [(0, MAX), (MAX, MAX)])
        # Exactly one call long: the next piece is empty, and that is the end.
        s = FakeSession()
        s.mem.fail["FilesRead"] = [self.piece(b"a" * MAX, 0), self.piece(b"", 0)]
        self.assertEqual(Workspace(s).read_whole("k"), b"a" * MAX)
        # A head stops at its length.
        s = FakeSession()
        s.mem.fail["FilesRead"] = [self.piece(b"abc", 0)]
        self.assertEqual(Workspace(s).read_head("k", 3), b"abc")
        self.assertEqual(len(s.ops), 1)
        # The limit holds as the bytes arrive.
        s = FakeSession()
        s.mem.fail["FilesRead"] = [self.piece(b"abcdef", 0)]
        with self.assertRaises(WorkspaceTooLargeError):
            Workspace(s).read_whole("k", limit=5)
        # A later piece whose open states a size: the file changed.
        for rest in ([self.piece(b"x", 7)], [files_result(error="not_found", errno="ENOENT")]):
            s = FakeSession()
            s.mem.fail["FilesRead"] = [self.piece(b"a" * MAX, 0)] + rest
            with self.subTest(rest=rest), self.assertRaises(ws.WorkspaceChangedError):
                Workspace(s).read_whole("k")

    def test_a_missing_file_and_a_folder_are_their_errors(self) -> None:
        s = FakeSession()
        with self.assertRaises(FileNotFoundError):
            Workspace(s).read_whole("nope")
        s.mem.put("d/x")
        with self.assertRaises(IsADirectoryError):
            Workspace(s).read_whole("d")


class GlobTests(unittest.TestCase):
    def tree(self) -> FakeSession:
        s = FakeSession()
        for p in ("a.py", "b.py", ".env.py", "my file1.txt", "my", "src/x/a.ts", "src/x/y/b.ts", "src/lib.py",
                  ws.STATE_DIR + "/cmd", ws.STATE_DIR + "/x.py"):
            s.mem.put(p)
        s.mem.link("link.py", "/etc/passwd")
        return s

    def test_the_helper_matches_and_a_dot_is_not_special(self) -> None:
        s = self.tree()
        w = Workspace(s)
        self.assertEqual(w.glob("*.py"), [".env.py", "a.py", "b.py", "link.py"])
        self.assertEqual(s.ops[-1], fs.FilesList(b".", recursive=False, match=b"*.py", after=b"", budget_bytes=1 << 20, scope="work"))
        self.assertEqual(w.glob("my file*.txt"), ["my file1.txt"])  # one pattern, a space and all (release-41)
        self.assertEqual(w.glob("**/*.ts", "src"), ["x/a.ts", "x/y/b.ts"])
        self.assertTrue(s.ops[-1].recursive)
        self.assertEqual(w.glob("**/b.ts"), ["src/x/y/b.ts"])
        self.assertEqual(w.glob("*.nothing"), [])
        self.assertEqual(w.glob("./*.py"), w.glob("*.py"))  # `./x` is `x`, as a shell reads it
        self.assertEqual(w.glob("src/./*.py"), ["src/lib.py"])
        self.assertEqual(s.calls, [])

    def test_a_literal_lead_lists_from_that_folder(self) -> None:
        s = self.tree()
        w = Workspace(s)
        self.assertEqual(w.glob("src/*.py"), ["src/lib.py"])
        self.assertEqual((s.ops[-1].path, s.ops[-1].match, s.ops[-1].recursive), (b"src", b"*.py", False))
        self.assertEqual(w.glob("src/x/**"), ["src/x/a.ts", "src/x/y", "src/x/y/b.ts"])
        self.assertEqual(w.glob("lib/**", "src"), [])  # a folder the pattern names is not there
        self.assertEqual(w.glob("a.py/*"), [])  # nor one that is a file
        self.assertEqual(w.glob(ws.STATE_DIR + "/*"), [])

    def test_sorted_by_bytes_and_cut_to_the_limit_across_pages(self) -> None:
        s = FakeSession()
        s.mem.page = 7
        names = [f"d{i:03d}/f.txt" for i in range(ws.GLOB_LIMIT + 50)] + ["a.txt", "a-b.txt"]
        for n in names:
            s.mem.put(n)
        got = Workspace(s).glob("**/*.txt")
        self.assertEqual(got, sorted(names, key=lambda n: n.encode())[: ws.GLOB_LIMIT])
        self.assertEqual(got[:2], ["a-b.txt", "a.txt"])  # by bytes, across folders: not depth first

    def test_refusals(self) -> None:
        s = self.tree()
        w = Workspace(s)
        with self.assertRaises(FileNotFoundError):
            w.glob("*", "missing")
        with self.assertRaises(FileNotFoundError):
            w.glob("x/*", "missing")
        for bad in ("/etc/*", "../*", "a\nb", "", ".", "./"):
            with self.assertRaises(ValueError, msg=bad):
                w.glob(bad)
        for bad in ("a**", "[abc", "x\\"):
            with self.subTest(pattern=bad), self.assertRaises(ValueError):
                w.glob(bad)  # the daemon refuses it as the helper would read it, before the call

    def test_the_fakes_glob_is_the_helpers(self) -> None:
        # The fake every adapter test leans on matches by the helper's own vectors.
        with open(os.path.join(HERE, "..", "..", "..", "sandbox", "internal", "nativehelper", "testdata", "glob-vectors.json")) as f:
            cases = json.load(f)["cases"]
        for c in cases:
            pattern = c["pattern"].encode()
            with self.subTest(pattern=c["pattern"]):
                if c.get("invalid"):
                    self.assertTrue(glob_refused(pattern))
                    continue
                for p in c.get("match", []):
                    self.assertTrue(glob_match(pattern, p.encode()), p)
                for p in c.get("no_match", []):
                    self.assertFalse(glob_match(pattern, p.encode()), p)


class GrepTests(unittest.TestCase):
    def test_grep_is_one_program_with_an_argument_list(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        s.replies.append(result(stdout=b"./a.py:1:import os\n./.plimsoll-shell/cmd:1:import os\n"))
        self.assertEqual(w.grep("import"), "a.py:1:import os")
        self.assertEqual(s.last[1], [ws._RUN_STEP])
        self.assertEqual(run_argv(s.last[0]), ["grep", "-rnHE", "-e", "import", "--", "."])
        s.replies.append(result(exit_code=1))
        self.assertEqual(w.grep("nothing", "src"), "")
        self.assertEqual(run_argv(s.last[0])[-1], "src")
        s.replies.append(result(exit_code=2, stderr=b"grep: bad regex\n"))
        with self.assertRaises(ValueError):
            w.grep("(")
        s.replies.append(result(stdout=b"a:1:x\n", stdout_truncated=True))
        self.assertEqual(w.grep("x"), "a:1:x\n[output truncated]")
        with self.assertRaises(ValueError):
            w.grep("")
        s.replies.append(result(exit_code=124, timed_out=True, outcome="timed_out"))
        with self.assertRaises(TimeoutError):
            w.grep("x")

    def test_a_file_name_with_a_digit_int_refuses_still_sorts(self) -> None:
        # Finding release-47: "²".isdigit() is true and int("²") raises, so a file the
        # sandbox named `x:²:y` made grep raise ValueError, which adapters read as a bad pattern.
        s = FakeSession()
        s.replies.append(result(stdout="./x:\u00b2:y:3:hit\n./a.py:2:hit\n./a.py:1:hit\n".encode()))
        self.assertEqual(Workspace(s).grep("hit"), "a.py:1:hit\na.py:2:hit\nx:\u00b2:y:3:hit")


class TreeTests(unittest.TestCase):
    def tar_session(self, archive: bytes = b"TAR", exit_code: int = 0) -> FakeSession:
        s = FakeSession()
        s.ran = []  # type: ignore[attr-defined]

        def on_run(argv: List[str]) -> ProjectResult:
            s.ran.append(argv)  # type: ignore[attr-defined]
            if argv[:2] == ["tar", "-cf"] and exit_code == 0:
                s.mem.put(argv[2], archive)
            return result(exit_code=exit_code, stderr=b"tar: failed\n" if exit_code else b"")

        s.on_run = on_run
        return s

    def test_persist_tars_in_the_sandbox_and_reads_the_archive_by_file_calls(self) -> None:
        archive = bytes(range(256)) * ((MAX + 1000) // 256)  # past 8 MiB: two reads
        s = self.tar_session(archive)
        self.assertEqual(Workspace(s).persist(), archive)
        [argv] = s.ran  # type: ignore[attr-defined]
        name = argv[2]
        self.assertTrue(name.startswith(ws.STATE_DIR + "/persist-") and name.endswith(".tar"), name)
        self.assertEqual(argv, ["tar", "-cf", name, "--exclude=./.plimsoll-shell", "--exclude=./.plimsoll-shell/*", "-C", ".", "."])
        reads = [o for o in s.ops if isinstance(o, fs.FilesRead)]
        self.assertEqual([(o.path, o.offset) for o in reads], [(name.encode(), 0), (name.encode(), MAX)])
        self.assertEqual(s.ops[-1], fs.FilesRemove(name.encode(), scope="work"))
        self.assertIsNone(s.mem.get(name))

    def test_persist_past_its_limit_or_a_failed_tar_is_an_error_and_the_archive_is_removed(self) -> None:
        s = self.tar_session(b"x" * 10)
        with self.assertRaises(WorkspaceTooLargeError):
            Workspace(s).persist(limit=5)
        self.assertIsInstance(s.ops[-1], fs.FilesRemove)
        self.assertEqual([p for p in s.mem.files if b"persist-" in p], [])
        s = self.tar_session(exit_code=1)
        with self.assertRaises(RuntimeError):
            Workspace(s).persist()
        self.assertIsInstance(s.ops[-1], fs.FilesRemove)  # tidied, though nothing was made

    def test_hydrate_writes_the_archive_by_file_calls_then_extracts_it(self) -> None:
        s = self.tar_session()
        data = b"T" * (ws.MAX_WRITE_BYTES + 1)
        Workspace(s).hydrate(data)
        writes = [o for o in s.ops if isinstance(o, fs.FilesWrite)]
        name = writes[0].path.decode()
        self.assertTrue(name.startswith(ws.STATE_DIR + "/hydrate-"), name)
        self.assertEqual([w.mode for w in writes], ["create_only", "append"])
        self.assertEqual(s.ran, [["tar", "-xf", name, "-C", "."]])  # type: ignore[attr-defined]
        self.assertEqual(s.ops[-1], fs.FilesRemove(name.encode(), scope="work"))
        with self.assertRaises(TypeError):
            Workspace(s).hydrate("TAR")  # type: ignore[arg-type]
        s = self.tar_session(exit_code=2)
        with self.assertRaises(RuntimeError):
            Workspace(s).hydrate(b"TAR")
        self.assertIsInstance(s.ops[-1], fs.FilesRemove)

    def cancelling_session(self, archive: bytes, after: type) -> Tuple[FakeSession, CancelHandle]:
        """A tar session whose calls refuse a cancelled handle as the client does (not
        dispatched, nothing sent), and whose handle is cancelled once the first file call of
        kind ``after`` has been answered."""
        s = self.tar_session(archive)
        handle = CancelHandle()
        answer = s.run_files

        def run_files(op: fs.FilesOperation, **kw: Any) -> fs.FilesResult:
            c = kw.get("cancel")
            if c is not None and c.cancelled:
                s.file_kwargs.append(kw)
                raise RequestCanceledError("plimsoll: the request was canceled before it was sent", not_dispatched="request")
            out = answer(op, **kw)
            if isinstance(op, after):
                handle.cancel()
            return out

        s.run_files = run_files  # type: ignore[method-assign]
        return s, handle

    def test_a_persist_or_hydrate_cut_by_its_cancel_handle_still_removes_its_archive(self) -> None:
        # release-128: the tidy's remove went with the same, already cancelled handle, so it
        # was refused before it was sent and the archive stayed in the work folder.
        s, handle = self.cancelling_session(b"x" * (MAX + 10), fs.FilesRead)  # two reads
        with self.assertRaises(RequestCanceledError):
            Workspace(s).persist(cancel=handle)
        self.assertEqual([p for p in s.mem.files if b"persist-" in p], [])
        self.assertIsInstance(s.ops[-1], fs.FilesRemove)
        self.assertIsNone(s.file_kwargs[-1].get("cancel"))
        s, handle = self.cancelling_session(b"", fs.FilesWrite)
        with self.assertRaises(RequestCanceledError):
            Workspace(s).hydrate(b"T" * (ws.MAX_WRITE_BYTES + 1), cancel=handle)  # two writes
        self.assertEqual([p for p in s.mem.files if b"hydrate-" in p], [])
        self.assertIsInstance(s.ops[-1], fs.FilesRemove)
        self.assertEqual(s.ran, [])  # type: ignore[attr-defined]  # the tar was never started

    def test_a_persist_or_hydrate_out_of_room_in_the_work_folder_is_a_size_error(self) -> None:
        # release-129: the archive is staged in the work folder, so a tree past about half
        # of it cannot be saved or restored; that is a size error naming the cause, not tar's
        # words in a RuntimeError.
        s = FakeSession()
        s.on_run = lambda argv: result(exit_code=2, stderr=b"tar: write error: No space left on device\n")
        with self.assertRaises(WorkspaceTooLargeError) as e:
            Workspace(s).persist()
        self.assertIn("work folder", str(e.exception))
        self.assertIsInstance(s.ops[-1], fs.FilesRemove)
        with self.assertRaises(WorkspaceTooLargeError) as e:
            Workspace(s).hydrate(b"TAR")
        self.assertIn("work folder", str(e.exception))
        # The archive's own write meets a full work folder: the helper's no_space answer.
        s = FakeSession()
        real = s.mem.run_files

        def full(op: fs.FilesOperation) -> fs.FilesResult:
            if isinstance(op, fs.FilesWrite):
                return files_result("write", error="no_space", errno="ENOSPC")
            return real(op)

        s.mem.run_files = full  # type: ignore[method-assign]
        with self.assertRaises(WorkspaceTooLargeError) as e:
            Workspace(s).hydrate(b"TAR")
        self.assertIsInstance(e.exception.__cause__, OSError)
        # Any other failure of tar stays tar's own words.
        s = FakeSession()
        s.on_run = lambda argv: result(exit_code=2, stderr=b"tar: This does not look like a tar archive\n")
        with self.assertRaises(RuntimeError) as e:
            Workspace(s).hydrate(b"TAR")
        self.assertNotIsInstance(e.exception, WorkspaceTooLargeError)


class NoProjectCallTests(unittest.TestCase):
    """D87 B: every file method goes through the session's file calls, with no shell text."""

    def test_no_file_method_sends_a_project_call_or_a_snippet(self) -> None:
        class Spy(FakeSession):
            def run_project(self, *a: Any, **kw: Any) -> ProjectResult:
                raise AssertionError("a file method sent a project call")

            def run_javascript(self, *a: Any, **kw: Any) -> Any:
                raise AssertionError("a file method sent a snippet")

            def run_cell(self, *a: Any, **kw: Any) -> Any:
                raise AssertionError("a file method sent a cell")

        for confined in (True, False):
            s = Spy()
            s.mem.put("x.txt", b"a b")
            s.mem.put("big", b"z" * (MAX + 1))
            w = Workspace(s, confined=confined)
            w.root
            w.read("x.txt")
            w.read("x.txt", offset=1)
            w.read_whole("big")
            list(w.read_pieces("big"))
            w.read_head("big", MAX + 1)
            w.write("y.txt", "text")
            w.write("z.bin", b"z" * (ws.MAX_WRITE_BYTES + 1))
            w.edit("x.txt", "a", "c")
            w.glob("*.txt")
            w.glob("**/*.bin")
            w.stat("x.txt")
            list(w.list(recursive=True))
            w.read_many(["x.txt", "y.txt"])
            w.make_dir("d")
            w.rename("y.txt", "d/y.txt")
            w.remove("d/y.txt")
            if not confined:
                s.mem.put("/tmp/out.txt", b"o")
                self.assertEqual(w.read("/tmp/out.txt"), b"o")
            self.assertGreater(len(s.ops), 15)
            self.assertEqual(s.calls, [])


class ShellSession:
    """A session whose project calls run the workspace's fixed steps under this machine's
    sh (dash here), in a work directory of its own: the command steps' shell behavior,
    proved with no daemon. docker_workspace_check.py proves them on the images' BusyBox."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.work_dir = root

    def run_project(self, files: Any, steps: List[str], artifacts: List[str] = (), *, timeout: Optional[float] = None, **kw: Any) -> ProjectResult:
        for name, content in (files or {}).items():
            p = os.path.join(self.root, name)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(content.encode("utf-8") if isinstance(content, str) else content)
        ran = []
        for step in steps:
            r = subprocess.run(["sh", "-c", step], cwd=self.root, capture_output=True, timeout=60,
                               env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
            ran.append(StepResult(command=step, stdout=r.stdout, stderr=r.stderr, exit_code=r.returncode, timed_out=False, duration_ms=1,
                                  stdout_truncated=False, stderr_truncated=False))
            if r.returncode != 0:
                break
        found = {}
        for a in artifacts:
            p = os.path.join(self.root, a)
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    found[a] = f.read()
        return result(steps=ran, artifacts=found)


class ShellStepTests(unittest.TestCase):
    """The command steps on a real shell: what a fake session cannot show."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._dir.name)
        self.w = Workspace(ShellSession(self.root))

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_grep_takes_its_pattern_and_path_as_given(self) -> None:
        with open(os.path.join(self.root, "-dash.txt"), "w") as f:
            f.write("one $(id) two\nthree\n")
        self.assertEqual(self.w.grep("\\$\\(id\\) two", "-dash.txt"), "-dash.txt:1:one $(id) two")
        self.assertEqual(self.w.grep("three"), "-dash.txt:2:three")
        self.assertEqual(self.w.grep("absent"), "")

    def test_exec_keeps_its_directory_and_exports(self) -> None:
        os.makedirs(os.path.join(self.root, "a"))
        self.w.exec("cd a && export X=1")
        out = self.w.exec("pwd; echo $X")
        self.assertEqual(out.stdout_text.split("\n")[:2], [self.root + "/a", "1"])
        self.assertEqual(out.cwd, self.root + "/a")


class RunTests(unittest.TestCase):
    def test_argv_env_and_stdin_travel_as_files_and_the_step_is_fixed(self) -> None:
        s = FakeSession()
        s.replies.append(result(stdout=b"out", exit_code=3))
        argv = ["printf", "%s\n", "a b", "it's", "$(id)", "`id`", "line\nbreak", "ünï", "*"]
        out = Workspace(s).run(argv, env={"GREETING": "hi 'there'\n", "PATH": "/bin"}, stdin=b"\x00\xffin")
        files, steps, artifacts, timeout = s.last
        self.assertEqual(steps, [ws._RUN_STEP])
        self.assertEqual(set(files), {ws.STATE_DIR + "/run", ws.STATE_DIR + "/in.b64"})
        self.assertEqual(base64.b64decode(files[ws.STATE_DIR + "/in.b64"]), b"\x00\xffin")
        words = shlex.split(files[ws.STATE_DIR + "/run"], posix=True)
        self.assertEqual(words, ["export", "GREETING=hi 'there'\n", "export", "PATH=/bin", "exec", *argv])
        self.assertEqual(artifacts, [])
        self.assertEqual(timeout, 120.0)
        self.assertEqual((out.exit_code, out.stdout, out.cwd), (3, b"out", ROOT))

    def test_no_stdin_is_an_empty_one_and_the_shell_state_is_untouched(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        w.run(["cat"])
        files = s.last[0]
        self.assertEqual(files[ws.STATE_DIR + "/in.b64"], "")
        self.assertNotIn(ws.STATE_DIR + "/cmd", files)
        self.assertNotIn(ws.STATE_DIR + "/env", ws._RUN_STEP)
        self.assertNotIn(ws.STATE_DIR + "/cwd", ws._RUN_STEP)
        self.assertIn('exec < "$__plimsoll_s/in"', ws._RUN_STEP)
        # The script (the environment's values) and the stdin copy are gone before the
        # program starts, so nothing a later call runs can read them.
        self.assertLess(ws._RUN_STEP.index("rm -f"), ws._RUN_STEP.index('eval "$__plimsoll_r"'))
        for name in ("in", "in.b64", "run"):
            self.assertIn(f'"$__plimsoll_s/{name}"', ws._RUN_STEP.split("rm -f", 1)[1])

    def test_a_timeout_is_an_outcome(self) -> None:
        s = FakeSession()
        s.replies.append(result(exit_code=124, timed_out=True, outcome="timed_out"))
        out = Workspace(s).run(["sleep", "99"], timeout=1)
        self.assertTrue(out.timed_out)
        self.assertEqual(s.last[3], 1.0)

    def test_refusals(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        for argv in ([], "ls", b"ls", ["a\x00b"], [1], ["-c", "id"], ["--", "id"]):
            with self.assertRaises((ValueError, TypeError), msg=repr(argv)):
                w.run(argv)  # type: ignore[arg-type]
        for name in ("", "1A", "A B", "A=B", "A-B", "é"):
            with self.assertRaises(ValueError, msg=name):
                w.run(["true"], env={name: "x"})
        with self.assertRaises(ValueError):
            w.run(["true"], env={"A": "x\x00"})
        with self.assertRaises(TypeError):
            w.run(["true"], stdin=3)  # type: ignore[arg-type]
        with self.assertRaises(WorkspaceTooLargeError):
            w.run(["cat"], stdin=b"x" * (4 << 20))
        self.assertEqual(s.calls, [])

    def test_a_cancel_handle_reaches_every_call(self) -> None:
        s = FakeSession()
        w = Workspace(s, confined=False)
        handle = object()
        w.run(["true"], cancel=handle)  # type: ignore[arg-type]
        s.mem.put("a", b"x")
        w.read("a", cancel=handle)  # type: ignore[arg-type]
        w.write("a", "text", cancel=handle)  # type: ignore[arg-type]
        w.write("/tmp/b", b"x" * (ws.MAX_WRITE_BYTES + 1), cancel=handle)  # type: ignore[arg-type]
        self.assertEqual([k.get("cancel") for k in s.kwargs], [handle])
        # read, write, and the two pieces of the bytes
        self.assertEqual([k.get("cancel") for k in s.file_kwargs], [handle] * 4)
        Workspace(s).exec("true")
        self.assertIsNone(s.kwargs[-1].get("cancel"))

    def test_a_cancel_handle_reaches_persist_and_hydrate(self) -> None:
        s = TreeTests().tar_session()
        w = Workspace(s)
        handle = object()
        w.persist(cancel=handle)  # type: ignore[arg-type]
        w.hydrate(b"TAR", cancel=handle)  # type: ignore[arg-type]
        self.assertEqual([k.get("cancel") for k in s.kwargs], [handle] * 2)  # the two tars
        # Every file call but the two archive removes, which go without it (release-128).
        removes = [i for i, o in enumerate(s.ops) if isinstance(o, fs.FilesRemove)]
        self.assertEqual(len(removes), 2)
        self.assertEqual([k.get("cancel") for i, k in enumerate(s.file_kwargs) if i not in removes], [handle] * (len(s.file_kwargs) - 2))
        self.assertEqual([s.file_kwargs[i].get("cancel") for i in removes], [None, None])


class UnconfinedTests(unittest.TestCase):
    def test_every_path_is_named_in_the_sandbox_scope(self) -> None:
        s = FakeSession()
        w = Workspace(s, confined=False)
        s.mem.put("/tmp/vf-artifact-1.tar", b"T")
        self.assertEqual(w.read("/tmp/vf-artifact-1.tar"), b"T")
        self.assertEqual(s.ops[-1], fs.FilesRead(b"/tmp/vf-artifact-1.tar", offset=0, max_bytes=1 << 20, scope="sandbox"))
        w.write("/tmp//x/../y.txt", "text")
        self.assertEqual((s.ops[-1].path, s.ops[-1].scope), (b"/tmp/y.txt", "sandbox"))
        w.write(ROOT + "/src/x.py", "print(1)\n")
        self.assertEqual((s.ops[-1].path, s.ops[-1].scope), (b"/work/src/x.py", "sandbox"))
        w.write("rel.txt", "r")
        self.assertEqual(s.ops[-1].path, b"/work/rel.txt")
        s.mem.link("/work/out", "/tmp")
        self.assertEqual(w.read("out/y.txt"), b"text")  # links are followed: the sandbox is the boundary
        self.assertEqual(w.glob("*.txt"), ["rel.txt"])
        self.assertEqual((s.ops[-1].path, s.ops[-1].scope), (b"/work", "sandbox"))
        for bad in ("/", "//", ROOT + "/" + ws.STATE_DIR + "/run", ws.STATE_DIR + "/cmd", "../x", "/tmp/a\nb", "/tmp/a\\b", ""):
            with self.assertRaises(WorkspacePathError, msg=bad):
                w.write(bad, b"x")
        self.assertEqual(s.calls, [])

    def test_a_confined_workspace_still_refuses_them(self) -> None:
        s = FakeSession()
        with self.assertRaises(WorkspacePathError):
            Workspace(s).write("/tmp/x", b"x")
        with self.assertRaises(WorkspacePathError):
            Workspace(s).read("/etc/passwd")
        # grep stays inside the work directory either way.
        with self.assertRaises(WorkspacePathError):
            Workspace(s, confined=False).grep("x", "/etc")
        self.assertEqual(s.ops, [])


class SandboxScopeOnlyTests(unittest.TestCase):
    """A session that states the sandbox scope alone (OpenShell's: its work folder is not a
    mount of its own, so the helper refuses the work scope there). A confined workspace names
    its paths in the sandbox scope under the work directory, checks them by their names, and
    follows a link inside the work directory that points out of it."""

    def session(self) -> FakeSession:
        s = FakeSession()
        s.file_scopes = ("sandbox",)

        def no_work(op: fs.FilesOperation) -> None:
            if op.scope != "sandbox":
                raise AssertionError(f"a {op.scope}-scope call to a session that states the sandbox scope alone: {op!r}")

        s.mem.hook = no_work
        return s

    def test_every_operation_names_the_sandbox_scope_under_the_work_directory(self) -> None:
        s = self.session()
        w = Workspace(s)
        w.write("src/a.txt", "one")
        self.assertEqual((s.ops[-1].path, s.ops[-1].scope), (b"/work/src/a.txt", "sandbox"))
        self.assertEqual(w.read("src/a.txt"), b"one")
        self.assertEqual(w.read(ROOT + "/src/./a.txt"), b"one")
        self.assertEqual(s.ops[-1].path, b"/work/src/a.txt")
        self.assertEqual(w.stat("src").type, "dir")
        self.assertEqual([e.path for e in w.list()], [b"src"])
        self.assertEqual((s.ops[-1].path, s.ops[-1].scope), (b"/work", "sandbox"))
        self.assertEqual([i.content for i in w.read_many(["src/a.txt", "src/b/../a.txt"])], [b"one", b"one"])
        self.assertEqual(list(s.ops[-1].paths), [b"/work/src/a.txt", b"/work/src/a.txt"])
        w.make_dir("d/e", parents=True)
        w.rename("src/a.txt", "d/e/a.txt")
        self.assertEqual((s.ops[-1].from_path, s.ops[-1].to_path), (b"/work/src/a.txt", b"/work/d/e/a.txt"))
        self.assertEqual(w.glob("**/*.txt"), ["d/e/a.txt"])
        w.remove("d/e/a.txt")
        self.assertIsNone(s.mem.get("d/e/a.txt"))
        self.assertTrue(all(op.scope == "sandbox" for op in s.ops))
        self.assertEqual(s.calls, [])  # no project call: every file method is a file call

    def test_a_path_that_leaves_the_work_directory_by_its_name_is_refused_before_any_call(self) -> None:
        s = self.session()
        s.mem.put("/etc/passwd", b"root")
        w = Workspace(s)
        for bad in ("../etc/passwd", "a/../../etc/passwd", "/etc/passwd", ROOT + "/../etc/passwd", ROOT + "x/y"):
            with self.assertRaises(WorkspacePathError, msg=bad):
                w.read(bad)
            with self.assertRaises(WorkspacePathError, msg=bad):
                w.write(bad, b"x")
        with self.assertRaises(WorkspacePathError):
            w.rename("a", "../b")
        with self.assertRaises(WorkspacePathError):
            list(w.list(".."))
        self.assertEqual(s.ops, [])

    def test_a_link_inside_the_work_directory_that_points_out_is_followed(self) -> None:
        # What the docstring states: by names alone, a link the guest made cannot be seen.
        s = self.session()
        s.mem.put("/etc/secret", b"S")
        s.mem.link("out", "/etc")
        w = Workspace(s)
        self.assertEqual(w.read("out/secret"), b"S")
        w.write("out/new", "through")
        self.assertEqual(s.mem.get("/etc/new"), b"through")

    def test_a_session_that_states_the_work_scope_keeps_it(self) -> None:
        for scopes in (("work", "sandbox"), ("work",)):
            s = FakeSession()
            s.file_scopes = scopes
            s.mem.put("/etc/secret", b"S")
            s.mem.link("out", "/etc")
            w = Workspace(s)
            w.write("a.txt", "x")
            self.assertEqual((s.ops[-1].path, s.ops[-1].scope), (b"a.txt", "work"), scopes)
            with self.assertRaises(WorkspacePathError, msg=scopes):
                w.read("out/secret")  # the work scope refuses a link that leaves
            self.assertTrue(all(op.scope == "work" for op in s.ops), scopes)

    def test_an_unconfined_workspace_is_the_same_on_either(self) -> None:
        for scopes in (("sandbox",), ("work", "sandbox")):
            s = FakeSession()
            s.file_scopes = scopes
            Workspace(s, confined=False).write("/tmp/x", "x")
            self.assertEqual((s.ops[-1].path, s.ops[-1].scope), (b"/tmp/x", "sandbox"), scopes)


class InvariantTests(unittest.TestCase):
    def test_close_quietly_drops_a_plimsoll_error_only_and_is_the_one_copy(self) -> None:
        from plimsoll_client import PlimsollError, SessionEndedError

        class Closing:
            def __init__(self, error: Optional[BaseException]) -> None:
                self.error, self.closed = error, False

            def close(self) -> None:
                self.closed = True
                if self.error is not None:
                    raise self.error

        for error in (None, PlimsollError("plimsoll: unreachable"), SessionEndedError("ended", reason="expired")):
            c = Closing(error)
            ws.close_quietly(c)
            self.assertTrue(c.closed)
        with self.assertRaises(KeyError):
            ws.close_quietly(Closing(KeyError("a bug, not a lost session")))
        # The review of the unread half (item 2) found it written five times: no adapter keeps a copy of its own.
        src = os.path.join(os.path.dirname(HERE), "src", "plimsoll_client")
        for name in sorted(os.listdir(src)):
            if name.endswith(".py"):
                with open(os.path.join(src, name), encoding="utf-8") as f:
                    self.assertNotIn("\ndef _close_quietly(", f.read(), f"{name} keeps its own _close_quietly; import workspace.close_quietly")

    def test_every_fixed_step_has_a_kind_and_only_commands_have_steps(self) -> None:
        self.assertEqual(set(ws.STEP_KINDS), set(ws.FIXED_STEPS))
        self.assertEqual(sorted(ws.STEP_KINDS.values()), ["exec", "run"])

    def test_the_shell_file_code_is_gone(self) -> None:
        # D87 B: deleted, with no fallback. A name coming back is a regression.
        for name in ("_ROOT_STEP", "_READ_STEP", "_READ_AT_STEP", "_WRITE_B64_STEP", "_APPEND_B64_STEP", "_TRUE_STEP",
                     "_GLOB_SHELL_STEP", "_GLOB_FIND_STEP", "_GREP_STEP", "_PERSIST_STEP", "_HYDRATE_STEP", "_CHUNK_BYTES",
                     "_A1", "_A2", "_A3", "_OUT", "_ROOT", "_WS_TAR"):
            self.assertFalse(hasattr(ws, name), name)
        self.assertFalse(hasattr(Workspace, "_size"))
        self.assertFalse(hasattr(Workspace, "_put_bytes"))
        with open(ws.__file__, encoding="utf-8") as f:
            text = f.read()
        for word in ("head -c", "tail -c", "base64 -d \"$__plimsoll_s/in.b64\" >>", "wc -c", "find .", '"-c", "wc"'):
            self.assertNotIn(word, text)

    def test_every_step_sent_is_a_fixed_script(self) -> None:
        s = TreeTests().tar_session()
        w = Workspace(s)
        w.exec("rm -rf /; echo $(id)")
        s.mem.put("x", b"a")
        w.read("x")
        w.write("y", "text")
        w.edit("x", "a", "b")
        w.glob("*; rm -rf x")
        w.grep("$(id)")
        w.persist()
        w.hydrate(b"T")
        self.assertEqual(len(s.calls), 4)  # exec, grep and the two tars: the files went by file calls
        for files, steps, _, _ in s.calls:
            for step in steps:
                self.assertIn(step, ws.FIXED_STEPS)
                self.assertNotIn("rm -rf", step)
                self.assertNotIn("$(id)", step)

    def test_close(self) -> None:
        s = FakeSession()
        with Workspace(s) as w:
            w.exec("true")
        self.assertTrue(s.closed)


if __name__ == "__main__":
    unittest.main()
