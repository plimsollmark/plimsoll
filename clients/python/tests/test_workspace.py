"""The agent workspace against a fake session: what it sends (fixed steps, the model's
text only in files), what it refuses, and how it reads results. The real thing runs in
docker_workspace_check.py, which client_test.go runs when docker is there."""

from __future__ import annotations

import base64
import os
import shlex
import subprocess
import tempfile
import unittest
from typing import Any, Dict, List, Optional, Tuple

from plimsoll_client import ExecOutcome, Workspace, WorkspacePathError, WorkspaceTooLargeError
from plimsoll_client import workspace as ws
from plimsoll_client.types import Artifact, ProjectResult, SessionSummary, StepResult

ROOT = "/work"


def result(
    *,
    exit_code: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    artifacts: Optional[Dict[str, bytes]] = None,
    timed_out: bool = False,
    outcome: str = "completed",
    artifacts_truncated: bool = False,
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
        artifacts_truncated=artifacts_truncated,
        advice=(),
    )


class FakeSession:
    """Records every project call; answers the queued results, else a completed call
    whose requested artifacts come from ``fs`` (root and cwd by default)."""

    def __init__(self) -> None:
        self.calls: List[Tuple[Dict[str, str], List[str], List[str], Optional[float]]] = []
        self.kwargs: List[Dict[str, Any]] = []
        self.replies: List[ProjectResult] = []
        self.fs: Dict[str, bytes] = {ws.STATE_DIR + "/root": (ROOT + "\n").encode(), ws.STATE_DIR + "/cwd": (ROOT + "\n").encode()}
        self.closed = False

    def run_project(self, files: Any, steps: List[str], artifacts: List[str] = (), *, timeout: Optional[float] = None, **kw: Any) -> ProjectResult:
        self.calls.append((dict(files or {}), list(steps), list(artifacts), timeout))
        self.kwargs.append(kw)
        if self.replies:
            return self.replies.pop(0)
        return result(artifacts={a: self.fs[a] for a in artifacts if a in self.fs})

    def close(self) -> SessionSummary:
        self.closed = True
        return SessionSummary(session="fake", calls=len(self.calls), last_record_sha256="", end="closed")

    @property
    def last(self) -> Tuple[Dict[str, str], List[str], List[str], Optional[float]]:
        return self.calls[-1]


class ExecTests(unittest.TestCase):
    def test_command_travels_as_a_file_and_the_step_is_fixed(self) -> None:
        s = FakeSession()
        s.replies.append(result(stdout=b"hi\n", artifacts={ws.STATE_DIR + "/root": b"/work\n", ws.STATE_DIR + "/cwd": b"/work/src\n"}))
        out = Workspace(s).exec("cd src && echo hi")
        files, steps, artifacts, timeout = s.last
        self.assertEqual(files, {ws.STATE_DIR + "/cmd": "cd src && echo hi"})
        self.assertEqual(steps, [ws._EXEC_STEP])
        self.assertNotIn("echo hi", steps[0])
        self.assertEqual(artifacts, [ws.STATE_DIR + "/root", ws.STATE_DIR + "/cwd"])
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

    def test_root_is_learned_from_the_first_command(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        w.exec("true")
        self.assertEqual(w.root, ROOT)
        self.assertEqual(len(s.calls), 1)

    def test_a_timeout_past_the_ceiling_is_clamped(self) -> None:
        s = FakeSession()
        Workspace(s, timeout=10, max_timeout=30).exec("true", timeout=300)
        self.assertEqual(s.last[3], 30.0)

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

    def test_a_call_that_did_not_run_is_an_error(self) -> None:
        s = FakeSession()
        s.replies.append(result(outcome="setup_failed", steps=[]))
        with self.assertRaises(RuntimeError):
            Workspace(s).exec("true")

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
        self.assertEqual(s.calls, [])
        self.assertEqual(w.resolve(ROOT + "/x/y"), "x/y")  # learns the root first
        self.assertEqual(s.calls[0][1], [ws._ROOT_STEP])
        self.assertEqual(w.resolve(ROOT), ".")
        for bad in ("", "../x", "a/../../x", "/etc/passwd", ROOT + "x/y", "a\nb", "a\\b", "a\x01b"):
            with self.assertRaises(WorkspacePathError, msg=bad):
                w.resolve(bad)
        with self.assertRaises(WorkspacePathError):
            w.read(".")
        with self.assertRaises(WorkspacePathError):
            w.write(ws.STATE_DIR + "/cmd", "x")
        with self.assertRaises(WorkspacePathError):
            w.read(ws.STATE_DIR)

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


class FileTests(unittest.TestCase):
    def test_read(self) -> None:
        s = FakeSession()
        s.replies.append(result(artifacts={ws.STATE_DIR + "/out": b"hello"}))
        w = Workspace(s)
        self.assertEqual(w.read("a.txt", max_bytes=10), b"hello")
        files, steps, artifacts, _ = s.last
        self.assertEqual(files, {ws.STATE_DIR + "/a1": "a.txt", ws.STATE_DIR + "/a2": "10"})
        self.assertEqual(steps, [ws._READ_STEP])
        self.assertEqual(artifacts, [ws.STATE_DIR + "/out"])
        s.replies.append(result(exit_code=1, stderr=b"head: a.txt: No such file or directory\n"))
        with self.assertRaises(FileNotFoundError):
            w.read("a.txt")
        s.replies.append(result(artifacts_truncated=True))
        with self.assertRaises(WorkspaceTooLargeError):
            w.read("big")
        with self.assertRaises(ValueError):
            w.read("a", max_bytes=ws.MAX_READ_BYTES + 1)
        with self.assertRaises(ValueError):
            w.read("a", max_bytes=0)

    def test_write_text(self) -> None:
        s = FakeSession()
        Workspace(s).write("src/x.py", "print(1)\n")
        self.assertEqual(s.last[:3], ({"src/x.py": "print(1)\n"}, [ws._TRUE_STEP], []))
        with self.assertRaises(WorkspaceTooLargeError):
            Workspace(s).write("big.txt", "x" * (4 << 20))

    def test_write_bytes_in_chunks(self) -> None:
        s = FakeSession()
        data = bytes(range(256)) * 20_000  # 5,120,000 bytes: three chunks
        Workspace(s).write("blob.bin", data)
        self.assertEqual(len(s.calls), 3)
        self.assertEqual([c[1] for c in s.calls], [[ws._WRITE_B64_STEP], [ws._APPEND_B64_STEP], [ws._APPEND_B64_STEP]])
        joined = b"".join(base64.b64decode(c[0][ws.STATE_DIR + "/in.b64"]) for c in s.calls)
        self.assertEqual(joined, data)
        for c in s.calls:
            self.assertEqual(c[0][ws.STATE_DIR + "/a1"], "blob.bin")
            self.assertLessEqual(sum(len(x.encode()) for x in c[0].values()), 4 << 20)
        s.replies.append(result(exit_code=1, stderr=b"base64: invalid\n"))
        with self.assertRaises(OSError):
            Workspace(s).write("blob.bin", b"x")

    def test_edit(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        s.replies.append(result(artifacts={ws.STATE_DIR + "/out": b"a b a"}))
        with self.assertRaises(ValueError):
            w.edit("f", "a", "c")
        s.replies.append(result(artifacts={ws.STATE_DIR + "/out": b"a b a"}))
        self.assertEqual(w.edit("f", "a", "c", replace_all=True), 2)
        self.assertEqual(s.last[0], {"f": "c b c"})
        s.replies.append(result(artifacts={ws.STATE_DIR + "/out": b"a b"}))
        self.assertEqual(w.edit("f", "b", "d"), 1)
        self.assertEqual(s.last[0], {"f": "a d"})
        s.replies.append(result(artifacts={ws.STATE_DIR + "/out": b"a b"}))
        with self.assertRaises(ValueError):
            w.edit("f", "z", "d")
        s.replies.append(result(artifacts={ws.STATE_DIR + "/out": b"\xff\xfe"}))
        with self.assertRaises(ValueError):
            w.edit("f", "a", "b")
        with self.assertRaises(ValueError):
            w.edit("f", "", "b")


class WholeReadTests(unittest.TestCase):
    """read_pieces and read_whole: a file of any size, never a cut or spliced copy."""

    MAX = ws.MAX_READ_BYTES

    def test_a_file_of_one_piece_is_one_call(self) -> None:
        s = FakeSession()
        s.replies.append(result(artifacts={ws._OUT: b"small"}))
        self.assertEqual(Workspace(s).read_whole("f.txt"), b"small")
        self.assertEqual(len(s.calls), 1)
        s.replies.append(result(artifacts={ws._OUT: b""}))
        self.assertEqual(list(Workspace(s).read_pieces("empty")), [])

    def test_a_longer_file_is_measured_and_read_in_pieces(self) -> None:
        s = FakeSession()
        s.replies += [result(artifacts={ws._OUT: b"a" * self.MAX}),
                      result(stdout=f"{self.MAX + 3} f.bin\n".encode()),
                      result(artifacts={ws._OUT: b"bcd"})]
        self.assertEqual(list(Workspace(s).read_pieces("f.bin")), [b"a" * self.MAX, b"bcd"])
        # The read steps, the size between them, and the second read from the first one's end.
        self.assertEqual([c[1][0] for c in s.calls], [ws._READ_STEP, ws._RUN_STEP, ws._READ_AT_STEP])
        self.assertEqual(s.calls[1][0][ws._RUN], "exec wc -c -- f.bin\n")
        self.assertEqual(s.calls[2][0][ws._A3], str(self.MAX + 1))
        # The rest of the measured size and one byte past it, which shows a file that grew.
        self.assertEqual(s.calls[2][0][ws._A2], "4")

    def test_a_file_longer_than_the_limit_is_refused_before_its_second_piece(self) -> None:
        # Finding release-46: a whole read had no limit, and a sandbox can make a file of
        # any size for nothing (a sparse one), so the caller's process held all of it.
        s = FakeSession()
        s.replies += [result(artifacts={ws._OUT: b"a" * self.MAX}), result(stdout=f"{ws.MAX_WHOLE_BYTES + 1} f.bin\n".encode())]
        with self.assertRaises(WorkspaceTooLargeError):
            Workspace(s).read_whole("f.bin")
        self.assertEqual(len(s.calls), 2)  # the first piece and the size, nothing after
        s = FakeSession()
        s.replies += [result(artifacts={ws._OUT: b"a" * self.MAX}), result(stdout=f"{self.MAX + 3} f.bin\n".encode())]
        with self.assertRaises(WorkspaceTooLargeError):
            list(Workspace(s).read_pieces("f.bin", limit=self.MAX + 2))
        s = FakeSession()
        s.replies.append(result(artifacts={ws._OUT: b"abc"}))
        with self.assertRaises(WorkspaceTooLargeError):
            Workspace(s).read_whole("f.txt", limit=2)
        for bad in (-1, 1.5, True, "8"):
            with self.subTest(limit=bad), self.assertRaises(ValueError):
                Workspace(FakeSession()).read_whole("f.txt", limit=bad)  # type: ignore[arg-type]

    def test_the_limit_is_the_callers_to_lift(self) -> None:
        s = FakeSession()
        s.replies += [result(artifacts={ws._OUT: b"a" * self.MAX}), result(stdout=f"{ws.MAX_WHOLE_BYTES + 1} f.bin\n".encode()),
                      result(artifacts={ws._OUT: b"b"})]
        pieces = Workspace(s).read_pieces("f.bin", limit=None)
        self.assertEqual(next(pieces), b"a" * self.MAX)
        self.assertEqual(next(pieces), b"b")  # read on, past 64 MiB, as asked
        pieces.close()

    def test_a_head_of_any_length_is_read_in_pieces_and_checked(self) -> None:
        s = FakeSession()
        s.replies += [result(artifacts={ws._OUT: b"a" * self.MAX}), result(stdout=f"{self.MAX + 100} f.bin\n".encode()),
                      result(artifacts={ws._OUT: b"bcd"})]
        self.assertEqual(Workspace(s).read_head("f.bin", self.MAX + 3), b"a" * self.MAX + b"bcd")
        self.assertEqual(s.calls[2][0][ws._A2], "3")  # exactly what the head still needs
        s = FakeSession()
        s.replies.append(result(artifacts={ws._OUT: b"ab"}))
        self.assertEqual(Workspace(s).read_head("f.txt", 2), b"ab")
        self.assertEqual(s.calls[0][0][ws._A2], "2")
        s = FakeSession()
        s.replies += [result(artifacts={ws._OUT: b"a" * self.MAX}), result(stdout=f"{self.MAX + 100} f.bin\n".encode()),
                      result(artifacts={ws._OUT: b"b"}), result(artifacts={ws._OUT: b""})]
        with self.assertRaises(ws.WorkspaceChangedError):
            Workspace(s).read_head("f.bin", self.MAX + 3)  # shrank between its pieces
        with self.assertRaises(ValueError):
            Workspace(FakeSession()).read_head("f.txt", 0)

    def test_a_file_exactly_one_piece_long_is_measured_and_done(self) -> None:
        s = FakeSession()
        s.replies += [result(artifacts={ws._OUT: b"a" * self.MAX}), result(stdout=f"{self.MAX} f\n".encode())]
        self.assertEqual(len(Workspace(s).read_whole("f")), self.MAX)
        self.assertEqual(len(s.calls), 2)

    def test_a_file_that_changed_size_while_read_is_an_error(self) -> None:
        for name, rest in (("grew", [result(artifacts={ws._OUT: b"bcdef"})]),
                           ("shrank", [result(artifacts={ws._OUT: b""})]),
                           ("removed", [result(exit_code=1, stderr=b"head: f.bin: No such file")])):
            s = FakeSession()
            s.replies += [result(artifacts={ws._OUT: b"a" * self.MAX}), result(stdout=f"{self.MAX + 3} f.bin\n".encode())] + rest
            with self.subTest(change=name), self.assertRaises(ws.WorkspaceChangedError) as caught:
                Workspace(s).read_whole("f.bin")
            self.assertIsInstance(caught.exception, OSError)
            self.assertIn("changed while it was read", str(caught.exception))
        s = FakeSession()
        s.replies += [result(artifacts={ws._OUT: b"a" * self.MAX}), result(exit_code=1, stderr=b"wc: gone")]
        with self.assertRaises(ws.WorkspaceChangedError):
            Workspace(s).read_whole("f.bin")

    def test_a_missing_file_is_file_not_found(self) -> None:
        s = FakeSession()
        s.replies.append(result(exit_code=1, stderr=b"head: nope: No such file or directory"))
        with self.assertRaises(FileNotFoundError):
            Workspace(s).read_whole("nope")


class ShellSession:
    """A session whose project calls run the workspace's fixed steps under this machine's
    sh (dash here), in a work directory of its own: the steps' shell behavior, proved with
    no daemon. docker_workspace_check.py proves them on the images' BusyBox."""

    def __init__(self, root: str) -> None:
        self.root = root

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
    """The fixed steps on a real shell: what a fake session cannot show."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._dir.name)
        self.w = Workspace(ShellSession(self.root))

    def tearDown(self) -> None:
        self._dir.cleanup()

    def put(self, name: str, content: bytes = b"x") -> None:
        with open(os.path.join(self.root, name), "wb") as f:
            f.write(content)

    def test_a_glob_pattern_with_a_space_is_one_pattern(self) -> None:
        # Finding release-41: the shell split `my file*.txt` into two words and answered `my`.
        for name in ("my", "my file1.txt", "notes.txt"):
            self.put(name)
        self.assertEqual(self.w.glob("my file*.txt"), ["my file1.txt"])
        self.assertEqual(self.w.glob("*.txt"), ["my file1.txt", "notes.txt"])
        self.assertEqual(self.w.glob("my"), ["my"])
        self.assertEqual(self.w.glob("no such*"), [])

    def test_a_file_named_with_a_leading_dash_past_one_piece_is_read_whole(self) -> None:
        # Finding release-42: `wc -c -big` read the name as options, and the read failed as
        # "the file changed while it was read".
        content = bytes(range(256)) * ((ws.MAX_READ_BYTES + 3000) // 256)
        self.put("-big", content)
        self.assertEqual(self.w.read_whole("-big"), content)

    def test_a_sparse_file_past_the_limit_is_refused_after_one_piece(self) -> None:
        # Finding release-46: a sparse file costs the sandbox no disk and a whole read held
        # all of it in the caller's memory.
        with open(os.path.join(self.root, "sparse"), "wb") as f:
            f.truncate(ws.MAX_WHOLE_BYTES + 1)
        with self.assertRaises(WorkspaceTooLargeError) as caught:
            self.w.read_whole("sparse")
        self.assertIn(str(ws.MAX_WHOLE_BYTES + 1), str(caught.exception))
        with self.assertRaises(WorkspaceTooLargeError):
            list(self.w.read_pieces("sparse"))
        self.assertEqual(self.w.read_head("sparse", ws.MAX_READ_BYTES + 3), bytes(ws.MAX_READ_BYTES + 3))


class SearchTests(unittest.TestCase):
    def test_glob(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        s.replies.append(result(stdout=b"a.py\nb.py\n.plimsoll-shell\n"))
        self.assertEqual(w.glob("*.py"), ["a.py", "b.py"])
        self.assertEqual(s.last[:3], ({ws.STATE_DIR + "/a1": "*.py", ws.STATE_DIR + "/a2": "."}, [ws._GLOB_SHELL_STEP], []))
        s.replies.append(result(stdout=b"x/a.ts\nx/y/b.ts\n"))
        self.assertEqual(w.glob("**/*.ts", "src"), ["x/a.ts", "x/y/b.ts"])
        self.assertEqual(s.last[0], {ws.STATE_DIR + "/a1": "./*.ts", ws.STATE_DIR + "/a3": "./*/*.ts", ws.STATE_DIR + "/a2": "src"})
        self.assertEqual(s.last[1], [ws._GLOB_FIND_STEP])
        s.replies.append(result())
        self.assertEqual(w.glob("lib/**", "src"), [])
        self.assertEqual(s.last[0][ws.STATE_DIR + "/a1"], "./lib/*")
        self.assertEqual(s.last[0][ws.STATE_DIR + "/a3"], "./lib/*")
        s.replies.append(result())
        w.glob("**/util.py")
        self.assertEqual((s.last[0][ws.STATE_DIR + "/a1"], s.last[0][ws.STATE_DIR + "/a3"]), ("./util.py", "./*/util.py"))
        s.replies.append(result(exit_code=2))
        with self.assertRaises(FileNotFoundError):
            w.glob("*", "missing")
        for bad in ("/etc/*", "../*", "a\nb", ""):
            with self.assertRaises(ValueError, msg=bad):
                w.glob(bad)

    def test_grep(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        s.replies.append(result(stdout=b"./a.py:1:import os\n./.plimsoll-shell/cmd:1:import os\n"))
        self.assertEqual(w.grep("import"), "a.py:1:import os")
        self.assertEqual(s.last[:3], ({ws.STATE_DIR + "/a1": "import", ws.STATE_DIR + "/a2": "."}, [ws._GREP_STEP], []))
        s.replies.append(result(exit_code=1))
        self.assertEqual(w.grep("nothing", "src"), "")
        s.replies.append(result(exit_code=2, stderr=b"grep: bad regex\n"))
        with self.assertRaises(ValueError):
            w.grep("(")
        s.replies.append(result(stdout=b"a:1:x\n", stdout_truncated=True))
        self.assertEqual(w.grep("x"), "a:1:x\n[output truncated]")
        with self.assertRaises(ValueError):
            w.grep("")

    def test_a_file_name_with_a_digit_int_refuses_still_sorts(self) -> None:
        # Finding release-47: "²".isdigit() is true and int("²") raises, so a file the
        # sandbox named `x:²:y` made grep raise ValueError, which adapters read as a bad pattern.
        s = FakeSession()
        s.replies.append(result(stdout="./x:\u00b2:y:3:hit\n./a.py:2:hit\n./a.py:1:hit\n".encode()))
        self.assertEqual(Workspace(s).grep("hit"), "a.py:1:hit\na.py:2:hit\nx:\u00b2:y:3:hit")


class TreeTests(unittest.TestCase):
    def test_persist(self) -> None:
        s = FakeSession()
        s.replies.append(result(artifacts={ws.STATE_DIR + "/ws.tar": b"TAR"}))
        self.assertEqual(Workspace(s).persist(), b"TAR")
        self.assertEqual(s.last[:3], ({}, [ws._PERSIST_STEP], [ws.STATE_DIR + "/ws.tar"]))
        s.replies.append(result(artifacts_truncated=True))
        with self.assertRaises(WorkspaceTooLargeError):
            Workspace(s).persist()
        s.replies.append(result(exit_code=1, stderr=b"tar: failed\n"))
        with self.assertRaises(RuntimeError):
            Workspace(s).persist()

    def test_hydrate(self) -> None:
        s = FakeSession()
        Workspace(s).hydrate(b"TAR")
        self.assertEqual([c[1] for c in s.calls], [[ws._WRITE_B64_STEP], [ws._HYDRATE_STEP]])
        self.assertEqual(s.calls[0][0], {ws.STATE_DIR + "/a1": ws.STATE_DIR + "/ws.tar", ws.STATE_DIR + "/in.b64": base64.b64encode(b"TAR").decode()})
        with self.assertRaises(TypeError):
            Workspace(s).hydrate("TAR")  # type: ignore[arg-type]


def _script_words(script: str) -> List[str]:
    """The words sh reads from a run script, quoting undone."""
    return shlex.split(script, posix=True)


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
        words = _script_words(files[ws.STATE_DIR + "/run"])
        self.assertEqual(words, ["export", "GREETING=hi 'there'\n", "export", "PATH=/bin", "exec", *argv])
        self.assertEqual(artifacts, [ws.STATE_DIR + "/root"])
        self.assertEqual(timeout, 120.0)
        self.assertEqual((out.exit_code, out.stdout, out.cwd), (3, b"out", ""))

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
        s.replies.append(result(artifacts={ws.STATE_DIR + "/out": b"x"}))
        w.read("a", cancel=handle)  # type: ignore[arg-type]
        w.write("a", "text", cancel=handle)  # type: ignore[arg-type]
        w.write("/tmp/b", b"x" * (3 << 20), cancel=handle)  # type: ignore[arg-type]
        # run (which also reports the root), read, write, and the two chunks of the bytes
        self.assertEqual([k.get("cancel") for k in s.kwargs], [handle] * 5)
        Workspace(s).exec("true")
        self.assertIsNone(s.kwargs[-1].get("cancel"))

    def test_a_cancel_handle_reaches_persist_and_hydrate(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        handle = object()
        s.replies.append(result(artifacts={ws.STATE_DIR + "/ws.tar": b"TAR"}))
        w.persist(cancel=handle)  # type: ignore[arg-type]
        w.hydrate(b"TAR", cancel=handle)  # type: ignore[arg-type]
        # persist, then hydrate's upload of the tar and its extract
        self.assertEqual([k.get("cancel") for k in s.kwargs], [handle] * 3)


class UnconfinedTests(unittest.TestCase):
    def test_absolute_paths_outside_the_work_directory(self) -> None:
        s = FakeSession()
        w = Workspace(s, confined=False)
        self.assertEqual(w.root, ROOT)  # an absolute path needs the root: one call
        s.replies.append(result(artifacts={ws.STATE_DIR + "/out": b"T"}))
        self.assertEqual(w.read("/tmp/vf-artifact-1.tar"), b"T")
        self.assertEqual(s.last[0], {ws.STATE_DIR + "/a1": "/tmp/vf-artifact-1.tar", ws.STATE_DIR + "/a2": str(1 << 20)})
        w.write("/tmp//x/../y.txt", "text")
        files, steps, _, _ = s.last
        self.assertEqual(steps, [ws._WRITE_B64_STEP])
        self.assertEqual(files[ws.STATE_DIR + "/a1"], "/tmp/y.txt")
        self.assertEqual(base64.b64decode(files[ws.STATE_DIR + "/in.b64"]), b"text")

    def test_paths_inside_the_work_directory_stay_relative_and_the_state_is_refused(self) -> None:
        s = FakeSession()
        w = Workspace(s, confined=False)
        w.write(ROOT + "/src/x.py", "print(1)\n")
        self.assertEqual(s.last[:3], ({"src/x.py": "print(1)\n"}, [ws._TRUE_STEP], []))
        w.write("rel.txt", "r")
        self.assertEqual(s.last[0], {"rel.txt": "r"})
        for bad in ("/", "//", ROOT + "/" + ws.STATE_DIR + "/run", ws.STATE_DIR + "/cmd", "../x", "/tmp/a\nb", "/tmp/a\\b", ""):
            with self.assertRaises(WorkspacePathError, msg=bad):
                w.write(bad, b"x")

    def test_a_confined_workspace_still_refuses_them(self) -> None:
        s = FakeSession()
        with self.assertRaises(WorkspacePathError):
            Workspace(s).write("/tmp/x", b"x")
        with self.assertRaises(WorkspacePathError):
            Workspace(s).read("/etc/passwd")
        # glob and grep stay inside the work directory either way.
        with self.assertRaises(WorkspacePathError):
            Workspace(s, confined=False).grep("x", "/etc")


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
        src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "plimsoll_client")
        for name in sorted(os.listdir(src)):
            if name.endswith(".py"):
                with open(os.path.join(src, name), encoding="utf-8") as f:
                    self.assertNotIn("\ndef _close_quietly(", f.read(), f"{name} keeps its own _close_quietly; import workspace.close_quietly")

    def test_every_fixed_step_has_a_kind(self) -> None:
        self.assertEqual(set(ws.STEP_KINDS), set(ws.FIXED_STEPS))
        self.assertEqual(ws.STEP_KINDS[ws._RUN_STEP], "run")
        self.assertEqual(len(set(ws.STEP_KINDS)), len(ws.STEP_KINDS))

    def test_every_step_sent_is_a_fixed_script(self) -> None:
        s = FakeSession()
        w = Workspace(s)
        w.exec("rm -rf /; echo $(id)")
        s.replies.append(result(artifacts={ws.STATE_DIR + "/out": b"a"}))
        w.read("x")
        w.write("y", "text")
        w.write("z", b"bytes")
        s.replies.append(result(artifacts={ws.STATE_DIR + "/out": b"a"}))
        w.edit("x", "a", "b")
        w.glob("*; rm -rf /")
        w.glob("**/x")
        w.grep("$(id)")
        s.replies.append(result(artifacts={ws.STATE_DIR + "/ws.tar": b"T"}))
        w.persist()
        w.hydrate(b"T")
        self.assertGreaterEqual(len(s.calls), 11)
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
