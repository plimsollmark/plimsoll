"""The agent workspace against a fake session: what it sends (fixed steps, the model's
text only in files), what it refuses, and how it reads results. The real thing runs in
docker_workspace_check.py, which client_test.go runs when docker is there."""

from __future__ import annotations

import base64
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
        self.replies: List[ProjectResult] = []
        self.fs: Dict[str, bytes] = {ws.STATE_DIR + "/root": (ROOT + "\n").encode(), ws.STATE_DIR + "/cwd": (ROOT + "\n").encode()}
        self.closed = False

    def run_project(self, files: Any, steps: List[str], artifacts: List[str] = (), *, timeout: Optional[float] = None, **kw: Any) -> ProjectResult:
        self.calls.append((dict(files or {}), list(steps), list(artifacts), timeout))
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


class InvariantTests(unittest.TestCase):
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
