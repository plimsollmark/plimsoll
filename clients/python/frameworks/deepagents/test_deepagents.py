"""The Deep Agents sandbox backend over a plimsoll workspace: deepagents' real BaseSandbox,
middleware and agent graph, a workspace faked in memory, and a scripted chat model (no
model is called). What deepagents' own scripts do on a real session is the docker suite's
(docker_deepagents_check.py, LangChain's standard sandbox tests); the daemon-backed cases
here use the echo daemon and the in-memory session daemon client_test.go serves."""

from __future__ import annotations

import asyncio
import threading
import unittest
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

from deepagents import create_deep_agent
from deepagents.backends.protocol import ExecuteResponse, SandboxBackendProtocol, execute_accepts_timeout
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage

import plimsoll_client.deepagents as pd
from plimsoll_client import (AtCapacityError, Client, InsufficientIsolationError, IsolationEvidenceMismatchError, PlimsollError, retry_on,
                             RecordMismatchError, UnsupportedError)
from plimsoll_client.checkpoint import MemoryCheckpointStore
from plimsoll_client.deepagents import PlimsollSandbox
from plimsoll_client.types import LostCall, RunRecord, StepResult
from plimsoll_client.files import FilesReadAnswer
from plimsoll_client.workspace import MAX_READ_BYTES, MAX_WHOLE_BYTES, ExecOutcome, Workspace, WorkspaceCallError, WorkspacePathError
from tests._env import setting



def outcome(stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0, timed_out: bool = False, truncated: bool = False) -> ExecOutcome:
    return ExecOutcome(stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=timed_out, stdout_truncated=truncated,
                       stderr_truncated=False, cwd="/work", result=None)  # type: ignore[arg-type]


class FakeSession:
    """What the backend reads of a Session: its tier, its close, and the lost call it is recovering from
    (``lost_call``, None when not recovering) with ``resolve_lost_call``, which ``resolves`` counts."""

    fingerprint = "fp-fake"

    def __init__(self, isolation: str = "kernel") -> None:
        self.isolation = isolation
        self.closed = False
        self.lost_call: Optional[LostCall] = None
        self.resolves = 0

    def resolve_lost_call(self) -> None:
        self.resolves += 1
        self.lost_call = None

    def close(self) -> None:
        self.closed = True


class FakeWorkspace:
    """What the backend asks of a Workspace, in memory. ``answers`` are what the next
    commands give (an ExecOutcome, or an exception to raise); ``errors`` maps a path to
    the exception a read or write of it raises."""

    root = "/work"

    def __init__(self, session: Any, *, timeout: float, max_timeout: Optional[float], confined: bool) -> None:
        self.session = session
        self.opened = {"timeout": timeout, "max_timeout": max_timeout, "confined": confined}
        self.python = 0
        self.probes = 0  # how many times the backend asked its probe
        self.probe_grep = "other-grep"  # what the probe says of the sandbox's grep
        self.commands: List[str] = []
        self.budgets: List[Optional[float]] = []
        self.answers: List[Any] = []
        self.files: Dict[str, bytes] = {}
        self.errors: Dict[str, BaseException] = {}
        self.sizes: Dict[str, int] = {}
        self.kinds: Dict[str, str] = {}
        self.reads: List[Any] = []
        self.cancels: List[Any] = []
        self.hold: Optional[threading.Event] = None

    def exec(self, command: str, *, timeout: Optional[float] = None, cancel: Any = None) -> ExecOutcome:
        if command == pd._PROBE:
            self.probes += 1
            return outcome(stdout=self.probe_grep.encode() + b"\n" if self.python == 0 else b"", exit_code=self.python)
        self.commands.append(command)
        self.budgets.append(timeout)
        self.cancels.append(cancel)
        if self.hold is not None:
            while not (cancel is not None and cancel.cancelled):
                self.hold.wait(0.01)
            raise PlimsollError("canceled", not_dispatched="request")
        answer = self.answers.pop(0) if self.answers else outcome(stdout=b"ok\n")
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def write(self, path: str, content: bytes, *, cancel: Any = None) -> None:
        if path in self.errors:
            raise self.errors[path]
        self.files[path] = content

    def read(self, path: str, *, max_bytes: int, offset: int = 0, cancel: Any = None) -> bytes:
        self.reads.append((path, offset))
        if path in self.errors:
            raise self.errors[path]
        if path not in self.files:
            raise FileNotFoundError(f"{path}: head: {path}: No such file or directory")
        return self.files[path][offset : offset + max_bytes]

    def run(self, argv: List[str], *, cancel: Any = None) -> ExecOutcome:
        if argv[0] == "sh":  # the backend's check of an unreadable path, the path as $1
            return outcome(stdout=(self.kinds.get(argv[-1], "") + "\n").encode())
        assert argv[:3] == ["wc", "-c", "--"], argv
        return outcome(stdout=f"{self.sizes[argv[-1]]} {argv[-1]}\n".encode())

    # The whole-file reads are the real Workspace's, over this fake's read, so the
    # backend's downloads past one call's budget run the code they run on a real session.
    read_whole = Workspace.read_whole
    read_pieces = Workspace.read_pieces
    read_head = Workspace.read_head
    _pieces = Workspace._pieces

    def _path(self, path: str, *, folder: bool) -> str:
        return path

    def _read(self, rel: str, shown: Any, offset: int, max_bytes: int, cancel: Any) -> FilesReadAnswer:
        # A read states the file's size as its open saw it, as a file call's does.
        content = self.read(rel, max_bytes=max_bytes, offset=offset, cancel=cancel)
        return FilesReadAnswer(content=content, size_at_open=self.sizes.get(rel, len(self.files.get(rel, b""))))


class Backend:
    """A PlimsollSandbox over a FakeWorkspace."""

    def __init__(self, isolation: str = "kernel", python: int = 0, grep: str = "other-grep", **opts: Any) -> None:
        self.session = FakeSession(isolation)
        self.workspace: Optional[FakeWorkspace] = None

        def make(session: Any, **kw: Any) -> FakeWorkspace:
            ws = FakeWorkspace(session, **kw)
            ws.python = python
            ws.probe_grep = grep
            self.workspace = ws
            return ws

        with patch.object(pd, "Workspace", make):
            self.backend = PlimsollSandbox(self.session, **opts)  # type: ignore[arg-type]

    @property
    def ws(self) -> FakeWorkspace:
        assert self.workspace is not None
        return self.workspace


class Scripted(GenericFakeChatModel):
    """A chat model that answers with the given messages in order and takes any tools."""

    def bind_tools(self, tools: Any, **kwargs: Any) -> "Scripted":
        return self


def call(tool: str, args: Dict[str, Any], id: str = "c1") -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": tool, "args": args, "id": id, "type": "tool_call"}])


class BackendTests(unittest.TestCase):
    def test_is_a_sandbox_backend_that_takes_a_timeout(self) -> None:
        b = Backend().backend
        self.assertIsInstance(b, SandboxBackendProtocol)
        self.assertTrue(execute_accepts_timeout(PlimsollSandbox))
        self.assertEqual((b.id, b.root, b.isolation), ("fp-fake", "/work", "kernel"))

    def test_paths_are_the_sandboxs_not_the_work_directorys(self) -> None:
        self.assertIs(Backend().ws.opened["confined"], False)

    def test_a_session_below_the_floor_is_refused_and_left_open(self) -> None:
        session = FakeSession("container")
        made: List[Any] = []
        with patch.object(pd, "Workspace", lambda *a, **k: made.append(a)):
            with self.assertRaises(InsufficientIsolationError) as cm:
                PlimsollSandbox(session)  # type: ignore[arg-type]
        self.assertEqual(cm.exception.not_dispatched, "isolation")
        self.assertEqual(made, [], "no call was made")
        self.assertFalse(session.closed)
        self.assertEqual(Backend("container", minimum_isolation="container").backend.isolation, "container")

    def test_a_floor_must_be_a_tier(self) -> None:
        for bad in ("", "kernl"):
            with self.assertRaises(PlimsollError if bad else ValueError):
                Backend(minimum_isolation=bad)

    def test_a_sandbox_without_python_is_refused_and_left_open(self) -> None:
        with self.assertRaises(PlimsollError) as cm:
            Backend(python=127)
        # Finding release-47 (candidate a): the backend's own probe ran in the sandbox, a
        # call in the session's chain, so the error must not say nothing was dispatched,
        # and a framework's retry (retry_on) must not take it for a refusal.
        self.assertIsNone(cm.exception.not_dispatched)
        self.assertFalse(retry_on(cm.exception))
        self.assertIn("python3", cm.exception.message)

    def test_execute_gives_stdout_then_marked_stderr_and_the_exit_code(self) -> None:
        b = Backend()
        b.ws.answers.append(outcome(stdout=b"a\nb", stderr=b"warn 1\nwarn 2\n", exit_code=3))
        r = b.backend.execute("make")
        self.assertEqual((r.output, r.exit_code, r.truncated), ("a\nb\n[stderr] warn 1\n[stderr] warn 2", 3, False))
        self.assertEqual(b.ws.commands, ["make"])

    def test_a_command_past_its_budget_is_exit_124_with_what_it_printed(self) -> None:
        b = Backend()
        b.ws.answers.append(outcome(stdout=b"partial\n", exit_code=124, timed_out=True))
        r = b.backend.execute("sleep 99", timeout=7)
        self.assertEqual((r.exit_code, r.output), (124, "Command timed out after 7 seconds\npartial\n"))
        self.assertEqual(b.ws.budgets, [7.0])

    def test_budgets(self) -> None:
        b = Backend(timeout=30, max_timeout=300)
        for t in (None, 0, 45, 900):
            b.backend.execute("true", timeout=t)
        # None: the default; 0 (no limit elsewhere): the daemon's longest; past it: capped.
        self.assertEqual(b.ws.budgets, [30.0, 300.0, 45.0, 300.0])
        with self.assertRaises(ValueError):
            b.backend.execute("true", timeout=-1)

    def test_truncation_is_reported(self) -> None:
        b = Backend()
        b.ws.answers.append(outcome(stdout=b"x" * 10, truncated=True))
        self.assertTrue(b.backend.execute("yes").truncated)

    def test_a_refusal_raises_and_ls_never_reads_it_as_an_empty_directory(self) -> None:
        b = Backend()
        b.ws.answers.append(AtCapacityError("plimsoll: at capacity", not_dispatched="capacity"))
        with self.assertRaises(AtCapacityError):
            b.backend.execute("ls")
        # BaseSandbox.ls skips every line of execute's output that is not JSON, so a refusal
        # answered as output would be an empty listing. It raises instead.
        b.ws.answers.append(AtCapacityError("plimsoll: at capacity", not_dispatched="capacity"))
        with self.assertRaises(AtCapacityError):
            b.backend.ls("/work")

    def test_grep_takes_the_python_route_unless_the_sandbox_has_gnu_grep(self) -> None:
        # deepagents' grep route sends GNU options with its errors discarded, which BusyBox
        # grep refuses: every search would answer "no matches".
        busybox = Backend()
        busybox.ws.answers.append(outcome(stdout=b"/work/a.py\x003:x = 1\n"))
        r = busybox.backend.grep("x = 1", path="/work", glob="*.py")
        self.assertEqual(r.matches, [{"path": "/work/a.py", "line": 3, "text": "x = 1"}])
        self.assertTrue(busybox.ws.commands[0].startswith('python3 -c "'), busybox.ws.commands[0][:80])
        self.assertNotIn("grep -rHnFZ", busybox.ws.commands[0])
        gnu = Backend(grep="gnu-grep")
        gnu.ws.answers.append(outcome())
        gnu.backend.grep("x = 1", path="/work")
        self.assertIn("grep -rHnFZ", gnu.ws.commands[0])

    def test_uploads_answer_per_file_in_order(self) -> None:
        b = Backend()
        b.ws.errors = {
            "/etc/x": OSError("/etc/x: base64: can't create '/etc/x': Permission denied"),
            "/work/.plimsoll-shell/env": WorkspacePathError(".plimsoll-shell is the workspace's own state"),
        }
        r = b.backend.upload_files([("/work/a.txt", b"A"), ("rel.txt", b"R"), ("/etc/x", b"X"),
                                    ("/work/.plimsoll-shell/env", b"E"), ("/tmp/b.bin", b"\x00\xff")])
        self.assertEqual([x.path for x in r], ["/work/a.txt", "rel.txt", "/etc/x", "/work/.plimsoll-shell/env", "/tmp/b.bin"])
        self.assertEqual([x.error for x in r], [None, "invalid_path", "permission_denied", "invalid_path", None])
        self.assertEqual(b.ws.files, {"/work/a.txt": b"A", "/tmp/b.bin": b"\x00\xff"})

    def test_a_call_that_may_have_run_or_failed_its_checks_raises_and_is_never_a_files_error(self) -> None:
        # Finding release-45: each of these came back as the file's error, so the model
        # read a write that may have run, or an answer whose record or tier did not check,
        # as a file that failed, and the agent's run went on.
        for name, error in (
            ("an unmarked plimsoll error", PlimsollError("plimsoll: the call may have run", not_dispatched=None)),
            ("a record that failed its check", RecordMismatchError("plimsoll: the run record does not match the answer")),
            ("an isolation-evidence mismatch", IsolationEvidenceMismatchError("plimsoll: the record names another tier")),
            ("a call past its budget", TimeoutError("plimsoll: the call ran past its budget of 120.0 s")),
            ("an answer the workspace cannot use", WorkspaceCallError("plimsoll: the call may have run: runner_failed", None)),  # type: ignore[arg-type]
        ):
            with self.subTest(error=name):
                b = Backend()
                b.ws.files = {"/work/lost": b"L"}
                b.ws.errors = {"/work/lost": error}
                with self.assertRaises(type(error)):
                    b.backend.upload_files([("/work/lost", b"L"), ("/work/after", b"A")])
                self.assertNotIn("/work/after", b.ws.files)  # the files after it are not written
                with self.assertRaises(type(error)):
                    b.backend.download_files(["/work/lost"])
                with self.assertRaises(type(error)):
                    asyncio.run(b.backend.aupload_files([("/work/lost", b"L")]))

    def test_downloads_answer_per_path_in_order(self) -> None:
        b = Backend()
        b.ws.files = {"/work/a.txt": b"A"}
        # BusyBox head says "I/O error" of a directory: the word comes from the path itself.
        b.ws.errors = {
            "/work/dir": FileNotFoundError("/work/dir: head: /work/dir: I/O error"),
            "/root/secret": FileNotFoundError("/root/secret: head: /root/secret: Permission denied"),
            "/work/odd": FileNotFoundError("/work/odd: head: something else"),
        }
        b.ws.kinds = {"/work/none": "file_not_found", "/work/dir": "is_directory", "/root/secret": "permission_denied"}
        r = b.backend.download_files(["/work/a.txt", "/work/none", "/work/dir", "/root/secret", "rel", "/work/odd"])
        self.assertEqual([(x.path, x.content, x.error) for x in r], [
            ("/work/a.txt", b"A", None),
            ("/work/none", None, "file_not_found"),
            ("/work/dir", None, "is_directory"),
            ("/root/secret", None, "permission_denied"),
            ("rel", None, "invalid_path"),
            ("/work/odd", None, "/work/odd: head: something else"),
        ])

    def test_a_typed_read_error_is_its_word_with_no_more_calls(self) -> None:
        # A file call names a folder, a permission and a part that is not a folder itself.
        import errno
        b = Backend()
        b.ws.errors = {"/work/d": IsADirectoryError(errno.EISDIR, "Is a directory", "/work/d"),
                       "/work/s": PermissionError(errno.EACCES, "Permission denied", "/work/s"),
                       "/work/f/x": NotADirectoryError(errno.ENOTDIR, "Not a directory", "/work/f/x")}
        r = b.backend.download_files(["/work/d", "/work/s", "/work/f/x"])
        self.assertEqual([x.error for x in r], ["is_directory", "permission_denied", "file_not_found"])

    def test_a_file_past_one_call_is_read_in_pieces_and_never_handed_over_cut(self) -> None:
        b = Backend()
        big = bytes(range(256)) * ((2 * MAX_READ_BYTES + 300) // 256)
        b.ws.files = {"/work/big": big, "/work/exact": b"y" * MAX_READ_BYTES, "/work/moving": b"z" * (MAX_READ_BYTES + 10)}
        b.ws.sizes = {"/work/big": len(big), "/work/exact": MAX_READ_BYTES, "/work/moving": MAX_READ_BYTES + 99}
        whole, exact, moving = b.backend.download_files(["/work/big", "/work/exact", "/work/moving"])
        self.assertEqual((whole.content, whole.error), (big, None))
        self.assertEqual([o for p, o in b.ws.reads if p == "/work/big"], [0, MAX_READ_BYTES, 2 * MAX_READ_BYTES])
        self.assertEqual((len(exact.content or b""), exact.error), (MAX_READ_BYTES, None))
        self.assertIsNone(moving.content)
        self.assertIn("changed while it was read", moving.error or "")

    def test_a_file_past_the_whole_read_limit_is_its_error_after_one_piece(self) -> None:
        # Finding release-46: a sandbox can make a file of any size (a sparse one costs it
        # nothing), and the download held all of it in this process's memory.
        b = Backend()
        b.ws.files = {"/work/huge": bytes(MAX_WHOLE_BYTES + 1)}
        b.ws.sizes = {"/work/huge": MAX_WHOLE_BYTES + 1}
        (huge,) = b.backend.download_files(["/work/huge"])
        self.assertIsNone(huge.content)
        self.assertIn(f"past the {MAX_WHOLE_BYTES} a whole read takes", huge.error or "")
        self.assertEqual([o for p, o in b.ws.reads if p == "/work/huge"], [0])

    def test_cancelling_an_async_command_cuts_its_call(self) -> None:
        b = Backend()
        b.ws.hold = threading.Event()

        async def main() -> None:
            task = asyncio.ensure_future(b.backend.aexecute("sleep 60"))
            while not b.ws.cancels:
                await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(main())
        self.assertTrue(b.ws.cancels[0].cancelled, "the call's cancel handle was cancelled")

    def test_close_closes_the_session(self) -> None:
        b = Backend()
        with b.backend:
            pass
        self.assertTrue(b.session.closed)


class AgentTests(unittest.TestCase):
    """A Deep Agents agent, deepagents' own graph and middleware, driven by a scripted model."""

    def agent(self, b: Backend, *script: AIMessage) -> Any:
        model = Scripted(messages=iter(list(script) + [AIMessage(content="done")]))
        return create_deep_agent(model=model, backend=b.backend)

    def test_the_agent_runs_a_command_through_execute(self) -> None:
        b = Backend()
        b.ws.answers.append(outcome(stdout=b"hello\n"))
        out = self.agent(b, call("execute", {"command": "echo hello"})).invoke({"messages": [{"role": "user", "content": "go"}]})
        self.assertEqual(b.ws.commands, ["echo hello"])
        msg = next(m for m in out["messages"] if isinstance(m, ToolMessage) and m.name == "execute")
        self.assertIn("hello", msg.content)
        self.assertIn("exit code 0", msg.content)

    def test_a_refusal_stops_the_run_instead_of_reaching_the_model_as_output(self) -> None:
        b = Backend()
        b.ws.answers.append(AtCapacityError("plimsoll: at capacity", not_dispatched="capacity"))
        with self.assertRaises(AtCapacityError):
            self.agent(b, call("execute", {"command": "echo hello"})).invoke({"messages": [{"role": "user", "content": "go"}]})

    def test_the_agent_writes_through_upload(self) -> None:
        b = Backend()
        agent = self.agent(b, call("write_file", {"file_path": "/work/notes.md", "content": "# hi\n"}))
        out = agent.invoke({"messages": [{"role": "user", "content": "go"}]})
        self.assertEqual(b.ws.files, {"/work/notes.md": b"# hi\n"})
        msg = next(m for m in out["messages"] if isinstance(m, ToolMessage) and m.name == "write_file")
        self.assertNotEqual(msg.status, "error", msg.content)


class FakeAttachClient:
    """What PlimsollSandbox.open and .attach ask of a Client: describe, and an open or an
    attach that hands back a FakeSession, each call recorded."""

    def __init__(self) -> None:
        self.session = FakeSession()
        self.opened: List[Dict[str, Any]] = []
        self.attached: List[Any] = []

    def describe(self, *, cancel: Any = None) -> Any:
        env = SimpleNamespace(languages=("python",), max_timeout_ms=300_000)
        return SimpleNamespace(provider="fake", supports_sessions=True, session_environment=env)

    def open_session(self, **kw: Any) -> Any:
        self.opened.append(kw)
        return self.session

    def attach_session(self, key: str, *, store: Any, trace_id: Optional[str] = None, cancel: Any = None) -> Any:
        self.attached.append((key, store, trace_id))
        return self.session


class AttachTests(unittest.TestCase):
    """A thread resumed on another worker: PlimsollSandbox.attach (step R7 of the sessions
    builds plan), over the client's attach and its checkpoint store."""

    def build(self, make: Any) -> Dict[str, Any]:
        seen: Dict[str, Any] = {}

        def workspace(session: Any, **kw: Any) -> FakeWorkspace:
            seen["ws"] = FakeWorkspace(session, **kw)
            return seen["ws"]

        with patch.object(pd, "Workspace", workspace):
            seen["backend"] = make()
        return seen

    def test_attach_carries_the_session_on_by_its_key_and_store(self) -> None:
        client, store = FakeAttachClient(), MemoryCheckpointStore()
        got = self.build(lambda: PlimsollSandbox.attach(client, "user-1/thread-1", store=store, minimum_isolation="kernel", trace_id="t1"))  # type: ignore[arg-type]
        self.assertEqual(client.attached, [("user-1/thread-1", store, "t1")])
        self.assertIs(got["backend"].session, client.session)
        self.assertEqual(got["ws"].opened["max_timeout"], 300.0, "the daemon's ceiling, as open sets it")
        self.assertEqual(got["ws"].probes, 1)

    def test_open_keeps_the_checkpoint_in_the_store(self) -> None:
        client, store = FakeAttachClient(), MemoryCheckpointStore()
        self.build(lambda: PlimsollSandbox.open(client, minimum_isolation="kernel", checkpoint_store=store, checkpoint_key="k"))  # type: ignore[arg-type]
        self.assertEqual((client.opened[0]["checkpoint_store"], client.opened[0]["checkpoint_key"]), (store, "k"))

    def test_over_a_recovering_session_the_backend_sends_nothing_of_its_own(self) -> None:
        # After an attach across an explained gap the session is recovering and refuses every
        # call until it is resolved: the backend asks no probe, and the agent's first tool call
        # is the one that tells the model of the lost call.
        client = FakeAttachClient()
        client.session.lost_call = LostCall(request_sha256="a" * 64)
        got = self.build(lambda: PlimsollSandbox.attach(client, "k", store=MemoryCheckpointStore(), minimum_isolation="kernel"))  # type: ignore[arg-type]
        self.assertEqual(got["ws"].probes, 0)
        self.assertEqual(got["ws"].commands, [])
        self.assertEqual(client.session.resolves, 0, "making the backend resolved the session")
        self.assertFalse(got["backend"]._gnu_grep, "searches go through Deep Agents' python3 search")


def lost_record(*, unanswered: str = "", ms: int = 2400) -> RunRecord:
    return RunRecord(
        version=5, request_sha256="3" * 64, result_sha256="" if unanswered else "4" * 64, provider="fake", isolation="kernel",
        environment="", policy="", software_identity="", software_rule_id="", started_unix_ms=1790000000000,
        ended_unix_ms=1790000000000 + ms, session="f" * 64, sequence=4, previous_sha256="a" * 64, sha256="b" * 64,
        unanswered=unanswered,
    )


class LostCallTests(unittest.TestCase):
    """A session taken over across a call whose answer was lost (lost call option 3): the agent's first tool call,
    whichever it is, is not run; the model reads what plimsoll's record of the lost call says (and its output when
    the answer came back) as that tool's answer, the backend resolves the session, and the next tool call runs."""

    def recovering(self, lost: LostCall, **opts: Any) -> Backend:
        b = Backend(**opts)
        b.session.lost_call = lost
        return b

    def test_each_entry_point_answers_with_the_lost_call_and_sends_nothing(self) -> None:
        lost = LostCall(request_sha256="3" * 64, record=lost_record(unanswered="canceled"))
        cases: List[Tuple[str, Any]] = [
            ("execute", lambda s: s.execute("ls")),
            ("aexecute", lambda s: asyncio.run(s.aexecute("ls"))),
            ("execute_with_offload", lambda s: s.execute_with_offload("ls", "/tmp/out", max_inline_bytes=100).response),
            ("ls", lambda s: s.ls("/work")),
            ("als", lambda s: asyncio.run(s.als("/work"))),
            ("read", lambda s: s.read("/work/a.txt")),
            ("write", lambda s: s.write("/work/a.txt", "x")),
            ("edit", lambda s: s.edit("/work/a.txt", "x", "y")),
            ("delete", lambda s: s.delete("/work/a.txt")),
            ("grep", lambda s: s.grep("x", "/work")),
            ("glob", lambda s: s.glob("*.txt", "/work")),
            ("upload_files", lambda s: s.upload_files([("/work/a.txt", b"x")])[0]),
            ("download_files", lambda s: s.download_files(["/work/a.txt"])[0]),
        ]
        for name, use in cases:
            with self.subTest(name):
                b = self.recovering(lost)
                got = use(b.backend)
                text = got.output if isinstance(got, ExecuteResponse) else got.error
                self.assertIn("this tool call was not run", text)
                self.assertIn("That call ended without an answer after 2.4 s: the request for it was called off.", text)
                if isinstance(got, ExecuteResponse):
                    self.assertEqual(got.exit_code, pd.NOT_RUN_EXIT)
                self.assertEqual((b.ws.commands, b.ws.files), ([], {}), "a call was sent")
                self.assertEqual(b.session.resolves, 1)
                self.assertIsNone(b.session.lost_call)

    def test_a_kept_answer_is_shown_cut_to_the_output_limit(self) -> None:
        from plimsoll_client.types import ProjectResult

        step = StepResult(command="", stdout=b"y" * 40 + b"TAIL", stderr=b"", exit_code=0, timed_out=False, duration_ms=1,
                          stdout_truncated=False, stderr_truncated=False)
        answer = ProjectResult(provider="fake", isolation="kernel", environment="", software_identity="", duration_ms=1,
                               record=lost_record(), outcome="completed", detail="", steps=(step,), artifacts=(),
                               artifacts_truncated=False, advice=())
        b = self.recovering(LostCall(request_sha256="3" * 64, record=lost_record(), answer=answer), max_output_chars=40)
        text = b.backend.execute("ls").output
        self.assertIn("and kept its answer, which follows", text)
        self.assertIn("y" * 40, text)
        self.assertNotIn("TAIL", text)
        self.assertIn("[output truncated]", text)

    def test_the_agent_is_told_then_its_next_call_runs(self) -> None:
        # Findings release-74 and release-84: the lost command sent again as the agent's first command, or after another
        # call, ran a second time with nothing said under the first-call rule. The first tool call is told now; the
        # command sent again on purpose after it runs.
        firsts = (
            call("execute", {"command": "python3 triage.py"}, id="c1"),
            call("ls", {"path": "/work"}, id="c1"),
            call("read_file", {"file_path": "/work/notes.md"}, id="c1"),
            call("write_file", {"file_path": "/work/notes.md", "content": "x"}, id="c1"),
            call("edit_file", {"file_path": "/work/notes.md", "old_string": "x", "new_string": "y"}, id="c1"),
            call("glob", {"pattern": "*.md", "path": "/work"}, id="c1"),
            call("grep", {"pattern": "x", "path": "/work"}, id="c1"),
        )
        for first in firsts:
            with self.subTest(first.tool_calls[0]["name"]):
                b = self.recovering(LostCall(request_sha256="3" * 64, record=lost_record()))
                b.ws.answers.append(outcome(stdout=b"done\n"))
                model = Scripted(messages=iter([first, call("execute", {"command": "python3 triage.py"}, id="c2"), AIMessage(content="done")]))
                out = create_deep_agent(model=model, backend=b.backend).invoke({"messages": [{"role": "user", "content": "go"}]})
                told = next(m for m in out["messages"] if isinstance(m, ToolMessage) and m.tool_call_id == "c1")
                self.assertIn("this tool call was not run", str(told.content))
                self.assertIn("The sandbox answered that call after 2.4 s, but the answer is lost", str(told.content))
                self.assertEqual(b.ws.commands, ["python3 triage.py"], "only the call after the one told ran")
                self.assertEqual(b.ws.files, {}, "the told call wrote a file")
                self.assertEqual(b.session.resolves, 1)


class DaemonTests(unittest.TestCase):
    def test_a_daemon_without_sessions_is_refused_before_anything_opens(self) -> None:
        with self.assertRaises(UnsupportedError) as cm:
            PlimsollSandbox.open(Client(setting("PLIMSOLL_TOOL_ECHO_URL")), minimum_isolation="container")
        self.assertEqual(cm.exception.not_dispatched, "unsupported")

    def test_the_session_is_closed_when_the_backend_cannot_be_made(self) -> None:
        # The in-memory session daemon states Python and opens sessions, and its calls give
        # no step's report, so the probe fails after the session is open.
        client = Client(setting("PLIMSOLL_SESSIONS_URL"))
        opened: List[Any] = []
        real = client.open_session

        def spy(**kw: Any) -> Any:
            s = real(**kw)
            opened.append(s)
            return s

        with patch.object(client, "open_session", spy):
            with self.assertRaises(RuntimeError):
                PlimsollSandbox.open(client, minimum_isolation="container")
        self.assertEqual(len(opened), 1)
        self.assertIsNotNone(opened[0].ended, "the session opened for the backend was closed")

    def test_the_default_floor_refuses_a_container_daemon(self) -> None:
        with self.assertRaises(PlimsollError) as cm:
            PlimsollSandbox.open(Client(setting("PLIMSOLL_SESSIONS_URL")))
        self.assertIn("kernel", cm.exception.message)


class FrameworkShapeTests(unittest.TestCase):
    """Each member the adapter defines over the framework's own (inherited, or declared by a protocol it is used
    as) against the framework at the version this suite installs: kind, coroutine, the calls it takes
    (tests/_framework_shapes.py)."""

    def test_the_adapter_takes_the_calls_the_framework_makes(self) -> None:
        import importlib

        from tests._framework_shapes import problems

        self.assertEqual(problems(importlib.import_module('plimsoll_client.deepagents')), [])


if __name__ == "__main__":
    unittest.main()
