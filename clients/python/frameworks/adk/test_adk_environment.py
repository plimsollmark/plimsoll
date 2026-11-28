"""PlimsollEnvironment, ADK's kept sandbox with a shell and files, over a plimsoll session.

ADK's real tools (ExecuteTool, ReadFileTool, EditFileTool, WriteFileTool), its real
EnvironmentToolset and Runner, and a scripted model (no model is called), over the real
Workspace on a fake session that understands the workspace's fixed steps, keeps files in
memory and counts every call it is handed. What a real shell does is the docker check's
(docker_adk_check.py); the cases at the end run against the Go daemons the suite serves."""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import shlex
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

from google.adk.agents import Agent
from google.adk.environment import LocalEnvironment
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.reflect_retry_tool_plugin import ReflectAndRetryToolPlugin
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.environment import EnvironmentToolset
from google.adk.tools.environment._edit_file_tool import EditFileTool
from google.adk.tools.environment._execute_tool import ExecuteTool
from google.adk.tools.environment._read_file_tool import ReadFileTool
from google.adk.tools.environment._write_file_tool import WriteFileTool
from google.genai import types
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import Field

from plimsoll_client import (AtCapacityError, Client, InsufficientIsolationError, PlimsollError, RequestCanceledError,
                             SessionEndedError, UnsupportedError)
from plimsoll_client import _langsmith
from plimsoll_client import workspace as w
from plimsoll_client.files import FilesRead, FilesReadAnswer, FilesResult, FilesWrite, FilesWriteAnswer, path_bytes
from plimsoll_client._tables import OUTCOME_NAMES, REFUSAL_NAMES, TIERS
from plimsoll_client.adk import (PlimsollCall, PlimsollEnvironment, PlimsollEnvironmentError, PlimsollEnvironmentGuard,
                                 PlimsollExecutionResult)
from plimsoll_client.types import Artifact, ProjectResult, RunRecord, SessionEnded, SessionSummary, StepResult
from tests._env import setting

SPANS = InMemorySpanExporter()


def setUpModule() -> None:
    # ADK's tracer is OpenTelemetry's global one (google/adk/telemetry/tracing.py); a
    # provider set here receives its spans, kept in memory.
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(SPANS))
    trace.set_tracer_provider(provider)


GUEST_TEXT = "GUEST-TEXT-7f3a"  # what a guest or a runner might write; never in a label or a raised message


class FakeSession:
    """A plimsoll session that runs nothing: it reads the workspace's fixed steps (each one
    of workspace.STEP_KINDS) and its file calls, keeps the files a write carries, answers reads from them and
    answers a command with what the test scripted (``cat PATH`` reads a kept file; any
    other command answers ``ran: COMMAND``). ``fail`` queues failures by kind. Every call
    it is handed is in ``log``."""

    _count = 0

    def __init__(self, isolation: str = "kernel", qualification: str = "", work_dir: str = "/work",
                 file_scopes: Optional[Tuple[str, ...]] = None) -> None:
        self.isolation = isolation
        self.isolation_qualification = qualification
        # Each its own, as a daemon's are (the SHA-256 of the session ID): an ADK invocation is
        # held to a session by its fingerprint (adk._Live.identity).
        FakeSession._count += 1
        self.fingerprint = f"fp-fake-{FakeSession._count}"
        # "" as a session that takes no file calls states (the in-memory session daemon's, a
        # daemon from before file calls): every file call is then the daemon's refusal, and the
        # work directory is asked by pwd. ("sandbox",) is OpenShell's (D94 D): its work folder
        # stated, file calls in the sandbox scope alone.
        self.work_dir = work_dir
        self.file_scopes = (("work", "sandbox") if work_dir else ()) if file_scopes is None else file_scopes
        self.files: Dict[str, bytes] = {}
        self.dirs: set = set()
        self.unreadable: set = set()
        self.special: set = set()  # a FIFO, socket or device: the helper never opens one
        self.answers: Dict[str, Tuple[bytes, bytes, int]] = {}
        self.fail: Dict[str, List[str]] = {}
        self.before_read: Any = None  # called with (path, offset) before a read is answered
        self.hold_reads_past_first = False  # a read at an offset waits for its cancel handle (2 s at most)
        self.cut: List[int] = []  # offsets of the reads a cancel handle cut
        self.log: List[Dict[str, Any]] = []
        self.closed = 0
        # What plimsoll_client.Session states, as it does: ``stopped`` once a call ended without
        # an answer it could check (every later call is then refused, nothing sent), ``ended``
        # once an answer reported the session's end.
        self.stopped: Optional[str] = None
        self.ended: Optional[SessionEnded] = None
        self._n = 0
        self._last = ""

    # ---- the session's interface, as Workspace uses it ----

    def run_project(self, files: Any, steps: List[str], artifacts: List[str] = (), *, timeout: Optional[float] = None,
                    cancel: Any = None, trace_id: Optional[str] = None) -> ProjectResult:
        files = dict(files)
        step = steps[0]
        kind = w.STEP_KINDS[step]
        entry: Dict[str, Any] = {"kind": kind, "timeout": timeout, "trace_id": trace_id}
        argv: List[str] = []
        if kind == "run":
            lines = files[w._RUN].strip().split("\n")
            entry["env"] = dict(l[len("export "):].split("=", 1) for l in lines[:-1])
            argv = shlex.split(lines[-1])[1:]
            if argv == ["pwd"]:
                kind = entry["kind"] = "pwd"
            else:
                entry["command"] = argv[2]
        self.log.append(entry)
        how = self.fail.get(kind, [])
        mode = how.pop(0) if how else None
        self._refuse(mode)
        if mode in ("runner_failed", "protocol_error", "setup_failed"):
            return self._result([], outcome=mode, detail=f"runner: {GUEST_TEXT}")
        if mode == "runner_failed_after_step":  # a step began, then the runner failed
            return self._result([self._step(step, stdout=GUEST_TEXT.encode())], outcome="runner_failed",
                                detail=f"runner: {GUEST_TEXT}")
        if kind == "pwd":
            return self._result([self._step(step, stdout=b"/work\n")])
        if kind == "run":
            return self._command(step, argv[2], mode)
        raise AssertionError(f"a step this fake does not know: {kind}")

    def run_files(self, op: Any, *, timeout: Optional[float] = None, cancel: Any = None,
                  trace_id: Optional[str] = None) -> FilesResult:
        """A file call (the workspace's reads and writes), answered from the kept files as the helper answers."""
        kind = {FilesRead: "read", FilesWrite: "write"}.get(type(op))
        if kind is None:
            raise AssertionError(f"a file call this fake does not know: {op!r}")
        if op.scope not in self.file_scopes:
            self.log.append({"kind": "refused " + kind})
            raise UnsupportedError(f"plimsoll: this session takes no {op.scope}-scope file calls; nothing ran",
                                   not_dispatched="unsupported")
        assert op.scope == "sandbox", op  # the environment's workspace is unconfined
        p = self._norm(path_bytes(op.path).decode("utf-8", "surrogateescape"))
        entry: Dict[str, Any] = {"kind": kind, "timeout": timeout, "trace_id": trace_id, "path": p}
        self.log.append(entry)
        how = self.fail.get(kind, [])
        mode = how.pop(0) if how else None
        self._refuse(mode)
        if mode in ("runner_failed", "protocol_error", "runner_failed_after_step"):
            return self._files_result(outcome="runner_failed" if mode == "runner_failed_after_step" else mode)
        if isinstance(op, FilesWrite):
            if mode == "write_denied" or p in self.unreadable:
                return self._files_result(error="permission_denied", errno="EACCES")
            if mode in ("no_space", "read_only", "other"):
                return self._files_result(error=mode, errno={"no_space": "ENOSPC", "read_only": "EROFS", "other": "EIO"}[mode])
            if self._is_dir(p):
                return self._files_result(error="is_dir", errno="EISDIR")
            parts = p.split("/")
            if any("/".join(parts[:i]) in self.files for i in range(1, len(parts))):
                return self._files_result(error="not_dir", errno="ENOTDIR")  # a folder on the way is a file
            data = bytes(op.content)
            self.files[p] = (self.files.get(p, b"") + data) if op.mode == "append" else data
            return self._files_result(FilesWriteAnswer(written=len(data)))
        if self.before_read is not None:
            self.before_read(p, op.offset)
        if self.hold_reads_past_first and op.offset:
            for _ in range(200):
                if cancel is not None and cancel.cancelled:
                    self.cut.append(op.offset)
                    self.stopped = "the request was cut after it was sent"
                    raise RequestCanceledError("plimsoll: the request was cut after it was sent")
                time.sleep(0.01)
        if self._is_dir(p):
            return self._files_result(error="is_dir", errno="EISDIR")
        if p in self.unreadable:
            return self._files_result(error="permission_denied", errno="EACCES")
        if p in self.special:
            return self._files_result(error="not_regular", errno="ENXIO")
        if p not in self.files:
            return self._files_result(error="not_found", errno="ENOENT")
        data = self.files[p]
        return self._files_result(FilesReadAnswer(content=data[op.offset : op.offset + op.max_bytes], size_at_open=len(data)))

    def _refuse(self, mode: Optional[str]) -> None:
        if self.closed:
            raise SessionEndedError("plimsoll: this session was closed; nothing was sent", reason="closed",
                                    not_dispatched="request")
        if self.stopped is not None:
            raise PlimsollError("plimsoll: an earlier call of this session ended without an answer this client could "
                                "check; nothing was sent", code="failed_precondition", not_dispatched="request")
        if mode == "capacity":
            raise AtCapacityError("plimsoll: the daemon is at capacity; nothing ran", not_dispatched="capacity")
        if mode == "ended":
            self.ended = SessionEnded(reason="expired", detail=GUEST_TEXT)
            raise SessionEndedError("plimsoll: the session ended (lifetime)", reason="expired", not_dispatched="request")
        if mode == "unanswered":
            self.stopped = f"the connection was cut ({GUEST_TEXT})"
            raise PlimsollError(f"plimsoll: the connection was cut after the request was sent ({GUEST_TEXT})")

    def close(self) -> SessionSummary:
        self.closed += 1
        return SessionSummary(session=self.fingerprint, calls=self._n, last_record_sha256=self._last, end="closed")

    # ---- what the fake answers ----

    def _command(self, step: str, command: str, mode: Optional[str]) -> ProjectResult:
        if command.startswith("cat "):
            p = self._norm(command[4:])
            out = (self.files[p], b"", 0) if p in self.files else (b"", f"cat: {p}: No such file\n".encode(), 1)
        else:
            out = self.answers.get(command, (f"ran: {command}\n".encode(), b"", 0))
        stdout, stderr, code = out
        if mode == "timed_out":
            return self._result([self._step(step, stdout=stdout, exit_code=124, timed_out=True)], outcome="timed_out")
        if mode == "truncated":
            return self._result([self._step(step, stdout=stdout, stderr=stderr, exit_code=code, cut=True)])
        return self._result([self._step(step, stdout=stdout, stderr=stderr, exit_code=code)])

    def _norm(self, p: str) -> str:
        root = (self.work_dir or "/work") + "/"
        return p[len(root):] if p.startswith(root) else p

    def _is_dir(self, p: str) -> bool:
        return p in self.dirs or any(k.startswith(p.rstrip("/") + "/") for k in self.files)

    @staticmethod
    def _step(command: str, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0, timed_out: bool = False,
              cut: bool = False) -> StepResult:
        return StepResult(command=command, stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=timed_out,
                          duration_ms=1, stdout_truncated=cut, stderr_truncated=False)

    def _files_result(self, answer: Any = None, *, outcome: str = "completed", error: str = "none", errno: str = "") -> FilesResult:
        record = self._result([]).record
        return FilesResult(provider="fake", isolation=self.isolation, isolation_qualification=self.isolation_qualification,
                           environment="", software_identity="", duration_ms=1, record=record, outcome=outcome,
                           error=error if outcome == "completed" else "none", errno=errno, answer=answer,
                           op="" if answer is None else ("read" if isinstance(answer, FilesReadAnswer) else "write"))

    def _result(self, steps: List[StepResult], *, outcome: str = "completed", detail: str = "",
                artifacts: Optional[List[Artifact]] = None) -> ProjectResult:
        self._n += 1
        digest = hashlib.sha256(f"record {self._n}".encode()).hexdigest()
        record = RunRecord(version=5, request_sha256="0" * 64, result_sha256="1" * 64, provider="fake",
                           isolation=self.isolation, environment="", policy="", software_identity="", software_rule_id="",
                           started_unix_ms=0, ended_unix_ms=0, session=self.fingerprint, sequence=self._n,
                           previous_sha256=self._last, sha256=digest, isolation_qualification=self.isolation_qualification)
        self._last = digest
        return ProjectResult(provider="fake", isolation=self.isolation, isolation_qualification=self.isolation_qualification,
                             environment="", software_identity="", duration_ms=1, record=record, outcome=outcome,
                             detail=detail, steps=tuple(steps), artifacts=tuple(artifacts or ()), artifacts_truncated=False,
                             advice=())

    # ---- what the tests read ----

    def runs(self, kind: str) -> List[Dict[str, Any]]:
        return [e for e in self.log if e["kind"] == kind]

    def commands(self) -> List[str]:
        return [e["command"] for e in self.runs("run")]


async def _drain(stream: Any) -> bytes:
    return b"".join([p async for p in stream])


class FakeClient:
    """describe() and open_session() of a Client, handing out FakeSessions."""

    def __init__(self, *, sessions: bool = True, isolation: str = "kernel", qualification: str = "",
                 max_timeout_ms: int = 300_000, work_dir: str = "/work", file_scopes: Optional[Tuple[str, ...]] = None) -> None:
        self.supports_sessions = sessions
        self.isolation = isolation
        self.qualification = qualification
        self.work_dir = work_dir
        self.file_scopes = file_scopes
        self.max_timeout_ms = max_timeout_ms
        self.describes = 0
        self.opened: List[Dict[str, Any]] = []
        self.sessions: List[FakeSession] = []

    def describe(self, *, cancel: Any = None) -> Any:
        self.describes += 1
        return SimpleNamespace(supports_sessions=self.supports_sessions, provider="fake",
                               session_environment=SimpleNamespace(max_timeout_ms=self.max_timeout_ms))

    def open_session(self, **kwargs: Any) -> FakeSession:
        self.opened.append(kwargs)
        s = FakeSession(self.isolation, self.qualification, self.work_dir, self.file_scopes)
        self.sessions.append(s)
        return s

    @property
    def session(self) -> FakeSession:
        return self.sessions[-1]


def run(coro: Any) -> Any:
    return asyncio.run(coro)


async def opened(client: Optional[FakeClient] = None, **kwargs: Any) -> Tuple[PlimsollEnvironment, FakeSession]:
    client = client or FakeClient()
    env = PlimsollEnvironment(client, **kwargs)  # type: ignore[arg-type]
    await env.initialize()
    return env, client.session


class EnvironmentContractTests(unittest.TestCase):
    """The interface method by method, as ADK 2.15.0 states it (_base_environment.py)."""

    def test_construction_touches_nothing_and_initialize_opens_once(self) -> None:
        async def go() -> None:
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            self.assertEqual((client.describes, client.opened, env.is_initialized, env.session), (0, [], False, None))
            with self.assertRaises(RuntimeError):
                env.working_dir
            await env.initialize()
            await env.initialize()
            self.assertEqual((client.describes, len(client.opened)), (1, 1))
            self.assertEqual(client.opened[0]["minimum_isolation"], "kernel")
            self.assertEqual(env.working_dir, Path("/work"))
            self.assertTrue(env.is_initialized)
            self.assertEqual(env.calls, ())  # the work directory is the open's: no call
            await env.close()
            await env.close()
            self.assertEqual(client.session.closed, 1)
            self.assertEqual(env.close_summary.end, "closed")
            self.assertFalse(env.is_initialized)
            with self.assertRaises(RuntimeError):
                env.working_dir
            with self.assertRaises(RuntimeError):
                await env.execute("echo after close")
            # ADK's lifecycle: initialize after close starts again, in a new, empty sandbox.
            await env.initialize()
            self.assertEqual(len(client.opened), 2)
            self.assertIsNot(env.session, client.sessions[0])
        run(go())

    def test_a_session_whose_open_was_cancelled_is_closed(self) -> None:
        import threading

        async def go() -> None:
            client = FakeClient()
            entered, release = threading.Event(), threading.Event()
            opened_session = client.open_session

            def slow_open(**kwargs: Any) -> FakeSession:
                entered.set()
                release.wait(10)
                return opened_session(**kwargs)

            client.open_session = slow_open  # type: ignore[assignment]
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            task = asyncio.ensure_future(env.initialize())
            while not entered.is_set():
                await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            release.set()
            for _ in range(500):
                if client.sessions and client.sessions[0].closed:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(client.sessions[0].closed, 1)
            self.assertEqual(client.sessions[0].log, [])  # not even the work directory's call
            self.assertIsNone(env.session)
            self.assertFalse(env.is_initialized)
        run(go())

    def test_a_cancelled_open_of_a_session_without_file_calls_is_closed(self) -> None:
        # The one cancelled-open check comes after the root, so it also covers the pwd a
        # session stating no work directory (the in-memory session daemon's) is asked: the pwd, which takes no
        # cancel handle, goes out, and the session is closed after it, never kept.
        import threading

        async def go() -> None:
            client = FakeClient(work_dir="")
            entered, release = threading.Event(), threading.Event()
            opened_session = client.open_session

            def slow_open(**kwargs: Any) -> FakeSession:
                entered.set()
                release.wait(10)
                return opened_session(**kwargs)

            client.open_session = slow_open  # type: ignore[assignment]
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            task = asyncio.ensure_future(env.initialize())
            while not entered.is_set():
                await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            release.set()
            for _ in range(500):
                if client.sessions and client.sessions[0].closed:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(client.sessions[0].closed, 1)
            self.assertEqual([e["kind"] for e in client.sessions[0].log], ["pwd"])
            self.assertIsNone(env.session)
            self.assertFalse(env.is_initialized)
        run(go())

    def test_a_close_that_races_an_open_leaves_no_live_session(self) -> None:
        # release-94: close() while initialize() is opening must not return with the open still
        # on its way to publishing a live session. The open is held mid-way (open_session waits
        # on an event) while close() is called; close must wait for the open and close what it
        # opened, so once both have returned the session is closed and the environment is empty.
        import threading

        async def go() -> None:
            client = FakeClient()
            entered, release = threading.Event(), threading.Event()
            opened_session = client.open_session

            def slow_open(**kwargs: Any) -> FakeSession:
                entered.set()
                release.wait(10)
                return opened_session(**kwargs)

            client.open_session = slow_open  # type: ignore[assignment]
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            opening = asyncio.ensure_future(env.initialize())
            while not entered.is_set():
                await asyncio.sleep(0.01)
            closing = asyncio.ensure_future(env.close())
            # The open is held until close() has returned (the old code's close returns at once,
            # with nothing yet to close), or for 0.2 s when close waits for the open, as it must.
            early, _ = await asyncio.wait({closing}, timeout=0.2)
            release.set()
            await opening
            await closing
            self.assertEqual(len(client.sessions), 1)
            self.assertEqual(client.sessions[0].closed, 1, "the session the racing open made is still open")
            self.assertIsNone(env.session)
            self.assertFalse(env.is_initialized)
            self.assertEqual(early, set(), "close() returned while the open was still on its way")
            with self.assertRaises(RuntimeError):
                await env.execute("echo after close")
            self.assertEqual(env.close_summary.end, "closed")
            # As the docs state (docs/google-adk.md, "What happens when"): initialize() after
            # close() opens a new, empty sandbox, and only when called.
            self.assertEqual(len(client.opened), 1)
            await env.initialize()
            self.assertEqual(len(client.opened), 2)
            self.assertIsNot(env.session, client.sessions[0])
            await env.close()
        run(go())

    def test_open_options_reach_the_session(self) -> None:
        async def go() -> None:
            client = FakeClient()
            env = PlimsollEnvironment(client, minimum_isolation="vm", lifetime=60, idle_timeout=5, owner="user-1",  # type: ignore[arg-type]
                                      trace_id="job-1")
            client.isolation = "vm"
            await env.initialize()
            self.assertEqual(client.opened[0], {"minimum_isolation": "vm", "lifetime": 60, "idle_timeout": 5,
                                                "owner": "user-1", "trace_id": "job-1"})
        run(go())

    def test_a_daemon_without_sessions_is_refused_before_any_open(self) -> None:
        client = FakeClient(sessions=False)
        with self.assertRaises(UnsupportedError) as caught:
            run(PlimsollEnvironment(client).initialize())  # type: ignore[arg-type]
        self.assertEqual(caught.exception.not_dispatched, "unsupported")
        self.assertEqual(client.opened, [])

    def test_a_session_below_the_floor_is_closed_before_any_call(self) -> None:
        client = FakeClient(isolation="container")
        env = PlimsollEnvironment(client)  # type: ignore[arg-type]
        with self.assertRaises(InsufficientIsolationError) as caught:
            run(env.initialize())
        self.assertEqual(caught.exception.not_dispatched, "isolation")
        self.assertEqual((client.session.log, client.session.closed, env.session, env.is_initialized), ([], 1, None, False))

    def test_env_vars_are_checked_when_the_environment_is_made(self) -> None:
        for bad, error in (({"1BAD": "x"}, ValueError), ({"A-B": "x"}, ValueError), ({"OK": "a\x00b"}, ValueError),
                           ({"OK": 3}, TypeError)):
            with self.subTest(env_vars=bad), self.assertRaises(error):
                PlimsollEnvironment(FakeClient(), env_vars=bad)  # type: ignore[arg-type]

    def test_a_floor_is_required(self) -> None:
        for bad in ("", None, "strong"):
            with self.subTest(floor=bad), self.assertRaises((ValueError, PlimsollError)):
                PlimsollEnvironment(FakeClient(), minimum_isolation=bad)  # type: ignore[arg-type]

    def test_execute_is_a_new_shell_in_the_work_directory(self) -> None:
        async def go() -> None:
            env, s = await opened(env_vars={"GREETING": "it's here"})
            out = await env.execute("cd sub && echo hi")
            # The command reaches the sandbox only as a file, under the fixed run step, as
            # sh -c COMMAND: a new shell each time, nothing kept but files.
            self.assertEqual(s.commands(), ["cd sub && echo hi"])
            self.assertEqual(s.runs("run")[0]["env"], {"GREETING": shlex.quote("it's here")})
            self.assertIsInstance(out, PlimsollExecutionResult)
            self.assertEqual((out.exit_code, out.stdout, out.stderr, out.timed_out), (0, "ran: cd sub && echo hi\n", "", False))
            self.assertEqual(out.plimsoll.method, "execute")
            self.assertEqual((out.plimsoll.dispatched, out.plimsoll.outcome, out.plimsoll.isolation), ("yes", "completed", "kernel"))
            self.assertRegex(out.plimsoll.record_sha256, r"^[0-9a-f]{64}$")
            self.assertIs(out.plimsoll.record, out.execution.record)
            self.assertIs(env.calls[-1], out.plimsoll)
        run(go())

    def test_execute_budgets(self) -> None:
        async def go() -> None:
            env, s = await opened(timeout=40)
            await env.execute("a")  # None: the daemon's longest (300 s here), as ADK's "no limit"
            await env.execute("b", timeout=30)
            await env.execute("c", timeout=10_000)  # capped at the daemon's ceiling
            self.assertEqual([e["timeout"] for e in s.runs("run")], [300.0, 30.0, 300.0])
            for bad in (True, "30"):
                with self.subTest(timeout=bad), self.assertRaises(ValueError):
                    await env.execute("d", timeout=bad)  # type: ignore[arg-type]
            # No time at all: timed out at once, as LocalEnvironment gives, and nothing sent.
            for none in (0, -1):
                out = await env.execute("e", timeout=none)
                self.assertEqual((out.timed_out, out.exit_code, out.plimsoll), (True, -1, None))
            self.assertEqual(len(s.runs("run")), 3)
        run(go())
        async def no_ceiling() -> None:
            env, s = await opened(FakeClient(max_timeout_ms=0), timeout=40)
            await env.execute("a")
            self.assertEqual(s.runs("run")[0]["timeout"], 40.0)
        run(no_ceiling())

    def test_a_command_failure_is_a_result(self) -> None:
        async def go() -> None:
            env, s = await opened()
            s.answers["false"] = (b"", b"no\n", 3)
            out = await env.execute("false")
            self.assertEqual((out.exit_code, out.stderr), (3, "no\n"))
            s.fail["run"] = ["timed_out"]
            out = await env.execute("sleep 99")
            self.assertTrue(out.timed_out)
            self.assertEqual(out.plimsoll.outcome, "timed_out")
            self.assertFalse(out.plimsoll.uncertain)
        run(go())

    def test_a_cut_stream_is_said_in_stderr(self) -> None:
        async def go() -> None:
            env, s = await opened()
            s.fail["run"] = ["truncated"]
            out = await env.execute("yes")
            self.assertEqual(out.stderr, "plimsoll: the daemon cut stdout at its output limit\n")
            self.assertTrue(out.execution.steps[0].stdout_truncated)
            out = await env.execute("yes")
            self.assertEqual(out.stderr, "")
        run(go())

    def test_files_persist_between_calls(self) -> None:
        async def go() -> None:
            env, s = await opened()
            await env.write_file("notes/a.txt", "one\ntwo\n")
            await env.write_file(Path("bin/data.bin"), b"\x00\xff\x00")
            await env.write_file("nul.txt", "a\x00b")
            self.assertEqual(await env.read_file("notes/a.txt"), b"one\ntwo\n")
            self.assertEqual(await env.read_file("/work/bin/data.bin"), b"\x00\xff\x00")
            self.assertEqual(await env.read_file("nul.txt"), b"a\x00b")
            self.assertEqual((await env.execute("cat notes/a.txt")).stdout, "one\ntwo\n")
            # Text, bytes and text with a NUL each go as one file call holding their bytes.
            steps = [e for e in s.log if e["kind"] == "write"]
            self.assertEqual([e["path"] for e in steps], ["notes/a.txt", "bin/data.bin", "nul.txt"])
            self.assertEqual([c.method for c in env.calls].count("write_file"), 3)
            await env.write_file("/tmp/outside.txt", "x")
            self.assertEqual(s.files["/tmp/outside.txt"], b"x")
        run(go())

    def test_large_files_go_in_pieces(self) -> None:
        async def go() -> None:
            env, s = await opened()
            big = bytes(range(256)) * (36 * 1024 + 7)  # 9 MiB and a bit: two read pieces
            await env.write_file("big.bin", big)
            self.assertEqual(s.files["big.bin"], big)
            self.assertEqual(len([e for e in s.log if e["kind"] == "write"]), -(-len(big) // w.MAX_WRITE_BYTES))
            self.assertEqual(await env.read_file("big.bin"), big)
            pieces = [p async for p in env.read_file_stream("big.bin")]
            self.assertEqual([len(p) for p in pieces], [8 << 20, len(big) - (8 << 20)])
            # Each read states the file's size, so no read needs a call to measure it.
            self.assertEqual([e["path"] for e in s.runs("read")], ["big.bin"] * 4)
            await env.write_file("eight.bin", b"8" * (8 << 20))  # exactly one piece's worth
            self.assertEqual(len(await env.read_file("eight.bin")), 8 << 20)
            text = "é" * (3 << 20)  # 6 MiB of UTF-8: past one write's 4 MiB, so two calls
            before = len(s.runs("write"))
            await env.write_file("big.txt", text)
            self.assertEqual(s.files["big.txt"], text.encode("utf-8"))
            self.assertEqual(len(s.runs("write")) - before, 2)
            await env.write_file("empty", "")
            self.assertEqual([p async for p in env.read_file_stream("empty")], [])
            # Finding release-46: a file past the whole-read limit (64 MiB; a sparse one
            # costs a sandbox nothing) is refused after its first piece, by both reads.
            s.files["huge.bin"] = bytes(w.MAX_WHOLE_BYTES + 1)
            before = len([e for e in s.log if e["kind"] == "read"])
            with self.assertRaises(w.WorkspaceTooLargeError):
                await env.read_file("huge.bin")
            with self.assertRaises(w.WorkspaceTooLargeError):
                _ = [p async for p in env.read_file_stream("huge.bin")]
            self.assertEqual(len([e for e in s.log if e["kind"] == "read"]) - before, 2)  # one piece for each
            self.assertEqual(await env.read_file("empty"), b"")
        run(go())

    def test_a_file_that_changes_while_it_is_read_is_an_error(self) -> None:
        async def go() -> None:
            env, s = await opened()
            big = b"x" * ((8 << 20) + 10)
            for name, change in (("grew", lambda p: s.files.__setitem__(p, s.files[p] + b"more")),
                                 ("shrank", lambda p: s.files.__setitem__(p, b"short")),
                                 ("removed", lambda p: s.files.pop(p))):
                s.before_read = lambda p, offset, change=change: change(p) if offset else None
                for read in (env.read_file, lambda p: _drain(env.read_file_stream(p))):
                    s.files["big.bin"] = big
                    with self.subTest(change=name, read=read), self.assertRaises(OSError) as caught:
                        await read("big.bin")
                    self.assertNotIsInstance(caught.exception, FileNotFoundError)
                    self.assertIn("while it was read", str(caught.exception))
            s.before_read = None
        run(go())

    def test_cancelling_a_stream_cuts_the_piece_in_flight(self) -> None:
        async def go() -> None:
            env, s = await opened()
            s.files["big.bin"] = b"x" * ((8 << 20) + 10)
            s.hold_reads_past_first = True

            async def consume() -> None:
                async for _ in env.read_file_stream("big.bin"):
                    pass

            task = asyncio.ensure_future(consume())
            for _ in range(200):
                if len(s.runs("read")) == 2:
                    break
                await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            for _ in range(200):
                if s.cut:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(s.cut, [8 << 20])
        run(go())

    def test_a_failed_read_says_why(self) -> None:
        async def go() -> None:
            env, s = await opened()
            s.files["d/f"] = b"x"
            s.files["secret"] = b"x"
            s.unreadable.add("secret")
            for read in (env.read_file, lambda p: _drain(env.read_file_stream(p))):
                with self.assertRaises(FileNotFoundError):
                    await read("missing")
                with self.assertRaises(IsADirectoryError):
                    await read("d")
                with self.assertRaises(PermissionError):
                    await read("secret")
            s.special.add("fifo")
            with self.assertRaises(OSError) as caught:
                await env.read_file("fifo")
            self.assertEqual((type(caught.exception), caught.exception.errno), (OSError, errno.ENXIO))
            # The file call's own answer says why: each failed read is one read and nothing else.
            self.assertEqual({e["kind"] for e in s.log}, {"read"})
            self.assertEqual(len(s.log), 7)
        run(go())

    def test_paths(self) -> None:
        async def go() -> None:
            env, s = await opened()
            for bad in ("../escape", "a/../../escape", ".plimsoll-shell/cmd", "/work/.plimsoll-shell/cwd", "a\nb"):
                with self.subTest(path=bad), self.assertRaises(ValueError):
                    await env.write_file(bad, "x")
            with self.assertRaises(TypeError):
                await env.write_file(3, "x")  # type: ignore[arg-type]
            with self.assertRaises(TypeError):
                await env.write_file("a", 3)  # type: ignore[arg-type]
            with self.assertRaises(TypeError):
                await env.execute(b"echo")  # type: ignore[arg-type]
            with self.assertRaises(ValueError):
                await env.execute("echo \x00")
            self.assertEqual(s.log, [])
        run(go())

    def test_a_write_error_is_the_one_its_answer_names(self) -> None:
        # Each error the file call's answer names reaches ADK as its own OSError, with its
        # errno and the path as given: a full or read-only disk too (the shell-text matching
        # this replaced read their words off the end of a message that ends with the path,
        # and gave EIO), and never any text of the sandbox's.
        async def go() -> None:
            env, s = await opened()
            s.files["plain"] = b"x"
            s.dirs.add("folder")
            cases = [("write_denied", "a.bin", PermissionError, errno.EACCES),
                     ("no_space", "a.bin", OSError, errno.ENOSPC),
                     ("read_only", "a.bin", OSError, errno.EROFS),
                     ("other", "a.bin", OSError, errno.EIO),
                     (None, "folder", IsADirectoryError, errno.EISDIR),
                     (None, "plain/under", NotADirectoryError, errno.ENOTDIR)]
            for mode, path, cls, code in cases:
                s.fail["write"] = [mode] if mode else []
                with self.subTest(mode=mode, path=path), self.assertRaises(OSError) as caught:
                    await env.write_file(path, b"x")
                e = caught.exception
                self.assertEqual((type(e), e.errno, e.filename), (cls, code, path))
                self.assertNotIn(GUEST_TEXT, str(e))
                # Answered: the call ran, completed, and is noted with its record.
                c = env.calls[-1]
                self.assertEqual((c.method, c.dispatched, c.outcome, c.uncertain), ("write_file", "yes", "completed", False))
                self.assertRegex(c.record_sha256, r"^[0-9a-f]{64}$")
            self.assertEqual({e["kind"] for e in s.log}, {"write"})
            self.assertEqual(len(s.log), len(cases))
        run(go())

    def test_what_adks_file_tools_answer_for_each_error(self) -> None:
        # The tool answer the model sees: ADK's ReadFileTool and WriteFileTool turn the error
        # into {"status": "error", "error": str(e)}; the text holds the model's own path and
        # the error's words, never anything of the sandbox's. EditFileTool lets a write's
        # error rise (ADK records it on the tool's span), with the same text.
        async def go() -> None:
            env, s = await opened()
            s.files["plain"] = b"x"
            s.files["secret"] = b"x"
            s.unreadable.add("secret")
            s.dirs.add("folder")
            s.special.add("fifo")
            tools = ToolsAgainstLocalEnvironmentTests.tools(env)
            read = lambda path: tools["ReadFile"].run_async(args={"path": path}, tool_context=None)
            write = lambda path: tools["WriteFile"].run_async(args={"path": path, "content": "x"}, tool_context=None)
            answers = {
                "missing": await read("missing"),
                "folder": await read("folder"),
                "secret": await read("secret"),
                "fifo": await read("fifo"),
                "write folder": await write("folder"),
                "write under a file": await write("plain/under"),
            }
            self.assertEqual(answers, {
                "missing": {"status": "error", "error": "File not found: missing"},
                "folder": {"status": "error", "error": "[Errno 21] Is a directory: 'folder'"},
                "secret": {"status": "error", "error": "[Errno 13] Permission denied: 'secret'"},
                "fifo": {"status": "error", "error": "[Errno 6] Not a regular file or a directory: 'fifo'"},
                "write folder": {"status": "error", "error": "[Errno 21] Is a directory: 'folder'"},
                "write under a file": {"status": "error", "error": "[Errno 20] Not a directory: 'plain/under'"},
            })
            s.fail["write"] = ["no_space"]
            with self.assertRaises(OSError) as caught:
                await tools["EditFile"].run_async(args={"path": "plain", "old_string": "x", "new_string": "y"}, tool_context=None)
            self.assertEqual(str(caught.exception), "[Errno 28] No space left on device: 'plain'")
            self.assertEqual(s.files["plain"], b"x")
        run(go())

    def test_a_session_without_file_calls_asks_pwd_once_and_refuses_its_files(self) -> None:
        # A session that takes no file calls (the in-memory session daemon's, a daemon from
        # before file calls) states no work_dir: the open asks it once, by running pwd, commands
        # work, and every read and write is the daemon's refusal, marked not dispatched, as it came.
        async def go() -> None:
            client = FakeClient(work_dir="")
            env, s = await opened(client)
            self.assertEqual(env.working_dir, Path("/work"))
            self.assertEqual([e["kind"] for e in s.log], ["pwd"])
            self.assertEqual([c.method for c in env.calls], ["initialize"])
            self.assertEqual((await env.execute("echo hi")).stdout, "ran: echo hi\n")
            for call in (env.read_file("a"), _drain(env.read_file_stream("a")), env.write_file("a", "x")):
                with self.assertRaises(UnsupportedError) as caught:
                    await call
                self.assertEqual(caught.exception.not_dispatched, "unsupported")
            self.assertEqual([e["kind"] for e in s.log], ["pwd", "run", "refused read", "refused read", "refused write"])
            self.assertEqual([c.dispatched for c in env.calls[2:]], ["no"] * 3)
            # Every session that takes file calls states its work directory: the open makes no call.
            env2, s2 = await opened()
            self.assertEqual((env2.working_dir, s2.log, env2.calls), (Path("/work"), [], ()))
        run(go())

    def test_an_openshell_session_reads_and_writes_in_the_sandbox_scope_under_its_work_folder(self) -> None:
        # OpenShell's sessions (D94 D) state their work folder and the sandbox scope alone: the open
        # makes no call, and ADK's file tools are file calls in the sandbox scope, each naming the
        # absolute path under /tmp/work, as on every provider (the environment's workspace is
        # unconfined), never refused for the scope.
        async def go() -> None:
            env, s = await opened(FakeClient(work_dir="/tmp/work", file_scopes=("sandbox",)))
            self.assertEqual((env.working_dir, s.log, env.calls), (Path("/tmp/work"), [], ()))
            await env.write_file("notes/a.txt", "one")
            self.assertEqual(await env.read_file("notes/a.txt"), b"one")
            self.assertEqual(await env.read_file("/tmp/work/notes/a.txt"), b"one")
            self.assertEqual([(e["kind"], e["path"]) for e in s.log],
                             [("write", "notes/a.txt"), ("read", "notes/a.txt"), ("read", "notes/a.txt")])
            self.assertEqual([c.dispatched for c in env.calls], ["yes"] * 3)
            self.assertEqual(s.files, {"notes/a.txt": b"one"})
        run(go())

    def test_a_refusal_comes_as_it_came_and_is_noted(self) -> None:
        async def go() -> None:
            env, s = await opened()
            s.fail["run"] = ["capacity"]
            with self.assertRaises(AtCapacityError) as caught:
                await env.execute("echo")
            self.assertEqual(caught.exception.not_dispatched, "capacity")
            c = env.calls[-1]
            self.assertEqual((c.method, c.dispatched, c.refused, c.uncertain, c.record), ("execute", "no", "capacity", False, None))
            self.assertEqual(c.labels(), {"plimsoll_dispatched": "no", "plimsoll_refused": "capacity"})
        run(go())

    def test_an_incomplete_answer_raises_without_its_detail(self) -> None:
        async def go() -> None:
            env, s = await opened()
            for mode, outcome in (("runner_failed", "runner_failed"), ("runner_failed_after_step", "runner_failed"),
                                  ("protocol_error", "protocol_error")):
                s.fail["run"] = [mode]
                with self.subTest(mode=mode), self.assertRaises(PlimsollEnvironmentError) as caught:
                    await env.execute("echo once >> log")
                e = caught.exception
                self.assertIsNone(e.not_dispatched)
                self.assertTrue(e.call.uncertain)
                self.assertEqual((e.call.dispatched, e.call.outcome), ("yes", outcome))
                self.assertEqual(e.execution.outcome, outcome)
                self.assertIn("may have run", str(e))
                self.assertNotIn(GUEST_TEXT, str(e))
                self.assertIsNone(e.__cause__)
                self.assertTrue(e.__suppress_context__)
            s.fail["run"] = ["setup_failed"]
            with self.assertRaises(PlimsollEnvironmentError) as caught:
                await env.execute("echo once >> log")
            self.assertFalse(caught.exception.call.uncertain)
            self.assertIn("nothing of it ran", str(caught.exception))
            # A file call has no setup: one the helper did not answer may have run.
            s.fail["write"] = ["runner_failed"]
            with self.assertRaises(PlimsollEnvironmentError) as caught:
                await env.write_file("a", "x")
            self.assertTrue(caught.exception.call.uncertain)
            self.assertEqual(caught.exception.execution.outcome, "runner_failed")
            self.assertIn("may have run", str(caught.exception))
        run(go())

    def test_no_answer_is_noted_as_unknown(self) -> None:
        async def go() -> None:
            env, s = await opened()
            s.fail["read"] = ["unanswered"]
            with self.assertRaises(PlimsollError) as caught:
                await env.read_file("a")
            self.assertIsNone(caught.exception.not_dispatched)
            c = env.calls[-1]
            self.assertEqual((c.method, c.dispatched, c.uncertain), ("read_file", "unknown", True))
            self.assertEqual(c.labels(), {"plimsoll_dispatched": "unknown"})
        run(go())

    def test_an_ended_session_is_never_replaced(self) -> None:
        async def go() -> None:
            client = FakeClient()
            env, s = await opened(client)
            s.fail["run"] = ["ended"]
            with self.assertRaises(SessionEndedError):
                await env.execute("echo")
            # The environment let the ended session go (closed, so the daemon's place is
            # free) and says so on every later call, with the daemon's reason and none of
            # its detail; nothing opens in its place.
            for call in (env.initialize(), env.execute("echo"), env.read_file("a"), env.write_file("a", "x")):
                with self.assertRaises(SessionEndedError) as caught:
                    await call
                e = caught.exception
                self.assertEqual((e.reason, e.not_dispatched), ("expired", "request"))
                self.assertIn("was lost", str(e))
                self.assertNotIn(GUEST_TEXT, str(e))
            self.assertEqual(len(client.opened), 1)
            self.assertEqual((s.closed, len(s.runs("run"))), (1, 1))
            self.assertIsNone(env.session)
            self.assertTrue(env.is_initialized)  # so ADK's close of the toolset reaches close()
        run(go())

    def test_labels_keep_only_their_closed_sets(self) -> None:
        good = PlimsollCall(method="execute", function_call_id=None, dispatched="yes", outcome="completed",
                            isolation="vm", isolation_qualification="Microsoft states that WSL is not a security sandbox.",
                            record=FakeSession()._result([]).record)
        self.assertEqual(set(good.labels()), {"plimsoll_dispatched", "plimsoll_outcome", "plimsoll_isolation",
                                              "plimsoll_isolation_qualification", "plimsoll_record_sha256"})
        bad = PlimsollCall(method="execute", function_call_id=None, dispatched="yes", outcome=GUEST_TEXT,
                           isolation=GUEST_TEXT, isolation_qualification="line\nbreak " + GUEST_TEXT)
        self.assertEqual(bad.labels(), {"plimsoll_dispatched": "yes"})

    def test_the_guard_untags_once_the_tool_call_is_over(self) -> None:
        from plimsoll_client import adk

        async def go() -> None:
            guard = PlimsollEnvironmentGuard()
            ctx = SimpleNamespace(function_call_id="adk-1", user_id="u", session=SimpleNamespace(app_name="app"))
            await guard.before_tool_callback(tool=None, tool_args={}, tool_context=ctx)
            self.assertEqual((adk._TOOL_CALL.get().function_call_id, adk._TOOL_CALL.get().owner), ("adk-1", ("app", "u")))
            await guard.after_tool_callback(tool=None, tool_args={}, tool_context=ctx, result={})
            self.assertIsNone(adk._TOOL_CALL.get())
            await guard.before_tool_callback(tool=None, tool_args={}, tool_context=ctx)
            await guard.on_tool_error_callback(tool=None, tool_args={}, tool_context=ctx, error=ValueError("x"))
            self.assertIsNone(adk._TOOL_CALL.get())
        run(go())

    def test_a_later_adk_ctx_names_the_tool_call(self) -> None:
        async def go() -> None:
            env, s = await opened()
            await env.execute("echo", ctx=SimpleNamespace(function_call_id="adk-123"))
            await env.write_file("a", "x", ctx=SimpleNamespace(function_call_id="adk-124"))
            self.assertEqual([c.function_call_id for c in env.calls], ["adk-123", "adk-124"])
            self.assertEqual([e["trace_id"] for e in s.log], ["adk-123", "adk-124"])
        run(go())


class ToolsAgainstLocalEnvironmentTests(unittest.TestCase):
    """ADK's own file tools over PlimsollEnvironment answer as they do over ADK's
    LocalEnvironment, for the same script. The local environment only reads and writes
    files in a temporary directory here; no command runs on this host."""

    SCRIPT: List[Tuple[str, Dict[str, Any]]] = [
        ("WriteFile", {"path": "notes/a.txt", "content": "one\ntwo\nthree\n"}),
        ("ReadFile", {"path": "notes/a.txt"}),
        ("ReadFile", {"path": "notes/a.txt", "start_line": 2, "end_line": 2}),
        ("ReadFile", {"path": "notes/a.txt", "start_line": 9}),
        ("EditFile", {"path": "notes/a.txt", "old_string": "two", "new_string": "2"}),
        ("ReadFile", {"path": "notes/a.txt"}),
        ("WriteFile", {"path": "deep/er/b.txt", "content": "x x\n"}),
        ("EditFile", {"path": "deep/er/b.txt", "old_string": "x", "new_string": "y"}),
        ("EditFile", {"path": "deep/er/b.txt", "old_string": "absent", "new_string": "y"}),
        ("EditFile", {"path": "missing.txt", "old_string": "a", "new_string": "b"}),
        ("ReadFile", {"path": "missing.txt"}),
        ("WriteFile", {"path": "empty.txt", "content": ""}),
        ("ReadFile", {"path": "empty.txt"}),
        ("ReadFile", {"path": ""}),
    ]

    @staticmethod
    def tools(env: Any) -> Dict[str, Any]:
        return {t.name: t for t in (ReadFileTool(env), EditFileTool(env), WriteFileTool(env), ExecuteTool(env))}

    async def play(self, env: Any) -> List[Any]:
        tools = self.tools(env)
        return [await tools[name].run_async(args=dict(args), tool_context=None) for name, args in self.SCRIPT]

    def test_the_same_script_gives_the_same_answers(self) -> None:
        async def go() -> None:
            scratch = Path(__file__).resolve().parents[4] / "tmp"  # the repository's own scratch directory
            scratch.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(dir=scratch) as d:
                local = LocalEnvironment(working_dir=Path(d))
                await local.initialize()
                expected = await self.play(local)
            env, s = await opened()
            got = await self.play(env)
            for (name, args), want, have in zip(self.SCRIPT, expected, got):
                with self.subTest(tool=name, args=args):
                    self.assertEqual(have, want)
            self.assertEqual(s.files["notes/a.txt"], b"one\n2\nthree\n")
        run(go())


class ToolModel(BaseLlm):
    """A scripted model: ``plan(responses, turn)`` gives the next answer, a list of
    (tool name, arguments) calls or a string of plain text, from the function responses
    the last request carries."""

    model: str = "offline-scripted-tools"
    plan: Any = Field(default=None, exclude=True)
    requests: List[Any] = Field(default_factory=list, exclude=True)

    async def generate_content_async(self, llm_request: Any, stream: bool = False):  # type: ignore[override]
        self.requests.append(llm_request)
        last = llm_request.contents[-1] if llm_request.contents else None
        responses = [p.function_response.response for p in (last.parts or []) if p.function_response] if last else []
        step = self.plan(responses, len(self.requests) - 1)
        if isinstance(step, str):
            parts = [types.Part(text=step)]
        else:
            parts = [types.Part(function_call=types.FunctionCall(name=n, args=a)) for n, a in step]
        yield LlmResponse(content=types.Content(role="model", parts=parts))


def scripted(*turns: Any) -> ToolModel:
    def plan(responses: List[Any], turn: int) -> Any:
        return turns[turn] if turn < len(turns) else "done"
    return ToolModel(plan=plan)


async def run_agent(env: PlimsollEnvironment, model: ToolModel, plugins: List[Any], *, user: str = "user",
                    app: str = "adk-env-test", sessions: Optional[InMemorySessionService] = None) -> List[Any]:
    agent = Agent(name="worker", model=model, tools=[EnvironmentToolset(environment=env)])
    sessions = sessions or InMemorySessionService()
    session = await sessions.create_session(app_name=app, user_id=user)
    runner = Runner(agent=agent, app_name=app, session_service=sessions, plugins=plugins)
    return [e async for e in runner.run_async(user_id=user, session_id=session.id,
                                              new_message=types.Content(role="user", parts=[types.Part(text="Work.")]))]


def responses_of(events: List[Any]) -> List[Any]:
    return [p.function_response for e in events for p in (e.content.parts if e.content else []) or [] if p.function_response]


class RunnerTests(unittest.TestCase):
    """A scripted agent through ADK's real Runner and EnvironmentToolset."""

    def setUp(self) -> None:
        SPANS.clear()

    def test_an_agent_keeps_its_files_across_calls_and_each_call_is_labeled(self) -> None:
        async def go() -> None:
            client = FakeClient(qualification="Microsoft states that WSL is not a security sandbox.")
            env = PlimsollEnvironment(client, minimum_isolation="kernel")  # type: ignore[arg-type]
            model = scripted(
                [("WriteFile", {"path": "hello.txt", "content": "hello\n"})],
                [("Execute", {"command": "cat hello.txt"})],
                [("EditFile", {"path": "hello.txt", "old_string": "hello", "new_string": "goodbye"})],
                [("ReadFile", {"path": "hello.txt"}), ("Execute", {"command": "cat hello.txt"})],
                "finished",
            )
            events = await run_agent(env, model, [PlimsollEnvironmentGuard()])
            s = client.session
            self.assertEqual(s.files["hello.txt"], b"goodbye\n")
            answers = {r.id: r.response for r in responses_of(events)}
            self.assertEqual(len(answers), 5)
            outputs = [r["stdout"] for r in answers.values() if "stdout" in r]
            self.assertEqual(outputs, ["hello\n", "goodbye\n"])
            # ADK 2.15 builds the toolset's instruction without initializing the environment
            # (_environment_toolset.py:121), and working_dir is unknown until the session is
            # open, so the first request names no work directory; once the first tool call has
            # opened the session, every later request does.
            self.assertNotIn("/work/", str(model.requests[0].config.system_instruction))
            self.assertIn("/work/", str(model.requests[1].config.system_instruction))
            # Every call serves one ADK tool call, names it, and sent its ID to the daemon as
            # the trace ID (the work directory is the open's, so no call comes before them).
            calls = env.calls
            self.assertEqual({c.function_call_id for c in calls}, set(answers))
            self.assertEqual([e["trace_id"] for e in s.log], [c.function_call_id for c in calls])
            # ADK's own span for each tool call carries plimsoll's labels, one per call.
            # (ADK adds one more span over calls made in parallel, "execute_tool (merged)".)
            spans = {sp.attributes.get("gen_ai.tool.call.id"): sp for sp in SPANS.get_finished_spans()
                     if sp.name.startswith("execute_tool ") and sp.name != "execute_tool (merged)"}
            self.assertEqual(set(spans), set(answers))
            for call_id, span in spans.items():
                mine = [c for c in calls if c.function_call_id == call_id]
                attrs = span.attributes
                self.assertEqual(attrs["plimsoll_calls"], len(mine))
                self.assertEqual(list(attrs["plimsoll_record_sha256"]), [c.record_sha256 for c in mine])
                self.assertEqual(set(attrs["plimsoll_isolation"]), {"kernel"})
                self.assertEqual(set(attrs["plimsoll_isolation_qualification"]),
                                 {"Microsoft states that WSL is not a security sandbox."})
                self.assertEqual(set(attrs["plimsoll_dispatched"]), {"yes"})
                self.assertEqual(set(attrs["plimsoll_outcome"]), {"completed"})
                for key in _langsmith.KEYS:
                    for value in attrs[key]:
                        self.assertNotIn(GUEST_TEXT, value)
            edit = next(sp for sp in spans.values() if sp.name == "execute_tool EditFile")
            self.assertEqual(edit.attributes["plimsoll_calls"], 2)  # its read, then its write
        run(go())

    def test_labels_never_carry_guest_text(self) -> None:
        async def go() -> None:
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            await env.initialize()
            client.session.isolation = GUEST_TEXT  # a tier this client does not know
            client.session.isolation_qualification = "a\nb" + GUEST_TEXT
            model = scripted([("Execute", {"command": "echo"})], "done")
            await run_agent(env, model, [PlimsollEnvironmentGuard()])
            span = next(sp for sp in SPANS.get_finished_spans() if sp.name == "execute_tool Execute")
            self.assertEqual(list(span.attributes["plimsoll_isolation"]), [""])
            self.assertEqual(list(span.attributes["plimsoll_isolation_qualification"]), [""])
            for key in _langsmith.KEYS:
                for value in span.attributes[key]:
                    self.assertNotIn(GUEST_TEXT, value)
                    self.assertTrue(value == "" or value in TIERS + OUTCOME_NAMES + REFUSAL_NAMES + ("yes", "no", "unknown")
                                    or len(value) == 64)
        run(go())

    @staticmethod
    def rerun_on_error(tool: str, args: Dict[str, Any]) -> ToolModel:
        """A model that does what ADK's error answer invites: when a call fails, it makes
        the same call again, once."""
        def plan(responses: List[Any], turn: int) -> Any:
            if turn == 0:
                return [(tool, args)]
            failed = any(r.get("status") == "error" or "reflection_guidance" in r for r in responses)
            return [(tool, args)] if failed and turn == 1 else "done"
        return ToolModel(plan=plan)

    def test_without_the_guard_a_model_runs_an_uncertain_command_again(self) -> None:
        async def go() -> None:
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            await env.initialize()
            client.session.fail["run"] = ["runner_failed"]
            events = await run_agent(env, self.rerun_on_error("Execute", {"command": "echo paid >> ledger"}), [])
            # ADK handed the model the error (_execute_tool.py:108) and the command ran twice.
            self.assertEqual(client.session.commands(), ["echo paid >> ledger", "echo paid >> ledger"])
            first = responses_of(events)[0].response
            self.assertEqual(first["status"], "error")
            self.assertIn("may have run", first["error"])
        run(go())

    def test_the_guard_stops_the_agent_after_an_uncertain_command(self) -> None:
        async def go() -> None:
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            await env.initialize()
            client.session.fail["run"] = ["runner_failed"]
            with self.assertRaises(RuntimeError) as caught:
                await run_agent(env, self.rerun_on_error("Execute", {"command": "echo paid >> ledger"}),
                                [PlimsollEnvironmentGuard()])
            self.assertEqual(client.session.commands(), ["echo paid >> ledger"])
            stop = caught.exception.__cause__
            self.assertIsInstance(stop, PlimsollEnvironmentError)
            self.assertTrue(stop.call.uncertain)
            self.assertIsNone(stop.not_dispatched)
            self.assertNotIn(GUEST_TEXT, str(caught.exception))
            span = next(sp for sp in SPANS.get_finished_spans() if sp.name == "execute_tool Execute")
            self.assertEqual(list(span.attributes["plimsoll_outcome"]), ["runner_failed"])
        run(go())

    def test_with_adks_retry_plugin_an_uncertain_write_is_written_again_and_the_guard_stops_it(self) -> None:
        async def go(plugins: List[Any], mode: str = "runner_failed") -> FakeSession:
            SPANS.clear()
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            await env.initialize()
            client.session.files["a.txt"] = b"count = 1\n"
            client.session.fail["write"] = [mode]
            model = self.rerun_on_error("EditFile", {"path": "a.txt", "old_string": "1", "new_string": "2"})
            try:
                await run_agent(env, model, plugins)
            except RuntimeError as e:
                self.assertIsInstance(e.__cause__, PlimsollEnvironmentError)
                self.assertNotIn(GUEST_TEXT, str(e))
            return client.session
        # EditFileTool does not catch a write's error (_edit_file_tool.py:154), so ADK's
        # ReflectAndRetryToolPlugin answers it by asking the model to try again. An answer
        # without a complete report leaves the session open, so the write goes again.
        s = run(go([ReflectAndRetryToolPlugin()]))
        self.assertEqual(len(s.runs("write")), 2)
        s = run(go([PlimsollEnvironmentGuard(), ReflectAndRetryToolPlugin()]))
        self.assertEqual(len(s.runs("write")), 1)
        # No answer at all stops the client's session: the environment lets the sandbox go,
        # and the retry is refused before anything reaches the session.
        s = run(go([ReflectAndRetryToolPlugin()], "unanswered"))
        self.assertEqual((len(s.runs("write")), s.closed), (1, 1))
        s = run(go([PlimsollEnvironmentGuard(), ReflectAndRetryToolPlugin()], "unanswered"))
        self.assertEqual(len(s.runs("write")), 1)
        # ADK records the error that ended the run on its span, with its chain: the
        # guard's error carries neither the tool's error nor its text.
        recorded = [str(ev.attributes) for sp in SPANS.get_finished_spans() for ev in sp.events if ev.name == "exception"]
        self.assertTrue(any("the agent was stopped" in r for r in recorded))
        for r in recorded:
            self.assertNotIn(GUEST_TEXT, r)

    def test_a_refusal_reaches_the_model_and_the_agent_goes_on(self) -> None:
        async def go() -> None:
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            await env.initialize()
            client.session.fail["run"] = ["capacity"]
            events = await run_agent(env, self.rerun_on_error("Execute", {"command": "echo"}), [PlimsollEnvironmentGuard()])
            answers = [r.response for r in responses_of(events)]
            self.assertEqual(answers[0]["status"], "error")
            self.assertEqual(answers[1], {"status": "ok", "stdout": "ran: echo\n"})
            self.assertEqual([c.dispatched for c in env.calls], ["no", "yes"])
        run(go())

    def test_the_guard_keeps_a_sandbox_to_one_user(self) -> None:
        async def go() -> None:
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            sessions = InMemorySessionService()
            await run_agent(env, scripted([("WriteFile", {"path": "mine.txt", "content": "alice's"})], "done"),
                            [PlimsollEnvironmentGuard()], user="alice", sessions=sessions)
            # The same user in another conversation shares the sandbox (one person, one domain).
            await run_agent(env, scripted([("ReadFile", {"path": "mine.txt"})], "done"),
                            [PlimsollEnvironmentGuard()], user="alice", sessions=sessions)
            before = len(client.session.log)
            events = await run_agent(env, scripted([("ReadFile", {"path": "mine.txt"}), ("Execute", {"command": "ls"})],
                                                   "done"), [PlimsollEnvironmentGuard()], user="mallory", sessions=sessions)
            self.assertEqual(len(client.session.log), before)  # nothing was sent
            for r in responses_of(events):
                self.assertEqual(r.response["status"], "error")
                self.assertIn("belongs to another ADK user", r.response["error"])
            # Closed and opened again, the environment holds a new sandbox for whoever comes first.
            await env.close()
            await run_agent(env, scripted([("Execute", {"command": "ls"})], "done"), [PlimsollEnvironmentGuard()],
                            user="mallory", sessions=sessions)
            self.assertEqual(client.sessions[-1].commands(), ["ls"])
            self.assertNotIn("mine.txt", client.sessions[-1].files)
        run(go())


class AgentToolTests(unittest.TestCase):
    """ADK runs an AgentTool's agent in a nested Runner (agent_tool.py:339) that closes that
    agent's toolsets when its run ends, and a toolset's close closes its environment
    (_environment_toolset.py:152). So one environment shared by an agent and the agent it
    wraps is closed when the wrapped agent finishes, as ADK's guide warns of two toolsets
    sharing one environment. ADK 2.15 initializes the environment before every tool call
    (_utils.py, ensure_initialized), so the wrapping agent's next call would open a new,
    empty sandbox: the environment refuses it. These cases hold what the docs say about it."""

    @staticmethod
    async def lead(lead_env: PlimsollEnvironment, child_env: PlimsollEnvironment, children: int = 1) -> Any:
        from google.adk.tools.agent_tool import AgentTool

        child = Agent(name="writer", description="Writes the file.",
                      model=ToolModel(plan=lambda responses, turn: "written" if responses
                                      else [("WriteFile", {"path": "from-child.txt", "content": "child\n"})]),
                      tools=[EnvironmentToolset(environment=child_env)])
        model = ToolModel(plan=lambda responses, turn: [("writer", {"request": "write it"})] if turn < children
                          else [("Execute", {"command": "echo lead"})] if turn == children else "done")
        agent = Agent(name="lead", model=model, tools=[AgentTool(agent=child), EnvironmentToolset(environment=lead_env)])
        sessions = InMemorySessionService()
        session = await sessions.create_session(app_name="adk-env-test", user_id="user")
        runner = Runner(agent=agent, app_name="adk-env-test", session_service=sessions, plugins=[PlimsollEnvironmentGuard()])
        try:
            return [e async for e in runner.run_async(user_id="user", session_id=session.id,
                                                      new_message=types.Content(role="user", parts=[types.Part(text="Go.")]))]
        except Exception as e:
            return e

    def test_a_wrapped_agent_with_an_environment_of_its_own_works(self) -> None:
        lead, child = FakeClient(), FakeClient()
        events = run(self.lead(PlimsollEnvironment(lead), PlimsollEnvironment(child)))  # type: ignore[arg-type]
        self.assertIsInstance(events, list)
        self.assertEqual(child.sessions[0].files["from-child.txt"], b"child\n")
        self.assertEqual(child.sessions[0].closed, 1)  # its nested Runner closed it when it finished
        self.assertEqual(lead.session.commands(), ["echo lead"])
        self.assertEqual(lead.session.closed, 0)

    def test_a_wrapped_agent_with_an_environment_of_its_own_can_be_called_again(self) -> None:
        # Each AgentTool call is an invocation of its own, in an empty ADK session, so the
        # wrapped agent's second call opens a sandbox of its own: only the invocation that
        # used a closed session is held to it, not every invocation under the same lead.
        lead, child = FakeClient(), FakeClient()
        events = run(self.lead(PlimsollEnvironment(lead), PlimsollEnvironment(child), children=2))  # type: ignore[arg-type]
        self.assertIsInstance(events, list)
        self.assertEqual([s.closed for s in child.sessions], [1, 1])
        self.assertEqual([s.files.get("from-child.txt") for s in child.sessions], [b"child\n", b"child\n"])
        self.assertEqual(lead.session.commands(), ["echo lead"])

    def test_an_environment_shared_with_a_wrapped_agent_refuses_the_wrapping_agent_once_closed(self) -> None:
        # The wrapped agent's nested Runner closes the shared environment when it finishes;
        # the lead's next call is refused, marked not dispatched, and no second sandbox is
        # opened in place of the one that held the wrapped agent's file. The refusal ends
        # the invocation: ADK's tools call initialize outside their own try (_execute_tool.py:97),
        # and the Runner raises it as it came.
        client = FakeClient()
        env = PlimsollEnvironment(client)  # type: ignore[arg-type]
        events = run(self.lead(env, env))
        self.assertIsInstance(events, SessionEndedError, repr(events))
        refusal = events
        self.assertEqual((refusal.reason, refusal.not_dispatched), ("closed", "request"))
        self.assertIn("give the wrapped agent an environment of its own", str(refusal))
        self.assertEqual(len(client.sessions), 1)  # no empty sandbox was put in its place
        self.assertEqual(client.sessions[0].files["from-child.txt"], b"child\n")
        self.assertEqual(client.sessions[0].closed, 1)
        self.assertEqual(client.sessions[0].commands(), [])
        self.assertIsNone(env.session)

        # A new invocation (the next turn of the conversation, or another Runner) is not
        # held to the closed session: it opens a new sandbox, as ADK's lifecycle has it.
        events = run(run_agent(env, scripted([("Execute", {"command": "echo again"})], "done"), [PlimsollEnvironmentGuard()]))
        self.assertEqual(responses_of(events)[0].response, {"status": "ok", "stdout": "ran: echo again\n"})
        self.assertEqual(len(client.sessions), 2)
        self.assertEqual(client.sessions[1].commands(), ["echo again"])


class InvocationHoldTests(unittest.TestCase):
    """The rule under the refusal, with ctx objects shaped as ADK's (invocation_id, and the
    wrapping invocation an AgentTool records)."""

    @staticmethod
    def ctx(invocation: str, parent: Optional[str] = None, call: str = "adk-1") -> Any:
        return SimpleNamespace(function_call_id=call, invocation_id=invocation,
                               _invocation_context=SimpleNamespace(_parent_invocation_id=parent))

    def test_an_invocation_never_joins_a_session_that_replaced_its_own(self) -> None:
        # Two conversations of one user share the environment; one's session is closed and
        # the other opens a new one: the first is refused there too, since it would find
        # none of its files.
        async def go() -> None:
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            await env.initialize(ctx=self.ctx("e-first"))
            await env.write_file("mine.txt", "first", ctx=self.ctx("e-first"))
            await env.close()
            await env.initialize(ctx=self.ctx("e-second"))
            await env.execute("ls", ctx=self.ctx("e-second"))
            sent = len(client.sessions[1].log)
            for call in (env.initialize(ctx=self.ctx("e-first")), env.execute("cat mine.txt", ctx=self.ctx("e-first")),
                         env.read_file("mine.txt", ctx=self.ctx("e-first"))):
                with self.assertRaises(SessionEndedError) as caught:
                    await call
                self.assertEqual(caught.exception.not_dispatched, "request")
            self.assertEqual(len(client.sessions[1].log), sent)  # nothing was sent
            self.assertEqual(len(client.sessions), 2)
            await env.execute("ls", ctx=self.ctx("e-second"))  # the second keeps its own
            # A close between a tool's initialize and its call: the call says why, as the
            # initialize would have.
            await env.close()
            with self.assertRaises(SessionEndedError):
                await env.execute("ls", ctx=self.ctx("e-second"))
            with self.assertRaisesRegex(RuntimeError, "call initialize"):
                await env.execute("ls", ctx=self.ctx("e-third"))
        run(go())

    def test_the_wrapping_invocation_is_held_but_not_its_other_wrapped_runs(self) -> None:
        async def go() -> None:
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            await env.initialize(ctx=self.ctx("e-child-1", parent="e-lead"))
            await env.close()
            with self.assertRaises(SessionEndedError):
                await env.initialize(ctx=self.ctx("e-lead"))
            self.assertEqual(len(client.sessions), 1)
            await env.initialize(ctx=self.ctx("e-child-2", parent="e-lead"))  # a run of its own
            self.assertEqual(len(client.sessions), 2)
            await env.initialize()  # a direct call names no invocation and is held to none
        run(go())


class FreshTurns:
    """Each test starts with no ADK invocation in progress (adk._TURNS is one per process)."""

    def setUp(self) -> None:
        from plimsoll_client import adk

        self._saved_turns = adk._TURNS
        adk._TURNS = adk._Turns()

    def tearDown(self) -> None:
        from plimsoll_client import adk

        adk._TURNS = self._saved_turns


class ScopedClient(FakeClient):
    """A FakeClient whose sessions each have a fingerprint of their own, and that attaches a
    session it opened under a checkpoint key, as another process's client would."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.daemon_name = "fake-daemon"
        self.by_key: Dict[str, FakeSession] = {}
        self.attached: List[Tuple[str, Optional[str]]] = []

    def open_session(self, **kwargs: Any) -> FakeSession:
        s = super().open_session(**kwargs)
        s.fingerprint = f"fp-{len(self.sessions)}"
        if kwargs.get("checkpoint_key"):
            self.by_key[kwargs["checkpoint_key"]] = s
        return s

    def attach_session(self, key: str, *, store: Any, fingerprint: Optional[str] = None, cancel: Any = None) -> FakeSession:
        self.attached.append((key, fingerprint))
        s = self.by_key.get(key)
        if s is None:
            raise LookupError("plimsoll: the checkpoint store holds no session under this key")
        if fingerprint is not None and s.fingerprint != fingerprint:
            raise LookupError("plimsoll: the checkpoint store holds another session under this key than the one named")
        return s


async def turn(env: PlimsollEnvironment, sessions: InMemorySessionService, session: Any, model: ToolModel,
               plugins: Optional[List[Any]] = None, *, close: bool = True) -> List[Any]:
    """One turn of an existing conversation, through a Runner of its own that is closed after
    it, as an app serving each request with a Runner closes it (Runner.close closes the
    toolsets, and so the environment)."""
    agent = Agent(name="worker", model=model, tools=[EnvironmentToolset(environment=env)])
    runner = Runner(agent=agent, app_name=session.app_name, session_service=sessions,
                    plugins=plugins if plugins is not None else [PlimsollEnvironmentGuard()])
    try:
        return [e async for e in runner.run_async(user_id=session.user_id, session_id=session.id,
                                                  new_message=types.Content(role="user", parts=[types.Part(text="Go.")]))]
    finally:
        if close:
            await runner.close()


class SessionScopeTests(FreshTurns, unittest.TestCase):
    """scope="session": a sandbox per ADK session, named in the session's state, let go
    (not closed) by close(), and refused, never replaced by an empty one, once this
    environment no longer holds it."""

    @staticmethod
    def ctx(app: str = "app", user: str = "alice", sid: str = "s-1", state: Optional[Dict[str, Any]] = None,
            invocation: str = "e-1") -> Any:
        return SimpleNamespace(function_call_id="adk-1", invocation_id=invocation, state={} if state is None else state,
                               session=SimpleNamespace(app_name=app, user_id=user, id=sid),
                               _invocation_context=SimpleNamespace(_parent_invocation_id=None))

    def test_the_scope_and_its_settings(self) -> None:
        from google.adk.environment import EnvironmentScope

        client = ScopedClient()
        self.assertIs(PlimsollEnvironment(client).scope, EnvironmentScope.SHARED)  # type: ignore[arg-type]
        self.assertIs(PlimsollEnvironment(client, scope="session").scope, EnvironmentScope.SESSION)  # type: ignore[arg-type]
        self.assertIs(PlimsollEnvironment(client, scope=EnvironmentScope.SESSION).scope,  # type: ignore[arg-type]
                      EnvironmentScope.SESSION)
        with self.assertRaisesRegex(ValueError, "shared or session"):
            PlimsollEnvironment(client, scope="user")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "needs scope='session'"):
            PlimsollEnvironment(client, checkpoint_store=object())  # type: ignore[arg-type]
        client.daemon_name = ""
        with self.assertRaisesRegex(ValueError, "daemon_name"):
            PlimsollEnvironment(client, scope="session", checkpoint_store=object())  # type: ignore[arg-type]
        self.assertEqual(client.opened, [])  # construction touches nothing

    def test_every_call_needs_an_adk_session(self) -> None:
        async def go() -> None:
            env = PlimsollEnvironment(ScopedClient(), scope="session")  # type: ignore[arg-type]
            for call in (env.initialize(), env.execute("ls"), env.read_file("a"), env.write_file("a", "x"),
                         env.initialize(ctx=SimpleNamespace(invocation_id="e-1", session=None, state={}))):
                with self.assertRaisesRegex(ValueError, "needs ADK's ctx with a session"):
                    await call
        run(go())

    def test_each_conversation_has_its_own_sandbox_and_keeps_it_across_turns(self) -> None:
        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            sessions = InMemorySessionService()
            alice = await sessions.create_session(app_name="adk-env-test", user_id="alice")
            bob = await sessions.create_session(app_name="adk-env-test", user_id="bob")
            await turn(env, sessions, alice, scripted([("WriteFile", {"path": "mine.txt", "content": "alice's"})], "done"))
            events = await turn(env, sessions, bob, scripted([("Execute", {"command": "cat mine.txt"})], "done"))
            self.assertNotIn("alice's", str(responses_of(events)[0].response))  # bob's sandbox is his own
            # alice's next turn, through a new Runner after the last one closed the environment.
            events = await turn(env, sessions, alice, scripted([("ReadFile", {"path": "mine.txt"})], "done"))
            self.assertIn("alice's", responses_of(events)[0].response["content"])
            self.assertEqual(len(client.sessions), 2)
            self.assertEqual([s.closed for s in client.sessions], [0, 0])  # close() let them go
            self.assertEqual([o["owner"] for o in client.opened], ["alice", "bob"])
            self.assertEqual(set(env.sessions), {("adk-env-test", "alice", alice.id), ("adk-env-test", "bob", bob.id)})
            self.assertIsNone(env.session)
            stored = (await sessions.get_session(app_name="adk-env-test", user_id="alice", session_id=alice.id)).state
            self.assertEqual(stored["plimsoll:sandbox"], {"session": alice.id, "fingerprint": "fp-1"})
            self.assertEqual(env.working_dir, Path("/work"))
            await env.end()  # the app stops
            self.assertEqual([s.closed for s in client.sessions], [1, 1])
            self.assertEqual(env.sessions, {})
        run(go())

    def test_a_wrapped_agent_sharing_the_environment_works_in_its_callers_sandbox(self) -> None:
        # The bug D12 C names: under SHARED the wrapped agent's nested Runner closes the shared
        # environment and the caller's next call is refused. Under the session scope the
        # nested run is a new ADK session whose state is a copy of the caller's, so it finds
        # the caller's sandbox, and the nested Runner's close lets it go: the file is there.
        from google.adk.tools.agent_tool import AgentTool

        async def go(include_plugins: bool) -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            child = Agent(name="writer", description="Writes the file.",
                          model=ToolModel(plan=lambda responses, turn: "written" if responses
                                          else [("WriteFile", {"path": "from-child.txt", "content": "child\n"})]),
                          tools=[EnvironmentToolset(environment=env)])
            model = ToolModel(plan=lambda responses, turn: [("Execute", {"command": "echo before"})] if turn == 0
                              else [("writer", {"request": "write it"})] if turn == 1
                              else [("Execute", {"command": "cat from-child.txt"})] if turn == 2 else "done")
            lead = Agent(name="lead", model=model, tools=[AgentTool(agent=child, include_plugins=include_plugins),
                                                          EnvironmentToolset(environment=env)])
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-env-test", user_id="user")
            runner = Runner(agent=lead, app_name="adk-env-test", session_service=sessions,
                            plugins=[PlimsollEnvironmentGuard()])
            events = [e async for e in runner.run_async(
                user_id="user", session_id=session.id, new_message=types.Content(role="user", parts=[types.Part(text="Go.")]))]
            outs = [r.response for r in responses_of(events) if r.name == "Execute"]
            self.assertEqual(outs[-1], {"status": "ok", "stdout": "child\n"})
            self.assertEqual(len(client.sessions), 1)  # one sandbox for the ADK session
            self.assertEqual(client.sessions[0].closed, 0)
            self.assertEqual(client.sessions[0].commands(), ["echo before", "cat from-child.txt"])
            self.assertEqual(client.sessions[0].files["from-child.txt"], b"child\n")

        for include_plugins in (True, False):
            with self.subTest(include_plugins=include_plugins):
                run(go(include_plugins))

    def test_a_wrapped_agent_that_runs_first_leaves_its_sandbox_to_its_caller(self) -> None:
        # The caller's first call is the AgentTool, so no sandbox is named yet: the wrapped
        # agent opens one under its nested session, and ADK forwards the state change that
        # names it to the caller, whose next call and next turn use it.
        from google.adk.tools.agent_tool import AgentTool

        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            child = Agent(name="writer", description="Writes the file.",
                          model=ToolModel(plan=lambda responses, turn: "written" if responses
                                          else [("WriteFile", {"path": "from-child.txt", "content": "child\n"})]),
                          tools=[EnvironmentToolset(environment=env)])
            model = ToolModel(plan=lambda responses, turn: [("writer", {"request": "write it"})] if turn == 0
                              else [("Execute", {"command": "cat from-child.txt"})] if turn == 1 else "done")
            lead = Agent(name="lead", model=model, tools=[AgentTool(agent=child, include_plugins=False),
                                                          EnvironmentToolset(environment=env)])
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-env-test", user_id="user")
            runner = Runner(agent=lead, app_name="adk-env-test", session_service=sessions)
            events = [e async for e in runner.run_async(
                user_id="user", session_id=session.id, new_message=types.Content(role="user", parts=[types.Part(text="Go.")]))]
            outs = [r.response for r in responses_of(events) if r.name == "Execute"]
            self.assertEqual(outs, [{"status": "ok", "stdout": "child\n"}])
            self.assertEqual(len(client.sessions), 1)
            events = await turn(env, sessions, session, scripted([("ReadFile", {"path": "from-child.txt"})], "done"))
            self.assertIn("child", responses_of(events)[0].response["content"])
            self.assertEqual(len(client.sessions), 1)
        run(go())

    def test_a_conversation_whose_sandbox_was_ended_is_refused_not_given_an_empty_one(self) -> None:
        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            state: Dict[str, Any] = {}
            await env.initialize(ctx=self.ctx(state=state))
            await env.write_file("mine.txt", "mine", ctx=self.ctx(state=state))
            await env.end()
            # The conversation's next turn: its state names a sandbox the environment no longer holds.
            with self.assertRaises(SessionEndedError) as caught:
                await env.initialize(ctx=self.ctx(state=state, invocation="e-2"))
            self.assertEqual((caught.exception.reason, caught.exception.not_dispatched), ("not_found", "request"))
            self.assertIn("Start a new ADK session", str(caught.exception))
            # The invocation that used it is held to it as under the shared scope, even with
            # its state's mark gone.
            with self.assertRaises(SessionEndedError) as caught:
                await env.initialize(ctx=self.ctx(state={}))
            self.assertEqual((caught.exception.reason, caught.exception.not_dispatched), ("closed", "request"))
            self.assertEqual(len(client.sessions), 1)  # nothing opened in its place
            await env.initialize(ctx=self.ctx(sid="s-2", invocation="e-3"))  # a new conversation opens its own
            self.assertEqual(len(client.sessions), 2)
        run(go())

    def test_another_process_is_refused_without_a_store_and_attaches_with_one(self) -> None:
        async def go() -> None:
            from plimsoll_client import MemoryCheckpointStore

            client = ScopedClient()
            store = MemoryCheckpointStore()
            first = PlimsollEnvironment(client, scope="session", checkpoint_store=store)  # type: ignore[arg-type]
            state: Dict[str, Any] = {}
            await first.initialize(ctx=self.ctx(state=state))
            await first.write_file("mine.txt", "mine", ctx=self.ctx(state=state))
            key = client.opened[0]["checkpoint_key"]
            self.assertIs(client.opened[0]["checkpoint_store"], store)
            self.assertRegex(key, r"^adk-session-[0-9a-f]{64}$")
            self.assertNotIn("alice", key)

            without = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            with self.assertRaises(SessionEndedError):
                await without.initialize(ctx=self.ctx(state=state, invocation="e-2"))
            later = PlimsollEnvironment(client, scope="session", checkpoint_store=store)  # type: ignore[arg-type]
            await later.initialize(ctx=self.ctx(state=state, invocation="e-2"))
            self.assertEqual(await later.read_file("mine.txt", ctx=self.ctx(state=state, invocation="e-2")), b"mine")
            self.assertEqual(client.attached, [(key, "fp-1")])
            self.assertEqual(len(client.sessions), 1)
        run(go())

    def test_a_mark_naming_another_sandbox_than_the_one_held_is_refused(self) -> None:
        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            await env.initialize(ctx=self.ctx())
            sent = len(client.session.log)
            stale = {"plimsoll:sandbox": {"session": "s-1", "fingerprint": "fp-old"}}
            for call in (env.initialize(ctx=self.ctx(state=dict(stale))), env.execute("ls", ctx=self.ctx(state=dict(stale)))):
                with self.assertRaises(SessionEndedError) as caught:
                    await call
                self.assertEqual(caught.exception.reason, "replaced")
            self.assertEqual(len(client.session.log), sent)
        run(go())

    def test_a_mark_reaches_only_the_same_users_sandboxes(self) -> None:
        # The app and user are always ctx.session's: a mark copied into another user's state
        # names a sandbox key of that other user, which holds nothing, so it is refused.
        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            alice: Dict[str, Any] = {}
            await env.initialize(ctx=self.ctx(state=alice))
            await env.write_file("mine.txt", "alice's", ctx=self.ctx(state=alice))
            with self.assertRaises(SessionEndedError):
                await env.initialize(ctx=self.ctx(user="mallory", sid="s-9", state=dict(alice), invocation="e-9"))
            with self.assertRaisesRegex(RuntimeError, "no sandbox"):
                await env.read_file("mine.txt", ctx=self.ctx(user="mallory", sid="s-9", state=dict(alice), invocation="e-9"))
            self.assertEqual(len(client.sessions), 1)
        run(go())

    def test_calls_of_one_conversation_open_one_sandbox(self) -> None:
        async def go() -> None:
            client = ScopedClient()
            describe = client.describe

            def slow_describe(**kwargs: Any) -> Any:
                time.sleep(0.05)  # every call is past its first look before the first open is done
                return describe(**kwargs)
            client.describe = slow_describe  # type: ignore[method-assign]
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            await asyncio.gather(*(env.initialize(ctx=self.ctx(state={}, invocation=f"e-{i}")) for i in range(5)),
                                 env.initialize(ctx=self.ctx(sid="s-2", invocation="e-other")))
            self.assertEqual(len(client.sessions), 2)
        run(go())

    def test_past_the_limit_the_least_recently_used_sandbox_is_closed_and_its_conversation_refused(self) -> None:
        from plimsoll_client import adk

        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            states: List[Dict[str, Any]] = [{}, {}, {}]
            for i, state in enumerate(states):  # each conversation's turn ended (the guard saw it)
                await env.initialize(ctx=finished_ctx(f"s-{i}", state=state))
            self.assertEqual([s.closed for s in client.sessions], [1, 0, 0])
            with self.assertRaises(SessionEndedError):
                await env.initialize(ctx=finished_ctx("s-0", state=states[0], invocation="e-9"))
            await env.initialize(ctx=finished_ctx("s-1", state=states[1], invocation="e-8"))  # still held
            self.assertEqual(len(client.sessions), 3)
        saved = adk._MAX_SANDBOXES
        adk._MAX_SANDBOXES = 2
        try:
            run(go())
        finally:
            adk._MAX_SANDBOXES = saved

    def test_an_end_racing_an_open_leaves_no_sandbox(self) -> None:
        async def go() -> None:
            import threading

            client = ScopedClient()
            release, opening = threading.Event(), threading.Event()
            real = client.open_session

            def slow(**kwargs: Any) -> FakeSession:
                opening.set()
                release.wait(5)
                return real(**kwargs)
            client.open_session = slow  # type: ignore[method-assign]
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            task = asyncio.ensure_future(env.initialize(ctx=self.ctx()))
            await asyncio.to_thread(opening.wait, 5)
            ending = asyncio.ensure_future(env.end())
            await asyncio.sleep(0.05)
            release.set()
            with self.assertRaises(SessionEndedError):
                await task
            await ending
            self.assertEqual([s.closed for s in client.sessions], [1])
            self.assertEqual(env.sessions, {})
        run(go())


class PlacedClient(ScopedClient):
    """A ScopedClient whose daemon has ``places`` places for this caller: an open past them
    is refused as docker's per-caller limit refuses it, AtCapacityError marked not dispatched.
    A session holds its place until it is closed, idle or not, as on docker."""

    def __init__(self, places: int, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.places = places
        self.refused = 0

    def open_session(self, **kwargs: Any) -> FakeSession:
        if sum(not s.closed for s in self.sessions) >= self.places:
            self.refused += 1
            raise AtCapacityError("per-caller concurrency limit reached (4 in flight)", not_dispatched="capacity",
                                  limit="caller_runs")
        return super().open_session(**kwargs)


class _Invocation:
    """What the guard reads of an ADK InvocationContext (weak references, as pydantic's have)."""

    def __init__(self, invocation_id: str, session: Any, parent: Optional[str]) -> None:
        self.invocation_id, self.session, self._parent_invocation_id = invocation_id, session, parent


def finished_ctx(sid: str, *, author: str = "worker", state: Optional[Dict[str, Any]] = None,
                 invocation: Optional[str] = None, parent: Optional[str] = None) -> Any:
    """A direct ctx of an ADK invocation the guard saw begin, as a Runner carrying
    PlimsollEnvironmentGuard begins every one (before_run_callback). By default the invocation
    has also ended (after_run_callback): its session is between turns. With author="user" it is
    in progress: the user's message is in, the turn has not ended."""
    session = SimpleNamespace(app_name="app", user_id="alice", id=sid)
    ic = _Invocation(invocation or f"e-{sid}", session, parent)
    from plimsoll_client import adk

    adk._TURNS.begin(ic)  # what the guard's before_run_callback does
    if author != "user":
        adk._TURNS.end(ic)  # and its after_run_callback
    return SimpleNamespace(function_call_id="adk-1", invocation_id=ic.invocation_id,
                           state={} if state is None else state, session=session, _invocation_context=ic)


def unguarded_ctx(sid: str, *, state: Optional[Dict[str, Any]] = None, invocation: Optional[str] = None) -> Any:
    """A direct ctx of an invocation no guard saw begin (a Runner without the guard)."""
    return SimpleNamespace(function_call_id="adk-1", invocation_id=invocation or f"u-{sid}",
                           state={} if state is None else state, session=SimpleNamespace(app_name="app", user_id="alice", id=sid),
                           _invocation_context=SimpleNamespace(_parent_invocation_id=None))


class SessionLifetimeTests(FreshTurns, unittest.TestCase):
    """scope="session" with no end(): what `adk eval` and `adk web` do. The finalizer closes
    the sandboxes still held when the environment is collected or the process exits, and an
    open the daemon refuses for capacity closes a finished conversation's sandbox, never one in
    its turn, and tries again."""

    def test_the_sandboxes_still_held_are_closed_when_the_environment_is_collected(self) -> None:
        import gc

        async def go(store: Any) -> Tuple[List[FakeSession], Any]:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session", checkpoint_store=store)  # type: ignore[arg-type]
            sessions = InMemorySessionService()
            for user in ("alice", "bob"):
                conversation = await sessions.create_session(app_name="adk-env-test", user_id=user)
                await turn(env, sessions, conversation, scripted([("WriteFile", {"path": "a", "content": user})], "done"))
            self.assertEqual([s.closed for s in client.sessions], [0, 0])  # each Runner's close let them go
            finalizer = getattr(env, "_finalizer", None)
            if finalizer is not None:
                self.assertTrue(finalizer.alive)
                self.assertTrue(finalizer.atexit)  # also at a normal interpreter exit, as `adk eval` exits
            return client.sessions, finalizer

        opened, finalizer = run(go(None))
        gc.collect()  # the environment went with go()'s frame: nothing else refers to it
        self.assertEqual([s.closed for s in opened], [1, 1])
        self.assertFalse(finalizer.alive)

        from plimsoll_client import MemoryCheckpointStore

        opened, finalizer = run(go(MemoryCheckpointStore()))
        self.assertIsNone(finalizer)  # with a store another process may attach them: left open
        gc.collect()
        self.assertEqual([s.closed for s in opened], [0, 0])

    def test_two_eval_runs_in_a_row_pass_the_daemons_capacity(self) -> None:
        # The live failure: two `adk eval` runs, each of four cases two at a time, against a
        # daemon with three places for the caller. Each case is a Runner of its own that is
        # closed after its one turn, so the first run's sandboxes stay open; the second run's
        # opens close finished ones to make room, and every case still reads its own word.
        async def go() -> None:
            client = PlacedClient(3)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            sessions = InMemorySessionService()
            parallel = asyncio.Semaphore(2)

            def model(word: str) -> ToolModel:
                return ToolModel(plan=lambda responses, n: [("WriteFile", {"path": "note.txt", "content": word})] if n == 0
                                 else [("Execute", {"command": "cat note.txt"})] if n == 1
                                 else f"note: {responses[0]['stdout']}")

            async def case(word: str) -> str:
                async with parallel:
                    conversation = await sessions.create_session(app_name="adk-env-test", user_id="user")
                    events = await turn(env, sessions, conversation, model(word))
                    return events[-1].content.parts[0].text

            for batch in ("a", "b"):
                words = [f"{batch}{n}" for n in range(4)]
                self.assertEqual(await asyncio.gather(*(case(w) for w in words)), [f"note: {w}" for w in words])
            self.assertEqual(len(client.sessions), 8)
            self.assertEqual(sum(not s.closed for s in client.sessions), 3)
            self.assertGreater(client.refused, 0)
        run(go())

    def test_at_capacity_the_least_recently_used_finished_sandbox_is_closed_and_the_open_retried(self) -> None:
        async def go() -> None:
            client = PlacedClient(2)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            old, recent = finished_ctx("old"), finished_ctx("recent")
            await env.initialize(ctx=old)
            await env.initialize(ctx=recent)
            await env.initialize(ctx=finished_ctx("new", author="user"))
            self.assertEqual(client.refused, 1)
            self.assertEqual([s.closed for s in client.sessions], [1, 0, 0])  # the least recently used went
            self.assertEqual(set(k[2] for k in env.sessions), {"recent", "new"})
            # Its conversation is refused from then on, never given an empty sandbox.
            sent = len(client.opened)
            with self.assertRaises(SessionEndedError) as caught:
                await env.initialize(ctx=finished_ctx("old", state=old.state, invocation="e-2"))
            self.assertEqual((caught.exception.reason, caught.exception.not_dispatched), ("not_found", "request"))
            self.assertIn("closed between turns to make room", str(caught.exception))
            self.assertIn("reopen_after_close=True", str(caught.exception))
            # The invocation that used it is held to it, as for any sandbox it lost.
            with self.assertRaises(SessionEndedError) as caught:
                await env.execute("ls", ctx=finished_ctx("old", state=old.state))
            self.assertEqual(caught.exception.reason, "closed")
            self.assertEqual(len(client.opened), sent)
        run(go())

    def test_a_capacity_refusal_that_closing_a_sandbox_does_not_cure_closes_no_more_than_one(self) -> None:
        # An open needs one place: when one sandbox closed did not make the open pass (another
        # caller took the place first), the next would not either, and each closed is a
        # conversation lost (finding release-114).
        async def go() -> None:
            client = PlacedClient(10)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            for name in ("a", "b", "c"):
                await env.initialize(ctx=finished_ctx(name))
            full = AtCapacityError("plimsoll: resource_exhausted: 8 sessions are open, the most this daemon keeps",
                                   not_dispatched="capacity", limit="sessions")
            with mock.patch.object(client, "open_session", side_effect=full):
                with self.assertRaises(AtCapacityError) as caught:
                    await env.initialize(ctx=finished_ctx("d", author="user"))
            self.assertIs(caught.exception, full)
            self.assertEqual([s.closed for s in client.sessions], [1, 0, 0])
            self.assertEqual(set(k[2] for k in env.sessions), {"b", "c"})
        run(go())

    def test_a_capacity_refusal_no_close_cures_closes_nothing(self) -> None:
        # Finding release-115: the daemon states which limit refused (AtCapacityError.limit).
        # The rate limit gives runs back only with time, the owner's cap is one the daemon
        # already closes that owner's idle session for, and a daemon that states no limit is
        # not known to be curable: none of them costs an idle conversation its files. Each
        # limit a close does cure closes one.
        async def go(limit: str) -> List[int]:
            client = PlacedClient(10)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            for name in ("a", "b", "c"):
                await env.initialize(ctx=finished_ctx(name))
            refusal = AtCapacityError("plimsoll: resource_exhausted: refused", not_dispatched="capacity", limit=limit)
            with mock.patch.object(client, "open_session", side_effect=refusal):
                with self.assertRaises(AtCapacityError) as caught:
                    await env.initialize(ctx=finished_ctx("d", author="user"))
            self.assertIs(caught.exception, refusal)
            return [s.closed for s in client.sessions]

        from plimsoll_client._tables import CAPACITY_LIMIT_NAMES

        cured = {"sessions", "caller_sessions", "runs", "caller_runs"}
        for limit in CAPACITY_LIMIT_NAMES:
            with self.subTest(limit):
                self.assertEqual(run(go(limit)), [1, 0, 0] if limit in cured else [0, 0, 0])

    def test_with_reopen_after_close_a_conversation_closed_for_room_gets_a_new_empty_sandbox(self) -> None:
        async def go() -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session", reopen_after_close=True)  # type: ignore[arg-type]
            old = finished_ctx("old")
            await env.initialize(ctx=old)
            await env.write_file("note.txt", "mine", ctx=old)
            self.assertEqual(old.state["plimsoll:sandbox"], {"session": "old", "fingerprint": "fp-1"})
            await env.initialize(ctx=finished_ctx("new"))  # closes old's sandbox for room
            again = finished_ctx("old", state=old.state, invocation="e-2")
            await env.initialize(ctx=again)  # closes new's in turn, and opens old an empty one
            self.assertEqual(old.state["plimsoll:sandbox"], {"session": "old", "fingerprint": "fp-3"})
            with self.assertRaises(FileNotFoundError):
                await env.read_file("note.txt", ctx=again)
            self.assertEqual([s.closed for s in client.sessions], [1, 1, 0])
        run(go())

    def test_reopen_after_close_is_for_the_session_scope_without_a_store(self) -> None:
        from plimsoll_client import MemoryCheckpointStore

        client = ScopedClient()
        with self.assertRaisesRegex(ValueError, "reopen_after_close is for scope='session'"):
            PlimsollEnvironment(client, reopen_after_close=True)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "pass one or the other"):
            PlimsollEnvironment(client, scope="session", reopen_after_close=True,  # type: ignore[arg-type]
                                checkpoint_store=MemoryCheckpointStore())
        with self.assertRaises(TypeError):
            PlimsollEnvironment(client, scope="session", reopen_after_close="yes")  # type: ignore[arg-type]

    def test_at_capacity_a_conversation_in_its_turn_keeps_its_sandbox(self) -> None:
        # A real Runner turn held between its two tool calls, as an `adk eval` case waits on its
        # model: its ADK session's last event is a tool's response, not a final answer.
        async def go() -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            sessions = InMemorySessionService()
            hold, reached = asyncio.Event(), asyncio.Event()

            class Held(ToolModel):
                async def generate_content_async(self, llm_request: Any, stream: bool = False):  # type: ignore[override]
                    if self.requests:
                        reached.set()
                        await hold.wait()
                    async for r in super().generate_content_async(llm_request, stream):
                        yield r

            model = Held(plan=lambda responses, n: [("WriteFile", {"path": "a", "content": "x"})] if n == 0
                         else [("ReadFile", {"path": "a"})] if n == 1 else "done")
            conversation = await sessions.create_session(app_name="adk-env-test", user_id="alice")
            working = asyncio.ensure_future(turn(env, sessions, conversation, model))
            await asyncio.wait_for(reached.wait(), 5)
            with self.assertRaises(AtCapacityError):
                await env.initialize(ctx=finished_ctx("new"))
            # A session whose last event is the user's message is in its turn too.
            with self.assertRaises(AtCapacityError):
                await env.initialize(ctx=finished_ctx("asked", author="user"))
            self.assertEqual([s.closed for s in client.sessions], [0])
            hold.set()
            events = await working
            self.assertIn("x", responses_of(events)[-1].response["content"])  # its sandbox and file are there
            await env.initialize(ctx=finished_ctx("new"))  # its turn ended: now it makes room
            self.assertEqual([s.closed for s in client.sessions], [1, 0])
        run(go())

    def test_at_capacity_a_sandbox_with_a_call_in_flight_is_kept_until_its_thread_ends(self) -> None:
        import threading

        async def go(cancel: bool) -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            busy = finished_ctx("busy")
            await env.initialize(ctx=busy)
            started, release = threading.Event(), threading.Event()
            session = client.session
            real = session.run_project

            def slow(*args: Any, **kwargs: Any) -> Any:
                started.set()
                release.wait(5)
                return real(*args, **kwargs)
            session.run_project = slow  # type: ignore[method-assign]
            running = asyncio.ensure_future(env.execute("echo hi", ctx=busy))
            await asyncio.to_thread(started.wait, 5)
            if cancel:
                running.cancel()  # the await ends; the worker thread goes on with the call
                with self.assertRaises(asyncio.CancelledError):
                    await running
            with self.assertRaises(AtCapacityError):
                await env.initialize(ctx=finished_ctx("new"))
            self.assertEqual(session.closed, 0)
            release.set()
            if not cancel:
                await running
            for _ in range(100):  # the worker thread ends the call
                if not getattr(env._slots[("app", "alice", "busy")], "busy", 0):
                    break
                await asyncio.sleep(0.01)
            await env.initialize(ctx=finished_ctx("new"))
            self.assertEqual([s.closed for s in client.sessions], [1, 0])

        for cancel in (False, True):
            with self.subTest(cancelled=cancel):
                run(go(cancel))

    def test_a_call_whose_sandbox_was_taken_for_room_before_it_counted_sends_nothing(self) -> None:
        # Another ADK session's open (in a worker thread) takes the sandbox between a call's
        # look at its slot and its count in flight: the call is refused as not held, with
        # nothing sent to the closed session.
        async def go() -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            ctx = finished_ctx("taken")
            await env.initialize(ctx=ctx)
            ready = env._ready

            def ready_then_taken(c: Any) -> Any:
                answer = ready(c)
                env._close_for_room(env._take_finished(None))  # type: ignore[arg-type]
                return answer
            env._ready = ready_then_taken  # type: ignore[method-assign]
            sent = len(client.session.log)
            with self.assertRaises(SessionEndedError) as caught:
                await env.execute("echo hi", ctx=ctx)
            self.assertEqual((caught.exception.reason, caught.exception.not_dispatched), ("not_found", "request"))
            self.assertEqual(client.session.closed, 1)
            self.assertEqual(len(client.session.log), sent)
        run(go())

    def test_an_agent_tools_finished_session_does_not_free_its_callers_sandbox(self) -> None:
        # The wrapped agent's nested ADK session has ended, its caller's has not: the sandbox
        # they share is in use.
        async def go() -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            caller = finished_ctx("caller", author="user")
            await env.initialize(ctx=caller)
            nested = finished_ctx("nested", state=dict(caller.state))
            await env.initialize(ctx=nested)
            self.assertEqual(len(client.sessions), 1)  # the nested session uses its caller's sandbox
            with self.assertRaises(AtCapacityError):
                await env.initialize(ctx=finished_ctx("new"))
            self.assertEqual(client.session.closed, 0)
        run(go())


class DaemonTests(unittest.TestCase):
    """Against the Go daemons TestPythonFrameworks serves."""

    def test_a_daemon_without_sessions_is_refused(self) -> None:
        env = PlimsollEnvironment(Client(setting("PLIMSOLL_WASM_URL")), minimum_isolation="process")
        with self.assertRaises(UnsupportedError) as caught:
            run(env.initialize())
        self.assertEqual(caught.exception.not_dispatched, "unsupported")
        self.assertEqual(env.calls, ())

    def test_the_default_floor_refuses_a_container_session(self) -> None:
        env = PlimsollEnvironment(Client(setting("PLIMSOLL_SESSIONS_URL")))
        with self.assertRaises(InsufficientIsolationError) as caught:
            run(env.initialize())
        self.assertEqual(caught.exception.not_dispatched, "isolation")
        self.assertIsNone(env.session)

    def test_an_answer_without_a_step_is_uncertain_and_the_session_is_let_go(self) -> None:
        # The in-memory session daemon answers every project with no step's report, so the
        # first call (the work directory) gives no usable result: the environment closes the
        # session it opened and raises, with the daemon's real, checked record.
        env = PlimsollEnvironment(Client(setting("PLIMSOLL_SESSIONS_URL")), minimum_isolation="container")
        with self.assertRaises(PlimsollEnvironmentError) as caught:
            run(env.initialize())
        call = caught.exception.call
        self.assertEqual((call.method, call.dispatched, call.uncertain, call.isolation), ("initialize", "yes", True, "container"))
        self.assertRegex(call.record_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(call.record.session, caught.exception.execution.record.session)
        self.assertIsNone(env.session)
        self.assertFalse(env.is_initialized)



class CutCallTests(unittest.TestCase):
    """One tool call cancelled after its request was sent, with the real client over a
    loopback server whose session runs never answer. The client then sends nothing more on
    that session, since the cut call may have run. ADK cancels the other calls of a
    parallel batch when one of them fails, and the guard's stop after an uncertain call is
    such a failure. The work directory, learnt by a session run at open, is given here,
    so the open needs no answered run."""

    def setUp(self) -> None:
        from plimsoll_client import PROTOCOL
        from plimsoll_client._record import session_fingerprint
        from tests.test_cancel import Server

        self.server = Server()
        self.addCleanup(self.server.close)
        sid = "cd" * 16
        self.server.answers["Describe"] = (200, json.dumps(
            {"sandbox": "stub", "isolation": "container", "protocol": PROTOCOL, "supportsSessions": True}).encode())
        self.server.answers["OpenSession"] = (200, json.dumps(
            {"generation": "1", "sessionId": sid, "session": session_fingerprint(sid), "sandbox": "stub",
             "isolation": "container", "minimumIsolation": "container"}).encode())
        self.server.held = {"SessionRun"}

    async def cut_one_call(self, ctx: Any = None, **kwargs: Any) -> Tuple[PlimsollEnvironment, Any]:
        from tests.test_cancel import wait_for

        env = PlimsollEnvironment(Client(self.server.url), minimum_isolation="container", **kwargs)
        with mock.patch.object(w.Workspace, "root", "/work"):
            await env.initialize(ctx=ctx)
        session = env.session if ctx is None else next(iter(env.sessions.values()))
        task = asyncio.ensure_future(env.execute("sleep 9", ctx=ctx))
        while self.server.waiting == 0:
            await asyncio.sleep(0.01)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(await asyncio.to_thread(wait_for, lambda: self.server.hung_up == ["SessionRun"], 2.0))
        self.assertTrue(await asyncio.to_thread(wait_for, lambda: session.stopped is not None, 2.0))
        # The call's own thread lets the stopped session go: it closes it, freeing the
        # daemon's place (this server answers no close, which the environment drops).
        self.assertTrue(await asyncio.to_thread(wait_for, lambda: self.server.count("CloseSession") == 1, 2.0))
        return env, session

    def assert_lost(self, call: Any, text: str) -> None:
        async def go() -> None:
            with self.assertRaises(SessionEndedError) as caught:
                await call
            e = caught.exception
            self.assertEqual((e.reason, e.not_dispatched), ("closed", "request"))
            self.assertIn("was lost", str(e))
            self.assertIn(text, str(e))
        return go()

    def test_a_cut_call_lets_the_stopped_session_go_and_every_later_call_says_so(self) -> None:
        # Until this fix (0.29.0), the environment kept the stopped session: every later call
        # of every conversation was refused by the client ("open a new one", which no agent
        # can do), initialize() said nothing, and the session held a daemon place.
        async def go() -> None:
            env, session = await self.cut_one_call()
            self.assertIsNone(env.session)
            for _ in range(2):
                await self.assert_lost(env.initialize(), "call close()")
                await self.assert_lost(env.execute("ls"), "call close()")
                await self.assert_lost(env.write_file("a", "x"), "call close()")
            # Nothing was sent for them, and no empty sandbox was opened in its place.
            self.assertEqual([self.server.count(n) for n in ("OpenSession", "SessionRun", "CloseSession")], [1, 1, 1])
            self.assertTrue(env.is_initialized)  # so the toolset's close reaches close()
            # close() ends the lost state: the next initialize() opens a new, empty sandbox.
            await env.close()
            self.assertFalse(env.is_initialized)
            with mock.patch.object(w.Workspace, "root", "/work"):
                await env.initialize()
            self.assertIsNotNone(env.session)
            self.assertIsNot(env.session, session)
            self.assertEqual(self.server.count("OpenSession"), 2)
        try:
            run(go())
        finally:
            self.server.release.set()

    def test_under_the_session_scope_a_cut_call_lets_that_conversations_sandbox_go(self) -> None:
        async def go() -> None:
            state: Dict[str, Any] = {}
            env, _ = await self.cut_one_call(SessionScopeTests.ctx(state=state), scope="session")
            self.assertEqual(env.sessions, {})
            # The conversation's next turn (a new invocation, its state naming the sandbox) and
            # a call with its state's mark gone are both told the sandbox was lost.
            for ctx in (SessionScopeTests.ctx(state=state, invocation="e-2"), SessionScopeTests.ctx(state={}, invocation="e-3")):
                await self.assert_lost(env.initialize(ctx=ctx), "Start a new ADK session")
                await self.assert_lost(env.read_file("a", ctx=ctx), "Start a new ADK session")
            self.assertEqual([self.server.count(n) for n in ("OpenSession", "SessionRun", "CloseSession")], [1, 1, 1])
            # Another conversation is not affected: it opens its own.
            with mock.patch.object(w.Workspace, "root", "/work"):
                await env.initialize(ctx=SessionScopeTests.ctx(sid="s-2", state={}, invocation="e-4"))
            self.assertEqual(self.server.count("OpenSession"), 2)
            self.assertEqual(len(env.sessions), 1)
        try:
            run(go())
        finally:
            self.server.release.set()


class LostSandboxTests(unittest.TestCase):
    """A sandbox whose session can take no more calls (the client stopped it, or the daemon
    ended it) is let go and named on every later call, with the fake session stating
    ``stopped`` and ``ended`` as the client does."""

    @staticmethod
    def ctx(invocation: str) -> Any:
        return SimpleNamespace(function_call_id="adk-1", invocation_id=invocation,
                               _invocation_context=SimpleNamespace(_parent_invocation_id=None))

    def test_an_adk_invocation_is_told_of_the_loss_not_of_a_close(self) -> None:
        # The invocation is held to the session it used, which is gone: the refusal it gets
        # names the loss, not an AgentTool's close.
        async def go() -> None:
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            await env.initialize(ctx=self.ctx("e-1"))
            client.session.fail["run"] = ["unanswered"]
            with self.assertRaises(PlimsollError) as caught:
                await env.execute("echo once >> log", ctx=self.ctx("e-1"))
            self.assertIsNone(caught.exception.not_dispatched)  # the call's own error: it may have run
            for call in (env.initialize(ctx=self.ctx("e-1")), env.execute("ls", ctx=self.ctx("e-1"))):
                with self.assertRaises(SessionEndedError) as caught:
                    await call
                self.assertIn("was lost", str(caught.exception))
                self.assertNotIn(GUEST_TEXT, str(caught.exception))
            self.assertEqual((client.session.closed, len(client.opened)), (1, 1))
        run(go())

    def test_an_answer_that_reports_the_end_returns_and_the_next_call_is_told(self) -> None:
        # The call that found the end returns its answer; the loss names the end's reason
        # from the client's closed set only ("unknown" for any other word).
        async def go() -> None:
            env, s = await opened()
            s.ended = SessionEnded(reason=GUEST_TEXT, detail=GUEST_TEXT)
            self.assertEqual((await env.execute("echo")).stdout, "ran: echo\n")
            with self.assertRaises(SessionEndedError) as caught:
                await env.execute("echo")
            self.assertEqual(caught.exception.reason, "unknown")
            self.assertNotIn(GUEST_TEXT, str(caught.exception))
            self.assertEqual(s.closed, 1)
        run(go())

    def test_a_refused_or_answered_call_keeps_the_sandbox(self) -> None:
        async def go() -> None:
            client = FakeClient()
            env, s = await opened(client)
            s.fail["run"] = ["capacity", "runner_failed"]
            with self.assertRaises(PlimsollError):
                await env.execute("echo")  # refused before it was sent
            with self.assertRaises(PlimsollEnvironmentError):
                await env.execute("echo")  # answered, without a complete report
            self.assertEqual((await env.execute("echo")).stdout, "ran: echo\n")
            self.assertIs(env.session, s)
            self.assertEqual(s.closed, 0)
        run(go())

    def test_a_late_loss_of_a_closed_sandbox_leaves_the_next_one_alone(self) -> None:
        # A cut call's thread that finishes after close() and a new initialize() finds its
        # session stopped, but the environment holds another sandbox now: that one stays.
        async def go() -> None:
            import threading

            client = FakeClient()
            env, old = await opened(client)
            proceed, done = threading.Event(), threading.Event()
            real_run, real_let_go = old.run_project, env._let_go_if_lost

            def held_run(*args: Any, cancel: Any = None, **kwargs: Any) -> Any:
                for _ in range(500):
                    if cancel is not None and cancel.cancelled:
                        proceed.wait(5)
                        old.stopped = "the request was cut after it was sent"
                        raise RequestCanceledError("plimsoll: the request was cut after it was sent")
                    time.sleep(0.01)
                return real_run(*args, cancel=cancel, **kwargs)

            def let_go(*args: Any) -> None:
                try:
                    real_let_go(*args)
                finally:
                    done.set()
            old.run_project = held_run  # type: ignore[method-assign]
            env._let_go_if_lost = let_go  # type: ignore[method-assign]
            task = asyncio.ensure_future(env.execute("sleep 9"))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await env.close()
            await env.initialize()
            new = client.session
            proceed.set()
            self.assertTrue(await asyncio.to_thread(done.wait, 5))
            self.assertIs(env.session, new)
            self.assertEqual((await env.execute("echo")).stdout, "ran: echo\n")
            self.assertEqual((old.closed, new.closed), (1, 0))
        run(go())

    def test_an_open_that_begins_after_a_loss_is_refused(self) -> None:
        # initialize() looks for a loss, then for a sandbox, without the lock; a loss between
        # the two is caught by the open, under the lock. Driven here as that interleaving.
        from plimsoll_client._transport import in_thread

        async def go() -> None:
            client = FakeClient()
            env, s = await opened(client)
            s.fail["run"] = ["unanswered"]
            with self.assertRaises(PlimsollError):
                await env.execute("echo")
            with self.assertRaises(SessionEndedError) as caught:
                await in_thread(env._open, env._tag(None))
            self.assertIn("was lost", str(caught.exception))
            self.assertEqual(len(client.opened), 1)
        run(go())

    def test_under_the_session_scope_a_loss_is_one_conversations(self) -> None:
        from plimsoll_client._transport import in_thread

        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            one: Dict[str, Any] = {}
            two: Dict[str, Any] = {}
            await env.initialize(ctx=SessionScopeTests.ctx(state=one))
            await env.initialize(ctx=SessionScopeTests.ctx(sid="s-2", state=two, invocation="e-2"))
            first, second = client.sessions
            first.fail["run"] = ["ended"]
            with self.assertRaises(SessionEndedError):
                await env.execute("echo", ctx=SessionScopeTests.ctx(state=one))
            # The invocation that used it (held to it), its next turn, and a call with the
            # state's mark gone are each told of the loss.
            for ctx in (SessionScopeTests.ctx(state=one), SessionScopeTests.ctx(state=one, invocation="e-3"),
                        SessionScopeTests.ctx(state={}, invocation="e-4")):
                for call in (env.initialize(ctx=ctx), env.execute("echo", ctx=ctx)):
                    with self.assertRaises(SessionEndedError) as caught:
                        await call
                    self.assertEqual(caught.exception.reason, "expired")
                    self.assertIn("Start a new ADK session", str(caught.exception))
            # The open under the slot's lock refuses too, as when the loss came between
            # initialize()'s look and its open.
            key = ("app", "alice", "s-1")
            with self.assertRaises(SessionEndedError):
                await in_thread(env._open_slot, key, None, env._tag(None))
            self.assertEqual(len(client.sessions), 2)
            self.assertEqual((first.closed, second.closed), (1, 0))
            self.assertEqual(list(env.sessions), [("app", "alice", "s-2")])
            out = await env.execute("echo", ctx=SessionScopeTests.ctx(sid="s-2", state=two, invocation="e-2"))
            self.assertEqual(out.stdout, "ran: echo\n")
            # end() forgets the loss with the sandboxes; the conversation's state still names
            # its sandbox, so it is refused, never given an empty one.
            await env.end()
            with self.assertRaises(SessionEndedError) as caught:
                await env.initialize(ctx=SessionScopeTests.ctx(state=one, invocation="e-5"))
            self.assertEqual(caught.exception.reason, "not_found")
        run(go())


class MarkFingerprintTests(unittest.TestCase):
    """Under the SESSION scope a conversation's mark reaches a sandbox only with that
    sandbox's own fingerprint."""

    def test_a_mark_with_an_empty_fingerprint_reaches_no_sandbox(self) -> None:
        async def go() -> None:
            from plimsoll_client import MemoryCheckpointStore

            for store in (None, MemoryCheckpointStore()):
                client = ScopedClient()
                env = PlimsollEnvironment(client, scope="session", checkpoint_store=store)  # type: ignore[arg-type]
                a: Dict[str, Any] = {}
                await env.initialize(ctx=SessionScopeTests.ctx(state=a))
                await env.write_file("mine.txt", "a's", ctx=SessionScopeTests.ctx(state=a))
                forged = {"plimsoll:sandbox": {"session": "s-1", "fingerprint": ""}}
                for call in (env.initialize(ctx=SessionScopeTests.ctx(sid="s-2", state=dict(forged), invocation="e-2")),
                             env.read_file("mine.txt", ctx=SessionScopeTests.ctx(sid="s-2", state=dict(forged),
                                                                                  invocation="e-2"))):
                    with self.subTest(store=store is not None), self.assertRaises(PlimsollError) as caught:
                        await call
                    self.assertEqual(caught.exception.not_dispatched, "permission")
                    self.assertIn("without its plimsoll session fingerprint", str(caught.exception))
                # Another process's environment, which holds no sandbox, does not attach one either.
                other = PlimsollEnvironment(client, scope="session", checkpoint_store=store)  # type: ignore[arg-type]
                with self.assertRaises(PlimsollError) as caught:
                    await other.initialize(ctx=SessionScopeTests.ctx(sid="s-2", state=dict(forged), invocation="e-3"))
                self.assertEqual(caught.exception.not_dispatched, "permission")
                self.assertEqual((len(client.sessions), client.attached), (1, []))
                self.assertEqual(client.sessions[0].commands(), [])
        run(go())

    def test_a_sandbox_without_a_fingerprint_matches_no_mark_and_writes_none(self) -> None:
        async def go() -> None:
            client = ScopedClient()
            real = client.open_session

            def no_fingerprint(**kwargs: Any) -> FakeSession:
                s = real(**kwargs)
                s.fingerprint = ""
                return s
            client.open_session = no_fingerprint  # type: ignore[method-assign]
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            state: Dict[str, Any] = {}
            await env.initialize(ctx=SessionScopeTests.ctx(state=state))
            self.assertNotIn("plimsoll:sandbox", state)  # a mark without one would be refused
            await env.write_file("a", "x", ctx=SessionScopeTests.ctx(state=state))  # its next call works
            named = {"plimsoll:sandbox": {"session": "s-1", "fingerprint": "fp-1"}}
            with self.assertRaises(SessionEndedError) as caught:
                await env.execute("ls", ctx=SessionScopeTests.ctx(state=named, invocation="e-2"))
            self.assertEqual(caught.exception.reason, "replaced")
        run(go())


class RoomAndLossTests(FreshTurns, unittest.TestCase):
    """scope="session" with both rules at once: a lost sandbox (the daemon ended its session,
    or a call ended without an answer the client could check) is named on every later call of
    its conversation, and an open refused at capacity closes a finished conversation's
    sandbox. A lost conversation holds no sandbox, so it is never taken for room, and it is
    not the same as one closed for room: reopen_after_close does not reopen it."""

    def lose(self, env: PlimsollEnvironment, client: ScopedClient, ctx: Any) -> FakeSession:
        """Ends ctx's sandbox's plimsoll session under a call, as the daemon's lifetime does."""
        session = next(s for s in client.sessions if s.fingerprint == ctx.state["plimsoll:sandbox"]["fingerprint"])
        session.fail["run"] = ["ended"]
        with self.assertRaises(SessionEndedError):
            run(env.execute("echo", ctx=ctx))
        self.assertEqual(session.closed, 1)
        return session

    def assert_lost(self, env: PlimsollEnvironment, ctx: Any) -> None:
        for call in (env.initialize(ctx=ctx), env.execute("ls", ctx=ctx)):
            with self.assertRaises(SessionEndedError) as caught:
                run(call)
            self.assertEqual((caught.exception.reason, caught.exception.not_dispatched), ("expired", "request"))
            self.assertIn("was lost", str(caught.exception))

    def test_a_lost_conversation_is_never_taken_for_room_and_stays_named(self) -> None:
        # The lost conversation is the least recently used and between turns, but holds no
        # sandbox: closing it frees nothing, and taking its slot out would turn its loss
        # into not_found. The finished conversation behind it is the one closed.
        client = PlacedClient(2)
        env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
        kept, lost = finished_ctx("kept"), finished_ctx("lost")
        run(env.initialize(ctx=kept))
        run(env.initialize(ctx=lost))
        self.lose(env, client, lost)
        run(env.execute("echo", ctx=kept))  # kept is now the more recently used
        run(env.initialize(ctx=finished_ctx("new")))  # the lost one's place was freed: no refusal
        self.assertEqual(client.refused, 0)
        run(env.initialize(ctx=finished_ctx("newer")))
        self.assertEqual(client.refused, 1)
        self.assertEqual([s.closed for s in client.sessions], [1, 1, 0, 0])  # kept went for room
        self.assert_lost(env, finished_ctx("lost", state=lost.state, invocation="e-2"))
        # The one closed for room is not lost: its conversation is told it is not held.
        with self.assertRaises(SessionEndedError) as caught:
            run(env.initialize(ctx=finished_ctx("kept", state=kept.state, invocation="e-3")))
        self.assertEqual(caught.exception.reason, "not_found")
        self.assertNotIn("was lost", str(caught.exception))

    def test_a_call_whose_sandbox_a_parallel_call_lost_is_told_of_the_loss(self) -> None:
        # Two calls of one conversation pass _ready together; the first loses the sandbox
        # before the second counts itself in flight. The second is refused with the loss
        # named, not as a sandbox taken for room, and sends nothing.
        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            ctx = finished_ctx("both")
            await env.initialize(ctx=ctx)
            session = client.session
            ready = env._ready

            def ready_then_lost(c: Any) -> Any:
                answer = ready(c)
                live, _, slot = answer
                session.stopped = "a parallel call was cut after it was sent"
                env._let_go_if_lost(live, slot)
                return answer
            env._ready = ready_then_lost  # type: ignore[method-assign]
            sent = len(session.log)
            with self.assertRaises(SessionEndedError) as caught:
                await env.execute("echo hi", ctx=ctx)
            self.assertEqual((caught.exception.reason, caught.exception.not_dispatched), ("closed", "request"))
            self.assertIn("was lost", str(caught.exception))
            self.assertEqual((len(session.log), session.closed), (sent, 1))
        run(go())

    def test_a_call_that_loses_its_sandbox_counts_in_flight_until_the_sandbox_is_let_go(self) -> None:
        # The let-go runs inside the call's count, so an open at capacity can never take the
        # sandbox for room between the call's end and the loss being recorded; the count is
        # back to zero after, on both ways a sandbox is lost.
        for mode in ("ended", "unanswered"):
            with self.subTest(mode=mode):
                client = ScopedClient()
                env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
                ctx = finished_ctx("one")
                run(env.initialize(ctx=ctx))
                slot = env._slots[("app", "alice", "one")]
                seen: List[int] = []
                real = env._let_go_if_lost

                def let_go(live: Any, s: Any) -> None:
                    seen.append(s.busy)
                    real(live, s)
                env._let_go_if_lost = let_go  # type: ignore[method-assign]
                client.session.fail["run"] = [mode]
                with self.assertRaises(PlimsollError):
                    run(env.execute("echo", ctx=ctx))
                self.assertEqual(seen, [1])
                self.assertEqual(slot.busy, 0)
                self.assertIsNotNone(slot.lost)
                self.assertIsNone(slot.live)

    def test_the_finalizer_and_end_skip_a_lost_sandbox_and_close_the_rest(self) -> None:
        import gc

        def held() -> Tuple[PlimsollEnvironment, ScopedClient]:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            lost, kept = finished_ctx("lost"), finished_ctx("kept")
            run(env.initialize(ctx=lost))
            run(env.initialize(ctx=kept))
            self.lose(env, client, lost)
            return env, client

        gc.collect()  # what earlier tests left is collected first: its finalizers may log
        env, client = held()
        with self.assertNoLogs("plimsoll_client", level="WARNING"):
            run(env.end())
        self.assertEqual([s.closed for s in client.sessions], [1, 1])
        env, client = held()
        opened = client.sessions
        with self.assertNoLogs("plimsoll_client", level="WARNING"):
            del env
            gc.collect()
        self.assertEqual([s.closed for s in opened], [1, 1])  # the lost one is not closed again

    def test_reopen_after_close_does_not_reopen_a_lost_conversation(self) -> None:
        client = PlacedClient(2)
        env = PlimsollEnvironment(client, scope="session", reopen_after_close=True)  # type: ignore[arg-type]
        lost = finished_ctx("lost")
        run(env.initialize(ctx=lost))
        run(env.write_file("note.txt", "mine", ctx=lost))
        self.lose(env, client, lost)
        self.assert_lost(env, finished_ctx("lost", state=lost.state, invocation="e-2"))
        self.assertEqual(len(client.sessions), 1)  # no empty sandbox in its place

    def test_with_reopen_after_close_a_mark_without_its_fingerprint_is_still_refused(self) -> None:
        # reopen_after_close skips the fingerprint match for the new sandbox it opens; the
        # refusal of a mark without a fingerprint comes before it, so no sandbox is opened.
        for held in (False, True):
            with self.subTest(held=held):
                client = ScopedClient()
                env = PlimsollEnvironment(client, scope="session", reopen_after_close=True)  # type: ignore[arg-type]
                if held:
                    run(env.initialize(ctx=finished_ctx("s-1")))
                forged = {"plimsoll:sandbox": {"session": "s-1", "fingerprint": ""}}
                with self.assertRaises(PlimsollError) as caught:
                    run(env.initialize(ctx=finished_ctx("s-2", state=forged, invocation="e-2")))
                self.assertEqual(caught.exception.not_dispatched, "permission")
                self.assertEqual(len(client.sessions), 1 if held else 0)


class D86Tests(FreshTurns, unittest.TestCase):
    """D86 B's four defects of scope="session" (private/decisions.md): a chat waiting on its
    model in its next turn, a SequentialAgent between its sub-agents and an AgentTool's caller
    keep their sandboxes at capacity (between turns is the Runner's own lifecycle, as the guard
    sees it, never the session's events); an AgentTool's agent and its caller that open at once
    share one sandbox, or the split is refused; the limit of 256 never lets go of a sandbox with
    a call in flight; and a call cancelled before its thread starts is counted out."""

    @staticmethod
    def held_model(plan: Any, hold: asyncio.Event, reached: asyncio.Event, at: Any) -> ToolModel:
        class Held(ToolModel):
            async def generate_content_async(self, llm_request: Any, stream: bool = False):  # type: ignore[override]
                if at(len(self.requests)):
                    reached.set()
                    await hold.wait()
                async for r in super().generate_content_async(llm_request, stream):
                    yield r
        return Held(plan=plan)

    def test_a_chats_next_turn_waiting_on_its_model_keeps_its_sandbox_at_capacity(self) -> None:
        # The measured defect (private/hunts/measure/adk-addon-room-window-2026-11-26.py): turn 2
        # has begun and waits on its model before any tool call; its sandbox was closed for room.
        async def go() -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            sessions = InMemorySessionService()
            hold, reached = asyncio.Event(), asyncio.Event()

            def plan(responses: Any, n: int) -> Any:
                return ([("WriteFile", {"path": "note.txt", "content": "first"})] if n == 0 else "done" if n == 1
                        else [("ReadFile", {"path": "note.txt"})] if n == 2 else "read")
            model = self.held_model(plan, hold, reached, lambda n: n == 2)
            chat = await sessions.create_session(app_name="adk-env-test", user_id="alice")
            await turn(env, sessions, chat, model)
            turn2 = asyncio.ensure_future(turn(env, sessions, chat, model))
            await asyncio.wait_for(reached.wait(), 5)
            with self.assertRaises(AtCapacityError) as caught:
                await env.initialize(ctx=finished_ctx("other"))  # another conversation at capacity
            self.assertEqual(caught.exception.not_dispatched, "capacity")
            self.assertEqual(client.sessions[0].closed, 0)
            hold.set()
            events = await turn2
            self.assertIn("first", responses_of(events)[-1].response["content"])
            await env.initialize(ctx=finished_ctx("other"))  # the chat is between turns now
            self.assertEqual([s.closed for s in client.sessions], [1, 0])
        run(go())

    def test_a_sequential_agent_keeps_its_sandbox_between_its_sub_agents(self) -> None:
        # The first sub-agent's final answer is stored in the middle of the turn: the session's
        # events would say it ended (measured, adk-addon-d86b-2026-11-26.py).
        from google.adk.agents import SequentialAgent

        async def go() -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            sessions = InMemorySessionService()
            hold, reached = asyncio.Event(), asyncio.Event()
            first = Agent(name="first", model=ToolModel(plan=lambda r, n: [("WriteFile", {"path": "a", "content": "x"})]
                                                        if n == 0 else "first done"),
                          tools=[EnvironmentToolset(environment=env)])
            second = Agent(name="second", model=self.held_model(lambda r, n: [("ReadFile", {"path": "a"})] if n == 0
                                                                else "second done", hold, reached, lambda n: n == 0),
                           tools=[EnvironmentToolset(environment=env)])
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                root = SequentialAgent(name="seq", sub_agents=[first, second])
            chat = await sessions.create_session(app_name="adk-env-test", user_id="alice")
            runner = Runner(agent=root, app_name="adk-env-test", session_service=sessions,
                            plugins=[PlimsollEnvironmentGuard()])
            working = asyncio.ensure_future(_events(runner.run_async(
                user_id="alice", session_id=chat.id, new_message=types.Content(role="user", parts=[types.Part(text="Go.")]))))
            await asyncio.wait_for(reached.wait(), 5)
            stored = await sessions.get_session(app_name="adk-env-test", user_id="alice", session_id=chat.id)
            self.assertTrue(stored.events[-1].is_final_response())  # the events say finished; it is not
            with self.assertRaises(AtCapacityError):
                await env.initialize(ctx=finished_ctx("other"))
            hold.set()
            events = await working
            self.assertIn("x", [r for r in responses_of(events) if r.name == "ReadFile"][0].response["content"])
            self.assertEqual(client.sessions[0].closed, 0)
        run(go())

    def test_an_agent_tools_caller_waiting_on_its_model_keeps_the_sandbox_its_agent_opened(self) -> None:
        # The wrapped agent ran first and opened the sandbox under its own nested ADK session,
        # which has ended; the caller's turn goes on, known through the AgentTool's link.
        from google.adk.tools.agent_tool import AgentTool

        async def go() -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            hold, reached = asyncio.Event(), asyncio.Event()
            child = Agent(name="writer", description="Writes the file.",
                          model=ToolModel(plan=lambda r, n: "written" if r
                                          else [("WriteFile", {"path": "c.txt", "content": "child"})]),
                          tools=[EnvironmentToolset(environment=env)])
            model = self.held_model(lambda r, n: [("writer", {"request": "write"})] if n == 0
                                    else [("Execute", {"command": "cat c.txt"})] if n == 1 else "done",
                                    hold, reached, lambda n: n == 1)
            lead = Agent(name="lead", model=model, tools=[AgentTool(agent=child), EnvironmentToolset(environment=env)])
            sessions = InMemorySessionService()
            chat = await sessions.create_session(app_name="adk-env-test", user_id="alice")
            runner = Runner(agent=lead, app_name="adk-env-test", session_service=sessions,
                            plugins=[PlimsollEnvironmentGuard()])
            working = asyncio.ensure_future(_events(runner.run_async(
                user_id="alice", session_id=chat.id, new_message=types.Content(role="user", parts=[types.Part(text="Go.")]))))
            await asyncio.wait_for(reached.wait(), 5)
            with self.assertRaises(AtCapacityError):
                await env.initialize(ctx=finished_ctx("other"))
            hold.set()
            events = await working
            self.assertEqual([r.response for r in responses_of(events) if r.name == "Execute"],
                             [{"status": "ok", "stdout": "child"}])
        run(go())

    def test_a_turns_end_is_the_runners_after_run_callback(self) -> None:
        # A plugin that keeps each run's context alive: the turn still ends when the run does,
        # by the guard's after_run_callback, not by the context being collected.
        from google.adk.plugins.base_plugin import BasePlugin

        class Keeper(BasePlugin):
            kept: List[Any] = []

            async def before_run_callback(self, *, invocation_context: Any) -> None:
                self.kept.append(invocation_context)
                return None

        async def go() -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            sessions = InMemorySessionService()
            chat = await sessions.create_session(app_name="adk-env-test", user_id="alice")
            keeper = Keeper(name="keeper")
            await turn(env, sessions, chat, scripted([("WriteFile", {"path": "a", "content": "x"})], "done"),
                       plugins=[PlimsollEnvironmentGuard(), keeper])
            self.assertEqual(len(keeper.kept), 1)
            await env.initialize(ctx=finished_ctx("other"))
            self.assertEqual([s.closed for s in client.sessions], [1, 0])
        run(go())

    def test_a_run_that_ends_in_an_error_ends_its_turn(self) -> None:
        async def go() -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]

            def plan(responses: Any, n: int) -> Any:
                if n == 1:
                    raise ValueError("the model service failed")
                return [("WriteFile", {"path": "a", "content": "x"})]
            sessions = InMemorySessionService()
            chat = await sessions.create_session(app_name="adk-env-test", user_id="alice")
            with self.assertRaises(Exception):
                await turn(env, sessions, chat, ToolModel(plan=plan))
            await env.initialize(ctx=finished_ctx("other"))  # its turn ended with the error
            self.assertEqual([s.closed for s in client.sessions], [1, 0])
        run(go())

    def test_without_the_guard_no_sandbox_is_closed_to_make_room(self) -> None:
        # Nothing then says when a turn of the conversation begins: its sandbox is kept, and the
        # newcomer is refused as the daemon refused it.
        async def go() -> None:
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            sessions = InMemorySessionService()
            chat = await sessions.create_session(app_name="adk-env-test", user_id="alice")
            await turn(env, sessions, chat, scripted([("WriteFile", {"path": "a", "content": "x"})], "done"), plugins=[])
            with self.assertRaises(AtCapacityError):
                await env.initialize(ctx=finished_ctx("other"))
            self.assertEqual(client.sessions[0].closed, 0)
            # Once unseen, a later guarded turn does not make it closable either.
            await turn(env, sessions, chat, scripted([("ReadFile", {"path": "a"})], "done"))
            with self.assertRaises(AtCapacityError):
                await env.initialize(ctx=finished_ctx("other"))
            self.assertEqual(client.sessions[0].closed, 0)
        run(go())

    def test_an_invocation_cancelled_from_outside_stays_in_its_turn_until_collected(self) -> None:
        import gc
        from plimsoll_client import adk

        ic = _Invocation("e-cut", SimpleNamespace(app_name="app", user_id="alice", id="cut"), None)
        adk._TURNS.begin(ic)
        adk._TURNS.begin(ic)  # on_user_message_callback, then before_run_callback: one invocation
        self.assertTrue(adk._TURNS.in_turn(("app", "alice", "cut")))
        del ic  # no after_run_callback: ADK calls none on an outside cancel
        gc.collect()
        self.assertFalse(adk._TURNS.in_turn(("app", "alice", "cut")))
        self.assertEqual(adk._TURNS.chain("e-cut"), [("app", "alice", "cut")])  # still seen, and ended

    def test_an_invocation_collected_while_its_lock_is_held_stops_nothing(self) -> None:
        # The pre-release ADK round's second refactor: a garbage collection runs finalizers in
        # whatever thread allocated, the one inside _Turns' lock included, and the lock is not
        # reentrant, so a finalizer that took it would stop that thread for good (an ADK
        # server's event loop). Collected here both ways, in the thread that holds the lock:
        # the last reference dropped, and a cycle found by gc.collect().
        import gc
        import threading
        from plimsoll_client import adk

        class Ctx(_Invocation):
            pass

        turns = adk._Turns()
        held = [Ctx("e-a", SimpleNamespace(app_name="app", user_id="alice", id="a"), None),
                Ctx("e-b", SimpleNamespace(app_name="app", user_id="alice", id="b"), None)]
        held[1].cycle = held[1]  # type: ignore[attr-defined]
        for ic in held:
            turns.begin(ic)
        del ic

        def collect() -> None:
            with turns._lock:
                held.clear()  # e-a goes at once; e-b, in a cycle, at the collection
                gc.collect()

        t = threading.Thread(target=collect, daemon=True)
        t.start()
        t.join(10)
        self.assertFalse(t.is_alive(), "a finalizer run inside the lock took it again")
        self.assertFalse(turns.in_turn(("app", "alice", "a")))
        self.assertFalse(turns.in_turn(("app", "alice", "b")))
        self.assertEqual(turns.chain("e-b"), [("app", "alice", "b")])  # still seen, and ended

    def parallel(self, include_plugins: bool) -> Tuple[ScopedClient, PlimsollEnvironment, Any, InMemorySessionService, Any]:
        from google.adk.tools.agent_tool import AgentTool

        async def go() -> Any:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            child = Agent(name="writer", description="Writes a file.",
                          model=ToolModel(plan=lambda r, n: "written" if r
                                          else [("WriteFile", {"path": "child.txt", "content": "child"})]),
                          tools=[EnvironmentToolset(environment=env)])
            # The caller's first answer holds its own call and the AgentTool call together.
            model = ToolModel(plan=lambda r, n: [("WriteFile", {"path": "lead.txt", "content": "lead"}),
                                                 ("writer", {"request": "write"})] if n == 0
                              else [("Execute", {"command": "cat lead.txt"})] if n == 1 else "done")
            lead = Agent(name="lead", model=model, tools=[AgentTool(agent=child, include_plugins=include_plugins),
                                                          EnvironmentToolset(environment=env)])
            sessions = InMemorySessionService()
            chat = await sessions.create_session(app_name="adk-env-test", user_id="alice")
            runner = Runner(agent=lead, app_name="adk-env-test", session_service=sessions,
                            plugins=[PlimsollEnvironmentGuard()])
            try:
                result: Any = await _events(runner.run_async(
                    user_id="alice", session_id=chat.id,
                    new_message=types.Content(role="user", parts=[types.Part(text="Go.")])))
            except Exception as e:
                result = e
            return client, env, result, sessions, chat
        return run(go())

    def test_an_agent_tools_agent_and_its_caller_opening_together_share_one_sandbox(self) -> None:
        client, env, events, sessions, chat = self.parallel(include_plugins=True)
        self.assertIsInstance(events, list, repr(events))
        self.assertEqual(len(client.sessions), 1)
        self.assertEqual(sorted(client.sessions[0].files), ["child.txt", "lead.txt"])
        self.assertEqual([r.response for r in responses_of(events) if r.name == "Execute"],
                         [{"status": "ok", "stdout": "lead"}])
        # The next turn reads the caller's file: the state names the one sandbox.
        events = run(turn(env, sessions, chat, scripted([("ReadFile", {"path": "lead.txt"})], "done")))
        self.assertIn("lead", responses_of(events)[0].response["content"])
        self.assertEqual(len(client.sessions), 1)

    def test_a_conversation_split_through_an_agent_tool_without_plugins_is_refused(self) -> None:
        # ADK names no link between the nested run and its caller: two sandboxes open, and the
        # caller's next call is refused with the split named, in this turn and the next, never
        # working silently in the wrapped agent's sandbox.
        client, env, refused, sessions, chat = self.parallel(include_plugins=False)
        self.assertEqual(len(client.sessions), 2)
        self.assertIsInstance(refused, SessionEndedError, repr(refused))
        self.assertIn("reached two sandboxes", str(refused))
        self.assertEqual(refused.not_dispatched, "request")
        with self.assertRaises(SessionEndedError) as caught:
            run(turn(env, sessions, chat, scripted([("ReadFile", {"path": "lead.txt"})], "done")))
        self.assertIn("reached two sandboxes", str(caught.exception))
        self.assertEqual([s.commands() for s in client.sessions], [[], []])

    def test_a_nested_call_that_opens_first_gives_its_sandbox_to_its_callers_own_call(self) -> None:
        # The other order of the two first calls: the AgentTool's agent's initialize runs first.
        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            nested = finished_ctx("nested", author="user", invocation="e-nested", parent="e-caller")
            caller = finished_ctx("caller", author="user", invocation="e-caller")
            await asyncio.gather(env.initialize(ctx=nested), env.initialize(ctx=caller))
            self.assertEqual(len(client.sessions), 1)
            self.assertEqual(caller.state["plimsoll:sandbox"], nested.state["plimsoll:sandbox"])
        run(go())

    def test_past_the_limit_a_sandbox_with_a_call_in_flight_or_in_its_turn_is_kept_and_the_open_refused(self) -> None:
        import threading
        from plimsoll_client import adk

        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            busy = finished_ctx("busy")
            await env.initialize(ctx=busy)
            started, release = threading.Event(), threading.Event()
            session = client.session
            real = session.run_project

            def slow(*a: Any, **k: Any) -> Any:
                started.set()
                release.wait(5)
                return real(*a, **k)
            session.run_project = slow  # type: ignore[method-assign]
            running = asyncio.ensure_future(env.execute("echo hi", ctx=busy))
            await asyncio.to_thread(started.wait, 5)
            with self.assertRaises(AtCapacityError) as caught:
                await env.initialize(ctx=finished_ctx("new"))
            self.assertEqual(caught.exception.not_dispatched, "capacity")
            self.assertIn("none of them can be let go", str(caught.exception))
            self.assertEqual((session.closed, len(client.sessions)), (0, 1))
            release.set()
            self.assertEqual((await running).exit_code, 0)  # the call kept its sandbox
            await env.initialize(ctx=finished_ctx("new"))  # between turns, no call: let go
            self.assertEqual([s.closed for s in client.sessions], [1, 0])
            # A conversation in its turn, with no call in flight, is kept too.
            asking = finished_ctx("asking", author="user")  # held: a run's context lives while it runs
            await env.initialize(ctx=asking)  # "new" ended: it goes
            with self.assertRaises(AtCapacityError):
                await env.initialize(ctx=finished_ctx("late"))  # "asking" is in its turn
            self.assertEqual([s.closed for s in client.sessions], [1, 1, 0])

        saved = adk._MAX_SANDBOXES
        adk._MAX_SANDBOXES = 1
        try:
            run(go())
        finally:
            adk._MAX_SANDBOXES = saved

    def test_past_the_limit_an_open_in_flight_counts(self) -> None:
        import threading
        from plimsoll_client import adk

        async def go() -> None:
            client = ScopedClient()
            opening, release = threading.Event(), threading.Event()
            real = client.open_session

            def slow(**kwargs: Any) -> FakeSession:
                opening.set()
                release.wait(5)
                return real(**kwargs)
            client.open_session = slow  # type: ignore[method-assign]
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            first = asyncio.ensure_future(env.initialize(ctx=finished_ctx("first")))
            await asyncio.to_thread(opening.wait, 5)
            with self.assertRaises(AtCapacityError):
                await env.initialize(ctx=finished_ctx("second"))
            release.set()
            await first
            self.assertEqual(len(client.sessions), 1)

        saved = adk._MAX_SANDBOXES
        adk._MAX_SANDBOXES = 1
        try:
            run(go())
        finally:
            adk._MAX_SANDBOXES = saved

    def test_past_the_limit_with_a_store_a_sandbox_in_its_turn_is_dropped_and_attached_again(self) -> None:
        from plimsoll_client import MemoryCheckpointStore, adk

        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session", checkpoint_store=MemoryCheckpointStore())  # type: ignore[arg-type]
            asking = finished_ctx("asking", author="user")
            await env.initialize(ctx=asking)
            await env.write_file("a", "mine", ctx=asking)
            await env.initialize(ctx=finished_ctx("other"))
            self.assertEqual(client.sessions[0].closed, 0)  # dropped, not closed
            again = finished_ctx("asking", author="user", state=asking.state, invocation="e-again")
            await env.initialize(ctx=again)
            self.assertEqual(await env.read_file("a", ctx=again), b"mine")

        saved = adk._MAX_SANDBOXES
        adk._MAX_SANDBOXES = 1
        try:
            run(go())
        finally:
            adk._MAX_SANDBOXES = saved

    def test_past_the_limit_with_a_store_the_turn_whose_sandbox_was_dropped_attaches_it_again(self) -> None:
        # The case the drop exists for: the turn in progress itself makes the next call. It was
        # refused, reason closed, as if its sandbox and files were gone, because the invocation
        # was held to the dropped _Live rather than to the plimsoll session it attaches again.
        from plimsoll_client import MemoryCheckpointStore, adk

        async def go() -> None:
            client = ScopedClient()
            env = PlimsollEnvironment(client, scope="session", checkpoint_store=MemoryCheckpointStore())  # type: ignore[arg-type]
            asking = finished_ctx("asking", author="user")
            await env.initialize(ctx=asking)
            await env.write_file("a", "mine", ctx=asking)
            await env.initialize(ctx=finished_ctx("other"))
            self.assertEqual(client.sessions[0].closed, 0)  # dropped, not closed
            await env.initialize(ctx=asking)  # the same turn's next tool call
            self.assertEqual(await env.read_file("a", ctx=asking), b"mine")
            self.assertEqual(client.attached[-1][1], client.sessions[0].fingerprint)

        saved = adk._MAX_SANDBOXES
        adk._MAX_SANDBOXES = 1
        try:
            run(go())
        finally:
            adk._MAX_SANDBOXES = saved

    def test_a_failed_open_holds_no_place_among_the_limit_and_a_call_waiting_on_it_starts_again(self) -> None:
        # The leads.md item: a refused open left an empty slot that counted toward the 256, and
        # since the limit refuses rather than letting an opening slot go, 256 refused opens
        # would have refused every later conversation.
        import threading
        from plimsoll_client import adk

        async def go() -> None:
            client = PlacedClient(0)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            for i in range(3):
                with self.assertRaises(AtCapacityError) as caught:
                    await env.initialize(ctx=finished_ctx(f"refused-{i}"))
                self.assertNotIn("none of them can be let go", str(caught.exception))  # the daemon's refusal
            self.assertEqual(env._slots, {})
            client.places = 1
            await env.initialize(ctx=finished_ctx("later"))
            self.assertEqual(len(client.sessions), 1)

            # Two calls of one conversation: the first's open fails, the second waited on it.
            client2 = ScopedClient()
            entered, release = threading.Event(), threading.Event()
            real, calls = client2.open_session, []

            def first_fails(**kwargs: Any) -> FakeSession:
                calls.append(1)
                if len(calls) == 1:
                    entered.set()
                    release.wait(5)
                    raise AtCapacityError("per-caller concurrency limit reached", not_dispatched="capacity")
                return real(**kwargs)
            client2.open_session = first_fails  # type: ignore[method-assign]
            env2 = PlimsollEnvironment(client2, scope="session")  # type: ignore[arg-type]
            one = asyncio.ensure_future(env2.initialize(ctx=finished_ctx("both", invocation="e-a")))
            await asyncio.to_thread(entered.wait, 5)
            two = asyncio.ensure_future(env2.initialize(ctx=finished_ctx("both", invocation="e-b")))
            await asyncio.sleep(0.05)
            release.set()
            with self.assertRaises(AtCapacityError):
                await one
            await two  # opened its own, not told "the environment was ended"
            self.assertEqual(len(client2.sessions), 1)

        saved = adk._MAX_SANDBOXES
        adk._MAX_SANDBOXES = 1
        try:
            run(go())
        finally:
            adk._MAX_SANDBOXES = saved

    def test_a_call_cancelled_before_its_worker_thread_starts_is_counted_out(self) -> None:
        # Review finding 5 of Google's copy: here the await counts it out (_InFlight).
        import concurrent.futures
        import threading

        async def go() -> None:
            asyncio.get_running_loop().set_default_executor(concurrent.futures.ThreadPoolExecutor(1))
            client = PlacedClient(1)
            env = PlimsollEnvironment(client, scope="session")  # type: ignore[arg-type]
            ctx = finished_ctx("one")
            await env.initialize(ctx=ctx)
            gate = threading.Event()
            blocker = asyncio.ensure_future(asyncio.to_thread(gate.wait, 5))  # the one thread is taken
            await asyncio.sleep(0.05)
            call = asyncio.ensure_future(env.execute("echo hi", ctx=ctx))
            await asyncio.sleep(0.05)
            call.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await call
            gate.set()
            await blocker
            await asyncio.sleep(0.05)  # the cancelled call's function, if it ran, would have run by now
            self.assertEqual(env._slots[("app", "alice", "one")].busy, 0)
            self.assertEqual(client.session.commands(), [])
            await env.initialize(ctx=finished_ctx("new"))  # so the sandbox can be closed for room
            self.assertEqual([s.closed for s in client.sessions], [1, 0])
        run(go())


async def _events(agen: Any) -> List[Any]:
    return [e async for e in agen]


if __name__ == "__main__":
    unittest.main()
