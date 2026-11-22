"""PlimsollEnvironment, ADK's kept sandbox with a shell and files, over a plimsoll session.

ADK's real tools (ExecuteTool, ReadFileTool, EditFileTool, WriteFileTool), its real
EnvironmentToolset and Runner, and a scripted model (no model is called), over the real
Workspace on a fake session that understands the workspace's fixed steps, keeps files in
memory and counts every call it is handed. What a real shell does is the docker check's
(docker_adk_check.py); the cases at the end run against the Go daemons the suite serves."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import shlex
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

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
from plimsoll_client._tables import OUTCOME_NAMES, REFUSAL_NAMES, TIERS
from plimsoll_client.adk import (PlimsollCall, PlimsollEnvironment, PlimsollEnvironmentError, PlimsollEnvironmentGuard,
                                 PlimsollExecutionResult)
from plimsoll_client.types import Artifact, ProjectResult, RunRecord, SessionSummary, StepResult
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
    of workspace.STEP_KINDS), keeps the files a call writes, answers reads from them and
    answers a command with what the test scripted (``cat PATH`` reads a kept file; any
    other command answers ``ran: COMMAND``). ``fail`` queues failures by kind. Every call
    it is handed is in ``log``."""

    def __init__(self, isolation: str = "kernel", qualification: str = "") -> None:
        self.isolation = isolation
        self.isolation_qualification = qualification
        self.fingerprint = "fp-fake"
        self.files: Dict[str, bytes] = {}
        self.dirs: set = set()
        self.unreadable: set = set()
        self.answers: Dict[str, Tuple[bytes, bytes, int]] = {}
        self.fail: Dict[str, List[str]] = {}
        self.before_read: Any = None  # called with (path, offset) before a read is answered
        self.hold_reads_past_first = False  # a read at an offset waits for its cancel handle (2 s at most)
        self.cut: List[int] = []  # offsets of the reads a cancel handle cut
        self.log: List[Dict[str, Any]] = []
        self.closed = 0
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
            if argv[:3] == ["sh", "-c", _why()]:
                kind = entry["kind"] = "why"
                entry["path"] = argv[4]
            elif argv[:3] == ["wc", "-c", "--"]:
                kind = entry["kind"] = "size"
                entry["path"] = argv[3]
            else:
                entry["command"] = argv[2]
        elif kind in ("read", "write") and w._A1 in files:
            entry["path"] = files[w._A1]
        elif kind == "write":
            entry["path"] = ",".join(k for k in files if not k.startswith(w.STATE_DIR))
        self.log.append(entry)
        how = self.fail.get(kind, [])
        mode = how.pop(0) if how else None
        if self.closed:
            raise SessionEndedError("plimsoll: this session was closed; nothing was sent", reason="closed",
                                    not_dispatched="request")
        if mode == "capacity":
            raise AtCapacityError("plimsoll: the daemon is at capacity; nothing ran", not_dispatched="capacity")
        if mode == "ended":
            raise SessionEndedError("plimsoll: the session ended (lifetime)", reason="expired", not_dispatched="request")
        if mode == "unanswered":
            raise PlimsollError(f"plimsoll: the connection was cut after the request was sent ({GUEST_TEXT})")
        if mode in ("runner_failed", "protocol_error", "setup_failed"):
            return self._result([], outcome=mode, detail=f"runner: {GUEST_TEXT}")
        if mode == "runner_failed_after_step":  # a step began, then the runner failed
            return self._result([self._step(step, stdout=GUEST_TEXT.encode())], outcome="runner_failed",
                                detail=f"runner: {GUEST_TEXT}")
        if kind == "root":
            return self._result([self._step(step)], artifacts=[Artifact(path=w._ROOT, content=b"/work\n")])
        if kind == "why":
            p = self._norm(entry["path"])
            word = "is_directory" if self._is_dir(p) else "permission_denied" if p in self.unreadable else "file_not_found"
            return self._result([self._step(step, stdout=word.encode() + b"\n")])
        if kind == "size":
            p = self._norm(entry["path"])
            if p not in self.files:
                return self._result([self._step(step, stderr=b"wc: no such file\n", exit_code=1)])
            return self._result([self._step(step, stdout=f"{len(self.files[p])} {entry['path']}\n".encode())])
        if kind == "run":
            return self._command(step, argv[2], mode)
        if kind == "write":
            if mode == "write_denied":
                return self._result([self._step(step, stderr=f"{GUEST_TEXT}: Permission denied\n".encode(), exit_code=1)])
            if step == w._TRUE_STEP:
                for k, val in files.items():
                    if not k.startswith(w.STATE_DIR):
                        self.files[self._norm(k)] = val.encode("utf-8") if isinstance(val, str) else bytes(val)
            else:
                p = self._norm(files[w._A1])
                data = base64.b64decode(files[w._IN_B64])
                self.files[p] = (self.files.get(p, b"") + data) if step == w._APPEND_B64_STEP else data
            return self._result([self._step(step)])
        if kind == "read":
            p = self._norm(files[w._A1])
            offset = int(files[w._A3]) - 1 if w._A3 in files else 0
            if self.before_read is not None:
                self.before_read(p, offset)
            if self.hold_reads_past_first and offset:
                for _ in range(200):
                    if cancel is not None and cancel.cancelled:
                        self.cut.append(offset)
                        raise RequestCanceledError("plimsoll: the request was cut after it was sent")
                    time.sleep(0.01)
            if p not in self.files or p in self.unreadable:
                return self._result([self._step(step, stderr=f"head: {p}: cannot read\n".encode(), exit_code=1)])
            start = int(files[w._A3]) - 1 if w._A3 in files else 0
            data = self.files[p][start : start + int(files[w._A2])]
            return self._result([self._step(step)], artifacts=[Artifact(path=w._OUT, content=data)])
        raise AssertionError(f"a step this fake does not know: {kind}")

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

    @staticmethod
    def _norm(p: str) -> str:
        return p[len("/work/"):] if p.startswith("/work/") else p

    def _is_dir(self, p: str) -> bool:
        return p in self.dirs or any(k.startswith(p.rstrip("/") + "/") for k in self.files)

    @staticmethod
    def _step(command: str, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0, timed_out: bool = False,
              cut: bool = False) -> StepResult:
        return StepResult(command=command, stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=timed_out,
                          duration_ms=1, stdout_truncated=cut, stderr_truncated=False)

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


def _why() -> str:
    from plimsoll_client import adk

    return adk._WHY_UNREADABLE


async def _drain(stream: Any) -> bytes:
    return b"".join([p async for p in stream])


class FakeClient:
    """describe() and open_session() of a Client, handing out FakeSessions."""

    def __init__(self, *, sessions: bool = True, isolation: str = "kernel", qualification: str = "",
                 max_timeout_ms: int = 300_000) -> None:
        self.supports_sessions = sessions
        self.isolation = isolation
        self.qualification = qualification
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
        s = FakeSession(self.isolation, self.qualification)
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
    """The interface method by method, as ADK 2.14.1 states it (_base_environment.py)."""

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
            self.assertEqual([c.method for c in env.calls], ["initialize"])
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
            # Text goes as the call's own file; bytes and text with a NUL through the
            # workspace's base64 write step.
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
            self.assertEqual(len([e for e in s.log if e["kind"] == "write"]), -(-len(big) // w._CHUNK_BYTES))
            self.assertEqual(await env.read_file("big.bin"), big)
            pieces = [p async for p in env.read_file_stream("big.bin")]
            self.assertEqual([len(p) for p in pieces], [8 << 20, len(big) - (8 << 20)])
            # A file past one piece is measured once, after its first piece, for each read.
            self.assertEqual([e["path"] for e in s.runs("size")], ["big.bin", "big.bin"])
            await env.write_file("eight.bin", b"8" * (8 << 20))  # exactly one piece's worth
            self.assertEqual(len(await env.read_file("eight.bin")), 8 << 20)
            text = "é" * (3 << 20)  # 6 MiB of UTF-8: past one call's file budget, so as bytes
            await env.write_file("big.txt", text)
            self.assertEqual(s.files["big.txt"], text.encode("utf-8"))
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
            with self.assertRaises(FileNotFoundError):
                await env.read_file("missing")
            with self.assertRaises(IsADirectoryError):
                await env.read_file("d")
            with self.assertRaises(PermissionError):
                await env.read_file("secret")
            with self.assertRaises(FileNotFoundError):
                async for _ in env.read_file_stream("missing"):
                    pass
            self.assertEqual(len(s.runs("why")), 4)
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
            self.assertEqual([e["kind"] for e in s.log], ["root"])
        run(go())

    def test_a_write_error_carries_no_sandbox_text(self) -> None:
        async def go() -> None:
            env, s = await opened()
            s.fail["write"] = ["write_denied"]
            with self.assertRaises(PermissionError) as caught:
                await env.write_file("a.bin", b"x")
            self.assertNotIn(GUEST_TEXT, str(caught.exception))
            self.assertEqual(caught.exception.filename, "a.bin")
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
            s.fail["write"] = ["setup_failed"]
            with self.assertRaises(PlimsollEnvironmentError) as caught:
                await env.write_file("a", "x")
            self.assertFalse(caught.exception.call.uncertain)
            self.assertIn("nothing of it ran", str(caught.exception))
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
            await env.initialize()  # idempotent while the environment holds a session
            self.assertEqual(len(client.opened), 1)
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
            self.assertEqual([c.function_call_id for c in env.calls], [None, "adk-123", "adk-124"])
            self.assertEqual([e["trace_id"] for e in s.log], [None, "adk-123", "adk-124"])
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
            # The toolset told the model where it works (_environment_toolset.py:144).
            self.assertIn("/work/", str(model.requests[0].config.system_instruction))
            # Every call but the first (the work directory, before any tool call) serves one
            # ADK tool call, names it, and sent its ID to the daemon as the trace ID.
            calls = env.calls
            self.assertEqual(calls[0].method, "initialize")
            self.assertEqual({c.function_call_id for c in calls[1:]}, set(answers))
            self.assertEqual([e["trace_id"] for e in s.log[1:]], [c.function_call_id for c in calls[1:]])
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
        async def go(plugins: List[Any]) -> FakeSession:
            SPANS.clear()
            client = FakeClient()
            env = PlimsollEnvironment(client)  # type: ignore[arg-type]
            await env.initialize()
            client.session.files["a.txt"] = b"count = 1\n"
            client.session.fail["write"] = ["unanswered"]
            model = self.rerun_on_error("EditFile", {"path": "a.txt", "old_string": "1", "new_string": "2"})
            try:
                await run_agent(env, model, plugins)
            except RuntimeError as e:
                self.assertIsInstance(e.__cause__, PlimsollEnvironmentError)
                self.assertNotIn(GUEST_TEXT, str(e))
            return client.session
        # EditFileTool does not catch a write's error (_edit_file_tool.py:154), so ADK's
        # ReflectAndRetryToolPlugin answers it by asking the model to try again.
        s = run(go([ReflectAndRetryToolPlugin()]))
        self.assertEqual(len(s.runs("write")), 2)
        s = run(go([PlimsollEnvironmentGuard(), ReflectAndRetryToolPlugin()]))
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
            self.assertEqual([c.dispatched for c in env.calls[1:]], ["no", "yes"])
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
    sharing one environment. These cases hold what the docs say about it."""

    @staticmethod
    async def lead(shared: bool) -> Tuple[FakeClient, FakeClient, Any]:
        lead_client, child_client = FakeClient(), FakeClient()
        lead_env = PlimsollEnvironment(lead_client)  # type: ignore[arg-type]
        child_env = lead_env if shared else PlimsollEnvironment(child_client)  # type: ignore[arg-type]
        from google.adk.tools.agent_tool import AgentTool

        child = Agent(name="writer", description="Writes the file.",
                      model=scripted([("WriteFile", {"path": "from-child.txt", "content": "child\n"})], "written"),
                      tools=[EnvironmentToolset(environment=child_env)])
        model = ToolModel(plan=lambda responses, turn: [("writer", {"request": "write it"})] if turn == 0
                          else [("Execute", {"command": "echo lead"})] if turn == 1 else "done")
        agent = Agent(name="lead", model=model, tools=[AgentTool(agent=child), EnvironmentToolset(environment=lead_env)])
        sessions = InMemorySessionService()
        session = await sessions.create_session(app_name="adk-env-test", user_id="user")
        runner = Runner(agent=agent, app_name="adk-env-test", session_service=sessions, plugins=[PlimsollEnvironmentGuard()])
        try:
            events = [e async for e in runner.run_async(user_id="user", session_id=session.id,
                                                        new_message=types.Content(role="user", parts=[types.Part(text="Go.")]))]
        except RuntimeError as e:
            events = e
        return lead_client, child_client, events

    def test_a_wrapped_agent_with_an_environment_of_its_own_works(self) -> None:
        lead, child, events = run(self.lead(shared=False))
        self.assertIsInstance(events, list)
        self.assertEqual(child.sessions[0].files["from-child.txt"], b"child\n")
        self.assertEqual(child.sessions[0].closed, 1)  # its nested Runner closed it when it finished
        self.assertEqual(lead.session.commands(), ["echo lead"])
        self.assertEqual(lead.session.closed, 0)

    def test_an_environment_shared_with_a_wrapped_agent_is_closed_when_it_finishes(self) -> None:
        lead, _, events = run(self.lead(shared=True))
        self.assertEqual(lead.sessions[0].files["from-child.txt"], b"child\n")
        self.assertEqual(lead.sessions[0].closed, 1)
        self.assertIsInstance(events, RuntimeError)  # the lead's toolset still takes it for open
        self.assertEqual(lead.sessions[0].commands(), [])


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


if __name__ == "__main__":
    unittest.main()
