"""PlimsollWorkspace, its backend, plimsoll's shell tool and the code tool through PydanticAI's own paths: real
Agents driven by TestModel or a scripted FunctionModel (no model provider is called, and a guard below fails any
test that would), PydanticAI's Workspace facade and FileSystem capability, and its durable engines' error table. A
real plimsoll Workspace runs over a session faked in memory (frameworks/pydantic_ai/_fake.py, checked against the
real Session attribute by attribute); the cases marked "daemon" use a real Session on the in-process daemon of
fake sessions. What the backend does on a real sandbox is the docker check's (docker_pydantic_ai_check.py).

The error mapping (map_error) has one case per kind of answer. The kinds that need a checkpoint store or a session
reached from another process have no case, because the package has neither: a stale owner refused, a checkpoint
that does not match, a store conflict, a store write that fails after a verified answer (a record sink's failure,
the nearest the package has, has its case)."""

from __future__ import annotations

import asyncio
import inspect
import os
import re
import threading
import tomllib
import types
import unittest
from dataclasses import replace
from typing import Any, List, Optional, Tuple
from unittest import mock

import pydantic_ai.models
from pydantic_ai import Agent
from pydantic_ai.exceptions import RunCancelled, UserError
from pydantic_ai.messages import ModelRequest, ModelResponse, RetryPromptPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.workspaces import (
    SupportsCommands,
    SupportsFilesystem,
    SupportsRealpath,
    Workspace,
    WorkspaceBackend,
    WorkspaceError,
    WorkspaceOutputLimitError,
    WorkspaceRef,
    WorkspaceTimeoutError,
    WorkspaceUnavailableError,
)
from pydantic_ai_harness import FileSystem

import plimsoll_client
import plimsoll_client.pydantic_ai as pa
import plimsoll_client.workspace as pw
from frameworks.pydantic_ai._fake import ROOT, FakeClient, FakeSession, real_session, record, shape_differences
from frameworks.pydantic_ai._scripted import Scripted
from plimsoll_client import (
    AtCapacityError,
    ChainError,
    Client,
    InsufficientIsolationError,
    InvalidRequestError,
    PlimsollError,
    ProtocolMismatchError,
    RecordMismatchError,
    RequestCanceledError,
    RequestTimeoutError,
    SessionEndedError,
    TransportError,
    UnsupportedError,
)
from plimsoll_client._tables import UNANSWERED_CODES
from plimsoll_client.execution import CodeExecutor
from plimsoll_client.pydantic_ai import (
    JsonLinesRecordSink,
    PlimsollAlreadySentError,
    PlimsollOutcomeUnknownError,
    PlimsollRetryableError,
    PlimsollWorkspace,
    PlimsollWorkspaceBackend,
    PlimsollWorkspaceGoneError,
    map_error,
    plimsoll_code_tool,
)
from tests._env import setting

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE = os.path.join(HERE, "..", "..", "pydantic-ai-plimsoll")

# ---- no model provider, ever ----

_infer_model = pydantic_ai.models.infer_model


def _only_local_models(model: Any, *args: Any, **kwargs: Any) -> Any:
    """PydanticAI's infer_model, refusing every model but TestModel and FunctionModel: no test of this suite may
    reach a model provider (a string names one)."""
    if not isinstance(model, (TestModel, FunctionModel)):
        raise AssertionError(f"a test asked for model {model!r}; this suite uses only TestModel and FunctionModel")
    return _infer_model(model, *args, **kwargs)


_guard = mock.patch.object(pydantic_ai.models, "infer_model", _only_local_models)


def setUpModule() -> None:
    _guard.start()


def tearDownModule() -> None:
    _guard.stop()


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def cap(client: Optional[Client] = None, **kw: Any) -> PlimsollWorkspace:
    return PlimsollWorkspace(client=client if client is not None else FakeClient(), minimum_isolation="kernel", **kw)


def backend(c: Optional[FakeClient] = None, **kw: Any) -> PlimsollWorkspaceBackend:
    return cap(c, **kw).backend()


async def first(b: WorkspaceBackend) -> str:
    return await b.working_dir()


def no_pause() -> Any:
    """The capacity retries' pauses recorded instead of slept."""
    pauses: List[float] = []
    return mock.patch.object(pa, "_sleep", pauses.append), pauses


class ChangedAfterFirstLoad(plimsoll_client.MemoryCheckpointStore):
    """A memory store that runs ``then`` once, right after its first load: another writer between a backend's check of
    the store and the attach's own read of it."""

    def __init__(self) -> None:
        super().__init__()
        self.then: Optional[Any] = None

    def load(self, key: str) -> Optional[plimsoll_client.StoredCheckpoint]:
        got = super().load(key)
        hook, self.then = self.then, None
        if hook is not None:
            hook()
        return got


def hold(store: Any, key: str, fingerprint: str) -> bool:
    """Puts a ready checkpoint of the session ``fingerprint`` under ``key``; whether the store took it."""
    cp = plimsoll_client.SessionCheckpoint(
        version=plimsoll_client.checkpoint.CHECKPOINT_VERSION, daemon="plimsoll", session=fingerprint, generation=1, calls=0,
        last_record_sha256="", provider="fake-sessions", isolation="kernel", isolation_qualification="",
        software_identity="", open_floor="", open_rule="", expires_unix_ms=1893456000000, idle_timeout_ms=60000)
    ready = plimsoll_client.StoredCheckpoint(revision=1, state="ready", operation="", checkpoint=cp)
    return store.compare_and_set(key, None, ready)


class NoModelProviderTests(unittest.TestCase):
    def test_a_model_by_name_is_refused(self) -> None:
        with self.assertRaises(AssertionError):
            pydantic_ai.models.infer_model("openai:any-model")
        with self.assertRaises(AssertionError):
            run(Agent("anthropic:claude-opus-5-5").run("x"))


class FakeShapeTests(unittest.TestCase):
    """The fakes against the real Session and Client, attribute by attribute."""

    # The fake's own handles for a test, which the real Session must not have (so none shadows a real name).
    TEST_ONLY = {"tree", "plan", "commands", "scripts", "budgets", "closes", "end", "result", "answer", "script", "lost_command"}

    def test_the_fake_session_is_the_real_sessions_shape(self) -> None:
        fake, real = FakeSession(), real_session()
        names = [n for n in dir(fake) if not n.startswith("_") and n not in self.TEST_ONLY]
        self.assertEqual(shape_differences(fake, real, only=names), [])
        for name in self.TEST_ONLY:
            self.assertFalse(hasattr(real, name), f"the real Session has {name}, which the fake uses for tests only")

    def test_every_session_member_the_backend_reads_is_on_the_fake(self) -> None:
        used = ["run_project", "close", "fingerprint", "isolation", "ended", "stopped", "lost_call"]
        self.assertEqual(shape_differences(FakeSession(), real_session(), only=used), [])

    def test_the_fake_clients_open_is_the_real_ones(self) -> None:
        self.assertEqual(shape_differences(FakeClient(), Client("http://127.0.0.1:9"), only=["open_session", "attach_session"]), [])

    def test_the_check_finds_a_property_modeled_as_a_method(self) -> None:
        class Wrong(FakeSession):
            def stopped(self) -> Optional[str]:  # type: ignore[override]
                return None

            def run_project(self, files: Any, steps: Any) -> Any:  # type: ignore[override]
                return None

        found = shape_differences(Wrong(), real_session(), only=["stopped", "run_project"])
        self.assertTrue(any(d.startswith("stopped: a method on the fake, a value") for d in found), found)
        self.assertTrue(any(d.startswith("run_project: the fake lacks the parameter 'artifacts'") for d in found), found)


class ContractTests(unittest.TestCase):
    def test_it_claims_no_command_support(self) -> None:
        b = backend()
        self.assertIsInstance(b, WorkspaceBackend)
        self.assertIsInstance(b, SupportsFilesystem)
        self.assertIsInstance(b, SupportsRealpath)
        self.assertNotIsInstance(b, SupportsCommands)
        for name in ("run", "run_in_directory"):
            self.assertFalse(hasattr(b, name), f"the backend has {name}: it would claim commands")

    def test_a_command_through_the_workspace_raises_user_error_and_sends_nothing(self) -> None:
        c = FakeClient()
        with self.assertRaises(UserError):
            run(Workspace(backend(c)).run(["true"]))
        self.assertEqual(c.opened, [])

    def test_it_does_no_io_when_built(self) -> None:
        c = FakeClient()
        b = backend(c)
        self.assertIsNone(b.ref)
        self.assertEqual(c.opened, [])

    def test_the_ref_is_recorded_at_the_open_and_never_changes(self) -> None:
        c = FakeClient()
        b = backend(c)
        self.assertEqual(run(first(b)), ROOT)
        self.assertEqual(b.ref, WorkspaceRef(provider="plimsoll", id="plimsoll/" + "f" * 64))
        run(Workspace(b).write_text("a", "x"))
        self.assertEqual(b.ref, WorkspaceRef(provider="plimsoll", id="plimsoll/" + "f" * 64))
        self.assertEqual(c.opened, [{"minimum_isolation": "kernel", "lifetime": 3600.0, "languages": None, "owner": None}])

    def test_concurrent_first_operations_open_one_session(self) -> None:
        c = FakeClient()
        b = backend(c)

        async def go() -> None:
            ws = Workspace(b)
            await asyncio.gather(*(ws.write_text(f"f{i}", str(i)) for i in range(5)))

        run(go())
        self.assertEqual(len(c.sessions), 1)
        self.assertEqual(sorted(c.session.tree.files), [f"{ROOT}/f{i}" for i in range(5)])

    def test_a_run_canceled_while_the_session_opens_keeps_its_ref(self) -> None:
        # asyncio's own cancel (Task.cancel, as wait_for, asyncio.timeout and PydanticAI's runs send it) is raised
        # only once the operation's thread has finished, the open and its ref included: anyio's shielded scope does
        # not hold it back, and it once ended the await while the open went on (release-95). The open is held after
        # it returns, before the ref is published, and the cancel must not end the await meanwhile; no sleep decides
        # it, only the event loop's own turns, in which the old code delivered the cancel.
        c = FakeClient()
        workspace = cap(c)
        b = workspace.backend()
        opened, release = threading.Event(), threading.Event()
        register = workspace._register

        def held(env: Any) -> None:
            opened.set()
            release.wait(5)
            register(env)

        workspace._register = held  # type: ignore[method-assign]

        async def go() -> bool:
            task = asyncio.create_task(first(b))
            await asyncio.to_thread(opened.wait, 5)
            task.cancel()
            for _ in range(200):
                if task.done():
                    break
                await asyncio.sleep(0)
            ended_early = task.done()
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            return ended_early

        self.assertFalse(run(go()), "the cancel ended the await while the open was still publishing its ref")
        self.assertIsNotNone(b.ref, "the open finished and its ref was kept")
        self.assertEqual(c.session.closes, 0, "a canceled open never closes the session it opened")

    def test_a_run_canceled_while_its_session_opens_records_the_ref_a_resumed_run_reaches(self) -> None:
        # The same cancel through PydanticAI's own path: AgentRun.cancel() while the first file tool opens the
        # session. The canceled run's messages, which RunCancelled hands back for a resumed run, carry the ref
        # (PydanticAI reads backend.ref as the run tears down), so the resumed run reaches the session the canceled
        # one opened, rather than opening a second and leaving the first open, named by nothing, until its lifetime
        # ends (release-95).
        c = FakeClient()
        workspace = cap(c)
        opened, release = threading.Event(), threading.Event()
        register = workspace._register

        def held(env: Any) -> None:
            opened.set()
            release.wait(5)
            register(env)

        workspace._register = held  # type: ignore[method-assign]
        one = Scripted(("write_file", {"path": "kept.txt", "content": "first run"}))
        agent = Agent(one.model, capabilities=[workspace, FileSystem(content_hashes=False)])
        runs: List[Any] = []

        async def drive() -> None:
            async with agent.iter("go") as r:
                runs.append(r)
                async for _ in r:
                    pass

        async def go() -> Tuple[bool, Any]:
            task = asyncio.create_task(drive())
            await asyncio.to_thread(opened.wait, 5)
            runs[0].cancel()
            for _ in range(500):
                if task.done():
                    break
                await asyncio.sleep(0)
            ended_early = task.done()
            release.set()
            with self.assertRaises(RunCancelled) as e:
                await task
            return ended_early, e.exception

        ended_early, canceled = run(go())
        workspace._register = register  # type: ignore[method-assign]
        self.assertFalse(ended_early, "the run ended while its session's open was still publishing its ref")
        refs = [m.workspace_ref for m in canceled.all_messages() if isinstance(m, ModelResponse)]
        self.assertEqual(refs[-1], WorkspaceRef(provider="plimsoll", id="plimsoll/" + c.session.fingerprint))
        # The canceled run's write never ran (its first operation, which opened the session, carried the cancel);
        # the resumed run's write lands in the session the canceled run opened.
        two = Scripted(("write_file", {"path": "kept.txt", "content": "resumed"}))
        run(Agent(two.model, capabilities=[workspace, FileSystem(content_hashes=False)]).run(
            "again", message_history=canceled.all_messages()))
        self.assertEqual(len(c.sessions), 1, "the resumed run opened a second session")
        self.assertEqual(c.session.tree.files[ROOT + "/kept.txt"], b"resumed")
        self.assertEqual(c.session.closes, 0)

    def test_a_second_operation_during_the_first_open_waits_for_it_and_opens_nothing(self) -> None:
        # The window between the open's return and the ref's publication: a second operation of the same backend
        # (another run's, in another thread) waits for the open in flight and uses its session; it never sees no ref
        # and opens a second one. The first open is held in that window until the second is at the backend's lock.
        c = FakeClient()
        workspace = cap(c)
        b = workspace.backend()
        opened, release, waiting = threading.Event(), threading.Event(), threading.Event()
        register = workspace._register

        def held(env: Any) -> None:
            opened.set()
            release.wait(5)
            register(env)

        workspace._register = held  # type: ignore[method-assign]
        lock = b._lock
        roots: List[str] = []
        starter = threading.Thread(target=lambda: roots.append(run(first(b))))

        class Watched:
            def __enter__(self) -> None:
                if threading.current_thread() is not starter:
                    waiting.set()
                lock.acquire()

            def __exit__(self, *exc: Any) -> None:
                lock.release()

        b._lock = Watched()  # type: ignore[assignment]
        starter.start()
        self.assertTrue(opened.wait(5))
        second = threading.Thread(target=lambda: roots.append(run(first(b))))
        second.start()
        self.assertTrue(waiting.wait(5), "the second operation never reached the backend's lock")
        opens_meanwhile = len(c.opened)
        release.set()
        starter.join(5)
        second.join(5)
        self.assertEqual(opens_meanwhile, 1, "the second operation opened a session while the first was publishing")
        self.assertEqual(len(c.opened), 1)
        self.assertEqual(len(c.sessions), 1)
        self.assertEqual(roots, [ROOT, ROOT])
        self.assertEqual(c.session.closes, 0)

    def test_a_run_never_closes_its_session(self) -> None:
        c = FakeClient()
        script = Scripted(("write_file", {"path": "a.txt", "content": "x"}))
        run(Agent(script.model, capabilities=[cap(c), FileSystem(content_hashes=False)]).run("go"))
        self.assertEqual(c.session.closes, 0)

    def test_a_session_below_the_floor_is_closed_and_nothing_runs(self) -> None:
        c = FakeClient(isolation="container")
        b = backend(c)
        with self.assertRaises(PlimsollWorkspaceGoneError) as e:
            run(first(b))
        self.assertEqual(e.exception.reason, "isolation")
        self.assertEqual(c.session.closes, 1)
        self.assertEqual(c.session.calls, 0)

    def test_paths_must_be_absolute(self) -> None:
        with self.assertRaises(ValueError):
            run(backend().read_bytes("relative"))
        with self.assertRaises(ValueError):
            run(backend().read_bytes("/a\x00b"))
        with self.assertRaises(TypeError):
            run(backend().read_bytes(b"/a"))  # type: ignore[arg-type]

    def test_plimsolls_state_directory_is_never_listed_or_touched(self) -> None:
        b = backend()
        ws = Workspace(b)
        run(ws.write_text("seen", "x"))
        self.assertEqual([e.name for e in run(ws.list_dir("."))], ["seen"])
        for op in (ws.read_bytes, ws.stat, ws.remove):
            with self.assertRaises(PermissionError):
                run(op(pw.STATE_DIR + "/cmd"))
        with self.assertRaises(PermissionError):
            run(ws.write_bytes(pw.STATE_DIR + "/env", b"export X=1"))

    def test_remove_refuses_the_working_directory_and_its_ancestors(self) -> None:
        ws = Workspace(backend())
        for path in (".", ROOT, "/"):
            with self.assertRaises(ValueError):
                run(ws.remove(path))

    def test_a_large_write_goes_in_pieces_and_keeps_the_file_whole(self) -> None:
        c = FakeClient()
        ws = Workspace(backend(c))
        data = bytes(range(256)) * (9 * 1024 * 4)  # 9 MiB
        run(ws.write_bytes("big.bin", data))
        self.assertEqual(c.session.tree.files[ROOT + "/big.bin"], data)
        self.assertEqual([k for k in c.session.tree.files if ".plimsoll-write-" in k], [], "the staging file was removed")
        self.assertEqual(c.session.scripts.count(pa._WRITE_BEGIN), 1)
        self.assertEqual(c.session.scripts.count(pa._WRITE_COMMIT), 1)

    def test_a_file_past_the_whole_read_limit_is_refused_before_it_is_read(self) -> None:
        # Finding release-46: a sandbox can make a file of any size for nothing (a sparse one), and a whole read ends
        # in this process's memory. The fake's file is the limit plus one byte.
        c = FakeClient()
        ws = Workspace(backend(c))
        run(ws.write_text("small", "x"))
        c.session.tree.files[ROOT + "/huge.bin"] = bytes(pw.MAX_WHOLE_BYTES + 1)
        calls = c.session._calls
        with self.assertRaises(WorkspaceError) as caught:
            run(ws.read_bytes("huge.bin"))
        self.assertIn("past the", str(caught.exception))
        self.assertEqual(c.session._calls - calls, 1, "a call past the read check (its size) was sent for a file past the limit")
        self.assertEqual(c.session.scripts[-1], pa._READ_CHECK)


class ErrorMappingTests(unittest.TestCase):
    """One case per kind of answer the mapping turns into PydanticAI's errors."""

    def setUp(self) -> None:
        self.client = FakeClient()
        self.backend = backend(self.client)
        self.ws = Workspace(self.backend)
        run(first(self.backend))
        self.session = self.client.session

    def plan(self, *items: Any) -> None:
        self.session.plan.extend(items)

    def test_row_an_answer_with_any_exit_code_is_a_result(self) -> None:
        self.assertFalse(run(self.ws.exists("missing")))  # `test -e` exiting 1 is an answer, not an error
        self.plan(lambda s, f, st: s.result(b"", b"boom", 7))
        with self.assertRaises(WorkspaceError) as e:
            run(self.ws.exists("x"))
        self.assertNotIsInstance(e.exception, WorkspaceUnavailableError)
        self.assertIn("exit 7", str(e.exception))

    def test_row_timed_out_raises_workspace_timeout_error_with_the_partial_output(self) -> None:
        self.plan(lambda s, f, st: s.result(b"part", b"", 124, outcome="timed_out", timed_out=True))
        with self.assertRaises(WorkspaceTimeoutError) as e:
            run(self.ws.stat("x"))
        self.assertEqual(e.exception.stdout, "part")

    def test_row_a_cut_stream_raises_the_output_limit_error(self) -> None:
        self.plan(lambda s, f, st: s.result(b"d", b"", 0, stdout_truncated=True))
        with self.assertRaises(WorkspaceOutputLimitError) as e:
            run(self.ws.list_dir("."))
        self.assertEqual(e.exception.limit, 1 << 20)

    def test_row_path_errors_are_the_builtin_errors(self) -> None:
        t = self.session.tree
        t.files[ROOT + "/file"] = b"x"
        t.dirs.add(ROOT + "/dir")
        t.files[ROOT + "/locked"] = b"x"
        t.unreadable.add(ROOT + "/locked")
        cases = [
            (self.ws.read_bytes, "missing", FileNotFoundError),
            (self.ws.stat, "missing", FileNotFoundError),
            (self.ws.list_dir, "missing", FileNotFoundError),
            (self.ws.remove, "missing", FileNotFoundError),
            (self.ws.read_bytes, "dir", IsADirectoryError),
            (self.ws.list_dir, "file", NotADirectoryError),
            (self.ws.make_dir, "file", FileExistsError),
            (self.ws.make_dir, "file/child", NotADirectoryError),
            (self.ws.read_bytes, "locked", PermissionError),
        ]
        for op, path, err in cases:
            with self.subTest(op=op.__name__, path=path):
                with self.assertRaises(err):
                    run(op(path))
        with self.assertRaises(IsADirectoryError):
            run(self.ws.write_bytes("dir", b"x"))
        with self.assertRaises(NotADirectoryError):
            run(self.ws.write_bytes("file/child", b"x"))
        self.assertEqual(pa._path_error(pa._ENOTREG, "/p", "", "reading").__class__, OSError)

    def test_row_capacity_is_retried_by_the_backend_then_raised_retryable(self) -> None:
        busy = lambda: AtCapacityError("busy", not_dispatched="capacity")  # noqa: E731
        patch, pauses = no_pause()
        with patch:
            self.plan(busy(), busy())
            self.assertFalse(run(self.ws.exists("x")))
            self.assertEqual(pauses, [0.5, 1.0])
            pauses.clear()
            self.plan(*[busy() for _ in range(10)])
            with self.assertRaises(PlimsollRetryableError) as e:
                run(self.ws.exists("x"))
        self.assertEqual(e.exception.reason, "capacity")
        self.assertLessEqual(sum(pauses), pa.CAPACITY_RETRY_SECONDS)
        self.assertIsInstance(e.exception, ConnectionError)
        self.assertNotIsInstance(e.exception, WorkspaceError)

    def test_row_capacity_at_the_open_is_retried_too(self) -> None:
        c = FakeClient()
        c.refuse = [AtCapacityError("full", not_dispatched="capacity")]
        patch, pauses = no_pause()
        with patch:
            run(first(backend(c)))
        self.assertEqual(len(c.opened), 2)
        self.assertEqual(pauses, [0.5])

    def test_row_environment_raises_retryable_at_once(self) -> None:
        self.plan(TransportError("connect refused", not_dispatched="environment"))
        with self.assertRaises(PlimsollRetryableError) as e:
            run(self.ws.exists("x"))
        self.assertEqual(e.exception.reason, "environment")
        self.assertTrue(run(self.ws.exists(".")), "nothing ran and the session goes on")

    def test_row_request_raises_value_error(self) -> None:
        self.plan(InvalidRequestError("too big", not_dispatched="request"))
        with self.assertRaises(ValueError):
            run(self.ws.exists("x"))
        self.assertTrue(run(self.ws.exists(".")))

    def test_row_permission_protocol_unsupported_and_isolation_raise_gone_naming_the_reason(self) -> None:
        for err in (
            PlimsollError("denied", not_dispatched="permission"),
            ProtocolMismatchError("old daemon", not_dispatched="protocol"),
            UnsupportedError("no", not_dispatched="unsupported"),
            InsufficientIsolationError("below", not_dispatched="isolation"),
        ):
            with self.subTest(reason=err.not_dispatched):
                self.plan(err)
                with self.assertRaises(PlimsollWorkspaceGoneError) as e:
                    run(self.ws.exists("x"))
                self.assertEqual(e.exception.reason, err.not_dispatched)

    def test_row_a_session_that_ended_raises_gone_and_is_never_replaced(self) -> None:
        self.plan(SessionEndedError("ended", reason="expired", not_dispatched="request"))
        with self.assertRaises(PlimsollWorkspaceGoneError) as e:
            run(self.ws.exists("x"))
        self.assertEqual(e.exception.reason, "expired")
        with self.assertRaises(PlimsollWorkspaceGoneError):
            run(self.ws.exists("x"))
        self.assertEqual(len(self.client.sessions), 1, "no session opened in its place")

    def test_row_a_call_that_ended_the_session_answers_then_the_next_raises_gone(self) -> None:
        self.plan(lambda s, f, st: s.result(b"", b"", 0, ended="disk_exceeded"))
        self.assertTrue(run(self.ws.exists(".")))
        with self.assertRaises(PlimsollWorkspaceGoneError) as e:
            run(self.ws.exists("."))
        self.assertEqual(e.exception.reason, "disk_exceeded")

    def test_row_an_unanswered_call_with_a_checked_record_is_unknown_and_the_session_goes_on(self) -> None:
        err = PlimsollError("the stream broke after the call started", code="unavailable")
        err.record = record(2, "1".zfill(64))
        self.plan(err)
        with self.assertRaises(PlimsollOutcomeUnknownError) as e:
            run(self.ws.exists("x"))
        self.assertIs(e.exception.record, err.record)
        self.assertIn(err.record, self.backend.records, "its record was kept")
        self.assertTrue(run(self.ws.exists(".")), "the chain moved past the call, so the session goes on")

    def test_row_any_other_unmarked_error_is_unknown_and_the_session_sends_nothing_more(self) -> None:
        for err in (
            TransportError("connection reset after sending"),
            RequestTimeoutError("no answer in time"),
            RequestCanceledError("cut in flight"),
            PlimsollError("internal error 7", code="internal"),
        ):
            with self.subTest(error=type(err).__name__):
                self.setUp()
                self.plan(err)
                with self.assertRaises(PlimsollOutcomeUnknownError):
                    run(self.ws.exists("x"))
                with self.assertRaises(PlimsollWorkspaceGoneError) as e:
                    run(self.ws.exists("x"))
                self.assertEqual(e.exception.reason, "stopped")

    def test_row_evidence_that_does_not_check_is_unknown_and_stops_the_session(self) -> None:
        for err in (RecordMismatchError("digest"), ChainError("chain")):
            with self.subTest(error=type(err).__name__):
                self.setUp()
                self.plan(err)
                with self.assertRaises(PlimsollOutcomeUnknownError) as e:
                    run(self.ws.exists("x"))
                self.assertIn(type(err).__name__, str(e.exception))
                with self.assertRaises(PlimsollWorkspaceGoneError):
                    run(self.ws.exists("x"))

    def test_row_a_record_that_cannot_be_kept_is_unknown_never_not_run(self) -> None:
        def broken(_: Any) -> None:
            raise OSError("disk full")

        c = FakeClient()
        ws = Workspace(cap(c, record_sink=broken).backend())
        with self.assertRaises(PlimsollOutcomeUnknownError) as e:
            run(ws.exists("."))
        self.assertIsNotNone(e.exception.record)

    def test_an_answer_without_a_step_report_is_unknown_and_setup_failed_did_not_run(self) -> None:
        for outcome in ("protocol_error", "runner_failed", "completed"):
            with self.subTest(outcome=outcome):
                self.plan(lambda s, f, st, o=outcome: s.result(outcome=o, steps=False))
                with self.assertRaises(PlimsollOutcomeUnknownError):
                    run(self.ws.exists("x"))
        self.plan(lambda s, f, st: s.result(outcome="setup_failed", steps=False))
        with self.assertRaises(WorkspaceError) as e:
            run(self.ws.exists("x"))
        self.assertNotIsInstance(e.exception, WorkspaceUnavailableError)

    def test_no_error_without_the_mark_is_ever_reported_as_one_that_did_not_run(self) -> None:
        def classes(c: type) -> List[type]:
            return [c] + [s for sub in c.__subclasses__() for s in classes(sub)]

        for cls in classes(PlimsollError):
            with self.subTest(cls=cls.__name__):
                e = cls.__new__(cls)
                PlimsollError.__init__(e, "may have run")
                if cls is SessionEndedError:
                    e.reason, e.detail = "closed", ""
                self.assertIsInstance(map_error(e), PlimsollOutcomeUnknownError)

    def test_the_engines_journal_what_may_have_run_and_retry_only_what_did_not(self) -> None:
        # PydanticAI's own table (durable_exec._workspace.error_as_data): an error it carries as data is re-raised and
        # never retried by the engine; one it does not carry (None) is retried.
        from pydantic_ai.durable_exec._workspace import error_as_data

        self.assertIsNotNone(error_as_data(PlimsollOutcomeUnknownError("may have run")))
        self.assertIsNotNone(error_as_data(PlimsollWorkspaceGoneError("ended", reason="closed")))
        self.assertIsNone(error_as_data(PlimsollRetryableError("busy", reason="capacity")))
        for cls in (PlimsollOutcomeUnknownError, PlimsollWorkspaceGoneError):
            self.assertTrue(issubclass(cls, WorkspaceUnavailableError), "Temporal and Prefect never retry it inside a tool")


class CheckpointStoreTests(unittest.TestCase):
    """Stage 2: a capability with a checkpoint store, and the mapping rows that need a store or an attach (the
    cross-process cases run on docker, docker_pydantic_ai_check.py)."""

    def stored(self, c: Optional[FakeClient] = None) -> Any:
        c = c if c is not None else FakeClient()
        c.daemon_name = "plimsoll"
        return c, plimsoll_client.MemoryCheckpointStore()

    def test_the_store_rows_of_the_mapping(self) -> None:
        ran = pa.map_error(plimsoll_client.CheckpointStoreError("written?", sent=True))
        self.assertIsInstance(ran, PlimsollOutcomeUnknownError)
        unsent = pa.map_error(plimsoll_client.CheckpointConflictError("moved", sent=False))
        self.assertIsInstance(unsent, PlimsollWorkspaceGoneError)
        self.assertEqual(unsent.reason, "store")
        again = pa.map_error(plimsoll_client.CallAlreadySentError("sent", not_dispatched="request"))
        self.assertIsInstance(again, PlimsollAlreadySentError)
        self.assertIsInstance(again, PlimsollOutcomeUnknownError, "no engine retries it: the lost call may have run")
        self.assertIn("was already sent once", str(again))
        self.assertNotIn("ran once", str(again))
        lost = pa.map_error(plimsoll_client.CheckpointMismatchError("mismatch", not_dispatched="request"))
        self.assertIsInstance(lost, PlimsollOutcomeUnknownError)
        stale = pa.map_error(plimsoll_client.StaleOwnerError("stale", not_dispatched="permission"))
        self.assertIsInstance(stale, PlimsollWorkspaceGoneError)
        self.assertEqual(stale.reason, "stale")

    def test_a_store_and_a_key_go_together_and_name_the_daemon(self) -> None:
        c, store = self.stored()
        with self.assertRaises(ValueError):
            cap(c, checkpoint_store=store)
        with self.assertRaises(ValueError):
            cap(c, checkpoint_key=lambda ctx: "k")
        other = FakeClient()
        with self.assertRaises(ValueError):
            cap(other, checkpoint_store=store, checkpoint_key=lambda ctx: "k")  # the client has no daemon_name
        cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: "k")

    def test_a_store_backed_open_keeps_the_checkpoint_under_the_runs_key(self) -> None:
        c, store = self.stored()
        b = cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: "k").backend(key="user-1/conv-1")
        run(b.working_dir())
        self.assertEqual((c.opened[0]["checkpoint_store"], c.opened[0]["checkpoint_key"]), (store, "user-1/conv-1"))

    def test_a_ref_not_open_here_is_taken_over_from_the_store_or_never_replaced(self) -> None:
        c, store = self.stored()
        ref = WorkspaceRef(provider="plimsoll", id="plimsoll/" + "a" * 64)
        b = cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: "k").backend(ref, key="user-1/conv-1")
        with self.assertRaises(PlimsollWorkspaceGoneError) as e:
            run(b.working_dir())
        self.assertEqual(e.exception.reason, "not_found")
        self.assertEqual(c.attached, [("user-1/conv-1", store)])
        self.assertEqual(c.opened, [], "no fresh session in place of the ref's")

    def holding(self, store: Any, key: str, fingerprint: str) -> None:
        """Puts a ready checkpoint of the session ``fingerprint`` under ``key``."""
        self.assertTrue(hold(store, key, fingerprint))

    def test_a_key_naming_another_session_never_takes_that_session(self) -> None:
        c, store = self.stored()
        self.holding(store, "user-1/conv-2", "b" * 64)
        ref = WorkspaceRef(provider="plimsoll", id="plimsoll/" + "a" * 64)
        b = cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: "k").backend(ref, key="user-1/conv-2")
        with self.assertRaises(PlimsollWorkspaceGoneError) as e:
            run(b.working_dir())
        self.assertEqual(e.exception.reason, "not_found")
        self.assertEqual(c.attached, [], "checked before the attach: conversation 2's session stays with its worker")
        self.assertEqual(c.opened, [])

    def test_a_store_changed_to_another_session_before_the_attach_sends_nothing(self) -> None:
        # The store held the ref's session when the backend checked it and another conversation's by the attach's own
        # read: the attach is pinned to the ref's session, so it is refused before it is sent, and the other session
        # stays with its worker.
        c = FakeClient()
        c.daemon_name = "plimsoll"
        store = ChangedAfterFirstLoad()
        self.holding(store, "user-1/conv-1", "a" * 64)

        def another_conversation() -> None:
            held = store.load("user-1/conv-1")
            assert held is not None
            moved = replace(held, revision=held.revision + 1, checkpoint=replace(held.checkpoint, session="b" * 64))
            self.assertTrue(store.compare_and_set("user-1/conv-1", held, moved))

        store.then = another_conversation
        c.attach_answer = FakeSession()
        c.attach_answer.fingerprint = "b" * 64  # what an attach that read the store again unpinned would take
        ref = WorkspaceRef(provider="plimsoll", id="plimsoll/" + "a" * 64)
        b = cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: "k").backend(ref, key="user-1/conv-1")
        with self.assertRaises(PlimsollWorkspaceGoneError) as e:
            run(b.working_dir())
        self.assertEqual(e.exception.reason, "not_found")
        self.assertEqual(c.attached, [], "the attach was refused before it was sent")
        self.assertEqual(c.attach_answer.scripts, [])

    def test_a_marked_stale_owner_refusal_takes_the_session_back_once(self) -> None:
        # Refused with plimsoll's not-dispatched mark, the call ran nothing: the backend takes the session back from
        # the store and sends the operation again.
        c, store = self.stored()
        self.holding(store, "user-1/conv-1", "f" * 64)
        b = cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: "k").backend(key="user-1/conv-1")
        run(b.working_dir())
        c.attach_answer = FakeSession()
        c.session.plan = [plimsoll_client.StaleOwnerError("plimsoll: failed_precondition: stale", not_dispatched="permission")]
        self.assertFalse(run(b.exists(ROOT + "/missing")))
        self.assertEqual(len(c.attached), 1)
        self.assertNotEqual(c.attach_answer.scripts, [], "the operation was sent again on the session taken back")

    def test_a_stale_owner_refusal_without_the_mark_is_never_sent_again(self) -> None:
        # Without the mark the call may have run: the backend neither takes the session back nor sends the operation
        # again, and the run is told the outcome is unknown.
        c, store = self.stored()
        self.holding(store, "user-1/conv-1", "f" * 64)
        b = cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: "k").backend(key="user-1/conv-1")
        run(b.working_dir())
        c.attach_answer = FakeSession()
        c.session.plan = [plimsoll_client.StaleOwnerError("plimsoll: failed_precondition: stale")]
        with self.assertRaises(PlimsollOutcomeUnknownError):
            run(b.exists(ROOT + "/missing"))
        self.assertEqual(c.attached, [], "the session was not taken back")
        self.assertEqual(c.attach_answer.scripts, [], "and the operation was not sent again")

    def test_an_attach_answering_another_session_is_not_used(self) -> None:
        # A client whose attach answers another session than the ref's (plimsoll's client refuses one before sending).
        c, store = self.stored()
        self.holding(store, "user-1/conv-1", "a" * 64)
        c.attach_answer = FakeSession()  # fingerprint "f" * 64
        ref = WorkspaceRef(provider="plimsoll", id="plimsoll/" + "a" * 64)
        b = cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: "k").backend(ref, key="user-1/conv-1")
        with self.assertRaises(PlimsollWorkspaceGoneError) as e:
            run(b.working_dir())
        self.assertEqual(e.exception.reason, "not_found")
        self.assertEqual(len(c.attached), 1)
        self.assertEqual(c.attach_answer.scripts, [], "nothing runs on the session the attach answered")
        self.assertEqual(c.attach_answer.closes, 0, "and it is not closed: it holds another conversation's files")

    def test_an_attach_answering_the_refs_session_is_used(self) -> None:
        c, store = self.stored()
        self.holding(store, "user-1/conv-1", "f" * 64)
        c.attach_answer = FakeSession()
        ref = WorkspaceRef(provider="plimsoll", id="plimsoll/" + "f" * 64)
        b = cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: "k").backend(ref, key="user-1/conv-1")
        run(b.working_dir())
        self.assertEqual(len(c.attached), 1)
        self.assertNotEqual(c.attach_answer.scripts, [])
        self.assertEqual(c.opened, [])

    def test_a_run_derives_the_key_from_its_context(self) -> None:
        c, store = self.stored()
        keys: List[Any] = []

        def key(ctx: Any) -> str:
            keys.append(ctx)
            return "user-1/conv-1"

        agent = Agent(TestModel(call_tools=[]), capabilities=[cap(c, checkpoint_store=store, checkpoint_key=key)])
        run(agent.run("go"))
        self.assertTrue(keys, "the run asked for its key")

    def test_a_durable_unit_is_still_refused_with_a_store(self) -> None:
        from pydantic_ai.durable_exec._operation_backend import durable_unit_scope

        c, store = self.stored()
        agent = Agent(TestModel(call_tools=[]), capabilities=[cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: "k")])
        with durable_unit_scope():
            with self.assertRaises(UserError):
                run(agent.run("go"))
        self.assertEqual(c.opened, [])


# ---- a call lost before a takeover ----

TAKEOVER_KEY = "user-1/conv-1"
LOST_COMMAND = "python3 triage.py > by_route.json"


def lost_record(*, unanswered: str = "", ms: int = 3265) -> plimsoll_client.RunRecord:
    """The record a takeover returns for the call lost before it: answered (a result digest) unless ``unanswered``
    names the code it ended with; ``ms`` from its start to its end."""
    return plimsoll_client.RunRecord(
        version=5, request_sha256="3" * 64, result_sha256="" if unanswered else "4" * 64, provider="fake", isolation="kernel",
        environment="", policy="", software_identity="", software_rule_id="", started_unix_ms=1790000000000,
        ended_unix_ms=1790000000000 + ms, session="f" * 64, sequence=11, previous_sha256="a" * 64, sha256="b" * 64,
        unanswered=unanswered,
    )


def taken_over(lost: Optional[plimsoll_client.RunRecord], **kw: Any) -> Tuple[FakeClient, PlimsollWorkspace, PlimsollWorkspaceBackend]:
    """A capability with a checkpoint store, and a backend of it whose first operation takes the session over across
    a lost call: the attach answers a session carrying ``lost`` as its ``lost_call``, whose first call is refused
    when it repeats LOST_COMMAND (the client's rule, on the fake)."""
    c = FakeClient()
    c.daemon_name = "plimsoll"
    store = plimsoll_client.MemoryCheckpointStore()
    assert hold(store, TAKEOVER_KEY, "f" * 64)
    c.attach_answer = FakeSession()
    c.attach_answer.lost_call, c.attach_answer.lost_command = lost, LOST_COMMAND
    workspace = cap(c, checkpoint_store=store, checkpoint_key=lambda ctx: TAKEOVER_KEY, **kw)
    return c, workspace, workspace.backend(WorkspaceRef(provider="plimsoll", id="plimsoll/" + "f" * 64), key=TAKEOVER_KEY)


def shell_answers(result: Any) -> List[Any]:
    """The parts that answered a plimsoll_shell call in a run's messages: tool returns and retry prompts."""
    return [p for m in result.all_messages() if isinstance(m, ModelRequest) for p in m.parts
            if isinstance(p, (ToolReturnPart, RetryPromptPart)) and p.tool_name == "plimsoll_shell"]


class LostCallTests(unittest.TestCase):
    """A call whose answer was lost before a takeover. When the run's first call after the takeover is plimsoll_shell
    repeating it, the client refuses it with nothing sent, the model is told what the lost call's record says, in a
    failed tool result, and the run goes on; the record reaches the sink first, once; everything else that may have
    run still ends the run, and the refusal covers only a repeat sent first."""

    def told(self, lost: Optional[plimsoll_client.RunRecord]) -> str:
        c, workspace, b = taken_over(lost)
        script = Scripted(("plimsoll_shell", {"command": LOST_COMMAND}))
        result = run(Agent(script.model, capabilities=[workspace]).run("go", workspace=b))
        answers = shell_answers(result)
        self.assertEqual(len(answers), 1)
        self.assertIsInstance(answers[0], ToolReturnPart, "a retry prompt tells the model to send the command again")
        self.assertEqual(answers[0].outcome, "failed", "a success would have the run's ledger say the command ran here")
        self.assertEqual(result.output, "done", "the run went on to its answer")
        self.assertEqual(c.attach_answer.commands, [], "the repeat reached the session")
        told = str(answers[0].content)
        for code in UNANSWERED_CODES:
            self.assertNotIn(code, told, "a code of the protocol's, not plimsoll's words")
        self.assertNotIn(LOST_COMMAND, told)
        return told

    def test_an_answered_lost_call_is_told_only_that_the_sandbox_answered_and_the_run_goes_on(self) -> None:
        # Finding release-80: a result digest shows the daemon answered, not that the command ran to its end (the
        # answer can be a step stopped at its time limit, a setup that never ran, or a runner that did not report).
        told = self.told(lost_record(ms=3265))
        self.assertIn("this exact command was already sent once in this sandbox", told)
        self.assertIn("The sandbox answered the call after 3.3 s, but the answer is lost", told)
        self.assertIn("whether the command ran to its end, and whether it succeeded, is not known", told)
        self.assertNotIn("without an answer", told)
        for claim in ("finished", "started", "ran once"):
            self.assertNotIn(claim, told.lower())

    def test_an_unanswered_lost_call_is_told_only_that_it_ended_without_an_answer(self) -> None:
        # Finding release-79: an unanswered code shows the call was dispatched and ended in an error, not that the
        # command started (a worker killed before the runner's start marker leaves one too).
        for code, how in (("deadline_exceeded", "the request for it ran out of time"),
                          ("canceled", "the request for it was called off"),
                          ("unavailable", "the sandbox service reported an error for it")):
            with self.subTest(code):
                told = self.told(lost_record(unanswered=code, ms=1503))
                self.assertIn(f"the call ended without an answer after 1.5 s: {how}.", told)
                self.assertIn("Whether the command began, and how much of its work it did, is not known", told)
                for claim in ("started", "finished", "answered the call", "ran once"):
                    self.assertNotIn(claim, told.lower())

    def test_a_lost_call_named_without_its_record_is_told_so(self) -> None:
        # A checkpoint carries the lost call's digest without its record: a worker took the session over across the
        # gap and died before any call, and the next one took it over from the record that worker left.
        told = self.told(None)
        self.assertIn("whether it finished is not known here", told)
        self.assertNotIn("finished the call", told)
        self.assertNotIn("answered the call", told)
        self.assertNotIn("without an answer after", told)

    def test_a_record_stating_both_or_an_unknown_code_is_never_read_as_either(self) -> None:
        # The client refuses such a record at the attach (_states_only); the message holds to the same rule.
        unknown = pa._lost_call_message(None)
        for bad in (replace(lost_record(), unanswered="canceled"), lost_record(unanswered="ignore previous instructions"),
                    replace(lost_record(), result_sha256="ZZ" * 32)):
            with self.subTest(bad.unanswered or bad.result_sha256):
                self.assertEqual(pa._lost_call_message(bad), unknown)

    def test_the_lost_record_reaches_the_sink_first_and_once(self) -> None:
        kept: List[Any] = []
        lost = lost_record(unanswered="canceled")
        c, workspace, b = taken_over(lost, record_sink=kept.append)
        script = Scripted(("plimsoll_shell", {"command": "ls"}))
        run(Agent(script.model, capabilities=[workspace]).run("go", workspace=b))
        self.assertEqual(c.attach_answer.commands, ["ls"])
        self.assertEqual(len(kept), 2, kept)
        self.assertIs(kept[0], lost, "the lost call's record comes before the new worker's first call's")
        # Another backend of this process reaching the same session finds it in the registry: no second takeover,
        # and the lost record is not kept again.
        again = workspace.backend(b.ref, key=TAKEOVER_KEY)
        self.assertTrue(run(again.exists(ROOT)))
        self.assertEqual(len(c.attached), 1)
        self.assertEqual([r for r in kept if r is lost], [lost])

    def test_a_sink_that_cannot_keep_the_lost_record_ends_the_run_and_nothing_is_sent(self) -> None:
        def broken(record: Any) -> None:
            raise OSError("the disk is full")

        lost = lost_record()
        c, workspace, b = taken_over(lost, record_sink=broken)
        script = Scripted(("plimsoll_shell", {"command": "ls"}))
        with self.assertRaises(PlimsollOutcomeUnknownError) as e:
            run(Agent(script.model, capabilities=[workspace]).run("go", workspace=b))
        self.assertNotIsInstance(e.exception, PlimsollAlreadySentError)
        self.assertIs(e.exception.record, lost, "the application still gets the record")
        self.assertEqual((c.attach_answer.commands, c.attach_answer.scripts), ([], []), "a call was sent")
        self.assertEqual(script.returned("plimsoll_shell"), [])

    def test_everything_else_that_may_have_run_still_ends_the_run(self) -> None:
        # A gap the store cannot name: nothing can say what ran.
        c, workspace, b = taken_over(None)
        c.attach_answer = plimsoll_client.CheckpointMismatchError("plimsoll: the checkpoint is not the head", not_dispatched="request")
        script = Scripted(("plimsoll_shell", {"command": LOST_COMMAND}))
        with self.assertRaises(PlimsollOutcomeUnknownError) as e:
            run(Agent(script.model, capabilities=[workspace]).run("go", workspace=b))
        self.assertNotIsInstance(e.exception, PlimsollAlreadySentError)
        self.assertEqual(script.returned("plimsoll_shell"), [], "the model was told something")
        # This worker's own command, ended without an answer, its record checked: it may have run.
        c = FakeClient()
        workspace = cap(c)
        b = workspace.backend()
        run(first(b))
        err = PlimsollError("plimsoll: the stream broke after the call started", code="canceled")
        err.record = record(c.session.calls + 1, c.session.last_record_sha256)
        c.session.plan.append(err)
        script = Scripted(("plimsoll_shell", {"command": "make"}))
        with self.assertRaises(PlimsollOutcomeUnknownError) as e:
            run(Agent(script.model, capabilities=[workspace]).run("go", workspace=b))
        self.assertNotIsInstance(e.exception, PlimsollAlreadySentError)
        self.assertEqual(script.returned("plimsoll_shell"), [], "the model was told something")

    def test_the_refusal_covers_only_a_repeat_sent_first(self) -> None:
        # The client's rule, which the README, the module docstring and docs/sessions.md state: any other first call
        # spends the note, so a different command and then the lost one are both sent.
        c, workspace, b = taken_over(lost_record())
        script = Scripted(("plimsoll_shell", {"command": "ls"}), ("plimsoll_shell", {"command": LOST_COMMAND}))
        run(Agent(script.model, capabilities=[workspace]).run("go", workspace=b))
        self.assertEqual(c.attach_answer.commands, ["ls", LOST_COMMAND])
        # A file tool sends calls of its own before its read: the lost command sent after it is sent too.
        c, workspace, b = taken_over(lost_record())
        script = Scripted(("read_file", {"path": "notes.txt"}), ("plimsoll_shell", {"command": LOST_COMMAND}))
        run(Agent(script.model, capabilities=[workspace, FileSystem(content_hashes=False)]).run("go", workspace=b))
        self.assertEqual(c.attach_answer.commands, [LOST_COMMAND])


class DurableExecutionTests(unittest.TestCase):
    def test_a_durable_unit_is_refused_with_why(self) -> None:
        from pydantic_ai.durable_exec._operation_backend import durable_unit_scope

        c = FakeClient()
        agent = Agent(TestModel(call_tools=[]), capabilities=[cap(c)])
        with durable_unit_scope():
            with self.assertRaises(UserError) as e:
                run(agent.run("go"))
        self.assertIn("does not support durable execution", str(e.exception))
        self.assertIn("may run again", str(e.exception))
        # Finding release-81: the store does not keep a lost call from running again; the first-call limit stands.
        self.assertNotIn("never run again", str(e.exception))
        self.assertIn("refused only when it is the first call after the takeover", str(e.exception))
        self.assertEqual(c.opened, [])

    def test_a_run_inside_a_durable_workflow_is_refused(self) -> None:
        # A real Agent run with a durability capability of PydanticAI's own base class, inside its workflow, and an
        # engine that fails any unit it is asked to run. The refusal must come from get_workspace, before the engine
        # is asked for anything. Until 2026-11-21 this test handed get_workspace a stand-in context whose
        # `capabilities` held the durability capability; PydanticAI's real context at that call has an empty
        # `capabilities` (measured on 2.70.0), so the check it proved never fired in a real run (finding release-96).
        from pydantic_ai.durable_exec._base import BaseDurabilityCapability
        from pydantic_ai.durable_exec._operation_backend import DurableOperationBackend
        from pydantic_ai.durable_exec._spec import DurabilityEngineSpec

        reached: List[Any] = []

        class NoEngine(DurableOperationBackend):  # type: ignore[type-arg]
            def bind(self, operation: Any) -> Any:
                class Bound:
                    @property
                    def operation(self) -> Any:
                        return operation

                    async def __call__(self, params: Any, *, config: Any = None) -> Any:
                        reached.append(operation.operation_id)
                        raise AssertionError(f"the engine was asked to run {operation.operation_id!r}")

                return Bound()

            def config_for_tool(self, operation: Any, *, tool: Any, tool_name: str) -> Any:
                return False

            def registrations(self) -> Any:
                return ()

        class InWorkflow(BaseDurabilityCapability):  # type: ignore[type-arg]
            engine_spec = DurabilityEngineSpec(engine_name="TestEngine", durable_unit_noun="activity", durable_container_noun="workflow")

            @property
            def in_durable_context(self) -> bool:
                return True

            def get_durable_operation_backend(self) -> Any:
                return NoEngine()

        c = FakeClient()
        agent = Agent(TestModel(call_tools=[]), name="durable", capabilities=[cap(c), InWorkflow()])
        with self.assertRaises(UserError) as e:
            run(agent.run("go"))
        self.assertIn("does not support durable execution (InWorkflow)", str(e.exception))
        self.assertEqual(reached, [])
        self.assertEqual(c.opened, [])

    def test_a_durability_capability_outside_its_workflow_is_not_refused(self) -> None:
        # The same capability outside its durable container (in_durable_context False, as on the caller's side of a
        # Temporal workflow) is not a durable run.
        self.assertIsNone(pa.durable_run(types.SimpleNamespace(in_durable_context=False, agent=None)))

    def test_a_plain_run_is_not_refused(self) -> None:
        self.assertIsNone(pa.durable_run(types.SimpleNamespace(capabilities={})))

    def test_the_private_names_it_reads_exist_at_the_pinned_version(self) -> None:
        from pydantic_ai import RunContext
        from pydantic_ai.durable_exec import _base, _operation_backend

        self.assertTrue(callable(_operation_backend.in_durable_unit))
        # durable_run reads the run context's own answer, and names the capability through the private base class
        # (a moved one only words the refusal "a durable workflow").
        self.assertIsInstance(inspect.getattr_static(RunContext, "in_durable_context"), property)
        self.assertTrue(callable(_base.BaseDurabilityCapability.from_agent))

    def test_a_pydantic_ai_without_the_durable_mark_is_refused_not_read_as_plain(self) -> None:
        # The mark is a private name. On a PydanticAI that moved it, "not durable" would be a guess that lets a
        # durable run through; the answer is a refusal that names what is missing. None in sys.modules makes the
        # import fail as it would on such a release.
        import sys

        name = "pydantic_ai.durable_exec._operation_backend"
        with mock.patch.dict(sys.modules, {name: None}):
            with self.assertRaises(ImportError) as e:
                pa.durable_run(types.SimpleNamespace(capabilities={}))
            self.assertIn("in_durable_unit", str(e.exception))
            self.assertIn("no run is started", str(e.exception))
            with self.assertRaises(ImportError):
                cap(FakeClient()).get_workspace(types.SimpleNamespace(capabilities={}), ref=None)  # type: ignore[arg-type]
        self.assertIsNone(pa.durable_run(types.SimpleNamespace(capabilities={})))


class RegistryTests(unittest.TestCase):
    def test_a_later_run_reaches_the_same_session_by_its_ref(self) -> None:
        c = FakeClient()
        workspace = cap(c)
        one = Scripted(("write_file", {"path": "kept.txt", "content": "first run"}))
        result = run(Agent(one.model, capabilities=[workspace, FileSystem(content_hashes=False)]).run("go"))
        two = Scripted(("read_file", {"path": "kept.txt"}))
        run(Agent(two.model, capabilities=[workspace, FileSystem(content_hashes=False)]).run("again", message_history=result.all_messages()))
        self.assertIn("first run", str(two.returned("read_file")[0]))
        self.assertEqual(len(c.sessions), 1)

    def test_a_backend_attached_by_ref_reaches_the_same_session(self) -> None:
        workspace = cap()
        b = workspace.backend()
        run(Workspace(b).write_text("x", "same"))
        assert b.ref is not None
        attached = workspace.backend(b.ref)
        self.assertEqual(attached.ref, b.ref)
        self.assertEqual(run(Workspace(attached).read_text("x")), "same")

    def test_a_ref_of_another_daemon_or_provider_is_left_to_other_capabilities(self) -> None:
        ctx = types.SimpleNamespace(capabilities={})
        self.assertIsNone(cap().get_workspace(ctx, ref=WorkspaceRef(provider="docker", id="x")))  # type: ignore[arg-type]
        self.assertIsNone(cap().get_workspace(ctx, ref=WorkspaceRef(provider="plimsoll", id="other/" + "f" * 64)))  # type: ignore[arg-type]

    def test_a_ref_not_open_in_this_process_is_gone_and_never_replaced(self) -> None:
        c = FakeClient()
        b = cap(c).backend(WorkspaceRef(provider="plimsoll", id="plimsoll/" + "e" * 64))
        with self.assertRaises(PlimsollWorkspaceGoneError) as e:
            run(first(b))
        self.assertEqual(e.exception.reason, "not_found")
        self.assertEqual(c.opened, [])

    def test_another_owner_cannot_reach_a_session_by_its_ref(self) -> None:
        c = FakeClient()
        workspace = cap(c, owner=lambda ctx: ctx.deps)
        b = workspace.get_workspace(types.SimpleNamespace(capabilities={}, deps="alice"), ref=None)  # type: ignore[arg-type]
        assert b is not None
        run(first(b))
        self.assertEqual(c.opened[0]["owner"], "alice")
        mallory = workspace.get_workspace(types.SimpleNamespace(capabilities={}, deps="mallory"), ref=b.ref)  # type: ignore[arg-type]
        assert mallory is not None
        with self.assertRaises(PlimsollWorkspaceGoneError) as e:
            run(first(mallory))
        self.assertEqual(e.exception.reason, "not_found", "the same answer as for no session at all")
        alice = workspace.get_workspace(types.SimpleNamespace(capabilities={}, deps="alice"), ref=b.ref)  # type: ignore[arg-type]
        assert alice is not None
        self.assertEqual(run(first(alice)), ROOT)

    def test_destroy_closes_the_session_and_later_operations_are_gone(self) -> None:
        c = FakeClient()
        workspace = cap(c)
        b = workspace.backend()
        run(first(b))
        assert b.ref is not None
        workspace.destroy(b.ref)
        self.assertEqual(c.session.closes, 1)
        for x in (b, workspace.backend(b.ref)):
            with self.assertRaises(PlimsollWorkspaceGoneError):
                run(first(x))
        self.assertIsNone(workspace.destroy(b.ref))


    def test_no_ref_is_seen_before_destroy_can_reach_its_session(self) -> None:
        # The ADK environment's release-94, in this adapter's form: destroy(ref) racing the
        # first operation's open must not answer "not open in this process" for a session that
        # is then registered and left live. The backend's ref is published only once destroy
        # can find the session: here a destroy made the instant the ref is visible (inside the
        # registration) stands in for another thread's.
        c = FakeClient()
        workspace = cap(c)
        b = workspace.backend()
        register = workspace._register
        raced: List[Any] = []

        def racing(env: Any) -> None:
            if b.ref is not None:
                raced.append(workspace.destroy(b.ref))
            register(env)

        workspace._register = racing  # type: ignore[method-assign]
        run(first(b))
        self.assertEqual(raced, [], "the ref was visible before its session could be destroyed by it")
        assert b.ref is not None
        self.assertIsNotNone(workspace.destroy(b.ref))
        self.assertEqual(c.session.closes, 1)


class RecordTests(unittest.TestCase):
    def test_every_record_is_kept_on_the_backend_by_default(self) -> None:
        c = FakeClient()
        b = backend(c)
        ws = Workspace(b)
        run(ws.write_text("a", "x"))
        run(ws.read_text("a"))
        self.assertEqual(len(b.records), c.session.calls)
        self.assertEqual([r.sequence for r in b.records], list(range(1, c.session.calls + 1)))

    def test_the_json_lines_sink_writes_each_record_in_chain_order(self) -> None:
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "records.jsonl")
            c = FakeClient()
            b = cap(c, record_sink=JsonLinesRecordSink(path)).backend()
            run(Workspace(b).write_text("a", "x"))
            with open(path, encoding="utf-8") as f:
                lines = [json.loads(line)["record"] for line in f]
        self.assertEqual(b.records, ())
        self.assertEqual(len(lines), c.session.calls)
        for before, after in zip(lines, lines[1:]):
            self.assertEqual(after["previous_sha256"], before["sha256"])


class ShellToolTests(unittest.TestCase):
    def test_the_shell_tool_runs_in_the_same_session_as_the_file_tools(self) -> None:
        c = FakeClient()
        script = Scripted(("write_file", {"path": "a.txt", "content": "x"}), ("plimsoll_shell", {"command": "cat a.txt"}))
        run(Agent(script.model, capabilities=[cap(c), FileSystem(content_hashes=False)]).run("go"))
        self.assertEqual(c.session.commands, ["cat a.txt"])
        self.assertIn("exit code: 0\nran cat a.txt", str(script.returned("plimsoll_shell")[0]))

    def test_the_description_states_the_sweep_the_tier_and_the_network(self) -> None:
        text = cap()._shell_description()
        for words in ("stopped when its command returns", "kernel isolation tier", "BusyBox sh", "no network access",
                      "keeps its output open"):
            self.assertIn(words, text)

    def test_a_non_zero_exit_and_a_timeout_are_results(self) -> None:
        c = FakeClient()
        script = Scripted(("plimsoll_shell", {"command": "false"}), ("plimsoll_shell", {"command": "sleep 999"}))
        c_cap = cap(c)
        b = c_cap.backend()
        run(first(b))
        c.session.plan.extend([
            lambda s, f, st: s.result(b"", b"no", 3),
            lambda s, f, st: s.result(b"part", b"", 124, outcome="timed_out", timed_out=True),
        ])
        agent = Agent(script.model, capabilities=[c_cap])
        run(agent.run("go", workspace=b))
        answers = [str(a) for a in script.returned("plimsoll_shell")]
        self.assertTrue(answers[0].startswith("exit code: 3"), answers[0])
        self.assertIn("ran past its time budget", answers[1])

    def test_a_command_that_may_have_run_stops_the_run(self) -> None:
        c = FakeClient()
        workspace = cap(c)
        b = workspace.backend()
        run(first(b))
        c.session.plan.append(TransportError("connection reset after sending"))
        script = Scripted(("plimsoll_shell", {"command": "rm -rf build"}))
        with self.assertRaises(PlimsollOutcomeUnknownError):
            run(Agent(script.model, capabilities=[workspace]).run("go", workspace=b))
        self.assertEqual(script.returned("plimsoll_shell"), [], "the model was never asked whether to run it again")

    def test_text_the_tool_cannot_send_goes_back_to_the_model_and_nothing_is_sent(self) -> None:
        c = FakeClient()
        script = Scripted(("plimsoll_shell", {"command": "a\x00b"}))
        run(Agent(script.model, capabilities=[cap(c)]).run("go"))
        self.assertIn("nothing was sent", str(script.returned("plimsoll_shell")[0]))
        self.assertEqual(c.opened, [])

    def test_the_answer_carries_the_tier_and_the_record_for_the_application(self) -> None:
        c = FakeClient()
        workspace = cap(c)
        tool = workspace.get_toolset()
        self.assertIsNotNone(tool)
        b = workspace.backend()
        run(first(b))
        out = c.session.result(b"hi", b"", 0)
        answer = pa._labels(out)
        self.assertEqual(answer["plimsoll_isolation"], "kernel")
        self.assertEqual(answer["plimsoll_record_sha256"], out.record.sha256)  # type: ignore[union-attr]
        self.assertEqual(answer["plimsoll_outcome"], "completed")

    def test_no_shell_tool_when_turned_off(self) -> None:
        self.assertIsNone(cap(shell_tool=False).get_toolset())


class AgentIntegrationTests(unittest.TestCase):
    def test_an_agent_with_testmodel_and_filesystem_reaches_the_backend(self) -> None:
        """The integration test upstream asks of a workspace (pydantic-ai issue 13728): an Agent with TestModel,
        PydanticAI's FileSystem and plimsoll's capability; the file tools reach the backend's session."""
        c = FakeClient()
        agent = Agent(TestModel(call_tools=["create_directory", "list_directory"]), capabilities=[cap(c), FileSystem(content_hashes=False)])
        run(agent.run("go"))
        self.assertEqual(len(c.sessions), 1)
        self.assertIn(pa._MAKE_DIR, c.session.scripts)
        self.assertIn(pa._LIST, c.session.scripts)
        made = [d for d in c.session.tree.dirs if d.startswith(ROOT + "/") and pw.STATE_DIR not in d]
        self.assertTrue(made, "TestModel's create_directory reached the session's tree")


class DaemonTests(unittest.TestCase):
    """A real Session on the in-process daemon of fake sessions (PLIMSOLL_SESSIONS_URL): its sessions complete every
    project with no step's report."""

    def test_on_a_real_session_an_answer_without_a_step_report_is_unknown_with_its_record_kept(self) -> None:
        workspace = PlimsollWorkspace(client=Client(setting("PLIMSOLL_SESSIONS_URL")), minimum_isolation="container")
        b = workspace.backend()
        with self.assertRaises(PlimsollOutcomeUnknownError) as e:
            run(first(b))
        assert b.ref is not None and b.session is not None
        self.assertEqual(b.ref.id, "plimsoll/" + b.session.fingerprint)
        self.assertIsNotNone(e.exception.record)
        self.assertEqual([r.sequence for r in b.records], [1])
        workspace.destroy(b.ref)
        with self.assertRaises(PlimsollWorkspaceGoneError):
            run(first(b))

    def test_on_a_real_daemon_a_floor_above_its_tier_is_gone_before_anything_runs(self) -> None:
        workspace = PlimsollWorkspace(client=Client(setting("PLIMSOLL_SESSIONS_URL")), minimum_isolation="vm")
        with self.assertRaises(PlimsollWorkspaceGoneError) as e:
            run(first(workspace.backend()))
        self.assertEqual(e.exception.reason, "isolation")


class CodeToolTests(unittest.TestCase):
    def test_a_refusal_is_an_answer_and_the_labels_go_to_the_application(self) -> None:
        executor = CodeExecutor(Client(setting("PLIMSOLL_WASM_URL")), minimum_isolation="container")
        script = Scripted((pa.ct.TOOL_NAME, {"code": "print(1)"}))
        result = run(Agent(script.model, tools=[plimsoll_code_tool(executor)]).run("go"))
        answer = script.returned(pa.ct.TOOL_NAME)[0]
        self.assertIs(answer["ran"], False)
        returns = [p for m in result.all_messages() for p in getattr(m, "parts", []) if getattr(p, "tool_name", "") == pa.ct.TOOL_NAME
                   and hasattr(p, "metadata")]
        self.assertEqual(returns[0].metadata["plimsoll_dispatched"], "no")

    def test_the_schema_offers_the_languages_given(self) -> None:
        executor = CodeExecutor(Client("http://127.0.0.1:9"), minimum_isolation="kernel")
        tool = plimsoll_code_tool(executor, languages=("python", "javascript"))
        schema = tool.function_schema.json_schema
        self.assertEqual(schema["properties"]["language"]["enum"], ["python", "javascript"])
        self.assertEqual(schema["required"], ["code"])

    def test_a_language_outside_the_schema_is_refused_before_the_call(self) -> None:
        executor = CodeExecutor(Client("http://127.0.0.1:9"), minimum_isolation="kernel")
        script = Scripted((pa.ct.TOOL_NAME, {"code": "x", "language": "ruby"}))
        run(Agent(script.model, tools=[plimsoll_code_tool(executor)]).run("go"))
        answer = script.returned(pa.ct.TOOL_NAME)[0]
        self.assertEqual(answer["refused"], "request")

    def test_a_granted_tool_tells_the_model_the_api_and_carries_the_applications_profile(self) -> None:
        import json

        from plimsoll_client._langsmith import KEYS as LABEL_KEYS

        from .._shared import API_DESCRIPTION, ECHO_ROUTES, granted

        tool = plimsoll_code_tool(granted(), languages=("javascript", "python"))
        self.assertIn(API_DESCRIPTION.strip(), tool.description)
        self.assertIn("plimsoll_host", tool.description)
        self.assertEqual(set(tool.function_schema.json_schema["properties"]), {"code", "language", "input_files"})
        script = Scripted((pa.ct.TOOL_NAME, {"code": "console.log(1)", "language": "javascript"}))
        result = run(Agent(script.model, tools=[tool]).run("go"))
        answer = script.returned(pa.ct.TOOL_NAME)[0]
        self.assertEqual(json.loads(answer["stdout"])["grant"]["allow"], ECHO_ROUTES)
        # The metadata the application gets holds the closed set of labels only.
        returns = [p for m in result.all_messages() for p in getattr(m, "parts", []) if getattr(p, "tool_name", "") == pa.ct.TOOL_NAME
                   and hasattr(p, "metadata")]
        self.assertTrue(set(returns[0].metadata) <= set(LABEL_KEYS), returns[0].metadata)
        with self.assertRaises(ValueError):
            plimsoll_code_tool(granted(guard=True))
        js = plimsoll_code_tool(granted(guard=True), languages=("python", "javascript"))
        self.assertEqual(js.function_schema.json_schema["properties"]["language"]["enum"], ["javascript"])
        self.assertIn("Python code cannot call the API on this sandbox", js.description)


class PackageTests(unittest.TestCase):
    """The pydantic-ai-plimsoll package beside plimsoll-client."""

    def test_names_are_plimsoll_clients_own(self) -> None:
        import pydantic_ai_plimsoll as pkg

        for name in pkg.__all__:
            if name != "__version__":
                self.assertIs(getattr(pkg, name), getattr(pa, name), name)
        # Finding release-82: the refused repeat of a lost call is named for a call already sent, not one that ran.
        self.assertIn("PlimsollAlreadySentError", pkg.__all__)
        for module in (pkg, pa, plimsoll_client):
            self.assertFalse([n for n in dir(module) if "AlreadyRan" in n], module.__name__)

    def test_version_is_plimsoll_clients(self) -> None:
        import pydantic_ai_plimsoll as pkg

        with open(os.path.join(PACKAGE, "pyproject.toml"), "rb") as f:
            project = tomllib.load(f)["project"]
        self.assertEqual(pkg.__version__, plimsoll_client.__version__)
        self.assertEqual(project["version"], plimsoll_client.__version__)
        self.assertIn(f"plimsoll-client=={plimsoll_client.__version__}", project["dependencies"])

    def test_the_pins_are_the_versions_this_suite_runs_against(self) -> None:
        with open(os.path.join(PACKAGE, "pyproject.toml"), "rb") as f:
            deps = tomllib.load(f)["project"]["dependencies"]
        with open(os.path.join(HERE, "requirements.in"), encoding="utf-8") as f:
            pins = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        self.assertIn("pydantic-ai-slim==2.70.0", pins)
        self.assertIn("pydantic-ai-slim==2.70.0", deps)
        self.assertEqual(pydantic_ai.__version__, "2.70.0")

    def test_the_readme_states_every_limit(self) -> None:
        with open(os.path.join(PACKAGE, "README.md"), encoding="utf-8") as f:
            text = " ".join(f.read().split()).lower()
        for words in (
            "one process",  # attach only in the process that opened the session
            "durable execution",  # refused
            "Coder",
            "Shell",
            "does not implement `SupportsCommands`",  # and why the tools vanish
            "needs a provider with sessions:",
            "if `pip` cannot find it yet",
            "not a hosted service",
            "not attestation",
            "minimum_isolation",
            # The lost-call refusal's limit (finding release-74), as test_the_refusal_covers_only_a_repeat_sent_first holds it.
            "only when it is the first call after the takeover",
            "any other first call, and every file tool, is sent as usual",
        ):
            self.assertIn(words.lower(), text)
        self.assertNotIn("already ran once", text)
        with open(pa.__file__, encoding="utf-8") as f:
            module = " ".join(f.read().split()).lower()
        self.assertIn("refuses to send that call again only when it is the first call after the takeover", module)
        self.assertIn("each file tool's included, is sent as usual", module)

    def test_the_readme_and_the_example_agree_on_whether_the_package_is_released(self) -> None:
        with open(os.path.join(PACKAGE, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        with open(os.path.join(HERE, "..", "..", "examples", "pydantic_ai_workspace.py"), encoding="utf-8") as f:
            example = f.read()
        # Both say the same thing about when the package reaches PyPI.
        self.assertIn("if `pip` cannot find it yet", " ".join(readme.split()).lower())
        self.assertIn("if pip cannot find it yet", " ".join(example.split()).lower())

    def test_the_skip_list_and_the_readme_agree(self) -> None:
        # The README counts the conformance rules the package skips; the docker test holds the list.
        with open(os.path.join(HERE, "..", "..", "pydantic_ai_docker_test.go"), encoding="utf-8") as f:
            listed = set(re.findall(r'"(test_\w+)":', f.read()))
        with open(os.path.join(PACKAGE, "README.md"), encoding="utf-8") as f:
            readme = " ".join(f.read().split())
        self.assertEqual(len(listed), 20)
        self.assertIn("20 of its 40 rules skip", readme)


class FrameworkShapeTests(unittest.TestCase):
    """Each member the adapter defines over the framework's own (inherited, or declared by a protocol it is used
    as) against the framework at the version this suite installs: kind, coroutine, the calls it takes
    (tests/_framework_shapes.py)."""

    def test_the_adapter_takes_the_calls_the_framework_makes(self) -> None:
        import plimsoll_client.pydantic_ai
        from tests._framework_shapes import problems

        from pydantic_ai.workspaces.protocol import SupportsFilesystem, SupportsRealpath, WorkspaceBackend

        self.assertEqual(problems(plimsoll_client.pydantic_ai, [(plimsoll_client.pydantic_ai.PlimsollWorkspaceBackend, p) for p in (WorkspaceBackend, SupportsFilesystem, SupportsRealpath)]), [])
