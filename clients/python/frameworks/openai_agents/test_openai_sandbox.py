"""The Agents SDK sandbox provider over a plimsoll workspace: the real SDK's base classes,
wrapper, events, tracing, state and exec path, a workspace faked in memory (frameworks/
openai_agents/_fake.py), and no model call anywhere. The daemon-backed cases use the
in-memory session daemon client_test.go serves, which runs nothing."""

from __future__ import annotations

import asyncio
import dataclasses
import io
import json
import threading
import time
import unittest
from pathlib import Path
from typing import Any, List

from agents.sandbox import LocalSnapshotSpec
from agents.sandbox.errors import ExecTimeoutError, ExecTransportError, WorkspaceArchiveReadError, WorkspaceArchiveWriteError
from agents.sandbox.manifest import Manifest
from agents.sandbox.session import SandboxSession, SandboxSessionState
from agents.sandbox.types import ExecResult
from agents.tracing import custom_span, trace

from frameworks.openai_agents._fake import CANARY, FakeWorkspace
from frameworks.openai_agents._kit import SHA256, SPANS, Events, check_labels, plimsoll_labels
from plimsoll_client import Client, SessionEndedError
from plimsoll_client.openai_sandbox import (
    LABEL_KEYS,
    PlimsollExecError,
    PlimsollExecResult,
    PlimsollExecTimeoutError,
    PlimsollSandboxClient,
    PlimsollSandboxClientOptions,
    PlimsollSandboxSession,
    PlimsollSandboxSessionState,
    _label_exec_span,
)
from plimsoll_client.workspace import MAX_READ_BYTES, MAX_WHOLE_BYTES
from tests._env import setting

_LOOPS: List[asyncio.AbstractEventLoop] = []
SCRATCH = Path(__file__).resolve().parents[4] / "tmp"


def tearDownModule() -> None:
    for loop in _LOOPS:
        if not loop.is_closed():
            loop.close()


class Harness:
    def __init__(self, **client_kw: Any) -> None:
        self.made: List[FakeWorkspace] = []
        self.options_seen: List[PlimsollSandboxClientOptions] = []
        self.open_gate: threading.Event | None = None

        def factory(options: PlimsollSandboxClientOptions) -> FakeWorkspace:
            self.options_seen.append(options)
            if self.open_gate is not None:
                self.open_gate.wait(10)
            ws = FakeWorkspace()
            self.made.append(ws)
            return ws

        self.client = PlimsollSandboxClient(None, workspace_factory=factory, **client_kw)
        self.loop = asyncio.new_event_loop()
        _LOOPS.append(self.loop)

    def run(self, coro: Any) -> Any:
        return self.loop.run_until_complete(coro)

    def create(self, **kw: Any) -> SandboxSession:
        return self.run(self.client.create(**kw))

    @property
    def ws(self) -> FakeWorkspace:
        return self.made[-1]


class ProviderTests(unittest.TestCase):
    def test_backend_and_options(self) -> None:
        self.assertEqual(PlimsollSandboxClient.backend_id, "plimsoll")
        self.assertTrue(PlimsollSandboxClient.supports_default_options)
        o = PlimsollSandboxClientOptions()
        self.assertEqual((o.type, o.minimum_isolation, o.languages, o.timeout), ("plimsoll", "kernel", ("python",), 120.0))
        o = PlimsollSandboxClientOptions("container", ("python", "javascript"), 30)
        self.assertEqual((o.minimum_isolation, o.languages, o.timeout), ("container", ("python", "javascript"), 30))
        with self.assertRaises(ValueError):
            PlimsollSandboxClient(None)

    def test_create_learns_the_root_and_the_state_carries_no_session_id(self) -> None:
        h = Harness()
        session = h.create(options=PlimsollSandboxClientOptions(minimum_isolation="container"))
        inner = session._inner
        self.assertIsInstance(inner, PlimsollSandboxSession)
        self.assertEqual(h.options_seen[0].minimum_isolation, "container")
        self.assertEqual(inner.state.type, "plimsoll")
        self.assertEqual(inner.state.manifest.root, "/work")
        self.assertEqual(inner.state.fingerprint, "fp-fake")
        self.assertEqual(inner.state.isolation, "container")
        self.assertEqual(inner.state.minimum_isolation, "container")
        payload = h.client.serialize_session_state(inner.state)
        self.assertNotIn("session", {k for k in payload if k != "session_id"} - {"session_id"})
        self.assertEqual(payload["type"], "plimsoll")
        back = h.client.deserialize_session_state(payload)
        self.assertIsInstance(back, PlimsollSandboxSessionState)
        self.assertEqual((back.session_id, back.manifest.root, back.fingerprint, back.minimum_isolation), (inner.state.session_id, "/work", "fp-fake", "container"))
        self.assertIsInstance(SandboxSessionState.parse(payload), PlimsollSandboxSessionState)

    def test_a_manifest_root_given_is_kept(self) -> None:
        h = Harness()
        session = h.create(manifest=Manifest(root="/tmp/work"))
        self.assertEqual(session._inner.state.manifest.root, "/tmp/work")

    def test_exec_through_the_sdk(self) -> None:
        h = Harness()
        session = h.create()
        ws = h.ws
        r = h.run(session.exec("echo hi"))
        self.assertIsInstance(r, ExecResult)
        self.assertEqual((r.stdout, r.stderr, r.exit_code), (b"hi\n", b"", 0))
        self.assertEqual(ws.commands[-1], "echo hi")  # the SDK's `sh -lc` prefix stripped
        h.run(session.exec("echo hi", shell=["sh", "-c"]))  # the shell tool's prefix with login=False
        self.assertEqual(ws.commands[-1], "echo hi")
        h.run(session.exec("echo", "a b"))
        self.assertEqual(ws.commands[-1], "echo 'a b'")
        r = h.run(session.exec("false"))
        self.assertEqual((r.exit_code, r.stderr), (1, b"no\n"))
        h.run(session.exec("ls", "-l", shell=False))
        self.assertEqual(ws.commands[-1], "ls -l")
        h.run(session.exec("sh", "-c", 'test -r "$1"', "sh", "a b", shell=False))  # the SDK's own checks
        self.assertEqual(ws.commands[-1], "sh -c 'test -r \"$1\"' sh 'a b'")

    def test_exec_returns_the_checked_result_its_record_and_labels(self) -> None:
        h = Harness()
        session = h.create()
        r = h.run(session.exec("echo hi"))
        self.assertIsInstance(r, PlimsollExecResult)
        self.assertEqual((r.isolation, r.isolation_qualification, r.outcome), ("container", "", "completed"))
        self.assertIsNotNone(r.record)
        self.assertRegex(r.record_sha256, SHA256)
        self.assertEqual(r.record_sha256, r.record.sha256)
        self.assertIs(r.result.record, r.record)
        check_labels(self, r.labels, dispatched="yes", isolation="container", outcome="completed", record=True)
        q = h.run(session.exec("qualified"))
        self.assertEqual(q.labels["plimsoll_isolation"], "vm")
        self.assertEqual(q.labels["plimsoll_isolation_qualification"], "The vendor states this is not a security boundary.")

    def test_labels_hold_only_closed_set_values(self) -> None:
        h = Harness()
        session = h.create()
        bad = h.run(session.exec("bad-labels"))
        self.assertEqual(bad.labels, {"plimsoll_dispatched": "yes", "plimsoll_outcome": "completed"})
        canary = h.run(session.exec("canary"))
        self.assertIn(CANARY.encode(), canary.stdout)
        for r in (bad, canary):
            self.assertLessEqual(set(r.labels), set(LABEL_KEYS))
            self.assertNotIn(CANARY, str(r.labels))

    def test_a_refusal_raises_the_sdks_error_marked_and_retryable_only_when_another_try_may_pass(self) -> None:
        h = Harness()
        session = h.create()
        with self.assertRaises(PlimsollExecError) as caught:
            h.run(session.exec("refuse capacity"))
        e = caught.exception
        self.assertIsInstance(e, ExecTransportError)
        self.assertEqual(e.not_dispatched, "capacity")
        self.assertIs(e.retryable, True)
        self.assertIs(e.__cause__, e.error)
        self.assertEqual(e.error.not_dispatched, "capacity")
        check_labels(self, e.labels, dispatched="no", refused="capacity")
        self.assertEqual(plimsoll_labels(e.context), e.labels)
        with self.assertRaises(PlimsollExecError) as caught:
            h.run(session.exec("refuse isolation"))
        self.assertIs(caught.exception.retryable, False)
        check_labels(self, caught.exception.labels, dispatched="no", refused="isolation")

    def test_an_error_after_which_the_command_may_have_run_is_unmarked_and_never_retryable(self) -> None:
        h = Harness()
        session = h.create()
        with self.assertRaises(PlimsollExecError) as caught:
            h.run(session.exec("lost"))
        e = caught.exception
        self.assertIsNone(e.not_dispatched)
        self.assertIs(e.retryable, False)
        check_labels(self, e.labels, dispatched="unknown", isolation="container", record=True)
        self.assertEqual(e.record.sha256, e.labels["plimsoll_record_sha256"])
        with self.assertRaises(PlimsollExecError) as caught:
            h.run(session.exec("incomplete"))
        e = caught.exception
        self.assertIs(e.retryable, False)
        self.assertIn("may have run", str(e))
        self.assertNotIn(CANARY, str(e))  # the runner's detail stays on the cause
        self.assertEqual(e.result.detail, CANARY)
        check_labels(self, e.labels, dispatched="yes", isolation="container", outcome="runner_failed", record=True)
        with self.assertRaises(PlimsollExecError) as caught:
            h.run(session.exec("setup"))
        self.assertIn("did not run", str(caught.exception))
        check_labels(self, caught.exception.labels, dispatched="yes", isolation="container", outcome="setup_failed", record=True)

    def test_timeouts(self) -> None:
        h = Harness()
        session = h.create()
        ws = h.ws
        with self.assertRaises(PlimsollExecTimeoutError) as caught:
            h.run(session.exec("sleep 9", timeout=0.5))
        self.assertIsInstance(caught.exception, ExecTimeoutError)
        self.assertEqual(ws.budgets[-1], 0.5)
        check_labels(self, caught.exception.labels, dispatched="yes", isolation="container", outcome="timed_out", record=True)
        sent = ws.calls
        for budget in (0, -1):
            with self.assertRaises(PlimsollExecTimeoutError) as caught:
                h.run(session.exec("echo never", timeout=budget))
            self.assertIsNone(caught.exception.result)
            check_labels(self, caught.exception.labels, dispatched="no", refused="request")
        self.assertEqual(ws.calls, sent, "a budget of zero sends nothing")
        h.run(session.exec("echo default"))
        self.assertIsNone(ws.budgets[-1], "no timeout from the SDK: the workspace's own budget")

    def test_a_command_for_another_user_is_refused_before_anything_is_sent(self) -> None:
        h = Harness()
        session = h.create()
        sent = h.ws.calls
        with self.assertRaises(PlimsollExecError) as caught:
            h.run(session.exec("id", user="bob"))  # the SDK prefixes sudo -u bob --
        self.assertEqual(caught.exception.not_dispatched, "request")
        self.assertIn("one user", str(caught.exception))
        self.assertEqual(h.ws.calls, sent)

    def test_a_nul_in_a_command_is_refused_before_anything_is_sent(self) -> None:
        h = Harness()
        session = h.create()
        sent = h.ws.calls
        with self.assertRaises(PlimsollExecError) as caught:
            h.run(session.exec("echo a\x00b"))
        self.assertEqual(caught.exception.not_dispatched, "request")
        self.assertEqual(h.ws.calls, sent)


class LabelChannelTests(unittest.TestCase):
    """Where an app finds the labels: the SDK's own audit events and tracing spans."""

    def test_every_command_event_carries_the_labels_on_success_and_on_failure(self) -> None:
        events = Events()
        h = Harness(instrumentation=events.instrumentation)
        session = h.create()
        h.run(session.exec("echo hi"))
        h.run(session.exec("false"))
        with self.assertRaises(PlimsollExecError):
            h.run(session.exec("refuse capacity"))
        with self.assertRaises(PlimsollExecError):
            h.run(session.exec("lost"))
        with self.assertRaises(PlimsollExecTimeoutError):
            h.run(session.exec("sleep 9", timeout=1))
        finished = events.finished("exec")
        self.assertEqual(len(finished), 5)
        ok, nonzero, refused, lost, timed = finished
        check_labels(self, plimsoll_labels(ok.data), dispatched="yes", isolation="container", outcome="completed", record=True)
        self.assertEqual(ok.data["exit_code"], 0)  # the kit's own field stays beside them
        check_labels(self, plimsoll_labels(nonzero.data), dispatched="yes", isolation="container", outcome="completed", record=True)
        self.assertFalse(nonzero.ok)
        check_labels(self, plimsoll_labels(refused.data), dispatched="no", refused="capacity")
        self.assertEqual((str(refused.error_code), refused.error_retryable), ("exec_transport_error", True))
        check_labels(self, plimsoll_labels(lost.data), dispatched="unknown", isolation="container", record=True)
        self.assertIs(lost.error_retryable, False)
        check_labels(self, plimsoll_labels(timed.data), dispatched="yes", isolation="container", outcome="timed_out", record=True)
        self.assertEqual(str(timed.error_code), "exec_timeout")
        starts = [e for e in events.seen if e.op == "exec" and e.phase == "start"]
        self.assertTrue(starts and all(not plimsoll_labels(e.data) and "plimsoll_record" not in e.data for e in starts),
                        "nothing is stated before the call")

    def test_every_answered_command_event_carries_its_checked_record_whole(self) -> None:
        events = Events()
        h = Harness(instrumentation=events.instrumentation)
        session = h.create()
        r = h.run(session.exec("echo hi"))
        with self.assertRaises(PlimsollExecError) as lost:
            h.run(session.exec("lost"))
        with self.assertRaises(PlimsollExecError):
            h.run(session.exec("refuse capacity"))
        with self.assertRaises(PlimsollExecTimeoutError) as timed:
            h.run(session.exec("sleep 9", timeout=1))
        ok, unanswered, refused, timeout = events.finished("exec")
        self.assertEqual(ok.data["plimsoll_record"], dataclasses.asdict(r.record))
        self.assertEqual(ok.data["plimsoll_record"]["sha256"], ok.data["plimsoll_record_sha256"])
        self.assertEqual(unanswered.data["plimsoll_record"], dataclasses.asdict(lost.exception.record))
        self.assertNotIn("plimsoll_record", refused.data, "a refusal has no record: nothing ran")
        self.assertEqual(timeout.data["plimsoll_record"], dataclasses.asdict(timed.exception.record))
        # As the SDK's JSONL and HTTP sinks write it.
        written = json.loads(ok.model_dump_json())
        self.assertEqual(written["data"]["plimsoll_record"]["sha256"], r.record_sha256)

    def test_the_span_gets_the_labels_and_never_the_record(self) -> None:
        h = Harness()
        session = h.create()
        SPANS.ended.clear()
        with trace("plimsoll-record"):
            h.run(session.exec("echo hi"))
        (span,) = SPANS.named("sandbox.exec")
        self.assertNotIn("plimsoll_record", span)
        self.assertIn("plimsoll_record_sha256", span)

    def test_the_sandbox_exec_span_carries_the_labels_and_no_guest_text(self) -> None:
        h = Harness()
        session = h.create()
        SPANS.ended.clear()
        with trace("plimsoll-labels"):
            r = h.run(session.exec("canary"))
            with self.assertRaises(PlimsollExecError):
                h.run(session.exec("refuse capacity"))
        spans = SPANS.named("sandbox.exec")
        self.assertEqual(len(spans), 2)
        self.assertEqual(plimsoll_labels(spans[0]), r.labels)
        check_labels(self, plimsoll_labels(spans[1]), dispatched="no", refused="capacity")
        self.assertNotIn(CANARY, str(SPANS.ended))

    def test_a_span_other_than_the_commands_own_is_left_alone(self) -> None:
        SPANS.ended.clear()
        with trace("plimsoll-other"):
            with custom_span("sandbox.read"):
                _label_exec_span({"plimsoll_dispatched": "yes"})
            with custom_span("sandbox.exec"):
                _label_exec_span({"plimsoll_dispatched": "yes"})
        self.assertEqual(plimsoll_labels(SPANS.named("sandbox.read")[0]), {})
        self.assertEqual(plimsoll_labels(SPANS.named("sandbox.exec")[0]), {"plimsoll_dispatched": "yes"})


class CancellationTests(unittest.TestCase):
    """The SDK cancels a call by cancelling the task that awaits it: the call's handle is
    cancelled, so a call not yet sent is never sent and one in flight is cut."""

    def cancel_during(self, h: Harness, start: Any) -> Any:
        ws = h.ws
        ws.hold = threading.Event()

        async def main() -> None:
            task = asyncio.ensure_future(start())
            while not ws.held.is_set():
                await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        t0 = time.monotonic()
        h.run(main())
        self.assertTrue(ws.ended_hold.wait(2), "the held call returned once its handle was cancelled")
        self.assertLess(time.monotonic() - t0, 2)
        self.assertTrue(ws.cancels[-1] is not None and ws.cancels[-1].cancelled, "the call's cancel handle was cancelled")
        return ws

    def test_cancelling_a_command_cancels_its_call(self) -> None:
        h = Harness()
        session = h.create()
        self.cancel_during(h, lambda: session.exec("sleep 60", timeout=60))

    def test_cancelling_a_file_or_tree_call_cancels_it(self) -> None:
        for name, start in (
            ("read", lambda s: s.read(Path("a.txt"))),
            ("write", lambda s: s.write(Path("a.txt"), io.BytesIO(b"x"))),
            ("persist", lambda s: s.persist_workspace()),
            ("hydrate", lambda s: s.hydrate_workspace(io.BytesIO(b"tar"))),
        ):
            with self.subTest(name):
                h = Harness()
                session = h.create()
                self.cancel_during(h, lambda: start(session._inner))

    def test_a_session_opened_after_its_create_was_cancelled_is_closed(self) -> None:
        h = Harness()
        h.open_gate = threading.Event()

        async def main() -> None:
            task = asyncio.ensure_future(h.client.create(options=PlimsollSandboxClientOptions(minimum_isolation="container")))
            while not h.options_seen:
                await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        h.run(main())
        h.open_gate.set()  # the open completes after nobody waits for it
        deadline = time.monotonic() + 5
        while not (h.made and h.made[0].session.closed) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(h.made and h.made[0].session.closed, "the abandoned session was closed")


class FileTests(unittest.TestCase):
    def test_files_persist_and_hydrate(self) -> None:
        h = Harness()
        session = h.create()
        inner = session._inner
        ws = h.ws
        h.run(inner.write(Path("src/a.txt"), io.BytesIO(b"hello")))
        self.assertEqual(ws.files, {"src/a.txt": b"hello"})
        self.assertEqual(h.run(inner.read(Path("src/a.txt"))).read(), b"hello")
        with self.assertRaises(FileNotFoundError):
            h.run(inner.read(Path("missing")))
        tar = h.run(inner.persist_workspace()).read()
        self.assertEqual(tar, b"TAR:src/a.txt")
        h.run(inner.hydrate_workspace(io.BytesIO(tar)))
        self.assertEqual(ws.hydrated, [tar])
        self.assertFalse(inner.supports_pty())

    def test_a_file_past_one_calls_budget_is_read_whole_in_pieces(self) -> None:
        h = Harness()
        session = h.create()
        big = bytes(range(256)) * ((MAX_READ_BYTES + 3000) // 256)
        h.ws.files["big.bin"] = big
        self.assertEqual(h.run(session.read(Path("big.bin"))).read(), big)
        self.assertEqual(h.run(session.read_bounded(Path("big.bin"), max_bytes=100)), big[:100])
        self.assertEqual(h.run(session.read_bounded(Path("big.bin"), max_bytes=MAX_READ_BYTES + 10)), big[: MAX_READ_BYTES + 10])
        h.ws.files["shrinking"] = big
        with self.assertRaises(WorkspaceArchiveReadError) as caught:
            h.run(session._inner.read(Path("shrinking")))
        self.assertEqual(caught.exception.context["reason"], "changed_while_read")

    def test_a_file_past_the_whole_read_limit_is_refused_after_its_first_piece(self) -> None:
        # Finding release-46: a sandbox can make a file of any size, and the whole read
        # ended in this process's memory. The fake's file is as long as the limit plus one
        # byte (a sparse file costs a real sandbox nothing).
        h = Harness()
        session = h.create()
        h.ws.files["huge.bin"] = bytes(MAX_WHOLE_BYTES + 1)
        with self.assertRaises(WorkspaceArchiveReadError) as caught:
            h.run(session._inner.read(Path("huge.bin")))
        self.assertEqual(caught.exception.context["reason"], "too_large")
        self.assertEqual([o for p, o in h.ws.reads if p == "huge.bin"], [0])  # its first piece, then its size, nothing more
        self.assertEqual(h.run(session.read_bounded(Path("huge.bin"), max_bytes=MAX_READ_BYTES + 1)), bytes(MAX_READ_BYTES + 1))

    def test_a_file_call_past_its_budget_raises_the_sdks_error_and_is_never_retried(self) -> None:
        # Finding release-47 (candidate c): the built-in TimeoutError the workspace raises
        # for a read or write past its budget escaped untranslated, with no statement
        # that the call may have run.
        h = Harness()
        session = h.create()
        with self.assertRaises(WorkspaceArchiveReadError) as read:
            h.run(session._inner.read(Path("slow")))
        with self.assertRaises(WorkspaceArchiveWriteError) as write:
            h.run(session._inner.write(Path("slow"), io.BytesIO(b"x")))
        for caught in (read, write):
            self.assertIs(caught.exception.retryable, False)
            self.assertEqual(caught.exception.context["reason"], "timed_out")
            self.assertIsInstance(caught.exception.cause, TimeoutError)

    def test_a_refused_file_call_raises_the_sdks_error_with_its_retryability(self) -> None:
        h = Harness()
        session = h.create()
        with self.assertRaises(WorkspaceArchiveReadError) as caught:
            h.run(session._inner.read(Path("refused")))
        self.assertIs(caught.exception.retryable, True)
        self.assertEqual(caught.exception.context["plimsoll_refused"], "capacity")
        with self.assertRaises(WorkspaceArchiveWriteError) as caught:
            h.run(session._inner.write(Path("refused"), io.BytesIO(b"x")))
        self.assertEqual(caught.exception.context["plimsoll_dispatched"], "no")

    def test_stop_persists_without_the_sdks_fingerprint_helper(self) -> None:
        h = Harness()
        snapshots = Path(SCRATCH) / "openai-agents-snapshots"
        snapshots.mkdir(parents=True, exist_ok=True)
        session = h.create(snapshot=LocalSnapshotSpec(base_path=snapshots))
        h.run(session.start())
        h.run(session.stop())
        tars = list(snapshots.glob(f"{session.state.snapshot.id}*"))
        self.addCleanup(lambda: [p.unlink() for p in tars])
        self.assertTrue(tars, "the workspace was persisted")
        self.assertFalse([c for c in h.ws.commands if "INSTALL_RUNTIME_HELPER" in c or "workspace-fingerprint" in c], h.ws.commands)


class LifecycleTests(unittest.TestCase):
    def test_running_stop_and_delete(self) -> None:
        h = Harness()
        session = h.create()
        inner = session._inner
        ws = h.ws
        self.assertFalse(h.run(inner.running()))
        h.run(inner._after_start())
        self.assertTrue(h.run(inner.running()))
        ws.session.stopped = "an earlier call was cut"
        self.assertFalse(h.run(inner.running()), "a session this client no longer sends on is not running")
        ws.session.stopped = None
        h.run(h.client.delete(session))
        self.assertTrue(ws.session.closed)
        self.assertFalse(h.run(inner.running()))
        inner._running = True
        self.assertFalse(h.run(inner.running()), "a session that ended is not running")

    def test_resume_opens_a_new_session_for_the_same_state(self) -> None:
        h = Harness()
        session = h.create(options=PlimsollSandboxClientOptions(minimum_isolation="container", languages=("javascript",)))
        state = session._inner.state
        payload = h.client.serialize_session_state(state)
        resumed = h.run(h.client.resume(h.client.deserialize_session_state(payload)))
        self.assertEqual(len(h.made), 2)
        self.assertEqual(h.options_seen[1].minimum_isolation, "container")
        self.assertEqual(h.options_seen[1].languages, ("javascript",))
        self.assertEqual(resumed._inner.state.session_id, state.session_id)
        self.assertEqual(resumed._inner.state.manifest.root, "/work")
        self.assertFalse(resumed._inner.state.workspace_root_ready)
        with self.assertRaises(TypeError):
            h.run(h.client.resume(SandboxSessionState(type="other", snapshot=state.snapshot, manifest=state.manifest)))

    def test_manifest_users_are_refused(self) -> None:
        h = Harness()
        session = h.create()
        inner = session._inner
        if "users" in Manifest.model_fields:
            inner.state.manifest = inner.state.manifest.model_copy(update={"users": {"bob": {}}}, deep=True)
            with self.assertRaises(ValueError):
                h.run(inner.provision_manifest_accounts())


class DaemonTests(unittest.TestCase):
    """Through the in-memory session daemon (its sessions run nothing): a session is
    opened at the floor the options name and closed by delete, and what it answers is
    checked and labelled as a real daemon's would be."""

    def setUp(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.client = PlimsollSandboxClient(Client(setting("PLIMSOLL_SESSIONS_URL")))

    def open(self) -> SandboxSession:
        return self.loop.run_until_complete(
            self.client.create(manifest=Manifest(root="/work"), options=PlimsollSandboxClientOptions(minimum_isolation="container"))
        )

    def test_create_and_delete(self) -> None:
        session = self.open()
        inner = session._inner
        self.assertEqual(inner.state.isolation, "container")
        self.assertEqual(inner.state.base_url, self.client._client.base_url)
        self.assertTrue(inner.state.fingerprint)
        self.assertNotIn(inner.workspace.session._id, str(self.client.serialize_session_state(inner.state)))
        self.loop.run_until_complete(self.client.delete(session))
        with self.assertRaises(SessionEndedError):
            inner.workspace.session.run_project({}, ["true"])

    def test_an_answer_without_a_step_is_an_error_with_its_checked_record(self) -> None:
        # The fake daemon completes every project with no step's report: the call was
        # answered, so its record is checked, but there is no command result to hand on.
        session = self.open()
        self.addCleanup(lambda: self.loop.run_until_complete(self.client.delete(session)))
        with self.assertRaises(PlimsollExecError) as caught:
            self.loop.run_until_complete(session.exec("echo hi"))
        e = caught.exception
        self.assertIs(e.retryable, False)
        check_labels(self, e.labels, dispatched="yes", isolation="container", outcome="completed", record=True)
        self.assertEqual(e.record.sha256, session._inner.workspace.session.last_record_sha256)

    def test_a_command_on_a_closed_session_is_refused_before_it_is_sent(self) -> None:
        session = self.open()
        self.loop.run_until_complete(self.client.delete(session))
        with self.assertRaises(PlimsollExecError) as caught:
            self.loop.run_until_complete(session.exec("echo hi"))
        self.assertEqual(caught.exception.not_dispatched, "request")
        self.assertIsInstance(caught.exception.error, SessionEndedError)
        check_labels(self, caught.exception.labels, dispatched="no", refused="request")


class FrameworkShapeTests(unittest.TestCase):
    """Each member the adapter defines over the framework's own (inherited, or declared by a protocol it is used
    as) against the framework at the version this suite installs: kind, coroutine, the calls it takes
    (tests/_framework_shapes.py)."""

    def test_the_adapter_takes_the_calls_the_framework_makes(self) -> None:
        import importlib

        from tests._framework_shapes import problems

        self.assertEqual(problems(importlib.import_module('plimsoll_client.openai_sandbox')), [])


if __name__ == "__main__":
    unittest.main()
