"""Session reattach in the Python client (step R3 of the sessions builds plan): the
checkpoint, the checkpoint store and attach, against the shared daemons and vectors of
internal/clientsuite (reattach.go), which the Go and TypeScript clients are held to too.

The reattach daemon is the in-memory session provider behind a token: a session call with
trace ID ``drop-answer`` runs and its answer is cut, ``GET /test/calls`` counts the calls
the provider ran and ``GET /test/checkpoint-vectors`` serves the vectors. The attach liar
answers an attach with trace ID ``forge-<name>`` with the honest answer with one thing
forged, and counts each session's closes."""

from __future__ import annotations

import asyncio
import json
import threading
import unittest
import urllib.request
from dataclasses import replace
from typing import Any, List, Optional

from plimsoll_client import (
    AsyncClient,
    ChainError,
    CheckpointConflictError,
    CheckpointMismatchError,
    CheckpointStoreError,
    CheckpointUnavailableError,
    Client,
    HeadMismatchError,
    InvalidOptionError,
    InvalidRequestError,
    LostCall,
    MemoryCheckpointStore,
    PlimsollError,
    RecoveringError,
    SessionCheckpoint,
    SessionEndedError,
    StaleOwnerError,
    StoredCheckpoint,
)

from plimsoll_client._tables import RECOVERING_TEXT

from ._cases import says_of, verdict
from ._env import setting

DAEMON = "suite-daemon"
KEY = "user-7/thread-3"


def get_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


class FakeInterleavingStore(MemoryCheckpointStore):
    """A memory store that runs ``after_pending`` once, right after it stores a pending
    record (another worker acting between one worker's begin and its send), and
    ``after_load`` once, right after a load (another writer between a worker's read and its
    write)."""

    def __init__(self) -> None:
        super().__init__()
        self.after_pending: Optional[Any] = None
        self.after_load: Optional[Any] = None

    def load(self, key: str) -> Optional[StoredCheckpoint]:
        got = super().load(key)
        hook = self.after_load
        if hook is not None:
            self.after_load = None
            hook()
        return got

    def compare_and_set(self, key: str, expected: Optional[StoredCheckpoint], replacement: StoredCheckpoint) -> bool:
        ok = super().compare_and_set(key, expected, replacement)
        hook = self.after_pending
        if ok and replacement.state == "pending" and hook is not None:
            self.after_pending = None
            hook()
        return ok


class FakeHoldingStore(MemoryCheckpointStore):
    """A memory store that, once ``hold`` is set to a barrier, keeps every loader at it
    after its load until all its parties have loaded (workers that all read the record
    before any of them acts), and keeps what each held load returned in ``loads``."""

    def __init__(self) -> None:
        super().__init__()
        self.hold: Optional[threading.Barrier] = None
        self.loads: List[Optional[StoredCheckpoint]] = []

    def load(self, key: str) -> Optional[StoredCheckpoint]:
        got = super().load(key)
        hold = self.hold
        if hold is not None:
            self.loads.append(got)
            hold.wait(10)
        return got


class FakeBeforeReadyStore(MemoryCheckpointStore):
    """A memory store that runs ``before_ready`` once, right before it is asked to store a
    record at a later generation than the one it replaces (an attacher's write after the
    daemon answered its attach): another worker acting between the attach and its write."""

    def __init__(self) -> None:
        super().__init__()
        self.before_ready: Optional[Any] = None

    def compare_and_set(self, key: str, expected: Optional[StoredCheckpoint], replacement: StoredCheckpoint) -> bool:
        hook = self.before_ready
        if hook is not None and expected is not None and replacement.checkpoint.generation > expected.checkpoint.generation:
            self.before_ready = None
            hook()
        return super().compare_and_set(key, expected, replacement)


class FakeFailingStore(MemoryCheckpointStore):
    """A memory store whose writes of a ready record after a call fail: by refusing
    (``refuse``) or by raising (``raise_``)."""

    def __init__(self) -> None:
        super().__init__()
        self.refuse = False
        self.raise_ = False

    def compare_and_set(self, key: str, expected: Optional[StoredCheckpoint], replacement: StoredCheckpoint) -> bool:
        after_call = expected is not None and expected.state == "pending" and replacement.state == "ready"
        if after_call and self.raise_:
            raise OSError("the store's disk is gone")
        if after_call and self.refuse:
            return False
        return super().compare_and_set(key, expected, replacement)


class Base(unittest.TestCase):
    url: str
    token: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.url = setting("PLIMSOLL_REATTACH_URL")
        cls.token = setting("PLIMSOLL_REATTACH_TOKEN")

    def client(self, url: Optional[str] = None) -> Client:
        return Client(url or self.url, self.token, daemon_name=DAEMON)

    def provider_calls(self) -> int:
        return int(get_json(f"{self.url}/test/calls")["calls"])

    def seeded(self, s: Any, key: str) -> MemoryCheckpointStore:
        """A store holding s's checkpoint under key, which s itself does not use: a worker
        whose calls do not pass through the store, so the daemon is the one to refuse it."""
        store = MemoryCheckpointStore()
        self.assertTrue(store.compare_and_set(key, None, StoredCheckpoint(revision=1, state="ready", operation="", checkpoint=s.checkpoint())))
        return store


class Vectors(Base):
    def test_every_client_reads_the_shared_vectors(self) -> None:
        vectors = get_json(f"{self.url}/test/checkpoint-vectors")
        for v in vectors["valid"]:
            with self.subTest(v["name"]):
                cp = SessionCheckpoint.from_json(v["json"])
                verdict("checkpoint/valid/" + v["name"], "checkpoint", "parsed")
                self.assertEqual(SessionCheckpoint.from_json(cp.to_json()), cp)
        for v in vectors["invalid"]:
            with self.subTest(v["name"]):
                try:
                    SessionCheckpoint.from_json(v["json"])
                    got = "parsed"
                except ValueError:
                    got = "refused"
                verdict("checkpoint/invalid/" + v["name"], "checkpoint", got)
                self.assertEqual(got, "refused")


class Checkpoints(Base):
    def test_checkpoint_round_trip(self) -> None:
        with self.client().open_session(minimum_isolation="container") as s:
            s.run_cell("x = 1")
            cp = s.checkpoint()
            self.assertEqual((cp.daemon, cp.session, cp.generation, cp.calls), (DAEMON, s.fingerprint, 1, 1))
            self.assertEqual((cp.provider, cp.isolation, cp.open_floor, cp.open_rule), ("fake-sessions", "container", "container", ""))
            self.assertEqual(cp.last_record_sha256, s.last_record_sha256)
            self.assertEqual(SessionCheckpoint.from_json(cp.to_json()), cp)

    def test_no_secret_in_checkpoint_json_or_repr(self) -> None:
        store = MemoryCheckpointStore()
        s = self.client().open_session(checkpoint_store=store, checkpoint_key=KEY)
        s.run_cell("x = 1")
        cp = s.checkpoint()
        stored = store.load(KEY)
        for text in (cp.to_json(), repr(cp), repr(stored), repr(s), str(cp)):
            self.assertNotIn(s._id, text)
            self.assertNotIn(self.token, text)
        self.assertNotIn(s.fingerprint, repr(s), "a session's repr shows the fingerprint's first 12 characters only")
        self.assertIn(s.fingerprint[:12], repr(s))
        s.close()

    def test_refused_when_unnamed_stopped_closed_ended(self) -> None:
        with Client(self.url, self.token).open_session() as unnamed:
            with self.assertRaises(CheckpointUnavailableError):
                unnamed.checkpoint()
        closed = self.client().open_session()
        closed.close()
        with self.assertRaises(CheckpointUnavailableError):
            closed.checkpoint()
        stopped = self.client().open_session()
        with self.assertRaises(PlimsollError) as cm:
            stopped.run_cell("1", trace_id="drop-answer")
        self.assertIsNone(cm.exception.not_dispatched, "a lost answer is never marked as nothing ran")
        with self.assertRaises(CheckpointUnavailableError):
            stopped.checkpoint()
        stopped._close_quietly()

    def test_a_daemon_name_is_never_a_url(self) -> None:
        with self.assertRaises(InvalidOptionError):
            Client(self.url, self.token, daemon_name="https://plimsoll.example")

    def test_an_open_answer_must_echo_the_floor_and_rule(self) -> None:
        liar = Client(setting("PLIMSOLL_LIAR_URL"))
        for trace in ("bad-floor", "bad-rule"):
            with self.subTest(trace), self.assertRaises(ChainError):
                liar.open_session(minimum_isolation="process", trace_id=trace)


class Attach(Base):
    def test_attach_continues_the_chain(self) -> None:
        store = MemoryCheckpointStore()
        a = self.client().open_session(checkpoint_store=store, checkpoint_key=KEY + "/chain")
        a.run_cell("x = 1")
        a.run_cell("y = 2")
        before = store.load(KEY + "/chain")
        assert before is not None
        b = self.client().attach_session(KEY + "/chain", store=store)
        r = b.run_cell("z = 3")
        self.assertEqual(r.stdout_text, "python 3: z = 3", "the same interpreter, now behind the second worker")
        assert r.record is not None
        self.assertEqual((r.record.sequence, r.record.previous_sha256), (3, before.checkpoint.last_record_sha256))
        after = store.load(KEY + "/chain")
        assert after is not None
        self.assertEqual((after.state, after.checkpoint.generation, after.checkpoint.calls), ("ready", 2, 3))
        self.assertEqual(b.close().calls, 3)

    def test_stale_worker_is_refused_before_dispatch(self) -> None:
        a = self.client().open_session()
        store = self.seeded(a, KEY + "/stale")
        b = self.client().attach_session(KEY + "/stale", store=store)
        calls = self.provider_calls()
        with self.assertRaises(StaleOwnerError) as cm:
            a.run_cell("1")
        self.assertEqual(cm.exception.not_dispatched, "permission")
        self.assertEqual(self.provider_calls(), calls, "the provider ran the stale worker's call")
        self.assertIsNotNone(a.stopped)
        with self.assertRaises(StaleOwnerError) as again:
            a.run_cell("1")
        self.assertEqual(again.exception.not_dispatched, "request", "refused here, nothing sent")
        b.close()

    def test_stale_worker_cannot_close(self) -> None:
        a = self.client().open_session()
        b = self.client().attach_session(KEY + "/close", store=self.seeded(a, KEY + "/close"))
        with self.assertRaises(StaleOwnerError):
            a.close()
        self.assertIsNotNone(a.stopped)
        b.run_cell("still open")
        b.close()

    def test_a_stale_worker_sharing_the_store_is_stopped_before_sending(self) -> None:
        # Through a shared store the stale worker never reaches the daemon: its record
        # changed under it, so its call is refused here with nothing sent.
        store = MemoryCheckpointStore()
        a = self.client().open_session(checkpoint_store=store, checkpoint_key=KEY + "/shared")
        b = self.client().attach_session(KEY + "/shared", store=store)
        calls = self.provider_calls()
        with self.assertRaises(CheckpointConflictError) as cm:
            a.run_cell("1")
        self.assertFalse(cm.exception.sent)
        self.assertEqual(self.provider_calls(), calls)
        self.assertIsNotNone(a.stopped)
        b.close()

    def test_attach_refuses_locally(self) -> None:
        store = MemoryCheckpointStore()
        s = self.client().open_session(checkpoint_store=store, checkpoint_key=KEY + "/local")
        stored = store.load(KEY + "/local")
        assert stored is not None
        other = MemoryCheckpointStore()
        other.compare_and_set("k", None, replace(stored, checkpoint=replace(stored.checkpoint, daemon="another-daemon")))
        nowhere = "http://127.0.0.1:9"  # nothing listens: a request sent would fail differently
        for name, client, key, st in (
            ("another daemon's checkpoint", Client(nowhere, self.token, daemon_name=DAEMON), "k", other),
            ("a client with no name", Client(nowhere, self.token), KEY + "/local", store),
        ):
            with self.subTest(name), self.assertRaises(InvalidRequestError) as cm:
                client.attach_session(key, store=st)
            self.assertEqual(cm.exception.not_dispatched, "request")
        with self.assertRaises(ValueError):
            replace(stored.checkpoint, generation=0)
        self.client().attach_session(KEY + "/local", store=store).close()
        del s

    def test_missing_checkpoint_never_becomes_fresh(self) -> None:
        with self.assertRaises(LookupError):
            self.client("http://127.0.0.1:9").attach_session("nobody", store=MemoryCheckpointStore())

    def test_a_named_fingerprint_attaches_that_session_or_sends_nothing(self) -> None:
        # attach_session(fingerprint=) checks the record it sends: a store holding another
        # session under the key is refused with nothing sent, so that session stays with
        # its worker.
        a = self.client().open_session()
        other = self.client().open_session()
        store = self.seeded(a, KEY + "/pinned")
        nowhere = self.client("http://127.0.0.1:9")  # nothing listens: a request sent would fail differently
        with self.assertRaises(InvalidRequestError):
            nowhere.attach_session(KEY + "/pinned", store=store, fingerprint="ABC")
        with self.assertRaises(LookupError):
            nowhere.attach_session(KEY + "/pinned", store=store, fingerprint=other.fingerprint)
        b = self.client().attach_session(KEY + "/pinned", store=store, fingerprint=a.fingerprint)
        self.assertEqual(b.fingerprint, a.fingerprint)
        with self.assertRaises(StaleOwnerError):
            a.run_cell("1")
        b.close()
        other.close()

    def test_forged_attach_answer_is_rejected_without_close(self) -> None:
        liar_url = setting("PLIMSOLL_ATTACH_LIAR_URL")
        store = MemoryCheckpointStore()
        s = self.client(liar_url).open_session(minimum_isolation="container", checkpoint_store=store, checkpoint_key="forged")
        s.run_cell("1")
        before = store.load("forged")
        b = self.client(liar_url)
        for name in get_json(f"{liar_url}/test/forgeries"):
            with self.subTest(name):
                err: Optional[PlimsollError] = None
                try:
                    b.attach_session("forged", store=store, trace_id="forge-" + name)
                except PlimsollError as e:
                    err = e
                verdict("attach/forgeries/" + name, "attach-live", says_of(err))
                self.assertIsInstance(err, ChainError)
            self.assertEqual(store.load("forged"), before, "a refused attach left the store changed")
        self.assertEqual(get_json(f"{liar_url}/test/closes?session={s.fingerprint}")["closes"], 0)
        b.attach_session("forged", store=store, trace_id="forge-none")  # the honest answer
        verdict("attach/forgeries/none", "attach-live", "accept")

    def test_two_attachers_one_store(self) -> None:
        # Two workers that both read the same checkpoint before either attaches: the
        # daemon raises the generation for the first, so the second's checkpoint is stale
        # under the session's turn and it is refused there, before anything moves. The
        # store holds each loader until both have loaded, so the race holds by
        # construction and not by thread timing (finding release-87: a barrier before
        # the attach only started the threads together, and one could finish its whole
        # attach before the other read the store, an ordinary later takeover).
        store = FakeHoldingStore()
        a = self.client().open_session(checkpoint_store=store, checkpoint_key=KEY + "/two")
        opened = store.load(KEY + "/two")
        store.hold = threading.Barrier(2)
        got: List[Any] = []

        def attach() -> None:
            try:
                got.append(self.client().attach_session(KEY + "/two", store=store))
            except Exception as e:  # every outcome is counted below, none hidden
                got.append(e)

        threads = [threading.Thread(target=attach) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        store.hold = None
        self.assertEqual(store.loads, [opened, opened], "both attachers held the same checkpoint before either attached")
        sessions = [g for g in got if not isinstance(g, Exception)]
        refused = [g for g in got if isinstance(g, Exception)]
        self.assertEqual(len(got), 2)
        self.assertEqual(len(sessions), 1, f"exactly one worker holds the session: {got}")
        self.assertIsInstance(refused[0], StaleOwnerError, f"the second attach from the same checkpoint: {got}")
        self.assertEqual(refused[0].not_dispatched, "permission")
        now = store.load(KEY + "/two")
        assert now is not None and opened is not None
        self.assertEqual((now.revision, now.checkpoint.generation), (opened.revision + 1, 2), "the store holds the winner's record")
        self.assertEqual(sessions[0].run_cell("1").exit_code, 0)
        with self.assertRaises(CheckpointConflictError):
            a.run_cell("1")
        sessions[0].close()

    def test_a_later_takeover_through_one_store_is_allowed(self) -> None:
        # A second attach that reads the store after the first attach finished takes
        # the session over from the first attacher, as any later attach may: the first
        # attacher's next call is refused here with nothing sent, and the provider runs
        # nothing for it.
        store = MemoryCheckpointStore()
        self.client().open_session(checkpoint_store=store, checkpoint_key=KEY + "/later")
        first = self.client().attach_session(KEY + "/later", store=store)
        second = self.client().attach_session(KEY + "/later", store=store)
        self.assertEqual(first.fingerprint, second.fingerprint)
        now = store.load(KEY + "/later")
        assert now is not None
        self.assertEqual(now.checkpoint.generation, 3)
        calls = self.provider_calls()
        with self.assertRaises(CheckpointConflictError) as cm:
            first.run_cell("1")
        self.assertFalse(cm.exception.sent)
        self.assertEqual(self.provider_calls(), calls, "the provider ran the earlier attacher's call")
        self.assertIsNotNone(first.stopped)
        self.assertEqual(second.run_cell("1").exit_code, 0)
        second.close()

    def test_a_lost_answer_the_record_does_not_name_prevents_attach(self) -> None:
        # The call ran and its answer was lost; a record that names no call (as a pending
        # close does) cannot explain the gap, so the attach is the plain mismatch.
        store = MemoryCheckpointStore()
        a = self.client().open_session(checkpoint_store=store, checkpoint_key=KEY + "/lost")
        calls = self.provider_calls()
        with self.assertRaises(PlimsollError) as cm:
            a.run_cell("lost", trace_id="drop-answer")
        self.assertIsNone(cm.exception.not_dispatched)
        self.assertEqual(self.provider_calls(), calls + 1, "the call ran")
        pending = store.load(KEY + "/lost")
        assert pending is not None
        self.assertEqual(pending.state, "pending", "a call that may have run leaves its record pending")
        self.assertEqual(pending.request_sha256, a.lost_request_sha256)
        unnamed = replace(pending, revision=pending.revision + 1, request_sha256="")
        self.assertTrue(store.compare_and_set(KEY + "/lost", pending, unnamed))
        with self.assertRaises(CheckpointMismatchError) as mm:
            self.client().attach_session(KEY + "/lost", store=store)
        self.assertEqual(mm.exception.not_dispatched, "request")
        self.assertEqual(store.load(KEY + "/lost"), unnamed, "a refused attach leaves the store as it was")

    def test_attach_is_never_retried(self) -> None:
        # The attach's answer is cut by a cancel once it was sent: the daemon may have
        # moved the session, so nothing is retried and the checkpoint is now stale.
        store = MemoryCheckpointStore()
        self.client().open_session(checkpoint_store=store, checkpoint_key=KEY + "/retry")
        stored = store.load(KEY + "/retry")
        c = self.client()
        c._transport.call = _send_then_fail(c._transport.call)  # type: ignore[method-assign]
        with self.assertRaises(PlimsollError) as cm:
            c.attach_session(KEY + "/retry", store=store)
        self.assertIsNone(cm.exception.not_dispatched)
        self.assertEqual(c._transport.call.sent, 1)  # type: ignore[attr-defined]
        self.assertEqual(store.load(KEY + "/retry"), stored, "nothing was written for an attach with no answer")
        with self.assertRaises(StaleOwnerError):
            self.client().attach_session(KEY + "/retry", store=store)

    def test_a_closed_session_attaches_to_nothing(self) -> None:
        store = MemoryCheckpointStore()
        s = self.client().open_session(checkpoint_store=store, checkpoint_key=KEY + "/closed")
        s.close()
        record = store.load(KEY + "/closed")
        assert record is not None
        self.assertEqual(record.state, "ready")
        with self.assertRaises(SessionEndedError) as cm:
            self.client().attach_session(KEY + "/closed", store=store)
        self.assertEqual(cm.exception.reason, "not_found")

    def test_open_with_a_taken_key_closes_the_new_session(self) -> None:
        store = MemoryCheckpointStore()
        first = self.client().open_session(checkpoint_store=store, checkpoint_key=KEY + "/taken")
        with self.assertRaises(CheckpointConflictError) as cm:
            self.client().open_session(checkpoint_store=store, checkpoint_key=KEY + "/taken")
        self.assertFalse(cm.exception.sent)
        first.close()

    def test_store_arguments_go_together(self) -> None:
        with self.assertRaises(InvalidRequestError):
            self.client().open_session(checkpoint_store=MemoryCheckpointStore())
        with self.assertRaises(InvalidRequestError):
            Client(self.url, self.token).open_session(checkpoint_store=MemoryCheckpointStore(), checkpoint_key="k")


class Pending(Base):
    def test_pending_record_left_by_a_dead_worker_can_be_taken_over(self) -> None:
        # Worker A marks its record pending, and before its call arrives worker B takes
        # the session over from the record A left: the call had not run, so the heads
        # match. A's call then reaches the daemon stale, and A's write of its result fails.
        store = FakeInterleavingStore()
        a = self.client().open_session(checkpoint_store=store, checkpoint_key="dead")
        taken: List[Any] = []
        store.after_pending = lambda: taken.append(self.client().attach_session("dead", store=store))
        calls = self.provider_calls()
        with self.assertRaises(StaleOwnerError):
            a.run_cell("late")
        self.assertEqual(len(taken), 1)
        self.assertEqual(self.provider_calls(), calls, "the stale call ran")
        record = store.load("dead")
        assert record is not None
        self.assertEqual((record.state, record.checkpoint.generation), ("ready", 2), "the store holds the new owner's record")
        self.assertIsNotNone(a.stopped)
        taken[0].run_cell("carries on")
        taken[0].close()

    def test_a_pending_record_naming_another_call_blocks(self) -> None:
        # The call that ran is not the one the record names: the gap is not explained.
        store = MemoryCheckpointStore()
        a = self.client().open_session(checkpoint_store=store, checkpoint_key="ran")
        with self.assertRaises(PlimsollError):
            a.run_cell("ran", trace_id="drop-answer")
        pending = store.load("ran")
        assert pending is not None
        other = replace(pending, revision=pending.revision + 1, request_sha256="0" * 64)
        self.assertTrue(store.compare_and_set("ran", pending, other))
        with self.assertRaises(CheckpointMismatchError):
            self.client().attach_session("ran", store=store)
        self.assertEqual(store.load("ran"), other)

    def test_store_write_failure_after_a_call_stops_the_session(self) -> None:
        for how in ("refuse", "raise_"):
            with self.subTest(how):
                store = FakeFailingStore()
                a = self.client().open_session(checkpoint_store=store, checkpoint_key="fail-" + how)
                setattr(store, how, True)
                with self.assertRaises(CheckpointStoreError) as cm:
                    a.run_cell("x = 1")
                e = cm.exception
                self.assertTrue(e.sent)
                self.assertEqual(e.result.stdout_text, "python 1: x = 1", "the call ran, and its result is attached")
                self.assertEqual(isinstance(e, CheckpointConflictError), how == "refuse")
                self.assertIsNotNone(a.stopped)
                record = store.load("fail-" + how)
                assert record is not None
                self.assertEqual(record.state, "pending", "the record stays pending")
                with self.assertRaises(PlimsollError) as again:
                    a.run_cell("1")
                self.assertEqual(again.exception.not_dispatched, "request")

    def test_a_refused_call_leaves_the_record_ready(self) -> None:
        # A call the daemon refused before it ran (a floor the session's tier cannot meet)
        # puts the record back to ready at the same head, and the session goes on.
        store = MemoryCheckpointStore()
        a = self.client().open_session(checkpoint_store=store, checkpoint_key="refused")
        before = store.load("refused")
        assert before is not None
        with self.assertRaises(PlimsollError) as cm:
            a.run_cell("1", minimum_isolation="vm")
        self.assertEqual(cm.exception.not_dispatched, "isolation")
        after = store.load("refused")
        assert after is not None
        self.assertEqual((after.state, after.revision, after.checkpoint), ("ready", before.revision + 2, before.checkpoint))
        self.assertIsNone(a.stopped)
        a.run_cell("x = 1")
        a.close()

    def test_conflict_on_begin_stops_the_session(self) -> None:
        store = MemoryCheckpointStore()
        a = self.client().open_session(checkpoint_store=store, checkpoint_key="begin")
        record = store.load("begin")
        assert record is not None
        store.compare_and_set("begin", record, replace(record, revision=record.revision + 1))  # another writer
        calls = self.provider_calls()
        with self.assertRaises(CheckpointConflictError) as cm:
            a.run_cell("1")
        self.assertFalse(cm.exception.sent)
        self.assertEqual(self.provider_calls(), calls, "nothing was sent")
        self.assertIsNotNone(a.stopped)

    def test_a_close_with_no_answer_is_sent_again_from_its_own_pending_record(self) -> None:
        # Finding hunt-quality-91: the first close leaves the record pending and gets no
        # answer; the second starts from that pending record, which is this worker's own, so
        # it is sent (no CheckpointConflictError) and collects the daemon's count. A close
        # the daemon answered is never sent again (the same rule as the Go and TypeScript
        # clients).
        store = MemoryCheckpointStore()
        a = self.client().open_session(checkpoint_store=store, checkpoint_key="close-lost")
        a.run_cell("x = 1")
        a._transport.call = _lose_first_close(a._transport.call)  # type: ignore[method-assign]
        with self.assertRaises(PlimsollError) as cm:
            a.close()
        self.assertIsNone(cm.exception.not_dispatched)
        record = store.load("close-lost")
        assert record is not None
        self.assertEqual(record.state, "pending", "the close may have reached the daemon")
        summary = a.close()
        self.assertEqual(summary.calls, 1)
        self.assertEqual(a._transport.call.closes, 2)  # type: ignore[attr-defined]
        record = store.load("close-lost")
        assert record is not None
        self.assertEqual(record.state, "ready")
        self.assertEqual(a.close(), summary, "a later close is the answered one")
        self.assertEqual(a._transport.call.closes, 2)  # type: ignore[attr-defined]


class ExplainedGap(Base):
    """The explained gap (option A of the PydanticAI design's section 3.3): a pending record
    names its call, and a call that ran with its answer lost is taken over across the gap,
    once, with the lost call's record and, when the daemon kept it, its answer; the attached
    session is then recovering, and refuses every call until the application resolves it
    (lost call option 3, the Go client's client/checkpoint_gap_test.go)."""

    def lost(self, key: str, url: Optional[str] = None, floor: Optional[str] = None, keep_no_answer: bool = False) -> MemoryCheckpointStore:
        store = MemoryCheckpointStore()
        a = self.client(url).open_session(checkpoint_store=store, checkpoint_key=key, minimum_isolation=floor, keep_no_answer=keep_no_answer)
        a.run_cell("x = 1")
        with self.assertRaises(PlimsollError):
            a.run_cell("y = 2", trace_id="drop-answer")
        return store

    def test_a_call_that_ran_with_its_answer_lost_is_explained(self) -> None:
        store = self.lost("gap")
        pending = store.load("gap")
        assert pending is not None and pending.state == "pending"
        b = self.client().attach_session("gap", store=store)
        lc = b.lost_call
        assert lc is not None and lc.record is not None
        self.assertEqual((lc.request_sha256, lc.record.request_sha256, lc.record.sequence), (pending.request_sha256, pending.request_sha256, 2))
        # The answer the worker that sent the call never got: its output, and its record the
        # lost one.
        assert lc.answer is not None
        self.assertEqual((lc.answer.stdout_text, lc.answer.record), ("python 2: y = 2", lc.record))
        ready = store.load("gap")
        assert ready is not None
        self.assertEqual((ready.state, ready.checkpoint.generation, ready.checkpoint.calls), ("ready", 2, 2))
        self.assertEqual(
            (ready.checkpoint.last_record_sha256, ready.checkpoint.recovering_request_sha256), (lc.record.sha256, pending.request_sha256),
            "the store holds the recovering state",
        )
        b.resolve_lost_call()
        self.assertIsNone(b.lost_call)
        resolved = store.load("gap")
        assert resolved is not None
        self.assertEqual(
            (resolved.revision, resolved.checkpoint.recovering_request_sha256, resolved.checkpoint.calls), (ready.revision + 1, "", 2),
            "resolving writes the store's record without the lost call",
        )
        r = b.run_cell("z = 3")
        self.assertEqual(r.stdout_text, "python 3: z = 3", "the same interpreter, after the lost call")
        assert r.record is not None
        self.assertEqual((r.record.sequence, r.record.previous_sha256), (3, lc.record.sha256))
        self.assertEqual(b.close().calls, 3)

    def test_a_recovering_session_refuses_every_call_until_resolved(self) -> None:
        # Finding release-74, release-84: under the first-call rule a repeat sent after any
        # other call ran a second time (starts.log 2). Every call is refused now, the lost
        # call's repeat and any other alike, before anything is sent, until the application
        # resolves the session; then a deliberate resend runs, the application's decision.
        store = self.lost("repeat")
        b = self.client().attach_session("repeat", store=store)
        calls = self.provider_calls()
        for code in ("y = 2", "w = 0", "y = 2"):
            with self.subTest(code), self.assertRaises(RecoveringError) as cm:
                b.run_cell(code)
            self.assertEqual(cm.exception.not_dispatched, "request")
            # What the client says, in the Go client's words (client.RecoveringText, copied
            # into _tables by internal/wiretables).
            self.assertEqual(cm.exception.message, f"plimsoll: {RECOVERING_TEXT}; nothing was sent")
        self.assertEqual(self.provider_calls(), calls, "a call ran while recovering")
        self.assertIsNone(b.stopped, "the refusals stopped the session")
        self.assertIsNotNone(b.lost_call, "the refusals resolved the session")
        self.assertTrue(b.checkpoint().recovering_request_sha256, "saving the head resolved the session")
        self.assertIsNotNone(b.lost_call)
        b.resolve_lost_call()
        b.run_cell("y = 2")  # the repeat, once resolved: running it again is the application's decision
        self.assertEqual(self.provider_calls(), calls + 1)
        b.close()

    def test_a_retry_on_another_worker_is_refused_too(self) -> None:
        # The worker that took the session over across the gap dies before it resolves it;
        # the next one attaches from the record it left, which carries the recovering state:
        # it knows the lost call by its request digest alone, and refuses every call until it
        # resolves it (finding release-62: the stored record carries the state until a
        # resolve, as the Go and TypeScript clients' checkpoints do).
        store = self.lost("retry")
        b = self.client().attach_session("retry", store=store)
        lost = b.lost_call
        assert lost is not None
        with self.assertRaises(RecoveringError):
            b.run_cell("w = 0")
        stored = store.load("retry")
        assert stored is not None
        self.assertEqual(stored.checkpoint.recovering_request_sha256, lost.request_sha256, "a refused call cleared the stored state")
        c = self.client().attach_session("retry", store=store)
        self.assertEqual(c.lost_call, LostCall(request_sha256=lost.request_sha256), "the record and answer stay with the worker that attached across the gap")
        calls = self.provider_calls()
        with self.assertRaises(RecoveringError):
            c.run_cell("y = 2")
        self.assertEqual(self.provider_calls(), calls)
        c.resolve_lost_call()
        c.run_cell("w = 0")
        after = store.load("retry")
        assert after is not None
        self.assertEqual(after.checkpoint.recovering_request_sha256, "", "the state outlived its resolution")
        c.close()

    def test_a_checkpoint_carries_the_recovering_state(self) -> None:
        # The application-held checkpoint, as Go's Session.Checkpoint: it carries the state
        # until the session is resolved, and round-trips through its JSON form.
        store = self.lost("json")
        b = self.client().attach_session("json", store=store)
        cp = b.checkpoint()
        assert b.lost_call is not None
        self.assertEqual(cp.recovering_request_sha256, b.lost_call.request_sha256)
        self.assertEqual(SessionCheckpoint.from_json(cp.to_json()), cp)
        self.assertIn('"recovering_request_sha256":"' + cp.recovering_request_sha256 + '"', cp.to_json())
        b.resolve_lost_call()
        self.assertEqual(b.checkpoint().recovering_request_sha256, "")

    def test_a_resolve_the_store_will_not_take_stops_the_session(self) -> None:
        # The record changed under this worker (another worker took the session over): the resolve writes nothing over
        # it, raises with nothing sent, and the session stops; the store still says recovering, so the next worker is
        # told again.
        store = self.lost("resolve-conflict")
        b = self.client().attach_session("resolve-conflict", store=store)
        held = store.load("resolve-conflict")
        assert held is not None
        moved = replace(held, revision=held.revision + 1)
        self.assertTrue(store.compare_and_set("resolve-conflict", held, moved))
        with self.assertRaises(CheckpointConflictError) as cm:
            b.resolve_lost_call()
        self.assertFalse(cm.exception.sent)
        self.assertIsNotNone(b.stopped)
        self.assertEqual(store.load("resolve-conflict"), moved)

    def test_keep_no_answer_returns_the_record_alone(self) -> None:
        store = self.lost("no-answer", keep_no_answer=True)
        b = self.client().attach_session("no-answer", store=store)
        lc = b.lost_call
        assert lc is not None and lc.record is not None
        self.assertTrue(lc.record.result_sha256, "the daemon answered the lost call")
        self.assertIsNone(lc.answer, "a session opened with keep_no_answer got an answer back")

    def test_forged_explained_gap_answers_are_refused(self) -> None:
        liar_url = setting("PLIMSOLL_ATTACH_LIAR_URL")
        store = self.lost("forged-gap", liar_url, "container")
        before = store.load("forged-gap")
        b = self.client(liar_url)
        for name in get_json(f"{liar_url}/test/lost-forgeries"):
            with self.subTest(name):
                err: Optional[PlimsollError] = None
                try:
                    b.attach_session("forged-gap", store=store, trace_id="forge-" + name)
                except PlimsollError as e:
                    err = e
                verdict("attach/lost-forgeries/" + name, "attach-live", says_of(err))
                self.assertIsInstance(err, ChainError)
            self.assertEqual(store.load("forged-gap"), before, "a refused attach left the store changed")
        assert before is not None
        self.assertEqual(get_json(f"{liar_url}/test/closes?session={before.checkpoint.session}")["closes"], 0)
        s = b.attach_session("forged-gap", store=store, trace_id="forge-lost-none")
        lc = s.lost_call
        assert lc is not None
        self.assertIsNotNone(lc.answer, "the honest answer carries the lost call's answer, checked")
        verdict("attach/lost-forgeries/lost-none", "attach-live", "accept")


class HeadOnEveryCall(Base):
    """Every session call states the head it expects (protocol 8), filled in inside the lock
    that serializes the session's calls."""

    def test_a_head_mismatch_stops_the_session(self) -> None:
        # The attach liar raises the head's count of a call whose trace ID is head-mismatch, so
        # the daemon refuses it as another holder's call would leave it: not dispatched,
        # reason request, the daemon's head beside it. The session stops: the call after it is
        # refused before it is sent (the liar counts no second call).
        liar_url = setting("PLIMSOLL_ATTACH_LIAR_URL")
        h = self.client(liar_url).open_session(minimum_isolation="container")
        with self.assertRaises(HeadMismatchError) as cm:
            h.run_cell("1", trace_id="head-mismatch")
        call_err = cm.exception
        self.assertEqual(call_err.not_dispatched, "request")
        assert call_err.head is not None
        self.assertEqual((call_err.head["generation"], call_err.head["calls"]), (1, 0), "the daemon's head, as its detail states it")
        self.assertIsNotNone(h.stopped)
        before = get_json(f"{liar_url}/test/session-calls?session={h.fingerprint}")["calls"]
        next_err: Optional[PlimsollError] = None
        try:
            h.run_cell("1")
        except PlimsollError as e:
            next_err = e
        sent = get_json(f"{liar_url}/test/session-calls?session={h.fingerprint}")["calls"] != before
        got = {"call": says_of(call_err).split("/")[0], "next": says_of(next_err).split("/")[0], "nextSent": sent}
        verdict("session/head-mismatch", "session-head", got)
        self.assertEqual(got, {"call": "not_dispatched:request", "next": "not_dispatched:request", "nextSent": False})
        with self.assertRaises(CheckpointUnavailableError):
            h.checkpoint()

    def test_concurrent_calls_on_one_session_each_state_the_head(self) -> None:
        s = self.client().open_session()
        calls = self.provider_calls()
        errors: List[BaseException] = []

        def call() -> None:
            try:
                s.run_cell("x = 1")
            except BaseException as e:  # every outcome is counted below, none hidden
                errors.append(e)

        threads = [threading.Thread(target=call) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(errors, [])
        self.assertEqual((self.provider_calls() - calls, s.calls), (8, 8))
        self.assertEqual(s.close().calls, 8)

    def test_the_head_is_sent_and_kept_out_of_the_request_digest(self) -> None:
        s = self.client().open_session()
        sent: List[Any] = []
        call = s._transport.call

        def spy(method: str, body: Any, path: str, cancel: Any = None) -> Any:
            if method == "SessionRun":
                sent.append(json.loads(json.dumps(body)))
            return call(method, body, path, cancel)

        s._transport.call = spy  # type: ignore[method-assign]
        first = s.run_cell("x = 1")
        second = s.run_cell("x = 1")
        assert first.record is not None and second.record is not None
        self.assertEqual([b["head"] for b in sent], [
            {"generation": "1", "calls": "0", "lastRecordSha256": ""},
            {"generation": "1", "calls": "1", "lastRecordSha256": first.record.sha256},
        ])
        self.assertNotIn("generation", sent[0], "the generation alone was deleted with protocol 8")
        self.assertEqual(first.record.request_sha256, second.record.request_sha256, "the head is not part of the request digest")
        s.close()


class AttachWriteOverAStaleWorker(Base):
    """Finding release-60: an attach the daemon answered, whose store write then found a
    record a stale worker wrote after the attach read the store."""

    def test_the_attacher_keeps_the_session_when_a_stale_worker_wrote_meanwhile(self) -> None:
        # Worker A holds the session; worker B reads the store and attaches. Between B's attach
        # and B's write, A begins a call (pending), the daemon refuses it as stale, and A puts
        # its record back to ready at the old generation. B's compare-and-set fails; the record
        # A wrote names the same session at the generation B attached from, so B writes over it
        # and holds the session, rather than dropping it to nobody until its lifetime ends.
        store = FakeBeforeReadyStore()
        a = self.client().open_session(checkpoint_store=store, checkpoint_key="stale-write")
        a.run_cell("x = 1")
        refused: List[BaseException] = []

        def stale_call() -> None:
            try:
                a.run_cell("late")
            except BaseException as e:  # asserted below
                refused.append(e)

        store.before_ready = stale_call
        calls = self.provider_calls()
        b = self.client().attach_session("stale-write", store=store)
        self.assertEqual(len(refused), 1)
        self.assertIsInstance(refused[0], StaleOwnerError)
        self.assertEqual(self.provider_calls(), calls, "the stale call ran")
        now = store.load("stale-write")
        assert now is not None
        self.assertEqual((now.state, now.checkpoint.generation, now.checkpoint.calls), ("ready", 2, 1), "the store holds the attacher's record")
        self.assertEqual(b.run_cell("y = 2").stdout_text, "python 2: y = 2")
        # The session is reachable by one worker, from the store, by the next attach too.
        c = self.client().attach_session("stale-write", store=store)
        self.assertEqual(c.close().calls, 2)

    def test_a_later_generation_written_meanwhile_still_drops_the_session(self) -> None:
        # Another worker's attach after this one's read leaves a record at a later generation:
        # that worker holds the session, so this attach is dropped, not written over it.
        store = FakeInterleavingStore()
        s = self.client().open_session(checkpoint_store=store, checkpoint_key="moved")
        record = store.load("moved")
        assert record is not None
        other = replace(record, revision=record.revision + 1, checkpoint=replace(record.checkpoint, generation=record.checkpoint.generation + 5))
        store.after_load = lambda: store.compare_and_set("moved", record, other)
        with self.assertRaises(CheckpointConflictError) as cm:
            self.client().attach_session("moved", store=store)
        self.assertTrue(cm.exception.sent, "the attach went through; only the store write failed")
        self.assertEqual(store.load("moved"), other)
        del s


class AsyncAttach(Base):
    def test_async_attach_continues_and_the_stale_worker_is_refused(self) -> None:
        async def run() -> None:
            c = AsyncClient(self.url, self.token, daemon_name=DAEMON)
            a = await c.open_session()
            await a.run_cell("x = 1")
            cp = await a.checkpoint()
            self.assertEqual(cp.calls, 1)
            store = self.seeded(a.sync, "async")
            b = await AsyncClient(self.url, self.token, daemon_name=DAEMON).attach_session("async", store=store)
            r = await b.run_cell("y = 2")
            self.assertEqual(r.stdout_text, "python 2: y = 2")
            with self.assertRaises(StaleOwnerError):
                await a.run_cell("1")
            await b.close()

        asyncio.run(run())


def _send_then_fail(call: Any) -> Any:
    """A transport call that sends an attach and then reports its connection lost."""

    def wrapped(method: str, body: Any, path: str, cancel: Any = None) -> Any:
        m = call(method, body, path, cancel)
        if method == "AttachSession":
            wrapped.sent += 1  # type: ignore[attr-defined]
            raise PlimsollError("plimsoll: the connection dropped after the daemon answered", code="unavailable")
        return m

    wrapped.sent = 0  # type: ignore[attr-defined]
    return wrapped


def _lose_first_close(call: Any) -> Any:
    """A transport call whose first CloseSession is lost before the daemon reads it, as a
    connection reset would leave it; it counts every CloseSession it is handed."""

    def wrapped(method: str, body: Any, path: str, cancel: Any = None) -> Any:
        if method == "CloseSession":
            wrapped.closes += 1  # type: ignore[attr-defined]
            if wrapped.closes == 1:  # type: ignore[attr-defined]
                raise PlimsollError("plimsoll: the connection was reset", code="unavailable")
        return call(method, body, path, cancel)

    wrapped.closes = 0  # type: ignore[attr-defined]
    return wrapped
