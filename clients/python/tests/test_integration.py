"""The client against real daemon handlers, which client_test.go serves: the wasm
provider for single runs, a scripted provider for projects and modules, a
tampering and a lying handler for the checks, and the in-memory session provider
for sessions."""

from __future__ import annotations

import asyncio
import math
import re
import ssl
import threading
import unittest
import urllib.request
from typing import List

from plimsoll_client import (
    PROTOCOL,
    RECORD_VERSION,
    AsyncClient,
    AsyncSession,
    ChainError,
    Client,
    InsufficientIsolationError,
    InvalidRequestError,
    IsolationEvidenceMismatchError,
    NoRecordError,
    PlimsollError,
    ProtocolMismatchError,
    RecordMismatchError,
    ResultKindMismatchError,
    Session,
    SessionEndedError,
    SoftwareMismatchError,
    SoftwareRule,
    TransportError,
    UnsupportedError,
)
from plimsoll_client._record import record_digest

from ._env import setting

HEX64 = re.compile(r"[0-9a-f]{64}")
OTHER_SOFTWARE = "oci-manifest:linux/amd64@sha256:" + "0" * 64


class Versions(unittest.TestCase):
    def test_the_client_speaks_the_daemons_numbers(self) -> None:
        self.assertEqual(PROTOCOL, int(setting("PLIMSOLL_GO_PROTOCOL")), "protocol.Number moved; update PROTOCOL")
        self.assertEqual(RECORD_VERSION, int(setting("PLIMSOLL_GO_RECORD_VERSION")), "record.Version moved")


class Wasm(unittest.TestCase):
    c: Client

    @classmethod
    def setUpClass(cls) -> None:
        cls.c = Client(setting("PLIMSOLL_WASM_URL"))

    def test_describe(self) -> None:
        info = self.c.describe()
        self.assertEqual((info.provider, info.isolation, info.protocol), ("wasm", "process", PROTOCOL))
        self.assertFalse(info.supports_sessions)
        self.assertFalse(info.supports_project)
        self.assertTrue(info.javascript_environment.identity.startswith("quickjs-wasm:sha256:"))

    def test_a_snippet_runs_and_its_record_checks(self) -> None:
        r = self.c.run_javascript("console.log(6*7)", timeout=60, minimum_isolation="process", trace_id="py-1")
        self.assertEqual((r.stdout, r.exit_code, r.timed_out), (b"42\n", 0, False))
        self.assertEqual(r.stdout_text, "42\n")
        self.assertEqual((r.provider, r.isolation), ("wasm", "process"))
        rec = r.record
        assert rec is not None
        self.assertEqual((rec.version, rec.provider, rec.isolation, rec.session, rec.sequence), (RECORD_VERSION, "wasm", "process", "", 0))
        self.assertTrue(rec.environment.startswith("quickjs-wasm:sha256:"))
        self.assertTrue(HEX64.fullmatch(rec.sha256))
        self.assertEqual(rec.sha256, record_digest(rec))
        self.assertLessEqual(rec.started_unix_ms, rec.ended_unix_ms)

    def test_a_failing_snippet_is_a_result(self) -> None:
        r = self.c.run_javascript("throw new Error('boom')")
        self.assertNotEqual(r.exit_code, 0)
        self.assertIn("boom", r.stderr_text)
        self.assertIsNotNone(r.record)

    def test_a_floor_above_the_tier_is_refused_before_dispatch(self) -> None:
        with self.assertRaises(InsufficientIsolationError) as cm:
            self.c.run_javascript("console.log(1)", minimum_isolation="container")
        self.assertEqual((cm.exception.code, cm.exception.not_dispatched), ("failed_precondition", "isolation"))

    def test_unsupported_operations_are_refused_before_dispatch(self) -> None:
        for name, call in {
            "project": lambda: self.c.run_project({"main.js": "1"}, ["node main.js"]),
            "module": lambda: self.c.run_module("VanDerPol", [[1, 2]], end_time=1, step=0.1),
            "session": lambda: self.c.open_session(),
        }.items():
            with self.subTest(name), self.assertRaises(UnsupportedError) as cm:
                call()
            self.assertEqual((cm.exception.code, cm.exception.not_dispatched), ("unimplemented", "unsupported"))

    def test_async(self) -> None:
        async def go() -> bytes:
            c = AsyncClient(setting("PLIMSOLL_WASM_URL"))
            results = await asyncio.gather(c.run_javascript("console.log(1)"), c.run_javascript("console.log(2)"))
            return b"".join(r.stdout for r in results)

        self.assertEqual(asyncio.run(go()), b"1\n2\n")


class TLS(unittest.TestCase):
    """The wasm daemon over TLS. The transport opens the TLS socket itself (so a cancel
    can reach it during the handshake); the daemon's certificate and its name are
    still checked."""

    def test_a_run_over_tls(self) -> None:
        ctx = ssl.create_default_context(cafile=setting("PLIMSOLL_TLS_CA"))
        c = Client(setting("PLIMSOLL_TLS_URL"), ssl_context=ctx)
        self.assertEqual(c.describe().provider, "wasm")
        r = c.run_javascript("console.log(6*7)", minimum_isolation="process")
        self.assertEqual((r.stdout, r.isolation), (b"42\n", "process"))

    def test_a_certificate_no_trusted_authority_signed_is_refused(self) -> None:
        with self.assertRaises(TransportError) as cm:
            Client(setting("PLIMSOLL_TLS_URL")).describe()
        self.assertIsInstance(cm.exception.__cause__, ssl.SSLCertVerificationError)
        self.assertEqual(cm.exception.not_dispatched, "environment")  # the handshake failed before any byte of the request

    def test_a_host_name_the_certificate_does_not_carry_is_refused(self) -> None:
        # The certificate names 127.0.0.1, ::1 and example.com, not localhost.
        url = setting("PLIMSOLL_TLS_URL").replace("127.0.0.1", "localhost")
        ctx = ssl.create_default_context(cafile=setting("PLIMSOLL_TLS_CA"))
        with self.assertRaises(TransportError) as cm:
            Client(url, ssl_context=ctx).describe()
        self.assertIsInstance(cm.exception.__cause__, ssl.SSLCertVerificationError)
        self.assertIn("localhost", str(cm.exception))


class Auth(unittest.TestCase):
    def test_the_token_is_sent(self) -> None:
        url = setting("PLIMSOLL_AUTH_URL")
        self.assertEqual(Client(url, token="py-token").run_javascript("console.log('ok')").stdout, b"ok\n")
        for token in (None, "wrong"):
            with self.subTest(token=token), self.assertRaises(PlimsollError) as cm:
                Client(url, token=token).run_javascript("console.log(1)")
            self.assertEqual((cm.exception.code, cm.exception.not_dispatched), ("unauthenticated", "permission"))


class Tamper(unittest.TestCase):
    def test_a_changed_output_byte_is_data_loss_with_the_result_attached(self) -> None:
        with self.assertRaises(RecordMismatchError) as cm:
            Client(setting("PLIMSOLL_TAMPER_URL")).run_javascript("console.log(42)")
        e = cm.exception
        self.assertEqual((e.code, e.not_dispatched), ("data_loss", None))
        self.assertIn("result digest", str(e))
        self.assertEqual(e.result.stdout, b"43\n")
        self.assertIsNone(e.result.record)


class Scripted(unittest.TestCase):
    c: Client
    software: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.c = Client(setting("PLIMSOLL_SCRIPTED_URL"))
        cls.software = setting("PLIMSOLL_SCRIPTED_SOFTWARE")

    def test_a_project_run(self) -> None:
        r = self.c.run_project(
            {"main.py": "print('é')\n", "data/in.txt": "héllo"},
            ["python3 main.py", "cat data/in.txt"],
            ["data/in.txt", "missing.txt"],
            minimum_isolation="container",
            timeout=30,
        )
        self.assertEqual(r.outcome, "completed")
        self.assertEqual([s.command for s in r.steps], ["python3 main.py", "cat data/in.txt"])
        self.assertEqual([s.exit_code for s in r.steps], [0, 1])
        self.assertEqual(r.steps[1].stderr, b"\x00\xff")
        self.assertEqual([(a.path, a.content) for a in r.artifacts], [("data/in.txt", "héllo".encode() + b"\x00\xff")])
        self.assertEqual((r.provider, r.isolation, r.software_identity), ("scripted", "container", self.software))
        rec = r.record
        assert rec is not None
        self.assertEqual((rec.policy, rec.environment), ("scripted-policy:sha256:00", "scripted-image:sha256:0001"))

    def test_output_bytes_survive_as_bytes(self) -> None:
        r = self.c.run_javascript("console.log('x')")
        self.assertEqual(r.stdout, b"\xff\xfeconsole.log('x')")
        self.assertTrue(r.stdout_text.startswith("�"))
        self.assertTrue(r.stdout_truncated)
        self.assertEqual(r.exit_code, 3)

    def test_software_rules(self) -> None:
        exact = self.c.run_javascript("1", software=SoftwareRule.exact(self.software))
        assert exact.record is not None
        self.assertEqual(exact.record.software_rule_id, "exact:" + self.software)
        approved = self.c.run_javascript("1", software=SoftwareRule.approved(OTHER_SOFTWARE, self.software))
        assert approved.record is not None
        self.assertTrue(approved.record.software_rule_id.startswith("approved:sha256:"))
        with self.assertRaises(SoftwareMismatchError) as cm:
            self.c.run_javascript("1", software=SoftwareRule.exact(OTHER_SOFTWARE))
        self.assertEqual(cm.exception.not_dispatched, "environment")

    def test_a_floor_above_the_tier(self) -> None:
        with self.assertRaises(InsufficientIsolationError) as cm:
            self.c.run_project(None, ["true"], minimum_isolation="kernel")
        self.assertEqual(cm.exception.not_dispatched, "isolation")

    def test_a_module_run_keeps_every_double(self) -> None:
        r = self.c.run_module("Lorenz", [[1.25, 2], [3, 4], [-0.0, 1]], end_time=1, step=0.5, minimum_isolation="container")
        self.assertEqual((r.outcome, r.width, r.stdout), ("completed", 3, b"rows=3\n"))
        self.assertEqual([run.status for run in r.runs], [2, -3, 2])
        out = r.runs[0].outputs
        self.assertEqual(out[0], 1.25)
        self.assertEqual(math.copysign(1, out[1]), -1.0)
        self.assertEqual(out[2:], (1.7976931348623157e308, 5e-324, 1e21, 123456789012345678901.0))
        self.assertEqual(math.copysign(1, r.runs[2].outputs[0]), -1.0)
        self.assertIsNotNone(r.record)

    def test_nan_in_a_module_result(self) -> None:
        # JSON writes every NaN as "NaN". The daemon sends every NaN of a module output
        # as the quiet NaN with no sign or payload, the one float("nan") encodes to, so
        # the record checks whichever NaN the simulator produced.
        for model in ("nan", "nan-payload", "nan-negative"):
            r = self.c.run_module(model, [[1]], end_time=1, step=0.5)
            self.assertTrue(math.isnan(r.runs[0].outputs[1]), model)
            self.assertIsNotNone(r.record, model)


class Liar(unittest.TestCase):
    c: Client

    @classmethod
    def setUpClass(cls) -> None:
        cls.c = Client(setting("PLIMSOLL_LIAR_URL"))

    def test_describe_on_another_protocol(self) -> None:
        with self.assertRaises(ProtocolMismatchError) as cm:
            self.c.describe()
        self.assertEqual(cm.exception.info.protocol, PROTOCOL + 1)

    def test_a_refusal_on_another_protocol(self) -> None:
        with self.assertRaises(ProtocolMismatchError) as cm:
            self.c.run_javascript("other-protocol")
        self.assertEqual((cm.exception.code, cm.exception.not_dispatched), ("unimplemented", "protocol"))

    def test_weaker_evidence_than_the_floor(self) -> None:
        with self.assertRaises(IsolationEvidenceMismatchError) as cm:
            self.c.run_javascript("weak-evidence", minimum_isolation="kernel")
        e = cm.exception
        self.assertEqual((e.code, e.not_dispatched), ("data_loss", None))
        self.assertEqual(e.result.stdout, b"already executed")
        self.assertIsNotNone(e.result.record, "the record checked; only the tier fell short")

    def test_no_record(self) -> None:
        with self.assertRaises(NoRecordError) as cm:
            self.c.run_javascript("no-record")
        self.assertEqual(cm.exception.result.stdout, b"already executed")

    def test_a_result_of_another_kind(self) -> None:
        with self.assertRaises(ResultKindMismatchError):
            self.c.run_javascript("wrong-kind")

    def test_an_unmarked_failure_never_says_nothing_ran(self) -> None:
        with self.assertRaises(PlimsollError) as cm:
            self.c.run_javascript("anything else")
        self.assertEqual((cm.exception.code, cm.exception.not_dispatched), ("internal", None))

    def test_a_session_below_its_floor(self) -> None:
        with self.assertRaises(IsolationEvidenceMismatchError):
            self.c.open_session(minimum_isolation="kernel")

    def test_a_session_whose_fingerprint_is_not_its_id(self) -> None:
        with self.assertRaises(ChainError):
            self.c.open_session(trace_id="bad-fingerprint")


class Sessions(unittest.TestCase):
    c: Client
    url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.url = setting("PLIMSOLL_SESSIONS_URL")
        cls.c = Client(cls.url)

    def end_last(self, reason: str) -> None:
        req = urllib.request.Request(f"{self.url}/test/end-last?reason={reason}", method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            self.assertEqual(resp.status, 200)

    def test_describe(self) -> None:
        info = self.c.describe()
        self.assertTrue(info.supports_sessions)
        self.assertEqual((info.session_lifetime_ms, info.session_idle_timeout_ms), (60000, 60000))

    def test_a_session_chains_its_records(self) -> None:
        with self.c.open_session(minimum_isolation="container", lifetime=30, trace_id="py-session") as s:
            self.assertEqual((s.isolation, s.provider), ("container", "fake-sessions"))
            self.assertTrue(HEX64.fullmatch(s.fingerprint))
            self.assertNotIn(s._id, repr(s))
            results = [s.run_javascript(str(i)) for i in range(3)]
            # The fake answers its nth call with n "x"s: one sandbox saw every call.
            self.assertEqual([r.stdout for r in results], [b"x", b"xx", b"xxx"])
            p = s.run_project({"a.txt": "1"}, ["cat a.txt"], minimum_isolation="process")
            self.assertEqual(p.outcome, "completed")
            records = [r.record for r in results] + [p.record]
            for i, rec in enumerate(records):
                assert rec is not None
                self.assertEqual((rec.session, rec.sequence), (s.fingerprint, i + 1))
                self.assertEqual(rec.previous_sha256, records[i - 1].sha256 if i else "")  # type: ignore[union-attr]
            last = records[-1]
            assert last is not None
        summary = s.close()  # closing again is harmless: the same summary, no request
        self.assertEqual((summary.session, summary.calls, summary.last_record_sha256, summary.end), (s.fingerprint, 4, last.sha256, "closed"))
        self.assertEqual(s.ended.reason if s.ended else None, "closed")
        with self.assertRaises(SessionEndedError) as cm:
            s.run_javascript("after the close")
        self.assertEqual((cm.exception.reason, cm.exception.not_dispatched), ("closed", "request"))

    def test_a_language_hint_is_sent_and_checked(self) -> None:
        # The daemon parses the field (an unknown one would fail the open) and passes
        # it on; the fake states no languages, so only the client's check refuses.
        with self.c.open_session(languages=["python", "javascript", "python"]) as s:
            self.assertEqual(s.run_cell("1").stdout, b"python 1: 1")
        with self.assertRaises(InvalidRequestError) as cm:
            self.c.open_session(languages=["cobol"])
        self.assertEqual(cm.exception.not_dispatched, "request")

    def test_cells_chain_with_the_other_calls(self) -> None:
        with self.c.open_session() as s:
            s.run_javascript("1")
            first = s.run_cell("x = 1")
            second = s.run_cell("x + 1", files={"in/a.csv": "a,b", "b.txt": "b"})
            js = s.run_cell("1 + 1", "javascript")
            # The fake answers with the language, its count of cells, and the code,
            # and lists a cell's files on stderr.
            self.assertEqual(first.stdout, b"python 1: x = 1")
            self.assertTrue(first.interpreter_started)
            self.assertEqual((second.stdout_text, second.stderr_text), ("python 2: x + 1", "in/a.csv\nb.txt\n"))
            self.assertFalse(second.interpreter_started)
            self.assertEqual((js.stdout, js.interpreter_started), (b"javascript 1: 1 + 1", True))
            self.assertEqual([r.record.sequence for r in (first, second, js)], [2, 3, 4])  # type: ignore[union-attr]
            with self.assertRaises(InvalidRequestError) as cm:
                s.run_cell("1", "ruby")
            self.assertEqual(cm.exception.not_dispatched, "request")
        self.assertEqual(s.close().calls, 4)

    def test_a_floor_above_the_session(self) -> None:
        with self.assertRaises(InsufficientIsolationError) as cm:
            self.c.open_session(minimum_isolation="kernel")
        self.assertEqual(cm.exception.not_dispatched, "isolation")
        with self.c.open_session() as s:
            s.run_javascript("1")
            with self.assertRaises(InsufficientIsolationError) as cm:
                s.run_javascript("2", minimum_isolation="vm")
            self.assertEqual(cm.exception.not_dispatched, "isolation")
            self.assertEqual(s.run_javascript("3").record.sequence, 2)  # type: ignore[union-attr]

    def test_a_software_rule_the_session_cannot_meet(self) -> None:
        with self.assertRaises(SoftwareMismatchError) as cm:
            self.c.open_session(software=SoftwareRule.exact(OTHER_SOFTWARE))
        self.assertEqual(cm.exception.not_dispatched, "environment")

    def test_a_call_this_client_did_not_make(self) -> None:
        s = self.c.open_session()
        s.run_javascript("1")
        # Another holder of the session ID makes a call; it sees a chain it did not start, too.
        other = Session.__new__(Session)
        other.__dict__.update(s.__dict__)
        other._lock, other._calls, other._last = threading.Lock(), 0, ""
        with self.assertRaises(ChainError):
            other.run_javascript("2")
        with self.assertRaises(ChainError) as cm:
            s.run_javascript("3")
        self.assertEqual(cm.exception.result.stdout, b"xxx")
        with self.assertRaises(ChainError) as close:
            s.close()
        self.assertEqual(close.exception.result.calls, 3)
        with self.assertRaises(ChainError):
            s.close()  # the same verdict again, not a quiet summary

    def test_an_owner_at_its_cap_replaces_its_least_recently_used_session(self) -> None:
        # The session daemon caps each owner at one session, and says so.
        info = self.c.describe()
        self.assertEqual((info.max_sessions_per_owner, info.max_sessions_per_caller), (1, 0))
        first = self.c.open_session(owner="alice@example.com")
        with self.c.open_session(owner="alice@example.com") as second:
            with self.assertRaises(SessionEndedError) as cm:
                first.run_javascript("1")
            self.assertEqual((cm.exception.reason, cm.exception.not_dispatched), ("replaced", "request"))
            self.assertEqual(first.close().end, "replaced")
            with self.c.open_session(owner="bob@example.com"):
                self.assertEqual(second.run_javascript("2").stdout, b"x")
        with self.assertRaises(TypeError):
            self.c.open_session(owner=7)  # type: ignore[arg-type]
        with self.assertRaises(InvalidRequestError) as cm:
            self.c.open_session(owner="")
        self.assertEqual(cm.exception.not_dispatched, "request")

    def test_a_session_the_daemon_forgot_is_ended(self) -> None:
        # What a restarted daemon finds: no such session. The refusal carries an end.
        s = self.c.open_session()
        s._id = "00" * 16
        with self.assertRaises(SessionEndedError) as cm:
            s.run_javascript("1")
        self.assertEqual((cm.exception.reason, cm.exception.not_dispatched), ("not_found", "request"))
        self.assertEqual(s.ended.reason if s.ended else None, "not_found")

    def test_a_session_nobody_claimed_by_its_first_idle_timeout_is_an_end(self) -> None:
        # The daemon suspends after 1 s, and closes a session no request named by then,
        # as it does one whose open answer was lost; here, the client waited.
        url = setting("PLIMSOLL_QUICK_IDLE_URL")
        s = Client(url).open_session()
        req = urllib.request.Request(f"{url}/test/wait-ended", method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            self.assertEqual(resp.status, 200)
        with self.assertRaises(SessionEndedError) as cm:
            s.run_javascript("1")
        self.assertEqual((cm.exception.reason, cm.exception.not_dispatched), ("unclaimed", "request"))
        self.assertEqual(s.ended.reason if s.ended else None, "unclaimed")
        summary = s.close()
        self.assertEqual((summary.calls, summary.end), (0, "unclaimed"))

    def test_an_ended_session(self) -> None:
        s = self.c.open_session()
        s.run_javascript("1")
        self.end_last("disk_exceeded")
        with self.assertRaises(SessionEndedError) as cm:
            s.run_javascript("2")
        e = cm.exception
        self.assertEqual((e.reason, e.code, e.not_dispatched), ("disk_exceeded", "failed_precondition", "request"))
        self.assertEqual(s.ended.reason if s.ended else None, "disk_exceeded")
        summary = s.close()
        self.assertEqual((summary.calls, summary.end), (1, "disk_exceeded"))

    def test_concurrent_calls_are_serialized(self) -> None:
        with self.c.open_session() as s:
            seqs: List[int] = []
            errors: List[BaseException] = []

            def call() -> None:
                try:
                    rec = s.run_javascript("1").record
                    assert rec is not None
                    seqs.append(rec.sequence)
                except BaseException as e:  # reported below
                    errors.append(e)

            threads = [threading.Thread(target=call) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(errors, [])
            self.assertEqual(sorted(seqs), [1, 2, 3, 4])
        self.assertEqual(s.close().calls, 4)

    def test_async_session(self) -> None:
        async def go() -> int:
            c = AsyncClient(self.url)
            async with await c.open_session() as s:
                await s.run_javascript("1")
                await s.run_project(None, ["true"])
                self.assertIsNone(s.stopped)
            return (await s.close()).calls

        self.assertEqual(asyncio.run(go()), 2)


if __name__ == "__main__":
    unittest.main()


class UnansweredEvidence(unittest.TestCase):
    def test_an_unanswered_record_must_state_the_sessions_evidence(self) -> None:
        # With no response to compare it with, an unanswered call's record must meet the
        # call's floor and repeat what the session stated at open; otherwise it is data
        # loss and the session sends nothing more (v0.15.0 review, M5.3).
        c = Client(setting("PLIMSOLL_LIAR_URL"))
        s = c.open_session(minimum_isolation="container")
        with self.assertRaises(IsolationEvidenceMismatchError):
            s.run_javascript("weaker")
        with self.assertRaises(PlimsollError) as cm:
            s.run_javascript("next")
        self.assertEqual(cm.exception.not_dispatched, "request")
        with self.assertRaises(RecordMismatchError):
            c.open_session().run_javascript("other-provider")


class UnansweredCalls(unittest.TestCase):
    def test_an_unanswered_call_is_in_the_chain(self) -> None:
        # The daemon sends the record of a call that may have run but ended in an
        # error; the session keeps it in its chain and goes on, and the close agrees.
        c = Client(setting("PLIMSOLL_BREAKING_URL"))
        s = c.open_session()
        s.run_javascript("1")
        with self.assertRaises(PlimsollError) as cm:
            s.run_javascript("2")
        self.assertIsNone(cm.exception.not_dispatched)
        self.assertIsNotNone(cm.exception.unanswered)
        self.assertEqual(cm.exception.unanswered["version"], 3)
        # The checked record is handed back too, as Go's UnansweredCallError.Record.
        self.assertIsNotNone(cm.exception.record)
        self.assertEqual(cm.exception.record.sequence, 2)
        r = s.run_javascript("3")
        self.assertEqual(r.record.sequence, 3)
        self.assertEqual(s.close().calls, 3)

    def test_a_lost_answer_stops_the_session(self) -> None:
        # A call whose answer never arrived may have run: the session sends nothing
        # more, and says the later call was not sent.
        with Client(setting("PLIMSOLL_SESSIONS_URL")).open_session() as usable:
            self.assertIsNone(usable.stopped)
            self.assertIsNone(usable.ended)
            with self.assertRaises(PlimsollError) as refused:
                usable.run_javascript("refused", minimum_isolation="vm")
            self.assertEqual(refused.exception.not_dispatched, "isolation")
            self.assertIsNone(usable.stopped)
            self.assertIsNone(usable.ended)
        c = Client(setting("PLIMSOLL_LOSSY_URL"))
        s = c.open_session()
        self.assertIsNone(s.stopped)
        self.assertIsNone(s.ended)
        s.run_javascript("1")
        with self.assertRaises(PlimsollError) as cm:
            s.run_javascript("2")
        self.assertIsNone(cm.exception.not_dispatched)
        self.assertIsInstance(s.stopped, str)
        self.assertTrue(s.stopped)
        self.assertIsNone(s.ended)
        self.assertEqual(AsyncSession(s).stopped, s.stopped)
        with self.assertRaises(PlimsollError) as cm:
            s.run_javascript("3")
        self.assertEqual(cm.exception.not_dispatched, "request")
