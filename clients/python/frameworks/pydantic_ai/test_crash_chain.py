"""The chain check of examples/pydantic_ai_crash.py ("kill the worker, keep the sandbox") on records made here: two
workers' record logs and worker B's close statement, good and bad. The check is what lets the example's receipt say
the logs form one chain that the daemon's own count at close matches, so each bad set must fail, with its own reason.
No daemon and no docker: TestPythonFrameworks runs it in make clients-suite; the example itself runs on real docker
sessions in TestPydanticAICrashDocker (make docker-suite)."""

from __future__ import annotations

import copy
import hashlib
import importlib
import os
import sys
import unittest
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "examples")))
crash = importlib.import_module("pydantic_ai_crash")

Record = Dict[str, Any]


def chain(n: int, *, session: str = "a" * 64, lost_at: int = 0, answered: bool = False) -> List[Record]:
    """n records of one session, each naming the one before. The record at sequence ``lost_at`` is the lost call's:
    with no answer (canceled, 1.5 s), or with ``answered`` a result digest and no code."""
    out: List[Record] = []
    previous = ""
    for seq in range(1, n + 1):
        digest = hashlib.sha256(f"{session}/{seq}".encode()).hexdigest()
        cut = seq == lost_at and not answered
        out.append({"session": session, "sequence": seq, "previous_sha256": previous, "sha256": digest,
                    "result_sha256": "" if cut else "b" * 64, "unanswered": "canceled" if cut else "",
                    "started_unix_ms": 1_000, "ended_unix_ms": 2_503 if seq == lost_at else 1_100})
        previous = digest
    return out


def close_of(records: List[Record], *, lost: str = "") -> Dict[str, Any]:
    return {"session": records[0]["session"], "calls": len(records), "last_record_sha256": records[-1]["sha256"],
            "end": "closed", "lost_call_sha256": lost}


def crash_logs(**kw: Any) -> Tuple[List[Record], List[Record], Dict[str, Any]]:
    """Worker A's 10 records, then worker B's 14: the lost call's (sequence 11) first, as the takeover returned it."""
    records = chain(24, lost_at=11, **kw)
    return records[:10], records[10:], close_of(records, lost=records[10]["sha256"])


def freeze_logs() -> Tuple[List[Record], List[Record], Dict[str, Any]]:
    records = chain(25)
    return records[:11], records[11:], close_of(records)


class ChainCheck(unittest.TestCase):
    def failed(self, a: List[Record], b: List[Record], close: Dict[str, Any], reason: str) -> None:
        problems, receipt = crash.check_chain(a, b, close)
        self.assertEqual(receipt, "", "a bad set got a receipt")
        self.assertTrue(any(reason in p for p in problems), f"no problem saying {reason!r}: {problems}")

    def test_a_crash_run_gets_its_receipt(self) -> None:
        a, b, close = crash_logs()
        self.assertEqual(crash.check_chain(a, b, close), ([], (
            "one session, 24 calls: 1 to 10 by worker A; 11 the lost call (no answer: canceled, after 1.5 s; its record "
            "reached worker B at the takeover); 12 to 24 by worker B; the daemon's own count at close "
            f"(24, last {close['last_record_sha256'][:12]}) matches")))

    def test_an_answered_lost_call_gets_its_receipt(self) -> None:
        a, b, close = crash_logs(answered=True)
        problems, receipt = crash.check_chain(a, b, close)
        self.assertEqual(problems, [])
        self.assertIn("11 the lost call (the sandbox answered after 1.5 s, and the answer is lost; its record reached worker B", receipt)

    def test_a_freeze_run_gets_its_receipt(self) -> None:
        a, b, close = freeze_logs()
        self.assertEqual(crash.check_chain(a, b, close), ([], (
            "one session, 25 calls: 1 to 11 by worker A, 12 to 25 by worker B; call 12 names call 11; the daemon's own "
            f"count at close (25, last {close['last_record_sha256'][:12]}) matches")))

    def test_a_dropped_line(self) -> None:
        a, b, close = crash_logs()
        del a[4]
        self.failed(a, b, close, "the sequences are not 1 to 23 in order")

    def test_two_lines_swapped(self) -> None:
        a, b, close = crash_logs()
        b[3], b[4] = b[4], b[3]
        self.failed(a, b, close, "call 15 does not name call 13")

    def test_a_record_of_another_session(self) -> None:
        a, b, close = crash_logs()
        b[5] = dict(b[5], session="c" * 64)
        self.failed(a, b, close, "the logs name 2 sessions, not one")

    def test_a_close_statement_of_another_session(self) -> None:
        a, b, close = crash_logs()
        self.failed(a, b, dict(close, session="c" * 64), "the close statement names another session")

    def test_a_record_of_worker_b_before_worker_as_last(self) -> None:
        # What a returning worker A that wrote after worker B took over leaves in its log.
        a, b, close = freeze_logs()
        self.failed(a + [b[-1]], b[:-1], close, "a record of worker B comes before worker A's last")

    def test_the_lost_record_missing_from_worker_bs_log(self) -> None:
        # What a record sink that never received the lost call's record leaves: a hole at sequence 11.
        a, b, close = crash_logs()
        self.failed(a, b[1:], close, "worker B's log does not start with the record of the call lost before its takeover")
        self.failed(a, b[1:], close, "the sequences are not 1 to 23 in order")

    def test_the_unanswered_record_missing(self) -> None:
        # The takeover returned an unanswered record, and the log holds an answered one in its place.
        a, b, close = crash_logs()
        b[0] = dict(b[0], unanswered="", result_sha256="b" * 64, sha256="e" * 64)
        b[1] = dict(b[1], previous_sha256="e" * 64)
        self.failed(a, b, close, "worker B's log does not start with the record of the call lost before its takeover")

    def test_two_unanswered_records(self) -> None:
        a, b, close = crash_logs()
        b[4] = dict(b[4], unanswered="canceled", result_sha256="")
        self.failed(a, b, close, "1 record(s) state no answer and are not the lost call's: call 15")

    def test_an_unanswered_record_when_no_call_was_lost(self) -> None:
        a, b, close = freeze_logs()
        b[0] = dict(b[0], unanswered="canceled", result_sha256="")
        self.failed(a, b, close, "1 record(s) state no answer and are not the lost call's: call 12")

    def test_a_close_count_off_by_one(self) -> None:
        a, b, close = crash_logs()
        self.failed(a, b, dict(close, calls=25), "the daemon's own count at close (25, last")

    def test_a_close_digest_that_is_not_the_last_record(self) -> None:
        a, b, close = crash_logs()
        self.failed(a, b, dict(close, last_record_sha256=b[-2]["sha256"]), "is not the logs' (24, last")

    def test_a_first_record_that_names_one_before_it(self) -> None:
        a, b, close = crash_logs()
        a[0] = dict(a[0], previous_sha256="d" * 64)
        self.failed(a, b, close, "the first record names a record before it")

    def test_an_empty_log(self) -> None:
        a, b, close = crash_logs()
        self.failed([], a + b, close, "a worker's log is empty")

    def test_the_inputs_are_not_changed(self) -> None:
        a, b, close = crash_logs()
        before = copy.deepcopy((a, b, close))
        crash.check_chain(a, b, close)
        self.assertEqual((a, b, close), before)


if __name__ == "__main__":
    unittest.main()
