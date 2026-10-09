"""Answers bound to their request (failure-injection review, findings 1 and 3).

The daemons are client_test.go's bindingDaemons: replaying proxies that forward each
request (so the daemon runs it) and answer it with the first request's answer, a
daemon that does not echo the request ID, one that refuses a body before the
handler, and one that serves no procedure.
"""

from __future__ import annotations

import unittest
import urllib.request

from plimsoll_client import (
    AnswerNotBoundError,
    AtCapacityError,
    Client,
    DataLossError,
    InsufficientIsolationError,
    PlimsollError,
    UnsupportedError,
)

from ._env import setting


def runs() -> int:
    with urllib.request.urlopen(setting("PLIMSOLL_REPLAY_RUNS_URL"), timeout=10) as r:
        return int(r.read())


class Binding(unittest.TestCase):
    def test_a_replayed_refusal_is_not_believed(self) -> None:
        c = Client(setting("PLIMSOLL_REPLAY_REFUSAL_URL"))
        with self.assertRaises(InsufficientIsolationError) as cm:
            c.run_javascript("1", minimum_isolation="vm")
        self.assertEqual(cm.exception.not_dispatched, "isolation")
        before = runs()
        with self.assertRaises(PlimsollError) as cm:
            c.run_javascript("console.log(42)")
        self.assertEqual(runs(), before + 1, "the daemon ran the call it was given another answer for")
        e = cm.exception
        self.assertIsNone(e.not_dispatched, "a replayed refusal reads as nothing ran for a call that ran")
        self.assertTrue(e.answer_not_bound)
        self.assertEqual(e.code, "failed_precondition")

    def test_a_replayed_success_is_data_loss(self) -> None:
        c = Client(setting("PLIMSOLL_REPLAY_SUCCESS_URL"))
        self.assertEqual(c.run_javascript("console.log(42)").stdout, b"42\n")
        before = runs()
        with self.assertRaises(AnswerNotBoundError) as cm:
            c.run_javascript("console.log(42)")
        self.assertEqual(runs(), before + 1)
        self.assertIsInstance(cm.exception, DataLossError)
        self.assertEqual((cm.exception.code, cm.exception.not_dispatched), ("data_loss", None))

    def test_a_daemon_without_the_echo_is_believed_in_nothing(self) -> None:
        c = Client(setting("PLIMSOLL_UNBOUND_URL"))
        with self.assertRaises(AnswerNotBoundError):
            c.describe()
        with self.assertRaises(PlimsollError) as cm:
            c.run_javascript("1", minimum_isolation="vm")
        self.assertIsNone(cm.exception.not_dispatched)
        self.assertTrue(cm.exception.answer_not_bound)

    def test_a_body_refused_before_the_handler_is_marked(self) -> None:
        with self.assertRaises(AtCapacityError) as cm:
            Client(setting("PLIMSOLL_EARLY_REFUSAL_URL")).run_javascript("console.log('" + "x" * 1024 + "')")
        self.assertEqual((cm.exception.code, cm.exception.not_dispatched), ("resource_exhausted", "request"))
        self.assertFalse(cm.exception.answer_not_bound)

    def test_a_procedure_the_daemon_lacks_is_marked_unsupported(self) -> None:
        with self.assertRaises(UnsupportedError) as cm:
            Client(setting("PLIMSOLL_NO_PROCEDURE_URL")).describe()
        self.assertEqual((cm.exception.code, cm.exception.not_dispatched), ("unimplemented", "unsupported"))
