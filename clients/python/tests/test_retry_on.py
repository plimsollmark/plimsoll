"""retry_on, the predicate a framework's automatic retry takes (LangGraph's RetryPolicy,
LangChain's ToolRetryMiddleware): yes only to a refusal marked capacity or environment,
no to everything else. The frameworks' own retry paths are exercised in
frameworks/deepagents/test_retry.py; here, every reason, every error class, the shared
wire answers and a real refused connect."""

from __future__ import annotations

import inspect
import json
import pathlib
import socket
import unittest

import plimsoll_client.errors as errors
from plimsoll_client import (
    RETRY_REASONS,
    AtCapacityError,
    Client,
    InvalidRequestError,
    PlimsollError,
    RequestCanceledError,
    SessionEndedError,
    TransportError,
    retry_on,
)
from plimsoll_client._tables import REFUSAL_NAMES
from plimsoll_client._wire import error_from_wire

ANSWERS = json.loads((pathlib.Path(__file__).resolve().parents[3] / "protocol" / "testdata" / "answers.json").read_text())


def every_error_class():
    for name in errors.__all__:
        obj = getattr(errors, name)
        if inspect.isclass(obj) and issubclass(obj, PlimsollError):
            yield obj


def make(cls, **kwargs):
    extra = {"reason": "closed"} if issubclass(cls, SessionEndedError) else {}
    return cls("plimsoll: a test error", **extra, **kwargs)


class RetryOn(unittest.TestCase):
    def test_the_reasons_are_capacity_and_environment(self) -> None:
        self.assertEqual(RETRY_REASONS, frozenset({"capacity", "environment"}))
        self.assertTrue(RETRY_REASONS <= set(REFUSAL_NAMES))

    def test_each_reason(self) -> None:
        for reason in REFUSAL_NAMES:
            with self.subTest(reason):
                self.assertIs(retry_on(PlimsollError("x", not_dispatched=reason)), reason in ("capacity", "environment"))

    def test_no_unmarked_error_of_any_class_is_retried(self) -> None:
        classes = list(every_error_class())
        self.assertGreater(len(classes), 20)
        for cls in classes:
            with self.subTest(cls.__name__):
                self.assertIs(retry_on(make(cls)), False)

    def test_a_retryable_mark_is_retried_whatever_the_class(self) -> None:
        # The mark is the one statement that nothing ran; the class only says why.
        for cls in every_error_class():
            with self.subTest(cls.__name__):
                self.assertIs(retry_on(make(cls, not_dispatched="capacity")), True)

    def test_only_plimsolls_errors_are_retried(self) -> None:
        class Lookalike(Exception):
            not_dispatched = "capacity"

        for exc in (Lookalike(), ConnectionError(), TimeoutError(), OSError(), RuntimeError(), ValueError(), Exception()):
            with self.subTest(type(exc).__name__):
                self.assertIs(retry_on(exc), False)

    def test_a_mark_that_is_not_a_reason_is_not_retried(self) -> None:
        e = PlimsollError("x")
        e.not_dispatched = ["capacity"]  # type: ignore[assignment]
        self.assertIs(retry_on(e), False)

    def test_the_clients_own_marks(self) -> None:
        self.assertIs(retry_on(AtCapacityError("busy", not_dispatched="capacity")), True)
        # Cancelled before sending, and a session that has ended: nothing ran, and the
        # same call cannot pass.
        self.assertIs(retry_on(RequestCanceledError("canceled", not_dispatched="request")), False)
        self.assertIs(retry_on(SessionEndedError("ended", reason="expired", not_dispatched="request")), False)
        self.assertIs(retry_on(InvalidRequestError("bad", not_dispatched="request")), False)

    def test_every_shared_answer(self) -> None:
        # The daemon answers all three clients read (protocol/testdata/answers.json): a
        # mark counts only on an answer bound to the request, so an unbound capacity
        # refusal is not retried.
        seen = set()
        for a in ANSWERS["answers"]:
            with self.subTest(a["name"]):
                e = error_from_wire(a["status"], a["body"].encode(), bound=a["echo"] == "match", mark=a.get("mark") or None)
                want = a["expect"]["notDispatched"] in ("capacity", "environment")
                self.assertIs(retry_on(e), want)
                seen.add(want)
        self.assertEqual(seen, {True, False}, "the shared answers hold a retryable refusal and others")

    def test_a_refused_connect_is_retried(self) -> None:
        # Nothing listens on the port, so nothing can have been sent: TransportError,
        # marked environment.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(TransportError) as cm:
            Client(f"http://127.0.0.1:{port}").describe()
        self.assertEqual(cm.exception.not_dispatched, "environment")
        self.assertIs(retry_on(cm.exception), True)


if __name__ == "__main__":
    unittest.main()
