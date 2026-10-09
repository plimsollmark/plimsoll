"""The v0.15.0 review's client findings (L20, L23, L24), each as the case that
failed before the fix: errors that escaped as something other than a PlimsollError,
a session that went on after a call it could not follow, and a strict decoder."""

from __future__ import annotations

import base64
import json
import unittest
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Optional

from plimsoll_client import (
    Client,
    InvalidBaseURLError,
    InvalidOptionError,
    MalformedResponseError,
    PlimsollError,
    Session,
)
from plimsoll_client._record import session_fingerprint
from plimsoll_client._wire import Msg, decode_unanswered, parse_response

from .test_transport import Stub, send

SESSION_ID = "00112233445566778899aabbccddeeff"


def _open_answer() -> Msg:
    return Msg({"sessionId": SESSION_ID, "session": session_fingerprint(SESSION_ID), "sandbox": "s", "isolation": "container"}, "r")


class _RaisingTransport:
    """A transport whose SessionRun ends however the test says."""

    def __init__(self, fail: Any) -> None:
        self.fail = fail
        self.calls = 0

    def call(self, method: str, body: Dict[str, Any], path: str, cancel: Any = None) -> Msg:
        self.calls += 1
        if isinstance(self.fail, BaseException):
            raise self.fail
        return Msg(self.fail, path)


class Options(unittest.TestCase):
    def test_an_unusable_token_or_timeout_is_a_plimsoll_error(self) -> None:
        secret = "é" + "x" * 40
        with self.assertRaises(InvalidOptionError) as cm:
            Client("http://127.0.0.1:1", secret)
        self.assertNotIn(secret, str(cm.exception))
        with self.assertRaises(InvalidOptionError):
            Client("http://127.0.0.1:1", request_timeout=float("inf"))

    def test_a_base_url_that_is_not_ascii_is_refused(self) -> None:
        with self.assertRaises(InvalidBaseURLError):
            Client("http://127.0.0.1:1/plimsollé")


class Answers(unittest.TestCase):
    def test_deep_nesting_and_lone_surrogates_are_malformed_answers(self) -> None:
        with self.assertRaises(MalformedResponseError):
            parse_response(b"[" * 200000 + b"]" * 200000, "r")
        m = parse_response(b'{"sandbox": "\\ud800"}', "r")
        with self.assertRaises(MalformedResponseError):
            m.get_str("sandbox")

    def test_a_content_length_of_other_digits_is_not_read_as_a_number(self) -> None:
        stub = Stub()
        self.addCleanup(stub.close)

        def reply(h: BaseHTTPRequestHandler) -> None:
            body = json.dumps({"sandbox": "s", "isolation": "process", "protocol": 1}).encode()
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.send_header("Content-Length", "²")
            h.end_headers()
            h.wfile.write(body)

        stub.reply = reply
        with self.assertRaises(PlimsollError):
            Client(stub.url).describe()

    def test_unknown_fields_of_any_wire_type_are_skipped(self) -> None:
        record = b"\x08\x03"  # version 3
        detail = b"\x10\x05" + b"\x0a" + bytes([len(record)]) + record + b"\x1d\x00\x00\x00\x00"
        self.assertEqual(decode_unanswered(detail), {"version": 3})


class SessionStops(unittest.TestCase):
    def _session(self, fail: Any) -> "tuple[Session, _RaisingTransport]":
        t = _RaisingTransport(fail)
        return Session(t, SESSION_ID, _open_answer(), None), t  # type: ignore[arg-type]

    def test_an_interrupt_stops_the_session(self) -> None:
        s, t = self._session(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            s.run_javascript("1")
        with self.assertRaises(PlimsollError) as cm:
            s.run_javascript("2")
        self.assertEqual((cm.exception.not_dispatched, t.calls), ("request", 1))

    def test_an_unreadable_answer_stops_the_session(self) -> None:
        s, t = self._session({"run": {}, "ended": "SESSION_END_FROM_A_NEWER_DAEMON"})
        with self.assertRaises(PlimsollError):
            s.run_javascript("1")
        with self.assertRaises(PlimsollError) as cm:
            s.run_javascript("2")
        self.assertEqual((cm.exception.not_dispatched, t.calls), ("request", 1))

    def test_the_body_exception_is_not_masked_by_the_close(self) -> None:
        s, _ = self._session(KeyboardInterrupt())

        def close() -> None:
            raise PlimsollError("the close failed")

        s.close = close  # type: ignore[method-assign]
        with self.assertRaises(ValueError):
            with s:
                raise ValueError("the body's own error")


if __name__ == "__main__":
    unittest.main()
