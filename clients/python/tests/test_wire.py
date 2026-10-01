"""Connect error answers, their two hand-decoded details, and the JSON reader."""

from __future__ import annotations

import base64
import json
import math
import struct
import unittest

from plimsoll_client import (
    AtCapacityError,
    DisabledError,
    InsufficientIsolationError,
    InvalidRequestError,
    MalformedResponseError,
    PlimsollError,
    ProtocolMismatchError,
    SessionEndedError,
    SoftwareMismatchError,
    UnsupportedError,
)
from plimsoll_client._wire import INT32, INT64, Msg, b64decode, decode_enum_and_string, error_from_wire, loads


def unpadded(b: bytes) -> str:
    # Connect writes detail values as unpadded standard base64.
    return base64.b64encode(b).decode().rstrip("=")


def not_dispatched(reason: int) -> dict:
    return {"type": "plimsoll.v1.NotDispatched", "value": unpadded(bytes([0x08, reason])), "debug": {"reason": reason}}


def session_ended(reason: int, detail: str) -> dict:
    d = detail.encode()
    return {"type": "plimsoll.v1.SessionEnded", "value": unpadded(bytes([0x08, reason, 0x12, len(d)]) + d)}


def answer(code: str, *details: dict, message: str = "refused") -> bytes:
    return json.dumps({"code": code, "message": message, "details": list(details)}).encode()


class Details(unittest.TestCase):
    def test_enum_and_string(self) -> None:
        self.assertEqual(decode_enum_and_string(b""), (0, ""))
        self.assertEqual(decode_enum_and_string(bytes([0x08, 5])), (5, ""))
        self.assertEqual(decode_enum_and_string(bytes([0x08, 3, 0x12, 2]) + b"hi"), (3, "hi"))
        # Unknown fields of every wire type are skipped, as protobuf skips them.
        extra = bytes([0x18, 0x96, 0x01]) + bytes([0x21]) + b"\x00" * 8 + bytes([0x2D]) + b"\x00" * 4 + bytes([0x32, 1]) + b"x"
        self.assertEqual(decode_enum_and_string(extra + bytes([0x08, 2])), (2, ""))
        # A negative enum is a ten-byte varint; it is an int32.
        self.assertEqual(decode_enum_and_string(bytes([0x08] + [0xFF] * 9 + [0x01])), (-1, ""))

    def test_malformed_details_refuse(self) -> None:
        for name, b in {
            "truncated varint": bytes([0x08, 0x80]),
            "overrun": bytes([0x12, 5]) + b"ab",
            "field 1 length-delimited": bytes([0x0A, 1]) + b"x",
            "field 2 varint": bytes([0x10, 1]),
            "field 1 fixed": bytes([0x0D]) + b"\x00" * 4,
            "group": bytes([0x1B]),
            "field 0": bytes([0x00, 1]),
            "not UTF-8": bytes([0x12, 1, 0xFF]),
            "eleven-byte varint": bytes([0x08] + [0xFF] * 10 + [0x01]),
        }.items():
            with self.subTest(name), self.assertRaises((ValueError, UnicodeDecodeError)):
                decode_enum_and_string(b)

    def test_base64_forms(self) -> None:
        for s in ("aGk=", "aGk", "_-8=", "_-8", "/+8="):
            with self.subTest(s):
                b64decode(s)
        self.assertEqual(b64decode("_-8"), b"\xff\xef")
        self.assertEqual(b64decode("/+8"), b"\xff\xef")
        for s in ("a", "a$bc", "ab c"):
            with self.subTest(s), self.assertRaises(ValueError):
                b64decode(s)


class Errors(unittest.TestCase):
    def test_refusals_are_restored_with_their_reason(self) -> None:
        cases = [
            ("invalid_argument", 1, InvalidRequestError, "request"),
            ("unauthenticated", 2, PlimsollError, "permission"),
            ("unimplemented", 3, ProtocolMismatchError, "protocol"),
            ("unimplemented", 4, UnsupportedError, "unsupported"),
            ("failed_precondition", 5, InsufficientIsolationError, "isolation"),
            ("resource_exhausted", 6, AtCapacityError, "capacity"),
            ("failed_precondition", 7, SoftwareMismatchError, "environment"),
            ("failed_precondition", 4, DisabledError, "unsupported"),
            ("failed_precondition", 99, DisabledError, "unknown"),
        ]
        for code, reason, cls, name in cases:
            with self.subTest(code=code, reason=reason):
                e = error_from_wire(400, answer(code, not_dispatched(reason)))
                self.assertIs(type(e), cls)
                self.assertEqual(e.code, code)
                self.assertEqual(e.not_dispatched, name)
                self.assertEqual(e.http_status, 400)

    def test_an_unmarked_error_never_claims_nothing_ran(self) -> None:
        for body in (
            answer("internal"),
            answer("unimplemented"),
            answer("failed_precondition", {"type": "plimsoll.v1.NotDispatched", "value": "!!"}),
            answer("failed_precondition", {"type": "plimsoll.v1.NotDispatched", "value": unpadded(bytes([0x0A, 0]))}),
            answer("invalid_argument", {"type": "plimsoll.v1.Other", "value": unpadded(bytes([0x08, 1]))}),
            b"not json",
            b"",
        ):
            with self.subTest(body=body):
                self.assertIsNone(error_from_wire(500, body).not_dispatched)

    def test_session_end(self) -> None:
        e = error_from_wire(400, answer("failed_precondition", not_dispatched(1), session_ended(3, "over budget")))
        self.assertIsInstance(e, SessionEndedError)
        assert isinstance(e, SessionEndedError)
        self.assertEqual((e.reason, e.detail, e.not_dispatched), ("disk_exceeded", "over budget", "request"))
        # Other codes keep their own class, as the Go client's switch does.
        self.assertIs(type(error_from_wire(400, answer("invalid_argument", session_ended(2, "")))), InvalidRequestError)
        self.assertIsInstance(error_from_wire(404, answer("not_found", session_ended(2, ""))), SessionEndedError)
        self.assertIs(type(error_from_wire(499, answer("canceled", session_ended(2, "")))), PlimsollError)

    def test_type_url_prefix_is_accepted(self) -> None:
        d = not_dispatched(6)
        d["type"] = "type.googleapis.com/" + d["type"]
        self.assertEqual(error_from_wire(429, answer("resource_exhausted", d)).not_dispatched, "capacity")

    def test_http_status_without_a_connect_body(self) -> None:
        for status, code in ((400, "internal"), (401, "unauthenticated"), (403, "permission_denied"), (404, "unimplemented"),
                             (429, "unavailable"), (503, "unavailable"), (500, "unknown"), (302, "unknown")):
            with self.subTest(status):
                self.assertEqual(error_from_wire(status, b"<html>").code, code)
        self.assertEqual(error_from_wire(500, answer("no_such_code")).code, "unknown")


class Reader(unittest.TestCase):
    def test_negative_zero_survives_parsing(self) -> None:
        v = loads(b'{"outputs":[-0,0,1e+21,-1.5,"NaN","Infinity"]}')
        out = Msg(v, "m").get_floats("outputs")
        self.assertEqual(struct.pack(">d", out[0]), struct.pack(">d", -0.0))
        self.assertEqual(struct.pack(">d", out[1]), struct.pack(">d", 0.0))
        self.assertEqual(out[2], 1e21)
        self.assertTrue(math.isnan(out[4]) and math.isinf(out[5]))

    def test_strict_json(self) -> None:
        for bad in (b'{"a":1,"a":2}', b'{"a":NaN}', b"\xff"):
            with self.subTest(bad), self.assertRaises(ValueError):
                loads(bad)

    def test_types_are_checked(self) -> None:
        m = Msg({"n": "12", "big": "9223372036854775807", "f": 1.0, "b": True, "s": 5, "neg0": -0.0}, "m")
        self.assertEqual(m.get_int("n", INT32), 12)
        self.assertEqual(m.get_int("big", INT64), (1 << 63) - 1)
        self.assertEqual(m.get_int("f", INT32), 1)
        self.assertEqual(m.get_int("neg0", INT32), 0)
        self.assertEqual(m.get_int("absent", INT32), 0)
        for name, f in {
            "out of range": lambda: m.get_int("big", INT32),
            "bool as int": lambda: m.get_int("b", INT32),
            "int as str": lambda: m.get_str("s"),
            "int as bool": lambda: m.get_bool("s"),
            "not base64": lambda: Msg({"x": "%%"}, "m").get_bytes("x"),
            "unknown enum": lambda: Msg({"x": "PROJECT_OUTCOME_NEW"}, "m").get_enum("x", {}),
            "not an object": lambda: Msg([], "m"),
        }.items():
            with self.subTest(name), self.assertRaises(MalformedResponseError):
                f()


if __name__ == "__main__":
    unittest.main()
