"""Checks made before anything is sent: the base URL and the request itself."""

from __future__ import annotations

import unittest

from plimsoll_client import Client, InsecureHTTPError, InvalidBaseURLError, InvalidRequestError, SoftwareRule
from plimsoll_client import _validate as v


class BaseURL(unittest.TestCase):
    # The cases of TestNewValidatesBaseURLAndFailsClosedOnRemoteHTTP, client/client_test.go.
    def test_valid(self) -> None:
        for raw in (
            "https://plimsoll.example",
            "https://plimsoll.example/grpc",
            "http://localhost:8746",
            "http://LOCALHOST:8746",
            "http://127.0.0.1:8746",
            "http://127.9.9.9:8746",
            "http://[::1]:8746",
        ):
            with self.subTest(raw):
                Client(raw)

    def test_invalid(self) -> None:
        for raw in (
            "",
            " https://plimsoll.example",
            "plimsoll.example",
            "//plimsoll.example",
            "ftp://plimsoll.example",
            "http://",
            "https://user@plimsoll.example",
            "https://user:pw@plimsoll.example",
            "https://plimsoll.example/path?debug=1",
            "https://plimsoll.example/?",
            "https://plimsoll.example/#fragment",
            "https://plimsoll.example:notaport",
            "https://[::1",
            "https://plimsoll.example/a b",
        ):
            with self.subTest(raw), self.assertRaises(InvalidBaseURLError):
                Client(raw)

    def test_cleartext_off_loopback_needs_the_opt_in(self) -> None:
        with self.assertRaises(InsecureHTTPError):
            Client("http://plimsoll.internal:8746")
        with self.assertRaises(InsecureHTTPError):
            Client("http://localhost.example:8746")
        Client("http://plimsoll.internal:8746", insecure_http=True)
        with self.assertRaises(InvalidBaseURLError):
            Client("ftp://plimsoll.internal", insecure_http=True)

    def test_normal_form(self) -> None:
        self.assertEqual(Client("HTTPS://plimsoll.example/base/").base_url, "https://plimsoll.example/base")

    def test_token_and_timeout(self) -> None:
        with self.assertRaises(ValueError):
            Client("http://127.0.0.1:1", token="a\r\nX-Injected: 1")
        with self.assertRaises(ValueError):
            Client("http://127.0.0.1:1", request_timeout=0)
        self.assertNotIn("secret", repr(Client("http://127.0.0.1:1", token="secret")))


class Requests(unittest.TestCase):
    def refused(self, f) -> None:
        with self.assertRaises(InvalidRequestError) as cm:
            f()
        self.assertEqual(cm.exception.not_dispatched, "request")
        self.assertEqual(cm.exception.code, "invalid_argument")

    def test_code(self) -> None:
        v.code("console.log(1)")
        self.refused(lambda: v.code(""))
        self.refused(lambda: v.code("a\x00b"))
        self.refused(lambda: v.code("\udcff"))  # a lone surrogate is not UTF-8
        self.refused(lambda: v.code("x" * (v.MAX_CODE_BYTES + 1)))
        self.refused(lambda: v.code(b"bytes"))

    def test_floor_trace_and_timeout(self) -> None:
        self.assertEqual(v.floor(None), "")
        self.assertEqual(v.floor("kernel"), "kernel")
        self.refused(lambda: v.floor("none"))
        self.refused(lambda: v.floor("Kernel"))
        self.assertEqual(v.trace_id("run-1:a.b_c"), "run-1:a.b_c")
        self.refused(lambda: v.trace_id("has space"))
        self.refused(lambda: v.trace_id("x" * 65))
        self.refused(lambda: v.trace_id("/path/like"))
        self.assertEqual(v.timeout_ms(None), 0)
        self.assertEqual(v.timeout_ms(-1), 0)
        self.assertEqual(v.timeout_ms(0.0001), 1)
        self.assertEqual(v.timeout_ms(4.35), 4350)
        self.assertEqual(v.timeout_ms(1e12), (1 << 31) - 1)
        self.assertEqual(v.timeout_ms(float("inf")), (1 << 31) - 1)
        self.refused(lambda: v.timeout_ms(float("nan")))
        self.assertEqual(v.duration_ms(1e12, "lifetime"), (1 << 32) - 1)

    def test_project(self) -> None:
        p = v.project({"main.py": "print(1)", "lib/util.py": ""}, ["python3 main.py"], ["out.txt"])
        self.assertEqual(p["files"][0], {"path": "main.py", "content": "print(1)"})
        self.assertEqual(v.project([("b", "1"), ("a", "2")], ["true"], [])["files"][0]["path"], "b")
        self.assertNotIn("files", v.project(None, ["true"], []))
        for bad in ("/abs", "../up", "a/../b", "a//b", "a/", ".", "a/./b", "back\\slash", "ctl\x07", "c1\x85", ""):
            with self.subTest(path=bad):
                self.refused(lambda: v.project({bad: ""}, ["true"], []))
                self.refused(lambda: v.project(None, ["true"], [bad]))
        self.refused(lambda: v.project(None, [], []))
        self.refused(lambda: v.project(None, "python3 main.py", []))
        self.refused(lambda: v.project(None, ["true"] * (v.MAX_PROJECT_STEPS + 1), []))
        self.refused(lambda: v.project(None, ["a\x00"], []))
        self.refused(lambda: v.project([("a", "1"), ("a", "2")], ["true"], []))
        self.refused(lambda: v.project({"a": b"bytes"}, ["true"], []))
        self.refused(lambda: v.project({"a": "x" * v.MAX_PROJECT_BYTES, "b": "y"}, ["true"], []))
        self.refused(lambda: v.project(None, ["true"], ["a", "a"]))

    def test_module(self) -> None:
        m = v.module("VanDerPol", [[1, 2], [0.5, -3]], 1, 0.1)
        self.assertEqual(m["rows"][0]["values"], [1.0, 2.0])
        for name, args in {
            "model": ("../x", [[1]], 1, 0.1),
            "model newline": ("m\n", [[1]], 1, 0.1),
            "no rows": ("m", [], 1, 0.1),
            "ragged": ("m", [[1, 2], [1]], 1, 0.1),
            "empty row": ("m", [[]], 1, 0.1),
            "not finite": ("m", [[float("nan")]], 1, 0.1),
            "huge int": ("m", [[10**400]], 1, 0.1),
            "bool": ("m", [[True]], 1, 0.1),
            "end time": ("m", [[1]], 0, 0.1),
            "step": ("m", [[1]], 1, float("inf")),
            "too many steps": ("m", [[1]], 1e7, 1),
            "over the result budget": ("m", [[1]] * 2000, 1000, 1),
        }.items():
            with self.subTest(name):
                self.refused(lambda: v.module(*args))

    def test_software_rules(self) -> None:
        a = "oci-manifest:linux/amd64@sha256:" + "a" * 64
        b = "oci-manifest:linux/amd64@sha256:" + "b" * 64
        v.software_rule(SoftwareRule.exact(a))
        for bad in (
            SoftwareRule("exact", (a, b)),
            SoftwareRule.approved(),
            SoftwareRule.approved(*[f"id{i}" for i in range(33)]),
            SoftwareRule.approved(a, a),
            SoftwareRule.exact("has space"),
            SoftwareRule.exact("x" * 257),
            SoftwareRule("pinned", (a,)),  # type: ignore[arg-type]
        ):
            with self.subTest(bad):
                self.refused(lambda: v.software_rule(bad))
        self.assertEqual(v.merge_rules(None, SoftwareRule.exact(a)), SoftwareRule.exact(a))
        self.assertEqual(v.merge_rules(SoftwareRule.approved(a, b), SoftwareRule.approved(b)), SoftwareRule.exact(b))
        self.refused(lambda: v.merge_rules(SoftwareRule.exact(a), SoftwareRule.exact(b)))


if __name__ == "__main__":
    unittest.main()


class LanguageHint(unittest.TestCase):
    def test_kept_in_order_without_repeats(self) -> None:
        self.assertEqual(v.languages(None), [])
        self.assertEqual(v.languages(["python", "javascript", "python"]), ["python", "javascript"])

    def test_refused(self) -> None:
        for bad in ("python", ["cobol"], [1], {"python": 1}):
            with self.subTest(bad), self.assertRaises(InvalidRequestError):
                v.languages(bad)
