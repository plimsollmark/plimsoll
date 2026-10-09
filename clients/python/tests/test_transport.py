"""The HTTP exchange, against a local stub server: what is sent, and every way an
answer can fail to be a Connect answer."""

from __future__ import annotations

import asyncio
import http.client
import io
import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import patch

from plimsoll_client._transport import _read_capped

from plimsoll_client import (
    MAX_RESPONSE_BYTES,
    PROTOCOL,
    AnswerNotBoundError,
    AsyncClient,
    Client,
    MalformedResponseError,
    PlimsollError,
    ProtocolMismatchError,
    RequestTimeoutError,
    ResponseTooLargeError,
    TransportError,
)
from plimsoll_client._record import session_fingerprint

Reply = Callable[[BaseHTTPRequestHandler], None]


class Stub:
    """A loopback HTTP server whose answer each test sets. Like the daemon, it echoes
    the request's Plimsoll-Request-Id on every answer, unless ``echo`` is false."""

    def __init__(self) -> None:
        self.reply: Reply = lambda h: None
        self.seen: List[Dict[str, Any]] = []
        self.echo = True
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                stub.seen.append({"path": self.path, "headers": dict(self.headers), "body": self.rfile.read(n)})
                stub.reply(self)

            def send_response(self, code: int, message: Optional[str] = None) -> None:
                super().send_response(code, message)
                rid = self.headers.get("Plimsoll-Request-Id")
                if stub.echo and rid:
                    self.send_header("Plimsoll-Request-Id", rid)

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def send(h: BaseHTTPRequestHandler, status: int, body: bytes, ctype: str = "application/json", length: Optional[int] = None) -> None:
    h.send_response(status)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(body) if length is None else length))
    h.end_headers()
    try:
        h.wfile.write(body)
    except OSError:
        pass


def describe_answer(protocol: int = PROTOCOL) -> bytes:
    return json.dumps({"sandbox": "stub", "isolation": "process", "protocol": protocol}).encode()


class CappedRead(unittest.TestCase):
    @staticmethod
    def read(headers: bytes, body: bytes) -> tuple[bytes, bool]:
        class BufferedSocket:
            def makefile(self, mode: str) -> io.BytesIO:
                return io.BytesIO(b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n\r\n" + body)

        # The real stdlib parser over fixed bytes: no server, sleeps, or cancel race.
        with http.client.HTTPResponse(BufferedSocket()) as resp:  # type: ignore[arg-type]
            resp.begin()
            conn = http.client.HTTPConnection("unused")
            with patch("plimsoll_client._transport.time.monotonic", return_value=0):
                return _read_capped(conn, resp, 1)

    def test_a_cleanly_ended_chunked_answer_is_complete(self) -> None:
        self.assertEqual(self.read(b"Transfer-Encoding: chunked", b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"), (b"abcde", True))
        self.assertEqual(self.read(b"Transfer-Encoding: Chunked", b"0\r\n\r\n"), (b"", True))

    def test_an_answer_cut_inside_a_chunk_raises_incomplete_read(self) -> None:
        with self.assertRaises(http.client.IncompleteRead):
            self.read(b"Transfer-Encoding: chunked", b"5\r\nabc")

    def test_an_answer_missing_its_final_chunk_raises_incomplete_read(self) -> None:
        with self.assertRaises(http.client.IncompleteRead):
            self.read(b"Transfer-Encoding: chunked", b"3\r\nabc\r\n")

    def test_content_length_completeness_is_unchanged(self) -> None:
        self.assertEqual(self.read(b"Content-Length: 5", b"abcde"), (b"abcde", True))
        self.assertEqual(self.read(b"Content-Length: 6", b"abcde"), (b"abcde", False))
        self.assertEqual(self.read(b"Content-Length: 0", b""), (b"", True))

    def test_a_close_delimited_answer_is_not_known_complete(self) -> None:
        self.assertEqual(self.read(b"Connection: close", b"abcde"), (b"abcde", False))


class Transport(unittest.TestCase):
    def setUp(self) -> None:
        self.stub = Stub()
        self.addCleanup(self.stub.close)

    def test_what_is_sent(self) -> None:
        self.stub.reply = lambda h: send(h, 200, describe_answer())
        info = Client(self.stub.url + "/base/", token="tok").describe()
        self.assertEqual((info.provider, info.isolation, info.protocol), ("stub", "process", PROTOCOL))
        seen = self.stub.seen[0]
        self.assertEqual(seen["path"], "/base/plimsoll.v1.SandboxService/Describe")
        self.assertEqual(seen["headers"]["Content-Type"], "application/json")
        self.assertEqual(seen["headers"]["Connect-Protocol-Version"], "1")
        self.assertEqual(seen["headers"]["Authorization"], "Bearer tok")
        self.assertEqual(json.loads(seen["body"]), {})

    def test_every_request_carries_a_fresh_id(self) -> None:
        self.stub.reply = lambda h: send(h, 200, describe_answer())
        c = Client(self.stub.url)
        for _ in range(3):
            c.describe()
        ids = [seen["headers"]["Plimsoll-Request-Id"] for seen in self.stub.seen]
        self.assertEqual(len(set(ids)), 3)
        for rid in ids:
            self.assertRegex(rid, r"\A[0-9a-f]{32}\Z")

    def test_an_answer_without_the_echo_is_refused(self) -> None:
        self.stub.echo = False
        self.stub.reply = lambda h: send(h, 200, describe_answer())
        with self.assertRaises(AnswerNotBoundError) as cm:
            Client(self.stub.url).describe()
        self.assertEqual((cm.exception.code, cm.exception.not_dispatched), ("data_loss", None))

    def test_no_token_sends_no_authorization(self) -> None:
        self.stub.reply = lambda h: send(h, 200, describe_answer())
        Client(self.stub.url).describe()
        self.assertNotIn("Authorization", self.stub.seen[0]["headers"])

    def test_every_request_states_the_protocol(self) -> None:
        self.stub.reply = lambda h: send(h, 500, b"{}")
        c = Client(self.stub.url)
        for call in (
            lambda: c.run_javascript("1"),
            lambda: c.run_project({"a": "1"}, ["true"]),
            lambda: c.run_module("m", [[1]], end_time=1, step=0.1),
            lambda: c.open_session(),
        ):
            with self.assertRaises(PlimsollError):
                call()
        self.assertEqual([json.loads(s["body"])["protocol"] for s in self.stub.seen], [PROTOCOL] * 4)

    def test_describe_compares_the_protocol(self) -> None:
        self.stub.reply = lambda h: send(h, 200, describe_answer(PROTOCOL + 1))
        with self.assertRaises(ProtocolMismatchError) as cm:
            Client(self.stub.url).describe()
        self.assertEqual(cm.exception.info.protocol, PROTOCOL + 1)

    def test_a_declared_oversized_answer_is_refused_unread(self) -> None:
        self.stub.reply = lambda h: send(h, 200, b"{}", length=MAX_RESPONSE_BYTES + 1)
        with self.assertRaises(ResponseTooLargeError) as cm:
            Client(self.stub.url).describe()
        self.assertIsNone(cm.exception.not_dispatched)

    def test_an_oversized_stream_is_cut_off(self) -> None:
        def reply(h: BaseHTTPRequestHandler) -> None:
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.end_headers()  # no length: the body runs until the connection closes
            h.close_connection = True
            chunk = b" " * (1 << 20)
            try:
                for _ in range(MAX_RESPONSE_BYTES // len(chunk) + 2):
                    h.wfile.write(chunk)
            except OSError:
                pass

        self.stub.reply = reply
        with self.assertRaises(ResponseTooLargeError):
            Client(self.stub.url).describe()

    def test_a_redirect_is_not_followed(self) -> None:
        def reply(h: BaseHTTPRequestHandler) -> None:
            if h.path.startswith("/elsewhere"):
                send(h, 200, describe_answer())
                return
            h.send_response(307)
            h.send_header("Location", "/elsewhere")
            h.send_header("Content-Length", "0")
            h.end_headers()

        self.stub.reply = reply
        with self.assertRaises(PlimsollError) as cm:
            Client(self.stub.url, token="tok").describe()
        self.assertEqual((cm.exception.code, cm.exception.http_status), ("unknown", 307))
        self.assertEqual(len(self.stub.seen), 1)

    def test_answers_that_are_not_connect_answers(self) -> None:
        for name, reply in {
            "html": lambda h: send(h, 200, b"<html></html>", ctype="text/html"),
            "not json": lambda h: send(h, 200, b"{not json"),
            "not an object": lambda h: send(h, 200, b"[1]"),
            "wrong field type": lambda h: send(h, 200, b'{"protocol":"two"}'),
        }.items():
            with self.subTest(name):
                self.stub.reply = reply
                with self.assertRaises(MalformedResponseError) as cm:
                    Client(self.stub.url).describe()
                self.assertIsNone(cm.exception.not_dispatched)

    def test_timeout(self) -> None:
        def slow(h: BaseHTTPRequestHandler) -> None:
            time.sleep(1.5)
            send(h, 200, describe_answer())

        self.stub.reply = slow
        start = time.monotonic()
        with self.assertRaises(RequestTimeoutError) as cm:
            Client(self.stub.url, request_timeout=0.3).describe()
        self.assertLess(time.monotonic() - start, 1.4)
        self.assertEqual(cm.exception.code, "deadline_exceeded")
        self.assertIsNone(cm.exception.not_dispatched)

    def test_a_trickled_answer_is_bounded_by_the_whole_timeout(self) -> None:
        body = describe_answer()

        def trickle(h: BaseHTTPRequestHandler) -> None:
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.send_header("Content-Length", str(len(body)))
            h.end_headers()
            try:
                for b in body:
                    h.wfile.write(bytes([b]))
                    h.wfile.flush()
                    time.sleep(0.1)
            except OSError:
                pass

        def trickle_headers(h: BaseHTTPRequestHandler) -> None:
            head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Padding: " + b"x" * 60
            try:
                for b in head:
                    h.wfile.write(bytes([b]))
                    h.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass

        for name, reply in (("body", trickle), ("headers", trickle_headers)):
            with self.subTest(name):
                self.stub.reply = reply
                start = time.monotonic()
                with self.assertRaises(RequestTimeoutError):
                    Client(self.stub.url, request_timeout=0.5).describe()
                self.assertLess(time.monotonic() - start, 1.5)

    def test_connection_refused(self) -> None:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(TransportError) as cm:
            Client(f"http://127.0.0.1:{port}").describe()
        self.assertEqual(cm.exception.not_dispatched, "environment")  # refused before any byte of the request left

    def test_async_client(self) -> None:
        self.stub.reply = lambda h: send(h, 200, describe_answer())
        info = asyncio.run(AsyncClient(self.stub.url).describe())
        self.assertEqual(info.provider, "stub")

    def sessions(self, open_delay: float) -> threading.Event:
        """Answers OpenSession after open_delay with one session, and CloseSession
        for it; the event is set when the session is closed."""
        sid = "ab" * 16
        closed = threading.Event()

        def reply(h: BaseHTTPRequestHandler) -> None:
            if h.path.endswith("/OpenSession"):
                time.sleep(open_delay)
                body = {"sessionId": sid, "session": session_fingerprint(sid), "sandbox": "stub", "isolation": "container"}
                send(h, 200, json.dumps(body).encode())
            elif h.path.endswith("/CloseSession"):
                if json.loads(self.stub.seen[-1]["body"]).get("sessionId") == sid:
                    closed.set()
                send(h, 200, json.dumps({"session": session_fingerprint(sid), "ended": "SESSION_END_CLOSED"}).encode())

        self.stub.reply = reply
        return closed

    def test_a_session_opened_after_its_await_was_cancelled_is_closed(self) -> None:
        # The daemon answers after the cancel: nobody waits for the session.
        closed = self.sessions(open_delay=0.3)

        async def main() -> None:
            t = asyncio.create_task(AsyncClient(self.stub.url).open_session())
            await asyncio.sleep(0.1)
            t.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await t

        asyncio.run(main())
        self.assertTrue(closed.wait(5), "the abandoned session was never closed")

    def test_a_session_handed_over_as_the_cancel_came_is_closed(self) -> None:
        # The open finishes in its thread while the event loop is busy, so the
        # cancel lands before the task can take the session.
        closed = self.sessions(open_delay=0)

        async def main() -> None:
            t = asyncio.create_task(AsyncClient(self.stub.url).open_session())
            await asyncio.sleep(0)
            deadline = time.monotonic() + 5
            while not any(s["path"].endswith("/OpenSession") for s in self.stub.seen) and time.monotonic() < deadline:
                time.sleep(0.01)  # blocks the loop on purpose
            time.sleep(0.3)
            t.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await t

        asyncio.run(main())
        self.assertTrue(closed.wait(5), "the session handed over as the cancel came was never closed")


if __name__ == "__main__":
    unittest.main()
