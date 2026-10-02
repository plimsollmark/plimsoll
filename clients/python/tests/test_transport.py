"""The HTTP exchange, against a local stub server: what is sent, and every way an
answer can fail to be a Connect answer."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional

from plimsoll_client import (
    MAX_RESPONSE_BYTES,
    PROTOCOL,
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
    """A loopback HTTP server whose answer each test sets."""

    def __init__(self) -> None:
        self.reply: Reply = lambda h: None
        self.seen: List[Dict[str, Any]] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                stub.seen.append({"path": self.path, "headers": dict(self.headers), "body": self.rfile.read(n)})
                stub.reply(self)

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
        self.assertIsNone(cm.exception.not_dispatched)

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
