"""CancelHandle against loopback servers: a request it stops before sending is marked
not dispatched and never arrives; one it cuts in flight (connecting, in the TLS
handshake, waiting for the answer) returns at once, marked only when no byte of the
request can have left; and the asyncio face cancels the request with the await.

The framework suites (frameworks/agno, frameworks/crewai) prove the same through each
framework's own async tool path against the real RPC handler."""

from __future__ import annotations

import asyncio
import base64
import json
import select
import socket
import threading
import time
import unittest
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from plimsoll_client import (
    AsyncClient,
    AtCapacityError,
    CancelHandle,
    Client,
    PlimsollError,
    RequestCanceledError,
    RequestTimeoutError,
)
from plimsoll_client._record import session_fingerprint

# Seconds a cut request may take to return. The work it stands for is a socket
# shutdown and a thread waking, so a real cut takes milliseconds; one that waits for
# its answer instead waits for the test's release or the request timeout, far longer.
PROMPT = 1.0


def wait_for(pred: Callable[[], bool], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while not pred():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


class Call(threading.Thread):
    """Runs fn in a thread and keeps what it returned or raised."""

    def __init__(self, fn: Callable[[], Any]) -> None:
        super().__init__(daemon=True)
        self.fn = fn
        self.error: Optional[BaseException] = None
        self.result: Any = None

    def run(self) -> None:
        try:
            self.result = self.fn()
        except BaseException as e:  # kept for the test to assert on
            self.error = e


class Server:
    """A loopback HTTP/1.1 server. It answers each procedure with what the test set
    (``answers``, by procedure name), or, for a procedure in ``held``, reads the whole
    request and then waits until ``release`` is set, noting a client that hangs up."""

    def __init__(self) -> None:
        self.answers: Dict[str, Tuple[int, bytes]] = {}
        self.held: Set[str] = set()
        self.release = threading.Event()
        self._lock = threading.Lock()
        self.connections = 0
        self.requests: List[str] = []
        self.waiting = 0
        self.hung_up: List[str] = []
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self) -> None:
        self.release.set()
        self.sock.close()

    def count(self, name: str) -> int:
        with self._lock:
            return self.requests.count(name)

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with self._lock:
                self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            f = conn.makefile("rb")
            line = f.readline()
            if not line:
                return
            name = line.split()[1].decode().rsplit("/", 1)[-1]
            length = 0
            while True:
                header = f.readline()
                if header in (b"\r\n", b""):
                    break
                key, _, value = header.decode().partition(":")
                if key.strip().lower() == "content-length":
                    length = int(value)
            f.read(length)
            with self._lock:
                self.requests.append(name)
            if name in self.held:
                with self._lock:
                    self.waiting += 1
                hung_up = self._hold(conn)
                with self._lock:
                    self.waiting -= 1
                    if hung_up:
                        self.hung_up.append(name)
                if hung_up:
                    return
            status, body = self.answers.get(name, (200, b"{}"))
            head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            try:
                conn.sendall(head.encode() + body)
            except OSError:
                pass

    def _hold(self, conn: socket.socket) -> bool:
        """Waits for the release; True when the client hung up first. The client
        sends nothing after its request, so readable means it closed its end."""
        while not self.release.is_set():
            readable, _, _ = select.select([conn], [], [], 0.01)
            if readable:
                try:
                    if not conn.recv(1):
                        return True
                except OSError:
                    return True
        return False


def describe_answer() -> Tuple[int, bytes]:
    from plimsoll_client import PROTOCOL

    return 200, json.dumps({"sandbox": "stub", "isolation": "process", "protocol": PROTOCOL}).encode()


def capacity_refusal() -> Tuple[int, bytes]:
    # A refusal the daemon marks not dispatched (reason capacity): the session goes on.
    detail = base64.b64encode(bytes([0x08, 6])).decode().rstrip("=")
    body = {"code": "resource_exhausted", "message": "busy", "details": [{"type": "plimsoll.v1.NotDispatched", "value": detail}]}
    return 429, json.dumps(body).encode()


def full_backlog() -> Tuple[socket.socket, List[socket.socket], int]:
    """A listening socket whose accept queue is full, so the next connect to it waits:
    Linux drops a SYN to a full queue and the client keeps retrying it."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(0)
    port = srv.getsockname()[1]
    queued: List[socket.socket] = []
    for _ in range(8):
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", port))
        except (TimeoutError, OSError):
            s.close()
            return srv, queued, port
        queued.append(s)
    raise AssertionError("the accept queue never filled, so a connect cannot be made to wait")


class Handle(unittest.TestCase):
    def setUp(self) -> None:
        self.server = Server()
        self.addCleanup(self.server.close)

    def test_a_cancelled_handle_sends_nothing_and_says_so(self) -> None:
        h = CancelHandle()
        h.cancel()
        self.assertTrue(h.cancelled)
        c = Client(self.server.url)
        for name, call in (
            ("Describe", lambda: c.describe(cancel=h)),
            ("Run", lambda: c.run_javascript("1", cancel=h)),
            ("Run", lambda: c.run_project({"a": "1"}, ["true"], cancel=h)),
            ("Run", lambda: c.run_module("m", [[1]], end_time=1, step=0.1, cancel=h)),
        ):
            with self.subTest(name), self.assertRaises(RequestCanceledError) as cm:
                call()
            self.assertEqual((cm.exception.not_dispatched, cm.exception.code), ("request", "canceled"))
            self.assertIn(f"{name} was canceled before it was sent", cm.exception.message)
        self.assertEqual(self.server.connections, 0, "a cancelled handle opened a connection")

    def test_a_request_in_flight_is_cut_at_once_and_left_unmarked(self) -> None:
        self.server.held = {"Describe"}
        h = CancelHandle()
        call = Call(lambda: Client(self.server.url).describe(cancel=h))
        call.start()
        self.assertTrue(wait_for(lambda: self.server.waiting == 1), "the request never reached the server")
        start = time.monotonic()
        h.cancel()
        call.join(PROMPT)
        self.assertFalse(call.is_alive(), "the cut request kept its thread waiting for an answer")
        self.assertLess(time.monotonic() - start, PROMPT)
        self.assertIsInstance(call.error, RequestCanceledError)
        assert isinstance(call.error, PlimsollError)
        # The daemon had the whole request: it may have run it.
        self.assertIsNone(call.error.not_dispatched)
        self.assertIn("may have received it", call.error.message)
        self.assertTrue(wait_for(lambda: self.server.hung_up == ["Describe"], PROMPT), "the server never saw the client hang up")
        # A cancelled handle refuses what comes after, with nothing sent.
        with self.assertRaises(RequestCanceledError) as cm:
            Client(self.server.url).describe(cancel=h)
        self.assertEqual(cm.exception.not_dispatched, "request")
        self.assertEqual(self.server.count("Describe"), 1)

    def test_an_answer_that_arrived_before_the_cancel_is_returned(self) -> None:
        self.server.answers["Describe"] = describe_answer()
        h = CancelHandle()
        self.assertEqual(Client(self.server.url).describe(cancel=h).provider, "stub")
        h.cancel()  # after the fact: nothing to cut

    def test_a_connect_that_waits_is_cut_with_nothing_sent(self) -> None:
        srv, queued, port = full_backlog()
        self.addCleanup(srv.close)
        for s in queued:
            self.addCleanup(s.close)
        h = CancelHandle()
        call = Call(lambda: Client(f"http://127.0.0.1:{port}").describe(cancel=h))
        call.start()
        time.sleep(0.3)
        self.assertTrue(call.is_alive(), "the connect did not wait, so this case tests nothing")
        h.cancel()
        call.join(PROMPT)
        self.assertFalse(call.is_alive(), "the cancel did not reach the connecting socket")
        self.assertIsInstance(call.error, RequestCanceledError)
        assert isinstance(call.error, PlimsollError)
        self.assertEqual(call.error.not_dispatched, "request")

    def test_the_deadline_covers_a_connect_that_waits(self) -> None:
        srv, queued, port = full_backlog()
        self.addCleanup(srv.close)
        for s in queued:
            self.addCleanup(s.close)
        start = time.monotonic()
        with self.assertRaises(RequestTimeoutError) as cm:
            Client(f"http://127.0.0.1:{port}", request_timeout=0.5).describe()
        self.assertLess(time.monotonic() - start, 0.5 + PROMPT)
        self.assertEqual(cm.exception.not_dispatched, "environment")  # nothing was sent before the deadline

    def test_a_tls_handshake_is_cut_with_nothing_sent(self) -> None:
        # A server that accepts and never answers the ClientHello: the client waits in
        # the handshake, before any byte of the request exists on the wire.
        srv = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(srv.close)
        got = bytearray()
        closed = threading.Event()

        def serve() -> None:
            conn, _ = srv.accept()
            with conn:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        closed.set()
                        return
                    got.extend(chunk)

        threading.Thread(target=serve, daemon=True).start()
        h = CancelHandle()
        call = Call(lambda: Client(f"https://127.0.0.1:{srv.getsockname()[1]}").describe(cancel=h))
        call.start()
        self.assertTrue(wait_for(lambda: len(got) > 0), "the client never started its handshake")
        h.cancel()
        call.join(PROMPT)
        self.assertFalse(call.is_alive(), "the cancel did not reach the handshake")
        self.assertIsInstance(call.error, RequestCanceledError)
        assert isinstance(call.error, PlimsollError)
        self.assertEqual(call.error.not_dispatched, "request")
        self.assertTrue(closed.wait(PROMPT))
        self.assertEqual(got[0], 0x16, "the bytes sent were not a TLS handshake record")
        self.assertNotIn(b"POST", bytes(got))


class Async(unittest.TestCase):
    def setUp(self) -> None:
        self.server = Server()
        self.addCleanup(self.server.close)

    def test_cancelling_an_awaited_call_cuts_its_request(self) -> None:
        self.server.held = {"Describe"}

        async def main() -> float:
            task = asyncio.ensure_future(AsyncClient(self.server.url).describe())
            try:
                while self.server.waiting == 0:
                    await asyncio.sleep(0.01)
                start = time.monotonic()
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                # The thread's request is cut, not left waiting for its answer.
                self.assertTrue(
                    await asyncio.to_thread(wait_for, lambda: self.server.hung_up == ["Describe"], PROMPT),
                    "the awaited request kept its connection after the cancel",
                )
                return time.monotonic() - start
            finally:
                self.server.release.set()  # so asyncio.run's executor shutdown never waits on a thread

        self.assertLess(asyncio.run(main()), PROMPT)

    def session_server(self) -> None:
        sid = "ab" * 16
        self.server.answers["OpenSession"] = (200, json.dumps(
            {"sessionId": sid, "session": session_fingerprint(sid), "sandbox": "stub", "isolation": "container"}).encode())
        # A call is held, then refused as the daemon refuses a call it never
        # dispatched: the session goes on, so a call queued behind it is sent next.
        self.server.answers["SessionRun"] = capacity_refusal()
        self.server.held = {"SessionRun"}

    def test_a_session_call_waiting_its_turn_is_never_sent(self) -> None:
        self.session_server()

        async def main() -> None:
            s = await AsyncClient(self.server.url).open_session()
            first = asyncio.ensure_future(s.run_javascript("1"))
            try:
                while self.server.waiting == 0:
                    await asyncio.sleep(0.01)
                second = asyncio.ensure_future(s.run_javascript("2"))
                await asyncio.sleep(0.2)  # its thread is now waiting for the session's turn
                second.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await second
            finally:
                self.server.release.set()
            with self.assertRaises(AtCapacityError):
                await first
            # The cancelled call took its turn and sent nothing; the session goes on.
            with self.assertRaises(AtCapacityError):
                await s.run_javascript("3")

        asyncio.run(main())  # returns once every worker thread has finished
        self.assertEqual(self.server.count("SessionRun"), 2, "the cancelled call was sent when its turn came")
        self.assertEqual(self.server.hung_up, [])

    def test_a_session_call_cut_in_flight_ends_the_session_for_this_client(self) -> None:
        self.session_server()

        async def main() -> None:
            s = await AsyncClient(self.server.url).open_session()
            first = asyncio.ensure_future(s.run_javascript("1"))
            try:
                while self.server.waiting == 0:
                    await asyncio.sleep(0.01)
                first.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await first
                self.assertTrue(
                    await asyncio.to_thread(wait_for, lambda: self.server.hung_up == ["SessionRun"], PROMPT),
                    "the cancelled session call kept its connection",
                )
                # The cut call may have run and moved the daemon's chain on: this client
                # sends nothing more on the session.
                with self.assertRaises(PlimsollError) as cm:
                    await s.run_javascript("2")
                self.assertEqual(cm.exception.not_dispatched, "request")
                self.assertIn("ended without an answer", cm.exception.message)
            finally:
                self.server.release.set()

        asyncio.run(main())
        self.assertEqual(self.server.count("SessionRun"), 1)


if __name__ == "__main__":
    unittest.main()
