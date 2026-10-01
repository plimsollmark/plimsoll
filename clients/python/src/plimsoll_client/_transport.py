"""One unary Connect call with the JSON codec, over HTTP/1.1.

It uses http.client (the layer urllib.request is built on) directly, for three
reasons: a redirect is never followed (a Connect call has none, and following one
would carry the bearer token and the code to another address); proxy settings in
the environment are not consulted; and the request timeout bounds the whole
exchange, not each socket read, so a daemon that trickles its answer a byte at a
time cannot hold the caller past it.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from ._version import __version__
from ._wire import Msg, dumps, error_from_wire, parse_response
from .errors import MalformedResponseError, RequestTimeoutError, ResponseTooLargeError, TransportError

SERVICE = "plimsoll.v1.SandboxService"

MAX_RESPONSE_BYTES = 32 << 20
"""Above the largest legitimate project answer (bounded step output plus the
aggregate artifact cap), so a misbehaving daemon cannot make the client buffer
without bound: the Go client's maxResponseBytes."""

_CHUNK = 1 << 16


class Transport:
    def __init__(self, base_url: str, token: Optional[str], timeout: float, ssl_context: Optional[ssl.SSLContext]) -> None:
        u = urlsplit(base_url)
        self._https = u.scheme == "https"
        self._host = u.hostname or ""
        self._port = u.port
        self._prefix = u.path.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._ssl = ssl_context if ssl_context is not None else (ssl.create_default_context() if self._https else None)

    def _connection(self) -> http.client.HTTPConnection:
        if self._https:
            return http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout, context=self._ssl)
        return http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)

    def call(self, method: str, body: Dict[str, Any], path: str) -> Msg:
        """POSTs body to the procedure and returns the answer as a message. A
        Connect error answer raises the restored error; anything that is not a
        Connect answer raises TransportError."""
        data = dumps(body)
        headers = {
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
            "Accept-Encoding": "identity",
            "User-Agent": f"plimsoll-client-python/{__version__}",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        deadline = time.monotonic() + self._timeout
        conn = self._connection()
        fired = threading.Event()
        timer: Optional[threading.Timer] = None
        try:
            try:
                conn.connect()
                # The socket timeout bounds each read; the timer bounds them all,
                # by shutting the socket down when the deadline passes.
                timer = threading.Timer(max(deadline - time.monotonic(), 0.0), _abort, (conn, fired))
                timer.daemon = True
                timer.start()
                conn.request("POST", f"{self._prefix}/{SERVICE}/{method}", body=data, headers=headers)
                _settimeout(conn, deadline)
                resp = conn.getresponse()
                raw = _read_capped(conn, resp, deadline)
                if fired.is_set():
                    raise socket.timeout("deadline passed")
            except (socket.timeout, TimeoutError):
                raise RequestTimeoutError(f"plimsoll: {method} did not finish within {self._timeout} s") from None
            except (OSError, http.client.HTTPException) as e:
                if fired.is_set():
                    raise RequestTimeoutError(f"plimsoll: {method} did not finish within {self._timeout} s") from None
                raise TransportError(f"plimsoll: {method}: {e}") from e
        finally:
            if timer is not None:
                timer.cancel()
            conn.close()
        if resp.status != 200:
            raise error_from_wire(resp.status, raw)
        ctype = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            raise MalformedResponseError(f"plimsoll: {method} answered with content type {ctype or 'none'!r}, not application/json")
        return parse_response(raw, path)


def _abort(conn: http.client.HTTPConnection, fired: threading.Event) -> None:
    fired.set()
    sock = conn.sock
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def _settimeout(conn: http.client.HTTPConnection, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("deadline passed")
    if conn.sock is not None:
        conn.sock.settimeout(remaining)


def _read_capped(conn: http.client.HTTPConnection, resp: http.client.HTTPResponse, deadline: float) -> bytes:
    length = resp.getheader("Content-Length")
    if length is not None and length.strip().isdigit() and int(length) > MAX_RESPONSE_BYTES:
        raise ResponseTooLargeError(f"plimsoll: the daemon's answer is {int(length)} bytes, over the {MAX_RESPONSE_BYTES} byte limit")
    chunks: List[bytes] = []
    n = 0
    while True:
        _settimeout(conn, deadline)
        chunk = resp.read1(_CHUNK)  # one read at most, so the deadline is checked between reads
        if not chunk:
            break
        n += len(chunk)
        if n > MAX_RESPONSE_BYTES:
            raise ResponseTooLargeError(f"plimsoll: the daemon's answer exceeds {MAX_RESPONSE_BYTES} bytes")
        chunks.append(chunk)
    return b"".join(chunks)
