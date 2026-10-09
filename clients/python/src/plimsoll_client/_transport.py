"""One unary Connect call with the JSON codec, over HTTP/1.1.

It uses http.client (the layer urllib.request is built on) directly, for four
reasons: a redirect is never followed (a Connect call has none, and following one
would carry the bearer token and the code to another address); proxy settings in
the environment are not consulted; the request timeout bounds the whole
exchange, not each socket read, so a daemon that trickles its answer a byte at a
time cannot hold the caller past it; and a :class:`CancelHandle` can end the
exchange from another thread at any point.
"""

from __future__ import annotations

import asyncio
import http.client
import re
import socket
import ssl
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar
from urllib.parse import urlsplit

from ._version import __version__
from ._wire import Msg, dumps, error_from_wire, parse_response
from .errors import MalformedResponseError, RequestCanceledError, RequestTimeoutError, ResponseTooLargeError, TransportError

SERVICE = "plimsoll.v1.SandboxService"

MAX_RESPONSE_BYTES = 32 << 20
"""Above the largest legitimate project answer (bounded step output plus the
aggregate artifact cap), so a misbehaving daemon cannot make the client buffer
without bound: the Go client's maxResponseBytes."""

_CHUNK = 1 << 16

_DIGITS = re.compile(r"[0-9]+")

T = TypeVar("T")


class CancelHandle:
    """Cancels the requests it is passed to, from any thread, the asyncio event loop's
    included. One handle can serve every request of one operation (a
    :class:`~plimsoll_client.execution.CodeExecutor` call sends Describe, then Run).

    :meth:`cancel` makes a request that has not been sent raise
    :class:`~plimsoll_client.errors.RequestCanceledError` marked not dispatched
    (reason ``request``): no byte of it left this process. It also shuts down the
    socket of a request in flight, so the thread blocked on it (connecting, in the TLS
    handshake, sending or waiting for the answer) returns at once with an unmarked
    RequestCanceledError: the daemon may have received the request and run it. Name
    resolution is not interrupted. A request whose whole answer had arrived returns
    it. Cancelling cannot be undone: a cancelled handle refuses every later request."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cancelled = False
        self._exchanges: Set[_Exchange] = set()

    def __repr__(self) -> str:
        return f"CancelHandle(cancelled={self._cancelled})"

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            exchanges = list(self._exchanges)
        for ex in exchanges:
            ex.abort()

    def _join(self, ex: "_Exchange") -> bool:
        """Registers a request about to start, unless the handle is cancelled."""
        with self._lock:
            if self._cancelled:
                return False
            self._exchanges.add(ex)
            return True

    def _leave(self, ex: "_Exchange") -> None:
        with self._lock:
            self._exchanges.discard(ex)


async def in_thread(fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
    """``await asyncio.to_thread(fn, *args, cancel=handle, **kwargs)`` with a fresh
    handle that is cancelled when the await is: the call in the thread then stops
    too, instead of going on to send what it had not sent yet or waiting for an
    answer nobody reads."""
    handle = CancelHandle()
    try:
        return await asyncio.to_thread(fn, *args, cancel=handle, **kwargs)
    except asyncio.CancelledError:
        handle.cancel()
        raise


class _Exchange:
    """The socket of one request, which the deadline timer and a cancel handle shut
    down from their own threads. Shutting a socket down wakes the thread blocked on
    it. Only the owning thread closes it, and only after release, so a shutdown
    never reaches a descriptor the process has reused for another file."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._aborted = False
        self._released = False

    @property
    def aborted(self) -> bool:
        return self._aborted

    def bind(self, sock: Optional[socket.socket]) -> bool:
        """Makes sock the socket an abort shuts down (None: no socket). False when
        the exchange was aborted already: the caller must not use sock."""
        with self._lock:
            self._sock = sock
            if self._aborted:
                if sock is not None:
                    _shutdown(sock)
                return False
            return True

    def abort(self) -> None:
        with self._lock:
            self._aborted = True
            if self._sock is not None and not self._released:
                _shutdown(self._sock)

    def release(self) -> None:
        with self._lock:
            self._released = True
            self._sock = None


def _shutdown(sock: socket.socket) -> None:
    # The plain socket's shutdown, also for a TLS socket: it wakes a blocked read or
    # handshake on the descriptor without touching the TLS state another thread is in.
    try:
        socket.socket.shutdown(sock, socket.SHUT_RDWR)
    except OSError:
        pass


def _connect(host: str, port: int, timeout: float, ex: _Exchange) -> socket.socket:
    """socket.create_connection, with each socket bound to ex before it connects, so
    an abort ends a connect that is waiting on an address that drops packets."""
    err: Optional[OSError] = None
    for af, socktype, proto, _, sa in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        sock = socket.socket(af, socktype, proto)
        if not ex.bind(sock):
            ex.bind(None)
            sock.close()
            break
        try:
            sock.settimeout(timeout)
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            ex.bind(None)
            sock.close()
            if ex.aborted:
                break
    if ex.aborted:
        raise OSError("the exchange was aborted while connecting")
    if err is not None:
        raise err
    raise OSError(f"no address to connect to for {host!r}")


def _canceled(method: str, sent: bool) -> RequestCanceledError:
    if not sent:
        return RequestCanceledError(f"plimsoll: {method} was canceled before it was sent", not_dispatched="request")
    return RequestCanceledError(f"plimsoll: {method} was canceled after it was sent; the daemon may have received it and run it")


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

    @property
    def token(self) -> Optional[str]:
        """The bearer token, which keys the owner digest; never logged."""
        return self._token

    def _connection(self) -> http.client.HTTPConnection:
        if self._https:
            return http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout, context=self._ssl)
        return http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)

    def _open(self, conn: http.client.HTTPConnection, ex: _Exchange) -> None:
        """conn.connect(), with every socket it uses bound to ex: the TCP socket while
        it connects, then the TLS socket while it shakes hands and carries the call."""
        sys.audit("http.client.connect", conn, conn.host, conn.port)
        sock = _connect(conn.host, conn.port, self._timeout, ex)
        conn.sock = sock  # conn.close() closes whichever socket conn.sock holds
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if self._https:
            assert self._ssl is not None  # set in __init__ for every https URL
            tls = self._ssl.wrap_socket(sock, server_hostname=conn.host, do_handshake_on_connect=False)
            conn.sock = tls
            if not ex.bind(tls):
                raise OSError("the exchange was aborted before the TLS handshake")
            tls.do_handshake()

    def call(self, method: str, body: Dict[str, Any], path: str, cancel: Optional[CancelHandle] = None) -> Msg:
        """POSTs body to the procedure and returns the answer as a message. A
        Connect error answer raises the restored error; anything that is not a
        Connect answer raises TransportError. A cancel handle that is or becomes
        cancelled raises RequestCanceledError, marked not dispatched only while no
        byte of the request can have left."""
        data = dumps(body)
        headers = {
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
            "Accept-Encoding": "identity",
            "User-Agent": f"plimsoll-client-python/{__version__}",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        conn = self._connection()  # an object only: nothing is opened until _open
        ex = _Exchange()
        if cancel is not None and not cancel._join(ex):
            raise _canceled(method, sent=False)
        deadline = time.monotonic() + self._timeout
        fired = threading.Event()
        # The socket timeout bounds each read; the timer bounds them all, connecting
        # included, by shutting the socket down when the deadline passes.
        timer = threading.Timer(self._timeout, _expire, (ex, fired))
        timer.daemon = True
        # Whether any byte of the request may have left: set before the first one can.
        # A cancel seen before it is set leaves nothing to run; one after may not.
        sent = False
        try:
            try:
                timer.start()
                self._open(conn, ex)
                # A cancel or the deadline that came while connecting: nothing is sent.
                if ex.aborted or (cancel is not None and cancel.cancelled):
                    raise socket.timeout("the exchange was aborted before the request was sent")
                sent = True
                try:
                    conn.request("POST", f"{self._prefix}/{SERVICE}/{method}", body=data, headers=headers)
                except (BrokenPipeError, ConnectionResetError):
                    # The daemon can answer before the whole body is sent (a refusal
                    # needs no payload) and close its end; its answer, which may say
                    # nothing ran, is read below instead of being lost to the write.
                    if ex.aborted:
                        raise
                _settimeout(conn, deadline)
                resp = conn.getresponse()
                raw, complete = _read_capped(conn, resp, deadline)
                # An abort shuts the socket down, which ends a read early: an answer cut
                # short is the abort's, but one read to its stated end is the answer.
                if ex.aborted and not complete:
                    raise socket.timeout("the exchange was cut short")
            except (OSError, http.client.HTTPException) as e:
                if cancel is not None and cancel.cancelled:
                    raise _canceled(method, sent) from None
                # Before the first byte could leave (a refused or hanging connect, a failed
                # TLS handshake), nothing reached the daemon: marked, reason environment, so
                # a caller may try again or elsewhere. After it, the daemon may have run it.
                unsent = None if sent else "environment"
                if fired.is_set() or isinstance(e, TimeoutError):
                    raise RequestTimeoutError(f"plimsoll: {method} did not finish within {self._timeout} s"
                                              + ("" if sent else " (nothing was sent)"), not_dispatched=unsent) from None
                raise TransportError(f"plimsoll: {method}: {e}" + ("" if sent else " (nothing was sent)"), not_dispatched=unsent) from e
        finally:
            timer.cancel()
            if cancel is not None:
                cancel._leave(ex)
            ex.release()
            conn.close()
        if resp.status != 200:
            raise error_from_wire(resp.status, raw)
        ctype = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            raise MalformedResponseError(f"plimsoll: {method} answered with content type {ctype or 'none'!r}, not application/json")
        return parse_response(raw, path)


def _expire(ex: _Exchange, fired: threading.Event) -> None:
    fired.set()
    ex.abort()


def _settimeout(conn: http.client.HTTPConnection, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("deadline passed")
    if conn.sock is not None:
        conn.sock.settimeout(remaining)


def _read_capped(conn: http.client.HTTPConnection, resp: http.client.HTTPResponse, deadline: float) -> Tuple[bytes, bool]:
    """The answer's body, and whether it is known complete: read to the length its
    Content-Length states."""
    header = (resp.getheader("Content-Length") or "").strip()
    # ASCII digits only: str.isdigit() also accepts "²", which int() refuses.
    length = int(header) if _DIGITS.fullmatch(header) else None
    if length is not None and length > MAX_RESPONSE_BYTES:
        raise ResponseTooLargeError(f"plimsoll: the daemon's answer is {length} bytes, over the {MAX_RESPONSE_BYTES} byte limit")
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
    return b"".join(chunks), length is not None and n == length
