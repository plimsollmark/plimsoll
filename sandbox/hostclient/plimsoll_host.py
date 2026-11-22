"""plimsoll_host: this run's web API, from Python.

A run that carries a grant can call the routes its grant profile allows. plimsoll's
broker, outside the sandbox, checks each request's method and path against the
profile's routes, adds the API's credential and makes the call; this module only sends
the request to the broker, over the Unix socket named by HOST_API_SOCKET, with the
standard library. It holds no credential and needs none.

    import plimsoll_host
    lights = plimsoll_host.get("/v1/lights")
    plimsoll_host.post("/v1/lights/kitchen/on", {"level": 40})

Each call returns the answer's JSON, parsed (its text when it is not JSON), for a 2xx
status, and raises HostAPIError, with the status and the body, for any other. A route
the profile does not allow is refused with 403, a run past its call budget with 429.
"""

import http.client
import json
import os
import socket

__all__ = ["HostAPIError", "call", "get", "post", "put", "patch", "delete"]

# The broker bounds every call by the run's own deadline; this only keeps a socket that
# never answers from holding the program past the daemon's five-minute ceiling.
_TIMEOUT = 300


class HostAPIError(Exception):
    """An answer outside 2xx: status is the HTTP status (0 when the broker could not be
    reached), body the answer's JSON parsed (its text when it is not JSON)."""

    def __init__(self, status, body, text):
        super().__init__("host api %d: %s" % (status, text))
        self.status = status
        self.body = body


class _BrokerConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=_TIMEOUT)
        self._socket_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._socket_path)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


def call(method, path, body=None):
    """Sends one request: method (GET, POST, PUT, PATCH, DELETE), a path that starts
    with "/" and has no query, and a body that is sent as JSON when it is not None."""
    where = os.environ.get("HOST_API_SOCKET", "")
    if not where:
        raise HostAPIError(0, None, "host api broker unavailable: this run carries no grant")
    method = str(method).upper()
    payload = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    conn = _BrokerConnection(where)
    try:
        try:
            conn.request(method, str(path), body=payload, headers=headers)
            answer = conn.getresponse()
            raw = answer.read()
        except OSError as e:
            raise HostAPIError(0, None, "host api broker unavailable: %s" % e) from e
    finally:
        conn.close()
    text = raw.decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except ValueError:
        data = text
    if 200 <= answer.status < 300:
        return data
    raise HostAPIError(answer.status, data, text)


def get(path):
    return call("GET", path)


def post(path, body=None):
    return call("POST", path, body)


def put(path, body=None):
    return call("PUT", path, body)


def patch(path, body=None):
    return call("PATCH", path, body)


def delete(path):
    return call("DELETE", path)
