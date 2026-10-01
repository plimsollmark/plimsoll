"""The proto3 JSON forms of plimsoll.v1 messages (proto/plimsoll/v1/sandbox.proto).

Field names are protobuf's lowerCamelCase JSON names (the original snake_case
names are accepted too, as protobuf's own JSON parser accepts them); ``bytes``
are base64; 64-bit integers usually arrive as strings; enums as their names; a
field at its zero value is omitted. Connect error details carry binary protobuf,
and the two this client reads are decoded by hand below, so no protobuf runtime
is needed.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from typing import Any, Dict, List, Optional, Tuple

from .errors import (
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

INT32 = (-(1 << 31), (1 << 31) - 1)
UINT32 = (0, (1 << 32) - 1)
INT64 = (-(1 << 63), (1 << 63) - 1)
UINT64 = (0, (1 << 64) - 1)

# plimsoll.v1.ProjectOutcome
OUTCOMES: Dict[str, int] = {
    "PROJECT_OUTCOME_UNSPECIFIED": 0,
    "PROJECT_OUTCOME_COMPLETED": 1,
    "PROJECT_OUTCOME_SETUP_FAILED": 2,
    "PROJECT_OUTCOME_TIMED_OUT": 3,
    "PROJECT_OUTCOME_PROTOCOL_ERROR": 4,
}
OUTCOME_NAMES = ("unspecified", "completed", "setup_failed", "timed_out", "protocol_error")

# plimsoll.v1.SessionEnd
SESSION_ENDS: Dict[str, int] = {
    "SESSION_END_UNSPECIFIED": 0,
    "SESSION_END_CLOSED": 1,
    "SESSION_END_EXPIRED": 2,
    "SESSION_END_DISK_EXCEEDED": 3,
    "SESSION_END_MAIN_PROCESS_ENDED": 4,
    "SESSION_END_BOUNDARY_FAILED": 5,
    "SESSION_END_SANDBOX_CHANGED": 6,
    "SESSION_END_SHUTDOWN": 7,
}
SESSION_END_NAMES = (
    "open",
    "closed",
    "expired",
    "disk_exceeded",
    "main_process_ended",
    "boundary_failed",
    "sandbox_changed",
    "shutdown",
)

# plimsoll.v1.NotDispatchedReason, by number.
REFUSAL_NAMES = (
    "unknown",
    "request",
    "permission",
    "protocol",
    "unsupported",
    "isolation",
    "capacity",
    "environment",
)

CONNECT_CODES = frozenset(
    {
        "canceled",
        "unknown",
        "invalid_argument",
        "deadline_exceeded",
        "not_found",
        "already_exists",
        "permission_denied",
        "resource_exhausted",
        "failed_precondition",
        "aborted",
        "out_of_range",
        "unimplemented",
        "internal",
        "unavailable",
        "data_loss",
        "unauthenticated",
    }
)

_SNAKE = re.compile(r"(?<!^)([A-Z])")
_JSON_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_DECIMAL_INT = re.compile(r"-?[0-9]+")


def snake(name: str) -> str:
    """The proto field name for a JSON name: ``stdoutTruncated`` -> ``stdout_truncated``."""
    return _SNAKE.sub(lambda m: "_" + m.group(1).lower(), name)


# --- JSON --------------------------------------------------------------------


def _parse_int(text: str) -> Any:
    # protobuf's JSON writer prints a double negative zero as "-0", which Python's
    # parser would read as the integer 0 and lose the sign the result digest covers.
    if text == "-0":
        return -0.0
    return int(text)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON key {k!r}")
        out[k] = v
    return out


def loads(data: bytes) -> Any:
    """Strict JSON: UTF-8, no duplicate keys, no bare NaN or Infinity."""
    return json.loads(
        data.decode("utf-8"),
        parse_int=_parse_int,
        parse_constant=_reject_constant,
        object_pairs_hook=_no_duplicates,
    )


def dumps(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def b64encode(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64decode(s: str) -> bytes:
    """Standard or URL-safe base64, padded or not, as protobuf JSON and Connect
    error details may carry it. Anything else raises ValueError."""
    if not isinstance(s, str):
        raise ValueError("base64 value is not a string")
    url = "-" in s or "_" in s
    core = s.rstrip("=")
    if len(core) % 4 == 1:
        raise ValueError("base64 value has an impossible length")
    padded = core + "=" * (-len(core) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_" if url else None, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"invalid base64: {e}") from None


# --- reading messages ----------------------------------------------------------


class Msg:
    """Typed, checked access to one JSON object holding a protobuf message.

    An absent field or a JSON null reads as the field's zero value. A value of the
    wrong type raises MalformedResponseError: the message did not come from a
    daemon that keeps the schema, and nothing in it can be trusted.
    """

    __slots__ = ("_d", "_path")

    def __init__(self, d: Any, path: str) -> None:
        if not isinstance(d, dict):
            raise MalformedResponseError(f"{path} is not a JSON object")
        self._d: Dict[str, Any] = d
        self._path = path

    @property
    def raw(self) -> Dict[str, Any]:
        return self._d

    def _get(self, name: str) -> Any:
        v = self._d.get(name)
        if v is None:
            v = self._d.get(snake(name))
        return v

    def _bad(self, name: str, what: str) -> MalformedResponseError:
        return MalformedResponseError(f"{self._path}.{name} is not {what}")

    def has(self, name: str) -> bool:
        return self._get(name) is not None

    def get_str(self, name: str) -> str:
        v = self._get(name)
        if v is None:
            return ""
        if not isinstance(v, str):
            raise self._bad(name, "a string")
        return v

    def get_bool(self, name: str) -> bool:
        v = self._get(name)
        if v is None:
            return False
        if not isinstance(v, bool):
            raise self._bad(name, "a boolean")
        return v

    def get_int(self, name: str, bounds: Tuple[int, int]) -> int:
        return _as_int(self._get(name), bounds, lambda: self._bad(name, "an integer in range"))

    def get_float(self, name: str) -> float:
        return _as_float(self._get(name), lambda: self._bad(name, "a number"))

    def get_floats(self, name: str) -> List[float]:
        return [_as_float(v, lambda: self._bad(name, "a list of numbers")) for v in self._list(name)]

    def get_bytes(self, name: str) -> bytes:
        v = self._get(name)
        if v is None:
            return b""
        try:
            return b64decode(v)
        except ValueError:
            raise self._bad(name, "base64") from None

    def get_enum(self, name: str, values: Dict[str, int]) -> int:
        """The enum's number. A name this client does not know cannot be turned
        into the number a digest covers, so it is malformed; a number is kept."""
        v = self._get(name)
        if v is None:
            return 0
        if isinstance(v, str):
            if v not in values:
                raise self._bad(name, "a known enum value")
            return values[v]
        return _as_int(v, INT32, lambda: self._bad(name, "an enum value"))

    def get_msg(self, name: str) -> Optional["Msg"]:
        v = self._get(name)
        if v is None:
            return None
        return Msg(v, f"{self._path}.{name}")

    def get_msgs(self, name: str) -> List["Msg"]:
        return [Msg(v, f"{self._path}.{name}[{i}]") for i, v in enumerate(self._list(name))]

    def get_strs(self, name: str) -> List[str]:
        out = self._list(name)
        if not all(isinstance(v, str) for v in out):
            raise self._bad(name, "a list of strings")
        return out

    def _list(self, name: str) -> List[Any]:
        v = self._get(name)
        if v is None:
            return []
        if not isinstance(v, list):
            raise self._bad(name, "a list")
        return v


def _as_int(v: Any, bounds: Tuple[int, int], bad: Any) -> int:
    if v is None:
        return 0
    if isinstance(v, bool):
        raise bad()
    if isinstance(v, int):
        n = v
    elif isinstance(v, float):
        if not math.isfinite(v) or not v.is_integer():
            raise bad()
        n = int(v)
    elif isinstance(v, str) and _DECIMAL_INT.fullmatch(v):
        n = int(v)
    else:
        raise bad()
    if not bounds[0] <= n <= bounds[1]:
        raise bad()
    return n


def _as_float(v: Any, bad: Any) -> float:
    if v is None:
        return 0.0
    if isinstance(v, bool):
        raise bad()
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        if v == "NaN":
            return math.nan
        if v == "Infinity":
            return math.inf
        if v == "-Infinity":
            return -math.inf
        if _JSON_NUMBER.fullmatch(v):
            return float(v)
    raise bad()


def parse_response(data: bytes, path: str) -> Msg:
    try:
        value = loads(data)
    except (UnicodeDecodeError, ValueError) as e:
        raise MalformedResponseError(f"the daemon's answer is not valid JSON: {e}") from None
    return Msg(value, path)


# --- the two error details, decoded by hand --------------------------------------


def _varint(b: bytes, i: int) -> Tuple[int, int]:
    v = 0
    shift = 0
    while True:
        if i >= len(b):
            raise ValueError("truncated varint")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if not c & 0x80:
            break
        shift += 7
        if shift >= 70:
            raise ValueError("varint longer than 10 bytes")
    if v >= 1 << 64:
        raise ValueError("varint overflows 64 bits")
    return v, i


def decode_enum_and_string(b: bytes) -> Tuple[int, str]:
    """Decodes a message whose field 1 is an enum and field 2 a string: both
    NotDispatched (reason) and SessionEnded (reason, detail) have that shape.

    Unknown fields are skipped as protobuf skips them. A known field of the wrong
    wire type, a truncated value or a string that is not UTF-8 raises ValueError,
    exactly where protobuf's own decoder refuses the message.
    """
    reason = 0
    detail = ""
    i = 0
    while i < len(b):
        tag, i = _varint(b, i)
        field, wire = tag >> 3, tag & 7
        if field == 0:
            raise ValueError("field number 0")
        if wire == 0:
            v, i = _varint(b, i)
            if field == 2:
                raise ValueError("field 2 is not length-delimited")
            if field == 1:
                v &= 0xFFFFFFFF  # an enum is an int32
                reason = v - (1 << 32) if v >= 1 << 31 else v
        elif wire == 2:
            n, i = _varint(b, i)
            if i + n > len(b):
                raise ValueError("length-delimited field overruns the message")
            if field == 1:
                raise ValueError("field 1 is not a varint")
            if field == 2:
                detail = b[i : i + n].decode("utf-8")
            i += n
        elif wire in (1, 5):
            if field in (1, 2):
                raise ValueError("a known field has a fixed-width wire type")
            i += 8 if wire == 1 else 4
            if i > len(b):
                raise ValueError("fixed-width field overruns the message")
        else:
            raise ValueError(f"unsupported wire type {wire}")
    return reason, detail


def _http_code(status: int) -> str:
    # Connect's mapping for an answer without a Connect error body.
    if status == 400:
        return "internal"
    if status == 401:
        return "unauthenticated"
    if status == 403:
        return "permission_denied"
    if status == 404:
        return "unimplemented"
    if status in (429, 502, 503, 504):
        return "unavailable"
    return "unknown"


def error_from_wire(status: int, body: bytes) -> PlimsollError:
    """The error a Connect error answer describes, restored the way the Go client's
    restoreSandboxError restores it: the NotDispatched detail marks it, a
    SessionEnded detail types it, and the code with the reason picks the class."""
    parsed: Any = None
    try:
        parsed = loads(body) if body else None
    except (UnicodeDecodeError, ValueError):
        parsed = None
    if not isinstance(parsed, dict):
        parsed = {}
    code = parsed.get("code")
    if not isinstance(code, str) or code not in CONNECT_CODES:
        code = _http_code(status)
    message = parsed.get("message")
    if not isinstance(message, str) or not message:
        message = f"HTTP {status}"

    refusal: Optional[str] = None
    end: Optional[Tuple[str, str]] = None
    details = parsed.get("details")
    for d in details if isinstance(details, list) else []:
        if not isinstance(d, dict):
            continue
        type_name = d.get("type")
        value = d.get("value")
        if not isinstance(type_name, str) or not isinstance(value, str):
            continue
        type_name = type_name.rsplit("/", 1)[-1]
        try:
            raw = b64decode(value)
            if type_name == "plimsoll.v1.NotDispatched" and refusal is None:
                n, _ = decode_enum_and_string(raw)
                refusal = REFUSAL_NAMES[n] if 0 <= n < len(REFUSAL_NAMES) else "unknown"
            elif type_name == "plimsoll.v1.SessionEnded" and end is None:
                n, text = decode_enum_and_string(raw)
                end = (SESSION_END_NAMES[n] if 0 <= n < len(SESSION_END_NAMES) else "open", text)
        except (ValueError, UnicodeDecodeError):
            # An undecodable detail states nothing; in particular not that nothing ran.
            continue

    kwargs: Dict[str, Any] = {"code": code, "not_dispatched": refusal, "http_status": status}
    message = f"plimsoll: {code}: {message}"
    if code == "failed_precondition":
        if end is not None:
            return SessionEndedError(message, reason=end[0], detail=end[1], **kwargs)
        if refusal == "isolation":
            return InsufficientIsolationError(message, **kwargs)
        if refusal == "environment":
            return SoftwareMismatchError(message, **kwargs)
        return DisabledError(message, **kwargs)
    if code == "unimplemented":
        if refusal == "protocol":
            return ProtocolMismatchError(message, **kwargs)
        return UnsupportedError(message, **kwargs)
    if code == "resource_exhausted":
        return AtCapacityError(message, **kwargs)
    if code == "invalid_argument":
        return InvalidRequestError(message, **kwargs)
    if end is not None and code not in ("canceled", "deadline_exceeded"):
        return SessionEndedError(message, reason=end[0], detail=end[1], **kwargs)
    return PlimsollError(message, **kwargs)
