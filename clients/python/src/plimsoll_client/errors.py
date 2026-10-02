"""Errors raised by the client.

Every error is a :class:`PlimsollError`. The one distinction that matters for a
retry is whether anything ran: a refusal the daemon raised before any code was
dispatched carries ``not_dispatched`` (the reason, one of ``request``,
``permission``, ``protocol``, ``unsupported``, ``isolation``, ``environment``,
``capacity`` or ``unknown``). An error whose ``not_dispatched`` is ``None`` may
have followed execution, whatever its class or code, so it is never a safe
automatic retry of a request that is not idempotent.

The classes mirror the Go client's sentinel errors (package ``client`` and
package ``sandbox``); the comment on each names its Go counterpart.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

__all__ = [
    "PlimsollError",
    "InvalidBaseURLError",
    "InsecureHTTPError",
    "InvalidRequestError",
    "InsufficientIsolationError",
    "SoftwareMismatchError",
    "DisabledError",
    "UnsupportedError",
    "ProtocolMismatchError",
    "AtCapacityError",
    "SessionEndedError",
    "TransportError",
    "RequestTimeoutError",
    "ResponseTooLargeError",
    "MalformedResponseError",
    "DataLossError",
    "RecordMismatchError",
    "NoRecordError",
    "RecordVersionError",
    "ChainError",
    "IsolationEvidenceMismatchError",
    "SoftwareEvidenceMismatchError",
    "ResultKindMismatchError",
]


class PlimsollError(Exception):
    """Base class of every error this client raises.

    ``code`` is the Connect status code (``"failed_precondition"``,
    ``"unimplemented"``, ...), as the daemon sent it or as this client assigned
    it. ``not_dispatched`` is set only when the daemon stated that nothing ran
    (or when the client refused the request before sending it). ``http_status``
    is the HTTP status of the daemon's answer, ``None`` when there was none.
    ``unanswered`` is the record the daemon sends with a session call that may have
    run but ended in an error (a version 3 record, in its proto3 JSON form): the
    Session checks it and keeps it in its chain, so the session goes on.
    """

    default_code = "unknown"

    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        not_dispatched: Optional[str] = None,
        http_status: Optional[int] = None,
        unanswered: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code: str = code if code is not None else self.default_code
        self.not_dispatched: Optional[str] = not_dispatched
        self.http_status: Optional[int] = http_status
        self.unanswered: Optional[Dict[str, Any]] = unanswered


# --- refused before anything was sent ----------------------------------------


class InvalidBaseURLError(PlimsollError, ValueError):
    """The base URL is not an absolute http or https URL without userinfo,
    query or fragment (Go: ``client.ErrInvalidBaseURL``)."""

    default_code = "invalid_argument"


class InsecureHTTPError(PlimsollError, ValueError):
    """Cleartext HTTP to a host that is not loopback, without
    ``insecure_http=True`` (Go: ``client.ErrInsecureHTTP``)."""

    default_code = "invalid_argument"


# --- refusals, restored from the daemon's status and details -------------------


class InvalidRequestError(PlimsollError):
    """The request is malformed or out of bounds (Go: ``sandbox.ErrInvalidRequest``).

    Raised by the client before sending (``not_dispatched == "request"``) and
    restored from a daemon's ``invalid_argument`` answer.
    """

    default_code = "invalid_argument"


class InsufficientIsolationError(PlimsollError):
    """The provider's isolation tier is below the request's floor; refused
    before dispatch (Go: ``sandbox.ErrInsufficientIsolation``)."""

    default_code = "failed_precondition"


class SoftwareMismatchError(PlimsollError):
    """The software the daemon would run is outside the request's software
    rule; refused before dispatch (Go: ``sandbox.ErrSoftwareMismatch``)."""

    default_code = "failed_precondition"


class DisabledError(PlimsollError):
    """The daemon's provider refuses to run anything (Go: ``sandbox.ErrDisabled``)."""

    default_code = "failed_precondition"


class UnsupportedError(PlimsollError):
    """The daemon's provider cannot perform the operation (Go: ``sandbox.ErrUnsupported``)."""

    default_code = "unimplemented"


class ProtocolMismatchError(PlimsollError):
    """The daemon serves another protocol number than this client speaks
    (Go: ``client.ErrProtocolMismatch``).

    Raised for a request the daemon refused on its protocol number, and by
    :meth:`Client.describe` when the number the daemon states differs; ``info``
    then holds what the daemon described.
    """

    default_code = "unimplemented"

    def __init__(self, message: str, *, info: Any = None, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.info = info


class AtCapacityError(PlimsollError):
    """Shed by the daemon's admission or rate limit (Go: ``sandbox.ErrAtCapacity``)."""

    default_code = "resource_exhausted"


class SessionEndedError(PlimsollError):
    """A session call refused because its session has ended
    (Go: ``sandbox.SessionEndedError``).

    ``reason`` is why it ended: ``closed``, ``expired``, ``disk_exceeded``,
    ``main_process_ended``, ``boundary_failed``, ``sandbox_changed`` or
    ``shutdown``. ``detail`` is the daemon's context, possibly empty.
    """

    default_code = "failed_precondition"

    def __init__(self, message: str, *, reason: str, detail: str = "", **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.reason = reason
        self.detail = detail


# --- no Connect answer --------------------------------------------------------


class TransportError(PlimsollError):
    """No usable answer: the connection failed, or the response could not be
    read as a Connect answer. Never marked not dispatched: the daemon may have
    received the request and run it."""

    default_code = "unavailable"


class RequestTimeoutError(TransportError):
    """The exchange did not finish within the client's request timeout."""

    default_code = "deadline_exceeded"


class ResponseTooLargeError(TransportError):
    """The answer is larger than the client accepts (32 MiB, the Go client's
    ``maxResponseBytes``)."""

    default_code = "resource_exhausted"


class MalformedResponseError(TransportError):
    """The answer is not a well-formed message of the expected type."""

    default_code = "internal"


# --- answered, but the answer does not check ------------------------------------


class DataLossError(PlimsollError):
    """The daemon answered, and the answer does not check. The run may already
    have executed, so this is never a retry signal (Go: ``connect.CodeDataLoss``).

    ``result`` is what came back, mapped as far as it could be (a result whose
    record did not check carries ``record=None``), or ``None``.
    """

    default_code = "data_loss"

    def __init__(self, message: str, *, result: Any = None, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.result = result


class RecordMismatchError(DataLossError):
    """The run record does not match the request sent and the result received
    (Go: ``record.ErrMismatch``)."""


class NoRecordError(DataLossError):
    """The answer carries no run record (Go: ``record.ErrNoRecord``)."""


class RecordVersionError(DataLossError):
    """The record uses an encoding version this client does not know, or one the
    request's protocol does not allow (Go: ``record.ErrVersion``)."""


class ChainError(DataLossError):
    """A session's chain of records is broken: a call this client did not make
    ran in the session, or a record was dropped or replayed (Go: ``record.ErrChain``)."""


class IsolationEvidenceMismatchError(DataLossError):
    """The tier the answer states is below the floor the request set
    (Go: ``sandbox.ErrIsolationEvidenceMismatch``)."""


class SoftwareEvidenceMismatchError(DataLossError):
    """A session opened on software outside the requested rule (Go: DataLoss
    wrapping ``sandbox.ErrSoftwareMismatch`` from ``OpenSession``)."""


class ResultKindMismatchError(DataLossError):
    """The answer holds a result of another kind than the request, or none
    (Go: ``client.ErrResultKindMismatch``)."""
