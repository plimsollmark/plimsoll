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

:func:`retry_on` is that distinction as a predicate for a framework's automatic
retry (LangGraph's ``RetryPolicy``, LangChain's ``ToolRetryMiddleware``): it says
yes only to a marked refusal that another try of the same call may pass.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, FrozenSet, Optional

if TYPE_CHECKING:
    from .types import RunRecord

__all__ = [
    "RETRY_REASONS",
    "retry_on",
    "PlimsollError",
    "InvalidBaseURLError",
    "InsecureHTTPError",
    "InvalidOptionError",
    "InvalidRequestError",
    "InsufficientIsolationError",
    "SoftwareMismatchError",
    "DisabledError",
    "UnsupportedError",
    "ProtocolMismatchError",
    "AtCapacityError",
    "SessionEndedError",
    "RequestCanceledError",
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
    run but ended in an error (an unanswered record, in its proto3 JSON form): the
    Session checks it and keeps it in its chain, so the session goes on; on a single
    run's error it is kept as it came and checked by nothing. ``record``
    is that record once the Session has checked it (Go: ``UnansweredCallError.Record``),
    else ``None``. ``answer_not_bound`` is true for an error built from an answer that
    did not carry this request's ``Plimsoll-Request-Id`` back (Go:
    ``client.ErrAnswerNotBound``): nothing it said about the call was believed, so it
    has no ``not_dispatched`` and no ``unanswered``. ``capacity_limit`` is the limit a
    capacity refusal states (``not_dispatched == "capacity"``), whatever its code, as
    :attr:`AtCapacityError.limit` names it, and ``None`` on every other error (Go:
    ``sandbox.CapacityLimitOf``). It is ``deadline`` on a refusal raised because the
    call's own time ran out before any of it was sent, answered ``deadline_exceeded`` or
    ``canceled``, not ``resource_exhausted``.
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
        answer_not_bound: bool = False,
        capacity_limit: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code: str = code if code is not None else self.default_code
        self.not_dispatched: Optional[str] = not_dispatched
        self.http_status: Optional[int] = http_status
        self.unanswered: Optional[Dict[str, Any]] = unanswered
        self.answer_not_bound: bool = answer_not_bound
        self.record: Optional["RunRecord"] = None
        self.capacity_limit: Optional[str] = (capacity_limit or "unknown") if not_dispatched == "capacity" else None


# --- refused before anything was sent ----------------------------------------


class InvalidBaseURLError(PlimsollError, ValueError):
    """The base URL is not an absolute http or https URL without userinfo,
    query or fragment (Go: ``client.ErrInvalidBaseURL``)."""

    default_code = "invalid_argument"


class InvalidOptionError(PlimsollError, ValueError):
    """A client option is unusable: a token that is not visible ASCII, a request
    timeout that is not a positive finite number of seconds."""

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
    """Shed by one of the daemon's limits (Go: ``sandbox.ErrAtCapacity``).

    ``limit`` says which, as the daemon states it (Go: ``sandbox.CapacityLimitOf``):
    ``sessions`` (the daemon's session places are all taken), ``caller_sessions`` (this
    caller holds as many sessions as one caller may), ``owner_sessions`` (the open's
    owner is at its cap and every one of its sessions is running a call), ``runs`` (the
    daemon's runs in flight; a running session holds one), ``caller_runs`` (this
    caller's runs in flight), ``rate`` (this caller's runs per minute are spent),
    ``paid_seconds`` (today's paid seconds are spent), ``queue`` (a short line is full;
    retry shortly), ``provider`` (the provider's own capacity), or ``unknown`` (a daemon
    that does not state it, or a limit this client has no name for). The one limit not
    raised as this error is ``deadline`` (the call's own time ran out before any of it was
    sent): it comes with the context's code, so read it as ``capacity_limit`` on any
    :class:`PlimsollError`, which every capacity refusal carries. Closing one of the
    caller's own sessions frees a place for ``sessions`` and ``caller_sessions``, and may
    for ``runs`` and ``caller_runs``; for ``rate`` only time does.
    """

    default_code = "resource_exhausted"

    def __init__(self, message: str, *, limit: str = "unknown", **kwargs: Any) -> None:
        kwargs.setdefault("capacity_limit", limit)
        super().__init__(message, **kwargs)
        self.limit: str = limit


class SessionEndedError(PlimsollError):
    """A session call refused because its session has ended
    (Go: ``sandbox.SessionEndedError``).

    ``reason`` is why it ended: ``closed``, ``expired``, ``disk_exceeded``,
    ``main_process_ended``, ``boundary_failed``, ``sandbox_changed``, ``shutdown``,
    ``replaced``, ``not_found``, ``unclaimed`` or, for a number this client has no name
    for, ``unknown``. ``detail`` is the daemon's context, possibly empty.
    """

    default_code = "failed_precondition"

    def __init__(self, message: str, *, reason: str, detail: str = "", **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.reason = reason
        self.detail = detail


class StaleOwnerError(PlimsollError):
    """A session call or close carried an ownership generation that is no longer the
    session's: another worker took the session over with an attach. Refused, not
    dispatched; the session goes on for its new owner, and this worker must not use it."""

    default_code = "failed_precondition"


class RecoveringError(PlimsollError):
    """A call on a session that is recovering from a call whose answer was lost: a session
    taken over across that call (an attach that returned its record), or attached from a
    checkpoint saved while recovering. Every call is refused so, before anything is sent
    (``not_dispatched == "request"``), until the application has read the lost call
    (``Session.lost_call``) and called ``Session.resolve_lost_call()`` (Go:
    ``client.ErrRecovering``, in the same words). Never a retry signal: the lost call was
    sent once and may have run. The lost call's record says whether the daemon answered
    it: a result digest when it did, an unanswered code when it ended without an answer."""

    default_code = "failed_precondition"


class CheckpointMismatchError(PlimsollError):
    """An attach's saved checkpoint is not the daemon's head of the session: a call ran
    after the checkpoint was saved, its answer perhaps lost. Refused, not dispatched;
    ownership did not move."""

    default_code = "failed_precondition"


class HeadMismatchError(PlimsollError):
    """A session call the daemon refused before running anything, because the head this
    client sent (its generation, count of calls and last record) is not the session's:
    another holder of the session ran a call between this client's, or a bug (Go:
    ``client.ErrHeadMismatch``). ``head`` is the daemon's head as the refusal's detail
    states it (``generation``, ``calls``, ``last_record_sha256``), or None. The client
    tracks the head exactly, so the session stops here: it sends nothing more, and a
    close reports the daemon's count, which differs from this client's (ChainError)."""

    default_code = "failed_precondition"

    def __init__(self, message: str, *, head: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.head = head


# --- no Connect answer --------------------------------------------------------


class RequestCanceledError(PlimsollError):
    """A :class:`~plimsoll_client.CancelHandle` stopped the request (not asyncio's
    ``CancelledError``, which an awaiting task raises). Marked not dispatched, reason
    ``request``, when it stopped the request before any byte of it was sent; unmarked
    when it cut the request after that, since the daemon may have received it and run
    it."""

    default_code = "canceled"


class TransportError(PlimsollError):
    """No usable answer: the connection failed, or the response could not be
    read as a Connect answer. Marked not dispatched, reason ``environment``, only
    when it failed before any byte of the request could leave (a refused or
    hanging connect, a failed TLS handshake); otherwise unmarked, since the
    daemon may have received the request and run it."""

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


class AnswerNotBoundError(DataLossError):
    """A success answer did not carry this request's ``Plimsoll-Request-Id`` back: a
    daemon older than protocol 3, or something between that answered with another
    request's answer or dropped the header. The call may have run (Go:
    ``client.ErrAnswerNotBound`` under ``connect.CodeDataLoss``)."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("answer_not_bound", True)
        super().__init__(message, **kwargs)


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


# --- whether an automatic retry may run a call again ------------------------------

RETRY_REASONS: FrozenSet[str] = frozenset({"capacity", "environment"})
"""The not-dispatched reasons :func:`retry_on` retries. Every marked refusal ran
nothing, so a retry of any of them is safe; these two are the ones where another try
of the same call on the same daemon may pass. ``capacity``: admission or a rate limit
shed the run, and a later try may be admitted. ``environment``: the daemon could not be
reached before anything was sent (a refused or hanging connect, a failed TLS
handshake, a Describe that failed), its token verifier was unavailable, or a session's
sandbox could not be read back before the call (a call the docs say can be sent to the
same session again). The same reason also covers an image outside the caller's
software rule, which fails the same way each time: a retry then costs the policy's few
attempts and runs nothing. Not retried, because the same daemon answers the same way:
``request`` (a malformed request, a call cancelled before it was sent, a session that
has ended), ``permission``, ``protocol``, ``unsupported``, ``isolation`` (a stronger
backend is a placement decision, not a retry) and ``unknown`` (a reason this client
has no name for)."""


def retry_on(exc: BaseException) -> bool:
    """Whether a framework's automatic retry may run this call again.

    True only for a :class:`PlimsollError` that carries the not-dispatched mark with a
    reason in :data:`RETRY_REASONS`: nothing ran, and another try may pass. False for
    every unmarked error, after which the code may have run and a second run could
    repeat what it did; for every other refusal; and for every exception that is not a
    :class:`PlimsollError`. Pass it as ``RetryPolicy(retry_on=retry_on)`` (LangGraph)
    or ``ToolRetryMiddleware(retry_on=retry_on)`` (LangChain): both frameworks' own
    defaults retry a :class:`PlimsollError`, unmarked ones included."""
    reason = exc.not_dispatched if isinstance(exc, PlimsollError) else None
    return isinstance(reason, str) and reason in RETRY_REASONS
