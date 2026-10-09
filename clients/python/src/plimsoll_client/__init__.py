"""A Python client for plimsolld, the plimsoll sandbox daemon.

    from plimsoll_client import Client

    c = Client("http://127.0.0.1:8080", token="...")
    r = c.run_javascript("console.log(6*7)", minimum_isolation="container")
    print(r.stdout_text, r.isolation, r.record.sha256)

Standard library only. Every answered run's record is recomputed and checked, the
isolation floor is sent and the answer's tier checked against it, a session's
chain of records is followed call by call, and refusals come back as typed errors
that say whether anything ran. See README.md beside this package.
"""

from ._record import VERSION as RECORD_VERSION
from ._transport import MAX_RESPONSE_BYTES, CancelHandle
from ._version import __version__
from .aio import AsyncClient, AsyncSession
from .client import PROTOCOL, Client, Session
from .errors import (
    AnswerNotBoundError,
    AtCapacityError,
    ChainError,
    DataLossError,
    DisabledError,
    InsecureHTTPError,
    InsufficientIsolationError,
    InvalidBaseURLError,
    InvalidOptionError,
    InvalidRequestError,
    IsolationEvidenceMismatchError,
    MalformedResponseError,
    NoRecordError,
    PlimsollError,
    ProtocolMismatchError,
    RecordMismatchError,
    RecordVersionError,
    RequestCanceledError,
    RequestTimeoutError,
    ResponseTooLargeError,
    ResultKindMismatchError,
    SessionEndedError,
    SoftwareEvidenceMismatchError,
    SoftwareMismatchError,
    TransportError,
    UnsupportedError,
)
from .types import (
    CellResult,
    AdviceFinding,
    Artifact,
    Info,
    JavaScriptResult,
    ModuleResult,
    ModuleRun,
    PayloadEnvironment,
    ProjectResult,
    Resources,
    RunEvidence,
    RunRecord,
    SessionEnded,
    SessionSummary,
    SoftwareRule,
    StepResult,
    meets,
)

__all__ = [
    "CellResult",
    "__version__",
    "PROTOCOL",
    "RECORD_VERSION",
    "MAX_RESPONSE_BYTES",
    "Client",
    "Session",
    "AsyncClient",
    "AsyncSession",
    "CancelHandle",
    "SoftwareRule",
    "meets",
    "Info",
    "PayloadEnvironment",
    "Resources",
    "RunEvidence",
    "RunRecord",
    "AdviceFinding",
    "JavaScriptResult",
    "ProjectResult",
    "StepResult",
    "Artifact",
    "ModuleResult",
    "ModuleRun",
    "SessionEnded",
    "SessionSummary",
    "PlimsollError",
    "InvalidBaseURLError",
    "InvalidOptionError",
    "InsecureHTTPError",
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
    "AnswerNotBoundError",
    "RecordMismatchError",
    "NoRecordError",
    "RecordVersionError",
    "ChainError",
    "IsolationEvidenceMismatchError",
    "SoftwareEvidenceMismatchError",
    "ResultKindMismatchError",
]
