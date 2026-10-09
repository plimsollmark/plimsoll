"""Results and descriptions, mirroring the Go client's types (package sandbox).

Guest output is ``bytes``: a guest can print any byte sequence, and the run
record's digest covers the exact bytes. The ``*_text`` properties decode it as
UTF-8 with invalid sequences replaced.

Durations and times coming back from the daemon are whole milliseconds, as on the
wire (``duration_ms``, ``started_unix_ms``); durations a caller passes in are
seconds, as elsewhere in Python.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal, Optional, Tuple

__all__ = [
    "Isolation",
    "Floor",
    "TIERS",
    "meets",
    "SoftwareRule",
    "RunRecord",
    "AdviceFinding",
    "RunEvidence",
    "JavaScriptResult",
    "StepResult",
    "Artifact",
    "ProjectResult",
    "ModuleRun",
    "ModuleResult",
    "PayloadEnvironment",
    "Resources",
    "Info",
    "SessionEnded",
    "SessionSummary",
]

Isolation = Literal["none", "process", "container", "kernel", "vm"]
"""An isolation tier, weakest first: how strong the walls around a run are."""

Floor = Literal["process", "container", "kernel", "vm"]
"""A request's floor: the weakest tier it accepts."""

TIERS: Tuple[str, ...] = ("none", "process", "container", "kernel", "vm")


def meets(actual: str, floor: str) -> bool:
    """Whether a tier the daemon stated is at least ``floor``. A tier this client
    does not know (including an empty one) meets nothing."""
    if actual not in TIERS or floor not in TIERS:
        return False
    return TIERS.index(actual) >= TIERS.index(floor)


@dataclass(frozen=True)
class SoftwareRule:
    """A caller's rule for the software a run may execute on: one exact image
    identity, or 1 to 32 approved ones. An identity names a selected image
    manifest with its platform, for example
    ``oci-manifest:linux/amd64@sha256:<digest>``. No rule is ``None``."""

    mode: Literal["exact", "approved"]
    identities: Tuple[str, ...]

    @classmethod
    def exact(cls, identity: str) -> "SoftwareRule":
        return cls("exact", (identity,))

    @classmethod
    def approved(cls, *identities: str) -> "SoftwareRule":
        return cls("approved", tuple(identities))

    def rule_id(self) -> str:
        """The ID a run record states: ``exact:<identity>`` for one identity,
        otherwise ``approved:sha256:`` over the identities sorted in byte order
        and joined by a zero byte."""
        if len(self.identities) == 1:
            return "exact:" + self.identities[0]
        ids = sorted(i.encode("utf-8") for i in self.identities)
        return "approved:sha256:" + hashlib.sha256(b"\x00".join(ids)).hexdigest()

    def allows(self, identity: str) -> bool:
        """An empty identity never satisfies a rule."""
        return identity != "" and identity in self.identities


@dataclass(frozen=True)
class RunRecord:
    """The daemon's statement of one run, checked by this client: digests of the
    request as sent and the result as returned, the evidence it ran under, when,
    and for a session call its place in the session's chain. The field meanings
    are in docs/run-records.md. ``sha256`` is the record's own digest."""

    version: int
    request_sha256: str
    result_sha256: str
    provider: str
    isolation: str
    environment: str
    policy: str
    software_identity: str
    software_rule_id: str
    started_unix_ms: int
    ended_unix_ms: int
    session: str
    sequence: int
    previous_sha256: str
    sha256: str
    unanswered: str = ""
    """On a version 3 record, the Connect code of the error a session call that may
    have run ended with (``result_sha256`` is then empty); "" when answered."""


@dataclass(frozen=True)
class AdviceFinding:
    """One efficiency observation about a run's brokered host-API calls. Advisory
    only: it never changed the run."""

    pattern: str
    severity: str
    remedy: str
    method: str
    route: str
    detail: str
    suggested_method: str
    suggested_route: str
    extra_calls: int
    added_latency_ms: int
    bytes_moved: int


@dataclass(frozen=True, kw_only=True)
class RunEvidence:
    """What every answered run states besides its result. Configuration and
    provider evidence, never runtime attestation."""

    provider: str
    """The provider that ran it (the wire's ``sandbox``)."""
    isolation: str
    """The tier the run executed behind, as the daemon states it."""
    environment: str
    """The exact outer image or interpreter selected, when stated."""
    software_identity: str
    """The selected executable image manifest, when the provider establishes it."""
    duration_ms: int
    """Wall time as the daemon measured it."""
    record: Optional[RunRecord]
    """The checked run record. ``None`` only on a result attached to an error
    whose record did not check."""


def _text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


@dataclass(frozen=True, kw_only=True)
class JavaScriptResult(RunEvidence):
    """A snippet's result. A non-zero exit code is a normal result: the guest's
    code failed."""

    stdout: bytes
    stderr: bytes
    exit_code: int
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    advice: Tuple[AdviceFinding, ...]

    @property
    def stdout_text(self) -> str:
        return _text(self.stdout)

    @property
    def stderr_text(self) -> str:
        return _text(self.stderr)


@dataclass(frozen=True, kw_only=True)
class CellResult(RunEvidence):
    """A cell's result: code run in the session's interpreter, which keeps what
    earlier cells defined. ``exit_code`` is 0 when the code ran, 1 when it raised
    (the error is on stderr) and 124 when the call's deadline ended it; a final
    expression's value is printed to stdout, as a notebook shows it."""

    stdout: bytes
    stderr: bytes
    exit_code: int
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    interpreter_started: bool
    """This call started a fresh interpreter: nothing an earlier cell defined exists."""
    interpreter_ended: bool
    """The interpreter ended during this call; the next cell starts a fresh one."""

    @property
    def stdout_text(self) -> str:
        return _text(self.stdout)

    @property
    def stderr_text(self) -> str:
        return _text(self.stderr)


@dataclass(frozen=True)
class StepResult:
    """One project step."""

    command: str
    stdout: bytes
    stderr: bytes
    exit_code: int
    timed_out: bool
    duration_ms: int
    stdout_truncated: bool
    stderr_truncated: bool

    @property
    def stdout_text(self) -> str:
        return _text(self.stdout)

    @property
    def stderr_text(self) -> str:
        return _text(self.stderr)


@dataclass(frozen=True)
class Artifact:
    """A file a project run captured."""

    path: str
    content: bytes


@dataclass(frozen=True, kw_only=True)
class ProjectResult(RunEvidence):
    """A project's result. ``outcome`` is how the run concluded: ``completed``,
    ``setup_failed``, ``timed_out``, ``protocol_error``, or ``unspecified`` for
    a value this client does not know. Per-step failures are in ``steps``."""

    outcome: str
    detail: str
    steps: Tuple[StepResult, ...]
    artifacts: Tuple[Artifact, ...]
    artifacts_truncated: bool
    advice: Tuple[AdviceFinding, ...]


@dataclass(frozen=True)
class ModuleRun:
    """One parameter row's result: ``status`` is the number of steps completed, or
    the model's or worker's negative code when the row failed; ``outputs`` holds
    ``width`` values per completed step, step-major."""

    status: int
    outputs: Tuple[float, ...]


@dataclass(frozen=True, kw_only=True)
class ModuleResult(RunEvidence):
    """A module run's result: one entry in ``runs`` per request row when the
    outcome is ``completed``."""

    runs: Tuple[ModuleRun, ...]
    width: int
    outcome: str
    detail: str
    stdout: bytes
    stderr: bytes

    @property
    def stdout_text(self) -> str:
        return _text(self.stdout)

    @property
    def stderr_text(self) -> str:
        return _text(self.stderr)


@dataclass(frozen=True)
class PayloadEnvironment:
    """Where one payload kind runs, as the daemon states it. ``languages`` are the
    interpreters its startup checks proved (``"javascript"``, ``"python"``): the
    languages a project's steps can invoke, and in a session the languages a cell may
    use."""

    identity: str
    software_identity: str
    max_timeout_ms: int
    languages: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Resources:
    """The per-run resource envelope the operator configured; 0 means the
    provider's default."""

    memory_mb: int
    cpus: float
    pids: int
    disk_mb: int


@dataclass(frozen=True)
class Info:
    """What ``Describe`` states: the active provider, its tier, the protocol
    number the daemon serves, and static operation support. Informational:
    configuration and provider evidence, never attestation."""

    provider: str
    isolation: str
    protocol: int
    supports_project: bool
    supports_module: bool
    supports_javascript_grants: bool
    supports_project_grants: bool
    supports_sessions: bool
    session_lifetime_ms: int
    session_idle_timeout_ms: int
    session_environment: PayloadEnvironment
    """Where a session's calls run (on docker the project image), stated with
    ``supports_sessions``; informational, like the other environments."""
    javascript_environment: PayloadEnvironment
    project_environment: PayloadEnvironment
    module_environment: PayloadEnvironment
    policy: str
    resources: Resources
    max_sessions_per_caller: int = 0
    max_sessions_per_owner: int = 0
    """The daemon's caps on this caller's sessions and on one owner's of them
    (``open_session(owner=...)``), 0 when there is none."""


@dataclass(frozen=True)
class SessionEnded:
    """Why a session ended: ``closed``, ``expired``, ``disk_exceeded``,
    ``main_process_ended``, ``boundary_failed``, ``sandbox_changed``,
    ``shutdown`` or ``replaced`` (the daemon closed it for a newer session of the same
    owner), with the daemon's detail."""

    reason: str
    detail: str


@dataclass(frozen=True)
class SessionSummary:
    """What closing a session states: the session's fingerprint, how many calls it
    executed, the last call's record digest (empty when there were none), and why
    it ended."""

    session: str
    calls: int
    last_record_sha256: str
    end: str
