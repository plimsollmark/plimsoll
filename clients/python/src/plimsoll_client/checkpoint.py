"""Session checkpoints and the store that holds them, so another process can carry on
with a session (:meth:`Client.attach_session`); Go's ``client.Checkpoint``.

A **checkpoint** is a session's public chain head (the ownership generation, the count of
calls and the last record's digest) and the policy the session stated at open. It holds
no secret: not the session ID, not a credential. Its JSON form is the one every official
client reads and writes (:meth:`SessionCheckpoint.to_json`).

A **checkpoint store** is where the application keeps them, under keys it derives from
identities it verified (never from model or user text). It must be one only the
application can write: anyone holding the caller's credential and a session's checkpoint
(or its run records, which carry the fingerprint and the head) can take the session over.
A session opened or attached with a store passes every call through it: before the call
the record is marked pending, after a checked answer it is ready at the new head, so two
workers never send at once and a worker that died mid-call leaves a record another can
take over from (the daemon decides, by comparing heads, whether that call ran).
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, fields
from typing import Any, Dict, Optional, Protocol

from ._record import valid_qualification
from ._tables import (
    CHECKPOINT_VERSION,
    DAEMON_NAME_PATTERN,
    FLOORS,
    MAX_SOFTWARE_IDENTITY_BYTES,
    SOFTWARE_IDENTITY_PATTERN,
    SOFTWARE_RULE_ID_PATTERN,
)

__all__ = [
    "SessionCheckpoint",
    "StoredCheckpoint",
    "CheckpointStore",
    "MemoryCheckpointStore",
    "CheckpointStoreError",
    "CheckpointConflictError",
    "CheckpointUnavailableError",
]

_DAEMON_NAME = re.compile(DAEMON_NAME_PATTERN)
_RULE_ID = re.compile(SOFTWARE_RULE_ID_PATTERN)
_IDENTITY = re.compile(SOFTWARE_IDENTITY_PATTERN)
_HEX64 = re.compile("[0-9a-f]{64}")
_DECIMAL = re.compile("0|[1-9][0-9]*")
_UINT64 = (1 << 64) - 1
_UINT32 = (1 << 32) - 1
_INT64 = (1 << 63) - 1


def _whole(v: Any, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _meets(tier: str, floor: str) -> bool:
    return not floor or FLOORS.index(tier) >= FLOORS.index(floor)


@dataclass(frozen=True)
class SessionCheckpoint:
    """A session's checkpoint (Go: ``client.Checkpoint``), the fields Go's has, in
    snake_case. Constructing one validates it (ValueError)."""

    version: int
    daemon: str
    """The application's own name for the daemon (``Client(daemon_name=...)``), never a URL."""
    session: str
    """The fingerprint: the SHA-256 of the session ID, 64 lowercase hex digits."""
    generation: int
    calls: int
    last_record_sha256: str
    provider: str
    isolation: str
    isolation_qualification: str
    software_identity: str
    open_floor: str
    """The floor sent at open, as the daemon echoed it; "" for none."""
    open_rule: str
    """The ID of the software rule sent at open, "" for none."""
    expires_unix_ms: int
    idle_timeout_ms: int
    lost_call_sha256: str = ""
    """The request digest of a call that was sent once with no answer reaching any worker (an
    attach explained the gap it left), which the session's next call is refused for
    repeating (CallAlreadySentError); "" for none. A checkpoint carries it until that next
    call, unless the daemon refused that call with the not-dispatched mark: nothing ran, so
    the call after it is still the next."""

    def __post_init__(self) -> None:
        problem = self._problem()
        if problem:
            raise ValueError(f"plimsoll: invalid session checkpoint: {problem}")

    def _problem(self) -> str:
        if not _whole(self.version, 0, _UINT32) or self.version != CHECKPOINT_VERSION:
            return "unknown version"
        if not isinstance(self.daemon, str) or not _DAEMON_NAME.fullmatch(self.daemon):
            return "the daemon name is not 1 to 64 of [A-Za-z0-9._-]"
        if not isinstance(self.session, str) or not _HEX64.fullmatch(self.session):
            return "the fingerprint is not 64 lowercase hex digits"
        if not _whole(self.generation, 1, _UINT64):
            return "the generation is not a positive 64-bit number"
        if not _whole(self.calls, 0, _UINT64) or not isinstance(self.last_record_sha256, str):
            return "the count of calls is not a 64-bit number"
        if (self.calls == 0) != (self.last_record_sha256 == "") or (self.calls and not _HEX64.fullmatch(self.last_record_sha256)):
            return "the last record does not match the count of calls"
        if not isinstance(self.provider, str) or not self.provider or len(self.provider.encode("utf-8", "surrogatepass")) > 256:
            return "the provider is empty or malformed"
        if self.isolation not in FLOORS:
            return "the tier is not one a session runs at"
        if not isinstance(self.isolation_qualification, str) or not valid_qualification(self.isolation_qualification):
            return "the isolation qualification is malformed"
        identity = self.software_identity
        if not isinstance(identity, str) or identity and (
            len(identity.encode("utf-8", "surrogatepass")) > MAX_SOFTWARE_IDENTITY_BYTES or not _IDENTITY.fullmatch(identity)
        ):
            return "the software identity is malformed"
        if self.open_floor != "" and self.open_floor not in FLOORS:
            return "the open floor is not a tier"
        if not _meets(self.isolation, self.open_floor):
            return "the tier is below the open floor"
        if not isinstance(self.open_rule, str) or self.open_rule and not _RULE_ID.fullmatch(self.open_rule):
            return "the open rule is not a software rule's ID"
        if not _whole(self.expires_unix_ms, 1, _INT64):
            return "the expiry is not a positive time"
        if not _whole(self.idle_timeout_ms, 0, _UINT32):
            return "the idle timeout is not a 32-bit number"
        if not isinstance(self.lost_call_sha256, str) or self.lost_call_sha256 and (
            not _HEX64.fullmatch(self.lost_call_sha256) or self.calls == 0
        ):
            return "the lost call is not a request digest of a call the session ran"
        return ""

    def to_json(self) -> str:
        """The JSON form every official client reads: every key, the generation and the
        count as decimal strings."""
        d: Dict[str, Any] = {f.name: getattr(self, f.name) for f in fields(self)}
        d["generation"] = str(self.generation)
        d["calls"] = str(self.calls)
        return json.dumps(d, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def from_json(cls, text: str) -> "SessionCheckpoint":
        """Reads the JSON form: one object holding every key and no other. Raises
        ValueError."""
        try:
            d = json.loads(text)
        except (TypeError, ValueError) as e:
            raise ValueError(f"plimsoll: invalid session checkpoint: {e}") from None
        names = [f.name for f in fields(cls)]
        if not isinstance(d, dict) or sorted(d) != sorted(names):
            raise ValueError("plimsoll: invalid session checkpoint: the object does not hold exactly the checkpoint's keys")
        for k in ("generation", "calls"):
            if not isinstance(d[k], str) or not _DECIMAL.fullmatch(d[k]):
                raise ValueError(f"plimsoll: invalid session checkpoint: {k} is not a decimal string with no leading zero")
            d[k] = int(d[k])
        return cls(**d)

    def __repr__(self) -> str:
        return f"SessionCheckpoint(daemon={self.daemon!r}, session={self.session[:12]!r}, generation={self.generation}, calls={self.calls})"


@dataclass(frozen=True)
class StoredCheckpoint:
    """One record of a checkpoint store. ``revision`` goes up by one on every write.
    ``state`` is ``"ready"`` or ``"pending"``: pending while a call of the session's is
    in progress, with ``operation`` a random ID naming it (``""`` when ready) and
    ``checkpoint`` the one from before the call. ``request_sha256`` is the pending call's
    request digest, ``""`` when ready or when the pending operation is a close."""

    revision: int
    state: str
    operation: str
    checkpoint: SessionCheckpoint
    request_sha256: str = ""

    def __post_init__(self) -> None:
        if not _whole(self.revision, 1, _INT64):
            raise ValueError("plimsoll: a stored checkpoint's revision is a positive number")
        if self.state not in ("ready", "pending") or (self.state == "ready") != (self.operation == ""):
            raise ValueError("plimsoll: a stored checkpoint is ready with no operation, or pending with one")
        if not isinstance(self.checkpoint, SessionCheckpoint):
            raise ValueError("plimsoll: a stored checkpoint holds a SessionCheckpoint")
        if self.request_sha256 and (self.state != "pending" or not _HEX64.fullmatch(self.request_sha256)):
            raise ValueError("plimsoll: only a pending call's record holds its request digest")


class CheckpointStore(Protocol):
    """Where an application keeps its sessions' checkpoints: storage only it can write,
    with an atomic compare-and-set. No timeout ever clears a pending record."""

    def load(self, key: str) -> Optional[StoredCheckpoint]:
        """The record under ``key``, or None."""
        ...

    def compare_and_set(self, key: str, expected: Optional[StoredCheckpoint], replacement: StoredCheckpoint) -> bool:
        """With ``expected`` None, store ``replacement`` only if ``key`` holds nothing;
        otherwise only if the stored record equals ``expected`` in full. True when it
        stored it."""
        ...


class MemoryCheckpointStore:
    """A CheckpointStore in this process's memory: a lock and a dict, for tests. It is
    not durable storage: it is gone with the process, so it cannot carry a session to
    another process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: Dict[str, StoredCheckpoint] = {}

    def load(self, key: str) -> Optional[StoredCheckpoint]:
        with self._lock:
            return self._records.get(key)

    def compare_and_set(self, key: str, expected: Optional[StoredCheckpoint], replacement: StoredCheckpoint) -> bool:
        if not isinstance(replacement, StoredCheckpoint):
            raise TypeError("the replacement must be a StoredCheckpoint")
        with self._lock:
            if self._records.get(key) != expected:
                return False
            self._records[key] = replacement
            return True


class CheckpointStoreError(RuntimeError):
    """The checkpoint store could not be written as this worker needed (it raised, or
    its compare-and-set failed). ``sent`` says whether the call it was for had been sent:
    False means nothing was sent and nothing ran. ``result`` is that call's result when
    it was answered, ``call_error`` its error when it raised one (an unanswered call
    whose record checked). After it the session sends nothing more; the store keeps
    whatever it held, so another worker decides by attaching."""

    def __init__(self, message: str, *, sent: bool, result: Any = None, call_error: Optional[BaseException] = None) -> None:
        super().__init__(message)
        self.sent = sent
        self.result = result
        self.call_error = call_error


class CheckpointConflictError(CheckpointStoreError):
    """The store's compare-and-set failed: another worker changed the record (it took the
    session over, or opened another session under the key)."""


class CheckpointUnavailableError(RuntimeError):
    """:meth:`Session.checkpoint` refused: the client has no daemon name, or the session
    is stopped, closed or ended."""
