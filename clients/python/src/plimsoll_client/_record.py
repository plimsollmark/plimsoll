"""Run-record digests and checks, ported from the Go package ``record``.

Every digest is lowercase hex SHA-256 over a length-prefixed encoding, never over
protobuf or JSON bytes (docs/run-records.md). The digests here are computed from
the JSON forms of the messages: the request exactly as this client sends it, the
response exactly as it was parsed.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Iterable, Optional

from ._wire import INT32, INT64, OUTCOMES, UINT32, UINT64, Msg
from .errors import NoRecordError, RecordMismatchError, RecordVersionError
from .types import RunRecord, SoftwareRule

VERSION = 2
"""The record encoding version this client computes and checks (record.Version)."""

UNANSWERED_VERSION = 3
"""The record version of a session call that may have run but ended in an error
(record.UnansweredVersion): version 2's fields, then ``unanswered``."""

_UNANSWERED_CODES = frozenset((
    "canceled", "unknown", "invalid_argument", "deadline_exceeded", "not_found", "already_exists",
    "permission_denied", "resource_exhausted", "failed_precondition", "aborted", "out_of_range",
    "unimplemented", "internal", "unavailable", "data_loss", "unauthenticated",
))


class _Encoder:
    def __init__(self, domain: str) -> None:
        self._h = hashlib.sha256()
        self._value(domain.encode("utf-8"))

    def _value(self, b: bytes) -> None:
        self._h.update(struct.pack(">Q", len(b)))
        self._h.update(b)

    def bytes(self, name: str, v: bytes) -> None:
        self._value(name.encode("utf-8"))
        self._value(v)

    def str(self, name: str, v: str) -> None:
        self.bytes(name, v.encode("utf-8"))

    def int(self, name: str, v: int) -> None:
        self.str(name, "%d" % v)

    def bool(self, name: str, v: bool) -> None:
        self.str(name, "true" if v else "false")

    def floats(self, name: str, vs: Iterable[float]) -> None:
        self.bytes(name, b"".join(struct.pack(">d", v) for v in vs))

    def sum(self) -> str:
        return self._h.hexdigest()


def request_digest(req: dict) -> str:
    """The request digest of a Run request or a session call, from its JSON form.
    The trace ID and the session ID are left out (record.RunRequestDigest and
    record.SessionRunRequestDigest)."""
    m = Msg(req, "request")
    protocol = m.get_int("protocol", UINT32)
    e = _Encoder("plimsoll.run-request.v2" if protocol >= 2 else "plimsoll.run-request.v1")
    e.int("protocol", protocol)
    e.str("minimum_isolation", m.get_str("minimumIsolation"))
    e.int("timeout_ms", m.get_int("timeoutMs", INT32))
    if protocol >= 2:
        rule = m.get_msg("softwareRule")
        ids = rule.get_strs("identities") if rule else []
        e.str("software_mode", rule.get_str("mode") if rule else "")
        e.int("software_identities", len(ids))
        for i in ids:
            e.str("software_identity", i)
    js, project, module, cell = m.get_msg("javascript"), m.get_msg("project"), m.get_msg("module"), m.get_msg("cell")
    if js is not None:
        e.str("kind", "javascript")
        e.str("code", js.get_str("code"))
        e.str("grant_profile", js.get_str("grantProfile"))
    elif cell is not None:
        e.str("kind", "cell")
        e.str("language", cell.get_str("language"))
        e.str("code", cell.get_str("code"))
        files = cell.get_msgs("files")
        e.int("files", len(files))
        for f in files:
            e.str("file_path", f.get_str("path"))
            e.str("file_content", f.get_str("content"))
    elif project is not None:
        e.str("kind", "project")
        e.str("grant_profile", project.get_str("grantProfile"))
        files = project.get_msgs("files")
        e.int("files", len(files))
        for f in files:
            e.str("file_path", f.get_str("path"))
            e.str("file_content", f.get_str("content"))
        steps = project.get_strs("steps")
        e.int("steps", len(steps))
        for s in steps:
            e.str("step_command", s)
        artifacts = project.get_strs("artifacts")
        e.int("artifacts", len(artifacts))
        for a in artifacts:
            e.str("artifact_path", a)
    elif module is not None:
        e.str("kind", "module")
        e.str("model", module.get_str("model"))
        e.floats("end_time", [module.get_float("endTime")])
        e.floats("step", [module.get_float("step")])
        rows = module.get_msgs("rows")
        e.int("rows", len(rows))
        for r in rows:
            e.floats("row_values", r.get_floats("values"))
    else:
        e.str("kind", "")
    return e.sum()


def result_digest(resp: Msg) -> str:
    """The result digest of a RunResponse as received (record.ResultDigest):
    durations, advice and the evidence fields are left out."""
    e = _Encoder("plimsoll.run-result.v1")
    js, project, module, cell = resp.get_msg("javascript"), resp.get_msg("project"), resp.get_msg("module"), resp.get_msg("cell")
    if cell is not None:
        e.str("kind", "cell")
        e.int("exit_code", cell.get_int("exitCode", INT32))
        e.bool("timed_out", cell.get_bool("timedOut"))
        e.bytes("stdout", cell.get_bytes("stdout"))
        e.bytes("stderr", cell.get_bytes("stderr"))
        e.bool("stdout_truncated", cell.get_bool("stdoutTruncated"))
        e.bool("stderr_truncated", cell.get_bool("stderrTruncated"))
        e.bool("interpreter_started", cell.get_bool("interpreterStarted"))
        e.bool("interpreter_ended", cell.get_bool("interpreterEnded"))
    elif js is not None:
        e.str("kind", "javascript")
        e.int("exit_code", js.get_int("exitCode", INT32))
        e.bool("timed_out", js.get_bool("timedOut"))
        e.bytes("stdout", js.get_bytes("stdout"))
        e.bytes("stderr", js.get_bytes("stderr"))
        e.bool("stdout_truncated", js.get_bool("stdoutTruncated"))
        e.bool("stderr_truncated", js.get_bool("stderrTruncated"))
    elif project is not None:
        e.str("kind", "project")
        e.int("outcome", project.get_enum("outcome", OUTCOMES))
        e.str("outcome_detail", project.get_str("outcomeDetail"))
        e.bool("artifacts_truncated", project.get_bool("artifactsTruncated"))
        steps = project.get_msgs("steps")
        e.int("steps", len(steps))
        for s in steps:
            e.str("step_command", s.get_str("command"))
            e.int("step_exit_code", s.get_int("exitCode", INT32))
            e.bool("step_timed_out", s.get_bool("timedOut"))
            e.bytes("step_stdout", s.get_bytes("stdout"))
            e.bytes("step_stderr", s.get_bytes("stderr"))
            e.bool("step_stdout_truncated", s.get_bool("stdoutTruncated"))
            e.bool("step_stderr_truncated", s.get_bool("stderrTruncated"))
        artifacts = project.get_msgs("artifacts")
        e.int("artifacts", len(artifacts))
        for a in artifacts:
            e.str("artifact_path", a.get_str("path"))
            e.bytes("artifact_content", a.get_bytes("content"))
    elif module is not None:
        e.str("kind", "module")
        e.int("outcome", module.get_enum("outcome", OUTCOMES))
        e.str("outcome_detail", module.get_str("outcomeDetail"))
        e.int("width", module.get_int("width", INT32))
        e.bytes("stdout", module.get_bytes("stdout"))
        e.bytes("stderr", module.get_bytes("stderr"))
        runs = module.get_msgs("runs")
        e.int("runs", len(runs))
        for run in runs:
            e.int("run_status", run.get_int("status", INT32))
            e.floats("run_outputs", run.get_floats("outputs"))
    else:
        e.str("kind", "")
    return e.sum()


def record_digest(r: RunRecord) -> str:
    """A record's own digest over every field but ``sha256`` (record.Digest). The
    version is the domain's suffix."""
    e = _Encoder("plimsoll.run-record.v%d" % r.version)
    e.str("request_sha256", r.request_sha256)
    e.str("result_sha256", r.result_sha256)
    if r.version >= 3:
        e.str("unanswered", r.unanswered)
    e.str("provider", r.provider)
    e.str("isolation", r.isolation)
    e.str("environment", r.environment)
    e.str("policy", r.policy)
    if r.version >= 2:
        e.str("software_identity", r.software_identity)
        e.str("software_rule_id", r.software_rule_id)
    e.int("started_unix_ms", r.started_unix_ms)
    e.int("ended_unix_ms", r.ended_unix_ms)
    e.str("session", r.session)
    e.int("sequence", r.sequence)
    e.str("previous_sha256", r.previous_sha256)
    return e.sum()


def session_fingerprint(session_id: str) -> str:
    """The SHA-256 of a session ID, which a session call's record carries instead
    of the ID (record.SessionFingerprint)."""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def record_from_wire(m: Msg) -> RunRecord:
    return RunRecord(
        version=m.get_int("version", UINT32),
        request_sha256=m.get_str("requestSha256"),
        result_sha256=m.get_str("resultSha256"),
        provider=m.get_str("provider"),
        isolation=m.get_str("isolation"),
        environment=m.get_str("environment"),
        policy=m.get_str("policy"),
        software_identity=m.get_str("softwareIdentity"),
        software_rule_id=m.get_str("softwareRuleId"),
        started_unix_ms=m.get_int("startedUnixMs", INT64),
        ended_unix_ms=m.get_int("endedUnixMs", INT64),
        session=m.get_str("session"),
        sequence=m.get_int("sequence", UINT64),
        previous_sha256=m.get_str("previousSha256"),
        sha256=m.get_str("recordSha256"),
        unanswered=m.get_str("unanswered"),
    )


def check(req_digest: str, protocol: int, rule: Optional[SoftwareRule], resp: Msg) -> RunRecord:
    """Everything a record states that the caller can recompute (record.check):
    the version, both digests, the evidence the response repeats, the software
    rule and the record's own digest. The rule was validated before sending."""
    rec_msg = resp.get_msg("record")
    if rec_msg is None:
        raise NoRecordError("plimsoll: the response carries no run record")
    r = record_from_wire(rec_msg)
    result = result_digest(resp)
    if r.version not in (1, VERSION):
        raise RecordVersionError(f"plimsoll: unknown run record version {r.version} (this client knows 1 and {VERSION})")
    if protocol >= 2 and r.version != VERSION:
        raise RecordVersionError(f"plimsoll: protocol {protocol} requires record version {VERSION}, the record is version {r.version}")
    if r.version == 1 and (r.software_identity or r.software_rule_id):
        raise RecordMismatchError("plimsoll: a version 1 record cannot carry software admission fields")
    if r.request_sha256 != req_digest:
        raise RecordMismatchError(f"plimsoll: request digest {r.request_sha256}, the request sent digests to {req_digest}")
    if r.result_sha256 != result:
        raise RecordMismatchError(f"plimsoll: result digest {r.result_sha256}, the result received digests to {result}")
    if r.provider != resp.get_str("sandbox") or r.isolation != resp.get_str("isolation"):
        raise RecordMismatchError(
            f"plimsoll: the record names {r.provider} at {r.isolation!r}, the response {resp.get_str('sandbox')} at {resp.get_str('isolation')!r}"
        )
    if r.version >= 2 and r.environment != resp.get_str("environment"):
        raise RecordMismatchError("plimsoll: the record's environment differs from the response's")
    if r.version >= 2:
        rule_id = rule.rule_id() if rule is not None else ""
        allowed = rule.allows(r.software_identity) if rule is not None else True
        if r.software_identity != resp.get_str("softwareIdentity") or r.software_rule_id != rule_id or not allowed:
            raise RecordMismatchError("plimsoll: the selected software or admission rule differs from the request and response")
    own = record_digest(r)
    if r.sha256 != own:
        raise RecordMismatchError(f"plimsoll: record digest {r.sha256}, its fields digest to {own}")
    return r


def check_unanswered(req_digest: str, rule: Optional[SoftwareRule], m: Msg) -> RunRecord:
    """The record an unanswered session call's error carries (record.CheckUnanswered,
    without the chain, which the Session checks): version 3, no result digest, a
    Connect code, the digest of the request sent, its software rule and the record's
    own digest."""
    r = record_from_wire(m)
    if r.version != UNANSWERED_VERSION:
        raise RecordVersionError(f"plimsoll: an unanswered call's record is version {r.version}, not {UNANSWERED_VERSION}")
    if r.result_sha256 or r.unanswered not in _UNANSWERED_CODES:
        raise RecordMismatchError("plimsoll: an unanswered call's record states a result or no error code")
    if r.request_sha256 != req_digest:
        raise RecordMismatchError(f"plimsoll: request digest {r.request_sha256}, the request sent digests to {req_digest}")
    if r.software_rule_id != (rule.rule_id() if rule is not None else ""):
        raise RecordMismatchError("plimsoll: the record's software rule is not the request's")
    own = record_digest(r)
    if r.sha256 != own:
        raise RecordMismatchError(f"plimsoll: record digest {r.sha256}, its fields digest to {own}")
    return r


def check_single(req_digest: str, protocol: int, rule: Optional[SoftwareRule], resp: Msg) -> RunRecord:
    """check, for a single run: a single run's record carries no session fields (record.Check)."""
    r = check(req_digest, protocol, rule, resp)
    if r.session or r.sequence or r.previous_sha256:
        raise RecordMismatchError("plimsoll: a single run's record carries session fields")
    return r
