"""Run-record digests and checks, ported from the Go package ``record``.

Every digest is lowercase hex SHA-256 over a length-prefixed encoding, never over
protobuf or JSON bytes (docs/run-records.md). The digests here are computed from
the JSON forms of the messages: the request exactly as this client sends it, the
response exactly as it was parsed.
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Iterable, Optional, Tuple

# The record's version, layouts and bounds, generated from the Go record and sandbox
# packages by internal/wiretables. VERSION is the encoding version this client computes and
# checks: every field, every time, for an answered call and an unanswered session call alike.
from ._tables import DAEMON_VERSION_PATTERN, INSTANCE_PATTERN, LAST_WALL_CLOCK_END_VERSION, MAX_DAEMON_VERSION_BYTES, MAX_QUALIFICATION_BYTES, QUALIFICATION_FORBIDDEN, RECORD_FIELDS, RETIRED_END_BEFORE_START_TEXT, TIERS, UNANSWERED_CODES
from ._tables import RECORD_VERSION as VERSION
from ._wire import INT32, INT64, OUTCOMES, UINT32, UINT64, Msg
from .errors import IsolationEvidenceMismatchError, MalformedResponseError, NoRecordError, RecordMismatchError, RecordVersionError, ResultKindMismatchError
from .types import RunRecord, SoftwareRule, meets


def _version_problem(version: int) -> str:
    """Why a live answer's record version is refused: a newer daemon (upgrade the client)
    or an older one. A live answer must carry the current version; it is never called
    forged."""
    if version > VERSION:
        return (f"plimsoll: a newer daemon answered with run record version {version}; "
                f"this client reads version {VERSION}: upgrade the client")
    return (f"plimsoll: the daemon answered with run record version {version}; "
            f"this client requires version {VERSION} of a live answer")


_INSTANCE_FORM = re.compile(INSTANCE_PATTERN)

# A control character, or a format character that breaks a line or shows text in another
# order than it is stored (record.ValidText), from the generated ranges: the one set every
# field a reader is shown is held to (the table's name is the qualification's, the first
# field it was written for).
_FORBIDDEN_IN_TEXT = re.compile("[" + "".join("\\U%08x-\\U%08x" % r for r in QUALIFICATION_FORBIDDEN) + "]")


def valid_text(s: str) -> bool:
    """Text a record may state where a reader is shown it as it is: UTF-8 with no control
    character and none of the format characters that break a line or reorder displayed
    text, as record.ValidText. The provider's name, the tier and the isolation qualification
    are held to it (shown_fields)."""
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate
        return False
    return _FORBIDDEN_IN_TEXT.search(s) is None


def shown_fields(r: RunRecord) -> Tuple[Tuple[str, str], ...]:
    """A record's fields a reader is shown as the run's evidence, each with the name a
    refusal gives it, as record.ShownFields."""
    return (("provider", r.provider), ("isolation", r.isolation), ("isolation qualification", r.isolation_qualification))


def valid_qualification(s: str) -> bool:
    """A record's isolation qualification: "" (the provider states none), or at most
    MAX_QUALIFICATION_BYTES of UTF-8 that valid_text accepts, as record.ValidQualification."""
    return valid_text(s) and len(s.encode("utf-8")) <= MAX_QUALIFICATION_BYTES


_DAEMON_VERSION_FORM = re.compile(DAEMON_VERSION_PATTERN)


def valid_daemon_version(s: str) -> bool:
    """A record's daemon version: "", "(devel)", or a module version such as "v0.28.0"
    or a pseudo-version, at most MAX_DAEMON_VERSION_BYTES (the grammar is ASCII, so
    characters are bytes), as record.ValidDaemonVersion."""
    return s == "" or (len(s) <= MAX_DAEMON_VERSION_BYTES and _DAEMON_VERSION_FORM.fullmatch(s) is not None)


def valid_instance(s: str) -> bool:
    """A record's instance: "" (the provider names none) or a typed reference such as
    ``k8s-pod-uid:`` and a pod's UID (sandbox.ValidInstance)."""
    return s == "" or _INSTANCE_FORM.fullmatch(s) is not None

_UNANSWERED_CODES = frozenset(UNANSWERED_CODES)


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
    # A protocol 1 request (the records of version 1) has the first encoding: no software rule.
    first = protocol < 2
    e = _Encoder("plimsoll.run-request.v1" if first else "plimsoll.run-request.v2")
    e.int("protocol", protocol)
    e.str("minimum_isolation", m.get_str("minimumIsolation"))
    e.int("timeout_ms", m.get_int("timeoutMs", INT32))
    if not first:
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


_RECORD_INTS = frozenset({"started_unix_ms", "ended_unix_ms", "sequence"})
_RECORD_BOOLS = frozenset({"warm"})
# What a record field holds when it states nothing, so a record of a version that does
# not cover a field can be told to state none (record.statesOnly).
_RECORD_UNSET = {"warm": False, "started_unix_ms": 0, "ended_unix_ms": 0, "sequence": 0}


def _states_only(r: RunRecord) -> None:
    """The fields a record's version does not cover are unset, it states a result digest
    or, for an unanswered call, an error code, exactly one, and the code is one of the
    closed set, its tier is one of TIERS (never "unknown" or empty, whatever floor the
    request named), it does not end before it starts, answered or not, its qualification
    and daemon version are in their bounds, and its instance is a typed reference
    (record.statesOnly); the digest is checked after. The record of a call lost across a
    takeover is checked by this alone, and an adapter tells a model whether that call
    finished from which of the two it states."""
    for name, text in shown_fields(r):
        if not isinstance(text, str) or not valid_text(text):
            raise RecordMismatchError(f"plimsoll: the record's {name} is not UTF-8 or holds a control or bidirectional format character")
    covered = RECORD_FIELDS.get(r.version, ())
    for name in RECORD_FIELDS[VERSION]:
        if name not in covered and getattr(r, name) != _RECORD_UNSET.get(name, ""):
            raise RecordMismatchError(f"plimsoll: a version {r.version} record does not cover {name}, so it cannot state one")
    unanswered = r.unanswered != ""
    if unanswered == (r.result_sha256 != ""):
        raise RecordMismatchError("plimsoll: a record states a result or, for an unanswered call, an error code, exactly one")
    if unanswered and r.unanswered not in _UNANSWERED_CODES:
        raise RecordMismatchError(f"plimsoll: an unanswered call's record names {r.unanswered!r}, not a Connect code")
    if r.isolation not in TIERS:
        raise RecordMismatchError(f"plimsoll: the record's isolation {r.isolation!r} is not a tier ({', '.join(TIERS)})")
    # A version 1 or 2 record that ends before it starts is refused as a retired reading, not
    # as a forgery (record.LastWallClockEndVersion, retired 2026-11-21).
    if r.ended_unix_ms < r.started_unix_ms and r.version <= LAST_WALL_CLOCK_END_VERSION:
        raise RecordMismatchError("plimsoll: " + RETIRED_END_BEFORE_START_TEXT)
    if r.ended_unix_ms < r.started_unix_ms:
        raise RecordMismatchError("plimsoll: the record ends before it starts")
    if not valid_instance(r.instance):
        raise RecordMismatchError(f"plimsoll: the record's instance {r.instance!r} is not a typed reference")
    if not valid_qualification(r.isolation_qualification):
        raise RecordMismatchError(f"plimsoll: the record's isolation qualification is over {MAX_QUALIFICATION_BYTES} bytes")
    if not valid_daemon_version(r.daemon_version):
        raise RecordMismatchError(f"plimsoll: the record's daemon version {r.daemon_version!r} is not a module version or (devel)")


def record_digest(r: RunRecord) -> str:
    """A record's own digest over the fields its version covers (RECORD_FIELDS; every
    field but ``sha256`` for an unknown version), as record.Digest. The version is the
    domain's suffix."""
    e = _Encoder("plimsoll.run-record.v%d" % r.version)
    for name in RECORD_FIELDS.get(r.version, RECORD_FIELDS[VERSION]):
        if name in _RECORD_INTS:
            e.int(name, getattr(r, name))
        elif name in _RECORD_BOOLS:
            e.bool(name, getattr(r, name))
        else:
            e.str(name, getattr(r, name))
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
        instance=m.get_str("instance"),
        isolation_qualification=m.get_str("isolationQualification"),
        warm=m.get_bool("warm"),
        daemon_version=m.get_str("daemonVersion"),
    )


def check(req_digest: str, kind: str, rule: Optional[SoftwareRule], resp: Msg) -> RunRecord:
    """Everything a record states that the caller can recompute (record.check):
    the version, that the result is of the request's kind, both digests, the
    evidence the response repeats, the software rule, the record's own digest and
    that it ends no earlier than it starts. The rule was validated before sending."""
    rec_msg = resp.get_msg("record")
    if rec_msg is None:
        raise NoRecordError("plimsoll: the response carries no run record")
    r = record_from_wire(rec_msg)
    result = result_digest(resp)
    if r.version != VERSION:
        raise RecordVersionError(_version_problem(r.version))
    if r.unanswered:
        raise RecordMismatchError("plimsoll: an answered call's record states an unanswered code")
    # The kind, inside the check as in Go's record.check since 2026-10-26: a result of
    # another kind fails here, before a session's chain moves on, so a daemon caught
    # answering the wrong kind is not used further (review, 2026-10-26).
    kinds = tuple(k for k in ("javascript", "project", "module", "cell") if resp.has(k))
    if len(kinds) > 1:
        raise MalformedResponseError(f"plimsoll: the answer holds {len(kinds)} results; a run has one")
    if kinds != (kind,):
        raise ResultKindMismatchError(f"plimsoll: the daemon answered a {kind} request with {kinds[0] if kinds else 'no'} result")
    if r.request_sha256 != req_digest:
        raise RecordMismatchError(f"plimsoll: request digest {r.request_sha256}, the request sent digests to {req_digest}")
    if r.result_sha256 != result:
        raise RecordMismatchError(f"plimsoll: result digest {r.result_sha256}, the result received digests to {result}")
    if r.provider != resp.get_str("sandbox") or r.isolation != resp.get_str("isolation"):
        raise RecordMismatchError(
            f"plimsoll: the record names {r.provider} at {r.isolation!r}, the response {resp.get_str('sandbox')} at {resp.get_str('isolation')!r}"
        )
    if r.environment != resp.get_str("environment"):
        raise RecordMismatchError("plimsoll: the record's environment differs from the response's")
    if r.instance != resp.get_str("instance") or not valid_instance(r.instance):
        raise RecordMismatchError(f"plimsoll: the record's instance {r.instance!r} is not the response's, or not a typed reference")
    if r.isolation_qualification != resp.get_str("isolationQualification"):
        raise RecordMismatchError("plimsoll: the record's isolation qualification is not the response's")
    if r.warm != resp.get_bool("warm"):
        raise RecordMismatchError(f"plimsoll: the record states warm {r.warm}, the response {resp.get_bool('warm')}")
    if r.daemon_version != resp.get_str("daemonVersion"):
        raise RecordMismatchError(f"plimsoll: the record's daemon version {r.daemon_version!r} is not the response's")
    _states_only(r)
    rule_id = rule.rule_id() if rule is not None else ""
    allowed = rule.allows(r.software_identity) if rule is not None else True
    if r.software_identity != resp.get_str("softwareIdentity") or r.software_rule_id != rule_id or not allowed:
        raise RecordMismatchError("plimsoll: the selected software or admission rule differs from the request and response")
    own = record_digest(r)
    if r.sha256 != own:
        raise RecordMismatchError(f"plimsoll: record digest {r.sha256}, its fields digest to {own}")
    return r


def check_unanswered(req_digest: str, floor: str, rule: Optional[SoftwareRule], m: Msg) -> RunRecord:
    """The record an unanswered session call's error carries (record.CheckUnanswered,
    without the chain, which the Session checks): the version, no result digest, a
    Connect code, the digest of the request sent, its software rule and that its
    software is in it, the record's own digest, and its tier against the call's floor."""
    r = record_from_wire(m)
    if r.version != VERSION:
        raise RecordVersionError(_version_problem(r.version))
    _states_only(r)
    if r.result_sha256 or r.unanswered not in _UNANSWERED_CODES:
        raise RecordMismatchError("plimsoll: an unanswered call's record states a result or no error code")
    if r.request_sha256 != req_digest:
        raise RecordMismatchError(f"plimsoll: request digest {r.request_sha256}, the request sent digests to {req_digest}")
    if r.software_rule_id != (rule.rule_id() if rule is not None else "") or (rule is not None and not rule.allows(r.software_identity)):
        raise RecordMismatchError("plimsoll: the record's software rule is not the request's, or its software is not in it")
    own = record_digest(r)
    if r.sha256 != own:
        raise RecordMismatchError(f"plimsoll: record digest {r.sha256}, its fields digest to {own}")
    if floor and not meets(r.isolation, floor):
        raise IsolationEvidenceMismatchError(
            f"plimsoll: the unanswered call's record states {r.isolation or 'unknown'}, below the call's minimum {floor}; execution may have occurred"
        )
    return r


def check_single(req_digest: str, kind: str, rule: Optional[SoftwareRule], resp: Msg) -> RunRecord:
    """check, for a single run: a single run's record carries no session fields (record.Check)."""
    r = check(req_digest, kind, rule, resp)
    if r.session or r.sequence or r.previous_sha256:
        raise RecordMismatchError("plimsoll: a single run's record carries session fields")
    return r
