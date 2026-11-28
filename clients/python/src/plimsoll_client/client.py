"""The plimsolld client: Connect's JSON protocol over HTTP/1.1, standard library only.

It keeps the official Go client's promises (package ``client``): it states the
protocol number on every request, checks every run record against what it sent
and what it received, checks the isolation evidence against the caller's floor,
restores the daemon's not-dispatched mark and session end, and tracks a session's
chain of records so a call it did not make is caught.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets
import ssl
import threading
from dataclasses import replace
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from . import _validate as v
from ._record import VERSION as RECORD_VERSION_LIVE
from ._record import (
    _states_only,
    check,
    files_answers,
    files_op,
    check_lost_answer,
    check_single,
    check_unanswered,
    record_digest,
    record_from_wire,
    request_digest,
    session_fingerprint,
)
from ._tables import CHECKPOINT_VERSION, DAEMON_NAME_PATTERN, RECOVERING_TEXT
from ._tables import FILES_ENTRY_TYPE_NAMES, FILES_ENTRY_TYPES, FILES_ERROR_NAMES, FILES_ERRORS, FILES_SCOPE_NAMES, FILES_SCOPES
from ._transport import CancelHandle, Transport
from .checkpoint import (
    CheckpointConflictError,
    CheckpointStore,
    CheckpointStoreError,
    CheckpointUnavailableError,
    SessionCheckpoint,
    StoredCheckpoint,
)
from ._wire import (
    INT32,
    INT64,
    OUTCOME_NAMES,
    OUTCOMES,
    SESSION_END_NAMES,
    SESSION_ENDS,
    UINT32,
    UINT64,
    Msg,
    b64encode,
)
from . import files as fs
from .errors import (
    ChainError,
    DataLossError,
    HeadMismatchError,
    PlimsollError,
    InvalidOptionError,
    IsolationEvidenceMismatchError,
    MalformedResponseError,
    ProtocolMismatchError,
    RecordMismatchError,
    RecoveringError,
    ResultKindMismatchError,
    SessionEndedError,
    SoftwareEvidenceMismatchError,
    StaleOwnerError,
)
from .types import (
    CellResult,
    AdviceFinding,
    Artifact,
    Info,
    JavaScriptResult,
    LostCall,
    ModuleResult,
    ModuleRun,
    PayloadEnvironment,
    ProjectResult,
    Resources,
    RunRecord,
    SessionEnded,
    SessionSummary,
    SoftwareRule,
    StepResult,
    TIERS,
    meets,
)

# PROTOCOL is the wire protocol number this client speaks (Go: protocol.Number, generated
# by internal/wiretables). It is stated on every request; a daemon serving another number
# refuses the request before reading its payload.
from ._tables import PROTOCOL

__all__ = ["PROTOCOL", "Client", "Session"]

DEFAULT_REQUEST_TIMEOUT = 360.0
"""Seconds one HTTP exchange may take: the Go client's six minutes, above the
daemon's five-minute ceiling on a run."""

# --- mapping answers to results -------------------------------------------------


def _outcome(n: int) -> str:
    return OUTCOME_NAMES[n] if 0 <= n < len(OUTCOME_NAMES) else "unspecified"


def _advice(m: Msg) -> Tuple[AdviceFinding, ...]:
    return tuple(
        AdviceFinding(
            pattern=f.get_str("pattern"),
            severity=f.get_str("severity"),
            remedy=f.get_str("remedy"),
            method=f.get_str("method"),
            route=f.get_str("route"),
            detail=f.get_str("detail"),
            suggested_method=f.get_str("suggestedMethod"),
            suggested_route=f.get_str("suggestedRoute"),
            extra_calls=f.get_int("extraCalls", INT32),
            added_latency_ms=f.get_int("addedLatencyMs", INT64),
            bytes_moved=f.get_int("bytesMoved", INT64),
        )
        for f in m.get_msgs("advice")
    )


def _evidence(resp: Msg) -> Dict[str, Any]:
    return {
        "provider": resp.get_str("sandbox"),
        "isolation": resp.get_str("isolation"),
        "isolation_qualification": resp.get_str("isolationQualification"),
        "environment": resp.get_str("environment"),
        "software_identity": resp.get_str("softwareIdentity"),
        "instance": resp.get_str("instance"),
        "duration_ms": resp.get_int("durationMs", INT64),
        "record": None,
    }


def _javascript_result(resp: Msg, j: Msg) -> JavaScriptResult:
    return JavaScriptResult(
        stdout=j.get_bytes("stdout"),
        stderr=j.get_bytes("stderr"),
        exit_code=j.get_int("exitCode", INT32),
        timed_out=j.get_bool("timedOut"),
        stdout_truncated=j.get_bool("stdoutTruncated"),
        stderr_truncated=j.get_bool("stderrTruncated"),
        advice=_advice(j),
        **_evidence(resp),
    )


def _project_result(resp: Msg, p: Msg) -> ProjectResult:
    return ProjectResult(
        outcome=_outcome(p.get_enum("outcome", OUTCOMES)),
        detail=p.get_str("outcomeDetail"),
        steps=tuple(
            StepResult(
                command=s.get_str("command"),
                stdout=s.get_bytes("stdout"),
                stderr=s.get_bytes("stderr"),
                exit_code=s.get_int("exitCode", INT32),
                timed_out=s.get_bool("timedOut"),
                duration_ms=s.get_int("durationMs", INT64),
                stdout_truncated=s.get_bool("stdoutTruncated"),
                stderr_truncated=s.get_bool("stderrTruncated"),
            )
            for s in p.get_msgs("steps")
        ),
        artifacts=tuple(Artifact(path=a.get_str("path"), content=a.get_bytes("content")) for a in p.get_msgs("artifacts")),
        artifacts_truncated=p.get_bool("artifactsTruncated"),
        advice=_advice(p),
        **_evidence(resp),
    )


def _module_result(resp: Msg, m: Msg) -> ModuleResult:
    return ModuleResult(
        runs=tuple(ModuleRun(status=r.get_int("status", INT32), outputs=tuple(r.get_floats("outputs"))) for r in m.get_msgs("runs")),
        width=m.get_int("width", INT32),
        outcome=_outcome(m.get_enum("outcome", OUTCOMES)),
        detail=m.get_str("outcomeDetail"),
        stdout=m.get_bytes("stdout"),
        stderr=m.get_bytes("stderr"),
        **_evidence(resp),
    )


def _cell_result(resp: Msg, c: Msg) -> CellResult:
    return CellResult(
        stdout=c.get_bytes("stdout"),
        stderr=c.get_bytes("stderr"),
        exit_code=c.get_int("exitCode", INT32),
        timed_out=c.get_bool("timedOut"),
        stdout_truncated=c.get_bool("stdoutTruncated"),
        stderr_truncated=c.get_bool("stderrTruncated"),
        interpreter_started=c.get_bool("interpreterStarted"),
        interpreter_ended=c.get_bool("interpreterEnded"),
        warm=resp.get_bool("warm"),
        **_evidence(resp),
    )


def _name(names: Tuple[str, ...], n: int) -> str:
    return names[n] if 0 <= n < len(names) else "unknown"


def _files_result(resp: Msg, f: Msg) -> fs.FilesResult:
    """A file call's result; paths and contents stay bytes."""
    answer: Optional[fs.FilesAnswer] = None
    op = ""
    stat, read, write, listing, read_many = f.get_msg("stat"), f.get_msg("read"), f.get_msg("write"), f.get_msg("list"), f.get_msg("readMany")
    if stat is not None:
        op = "stat"
        answer = fs.FilesStatAnswer(
            type=_name(FILES_ENTRY_TYPE_NAMES, stat.get_enum("type", FILES_ENTRY_TYPES)), size=stat.get_int("size", UINT64), mode=stat.get_int("mode", UINT32)
        )
    elif read is not None:
        op = "read"
        answer = fs.FilesReadAnswer(content=read.get_bytes("content"), size_at_open=read.get_int("sizeAtOpen", UINT64))
    elif write is not None:
        op = "write"
        answer = fs.FilesWriteAnswer(written=write.get_int("written", UINT64))
    elif listing is not None:
        op = "list"
        answer = fs.FilesListAnswer(
            entries=tuple(
                fs.FilesEntry(path=e.get_bytes("path"), type=_name(FILES_ENTRY_TYPE_NAMES, e.get_enum("type", FILES_ENTRY_TYPES)), size=e.get_int("size", UINT64))
                for e in listing.get_msgs("entries")
            ),
            more=listing.get_bool("more"),
        )
    elif read_many is not None:
        op = "read_many"
        answer = fs.FilesReadManyAnswer(
            items=tuple(
                fs.FilesItem(
                    error=_name(FILES_ERROR_NAMES, it.get_enum("error", FILES_ERRORS)),
                    errno=it.get_str("errno"),
                    content=it.get_bytes("content"),
                    size_at_open=it.get_int("sizeAtOpen", UINT64),
                )
                for it in read_many.get_msgs("items")
            ),
            more=read_many.get_bool("more"),
        )
    else:
        op = next(iter(files_answers(f)), "")  # make_dir, remove or rename: an empty answer, a JSON object
    return fs.FilesResult(
        outcome=_outcome(f.get_enum("outcome", OUTCOMES)),
        error=_name(FILES_ERROR_NAMES, f.get_enum("error", FILES_ERRORS)),
        errno=f.get_str("errno"),
        op=op,
        answer=answer,
        **_evidence(resp),
    )


_MAPPERS: Dict[str, Callable[[Msg, Msg], Any]] = {
    "javascript": _javascript_result,
    "project": _project_result,
    "module": _module_result,
    "cell": _cell_result,
    "files": _files_result,
}


def _kinds(resp: Msg) -> Tuple[str, ...]:
    return tuple(k for k in ("javascript", "project", "module", "cell", "files") if resp.has(k))


_FILES_SCOPES = {"work": "FILES_SCOPE_WORK", "sandbox": "FILES_SCOPE_SANDBOX"}
_FILES_WRITE_MODES = {"replace": "FILES_WRITE_MODE_REPLACE", "create_only": "FILES_WRITE_MODE_CREATE_ONLY", "append": "FILES_WRITE_MODE_APPEND"}


def _files_payload(op: Any) -> Dict[str, Any]:
    """A file operation's wire form (FilesRun): paths and contents as bytes, base64 in the
    JSON, never decoded or normalized. A malformed operation is refused before anything is
    sent; the daemon checks the paths themselves (their scope, their parts, their length)."""

    def path(p: Any, what: str) -> str:
        try:
            return b64encode(fs.path_bytes(p))
        except TypeError:
            raise v.invalid(f"the file call's {what} is bytes or str") from None

    def flag(b: Any, what: str) -> bool:
        if not isinstance(b, bool):
            raise v.invalid(f"the file call's {what} is a bool")
        return b

    def number(n: Any, what: str, top: int) -> int:
        if isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= top:
            raise v.invalid(f"the file call's {what} is an integer from 0 to {top}")
        return n

    if not isinstance(op, (fs.FilesStat, fs.FilesRead, fs.FilesWrite, fs.FilesList, fs.FilesReadMany, fs.FilesMakeDir, fs.FilesRemove, fs.FilesRename)):
        raise v.invalid(f"a file call's operation is one of plimsoll_client.files' operations, not {type(op).__name__}")
    scope = _FILES_SCOPES.get(op.scope) if isinstance(op.scope, str) else None
    if scope is None:
        raise v.invalid("the file call's scope is work or sandbox")
    out: Dict[str, Any] = {"scope": scope}
    u32, u64 = UINT32[1], UINT64[1]
    if isinstance(op, fs.FilesStat):
        out["stat"] = {"path": path(op.path, "path")}
    elif isinstance(op, fs.FilesRead):
        out["read"] = {"path": path(op.path, "path"), "offset": str(number(op.offset, "offset", u64)), "maxBytes": number(op.max_bytes, "max_bytes", u32)}
    elif isinstance(op, fs.FilesWrite):
        mode = _FILES_WRITE_MODES.get(op.mode) if isinstance(op.mode, str) else None
        if mode is None:
            raise v.invalid("the file call's write mode is replace, create_only or append")
        if not isinstance(op.content, (bytes, bytearray, memoryview)):
            raise v.invalid("the file call's content is bytes")
        out["write"] = {"path": path(op.path, "path"), "content": b64encode(bytes(op.content)), "mode": mode, "makeParents": flag(op.make_parents, "make_parents")}
    elif isinstance(op, fs.FilesList):
        out["list"] = {
            "path": path(op.path, "path"),
            "recursive": flag(op.recursive, "recursive"),
            "match": path(op.match, "match"),
            "after": path(op.after, "after"),
            "budgetBytes": number(op.budget_bytes, "budget_bytes", u32),
        }
    elif isinstance(op, fs.FilesReadMany):
        if not isinstance(op.paths, (list, tuple)):
            raise v.invalid("the file call's paths are a list or tuple of paths")
        out["readMany"] = {
            "paths": [path(p, "paths") for p in op.paths],
            "maxBytesEach": number(op.max_bytes_each, "max_bytes_each", u32),
            "budgetBytes": number(op.budget_bytes, "budget_bytes", u32),
        }
    elif isinstance(op, fs.FilesMakeDir):
        out["makeDir"] = {"path": path(op.path, "path"), "parents": flag(op.parents, "parents")}
    elif isinstance(op, fs.FilesRemove):
        out["remove"] = {"path": path(op.path, "path"), "dir": flag(op.dir, "dir")}
    else:
        out["rename"] = {"fromPath": path(op.from_path, "from_path"), "toPath": path(op.to_path, "to_path"), "replace": flag(op.replace, "replace")}
    return out


def _finish(
    kind: str,
    resp: Msg,
    check_record: Callable[[], RunRecord],
    floor: str,
) -> Any:
    """Maps a run's answer and applies the client's checks in the Go client's
    order: the result is of the request's kind, its record checks, and the tier
    it states meets the floor. A failed check raises with the result attached."""
    record_error: Optional[DataLossError] = None
    rec: Optional[RunRecord] = None
    try:
        rec = check_record()
    except DataLossError as e:
        record_error = e
    kinds = _kinds(resp)
    if len(kinds) > 1:
        raise MalformedResponseError(f"plimsoll: the answer holds {len(kinds)} results; a run has one")
    payload = resp.get_msg(kind)
    if kinds != (kind,) or payload is None:
        raise ResultKindMismatchError(
            f"plimsoll: the daemon answered a {kind} request with {kinds[0] if kinds else 'no'} result"
        )
    result = _MAPPERS[kind](resp, payload)
    if record_error is not None:
        record_error.result = result
        raise record_error
    result = replace(result, record=rec)
    if floor and not meets(result.isolation, floor):
        raise IsolationEvidenceMismatchError(
            f"plimsoll: result isolation {result.isolation or 'unknown'} is below the requested minimum {floor}; execution may have occurred",
            result=result,
        )
    return result


def _payload_environment(m: Optional[Msg]) -> PayloadEnvironment:
    if m is None:
        return PayloadEnvironment(identity="", software_identity="", max_timeout_ms=0)
    return PayloadEnvironment(
        identity=m.get_str("identity"),
        software_identity=m.get_str("softwareIdentity"),
        max_timeout_ms=m.get_int("maxTimeoutMs", UINT32),
        languages=tuple(m.get_strs("languages")),
    )


def _stronger(a: str, b: str) -> str:
    """The stronger of two validated floors ("" is none): a session's calls carry the
    floor given at open unless the call asks for more."""
    if not a or not b:
        return a or b
    return a if TIERS.index(a) >= TIERS.index(b) else b


def _envelope(
    timeout: Optional[float],
    minimum_isolation: Optional[str],
    rule: Optional[SoftwareRule],
    trace_id: Optional[str],
) -> Dict[str, Any]:
    env: Dict[str, Any] = {"protocol": PROTOCOL}
    floor = v.floor(minimum_isolation)
    if floor:
        env["minimumIsolation"] = floor
    tid = v.trace_id(trace_id)
    if tid:
        env["traceId"] = tid
    ms = v.timeout_ms(timeout)
    if ms:
        env["timeoutMs"] = ms
    wire_rule = v.rule_wire(rule)
    if wire_rule is not None:
        env["softwareRule"] = wire_rule
    return env


def _javascript_payload(code: str, grant_profile: Optional[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"code": v.code(code)}
    profile = v.grant_profile(grant_profile)
    if profile:
        out["grantProfile"] = profile
    return out


def _project_payload(files: v.FilesArg, steps: Sequence[str], artifacts: Sequence[str], grant_profile: Optional[str]) -> Dict[str, Any]:
    out = v.project(files, steps, artifacts)
    profile = v.grant_profile(grant_profile)
    if profile:
        out["grantProfile"] = profile
    return out


# --- the client -------------------------------------------------------------------


def _owner_digest(token: Optional[str], owner: str) -> str:
    """What an owner is sent as: hex(HMAC-SHA256(key = SHA-256("plimsoll session
    owner key v2\\n" + the client's token), message = "plimsoll session owner v2\\n"
    + owner)), the same in every official client, so the processes of one app agree
    on a user. The daemon stores only a token's SHA-256, so it cannot test a guessed
    name against a digest; without a token anyone can. The key is derived, not the
    token itself: HMAC replaces a key longer than 64 bytes with its SHA-256, which for
    a long imported token is exactly the token_sha256 the clients file holds."""
    key = hashlib.sha256(("plimsoll session owner key v2\n" + (token or "")).encode("utf-8")).digest()
    msg = ("plimsoll session owner v2\n" + owner).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


class Client:
    """A client for one plimsolld.

    ``base_url`` is the daemon's absolute http or https URL. Cleartext http is
    accepted only to a loopback host (``localhost``, ``127.0.0.0/8``, ``::1``)
    unless ``insecure_http=True``, a development-only opt-in: without it the
    bearer token and the submitted code would cross the network unencrypted.
    ``token`` is a bearer token with the ``code:run`` scope; omit it for a
    development daemon without authentication. ``request_timeout`` bounds each
    HTTP exchange, in seconds. ``ssl_context`` replaces the default certificate
    verification, for a daemon whose certificate a private authority issued.

    A Client holds no connection between calls and may be shared by threads.
    """

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        *,
        insecure_http: bool = False,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        ssl_context: Optional[ssl.SSLContext] = None,
        daemon_name: Optional[str] = None,
    ) -> None:
        url = v.validate_base_url(base_url, insecure_http)
        # The application's own name for this daemon, never a URL: a session's checkpoint
        # states it, and attach_session takes only a checkpoint that names it, so a
        # checkpoint read from a store can only reach a daemon the application configured.
        if daemon_name is not None and (not isinstance(daemon_name, str) or not _DAEMON_NAME.fullmatch(daemon_name)):
            raise InvalidOptionError("plimsoll: daemon_name is 1 to 64 of [A-Za-z0-9._-], never a URL")
        self.daemon_name: Optional[str] = daemon_name
        # Visible ASCII only, as an HTTP bearer value: a token http.client cannot encode
        # would surface as a UnicodeEncodeError carrying the whole header, token
        # included. The message never repeats the token.
        if token is not None and (not isinstance(token, str) or not all(0x21 <= ord(c) <= 0x7E for c in token)):
            raise InvalidOptionError("plimsoll: the token must be a str of visible ASCII characters")
        if isinstance(request_timeout, bool) or not isinstance(request_timeout, (int, float)) or not 0 < request_timeout < math.inf:
            raise InvalidOptionError("plimsoll: request_timeout must be a positive, finite number of seconds")
        self.base_url = url
        self._transport = Transport(url, token or None, float(request_timeout), ssl_context)

    def __repr__(self) -> str:
        return f"Client({self.base_url!r})"

    def describe(self, *, cancel: Optional[CancelHandle] = None) -> Info:
        """What the daemon states about itself. Raises ProtocolMismatchError,
        with the description attached as ``info``, when the daemon serves another
        protocol number than this client speaks: every request would be refused.
        ``cancel`` stops the request from another thread (:class:`CancelHandle`)."""
        m = self._transport.call("Describe", {}, "DescribeResponse", cancel)
        res = m.get_msg("resources")
        info = Info(
            provider=m.get_str("sandbox"),
            isolation=m.get_str("isolation"),
            protocol=m.get_int("protocol", UINT32),
            supports_project=m.get_bool("supportsProject"),
            supports_module=m.get_bool("supportsModule"),
            supports_javascript_grants=m.get_bool("supportsJavascriptGrants"),
            supports_project_grants=m.get_bool("supportsProjectGrants"),
            supports_sessions=m.get_bool("supportsSessions"),
            session_lifetime_ms=m.get_int("sessionLifetimeMs", UINT32),
            session_idle_timeout_ms=m.get_int("sessionIdleTimeoutMs", UINT32),
            session_environment=_payload_environment(m.get_msg("sessionEnvironment")),
            max_sessions_per_caller=m.get_int("maxSessionsPerCaller", UINT32),
            max_sessions_per_owner=m.get_int("maxSessionsPerOwner", UINT32),
            session_pool=m.get_int("sessionPool", UINT32),
            isolation_qualification=m.get_str("isolationQualification"),
            javascript_environment=_payload_environment(m.get_msg("javascriptEnvironment")),
            project_environment=_payload_environment(m.get_msg("projectEnvironment")),
            module_environment=_payload_environment(m.get_msg("moduleEnvironment")),
            policy=m.get_str("policy"),
            resources=Resources(
                memory_mb=res.get_int("memoryMb", UINT32) if res else 0,
                cpus=res.get_float("cpus") if res else 0.0,
                pids=res.get_int("pids", UINT32) if res else 0,
                disk_mb=res.get_int("diskMb", UINT32) if res else 0,
            ),
        )
        if info.protocol != PROTOCOL:
            raise ProtocolMismatchError(
                f"plimsoll: the daemon serves protocol {info.protocol} and this client speaks {PROTOCOL}",
                info=info,
                not_dispatched="protocol",
            )
        return info

    def run_javascript(
        self,
        code: str,
        *,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        grant_profile: Optional[str] = None,
        trace_id: Optional[str] = None,
        cancel: Optional[CancelHandle] = None,
    ) -> JavaScriptResult:
        """Runs a JavaScript snippet in a fresh sandbox.

        ``timeout`` is the run's whole budget in seconds (the daemon defaults and
        clamps it). ``minimum_isolation`` is the weakest tier the run accepts,
        checked by the daemon before dispatch and by this client on the answer.
        ``software`` requires the selected software to be in a rule.
        ``grant_profile`` names a host-API capability configured on the daemon;
        without one the run has no network. ``trace_id`` is an opaque correlation
        ID for the daemon's audit line, 1 to 64 characters of ``[A-Za-z0-9._:-]``.
        ``cancel`` stops the request from another thread (:class:`CancelHandle`):
        before it is sent, nothing runs and the error says so; once it may have
        been sent, the connection is cut and the error is unmarked.
        """
        rule = v.software_rule(software)
        req = _envelope(timeout, minimum_isolation, rule, trace_id)
        req["javascript"] = _javascript_payload(code, grant_profile)
        return self._run("javascript", req, rule, cancel)

    def run_project(
        self,
        files: v.FilesArg,
        steps: Sequence[str],
        artifacts: Sequence[str] = (),
        *,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        grant_profile: Optional[str] = None,
        trace_id: Optional[str] = None,
        cancel: Optional[CancelHandle] = None,
    ) -> ProjectResult:
        """Writes ``files`` (a mapping of relative path to text, or a list of
        ``(path, text)`` pairs, sent in that order) into a fresh sandbox and runs
        ``steps``, shell commands, in order, stopping at the first that fails.
        ``artifacts`` are relative paths to capture and return. The other
        arguments are as for :meth:`run_javascript`."""
        rule = v.software_rule(software)
        req = _envelope(timeout, minimum_isolation, rule, trace_id)
        req["project"] = _project_payload(files, steps, artifacts, grant_profile)
        return self._run("project", req, rule, cancel)

    def run_module(
        self,
        model: str,
        rows: Sequence[Sequence[float]],
        *,
        end_time: float,
        step: float,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        trace_id: Optional[str] = None,
        cancel: Optional[CancelHandle] = None,
    ) -> ModuleResult:
        """Runs a compiled simulator built into the daemon's module image once per
        parameter row, each instance stepping from 0 to ``end_time`` with
        communication step ``step``. Only some providers run modules
        (``Info.supports_module``)."""
        rule = v.software_rule(software)
        req = _envelope(timeout, minimum_isolation, rule, trace_id)
        req["module"] = v.module(model, rows, end_time, step)
        return self._run("module", req, rule, cancel)

    def _run(self, kind: str, req: Dict[str, Any], rule: Optional[SoftwareRule], cancel: Optional[CancelHandle]) -> Any:
        digest = request_digest(req)
        resp = self._transport.call("Run", req, "RunResponse", cancel)
        floor = req.get("minimumIsolation", "")
        return _finish(kind, resp, lambda: check_single(digest, kind, rule, resp), floor)

    def run_cell(
        self,
        code: str,
        language: str = "python",
        *,
        files: v.FilesArg = None,
        prefer_warm: bool = False,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        trace_id: Optional[str] = None,
        cancel: Optional[CancelHandle] = None,
    ) -> CellResult:
        """Runs ``code`` by itself as a cell for an interpreter of ``language``
        (``"python"`` or ``"javascript"``): ``files`` are written into its work
        directory first and its final expression's value is printed, in a sandbox of
        its own that keeps nothing after the call (``interpreter_started`` and
        ``interpreter_ended`` are both true). Files under ``.plimsoll/``, where the
        code and its runner go, are refused.

        ``prefer_warm`` lets the daemon run it in a sandbox it keeps ready for
        sessions (``Info.session_pool``): one that has run only plimsoll's own
        programs, with the interpreter already running, claimed for this call alone
        and deleted after it, so the call answers without a sandbox being made for
        it. When none fits it runs in a sandbox made for it, as without the flag, so
        a miss is never a refusal; the result's ``warm`` says which ran. What it
        costs: a pool member runs the cell in the session image (on docker the
        project image, which a fresh cell uses too), in a sandbox that waited with
        plimsoll's interpreters in it. The record is a single run's either way, and
        does not cover ``warm``. The other arguments are as for
        :meth:`run_javascript`."""
        if not isinstance(prefer_warm, bool):
            raise TypeError("prefer_warm must be a bool")
        rule = v.software_rule(software)
        req = _envelope(timeout, minimum_isolation, rule, trace_id)
        if prefer_warm:
            req["preferWarm"] = True
        req["cell"] = v.cell(language, code, files)
        return self._run("cell", req, rule, cancel)

    def open_session(
        self,
        *,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        lifetime: Optional[float] = None,
        idle_timeout: Optional[float] = None,
        trace_id: Optional[str] = None,
        languages: Optional[Sequence[str]] = None,
        owner: Optional[str] = None,
        warm_only: bool = False,
        keep_no_answer: bool = False,
        checkpoint_store: Optional[CheckpointStore] = None,
        checkpoint_key: Optional[str] = None,
    ) -> "Session":
        """Opens a session: one sandbox kept for many calls, in which the files a
        call writes persist for later calls and no process a call starts outlives
        it. Only on a daemon whose ``describe()`` states ``supports_sessions``.

        ``minimum_isolation`` and ``software`` apply to the whole session and are
        checked again on the session the daemon opened. ``lifetime`` and
        ``idle_timeout`` (seconds) may only shorten the daemon's own.
        ``languages`` names the languages the session's cells will use: a hint, so
        a daemon with a warm pool hands over a sandbox with those interpreters
        already running; a cell in any language the daemon states still runs.
        ``owner`` names the end user the session is for (an account ID, an
        email), so a daemon with a per-owner cap (``SANDBOX_MAX_SESSIONS_PER_OWNER``)
        keeps each user to it across every process of the app: at the cap it
        closes that user's least recently used session with no call in progress.
        It never leaves this process: the daemon gets a digest keyed by this
        client's token (:func:`_owner_digest`). ``warm_only`` asks for a waiting
        pool member or nothing: with none to hand over the open is refused, not
        dispatched, reason ``capacity``, and no sandbox is made, so the caller can run
        fresh instead; it never closes another session of the owner to make room.
        A daemon that predates ``warm_only`` would have ignored it and made a
        sandbox, so it came with protocol 5, which such a daemon refuses before
        reading the open. A cell for one call needs no session of its own:
        :meth:`run_cell` with ``prefer_warm``.

        ``keep_no_answer`` asks the daemon to keep no call's answer. By default it keeps the
        last answered call's answer in memory, until the next call starts or the session
        suspends or ends, so that a worker taking the session over across that call's lost
        answer gets it back (``Session.lost_call``). Set it when the application promises
        its users that the daemon retains no output; it holds for the whole session.

        ``checkpoint_store`` and ``checkpoint_key`` (both or neither, and the client's
        ``daemon_name`` with them) keep the session's checkpoint in the store under the
        key, so another process can carry on with it (:meth:`attach_session`); every call
        then passes through the store (:mod:`plimsoll_client.checkpoint`). A key that
        already holds a record closes the new session and raises
        CheckpointConflictError.
        Use it as a context manager, or call :meth:`Session.close`."""
        store, key = self._store_args(checkpoint_store, checkpoint_key)
        rule = v.software_rule(software)
        hint = v.languages(languages)
        req: Dict[str, Any] = {"protocol": PROTOCOL}
        if hint:
            req["languages"] = hint
        if not isinstance(warm_only, bool):
            raise TypeError("warm_only must be a bool")
        if warm_only:
            req["warmOnly"] = True
        if not isinstance(keep_no_answer, bool):
            raise TypeError("keep_no_answer must be a bool")
        if keep_no_answer:
            req["keepNoAnswer"] = True
        if owner is not None:
            if not isinstance(owner, str):
                raise TypeError("owner must be a string")
            if not owner:
                # An empty owner would send none, and the per-owner cap would silently
                # not apply; the TypeScript client refuses it the same way.
                raise v.invalid("owner must not be empty; omit it for a session with no owner")
            req["owner"] = _owner_digest(self._transport.token, owner)
        floor = v.floor(minimum_isolation)
        if floor:
            req["minimumIsolation"] = floor
        tid = v.trace_id(trace_id)
        if tid:
            req["traceId"] = tid
        life = v.duration_ms(lifetime, "lifetime")
        if life:
            req["lifetimeMs"] = life
        idle = v.duration_ms(idle_timeout, "idle_timeout")
        if idle:
            req["idleTimeoutMs"] = idle
        wire_rule = v.rule_wire(rule)
        if wire_rule is not None:
            req["softwareRule"] = wire_rule
        m = self._transport.call("OpenSession", req, "OpenSessionResponse")
        session_id = m.get_str("sessionId")
        s = Session(self._transport, session_id, m, rule, floor, self.daemon_name)
        if s._generation != 1:
            # Every daemon opens a session at generation 1, so that is the number its
            # close must carry, whatever this answer said.
            s._generation = 1
            s._close_quietly()  # the session exists on the daemon either way; nothing else holds its ID
            raise ChainError("plimsoll: the daemon's answer to the open states an ownership generation other than 1; the session was closed")
        if s.fingerprint != session_fingerprint(session_id):
            s._close_quietly()  # the session exists on the daemon either way; nothing else holds its ID
            raise ChainError("plimsoll: the daemon's session fingerprint does not match its session ID; the session was closed")
        if m.get_str("minimumIsolation") != floor or _wire_rule_id(m.get_msg("softwareRule")) != (rule.rule_id() if rule else ""):
            # The floor and rule the daemon keeps for the session are what an attach answer
            # repeats and a checkpoint states, so they must be the ones sent.
            s._close_quietly()
            raise ChainError("plimsoll: the daemon's answer to the open states another floor or software rule than the open sent; the session was closed")
        if floor and not meets(s.isolation, floor):
            s._close_quietly()
            raise IsolationEvidenceMismatchError(
                f"plimsoll: the session opened at {s.isolation or 'unknown'}, below the requested minimum {floor}; the session was closed"
            )
        if rule is not None and not rule.allows(s.software_identity):
            s._close_quietly()
            raise SoftwareEvidenceMismatchError(
                "plimsoll: the session's selected software is outside the requested rule; the session was closed"
            )
        if store is not None and key is not None:
            first = StoredCheckpoint(revision=1, state="ready", operation="", checkpoint=s.checkpoint())
            try:
                taken = not store.compare_and_set(key, None, first)
            except Exception as e:
                s._close_quietly()
                raise CheckpointStoreError("plimsoll: the checkpoint store failed at the open; the session was closed", sent=False) from e
            if taken:
                s._close_quietly()
                raise CheckpointConflictError("plimsoll: the checkpoint key already holds a session; the new session was closed", sent=False)
            s._bind(store, key, first)
        return s

    def _store_args(self, store: Optional[CheckpointStore], key: Optional[str]) -> Tuple[Optional[CheckpointStore], Optional[str]]:
        if (store is None) != (key is None):
            raise v.invalid("checkpoint_store and checkpoint_key go together")
        if store is None:
            return None, None
        if not isinstance(key, str) or not key:
            raise v.invalid("checkpoint_key must be a non-empty string")
        if not self.daemon_name:
            raise v.invalid("a checkpoint store needs the client's daemon_name")
        return store, key

    def attach_session(
        self,
        key: str,
        *,
        store: CheckpointStore,
        fingerprint: Optional[str] = None,
        trace_id: Optional[str] = None,
        cancel: Optional[CancelHandle] = None,
    ) -> "Session":
        """Takes over the session whose checkpoint ``store`` holds under ``key`` and
        carries its chain on (Go: ``Remote.AttachSession``): the daemon raises the
        session's ownership generation by one, and every call or close a worker holding
        an older one sends is refused before it runs (StaleOwnerError). The returned
        session passes every call through the store.

        ``fingerprint``, when given, is the session the application means: a stored
        record that names another raises LookupError with nothing sent. It is checked
        on the record the attach sends, so a store that changed after the application
        last read it never moves another session to this worker.

        It sends the stored checkpoint whether the record is ready or pending: a worker
        that died mid-call leaves a pending record with the checkpoint from before its
        call, and the daemon compares that with its head under the session's turn. If the
        daemon never dispatched the call, the heads match and the attach succeeds. If it
        dispatched it, the heads differ by that one call, which the pending record names,
        so the daemon takes the session over across it (the explained gap) and returns
        its record, and its answer when the daemon still keeps it, both checked here. The
        session is then recovering (``Session.lost_call``): every call is refused before
        it is sent (RecoveringError) until the application has read the lost call and
        called ``Session.resolve_lost_call()``. The lost call's record says whether the
        daemon answered it: a result digest when it did, an unanswered code when the call
        ended without an answer. A stored checkpoint saved while recovering makes the
        attached session recovering too, with the lost call's request digest alone. Any
        other difference is refused (CheckpointMismatchError).

        A missing record raises LookupError: it never becomes a fresh session. A
        checkpoint naming another daemon than this client's ``daemon_name`` is refused
        before anything is sent. The daemon refuses an unknown, ended or another caller's
        session as not found, and open development mode refuses every attach. A refusal
        leaves the store as it was. The answer must repeat the checkpoint exactly, else
        ChainError, and the session is not closed: a bad answer gives this client no right
        to destroy a session another worker may be using. A transport failure or a cancel
        after sending is raised as it is and never retried: the daemon may have raised
        the generation.

        The daemon holds the session for this worker once the attach is answered, so the
        store is written after it even when its record changed meanwhile, provided the
        record it now holds names the same session at no later generation than the one
        attached from: only an attach raises the generation, so such a record was written
        by a worker the daemon now refuses as stale (one whose call was refused between this
        worker's read and its write, finding release-60), and the session would otherwise be
        held by nobody until its lifetime ended. A record at a later generation, of another
        session, or gone raises CheckpointConflictError, and the attached session is
        dropped, not closed."""
        if not self.daemon_name:
            raise v.invalid("attach_session needs the client's daemon_name")
        if not isinstance(key, str) or not key:
            raise v.invalid("the checkpoint key must be a non-empty string")
        if fingerprint is not None and (not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint)):
            raise v.invalid("fingerprint must be a session fingerprint: 64 lowercase hex digits")
        loaded = store.load(key)
        if loaded is None:
            raise LookupError("plimsoll: the checkpoint store holds no session under this key")
        if not isinstance(loaded, StoredCheckpoint):
            raise TypeError("the checkpoint store's load must return a StoredCheckpoint or None")
        cp = loaded.checkpoint
        if cp.daemon != self.daemon_name:
            raise v.invalid("the checkpoint names another daemon than this client's daemon_name")
        if fingerprint is not None and cp.session != fingerprint:
            raise LookupError("plimsoll: the checkpoint store holds another session under this key than the one named; nothing was sent")
        req: Dict[str, Any] = {
            "protocol": PROTOCOL,
            "session": cp.session,
            "checkpoint": {"generation": str(cp.generation), "calls": str(cp.calls), "lastRecordSha256": cp.last_record_sha256},
        }
        # A pending record names its call: if the daemon dispatched that call and no answer
        # reached the worker that sent it, the daemon takes the session over across the gap
        # it left (the explained gap) and returns its record; if the daemon never dispatched
        # it, the heads match.
        lost = loaded.request_sha256 if loaded.state == "pending" else ""
        if lost:
            req["lostRequestSha256"] = lost
        tid = v.trace_id(trace_id)
        if tid:
            req["traceId"] = tid
        m = self._transport.call("AttachSession", req, "AttachSessionResponse", cancel)
        s = self._attached(cp, m, lost)
        expected = loaded
        for _ in range(_ATTACH_WRITE_TRIES):
            ready = StoredCheckpoint(revision=expected.revision + 1, state="ready", operation="", checkpoint=s.checkpoint())
            try:
                moved = store.compare_and_set(key, expected, ready)
                now = None if moved else store.load(key)
            except Exception as e:
                raise CheckpointStoreError("plimsoll: the checkpoint store failed after the attach; the attached session is dropped", sent=True) from e
            if moved:
                s._bind(store, key, ready)
                return s
            # A record a stale worker wrote since the read (the same session, at no later
            # generation than the one attached from) is replaced: the daemon holds the
            # session for this worker now. Anything else is another worker's.
            if not isinstance(now, StoredCheckpoint) or now.checkpoint.session != cp.session or now.checkpoint.generation > cp.generation:
                break
            expected = now
        raise CheckpointConflictError(
            "plimsoll: another worker took the session over, or the store's record under this key changed to another session, "
            "while this worker attached; the attached session is dropped (the daemon moved the session to this worker, and the "
            "store names another holder)",
            sent=True,
        )

    def _attached(self, cp: SessionCheckpoint, m: Msg, lost: str = "") -> "Session":
        """The attached session, once the answer repeats the checkpoint exactly, or carries
        the record of the call ``lost`` names at the checkpoint's next place and a head
        after it, and beside it, when the daemon kept it, that call's answer, which must
        carry the same record and a result whose digest is the record's; else ChainError,
        with nothing closed. A lost call's answer with no lost record is refused the same
        way."""
        info, head = m.get_msg("sessionInfo"), m.get_msg("checkpoint")
        lost_msg, answer_msg = m.get_msg("lostRecord"), m.get_msg("lostAnswer")
        recovering: Optional[LostCall] = LostCall(request_sha256=cp.recovering_request_sha256) if cp.recovering_request_sha256 else None
        problem = ""
        if answer_msg is not None and lost_msg is None:
            problem = "carries a lost call's answer without the lost call's record"
        calls, last = cp.calls, cp.last_record_sha256
        if lost_msg is not None and not problem:
            lost_call, problem = _lost_record(cp, lost, lost_msg)
            if lost_call is not None:
                answer: Any = None
                if answer_msg is not None:
                    answer, problem = _lost_answer(answer_msg, lost_call)
                recovering = LostCall(request_sha256=lost_call.request_sha256, record=lost_call, answer=answer)
                calls, last = lost_call.sequence, lost_call.sha256
        if not problem and (info is None or head is None):
            problem = "lacks the session or its checkpoint"
        elif not problem and info is not None and head is not None:
            session_id = info.get_str("sessionId")
            generation = info.get_int("generation", UINT64)
            if info.get_str("session") != cp.session or session_fingerprint(session_id) != cp.session:
                problem = "names another session, or a session ID whose SHA-256 is not the fingerprint"
            elif generation != cp.generation + 1 or head.get_int("generation", UINT64) != generation:
                problem = "states a generation other than one past the checkpoint's"
            elif head.get_int("calls", UINT64) != calls or head.get_str("lastRecordSha256") != last:
                problem = "states another chain head than the checkpoint's (or, across an explained gap, than the lost call's)"
            elif (info.get_str("sandbox"), info.get_str("isolation"), info.get_str("isolationQualification"), info.get_str("softwareIdentity")) != (
                cp.provider, cp.isolation, cp.isolation_qualification, cp.software_identity
            ):
                problem = "states another provider, tier, qualification or software than the session stated at open"
            elif info.get_str("minimumIsolation") != cp.open_floor or _wire_rule_id(info.get_msg("softwareRule")) != cp.open_rule:
                problem = "states another floor or software rule than the session was opened with"
            elif info.get_int("expiresUnixMs", INT64) != cp.expires_unix_ms or info.get_int("idleTimeoutMs", UINT32) != cp.idle_timeout_ms:
                problem = "states another lifetime or idle timeout than the session's"
        if problem:
            raise ChainError(f"plimsoll: the daemon's answer to the attach {problem}; the session was left as it is")
        assert info is not None
        wire_rule = info.get_msg("softwareRule")
        rule = SoftwareRule(wire_rule.get_str("mode"), tuple(wire_rule.get_strs("identities"))) if wire_rule is not None and cp.open_rule else None  # type: ignore[arg-type]
        s = Session(self._transport, info.get_str("sessionId"), info, rule, cp.open_floor, self.daemon_name)
        s._calls, s._last = calls, last
        s._recovering = recovering
        return s


_DAEMON_NAME = re.compile(DAEMON_NAME_PATTERN)
_FINGERPRINT = re.compile("[0-9a-f]{64}")
# How many times an attach writes its record over one a stale worker wrote meanwhile: a
# stale worker writes at most two (its call's pending record, then the ready one after the
# refusal), and every later write it tries fails, since the store then holds this one's.
_ATTACH_WRITE_TRIES = 4


def _lost_record(cp: SessionCheckpoint, lost: str, m: Msg) -> Tuple[Optional[RunRecord], str]:
    """The record an attach answer returns for the call the attach named (``lost``), once
    it is a live record that checks on its own, of the session ``cp`` names, at cp's next
    place in the chain, carrying the named request digest and the evidence the session
    stated at open; else what differs."""
    if not lost:
        return None, "carries a lost call's record, but the attach named no lost call"
    r = record_from_wire(m)
    if r.version != RECORD_VERSION_LIVE:
        return None, f"carries a lost call's record of version {r.version}, not the live version {RECORD_VERSION_LIVE}"
    try:
        _states_only(r)
    except PlimsollError as e:
        return None, f"carries a lost call's record that does not check ({e.message})"
    if record_digest(r) != r.sha256:
        return None, "carries a lost call's record whose own digest does not match"
    if r.session != cp.session or r.sequence != cp.calls + 1 or r.previous_sha256 != cp.last_record_sha256:
        return None, "carries a lost call's record that is not the checkpoint's next call"
    if r.request_sha256 != lost:
        return None, "carries the record of another call than the one the attach named"
    if (r.provider, r.isolation, r.software_identity, r.isolation_qualification) != (
        cp.provider, cp.isolation, cp.software_identity, cp.isolation_qualification
    ):
        return None, "carries a lost call's record stating other evidence than the session stated at open"
    return r, ""


def _lost_answer(m: Msg, lost: RunRecord) -> Tuple[Any, str]:
    """The result of a lost call's answer an attach returned (``m``), once it checks against
    the lost call's record ``lost`` (_record.check_lost_answer), carrying that record; else
    what differs."""
    try:
        check_lost_answer(m, lost)
        kind = _kinds(m)[0]
        payload = m.get_msg(kind)
        assert payload is not None
        return replace(_MAPPERS[kind](m, payload), record=lost), ""
    except PlimsollError as e:
        return None, f"carries a lost call's answer that does not check against its record ({e.message})"


def _wire_rule_id(m: Optional[Msg]) -> Optional[str]:
    """The ID of a software rule in its wire form, "" for none, None when it is not a
    rule this client accepts."""
    if m is None:
        return ""
    mode, ids = m.get_str("mode"), tuple(m.get_strs("identities"))
    if not mode and not ids:
        return ""
    try:
        rule = v.software_rule(SoftwareRule(mode, ids))  # type: ignore[arg-type]
    except PlimsollError:
        return None
    return rule.rule_id() if rule is not None else ""


class Session:
    """An open session on a daemon. Calls are serialized here as they are on the
    daemon, so the chain this client tracks follows the daemon's: a record that
    does not continue it means someone else holding the session ID made a call
    (ChainError). The session ID is a capability: it is sent to the daemon and
    appears nowhere else, not in ``repr`` and not in errors.

    A call's ``cancel`` handle, cancelled before the call is sent (while it waits
    for an earlier call to finish, say), refuses it with nothing sent and the
    session unchanged. Cancelled once the call may have been sent, it cuts the
    connection: the call may have run, so, as after any call left without an
    answer, the session sends nothing more (open a new one; closing this one
    reports the daemon's count)."""

    def __init__(
        self, transport: Transport, session_id: str, m: Msg, rule: Optional[SoftwareRule], floor: str = "", daemon: Optional[str] = None
    ) -> None:
        self._transport = transport
        self._id = session_id
        self._generation = m.get_int("generation", UINT64)
        self._rule = rule  # the rule given at open
        self._floor = floor  # the floor given at open, sent with every call
        self._daemon = daemon  # the client's daemon_name, which a checkpoint states
        self.fingerprint: str = m.get_str("session")
        """The SHA-256 of the session ID, as the session's records carry it."""
        self.provider: str = m.get_str("sandbox")
        self.isolation: str = m.get_str("isolation")
        """The tier the daemon measured when the session opened."""
        self.isolation_qualification: str = m.get_str("isolationQualification")
        """The sentence the provider states beside that tier, "" when it states none. Every
        call's record states it too."""
        self.software_identity: str = m.get_str("softwareIdentity")
        self.expires_unix_ms: int = m.get_int("expiresUnixMs", INT64)
        self.idle_timeout_ms: int = m.get_int("idleTimeoutMs", UINT32)
        self.file_scopes: Tuple[str, ...] = m.get_enum_set("fileScopes", FILES_SCOPES, FILES_SCOPE_NAMES)
        """The scopes the open stated the session takes file calls in (``run_files``), of
        ``"work"`` and ``"sandbox"``, in that order; empty when it takes none. An OpenShell
        session states ``("sandbox",)`` alone: its work folder is not a mount of its own, so
        the work scope's confinement is not offered there (docs/openshell.md). Informational:
        the daemon refuses a file call in a scope it does not take, not dispatched, whatever
        this says."""
        self.work_dir: str = m.get_str("workDir")
        """The absolute path of the session's work folder as the open stated it, the folder a
        ``work`` path resolves from; "" when it stated none."""
        self._lock = threading.Lock()
        self._calls = 0
        self._last = ""
        self._ended: Optional[SessionEnded] = None
        self._closed: Optional[SessionSummary] = None
        self._close_error: Optional[ChainError] = None
        # Set once a call ended without an answer this client could check (no answer,
        # or one whose record did not check): that call may have run and moved the
        # daemon's chain on, so later calls would run and then fail the chain check.
        # They are refused instead, before anything is sent.
        self._unanswered: Optional[str] = None
        # Set once the daemon refused a call or close because another worker attached
        # the session: this worker must not use it again.
        self._stale: Optional[str] = None
        # The checkpoint store the session's calls pass through (open_session or
        # attach_session with one), its key, and the record this worker last wrote.
        self._store: Optional[CheckpointStore] = None
        self._key = ""
        self._stored: Optional[StoredCheckpoint] = None
        # The pending record this worker's close wrote when that close got no answer: the
        # next close starts from it, since the record stays pending and the store holds it,
        # not the ready one before it (finding hunt-quality-91).
        self._close_pending: Optional[StoredCheckpoint] = None
        # The lost call this session is recovering from, set by an attach across an explained
        # gap or from a checkpoint saved while recovering, None otherwise: while it is set
        # every call is refused before anything is sent (RecoveringError), until
        # resolve_lost_call. And the request digest of the call after which this session
        # stopped with no answer it could check.
        self._recovering: Optional[LostCall] = None
        self._lost_request = ""

    def __repr__(self) -> str:
        return f"Session(fingerprint={self.fingerprint[:12]!r}, calls={self._calls})"

    def _bind(self, store: CheckpointStore, key: str, stored: StoredCheckpoint) -> None:
        self._store, self._key, self._stored = store, key, stored

    def checkpoint(self) -> SessionCheckpoint:
        """The session's checkpoint (Go: ``Session.Checkpoint``), for an application that
        keeps it itself; a session with a store keeps its own. It waits for a call in
        flight, so the head it states follows that call. Raises
        CheckpointUnavailableError when the client has no ``daemon_name`` and when the
        session is stopped, closed or ended. A session recovering from a lost call saves
        that state (``recovering_request_sha256``), so the worker that attaches from it is
        recovering too."""
        if not self._daemon:
            raise CheckpointUnavailableError("plimsoll: the client has no daemon_name, so its sessions have no checkpoint")
        with self._lock:
            if self._unanswered is not None or self._stale is not None:
                raise CheckpointUnavailableError(f"plimsoll: the session is stopped ({self._stale or self._unanswered})")
            if self._closed is not None or self._close_error is not None:
                raise CheckpointUnavailableError("plimsoll: the session is closed")
            if self._ended is not None:
                raise CheckpointUnavailableError(f"plimsoll: the session ended ({self._ended.reason})")
            return self._checkpoint()

    def _checkpoint(self) -> SessionCheckpoint:
        assert self._daemon is not None
        return SessionCheckpoint(
            version=CHECKPOINT_VERSION,
            daemon=self._daemon,
            session=self.fingerprint,
            generation=self._generation,
            calls=self._calls,
            last_record_sha256=self._last,
            provider=self.provider,
            isolation=self.isolation,
            isolation_qualification=self.isolation_qualification,
            software_identity=self.software_identity,
            open_floor=self._floor,
            open_rule=self._rule.rule_id() if self._rule is not None else "",
            expires_unix_ms=self.expires_unix_ms,
            idle_timeout_ms=self.idle_timeout_ms,
            recovering_request_sha256=self._recovering.request_sha256 if self._recovering is not None else "",
        )

    @property
    def lost_request_sha256(self) -> str:
        """The request digest of the call after which this session stopped with no answer
        it could check, or "": the call that may have run. A store-backed session's pending
        record holds it already, and :meth:`Client.attach_session` names it."""
        return self._lost_request

    @property
    def lost_call(self) -> Optional[LostCall]:
        """The call this session is recovering from (:class:`~plimsoll_client.types.LostCall`),
        or None when it is not recovering: after an attach across an explained gap, or from
        a checkpoint saved while recovering, until :meth:`resolve_lost_call`. While it is not
        None every call is refused before it is sent (RecoveringError). Its record says
        whether the daemon answered the call: a result digest when the daemon answered,
        which does not show that the call ran to its end (a step stopped at its time limit
        and a setup that failed are answers too), an ``unanswered`` code when it ended
        without an answer, so that it may have done none, part or all of its work. Its
        ``answer`` is the call's result when the daemon kept it."""
        return self._recovering

    def resolve_lost_call(self) -> None:
        """Ends the recovering state (Go: ``Session.ResolveLostCall``): the application has
        read the lost call (:attr:`lost_call`) and handled its outcome, or accepts it as
        unknown, and the session's calls are sent again. Taking the session over, or
        copying its head, does not resolve it. A store-backed session writes its record
        ready without the lost call first, so a worker that attaches from it later is not
        recovering; a store that will not take the write raises CheckpointStoreError (or
        CheckpointConflictError) with nothing sent, and the session sends nothing more. On
        a session that is not recovering it does nothing."""
        with self._lock:
            if self._recovering is None:
                return
            current = self._stored
            live = self._unanswered is None and self._stale is None and self._closed is None and self._close_error is None
            if self._store is not None and current is not None and live and self._close_pending is None and current.checkpoint.recovering_request_sha256:
                ready = StoredCheckpoint(
                    revision=current.revision + 1, state="ready", operation="",
                    checkpoint=replace(current.checkpoint, recovering_request_sha256=""),
                )
                try:
                    ok = self._store.compare_and_set(self._key, current, ready)
                except Exception as e:
                    self._unanswered = "the checkpoint store could not be written"
                    raise CheckpointStoreError("plimsoll: the checkpoint store failed as the lost call was resolved; nothing was sent", sent=False) from e
                if not ok:
                    self._unanswered = "the checkpoint store changed under this worker"
                    raise CheckpointConflictError("plimsoll: the checkpoint store changed under this worker; nothing was sent", sent=False)
                self._stored = ready
            self._recovering = None

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc is None:
            self.close()
            return
        # The body's exception is the one to see: a close that fails too (its count
        # differs once a call was lost) is attached to it, not raised over it.
        try:
            self.close()
        except Exception as close_error:
            if hasattr(exc, "add_note"):
                exc.add_note(f"closing the session also failed: {close_error}")

    @property
    def ended(self) -> Optional[SessionEnded]:
        """The session's end once an answer reported it, else None."""
        return self._ended

    @property
    def stopped(self) -> Optional[str]:
        """Why this client sends no more calls, or None until it stops: after an answer it
        could not check, after the daemon refused a call or close because another worker
        attached the session, after the daemon refused a call because its head is not this
        client's (HeadMismatchError), or after its checkpoint store could not be written.
        Separate from an end the daemon reported."""
        return self._stale or self._unanswered

    @property
    def calls(self) -> int:
        """The calls this client has seen the session execute."""
        return self._calls

    @property
    def last_record_sha256(self) -> str:
        """The digest of the last record this client checked, "" before the first call."""
        return self._last

    def run_javascript(
        self,
        code: str,
        *,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        grant_profile: Optional[str] = None,
        trace_id: Optional[str] = None,
        cancel: Optional[CancelHandle] = None,
    ) -> JavaScriptResult:
        """Runs a snippet in the session. Arguments as for :meth:`Client.run_javascript`;
        ``software`` narrows the session's rule."""
        rule = v.merge_rules(self._rule, v.software_rule(software))
        req = _envelope(timeout, _stronger(self._floor, v.floor(minimum_isolation)), rule, trace_id)
        req["javascript"] = _javascript_payload(code, grant_profile)
        return self._call("javascript", req, rule, cancel)

    def run_project(
        self,
        files: v.FilesArg,
        steps: Sequence[str],
        artifacts: Sequence[str] = (),
        *,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        grant_profile: Optional[str] = None,
        trace_id: Optional[str] = None,
        cancel: Optional[CancelHandle] = None,
    ) -> ProjectResult:
        """Runs a project in the session; its files persist for later calls."""
        rule = v.merge_rules(self._rule, v.software_rule(software))
        req = _envelope(timeout, _stronger(self._floor, v.floor(minimum_isolation)), rule, trace_id)
        req["project"] = _project_payload(files, steps, artifacts, grant_profile)
        return self._call("project", req, rule, cancel)

    def run_cell(
        self,
        code: str,
        language: str = "python",
        *,
        files: v.FilesArg = None,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        trace_id: Optional[str] = None,
        cancel: Optional[CancelHandle] = None,
    ) -> CellResult:
        """Runs ``code`` in the session's interpreter for ``language``
        (``"python"`` or ``"javascript"``), which keeps what earlier cells defined,
        unless the result says a fresh interpreter started. ``files`` (a mapping
        or pairs of relative path and text) are written into the session's work
        directory, the interpreter's working directory, before the code runs. A
        cell carries no grant profile."""
        rule = v.merge_rules(self._rule, v.software_rule(software))
        req = _envelope(timeout, _stronger(self._floor, v.floor(minimum_isolation)), rule, trace_id)
        req["cell"] = v.cell(language, code, files)
        return self._call("cell", req, rule, cancel)

    def run_files(
        self,
        op: "fs.FilesOperation",
        *,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        trace_id: Optional[str] = None,
        cancel: Optional[CancelHandle] = None,
    ) -> "fs.FilesResult":
        """Carries out one operation on the session's files (``plimsoll_client.files``),
        inside its sandbox, as the guest's own user: a session call like any other, in the
        chain, its record checked against the request sent, the operation included. Paths
        are bytes end to end (a ``str`` is encoded as ``os.fsencode`` encodes it). A file
        that is not there is an answered result (``error`` ``not_found``), not an
        exception. A session whose provider carries no file calls refuses the call, not
        dispatched (UnsupportedError), and so does one in a scope the session does not take;
        ``file_scopes`` says which scopes the open stated."""
        rule = v.merge_rules(self._rule, v.software_rule(software))
        req = _envelope(timeout, _stronger(self._floor, v.floor(minimum_isolation)), rule, trace_id)
        req["files"] = _files_payload(op)
        return self._call("files", req, rule, cancel)

    def _call(self, kind: str, req: Dict[str, Any], rule: Optional[SoftwareRule], cancel: Optional[CancelHandle]) -> Any:
        req["sessionId"] = self._id
        digest = request_digest(req)  # neither the session ID nor the head is part of it
        floor = req.get("minimumIsolation", "")
        with self._lock:
            if self._closed is not None or self._close_error is not None:
                raise SessionEndedError(
                    "plimsoll: this session was closed; nothing was sent",
                    reason="closed",
                    not_dispatched="request",
                )
            self._refuse_if_stopped()
            # A session recovering from a lost call sends nothing until the application has
            # resolved it: every call is refused here, whatever it is.
            if self._recovering is not None:
                raise RecoveringError(f"plimsoll: {RECOVERING_TEXT}; nothing was sent", not_dispatched="request")
            # The head this call expects, filled in here, inside the lock that serializes the
            # session's calls, so each call carries the head the call before it left.
            req["head"] = {"generation": str(self._generation), "calls": str(self._calls), "lastRecordSha256": self._last}
            calls_before = self._calls
            pending = self._begin(digest)
            try:
                result = self._exchange(kind, req, rule, digest, floor, cancel)
            except BaseException as e:
                # Whatever ended the exchange (an error of the daemon's or the
                # transport's, an answer this client could not read, a
                # KeyboardInterrupt), the call may have run: unless the error says
                # nothing ran, or the chain moved past this call, this client can no
                # longer follow the daemon's chain, so it sends nothing more.
                marked = isinstance(e, PlimsollError) and e.not_dispatched is not None
                if not marked and self._calls == calls_before:
                    self._lost_request = self._lost_request or digest
                    if self._unanswered is None:
                        self._unanswered = e.message if isinstance(e, PlimsollError) else type(e).__name__
                if isinstance(e, StaleOwnerError):
                    self._stale = "another worker attached the session"
                if isinstance(e, HeadMismatchError) and self._unanswered is None:
                    # The daemon's own word that its chain holds a call this client did not
                    # send (or counts one it never ran): this client can no longer follow it.
                    h = e.head or {}
                    self._unanswered = (
                        f"the daemon's head is call {h.get('calls')} ending {h.get('last_record_sha256')!r}, this client sent "
                        f"call {self._calls} ending {self._last!r} ({e.message}); open a new session"
                    )
                self._settle(pending, calls_before, e, None)
                raise
            self._settle(pending, calls_before, None, result)
            return result

    def _refuse_if_stopped(self) -> None:
        if self._stale is not None:
            raise StaleOwnerError(
                f"plimsoll: {self._stale}; this worker sends nothing more on the session",
                not_dispatched="request",
            )
        if self._unanswered is not None:
            raise PlimsollError(
                "plimsoll: an earlier call of this session ended without an answer this client could check "
                f"({self._unanswered}); it may have run, so this client sends nothing more on the session: open a new one",
                code="failed_precondition",
                not_dispatched="request",
            )

    def _begin(self, digest: str) -> Optional[StoredCheckpoint]:
        """Marks the session's stored record pending before a call is sent, or raises
        with nothing sent (and the session stopped) when the store will not take it."""
        if self._store is None or self._stored is None:
            return None
        ready = self._stored
        pending = StoredCheckpoint(
            revision=ready.revision + 1, state="pending", operation=secrets.token_hex(16), checkpoint=ready.checkpoint, request_sha256=digest
        )
        try:
            ok = self._store.compare_and_set(self._key, ready, pending)
        except Exception as e:
            self._unanswered = "the checkpoint store could not be written"
            raise CheckpointStoreError("plimsoll: the checkpoint store failed before the call; nothing was sent", sent=False) from e
        if not ok:
            self._unanswered = "the checkpoint store changed under this worker"
            raise CheckpointConflictError("plimsoll: the checkpoint store changed under this worker; nothing was sent", sent=False)
        return pending

    def _settle(self, pending: Optional[StoredCheckpoint], calls_before: int, error: Optional[BaseException], result: Any) -> None:
        """After a call that went through the store: ready at the new head when the chain
        moved (a checked answer, or a checked unanswered record), ready as it was when the
        daemon said nothing ran; otherwise the record stays pending, and the session is
        stopped already. A failed write stops the session; after a call that ran it raises
        CheckpointStoreError with the call's result or error attached."""
        if pending is None:
            return
        moved = self._calls != calls_before
        marked = isinstance(error, PlimsollError) and error.not_dispatched is not None
        if not moved and not marked:
            return
        # A call is sent only once the session is not recovering, so the record it leaves
        # carries no lost call.
        recovering = self._recovering.request_sha256 if self._recovering is not None else ""
        checkpoint = replace(pending.checkpoint, calls=self._calls, last_record_sha256=self._last, recovering_request_sha256=recovering)
        ready = StoredCheckpoint(revision=pending.revision + 1, state="ready", operation="", checkpoint=checkpoint)
        cause: Optional[BaseException] = None
        try:
            ok = self._store is not None and self._store.compare_and_set(self._key, pending, ready)
        except Exception as e:
            ok, cause = False, e
        if ok:
            self._stored = ready
            return
        if self._unanswered is None and self._stale is None:
            self._unanswered = "the checkpoint store could not be written after a call"
        if not moved:
            return  # nothing ran: the call's own refusal says so, and is the error raised
        err_type = CheckpointStoreError if cause is not None else CheckpointConflictError
        raise err_type(
            "plimsoll: the call ran, and the checkpoint store could not be written after it; the session sends nothing more",
            sent=True,
            result=result,
            call_error=error,
        ) from (cause or error)

    def _exchange(
        self, kind: str, req: Dict[str, Any], rule: Optional[SoftwareRule], digest: str, floor: str, cancel: Optional[CancelHandle]
    ) -> Any:
        try:
            m = self._transport.call("SessionRun", req, "SessionRunResponse", cancel)
        except PlimsollError as e:
            if isinstance(e, SessionEndedError):
                self._ended = SessionEnded(reason=e.reason, detail=e.detail)
            if e.not_dispatched is not None or e.unanswered is None:
                raise
            # The call may have run, and the daemon chained its record: check it and
            # keep it, so the session goes on and the call is not hidden.
            try:
                r = check_unanswered(digest, floor, rule, Msg(e.unanswered, "unanswered"))
                # With no response to compare it with, the record's evidence must be
                # what the session stated at open.
                if (r.provider, r.isolation, r.software_identity, r.isolation_qualification) != (
                    self.provider, self.isolation, self.software_identity, self.isolation_qualification
                ):
                    raise RecordMismatchError(
                        f"plimsoll: the unanswered call's record names {r.provider} at {r.isolation!r} running {r.software_identity!r}, "
                        f"the session opened as {self.provider} at {self.isolation!r} running {self.software_identity!r} "
                        "(or the tier's qualification differs from the one stated at open)"
                    )
                if r.session != self.fingerprint or r.sequence != self._calls + 1 or r.previous_sha256 != self._last:
                    raise ChainError(
                        f"plimsoll: the session's chain is broken: call {r.sequence} after {r.previous_sha256!r}, "
                        f"this client's last was call {self._calls}, {self._last!r}"
                    )
            except PlimsollError as ce:
                raise ce from e
            self._calls, self._last = r.sequence, r.sha256
            e.record = r  # the checked record, as Go's UnansweredCallError carries it
            raise
        run = m.get_msg("run")
        if run is None:
            raise ResultKindMismatchError("plimsoll: the session call's answer carries no run")
        end = m.get_enum("ended", SESSION_ENDS, unknown=-1)
        if end != 0:
            # A number this client has no name for is an end all the same: "unknown".
            name = SESSION_END_NAMES[end] if 0 < end < len(SESSION_END_NAMES) else "unknown"
            self._ended = SessionEnded(reason=name, detail=m.get_str("endDetail"))
        # A file call's answer must be of the operation the request asked (its record's rule).
        op = files_op(Msg(req["files"], "files")) if kind == "files" else ""
        return _finish(kind, run, lambda: self._checked_chain(kind, digest, rule, run, floor, op), floor)

    def _checked_chain(self, kind: str, digest: str, rule: Optional[SoftwareRule], run: Msg, floor: str, op: str = "") -> RunRecord:
        try:
            return self._check_chain(kind, digest, rule, run, floor, op)
        except PlimsollError as e:
            self._unanswered = e.message
            raise

    def _check_chain(self, kind: str, digest: str, rule: Optional[SoftwareRule], run: Msg, floor: str, op: str = "") -> RunRecord:
        # record.CheckSessionCall, then the chain this client tracks moves on. A tier
        # below the call's floor, or a result of another kind, fails it before the chain
        # moves, as in Go's record.check, so the session sends nothing more.
        r = check(digest, kind, rule, run, op)
        if floor and not meets(r.isolation, floor):
            raise IsolationEvidenceMismatchError(
                f"plimsoll: result isolation {r.isolation or 'unknown'} is below the requested minimum {floor}; execution may have occurred"
            )
        if r.session != self.fingerprint:
            raise ChainError(f"plimsoll: the record names session {r.session}, the call was sent to {self.fingerprint}")
        if r.sequence != self._calls + 1 or r.previous_sha256 != self._last:
            raise ChainError(
                f"plimsoll: the session's chain is broken: call {r.sequence} after {r.previous_sha256!r}, "
                f"this client's last was call {self._calls}, {self._last!r}"
            )
        self._calls, self._last = r.sequence, r.sha256
        return r

    def close(self) -> SessionSummary:
        """Ends the session, or collects one that ended by itself, and checks the
        daemon's count of executed calls and its last record against the chain this
        client saw. A difference raises ChainError with the summary attached: a call
        this client did not make ran in the session. Closing again returns the same
        summary (or raises the same error) without another request; a close that got no
        count back (lost in transit, timed out, refused) is sent again."""
        with self._lock:
            if self._close_error is not None:
                raise self._close_error
            if self._closed is not None:
                return self._closed
            if self._stale is not None:
                self._refuse_if_stopped()
            # A session stopped after an unanswered call or a failed store write closes
            # without its store: the record it left (pending, or another worker's) is not
            # this worker's to move, and a record of a closed session attaches to nothing.
            # A close sent again after one that got no answer starts from the pending record
            # that close left, which is this worker's own.
            pending = (self._close_pending or self._begin("")) if self._unanswered is None else None
            self._close_pending = None
            try:
                m = self._transport.call(
                    "CloseSession", {"protocol": PROTOCOL, "sessionId": self._id, "generation": str(self._generation)}, "CloseSessionResponse"
                )
            except BaseException as e:
                if isinstance(e, StaleOwnerError):
                    self._stale = "another worker attached the session"
                self._settle(pending, self._calls, e, None)
                # Unless the daemon said nothing ran (_settle then made the record ready), the
                # record stays pending: the close may have reached the daemon.
                if not (isinstance(e, PlimsollError) and e.not_dispatched is not None):
                    self._close_pending = pending
                raise
            # Answered: the session is closed on the daemon whatever the summary says, so
            # its stored record is ready as it was, and attaching it finds no session.
            self._settle_closed(pending)
            end = m.get_enum("ended", SESSION_ENDS, unknown=-1)
            summary = SessionSummary(
                session=m.get_str("session"),
                calls=m.get_int("calls", UINT64),
                last_record_sha256=m.get_str("lastRecordSha256"),
                end=SESSION_END_NAMES[end] if 0 <= end < len(SESSION_END_NAMES) else "unknown",
            )
            if self._ended is None and summary.end != "open":
                self._ended = SessionEnded(reason=summary.end, detail="")
            if summary.session != self.fingerprint or summary.calls != self._calls or summary.last_record_sha256 != self._last:
                self._close_error = ChainError(
                    f"plimsoll: the daemon counts {summary.calls} calls ending {summary.last_record_sha256!r}, "
                    f"this client saw {self._calls} ending {self._last!r}",
                    result=summary,
                )
                raise self._close_error
            self._closed = summary
            return summary

    def _settle_closed(self, pending: Optional[StoredCheckpoint]) -> None:
        if pending is None or self._store is None:
            return
        ready = StoredCheckpoint(revision=pending.revision + 1, state="ready", operation="", checkpoint=pending.checkpoint)
        try:
            if self._store.compare_and_set(self._key, pending, ready):
                self._stored = ready
        except Exception:
            pass  # the session is closed; a record left pending finds no session to attach

    def _close_quietly(self) -> None:
        try:
            self.close()
        except Exception:  # the open already failed; that error is the one to report
            pass
