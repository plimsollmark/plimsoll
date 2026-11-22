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
from ._record import _states_only, check, check_single, check_unanswered, record_digest, record_from_wire, request_digest, session_fingerprint
from ._tables import CALL_ALREADY_SENT_TEXT, DAEMON_NAME_PATTERN
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
)
from .errors import (
    CallAlreadySentError,
    ChainError,
    DataLossError,
    PlimsollError,
    InvalidOptionError,
    IsolationEvidenceMismatchError,
    MalformedResponseError,
    ProtocolMismatchError,
    RecordMismatchError,
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


_MAPPERS: Dict[str, Callable[[Msg, Msg], Any]] = {
    "javascript": _javascript_result,
    "project": _project_result,
    "module": _module_result,
    "cell": _cell_result,
}


def _kinds(resp: Msg) -> Tuple[str, ...]:
    return tuple(k for k in ("javascript", "project", "module", "cell") if resp.has(k))


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
        its record (``Session.lost_call``). The session then refuses its first call if it
        repeats the lost one (CallAlreadySentError); only the first call is checked, so a
        later call can send the lost call again. Any other difference is refused
        (CheckpointMismatchError).

        A missing record raises LookupError: it never becomes a fresh session. A
        checkpoint naming another daemon than this client's ``daemon_name`` is refused
        before anything is sent. The daemon refuses an unknown, ended or another caller's
        session as not found, and open development mode refuses every attach. A refusal
        leaves the store as it was. The answer must repeat the checkpoint exactly, else
        ChainError, and the session is not closed: a bad answer gives this client no right
        to destroy a session another worker may be using. A transport failure or a cancel
        after sending is raised as it is and never retried: the daemon may have raised
        the generation. If the store changed meanwhile, CheckpointConflictError, and the
        attached session is dropped, not closed."""
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
        ready = StoredCheckpoint(revision=loaded.revision + 1, state="ready", operation="", checkpoint=s.checkpoint())
        try:
            moved = store.compare_and_set(key, loaded, ready)
        except Exception as e:
            raise CheckpointStoreError("plimsoll: the checkpoint store failed after the attach; the attached session is dropped", sent=True) from e
        if not moved:
            raise CheckpointConflictError("plimsoll: the checkpoint store changed during the attach; the attached session is dropped", sent=True)
        s._bind(store, key, ready)
        return s

    def _attached(self, cp: SessionCheckpoint, m: Msg, lost: str = "") -> "Session":
        """The attached session, once the answer repeats the checkpoint exactly, or carries
        the record of the call ``lost`` names at the checkpoint's next place and a head
        after it; else ChainError, with nothing closed."""
        info, head = m.get_msg("sessionInfo"), m.get_msg("checkpoint")
        lost_msg = m.get_msg("lostRecord")
        lost_call: Optional[RunRecord] = None
        problem = ""
        if lost_msg is not None:
            lost_call, problem = _lost_record(cp, lost, lost_msg)
        calls, last, note = cp.calls, cp.last_record_sha256, cp.lost_call_sha256
        if lost_call is not None:
            calls, last, note = lost_call.sequence, lost_call.sha256, lost_call.request_sha256
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
        s._lost_call, s._lost_record = note, lost_call
        return s


_DAEMON_NAME = re.compile(DAEMON_NAME_PATTERN)
_FINGERPRINT = re.compile("[0-9a-f]{64}")


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
        # The request digest the session's next call is refused for repeating, set by an
        # attach across an explained gap (or inherited with a checkpoint) and spent by that
        # refusal or by the next call that may have run (a call the daemon refuses with the
        # not-dispatched mark leaves it); the record of that lost call; and the request
        # digest of the call after which this session stopped with no answer it could check.
        self._lost_call = ""
        self._lost_record: Optional[RunRecord] = None
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
        session is stopped, closed or ended."""
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
            version=1,
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
            lost_call_sha256=self._lost_call,
        )

    @property
    def lost_request_sha256(self) -> str:
        """The request digest of the call after which this session stopped with no answer
        it could check, or "": the call that may have run. A store-backed session's pending
        record holds it already, and :meth:`Client.attach_session` names it."""
        return self._lost_request

    @property
    def lost_call_sha256(self) -> str:
        """The request digest the session's next call is refused for repeating, or "": set
        by an attach across an explained gap (or with a checkpoint that carries it) and spent
        by the next call, unless the daemon refuses that call with the not-dispatched mark.
        An adapter that sends a call of its own before the application's first (a probe)
        would spend it, so it sends none while this is set."""
        return self._lost_call

    @property
    def lost_call(self) -> Optional[RunRecord]:
        """The record of the call that was sent once and whose answer was lost, on a
        session attached across an explained gap, or None. Its output is lost. The record
        says whether the daemon answered it: a result digest when the daemon answered,
        which does not show that the call ran to its end (a step stopped at its time limit
        and a setup that failed are answers too), an ``unanswered`` code when it ended
        without an answer, so that it may have done none, part or all of its work."""
        return self._lost_record

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
        attached the session, or after its checkpoint store could not be written.
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

    def _call(self, kind: str, req: Dict[str, Any], rule: Optional[SoftwareRule], cancel: Optional[CancelHandle]) -> Any:
        req["sessionId"] = self._id
        req["generation"] = str(self._generation)
        digest = request_digest(req)  # the session ID is not part of it
        floor = req.get("minimumIsolation", "")
        with self._lock:
            if self._closed is not None or self._close_error is not None:
                raise SessionEndedError(
                    "plimsoll: this session was closed; nothing was sent",
                    reason="closed",
                    not_dispatched="request",
                )
            self._refuse_if_stopped()
            # The first call after an attach across an explained gap: a repeat of the lost
            # call is a retry of a call that was already sent once, refused here with nothing
            # sent, and the refusal spends the note. Only the first call is checked: any
            # other call spends the note once it is sent, unless the daemon refuses it with
            # the not-dispatched mark, since then nothing ran, the head is where it was, and
            # the next call is still the first.
            if self._lost_call and digest == self._lost_call:
                self._lost_call = ""
                raise CallAlreadySentError(f"plimsoll: {CALL_ALREADY_SENT_TEXT}; nothing was sent", not_dispatched="request")
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
                if not marked:
                    self._lost_call = ""
                if not marked and self._calls == calls_before:
                    self._lost_request = self._lost_request or digest
                    if self._unanswered is None:
                        self._unanswered = e.message if isinstance(e, PlimsollError) else type(e).__name__
                if isinstance(e, StaleOwnerError):
                    self._stale = "another worker attached the session"
                self._settle(pending, calls_before, e, None)
                raise
            self._lost_call = ""
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
        # A lost call's note stays only when the daemon said nothing ran (_call spent it
        # otherwise).
        checkpoint = replace(pending.checkpoint, calls=self._calls, last_record_sha256=self._last, lost_call_sha256=self._lost_call)
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
        return _finish(kind, run, lambda: self._checked_chain(kind, digest, rule, run, floor), floor)

    def _checked_chain(self, kind: str, digest: str, rule: Optional[SoftwareRule], run: Msg, floor: str) -> RunRecord:
        try:
            return self._check_chain(kind, digest, rule, run, floor)
        except PlimsollError as e:
            self._unanswered = e.message
            raise

    def _check_chain(self, kind: str, digest: str, rule: Optional[SoftwareRule], run: Msg, floor: str) -> RunRecord:
        # record.CheckSessionCall, then the chain this client tracks moves on. A tier
        # below the call's floor, or a result of another kind, fails it before the chain
        # moves, as in Go's record.check, so the session sends nothing more.
        r = check(digest, kind, rule, run)
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
