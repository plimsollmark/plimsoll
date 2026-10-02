"""The plimsolld client: Connect's JSON protocol over HTTP/1.1, standard library only.

It keeps the official Go client's promises (package ``client``): it states the
protocol number on every request, checks every run record against what it sent
and what it received, checks the isolation evidence against the caller's floor,
restores the daemon's not-dispatched mark and session end, and tracks a session's
chain of records so a call it did not make is caught.
"""

from __future__ import annotations

import math
import ssl
import threading
from dataclasses import replace
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from . import _validate as v
from ._record import check, check_single, check_unanswered, request_digest, session_fingerprint
from ._transport import Transport
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

__all__ = ["PROTOCOL", "Client", "Session"]

PROTOCOL = 2
"""The wire protocol number this client speaks (Go: protocol.Number). It is stated
on every request; a daemon serving another number refuses the request before
reading its payload."""

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
        "environment": resp.get_str("environment"),
        "software_identity": resp.get_str("softwareIdentity"),
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
    ) -> None:
        url = v.validate_base_url(base_url, insecure_http)
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

    def describe(self) -> Info:
        """What the daemon states about itself. Raises ProtocolMismatchError,
        with the description attached as ``info``, when the daemon serves another
        protocol number than this client speaks: every request would be refused."""
        m = self._transport.call("Describe", {}, "DescribeResponse")
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
    ) -> JavaScriptResult:
        """Runs a JavaScript snippet in a fresh sandbox.

        ``timeout`` is the run's whole budget in seconds (the daemon defaults and
        clamps it). ``minimum_isolation`` is the weakest tier the run accepts,
        checked by the daemon before dispatch and by this client on the answer.
        ``software`` requires the selected software to be in a rule.
        ``grant_profile`` names a host-API capability configured on the daemon;
        without one the run has no network. ``trace_id`` is an opaque correlation
        ID for the daemon's audit line, 1 to 64 characters of ``[A-Za-z0-9._:-]``.
        """
        rule = v.software_rule(software)
        req = _envelope(timeout, minimum_isolation, rule, trace_id)
        req["javascript"] = _javascript_payload(code, grant_profile)
        return self._run("javascript", req, rule)

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
    ) -> ProjectResult:
        """Writes ``files`` (a mapping of relative path to text, or a list of
        ``(path, text)`` pairs, sent in that order) into a fresh sandbox and runs
        ``steps``, shell commands, in order, stopping at the first that fails.
        ``artifacts`` are relative paths to capture and return. The other
        arguments are as for :meth:`run_javascript`."""
        rule = v.software_rule(software)
        req = _envelope(timeout, minimum_isolation, rule, trace_id)
        req["project"] = _project_payload(files, steps, artifacts, grant_profile)
        return self._run("project", req, rule)

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
    ) -> ModuleResult:
        """Runs a compiled simulator built into the daemon's module image once per
        parameter row, each instance stepping from 0 to ``end_time`` with
        communication step ``step``. Only some providers run modules
        (``Info.supports_module``)."""
        rule = v.software_rule(software)
        req = _envelope(timeout, minimum_isolation, rule, trace_id)
        req["module"] = v.module(model, rows, end_time, step)
        return self._run("module", req, rule)

    def _run(self, kind: str, req: Dict[str, Any], rule: Optional[SoftwareRule]) -> Any:
        digest = request_digest(req)
        resp = self._transport.call("Run", req, "RunResponse")
        floor = req.get("minimumIsolation", "")
        return _finish(kind, resp, lambda: check_single(digest, PROTOCOL, rule, resp), floor)

    def open_session(
        self,
        *,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        lifetime: Optional[float] = None,
        idle_timeout: Optional[float] = None,
        trace_id: Optional[str] = None,
        languages: Optional[Sequence[str]] = None,
    ) -> "Session":
        """Opens a session: one sandbox kept for many calls, in which the files a
        call writes persist for later calls and no process a call starts outlives
        it. Only on a daemon whose ``describe()`` states ``supports_sessions``.

        ``minimum_isolation`` and ``software`` apply to the whole session and are
        checked again on the session the daemon opened. ``lifetime`` and
        ``idle_timeout`` (seconds) may only shorten the daemon's own.
        ``languages`` names the languages the session's cells will use: a hint, so
        a daemon with a warm pool hands over a sandbox with those interpreters
        already running; a cell in any language the daemon states still runs. Use
        it as a context manager, or call :meth:`Session.close`."""
        rule = v.software_rule(software)
        hint = v.languages(languages)
        req: Dict[str, Any] = {"protocol": PROTOCOL}
        if hint:
            req["languages"] = hint
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
        s = Session(self._transport, session_id, m, rule, floor)
        if s.fingerprint != session_fingerprint(session_id):
            s._close_quietly()  # the session exists on the daemon either way; nothing else holds its ID
            raise ChainError("plimsoll: the daemon's session fingerprint does not match its session ID; the session was closed")
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
        return s


class Session:
    """An open session on a daemon. Calls are serialized here as they are on the
    daemon, so the chain this client tracks follows the daemon's: a record that
    does not continue it means someone else holding the session ID made a call
    (ChainError). The session ID is a capability: it is sent to the daemon and
    appears nowhere else, not in ``repr`` and not in errors."""

    def __init__(self, transport: Transport, session_id: str, m: Msg, rule: Optional[SoftwareRule], floor: str = "") -> None:
        self._transport = transport
        self._id = session_id
        self._rule = rule
        self._floor = floor  # the floor given at open, sent with every call
        self.fingerprint: str = m.get_str("session")
        """The SHA-256 of the session ID, as the session's records carry it."""
        self.provider: str = m.get_str("sandbox")
        self.isolation: str = m.get_str("isolation")
        """The tier the daemon measured when the session opened."""
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

    def __repr__(self) -> str:
        return f"Session(fingerprint={self.fingerprint!r}, calls={self._calls})"

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
    ) -> JavaScriptResult:
        """Runs a snippet in the session. Arguments as for :meth:`Client.run_javascript`;
        ``software`` narrows the session's rule."""
        rule = v.merge_rules(self._rule, v.software_rule(software))
        req = _envelope(timeout, _stronger(self._floor, v.floor(minimum_isolation)), rule, trace_id)
        req["javascript"] = _javascript_payload(code, grant_profile)
        return self._call("javascript", req, rule)

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
    ) -> ProjectResult:
        """Runs a project in the session; its files persist for later calls."""
        rule = v.merge_rules(self._rule, v.software_rule(software))
        req = _envelope(timeout, _stronger(self._floor, v.floor(minimum_isolation)), rule, trace_id)
        req["project"] = _project_payload(files, steps, artifacts, grant_profile)
        return self._call("project", req, rule)

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
        return self._call("cell", req, rule)

    def _call(self, kind: str, req: Dict[str, Any], rule: Optional[SoftwareRule]) -> Any:
        req["sessionId"] = self._id
        digest = request_digest(req)  # the session ID is not part of it
        floor = req.get("minimumIsolation", "")
        with self._lock:
            if self._closed is not None or self._close_error is not None:
                raise SessionEndedError(
                    "plimsoll: this session was closed; nothing was sent",
                    reason="closed",
                    not_dispatched="request",
                )
            if self._unanswered is not None:
                raise PlimsollError(
                    "plimsoll: an earlier call of this session ended without an answer this client could check "
                    f"({self._unanswered}); it may have run, so this client sends nothing more on the session: open a new one",
                    code="failed_precondition",
                    not_dispatched="request",
                )
            calls_before = self._calls
            try:
                return self._exchange(kind, req, rule, digest, floor)
            except BaseException as e:
                # Whatever ended the exchange (an error of the daemon's or the
                # transport's, an answer this client could not read, a
                # KeyboardInterrupt), the call may have run: unless the error says
                # nothing ran, or the chain moved past this call, this client can no
                # longer follow the daemon's chain, so it sends nothing more.
                marked = isinstance(e, PlimsollError) and e.not_dispatched is not None
                if not marked and self._calls == calls_before and self._unanswered is None:
                    self._unanswered = e.message if isinstance(e, PlimsollError) else type(e).__name__
                raise

    def _exchange(self, kind: str, req: Dict[str, Any], rule: Optional[SoftwareRule], digest: str, floor: str) -> Any:
        try:
            m = self._transport.call("SessionRun", req, "SessionRunResponse")
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
                if (r.provider, r.isolation, r.software_identity) != (self.provider, self.isolation, self.software_identity):
                    raise RecordMismatchError(
                        f"plimsoll: the unanswered call's record names {r.provider} at {r.isolation!r} running {r.software_identity!r}, "
                        f"the session opened as {self.provider} at {self.isolation!r} running {self.software_identity!r}"
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
        end = m.get_enum("ended", SESSION_ENDS)
        if end != 0:
            name = SESSION_END_NAMES[end] if 0 < end < len(SESSION_END_NAMES) else "open"
            self._ended = SessionEnded(reason=name, detail=m.get_str("endDetail"))
        return _finish(kind, run, lambda: self._checked_chain(digest, rule, run, floor), floor)

    def _checked_chain(self, digest: str, rule: Optional[SoftwareRule], run: Msg, floor: str) -> RunRecord:
        try:
            return self._check_chain(digest, rule, run, floor)
        except PlimsollError as e:
            self._unanswered = e.message
            raise

    def _check_chain(self, digest: str, rule: Optional[SoftwareRule], run: Msg, floor: str) -> RunRecord:
        # record.CheckSessionCall, then the chain this client tracks moves on. A tier
        # below the call's floor fails it before the chain moves, as in Go's
        # record.check, so the session sends nothing more.
        r = check(digest, PROTOCOL, rule, run)
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
        summary (or raises the same error) without another request."""
        with self._lock:
            if self._close_error is not None:
                raise self._close_error
            if self._closed is not None:
                return self._closed
            m = self._transport.call("CloseSession", {"protocol": PROTOCOL, "sessionId": self._id}, "CloseSessionResponse")
            end = m.get_enum("ended", SESSION_ENDS)
            summary = SessionSummary(
                session=m.get_str("session"),
                calls=m.get_int("calls", UINT64),
                last_record_sha256=m.get_str("lastRecordSha256"),
                end=SESSION_END_NAMES[end] if 0 <= end < len(SESSION_END_NAMES) else "open",
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

    def _close_quietly(self) -> None:
        try:
            self.close()
        except Exception:  # the open already failed; that error is the one to report
            pass
