"""OpenAI Agents SDK, sandbox provider: a plimsoll session as a `SandboxAgent`'s sandbox.

The Agents SDK (``openai-agents`` 0.25.0, read on 2026-11-17) runs a ``SandboxAgent``'s
commands and files in a sandbox session it gets from a provider: a ``BaseSandboxClient``
that creates, resumes and deletes sessions, and a ``BaseSandboxSession`` that runs a
command, reads and writes a file, and saves and restores the workspace. This module is that
provider over plimsoll: every command is a call of one plimsoll session through
:class:`plimsoll_client.workspace.Workspace` (a fixed step, the command as a file), so the
daemon's guarantees hold for the agent's whole run: the isolation floor the session was
opened at, a run record on every call, no network. The SDK's maintainers keep third-party
providers out of the SDK, so this one lives here.

    from agents import RunConfig, Runner
    from agents.sandbox import SandboxAgent, SandboxRunConfig
    from plimsoll_client import Client
    from plimsoll_client.openai_sandbox import PlimsollSandboxClient, PlimsollSandboxClientOptions

    client = PlimsollSandboxClient(Client("https://plimsoll.internal", token=...))
    sandbox = SandboxRunConfig(client=client, options=PlimsollSandboxClientOptions(minimum_isolation="kernel"))
    result = await Runner.run(SandboxAgent(name="coder", instructions="..."), "...", run_config=RunConfig(sandbox=sandbox))

**What plimsoll states about each command, and where it appears.** Six labels, each
checked against its closed set (the same check as the LangSmith labels,
``plimsoll_client._langsmith.labels``) so that no code, output, path or detail text is
ever one: ``plimsoll_dispatched`` (``yes``, ``no`` or ``unknown``), ``plimsoll_refused``
(the reason, when nothing ran), ``plimsoll_outcome``, ``plimsoll_isolation`` and
``plimsoll_isolation_qualification`` (the tier and the sentence the provider states beside
it), ``plimsoll_record_sha256`` (the checked run record's digest). They appear in the SDK's
own two channels for sandbox operations, both made by its ``SandboxSession`` wrapper
(``agents/sandbox/session/sandbox_session.py``: "Wrap sandbox operations in audit events
and SDK tracing spans when tracing is active"):

- the ``exec`` finish event every event sink of the client's ``Instrumentation`` receives
  (``event.data``), on a command that ran and on one that raised, with the checked run
  record whole beside them as ``plimsoll_record`` when the daemon answered with one;
- the ``sandbox.exec`` tracing span (``span_data.data``), so a tracing processor sees them
  (the labels only: the SDK uploads traces to OpenAI when it has a key).

The kit's own fields beside them are the kit's: its exec event carries the command text,
and its output only when the sink's ``EventPayloadPolicy`` includes it; its function-tool
span carries the tool's input and output unless ``RunConfig(trace_include_sensitive_data=
False)``. A command the app runs itself (``await session.exec(...)``) returns a
:class:`PlimsollExecResult`, the SDK's ``ExecResult`` with the checked result, its record
and the labels. A refusal or an error after which the command may have run raises
:class:`PlimsollExecError`, the SDK's ``ExecTransportError`` with the plimsoll error as
its cause, the labels as its ``context`` and ``retryable`` from
:func:`plimsoll_client.retry_on`, as OpenAI's provider guide asks ("Translate provider
failures into the SDK's sandbox error types while preserving useful error codes and
retryability").

**Cancellation.** A command, read, write, save or restore the SDK cancels is cancelled
through a :class:`~plimsoll_client.CancelHandle`, as everywhere else in this client: a call
not yet sent is never sent (marked not dispatched, reason ``request``), and the connection
of one in flight is cut (unmarked: the command may have run). A session open the SDK
cancels is closed once it completes, so it does not hold the daemon's slot.

What differs from a provider that owns a machine, stated here and in the docstrings: the
work directory is the daemon's (``/work`` on docker), learned from the sandbox at create
unless the manifest names it; ``resume`` opens a new session and lets the SDK restore the
snapshot into it, since this client cannot re-attach to a session another process opened
(the state carries the session's public fingerprint, never its ID); no PTY, so no
streamed output and no ``write_stdin``; no exposed ports; no manifest users or groups (a
plimsoll sandbox runs as one user); a background process does not survive a command (the
session's sweep). ``stop`` and ``delete`` close the session: the sandbox is gone, the
snapshot keeps the files. A command's budget is the timeout the SDK gives it (the shell
tool gives 10 s unless the model asks for more, ``yield_time_ms``), the options' ``timeout``
when it gives none; a budget of zero or less expires before anything is sent.
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import io
import logging
import shlex
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence

try:
    import agents.sandbox  # noqa: F401  (the extra this module needs; named if it is missing)
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.openai_sandbox needs the OpenAI Agents SDK: pip install 'plimsoll-client[openai-agents]'") from e
# Where each interface is, in openai-agents 0.25.0 (the version the suite's lock pins):
# BaseSandboxSession's required methods, agents/sandbox/session/base_sandbox_session.py:743
# (_exec_internal), 925 (read), 985 (write), 1150 (running), 1156 (persist_workspace), 1165
# (hydrate_workspace), and the optional _read_bounded at 969; BaseSandboxClient,
# agents/sandbox/session/sandbox_client.py:121 (_wrap_session), 148 (create), 170 (delete),
# 174 (resume), 280 (deserialize_session_state); ExecResult, agents/sandbox/types.py:147; the
# errors, agents/sandbox/errors.py:294 (ExecTimeoutError), 318 (ExecTransportError), 478
# (WorkspaceArchiveReadError), 499 (WorkspaceArchiveWriteError); the instrumented wrapper,
# agents/sandbox/session/sandbox_session.py:221; get_current_span, agents/tracing/create.py:84.
from agents.sandbox.errors import ExecTimeoutError, ExecTransportError, WorkspaceArchiveReadError, WorkspaceArchiveWriteError
from agents.sandbox.manifest import Manifest
from agents.sandbox.materialization import MaterializationResult
from agents.sandbox.session import SandboxSession, SandboxSessionState
from agents.sandbox.session.base_sandbox_session import BaseSandboxSession
from agents.sandbox.session.dependencies import Dependencies
from agents.sandbox.session.manager import Instrumentation
from agents.sandbox.session.sandbox_client import BaseSandboxClient, BaseSandboxClientOptions
from agents.sandbox.snapshot import SnapshotBase, SnapshotSpec, resolve_snapshot
from agents.sandbox.types import ExecResult
from agents.tracing import CustomSpanData, get_current_span

# The hook every operation of the SDK's SandboxSession wrapper runs through
# (agents/sandbox/session/sandbox_session.py:383 at 0.25.0): it emits the operation's start
# and finish events and opens its span. A private name, so it is checked here rather than
# found missing by a run that quietly loses its labels.
if not {"op", "start_data", "run", "finish_data"} <= set(inspect.signature(SandboxSession._annotate).parameters):  # pragma: no cover
    raise ImportError(
        "plimsoll_client.openai_sandbox: this openai-agents no longer has SandboxSession._annotate(op, start_data, run, "
        "finish_data), the hook the provider labels each command's event and span through; it was checked on 0.25.0"
    )

from ._langsmith import KEYS as LABEL_KEYS
from ._langsmith import labels as _closed_set_labels
from ._tables import OUTCOME_NAMES
from ._transport import CancelHandle, in_thread
from .client import Client
from .errors import InvalidRequestError, PlimsollError, retry_on
from .types import ProjectResult, RunRecord
from .workspace import ExecOutcome, Workspace, WorkspaceCallError, WorkspaceChangedError, WorkspaceTooLargeError
from .workspace import close_quietly as _close_quietly

__all__ = [
    "LABEL_KEYS",
    "PlimsollExecError",
    "PlimsollExecResult",
    "PlimsollExecTimeoutError",
    "PlimsollSandboxClient",
    "PlimsollSandboxClientOptions",
    "PlimsollSandboxSession",
    "PlimsollSandboxSessionState",
]

BACKEND_ID = "plimsoll"
_DEFAULT_MANIFEST_ROOT = str(Manifest.model_fields["root"].default)
# The span the SDK's wrapper opens around a command (sandbox_session.py:396, "sandbox.{op}").
_EXEC_SPAN = "sandbox.exec"

log = logging.getLogger("plimsoll_client")

WorkspaceFactory = Callable[["PlimsollSandboxClientOptions"], Workspace]


# ---- what plimsoll states about a command: labels from trusted fields only ----


def _result_labels(r: Optional[ProjectResult]) -> Dict[str, str]:
    if r is None:
        return {}
    return _closed_set_labels(
        {
            "outcome": r.outcome,
            "isolation": r.isolation,
            "isolation_qualification": r.isolation_qualification,
            "record_sha256": r.record.sha256 if r.record is not None else "",
        }
    )


def _error_labels(e: BaseException) -> Dict[str, str]:
    if isinstance(e, PlimsollError):
        if e.not_dispatched is not None:
            return _closed_set_labels({"refused": e.not_dispatched})
        rec = e.record  # a session call's unanswered record, checked by the Session
        if rec is None:
            return _closed_set_labels({})
        return _closed_set_labels(
            {"isolation": rec.isolation, "isolation_qualification": rec.isolation_qualification, "record_sha256": rec.sha256}
        )
    if isinstance(e, WorkspaceCallError):
        return _result_labels(e.result)
    return {}


class PlimsollExecResult(ExecResult):
    """One command's result as the SDK's ``ExecResult``, with what plimsoll states about
    its call: ``result`` (the checked project result: its tier, its sentence, its
    outcome, its run record), the truncation flags the daemon set, and ``labels``."""

    def __init__(self, out: ExecOutcome) -> None:
        super().__init__(stdout=out.stdout, stderr=out.stderr, exit_code=out.exit_code)
        self.result: ProjectResult = out.result
        self.stdout_truncated = out.stdout_truncated
        self.stderr_truncated = out.stderr_truncated
        self.labels: Dict[str, str] = _result_labels(out.result)

    @property
    def record(self) -> Optional[RunRecord]:
        return self.result.record

    @property
    def record_sha256(self) -> str:
        return self.result.record.sha256 if self.result.record is not None else ""

    @property
    def isolation(self) -> str:
        return self.result.isolation

    @property
    def isolation_qualification(self) -> str:
        return self.result.isolation_qualification

    @property
    def outcome(self) -> str:
        return self.result.outcome


def _error_message(e: BaseException) -> str:
    if isinstance(e, PlimsollError):
        return e.message
    if isinstance(e, WorkspaceCallError):
        if e.result.outcome == "setup_failed":
            return "plimsoll: the command's call ended setup_failed before any step began, so it did not run"
        # The detail is the runner's text and stays on the cause: it can name a file.
        outcome = e.result.outcome if e.result.outcome in OUTCOME_NAMES else "unknown"
        return f"plimsoll: the command's call ended {outcome} without a usable result; it may have run"
    return "plimsoll: the command failed"


class PlimsollExecError(ExecTransportError):
    """A command plimsoll refused before anything ran, or whose call ended in an error
    after which it may have run, as the SDK's ``ExecTransportError``.

    ``error`` (also the exception's cause) is the plimsoll error or the workspace's
    :class:`~plimsoll_client.workspace.WorkspaceCallError`. ``not_dispatched`` is the
    refusal's reason when nothing ran, else None: the command may have run. ``retryable``
    is :func:`plimsoll_client.retry_on`'s answer, true only for a refusal another try may
    pass. ``labels`` are the trusted labels, also the error's ``context``; ``result`` and
    ``record`` are what the daemon answered, when it answered."""

    def __init__(self, command: Sequence[Any], error: BaseException) -> None:
        labels = _error_labels(error)
        super().__init__(command=command, context=dict(labels), cause=error, message=_error_message(error), retryable=retry_on(error))
        self.error = error
        self.labels = labels
        self.not_dispatched: Optional[str] = error.not_dispatched if isinstance(error, PlimsollError) else None
        self.result: Optional[ProjectResult] = error.result if isinstance(error, WorkspaceCallError) else None

    @property
    def record(self) -> Optional[RunRecord]:
        if self.result is not None:
            return self.result.record
        return self.error.record if isinstance(self.error, PlimsollError) else None


class PlimsollExecTimeoutError(ExecTimeoutError):
    """A command past its budget, as the SDK's ``ExecTimeoutError``, with the call's
    checked ``result`` (None when the budget was zero and nothing was sent) and its
    ``labels``."""

    def __init__(self, *, command: Sequence[Any], timeout_s: Optional[float], result: Optional[ProjectResult], labels: Dict[str, str]) -> None:
        super().__init__(command=command, timeout_s=timeout_s, context=dict(labels))
        self.result = result
        self.labels = labels

    @property
    def record(self) -> Optional[RunRecord]:
        return self.result.record if self.result is not None else None


def _command_text(command: Sequence[Any]) -> str:
    parts = [str(c) for c in command]
    # The base class's own prefixes (base_sandbox_session.py:678, shell_tool.py:95): the
    # shell is the sandbox's already, and its directory and exports persist only there.
    if len(parts) == 3 and parts[0] == "sh" and parts[1] in ("-lc", "-c"):
        return parts[2]
    return shlex.join(parts)


def _label_exec_span(labels: Dict[str, str]) -> None:
    """Adds ``labels`` to the current span if it is the SDK's span around this command;
    with tracing off the current span is another (the tool call's), which is left as it
    is. Never raises: a label is never worth the command's answer."""
    if not labels:
        return
    try:
        span = get_current_span()
        data = getattr(span, "span_data", None)
        if isinstance(data, CustomSpanData) and data.name == _EXEC_SPAN and isinstance(data.data, dict):
            data.data.update(labels)
    except Exception as e:  # pragma: no cover
        log.debug("plimsoll: the sandbox.exec span was not labeled (%s)", type(e).__name__)


def _event_fields(labels: Dict[str, str], record: Optional[RunRecord]) -> Dict[str, object]:
    """What an exec finish event gets: the labels, and the checked run record whole as
    ``plimsoll_record`` (every field is the daemon's statement, checked by this client:
    digests, the provider, the tier and its sentence, the image, the times, the
    session's public fingerprint). The span gets the labels alone: a trace can leave the
    app's hands (the SDK uploads traces to OpenAI), an event sink is the app's own."""
    fields: Dict[str, object] = dict(labels)
    if record is not None:
        fields["plimsoll_record"] = dataclasses.asdict(record)
    return fields


class _InstrumentedSession(SandboxSession):
    """The SDK's instrumented wrapper (sandbox_session.py:221), the one the SDK's Vercel
    provider also subclasses, with plimsoll's labels on every command's finish event and
    span, and the run record on the event. Only what the session's own exec returned or
    raised is read for them."""

    async def _annotate(self, *, op: Any, start_data: Any, run: Any, finish_data: Any = None, **kwargs: Any) -> Any:
        if op != "exec":
            return await super()._annotate(op=op, start_data=start_data, run=run, finish_data=finish_data, **kwargs)
        fields: Dict[str, object] = {}
        # The failure event carries the start data (sandbox_session.py:416-430): a copy
        # of the kit's, which gets the fields once the command has raised.
        data = dict(start_data or {})

        async def labeled() -> Any:
            try:
                value = await run()
            except Exception as e:
                if isinstance(e, (PlimsollExecError, PlimsollExecTimeoutError)):
                    _label_exec_span(e.labels)
                    fields.update(_event_fields(e.labels, e.record))
                data.update(fields)
                raise
            if isinstance(value, PlimsollExecResult):
                _label_exec_span(value.labels)
                fields.update(_event_fields(value.labels, value.record))
            return value

        def finished(value: Any) -> Dict[str, object]:
            out: Dict[str, object] = dict(finish_data(value)) if finish_data is not None else dict(data)
            out.update(fields)
            return out

        return await super()._annotate(op=op, start_data=data, run=labeled, finish_data=finished, **kwargs)


class PlimsollSandboxClientOptions(BaseSandboxClientOptions):
    """How a session is opened: the isolation floor (``kernel`` by default: a docker
    daemon without gVisor is refused), the languages hint for a daemon's warm pool, and
    the budget of a command the SDK gives no timeout."""

    type: Literal["plimsoll"] = "plimsoll"
    minimum_isolation: str = "kernel"
    languages: tuple[str, ...] = ("python",)
    timeout: float = 120.0

    def __init__(
        self,
        minimum_isolation: str = "kernel",
        languages: tuple[str, ...] = ("python",),
        timeout: float = 120.0,
        *,
        type: Literal["plimsoll"] = "plimsoll",
    ) -> None:
        super().__init__(type=type, minimum_isolation=minimum_isolation, languages=tuple(languages), timeout=timeout)


class PlimsollSandboxSessionState(SandboxSessionState):
    """What a persisted session keeps: the daemon, how the session was opened (so a resume
    opens its replacement the same way), the session's public fingerprint and the tier it
    opened at. Never the session ID: a resume cannot use it, and the state is written
    wherever the app keeps run state."""

    type: Literal["plimsoll"] = "plimsoll"
    base_url: str = ""
    minimum_isolation: str = "kernel"
    languages: tuple[str, ...] = ("python",)
    timeout: float = 120.0
    fingerprint: str = ""
    isolation: str = ""


class PlimsollSandboxSession(BaseSandboxSession):
    """One plimsoll session as an Agents SDK sandbox session."""

    state: PlimsollSandboxSessionState

    def __init__(self, *, state: PlimsollSandboxSessionState, workspace: Workspace) -> None:
        self.state = state
        self._workspace = workspace
        self._running = False

    @property
    def workspace(self) -> Workspace:
        return self._workspace

    # ---- lifecycle hooks the base class drives ----

    async def _validate_manifest_application(
        self,
        *,
        only_ephemeral: bool = False,
        manifest: Manifest | None = None,
        session_running: bool | None = None,
    ) -> None:
        _ = (only_ephemeral, session_running)
        from agents.sandbox._mount_security import validate_manifest_mount_credential_boundaries

        validate_manifest_mount_credential_boundaries(manifest or self.state.manifest, provider_backend_id=BACKEND_ID)

    async def _prepare_backend_workspace(self) -> None:
        # The work directory exists before any call: the daemon made it with the session.
        return None

    async def _after_start(self) -> None:
        self._running = True

    async def _after_start_failed(self) -> None:
        self._running = False

    async def _apply_manifest(self, *, only_ephemeral: bool = False, provision_accounts: bool = True) -> MaterializationResult:
        if self.state.manifest.users or self.state.manifest.groups:
            raise ValueError("a plimsoll sandbox runs as one user: manifest users and groups are not supported")
        return await super()._apply_manifest(only_ephemeral=only_ephemeral, provision_accounts=provision_accounts)

    async def provision_manifest_accounts(self) -> None:
        if self.state.manifest.users or self.state.manifest.groups:
            raise ValueError("a plimsoll sandbox runs as one user: manifest users and groups are not supported")

    async def _shutdown_backend(self) -> None:
        await asyncio.to_thread(self._close_quietly)

    async def _after_shutdown(self) -> None:
        self._running = False

    async def _after_stop(self) -> None:
        # A stopped session is closed on the daemon: the snapshot the base class persisted
        # before this hook is what a resume restores.
        await asyncio.to_thread(self._close_quietly)
        self._running = False

    def _close_quietly(self) -> None:
        try:
            self._workspace.close()
        except PlimsollError:
            pass  # ended already; the daemon has it either way

    def supports_pty(self) -> bool:
        return False

    def _should_compute_snapshot_fingerprint_on_persist(self) -> bool:
        # The fingerprint only lets a resume that reattaches to the same sandbox skip the
        # restore (snapshot_lifecycle.py:63-83); a resume here always opens a new one. Its
        # helper is also installed in /tmp and run from there, and /tmp is noexec in a
        # plimsoll docker sandbox (exit 126, seen on docker 2026-11-17), so it is two calls
        # at every stop that cannot succeed. The SDK's Vercel provider turns it off too.
        return False

    # ---- what the SDK requires of a session ----

    async def _exec_internal(self, *command: str | Path, timeout: float | None = None) -> ExecResult:
        """Runs the command as one call of the session. Returns a
        :class:`PlimsollExecResult` (a non-zero exit is a result); raises
        :class:`PlimsollExecTimeoutError` past the budget and :class:`PlimsollExecError`
        on a refusal or an error after which the command may have run. Cancelling the
        await cancels the call."""
        if timeout is not None and timeout <= 0:
            # A budget of zero expires before anything could run, as the SDK's own local
            # client's asyncio.wait_for does (unix_local.py:410); nothing is sent.
            raise PlimsollExecTimeoutError(command=command, timeout_s=timeout, result=None, labels=_closed_set_labels({"refused": "request"}))
        parts = [str(c) for c in command]
        if len(parts) >= 4 and parts[:2] == ["sudo", "-u"] and parts[3] == "--":
            # The SDK's prefix for a command run as another user (base_sandbox_session.py:699).
            raise PlimsollExecError(
                command, InvalidRequestError("plimsoll: a plimsoll sandbox runs as one user; a command for another user was not sent", not_dispatched="request")
            )
        text = _command_text(command)
        if "\x00" in text:
            raise PlimsollExecError(command, InvalidRequestError("plimsoll: a command cannot carry a NUL byte; nothing was sent", not_dispatched="request"))
        try:
            out = await in_thread(self._workspace.exec, text, timeout=timeout)
        except (PlimsollError, WorkspaceCallError) as e:
            raise PlimsollExecError(command, e) from e
        if out.timed_out:
            raise PlimsollExecTimeoutError(command=command, timeout_s=timeout, result=out.result, labels=_result_labels(out.result))
        return PlimsollExecResult(out)

    async def read(self, path: Path, *, user: Any = None) -> io.IOBase:
        """The whole file. FileNotFoundError when there is none (the SDK's contract,
        base_sandbox_session.py:925); a file past one call's artifact budget (8 MiB) is
        read in pieces and checked against its size, never handed over cut. A file longer
        than 64 MiB (``workspace.MAX_WHOLE_BYTES``) is a ``WorkspaceArchiveReadError`` with
        reason ``too_large``, read no further than its first piece: code in the sandbox
        can make a file of any size, and a whole read ends in this process's memory."""
        _ = user
        return io.BytesIO(await self._file_call(path, WorkspaceArchiveReadError, self._read_whole, str(path), None))

    async def _read_bounded(self, path: Path, *, max_bytes: int) -> bytes:
        # The SDK's bounded read (base_sandbox_session.py:935) asks only for a prefix.
        return await self._file_call(path, WorkspaceArchiveReadError, self._read_whole, str(path), max_bytes)

    async def write(self, path: Path, data: io.IOBase, *, user: Any = None) -> None:
        _ = user
        payload = data.read()
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        await self._file_call(path, WorkspaceArchiveWriteError, self._workspace.write, str(path), bytes(payload))

    async def _file_call(self, path: Path, error: type, fn: Callable[..., Any], *args: Any) -> Any:
        try:
            return await in_thread(fn, *args)
        except (PlimsollError, WorkspaceCallError) as e:
            raise error(path=path, context=_error_labels(e), cause=e, retryable=retry_on(e)) from e
        except TimeoutError as e:
            # The workspace's call ran past its budget: it may have run (a write may be half
            # done), so it is the SDK's error and never retried, not a bare OSError.
            raise error(path=path, context={"reason": "timed_out"}, cause=e, retryable=False) from e

    def _read_whole(self, path: str, limit: Optional[int], cancel: Optional[CancelHandle] = None) -> bytes:
        """The whole file (``Workspace.read_whole``, at most its 64 MiB, MAX_WHOLE_BYTES),
        or its first ``limit`` bytes (``Workspace.read_head``), checked against its size."""
        try:
            if limit is None:
                return self._workspace.read_whole(path, cancel=cancel)
            return self._workspace.read_head(path, limit, cancel=cancel)
        except WorkspaceChangedError:
            raise WorkspaceArchiveReadError(path=Path(path), context={"reason": "changed_while_read"}) from None
        except WorkspaceTooLargeError as e:
            raise WorkspaceArchiveReadError(path=Path(path), context={"reason": "too_large"}, cause=e) from e

    async def running(self) -> bool:
        """False once the daemon reported the session's end, or once this client stopped
        sending on it after a call it could not check (a command cut in flight): every
        later call would be refused, so the SDK's runtime must not take it as live."""
        if not self._running:
            return False
        s = self._workspace.session
        return getattr(s, "ended", None) is None and getattr(s, "stopped", None) is None

    async def persist_workspace(self) -> io.IOBase:
        return io.BytesIO(await in_thread(self._workspace.persist))

    async def hydrate_workspace(self, data: io.IOBase) -> None:
        payload = data.read()
        await in_thread(self._workspace.hydrate, bytes(payload))


class PlimsollSandboxClient(BaseSandboxClient[PlimsollSandboxClientOptions]):
    """Creates, resumes and deletes plimsoll sessions for the Agents SDK.

    ``client`` is the plimsoll client the sessions are opened with. ``instrumentation``
    is the SDK's: its event sinks get every command's labels. ``workspace_factory``
    replaces how a session's :class:`Workspace` is made, for tests.
    """

    backend_id = BACKEND_ID
    supports_default_options = True

    def __init__(
        self,
        client: Optional[Client],
        *,
        instrumentation: Instrumentation | None = None,
        dependencies: Dependencies | None = None,
        workspace_factory: Optional[WorkspaceFactory] = None,
    ) -> None:
        if client is None and workspace_factory is None:
            raise ValueError("a plimsoll Client is required (a workspace_factory stands in for it in tests)")
        self._client = client
        self._factory = workspace_factory
        self._instrumentation = instrumentation if instrumentation is not None else Instrumentation()
        self._dependencies = dependencies

    def _wrap_session(self, inner: BaseSandboxSession, *, instrumentation: Instrumentation | None = None) -> SandboxSession:
        # As the base class's (sandbox_client.py:121), with the labelling wrapper.
        return _InstrumentedSession(inner, instrumentation=instrumentation, dependencies=self._resolve_dependencies())

    def _open(self, options: PlimsollSandboxClientOptions) -> Workspace:
        if self._factory is not None:
            return self._factory(options)
        assert self._client is not None
        session = self._client.open_session(minimum_isolation=options.minimum_isolation, languages=list(options.languages))
        return Workspace(session, timeout=options.timeout)

    async def _open_owned(self, options: PlimsollSandboxClientOptions) -> Workspace:
        """:meth:`_open` in a worker thread. Cancelling the await cannot stop an open in
        flight, so a session the daemon opens after the cancel is closed when it arrives
        instead of holding the daemon's slot until it expires."""
        lock = threading.Lock()
        handed: List[Workspace] = []
        abandoned = False

        def open_in_thread() -> Optional[Workspace]:
            ws = self._open(options)
            with lock:
                if not abandoned:
                    handed.append(ws)
                    return ws
            _close_quietly(ws)
            return None

        try:
            ws = await asyncio.to_thread(open_in_thread)
        except asyncio.CancelledError:
            with lock:
                abandoned = True
                orphans = list(handed)
            for o in orphans:
                threading.Thread(target=_close_quietly, args=(o,), name="plimsoll-close-abandoned-session").start()
            raise
        if ws is None:  # pragma: no cover  (only a cancel abandons the open)
            raise asyncio.CancelledError()
        return ws

    async def create(
        self,
        *,
        snapshot: SnapshotSpec | SnapshotBase | None = None,
        manifest: Manifest | None = None,
        options: PlimsollSandboxClientOptions | None = None,
    ) -> SandboxSession:
        resolved = options if options is not None else PlimsollSandboxClientOptions()
        manifest = manifest if manifest is not None else Manifest()
        self._validate_manifest_for_create(manifest)
        workspace = await self._open_owned(resolved)
        try:
            if manifest.root == _DEFAULT_MANIFEST_ROOT:
                # The daemon decides the work directory; the SDK's default names another.
                root = await asyncio.to_thread(lambda: workspace.root)
                manifest = manifest.model_copy(update={"root": root}, deep=True)
            session_id = uuid.uuid4()
            state = PlimsollSandboxSessionState(
                session_id=session_id,
                manifest=manifest,
                snapshot=resolve_snapshot(snapshot, str(session_id)),
                base_url=self._client.base_url if self._client is not None else "",
                minimum_isolation=resolved.minimum_isolation,
                languages=tuple(resolved.languages),
                timeout=resolved.timeout,
                fingerprint=getattr(workspace.session, "fingerprint", "") or "",
                isolation=getattr(workspace.session, "isolation", "") or "",
            )
        except BaseException:
            await asyncio.to_thread(lambda: _close_quietly(workspace))
            raise
        inner = PlimsollSandboxSession(state=state, workspace=workspace)
        return self._wrap_session(inner, instrumentation=self._instrumentation)

    async def resume(self, state: SandboxSessionState) -> SandboxSession:
        """A new session opened as the old one was; the base class's ``start`` restores
        the snapshot into it. The old session, if it still exists on the daemon, ends by
        its own lifetime: this client cannot reach it from here."""
        if not isinstance(state, PlimsollSandboxSessionState):
            raise TypeError("PlimsollSandboxClient.resume expects a PlimsollSandboxSessionState")
        options = PlimsollSandboxClientOptions(
            minimum_isolation=state.minimum_isolation, languages=tuple(state.languages), timeout=state.timeout
        )
        workspace = await self._open_owned(options)
        try:
            root = await asyncio.to_thread(lambda: workspace.root) if state.manifest.root == _DEFAULT_MANIFEST_ROOT else state.manifest.root
            new_state = state.model_copy(
                update={
                    "manifest": state.manifest.model_copy(update={"root": root}, deep=True),
                    "fingerprint": getattr(workspace.session, "fingerprint", "") or "",
                    "isolation": getattr(workspace.session, "isolation", "") or "",
                    "workspace_root_ready": False,
                },
                deep=True,
            )
        except BaseException:
            await asyncio.to_thread(lambda: _close_quietly(workspace))
            raise
        inner = PlimsollSandboxSession(state=new_state, workspace=workspace)
        return self._wrap_session(inner, instrumentation=self._instrumentation)

    async def delete(self, session: SandboxSession) -> SandboxSession:
        inner = session._inner
        if not isinstance(inner, PlimsollSandboxSession):
            raise TypeError("PlimsollSandboxClient.delete expects a PlimsollSandboxSession")
        await asyncio.to_thread(inner._close_quietly)
        inner._running = False
        return session

    def deserialize_session_state(self, payload: dict[str, object]) -> SandboxSessionState:
        return self._deserialize_session_state_payload(payload, PlimsollSandboxSessionState)
