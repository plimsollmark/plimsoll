"""Microsoft Agent Framework: a plimsoll session as an agent's shell, and plimsoll's code tool.

Microsoft Agent Framework (``agent-framework-core`` 1.26.0, with the shell tools of
``agent-framework-tools`` 1.0.0b261112, read on 2026-11-15) gives an agent a shell through a
**shell executor**: an object with ``start``, ``run``, ``close`` and ``as_function``, which
``create_harness_agent(client, shell_executor=...)`` turns into the agent's ``run_shell``
tool, and whose ``run`` the framework's ``ShellEnvironmentProvider`` uses to tell the model
what shell it has. :class:`PlimsollShellTool` is that executor over one plimsoll session,
through :class:`plimsoll_client.workspace.Workspace` (every command is a call of the session
with a fixed step, the command as a file), so the daemon's guarantees hold for the agent's
whole conversation: the isolation floor, a run record on every call, no network unless the
operator granted it.

    from agent_framework import create_harness_agent
    from plimsoll_client import Client
    from plimsoll_client.agent_framework import PlimsollShellTool

    async with PlimsollShellTool(Client("https://plimsoll.internal:8746", token=TOKEN),
                                 minimum_isolation="kernel") as shell:
        agent = create_harness_agent(chat_client, shell_executor=shell)
        session = agent.create_session()
        print(await agent.run("...", session=session))

What the tool needs and does, stated here and in the docstrings:

- **The floor is yours to set.** ``minimum_isolation`` has no default. :meth:`~PlimsollShellTool.start`
  opens the session and checks the tier it states before any command; below the floor it
  closes the session and raises, and nothing of the agent's ran.
- **One tool, one conversation.** The tool opens one session and keeps it: the files, the
  shell's directory and its exported variables persist from one command to the next, as the
  framework's own shell executors promise. A process left in the background is killed when
  its command's call ends; a session left idle is suspended by the daemon and resumes, files
  kept, on its next command. Once the session has ended (its lifetime ran out, the daemon
  closed it, or :meth:`~PlimsollShellTool.close`) every later command raises
  :class:`~plimsoll_client.SessionEndedError`; the tool never opens a fresh sandbox in its
  place, because an agent would take it for the one with its files.
- **A refusal raises.** A call plimsoll refused before anything ran, one that may have run
  without an answer to show for it, and a call on an ended session raise the client's own
  exceptions, unchanged; they never come back as command output. Through an agent, a refusal
  before anything ran (and ``setup_failed``, where no step began) reaches the model as the
  framework's error result. Any other error (a command that may have run without an answer, or
  an exception plimsoll cannot vouch ran nothing) instead ends the agent's run: the tool raises the framework's ``MiddlewareFailure``, its fail-closed escape,
  with plimsoll's error as its ``__cause__``, so the model is never asked whether to run it
  again (:func:`may_have_run` says which errors those are). They are not the framework's own shell errors
  (``ShellExecutionError`` and its kin) on purpose: its ``ShellEnvironmentProvider`` reads a
  probe that raises one of those as a command that is not installed
  (agent_framework_tools/shell/_environment.py:238), so a refusal would reach the model as a
  missing CLI; and the framework has no retry flag on them to carry
  :func:`plimsoll_client.retry_on`'s answer. A command's own non-zero exit, and a command past
  its time budget, are results.
- **The shell is the image's.** On plimsoll's docker images that is BusyBox ``sh``, not bash.
- **What plimsoll states about each call reaches the application**, through the framework's
  own channels. :meth:`~PlimsollShellTool.run` returns a :class:`PlimsollShellResult` (the
  framework's ``ShellResult`` with the tier, the sentence the provider states beside it, the
  outcome, the run record's SHA-256 and the checked result). Through an agent, each command's
  function result carries, in its text item's ``additional_properties``, the five fields
  Microsoft's own shell tool puts there (``stdout``, ``stderr``, ``exit_code``, ``truncated``,
  ``timed_out``) and plimsoll's labels (:data:`LABEL_KEYS`): whether the call was dispatched,
  the refusal's reason when it was not, the outcome, the tier, the provider's sentence and the
  record's SHA-256. A raised refusal reaches the application as the exception itself, in a
  function middleware (``context`` and ``call_next``) that awaits ``call_next()``: the
  framework turns it into the model's error result after the middleware. When the
  framework's OpenTelemetry tool span is recording, the same labels go on it as span
  attributes named ``plimsoll.<label>``. Every label is checked against its closed set
  (``plimsoll_client._langsmith.labels``): no code, output, path or detail text is ever a
  label.
- **No automatic retry.** The framework does not run a failed tool call again by itself
  (agent-framework-core 1.26.0, ``_tools.py``: a raised exception becomes one error result,
  and ``max_consecutive_errors_per_request``, 3 by default, ends the request). After a
  refusal the model may ask for the command again, which runs nothing twice; after a command
  that may have run, the run has stopped. A retry of your own (an agent middleware, say)
  should ask :func:`plimsoll_client.retry_on` first: it says yes only when nothing ran.

:func:`plimsoll_code_tool` is plimsoll's stateless code tool (a fresh sandbox per call,
:class:`~plimsoll_client.execution.CodeExecutor`) as an Agent Framework tool; it answers with
the dict ``plimsoll_client._code_tool`` describes and never raises, and its function result's
text item carries the same labels in ``additional_properties``.

Needs Agent Framework and its shell tools (``pip install agent-framework-plimsoll``, which pins
``agent-framework-tools`` exactly: it is a beta, released about weekly).
"""

from __future__ import annotations

import asyncio
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Mapping, Optional, Sequence, Type

try:
    from agent_framework import Content, FunctionTool, MiddlewareFailure, tool
    from agent_framework_tools.shell import ShellResult
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "plimsoll_client.agent_framework needs Microsoft Agent Framework and its shell tools: pip install "
        "agent-framework-plimsoll (or agent-framework-core and agent-framework-tools==1.0.0b261112)"
    ) from e
try:
    # The kind that marks a tool as the agent's shell. A private module's name, imported as the
    # framework's own DockerShellTool imports it (read at agent-framework-core 1.26.0).
    from agent_framework._tools import SHELL_TOOL_KIND_VALUE
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "plimsoll_client.agent_framework: this agent-framework-core no longer has SHELL_TOOL_KIND_VALUE in "
        "agent_framework._tools, which marks the shell tool; it was checked on agent-framework-core 1.26.0"
    ) from e
from pydantic import BaseModel, Field, create_model

from . import _code_tool as ct
from . import _validate as v
from ._langsmith import KEYS as LABEL_KEYS
from ._langsmith import labels as _closed_set_labels
from ._transport import CancelHandle, in_thread
from .aio import AsyncClient
from .client import Client, Session
from .errors import InsufficientIsolationError, InvalidRequestError, PlimsollError
from .execution import CodeExecutor
from .types import ProjectResult, RunRecord, meets
from .workspace import Workspace, WorkspaceCallError, _check_text
from .workspace import close_quietly as _close_quietly

__all__ = ["PlimsollShellTool", "PlimsollShellResult", "plimsoll_code_tool", "call_labels", "may_have_run", "LABEL_KEYS", "InputFile"]

#: Characters of stdout and of stderr a command returns, each: about 7,500 tokens per stream.
MAX_OUTPUT_CHARS = 30_000

_APPROVAL_MODES = ("always_require", "never_require")

log = logging.getLogger("plimsoll_client")


@dataclass(frozen=True)
class PlimsollShellResult(ShellResult):
    """One command's result: the framework's ``ShellResult`` (agent_framework_tools/shell/_types.py:16,
    at 1.0.0b261112), so the harness and its environment provider read it as any shell's, with
    what plimsoll states about the call. ``isolation`` is the tier the call ran at,
    ``isolation_qualification`` the sentence the provider states beside it ("" when it states
    none), ``outcome`` plimsoll's word for how the run ended (``completed`` or ``timed_out``),
    ``record_sha256`` the SHA-256 of the run record the client checked ("" when the answer
    carried none), and ``result`` the checked result itself (``result.record`` is the record)."""

    isolation: str = ""
    isolation_qualification: str = ""
    outcome: str = ""
    record_sha256: str = ""
    result: Optional[ProjectResult] = field(default=None, compare=False, repr=False)

    @property
    def record(self) -> Optional[RunRecord]:
        """The run record the client checked, or None."""
        return self.result.record if self.result is not None else None


def _answer(r: ProjectResult) -> Dict[str, Any]:
    """A checked result in the shape of the code tool's answer, for the label check."""
    return {
        "outcome": r.outcome,
        "isolation": r.isolation,
        "isolation_qualification": r.isolation_qualification,
        "record_sha256": r.record.sha256 if r.record is not None else "",
    }


def call_labels(value: Any) -> Dict[str, str]:
    """plimsoll's labels (:data:`LABEL_KEYS`) for what a call of either tool gave: a
    :class:`PlimsollShellResult`, the code tool's answer (a dict), or the exception a shell
    command raised. Each value is checked against its closed set and left out when it does
    not pass, so nothing the guest wrote is ever a label. A refusal before anything ran is
    ``plimsoll_dispatched`` ``no`` with its reason; an answered run is ``yes`` with its
    outcome; any other exception is ``unknown`` (no mark means the command may have run),
    with the tier and record digest when the error carries the unanswered call's record. The
    ``MiddlewareFailure`` that stops a run after a command that may have run is read through to
    plimsoll's error, its ``__cause__``."""
    if isinstance(value, MiddlewareFailure) and value.__cause__ is not None:
        value = value.__cause__
    if isinstance(value, PlimsollShellResult):
        return _closed_set_labels(_answer(value.result) if value.result is not None else {
            "outcome": value.outcome, "isolation": value.isolation,
            "isolation_qualification": value.isolation_qualification, "record_sha256": value.record_sha256,
        })
    if isinstance(value, Mapping):
        return _closed_set_labels(value)
    if isinstance(value, WorkspaceCallError):
        return _closed_set_labels(_answer(value.result))
    if isinstance(value, PlimsollError) and value.not_dispatched is not None:
        return _closed_set_labels({"refused": value.not_dispatched})
    record = value.record if isinstance(value, PlimsollError) else None
    if record is None:
        return _closed_set_labels({})
    return _closed_set_labels({
        "isolation": record.isolation, "isolation_qualification": record.isolation_qualification, "record_sha256": record.sha256,
    })


def may_have_run(e: BaseException) -> bool:
    """Whether a shell command that raised ``e`` may have run. Only three things say it did not:
    a refusal carrying plimsoll's not-dispatched mark (the tool's own check of the command, made
    before anything is sent, raises one too), and an answered call that ended ``setup_failed``
    (no step began). Everything else may have followed the command running, whatever its type:
    an unmarked error of plimsoll's, an answered call with no step report, and any exception
    that is not plimsoll's, as the client's ``Session`` takes it (after one, the session refuses
    every later call before sending)."""
    if isinstance(e, PlimsollError) and e.not_dispatched is not None:
        return False
    if isinstance(e, WorkspaceCallError) and e.result.outcome == "setup_failed":
        return False
    return True


def _check_command(command: Any) -> None:
    """The workspace's check of a command's text, made before the call and raised as a marked
    refusal (``not_dispatched == "request"``), so nothing that ran is ever taken for one that did
    not: a command that is not text or holds a NUL is refused before anything is sent."""
    try:
        _check_text("command", command, allow_newline=True)
    except (TypeError, ValueError) as e:
        raise InvalidRequestError(f"plimsoll: {e}; nothing was sent", not_dispatched="request") from e


def _label_span(tool_name: str, labels: Mapping[str, str]) -> None:
    """Puts ``labels`` on the framework's OpenTelemetry span for this tool call as
    ``plimsoll.<label>`` attributes. The framework opens that span as the current span
    around the tool's function (``FunctionTool.invoke``, agent_framework/_tools.py, through
    ``get_function_span``, agent_framework/observability.py:2724) whenever its
    instrumentation is enabled; a span that says it is another operation or another tool is
    left alone, and so is a span that is not recording (no OpenTelemetry SDK installed) or does
    not show its attributes.
    Never raises: a label is never worth the call's answer."""
    try:
        from agent_framework.observability import OBSERVABILITY_SETTINGS, OtelAttr
        from opentelemetry import trace

        if not OBSERVABILITY_SETTINGS.ENABLED:
            return
        span = trace.get_current_span()
        if not span.is_recording():
            return
        attributes = getattr(span, "attributes", None)
        # Only a span that shows it is this tool's call is labeled: one whose attributes cannot
        # be read may be an application's own.
        if attributes is None or (
            attributes.get(OtelAttr.OPERATION) != OtelAttr.TOOL_EXECUTION_OPERATION or attributes.get(OtelAttr.TOOL_NAME) != tool_name
        ):
            return
        span.set_attributes({"plimsoll." + k[len("plimsoll_"):]: v for k, v in labels.items()})
    except Exception as e:
        log.debug("plimsoll: the tool span was not labeled (%s)", type(e).__name__)


def _with_labels(parsed: List[Content], extra: Mapping[str, Any]) -> List[Content]:
    """``parsed`` (the framework's own parse of the tool's answer), each item carrying
    ``extra`` in its ``additional_properties``, as Microsoft's shell tool carries its fields
    (agent_framework_tools/shell/_types.py:67)."""
    for item in parsed:
        item.additional_properties = {**(item.additional_properties or {}), **extra}
    return parsed


def _seconds(what: str, value: Any, *, optional: bool = False) -> Optional[float]:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"plimsoll: {what} must be a positive number of seconds, not {value!r}")
    return float(value)


def _format(result: ShellResult) -> str:
    """What the model is shown of one command: the exit code line, then stdout, then
    stderr, then a note when either was cut."""
    parts = [f"exit code: {result.exit_code}" + (" (the command ran past its time budget and was stopped)" if result.timed_out else "")]
    if result.stdout:
        parts.append(result.stdout.rstrip("\n"))
    if result.stderr:
        parts.append("stderr:\n" + result.stderr.rstrip("\n"))
    if result.truncated:
        parts.append("[output truncated]")
    return "\n".join(parts)


class PlimsollShellTool:
    """An Agent Framework shell executor over one plimsoll session (``ShellExecutor``,
    with ``as_function`` as ``create_harness_agent`` requires of one).

    ``minimum_isolation`` (``process``, ``container``, ``kernel`` or ``vm``) is the tier
    the session must state; it has no default. ``lifetime`` (seconds) may only shorten
    the daemon's own session lifetime. ``timeout`` is the budget of a command that names
    none; ``max_timeout`` caps any budget, for a daemon whose ceiling you know (the docker
    provider cuts a budget past its own ceiling to that ceiling, with no error: a command
    given 600 s on a daemon whose ceiling is 120 s ends ``timed_out`` at 120 s, measured
    2026-11-18). ``max_output_chars`` cuts stdout and stderr,
    each, before the model sees them. ``approval_mode`` is the framework's
    (``never_require`` by default: the sandbox, not a person, is the boundary).
    ``languages`` hints which interpreters a daemon with a warm pool should have ready;
    ``owner`` names the end user, for a daemon's per-owner cap
    (:meth:`plimsoll_client.Client.open_session`).

    ``client`` is a :class:`plimsoll_client.Client`: the tool runs its calls in a worker
    thread, so the event loop is never blocked.
    """

    def __init__(
        self,
        client: Client,
        *,
        minimum_isolation: str,
        lifetime: float = 3600.0,
        timeout: float = 120.0,
        max_timeout: Optional[float] = None,
        max_output_chars: int = MAX_OUTPUT_CHARS,
        approval_mode: str = "never_require",
        languages: Optional[Sequence[str]] = None,
        owner: Optional[str] = None,
    ) -> None:
        if isinstance(client, AsyncClient):
            raise TypeError("plimsoll: PlimsollShellTool needs a plimsoll_client.Client (it runs each call in a worker thread)")
        if not v.floor(minimum_isolation):
            raise ValueError("plimsoll: a shell tool needs a floor: minimum_isolation process, container, kernel or vm")
        if approval_mode not in _APPROVAL_MODES:
            raise ValueError(f"plimsoll: approval_mode must be one of {_APPROVAL_MODES}, not {approval_mode!r}")
        self._client = client
        self._floor = minimum_isolation
        self._lifetime = _seconds("lifetime", lifetime)
        self._timeout = _seconds("timeout", timeout)
        self._max_timeout = _seconds("max_timeout", max_timeout, optional=True)
        self._max_output_chars = ct.check_max_output(max_output_chars)
        self._approval_mode = approval_mode
        self._languages = v.languages(languages) or None
        self._owner = owner
        # Held while the session is opened, in the worker thread: the open is one blocking
        # call, and two starts at once (the framework's environment probe and a command,
        # say) must open one session between them, whatever event loop each runs on.
        self._lock = threading.Lock()
        self._session: Optional[Session] = None
        self._workspace: Optional[Workspace] = None

    # ---- the session ----

    def _open(self) -> Workspace:
        with self._lock:
            if self._workspace is not None:
                return self._workspace
            session = self._client.open_session(
                minimum_isolation=self._floor, lifetime=self._lifetime, languages=self._languages, owner=self._owner
            )
            try:
                # The client checks the tier against the floor it sent; this is the tool's own
                # check, so the floor holds whatever the client is.
                if not meets(getattr(session, "isolation", "") or "", self._floor):
                    raise InsufficientIsolationError(
                        f"plimsoll: the session states {getattr(session, 'isolation', '') or 'no tier'}, below the required "
                        f"{self._floor}; nothing ran (the session was closed)",
                        not_dispatched="isolation",
                    )
                workspace = Workspace(session, timeout=self._timeout, max_timeout=self._max_timeout)
            except BaseException:
                _close_quietly(session)
                raise
            self._session, self._workspace = session, workspace
            return workspace

    async def start(self) -> None:
        """Opens the session and checks its tier against the floor; below it, closes the
        session and raises :class:`~plimsoll_client.InsufficientIsolationError`, and no
        command is sent. Once a session is open, a second call does nothing, and so does
        a call after :meth:`close`: the tool never replaces the session it opened."""
        await asyncio.to_thread(self._open)

    async def close(self) -> None:
        """Closes the session: the sandbox and its files are gone, and every later
        command raises :class:`~plimsoll_client.SessionEndedError`. Safe to call twice,
        and before :meth:`start` (nothing to close)."""
        await asyncio.to_thread(self._close)

    def _close(self) -> None:
        # Under the open's lock: a close that races a start (or a start whose await was
        # canceled while its thread went on opening) waits for the open, then closes what
        # it opened, so no session outlives close().
        with self._lock:
            if self._session is not None:
                _close_quietly(self._session)

    async def __aenter__(self) -> "PlimsollShellTool":
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    @property
    def session(self) -> Session:
        """The plimsoll session; raises :class:`RuntimeError` before :meth:`start`."""
        if self._session is None:
            raise RuntimeError("plimsoll: the shell tool has no session before start()")
        return self._session

    @property
    def isolation(self) -> str:
        """The tier the session stated when it opened; raises :class:`RuntimeError` before :meth:`start`."""
        return self.session.isolation

    # ---- commands ----

    def _budget(self, timeout: Optional[float]) -> float:
        if timeout is None or (not isinstance(timeout, bool) and timeout == 0):
            budget = self._timeout
        else:
            budget = _seconds("timeout", timeout)
        assert budget is not None
        if self._max_timeout is not None and budget > self._max_timeout:
            budget = self._max_timeout
        return budget

    def _exec(self, command: str, budget: float, cancel: Optional[CancelHandle] = None) -> PlimsollShellResult:
        workspace = self._open()  # opens the session on the first command, if start() was not called
        began = time.monotonic()
        out = workspace.exec(command, timeout=budget, cancel=cancel)
        duration_ms = int((time.monotonic() - began) * 1000)
        stdout, stderr = out.stdout_text, out.stderr_text
        n = self._max_output_chars
        r = out.result
        return PlimsollShellResult(
            stdout=stdout[:n],
            stderr=stderr[:n],
            exit_code=out.exit_code,
            duration_ms=duration_ms,
            truncated=out.stdout_truncated or out.stderr_truncated or len(stdout) > n or len(stderr) > n,
            timed_out=out.timed_out,
            isolation=r.isolation,
            isolation_qualification=r.isolation_qualification,
            outcome=r.outcome,
            record_sha256=r.record.sha256 if r.record is not None else "",
            result=r,
        )

    async def run(self, command: str, *, timeout: Optional[float] = None) -> PlimsollShellResult:  # noqa: ASYNC109
        """Runs ``command`` as shell text in the session (BusyBox ``sh`` on plimsoll's docker
        images), in the shell's current directory with its exported variables, and keeps
        both for the next command. Opens the session first if :meth:`start` was not called.

        ``timeout`` (seconds; ``None`` or 0 for the tool's default) is capped at
        ``max_timeout``. plimsoll enforces it, not this process: the daemon stops a command
        at its budget, and its cleanup after every call kills whatever the command left
        running, so a timeout never leaks a process; that is the cancellation-safe
        enforcement the ``ShellExecutor`` protocol asks for. A command past its budget is a
        result with ``timed_out`` set, as a non-zero exit is a result. The result is a
        :class:`PlimsollShellResult`: the tier, the provider's sentence, the outcome and the
        run record come with the output.

        The call runs in a worker thread. Canceling the await cancels the call: a command
        not yet sent is never sent, and the connection of one in flight is cut (it may have
        run; the session then sends nothing more). A refusal before anything ran, an error
        after which the command may have run, and a call on an ended session raise the
        client's own exceptions; none is ever returned as output, and none is retried.
        """
        budget = self._budget(timeout)
        _check_command(command)
        return await in_thread(self._exec, command, budget)

    def _description(self) -> str:
        tier = f"the {self._session.isolation} isolation tier" if self._session is not None else f"the {self._floor} isolation tier or stronger"
        return (
            f"Run a shell command in a plimsoll sandbox, isolated at {tier}, and return its exit code, stdout and "
            "stderr. The shell is the sandbox image's sh (BusyBox sh on plimsoll's docker images). There is no network access unless the operator of the sandbox "
            "granted it. Files, the working directory and exported variables persist from one command to the next for "
            "this conversation; a process left running in the background is stopped when its command returns."
        )

    def as_function(self, *, name: str = "run_shell", description: Optional[str] = None) -> FunctionTool:
        """The agent's shell tool, ``name(command)``, marked as the shell
        (``SHELL_TOOL_KIND_VALUE``) and with this tool's ``approval_mode``. It answers the
        model with one text block (the exit code line, then stdout, then stderr, with a note
        when output was cut), whose ``additional_properties`` carry Microsoft's five shell
        fields and plimsoll's labels for the application, and lets every exception out: a
        refusal is never shown to the model as a command's output. The labels also go on the
        framework's tool span when it is recording."""

        async def _run_shell(command: str) -> PlimsollShellResult:
            try:
                result = await self.run(command)
            except Exception as e:
                _label_span(name, call_labels(e))
                if may_have_run(e):
                    # The framework's fail-closed escape (agent_framework._middleware.MiddlewareFailure,
                    # at 1.26.0): never turned into the model's error result, so the model cannot ask
                    # for a command again that may already have run; plimsoll's error is its cause.
                    raise MiddlewareFailure(
                        f"plimsoll: the command may have run without an answer to show for it ({e}); the agent's run "
                        "is stopped rather than handing the model an error it could answer by running the command again"
                    ) from e
                raise
            _label_span(name, call_labels(result))
            return result

        def _parse(result: Any) -> List[Content]:
            if not isinstance(result, PlimsollShellResult):  # pragma: no cover  # only _run_shell's answer reaches it
                return FunctionTool.parse_result(result)
            fields = {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
                "truncated": result.truncated,
                "timed_out": result.timed_out,
            }
            return _with_labels([Content.from_text(_format(result))], {**fields, **call_labels(result)})

        text = description or self._description()
        _run_shell.__doc__ = text
        return tool(
            func=_run_shell, name=name, description=text, approval_mode=self._approval_mode, kind=SHELL_TOOL_KIND_VALUE, result_parser=_parse
        )


# ---- the stateless code tool ----


class InputFile(BaseModel):
    """One text file written into the sandbox before the code runs."""

    path: str = Field(description=ct.PATH_HELP)
    content: str = Field(description=ct.CONTENT_HELP)


def _code_schema(languages: Sequence[str]) -> Type[BaseModel]:
    # The language enum names exactly the languages this tool offers.
    return create_model(
        "PlimsollCodeInput",
        code=(str, Field(description=ct.CODE_HELP)),
        language=(Literal[tuple(languages)], Field(default=languages[0], description=f'{ct.LANGUAGE_HELP} Default "{languages[0]}".')),  # type: ignore[valid-type]
        input_files=(Optional[List[InputFile]], Field(default=None, description=ct.FILES_HELP)),
    )


def plimsoll_code_tool(
    executor: CodeExecutor,
    *,
    languages: Sequence[str] = ("python",),
    name: str = ct.TOOL_NAME,
    max_output_chars: int = MAX_OUTPUT_CHARS,
) -> FunctionTool:
    """Agent Framework tool ``plimsoll_run_code`` (code, language, input_files): every call
    runs in a fresh sandbox through ``executor``, which sets the isolation floor, the time
    budget and the software rule; nothing persists between calls. ``languages`` are the
    languages offered, the first being the default; offer only what the daemon's project
    image runs. ``max_output_chars`` cuts stdout and stderr, each.

    The tool answers with the dict ``plimsoll_client._code_tool`` describes, for a result, a
    refusal and an unknown outcome alike, and never raises: the framework stops a request
    after three tool errors in a row, and a refusal is information for the model. The model
    sees the dict as the framework's own JSON text; that text item's ``additional_properties``
    carry plimsoll's labels for the application, and the framework's tool span gets them
    when it is recording. The call runs in a worker thread; canceling the await cancels the
    call."""
    if not isinstance(executor, CodeExecutor):
        raise TypeError("plimsoll: plimsoll_code_tool needs a plimsoll_client.execution.CodeExecutor")
    langs = ct.offered(executor, languages)
    max_chars = ct.check_max_output(max_output_chars)

    async def _run_code(code: str, language: Optional[str] = None, input_files: Optional[List[Any]] = None) -> Dict[str, Any]:
        answer = await ct.arun(executor, langs, max_chars, code, language, input_files)
        _label_span(name, call_labels(answer))
        return answer

    def _parse(answer: Any) -> List[Content]:
        return _with_labels(FunctionTool.parse_result(answer), call_labels(answer) if isinstance(answer, Mapping) else {})

    text = ct.description(langs, executor.grant)
    _run_code.__doc__ = text
    return tool(func=_run_code, name=name, description=text, schema=_code_schema(langs), result_parser=_parse)
