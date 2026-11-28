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

Files: :class:`PlimsollFileStore` is the harness's other slot over the same session, Agent
Framework's ``AgentFileStore``, which ``create_harness_agent(client, file_access_store=...)`` gives
the model as its ``file_access_*`` tools (read, write, list, grep, replace). Each operation is one or
a few of the session's file calls (``Session.run_files``, through the workspace's file methods),
carried out inside the sandbox by plimsoll's own helper as the guest's user, so a file the model
writes with one tool is the file the shell sees, and the reverse, and no operation sends shell text.
It refuses, before any call or by the helper's typed answer: a path that is absolute, holds a ``.``
or ``..`` segment, a control character or a backslash, names the workspace's own state
(``.plimsoll-shell``), or passes through a symbolic link anywhere along it (``ValueError``, as
Microsoft's own disk store raises it); a file past ``max_file_bytes``, 1 MiB by default and at most
8 MiB, one file call's read (``OSError``, ``errno.EFBIG``). Each part of a path is looked at before
the operation, and a link that leaves the work directory is refused inside the operation's own call
as well, by the kernel's resolution in the helper, so no link swapped in between reaches a file
outside it. The refusals keep the store's paths in the work directory, as the framework's contract
asks of a store; the sandbox is what keeps the guest in, and the store reaches nothing a shell
command could not: it is the same session, with no grant. :func:`harness_options` builds the
harness's arguments for both slots.

Needs Agent Framework and its shell tools (``pip install agent-framework-plimsoll``, which pins
``agent-framework-tools`` exactly: it is a beta, released about weekly).
"""

from __future__ import annotations

import asyncio
import errno
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Sequence, Tuple, Type

try:
    from agent_framework import AgentFileStore, Content, FileSearchResult, FileStoreEntry, FunctionTool, MiddlewareFailure, tool
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
try:
    # The search's pattern compiler (a length cap, and a deadline the match itself checks), its
    # wall-clock bound and its glob rule, as the framework's own stores use them: a store that supplies
    # its own search keeps all three (agent_framework/_harness/_file_access.py, read at
    # agent-framework-core 1.26.0).
    from agent_framework._harness._file_access import _compile_search_regex, _matches_glob, _run_search_with_timeout
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "plimsoll_client.agent_framework: this agent-framework-core no longer has _compile_search_regex, _matches_glob "
        "and _run_search_with_timeout in agent_framework._harness._file_access, which the file store's search uses; "
        "they were checked on agent-framework-core 1.26.0"
    ) from e
from pydantic import BaseModel, Field, create_model

from . import _code_tool as ct
from . import _validate as v
from ._langsmith import KEYS as LABEL_KEYS
from ._langsmith import labels as _closed_set_labels
from ._transport import CancelHandle, in_thread
from .aio import AsyncClient
from .client import Client, Session
from .errors import InsufficientIsolationError, InvalidRequestError, PlimsollError, UnsupportedError
from .execution import CodeExecutor
from .files import FilesStatAnswer
from .types import ProjectResult, RunRecord, meets
from .workspace import MAX_READ_BYTES, STATE_DIR, Workspace, WorkspaceCallError, WorkspacePathError, WorkspaceTooLargeError, _check_text
from .workspace import close_quietly as _close_quietly

__all__ = ["PlimsollShellTool", "PlimsollShellResult", "PlimsollFileStore", "harness_options", "plimsoll_code_tool", "call_labels",
           "may_have_run", "LABEL_KEYS", "InputFile", "MAX_FILE_BYTES"]

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


# ---- the file store ----

#: The default of ``max_file_bytes``: about 250,000 tokens of text, past what a model reads in one
#: tool answer. Its ceiling is :data:`~plimsoll_client.workspace.MAX_READ_BYTES` (8 MiB), the most
#: one file call reads, so a read is one call with its checks.
MAX_FILE_BYTES = 1 << 20

# The longest path the store takes, in bytes: Linux's PATH_MAX, as the framework's own stores cap it.
_MAX_PATH_BYTES = 4096

# A search reads what it listed in read_many calls of at most 16,384 paths (the helper's own cap,
# docs/session-files.md) and about one answer's budget of their listed sizes, so a batch is one call
# unless its files grew meanwhile, and the store holds one batch's bytes at a time. _ITEM_FRAMES is
# what an item's frames cost beside its bytes, at most (three tags, three lengths of up to 20
# digits with their colons, a size of up to 20 digits) and the answer's last frame: a file whose
# bytes, path and frames do not fit one answer alone is read by itself.
_BATCH_PATHS = 16384
_ITEM_FRAMES = 128

# What one batch's paths may hold, in bytes, beside the count: the request carries each path in
# base64 (4/3 of its bytes) under the daemon's 8 MiB request cap (cmd/plimsolld, maxRequestBytes),
# and a path can be 4,096 bytes, so 16,384 long paths would be a request the daemon refuses. 4 MiB
# of paths is at most about 5.4 MiB on the wire, the same bound 1,024 paths of 4,096 bytes gave.
# A path on a session stating the sandbox scope alone travels absolute, longer by the work
# directory's name and a slash, which each path is counted with.
_BATCH_PATH_BYTES = 4 << 20

# What a read_many item's error means to a search: the file changed after the listing named it (it
# went, became a folder, a link the work scope does not follow, something else), so it is passed
# over without a word; any other error is passed over with a warning.
_CHANGED_SINCE_LISTED = frozenset({"not_found", "is_dir", "not_dir", "symlink", "not_regular"})


def _store_path(path: Any, *, directory: bool = False) -> str:
    """The work-directory-relative path a store operation acts on, refused with ``ValueError`` (as the
    framework's own stores refuse a path) before any call: not text, absolute, a ``.`` or ``..``
    segment, a backslash, a NUL or another control character, or the workspace's own state. Empty
    segments are dropped, as the framework's normalizer drops them; an empty path is the work
    directory, which only a directory operation takes. Past 4096 bytes is ``OSError`` ENAMETOOLONG."""
    if not isinstance(path, str):
        raise TypeError("plimsoll: a store path must be a str")
    if path.startswith("/"):
        raise ValueError(f"Invalid path: {path!r}. Paths must be relative to the work directory, not absolute.")
    if "\\" in path or any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in path):
        raise ValueError(f"Invalid path: {path!r}. Paths must not hold a backslash or a control character.")
    if not directory and path.endswith("/"):
        raise ValueError(f"Invalid path: {path!r}. A file path must not end with a path separator.")
    segments = [seg for seg in path.split("/") if seg]
    if any(seg in (".", "..") for seg in segments):
        raise ValueError(f"Invalid path: {path!r}. Paths must not contain '.' or '..' segments.")
    if segments and segments[0] == STATE_DIR:
        raise ValueError(f"Invalid path: {path!r}. {STATE_DIR} is the workspace's own state.")
    rel = "/".join(segments)
    if not rel and not directory:
        raise ValueError(f"Invalid path: {path!r}. A file path must not be empty.")
    try:
        size = len(rel.encode("utf-8"))
    except UnicodeEncodeError as e:
        raise ValueError(f"Invalid path: {path!r}. Paths must be UTF-8 text.") from e
    if size > _MAX_PATH_BYTES:
        raise OSError(errno.ENAMETOOLONG, "File name too long", path)
    return rel or "."


def _takes(rel: str) -> bool:
    """Whether the store takes ``rel``, a name a listing gave, back as a path: one it refuses (a
    newline or another control character, a backslash) is left out of its listings and searches,
    with a warning, since no other operation of the store could name it."""
    try:
        _store_path(rel)
    except (ValueError, OSError):
        log.warning("plimsoll: a listing left out a name the store does not take as a path (a control character or a backslash)")
        return False
    return True


def _link_error(path: str) -> ValueError:
    return ValueError(f"Invalid path: {path!r}. The path passes through a symbolic link, which this store does not follow.")


class PlimsollFileStore(AgentFileStore):
    """Agent Framework's ``AgentFileStore`` over the session of a :class:`PlimsollShellTool`: the
    harness's file tools and its shell work on one sandbox, so a file written with either is the
    file the other reads. Paths are relative to the session's work directory (``/work`` on docker).

    Every operation is one or a few of the session's file calls (``Session.run_files``, through
    :class:`~plimsoll_client.Workspace`'s file methods): plimsoll's own helper carries each out
    inside the sandbox as the guest's own user (docs/session-files.md), and its answer is typed, so
    no operation sends shell text and none reads a shell's words. The session must take file calls
    (``Session.file_scopes``; docker, E2B and OpenShell sessions do): on one that takes none (a
    daemon from before file calls), every operation raises
    :class:`~plimsoll_client.UnsupportedError`, not dispatched, and sends nothing. On a session
    that states the sandbox scope alone (OpenShell's), the workspace names each path as the
    absolute path under the work directory, checked by its name (see the link rule below).

    The store holds no session of its own. Its first operation opens the shell tool's session if the
    shell has not (with the shell tool's floor, checked as :meth:`PlimsollShellTool.start` checks
    it); closing the shell tool ends the store too, and every later operation raises
    :class:`~plimsoll_client.SessionEndedError`.

    What it refuses, and how:

    - a path that is absolute, holds a ``.`` or ``..`` segment, a backslash or a control
      character, or names the workspace's state ``.plimsoll-shell``: ``ValueError``, before any call;
    - a path through a symbolic link, at any component, the last included: ``ValueError``, and the
      operation does not happen. A listing leaves links out; a search skips them. Each part of the
      path is looked at (a ``stat`` call each, which never follows the link it names) before the
      operation's own call. Where the session states the work scope (docker, E2B), a link that
      leaves the work directory is refused inside that call too, by the kernel's own resolution in
      the helper, so no link swapped in between the two reaches a file outside the work directory;
      one swapped in that stays inside is followed, to a file the store could name by its own path.
      Where it states the sandbox scope alone (OpenShell's), the call follows a link wherever it
      points, so one swapped in between the two by a process of the guest's is followed out of the
      work directory, to whatever the sandbox's user may reach: there the sandbox's walls bound the
      store, not the work directory;
    - a name in the sandbox that no store path could name back (one holding a control character
      or a backslash, or one that is not UTF-8): left out of listings and searches, with a
      warning in the log, so the model is not told such a file exists;
    - a write or a read of a file past ``max_file_bytes`` (1 MiB by default, 8 MiB at most: one
      file call's read): ``OSError`` with ``errno.EFBIG``; a search skips such a file. A file is
      sized by its ``stat`` before any of it is read, so a sparse one past the cap is never read.

    A write up to 4 MiB is one call that publishes the whole file at once; past 4 MiB it is
    several (the first 4 MiB, then appends), and a failure partway leaves the first pieces.

    Errors reach the framework as its own stores raise them, so its file tools tell the model what
    went wrong: ``FileExistsError``, ``IsADirectoryError``, ``NotADirectoryError``,
    ``PermissionError``, and ``ValueError`` for a file that is not UTF-8. plimsoll's own errors are
    not those: a refusal before anything ran raises the client's exception, unchanged, which the
    framework turns into its error result; an operation that may have run without an answer raises
    the framework's ``MiddlewareFailure`` with plimsoll's error as its ``__cause__``, which ends the
    agent's run, as the shell tool's commands do (:func:`may_have_run` says which errors those are).
    A call past its time budget is ``TimeoutError``.

    Every call runs in a worker thread and is not cut by a cancel of its await (a search past the
    framework's 10-second bound, say): the call finishes, so the session stays in step with the
    daemon, and a search stops before its next call."""

    def __init__(self, shell: PlimsollShellTool, *, max_file_bytes: int = MAX_FILE_BYTES) -> None:
        if not isinstance(shell, PlimsollShellTool):
            raise TypeError("plimsoll: PlimsollFileStore works over a PlimsollShellTool's session")
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int) or not 0 < max_file_bytes <= MAX_READ_BYTES:
            raise ValueError(f"plimsoll: max_file_bytes must be an int from 1 to {MAX_READ_BYTES}, the most one file call reads")
        self._shell = shell
        self._max = max_file_bytes

    @property
    def shell(self) -> PlimsollShellTool:
        """The shell tool whose session the store works over."""
        return self._shell

    @property
    def max_file_bytes(self) -> int:
        return self._max

    # ---- the one way out ----

    def _do(self, path: str, fn: Callable[[Workspace], Any]) -> Any:
        """Runs ``fn`` over the shell tool's workspace, its errors read as the store raises them
        (see the class docstring). ``path`` is the caller's, for the messages."""
        try:
            workspace = self._shell._open()
            session = workspace.session
            if not getattr(session, "file_scopes", ()):
                raise UnsupportedError(
                    f"plimsoll: this session's provider ({getattr(session, 'provider', '') or 'unnamed'}) carries no file calls, "
                    "which the file store works through (the in-sandbox helper's file commands); nothing was sent",
                    not_dispatched="unsupported",
                )
            return fn(workspace)
        except PlimsollError as e:
            if may_have_run(e):
                raise self._stopped(e) from e
            raise
        except WorkspaceTooLargeError as e:
            raise OSError(errno.EFBIG, f"File too large: past the {self._max} bytes this store reads ({e})", path) from e
        except WorkspacePathError as e:
            # The store checked the path's form before the call, so what the workspace refuses here
            # is a link the work scope does not follow, answered by the helper.
            raise _link_error(path) from e
        except (OSError, ValueError, TypeError):
            raise  # an answered error of the call's, or the store's own refusal
        except Exception as e:
            # WorkspaceCallError among them: a file call that ended protocol_error or
            # runner_failed may have changed something, and its answer is not known.
            raise self._stopped(e) from e

    @staticmethod
    def _stopped(e: BaseException) -> MiddlewareFailure:
        return MiddlewareFailure(
            f"plimsoll: a file operation may have run without an answer to show for it ({e}); the agent's run is "
            "stopped, as it is after a shell command that may have run"
        )

    async def _run(self, path: str, fn: Callable[[Workspace], Any]) -> Any:
        # asyncio.to_thread, not in_thread: a cancel of the await never cuts a call in flight.
        return await asyncio.to_thread(self._do, path, fn)

    def _walk(self, w: Workspace, rel: str) -> Tuple[Optional[FilesStatAnswer], bool]:
        """Each part of ``rel`` from the first, by ``stat``, which names a link at the part it is
        asked about and never follows it: the last part's answer (None when a part is not there),
        and whether a part before the last is there and not a folder. A link at any part is
        :func:`_link_error`. The work directory itself (``.``) is one call."""
        if rel == ".":
            return w.stat("."), False
        parts = rel.split("/")
        st: Optional[FilesStatAnswer] = None
        for i in range(1, len(parts) + 1):
            try:
                st = w.stat("/".join(parts[:i]))
            except FileNotFoundError:
                return None, False
            except NotADirectoryError:
                return None, True  # the part before changed since its own stat
            if st.type == "link":
                raise _link_error(rel)
            if i < len(parts) and st.type != "dir":
                return None, True
        return st, False

    # ---- AgentFileStore ----

    async def write(self, path: str, content: str, *, overwrite: bool = True) -> None:
        """Writes ``content``, UTF-8, to the file at ``path``, making the directories on the way.
        ``overwrite=False`` refuses a file already there with ``FileExistsError`` (decided by the
        write itself, which publishes only where nothing is)."""
        rel = _store_path(path)
        if not isinstance(content, str):
            raise TypeError("plimsoll: content must be a str")
        if not isinstance(overwrite, bool):
            raise TypeError("plimsoll: overwrite must be a bool")
        data = content.encode("utf-8")  # a lone surrogate is UnicodeEncodeError, a ValueError
        if len(data) > self._max:
            raise OSError(errno.EFBIG, f"File too large: {len(data)} bytes, past the {self._max} this store writes", path)

        def op(w: Workspace) -> None:
            st, blocked = self._walk(w, rel)
            if blocked:
                raise NotADirectoryError(errno.ENOTDIR, "A parent path is not a directory", path)
            if st is not None:
                if st.type == "dir":
                    raise IsADirectoryError(errno.EISDIR, "Is a directory", path)
                if st.type != "file":
                    raise OSError(errno.EINVAL, "Not a regular file", path)
                if not overwrite:
                    raise FileExistsError(errno.EEXIST, "File exists", path)
            # The workspace's own write, in the mode the store needs: replace, or create-only,
            # which the helper publishes with a link that refuses a name already there.
            w._write(rel, path, data, "replace" if overwrite else "create_only", None)

        await self._run(path, op)

    async def read(self, path: str) -> Optional[str]:
        """The text of the file at ``path``, or None when there is none. ``ValueError`` for a file
        that is not UTF-8, as the framework's disk store raises it."""
        rel = _store_path(path)

        def op(w: Workspace) -> Optional[bytes]:
            st, _ = self._walk(w, rel)
            if st is None:
                return None
            if st.type == "dir":
                raise IsADirectoryError(errno.EISDIR, "Is a directory", path)
            if st.type != "file":
                raise OSError(errno.EINVAL, "Not a regular file", path)
            if st.size > self._max:
                raise OSError(errno.EFBIG, f"File too large: past the {self._max} bytes this store reads", path)
            try:
                return w.read_whole(rel, limit=self._max)
            except FileNotFoundError:
                return None  # removed since its stat

        out = await self._run(path, op)
        if out is None:
            return None
        try:
            return out.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"File {path!r} is not UTF-8 text and cannot be read.") from e

    async def delete(self, path: str) -> bool:
        """Removes the file at ``path``: True when one was removed; False when there was none, or it
        is a directory or anything else that is not a regular file (files only, as the framework's
        stores delete)."""
        rel = _store_path(path)

        def op(w: Workspace) -> bool:
            st, _ = self._walk(w, rel)
            if st is None or st.type != "file":
                return False
            try:
                w.remove(rel)
            except (FileNotFoundError, IsADirectoryError):
                return False  # changed since its stat
            return True

        return bool(await self._run(path, op))

    async def file_exists(self, path: str) -> bool:
        rel = _store_path(path)

        def op(w: Workspace) -> bool:
            st, _ = self._walk(w, rel)
            return st is not None and st.type == "file"

        return bool(await self._run(path, op))

    async def create_directory(self, path: str) -> None:
        rel = _store_path(path, directory=True)
        if rel == ".":
            return

        def op(w: Workspace) -> None:
            st, blocked = self._walk(w, rel)
            if blocked or (st is not None and st.type != "dir"):
                raise FileExistsError(errno.EEXIST, "File exists", path)
            if st is None:
                w.make_dir(rel, parents=True)  # a folder made meanwhile is done

        await self._run(path, op)

    async def delete_directory(self, path: str) -> bool:
        """Removes the empty directory at ``path``: True when it was removed; False when it is
        missing, not a directory, or not empty, and for the work directory itself.
        ``PermissionError`` when the guest may not remove it."""
        rel = _store_path(path, directory=True)
        if rel == ".":
            return False

        def op(w: Workspace) -> bool:
            st, _ = self._walk(w, rel)
            if st is None or st.type != "dir":
                return False
            try:
                w.remove(rel, dir=True)
            except (FileNotFoundError, NotADirectoryError):
                return False
            except OSError as e:
                if e.errno == errno.ENOTEMPTY:
                    return False
                raise
            return True

        return bool(await self._run(path, op))

    async def list_children(self, directory: str = "") -> List[FileStoreEntry]:
        """The directory's subdirectories, then its files, each sorted by name; symbolic links,
        anything that is neither a file nor a directory, and the workspace's own state are left
        out, and a missing directory lists nothing."""
        rel = _store_path(directory, directory=True)

        def op(w: Workspace) -> List[FileStoreEntry]:
            st, _ = self._walk(w, rel)
            if st is None or st.type != "dir":
                return []
            dirs: List[str] = []
            files: List[str] = []
            try:
                entries = list(w.list(rel))
            except (FileNotFoundError, NotADirectoryError):
                return []  # changed since its stat
            for e in entries:
                if e.type not in ("dir", "file"):
                    continue
                try:
                    name = e.path.decode("utf-8")
                except UnicodeDecodeError:
                    log.warning("plimsoll: a listing left out a name that is not UTF-8")
                    continue
                if _takes(name if rel == "." else rel + "/" + name):
                    (dirs if e.type == "dir" else files).append(name)
            return [FileStoreEntry(n, FileStoreEntry.DIRECTORY) for n in sorted(dirs)] + [FileStoreEntry(n, FileStoreEntry.FILE) for n in sorted(files)]

        return list(await self._run(directory, op))

    def _files(self, w: Workspace, rel: str, recursive: bool) -> List[Tuple[str, int]]:
        """Every regular file under ``rel`` (its direct children unless ``recursive``), as its path
        from there and its size, sorted; the workspace's state left out. One listing, a call a page
        of about 1 MiB (some 20,000 short names), so a tree of any size lists. A listing never
        enters a link, and leaves out a folder it may not enter, with a warning."""
        st, _ = self._walk(w, rel)
        if st is None or st.type != "dir":
            return []
        found: List[Tuple[str, int]] = []
        try:
            for e in w.list(rel, recursive=recursive):
                if e.type == "unreadable":
                    log.warning("plimsoll: a search left out a folder the sandbox's user may not enter")
                    continue
                if e.type != "file":
                    continue
                try:
                    name = e.path.decode("utf-8")
                except UnicodeDecodeError:
                    log.warning("plimsoll: a search left out a name that is not UTF-8")
                    continue
                if _takes(name if rel == "." else rel + "/" + name):
                    found.append((name, e.size))
        except (FileNotFoundError, NotADirectoryError):
            return []  # changed since its stat
        return sorted(found)

    async def find_matching_files(
        self, directory: str, regex_pattern: str, glob_pattern: Optional[str] = None, *, recursive: bool = False
    ) -> List[str]:
        """Every regular file in scope whose path from ``directory`` matches ``glob_pattern``, from one
        listing; the pattern is not pushed down (the framework's search reads and scans what comes back)."""
        del regex_pattern
        rel = _store_path(directory, directory=True)
        files = await self._run(directory, lambda w: self._files(w, rel, recursive))
        return [name for name, _ in files if _matches_glob(name, glob_pattern)]

    async def search(
        self, directory: str, regex_pattern: str, glob_pattern: Optional[str] = None, *, recursive: bool = False
    ) -> List[FileSearchResult]:
        """The framework's search (a case-insensitive pattern, an optional glob, its 10-second bound).
        The contents are searched here, not in the sandbox: one listing, then the files' bytes in
        read_many calls of up to 16,384 files and about 8 MiB, each scanned as it arrives, every match
        numbered by ``AgentFileStore.scan_content`` over the same text :meth:`read` returns. A file
        past ``max_file_bytes``, one that is not UTF-8, and a symbolic link are skipped."""
        pattern = _compile_search_regex(regex_pattern)
        return await _run_search_with_timeout(self._search(directory, pattern, glob_pattern, recursive))

    async def _search(self, directory: str, pattern: Any, glob_pattern: Optional[str], recursive: bool) -> List[FileSearchResult]:
        rel = _store_path(directory, directory=True)
        prefix = "" if rel == "." else rel + "/"
        files, room = await self._run(directory, lambda w: (self._files(w, rel, recursive), len(w.root.encode("utf-8")) + 1))
        results: List[FileSearchResult] = []
        batch: List[str] = []
        held = named = 0
        for name, size in [f for f in files if _matches_glob(f[0], glob_pattern)] + [("", -1)]:
            if size > self._max:
                log.warning("plimsoll: search skipped a file past %d bytes", self._max)
                continue
            path = prefix + name
            length = len(path.encode("utf-8"))
            cost = size + length + _ITEM_FRAMES
            if batch and (size < 0 or len(batch) == _BATCH_PATHS or held + cost > MAX_READ_BYTES
                          or named + length + room > _BATCH_PATH_BYTES):
                contents = await self._run(directory, lambda w, b=batch: self._contents(w, b))
                results.extend(self._scan(contents, rel, pattern))
                batch, held, named = [], 0, 0
            if size < 0:
                break
            if cost > MAX_READ_BYTES:
                # Too large for one answer's frames even alone: read by itself, as read reads it.
                one = await self._run(directory, lambda w, p=path: self._one(w, p))
                results.extend(self._scan(one, rel, pattern))
                continue
            batch.append(path)
            held += cost
            named += length + room
        return results

    def _contents(self, w: Workspace, paths: List[str]) -> List[Tuple[str, bytes]]:
        """The bytes of each of ``paths`` (from one listing, each at most the cap) that is still a
        regular file the work scope reaches, in order; the rest are passed over (see
        ``_CHANGED_SINCE_LISTED``). Every item is exactly the bytes its read returned, framed by
        its own length, so no file's bytes can run into the next one's."""
        got: List[Tuple[str, bytes]] = []
        for path, item in zip(paths, w.read_many(paths, max_bytes_each=self._max)):
            if item.error == "none":
                got.append((path, item.content))
            elif item.error == "too_large":
                log.warning("plimsoll: search skipped a file that grew past %d bytes", self._max)
            elif item.error not in _CHANGED_SINCE_LISTED:
                log.warning("plimsoll: search skipped a file it could not read (%s)", item.error)
        return got

    def _one(self, w: Workspace, path: str) -> List[Tuple[str, bytes]]:
        try:
            return [(path, w.read_whole(path, limit=self._max))]
        except TimeoutError:
            raise
        except (WorkspacePathError, WorkspaceTooLargeError, OSError):
            return []  # changed since the listing, as _contents passes such a file over

    @staticmethod
    def _scan(contents: List[Tuple[str, bytes]], rel: str, pattern: Any) -> List[FileSearchResult]:
        found: List[FileSearchResult] = []
        prefix = "" if rel == "." else rel + "/"
        for path, raw in contents:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                log.warning("plimsoll: search skipped a file that is not UTF-8")
                continue
            # Called on the class, as the framework's own search calls it.
            result = AgentFileStore.scan_content(path[len(prefix):], text, pattern)
            if result is not None:
                found.append(result)
        return found


def harness_options(
    shell: PlimsollShellTool, *, file_approval: Optional[str] = None, max_file_bytes: int = MAX_FILE_BYTES
) -> Dict[str, Any]:
    """The arguments that give ``create_harness_agent`` plimsoll for both of its slots on one session:
    ``shell_executor`` the shell tool, ``file_access_store`` a :class:`PlimsollFileStore` over it, and
    the file tools' approval, the harness's two ``file_access_disable_*_tool_approval`` switches.

    ``file_approval`` sets that approval. ``None``, the default, follows the shell tool's
    ``approval_mode``: the harness otherwise asks a person to approve every file tool call, and an
    approval on a file write while the shell writes the same files unasked would guard nothing, so the
    two go together. ``"always_require"`` asks a person for every file tool call whatever the shell
    does (the harness's own default, for a shell that cannot write the store's files, or a chat client
    with no shell tool, where the harness leaves the shell out and keeps the file tools);
    ``"never_require"`` asks for none. Pass it here, not as the switches beside
    ``**harness_options(shell)``, which Python refuses as a keyword given twice.

    The harness's file memory is not here: over this store every run after the sandbox ends would
    raise, and the shell could rewrite what the harness shows the model as memory. Agent Framework's
    ``InMemoryAgentFileStore`` keeps it off the agent's disk::

        async with PlimsollShellTool(client, minimum_isolation="kernel") as shell:
            agent = create_harness_agent(chat_client, **harness_options(shell), file_memory_store=InMemoryAgentFileStore())
    """
    if file_approval is not None and file_approval not in _APPROVAL_MODES:
        raise ValueError(f"plimsoll: file_approval must be None (follow the shell tool) or one of {_APPROVAL_MODES}, not {file_approval!r}")
    store = PlimsollFileStore(shell, max_file_bytes=max_file_bytes)  # refuses a shell that is not plimsoll's
    unasked = (file_approval or shell._approval_mode) == "never_require"
    return {
        "shell_executor": shell,
        "file_access_store": store,
        "file_access_disable_readonly_tool_approval": unasked,
        "file_access_disable_write_tool_approval": unasked,
    }


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
