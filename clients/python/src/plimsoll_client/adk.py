"""Optional Google ADK adapters over the checked client: a code executor (each Python block
in a fresh sandbox) and an environment (one plimsoll session as ADK's kept sandbox with a
shell and files)."""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextvars
import errno
import mimetypes
import os
import threading
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Callable, Dict, Iterator, List, Literal, Mapping, Optional, Sequence, Tuple

try:
    import google.adk  # noqa: F401  (the extra this module needs; named if it is missing)
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.adk needs Google ADK: pip install 'plimsoll-client[adk]'") from e
from google.adk.code_executors.base_code_executor import BaseCodeExecutor
from google.adk.code_executors.code_execution_utils import CodeExecutionInput, CodeExecutionResult, File
from google.adk.environment import BaseEnvironment, ExecutionResult
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.agent_tool import AgentTool
from pydantic import ConfigDict, Field

from . import _langsmith
from . import _validate as v
from ._transport import CancelHandle, in_thread
from .client import Client, Session
from .execution import CodeExecutor
from .errors import InsufficientIsolationError, PlimsollError, RequestCanceledError, UnsupportedError
from .types import ProjectResult, RunRecord, SessionSummary, SoftwareRule, meets
from .workspace import _ENV_NAME, ExecOutcome, Workspace, WorkspaceCallError
from .workspace import close_quietly as _close_quietly

__all__ = ["PlimsollCodeExecutor", "PlimsollCodeExecutionResult", "PlimsollCodeExecutionError", "PlimsollCodeExecutorGuard",
           "CODE_EXECUTION_INSTRUCTION", "PlimsollEnvironment", "PlimsollExecutionResult", "PlimsollCall",
           "PlimsollEnvironmentError", "PlimsollEnvironmentGuard"]

# What the guard tells a model whose agent executes through plimsoll. ADK 2.14.1 adds
# its own version (_NON_BUILTIN_EXECUTOR_INSTRUCTION) only under optimize_data_file, which this
# executor refuses (_code_execution.py:236 in 2.14.1), so without this a model would get no word on
# the fence or on the fresh sandbox, and Gemini may answer with a native code part the API
# rejects. {start} and {end} are the executor's first code block delimiters.
CODE_EXECUTION_INSTRUCTION = """\
# Code execution

You can run Python in a sandbox the host application manages. Write the code in a fenced
block exactly like this, and what it prints comes back to you:

{start}print("hello"){end}

Each block runs in a new sandbox: define everything a block needs in that block, and print
what you want to see. Do not emit native executable_code parts, and do not call a
code_execution tool: none is registered, and the API rejects such a response.
"""


# The asyncio task an agent's model call ran in, which the guard records. ADK 2.14.1 runs the
# executor through asyncio.to_thread (_code_execution.py:301, :430), which copies the
# context into the worker thread, so the execution finds the task that awaits it there.
_AWAITING: contextvars.ContextVar[Optional["asyncio.Task[Any]"]] = contextvars.ContextVar("plimsoll_adk_task", default=None)


class _CancelWithTask:
    """A CancelHandle that is cancelled when the task awaiting the execution ends
    cancelled. ADK gives the executor no cancellation signal: cancelling the task stops
    the await, not the thread, so without this the request would go on to be sent, or
    run to its deadline, for nobody."""

    def __init__(self, task: "asyncio.Task[Any]") -> None:
        self.handle = CancelHandle()
        self._task = task
        self._loop = task.get_loop()
        self._loop.call_soon_threadsafe(task.add_done_callback, self._done)

    def _done(self, task: "asyncio.Task[Any]") -> None:
        if task.cancelled():
            self.handle.cancel()

    def detach(self) -> None:
        try:
            self._loop.call_soon_threadsafe(self._task.remove_done_callback, self._done)
        except RuntimeError:
            pass  # the loop has closed: nothing to remove


@dataclass
class PlimsollCodeExecutionResult(CodeExecutionResult):
    """ADK's text result plus the complete, byte-preserving checked run.

    ADK consumes stdout, stderr and output_files. Application code can inspect
    execution for isolation, records, original bytes and truncation flags, and
    refusal when plimsoll refused the block before any of it ran: then execution is
    None, exit_code is None and stderr starts "Nothing ran (<reason>): ".
    """

    execution: Optional[ProjectResult] = field(default=None, repr=False)
    refusal: Optional[PlimsollError] = field(default=None, repr=False)


class PlimsollCodeExecutionError(PlimsollError):
    """No step report was received. Execution is uncertain, not a correction signal.

    execution preserves the complete checked result, including its run record.
    There is no not-dispatched mark: automatically repeating the block is unsafe.
    """

    def __init__(self, execution: ProjectResult) -> None:
        detail = ": " + execution.detail if execution.detail else ""
        super().__init__(
            "plimsoll returned no step report (" + execution.outcome + detail + "). "
            "Code may have run; repeating it may repeat its effects. The ADK invocation is stopped."
        )
        self.execution = execution


class PlimsollCodeExecutor(BaseCodeExecutor):
    """Run each ADK Python block in a new sandbox. No host execution or retry.

    The default 30-second budget bounds interactive calculations below the
    daemon's five-minute ceiling. ADK 2.14 checks its retry count before the first
    execution: its default of two lets the model correct a failed block.
    Positive retry limits are configurable; stateful operation is refused.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    client: Client = Field(exclude=True, repr=False)
    minimum_isolation: Literal["process", "container", "kernel", "vm"] = "kernel"
    timeout_seconds: int = Field(default=30, gt=0, le=300, strict=True)
    stateful: Literal[False] = False
    # ADK's CSV exploration defines dataframes for later blocks, which require
    # a persistent interpreter. A fresh sandbox cannot satisfy that contract.
    optimize_data_file: Literal[False] = False
    error_retry_attempts: int = Field(default=2, ge=1, strict=True)
    artifact_paths: Tuple[str, ...] = ()
    software: Optional[SoftwareRule] = None

    def execute_code(self, invocation_context: Any, code_execution_input: CodeExecutionInput) -> PlimsollCodeExecutionResult:
        # ADK 2.14.1 calls this through asyncio.to_thread with no handler
        # (flows/llm_flows/extensions/_code_execution.py:301 and :430), so an exception
        # ends the Runner invocation; its own executors report a failure in stderr
        # instead. A refusal before dispatch ran nothing, so it is reported ADK's way:
        # the model sees it, ADK's retry counter bounds the next try, and the session's
        # later turns are unaffected. An error that may follow execution still raises,
        # outside ADK's correction loop, since a retry could repeat what the code did.
        task = _AWAITING.get()
        watch = _CancelWithTask(task) if task is not None and not task.done() else None
        try:
            return self._execute(code_execution_input, watch.handle if watch else None)
        except PlimsollError as e:
            if e.not_dispatched is None:
                raise
            return PlimsollCodeExecutionResult(stderr=f"Nothing ran ({e.not_dispatched}): {e}", refusal=e)
        finally:
            if watch is not None:
                watch.detach()

    def _execute(self, code_execution_input: CodeExecutionInput, cancel: Optional[CancelHandle]) -> PlimsollCodeExecutionResult:
        files = []
        size = 0
        for item in code_execution_input.input_files:
            if not (item.mime_type.startswith("text/") or item.mime_type == "application/json"):
                raise v.invalid(f"ADK input file {item.name!r} is {item.mime_type}; only UTF-8 text is supported")
            content = item.content
            try:
                if isinstance(content, str):
                    # ADK passes encoded strings, but passes bytes as raw data.
                    # Bound the allocation before decoding model-supplied data.
                    if len(content) > 4 * ((v.MAX_PROJECT_BYTES + 2) // 3):
                        raise v.invalid("ADK input file exceeds the project byte limit")
                    raw = base64.b64decode(content, validate=True)
                elif isinstance(content, bytes):
                    raw = content
                else:
                    raise v.invalid("ADK file content must be encoded text or raw bytes")
                size += len(raw)
                if size > v.MAX_PROJECT_BYTES:
                    raise v.invalid("ADK input files exceed the project byte limit")
                files.append((item.name, raw.decode("utf-8", errors="strict")))
            except UnicodeError as exc:
                raise v.invalid(f"ADK input file {item.name!r} is not UTF-8 text (save it as UTF-8)") from exc
            except (binascii.Error, ValueError) as exc:
                raise v.invalid(f"ADK input file {item.name!r} is not valid base64") from exc

        result = CodeExecutor(self.client, minimum_isolation=self.minimum_isolation,
                              timeout=self.timeout_seconds, software=self.software).execute_code(
            code_execution_input.code, language="python", files=files, artifacts=self.artifact_paths, cancel=cancel)
        if not result.steps:
            # Outcome text cannot prove that execution never started. Raising
            # leaves ADK's ordinary guest-error correction loop before a replay.
            raise PlimsollCodeExecutionError(result)
        stdout = "".join(step.stdout_text for step in result.steps)
        stderr = "".join(step.stderr_text for step in result.steps)
        exit_code = result.steps[-1].exit_code
        if stderr and not exit_code and result.outcome == "completed":
            # ADK reads any stderr as a failure (code_execution_utils.py:220): it shows the
            # model the stderr alone, drops stdout, and counts an error toward the retry
            # limit, after which it stops executing. A program that exited 0 succeeded
            # whatever it wrote there (a warning), so the exit status decides, as in ADK's
            # own UnsafeLocalCodeExecutor (unsafe_local_code_executor.py:196); the text
            # still reaches the model, after stdout, under a heading.
            stdout += ("\n" if stdout and not stdout.endswith("\n") else "") + "stderr (the program exited 0):\n" + stderr
            stderr = ""
        diagnostics = []
        if result.outcome != "completed":
            diagnostics.append("plimsoll: " + result.outcome + (": " + result.detail if result.detail else ""))
        if exit_code and not stderr:
            # ADK builds its success/failure event from stderr, not exit_code.
            diagnostics.append("plimsoll: code exited with status " + str(exit_code))
        if diagnostics:
            stderr += ("\n" if stderr and not stderr.endswith("\n") else "") + "\n".join(diagnostics)
        output = [File(name=a.path, content=a.content,
                       mime_type=mimetypes.guess_type(a.path)[0] or "application/octet-stream")
                  for a in result.artifacts]
        return PlimsollCodeExecutionResult(stdout=stdout, stderr=stderr, exit_code=exit_code,
                                           output_files=output, execution=result)


class PlimsollCodeExecutorGuard(BasePlugin):
    """Register first on Runner to refuse, before any model or code call, what would
    otherwise fail around plimsoll's execution.

    It also adds CODE_EXECUTION_INSTRUCTION to the request of every agent that executes
    through plimsoll, and records the task each model call runs in, so cancelling that
    task cancels the code execution's request too. ADK's compositional function calling (support_cfc) replaces the executor with
    BuiltInCodeExecutor without invoking any of its methods, so the executor itself
    cannot refuse it. And ADK saves every execution's result through the Runner's
    artifact service, raising after the block has run when there is none
    (_code_execution.py:554 in ADK 2.14.1), so a Runner without one is refused first.
    """

    def __init__(self) -> None:
        super().__init__(name="plimsoll_code_executor_guard")

    async def before_run_callback(self, *, invocation_context: Any) -> None:
        agent = invocation_context.agent
        while agent.parent_agent is not None:
            agent = agent.parent_agent
        self._check(agent, invocation_context.run_config)
        _refuse_without_artifacts(invocation_context, agent)

    async def before_model_callback(self, *, callback_context: Any, llm_request: Any) -> None:
        # The task this agent's model call runs in, and its code execution after it: a
        # cancel of that task then cuts the execution's request (_CancelWithTask).
        _AWAITING.set(asyncio.current_task())
        # The agent this model call is for, through the context's public accessor (ADK
        # 2.14.1, agents/context.py:423; it returns a copy with the same agent). A rename
        # fails this hook loudly (ADK wraps the AttributeError in RuntimeError), never
        # silently drops the instruction.
        executor = getattr(callback_context.get_invocation_context().agent, "code_executor", None)
        if isinstance(executor, PlimsollCodeExecutor):
            # ADK's own flow falls back to a tool_code fence when the list is empty.
            start, end = executor.code_block_delimiters[0] if executor.code_block_delimiters else ("```tool_code\n", "\n```")
            llm_request.append_instructions([CODE_EXECUTION_INSTRUCTION.format(start=start, end=end)])
        return None

    async def before_agent_callback(self, *, agent: Any, callback_context: Any) -> None:
        # This hook also covers ADK's live flow, which skips before_run_callback. A nested
        # Runner (AgentTool) has a forwarding artifact service, never None, so this check
        # cannot refuse it; the outer Runner's check covers the agents it reaches.
        self._check(agent, callback_context.run_config)
        _refuse_without_artifacts(callback_context.get_invocation_context(), agent)

    @staticmethod
    def _check(agent: Any, run_config: Any) -> None:
        # Refused wherever plimsoll executes in the tree, not only at the root: ADK 2.14.1
        # replaces only the root agent's executor, but that is a private condition
        # (_resolve_code_executor) a later 2.x may widen, and a widened one would run the
        # model's code with no floor and no record while this guard still passed.
        if run_config is not None and run_config.support_cfc and _uses_plimsoll(agent):
            raise UnsupportedError(
                "PlimsollCodeExecutor refuses support_cfc=True: ADK replaces an agent's "
                "executor with Gemini's built-in code execution, bypassing plimsoll's "
                "isolation floor and checked run records. Set support_cfc=False.",
                not_dispatched="unsupported",
            )


def _uses_plimsoll(agent: Any) -> bool:
    """Whether the agent or any agent it can reach executes code through plimsoll: its
    sub-agents, and agents wrapped as its tools (AgentTool), whose nested Runner forwards
    artifacts to this one's artifact service."""
    stack, seen = [agent], set()
    while stack:
        a = stack.pop()
        if id(a) in seen:
            continue
        seen.add(id(a))
        if isinstance(getattr(a, "code_executor", None), PlimsollCodeExecutor):
            return True
        stack.extend(getattr(a, "sub_agents", None) or [])
        stack.extend(t.agent for t in getattr(a, "tools", None) or [] if isinstance(t, AgentTool))
    return False


def _refuse_without_artifacts(invocation_context: Any, agent: Any) -> None:
    if invocation_context.artifact_service is None and _uses_plimsoll(agent):
        raise UnsupportedError(
            "PlimsollCodeExecutor needs an artifact service on the Runner: ADK saves every "
            "code execution result through it and raises after the block has run without "
            "one. Pass artifact_service= (InMemoryArtifactService() for development).",
            not_dispatched="unsupported",
        )


# ---- the environment: one plimsoll session as ADK's kept sandbox with a shell and files ----
#
# ADK's interface, read in google-adk 2.14.1 (google/adk/environment/_base_environment.py):
# ExecutionResult (line 27), BaseEnvironment (43) with initialize (69), close (76), the
# abstract working_dir (86), execute (90), read_file (109), read_file_stream (122) and
# write_file (139). EnvironmentToolset (google/adk/tools/environment/_environment_toolset.py)
# calls initialize once before its tools are listed (116, 129, 144) and close from its own
# close (152), which Runner.close calls (runners.py:2214). ADK's main branch, not yet
# released, passes every method a keyword ``ctx`` (the calling run's context, commit
# 1bd22e34); each method here accepts it, so this class runs unchanged on 2.14.1 and on the
# next release without the DeprecationWarning main gives an override that lacks it.

#: Seconds a call may run when ADK names no budget for it: a file read or write, and the
#: call that learns the work directory.
DEFAULT_TIMEOUT = 120.0

# Run as `sh -c SCRIPT sh PATH`: the path is an argument, never part of the script. Why a
# read failed, which the read step's own exit status cannot tell (BusyBox head says "I/O
# error" of a directory).
_WHY_UNREADABLE = (
    'if [ -d "$1" ]; then echo is_directory; elif [ ! -e "$1" ]; then echo file_not_found; '
    'elif [ ! -r "$1" ]; then echo permission_denied; fi'
)

# What a write step's stderr ends with, as the OSError ADK's tools see: the sandbox's own
# text never travels on (EditFileTool does not catch a write's error, _edit_file_tool.py:154,
# and ADK records a raised error on its span, telemetry/tracing.py:330).
_WRITE_ERRORS: Tuple[Tuple[str, int, str], ...] = (
    ("Permission denied", errno.EACCES, "Permission denied"),
    ("Read-only file system", errno.EROFS, "Read-only file system"),
    ("Is a directory", errno.EISDIR, "Is a directory"),
    ("Not a directory", errno.ENOTDIR, "Not a directory"),
    ("No space left on device", errno.ENOSPC, "No space left on device"),
)

# An outcome whose answer may hide what ran: a runner that failed after a step began, or
# no step's report. setup_failed proves no step began (ProjectResult's docstring).
_INCOMPLETE = frozenset({"protocol_error", "runner_failed", "unspecified"})


@dataclass(frozen=True)
class PlimsollCall:
    """What plimsoll stated about one call a :class:`PlimsollEnvironment` made, and nothing
    the guest wrote: no output, command, path or detail text.

    ``method`` is the environment method that made it (``initialize``, ``execute``,
    ``read_file``, ``write_file``); ``function_call_id`` the ADK tool call it served, when
    :class:`PlimsollEnvironmentGuard` (or the ``ctx`` a later ADK passes) said which.
    ``dispatched`` is ``yes`` (the daemon answered: the call was handed to the sandbox),
    ``no`` (refused before anything ran; ``refused`` is the reason) or ``unknown`` (no
    answer: the call may have run). ``outcome``, ``isolation``, ``isolation_qualification``
    (the sentence the provider states beside the tier, "" when none) and ``record`` (the
    checked run record) are the answer's. ``uncertain`` is true when the call may have run
    and its result is not complete: no answer, a runner that failed after a step began, or
    an answer without a step's report other than ``setup_failed``."""

    method: str
    function_call_id: Optional[str]
    dispatched: str
    refused: str = ""
    outcome: str = ""
    isolation: str = ""
    isolation_qualification: str = ""
    record: Optional[RunRecord] = field(default=None, repr=False)
    exit_code: Optional[int] = None
    uncertain: bool = False

    @property
    def record_sha256(self) -> str:
        """The checked record's digest, "" without one."""
        return self.record.sha256 if self.record is not None else ""

    def labels(self) -> Dict[str, str]:
        """This call's trusted labels, each value checked against its closed set: the
        keys the LangChain tool puts on a LangSmith run (``plimsoll_client._langsmith``)."""
        answer: Dict[str, Any] = {"isolation": self.isolation, "isolation_qualification": self.isolation_qualification,
                                  "record_sha256": self.record_sha256}
        if self.dispatched == "no":
            answer["refused"] = self.refused
        elif self.dispatched == "yes":
            answer["outcome"] = self.outcome
        return _langsmith.labels(answer)


def _from_result(method: str, call_id: Optional[str], r: ProjectResult) -> PlimsollCall:
    return PlimsollCall(
        method=method,
        function_call_id=call_id,
        dispatched="yes",
        outcome=r.outcome,
        isolation=r.isolation,
        isolation_qualification=r.isolation_qualification,
        record=r.record,
        exit_code=r.steps[0].exit_code if r.steps else None,
        uncertain=r.outcome in _INCOMPLETE or (not r.steps and r.outcome != "setup_failed"),
    )


def _from_error(method: str, call_id: Optional[str], e: BaseException) -> PlimsollCall:
    reason = e.not_dispatched if isinstance(e, PlimsollError) else None
    if reason is not None:
        return PlimsollCall(method=method, function_call_id=call_id, dispatched="no", refused=reason)
    # No answer to check: the call may have run. A session call the daemon chained anyway
    # comes with its checked record (PlimsollError.record), which states the tier.
    record = e.record if isinstance(e, PlimsollError) else None
    return PlimsollCall(method=method, function_call_id=call_id, dispatched="unknown", uncertain=True, record=record,
                        isolation=record.isolation if record is not None else "",
                        isolation_qualification=record.isolation_qualification if record is not None else "")


@dataclass
class PlimsollExecutionResult(ExecutionResult):
    """ADK's ``ExecutionResult`` of one command, plus what plimsoll stated about it:
    ``plimsoll`` (its :class:`PlimsollCall`: the checked record, the tier with its sentence,
    the outcome) and ``execution`` (the complete :class:`~plimsoll_client.ProjectResult`,
    the original bytes and truncation flags included). ADK's ``ExecuteTool`` reads only the
    four fields of its own."""

    plimsoll: Optional[PlimsollCall] = field(default=None, repr=False)
    execution: Optional[ProjectResult] = field(default=None, repr=False)


class PlimsollEnvironmentError(PlimsollError):
    """A call of the environment that gave no usable result. ``call`` is what plimsoll
    stated about it; ``execution`` the answer, when one came back (its ``detail`` is the
    runner's text, kept out of this message). It carries no not-dispatched mark: when
    ``call.uncertain`` the command may have run, and repeating it may repeat what it did.
    The message is built from trusted fields only, since ADK records a raised error on its
    span (``telemetry/tracing.py:330``)."""

    def __init__(self, message: str, *, call: Optional[PlimsollCall], execution: Optional[ProjectResult] = None) -> None:
        super().__init__(message, code="unknown")
        self.call = call
        self.execution = execution


@dataclass
class _ToolCall:
    """The ADK tool call the guard is in: its ID, the app and user it runs for, and the
    plimsoll calls the environment made for it."""

    function_call_id: Optional[str]
    owner: Tuple[str, str]
    calls: List[PlimsollCall] = field(default_factory=list)


# Set by PlimsollEnvironmentGuard.before_tool_callback. ADK runs each tool call as a task
# of its own, in a copy of the context (flows/llm_flows/tools/_batch_executor.py:186), and
# awaits the plugins' before-tool callbacks and then the tool in that task (_caller.py:521,
# 586), so the environment's methods find here the call they serve; asyncio.to_thread
# copies it into the worker thread.
_TOOL_CALL: contextvars.ContextVar[Optional[_ToolCall]] = contextvars.ContextVar("plimsoll_adk_tool_call", default=None)


@dataclass(frozen=True)
class _Tag:
    """Which ADK tool call an operation serves."""

    function_call_id: Optional[str]
    tool_call: Optional[_ToolCall]


class _Recorder:
    """The session as the workspace sees it: each call goes to the session, and what
    plimsoll stated about it (or the error) is noted before the workspace reads it. The
    workspace's read and write return no result, so without this their records would be
    lost. The ADK function call ID goes with each call as its trace ID when it fits the
    daemon's charset (dropped whole otherwise, never cut), so the daemon's audit line joins
    ADK's span (``gen_ai.tool.call.id``, telemetry/tracing.py:381)."""

    def __init__(self, session: Session, note: Callable[[PlimsollCall, Optional[_ToolCall]], None]) -> None:
        self._session = session
        self._note = note
        self.local = threading.local()

    def run_project(self, files: Any, steps: Sequence[str], artifacts: Sequence[str] = (), *,
                    timeout: Optional[float] = None, cancel: Optional[CancelHandle] = None) -> ProjectResult:
        method, tag = getattr(self.local, "op", None) or ("unknown", _Tag(None, None))
        call_id = tag.function_call_id
        try:
            r = self._session.run_project(files, steps, artifacts, timeout=timeout, cancel=cancel,
                                          trace_id=_langsmith.trace_id(call_id))
        except BaseException as e:
            c = _from_error(method, call_id, e)
            self.local.last = (c, None)
            self._note(c, tag.tool_call)
            raise
        c = _from_result(method, call_id, r)
        self.local.last = (c, r)
        self._note(c, tag.tool_call)
        return r

    def close(self) -> SessionSummary:
        return self._session.close()

    def run(self, method: str, tag: _Tag, fn: Callable[..., Any], *args: Any, cancel: Optional[CancelHandle] = None,
            **kwargs: Any) -> Any:
        """Runs one operation of the workspace in this (worker) thread, with this recorder
        told which method and tool call it serves. An answer the workspace could not use
        (its WorkspaceCallError, which carries the answer and the runner's text) becomes a
        PlimsollEnvironmentError carrying what was noted and none of that text."""
        self.local.op, self.local.last = (method, tag), (None, None)
        try:
            return fn(*args, cancel=cancel, **kwargs)
        except WorkspaceCallError as e:
            call, _ = self.local.last
            raise _environment_error(method, call or _from_result(method, tag.function_call_id, e.result), e.result) from None
        finally:
            self.local.op = None

    def last(self) -> Optional[PlimsollCall]:
        """The call the last operation in this thread made last."""
        call, _ = getattr(self.local, "last", (None, None))
        return call


def _environment_error(method: str, call: PlimsollCall, result: Optional[ProjectResult]) -> PlimsollEnvironmentError:
    if call.uncertain:
        state = f"ended {call.outcome} without a complete report" if call.outcome else "got no answer"
        text = (f"plimsoll: the {method} call {state}. It may have run; repeating it may repeat what it did. "
                "Check its effects before running it again.")
    else:
        text = f"plimsoll: the {method} call ended {call.outcome} before any step began; nothing of it ran."
    return PlimsollEnvironmentError(text, call=call, execution=result)


def _posix(path: Any) -> str:
    """ADK's path argument as a POSIX path string: the tools pass the model's text; a
    caller may pass a Path, taken as POSIX so a Windows host's backslashes never reach the
    sandbox."""
    if isinstance(path, PurePath):
        return path.as_posix()
    if isinstance(path, str):
        return path
    if isinstance(path, os.PathLike):
        p = os.fspath(path)
        if isinstance(p, str):
            return p
    raise TypeError(f"path must be str or a path, not {type(path).__name__}")


def _write_error(path: str, message: str) -> OSError:
    text = message.strip()
    for tail, code, words in _WRITE_ERRORS:
        if text.endswith(tail):
            return OSError(code, words, path)
    return OSError(errno.EIO, "the sandbox could not write the file", path)


@dataclass(frozen=True)
class _Live:
    """The open session's workspace and recorder, taken together so a close() between a
    method's check and its call cannot pair one session's workspace with another's."""

    workspace: Workspace
    recorder: _Recorder


class PlimsollEnvironment(BaseEnvironment):
    """ADK's environment (``google.adk.environment.BaseEnvironment``) over one plimsoll
    session: every shell command and file read or write of an agent's
    ``EnvironmentToolset`` is a call of that session, behind the isolation floor it was
    opened at, with a checked run record on every call and no network.

    Construction touches nothing. ``initialize()`` (ADK's toolset calls it when the agent
    first runs) asks the daemon whether it offers sessions, opens one at
    ``minimum_isolation`` (``kernel`` by default: a docker daemon without gVisor is refused,
    marked not dispatched) and learns the work directory (``/work`` on docker), which is
    ``working_dir``. ``close()`` (the toolset's close calls it, and ``Runner.close()`` calls
    that) closes the session: the sandbox and its files are gone; ``initialize()`` after it
    opens a new, empty one, as ADK's lifecycle has it. ``lifetime`` and ``idle_timeout``
    (seconds) may only shorten the daemon's own; ``owner`` names the end user, for a
    daemon's per-owner cap; ``trace_id`` goes with the open. ``timeout`` (seconds) is the
    budget of a call ADK names none for; ``execute(timeout=None)`` gets the daemon's longest.
    ``env_vars`` are added to every command's environment (they enter the sandbox: never put
    a credential there).

    Each command runs in a new ``sh`` in the work directory, as ADK's own environments run
    theirs (``_local_environment.py:135``): files persist from one command to the next, a
    ``cd`` or an ``export`` does not, and a process left in the background is killed when
    its call ends (the session's sweep). Paths are relative to the work directory, or
    absolute anywhere in the sandbox (the sandbox is the boundary, as for ADK's E2B and
    Daytona environments); ``..`` out of the work directory and the workspace's own state
    directory are refused. When the session has ended (its lifetime, the daemon), every call
    raises :class:`~plimsoll_client.SessionEndedError`, marked not dispatched: the
    environment never puts a fresh sandbox in its place, since the agent would take an empty
    sandbox for the one with its files. After a call that may have run without an answer,
    the client sends nothing more on the session: every later call is refused, marked not
    dispatched.

    What plimsoll states about each call is in :attr:`calls` (a :class:`PlimsollCall`
    each) and, for a direct ``execute``, in the result's ``plimsoll`` field. Register
    :class:`PlimsollEnvironmentGuard` first on the Runner to tie each call to its ADK tool
    call, label ADK's spans, stop an agent after a call that may have run, and keep one
    sandbox to one user.
    """

    def __init__(
        self,
        client: Client,
        *,
        minimum_isolation: str = "kernel",
        timeout: float = DEFAULT_TIMEOUT,
        env_vars: Optional[Mapping[str, str]] = None,
        lifetime: Optional[float] = None,
        idle_timeout: Optional[float] = None,
        owner: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        if not v.floor(minimum_isolation):
            raise ValueError("plimsoll: an ADK environment needs a floor: minimum_isolation process, container, kernel or vm")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        variables = dict(env_vars or {})
        for name, value in variables.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise TypeError("env_vars must map str to str")
            # What the workspace's run step accepts (workspace.py, _argv_script), refused here,
            # when the environment is made, rather than at every command.
            if not _ENV_NAME.match(name):
                raise ValueError(f"env_vars: {name!r} is not a shell variable name")
            if "\x00" in value:
                raise ValueError(f"env_vars: the value of {name} contains NUL")
        self._client = client
        self._floor = minimum_isolation
        self._timeout = float(timeout)
        self._env_vars = variables
        self._open_options: Dict[str, Any] = {"lifetime": lifetime, "idle_timeout": idle_timeout, "owner": owner,
                                              "trace_id": trace_id}
        # _open_lock is held across an open's network calls, in a worker thread; _state_lock
        # only for the swaps of the state below, so the event loop never waits on the network.
        self._open_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._calls_lock = threading.Lock()
        self._calls: List[PlimsollCall] = []
        self._session: Optional[Session] = None
        self._live: Optional[_Live] = None
        self._root: Optional[str] = None
        self._ceiling: Optional[float] = None
        self._owner: Optional[Tuple[str, str]] = None
        self._summary: Optional[SessionSummary] = None
        self._is_initialized = False

    # ---- what the environment states ----

    @property
    def working_dir(self) -> Path:
        """The sandbox's work directory (``/work`` on docker). Before ``initialize()``, a
        RuntimeError, as ADK's LocalEnvironment gives (``_local_environment.py:99``)."""
        root = self._root
        if root is None:
            raise RuntimeError("plimsoll: the environment has no session yet; call initialize() first (ADK's toolset does)")
        return Path(root)

    @property
    def session(self) -> Optional[Session]:
        """The open plimsoll session; None before ``initialize()`` and after ``close()``."""
        return self._session

    @property
    def calls(self) -> Tuple[PlimsollCall, ...]:
        """Every call the environment made, in order, across its sessions."""
        with self._calls_lock:
            return tuple(self._calls)

    @property
    def close_summary(self) -> Optional[SessionSummary]:
        """The daemon's summary of the last session ``close()`` closed."""
        return self._summary

    # ---- the lifecycle ----

    async def initialize(self, *, ctx: Any = None) -> None:
        """Opens the session; returns at once while one is open (a later ADK calls this
        before every tool call)."""
        if self._live is not None:
            return
        await in_thread(self._open, self._tag(ctx))

    def _open(self, tag: _Tag, cancel: Optional[CancelHandle] = None) -> None:
        with self._open_lock:
            if self._live is not None:
                return
            info = self._client.describe(cancel=cancel)
            if not info.supports_sessions:
                raise UnsupportedError(
                    f"plimsoll: the daemon ({info.provider}) offers no sessions, which an ADK environment needs; nothing ran",
                    not_dispatched="unsupported",
                )
            ms = info.session_environment.max_timeout_ms
            ceiling = ms / 1000 if ms > 0 else None
            session = self._client.open_session(minimum_isolation=self._floor, **self._open_options)
            try:
                if cancel is not None and cancel.cancelled:
                    # The await was cancelled while the open was on its way: nobody will use
                    # or close this session, so it is closed here rather than holding one of
                    # the daemon's places until its idle limit.
                    raise RequestCanceledError("plimsoll: the open was cancelled; its session is closed", not_dispatched="request")
                if not meets(session.isolation, self._floor):
                    # The client checks the floor at open; this is the second look a session
                    # stating less gets, before any call of it.
                    raise InsufficientIsolationError(
                        f"plimsoll: the session states {session.isolation or 'no tier'}, below the required {self._floor}; "
                        "nothing ran",
                        not_dispatched="isolation",
                    )
                recorder = _Recorder(session, self._note)
                workspace = Workspace(recorder, timeout=self._timeout, max_timeout=ceiling, confined=False)
                root = recorder.run("initialize", tag, lambda cancel=None: workspace.root, cancel=cancel)
                if cancel is not None and cancel.cancelled:
                    raise RequestCanceledError("plimsoll: the open was cancelled; its session is closed", not_dispatched="request")
            except BaseException:
                _close_quietly(session)
                raise
            with self._state_lock:
                # _live last: initialize() and the methods read it without the lock, from the
                # event loop's thread, and take a set _live to mean the rest is set.
                self._root, self._ceiling, self._session = root, ceiling, session
                self._is_initialized = True
                self._live = _Live(workspace, recorder)

    async def close(self) -> None:
        """Closes the session: the sandbox and everything in it are gone. Idempotent. An
        error of the close (a ChainError: a call this client did not make ran in the
        session) is raised after the environment has let the session go. A close made while
        ``initialize()`` is opening waits for that open and closes the session it opened, so
        no session outlives a close that has returned."""
        summary = await in_thread(self._close)
        if summary is not None:
            self._summary = summary

    def _close(self, cancel: Optional[CancelHandle] = None) -> Optional[SessionSummary]:
        # Under the open's lock, in a worker thread so the event loop never waits on it: a close
        # that races an open (or an open whose await was cancelled while its thread went on
        # opening) waits for the open to publish, then closes what it opened (release-94). The
        # close is not cut by the await's cancel handle: a close begun is a close finished.
        with self._open_lock:
            with self._state_lock:
                session = self._session
                self._session, self._live, self._root, self._ceiling, self._owner = None, None, None, None, None
                self._is_initialized = False
            if session is None:
                return None
            return _close_session(session)

    # ---- the four methods ADK's tools call ----

    async def execute(self, command: str, *, timeout: Optional[float] = None, ctx: Any = None) -> PlimsollExecutionResult:
        """Runs ``command`` in a new ``sh`` in the work directory. A non-zero exit is a
        result, not an error. ``timeout`` None gets the daemon's longest budget (zero or less:
        a timed-out result with nothing sent, as ADK's LocalEnvironment gives). When the
        daemon cut a stream at its output limit a ``plimsoll:`` line says so at the end of
        ``stderr``, since ADK's result has no field for it; the flags and the original bytes
        are in ``execution``. Raises a refusal (marked not dispatched: nothing ran) as it
        came, and :class:`PlimsollEnvironmentError` when the call gave no usable result;
        never repeats a call."""
        if not isinstance(command, str):
            raise TypeError("command must be a str")
        live, tag = self._ready(ctx)
        budget = self._budget(timeout)
        if budget <= 0:
            # ADK's LocalEnvironment times such a command out at once (asyncio.wait_for with
            # no time, _local_environment.py:153); here it ends before anything is sent.
            return PlimsollExecutionResult(exit_code=-1, timed_out=True,
                                           stderr=f"plimsoll: a budget of {budget:g} s; nothing was sent\n")
        out, call = await in_thread(live.recorder.run, "execute", tag, self._run_command, live, command, budget)
        stderr = out.stderr_text
        notes = [f"plimsoll: the daemon cut {name} at its output limit"
                 for name, cut in (("stdout", out.stdout_truncated), ("stderr", out.stderr_truncated)) if cut]
        if notes:
            stderr += ("\n" if stderr and not stderr.endswith("\n") else "") + "\n".join(notes) + "\n"
        return PlimsollExecutionResult(exit_code=out.exit_code, stdout=out.stdout_text, stderr=stderr,
                                       timed_out=out.timed_out, plimsoll=call, execution=out.result)

    async def read_file(self, path: Any, *, ctx: Any = None) -> bytes:
        """The whole file at ``path``, 8 MiB a call (``Workspace.read_whole``).
        FileNotFoundError when there is none, IsADirectoryError for a directory,
        PermissionError for a file the sandbox's user cannot read, and
        :class:`~plimsoll_client.WorkspaceChangedError` (an OSError) for a file longer than
        one call that changed size while it was read: never a cut copy. A file past 64 MiB
        (``workspace.MAX_WHOLE_BYTES``) is :class:`~plimsoll_client.WorkspaceTooLargeError`,
        raised after its first piece: the file ends in this process's memory, and code in
        the sandbox can make one of any size for nothing (a sparse file)."""
        rel = _posix(path)
        live, tag = self._ready(ctx)
        return await in_thread(live.recorder.run, "read_file", tag, self._read_whole, live, rel)

    async def read_file_stream(self, path: Any, *, ctx: Any = None) -> AsyncGenerator[bytes, None]:
        """The bytes :meth:`read_file` returns, each 8 MiB piece yielded as it arrives
        (``Workspace.read_pieces``). Cancelling the await cuts the piece in flight. The
        same 64 MiB limit as :meth:`read_file`, so a caller that joins the pieces holds at
        most that. google-adk 2.14.1, the version locked here, calls no stream: its
        ReadFileTool reads through :meth:`read_file` (``_read_file_tool.py:117``)."""
        rel = _posix(path)
        live, tag = self._ready(ctx)
        handle = CancelHandle()
        pieces = live.workspace.read_pieces(rel, cancel=handle)
        first, in_flight = True, False
        try:
            while True:
                in_flight = True
                piece = await in_thread(live.recorder.run, "read_file", tag, self._next_piece, live, rel, pieces, first)
                in_flight = False
                if piece is None:
                    return
                first = False
                yield piece
        except asyncio.CancelledError:
            handle.cancel()  # the worker thread is still in the read: cut it there
            raise
        finally:
            if not in_flight:
                pieces.close()  # a read still running in its thread ends with the cut instead

    async def write_file(self, path: Any, content: Any, *, ctx: Any = None) -> None:
        """Writes ``content`` (str, as UTF-8, or bytes) to ``path``, creating its parent
        directories."""
        if not isinstance(content, (str, bytes)):
            raise TypeError(f"content must be str or bytes, got {type(content).__name__}")
        data = content.encode("utf-8") if isinstance(content, str) else content
        rel = _posix(path)
        live, tag = self._ready(ctx)
        await in_thread(live.recorder.run, "write_file", tag, self._write, live, rel, content, data)

    # ---- in the worker thread ----

    def _run_command(self, live: _Live, command: str, budget: float,
                     cancel: Optional[CancelHandle] = None) -> Tuple[ExecOutcome, Optional[PlimsollCall]]:
        out = live.workspace.run(["sh", "-c", command], env=self._env_vars, timeout=budget, cancel=cancel)
        return out, live.recorder.last()

    def _read_whole(self, live: _Live, rel: str, cancel: Optional[CancelHandle] = None) -> bytes:
        try:
            return live.workspace.read_whole(rel, cancel=cancel)
        except FileNotFoundError:
            raise self._unreadable(live, rel, cancel) from None

    def _next_piece(self, live: _Live, rel: str, pieces: Iterator[bytes], first: bool,
                    cancel: Optional[CancelHandle] = None) -> Optional[bytes]:
        try:
            return next(pieces, None)
        except FileNotFoundError:
            if not first:
                raise
            raise self._unreadable(live, rel, cancel) from None

    @staticmethod
    def _unreadable(live: _Live, rel: str, cancel: Optional[CancelHandle]) -> OSError:
        """Why a read found no file, which the read step's exit status cannot tell
        (BusyBox head says "I/O error" of a directory): one more call."""
        r = live.workspace.run(["sh", "-c", _WHY_UNREADABLE, "sh", rel], cancel=cancel)
        word = r.stdout_text.strip()
        if word == "is_directory":
            return IsADirectoryError(errno.EISDIR, "Is a directory", rel)
        if word == "permission_denied":
            return PermissionError(errno.EACCES, "Permission denied", rel)
        return FileNotFoundError(errno.ENOENT, "No such file or directory", rel)

    def _write(self, live: _Live, rel: str, content: Any, data: bytes, cancel: Optional[CancelHandle] = None) -> None:
        # Text goes as the call's file, which the daemon writes; bytes, text with a NUL (which
        # a call's text file cannot carry) and text past one call's file budget go as base64
        # through the workspace's fixed write step.
        as_text = isinstance(content, str) and "\x00" not in content and len(data) <= v.MAX_PROJECT_BYTES - 1024
        try:
            live.workspace.write(rel, content if as_text else data, cancel=cancel)
        except OSError as e:
            if type(e) is not OSError:
                raise
            raise _write_error(rel, str(e)) from None

    # ---- helpers ----

    def _ready(self, ctx: Any) -> Tuple[_Live, _Tag]:
        live = self._live
        if live is None:
            raise RuntimeError("plimsoll: the environment has no session; call initialize() first (ADK's toolset does)")
        tag = self._tag(ctx)
        if tag.tool_call is not None:
            self._bind(tag.tool_call.owner)
        return live, tag

    @staticmethod
    def _tag(ctx: Any) -> _Tag:
        tool_call = _TOOL_CALL.get()
        if tool_call is not None:
            return _Tag(tool_call.function_call_id, tool_call)
        call_id = getattr(ctx, "function_call_id", None) if ctx is not None else None
        return _Tag(call_id if isinstance(call_id, str) else None, None)

    def _bind(self, owner: Tuple[str, str]) -> None:
        # One sandbox is one trust domain (docs/sessions.md, "Who may share a session"): the
        # first ADK app and user whose tool call reaches it hold it until close().
        with self._state_lock:
            if self._owner is None:
                self._owner = owner
            elif self._owner != owner:
                raise PlimsollError(
                    "plimsoll: this environment's sandbox belongs to another ADK user, and one sandbox is one trust "
                    "domain; give each user an environment of their own. Nothing was sent.",
                    code="permission_denied",
                    not_dispatched="permission",
                )

    def _budget(self, timeout: Optional[float]) -> float:
        if timeout is None:
            budget = self._ceiling if self._ceiling is not None else self._timeout
        elif isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError(f"timeout must be a number of seconds or None, not {timeout!r}")
        else:
            budget = float(timeout)
        return budget  # the workspace caps it at the daemon's ceiling (its max_timeout)

    def _note(self, call: PlimsollCall, tool_call: Optional[_ToolCall]) -> None:
        with self._calls_lock:
            self._calls.append(call)
        if tool_call is not None:
            tool_call.calls.append(call)


def _close_session(session: Session, cancel: Optional[CancelHandle] = None) -> SessionSummary:
    return session.close()


class PlimsollEnvironmentGuard(BasePlugin):
    """Register first on the Runner (``plugins=[PlimsollEnvironmentGuard(), ...]``) with a
    :class:`PlimsollEnvironment`. For every ADK tool call it:

    - **tags** each plimsoll call the environment makes for it with the tool call's ID (in
      :attr:`PlimsollEnvironment.calls`), and sends that ID to the daemon as the call's
      trace ID, so the daemon's audit line joins ADK's span and the session's event;
    - **labels ADK's span** for the tool call (``execute_tool <name>``) with what plimsoll
      stated, one value per plimsoll call, under the keys the LangChain tool puts on a
      LangSmith run: ``plimsoll_record_sha256``, ``plimsoll_isolation``,
      ``plimsoll_isolation_qualification``, ``plimsoll_dispatched``, ``plimsoll_refused``,
      ``plimsoll_outcome``, and ``plimsoll_calls`` (how many). Each value is checked
      against its closed set and is "" when it does not pass, so no guest text reaches the
      trace through these labels;
    - **stops the agent** after a tool call one of whose plimsoll calls may have run
      without a complete answer: it raises :class:`PlimsollEnvironmentError`, which ends
      the invocation (ADK wraps it in RuntimeError). ADK's environment tools hand any error
      of the environment to the model as an ordinary failure (``_execute_tool.py:108``),
      which invites the model to run the command again, and ``ReflectAndRetryToolPlugin``
      asks it to, for any raised error; a rerun of a command that already ran repeats what
      it did. A refusal before anything ran is left to the model and to other plugins;
    - **keeps one sandbox to one user**: the first ADK app and user whose tool call reaches
      an environment hold it until it closes, and a tool call of another is refused before
      anything is sent (marked not dispatched, reason ``permission``), since one plimsoll
      session is one trust domain (docs/sessions.md). One user's several conversations
      share it.

    It reads ADK's public hooks only: ``before_tool_callback``, ``after_tool_callback``,
    ``on_tool_error_callback`` (``plugins/base_plugin.py``), the tool context's
    ``function_call_id``, ``user_id`` and ``session.app_name``, and OpenTelemetry's current
    span, which is ADK's ``execute_tool`` span while these callbacks run
    (``telemetry/_instrumentation.py:996``).
    """

    def __init__(self) -> None:
        super().__init__(name="plimsoll_environment_guard")

    async def before_tool_callback(self, *, tool: Any, tool_args: Dict[str, Any], tool_context: Any) -> None:
        app = getattr(getattr(tool_context, "session", None), "app_name", "") or ""
        user = getattr(tool_context, "user_id", "") or ""
        call_id = tool_context.function_call_id
        _TOOL_CALL.set(_ToolCall(call_id if isinstance(call_id, str) else None, (str(app), str(user))))
        return None

    async def after_tool_callback(self, *, tool: Any, tool_args: Dict[str, Any], tool_context: Any, result: Any) -> None:
        try:
            self._settle(tool_context)
        finally:
            _TOOL_CALL.set(None)  # nothing after the tool call is tagged with it
        return None

    async def on_tool_error_callback(self, *, tool: Any, tool_args: Dict[str, Any], tool_context: Any,
                                     error: BaseException) -> None:
        try:
            if isinstance(error, asyncio.CancelledError):
                # ADK calls this for a cancelled tool call too, for cleanup only (2.14.1,
                # plugins/base_plugin.py): label what happened, never raise.
                _label_span(self._calls(tool_context))
                return None
            self._settle(tool_context)
        finally:
            _TOOL_CALL.set(None)
        return None

    @staticmethod
    def _calls(tool_context: Any) -> List[PlimsollCall]:
        tool_call = _TOOL_CALL.get()
        if tool_call is None or tool_call.function_call_id != tool_context.function_call_id:
            return []
        return list(tool_call.calls)

    def _settle(self, tool_context: Any) -> None:
        calls = self._calls(tool_context)
        if not calls:
            return
        _label_span(calls)
        for call in calls:
            if call.uncertain:
                # From None: ADK calls on_tool_error_callback while the tool's own error is
                # being handled, and records the error that ends the run on its span with its
                # chain; the tool's error may carry text this message keeps out.
                raise PlimsollEnvironmentError(
                    f"plimsoll: the agent was stopped: the {call.method} call of this tool call may have run without a "
                    "complete answer, and running it again could repeat what it did. What plimsoll stated about each "
                    "call is in PlimsollEnvironment.calls.",
                    call=call,
                ) from None


def _label_span(calls: Sequence[PlimsollCall]) -> None:
    """Puts each call's trusted labels on the current OpenTelemetry span, one value per
    call in order ("" where a call has none). Never raises: a label is never worth the
    tool call."""
    if not calls:
        return
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        if not span.is_recording():
            return
        labels = [c.labels() for c in calls]
        span.set_attribute("plimsoll_calls", len(calls))
        for key in _langsmith.KEYS:
            span.set_attribute(key, [one.get(key, "") for one in labels])
    except Exception as e:  # pragma: no cover (an OpenTelemetry failure)
        _langsmith.log.debug("plimsoll: the ADK span was not labeled (%s)", type(e).__name__)
