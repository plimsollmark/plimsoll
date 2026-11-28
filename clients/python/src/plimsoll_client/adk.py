"""Optional Google ADK adapters over the checked client: a code executor (each Python block
in a fresh sandbox) and an environment (one plimsoll session as ADK's kept sandbox with a
shell and files)."""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextvars
import hashlib
import json
import logging
import mimetypes
import os
import queue
import threading
import weakref
from collections import OrderedDict
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Callable, Dict, Iterator, List, Literal, Mapping, Optional, Sequence, Tuple, Union

try:
    import google.adk  # noqa: F401  (the extra this module needs; named if it is missing)
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.adk needs Google ADK: pip install 'plimsoll-client[adk]'") from e
from google.adk.code_executors.base_code_executor import BaseCodeExecutor
from google.adk.code_executors.code_execution_utils import CodeExecutionInput, CodeExecutionResult, File
from google.adk.environment import BaseEnvironment, EnvironmentScope, ExecutionResult
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.agent_tool import AgentTool
from pydantic import ConfigDict, Field

from . import _langsmith
from . import _validate as v
from ._transport import CancelHandle, in_thread
from .checkpoint import CheckpointStore
from .client import Client, Session
from .execution import CodeExecutor
from .files import FilesResult
from .errors import (AtCapacityError, InsufficientIsolationError, PlimsollError, RequestCanceledError, SessionEndedError,
                     UnsupportedError)
from ._tables import SESSION_END_NAMES
from .types import ProjectResult, RunRecord, SessionSummary, SoftwareRule, meets
from .workspace import _ENV_NAME, ExecOutcome, Workspace, WorkspaceCallError
from .workspace import close_quietly as _close_quietly

__all__ = ["PlimsollCodeExecutor", "PlimsollCodeExecutionResult", "PlimsollCodeExecutionError", "PlimsollCodeExecutorGuard",
           "CODE_EXECUTION_INSTRUCTION", "PlimsollEnvironment", "PlimsollExecutionResult", "PlimsollCall",
           "PlimsollEnvironmentError", "PlimsollEnvironmentGuard"]

# What the guard tells a model whose agent executes through plimsoll. ADK 2.15.0 adds
# its own version (_NON_BUILTIN_EXECUTOR_INSTRUCTION) only under optimize_data_file, which this
# executor refuses (extensions/_code_execution.py:236 in 2.15.0, as in 2.14.1), so without this a model would get no word on
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


# The asyncio task an agent's model call ran in, which the guard records. ADK 2.15.0 runs the
# executor through asyncio.to_thread (extensions/_code_execution.py:301, :431), which copies the
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
    daemon's five-minute ceiling. ADK 2.15 checks its retry count before the first
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
        # ADK 2.15.0 calls this through asyncio.to_thread with no handler
        # (flows/llm_flows/extensions/_code_execution.py:301 and :431), so an exception
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
        # Only the files this executor asked for reach ADK: the client does not hold a daemon
        # to the request's artifact list, and the guard lets a Runner without an artifact
        # service through only when artifact_paths is empty, so a file it never named would
        # make ADK raise after the block had run.
        output = [File(name=a.path, content=a.content,
                       mime_type=mimetypes.guess_type(a.path)[0] or "application/octet-stream")
                  for a in result.artifacts if a.path in self.artifact_paths]
        return PlimsollCodeExecutionResult(stdout=stdout, stderr=stderr, exit_code=exit_code,
                                           output_files=output, execution=result)


class PlimsollCodeExecutorGuard(BasePlugin):
    """Register first on Runner to refuse, before any model or code call, what would
    otherwise fail around plimsoll's execution.

    It also adds CODE_EXECUTION_INSTRUCTION to the request of every agent that executes
    through plimsoll, and records the task each model call runs in, so cancelling that
    task cancels the code execution's request too. ADK's compositional function calling (support_cfc) replaces the executor with
    BuiltInCodeExecutor without invoking any of its methods, so the executor itself
    cannot refuse it. And ADK saves every file a block returns through the Runner's
    artifact service, raising after the block has run when there is none
    (flows/llm_flows/extensions/_code_execution.py:576 in ADK 2.15.0; 2.14 raised for
    every execution, files or not), so a Runner without one is refused first when a
    ``PlimsollCodeExecutor`` it reaches names ``artifact_paths``.
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
        # 2.15.0, agents/context.py:423; it returns a copy with the same agent). A rename
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
        # Refused wherever plimsoll executes in the tree, not only at the root: ADK 2.15.0
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


def _plimsoll_executors(agent: Any) -> Iterator["PlimsollCodeExecutor"]:
    """Every PlimsollCodeExecutor of the agent and of the agents it can reach: its
    sub-agents, and agents wrapped as its tools (AgentTool), whose nested Runner forwards
    artifacts to this one's artifact service."""
    stack, seen = [agent], set()
    while stack:
        a = stack.pop()
        if id(a) in seen:
            continue
        seen.add(id(a))
        executor = getattr(a, "code_executor", None)
        if isinstance(executor, PlimsollCodeExecutor):
            yield executor
        stack.extend(getattr(a, "sub_agents", None) or [])
        stack.extend(t.agent for t in getattr(a, "tools", None) or [] if isinstance(t, AgentTool))


def _uses_plimsoll(agent: Any) -> bool:
    """Whether the agent or any agent it can reach executes code through plimsoll."""
    return next(_plimsoll_executors(agent), None) is not None


def _refuse_without_artifacts(invocation_context: Any, agent: Any) -> None:
    # Only an executor that names artifact_paths can hand ADK a file (execute_code passes on
    # only the artifacts those paths name); a block that returns none needs no artifact
    # service in ADK 2.15.
    if invocation_context.artifact_service is None and any(e.artifact_paths for e in _plimsoll_executors(agent)):
        raise UnsupportedError(
            "PlimsollCodeExecutor with artifact_paths needs an artifact service on the Runner: "
            "ADK saves every file a block returns through it and raises after the block has run "
            "without one. Pass artifact_service= (InMemoryArtifactService() for development), "
            "or name no artifact_paths.",
            not_dispatched="unsupported",
        )


# ---- the environment: one plimsoll session as ADK's kept sandbox with a shell and files ----
#
# ADK's interface, read in google-adk 2.15.0 (google/adk/environment/_base_environment.py):
# ExecutionResult, BaseEnvironment with scope (157), initialize (178), close, working_dir
# (208, None by default: this class raises RuntimeError until a session is open, which ADK's
# toolset reads as None, tools/environment/_utils.py working_dir_or_none), execute,
# read_file (244), read_file_stream (259) and write_file (280), each of the five called with a
# keyword ``ctx``: the calling tool's Context, which carries function_call_id. ADK's tools
# call ensure_initialized (tools/environment/_utils.py) before every tool call, so
# initialize returns at once while a session is open; EnvironmentToolset builds its
# instruction without initializing (_environment_toolset.py:121), so a model's first request
# names no work directory, and its close closes the environment (Runner.close calls it). The
# scope is SHARED by default (one environment is one session, and the guard keeps it to one
# user) or SESSION (scope="session": a sandbox per ADK session, keyed by ctx.session's
# app_name, user_id and id; the toolsets then serialize initialize per ADK session,
# tools/environment/_utils.py _scope_lock_key). An AgentTool's nested Runner runs the wrapped
# agent in a new ADK session (InMemorySessionService) of the same app and user whose state is
# a copy of the caller's, keys starting _adk left out, and forwards the state changes the
# wrapped agent makes back to the caller's (agent_tool.py, state_dict and "Forward state
# delta"); _SANDBOX_STATE_KEY rides that copy.
# Each tool's ctx names its ADK invocation (ReadonlyContext.invocation_id); an AgentTool's
# nested Runner, which closes the wrapped agent's toolsets when it finishes (agent_tool.py),
# records the wrapping invocation on each invocation it makes (InvocationContext's
# _parent_invocation_id, agent_tool.py:331, set when the tool inherits plugins, its default).

# How many ADK invocations an environment remembers the session of. One environment serves
# one user, whose invocations each last one turn of a conversation: an invocation is
# forgotten only after this many others have used the environment since its last call
# (a few hundred bytes each, so well under a megabyte).
_MAX_REMEMBERED_INVOCATIONS = 1024

# Under the SESSION scope: the session state key that names the ADK session whose sandbox a
# conversation uses, and that sandbox's plimsoll session fingerprint (neither is a secret).
# An AgentTool's wrapped agent finds its caller's sandbox through it, and a conversation
# whose sandbox this environment no longer holds is refused instead of given an empty one.
_SANDBOX_STATE_KEY = "plimsoll:sandbox"
# How many ADK sessions' sandboxes one environment holds, opens in flight included. A new
# conversation's open past it lets the least recently used one go that has no call in flight
# and, without a checkpoint store, is between turns (closed, and its conversation refused from
# then on; with a store dropped, and attached again by its next call); with none such the open
# is refused, AtCapacityError marked not dispatched. Never a sandbox with a call in flight.
_MAX_SANDBOXES = 256

# The capacity limits a close of one of this environment's own idle sandboxes can cure, as
# the daemon states them on its refusal (AtCapacityError.limit): its session places, the
# caller's, and runs in flight, the daemon's or the caller's, which a running session holds.
# Not "owner_sessions": the daemon closes that owner's idle session itself and refuses only
# when every one is running a call. Not "rate", "paid_seconds", "queue", "provider",
# "deadline" (the call's own time ran out, which no close gives back) or "unknown" (a daemon
# that does not state the limit): no close is known to cure them.
_ROOM_LIMITS = frozenset({"sessions", "caller_sessions", "runs", "caller_runs"})
# How many ADK sessions a sandbox remembers as having used it (its own conversation, the
# AgentTool sessions run in it and the sessions that ran those), to tell whether all of them
# are between turns. Past it the least recently seen is forgotten: each call refreshes its
# whole chain, so the conversation of a call in progress is always among the most recent.
_MAX_ADK_SESSIONS_PER_SANDBOX = 16

log = logging.getLogger("plimsoll_client")

# Why a conversation whose state names a sandbox this environment does not hold is refused.
_SESSION_GONE = (
    "plimsoll: the sandbox this ADK session used (its state's plimsoll:sandbox) is not one this environment holds: "
    f"end() closed it, it was let go between turns as the least recently used past {_MAX_SANDBOXES}, it was closed "
    "between turns to make room "
    "when the daemon was at capacity, or another process opened it; an empty sandbox is not put in its place. Start a "
    "new ADK session, pass reopen_after_close=True for an empty one, or give the environment a checkpoint_store so it "
    "attaches the sandbox again (docs/google-adk.md). Nothing was sent."
)

# Why a new conversation's open is refused when the environment holds _MAX_SANDBOXES already.
_FULL = (
    f"plimsoll: this environment holds {_MAX_SANDBOXES} ADK sessions' sandboxes, and none of them can be let go: each "
    "has a call in flight, is opening, or is not known to be between turns (a turn is known only through a Runner that "
    "carries PlimsollEnvironmentGuard). Nothing was sent; try again when a conversation's turn has ended."
)

# Why a call is refused when its conversation reached two sandboxes.
_SPLIT = (
    "plimsoll: this ADK conversation reached two sandboxes: its own first tool call and an AgentTool's agent each "
    "opened one at the same time, and its state now names the agent's, so its files are split between them and "
    "neither is given to it. ADK says which call an AgentTool's run belongs to only when the tool inherits the Runner's "
    "plugins (include_plugins=True, its default), and then the two share one sandbox. Start a new ADK session for "
    "this conversation (docs/google-adk.md). Nothing was sent."
)


@dataclass
class _Turn:
    """One ADK invocation in progress, as the guard saw it begin: its ADK session's key, the
    invocation an AgentTool ran it inside (None for a top-level one), and the ids of the
    InvocationContext objects it began with, each forgotten when the object is collected."""

    key: Tuple[str, str, str]
    parent: Optional[str]
    objects: set = field(default_factory=set)


class _Turns:
    """The ADK invocations in progress in this process, from the Runner's own lifecycle as
    :class:`PlimsollEnvironmentGuard` sees it: ADK calls ``on_user_message_callback`` and
    ``before_run_callback`` after it has the session and before the agent runs, and
    ``after_run_callback`` when the invocation has ended (``utils/_runner_utils.py``,
    ``_run_invocation_lifecycle``; ``on_run_error_callback`` when it ended with an error). An
    invocation cancelled from outside calls neither: it stays in progress until its
    InvocationContext is collected, so its conversation's sandbox is kept, never closed under
    it. Under the SESSION scope this is the one fact the environment reads to tell whether a
    conversation is between turns; one for the whole process, since a conversation may be run
    by any Runner of it. The latest ended invocations are remembered too (as many as
    _MAX_REMEMBERED_INVOCATIONS), so a call of one still names its sessions; one forgotten is
    as one the guard never saw.

    A collected InvocationContext's finalizer never takes the lock: a garbage collection runs
    finalizers in whatever thread allocated at that moment, the one holding the lock
    included, and the lock is not reentrant, so a finalizer that took it could stop that
    thread (and with it a whole ADK server's event loop) for good. It puts what was
    collected on ``_gone``, which every method drains under the lock before it reads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._gone: "queue.SimpleQueue[Tuple[str, int]]" = queue.SimpleQueue()
        self._by_invocation: Dict[str, _Turn] = {}
        self._by_session: Dict[Tuple[str, str, str], int] = {}
        self._ended: "OrderedDict[str, _Turn]" = OrderedDict()

    def begin(self, ic: Any) -> None:
        invocation = getattr(ic, "invocation_id", None)
        session = getattr(ic, "session", None)
        key = tuple(getattr(session, name, None) for name in ("app_name", "user_id", "id"))
        if not isinstance(invocation, str) or not invocation or not all(isinstance(x, str) for x in key):
            return  # not ADK's: nothing to count, and the sandbox it reaches is never taken as between turns
        parent = getattr(ic, "_parent_invocation_id", None)
        with self._lock:
            self._drain()
            turn = self._by_invocation.get(invocation)
            if turn is None:
                self._ended.pop(invocation, None)
                turn = self._by_invocation[invocation] = _Turn(key, parent if isinstance(parent, str) and parent else None)  # type: ignore[arg-type]
                self._by_session[turn.key] = self._by_session.get(turn.key, 0) + 1
            if id(ic) in turn.objects:
                return
            turn.objects.add(id(ic))
        try:
            weakref.finalize(ic, self._collected, invocation, id(ic)).atexit = False
        except TypeError:
            pass  # an object without weak references: it ends only by after_run or on_run_error

    def end(self, ic: Any) -> None:
        invocation = getattr(ic, "invocation_id", None)
        with self._lock:
            self._drain()
            turn = self._by_invocation.pop(invocation, None) if isinstance(invocation, str) else None
            if turn is not None:
                self._forget(invocation, turn)

    def _collected(self, invocation: str, object_id: int) -> None:
        """The finalizer of a collected InvocationContext: hands it off, taking no lock
        (SimpleQueue.put is reentrant, safe from a finalizer)."""
        self._gone.put((invocation, object_id))

    def _drain(self) -> None:
        """Under _lock: forgets each collected InvocationContext handed off since the last
        drain, and its invocation once none of its objects is left."""
        while True:
            try:
                invocation, object_id = self._gone.get_nowait()
            except queue.Empty:
                return
            turn = self._by_invocation.get(invocation)
            if turn is None or object_id not in turn.objects:
                continue  # ended already, or begun again (a resumed invocation) by another object
            turn.objects.discard(object_id)
            if not turn.objects:
                del self._by_invocation[invocation]
                self._forget(invocation, turn)

    def _forget(self, invocation: str, turn: _Turn) -> None:
        left = self._by_session.get(turn.key, 0) - 1
        if left > 0:
            self._by_session[turn.key] = left
        else:
            self._by_session.pop(turn.key, None)
        self._ended[invocation] = turn
        while len(self._ended) > _MAX_REMEMBERED_INVOCATIONS:
            self._ended.popitem(last=False)

    def chain(self, invocation: Optional[str]) -> Optional[List[Tuple[str, str, str]]]:
        """The ADK sessions of ``invocation`` and of each invocation that ran it as an
        AgentTool, innermost first; None when the guard did not see ``invocation`` begin (a Runner without it, a direct call, an AgentTool that does not
        inherit the Runner's plugins)."""
        if invocation is None:
            return None
        with self._lock:
            self._drain()
            turn = self._by_invocation.get(invocation) or self._ended.get(invocation)
            if turn is None:
                return None
            keys = [turn.key]
            for _ in range(64):  # AgentTools nest a handful deep; the bound only stops a cycle
                parent = self._by_invocation.get(turn.parent) or self._ended.get(turn.parent) if turn.parent else None
                if parent is None:
                    break
                turn = parent
                keys.append(turn.key)
            return keys

    def in_turn(self, key: Tuple[str, str, str]) -> bool:
        with self._lock:
            self._drain()
            return self._by_session.get(key, 0) > 0


_TURNS = _Turns()

#: Seconds a call may run when ADK names no budget for it: a file read or write, and the
#: pwd that learns the work directory of a session whose open stated none.
DEFAULT_TIMEOUT = 120.0

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


def _from_result(method: str, call_id: Optional[str], r: Union[ProjectResult, FilesResult]) -> PlimsollCall:
    if isinstance(r, FilesResult):
        # A file call has no step: it was carried out when it completed (with or without an
        # error of the operation's), and may have run when it did not.
        return PlimsollCall(method=method, function_call_id=call_id, dispatched="yes", outcome=r.outcome, isolation=r.isolation,
                            isolation_qualification=r.isolation_qualification, record=r.record, exit_code=None,
                            uncertain=r.outcome != "completed")
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
    stated about it; ``execution`` the answer, when one came back: a command's
    :class:`~plimsoll_client.types.ProjectResult` (its ``detail`` is the runner's text, kept
    out of this message) or a file call's :class:`~plimsoll_client.files.FilesResult`. It carries no not-dispatched mark: when
    ``call.uncertain`` the command may have run, and repeating it may repeat what it did.
    The message is built from trusted fields only, since ADK records a raised error on its
    span (``telemetry/tracing.py:330``)."""

    def __init__(self, message: str, *, call: Optional[PlimsollCall],
                 execution: Optional[Union[ProjectResult, FilesResult]] = None) -> None:
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


class _CallLog:
    """Every call an environment made, in order, across its sessions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: List[PlimsollCall] = []

    def note(self, call: PlimsollCall, tool_call: Optional[_ToolCall]) -> None:
        with self._lock:
            self._calls.append(call)
        if tool_call is not None:
            tool_call.calls.append(call)

    def calls(self) -> Tuple[PlimsollCall, ...]:
        with self._lock:
            return tuple(self._calls)


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

    def run_files(self, op: Any, *, timeout: Optional[float] = None, cancel: Optional[CancelHandle] = None) -> FilesResult:
        """A file call of the workspace's, noted as run_project's calls are."""
        method, tag = getattr(self.local, "op", None) or ("unknown", _Tag(None, None))
        call_id = tag.function_call_id
        try:
            r = self._session.run_files(op, timeout=timeout, cancel=cancel, trace_id=_langsmith.trace_id(call_id))
        except BaseException as e:
            c = _from_error(method, call_id, e)
            self.local.last = (c, None)
            self._note(c, tag.tool_call)
            raise
        c = _from_result(method, call_id, r)
        self.local.last = (c, r)
        self._note(c, tag.tool_call)
        return r

    @property
    def work_dir(self) -> str:
        return self._session.work_dir

    @property
    def file_scopes(self) -> Tuple[str, ...]:
        # What the workspace reads to choose a confined path's scope; the environment's is
        # unconfined (every path in the sandbox scope), so it is passed on for any other use.
        return tuple(getattr(self._session, "file_scopes", ()) or ())

    @property
    def session(self) -> Session:
        return self._session

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


def _environment_error(method: str, call: PlimsollCall,
                       result: Optional[Union[ProjectResult, FilesResult]]) -> PlimsollEnvironmentError:
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


@dataclass(frozen=True)
class _Live:
    """The open session's workspace and recorder, taken together so a close() between a
    method's check and its call cannot pair one session's workspace with another's."""

    workspace: Workspace
    recorder: _Recorder
    generation: int  # which of the environment's sessions: one more at each open
    ceiling: Optional[float] = None  # the daemon's longest call budget, None for no limit
    fingerprint: str = ""  # the plimsoll session's

    @property
    def identity(self) -> Any:
        """Which plimsoll session this is, as an ADK invocation is held to it (_hold): its
        fingerprint, which stays the same when a checkpoint store attaches the session again
        under a new _Live; the generation for a session that states none."""
        return self.fingerprint or self.generation


@dataclass(frozen=True)
class _Lost:
    """Why an environment (or, under the SESSION scope, one ADK session) lost its sandbox:
    ``reason`` is a SessionEndedError reason (the daemon's, or ``closed`` when the client
    stopped the session), ``why`` a sentence from trusted words only."""

    reason: str
    why: str


def _lost_from(session: Session) -> Optional[_Lost]:
    """The loss ``session`` states once it can take no more calls, else None. The client
    sends nothing more on a session once a call ended without an answer it could check (a
    call cancelled after it was sent ends so), and the daemon takes nothing more once it
    ended the session. Its own texts are not carried: they may hold a transport's words."""
    ended = session.ended
    if ended is not None:
        reason = ended.reason if ended.reason in SESSION_END_NAMES else "unknown"
        return _Lost(reason, f"the daemon ended its plimsoll session ({reason})")
    if session.stopped is not None:
        return _Lost("closed", "a call ended without an answer the client could check, as a call cancelled after it "
                               "was sent does, so the client sends nothing more on its plimsoll session")
    return None


def _lost_error(lost: _Lost, *, scoped: bool) -> SessionEndedError:
    then = ("Start a new ADK session for this conversation." if scoped else
            "Give the agent a new PlimsollEnvironment, or call close(): the next initialize() then opens a new, empty "
            "sandbox.")
    what = "this ADK session's sandbox" if scoped else "this environment's sandbox"
    return SessionEndedError(
        f"plimsoll: {what} was lost, and the files in it: {lost.why}. The environment closed it and does not put an "
        f"empty sandbox in its place, since the agent would take it for the one holding its files. {then} Nothing was "
        "sent.",
        reason=lost.reason,
        not_dispatched="request",
    )


class _Slot:
    """One ADK session's sandbox under the SESSION scope. ``lock`` is held across its open
    (a network call, in a worker thread), so two calls of one ADK session never open two
    sandboxes, and other ADK sessions' opens do not wait on it."""

    def __init__(self, key: Tuple[str, str, str]) -> None:
        self.key = key
        self.lock = threading.Lock()
        self.session: Optional[Session] = None
        self.live: Optional[_Live] = None
        # Why its sandbox was lost (set under ``lock``, before ``live`` is cleared), until end().
        # A lost slot holds no sandbox: it is never closed to make room, and its conversation
        # is refused with the loss named, reopen_after_close or not.
        self.lost: Optional[_Lost] = None
        # Under the environment's _state_lock: the calls in flight (each counted until its
        # worker thread ends, or by the await when the thread never started), the keys of the
        # ADK sessions that used the sandbox (_TURNS.chain of each call, most recent last),
        # and whether a call reached it from an invocation the guard did not see begin: then
        # nothing says when its turns end, and it is never let go to make room.
        self.busy = 0
        self.turns: "OrderedDict[Tuple[str, str, str], None]" = OrderedDict()
        self.unseen = False
        # Set under _state_lock when its open failed and it was taken out of _slots.
        self.failed = False


class PlimsollEnvironment(BaseEnvironment):
    """ADK's environment (``google.adk.environment.BaseEnvironment``) over one plimsoll
    session: every shell command and file read or write of an agent's
    ``EnvironmentToolset`` is a call of that session, behind the isolation floor it was
    opened at, with a checked run record on every call and no network.

    Construction touches nothing. ``initialize()`` (ADK's toolset calls it when the agent
    first runs) asks the daemon whether it offers sessions, opens one at
    ``minimum_isolation`` (``kernel`` by default: a docker daemon without gVisor is refused,
    marked not dispatched) and takes the work directory the open stated (``/work`` on
    docker, ``/tmp/work`` on OpenShell), with no call, as ``working_dir``; a session that
    states none, one that takes no file calls (a daemon from before file calls), is asked once
    by running ``pwd``, and its file reads and writes are refused, marked not dispatched. The
    file reads and writes are file calls in the sandbox scope (an absolute path, links followed
    as the guest's shell follows them), which every provider with file calls takes, OpenShell's
    included. ``close()`` (the toolset's close calls it, and ``Runner.close()`` calls
    that) closes the session: the sandbox and its files are gone; ``initialize()`` after it
    opens a new, empty one, as ADK's lifecycle has it, for a new ADK invocation. An ADK
    invocation that used a session is held to it: once that session is closed (an
    ``AgentTool``'s agent sharing this environment closes it when it finishes), a call of
    that invocation, or of the invocation that ran it as an ``AgentTool``, raises
    :class:`~plimsoll_client.SessionEndedError` (reason ``closed``, marked not dispatched),
    never opening or joining another sandbox, which would not hold its files. ``lifetime``
    and ``idle_timeout`` (seconds) may only shorten the daemon's own; ``owner`` names the
    end user, for a daemon's per-owner cap; ``trace_id`` goes with the open. ``timeout`` (seconds) is the
    budget of a call ADK names none for; ``execute(timeout=None)`` gets the daemon's longest.
    ``env_vars`` are added to every command's environment (they enter the sandbox: never put
    a credential there).

    Each command runs in a new ``sh`` in the work directory, as ADK's own environments run
    theirs (``_local_environment.py:135``): files persist from one command to the next, a
    ``cd`` or an ``export`` does not, and a process left in the background is killed when
    its call ends (the session's sweep). Paths are relative to the work directory, or
    absolute anywhere in the sandbox (the sandbox is the boundary, as for ADK's E2B and
    Daytona environments); ``..`` out of the work directory and the workspace's own state
    directory are refused. The sandbox is lost when the daemon ends the session (its
    lifetime, a restart) and when a call ends without an answer the client can check, as a
    call cancelled after it was sent does (ADK cancels the other calls of a parallel batch
    when one fails): the client then sends nothing more on the session. The call that found
    it raises its own error, the environment closes the session (freeing its place on the
    daemon), and every later call raises :class:`~plimsoll_client.SessionEndedError`, marked
    not dispatched, naming the loss, until ``close()`` (under the SESSION scope, for that ADK
    session, until :meth:`end`). The environment never puts a fresh sandbox in its place,
    since the agent would take an empty sandbox for the one with its files.

    ``scope="session"`` (ADK's ``EnvironmentScope.SESSION``) keeps a sandbox per ADK
    session instead, so one environment serves every user and conversation of an app: the
    first tool call of a conversation opens its sandbox, the conversation's later turns use
    it, and the session's state names it (``plimsoll:sandbox``: the ADK session and the
    plimsoll session fingerprint), so an ``AgentTool``'s agent sharing the environment works
    in its caller's sandbox and keeps its files there. ``close()`` (ADK's ``Runner.close()``,
    which an ``AgentTool``'s nested Runner calls when its agent finishes) then lets the
    sandboxes go without closing them: each stays until :meth:`end` closes them all, the
    environment is collected or the process exits normally (``adk eval`` and ``adk web`` never
    call :meth:`end`; without a checkpoint store a finalizer closes what is still held), or the
    daemon's lifetime ends it (``lifetime`` shortens it). When the daemon refuses an open for
    capacity (:class:`~plimsoll_client.AtCapacityError`), the least recently used sandbox that
    is between turns and has no call in flight is closed and the open tried once more (one at
    most: the refusal may be the daemon's rate limit, which no close cures); with none, or
    when the second try is refused too, the refusal is raised as it came. Between turns is the Runner's own lifecycle, as
    :class:`PlimsollEnvironmentGuard` sees it: from the user's message (stored before the
    agent runs) to the end of the run, every invocation of the conversation, and of the
    AgentTool runs in its sandbox, is in progress, so a turn waiting on its model keeps its
    sandbox; a sandbox any call of which came from an invocation the guard did not see begin
    (a Runner without the guard) is never closed this way, and a lost one (above) holds none
    to close. A new conversation past the 256 sandboxes held (opens in flight counted) lets go
    of the least recently used of them the same way (with a store, any without a call in
    flight: it is attached again); with none, its open is refused, AtCapacityError marked not
    dispatched. An AgentTool's agent and its caller that open together, as the first calls of
    a conversation, share one sandbox when the tool inherits the Runner's plugins (its
    default), which is how ADK names the call a nested run belongs to; without that the two
    open one each, and the conversation's next call is refused,
    :class:`~plimsoll_client.SessionEndedError` reason ``replaced``, rather than working in
    the agent's sandbox without the caller's files. A conversation whose state names a
    sandbox this environment no longer holds (it ended, was let go past the 256 most recently
    used, was closed to make room, or another process opened it) is refused, :class:`~plimsoll_client.SessionEndedError` reason ``not_found``, never given an
    empty one unless ``reopen_after_close`` is set (then it gets a new, empty sandbox; this
    scope only, and not with a store). A sandbox closed to make room is not lost: only a lost
    one is refused with its loss named, and ``reopen_after_close`` does not reopen it. A state
    naming a sandbox without its fingerprint is refused too, marked not dispatched, reason
    ``permission``, ``reopen_after_close`` or not; with ``checkpoint_store`` (a
    :class:`~plimsoll_client.CheckpointStore` only the application can write, and the
    client's ``daemon_name``) the environment attaches it
    again instead, from a checkpoint kept under a key derived from the ADK session's app,
    user and ID, and leaves the sandboxes open at exit for another process to attach. Every
    call needs ADK's ``ctx`` with a session; ``owner`` is then the ADK user unless given.

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
        scope: str = "shared",
        checkpoint_store: Optional[CheckpointStore] = None,
        reopen_after_close: bool = False,
    ) -> None:
        if scope not in (EnvironmentScope.SHARED, EnvironmentScope.SESSION):
            raise ValueError("plimsoll: an ADK environment's scope is shared or session (EnvironmentScope.SHARED or SESSION)")
        self._scope = EnvironmentScope(scope)
        if checkpoint_store is not None:
            if self._scope is not EnvironmentScope.SESSION:
                raise ValueError("plimsoll: checkpoint_store keeps the sandbox of each ADK session, so it needs scope='session'")
            if not getattr(client, "daemon_name", ""):
                raise ValueError("plimsoll: checkpoint_store needs the client's daemon_name (Client(..., daemon_name=...))")
        if not isinstance(reopen_after_close, bool):
            raise TypeError("reopen_after_close must be a bool")
        if reopen_after_close:
            if self._scope is not EnvironmentScope.SESSION:
                raise ValueError("plimsoll: reopen_after_close is for scope='session'; under the default scope initialize() "
                                 "after close() already opens a new sandbox for a new ADK invocation")
            if checkpoint_store is not None:
                raise ValueError("plimsoll: reopen_after_close gives a conversation an empty sandbox where checkpoint_store "
                                 "attaches its own again; pass one or the other")
        self._reopen = reopen_after_close
        self._store = checkpoint_store
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
        # What each call stated, apart from the environment: every session's recorder notes
        # into it, so nothing a slot holds refers back to the environment and the finalizer
        # below can run when the environment is collected.
        self._log = _CallLog()
        self._session: Optional[Session] = None
        self._live: Optional[_Live] = None
        self._root: Optional[str] = None
        self._owner: Optional[Tuple[str, str]] = None
        # Under the SESSION scope: each ADK session's sandbox, least recently used first.
        self._slots: "OrderedDict[Tuple[str, str, str], _Slot]" = OrderedDict()
        self._summary: Optional[SessionSummary] = None
        self._is_initialized = False
        # Under the SHARED scope: why the sandbox was lost, until close().
        self._lost: Optional[_Lost] = None
        # Under _state_lock: how many sessions have opened, and, for each ADK invocation that
        # used one, which (its _Live.identity).
        self._generation = 0
        self._held: "OrderedDict[str, int]" = OrderedDict()
        # Under the SESSION scope, under _state_lock: the sandbox key each ADK invocation's calls
        # reached, and the one an invocation that ran an AgentTool reached through it, so an
        # AgentTool's agent and its caller that open at the same time share one sandbox.
        self._conversations: "OrderedDict[str, Tuple[str, str, str]]" = OrderedDict()
        # Under the SESSION scope no Runner's close() ends a sandbox, and `adk eval` and `adk
        # web` never call end(), so the sandboxes still held are closed when the environment is
        # collected or the interpreter exits normally (weakref.finalize runs at exit, as for
        # ADK's ContainerCodeExecutor). Without it each would hold a place on the daemon until
        # its lifetime: on docker an idle session keeps one of the caller's concurrent places,
        # so the next process's opens were refused at capacity. With a checkpoint store the
        # sandboxes are left open, since another process may attach them.
        self._finalizer = (weakref.finalize(self, _end_quietly, self._slots, self._state_lock)
                           if self._scope is EnvironmentScope.SESSION and self._store is None else None)

    # ---- what the environment states ----

    @property
    def scope(self) -> EnvironmentScope:
        """``SHARED`` (one sandbox) or ``SESSION`` (one per ADK session), as constructed."""
        return self._scope

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
        """The open plimsoll session; None before ``initialize()``, after ``close()``, and
        under the SESSION scope (see :attr:`sessions`)."""
        return self._session

    @property
    def sessions(self) -> Dict[Tuple[str, str, str], Session]:
        """Under the SESSION scope, the open plimsoll session of each ADK session this
        environment holds, keyed by (app name, user ID, ADK session ID); empty otherwise."""
        with self._state_lock:
            return {k: slot.session for k, slot in self._slots.items() if slot.session is not None and slot.live is not None}

    @property
    def calls(self) -> Tuple[PlimsollCall, ...]:
        """Every call the environment made, in order, across its sessions."""
        return self._log.calls()

    @property
    def close_summary(self) -> Optional[SessionSummary]:
        """The daemon's summary of the last session ``close()`` closed."""
        return self._summary

    # ---- the lifecycle ----

    async def initialize(self, *, ctx: Any = None) -> None:
        """Opens the session (under the SESSION scope, the sandbox of ``ctx``'s ADK
        session); returns at once while one is open (a later ADK calls this before every tool
        call)."""
        if self._scope is EnvironmentScope.SESSION:
            await self._initialize_slot(ctx)
            return
        invocation = _invocation(ctx)
        self._refuse_if_lost()
        self._hold(invocation, self._live)  # refused here, before anything is sent
        if self._live is not None:
            return
        await in_thread(self._open, self._tag(ctx))
        self._hold(invocation, self._live)

    def _open(self, tag: _Tag, cancel: Optional[CancelHandle] = None) -> None:
        with self._open_lock:
            if self._live is not None:
                return
            self._refuse_if_lost()  # a loss let go of the sandbox since initialize() looked
            session, live, root = self._start(tag, cancel)
            with self._state_lock:
                # _live last: initialize() and the methods read it without the lock, from the
                # event loop's thread, and take a set _live to mean the rest is set.
                self._root, self._session = root, session
                self._is_initialized = True
                self._live = live

    def _start(self, tag: _Tag, cancel: Optional[CancelHandle], *, owner: Optional[str] = None,
               attach: Optional[Tuple[str, str]] = None, store_key: Optional[str] = None) -> Tuple[Session, _Live, str]:
        """Opens a session (or, with ``attach``, a (store key, fingerprint) pair, takes the
        stored one over), checks its tier and learns the work directory: the session, its
        _Live (a new generation) and the root. A session that fails a check is closed; an
        attached one is dropped instead, since its checkpoint stays in the store."""
        info = self._client.describe(cancel=cancel)
        if not info.supports_sessions:
            raise UnsupportedError(
                f"plimsoll: the daemon ({info.provider}) offers no sessions, which an ADK environment needs; nothing ran",
                not_dispatched="unsupported",
            )
        ms = info.session_environment.max_timeout_ms
        ceiling = ms / 1000 if ms > 0 else None
        if attach is not None:
            session = self._client.attach_session(attach[0], store=self._store, fingerprint=attach[1], cancel=cancel)
        else:
            options = dict(self._open_options)
            if owner is not None and options["owner"] is None:
                options["owner"] = owner
            if self._store is not None and store_key is not None:
                options.update(checkpoint_store=self._store, checkpoint_key=store_key)
            session = self._client.open_session(minimum_isolation=self._floor, **options)
        try:
            if not meets(session.isolation, self._floor):
                # The client checks the floor at open; this is the second look a session
                # stating less gets, before any call of it.
                raise InsufficientIsolationError(
                    f"plimsoll: the session states {session.isolation or 'no tier'}, below the required {self._floor}; "
                    "nothing ran",
                    not_dispatched="isolation",
                )
            recorder = _Recorder(session, self._log.note)
            workspace = Workspace(recorder, timeout=self._timeout, max_timeout=ceiling, confined=False)
            # The open's work_dir, with no call; a session that states none (one with no file
            # calls: a daemon from before them) is asked once, by running pwd (Workspace.root).
            root = recorder.run("initialize", tag, lambda cancel=None: workspace.root, cancel=cancel)
            if cancel is not None and cancel.cancelled:
                # The await was cancelled while the open (or the pwd) was on its way: nobody
                # will use or close this session, so it is closed here rather than holding one
                # of the daemon's places until its idle limit.
                raise RequestCanceledError("plimsoll: the open was cancelled; its session is closed", not_dispatched="request")
        except BaseException:
            if attach is None:
                _close_quietly(session)
            raise
        with self._state_lock:
            self._generation += 1
            live = _Live(workspace, recorder, self._generation, ceiling, getattr(session, "fingerprint", "") or "")
        return session, live, root

    async def close(self) -> None:
        """Closes the session: the sandbox and everything in it are gone. Idempotent. An
        error of the close (a ChainError: a call this client did not make ran in the
        session) is raised after the environment has let the session go. A close made while
        ``initialize()`` is opening waits for that open and closes the session it opened, so
        no session outlives a close that has returned.

        Under the SESSION scope it closes nothing: each ADK session's sandbox is let go and
        kept for that conversation's next call (an ``AgentTool``'s nested Runner calls this
        when its agent finishes, in the middle of its caller's turn), until the daemon's idle
        limit or lifetime ends it or :meth:`end` closes it."""
        if self._scope is EnvironmentScope.SESSION:
            self._is_initialized = False
            return
        summary = await in_thread(self._close)
        if summary is not None:
            self._summary = summary

    async def end(self) -> None:
        """Closes every sandbox this environment holds: under the SESSION scope, each ADK
        session's (call it when the app stops, after ``Runner.close()``); otherwise the same as
        :meth:`close`. A conversation whose sandbox was closed here is refused from then on,
        never given an empty one unless ``reopen_after_close`` is set. The first error of a
        close is raised once all were tried. Without it, a finalizer closes them when the
        environment is collected or the interpreter exits normally (not on a signal)."""
        if self._scope is not EnvironmentScope.SESSION:
            await self.close()
            return
        summary = await in_thread(self._end_slots)
        if summary is not None:
            self._summary = summary

    def _end_slots(self, cancel: Optional[CancelHandle] = None) -> Optional[SessionSummary]:
        with self._state_lock:
            self._root = None
            self._is_initialized = False
        summary, first = _end_all(self._slots, self._state_lock)
        if first is not None:
            raise first
        return summary

    def _close(self, cancel: Optional[CancelHandle] = None) -> Optional[SessionSummary]:
        # Under the open's lock, in a worker thread so the event loop never waits on it: a close
        # that races an open (or an open whose await was cancelled while its thread went on
        # opening) waits for the open to publish, then closes what it opened (release-94). The
        # close is not cut by the await's cancel handle: a close begun is a close finished.
        with self._open_lock:
            with self._state_lock:
                session = self._session
                self._session, self._live, self._root, self._owner = None, None, None, None
                self._is_initialized = False
                # A lost sandbox is closed with the environment: from here on the rule for a
                # closed environment applies, and the next initialize() opens a new one.
                self._lost = None
            if session is None:
                return None
            return _close_session(session)

    # ---- the SESSION scope: a sandbox per ADK session ----

    async def _initialize_slot(self, ctx: Any) -> None:
        key, mark = self._key(ctx)
        invocation = _invocation(ctx)
        slot = self._slot(key)
        if slot is not None and slot.lost is not None:
            raise _lost_error(slot.lost, scoped=True)
        live = slot.live if slot is not None else None
        if live is not None or self._store is None:
            # Refused here, before anything is sent. With a store a sandbox let go for the
            # limit is attached again below, the same plimsoll session, and held to then.
            self._hold(invocation, live)
        reopened = False
        if live is None:
            slot, live, reopened = await in_thread(self._open_slot, key, mark, self._tag(ctx))
            self._hold(invocation, live)
        if not reopened:  # a new, empty sandbox in place of the one the mark names: renamed below
            _check_mark(mark, live)
        _write_mark(ctx, key, live)
        self._seen(slot, ctx)
        self._is_initialized = True

    def _seen(self, slot: _Slot, ctx: Any) -> None:
        """Remembers on the sandbox which ADK sessions use it: ctx's, and those of the
        invocations that ran ctx's as an AgentTool, as the guard saw them begin (_TURNS), so the
        sandbox is let go between turns only when none of them is in a turn. A call of an
        invocation the guard did not see begin marks it unseen for good."""
        chain = _TURNS.chain(_invocation(ctx)[0])
        with self._state_lock:
            if chain is None:
                slot.unseen = True
                return
            for key in chain:
                slot.turns[key] = None
                slot.turns.move_to_end(key)
            while len(slot.turns) > _MAX_ADK_SESSIONS_PER_SANDBOX:
                slot.turns.popitem(last=False)

    def _key(self, ctx: Any) -> Tuple[Tuple[str, str, str], Optional[Tuple[str, str]]]:
        """:func:`_adk_session`, with the conversation's own sandbox kept to one: a call whose
        state names no sandbox yet joins the one its invocation, or the invocation that ran it
        as an AgentTool, already reached (an AgentTool's agent and its caller's own call, run in
        parallel as the first calls of a conversation, would otherwise open one each); a call
        whose state names a sandbox other than the one its own ADK session holds (they opened
        apart, through an AgentTool that does not inherit the Runner's plugins) is refused."""
        key, mark = _adk_session(ctx)
        own, parent = _invocation(ctx)
        with self._state_lock:
            if mark is None:
                for invocation in (own, parent):
                    joined = self._conversations.get(invocation) if invocation is not None else None
                    if joined is not None and joined[:2] == key[:2]:
                        key = joined
                        break
            else:
                session_id = ctx.session.id
                reached = self._conversations.get(own) if own is not None else None
                if (key[2] != session_id and key[:2] + (session_id,) in self._slots) or (
                        reached is not None and reached != key):
                    raise SessionEndedError(_SPLIT, reason="replaced", not_dispatched="request")
            for invocation in (own, parent):
                if invocation is None:
                    continue
                if invocation not in self._conversations:
                    self._conversations[invocation] = key
                self._conversations.move_to_end(invocation)
            while len(self._conversations) > _MAX_REMEMBERED_INVOCATIONS:
                self._conversations.popitem(last=False)
        return key, mark

    def _slot(self, key: Tuple[str, str, str]) -> Optional[_Slot]:
        with self._state_lock:
            slot = self._slots.get(key)
            if slot is not None:
                self._slots.move_to_end(key)
            return slot

    def _open_slot(self, key: Tuple[str, str, str], mark: Optional[Tuple[str, str]], tag: _Tag,
                   cancel: Optional[CancelHandle] = None) -> Tuple[_Slot, _Live, bool]:
        """Opens (or attaches) ``key``'s sandbox: its slot, its _Live, and whether this call
        opened a new, empty one in place of the sandbox the conversation's mark names
        (reopen_after_close)."""
        # The conversation's state names a sandbox this environment does not hold: one it let go
        # past _MAX_SANDBOXES, ended, or closed to make room at capacity, or one another process
        # opened. An empty one in its place would not hold its files.
        not_held = mark is not None and self._store is None and not self._reopen
        while True:
            victim: Optional[_Slot] = None
            with self._state_lock:
                slot = self._slots.get(key)
                if slot is None and not_held:  # before the limit, so the refusal lets nothing go
                    raise SessionEndedError(_SESSION_GONE, reason="not_found", not_dispatched="request")
                if slot is None:
                    if len(self._slots) >= _MAX_SANDBOXES:  # opens in flight are in _slots, so counted
                        victim = self._take(for_limit=True)
                        if victim is None:
                            raise AtCapacityError(_FULL, not_dispatched="capacity")
                    slot = self._slots[key] = _Slot(key)
                self._slots.move_to_end(key)
            if victim is not None:
                self._let_go(victim)
            with slot.lock:
                if slot.failed:
                    continue  # the open this call waited on failed and took its slot out: a new one
                if slot.live is not None:
                    return slot, slot.live, False  # another call of this conversation opened it meanwhile
                if slot.lost is not None:
                    raise _lost_error(slot.lost, scoped=True)  # lost since _initialize_slot looked
                store_key = _store_key(key)
                reopened = False
                try:
                    if mark is not None and self._store is not None:
                        session, live, root = self._start(tag, cancel, attach=(store_key, mark[1]))
                    elif not_held:  # a slot that was opening when this call looked, since gone
                        raise SessionEndedError(_SESSION_GONE, reason="not_found", not_dispatched="request")
                    else:
                        reopened = mark is not None
                        session, live, root = self._start_making_room(slot, tag, cancel, owner=key[1] or None,
                                                                      store_key=store_key)
                except BaseException:
                    # A slot holds a place among the _MAX_SANDBOXES while it opens; one whose open
                    # failed holds no sandbox, so it goes, and a call waiting on it starts again.
                    with self._state_lock:
                        slot.failed = True
                        if self._slots.get(key) is slot:
                            del self._slots[key]
                    raise
                with self._state_lock:
                    gone = self._slots.get(key) is not slot
                    if not gone:
                        slot.session, slot.live = session, live
                        if self._root is None:
                            self._root = root
                if gone:
                    # end() took the slot while it opened: what the open opened is closed, as a
                    # close racing an open closes what that open opened.
                    _close_quietly(session)
                    raise SessionEndedError("plimsoll: the environment was ended while this sandbox opened; nothing "
                                            "was sent", reason="closed", not_dispatched="request")
            return slot, live, reopened

    def _start_making_room(self, opening: _Slot, tag: _Tag, cancel: Optional[CancelHandle], *, owner: Optional[str],
                           store_key: str) -> Tuple[Session, _Live, str]:
        """Opens a sandbox; when the daemon refuses the open for capacity, closes one finished
        sandbox and tries once more.

        ADK never tells an environment when a conversation is finished, and a Runner's close
        does not say which sessions it ran, so the sandboxes of finished ones (the cases of an
        earlier ``adk eval`` run) stay open, and on docker each holds one of the caller's
        concurrent places even when idle. The one closed is the least recently used that is
        between turns by the Runner's own lifecycle (:meth:`_between_turns`), with no call in
        flight, and the refusal is raised as it came when there is none.

        Only for a limit a close can cure, as the refusal states it (AtCapacityError.limit,
        _ROOM_LIMITS): the daemon's or the caller's session places, or runs in flight, which a
        running session holds. Nothing is closed for the rate limit, which only time gives
        back, nor for anything else (finding release-115: each refused open closed one idle
        conversation's sandbox for nothing, so an app retrying on the rate lost one per try).
        One at most: an open needs one place, and a second close for the same open would lose
        another conversation's files and free nothing the first did not."""
        closed = False
        while True:
            try:
                return self._start(tag, cancel, owner=owner, store_key=store_key)
            except AtCapacityError as e:
                if closed or e.limit not in _ROOM_LIMITS:
                    raise
                with self._state_lock:
                    victim = self._take(opening=opening)
                if victim is None:
                    raise
            self._close_for_room(victim)
            closed = True

    def _take_finished(self, opening: Optional[_Slot]) -> Optional[_Slot]:
        """:meth:`_take` for room at capacity, under its lock."""
        with self._state_lock:
            return self._take(opening=opening)

    def _take(self, *, opening: Optional[_Slot] = None, for_limit: bool = False) -> Optional[_Slot]:
        """Under _state_lock, the lock every call takes to count itself in flight (_call), so a
        call either counted before this looked or finds its sandbox gone: takes out the least
        recently used sandbox with no call in flight that is between turns, or None. For the
        limit of _MAX_SANDBOXES, a lost one (it holds no sandbox) and, with a checkpoint store,
        one in a turn may go too: a dropped sandbox is attached again by its next call. An
        opening one is never taken."""
        for key, slot in self._slots.items():  # least recently used first
            if slot is opening or slot.busy:
                continue
            if slot.live is None:
                if not (for_limit and slot.lost is not None):
                    continue  # opening, or lost (closing one frees nothing)
            elif not (self._between_turns(slot) or (for_limit and self._store is not None)):
                continue
            del self._slots[key]
            return slot
        return None

    @staticmethod
    def _between_turns(slot: _Slot) -> bool:
        """Whether every ADK session that used the sandbox is between turns: each call reached
        it from an invocation the guard saw begin, and none of those sessions (nor the
        conversation the sandbox is keyed by) has an invocation in progress now (_TURNS). The
        Runner stores the user's message and calls the guard's on_user_message_callback and
        before_run_callback before the agent runs, so a turn waiting on its model is in
        progress; a session's events are no such fact (a SequentialAgent's first sub-agent
        stores a final response in the middle of the turn)."""
        if slot.unseen or not slot.turns:
            return False
        return not any(_TURNS.in_turn(k) for k in (slot.key, *slot.turns))

    def _close_for_room(self, slot: _Slot) -> None:
        """Closes a sandbox taken out to make room; its conversation is refused from then on
        (``not_found``), or given a new, empty sandbox with reopen_after_close. A failed close
        is logged, not raised: the open it makes room for goes on, and the daemon ends the
        session at its lifetime either way."""
        with slot.lock:
            session, slot.session, slot.live = slot.session, None, None
        if session is None:
            return
        try:
            session.close()
        except Exception as e:  # the open's own outcome is what the caller needs
            log.warning("plimsoll: a sandbox closed to make room at the daemon's capacity did not close cleanly (%s)",
                        type(e).__name__)

    def _let_go(self, slot: _Slot) -> None:
        """A sandbox let go for the limit of _MAX_SANDBOXES (:meth:`_take`): with a checkpoint
        store it is dropped (its checkpoint stays, and its conversation's next call attaches it
        again); without one it is closed, and its conversation refused from then on."""
        with slot.lock:
            session, slot.session, slot.live = slot.session, None, None
        if session is not None and self._store is None:
            _close_quietly(session)

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
        live, tag, slot = self._ready(ctx)
        budget = self._budget(timeout, live)
        if budget <= 0:
            # ADK's LocalEnvironment times such a command out at once (asyncio.wait_for with
            # no time, _local_environment.py:153); here it ends before anything is sent.
            return PlimsollExecutionResult(exit_code=-1, timed_out=True,
                                           stderr=f"plimsoll: a budget of {budget:g} s; nothing was sent\n")
        out, call = await self._call(live, slot, "execute", tag, self._run_command, live, command, budget)
        stderr = out.stderr_text
        notes = [f"plimsoll: the daemon cut {name} at its output limit"
                 for name, cut in (("stdout", out.stdout_truncated), ("stderr", out.stderr_truncated)) if cut]
        if notes:
            stderr += ("\n" if stderr and not stderr.endswith("\n") else "") + "\n".join(notes) + "\n"
        return PlimsollExecutionResult(exit_code=out.exit_code, stdout=out.stdout_text, stderr=stderr,
                                       timed_out=out.timed_out, plimsoll=call, execution=out.result)

    async def read_file(self, path: Any, *, ctx: Any = None) -> bytes:
        """The whole file at ``path``, 8 MiB a file call (``Workspace.read_whole``). Each
        error is the one the file call's answer names, carrying the errno and ``path`` as
        given, never text from the sandbox: FileNotFoundError when there is none,
        IsADirectoryError for a directory, PermissionError for a file the sandbox's user
        cannot read, OSError (``ENXIO``) for a FIFO, a socket or a device, which is never
        opened, and :class:`~plimsoll_client.WorkspaceChangedError` (an OSError) for a file
        longer than one call that changed size while it was read: never a cut copy. A file past 64 MiB
        (``workspace.MAX_WHOLE_BYTES``) is :class:`~plimsoll_client.WorkspaceTooLargeError`,
        raised after its first piece: the file ends in this process's memory, and code in
        the sandbox can make one of any size for nothing (a sparse file)."""
        rel = _posix(path)
        live, tag, slot = self._ready(ctx)
        return await self._call(live, slot, "read_file", tag, self._read_whole, live, rel)

    async def read_file_stream(self, path: Any, *, ctx: Any = None) -> AsyncGenerator[bytes, None]:
        """The bytes :meth:`read_file` returns, each 8 MiB piece yielded as it arrives
        (``Workspace.read_pieces``). Cancelling the await cuts the piece in flight. The
        same 64 MiB limit as :meth:`read_file`, so a caller that joins the pieces holds at
        most that. ADK's ReadFileTool reads through this stream (``_read_file_tool.py:177`` in
        google-adk 2.15.0, the version locked here, and at 2.14.1)."""
        rel = _posix(path)
        live, tag, slot = self._ready(ctx)
        handle = CancelHandle()
        pieces = live.workspace.read_pieces(rel, cancel=handle)
        in_flight = False
        try:
            while True:
                in_flight = True
                piece = await self._call(live, slot, "read_file", tag, self._next_piece, pieces)
                in_flight = False
                if piece is None:
                    return
                yield piece
        except asyncio.CancelledError:
            handle.cancel()  # the worker thread is still in the read: cut it there
            raise
        finally:
            if not in_flight:
                pieces.close()  # a read still running in its thread ends with the cut instead

    async def write_file(self, path: Any, content: Any, *, ctx: Any = None) -> None:
        """Writes ``content`` (str, as UTF-8, or bytes) to ``path``, creating its parent
        directories (``Workspace.write``: one file call that replaces the file whole up to 4
        MiB; past that, the first 4 MiB replace it and each later call appends the next, so
        a failure partway leaves the first pieces). Its errors are those the file call's
        answer names, with the errno and ``path`` as given and no text from the sandbox:
        FileNotFoundError or NotADirectoryError for a folder on the way that is not one,
        IsADirectoryError for a folder at ``path``, PermissionError, OSError with ``ENOSPC``
        or ``EROFS``."""
        if not isinstance(content, (str, bytes)):
            raise TypeError(f"content must be str or bytes, got {type(content).__name__}")
        data = content.encode("utf-8") if isinstance(content, str) else content
        rel = _posix(path)
        live, tag, slot = self._ready(ctx)
        await self._call(live, slot, "write_file", tag, self._write, live, rel, data)

    # ---- in the worker thread ----

    def _run_call(self, live: _Live, slot: Optional[_Slot], method: str, tag: _Tag, fn: Callable[..., Any], *args: Any,
                  cancel: Optional[CancelHandle] = None) -> Any:
        """One operation of the four methods, in its worker thread (from :meth:`_call`); after
        it, however it ended, the sandbox is let go if its session can take no more calls.
        Here, not in the event loop: a cancelled await returns before the client has cut the
        request and stopped the session."""
        try:
            return live.recorder.run(method, tag, fn, *args, cancel=cancel)
        finally:
            self._let_go_if_lost(live, slot)

    def _let_go_if_lost(self, live: _Live, slot: Optional[_Slot]) -> None:
        """Lets the sandbox of ``live`` go when its session can take no more calls (the
        client stopped it, or the daemon ended it): closes the session, which frees one of
        the daemon's places, and from then on every call of this environment (under the
        SESSION scope, of that ADK session) is refused with the loss named, never handed an
        empty sandbox the agent would take for its own. The call that found it raises its
        own error, or returns its answer."""
        lost = _lost_from(live.recorder.session)
        if lost is None:
            return
        # The close of a cut session usually raises ChainError (the daemon counts the call
        # this client never saw answered); _close_quietly drops it, so the call's own error
        # is the one raised.
        if slot is None:
            with self._open_lock:  # a close() or open() in flight finishes first
                with self._state_lock:
                    if self._live is not live:
                        return  # closed or replaced meanwhile: not this sandbox's to let go
                    session = self._session
                    # Under _open_lock, which _open() takes before it checks _lost again: an
                    # initialize() that looked before this line opens nothing.
                    self._lost = lost
                    self._session, self._live, self._root = None, None, None
                    # _is_initialized stays true, so ADK's close of the toolset reaches close().
                if session is not None:
                    _close_quietly(session)
            return
        with slot.lock:
            # end() may have taken the session meanwhile (and closed it): then there is none.
            session, slot.lost = slot.session, lost
            slot.session, slot.live = None, None
        if session is not None:
            _close_quietly(session)

    def _run_command(self, live: _Live, command: str, budget: float,
                     cancel: Optional[CancelHandle] = None) -> Tuple[ExecOutcome, Optional[PlimsollCall]]:
        out = live.workspace.run(["sh", "-c", command], env=self._env_vars, timeout=budget, cancel=cancel)
        return out, live.recorder.last()

    @staticmethod
    def _read_whole(live: _Live, rel: str, cancel: Optional[CancelHandle] = None) -> bytes:
        return live.workspace.read_whole(rel, cancel=cancel)

    @staticmethod
    def _next_piece(pieces: Iterator[bytes], cancel: Optional[CancelHandle] = None) -> Optional[bytes]:
        # ``cancel`` is the call's, which _call hands every operation; the read in flight is
        # cut by the handle read_file_stream gave read_pieces instead.
        return next(pieces, None)

    @staticmethod
    def _write(live: _Live, rel: str, data: bytes, cancel: Optional[CancelHandle] = None) -> None:
        live.workspace.write(rel, data, cancel=cancel)

    # ---- helpers ----

    def _ready(self, ctx: Any) -> Tuple[_Live, _Tag, Optional[_Slot]]:
        """The session ctx's calls use, the tool call they serve, and under the SESSION scope
        the slot that holds it (None otherwise)."""
        if self._scope is EnvironmentScope.SESSION:
            return self._ready_slot(ctx)
        invocation = _invocation(ctx)
        self._refuse_if_lost()
        live = self._live
        if live is None:
            self._hold(invocation, None)  # an invocation whose session was closed is told so
            raise RuntimeError("plimsoll: the environment has no session; call initialize() first (ADK's toolset does)")
        tag = self._tag(ctx)
        if tag.tool_call is not None:
            self._bind(tag.tool_call.owner)
        self._hold(invocation, live)
        return live, tag, None

    def _refuse_if_lost(self) -> None:
        lost = self._lost
        if lost is not None:
            raise _lost_error(lost, scoped=False)

    def _ready_slot(self, ctx: Any) -> Tuple[_Live, _Tag, Optional[_Slot]]:
        key, mark = self._key(ctx)
        invocation = _invocation(ctx)
        tag = self._tag(ctx)
        if tag.tool_call is not None and tag.tool_call.owner != key[:2]:
            # The guard's tool call and ctx's session are one ADK call's; they differ only
            # when something hands one tool call another's context.
            raise PlimsollError(
                "plimsoll: this tool call's ADK user is not the one whose session's sandbox it reached. Nothing was sent.",
                code="permission_denied",
                not_dispatched="permission",
            )
        slot = self._slot(key)
        if slot is not None and slot.lost is not None:
            raise _lost_error(slot.lost, scoped=True)
        live = slot.live if slot is not None else None
        self._hold(invocation, live)  # an invocation whose sandbox was closed is told so
        if live is None or slot is None:
            raise RuntimeError("plimsoll: this ADK session has no sandbox; call initialize() first (ADK's toolset does)")
        _check_mark(mark, live)
        self._seen(slot, ctx)
        return live, tag, slot

    async def _call(self, live: _Live, slot: Optional[_Slot], method: str, tag: _Tag, fn: Callable[..., Any],
                    *args: Any) -> Any:
        """Runs one operation of the four methods in a worker thread, through :meth:`_run_call`
        (in_thread: a cancelled await cuts it). Under the SESSION scope the slot counts it in
        flight from before it is sent until its worker thread ends, so a sandbox is never
        closed to make room under a call, and a call that loses its sandbox is still counted
        while the sandbox is let go. A sandbox gone since :meth:`_ready` looked is refused
        here, with nothing sent: a lost one with its loss named, one taken out for room
        ``not_found``."""
        if slot is None:
            return await in_thread(self._run_call, live, None, method, tag, fn, *args)
        ticket = _InFlight()
        with self._state_lock:
            if self._slots.get(slot.key) is not slot or slot.live is not live:
                # _let_go_if_lost sets lost before it clears live, so a sandbox lost by a
                # parallel call of this conversation is told as lost, not as not held.
                lost = slot.lost
                if lost is not None:
                    raise _lost_error(lost, scoped=True)
                raise SessionEndedError(_SESSION_GONE, reason="not_found", not_dispatched="request")
            slot.busy += 1

        def counted(*a: Any, cancel: Optional[CancelHandle] = None) -> Any:
            with self._state_lock:
                if ticket.abandoned:  # the await was cancelled before this thread started
                    raise RequestCanceledError("plimsoll: the call was cancelled before it was sent",
                                               not_dispatched="request")
                ticket.started = True
            try:
                return self._run_call(live, slot, method, tag, fn, *a, cancel=cancel)
            finally:
                with self._state_lock:
                    slot.busy -= 1

        try:
            return await in_thread(counted, *args)
        except asyncio.CancelledError:
            with self._state_lock:
                if not ticket.started:  # the thread may never run: count the call out here
                    ticket.abandoned = True
                    slot.busy -= 1
            raise

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

    def _hold(self, invocation: Tuple[Optional[str], Optional[str]], live: Optional[_Live]) -> None:
        # An ADK invocation is held to the first session it used: when that session has been
        # closed (live None) or replaced (another identity), its call is refused, since an
        # agent takes the sandbox it is given for the one with its files. The invocation that
        # ran it as an AgentTool is held to that session too: its model has the wrapped agent's
        # answer about those files. Invocation IDs are ADK's own, one per invocation
        # (new_invocation_context_id, a UUID), so concurrent invocations never share a key.
        own, parent = invocation
        if own is None:
            return  # a direct call, not from an ADK tool: the caller manages the lifecycle
        with self._state_lock:
            held = self._held.get(own)
            if held is not None and (live is None or live.identity != held):
                raise SessionEndedError(
                    "plimsoll: the sandbox this ADK invocation used has been closed, and its files with it; an empty "
                    "sandbox is not put in its place. An AgentTool's agent that shares this environment closes it when "
                    "it finishes: give the wrapped agent an environment of its own (docs/google-adk.md). Nothing was "
                    "sent.",
                    reason="closed",
                    not_dispatched="request",
                )
            if live is None:
                return
            if held is not None:
                self._held.move_to_end(own)  # the longest unused is forgotten first
            for key in (own, parent):
                if key is not None and key not in self._held:
                    self._held[key] = live.identity
            while len(self._held) > _MAX_REMEMBERED_INVOCATIONS:
                self._held.popitem(last=False)

    def _budget(self, timeout: Optional[float], live: _Live) -> float:
        if timeout is None:
            budget = live.ceiling if live.ceiling is not None else self._timeout
        elif isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError(f"timeout must be a number of seconds or None, not {timeout!r}")
        else:
            budget = float(timeout)
        return budget  # the workspace caps it at the daemon's ceiling (its max_timeout)



def _invocation(ctx: Any) -> Tuple[Optional[str], Optional[str]]:
    """The ADK invocation a tool's ctx belongs to, and the invocation an AgentTool ran it
    inside (None for a top-level one, and for a ctx that is not ADK's)."""
    if ctx is None:
        return None, None
    own = getattr(ctx, "invocation_id", None)
    parent = getattr(getattr(ctx, "_invocation_context", None), "_parent_invocation_id", None)
    return (own if isinstance(own, str) and own else None,
            parent if isinstance(parent, str) and parent else None)


def _close_session(session: Session, cancel: Optional[CancelHandle] = None) -> SessionSummary:
    return session.close()


class _InFlight:
    """One call's place in its slot's count (PlimsollEnvironment._call), under _state_lock."""

    __slots__ = ("started", "abandoned")

    def __init__(self) -> None:
        self.started = False
        self.abandoned = False


def _end_all(slots: "OrderedDict[Tuple[str, str, str], _Slot]",
             lock: threading.Lock) -> Tuple[Optional[SessionSummary], Optional[Exception]]:
    """Closes every sandbox in ``slots`` (end(), and the finalizer): the last summary, and
    the first error once every sandbox has been tried."""
    with lock:
        held = list(slots.values())
        slots.clear()
    summary: Optional[SessionSummary] = None
    first: Optional[Exception] = None
    for slot in held:
        with slot.lock:  # an open in flight finishes first, and what it opened is closed here
            session, slot.session, slot.live = slot.session, None, None
        if session is None:
            continue
        try:
            summary = _close_session(session)
        except Exception as e:  # every sandbox is tried before an error is raised
            first = first or e
    return summary, first


def _end_quietly(slots: "OrderedDict[Tuple[str, str, str], _Slot]", lock: threading.Lock) -> None:
    """The finalizer: end() at collection or interpreter exit, where nothing can be raised to."""
    _, error = _end_all(slots, lock)
    if error is not None:
        log.warning("plimsoll: a sandbox the ADK environment held did not close at exit (%s)", type(error).__name__)


def _adk_session(ctx: Any) -> Tuple[Tuple[str, str, str], Optional[Tuple[str, str]]]:
    """Under the SESSION scope: the key of the sandbox ``ctx``'s calls use, (app name, user
    ID, ADK session ID), and the mark its session's state carries, (ADK session ID, plimsoll
    session fingerprint), or None. The app and user are always ``ctx.session``'s, which the
    application's session service set, so a mark (state a client of ADK's API server can
    write, RunAgentRequest.state_delta) can only point at a sandbox of the same user: that is
    how an AgentTool's agent, in a nested ADK session of its own, finds its caller's."""
    session = getattr(ctx, "session", None) if ctx is not None else None
    if session is None:
        # As ADK's toolsets refuse a scoped environment without one (_utils.py _require_session).
        raise ValueError("plimsoll: this environment has the session scope, so every call needs ADK's ctx with a session")
    app, user, sid = (getattr(session, name, None) for name in ("app_name", "user_id", "id"))
    if not all(isinstance(x, str) for x in (app, user, sid)) or not sid:
        raise ValueError("plimsoll: ctx.session must name its app_name, user_id and id as text")
    mark = None
    state = getattr(ctx, "state", None)
    raw = state.get(_SANDBOX_STATE_KEY) if state is not None and hasattr(state, "get") else None
    if isinstance(raw, Mapping):
        named, fingerprint = raw.get("session"), raw.get("fingerprint")
        if isinstance(named, str) and named:
            if not isinstance(fingerprint, str) or not fingerprint:
                # Every mark this environment writes carries its session's fingerprint, and
                # the fingerprint is what ties a mark to one sandbox: without it, a mark would
                # reach any conversation's sandbox of the same app and user it names.
                raise PlimsollError(
                    "plimsoll: this ADK session's state names a sandbox (plimsoll:sandbox) without its plimsoll "
                    "session fingerprint, so it cannot be told which sandbox it means; it is refused. Start a new ADK "
                    "session. Nothing was sent.",
                    code="permission_denied",
                    not_dispatched="permission",
                )
            mark = (named, fingerprint)
            sid = named
    return (app, user, sid), mark


def _check_mark(mark: Optional[Tuple[str, str]], live: _Live) -> None:
    """Refuses a sandbox whose plimsoll session is not the one the conversation's state
    names: the one with its files is gone. A mark's fingerprint is never empty
    (:func:`_adk_session` refuses one that is), and a sandbox without one matches no mark."""
    if mark is not None and mark[1] != live.fingerprint:
        raise SessionEndedError(
            "plimsoll: this ADK session's state names another plimsoll sandbox than the one its key now holds, so the one "
            "with its files is gone; an empty sandbox is not put in its place. Start a new ADK session. Nothing was sent.",
            reason="replaced",
            not_dispatched="request",
        )


def _write_mark(ctx: Any, key: Tuple[str, str, str], live: _Live) -> None:
    """Names the sandbox in the conversation's state, where ADK keeps it with the session
    (and, through an AgentTool, hands it to the wrapped agent and back). Written only when it
    changes, so a tool call adds no state change of its own after the first."""
    state = getattr(ctx, "state", None)
    if not live.fingerprint:
        return  # a mark without one would be refused (_adk_session); the client's sessions all have one
    mark = {"session": key[2], "fingerprint": live.fingerprint}
    try:
        if state is not None and state.get(_SANDBOX_STATE_KEY) != mark:
            state[_SANDBOX_STATE_KEY] = mark
    except (TypeError, AttributeError):
        pass  # a read-only context: the sandbox is still the ADK session's, by its key


def _store_key(key: Tuple[str, str, str]) -> str:
    """The checkpoint store key of an ADK session's sandbox: derived from the identities the
    application's session service set, never from model or user text
    (plimsoll_client.checkpoint), and of a fixed length whatever they hold."""
    return "adk-session-" + hashlib.sha256(json.dumps(list(key)).encode("utf-8")).hexdigest()


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

    And for every ADK invocation (one turn of a conversation, or one run of an AgentTool's
    agent) it **notes when it begins and ends**, from the Runner's own lifecycle: under
    ``scope="session"`` a sandbox is closed to make room at the daemon's capacity, or let go
    past 256, only when every conversation that used it is between turns by this note, so
    a turn waiting on its model keeps its sandbox. A conversation one of whose turns ran
    through a Runner without the guard is never closed that way.

    It reads ADK's public hooks only: ``on_user_message_callback``, ``before_run_callback``,
    ``after_run_callback``, ``on_run_error_callback``, ``before_tool_callback``,
    ``after_tool_callback``, ``on_tool_error_callback`` (``plugins/base_plugin.py``), the
    invocation context's ``invocation_id``, ``session`` and ``_parent_invocation_id`` (the
    one private name, which ADK's AgentTool sets for this purpose, ``tools/agent_tool.py``),
    the tool context's ``function_call_id``, ``user_id`` and ``session.app_name``, and
    OpenTelemetry's current span, which is ADK's ``execute_tool`` span while these callbacks
    run (``telemetry/_instrumentation.py:996``).
    """

    def __init__(self) -> None:
        super().__init__(name="plimsoll_environment_guard")

    async def on_user_message_callback(self, *, invocation_context: Any, user_message: Any) -> None:
        # Called before the Runner stores the user's message, so a turn is in progress from
        # before anything of it is in the session (workflow/_node_runner_utils.py).
        _TURNS.begin(invocation_context)
        return None

    async def before_run_callback(self, *, invocation_context: Any) -> None:
        _TURNS.begin(invocation_context)  # the first call when the run resumes with no message
        return None

    async def after_run_callback(self, *, invocation_context: Any) -> None:
        _TURNS.end(invocation_context)
        return None

    async def on_run_error_callback(self, *, invocation_context: Any, error: Exception) -> None:
        _TURNS.end(invocation_context)  # the run ends with this error: ADK raises it on
        return None

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
