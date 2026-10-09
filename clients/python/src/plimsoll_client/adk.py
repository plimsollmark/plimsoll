"""Optional Google ADK code executor, fresh Python projects over the checked client."""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextvars
import mimetypes
from dataclasses import dataclass, field
from typing import Any, Literal, Optional, Tuple

try:
    import google.adk  # noqa: F401  (the extra this module needs; named if it is missing)
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.adk needs Google ADK: pip install 'plimsoll-client[adk]'") from e
from google.adk.code_executors.base_code_executor import BaseCodeExecutor
from google.adk.code_executors.code_execution_utils import CodeExecutionInput, CodeExecutionResult, File
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.agent_tool import AgentTool
from pydantic import ConfigDict, Field

from . import _validate as v
from ._transport import CancelHandle
from .client import Client
from .execution import CodeExecutor
from .errors import PlimsollError, UnsupportedError
from .types import ProjectResult, SoftwareRule

__all__ = ["PlimsollCodeExecutor", "PlimsollCodeExecutionResult", "PlimsollCodeExecutionError", "PlimsollCodeExecutorGuard",
           "CODE_EXECUTION_INSTRUCTION"]

# What the guard tells a model whose agent executes through plimsoll. ADK 2.11 adds its own
# version (_NON_BUILTIN_EXECUTOR_INSTRUCTION) only under optimize_data_file, which this
# executor refuses (_code_execution.py:237), so without this a model would get no word on
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


# The asyncio task an agent's model call ran in, which the guard records. ADK 2.11 runs the
# executor through asyncio.to_thread (_code_execution.py:302, :431), which copies the
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
    daemon's five-minute ceiling. ADK 2.11 checks its retry count before the first
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
        # ADK 2.11 calls this through asyncio.to_thread with no handler
        # (flows/llm_flows/extensions/_code_execution.py:302 and :431), so an exception
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
            # own UnsafeLocalCodeExecutor (unsafe_local_code_executor.py:187); the text
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
    (_code_execution.py:554 in ADK 2.11), so a Runner without one is refused first.
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
        # ADK 2.11's CallbackContext has no public accessor for the agent itself; its
        # own properties read _invocation_context. A rename fails this hook loudly (ADK
        # wraps the AttributeError in RuntimeError), never silently drops the instruction.
        executor = getattr(callback_context._invocation_context.agent, "code_executor", None)
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
        _refuse_without_artifacts(callback_context._invocation_context, agent)

    @staticmethod
    def _check(agent: Any, run_config: Any) -> None:
        if (run_config is not None and run_config.support_cfc
                and agent.parent_agent is None
                and isinstance(getattr(agent, "code_executor", None), PlimsollCodeExecutor)):
            raise UnsupportedError(
                "PlimsollCodeExecutor refuses support_cfc=True: ADK replaces the root "
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

