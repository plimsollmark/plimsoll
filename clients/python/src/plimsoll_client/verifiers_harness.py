"""verifiers v1, harness ``plimsoll-bash``: verifiers' own bash harness, its loop on the evaluator.

Every harness verifiers ships starts its agent program inside the runtime: it installs the
program with uv from the network (``Runtime.prepare_uv_script``) and the program calls the
model over HTTP from inside the sandbox. A plimsoll sandbox has no network, so none of them
can run on the plimsoll runtime (:mod:`plimsoll_client.verifiers_runtime`). verifiers'
harness contract allows the other placement in so many words (``Harness.launch``: "a harness
may run its loop in-process instead of launching a program, as long as every model call
goes through ``endpoint`` + ``secret``"), and this harness is that placement for the shipped
``bash`` harness:

- **The loop is verifiers' own.** The chat program the ``bash`` harness would install
  (``verifiers.v1.harnesses.utils.launch.CHAT_PROGRAM_SOURCE``) is loaded as a module on the
  evaluator, unedited, and its ``run_chat_loop`` drives the rollout: the same system prompt,
  tool definitions, streaming, compaction, tool-result bounding and error strings as the
  shipped harness, following whatever verifiers version is installed.
- **Every model call goes through verifiers' interception server** at the rollout's
  ``endpoint`` with its ``secret``, so the trace records each turn as it would for the
  shipped harness.
- **Every tool call is one call of the runtime.** ``bash`` runs ``bash -c COMMAND`` with
  ``runtime.run`` in the runtime's work directory; ``edit`` runs the shipped ``run_edit``
  function, by its own source, in the runtime with ``python3``. On the plimsoll runtime each
  is one session call with a run record the client recomputes. The loop reaches them
  through its own tool-dispatch table (the one it uses for MCP tools), so nothing in the
  loop changes.

Select it with ``--env.agent.harness.id plimsoll-bash`` (the id resolves to the top-level
module :mod:`plimsoll_bash`, which re-exports :class:`PlimsollBashHarness`). It is meant for
runtimes whose sandbox cannot reach the evaluator, and needs ``bash`` in the runtime's image
and, with ``edit`` on, ``python3``. A runtime that hands its programs a rewritten model
endpoint (verifiers' docker runtime) is refused: the evaluator cannot use that address, and
the shipped harness runs there anyway.

Where it differs from the shipped ``bash`` harness:

- The ``search`` tool (a paid web search the program calls) is refused, and so are task
  tool servers (``SUPPORTS_MCP`` is off): neither has been run through this loop.
- A ``bash`` call's time limit is the runtime's per-call budget (``command_timeout`` on
  the plimsoll runtime, capped by the daemon) instead of the shipped program's 3600 s.
- A tool call the runtime cannot make (the sandbox is gone, the session's use ended) fails
  the rollout as verifiers' ``SandboxError`` instead of reaching the model as text, since
  the call may have run.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import inspect
import json
import traceback
import types
from typing import Any, Dict, List, Optional

try:
    from verifiers.v1.harnesses.bash.harness import BASH_SYSTEM_PROMPT, EDIT_SYSTEM_PROMPT, BashHarness
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "plimsoll_client.verifiers_harness needs verifiers v1 (0.4.1.dev97 or later): pip install 'plimsoll-client[verifiers]'"
    ) from e
import certifi
import httpx
from openai import AsyncOpenAI, DefaultAsyncHttpxClient
from verifiers.v1.clients import ModelContext
from verifiers.v1.dialects.chat import message_to_wire
from verifiers.v1.errors import MODEL_TRANSPORT_ERROR_EXIT_CODE, HarnessError, RolloutError
from verifiers.v1.harnesses.utils import core
from verifiers.v1.harnesses.utils.launch import CHAT_PROGRAM_SOURCE, PEP_723_END
from verifiers.v1.runtimes import ProgramResult, Runtime
from verifiers.v1.task import TaskData
from verifiers.v1.trace import Trace

__all__ = ["HARNESS_ID", "PlimsollBashHarness", "chat_program"]

HARNESS_ID = "plimsoll-bash"

# The dispatch table's server name for the runtime's tools; never a task tool server's
# name, since this harness takes none.
_SERVER = "runtime"

# The shipped edit tool, run in the runtime by its own source: the tool's arguments go
# in as one JSON argument, read the way the chat loop reads them (``tool_args.get``).
_EDIT_SCRIPT = (
    "import json, sys\n"
    "from pathlib import Path\n"
    + inspect.getsource(core.run_edit)
    + "\n_args = json.loads(sys.argv[1])\n"
    "sys.stdout.write(run_edit(_args.get('path'), _args.get('old_str'), _args.get('new_str')))\n"
)

# A loopback URL a runtime would hand on unchanged if its programs could use the
# evaluator's own address (plimsoll, subprocess); a runtime that rewrites it does not.
_LOOPBACK_PROBE = "http://127.0.0.1:9/v1"

# One call at setup: the tools' programs, named in the failure.
_PROBE = 'missing=""; for p in "$@"; do command -v "$p" >/dev/null 2>&1 || missing="$missing $p"; done; printf %s "$missing"'


@functools.lru_cache(maxsize=4)
def _load_chat_program(digest: str, source: str) -> types.ModuleType:
    module = types.ModuleType(f"plimsoll_client._verifiers_chat_program_{digest[:12]}")
    module.__file__ = "<verifiers chat program>"
    # Not __main__: the program's entry point stays inert, as on any package import.
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def chat_program() -> types.ModuleType:
    """The chat program the installed verifiers' ``bash`` harness would install in the
    runtime, as a module: its PEP 723 header dropped, nothing else touched."""
    body = CHAT_PROGRAM_SOURCE.split(PEP_723_END, 1)[1]
    return _load_chat_program(hashlib.sha256(body.encode("utf-8")).hexdigest(), body)


class _Text:
    """One text block, the shape the loop's tool dispatch turns into tool-result text."""

    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _ToolResult:
    def __init__(self, text: str) -> None:
        self.content = [_Text(text)]


class _RuntimeTools:
    """The loop's dispatch entry for ``bash`` and ``edit``: the connection object
    ``call_mcp`` expects (``run`` a call against a client with ``call_tool``), each call
    one ``runtime.run``. Never retried: a runtime call may have run."""

    def __init__(self, runtime: Runtime, env: Dict[str, str]) -> None:
        self.runtime = runtime
        self.env = env
        self.calls = 0

    async def run(self, call: Any) -> Any:
        return await call(self)

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> _ToolResult:
        self.calls += 1
        if name == "bash":
            command = arguments.get("command", "")
            if not isinstance(command, str):
                return _ToolResult(f"error: 'command' must be a string, got {type(command).__name__}")
            result = await self.runtime.run(["bash", "-c", command], dict(self.env))
            return _ToolResult(result.stdout + result.stderr)
        if name == "edit":
            result = await self.runtime.run(["python3", "-c", _EDIT_SCRIPT, json.dumps(arguments)], dict(self.env))
            if result.exit_code != 0:
                return _ToolResult(f"error: the edit tool failed in the runtime (exit {result.exit_code}): {result.stderr.strip()[-2000:]}")
            return _ToolResult(result.stdout)
        raise HarnessError(f"harness {HARNESS_ID!r} dispatched an unknown tool {name!r}")


class PlimsollBashHarness(BashHarness):
    """The shipped ``bash`` harness with its chat loop on the evaluator (module docstring)."""

    SUPPORTS_MCP = False

    async def setup(self, runtime: Runtime) -> None:
        if self.config.search:
            raise HarnessError(f"harness {HARNESS_ID!r} does not offer the search tool; set --env.agent.harness.search false")
        programs = ["bash"] + (["python3"] if self.config.edit else [])
        # With the tools' own environment, so the probe finds what they will.
        probe = await runtime.run(["sh", "-c", _PROBE, "probe", *programs], {**self.config.resolved_env})
        missing = probe.stdout.split()
        if probe.exit_code != 0 or missing:
            hint = " (or set --env.agent.harness.edit false)" if "python3" in missing else ""
            raise HarnessError(
                f"harness {HARNESS_ID!r} runs its tools with {' and '.join(programs)} in the runtime, "
                f"and the runtime's image lacks {' and '.join(missing) or 'them (the probe failed: ' + probe.stderr.strip()[-200:] + ')'}{hint}"
            )

    def _system_prompt(self, data: TaskData) -> tuple[Optional[str], Any]:
        """The system prompt and prompt exactly as ``BashHarness.launch`` builds them."""
        system_prompt, prompt = self.resolve_prompt(data)
        fragments = [BASH_SYSTEM_PROMPT]
        if self.config.edit:
            fragments.append(EDIT_SYSTEM_PROMPT)
        harness_prompt = " ".join(fragments)
        system_prompt = "\n\n".join(p for p in (harness_prompt, system_prompt) if p)
        if (
            data.system_prompt is None
            and prompt is not None
            and not isinstance(prompt, str)
            and any(message.role == "system" and message.content == harness_prompt for message in prompt)
        ):
            system_prompt = None
        return system_prompt, prompt

    async def launch(
        self,
        ctx: ModelContext,
        trace: Trace,
        runtime: Runtime,
        endpoint: str,
        secret: str,
        mcp_urls: Dict[str, str],
        data: TaskData,
        tool_interception_url: Optional[str] = None,
    ) -> ProgramResult:
        if mcp_urls:
            raise HarnessError(f"harness {HARNESS_ID!r} takes no task tool servers, and the task has {sorted(mcp_urls)}")
        if self.config.search:
            raise HarnessError(f"harness {HARNESS_ID!r} does not offer the search tool")
        if runtime.host_url(_LOOPBACK_PROBE) != _LOOPBACK_PROBE:
            # The endpoint was rewritten for programs inside the runtime (verifiers' docker
            # runtime routes them through a proxy only its containers reach): this loop runs
            # on the evaluator and cannot use it, and the shipped harness can run there.
            raise HarnessError(
                f"harness {HARNESS_ID!r} runs its loop on the evaluator, and this runtime gives its programs a "
                f"rewritten model endpoint the evaluator cannot use; its sandbox can reach the evaluator, so use "
                f"verifiers' own bash harness on it"
            )
        program = chat_program()
        system_prompt, prompt = self._system_prompt(data)
        messages: List[Dict[str, Any]] = [{"role": "system", "content": system_prompt}] if system_prompt else []
        if isinstance(prompt, str):
            if prompt:
                messages.append({"role": "user", "content": prompt})
        elif prompt is not None:
            messages.extend(message_to_wire(message) for message in prompt)

        tools = [program.BASH_TOOL] + ([program.EDIT_TOOL] if self.config.edit else [])
        dispatch = {tool["function"]["name"]: (_SERVER, tool["function"]["name"]) for tool in tools}
        runtime_tools = _RuntimeTools(runtime, {**self.config.resolved_env})
        # What the program's argument parser would hold: the built-in tools stay off, so
        # every tool call goes through the dispatch table to the runtime.
        args = argparse.Namespace(
            api_key=secret,
            tool_interception_url=tool_interception_url or "",
            bash=False,
            edit=False,
            search=False,
            serper_key="",
            search_block=[],
        )
        compaction = self.config.compaction
        client = AsyncOpenAI(
            base_url=endpoint,
            api_key=secret,
            timeout=httpx.Timeout(600.0, connect=5.0),
            http_client=DefaultAsyncHttpxClient(verify=certifi.where()),
        )
        tool_client = httpx.AsyncClient(timeout=httpx.Timeout(None, connect=5.0)) if tool_interception_url else None
        try:
            compactor = program.Compactor(
                client,
                ctx.model,
                tools,
                compaction is not None,
                compaction.summarize_at_tokens if compaction is not None else None,
            )
            if compactor.enabled and compactor.threshold is None:
                compactor.threshold = await program.discover_threshold(client, ctx.model)
            compactor.note_good(messages)
            await program.run_chat_loop(args, compactor, messages, dispatch, {_SERVER: runtime_tools}, tool_client)
        except RolloutError:
            raise
        except SystemExit as e:
            # The loop's model-transport failure: it printed the cause and exits 97,
            # which the harness maps to verifiers' InterceptionError.
            code = e.code if isinstance(e.code, int) else MODEL_TRANSPORT_ERROR_EXIT_CODE
            return ProgramResult(code, "", traceback.format_exc()[-4000:])
        except Exception:
            # The program would exit 1 with a traceback; the harness then decides (a
            # rollout a @stop ended is not an error).
            return ProgramResult(1, "", traceback.format_exc()[-4000:])
        finally:
            await client.close()
            if tool_client is not None:
                await tool_client.aclose()
        return ProgramResult(0, "", "")
