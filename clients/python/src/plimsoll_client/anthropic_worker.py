"""Claude Managed Agents, self-hosted worker: the agent's six tools served from a plimsoll session.

A Managed Agents session on a ``self_hosted`` environment sends its tool calls (``bash``,
``read``, ``write``, ``edit``, ``glob``, ``grep``) to a worker on your infrastructure, which
runs them and posts the results back (the SDK's ``EnvironmentWorker``). This module gives
that worker implementations of the six tools that run in a plimsoll session instead of on
the worker host: the worker keeps the environment key and the sandbox holds no credential
and has no network; every call carries a run record; the session is opened at the
isolation floor you choose. Read from the ``anthropic`` package 1.13.0 on 2026-10-13: the
worker dispatches a tool call by name (``tool_registry`` in ``_tool_dispatch.py``), so
these implementations stand in for the built-ins under the same names and input schemas
(``beta_agent_toolset_20260401``), and the built-in ``bash`` is an async context manager
the runner enters on the first call and exits on cleanup, which this one is too: that exit
closes the plimsoll session.

    from anthropic import AsyncAnthropic
    from anthropic.lib.environments import EnvironmentWorker
    from plimsoll_client import Client
    from plimsoll_client.anthropic_worker import PlimsollTools

    tools = PlimsollTools(Client("https://plimsoll.internal", token=...), minimum_isolation="kernel")
    worker = EnvironmentWorker(client, environment_id=..., environment_key=..., workdir="/workspace", tools=tools.tools)

One plimsoll session per Managed Agents session, opened on the first tool call (or by
:meth:`PlimsollTools.open`), closed when the runner exits the ``bash`` tool or by
:meth:`PlimsollTools.close`; the session's owner, for a daemon's per-owner cap, is the
Managed Agents session ID. With ``stage_skills`` (the default) the skills the worker
downloaded under ``<workdir>/skills/`` are written into the sandbox at open, executable bits
kept, so the agent finds them at ``skills/<name>/`` in its work directory as it would on the
host.

Not supported here, by design, and said so the model sees it: memory stores (``/mnt/memory``
is a copy on the worker host synced through the session's secret; the sandbox never sees
it); images and PDFs from ``read`` (text only); a background job surviving a call (the
session's sweep ends a call's processes); a ``bash`` whose state is a process (``cd`` and
``export`` persist through files in the work directory, see :mod:`plimsoll_client.workspace`).
"""

from __future__ import annotations

import asyncio
import posixpath
import shlex
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Sequence

try:
    import anthropic  # noqa: F401  (the extra this module needs; named if it is missing)
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.anthropic_worker needs the Anthropic SDK: pip install 'plimsoll-client[anthropic]'") from e
from anthropic.lib.tools import BetaAsyncFunctionTool, ToolError, beta_async_tool
from anthropic.types.beta import (
    BetaManagedAgentsAgentToolset20260401BashInput,
    BetaManagedAgentsAgentToolset20260401EditInput,
    BetaManagedAgentsAgentToolset20260401GlobInput,
    BetaManagedAgentsAgentToolset20260401GrepInput,
    BetaManagedAgentsAgentToolset20260401ReadInput,
    BetaManagedAgentsAgentToolset20260401WriteInput,
)

from .client import Client
from .errors import PlimsollError, SessionEndedError
from .workspace import MAX_READ_BYTES, ExecOutcome, Workspace, WorkspacePathError, WorkspaceTooLargeError

__all__ = ["PlimsollTools", "TOOL_NAMES", "BASH_DEFAULT_TIMEOUT", "BASH_OUTPUT_LIMIT", "MAX_FILE_BYTES", "session_key"]

#: The six tools, in the order the SDK's own toolset lists them.
TOOL_NAMES = ("bash", "read", "write", "edit", "glob", "grep")
#: The SDK's defaults, kept so a model sees the same limits it would on the host.
BASH_DEFAULT_TIMEOUT = 120.0  # seconds a command may run when the call names no timeout_ms
BASH_OUTPUT_LIMIT = 100 * 1024  # a command's output is kept to its last 100 KiB
MAX_FILE_BYTES = 256 * 1024  # a whole-file read, and an edit, past this needs view_range

WorkspaceFactory = Callable[[str], Workspace]


def session_key(ctx: Any) -> str:
    """The Managed Agents session a tool context serves: ``ctx.session.id`` when the
    worker fetched the session, else ``ctx.session_id``, else the context's identity."""
    session = getattr(ctx, "session", None)
    session_id = getattr(session, "id", None) if session is not None else None
    if session_id:
        return str(session_id)
    session_id = getattr(ctx, "session_id", None)
    if session_id:
        return str(session_id)
    return "context-%x" % id(ctx)


class PlimsollTools:
    """The six agent tools over plimsoll sessions, one per Managed Agents session.

    ``client`` is the plimsoll client every session is opened with; ``minimum_isolation``
    the floor each session is opened at (``kernel`` by default: refuse a docker daemon
    without gVisor); ``languages``, ``lifetime`` and ``idle_timeout`` go to
    ``Client.open_session``; ``timeout`` is the budget of a command whose call names no
    ``timeout_ms``; ``max_file_bytes`` the cap on a whole-file ``read`` and on ``edit``.
    ``workspace_factory`` replaces how a session's :class:`Workspace` is made, for tests.
    """

    def __init__(
        self,
        client: Optional[Client],
        *,
        minimum_isolation: str = "kernel",
        languages: Sequence[str] = ("python",),
        lifetime: Optional[float] = None,
        idle_timeout: Optional[float] = None,
        timeout: float = BASH_DEFAULT_TIMEOUT,
        max_file_bytes: int = MAX_FILE_BYTES,
        stage_skills: bool = True,
        workspace_factory: Optional[WorkspaceFactory] = None,
    ) -> None:
        if client is None and workspace_factory is None:
            raise ValueError("a plimsoll Client is required (a workspace_factory stands in for it in tests)")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int) or not 0 < max_file_bytes <= MAX_READ_BYTES:
            raise ValueError(f"max_file_bytes must be between 1 and {MAX_READ_BYTES}")
        self._client = client
        self._floor = minimum_isolation
        self._languages = tuple(languages)
        self._lifetime = lifetime
        self._idle_timeout = idle_timeout
        self._timeout = float(timeout)
        self._max_file_bytes = max_file_bytes
        self._stage_skills = stage_skills
        self._factory = workspace_factory
        self._open: Dict[str, Workspace] = {}
        self._lock = threading.Lock()

    # ---- lifecycle ----

    def open(self, ctx: Any) -> Workspace:
        """The workspace of the context's Managed Agents session, opened now if it is not
        yet: a worker may call this before the first tool call to have the sandbox ready."""
        key = session_key(ctx)
        with self._lock:
            ws = self._open.get(key)
            if ws is not None:
                return ws
            ws = self._make(key)
            self._open[key] = ws
        try:
            if self._stage_skills:
                self._stage(ws, getattr(ctx, "workdir", None))
        except BaseException:
            self.close(key)
            raise
        return ws

    def close(self, key_or_ctx: Any) -> None:
        """Closes the session's workspace, if open; a later tool call opens a new one."""
        key = key_or_ctx if isinstance(key_or_ctx, str) else session_key(key_or_ctx)
        with self._lock:
            ws = self._open.pop(key, None)
        if ws is not None:
            try:
                ws.close()
            except PlimsollError:
                pass  # ended already: the daemon has it either way

    def close_all(self) -> None:
        with self._lock:
            keys = list(self._open)
        for key in keys:
            self.close(key)

    @property
    def open_sessions(self) -> List[str]:
        with self._lock:
            return list(self._open)

    def _make(self, key: str) -> Workspace:
        if self._factory is not None:
            return self._factory(key)
        assert self._client is not None
        session = self._client.open_session(
            minimum_isolation=self._floor,
            languages=list(self._languages),
            lifetime=self._lifetime,
            idle_timeout=self._idle_timeout,
            owner=key,
        )
        return Workspace(session, timeout=self._timeout)

    def _stage(self, ws: Workspace, workdir: Any) -> None:
        """Writes the worker's downloaded skills tree into the sandbox, executable bits
        kept. Symbolic links are skipped: a link in a skill bundle could point anywhere on
        the worker host."""
        if not workdir:
            return
        root = Path(workdir) / "skills"
        if not root.is_dir():
            return
        executables: List[str] = []
        for p in sorted(root.rglob("*")):
            if p.is_symlink() or not p.is_file():
                continue
            rel = "skills/" + p.relative_to(root).as_posix()
            data = p.read_bytes()
            written = False
            if b"\x00" not in data:
                try:
                    ws.write(rel, data.decode("utf-8"))
                    written = True
                except (UnicodeDecodeError, WorkspaceTooLargeError):
                    written = False
            if not written:
                ws.write(rel, data)
            if p.stat().st_mode & 0o111:
                executables.append(rel)
        if executables:
            # Paths of the bundle Anthropic served, not text a model wrote.
            ws.exec("chmod +x " + " ".join(shlex.quote(e) for e in executables))

    async def _ws(self, key: str, ctx: Any) -> Workspace:
        with self._lock:
            ws = self._open.get(key)
        if ws is not None:
            return ws
        return await asyncio.to_thread(self.open, ctx)

    def _ended(self, key: str, e: SessionEndedError) -> ToolError:
        with self._lock:
            self._open.pop(key, None)
        return ToolError(f"the sandbox session ended ({e.reason or 'unknown'}); the next call opens a new one")

    # ---- the tools ----

    def tools(self, ctx: Any) -> List[BetaAsyncFunctionTool[Any]]:
        """The six tools for one Managed Agents session, for ``EnvironmentWorker(tools=...)``."""
        key = session_key(ctx)
        return [
            self._bash_tool(key, ctx),
            self._read_tool(key, ctx),
            self._write_tool(key, ctx),
            self._edit_tool(key, ctx),
            self._glob_tool(key, ctx),
            self._grep_tool(key, ctx),
        ]

    def _bash_tool(self, key: str, ctx: Any) -> BetaAsyncFunctionTool[Any]:
        tools = self

        @asynccontextmanager
        async def bash_tool() -> AsyncIterator[Callable[..., Awaitable[str]]]:
            """Run a command in the sandbox's shell."""

            async def bash(
                command: Optional[str] = None, restart: Optional[bool] = None, timeout_ms: Optional[int] = None
            ) -> str:
                if restart:
                    await asyncio.to_thread(tools.close, key)
                    await tools._ws(key, ctx)
                    return "bash session restarted"
                if not command:
                    raise ToolError("bash: command is required")
                timeout = timeout_ms / 1000.0 if timeout_ms else tools._timeout
                ws = await tools._ws(key, ctx)
                try:
                    out = await asyncio.to_thread(ws.exec, command, timeout=timeout)
                except SessionEndedError as e:
                    raise tools._ended(key, e) from e
                except (PlimsollError, ValueError, RuntimeError) as e:
                    raise ToolError(f"bash: {e}") from e
                text = _bash_text(out)
                if out.timed_out:
                    raise ToolError(f"bash: command timed out after {timeout:g}s" + ("\n" + text if text else ""))
                if out.exit_code != 0:
                    raise ToolError(text or f"bash: exit {out.exit_code}")
                return text

            try:
                yield bash
            finally:
                await asyncio.to_thread(tools.close, key)

        return beta_async_tool(name="bash", input_schema=BetaManagedAgentsAgentToolset20260401BashInput)(bash_tool)  # type: ignore[arg-type]

    def _read_tool(self, key: str, ctx: Any) -> BetaAsyncFunctionTool[Any]:
        tools = self

        @beta_async_tool(name="read", input_schema=BetaManagedAgentsAgentToolset20260401ReadInput)
        async def read(file_path: str, view_range: Optional[List[int]] = None) -> str:
            """Read a text file in the sandbox, rooted at the work directory."""
            if view_range is not None and len(view_range) != 2:
                raise ToolError("read: view_range must be [start_line, end_line]")
            ws = await tools._ws(key, ctx)
            cap = MAX_READ_BYTES if view_range else tools._max_file_bytes + 1
            try:
                raw = await asyncio.to_thread(ws.read, file_path, max_bytes=cap)
            except SessionEndedError as e:
                raise tools._ended(key, e) from e
            except (FileNotFoundError, WorkspacePathError, WorkspaceTooLargeError, PlimsollError, ValueError, RuntimeError) as e:
                raise ToolError(f"read: {e}") from e
            if not view_range and len(raw) > tools._max_file_bytes:
                raise ToolError(
                    f"read: {file_path} exceeds the {tools._max_file_bytes}-byte limit. "
                    "Use the view_range parameter to read specific line ranges, e.g. view_range: [1, 500]."
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as e:
                raise ToolError(f"read: {file_path}: not valid UTF-8 text (this worker reads text files only)") from e
            if not view_range:
                return text
            start_line, end_line = view_range
            lines = text.split("\n")
            start = max(0, start_line - 1)
            end = end_line if end_line > 0 else len(lines)
            return "\n".join(lines[start:end])

        return read

    def _write_tool(self, key: str, ctx: Any) -> BetaAsyncFunctionTool[Any]:
        tools = self

        @beta_async_tool(name="write", input_schema=BetaManagedAgentsAgentToolset20260401WriteInput)
        async def write(file_path: str, content: str) -> str:
            """Write a file in the sandbox, creating parent directories as needed."""
            ws = await tools._ws(key, ctx)
            try:
                await asyncio.to_thread(ws.write, file_path, content)
            except SessionEndedError as e:
                raise tools._ended(key, e) from e
            except (WorkspacePathError, WorkspaceTooLargeError, OSError, PlimsollError, ValueError, RuntimeError) as e:
                raise ToolError(f"write: {e}") from e
            return f"wrote {len(content)} bytes to {file_path}"

        return write

    def _edit_tool(self, key: str, ctx: Any) -> BetaAsyncFunctionTool[Any]:
        tools = self

        @beta_async_tool(name="edit", input_schema=BetaManagedAgentsAgentToolset20260401EditInput)
        async def edit(file_path: str, old_string: str, new_string: str, replace_all: Optional[bool] = None) -> str:
            """Replace text in a sandbox file by exact string match."""
            ws = await tools._ws(key, ctx)
            try:
                count = await asyncio.to_thread(ws.edit, file_path, old_string, new_string, replace_all=bool(replace_all))
            except SessionEndedError as e:
                raise tools._ended(key, e) from e
            except (FileNotFoundError, WorkspacePathError, WorkspaceTooLargeError, PlimsollError, ValueError, RuntimeError) as e:
                raise ToolError(f"edit: {e}") from e
            return f"edited {file_path} ({count} replacement(s))"

        return edit

    def _glob_tool(self, key: str, ctx: Any) -> BetaAsyncFunctionTool[Any]:
        tools = self

        @beta_async_tool(name="glob", input_schema=BetaManagedAgentsAgentToolset20260401GlobInput)
        async def glob(pattern: str, path: Optional[str] = None) -> str:
            """List sandbox files matching a glob pattern, paths from the work directory."""
            ws = await tools._ws(key, ctx)

            def run() -> List[str]:
                matches = ws.glob(pattern, path)
                base = ws.resolve(path) if path else "."
                if base != ".":
                    matches = [posixpath.join(base, m) for m in matches]
                return matches

            try:
                matches = await asyncio.to_thread(run)
            except SessionEndedError as e:
                raise tools._ended(key, e) from e
            except (FileNotFoundError, WorkspacePathError, PlimsollError, ValueError, RuntimeError) as e:
                raise ToolError(f"glob: {e}") from e
            return "\n".join(matches) if matches else "no matches"

        return glob

    def _grep_tool(self, key: str, ctx: Any) -> BetaAsyncFunctionTool[Any]:
        tools = self

        @beta_async_tool(name="grep", input_schema=BetaManagedAgentsAgentToolset20260401GrepInput)
        async def grep(pattern: str, path: Optional[str] = None) -> str:
            """Search sandbox files for a regular expression; lines as file:line:text."""
            ws = await tools._ws(key, ctx)
            try:
                text = await asyncio.to_thread(ws.grep, pattern, path)
            except SessionEndedError as e:
                raise tools._ended(key, e) from e
            except (FileNotFoundError, WorkspacePathError, PlimsollError, ValueError, RuntimeError) as e:
                raise ToolError(f"grep: {e}") from e
            return text or "no matches"

        return grep


def _bash_text(out: ExecOutcome) -> str:
    """A command's output as the built-in bash tool gives it: both streams as one text
    (stdout first, then stderr, since the sandbox keeps them apart), the sandbox's cut
    stated, and at most the last BASH_OUTPUT_LIMIT characters."""
    text = out.stdout_text
    if out.stderr:
        if text and not text.endswith("\n"):
            text += "\n"
        text += out.stderr_text
    if out.stdout_truncated or out.stderr_truncated:
        text = "[output truncated by the sandbox]\n" + text
    if len(text) > BASH_OUTPUT_LIMIT:
        text = "[earlier output dropped]\n" + text[-BASH_OUTPUT_LIMIT:]
    return text
