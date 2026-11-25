"""Deep Agents sandbox backend: a plimsoll session as a Deep Agents agent's sandbox.

Deep Agents (LangChain's agent harness on LangGraph, ``deepagents`` 0.7.38, read on
2026-11-14) gives an agent an ``execute`` tool and file tools (``ls``, ``read_file``,
``write_file``, ``edit_file``, ``glob``, ``grep``) when its backend is a sandbox: a
``BaseSandbox`` that runs a shell command and moves files in and out. This module is that
backend over one plimsoll session, through :class:`plimsoll_client.workspace.Workspace`
(every command is a call of the session with a fixed step, the command as a file), so the
daemon's guarantees hold for the agent's whole run: the isolation floor the session was
opened at, a run record on every call, no network.

    from deepagents import create_deep_agent
    from plimsoll_client import Client
    from plimsoll_client.deepagents import PlimsollSandbox

    with PlimsollSandbox.open(Client("https://plimsoll.internal:8746", token=TOKEN)) as backend:
        agent = create_deep_agent(model=..., backend=backend, system_prompt=f"Work in {backend.root}.")
        agent.invoke({"messages": [{"role": "user", "content": "..."}]})

What the backend needs and does, stated here and in the docstrings:

- **Python 3 in the sandbox.** ``BaseSandbox`` runs each file tool as a ``python3 -c``
  script through ``execute``. :meth:`PlimsollSandbox.open` refuses a daemon whose session
  environment does not state Python, before any sandbox is made, and every backend asks
  the sandbox for ``python3`` once when it is made. On docker that is the
  ``plimsoll/sandbox-python`` image (``SANDBOX_DOCKER_PROJECT_IMAGE``).
- **A refusal raises.** A call plimsoll refused, or one that may have run without an
  answer to show for it, raises its :class:`~plimsoll_client.PlimsollError` (or the
  workspace's error); it never comes back as command output, since ``BaseSandbox`` reads
  ``execute``'s output as data and its ``ls`` would read an unparsable answer as an empty
  directory. Deep Agents and LangGraph do not catch it, so the agent's run stops where the
  developer sees it. A command's own non-zero exit is a normal result.
- **One sandbox, many commands.** The files, the shell's directory and its exported
  variables persist from one command to the next. A process left in the background is
  killed when its command's call ends (the session's sweep). When the session ends (the
  daemon's lifetime or idle limit, or :meth:`PlimsollSandbox.close`), every later call
  raises :class:`~plimsoll_client.SessionEndedError`; the backend never opens a fresh
  sandbox in its place, because an agent would take it for the one with its files.
- **Paths are absolute, anywhere in the sandbox,** as Deep Agents gives them: the sandbox
  is the boundary, as it is for ``execute``. The workspace's own state directory
  (``.plimsoll-shell`` in the work directory) is refused as a path. The work directory
  (``/work`` on docker) is :attr:`PlimsollSandbox.root`; Deep Agents does not tell the
  model where to work, so put it in the system prompt.
- **Every call has a budget.** ``execute`` without a timeout gets the backend's default;
  ``timeout=0`` (no limit, on backends that have such a thing) gets the daemon's longest.
  A command past its budget answers exit 124 with what it printed.

Needs ``deepagents`` (``pip install 'plimsoll-client[deepagents]'``).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import base64
import functools
import inspect
import threading

try:
    from deepagents.backends.protocol import (
        DeleteResult,
        EditResult,
        ExecuteOffloadResult,
        ExecuteResponse,
        FileDownloadResponse,
        FileUploadResponse,
        GlobResult,
        GrepResult,
        LsResult,
        ReadResult,
        WriteResult,
    )
    from deepagents.backends.sandbox import BaseSandbox
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.deepagents needs Deep Agents: pip install 'plimsoll-client[deepagents]'") from e
try:
    # deepagents' own python3 grep script and its parser (private names, read at 0.7.38),
    # for a sandbox whose grep is not GNU grep: see PlimsollSandbox.grep.
    from deepagents.backends.sandbox import _GREP_PATH_GLOB_TEMPLATE, _grep_excluded_dirs, _parse_grep_output
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "plimsoll_client.deepagents: this deepagents no longer has the python3 grep route the backend uses on a "
        "sandbox without GNU grep; it was checked on deepagents 0.7.38"
    ) from e

from . import _code_tool as ct
from . import _validate as v
from ._lost_call import lost_call_message
from ._transport import CancelHandle, in_thread
from .checkpoint import CheckpointStore
from .client import Client, Session
from .errors import InsufficientIsolationError, PlimsollError, UnsupportedError
from .types import meets
from .workspace import Workspace, WorkspaceChangedError, WorkspacePathError, WorkspaceTooLargeError
from .workspace import close_quietly as _close_quietly

__all__ = ["PlimsollSandbox"]

#: Seconds a command, or a file transfer, may run when the agent names no budget.
DEFAULT_TIMEOUT = 120.0

#: Characters of stdout and of stderr of a lost call's kept answer the model is told, each (the PydanticAI kit's
#: shell tool limit): about 7,500 tokens per stream.
MAX_OUTPUT_CHARS = 30_000

# The exit code the backend answers an ``execute`` it did not run because the session was recovering from a lost
# call: a failure, so no tool reads the explanation as the command's own output.
NOT_RUN_EXIT = 1

# The exit code of a command past its budget: plimsoll's own (a timed-out step), and the
# one langchain-daytona and coreutils' timeout(1) give.
TIMEOUT_EXIT = 124

# One call when the backend is made: python3 must answer (exit 127 otherwise), and the
# sandbox's grep is GNU grep or not. deepagents' grep sends `grep -rHnFZ --exclude-dir=...`
# with its errors discarded and `|| true`, so on BusyBox grep (plimsoll's Alpine images),
# which has neither option, every such search would answer "no matches".
_PROBE = (
    "command -v python3 >/dev/null 2>&1 || exit 127; "
    "if printf 'x\\n' | grep -HnFZ --exclude-dir=.git -e x >/dev/null 2>&1; then echo gnu-grep; else echo other-grep; fi"
)

# deepagents' error words for a file it could not move (deepagents.backends.protocol),
# keyed by the end of the message the sandbox's head(1) or the write step gave.
_FILE_ERRORS: Tuple[Tuple[str, str], ...] = (
    ("No such file or directory", "file_not_found"),
    ("Is a directory", "is_directory"),
    ("Not a directory", "file_not_found"),
    ("Permission denied", "permission_denied"),
    ("Read-only file system", "permission_denied"),
)


# Run as `sh -c SCRIPT sh PATH`: the path is an argument, never part of the script.
_WHY_UNREADABLE = (
    'if [ -d "$1" ]; then echo is_directory; elif [ ! -e "$1" ]; then echo file_not_found; '
    'elif [ ! -r "$1" ]; then echo permission_denied; fi'
)


def _file_error(message: str) -> str:
    text = message.strip()
    for tail, word in _FILE_ERRORS:
        if text.endswith(tail):
            return word
    return text


def _combine(stdout: str, stderr: str) -> str:
    """stdout, then each stderr line marked ``[stderr] ``, as deepagents' own local shell
    backend gives them (the two streams come back apart, so their interleaving is lost)."""
    parts = [stdout] if stdout else []
    if stderr.strip():
        if parts and not stdout.endswith("\n"):
            parts.append("\n")
        parts.append("\n".join(f"[stderr] {line}" for line in stderr.rstrip("\n").split("\n")))
    return "".join(parts)


class PlimsollSandbox(BaseSandbox):
    """A Deep Agents sandbox backend over one open plimsoll :class:`~plimsoll_client.Session`.

    ``minimum_isolation`` is the tier the session must state (``kernel`` by default: a
    docker daemon without gVisor is refused); a session below it is refused here and left
    open, since it is the caller's. ``timeout`` (seconds) is the budget of a command that
    names none and of each file transfer; ``max_timeout`` caps any budget asked for, and
    is the budget of ``timeout=0`` (:meth:`open` sets it from the daemon's ceiling).

    Making one asks the sandbox for ``python3`` (one call), which Deep Agents' file tools
    need, and refuses a sandbox without it; over a session recovering from a call whose
    answer was lost (an attach across an explained gap: ``session.lost_call``), it asks
    nothing, and searches go through Deep Agents' ``python3`` search.

    On such a session the agent's first tool call (``execute`` or a file tool, whichever
    comes first) is not run: the backend answers it with what plimsoll's record of the lost
    call says (the record says whether the daemon answered the call) and the lost call's
    output when its answer came back, each stream cut at ``max_output_chars``, as an
    ``execute`` output or the file tool's error, so the model reads it; then it resolves the
    session (``Session.resolve_lost_call``), and the next tool call runs. A lost command or
    file operation is so never sent again before the model has been told. Use :meth:`open`
    to open a session for it, or :meth:`attach` to carry on with one another process opened;
    :meth:`close` (or the context manager) closes the session.
    """

    def __init__(
        self,
        session: Session,
        *,
        minimum_isolation: str = "kernel",
        timeout: float = DEFAULT_TIMEOUT,
        max_timeout: Optional[float] = None,
        max_output_chars: int = MAX_OUTPUT_CHARS,
    ) -> None:
        if not v.floor(minimum_isolation):
            raise ValueError("plimsoll: a Deep Agents backend needs a floor: minimum_isolation process, container, kernel or vm")
        max_output_chars = ct.check_max_output(max_output_chars)
        if not meets(getattr(session, "isolation", "") or "", minimum_isolation):
            raise InsufficientIsolationError(
                f"plimsoll: the session states {getattr(session, 'isolation', '') or 'no tier'}, below the required "
                f"{minimum_isolation}; nothing ran (the session is left open)",
                not_dispatched="isolation",
            )
        self._session = session
        self._timeout = float(timeout)
        self._max_timeout = float(max_timeout) if max_timeout is not None else None
        self._workspace = Workspace(session, timeout=timeout, max_timeout=max_timeout, confined=False)
        self._max_output_chars = max_output_chars
        self._lost_lock = threading.Lock()
        if getattr(session, "lost_call", None) is not None:
            # The session is recovering from a call whose answer was lost (Session.lost_call):
            # it sends nothing until it is resolved, which the agent's first tool call does
            # after the model is told of the lost call (_recovering). The session passed the
            # probe when it was opened.
            self._gnu_grep = False
            return
        probe = self._workspace.exec(_PROBE)
        self._gnu_grep = probe.stdout_text.strip() == "gnu-grep"
        if probe.timed_out:
            raise PlimsollError(
                f"plimsoll: the sandbox did not answer the backend's first command within {self._timeout:g} s; nothing of "
                "the agent's ran (the session is left open)",
                code="deadline_exceeded",
            )
        if probe.exit_code != 0:
            # Not marked not dispatched: the probe is a call that ran in the sandbox (it is in
            # the session's chain), so a mark would tell a retry policy nothing ran.
            raise PlimsollError(
                "plimsoll: this sandbox has no python3, which Deep Agents' file tools run; use an image with Python "
                "(plimsoll/sandbox-python on docker); nothing of the agent's ran, only the backend's own check "
                "(the session is left open)",
                code="failed_precondition",
            )

    @classmethod
    def open(
        cls,
        client: Client,
        *,
        minimum_isolation: str = "kernel",
        timeout: float = DEFAULT_TIMEOUT,
        lifetime: Optional[float] = None,
        idle_timeout: Optional[float] = None,
        owner: Optional[str] = None,
        trace_id: Optional[str] = None,
        checkpoint_store: Optional[CheckpointStore] = None,
        checkpoint_key: Optional[str] = None,
    ) -> "PlimsollSandbox":
        """Opens a session on ``client``'s daemon at ``minimum_isolation`` and makes the
        backend over it. Refuses, before any sandbox is made, a daemon without sessions or
        whose session environment does not state Python. ``lifetime`` and
        ``idle_timeout`` (seconds) may only shorten the daemon's own; ``owner`` names the
        end user, for a daemon's per-owner cap (:meth:`Client.open_session`).
        ``checkpoint_store`` and ``checkpoint_key`` keep the session's checkpoint, so a
        thread resumed on another worker can :meth:`attach` (both or neither, and the
        client's ``daemon_name`` with them; :meth:`Client.open_session`). The session is
        closed again if the backend cannot be made."""
        info = client.describe()
        if not info.supports_sessions:
            raise UnsupportedError(
                f"plimsoll: the daemon ({info.provider}) offers no sessions, which a Deep Agents backend needs; nothing ran",
                not_dispatched="unsupported",
            )
        if "python" not in info.session_environment.languages:
            raise PlimsollError(
                "plimsoll: the daemon's session environment states no Python, which Deep Agents' file tools run; use an "
                "image with Python (plimsoll/sandbox-python on docker); nothing ran",
                code="failed_precondition",
                not_dispatched="environment",
            )
        ceiling = info.session_environment.max_timeout_ms / 1000 if info.session_environment.max_timeout_ms > 0 else None
        session = client.open_session(
            minimum_isolation=minimum_isolation,
            lifetime=lifetime,
            idle_timeout=idle_timeout,
            owner=owner,
            trace_id=trace_id,
            checkpoint_store=checkpoint_store,
            checkpoint_key=checkpoint_key,
        )
        try:
            return cls(session, minimum_isolation=minimum_isolation, timeout=timeout, max_timeout=ceiling)
        except BaseException:
            _close_quietly(session)
            raise

    @classmethod
    def attach(
        cls,
        client: Client,
        key: str,
        *,
        store: CheckpointStore,
        minimum_isolation: str = "kernel",
        timeout: float = DEFAULT_TIMEOUT,
        trace_id: Optional[str] = None,
    ) -> "PlimsollSandbox":
        """Carries on with the session whose checkpoint ``store`` holds under ``key``, which
        another process opened (:meth:`open` with the same store) or held: a LangGraph
        thread resumed on another worker gets the same sandbox, with its files
        (:meth:`Client.attach_session`). The key must come from identities your application
        verified (the user and the thread), never from model or user text. The process that
        held the session is refused from then on. A missing key raises ``LookupError``,
        never opens a fresh sandbox. The session is left open if the backend cannot be made
        over it: it holds the thread's files."""
        info = client.describe()
        ceiling = info.session_environment.max_timeout_ms / 1000 if info.session_environment.max_timeout_ms > 0 else None
        session = client.attach_session(key, store=store, trace_id=trace_id)
        return cls(session, minimum_isolation=minimum_isolation, timeout=timeout, max_timeout=ceiling)

    # ---- what the backend states ----

    @property
    def id(self) -> str:
        """The session's public fingerprint (never its ID, which is a capability)."""
        return self._session.fingerprint

    @property
    def root(self) -> str:
        """The sandbox's work directory (``/work`` on docker), for the agent's prompt."""
        return self._workspace.root

    @property
    def isolation(self) -> str:
        """The tier the session stated when it opened."""
        return self._session.isolation

    @property
    def session(self) -> Session:
        return self._session

    def close(self) -> None:
        """Closes the session: the sandbox and its files are gone, and every later call
        raises :class:`~plimsoll_client.SessionEndedError`."""
        _close_quietly(self._session)

    def __enter__(self) -> "PlimsollSandbox":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    # ---- a call lost before a takeover ----

    def _recovering(self) -> Optional[str]:
        """When the session is recovering from a call whose answer was lost, what the model is told in place of the
        tool call that asked (nothing of it is sent), after which the session is resolved; else None. Once: of tool
        calls made at the same moment, the first gets it and the others run."""
        with self._lost_lock:
            lost = getattr(self._session, "lost_call", None)
            if lost is None:
                return None
            self._session.resolve_lost_call()
        return lost_call_message(lost, self._max_output_chars)

    # ---- commands ----

    def _budget(self, timeout: Optional[int]) -> float:
        if timeout is None:
            budget = self._timeout
        elif isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0:
            raise ValueError(f"timeout must be a non-negative number of seconds, not {timeout!r}")
        elif timeout == 0:
            budget = self._max_timeout if self._max_timeout is not None else self._timeout
        else:
            budget = float(timeout)
        if self._max_timeout is not None and budget > self._max_timeout:
            budget = self._max_timeout
        return budget

    def _execute(self, command: str, timeout: Optional[int], cancel: Optional[CancelHandle] = None) -> ExecuteResponse:
        budget = self._budget(timeout)
        out = self._workspace.exec(command, timeout=budget, cancel=cancel)
        text = _combine(out.stdout_text, out.stderr_text)
        truncated = out.stdout_truncated or out.stderr_truncated
        if out.timed_out:
            note = f"Command timed out after {budget:g} seconds"
            return ExecuteResponse(output=note + ("\n" + text if text else ""), exit_code=TIMEOUT_EXIT, truncated=truncated)
        return ExecuteResponse(output=text, exit_code=out.exit_code, truncated=truncated)

    def execute(self, command: str, *, timeout: Optional[int] = None) -> ExecuteResponse:
        """Runs ``command`` as shell text in the session, in the shell's current
        directory with its exported variables. stdout comes first, then each stderr line
        marked ``[stderr] ``. Raises on a refusal or an error after which the command may
        have run (never retried); a command with a NUL is a ValueError."""
        return self._execute(command, timeout)

    async def aexecute(self, command: str, *, timeout: Optional[int] = None) -> ExecuteResponse:  # noqa: ASYNC109
        """:meth:`execute` in a worker thread. Cancelling the await cancels the call: a
        command not yet sent is never sent, and the connection of one in flight is cut."""
        return await in_thread(self._execute, command, timeout)

    # ---- search ----

    def _python_grep_cmd(self, pattern: str, path: Optional[str], glob: Optional[str], max_count: Optional[int]) -> str:
        """deepagents' python3 grep script for any search: a glob without a slash matches
        basenames at any depth (what grep --include means), and no glob matches every
        file. It reports its errors instead of discarding them. Unlike GNU grep -r it skips
        hidden files and directories (Python glob)."""
        if glob is None:
            rel_glob = "**/*"
        elif "/" in glob:
            rel_glob = glob
        else:
            rel_glob = "**/" + glob
        excluded = _grep_excluded_dirs(path, self.grep_exclude_dirs)

        def b64(text: str) -> str:
            return base64.b64encode(text.encode("utf-8")).decode("ascii")

        return _GREP_PATH_GLOB_TEMPLATE.format(
            path_b64=b64(path or "."),
            glob_b64=b64(rel_glob),
            pattern_b64=b64(pattern),
            exclude_b64=b64("\0".join(excluded)),
            max_count=None if max_count is None else int(max_count),
        )

    def grep(self, pattern: str, path: Optional[str] = None, glob: Optional[str] = None, *, max_count: Optional[int] = None) -> GrepResult:
        """deepagents' grep. On a sandbox without GNU grep (BusyBox, plimsoll's Alpine
        images), through deepagents' python3 route for every search
        (:meth:`_python_grep_cmd`), since its grep route would read BusyBox's refusal of
        its options as no matches."""
        if self._gnu_grep:
            return super().grep(pattern, path, glob, max_count=max_count)
        return _parse_grep_output(self.execute(self._python_grep_cmd(pattern, path, glob, max_count)), path, max_count)

    async def agrep(self, pattern: str, path: Optional[str] = None, glob: Optional[str] = None, *, max_count: Optional[int] = None) -> GrepResult:
        if self._gnu_grep:
            return await super().agrep(pattern, path, glob, max_count=max_count)
        return _parse_grep_output(await self.aexecute(self._python_grep_cmd(pattern, path, glob, max_count)), path, max_count)

    # ---- files ----

    def _upload(self, files: Sequence[Tuple[str, bytes]], cancel: Optional[CancelHandle] = None) -> List[FileUploadResponse]:
        out: List[FileUploadResponse] = []
        for path, content in files:
            if not isinstance(path, str) or not path.startswith("/"):
                out.append(FileUploadResponse(path=path, error="invalid_path"))
                continue
            # Only the file's own outcomes are answered per file: a refusal, a call that
            # may have run without an answer, a record or tier that failed its check and a
            # call past its budget raise and stop the run (the module docstring), so the
            # model never reads one as a file that failed and writes it again.
            try:
                self._workspace.write(path, bytes(content), cancel=cancel)
            except WorkspacePathError:
                out.append(FileUploadResponse(path=path, error="invalid_path"))
            except WorkspaceTooLargeError as e:
                out.append(FileUploadResponse(path=path, error=f"plimsoll: {e}"))
            except TimeoutError:
                raise  # an OSError, so before the file's own errors: the write may have run
            except OSError as e:
                out.append(FileUploadResponse(path=path, error=_file_error(str(e))))
            else:
                out.append(FileUploadResponse(path=path, error=None))
        return out

    def upload_files(self, files: List[Tuple[str, bytes]]) -> List[FileUploadResponse]:
        """Writes each ``(path, bytes)``, creating parent directories, and answers per
        file in order. A relative path is ``invalid_path``, a write the sandbox refused
        (``permission_denied``, say) the file's error. A call plimsoll refused, one that
        may have written without an answer, an answer that failed its check and a write
        past its budget raise, as :meth:`execute` does, and the files after it are not
        written."""
        return self._upload(files)

    async def aupload_files(self, files: List[Tuple[str, bytes]]) -> List[FileUploadResponse]:
        return await in_thread(self._upload, files)

    def _download(self, paths: Sequence[str], cancel: Optional[CancelHandle] = None) -> List[FileDownloadResponse]:
        out: List[FileDownloadResponse] = []
        for path in paths:
            if not isinstance(path, str) or not path.startswith("/"):
                out.append(FileDownloadResponse(path=path, error="invalid_path"))
                continue
            try:
                content = self._workspace.read_whole(path, cancel=cancel)
            except WorkspacePathError:
                out.append(FileDownloadResponse(path=path, error="invalid_path"))
            except WorkspaceTooLargeError as e:
                out.append(FileDownloadResponse(path=path, error=f"plimsoll: {e}"))
            except WorkspaceChangedError as e:
                out.append(FileDownloadResponse(path=path, error=f"plimsoll: {path}: {e.strerror}"))
            except TimeoutError:
                raise  # as an upload's: never a file's error
            except FileNotFoundError as e:
                out.append(FileDownloadResponse(path=path, error=self._why_unreadable(path, str(e), cancel)))
            except OSError as e:
                out.append(FileDownloadResponse(path=path, error=_file_error(str(e))))
            else:
                out.append(FileDownloadResponse(path=path, content=content, error=None))
        return out

    def _why_unreadable(self, path: str, message: str, cancel: Optional[CancelHandle]) -> str:
        """deepagents' word for a path the sandbox could not read, from the path itself
        (one call): BusyBox head says "I/O error" of a directory, so the message alone
        cannot tell."""
        r = self._workspace.run(["sh", "-c", _WHY_UNREADABLE, "sh", path], cancel=cancel)
        word = r.stdout_text.strip()
        return word if word in ("is_directory", "file_not_found", "permission_denied") else _file_error(message)

    def download_files(self, paths: List[str]) -> List[FileDownloadResponse]:
        """Reads each path whole (``Workspace.read_whole``: 8 MiB per call, one call's
        artifact budget, and at most 64 MiB, ``workspace.MAX_WHOLE_BYTES``, since the file
        ends in this process's memory and code in the sandbox can make one of any size)
        and answers per path in order. A file past 64 MiB is its error, read no further
        than its first piece. A relative path is ``invalid_path``; a missing file
        ``file_not_found``, a directory ``is_directory``, an unreadable file
        ``permission_denied``; a file that changed while it was read is an error, never
        a cut copy. A call plimsoll refused, one that may have run without an answer, an
        answer that failed its check and a read past its budget raise, as an upload's
        do."""
        return self._download(paths)

    async def adownload_files(self, paths: List[str]) -> List[FileDownloadResponse]:
        return await in_thread(self._download, paths)


# ---- every tool entry point answers a recovering session first ----
#
# Each public method a Deep Agents tool calls, and what it answers, in place of running, on a session recovering from
# a lost call: the explanation as the method's own error field (or as an ``execute`` output with a failing exit code),
# so the model reads it and the run goes on. BaseSandbox's file tools call ``execute`` themselves; the outermost
# method that runs first resolves the session, so the calls it makes after that run as usual.


def _not_run(msg: str) -> ExecuteResponse:
    return ExecuteResponse(output=msg, exit_code=NOT_RUN_EXIT, truncated=False)


_LOST_CALL_ANSWERS: Dict[str, Callable[[str, Tuple[Any, ...], Dict[str, Any]], Any]] = {
    "execute": lambda msg, a, k: _not_run(msg),
    "execute_with_offload": lambda msg, a, k: ExecuteOffloadResult(offloaded=False, response=_not_run(msg)),
    "ls": lambda msg, a, k: LsResult(error=msg),
    "read": lambda msg, a, k: ReadResult(error=msg),
    "write": lambda msg, a, k: WriteResult(error=msg),
    "edit": lambda msg, a, k: EditResult(error=msg),
    "delete": lambda msg, a, k: DeleteResult(error=msg),
    "grep": lambda msg, a, k: GrepResult(error=msg),
    "glob": lambda msg, a, k: GlobResult(error=msg),
    "upload_files": lambda msg, a, k: [FileUploadResponse(path=p, error=msg) for p, _ in (a[0] if a else k["files"])],
    "download_files": lambda msg, a, k: [FileDownloadResponse(path=p, content=None, error=msg) for p in (a[0] if a else k["paths"])],
}


def _answering_a_lost_call_first(fn: Callable[..., Any], answer: Callable[[str, Tuple[Any, ...], Dict[str, Any]], Any]) -> Callable[..., Any]:
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def guarded_async(self: PlimsollSandbox, *a: Any, **k: Any) -> Any:
            msg = self._recovering()
            return answer(msg, a, k) if msg is not None else await fn(self, *a, **k)

        return guarded_async

    @functools.wraps(fn)
    def guarded(self: PlimsollSandbox, *a: Any, **k: Any) -> Any:
        msg = self._recovering()
        return answer(msg, a, k) if msg is not None else fn(self, *a, **k)

    return guarded


for _name, _answer in _LOST_CALL_ANSWERS.items():
    for _method in (_name, "a" + _name):
        setattr(PlimsollSandbox, _method, _answering_a_lost_call_first(getattr(PlimsollSandbox, _method), _answer))
del _name, _answer, _method
