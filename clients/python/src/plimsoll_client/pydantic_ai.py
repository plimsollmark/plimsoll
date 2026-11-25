"""PydanticAI: one plimsoll session as an agent run's workspace, plimsoll's shell tool over it, and the code tool.

PydanticAI (``pydantic-ai-slim`` 2.70.0, read on 2026-11-18) gives an agent run a **workspace**: an object a
capability supplies (``get_workspace``) that every tool of the run reaches as ``ctx.workspace``, PydanticAI's own
``FileSystem`` file tools included. :class:`PlimsollWorkspace` is that capability, and
:class:`PlimsollWorkspaceBackend` the workspace backend: one plimsoll session, opened on the run's first
workspace operation, kept for the rest of the run and for later runs of the same conversation in this process.
Every operation is a call of the session, so the daemon's guarantees hold for all of them: the isolation floor,
a run record on every call, no network unless the operator granted it (a workspace call never carries a grant).

    from pydantic_ai import Agent
    from pydantic_ai_harness import FileSystem
    from plimsoll_client import Client
    from plimsoll_client.pydantic_ai import PlimsollWorkspace

    workspace = PlimsollWorkspace(client=Client("https://plimsoll.internal:8746", token=TOKEN),
                                  minimum_isolation="kernel")
    agent = Agent(model, capabilities=[workspace, FileSystem()])
    result = await agent.run("...")

What it is, and what it is not, stated here and in the docstrings:

- **Files only, as PydanticAI's contract counts it.** The backend implements ``WorkspaceBackend``,
  ``SupportsFilesystem`` and ``SupportsRealpath``, and not ``SupportsCommands``: plimsoll's sessions kill every
  process a call leaves behind when the call ends, and the contract's command clause says a backend must "never
  stop a process the command detached into its own session". So ``ctx.workspace.run`` raises PydanticAI's
  ``UserError``, and PydanticAI's ``Coder`` and ``Shell`` capabilities, which run every command as a detached job
  and poll it with later calls, do not work on it. Commands go through plimsoll's own tool instead.
- **plimsoll's shell tool.** The capability adds ``plimsoll_shell(command)``, which runs a command in the same
  session (BusyBox ``sh`` on plimsoll's docker images; the shell's directory and exported variables persist from
  one command to the next) and says in its description that a process it leaves running stops when the command
  returns. The file tools and this tool see the same files.
- **The floor is yours to set.** ``minimum_isolation`` has no default; a session below it is closed and nothing
  of the agent's runs.
- **One process, or every process with a checkpoint store.** A backend rebuilt from the run's ``WorkspaceRef``
  (a later run of the conversation, whose message history carries the ref) reaches the same session through this
  capability's registry of open sessions, in this process. With a ``checkpoint_store`` and a ``checkpoint_key``
  (a function of the run context naming the conversation by identities the application verified), a backend in
  another process takes the session over from the store (plimsoll's session reattach) and keeps it in its own
  registry for the backends rebuilt there; the process that held it is refused from then on, and its backend
  takes the session back from the store once, and sends its operation again, before it gives up. Without a
  store, another process, or this one after a restart, gets ``WorkspaceUnavailableError``. Either way the
  backend never opens a fresh session in place of the one a ref names. The ref is
  ``WorkspaceRef(provider="plimsoll", id="<daemon>/<fingerprint>")``: the daemon's name in this capability's
  configuration and the session's public fingerprint, never the session ID (a capability) or a URL.
- **A call whose answer was lost.** With a checkpoint store, a call whose answer never reached its process leaves
  the store pending with that call, and the next process takes the session over across it; the takeover returns
  the lost call's record, which says whether the daemon answered the call (a result digest, which does not show
  that the command ran to its end) or the call ended without an answer (an unanswered code, which does not show that
  the command started: it may have done none, part or all of its work), and the call's answer when the daemon kept
  it. The session is then recovering: plimsoll's client refuses every call until it is resolved. The model's next
  tool call after the takeover, whichever it is (``plimsoll_shell`` or a file tool), is not run: the lost call's
  record goes to the ``record_sink``, the model gets a failed tool result (PydanticAI's ``ToolFailed``) saying what
  the record says, and the lost call's output when its answer came back, cut to ``max_output_chars``, and the backend
  resolves the session; the run goes on, and the model's next call runs. So a lost command or file operation is
  never sent again before the model has been told; the model may then send it again on purpose.
- **Not for durable execution yet.** Under Temporal, DBOS or Prefect a workspace call may run again after its
  answer was lost, and every call rebuilds the backend in whichever worker runs it. The checkpoint store is what
  makes that safe (a lost call is either never run, or named, and no call is sent until the model was told of it),
  but no engine's own test runs here yet, so ``get_workspace`` still refuses a durable run with a ``UserError`` that
  says so.
- **The session ends when its lifetime does**, or when :meth:`PlimsollWorkspace.destroy` closes it; a run never
  closes it (the contract leaves that to whoever holds the ref).
- **A call that may have run is never reported as one that did not.** :func:`map_error` is the one mapping from
  plimsoll's errors to PydanticAI's. An error without plimsoll's not-dispatched mark raises
  :class:`PlimsollOutcomeUnknownError`, a ``WorkspaceUnavailableError``, which no engine retries; the tool call
  refused for a lost call raises :class:`PlimsollLostCallError` (nothing of it was sent), a plain
  ``WorkspaceError``, which PydanticAI's file tools give the model as a failed tool result; a refusal that another
  try may pass raises :class:`PlimsollRetryableError`, a
  ``ConnectionError``; a session that has ended, or that this run can no longer use, raises
  :class:`PlimsollWorkspaceGoneError`.
- **Records are kept.** Every record the client checked goes to the capability's ``record_sink`` (by default a
  list on the session's backends, :attr:`PlimsollWorkspaceBackend.records`; :class:`JsonLinesRecordSink` writes a
  file), the record of a call lost before a takeover included, once, before any call of the new worker's is sent
  (a sink that fails is tried again on the next operation, and nothing is sent until it takes the record).

:func:`plimsoll_code_tool` is plimsoll's stateless code tool (a fresh sandbox per call,
:class:`~plimsoll_client.execution.CodeExecutor`) as a PydanticAI tool; it answers with the dict
``plimsoll_client._code_tool`` describes and never raises.

Needs PydanticAI (``pip install pydantic-ai-plimsoll``, which pins ``pydantic-ai-slim`` exactly: upstream adds
conformance rules in minor releases).
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import posixpath
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from functools import partial
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, TypeVar

try:
    import anyio
    import anyio.to_thread
    from pydantic_ai import FunctionToolset, ModelRetry, RunContext, Tool, ToolReturn
    from pydantic_ai.capabilities import AbstractCapability
    from pydantic_ai.exceptions import ToolFailed, UserError
    from pydantic_ai.workspaces import FileEntry, WorkspaceError, WorkspaceOutputLimitError, WorkspaceRef
    from pydantic_ai.workspaces import WorkspaceTimeoutError, WorkspaceUnavailableError
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "plimsoll_client.pydantic_ai needs PydanticAI: pip install pydantic-ai-plimsoll (or pydantic-ai-slim==2.70.0)"
    ) from e

from . import _code_tool as ct
from . import _validate as v
from ._langsmith import labels as _closed_set_labels
from ._lost_call import lost_call_message
from ._transport import CancelHandle
from .aio import AsyncClient
from .checkpoint import CheckpointConflictError, CheckpointStore, CheckpointStoreError
from .client import Client, Session
from .errors import (
    CheckpointMismatchError,
    DataLossError,
    HeadMismatchError,
    InsufficientIsolationError,
    PlimsollError,
    RecoveringError,
    SessionEndedError,
    StaleOwnerError,
)
from .execution import CodeExecutor
from .types import LostCall, ProjectResult, RunRecord, SessionSummary, meets
from .workspace import MAX_WHOLE_BYTES, STATE_DIR, Workspace, WorkspaceCallError, WorkspacePathError, WorkspaceTooLargeError, _check_text
from .workspace import close_quietly as _close_quietly

__all__ = [
    "PROVIDER",
    "PlimsollWorkspace",
    "PlimsollWorkspaceBackend",
    "PlimsollOutcomeUnknownError",
    "PlimsollLostCallError",
    "PlimsollWorkspaceGoneError",
    "PlimsollRetryableError",
    "JsonLinesRecordSink",
    "map_error",
    "plimsoll_code_tool",
]

#: The ``provider`` of every ref this package makes.
PROVIDER = "plimsoll"

#: Characters of stdout and of stderr the shell tool returns, each: about 7,500 tokens per stream.
MAX_OUTPUT_CHARS = 30_000

#: The step output limit a file operation's answer must fit (the project runner's, its MAX_STEP_OUTPUT): a listing or
#: a stat answer cut there raises ``WorkspaceOutputLimitError``, never a short answer.
STEP_OUTPUT_LIMIT = 1 << 20

#: How long, at most, the backend retries a refusal marked ``capacity`` itself (nothing ran) before raising
#: :class:`PlimsollRetryableError`: about 30 seconds.
CAPACITY_RETRY_SECONDS = 30.0
#: The pauses between those retries, doubling from half a second: six retries, 23.5 seconds in all, within
#: :data:`CAPACITY_RETRY_SECONDS` (a test holds the sum to it).
_CAPACITY_BACKOFF = (0.5, 1.0, 2.0, 4.0, 8.0, 8.0)

# Raw bytes a write carries per call: 2.25 MiB, 3 MiB as base64, under the 4 MiB the client allows one call's
# files, as plimsoll_client.workspace sends bytes.
_WRITE_CHUNK_BYTES = 2_359_296

log = logging.getLogger("plimsoll_client")

AgentDepsT = TypeVar("AgentDepsT")


# ---- errors ----


class PlimsollOutcomeUnknownError(WorkspaceUnavailableError):
    """A workspace call that may have run: the daemon's answer was lost, did not check, or could not be kept.
    A ``WorkspaceUnavailableError``, so Temporal and Prefect never retry it (running it again could repeat what
    it did). ``cause`` is plimsoll's error; ``record`` the call's record when the client checked one."""

    def __init__(self, message: str, *, record: Optional[RunRecord] = None, result: Optional[ProjectResult] = None) -> None:
        super().__init__(message)
        self.record = record
        self.result = result


class PlimsollLostCallError(ToolFailed, WorkspaceError):
    """The operation was not run: it was the first after a takeover across a call whose answer was lost, and the
    session was recovering (plimsoll's client refuses every call until the session is resolved). Its message is what
    the model is told: what plimsoll's record of the lost call says (the record says whether the daemon answered the
    call), and the lost call's output when its answer came back. The backend resolved the session before raising it,
    so the next operation runs. PydanticAI's ``ToolFailed`` and a plain ``WorkspaceError`` (not
    ``WorkspaceUnavailableError``): raised anywhere in a tool's body (a file tool reads the working directory before
    its own error handling), PydanticAI gives it to the model as a failed tool result and the run goes on. ``lost`` is
    the lost call (:class:`~plimsoll_client.types.LostCall`)."""

    def __init__(self, message: str, *, lost: Optional[LostCall] = None) -> None:
        super().__init__(message)
        self.lost = lost


class PlimsollWorkspaceGoneError(WorkspaceUnavailableError):
    """The session has ended (closed, expired, past its disk budget, lost by a daemon restart), it is not open
    in this process, or this run can no longer use it (plimsoll refused it for good, or an earlier call left it
    stopped). ``reason`` names which."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class PlimsollRetryableError(ConnectionError):
    """A refusal plimsoll marked not dispatched (nothing ran) whose reason says another try may pass:
    ``capacity`` after the backend's own retries, or ``environment``. A ``ConnectionError``, which PydanticAI's
    durable engines count as transient; a plain run sees it raised."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


# The refusals another try of the same call may pass (plimsoll_client.RETRY_REASONS).
_RETRYABLE = frozenset({"capacity", "environment"})


def map_error(e: BaseException) -> BaseException:
    """The PydanticAI error for plimsoll error ``e``. Only an error that carries plimsoll's
    not-dispatched mark can come back as anything but :class:`PlimsollOutcomeUnknownError`: no mark means the
    call may have run. Returns ``e`` itself for anything that is not plimsoll's."""
    if isinstance(e, CheckpointStoreError):
        if e.sent:
            return PlimsollOutcomeUnknownError(
                f"plimsoll: the call ran and the checkpoint store could not be written after it ({e}); it was not retried, "
                "and this run sends nothing more on the session",
                record=getattr(e.result, "record", None), result=e.result if isinstance(e.result, ProjectResult) else None,
            )
        return PlimsollWorkspaceGoneError(f"plimsoll: the checkpoint store would not take the call ({e}); nothing was sent", reason="store")
    if isinstance(e, RecoveringError) and e.not_dispatched is not None:
        # The backend resolves a recovering session before its first operation runs, so only a session handed to it
        # recovering by another path reaches this.
        return PlimsollLostCallError(
            "plimsoll: this session is recovering from a call whose answer was lost, and the operation was not sent; "
            "read the lost call and resolve it (Session.resolve_lost_call) before sending another"
        )
    if isinstance(e, HeadMismatchError) and e.not_dispatched is not None:
        return PlimsollWorkspaceGoneError(
            f"plimsoll: the daemon ran a call on this session that this run did not send ({e.message}); nothing ran, and "
            "this run sends nothing more on the session",
            reason="head_mismatch",
        )
    if isinstance(e, CheckpointMismatchError):
        return PlimsollOutcomeUnknownError(
            "plimsoll: a call of this run ran after the stored checkpoint and its answer was lost, and the store does not "
            "name it; nothing was run again"
        )
    if isinstance(e, StaleOwnerError) and e.not_dispatched is not None:
        return PlimsollWorkspaceGoneError(f"plimsoll: another process holds the session ({e.message}); nothing ran", reason="stale")
    if isinstance(e, WorkspaceCallError):
        r = e.result
        if r.outcome == "setup_failed":
            return WorkspaceError(f"plimsoll: the call did not run (setup_failed: no step began){': ' + r.detail if r.detail else ''}")
        return PlimsollOutcomeUnknownError(
            f"plimsoll: the call may have run and its answer is incomplete ({r.outcome}); it was not retried",
            record=r.record, result=r,
        )
    if not isinstance(e, PlimsollError):
        return e
    reason = e.not_dispatched
    if reason is None:
        if isinstance(e, DataLossError):
            return PlimsollOutcomeUnknownError(
                f"plimsoll: the daemon answered and the answer does not check ({type(e).__name__}: {e.message}); the call may "
                "have run, it was not retried, and this run sends nothing more on the session",
                record=e.record,
            )
        if e.record is not None:
            return PlimsollOutcomeUnknownError(
                f"plimsoll: the call may have run without an answer ({e.message}); its record checked and the session goes on; "
                "it was not retried",
                record=e.record,
            )
        return PlimsollOutcomeUnknownError(
            f"plimsoll: the call may have run without an answer ({e.message}); it was not retried, and this run sends nothing "
            "more on the session"
        )
    if isinstance(e, SessionEndedError):
        return PlimsollWorkspaceGoneError(f"plimsoll: the session has ended ({e.reason}); nothing ran", reason=e.reason)
    if reason in _RETRYABLE:
        return PlimsollRetryableError(f"plimsoll: refused before anything ran ({reason}): {e.message}", reason=reason)
    if reason == "request":
        return ValueError(f"plimsoll: refused before anything ran (request): {e.message}")
    return PlimsollWorkspaceGoneError(f"plimsoll: refused before anything ran ({reason}): {e.message}", reason=reason)


# The pause between capacity retries; a test replaces it.
_sleep = time.sleep


async def _to_its_end(fn: Callable[[], Any]) -> Any:
    """``fn()`` in a worker thread, answered only once it has returned or raised; a cancel of the await is raised
    after that. anyio's shielded scope holds back anyio's own cancel but not asyncio's ``Task.cancel`` (a run
    canceled by ``task.cancel()``, ``asyncio.wait_for`` or ``asyncio.timeout``, as PydanticAI's own runs are),
    which it raised at once while the thread went on: a run canceled while its first operation opened the session
    then ended, and PydanticAI recorded its ``workspace_ref``, before the ref existed, leaving the session open with
    nothing naming it (release-95)."""
    call = asyncio.ensure_future(anyio.to_thread.run_sync(fn))
    canceled: Optional[BaseException] = None
    # Shielded, so an anyio scope's cancel waits outside as before (anyio sends one on every turn of the loop to a
    # task it reaches); asyncio's own arrives once per Task.cancel and is kept for after the call.
    with anyio.CancelScope(shield=True):
        while not call.done():
            try:
                await asyncio.wait((call,))  # never cancels the call it waits on
            except asyncio.CancelledError as e:
                canceled = e
    if canceled is not None:
        if not call.cancelled():
            call.exception()  # retrieved: the cancel is what the caller asked for, and it is raised instead
        raise canceled
    return call.result()


def _with_capacity_retry(call: Callable[[], Any]) -> Any:
    """``call()``, sent again after a refusal marked ``capacity`` (nothing ran), after each pause of
    :data:`_CAPACITY_BACKOFF` in turn; the last refusal is raised."""
    for pause in _CAPACITY_BACKOFF + (None,):
        try:
            return call()
        except PlimsollError as e:
            if e.not_dispatched != "capacity" or pause is None:
                raise
        _sleep(pause)
    raise AssertionError("unreachable")  # pragma: no cover


# ---- records ----


class JsonLinesRecordSink:
    """A ``record_sink`` that appends each record the client checked to a JSON-lines file at ``path``, one
    ``{"record": {...}}`` object per line with the record's fields as :class:`~plimsoll_client.types.RunRecord`
    names them. The lines of one session form its chain (each record's ``previous_sha256`` is the one before's
    ``sha256``). The file is a log of checked records, not a signed bundle: plimsoll-attest's bundles are signed
    by a harness key this sink does not hold."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()

    def __call__(self, record: RunRecord) -> None:
        line = json.dumps({"record": dataclasses.asdict(record)}, sort_keys=True) + "\n"
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()


class _RecordingSession:
    """The session a backend's :class:`Workspace` calls: the real one, with every record the client checked
    handed to the sink, the record of a call left without an answer included."""

    def __init__(self, session: Session, sink: Callable[[RunRecord], None]) -> None:
        self._session = session
        self._sink = sink

    def run_project(self, files: Any, steps: Sequence[str], artifacts: Sequence[str] = (), **kw: Any) -> ProjectResult:
        try:
            result = self._session.run_project(files, steps, artifacts, **kw)
        except PlimsollError as e:
            if e.record is not None:
                self._keep(e.record, result=None)
            raise
        if result.record is not None:
            self._keep(result.record, result=result)
        return result

    def _keep(self, record: RunRecord, *, result: Optional[ProjectResult]) -> None:
        try:
            self._sink(record)
        except Exception as e:
            # The call ran and answered; its evidence could not be kept. Never retried: running it again would
            # repeat it.
            raise PlimsollOutcomeUnknownError(
                f"plimsoll: the call ran and its record could not be kept by the record sink ({type(e).__name__}: {e}); "
                "it was not retried",
                record=record, result=result,
            ) from e

    def keep_lost(self, record: RunRecord) -> None:
        """Hands the sink the record of the call lost before a takeover, which the attach answer carried and the
        client checked, before this worker sends any call: the record logs of the two workers then form one chain
        with no hole."""
        try:
            self._sink(record)  # the lost call's, from the attach answer
        except Exception as e:
            raise PlimsollOutcomeUnknownError(
                "plimsoll: the record of the call lost before this takeover could not be kept by the record sink "
                f"({type(e).__name__}: {e}); no call was sent, and none is until the sink takes it (the next operation "
                "offers it again)",
                record=record,
            ) from e

    def close(self) -> SessionSummary:
        return self._session.close()


# ---- the fixed scripts ----
#
# Every file operation is one or a few session calls, each running one of these scripts through
# Workspace.run as `sh -c SCRIPT sh ARG...`: the script is a constant of this module and each path reaches it as
# an argument, never in its text. A path-level failure exits 100 plus the matching Linux errno, outside the small
# codes the shell and its utilities return themselves, so a utility's own failure is never read as a missing
# path.

_ENOENT, _EEXIST, _ENOTDIR, _EISDIR, _EACCES, _ENOTREG = 102, 117, 120, 121, 113, 122

# Exits _ENOTDIR when an existing ancestor of $1 is not a directory, _EACCES when the nearest existing ancestor
# (a directory) is not writable and $2 is "w"; returns otherwise.
_ANCESTORS = (
    '__pa_a=${1%/*}; [ -n "$__pa_a" ] || __pa_a=/; '
    'while :; do '
    f'if [ -e "$__pa_a" ] && [ ! -d "$__pa_a" ]; then exit {_ENOTDIR}; fi; '
    f'if [ -d "$__pa_a" ]; then if [ "$2" = w ] && [ ! -w "$__pa_a" ]; then exit {_EACCES}; fi; break; fi; '
    '[ "$__pa_a" = / ] && break; __pa_a=${__pa_a%/*}; [ -n "$__pa_a" ] || __pa_a=/; '
    'done; '
)

# A regular file's size comes from stat, as os.stat gives it without reading the file; a stat that cannot say leaves
# the size unknown (the contract allows None).
_STAT = (
    'if [ -d "$1" ]; then printf "d\\n"; exit 0; fi; '
    'if [ -f "$1" ]; then __pa_n=$(stat -L -c %s -- "$1" 2>/dev/null) || __pa_n=; printf "f%s\\n" "$__pa_n"; exit 0; fi; '
    'if [ -e "$1" ]; then printf "o\\n"; exit 0; fi; '
    + _ANCESTORS
    + f"exit {_ENOENT}"
)

_READ_CHECK = (
    f'if [ -d "$1" ]; then exit {_EISDIR}; fi; '
    f'if [ ! -e "$1" ]; then {_ANCESTORS}exit {_ENOENT}; fi; '
    f'if [ ! -f "$1" ]; then exit {_ENOTREG}; fi; '
    f'[ -r "$1" ] || exit {_EACCES}; '
    'wc -c < "$1"'
)

# Each entry: d or -, whether it is a directory (following a symlink to its target), then its name, then NUL.
_LIST = (
    f'if [ ! -d "$1" ]; then [ -e "$1" ] && exit {_ENOTDIR}; {_ANCESTORS}exit {_ENOENT}; fi; '
    f'[ -r "$1" ] && [ -x "$1" ] || exit {_EACCES}; '
    'if [ "$1" = / ]; then __pa_p=; else __pa_p=$1; fi; '
    'for __pa_f in "$__pa_p"/* "$__pa_p"/.[!.]* "$__pa_p"/..?*; do '
    '[ -e "$__pa_f" ] || [ -L "$__pa_f" ] || continue; '
    'if [ -d "$__pa_f" ]; then __pa_d=d; else __pa_d=-; fi; '
    'printf "%s%s\\000" "$__pa_d" "${__pa_f##*/}"; '
    'done'
)

# $1 the file, $2 "w", $3 the staging file or "" to write $1 at once; the data is stdin. The nearest existing
# directory must be writable when a file is made in it (a new $1, or the staging file); rewriting an existing $1
# in place needs only $1's own permission, so $2 is then cleared.
_WRITE_BEGIN = (
    f'if [ -d "$1" ]; then exit {_EISDIR}; fi; '
    f'if [ -e "$1" ] && [ ! -f "$1" ]; then exit {_ENOTREG}; fi; '
    f'if [ -e "$1" ] && [ ! -w "$1" ]; then exit {_EACCES}; fi; '
    'if [ -z "$3" ] && [ -e "$1" ]; then set -- "$1" "" ""; fi; '
    + _ANCESTORS
    + '__pa_d=${1%/*}; [ -n "$__pa_d" ] || __pa_d=/; mkdir -p -- "$__pa_d" || exit 1; '
    'if [ -z "$3" ]; then cat > "$1"; else cat > "$3"; fi'
)
_WRITE_APPEND = 'cat >> "$1"'
# $1 the file, $2 the staging file, which gets the last piece (stdin) and is then copied into $1 (through a
# symlink, as the contract asks) and removed.
_WRITE_COMMIT = 'cat >> "$2" && cat < "$2" > "$1"; __pa_s=$?; rm -f -- "$2"; exit $__pa_s'
_WRITE_ABORT = 'rm -f -- "$1"'

_MAKE_DIR = (
    f'if [ -d "$1" ]; then exit 0; fi; '
    f'if [ -e "$1" ] || [ -L "$1" ]; then exit {_EEXIST}; fi; '
    + _ANCESTORS
    + 'mkdir -p -- "$1"'
)

_REMOVE = (
    f'if [ ! -e "$1" ] && [ ! -L "$1" ]; then {_ANCESTORS}exit {_ENOENT}; fi; '
    '__pa_d=${1%/*}; [ -n "$__pa_d" ] || __pa_d=/; '
    f'[ -w "$__pa_d" ] || exit {_EACCES}; '
    'rm -rf -- "$1"'
)

_EXISTS = 'test -e "$1"'

# Resolves $1 the way os.path.realpath(strict=False) does: components left to right, each symlink followed one
# level with readlink and its target walked in place of the link, `..` climbing what is resolved so far, a
# missing component kept as written. Past 40 links (Linux's MAXSYMLINKS), as in a loop, the rest is kept as
# written. A link readlink cannot read fails the call. The answer is the path on stdout, nothing after it.
_REALPATH = (
    '__pa_r=${1#/}; __pa_o=; __pa_n=0; '
    'while [ -n "$__pa_r" ]; do '
    'case $__pa_r in */*) __pa_c=${__pa_r%%/*}; __pa_r=${__pa_r#*/};; *) __pa_c=$__pa_r; __pa_r=;; esac; '
    'case $__pa_c in ""|.) ;; ..) __pa_o=${__pa_o%/*};; *) '
    'if [ "$__pa_n" -lt 40 ] && [ -L "$__pa_o/$__pa_c" ]; then '
    '__pa_n=$((__pa_n + 1)); __pa_t=$(readlink -- "$__pa_o/$__pa_c" && printf x) || exit 1; '
    '__pa_t=${__pa_t%x}; __pa_t=${__pa_t%?}; '
    'case $__pa_t in /*) __pa_o=;; esac; __pa_r=$__pa_t/$__pa_r; '
    'else __pa_o=$__pa_o/$__pa_c; fi;; esac; '
    'done; printf %s "${__pa_o:-/}"'
)

_ERRNO = {
    _ENOENT: FileNotFoundError,
    _EEXIST: FileExistsError,
    _ENOTDIR: NotADirectoryError,
    _EISDIR: IsADirectoryError,
    _EACCES: PermissionError,
}


def _path_error(code: int, path: str, stderr: str, what: str) -> BaseException:
    """The builtin error for a fixed script's exit ``code`` on ``path``; any other non-zero exit is a plain
    ``WorkspaceError`` naming the operation."""
    cls = _ERRNO.get(code)
    if cls is not None:
        return cls(path)
    if code == _ENOTREG:
        return OSError(f"not a regular file: {path!r}")
    return WorkspaceError(f"plimsoll: {what} {path!r} failed (exit {code}){': ' + stderr.strip() if stderr.strip() else ''}")


def _check_abs(path: Any) -> str:
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if "\x00" in path:
        raise ValueError("path must not contain NUL")
    if not path.startswith("/"):
        raise ValueError(f"path must be an absolute POSIX path, not {path!r}")
    return posixpath.normpath(path) if path != "/" else "/"


# ---- one open session, shared by every backend that reaches it in this process ----


# The fixed scripts that change the sandbox's files. An operation is one or a few session calls (each through
# _Environment.script, or Workspace's own steps):
#
#   working_dir   the work directory step and _REALPATH, once per session (root()); no call after
#   read_bytes    _READ_CHECK, then Workspace.read_whole's pieces (one call per 8 MiB): reads only
#   write_bytes   _WRITE_BEGIN alone up to _WRITE_CHUNK_BYTES; above it _WRITE_BEGIN to a staging file,
#                 _WRITE_APPEND for each middle piece, _WRITE_COMMIT (and _WRITE_ABORT on a failure)
#   stat, list_dir, exists, realpath   one reading call each (_STAT, _LIST, _EXISTS, _REALPATH)
#   make_dir      _MAKE_DIR, one call
#   remove        _REALPATH of the parent, then _REMOVE
#   plimsoll_shell   one call (the command)
#
# An operation refused part way, after one of these ran under this worker, is not sent again from its start after a
# takeover (finding release-61): only the large write and remove can be, and a repeat could write over what the
# process that took the session changed. Reading calls are safe to repeat.
_MUTATING = frozenset({_WRITE_BEGIN, _WRITE_APPEND, _WRITE_COMMIT, _WRITE_ABORT, _MAKE_DIR, _REMOVE})


class _Environment:
    """One open session: the session, the Workspace over it, its ref, who opened it, its records."""

    def __init__(self, capability: "PlimsollWorkspace", session: Session, owner: Optional[str], key: Optional[str] = None) -> None:
        self.session = session
        self.owner = owner
        self.key = key  # the checkpoint store's key, when the session's calls pass through one
        self.ref = WorkspaceRef(provider=PROVIDER, id=f"{capability.daemon}/{session.fingerprint}")
        self.records: List[RunRecord] = []
        # The record of the call lost before the takeover that made this environment, until the sink has taken it;
        # held under lost_lock with the session's recovering state (finding release-83).
        lost = getattr(session, "lost_call", None)
        self.pending_lost: Optional[RunRecord] = lost.record if lost is not None else None
        self.resolved_lost: Optional[LostCall] = None  # the lost call recover() told the model of and resolved
        self.lost_lock = threading.Lock()
        self.mutations = 0  # the file-changing calls (_MUTATING) that ran on this session from this process
        sink = capability.record_sink if capability.record_sink is not None else self.records.append
        self.recording = _RecordingSession(session, sink)
        self.workspace = Workspace(self.recording, timeout=capability.timeout, max_timeout=capability.max_timeout, confined=False)
        self._root: Optional[str] = None
        self._root_lock = threading.Lock()
        self.state_dirs: Set[str] = set()  # plimsoll's state directory, as reported and resolved, once root() ran

    def usable(self) -> None:
        """Raises :class:`PlimsollWorkspaceGoneError` once the session has ended or this client has stopped
        sending on it (an earlier call may have run without an answer it could check)."""
        ended = self.session.ended
        if ended is not None:
            raise PlimsollWorkspaceGoneError(f"plimsoll: the session has ended ({ended.reason}); nothing ran", reason=ended.reason)
        if self.session.stopped is not None:
            raise PlimsollWorkspaceGoneError(
                "plimsoll: an earlier call of this session may have run without an answer this client could check "
                f"({self.session.stopped}); this run can no longer use the session, and nothing ran",
                reason="stopped",
            )

    def recover(self, max_chars: int) -> None:
        """When the session is recovering from a call lost before the takeover, before anything is sent: the lost
        call's record goes to the sink (a sink that fails raises, and the session stays recovering, so the next
        operation offers it again and nothing is sent until the sink takes it), the session is resolved, and
        :class:`PlimsollLostCallError` is raised with what the model is told. Once per takeover: the first operation
        of any backend of this process that reaches the session does it."""
        with self.lost_lock:
            lost = getattr(self.session, "lost_call", None)
            if lost is None:
                return
            if self.pending_lost is not None:
                self.recording.keep_lost(self.pending_lost)
                self.pending_lost = None
            self.session.resolve_lost_call()
            self.resolved_lost = lost
        raise PlimsollLostCallError(lost_call_message(lost, max_chars), lost=lost)

    def root(self) -> str:
        """The working directory, symlinks resolved (the contract asks for it canonical): the work directory the
        sandbox reports, then resolved by the realpath script. Two calls, once per session."""
        with self._root_lock:
            if self._root is None:
                reported = self.workspace.root
                code, out, _ = self.script(_REALPATH, reported)
                real = out.decode("utf-8", "surrogateescape") if code == 0 else ""
                self._root = real if real.startswith("/") else reported
                self.state_dirs = {posixpath.join(reported, STATE_DIR), posixpath.join(self._root, STATE_DIR)}
            return self._root

    def script(self, script: str, *args: str, stdin: Optional[bytes] = None) -> Tuple[int, bytes, str]:
        """Runs a fixed script with ``args`` and ``stdin``: its exit code, stdout and stderr. A call past its budget
        raises ``WorkspaceTimeoutError``; an answer whose stdout or stderr the daemon cut raises
        ``WorkspaceOutputLimitError``."""
        try:
            out = _with_capacity_retry(lambda: self.workspace.run(["sh", "-c", script, "sh", *args], stdin=stdin))
        except PlimsollError as e:
            if script in _MUTATING and e.not_dispatched is None:
                self.mutations += 1  # it may have run
            raise
        if script in _MUTATING:
            self.mutations += 1
        if out.timed_out:
            raise WorkspaceTimeoutError("plimsoll: the file operation ran past its time budget", stdout=out.stdout_text, stderr=out.stderr_text)
        if out.stdout_truncated or out.stderr_truncated:
            raise WorkspaceOutputLimitError(
                "plimsoll: the file operation's answer is past the step output limit", limit=STEP_OUTPUT_LIMIT,
                stdout=out.stdout_text, stderr=out.stderr_text,
            )
        return out.exit_code, out.stdout, out.stderr_text


# ---- the backend ----


class PlimsollWorkspaceBackend:
    """A PydanticAI workspace backend over one plimsoll session: ``WorkspaceBackend``, ``SupportsFilesystem`` and
    ``SupportsRealpath``, not ``SupportsCommands`` (the module docstring says why). Built by
    :meth:`PlimsollWorkspace.backend` (or a run's ``get_workspace``), with no I/O: the first operation opens a
    session, or reaches the open one its ref names in this process.

    Every operation runs its session calls in a worker thread and is not cut by a cancel of its await: the call
    finishes, so the session stays in step with the daemon, and the cancel is raised after it. The open is
    shielded the same way, so a run canceled while the session opens still keeps its ref."""

    def __init__(
        self, capability: "PlimsollWorkspace", *, ref: Optional[WorkspaceRef] = None, owner: Optional[str] = None, key: Optional[str] = None
    ) -> None:
        if ref is not None:
            if not isinstance(ref, WorkspaceRef) or ref.provider != PROVIDER:
                raise ValueError(f"plimsoll: not a plimsoll workspace ref: {ref!r}")
        self._capability = capability
        self._owner = owner
        self._key = key
        self._own_lost = ""  # the request digest of this process's own lost call, while it takes the session back
        self._ref = ref
        self._attach = ref is not None
        self._env: Optional[_Environment] = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"PlimsollWorkspaceBackend(ref={self._ref!r})"

    # ---- WorkspaceBackend ----

    @property
    def ref(self) -> Optional[WorkspaceRef]:
        """``None`` until the first operation opens a session, then that session's ref for good; the ref it was
        built with, when it attaches."""
        return self._ref

    @property
    def records(self) -> Tuple[RunRecord, ...]:
        """The records the client checked on this backend's session, in order, when the capability has no
        ``record_sink`` (else empty)."""
        env = self._env
        return tuple(env.records) if env is not None else ()

    @property
    def session(self) -> Optional[Session]:
        """The plimsoll session, once open; ``None`` before the first operation."""
        env = self._env
        return env.session if env is not None else None

    @property
    def resolved_lost_call(self) -> Optional[LostCall]:
        """The call lost before this backend's session was taken over, once an operation told the model of it and
        resolved the session (the session's own ``lost_call`` is then ``None``), else ``None``: what the application
        reads after the run of what the model was told. Its record says whether the daemon answered the call."""
        env = self._env
        return env.resolved_lost if env is not None else None

    async def working_dir(self) -> str:
        return await self._run(lambda env: env.root())

    # ---- SupportsFilesystem ----

    async def read_bytes(self, path: str) -> bytes:
        """The whole file, at most 64 MiB (``workspace.MAX_WHOLE_BYTES``): a longer one is a ``WorkspaceError``,
        refused before any of it is read, since the file ends in this process's memory."""
        p = _check_abs(path)
        return await self._run(partial(self._read, p))

    async def write_bytes(self, path: str, data: bytes) -> None:
        p = _check_abs(path)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes")
        await self._run(partial(self._write, p, bytes(data)))

    async def stat(self, path: str) -> FileEntry:
        p = _check_abs(path)
        return await self._run(partial(self._stat, p))

    async def list_dir(self, path: str) -> Sequence[FileEntry]:
        p = _check_abs(path)
        return await self._run(partial(self._list_dir, p))

    async def make_dir(self, path: str) -> None:
        p = _check_abs(path)
        await self._run(partial(self._make_dir, p))

    async def remove(self, path: str) -> None:
        p = _check_abs(path)
        await self._run(partial(self._remove, p))

    async def exists(self, path: str) -> bool:
        p = _check_abs(path)
        return await self._run(partial(self._exists, p))

    # ---- SupportsRealpath ----

    async def realpath(self, path: str) -> str:
        if not isinstance(path, str) or "\x00" in path or not path.startswith("/"):
            _check_abs(path)
        return await self._run(partial(self._realpath, path))

    # ---- the session ----

    async def _run(self, op: Callable[[_Environment], Any]) -> Any:
        # A backend handed to a run as is (Agent.run(workspace=backend)) never meets get_workspace's check, so every
        # operation makes the durable unit's half of it.
        if _in_durable_unit():
            raise UserError(_DURABLE_REFUSAL.format(what="a durable unit"))
        # Not abandoned on cancel: the thread's session call finishes, then the cancel is raised.
        return await _to_its_end(partial(self._in_thread, op))

    def _in_thread(self, op: Callable[[_Environment], Any]) -> Any:
        env = self._environment()
        cap = self._capability
        mutations = env.mutations
        try:
            env.usable()
            env.recover(cap.max_output_chars)
            return op(env)
        except PlimsollWorkspaceGoneError as e:
            # The session stopped taking this process's calls: another process took it over, the store moved on,
            # or an earlier call's answer was lost. With a store, take it back once.
            if e.reason != "stopped" or not self._store_backed():
                raise
            first: BaseException = e
        except (PlimsollError, WorkspaceCallError, CheckpointStoreError) as e:
            if not self._taken_over(e):
                raise map_error(e) from e
            first = e
        if env.mutations != mutations:
            # A call of this operation that changes files ran under this worker before the refusal (a large write's
            # first piece): sent again from its start, it could write over what the process that took the session
            # changed since (finding release-61).
            raise PlimsollWorkspaceGoneError(
                "plimsoll: another process took the session over part way through this operation, after a call of it "
                "that changes files ran here; it is not sent again, and this run can no longer use the session",
                reason="stale",
            ) from first
        # Nothing of the refused call ran, and nothing the operation sent before it changed a file. Take the session
        # back from the store once and send the operation again, from its start; a second refusal gives up.
        env = self._reattach(env, first)
        try:
            env.usable()
            env.recover(cap.max_output_chars)
            return op(env)
        except PlimsollWorkspaceGoneError:
            raise
        except (PlimsollError, WorkspaceCallError, CheckpointStoreError) as e:
            if self._taken_over(e):
                raise PlimsollWorkspaceGoneError(
                    "plimsoll: another process took the session over again while this run took it back; nothing ran",
                    reason="stale",
                ) from e
            raise map_error(e) from e

    def _store_backed(self) -> bool:
        return self._capability.checkpoint_store is not None and self._key is not None

    def _taken_over(self, e: BaseException) -> bool:
        """Whether ``e`` says another process holds the session and nothing of the call ran, on a backend whose
        session can be taken back from its store: a stale-owner refusal that carries plimsoll's not-dispatched mark
        (without the mark the call may have run, so it is never sent again, as :func:`map_error` holds too), or a
        store conflict before anything was sent."""
        if not self._store_backed():
            return False
        if isinstance(e, StaleOwnerError):
            return e.not_dispatched is not None
        return isinstance(e, CheckpointConflictError) and not e.sent

    def _wait_ready(self, own: str) -> None:
        """Waits, within :data:`CAPACITY_RETRY_SECONDS`, while the stored record is pending for a call that is not
        ``own`` (this process's own lost call, which never settles): another process's call may still be running,
        and parallel tools of one run take turns. Past the bound the attach goes ahead from the pending record, and
        the daemon's comparison decides (the call was never dispatched, or it was and the attach names it)."""
        store = self._capability.checkpoint_store
        assert store is not None and self._key is not None
        deadline = time.monotonic() + CAPACITY_RETRY_SECONDS
        while time.monotonic() < deadline:
            stored = store.load(self._key)
            if stored is None or stored.state == "ready" or (own and stored.request_sha256 == own):
                return
            _sleep(0.25)

    def _reattach(self, env: _Environment, cause: BaseException) -> _Environment:
        """Takes the session back from the store for this backend and registers it in place of ``env``; another
        backend of this process that took it back first is joined instead."""
        cap = self._capability
        self._own_lost = getattr(env.session, "lost_request_sha256", "") or ""
        self._wait_ready(self._own_lost)
        with self._lock:
            cap._forget(env)
            self._env = None
            self._attach = True
            if self._ref is None:
                self._ref = env.ref
        return self._environment()

    def _attached(self, cap: "PlimsollWorkspace", ref: WorkspaceRef) -> _Environment:
        """Takes over the session ``ref`` names from the capability's checkpoint store, under this backend's key."""
        store = cap.checkpoint_store
        assert store is not None and self._key is not None
        prefix = f"{cap.daemon}/"
        fingerprint = ref.id[len(prefix):] if ref.id.startswith(prefix) else ""
        stored = store.load(self._key)
        if not fingerprint or (stored is not None and stored.checkpoint.session != fingerprint):
            # Refused at once, rather than after waiting on another conversation's call; the attach checks again.
            raise PlimsollWorkspaceGoneError(
                f"plimsoll: the checkpoint store's session under this run's key is not {ref.id!r}; nothing was sent, and it "
                "is never replaced by another",
                reason="not_found",
            )
        self._wait_ready(self._own_lost)
        try:
            # Pinned to the ref's session: the client checks the record it sends, so a store that changed since the
            # check above never moves another conversation's session to this run.
            session = _with_capacity_retry(
                lambda: cap.client.attach_session(self._key, store=store, fingerprint=fingerprint)  # type: ignore[arg-type]
            )
        except LookupError as e:
            raise PlimsollWorkspaceGoneError(
                f"plimsoll: the checkpoint store holds no session {ref.id!r} under this run's key ({e}), so it cannot be "
                "reached; it is never replaced by another or a fresh one",
                reason="not_found",
            ) from e
        except CheckpointStoreError as e:
            if e.sent:
                # The attach's own write (finding release-60): the daemon moved the session to this worker and the store
                # names another holder. Nothing of the run's ran.
                raise PlimsollWorkspaceGoneError(
                    f"plimsoll: the attach went through and its checkpoint store write did not ({e}): another worker holds "
                    "the session now, or the store failed; nothing of this run's ran, and this run does not use the session",
                    reason="store",
                ) from e
            raise map_error(e) from e
        except PlimsollError as e:
            raise map_error(e) from e
        if f"{cap.daemon}/{session.fingerprint}" != ref.id:
            # Not with plimsoll's client, which refuses another session before sending. A client that did not would
            # have taken that session from its worker (whose calls are now refused as stale); it is still not used,
            # and not closed, since it holds another conversation's files.
            raise PlimsollWorkspaceGoneError(
                f"plimsoll: the attach answered another session than {ref.id!r}; it is not used, and that session's worker "
                "may now be refused as a stale owner",
                reason="not_found",
            )
        env = _Environment(cap, session, self._owner, self._key)
        if not meets(getattr(session, "isolation", "") or "", cap.minimum_isolation):
            # The session is not used: the record of the call lost before the takeover still goes to the sink first,
            # since no later operation of this process will reach this environment (finding release-83).
            if env.pending_lost is not None:
                env.recording.keep_lost(env.pending_lost)
                env.pending_lost = None
            raise map_error(InsufficientIsolationError(
                f"plimsoll: the session states {getattr(session, 'isolation', '') or 'no tier'}, below the required "
                f"{cap.minimum_isolation}; nothing ran (the session is left open: it holds the conversation's files)",
                not_dispatched="isolation",
            ))
        # Registered after the floor check. The record of the call lost before the takeover goes to the record sink
        # before this process sends any call on the session, by whichever backend's operation reaches it first
        # (_Environment.recover): the session is recovering, so the client sends nothing until it is resolved, and
        # the environment resolves it only once the sink has taken the record. A sink that fails ends the run; the
        # session stays registered and recovering, so the next operation offers the record again.
        cap._register(env)
        return env

    def _environment(self) -> _Environment:
        with self._lock:
            if self._env is not None:
                return self._env
            if self._attach:
                assert self._ref is not None
                env = self._capability._lookup(self._ref, self._owner)
                if env is None and self._capability.checkpoint_store is not None and self._key is not None:
                    env = self._attached(self._capability, self._ref)
                if env is None:
                    raise PlimsollWorkspaceGoneError(
                        f"plimsoll: no session of this capability named {self._ref.id!r} is open in this process; a session "
                        "is reached only from the process that opened it, while it lives, and is never replaced by a fresh one",
                        reason="not_found",
                    )
                self._env = env
                return env
            cap = self._capability
            try:
                session = _with_capacity_retry(lambda: cap.client.open_session(
                    minimum_isolation=cap.minimum_isolation, lifetime=cap.lifetime, languages=cap.languages, owner=self._owner,
                    **self._store_args(),
                ))
            except (PlimsollError, CheckpointStoreError) as e:
                raise map_error(e) from e
            env = _Environment(cap, session, self._owner, self._key if cap.checkpoint_store is not None else None)
            # Registered before the ref is published, and both as soon as the open returns, before anything that can
            # fail: a destroy(ref) made the moment the ref is visible finds the session, rather than answering
            # "not open in this process" and leaving it live (the ADK environment's release-94, in this form).
            cap._register(env)
            self._ref = env.ref
            self._env = env
            # The client checks the tier against the floor it sent; this is the backend's own check, so the
            # floor holds whatever the client is.
            if not meets(getattr(session, "isolation", "") or "", cap.minimum_isolation):
                _close_quietly(session)
                cap._forget(env)
                raise map_error(InsufficientIsolationError(
                    f"plimsoll: the session states {getattr(session, 'isolation', '') or 'no tier'}, below the required "
                    f"{cap.minimum_isolation}; nothing ran (the session was closed)",
                    not_dispatched="isolation",
                ))
            return env

    def _store_args(self) -> Dict[str, Any]:
        cap = self._capability
        if cap.checkpoint_store is None:
            return {}
        if self._key is None:
            raise UserError("plimsoll: a PlimsollWorkspace with a checkpoint_store needs a checkpoint key for each run (checkpoint_key)")
        return {"checkpoint_store": cap.checkpoint_store, "checkpoint_key": self._key}

    @staticmethod
    def _script(env: _Environment, script: str, *args: str, stdin: Optional[bytes] = None) -> Tuple[int, bytes, str]:
        return env.script(script, *args, stdin=stdin)

    @staticmethod
    def _guard(env: _Environment, path: str) -> None:
        """Refuses plimsoll's own state directory in the work directory (each call's arguments, the shell tool's
        saved directory and exports), as :class:`~plimsoll_client.workspace.Workspace` does."""
        env.root()
        for state in env.state_dirs:
            if path == state or path.startswith(state + "/"):
                raise PermissionError(f"{path}: plimsoll's own state directory")

    def _read(self, path: str, env: _Environment) -> bytes:
        self._guard(env, path)
        code, out, err = self._script(env, _READ_CHECK, path)
        if code != 0:
            raise _path_error(code, path, err, "reading")
        size = int(out.decode("ascii", "replace").strip() or "0")
        # A whole read ends in this process's memory, and code in the sandbox can make a file of any size for nothing
        # (a sparse one), so a file past Workspace's whole-read limit (MAX_WHOLE_BYTES, 64 MiB) is refused before any
        # of it is read, and one that grew past it while it was read is refused too.
        if size > MAX_WHOLE_BYTES:
            raise WorkspaceError(f"plimsoll: {path!r} is {size} bytes, past the {MAX_WHOLE_BYTES} a whole read takes; nothing of it was read")
        try:
            data = env.workspace.read_whole(path) if size else b""
        except FileNotFoundError:
            raise FileNotFoundError(path) from None
        except WorkspacePathError as e:
            raise ValueError(str(e)) from e
        except WorkspaceTooLargeError as e:
            raise WorkspaceError(f"plimsoll: {path!r} grew past the {MAX_WHOLE_BYTES} bytes a whole read takes while it was read") from e
        if len(data) != size:
            raise WorkspaceError(f"plimsoll: {path!r} changed while it was read ({len(data)} bytes read, {size} measured)")
        return data

    def _write(self, path: str, data: bytes, env: _Environment) -> None:
        self._guard(env, path)
        if path == "/":
            raise IsADirectoryError(path)
        if len(data) <= _WRITE_CHUNK_BYTES:
            code, _, err = self._script(env, _WRITE_BEGIN, path, "w", "", stdin=data)
            if code != 0:
                raise _path_error(code, path, err, "writing")
            return
        stage = posixpath.join(posixpath.dirname(path), f".plimsoll-write-{uuid.uuid4().hex}.tmp")
        pieces = [data[i : i + _WRITE_CHUNK_BYTES] for i in range(0, len(data), _WRITE_CHUNK_BYTES)]
        try:
            code, _, err = self._script(env, _WRITE_BEGIN, path, "w", stage, stdin=pieces[0])
            if code != 0:
                raise _path_error(code, path, err, "writing")
            for piece in pieces[1:-1]:
                code, _, err = self._script(env, _WRITE_APPEND, stage, stdin=piece)
                if code != 0:
                    raise _path_error(code, path, err, "writing")
            code, _, err = self._script(env, _WRITE_COMMIT, path, stage, stdin=pieces[-1])
            if code != 0:
                raise _path_error(code, path, err, "writing")
        except BaseException:
            # Best effort: the staging file is removed when the session still takes calls.
            try:
                if env.session.stopped is None and env.session.ended is None:
                    env.workspace.run(["sh", "-c", _WRITE_ABORT, "sh", stage])
            except Exception:
                pass
            raise

    def _stat(self, path: str, env: _Environment) -> FileEntry:
        self._guard(env, path)
        code, out, err = self._script(env, _STAT, path)
        if code != 0:
            raise _path_error(code, path, err, "stat of")
        line = out.decode("utf-8", "replace").strip()
        name = posixpath.basename(path) if path != "/" else "/"
        if line == "d":
            return FileEntry(name=name, path=path, is_dir=True, size=None)
        if line.startswith("f") and line[1:].isdigit():
            return FileEntry(name=name, path=path, is_dir=False, size=int(line[1:]))
        return FileEntry(name=name, path=path, is_dir=False, size=None)

    def _list_dir(self, path: str, env: _Environment) -> Sequence[FileEntry]:
        self._guard(env, path)
        code, out, err = self._script(env, _LIST, path)
        if code != 0:
            raise _path_error(code, path, err, "listing")
        entries = []
        for item in out.decode("utf-8", "surrogateescape").split("\0"):
            if len(item) < 2:
                continue
            child = posixpath.join(path, item[1:])
            if child in env.state_dirs:
                continue  # plimsoll's own state, never listed
            entries.append(FileEntry(name=item[1:], path=child, is_dir=item[0] == "d", size=None))
        return tuple(sorted(entries, key=lambda e: e.name))

    def _make_dir(self, path: str, env: _Environment) -> None:
        self._guard(env, path)
        code, _, err = self._script(env, _MAKE_DIR, path, "w")
        if code != 0:
            raise _path_error(code, path, err, "making the directory")

    def _remove(self, path: str, env: _Environment) -> None:
        self._guard(env, path)
        root = env.root()
        target = path if path == "/" else posixpath.join(self._realpath(posixpath.dirname(path), env), posixpath.basename(path))
        if target == "/" or target == root or root.startswith(target.rstrip("/") + "/"):
            raise ValueError("cannot remove the workspace's working directory or one of its ancestors")
        self._guard(env, target)
        code, _, err = self._script(env, _REMOVE, path)
        if code != 0:
            raise _path_error(code, path, err, "removing")

    def _exists(self, path: str, env: _Environment) -> bool:
        code, _, err = self._script(env, _EXISTS, path)
        if code in (0, 1):
            return code == 0
        raise WorkspaceError(f"plimsoll: could not check whether {path!r} exists (exit {code}){': ' + err.strip() if err.strip() else ''}")

    def _realpath(self, path: str, env: _Environment) -> str:
        code, out, err = self._script(env, _REALPATH, path)
        if code != 0:
            raise OSError(f"plimsoll: cannot resolve {path!r}{': ' + err.strip() if err.strip() else ''}")
        return out.decode("utf-8", "surrogateescape")

    # ---- plimsoll's shell tool ----

    def _shell(self, command: str, budget: float, cancel: CancelHandle) -> Any:
        return self._in_thread(lambda env: _with_capacity_retry(lambda: env.workspace.exec(command, timeout=budget, cancel=cancel)))


# ---- durable execution, refused ----


def _in_durable_unit() -> bool:
    """Whether this task runs a durable unit's body (a tool or operation Temporal, DBOS or Prefect runs), as
    PydanticAI marks it (``pydantic_ai.durable_exec._operation_backend.in_durable_unit``, a private name read at the
    pinned pydantic-ai-slim; a test checks it is there). A PydanticAI without the name is refused: read as "not
    durable" (as it was until 2026-11-20), a durable run would go on unrefused."""
    try:
        from pydantic_ai.durable_exec._operation_backend import in_durable_unit
    except ImportError as e:
        raise ImportError(
            "plimsoll_client.pydantic_ai: this pydantic-ai has no pydantic_ai.durable_exec._operation_backend."
            "in_durable_unit, the mark that says a run is a durable unit's body; without it a durable run could not "
            "be refused, so no run is started. It was checked on pydantic-ai-slim 2.70.0"
        ) from e
    return bool(in_durable_unit())


def durable_run(ctx: Any) -> Optional[str]:
    """What makes this run a durable one, or ``None``: a durable unit's body, or a durability capability of
    PydanticAI's that says the run is inside its workflow or flow. Read from the run context only, without
    importing an engine: ``RunContext.in_durable_context`` asks the agent's durability capability
    (pydantic_ai/_run_context.py:593 at pydantic-ai-slim 2.70.0). ``ctx.capabilities`` cannot answer this: it is
    empty when PydanticAI asks ``get_workspace`` (measured on 2.70.0, finding release-96)."""
    if _in_durable_unit():
        return "a durable unit"
    if getattr(ctx, "in_durable_context", False) is not True:
        return None
    base = getattr(sys.modules.get("pydantic_ai.durable_exec._base"), "BaseDurabilityCapability", None)
    durability = base.from_agent(ctx.agent) if base is not None and getattr(ctx, "agent", None) is not None else None
    return type(durability).__name__ if durability is not None else "a durable workflow"


_DURABLE_REFUSAL = (
    "plimsoll: PlimsollWorkspace does not support durable execution ({what}), and refuses it before anything runs. "
    "Under Temporal, DBOS or Prefect a workspace call may run again after its answer was lost, and every call rebuilds "
    "the backend in whichever worker runs it. A checkpoint store narrows that (a lost call is named at the takeover, "
    "and the model's next tool call is not run: the model is told of the lost call first), but no engine's own test "
    "runs against this package yet. Run the agent without durable execution for now."
)


# ---- the capability ----


def _seconds(what: str, value: Any, *, optional: bool = False) -> Optional[float]:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not value == value or value in (float("inf"),) or value <= 0:
        raise ValueError(f"plimsoll: {what} must be a positive number of seconds, not {value!r}")
    return float(value)


def _format(out: Any, max_chars: int) -> Tuple[str, bool]:
    stdout, stderr = out.stdout_text, out.stderr_text
    cut = out.stdout_truncated or out.stderr_truncated or len(stdout) > max_chars or len(stderr) > max_chars
    head = f"exit code: {out.exit_code}"
    if out.timed_out:
        head += " (the command ran past its time budget and was stopped)"
    parts = [head]
    if stdout:
        parts.append(stdout[:max_chars].rstrip("\n"))
    if stderr:
        parts.append("stderr:\n" + stderr[:max_chars].rstrip("\n"))
    if cut:
        parts.append("[output truncated]")
    return "\n".join(parts), cut


def _labels(result: ProjectResult) -> Dict[str, str]:
    return _closed_set_labels({
        "outcome": result.outcome,
        "isolation": result.isolation,
        "isolation_qualification": result.isolation_qualification,
        "record_sha256": result.record.sha256 if result.record is not None else "",
    })


@dataclass(kw_only=True)
class PlimsollWorkspace(AbstractCapability[AgentDepsT]):
    """Supplies one plimsoll session as a run's workspace, created on the run's first workspace operation, and
    plimsoll's shell tool over it.

    ``client`` is a :class:`plimsoll_client.Client` (the backend runs its calls in worker threads).
    ``minimum_isolation`` (``process``, ``container``, ``kernel`` or ``vm``) is the tier the session must state;
    it has no default. ``daemon`` names this daemon in refs (``<daemon>/<fingerprint>``): a ref naming another
    daemon, or another provider, is left to other capabilities. ``owner`` is a function of the run context that
    names the application's verified end user, sent as plimsoll's keyed owner digest (a daemon's per-owner cap
    applies) and required to match when a later run reaches an open session by its ref. ``lifetime`` (seconds)
    may only shorten the daemon's own session lifetime; ``timeout`` is each call's budget and ``max_timeout``
    caps it. ``shell_tool`` adds ``plimsoll_shell``; ``max_output_chars`` cuts its stdout and stderr, each.
    ``record_sink`` receives every record the client checked (by default they are kept on the backends);
    ``languages`` hints which interpreters a daemon with a warm pool should have ready.

    ``checkpoint_store`` and ``checkpoint_key`` (both or neither) let a backend in another process carry the
    session on: every call passes through the store (:mod:`plimsoll_client.checkpoint`), and a backend rebuilt from
    the ref in a process that does not hold the session takes it over from the store. ``checkpoint_key`` is a
    function of the run context returning the store key: derive it from identities the application verified (the
    user and the conversation), never from model or user text. The client's ``daemon_name`` must be ``daemon``.
    """

    client: Client
    minimum_isolation: str
    daemon: str = "plimsoll"
    owner: Optional[Callable[[Any], Optional[str]]] = None
    lifetime: float = 3600.0
    timeout: float = 120.0
    max_timeout: Optional[float] = None
    shell_tool: bool = True
    max_output_chars: int = MAX_OUTPUT_CHARS
    record_sink: Optional[Callable[[RunRecord], None]] = None
    languages: Optional[Sequence[str]] = None
    checkpoint_store: Optional[CheckpointStore] = None
    checkpoint_key: Optional[Callable[[Any], str]] = None

    _open: Dict[str, _Environment] = field(default_factory=dict, init=False, repr=False, compare=False)
    _open_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.defer_loading:
            raise UserError("PlimsollWorkspace does not support defer_loading=True: the workspace is selected before deferred capabilities load.")
        if isinstance(self.client, AsyncClient) or not isinstance(self.client, Client):
            raise TypeError("plimsoll: PlimsollWorkspace needs a plimsoll_client.Client (the backend runs each call in a worker thread)")
        if not v.floor(self.minimum_isolation):
            raise ValueError("plimsoll: a workspace needs a floor: minimum_isolation process, container, kernel or vm")
        if not isinstance(self.daemon, str) or not self.daemon or "/" in self.daemon:
            raise ValueError("plimsoll: daemon must be a non-empty name without '/'")
        self.lifetime = _seconds("lifetime", self.lifetime)  # type: ignore[assignment]
        self.timeout = _seconds("timeout", self.timeout)  # type: ignore[assignment]
        self.max_timeout = _seconds("max_timeout", self.max_timeout, optional=True)
        self.max_output_chars = ct.check_max_output(self.max_output_chars)
        self.languages = v.languages(self.languages) or None
        if (self.checkpoint_store is None) != (self.checkpoint_key is None):
            raise ValueError("plimsoll: checkpoint_store and checkpoint_key go together")
        if self.checkpoint_store is not None and self.client.daemon_name != self.daemon:
            raise ValueError(
                f"plimsoll: with a checkpoint store the client's daemon_name must be this capability's daemon {self.daemon!r}"
            )

    @classmethod
    def get_serialization_name(cls) -> Optional[str]:
        return None  # not spec-serializable: it holds a client

    # ---- the registry of open sessions, in this process ----

    def _register(self, env: _Environment) -> None:
        with self._open_lock:
            self._open[env.ref.id] = env

    def _forget(self, env: _Environment) -> None:
        with self._open_lock:
            if self._open.get(env.ref.id) is env:
                del self._open[env.ref.id]

    def _lookup(self, ref: WorkspaceRef, owner: Optional[str]) -> Optional[_Environment]:
        with self._open_lock:
            env = self._open.get(ref.id)
        if env is None or env.owner != owner:
            return None  # the same answer for a session another owner opened: nothing says it exists
        if env.session.ended is not None:
            self._forget(env)
            return None
        return env

    def _owns(self, ref: WorkspaceRef) -> bool:
        return ref.provider == PROVIDER and ref.id.split("/", 1)[0] == self.daemon

    def backend(self, ref: Optional[WorkspaceRef] = None, *, owner: Optional[str] = None, key: Optional[str] = None) -> PlimsollWorkspaceBackend:
        """A backend, with no I/O: without ``ref`` it opens a fresh session on its first operation; with one it
        reaches the session ``ref`` names, open in this process and opened for the same ``owner``, or, with a
        checkpoint store, takes it over from the store under ``key``; else it raises
        :class:`PlimsollWorkspaceGoneError` on its first operation. ``key`` is the store key
        (``checkpoint_key(ctx)`` in a run)."""
        if ref is not None and not self._owns(ref):
            raise ValueError(f"plimsoll: {ref!r} is not a ref of this capability's daemon {self.daemon!r}")
        return PlimsollWorkspaceBackend(self, ref=ref, owner=owner, key=key)

    def destroy(self, ref: WorkspaceRef) -> Optional[SessionSummary]:
        """Closes the session ``ref`` names, when it is open in this process (``None`` otherwise): its sandbox and
        files are gone, and every backend that reaches it raises :class:`PlimsollWorkspaceGoneError` from then on."""
        with self._open_lock:
            env = self._open.pop(ref.id, None)
        if env is None:
            return None
        return env.session.close()

    # ---- AbstractCapability ----

    def get_workspace(self, ctx: RunContext[AgentDepsT], *, ref: Optional[WorkspaceRef]) -> Optional[PlimsollWorkspaceBackend]:
        what = durable_run(ctx)
        if what is not None:
            raise UserError(_DURABLE_REFUSAL.format(what=what))
        if ref is not None and not self._owns(ref):
            return None
        owner = self.owner(ctx) if self.owner is not None else None
        if owner is not None and not isinstance(owner, str):
            raise UserError("plimsoll: owner(ctx) must return a str or None")
        key = None
        if self.checkpoint_key is not None:
            key = self.checkpoint_key(ctx)
            if not isinstance(key, str) or not key:
                raise UserError("plimsoll: checkpoint_key(ctx) must return a non-empty str")
        return PlimsollWorkspaceBackend(self, ref=ref, owner=owner, key=key)

    def get_toolset(self) -> Optional[FunctionToolset[AgentDepsT]]:
        if not self.shell_tool:
            return None
        return FunctionToolset([Tool(self._plimsoll_shell, name="plimsoll_shell", takes_ctx=True,
                                     description=self._shell_description())], id="plimsoll_shell")

    def _shell_description(self) -> str:
        return (
            f"Run a shell command in this conversation's plimsoll sandbox, isolated at the {self.minimum_isolation} isolation "
            "tier or stronger, and return its exit code, stdout and stderr. The shell is the sandbox image's sh (BusyBox sh "
            "on plimsoll's docker images). It works on the same files as the file tools. Files, the working directory and "
            "exported variables persist from one command to the next; a process left running in the background is stopped "
            "when its command returns, so start nothing you mean to keep running, and a background process that keeps its "
            "output open makes the command wait until it exits or the command's time budget ends (redirect its output to "
            "a file). There is no network access unless the operator of the sandbox granted it."
        )

    async def _plimsoll_shell(self, ctx: RunContext[Any], command: str) -> ToolReturn:
        """Run a shell command in the sandbox and return its exit code, stdout and stderr."""
        try:
            _check_text("command", command, allow_newline=True)
        except (TypeError, ValueError) as e:
            raise ModelRetry(f"plimsoll: {e}; nothing was sent") from e
        if _in_durable_unit():
            raise UserError(_DURABLE_REFUSAL.format(what="a durable unit"))
        workspace = ctx.workspace
        backend = workspace.backend
        if not isinstance(backend, PlimsollWorkspaceBackend) or backend._capability is not self:
            raise UserError("plimsoll: the plimsoll_shell tool needs this run's workspace to be its PlimsollWorkspace's session")
        if workspace.read_only:
            raise UserError("plimsoll: the run's workspace is read-only, and plimsoll_shell can change it")
        budget = self.timeout
        if self.max_timeout is not None and budget > self.max_timeout:
            budget = self.max_timeout
        handle = CancelHandle()
        try:
            # Abandoned on cancel, with the call cut: a command may run for its whole budget. A cut call may have
            # run, so the session then sends nothing more.
            out = await anyio.to_thread.run_sync(partial(backend._shell, command, budget, handle), abandon_on_cancel=True)
        except anyio.get_cancelled_exc_class():
            handle.cancel()
            raise
        except PlimsollLostCallError as e:
            # The first operation after a takeover across a lost call: the command was not sent, the backend resolved
            # the session, and the model gets a failed tool result saying what plimsoll's record of the lost call says
            # (and its output, when its answer came back); the run goes on. Every call that may have run still ends
            # the run.
            raise ToolFailed(str(e)) from e
        text, cut = _format(out, self.max_output_chars)
        metadata = {"exit_code": out.exit_code, "timed_out": out.timed_out, "truncated": cut, **_labels(out.result)}
        return ToolReturn(return_value=text, metadata=metadata)


# ---- the stateless code tool ----


def plimsoll_code_tool(
    executor: CodeExecutor,
    *,
    languages: Sequence[str] = ("python",),
    name: str = ct.TOOL_NAME,
    max_output_chars: int = ct.MAX_OUTPUT_CHARS,
) -> Tool[Any]:
    """PydanticAI tool ``plimsoll_run_code`` (code, language, input_files): every call runs in a fresh sandbox
    through ``executor``, which sets the isolation floor, the time budget and the software rule; nothing persists
    between calls. ``languages`` are the languages offered, the first being the default; offer only what the
    daemon's project image runs. ``max_output_chars`` cuts stdout and stderr, each.

    The tool answers with the dict ``plimsoll_client._code_tool`` describes, for a result, a refusal and an
    unknown outcome alike, and never raises (a refusal is information for the model; a call that may have run says
    ``ran: "unknown"`` and was not retried). The answer's ``metadata`` (a ``ToolReturn``'s, which the model is not
    sent) carries plimsoll's labels for the application. The call runs in a worker thread; canceling the await
    cancels the call."""
    if not isinstance(executor, CodeExecutor):
        raise TypeError("plimsoll: plimsoll_code_tool needs a plimsoll_client.execution.CodeExecutor")
    langs = ct.offered(executor, languages)
    max_chars = ct.check_max_output(max_output_chars)
    schema = {
        "type": "object",
        "properties": {
            "code": {"type": "string", "description": ct.CODE_HELP},
            "language": {"type": "string", "enum": list(langs), "default": langs[0], "description": f'{ct.LANGUAGE_HELP} Default "{langs[0]}".'},
            "input_files": {
                "type": "array",
                "description": ct.FILES_HELP,
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": ct.PATH_HELP},
                        "content": {"type": "string", "description": ct.CONTENT_HELP},
                    },
                    "required": ["path", "content"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["code"],
        "additionalProperties": False,
    }

    async def _run_code(code: Any = None, language: Any = None, input_files: Any = None) -> ToolReturn:
        handle = CancelHandle()
        try:
            answer = await anyio.to_thread.run_sync(
                partial(ct.run, executor, langs, max_chars, code, language, input_files, cancel=handle), abandon_on_cancel=True
            )
        except anyio.get_cancelled_exc_class():
            handle.cancel()
            raise
        return ToolReturn(return_value=answer, metadata=_closed_set_labels(answer))

    return Tool.from_schema(_run_code, name=name, description=ct.description(langs, executor.grant), json_schema=schema)
