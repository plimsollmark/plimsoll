"""An agent workspace: a shell, files and search over one plimsoll session.

A :class:`Workspace` gives an agent framework what its tools need from a sandbox (run a
command, read and write files, search, carry the working directory and the exported
variables from one command to the next, save and restore the whole tree) over one
plimsoll session. Every framework adapter in this package is a naming layer over it,
so the daemon's guarantees hold the same for each: the isolation floor the session was
opened with, a run record on every call, no network unless a call carries a grant (a
Workspace call never does).

Mechanism. **Every file operation is one file call of the session**
(``Session.run_files``, :mod:`plimsoll_client.files`): plimsoll's own helper carries it
out inside the sandbox as the guest's own user (docs/session-files.md), and its answer is
typed, so a missing file, a folder where a file was meant or a refused link comes back as
the Python error it names, never as a shell's words. No file method sends shell text.
A confined workspace names its paths in the ``work`` scope: relative to the work folder,
resolved by the kernel beneath it, a link followed only while it stays inside (one that
leaves is :class:`WorkspacePathError`). ``confined=False`` names every path in the
``sandbox`` scope: absolute, resolved as the guest's own shell resolves it.

**On a session that does not state the work scope** (``Session.file_scopes`` is
``("sandbox",)``: OpenShell's, whose work folder is not a mount of its own, so plimsoll's
helper refuses the work scope there), a confined workspace names its paths in the
``sandbox`` scope, as absolute paths under the work folder, and confines them by their
names alone: a path whose ``..`` leads out of the work folder, or an absolute path outside
it, is :class:`WorkspacePathError` before any call, as on every provider. **What it cannot
refuse there is a symbolic link inside the work folder that points outside it: the link is
followed**, as the guest's own shell follows it, so a read, a write or a listing through it
reaches wherever it points that the guest's own user may reach. The sandbox's walls are then
the boundary, not the work folder. Each call's record names the scope it used, so no record
claims the work scope's confinement for such a call.

Commands are project calls (``Session.run_project``: the call's files are written into
the work directory, then its steps run through the runner). **A step is one of the
fixed scripts in this module, never assembled from the text an agent supplied**: the
command and every argument travel as files under ``.plimsoll-shell/`` in the work
directory (``cmd``, ``run``, ``in.b64``), which the daemon writes before the step runs
and the step reads back, so nothing an agent writes can change what a step is. The
shell's working directory and its exported variables persist between commands through
two files there, ``cwd`` and ``env``, which the exec script restores before the command
and saves after it; a session that is suspended and resumed keeps them. ``grep``,
``persist`` and ``hydrate`` run one program each through :meth:`Workspace.run` (``grep``
and ``tar``, every argument passed as given); ``persist`` and ``hydrate`` move the
archive itself by file calls.

What a command gives up against a shell kept as a process: a process it leaves in the
background is killed when the call ends (the session's sweep), ``exit`` in a command
ends the step before the state is saved (the state is then what it was), a syntax
error fails the step, and the output limits are the daemon's, reported by the
truncation flags on the outcome. Paths are resolved against the work directory, not
the shell's current directory, as the agent tool sets of Anthropic and OpenAI do; an
absolute path is accepted when it lies inside the work directory.

Calls of one Workspace are serialized by the session; an operation made of several
calls (``edit``, a write past 4 MiB, a read past 8 MiB, ``persist``, ``hydrate``) is not
atomic against another thread's, nor against the guest's own processes.

Two uses that are not an agent's shell. :meth:`Workspace.run` runs one program, each
argument passed as given and never parsed by a shell, with an environment and a stdin of
its own and outside the shell's saved directory and exports (the script that starts it
travels as a file too, ``run``, sets nothing a later ``exec`` sees, and is deleted, with
the stdin copy, before the program starts). And a Workspace
made with ``confined=False`` lets the file methods take an absolute path anywhere in
the sandbox, for a caller that is not an agent and needs a file outside the work directory
(a harness staging an archive in ``/tmp``): the sandbox, not the work directory, is then
the boundary.
"""

from __future__ import annotations

import base64
import errno
import heapq
import os
import posixpath
import re
import secrets
import shlex
from dataclasses import dataclass
from typing import Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from . import _validate as v
from . import files as fs
from ._transport import CancelHandle
from .errors import InvalidRequestError, PlimsollError
from .types import ProjectResult, SessionSummary

__all__ = ["ExecOutcome", "Workspace", "WorkspaceCallError", "WorkspaceChangedError", "WorkspacePathError", "WorkspaceTooLargeError",
           "STATE_DIR", "MAX_READ_BYTES", "MAX_WHOLE_BYTES", "MAX_WRITE_BYTES", "STEP_KINDS", "close_quietly"]

#: The directory in the work directory that carries each command's arguments and the
#: shell's state. Never captured by ``persist``, never listed by ``glob`` or ``grep``, and
#: refused as a path by every file method.
STATE_DIR = ".plimsoll-shell"

#: The most one file call reads: a ``read``'s ``max_bytes`` at most, and each piece of a
#: longer read (the helper's own bound, docs/session-files.md).
MAX_READ_BYTES = fs.MAX_READ

#: The most one file call writes: a ``write`` past it is several calls (see its docstring).
MAX_WRITE_BYTES = fs.MAX_WRITE

#: The most a whole-file read (``read_whole``, ``read_pieces``) and ``persist`` take unless
#: their caller names another limit: 64 MiB, eight pieces. A whole read ends in the caller's
#: memory, and code in the sandbox can make a file of any size for nothing (a sparse file
#: takes no disk), so without a limit an agent's read could make the developer's process
#: hold all of it. 64 MiB is far past the text any model's context takes in one tool answer
#: and small beside the memory of a process that runs an agent.
MAX_WHOLE_BYTES = 64 << 20

# What one read_many call of :meth:`Workspace.read_many` names: at most 16,384 paths (the
# helper's own cap, docs/session-files.md) and at most 4 MiB of path bytes. The request carries
# each path in base64 (4/3 of its bytes) under the daemon's 8 MiB request cap (cmd/plimsolld,
# maxRequestBytes), and a path can be 4,096 bytes (longer still on a session that states the
# sandbox scope alone, where it travels absolute), so 16,384 long paths would be a request the
# daemon refuses; 4 MiB of paths is at most about 5.4 MiB on the wire. The Agent Framework
# store batches its search by the same two bounds.
_READ_MANY_PATHS = 16384
_READ_MANY_PATH_BYTES = 4 << 20

# The fixed scripts. Each begins by naming the state directory from the runner's
# working directory, which is the work directory, and never from an agent's file. The
# variable names are kept out of the saved environment, so a command that exports
# them cannot change where a later step keeps its state.
_PRELUDE = '__plimsoll_s="$PWD/' + STATE_DIR + '"; mkdir -p "$__plimsoll_s"; '
_EXEC_STEP = (
    _PRELUDE
    + '[ -f "$__plimsoll_s/env" ] && . "$__plimsoll_s/env"; '
    + '[ -f "$__plimsoll_s/cwd" ] && cd "$(cat "$__plimsoll_s/cwd")" 2>/dev/null; '
    + '. "$__plimsoll_s/cmd"; __plimsoll_rc=$?; '
    + "export -p | grep -Ev '^export (PWD|OLDPWD|__plimsoll_)' > \"$__plimsoll_s/env.new\"; "
    + 'mv "$__plimsoll_s/env.new" "$__plimsoll_s/env"; pwd > "$__plimsoll_s/cwd"; exit $__plimsoll_rc'
)
# The run script and the stdin copy are read, then deleted before the program starts: the
# script holds the environment's values (a setup step's credential, say), and nothing a
# later call runs may find them on disk. The open descriptor keeps stdin readable.
_RUN_STEP = (
    _PRELUDE
    + 'base64 -d "$__plimsoll_s/in.b64" > "$__plimsoll_s/in" || exit 125; '
    + 'exec < "$__plimsoll_s/in"; __plimsoll_r="$(cat "$__plimsoll_s/run")" || exit 125; '
    + 'rm -f "$__plimsoll_s/in" "$__plimsoll_s/in.b64" "$__plimsoll_s/run"; eval "$__plimsoll_r"'
)

#: What each fixed step does, by its text: a label for a log of a workspace's calls (a
#: call's record names its request by digest only). Only commands are project calls; a
#: file call names its operation itself (``FilesResult.op``, the request's class).
STEP_KINDS: Dict[str, str] = {
    _EXEC_STEP: "exec",
    _RUN_STEP: "run",
}

#: Every step this module sends, for a test that asserts no other text ever becomes a step.
FIXED_STEPS = frozenset(STEP_KINDS)

# An environment variable `run` may set: a shell name, so `export NAME=...` sets exactly it.
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_CMD = STATE_DIR + "/cmd"
_RUN = STATE_DIR + "/run"
_IN_B64 = STATE_DIR + "/in.b64"
_CWD = STATE_DIR + "/cwd"

GLOB_LIMIT = 200  # entries a glob returns at most: the first 200 in sorted order

# The page size of the listings glob and list ask for: 1 MiB of frames, about 20,000
# entries of 40-byte names a call.
_LIST_BUDGET = 1 << 20


class WorkspacePathError(ValueError):
    """A path the workspace refuses: outside the work directory, escaping it with
    ``..``, carrying a character a tool should never be handed, or (in the work scope) a
    symbolic link that leaves the work directory."""


class WorkspaceTooLargeError(RuntimeError):
    """A file or a tree past a limit: the caller's (``limit``), a call's (the most one read
    returns), or a listing's bounds inside the sandbox (``scan_limit``)."""


class WorkspaceChangedError(OSError):
    """A file read in pieces that changed size while it was read (another call of the
    session, or a process of the guest's, wrote it between two pieces): the pieces are not
    the file, so they are not returned."""


class WorkspaceCallError(RuntimeError):
    """A call the daemon answered whose result the workspace cannot use. For a command
    (a :class:`~plimsoll_client.types.ProjectResult`): it ended ``setup_failed`` (no step
    began), ``protocol_error`` or ``runner_failed``, or without a step's report. For a file
    call (a :class:`~plimsoll_client.files.FilesResult`): it ended ``protocol_error`` or
    ``runner_failed``, so it may have run and its answer is not known. ``result`` is the
    answer, checked like any other: its tier and its run record; both kinds have
    ``outcome``, with the same words."""

    def __init__(self, message: str, result: Union[ProjectResult, fs.FilesResult]) -> None:
        super().__init__(message)
        self.result = result


@dataclass(frozen=True)
class ExecOutcome:
    """What one command gave: its streams, exit code, whether the daemon cut either
    stream or ended the command at the call's budget, the shell's directory after it,
    and the call's full result (the tier it ran at, its run record)."""

    stdout: bytes
    stderr: bytes
    exit_code: int
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    cwd: str
    result: ProjectResult

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")


def _grep_key(line: str):
    """(file, line number, text) of a `file:line:text` line; a line in another shape
    sorts after the rest, by its text."""
    parts = line.split(":", 2)
    # ASCII digits only: str.isdigit is true of "²" too, which int() refuses, and a file
    # the sandbox names `x:²:y` makes such a line (finding release-47).
    if len(parts) == 3 and parts[1].isascii() and parts[1].isdigit():
        return (0, parts[0], int(parts[1]), parts[2])
    return (1, line, 0, "")


def _check_text(what: str, text: str, *, allow_newline: bool) -> str:
    if not isinstance(text, str):
        raise TypeError(f"{what} must be a str")
    if "\x00" in text:
        raise ValueError(f"{what} must not contain NUL")
    if not allow_newline and ("\n" in text or "\r" in text):
        raise ValueError(f"{what} must not contain a line break")
    return text


def close_quietly(closeable) -> None:
    """Closes a session or a workspace on a path that is already reporting another error (an open that failed, a
    floor check after it, the end of a run). A PlimsollError from the close is dropped: the session has ended
    already or is out of reach, and the daemon closes it at its lifetime either way. Any other error is raised.
    Every framework adapter in this package closes through this one (the review of the unread half, 2026-11-18,
    item 2: it was written five times)."""
    try:
        closeable.close()
    except PlimsollError:
        pass


def _check_limit(limit: Optional[int]) -> Optional[int]:
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 0):
        raise ValueError("limit must be a non-negative int of bytes, or None for none")
    return limit


def _as_text(path) -> str:
    """A path given as bytes is taken as ``os.fsdecode`` takes it (UTF-8, with
    ``surrogateescape``), so a name a listing returned round-trips byte for byte."""
    if isinstance(path, (bytes, bytearray)):
        return bytes(path).decode("utf-8", "surrogateescape")
    return path


def _check_path(path) -> str:
    path = _as_text(path)
    if not isinstance(path, str):
        raise WorkspacePathError("path must be a str")
    if path == "":
        raise WorkspacePathError("path is required")
    if "\x00" in path or "\n" in path or "\r" in path or "\\" in path:
        raise WorkspacePathError(f"unsafe path {path!r}")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in path):
        raise WorkspacePathError(f"unsafe path {path!r}")
    return path


def _in_state(rel: str) -> bool:
    return rel == STATE_DIR or rel.startswith(STATE_DIR + "/")


def _argv_script(argv: Sequence[str], env: Mapping[str, str]) -> str:
    """The script the run step sources: one export per variable, then exec of the
    program, every value quoted so the shell reads it back byte for byte."""
    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence) or len(argv) == 0:
        raise ValueError("argv must be a non-empty sequence of str")
    # After `exec`, bash reads a leading - as its own option and dash has no `--` to stop
    # that, so such a program name could run something else: refused.
    if isinstance(argv[0], str) and argv[0].startswith("-"):
        raise ValueError(f"program name {argv[0]!r} starts with -; name it by path (./{argv[0]})")
    lines = []
    for name, value in env.items():
        if not isinstance(name, str) or not _ENV_NAME.match(name):
            raise ValueError(f"environment variable name {name!r} is not a shell name")
        lines.append(f"export {name}={shlex.quote(_check_text('environment value', value, allow_newline=True))}")
    words = [shlex.quote(_check_text("argument", a, allow_newline=True)) for a in argv]
    lines.append("exec " + " ".join(words))
    return "\n".join(lines) + "\n"


# The Python error each answered file error names (docs/session-files.md, "Exit codes").
# SYMLINK, a link the work scope does not follow, is a path the workspace refuses.
_ERRORS = {
    "not_found": (FileNotFoundError, errno.ENOENT, "No such file or directory"),
    "is_dir": (IsADirectoryError, errno.EISDIR, "Is a directory"),
    "not_dir": (NotADirectoryError, errno.ENOTDIR, "Not a directory"),
    "exists": (FileExistsError, errno.EEXIST, "File exists"),
    "permission_denied": (PermissionError, errno.EACCES, "Permission denied"),
    "not_regular": (OSError, errno.ENXIO, "Not a regular file or a directory"),
    "too_large": (OSError, errno.EFBIG, "File too large"),
    "no_space": (OSError, errno.ENOSPC, "No space left on device"),
    "read_only": (OSError, errno.EROFS, "Read-only file system"),
    "not_empty": (OSError, errno.ENOTEMPTY, "Directory not empty"),
}


# What tar in the sandbox prints when a write fails for room: the C library's text for
# ENOSPC (glibc's and musl's alike), the one signal there is, since tar's exit code (2)
# is the same for every fatal error. A row of internal/outsidefacts/facts.json
# (py-tar-no-space-words) holds the fact; another wording leaves tar's own error.
_TAR_NO_SPACE = "No space left on device"


def _tar_out_of_room(out: "ExecOutcome") -> bool:
    return out.exit_code != 0 and _TAR_NO_SPACE in out.stderr_text


def _file_error(error: str, errno_name: str, path: str) -> Exception:
    """The exception an answered file error is: the Python error its code names, carrying
    the errno, with the path the caller gave (never text from the sandbox)."""
    if error == "symlink":
        return WorkspacePathError(f"{path!r} goes through a symbolic link the sandbox would not follow: one that leaves the work directory, or a loop")
    if error == "scan_limit":
        return WorkspaceTooLargeError(f"{path}: the listing passed one of its bounds inside the sandbox; list a folder further down")
    # An errno the error has no word of its own for is read by its name, which the answer
    # carries: only a name the errno module holds as a number (never its errorcode table or
    # a dunder an answer could name), else EIO.
    named = getattr(errno, errno_name, None) if errno_name else None
    cls, code, words = _ERRORS.get(error, (OSError, named if type(named) is int else errno.EIO, ""))
    if not words:
        words = os.strerror(code)
    return cls(code, words, path)


class Workspace:
    """Shell, files and search over one open :class:`~plimsoll_client.client.Session`.

    ``timeout`` (seconds) is the budget of a command whose ``exec`` names none, and of
    every other call; ``max_timeout`` caps any budget asked for, for a daemon whose
    ceiling is known (``Info.project_environment.max_timeout_ms``). The docker provider
    cuts a budget past its own ceiling to that ceiling rather than refusing it: measured on
    2026-11-18, a session call asking 600 s of a 125-second command on a daemon whose
    project ceiling is 120 s ended ``timed_out`` after 120.3 s (exit 124), so a long budget
    can end a command early with no error. ``confined=False`` lets the file methods take an
    absolute path outside the work directory (see the module docstring); everything else
    stays inside it.

    The session must take file calls (``Session.file_scopes``; docker, E2B and OpenShell
    sessions do): on one that does not, every file method raises the daemon's refusal,
    :class:`~plimsoll_client.UnsupportedError`, with nothing run. Where the session states
    the ``sandbox`` scope alone (OpenShell's), a confined workspace checks its paths by their
    names and **follows a link inside the work directory that points outside it** (see the
    module docstring).
    """

    def __init__(self, session, *, timeout: float = 120.0, max_timeout: Optional[float] = None, confined: bool = True) -> None:
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        if max_timeout is not None and (not isinstance(max_timeout, (int, float)) or max_timeout <= 0):
            raise ValueError("max_timeout must be a positive number of seconds")
        self._session = session
        self._timeout = float(timeout)
        self._max_timeout = float(max_timeout) if max_timeout is not None else None
        self._confined = bool(confined)
        self._asked_root: Optional[str] = None

    @property
    def session(self):
        return self._session

    def __enter__(self) -> "Workspace":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> SessionSummary:
        """Closes the session; the sandbox and everything in it are gone."""
        return self._session.close()

    # ---- the work directory ----

    @property
    def root(self) -> str:
        """The work directory's absolute path in the sandbox, as the session's open stated
        it (``Session.work_dir``): no call. Every session that takes file calls states it
        (docker's and E2B's ``/work``, OpenShell's ``/tmp/work``). A session whose open stated
        none, one that takes no file calls (the in-memory session daemon of the client suites,
        a daemon from before file calls), is asked once, by running ``pwd`` through
        :meth:`run`: its file methods are refused, but :meth:`run` and :meth:`exec` work there,
        and an adapter (the ADK environment) names the folder to its model."""
        root = getattr(self._session, "work_dir", "") or ""
        if root:
            return root
        if self._asked_root is None:
            out = self.run(["pwd"])
            text = out.stdout_text.strip()
            if out.exit_code != 0 or not text.startswith("/") or "\n" in text:
                raise RuntimeError("plimsoll: the sandbox did not report its work directory")
            self._asked_root = text
        return self._asked_root

    def resolve(self, path: str) -> str:
        """The work-directory-relative form of ``path``: a relative path is taken from
        the work directory (``.`` is the directory itself); an absolute path must lie
        inside it. Raises :class:`WorkspacePathError` otherwise."""
        path = _check_path(path)
        rel = path
        if rel.startswith("/"):
            root = self.root
            # Normalized before it is compared, so `/work//etc` (whose rest, `/etc`, is
            # absolute) and `/work/a/../../etc` are outside, as they are to the sandbox
            # (finding release-47). normpath keeps a leading `//`, which POSIX leaves to the
            # system; Linux reads it as `/`.
            rel = "/" + posixpath.normpath(rel).lstrip("/")
            if rel == root:
                return "."
            if not rel.startswith(root + "/"):
                raise WorkspacePathError(f"{path!r} is outside the work directory {root}")
            rel = rel[len(root) + 1 :]
        rel = posixpath.normpath(rel)
        if rel == ".":
            return "."
        if rel == ".." or rel.startswith("../"):
            raise WorkspacePathError(f"{path!r} escapes the work directory")
        return rel

    def _path(self, path, *, folder: bool) -> str:
        """``path`` as the workspace names it: relative to the work directory, or, in an
        unconfined workspace, absolute when it lies outside it. The work directory itself
        (``.``) only where a folder is meant; the state directory never."""
        path = _check_path(path)
        if not self._confined and path.startswith("/"):
            full = "/" + posixpath.normpath(path).lstrip("/")
            root = self.root
            if full != root and not full.startswith(root + "/"):
                if full == "/" and not folder:
                    raise WorkspacePathError("/ is not a file")
                return full
            path = full
        rel = self.resolve(path)
        if rel == "." and not folder:
            raise WorkspacePathError("the work directory itself is not a file")
        if _in_state(rel):
            raise WorkspacePathError(f"{STATE_DIR} is the workspace's own state")
        return rel

    def _work_scope(self) -> bool:
        """Whether a confined workspace names its paths in the work scope: where the session
        states it, and where the session states no scope the client knows (or is not a
        client session), so the daemon's own answer, the refusal of a session that takes no
        file calls, is the one the caller meets. A session that states the sandbox scope
        alone (OpenShell's) gets the sandbox scope, with the names checked here
        (:meth:`resolve`)."""
        scopes = getattr(self._session, "file_scopes", None)
        if not scopes:
            return True
        return "work" in scopes or "sandbox" not in scopes

    def _target(self, rel: str) -> Tuple[bytes, str]:
        """The bytes and scope a file call names ``rel`` by: the work scope in a confined
        workspace whose session states it, the sandbox scope (an absolute path) in an
        unconfined one and in a confined one whose session states the sandbox scope alone.
        ``rel`` has passed :meth:`resolve` (``..`` resolved by its name, nothing out of the work
        directory), so in the latter the absolute path stays under the work directory by its
        name; a link inside it is followed wherever it points."""
        if rel.startswith("/"):
            return fs.path_bytes(rel), "sandbox"
        if self._confined and self._work_scope():
            return fs.path_bytes(rel), "work"
        root = self.root
        return fs.path_bytes(root if rel == "." else root + "/" + rel), "sandbox"

    # ---- commands ----

    def exec(self, command: str, *, timeout: Optional[float] = None, cancel: Optional[CancelHandle] = None) -> ExecOutcome:
        """Runs ``command`` as shell text (BusyBox ``sh`` on the docker images) in the
        shell's current directory with its exported variables, and keeps both for the
        next command. A non-zero exit is an outcome, not an error. ``cancel`` stops a
        call not yet sent and cuts one in flight."""
        _check_text("command", command, allow_newline=True)
        result = self._call({_CMD: command}, [_EXEC_STEP], [_CWD], timeout, tolerate_timeout=True, cancel=cancel)
        step = result.steps[0]
        cwd = self._artifact_text(result, _CWD)
        if cwd is None:
            cwd = getattr(self._session, "work_dir", "") or ""
        return ExecOutcome(
            stdout=step.stdout,
            stderr=step.stderr,
            exit_code=step.exit_code,
            timed_out=step.timed_out or result.outcome == "timed_out",
            stdout_truncated=step.stdout_truncated,
            stderr_truncated=step.stderr_truncated,
            cwd=cwd,
            result=result,
        )

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Optional[Mapping[str, str]] = None,
        stdin: Union[str, bytes, bytearray, None] = None,
        timeout: Optional[float] = None,
        cancel: Optional[CancelHandle] = None,
    ) -> ExecOutcome:
        """Runs the program ``argv`` in the work directory: each argument reaches it as
        given (no shell parses one), ``env`` is added to the sandbox's environment,
        ``stdin`` is its whole input (None: an empty one), and the shell ``exec`` keeps
        sees nothing of it, neither a directory change nor an export. A non-zero exit is
        an outcome, not an error; a program that is not found exits 127."""
        script = _argv_script(argv, env or {})
        if stdin is None:
            data = b""
        elif isinstance(stdin, str):
            data = _check_text("stdin", stdin, allow_newline=True).encode("utf-8")
        elif isinstance(stdin, (bytes, bytearray)):
            data = bytes(stdin)
        else:
            raise TypeError("stdin must be str, bytes or None")
        encoded = base64.b64encode(data).decode("ascii")
        if len(script.encode("utf-8")) + len(encoded) > v.MAX_PROJECT_BYTES - 1024:
            raise WorkspaceTooLargeError("the program's arguments, environment and stdin are past one call's files budget")
        result = self._call({_RUN: script, _IN_B64: encoded}, [_RUN_STEP], [], timeout, tolerate_timeout=True, cancel=cancel)
        step = result.steps[0]
        return ExecOutcome(
            stdout=step.stdout,
            stderr=step.stderr,
            exit_code=step.exit_code,
            timed_out=step.timed_out or result.outcome == "timed_out",
            stdout_truncated=step.stdout_truncated,
            stderr_truncated=step.stderr_truncated,
            cwd=getattr(self._session, "work_dir", "") or "",
            result=result,
        )

    # ---- files ----

    def read(self, path: str, *, max_bytes: int = 1 << 20, offset: int = 0, cancel: Optional[CancelHandle] = None) -> bytes:
        """At most ``max_bytes`` (at most :data:`MAX_READ_BYTES`, 8 MiB) of the file at
        ``path``, from byte ``offset``; none past its end. One file call.
        FileNotFoundError when nothing is there, IsADirectoryError for a folder,
        PermissionError when the guest may not read it, OSError (``ENXIO``) for a FIFO, a
        socket or a device, which is never opened."""
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("max_bytes must be a positive int")
        if max_bytes > MAX_READ_BYTES:
            raise ValueError(f"max_bytes must be at most {MAX_READ_BYTES}, the most one file call reads")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a non-negative int")
        return self._read(self._path(path, folder=False), path, offset, max_bytes, cancel).content

    def _read(self, rel: str, shown, offset: int, max_bytes: int, cancel: Optional[CancelHandle]) -> fs.FilesReadAnswer:
        name, scope = self._target(rel)
        answer = self._files(fs.FilesRead(name, offset=offset, max_bytes=max_bytes, scope=scope), shown, cancel).answer
        assert isinstance(answer, fs.FilesReadAnswer)
        return answer

    def read_pieces(self, path: str, *, limit: Optional[int] = MAX_WHOLE_BYTES, cancel: Optional[CancelHandle] = None) -> Iterator[bytes]:
        """The whole file at ``path``, :data:`MAX_READ_BYTES` a call, each piece yielded as
        it arrives (an empty file yields none). A file of one piece is one call. Every read
        states the file's size as its open saw it, and each piece must state the size the
        first one did, and the pieces must add up to it: :class:`WorkspaceChangedError`
        otherwise, never a cut or spliced copy, since another call of the session or a
        process of the guest's can change the file between two pieces. A change that keeps
        the size is not seen. A file whose open states size 0 (an empty one, or one of the
        kernel's such as ``/proc/self/status``, whose stated size says nothing of its
        content) is read on until a piece comes back short. The errors of :meth:`read`,
        before any piece.

        ``limit`` (bytes, :data:`MAX_WHOLE_BYTES` by default, None for none) is the
        longest file it reads: a longer one is :class:`WorkspaceTooLargeError`, raised
        on the first piece's answer, before anything is yielded or any other piece read."""
        yield from self._pieces(self._path(path, folder=False), path, stop=None, limit=_check_limit(limit), cancel=cancel)

    def read_whole(self, path: str, *, limit: Optional[int] = MAX_WHOLE_BYTES, cancel: Optional[CancelHandle] = None) -> bytes:
        """The whole file at ``path``: :meth:`read_pieces` joined, with its ``limit``
        (:data:`MAX_WHOLE_BYTES`, 64 MiB, unless the caller names another)."""
        return b"".join(self.read_pieces(path, limit=limit, cancel=cancel))

    def read_head(self, path: str, max_bytes: int, *, cancel: Optional[CancelHandle] = None) -> bytes:
        """The first ``max_bytes`` of the file at ``path`` (all of it when it is shorter),
        for any ``max_bytes``: read in pieces as :meth:`read_pieces` reads, checked against
        the smaller of ``max_bytes`` and the size each read states, so a file that changed
        while it was read is :class:`WorkspaceChangedError`, never a cut copy.
        ``max_bytes`` bounds what it holds."""
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("max_bytes must be a positive int")
        return b"".join(self._pieces(self._path(path, folder=False), path, stop=max_bytes, limit=None, cancel=cancel))

    def _pieces(self, rel: str, shown, *, stop: Optional[int], limit: Optional[int], cancel: Optional[CancelHandle]) -> Iterator[bytes]:
        """The file from its start: up to ``stop`` bytes (None: the whole file), refusing a
        whole file longer than ``limit`` (None: no limit)."""
        ask = MAX_READ_BYTES if stop is None else min(stop, MAX_READ_BYTES)
        first = self._read(rel, shown, 0, ask, cancel)
        size = first.size_at_open
        if size == 0:
            yield from self._unsized(rel, shown, first, ask, stop=stop, limit=limit, cancel=cancel)
            return
        if limit is not None and max(size, len(first.content)) > limit:
            raise WorkspaceTooLargeError(
                f"{shown}: {max(size, len(first.content))} bytes, past the {limit} a whole read takes; read it in parts with read and an offset"
            )
        target = size if stop is None else min(size, stop)
        got = len(first.content)
        changed = got > target  # more bytes than its open counted: it grew while it was read
        if first.content and not changed:
            yield first.content
        while not changed and got < target:
            # Never past the target: a piece that would hold bytes the first answer did not
            # count is not asked for, so a file that grows is seen by its stated size.
            try:
                piece = self._read(rel, shown, got, min(MAX_READ_BYTES, target - got), cancel)
            except FileNotFoundError:
                break  # removed after its first piece: the size check below says it changed
            if piece.size_at_open != size:
                changed = True
                break
            if not piece.content:
                break
            got += len(piece.content)
            yield piece.content
        if changed or got != target:
            raise WorkspaceChangedError(errno.EIO, f"the file changed while it was read ({size} bytes when its first piece was read)", shown)

    def _unsized(self, rel: str, shown, first: fs.FilesReadAnswer, ask: int, *, stop: Optional[int], limit: Optional[int],
                 cancel: Optional[CancelHandle]) -> Iterator[bytes]:
        """The rest of _pieces for a file whose open stated size 0: an empty file, or one of
        the kernel's (/proc/self/status) whose size says nothing of its content, which the
        helper reads to its end all the same. There is no size to check the pieces against,
        so it reads on until a piece comes back shorter than asked (the end), each piece's
        open stating 0 too; one stating a size is a file that changed. A regular file that
        grew from empty while it was read is therefore read as it grew. ``limit`` is checked
        as the bytes arrive, so on a file past it the pieces before the refusal were already
        yielded."""
        got, piece = 0, first
        while True:
            if piece.size_at_open != 0:
                raise WorkspaceChangedError(errno.EIO, f"the file changed while it was read (0 bytes when its first piece was read, {piece.size_at_open} at a later one)", shown)
            got += len(piece.content)
            if limit is not None and got > limit:
                raise WorkspaceTooLargeError(f"{shown}: more than the {limit} bytes a whole read takes; read it in parts with read and an offset")
            if piece.content:
                yield piece.content
            if len(piece.content) < ask or (stop is not None and got >= stop):
                return
            ask = MAX_READ_BYTES if stop is None else min(stop - got, MAX_READ_BYTES)
            try:
                piece = self._read(rel, shown, got, ask, cancel)
            except FileNotFoundError:
                raise WorkspaceChangedError(errno.EIO, "the file changed while it was read (removed after its first piece)", shown) from None

    def write(self, path: str, content: Union[str, bytes, bytearray], *, cancel: Optional[CancelHandle] = None) -> None:
        """Writes ``content`` (text as UTF-8, or bytes) to the file at ``path``, making the
        folders on the way.

        Up to :data:`MAX_WRITE_BYTES` (4 MiB) it is one file call that replaces the file
        whole: the name then holds all of the new content or, after an answered error,
        what it held before (docs/session-files.md, "Writes"). Past 4 MiB it is several
        calls, and not atomic: the first replaces the file with the first 4 MiB, each
        later one appends the next. A failure partway (an answered error, a timeout, a call
        that got no answer) leaves the file holding the first pieces, the one that failed
        possibly in part (an append that fails after adding some of its piece, at a full
        disk say, keeps that part, since the helper never cuts an append back; one that timed
        out or got no answer may have added any part of its piece), and nothing after it:
        the file is not the content, and the call that failed is not retried, since it
        may have changed the file. Write the content again from the start to repair it.

        FileNotFoundError and NotADirectoryError for a folder on the way that is not one,
        IsADirectoryError when ``path`` is a folder, PermissionError, OSError with
        ``ENOSPC`` or ``EROFS``. A link at ``path`` itself is replaced by the new file, its
        target untouched."""
        if isinstance(content, str):
            data = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray)):
            data = bytes(content)
        else:
            raise TypeError("content must be str or bytes")
        self._write(self._path(path, folder=False), path, data, "replace", cancel)

    def _write(self, rel: str, shown, data: bytes, first_mode: str, cancel: Optional[CancelHandle]) -> None:
        name, scope = self._target(rel)
        pieces = [data[i : i + MAX_WRITE_BYTES] for i in range(0, len(data), MAX_WRITE_BYTES)] or [b""]
        for i, piece in enumerate(pieces):
            op = fs.FilesWrite(name, piece, mode=first_mode if i == 0 else "append", make_parents=i == 0, scope=scope)
            answer = self._files(op, shown, cancel).answer
            assert isinstance(answer, fs.FilesWriteAnswer)
            if answer.written != len(piece):
                raise OSError(errno.EIO, f"the sandbox wrote {answer.written} of {len(piece)} bytes", shown)

    def edit(self, path: str, old: str, new: str, *, replace_all: bool = False) -> int:
        """Replaces ``old`` with ``new`` in the text file at ``path``: once, when ``old``
        occurs exactly once; every occurrence with ``replace_all``. Returns the number
        of replacements. ValueError when ``old`` is absent, or ambiguous without
        ``replace_all``, or the file is not UTF-8 text; :class:`WorkspaceTooLargeError` for
        a file past :data:`MAX_READ_BYTES`. Two calls (a read, then a write), not atomic: a
        change made between them is overwritten."""
        if not isinstance(old, str) or not isinstance(new, str):
            raise TypeError("old and new must be str")
        if old == "":
            raise ValueError("old must not be empty")
        rel = self._path(path, folder=False)
        answer = self._read(rel, path, 0, MAX_READ_BYTES, None)
        if answer.size_at_open > len(answer.content):
            raise WorkspaceTooLargeError(f"{path}: {answer.size_at_open} bytes, past the {MAX_READ_BYTES} an edit reads")
        try:
            text = answer.content.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"{path}: not UTF-8 text") from e
        count = text.count(old)
        if count == 0:
            raise ValueError(f"{path}: old string not found")
        if count > 1 and not replace_all:
            raise ValueError(f"{path}: old string occurs {count} times; pass replace_all=True to replace every one")
        updated = text.replace(old, new) if replace_all else text.replace(old, new, 1)
        self._write(rel, path, updated.encode("utf-8"), "replace", None)
        return count if replace_all else 1

    def stat(self, path: str, *, cancel: Optional[CancelHandle] = None) -> fs.FilesStatAnswer:
        """What ``path`` is (``type``: ``file``, ``dir``, ``link``, ``other``), its size and
        permission bits; ``.`` is the work directory. A link at the last part is reported
        as a link, not followed. FileNotFoundError when nothing is there."""
        rel = self._path(path, folder=True)
        name, scope = self._target(rel)
        answer = self._files(fs.FilesStat(name, scope=scope), path, cancel).answer
        assert isinstance(answer, fs.FilesStatAnswer)
        return answer

    def list(self, path: Optional[str] = None, *, recursive: bool = False, match: Optional[str] = None,
             cancel: Optional[CancelHandle] = None) -> Iterator[fs.FilesEntry]:
        """The entries of the folder ``path`` (the work directory by default), yielded page
        by page, one file call a page: each entry's path from the folder (bytes; name it
        back by those bytes, or by ``os.fsdecode`` of them), its type and a regular file's
        size. Each folder's entries come sorted by their bytes; ``recursive`` goes depth
        first into every folder below (a link is listed, never entered); a folder below it
        that the walk may not enter (one the guest may not read or search, or, in the work
        scope, a mount below the work directory) is an entry of type ``unreadable``, and the
        walk goes on past it, so no subtree is left out unnamed. ``match`` keeps the entries
        whose path matches a glob (see :meth:`glob`). The workspace's own state directory is
        left out. A listing is not isolated from changes made while it runs.

        FileNotFoundError, NotADirectoryError; PermissionError when the guest may not read
        or search the folder ``path`` itself; :class:`WorkspaceTooLargeError` past a listing's bounds inside the sandbox
        (1,000,000 entries read in one call, 512 folders deep); ValueError for a ``match``
        the helper does not read."""
        if not isinstance(recursive, bool):
            raise TypeError("recursive must be a bool")
        pattern = None if match is None else _check_text("match", match, allow_newline=False)
        yield from self._list(self._dir_path(path), path if path is not None else ".", recursive, pattern, cancel)

    def _list(self, base: str, shown, recursive: bool, match: Optional[str], cancel: Optional[CancelHandle]) -> Iterator[fs.FilesEntry]:
        name, scope = self._target(base)
        pattern = b"" if match is None else fs.path_bytes(match)
        after = b""
        while True:
            op = fs.FilesList(name, recursive=recursive, match=pattern, after=after, budget_bytes=_LIST_BUDGET, scope=scope)
            try:
                result = self._files(op, shown, cancel)
            except InvalidRequestError as e:
                # Refused before anything ran. The daemon checks a glob as the helper reads
                # it, so with a pattern, the pattern is what it refused.
                if match is not None:
                    raise ValueError(f"the pattern {match!r} is not a glob the sandbox reads: {e.message}") from None
                raise
            answer = result.answer
            assert isinstance(answer, fs.FilesListAnswer)
            for entry in answer.entries:
                if base == "." and _in_state(_as_text(entry.path)):
                    continue
                yield entry
            if not answer.more:
                return
            if not answer.entries:
                raise WorkspaceCallError("plimsoll: a listing page ended at its budget with no entry", result)
            after = answer.entries[-1].path

    def read_many(self, paths: Sequence[str], *, max_bytes_each: int = 1 << 20,
                  cancel: Optional[CancelHandle] = None) -> List[fs.FilesItem]:
        """The files at ``paths``, each up to ``max_bytes_each`` (at most
        :data:`MAX_READ_BYTES`), in order, one call or more: one file's error does not
        fail the others, it is that item's ``error`` (``not_found``, ``is_dir``,
        ``too_large`` for one past ``max_bytes_each`` ...). Each item states the file's size
        as its open saw it. A call names at most 16,384 paths and 4 MiB of their bytes, so
        a longer list is several calls; an answer that ended at its budget is asked again
        for the rest."""
        if isinstance(paths, (str, bytes)) or not isinstance(paths, Sequence):
            raise TypeError("paths must be a sequence of paths")
        targets = [self._target(self._path(p, folder=False)) for p in paths]
        if not targets:
            return []
        if len({scope for _, scope in targets}) != 1:
            # An unconfined workspace names every path in the sandbox scope, a confined one
            # every path in one scope (the work scope, or the sandbox scope where its session
            # states that alone): one scope per call either way.
            raise WorkspacePathError("the paths of one read_many must resolve in one scope")
        scope = targets[0][1]
        names = [n for n, _ in targets]
        items: List[fs.FilesItem] = []
        while len(items) < len(names):
            start = end = len(items)
            held = 0
            # At least one path a call (one path is far below the byte bound), then as many as
            # both bounds allow.
            while end < len(names) and end - start < _READ_MANY_PATHS and (end == start or held + len(names[end]) <= _READ_MANY_PATH_BYTES):
                held += len(names[end])
                end += 1
            op = fs.FilesReadMany(names[start:end], max_bytes_each=max_bytes_each, budget_bytes=MAX_READ_BYTES, scope=scope)
            result = self._files(op, "read_many", cancel)
            answer = result.answer
            assert isinstance(answer, fs.FilesReadManyAnswer)
            if not answer.items or len(answer.items) > end - start:
                raise WorkspaceCallError("plimsoll: a read_many answer named no path, or more than were asked", result)
            items.extend(answer.items)
            if not answer.more and len(items) < end:
                raise WorkspaceCallError("plimsoll: a read_many answer left paths out and did not say so", result)
        return items

    def make_dir(self, path: str, *, parents: bool = False, cancel: Optional[CancelHandle] = None) -> None:
        """Makes the folder ``path``; with ``parents``, the folders on the way, and a folder
        already there is done. FileExistsError when something else is there (and, without
        ``parents``, when the folder is)."""
        rel = self._path(path, folder=False)
        name, scope = self._target(rel)
        self._files(fs.FilesMakeDir(name, parents=bool(parents), scope=scope), path, cancel)

    def remove(self, path: str, *, dir: bool = False, cancel: Optional[CancelHandle] = None) -> None:
        """Removes the file at ``path`` (a link is removed itself, never its target), or with
        ``dir`` the empty folder there: IsADirectoryError for a folder without ``dir``,
        NotADirectoryError for anything else with it, OSError ``ENOTEMPTY`` for a folder
        that is not empty. There is no recursive remove: run ``rm -r`` for that."""
        rel = self._path(path, folder=False)
        name, scope = self._target(rel)
        self._files(fs.FilesRemove(name, dir=bool(dir), scope=scope), path, cancel)

    def rename(self, src: str, dst: str, *, replace: bool = False, cancel: Optional[CancelHandle] = None) -> None:
        """Renames ``src`` to ``dst`` in one step; with ``replace`` a file at ``dst`` is
        replaced, without it FileExistsError (checked by the rename itself, atomically)."""
        a, b = self._target(self._path(src, folder=False)), self._target(self._path(dst, folder=False))
        if a[1] != b[1]:
            raise WorkspacePathError("a rename's two paths must resolve in one scope")
        self._files(fs.FilesRename(a[0], b[0], replace=bool(replace), scope=a[1]), src, cancel)

    def _dir_path(self, path: Optional[str]) -> str:
        if path is None:
            return "."
        return self._path(path, folder=True)

    # ---- search ----

    def glob(self, pattern: str, path: Optional[str] = None) -> List[str]:
        """Paths under ``path`` (the work directory by default) matching ``pattern``,
        relative to ``path``, sorted by their bytes, at most ``GLOB_LIMIT``: files,
        folders and links (a link is matched by its own name, never entered). The pattern
        is matched by plimsoll's helper inside the sandbox, part by part
        (docs/session-files.md, "Glob"): ``*`` any run of characters within one part, ``?``
        one, ``[...]`` one of a set, ``**`` as a whole part zero or more parts
        (``src/**/*.ts``, ``**/util.py``). **A leading dot is not special: ``*`` matches
        dot files** (``*`` lists ``.env``), where the shell glob of earlier releases skipped
        them without ``**`` and matched them with it. Absolute patterns and ``..`` are
        refused, and so is a pattern the helper does not read (``**`` inside a part, an
        unclosed ``[``): ValueError. FileNotFoundError when ``path`` is not there."""
        _check_text("pattern", pattern, allow_newline=False)
        if pattern == "":
            raise ValueError("pattern is required")
        if pattern.startswith("/"):
            raise WorkspacePathError("an absolute pattern is not permitted; pass a relative pattern and a path")
        parts = pattern.split("/")
        if ".." in parts:
            raise WorkspacePathError("'..' is not permitted in a pattern")
        # `./x` is `x`, as a shell reads it; the helper's glob has no `.` part.
        parts = [p for p in parts if p != "."]
        if not parts or "" in parts:
            # An empty pattern would list every entry rather than match none.
            raise ValueError(f"the pattern {pattern!r} holds an empty part, or only `.`")
        base = self._dir_path(path)
        # The parts before the first that holds a wildcard name a folder: listing from it
        # keeps the walk out of every folder the pattern cannot reach.
        lead: List[str] = []
        for part in parts[:-1]:
            if any(c in part for c in "*?[\\") or part in ("", "."):
                break
            lead.append(part)
        rest = "/".join(parts[len(lead) :])
        start = posixpath.normpath(posixpath.join(base, *lead)) if lead else base
        if base == "." and _in_state(start):
            return []
        prefix = "".join(p + "/" for p in lead).encode("utf-8", "surrogateescape")
        best: List[_Desc] = []  # the smallest GLOB_LIMIT paths so far, the largest on top
        shown = path if path is not None else "."
        try:
            # One part with no `**` matches the folder's own entries alone: no walk below it.
            for entry in self._list(start, shown, "/" in rest or "**" in rest, rest, None):
                full = prefix + entry.path
                if base == "." and _in_state(_as_text(full)):
                    continue
                if len(best) < GLOB_LIMIT:
                    heapq.heappush(best, _Desc(full))
                elif full < best[0].key:
                    heapq.heapreplace(best, _Desc(full))
        except (FileNotFoundError, NotADirectoryError):
            if lead and self._is_dir(base):
                return []  # a folder the pattern names is not there: nothing matches
            raise FileNotFoundError(errno.ENOENT, "No such directory", shown) from None
        return [_as_text(d.key) for d in sorted(best, key=lambda d: d.key)]

    def _is_dir(self, rel: str) -> bool:
        name, scope = self._target(rel)
        try:
            answer = self._files(fs.FilesStat(name, scope=scope), rel, None).answer
        except (FileNotFoundError, NotADirectoryError):
            return False
        return isinstance(answer, fs.FilesStatAnswer) and answer.type == "dir"

    def grep(self, pattern: str, path: Optional[str] = None) -> str:
        """Lines matching the extended regular expression ``pattern`` under ``path``
        (the work directory by default, a directory or a file), as ``file:line:text``
        lines relative to the work directory; empty when nothing matches. ValueError
        for a pattern grep refuses. A final line ``[output truncated]`` marks a result
        the daemon cut. The search runs in the sandbox (``grep -rnHE``, through
        :meth:`run`), so only the matching lines come back."""
        _check_text("pattern", pattern, allow_newline=False)
        if pattern == "":
            raise ValueError("pattern is required")
        base = self.resolve(path) if path is not None else "."
        out = self.run(["grep", "-rnHE", "-e", pattern, "--", base])
        if out.timed_out:
            raise TimeoutError("plimsoll: grep ran past its budget")
        if out.exit_code == 1:
            return ""
        if out.exit_code != 0:
            raise ValueError(f"grep: {out.stderr_text.strip() or 'failed'}")
        lines = []
        for line in out.stdout_text.split("\n"):
            if not line:
                continue
            if line.startswith("./"):
                line = line[2:]
            if _in_state(line.split(":", 1)[0]):
                continue
            lines.append(line)
        # grep walks directories in no fixed order; an agent gets the same answer for
        # the same tree: by file, then by line number.
        lines.sort(key=_grep_key)
        if out.stdout_truncated:
            lines.append("[output truncated]")
        return "\n".join(lines)

    # ---- the whole tree ----

    def persist(self, *, limit: Optional[int] = MAX_WHOLE_BYTES, cancel: Optional[CancelHandle] = None) -> bytes:
        """The work directory as a tar stream with relative member names, the
        workspace's own state left out. ``tar`` writes it inside the sandbox (through
        :meth:`run`, under a fresh name in the state directory), then it is read back in
        pieces by file calls, as :meth:`read_pieces` reads, and the archive removed.
        ``limit`` (bytes, :data:`MAX_WHOLE_BYTES` by default, None for none) is the
        longest archive it takes: :class:`WorkspaceTooLargeError` past it. The archive is
        made inside a sandbox whose files the guest controls: extract it as you would any
        archive from an untrusted source.

        The archive is staged in the work directory itself, beside the tree it holds, so it
        needs as much free room there as the tree takes: a tree past about half of the work
        directory's room cannot be saved this way (on docker, whose work directory is a
        128 MiB tmpfs by default, 51 MiB of files persisted and 64 MiB did not).
        :class:`WorkspaceTooLargeError` says so when ``tar`` runs out of room."""
        name = f"{STATE_DIR}/persist-{secrets.token_hex(8)}.tar"
        try:
            out = self.run(["tar", "-cf", name, f"--exclude=./{STATE_DIR}", f"--exclude=./{STATE_DIR}/*", "-C", ".", "."], cancel=cancel)
            if out.timed_out:
                raise TimeoutError("plimsoll: persist's tar ran past its budget")
            if out.exit_code != 0:
                if _tar_out_of_room(out):
                    raise WorkspaceTooLargeError(
                        "plimsoll: persist stages its archive in the work directory, beside the tree, and the work directory ran out "
                        "of room for it: a tree past about half of the work folder's room cannot be persisted"
                    )
                raise RuntimeError(f"persist: {out.stderr_text.strip() or 'tar failed'}")
            return b"".join(self._pieces(name, "persist", stop=None, limit=_check_limit(limit), cancel=cancel))
        finally:
            self._tidy(name)

    def hydrate(self, data: bytes, *, cancel: Optional[CancelHandle] = None) -> None:
        """Extracts a stream ``persist`` produced into the work directory: the stream is
        written by file calls, 4 MiB a call, under a fresh name in the state directory,
        then ``tar`` extracts it (through :meth:`run`) and the archive is removed.

        The archive is staged in the work directory, beside the tree it unpacks, so it needs
        room there for the archive and the tree at once: a tree past about half of the work
        directory's room cannot be hydrated this way. :class:`WorkspaceTooLargeError` says
        so when the archive's write or ``tar`` runs out of room."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        name = f"{STATE_DIR}/hydrate-{secrets.token_hex(8)}.tar"
        too_large = WorkspaceTooLargeError(
            "plimsoll: hydrate stages its archive in the work directory, beside the tree it unpacks, and the work directory "
            "ran out of room: a tree past about half of the work folder's room cannot be hydrated"
        )
        try:
            try:
                self._write(name, "hydrate", bytes(data), "create_only", cancel)
            except OSError as e:
                if e.errno == errno.ENOSPC:
                    raise too_large from e
                raise
            out = self.run(["tar", "-xf", name, "-C", "."], cancel=cancel)
            if out.timed_out:
                raise TimeoutError("plimsoll: hydrate's tar ran past its budget")
            if out.exit_code != 0:
                if _tar_out_of_room(out):
                    raise too_large
                raise RuntimeError(f"hydrate: {out.stderr_text.strip() or 'tar failed'}")
        finally:
            self._tidy(name)

    def _tidy(self, rel: str) -> None:
        """Removes an archive of the workspace's own, best effort: one left behind (a call
        that failed, a session that stopped) sits in the state directory, which persist,
        glob and grep leave out, under a name no later call reuses; it costs its disk until
        the session ends. The remove is sent without the caller's cancel handle, under the
        workspace's own call budget (``timeout``): a cancel ends the operation, and the
        archive it was making or reading must still go, since it takes the work directory's
        room from every later call (finding release-128: a cancelled persist of 20 MiB left
        its 20 MiB archive). A cancel that cut a call in flight has stopped the session
        already (the call may have run), so nothing is sent then and the archive stays until
        the session ends."""
        name, scope = self._target(rel)
        try:
            self._files(fs.FilesRemove(name, scope=scope), rel, None)
        except (OSError, TimeoutError, WorkspaceCallError, PlimsollError):
            pass

    # ---- the one way out ----

    def _budget(self, timeout: Optional[float]) -> float:
        budget = self._timeout if timeout is None else float(timeout)
        if budget <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        if self._max_timeout is not None and budget > self._max_timeout:
            budget = self._max_timeout
        return budget

    def _files(self, op: fs.FilesOperation, shown, cancel: Optional[CancelHandle]) -> fs.FilesResult:
        """One file call: its result when the operation was carried out, or the exception
        its error names. A call that timed out or ended without an answer may have run (a
        write may have changed the file), and is never repeated here."""
        budget = self._budget(None)
        result = self._session.run_files(op, timeout=budget, cancel=cancel)
        if result.outcome == "timed_out":
            raise TimeoutError(f"plimsoll: the file call ran past its budget of {budget} s; it may have run")
        if result.outcome != "completed":
            raise WorkspaceCallError(f"plimsoll: the file call may have run, and its answer is not known: {result.outcome}", result)
        if result.error != "none":
            raise _file_error(result.error, result.errno, str(_as_text(shown)))
        return result

    def _call(
        self,
        files,
        steps: Sequence[str],
        artifacts: Sequence[str],
        timeout: Optional[float] = None,
        *,
        tolerate_timeout: bool = False,
        cancel: Optional[CancelHandle] = None,
    ) -> ProjectResult:
        budget = self._budget(timeout)
        result = self._session.run_project(files, list(steps), list(artifacts), timeout=budget, cancel=cancel)
        if result.outcome == "setup_failed":
            raise WorkspaceCallError(f"plimsoll: the call did not run: {result.outcome}: {result.detail}", result)
        if result.outcome in ("protocol_error", "runner_failed") or not result.steps:
            raise WorkspaceCallError(f"plimsoll: the call may have run, and its result is incomplete: {result.outcome}: {result.detail}", result)
        if result.outcome == "timed_out" and not tolerate_timeout:
            raise TimeoutError(f"plimsoll: the call ran past its budget of {budget} s")
        return result

    @staticmethod
    def _artifact_text(result: ProjectResult, path: str) -> Optional[str]:
        for a in result.artifacts:
            if a.path == path:
                return a.content.decode("utf-8", errors="replace").rstrip("\n")
        return None


class _Desc:
    """A heap entry that orders by its key, largest first, so heapq's min-heap keeps the
    smallest GLOB_LIMIT keys with the largest at its top."""

    __slots__ = ("key",)

    def __init__(self, key: bytes) -> None:
        self.key = key

    def __lt__(self, other: "_Desc") -> bool:
        return self.key > other.key

