"""An agent workspace: a shell, files and search over one plimsoll session.

A :class:`Workspace` gives an agent framework what its tools need from a sandbox (run a
command, read and write files, search, carry the working directory and the exported
variables from one command to the next, save and restore the whole tree) over one
plimsoll session. Every framework adapter in this package is a naming layer over it,
so the daemon's guarantees hold the same for each: the isolation floor the session was
opened with, a run record on every call, no network unless a call carries a grant (a
Workspace call never does).

Mechanism. Every operation is one project call of the session (``Session.run_project``:
the call's files are written into the work directory, then its steps run through the
runner, then the named artifacts come back). **A step is one of the fixed scripts in
this module, never assembled from the text an agent supplied**: the command and every
argument travel as files under ``.plimsoll-shell/`` in the work directory (``cmd``,
``a1``, ``a2``, ``in.b64``), which the daemon writes before the step runs and the step
reads back, so nothing an agent writes can change what a step is. The shell's working
directory and its exported variables persist between commands through two files
there, ``cwd`` and ``env``, which the exec script restores before the command and saves
after it; a session that is suspended and resumed keeps them.

What a command gives up against a shell kept as a process: a process it leaves in the
background is killed when the call ends (the session's sweep), ``exit`` in a command
ends the step before the state is saved (the state is then what it was), a syntax
error fails the step, and the output limits are the daemon's, reported by the
truncation flags on the outcome. Paths are resolved against the work directory, not
the shell's current directory, as the agent tool sets of Anthropic and OpenAI do; an
absolute path is accepted when it lies inside the work directory.

Calls of one Workspace are serialized by the session; an operation made of several
calls (``edit``, a large ``write``, ``hydrate``) is not atomic against another thread's.
"""

from __future__ import annotations

import base64
import posixpath
from dataclasses import dataclass
from typing import List, Optional, Sequence, Union

from . import _validate as v
from .types import ProjectResult, SessionSummary

__all__ = ["ExecOutcome", "Workspace", "WorkspacePathError", "WorkspaceTooLargeError", "STATE_DIR", "MAX_READ_BYTES"]

#: The directory in the work directory that carries each call's arguments and the
#: shell's state. Never captured by ``persist`` and never listed by ``glob`` or ``grep``.
STATE_DIR = ".plimsoll-shell"

#: The most ``read`` returns and ``persist`` captures: the runner's artifact budget
#: (docker/runner.mjs MAX_ARTIFACT_BYTES, 8 MiB across one call's artifacts).
MAX_READ_BYTES = 8 << 20

# Raw bytes per call when bytes travel as base64 in a text file: 2.25 MiB, a multiple
# of three so every chunk decodes on its own, 3 MiB encoded, under the 4 MiB the
# client allows one call's files.
_CHUNK_BYTES = 2_359_296

# The fixed scripts. Each begins by naming the state directory from the runner's
# working directory, which is the work directory, and never from an agent's file. The
# variable names are kept out of the saved environment, so a command that exports
# them cannot change where a later step keeps its state.
_PRELUDE = '__plimsoll_s="$PWD/' + STATE_DIR + '"; mkdir -p "$__plimsoll_s"; '
_ROOT_STEP = _PRELUDE + 'pwd > "$__plimsoll_s/root"'
_EXEC_STEP = (
    _PRELUDE
    + 'pwd > "$__plimsoll_s/root"; '
    + '[ -f "$__plimsoll_s/env" ] && . "$__plimsoll_s/env"; '
    + '[ -f "$__plimsoll_s/cwd" ] && cd "$(cat "$__plimsoll_s/cwd")" 2>/dev/null; '
    + '. "$__plimsoll_s/cmd"; __plimsoll_rc=$?; '
    + "export -p | grep -Ev '^export (PWD|OLDPWD|__plimsoll_)' > \"$__plimsoll_s/env.new\"; "
    + 'mv "$__plimsoll_s/env.new" "$__plimsoll_s/env"; pwd > "$__plimsoll_s/cwd"; exit $__plimsoll_rc'
)
_TRUE_STEP = "true"
_READ_STEP = _PRELUDE + 'head -c "$(cat "$__plimsoll_s/a2")" -- "$(cat "$__plimsoll_s/a1")" > "$__plimsoll_s/out"'
_WRITE_B64_STEP = (
    _PRELUDE + '__plimsoll_p="$(cat "$__plimsoll_s/a1")"; mkdir -p "$(dirname "$__plimsoll_p")" && '
    'base64 -d "$__plimsoll_s/in.b64" > "$__plimsoll_p"'
)
_APPEND_B64_STEP = _PRELUDE + 'base64 -d "$__plimsoll_s/in.b64" >> "$(cat "$__plimsoll_s/a1")"'
_GLOB_SHELL_STEP = (
    _PRELUDE + 'cd "$(cat "$__plimsoll_s/a2")" || exit 2; '
    'for __plimsoll_f in $(cat "$__plimsoll_s/a1"); do [ -e "$__plimsoll_f" ] && printf \'%s\\n\' "$__plimsoll_f"; done '
    "| sort | head -n 200"
)
_GLOB_FIND_STEP = (
    _PRELUDE + 'cd "$(cat "$__plimsoll_s/a2")" || exit 2; '
    'find . \\( -path "$(cat "$__plimsoll_s/a1")" -o -path "$(cat "$__plimsoll_s/a3")" \\) '
    '-not -path "./' + STATE_DIR + '" -not -path "./' + STATE_DIR + '/*" '
    "| sed 's#^\\./##' | sort | head -n 200"
)
_GREP_STEP = _PRELUDE + 'grep -rnHE -e "$(cat "$__plimsoll_s/a1")" -- "$(cat "$__plimsoll_s/a2")"'
_PERSIST_STEP = (
    _PRELUDE + 'tar -cf "$__plimsoll_s/ws.tar" --exclude="./' + STATE_DIR + '" --exclude="./' + STATE_DIR + '/*" '
    '-C "$PWD" .'
)
_HYDRATE_STEP = _PRELUDE + 'tar -xf "$__plimsoll_s/ws.tar" -C "$PWD" && rm -f "$__plimsoll_s/ws.tar"'

#: Every step this module sends, for a test that asserts no other text ever becomes a step.
FIXED_STEPS = frozenset(
    {
        _ROOT_STEP,
        _EXEC_STEP,
        _TRUE_STEP,
        _READ_STEP,
        _WRITE_B64_STEP,
        _APPEND_B64_STEP,
        _GLOB_SHELL_STEP,
        _GLOB_FIND_STEP,
        _GREP_STEP,
        _PERSIST_STEP,
        _HYDRATE_STEP,
    }
)

_CMD = STATE_DIR + "/cmd"
_A1 = STATE_DIR + "/a1"
_A2 = STATE_DIR + "/a2"
_A3 = STATE_DIR + "/a3"
_IN_B64 = STATE_DIR + "/in.b64"
_ROOT = STATE_DIR + "/root"
_CWD = STATE_DIR + "/cwd"
_OUT = STATE_DIR + "/out"
_WS_TAR = STATE_DIR + "/ws.tar"

GLOB_LIMIT = 200  # entries a glob returns at most, the fixed step's `head -n`


class WorkspacePathError(ValueError):
    """A path the workspace refuses: outside the work directory, escaping it with
    ``..``, or carrying a character the daemon or a step cannot carry."""


class WorkspaceTooLargeError(RuntimeError):
    """A file or a tree past what one call can carry (the artifact budget, the files
    budget)."""


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
    if len(parts) == 3 and parts[1].isdigit():
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


class Workspace:
    """Shell, files and search over one open :class:`~plimsoll_client.client.Session`.

    ``timeout`` (seconds) is the budget of a command whose ``exec`` names none, and of
    every other call; ``max_timeout`` caps any budget asked for, for a daemon whose
    ceiling is known (``Info.project_environment.max_timeout_ms``). The daemon refuses
    a budget past its own ceiling either way.
    """

    def __init__(self, session, *, timeout: float = 120.0, max_timeout: Optional[float] = None) -> None:
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        if max_timeout is not None and (not isinstance(max_timeout, (int, float)) or max_timeout <= 0):
            raise ValueError("max_timeout must be a positive number of seconds")
        self._session = session
        self._timeout = float(timeout)
        self._max_timeout = float(max_timeout) if max_timeout is not None else None
        self._root: Optional[str] = None

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
        """The work directory's absolute path in the sandbox, learned from the sandbox
        itself on first use (one call) or from the first command."""
        if self._root is None:
            self._learn(self._call({}, [_ROOT_STEP], [_ROOT]))
            if self._root is None:
                raise RuntimeError("plimsoll: the sandbox did not report its work directory")
        return self._root

    def resolve(self, path: str) -> str:
        """The work-directory-relative form of ``path``: a relative path is taken from
        the work directory (``.`` is the directory itself); an absolute path must lie
        inside it. Raises :class:`WorkspacePathError` otherwise."""
        if not isinstance(path, str):
            raise WorkspacePathError("path must be a str")
        if path == "":
            raise WorkspacePathError("path is required")
        if "\x00" in path or "\n" in path or "\r" in path or "\\" in path:
            raise WorkspacePathError(f"unsafe path {path!r}")
        if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in path):
            raise WorkspacePathError(f"unsafe path {path!r}")
        rel = path
        if rel.startswith("/"):
            root = self.root
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

    def _file_path(self, path: str) -> str:
        rel = self.resolve(path)
        if rel == ".":
            raise WorkspacePathError("the work directory itself is not a file")
        if rel == STATE_DIR or rel.startswith(STATE_DIR + "/"):
            raise WorkspacePathError(f"{STATE_DIR} is the workspace's own state")
        v._project_path("file", rel)
        return rel

    def _dir_path(self, path: Optional[str]) -> str:
        if path is None:
            return "."
        rel = self.resolve(path)
        if rel != ".":
            v._project_path("path", rel)
        return rel

    # ---- commands ----

    def exec(self, command: str, *, timeout: Optional[float] = None) -> ExecOutcome:
        """Runs ``command`` as shell text (BusyBox ``sh`` on the docker images) in the
        shell's current directory with its exported variables, and keeps both for the
        next command. A non-zero exit is an outcome, not an error."""
        _check_text("command", command, allow_newline=True)
        result = self._call({_CMD: command}, [_EXEC_STEP], [_ROOT, _CWD], timeout, tolerate_timeout=True)
        self._learn(result)
        step = result.steps[0]
        cwd = self._artifact_text(result, _CWD)
        if cwd is None:
            cwd = self._root or ""
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

    # ---- files ----

    def read(self, path: str, *, max_bytes: int = 1 << 20) -> bytes:
        """At most ``max_bytes`` of the file at ``path``. FileNotFoundError when there is
        no such file (a directory counts as none)."""
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("max_bytes must be a positive int")
        if max_bytes > MAX_READ_BYTES:
            raise ValueError(f"max_bytes must be at most {MAX_READ_BYTES}, the artifact budget")
        rel = self._file_path(path)
        result = self._call({_A1: rel, _A2: str(max_bytes)}, [_READ_STEP], [_OUT])
        step = result.steps[0]
        if step.exit_code != 0:
            raise FileNotFoundError(f"{path}: {step.stderr_text.strip() or 'cannot read'}")
        content = self._artifact(result, _OUT)
        if content is None:
            raise WorkspaceTooLargeError(f"{path}: the sandbox could not return it within the artifact budget")
        return content

    def write(self, path: str, content: Union[str, bytes, bytearray]) -> None:
        """Writes ``content`` to ``path``, creating parent directories. Text goes as the
        call's file; bytes go as base64 and are decoded by a fixed step."""
        rel = self._file_path(path)
        if isinstance(content, str):
            _check_text("content", content, allow_newline=True)
            if len(content.encode("utf-8")) > v.MAX_PROJECT_BYTES - 1024:
                raise WorkspaceTooLargeError(f"{path}: text past one call's files budget; write it as bytes")
            self._call({rel: content}, [_TRUE_STEP], [])
            return
        if isinstance(content, (bytes, bytearray)):
            self._put_bytes(rel, bytes(content))
            return
        raise TypeError("content must be str or bytes")

    def _put_bytes(self, rel: str, data: bytes) -> None:
        chunks = [data[i : i + _CHUNK_BYTES] for i in range(0, len(data), _CHUNK_BYTES)] or [b""]
        for i, chunk in enumerate(chunks):
            step = _WRITE_B64_STEP if i == 0 else _APPEND_B64_STEP
            encoded = base64.b64encode(chunk).decode("ascii")
            result = self._call({_A1: rel, _IN_B64: encoded}, [step], [])
            if result.steps[0].exit_code != 0:
                raise OSError(f"{rel}: {result.steps[0].stderr_text.strip() or 'cannot write'}")

    def edit(self, path: str, old: str, new: str, *, replace_all: bool = False) -> int:
        """Replaces ``old`` with ``new`` in the text file at ``path``: once, when ``old``
        occurs exactly once; every occurrence with ``replace_all``. Returns the number
        of replacements. ValueError when ``old`` is absent, or ambiguous without
        ``replace_all``, or the file is not UTF-8 text."""
        if not isinstance(old, str) or not isinstance(new, str):
            raise TypeError("old and new must be str")
        if old == "":
            raise ValueError("old must not be empty")
        raw = self.read(path, max_bytes=MAX_READ_BYTES)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"{path}: not UTF-8 text") from e
        count = text.count(old)
        if count == 0:
            raise ValueError(f"{path}: old string not found")
        if count > 1 and not replace_all:
            raise ValueError(f"{path}: old string occurs {count} times; pass replace_all=True to replace every one")
        updated = text.replace(old, new) if replace_all else text.replace(old, new, 1)
        self.write(path, updated)
        return count if replace_all else 1

    # ---- search ----

    def glob(self, pattern: str, path: Optional[str] = None) -> List[str]:
        """Paths under ``path`` (the work directory by default) matching ``pattern``,
        relative to ``path``, sorted, at most ``GLOB_LIMIT``. A pattern without ``**``
        is a shell glob (``*.py``, ``src/*/main.go``); one with ``**`` matches across
        directories (``src/**/*.ts``). Absolute patterns and ``..`` are refused."""
        _check_text("pattern", pattern, allow_newline=False)
        if pattern == "":
            raise ValueError("pattern is required")
        if pattern.startswith("/"):
            raise WorkspacePathError("an absolute pattern is not permitted; pass a relative pattern and a path")
        if ".." in pattern.split("/"):
            raise WorkspacePathError("'..' is not permitted in a pattern")
        base = self._dir_path(path)
        if "**" in pattern:
            # find's `*` crosses `/`, so `**/` read as nothing matches any depth from
            # the pattern's own directory down, and read as `*/` matches one directory
            # or more; the two together are the glob's "zero or more directories".
            step = _GLOB_FIND_STEP
            files = {
                _A1: "./" + pattern.replace("**/", "").replace("**", "*"),
                _A3: "./" + pattern.replace("**/", "*/").replace("**", "*"),
                _A2: base,
            }
        else:
            step = _GLOB_SHELL_STEP
            files = {_A1: pattern, _A2: base}
        result = self._call(files, [step], [])
        step_result = result.steps[0]
        if step_result.exit_code == 2:
            raise FileNotFoundError(f"{path}: no such directory")
        return [
            line
            for line in step_result.stdout_text.split("\n")
            if line and line != STATE_DIR and not line.startswith(STATE_DIR + "/")
        ]

    def grep(self, pattern: str, path: Optional[str] = None) -> str:
        """Lines matching the extended regular expression ``pattern`` under ``path``
        (the work directory by default, a directory or a file), as ``file:line:text``
        lines relative to the work directory; empty when nothing matches. ValueError
        for a pattern grep refuses. A final line ``[output truncated]`` marks a result
        the daemon cut."""
        _check_text("pattern", pattern, allow_newline=False)
        if pattern == "":
            raise ValueError("pattern is required")
        base = self._dir_path(path)
        result = self._call({_A1: pattern, _A2: base}, [_GREP_STEP], [])
        step = result.steps[0]
        if step.exit_code == 1:
            return ""
        if step.exit_code != 0:
            raise ValueError(f"grep: {step.stderr_text.strip() or 'failed'}")
        lines = []
        for line in step.stdout_text.split("\n"):
            if not line:
                continue
            if line.startswith("./"):
                line = line[2:]
            if line.startswith(STATE_DIR + "/"):
                continue
            lines.append(line)
        # grep walks directories in no fixed order; an agent gets the same answer for
        # the same tree: by file, then by line number.
        lines.sort(key=_grep_key)
        if step.stdout_truncated:
            lines.append("[output truncated]")
        return "\n".join(lines)

    # ---- the whole tree ----

    def persist(self) -> bytes:
        """The work directory as a tar stream with relative member names, the
        workspace's own state left out. :class:`WorkspaceTooLargeError` when the tree
        does not fit one call's artifact budget."""
        result = self._call({}, [_PERSIST_STEP], [_WS_TAR])
        step = result.steps[0]
        if step.exit_code != 0:
            raise RuntimeError(f"persist: {step.stderr_text.strip() or 'tar failed'}")
        content = self._artifact(result, _WS_TAR)
        if content is None:
            raise WorkspaceTooLargeError("the work directory does not fit the artifact budget")
        return content

    def hydrate(self, data: bytes) -> None:
        """Extracts a stream ``persist`` produced into the work directory."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        self._put_bytes(_WS_TAR, bytes(data))
        result = self._call({}, [_HYDRATE_STEP], [])
        step = result.steps[0]
        if step.exit_code != 0:
            raise RuntimeError(f"hydrate: {step.stderr_text.strip() or 'tar failed'}")

    # ---- the one way out ----

    def _call(
        self,
        files,
        steps: Sequence[str],
        artifacts: Sequence[str],
        timeout: Optional[float] = None,
        *,
        tolerate_timeout: bool = False,
    ) -> ProjectResult:
        budget = self._timeout if timeout is None else float(timeout)
        if budget <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        if self._max_timeout is not None and budget > self._max_timeout:
            budget = self._max_timeout
        result = self._session.run_project(files, list(steps), list(artifacts), timeout=budget)
        if result.outcome == "setup_failed":
            raise RuntimeError(f"plimsoll: the call did not run: {result.outcome}: {result.detail}")
        if result.outcome in ("protocol_error", "runner_failed") or not result.steps:
            raise RuntimeError(f"plimsoll: the call may have run, and its result is incomplete: {result.outcome}: {result.detail}")
        if result.outcome == "timed_out" and not tolerate_timeout:
            raise TimeoutError(f"plimsoll: the call ran past its budget of {budget} s")
        return result

    def _learn(self, result: ProjectResult) -> None:
        root = self._artifact_text(result, _ROOT)
        if root:
            self._root = root

    @staticmethod
    def _artifact(result: ProjectResult, path: str) -> Optional[bytes]:
        for a in result.artifacts:
            if a.path == path:
                return a.content
        return None

    @classmethod
    def _artifact_text(cls, result: ProjectResult, path: str) -> Optional[str]:
        content = cls._artifact(result, path)
        if content is None:
            return None
        return content.decode("utf-8", errors="replace").rstrip("\n")
