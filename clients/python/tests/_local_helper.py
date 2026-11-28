"""A session's file calls carried out by plimsoll's real helper on this machine, for the unit
tests of code built on :class:`~plimsoll_client.Workspace` that need a real tree on disk (one a
shell step also works on, links, modes, a process racing the call). No daemon: each call starts
the committed build (sandbox/internal/nativehelper/program/plimsoll-helper_amd64, the bytes every
project image carries) with the words on stdin, as the daemon's driver does
(sandbox/internal/sessionkit/files.go), and reads its exit and frames into a ``FilesResult``.

The work scope needs the work folder to be a mount of its own (docs/session-files.md, "Scopes"),
so each call runs in a user and mount namespace of its own (``unshare -rm``) that bind-mounts the
folder on itself, then drops every capability before the helper starts (``setpriv``), so the
kernel checks the files' own modes against it as it does against the guest. Where that namespace
cannot be made (a kernel or a policy that refuses unprivileged user namespaces, such as Ubuntu
24.04's AppArmor default) :func:`unavailable` says why, and the tests that need it skip with that
reason; what the helper does in a real sandbox is the docker checks'."""

from __future__ import annotations

import atexit
import os
import platform
import shutil
import subprocess
import tempfile
import time
from typing import List, Optional, Tuple

from plimsoll_client import _validate as v
from plimsoll_client import files as fs

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "..", "..", "..", "sandbox", "internal", "nativehelper", "program", "plimsoll-helper_amd64")

# The helper's exit codes that name an error (sessionkit.HelperExits): the error and its errno.
EXITS = {80: ("symlink", "ELOOP"), 81: ("not_found", "ENOENT"), 82: ("is_dir", "EISDIR"), 83: ("not_dir", "ENOTDIR"),
         84: ("exists", "EEXIST"), 85: ("not_regular", ""), 86: ("permission_denied", "EACCES"), 87: ("too_large", "EFBIG"),
         88: ("not_empty", "ENOTEMPTY"), 89: ("no_space", "ENOSPC"), 90: ("read_only", "EROFS"), 91: ("scan_limit", "")}
KINDS = {b"f": "file", b"d": "dir", b"l": "link", b"o": "other", b"u": "unreadable"}
MODES = {"replace": b"replace", "create_only": b"create-only", "append": b"append"}

# Runs in the new namespaces: the work folder mounted on itself, entered, then the helper with no
# capability left (the bounding set emptied, so the exec gains none back).
_LAUNCH = 'mount --bind "$1" "$1" && cd "$1" && exec setpriv --bounding-set=-all --inh-caps=-all "$2" files "$3" -'

_copy: Optional[str] = None
_why: Optional[str] = None


def _helper() -> str:
    """A copy of the committed build that this user may run (git keeps it without its mode)."""
    global _copy
    if _copy is None:
        d = tempfile.mkdtemp(prefix="plimsoll-helper-")
        atexit.register(shutil.rmtree, d, True)
        p = os.path.join(d, "plimsoll-helper")
        shutil.copyfile(SOURCE, p)
        os.chmod(p, 0o755)
        _copy = p
    return _copy


def unavailable() -> str:
    """Why the real helper cannot carry out a call here, or "" when it can (measured once)."""
    global _why
    if _why is None:
        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
            _why = f"the committed helper is a Linux amd64 build; this is {platform.system()} {platform.machine()}"
        elif shutil.which("unshare") is None or shutil.which("setpriv") is None:
            _why = "unshare or setpriv (util-linux) is not on PATH"
        else:
            d = tempfile.mkdtemp(prefix="plimsoll-helper-probe-")
            try:
                code, out, err = _start(d, "work", b"2:stat\0.\0", 30)
                _why = "" if code == 0 and out.startswith(b"k1:d") else f"the helper in a namespace of its own exited {code}: {err[:200]!r}"
            except (OSError, subprocess.SubprocessError) as e:
                _why = f"the helper could not be started in a namespace of its own: {e}"
            finally:
                shutil.rmtree(d, ignore_errors=True)
    return _why


def _start(root: str, scope: str, stdin: bytes, timeout: float) -> Tuple[int, bytes, bytes]:
    r = subprocess.run(["unshare", "-rm", "sh", "-c", _LAUNCH, "sh", root, _helper(), scope], input=stdin, capture_output=True,
                       timeout=timeout, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    return r.returncode, r.stdout, r.stderr


def _words(op: fs.FilesOperation) -> Tuple[List[bytes], bytes]:
    """The command's words and the input after them, as sessionkit's FileCall.Stdin builds them."""
    b = lambda x: b"1" if x else b"0"  # noqa: E731
    n = lambda x: str(x).encode()  # noqa: E731
    p = fs.path_bytes
    if isinstance(op, fs.FilesStat):
        return [b"stat", p(op.path)], b""
    if isinstance(op, fs.FilesRead):
        return [b"read", p(op.path), n(op.offset), n(op.max_bytes)], b""
    if isinstance(op, fs.FilesWrite):
        return [b"write", p(op.path), MODES[op.mode], b(op.make_parents)], bytes(op.content)
    if isinstance(op, fs.FilesList):
        words = [b"list", p(op.path), b(op.recursive), n(op.budget_bytes)]
        if p(op.match):
            words.append(p(op.match))
        return words, p(op.after)
    if isinstance(op, fs.FilesReadMany):
        return [b"readmany", n(op.max_bytes_each), n(op.budget_bytes)], b"".join(p(x) + b"\0" for x in op.paths)
    if isinstance(op, fs.FilesMakeDir):
        return [b"mkdir", p(op.path), b(op.parents)], b""
    if isinstance(op, fs.FilesRemove):
        return [b"remove", p(op.path), b(op.dir)], b""
    if isinstance(op, fs.FilesRename):
        return [b"rename", p(op.from_path), p(op.to_path), b(op.replace)], b""
    raise AssertionError(f"no such operation {op!r}")


def _frames(out: bytes, group: int) -> Tuple[List[List[Tuple[bytes, bytes]]], bool]:
    """The answer's entries and whether it is whole, read strictly (sessionkit.readFrames)."""
    frames: List[Tuple[bytes, bytes]] = []
    i = 0
    while i < len(out):
        colon = out.index(b":", i + 1)
        size = int(out[i + 1 : colon])
        start = colon + 1
        if start + size > len(out):
            raise ValueError("a frame past the answer's end")
        frames.append((out[i : i + 1], out[start : start + size]))
        i = start + size
    tag, count = frames[-1]
    body = frames[:-1]
    if tag not in (b".", b"+") or int(count) * group != len(body):
        raise ValueError("the end frame's count is not the entries'")
    return [body[k : k + group] for k in range(0, len(body), group)], tag == b"."


_OPS = {fs.FilesStat: "stat", fs.FilesRead: "read", fs.FilesWrite: "write", fs.FilesList: "list", fs.FilesReadMany: "read_many",
        fs.FilesMakeDir: "make_dir", fs.FilesRemove: "remove", fs.FilesRename: "rename"}
_GROUP = {"stat": 4, "read": 2, "write": 1, "list": 3, "read_many": 3}


def _answer(name: str, op: fs.FilesOperation, out: bytes):
    if name in ("make_dir", "remove", "rename"):
        if out:
            raise ValueError("an answer to an operation that answers nothing")
        return None
    entries, whole = _frames(out, _GROUP[name])
    if name == "stat":
        (k, s, m, _t), = entries
        return fs.FilesStatAnswer(type=KINDS[k[1]], size=int(s[1]), mode=int(m[1]))
    if name == "read":
        (s, body), = entries
        return fs.FilesReadAnswer(content=body[1], size_at_open=int(s[1]))
    if name == "write":
        (count,), = entries
        return fs.FilesWriteAnswer(written=int(count[1]))
    if name == "list":
        return fs.FilesListAnswer(entries=tuple(fs.FilesEntry(path=e[0][1], type=KINDS[e[1][1]], size=int(e[2][1])) for e in entries),
                                  more=not whole)
    items = []
    for _p, s, e in entries:
        if e[0] == b"b":
            items.append(fs.FilesItem(error="none", errno="", content=e[1], size_at_open=int(s[1])))
        else:
            err, eno = EXITS.get(int(e[1]), ("other", ""))
            items.append(fs.FilesItem(error=err, errno=eno, content=b"", size_at_open=0))
    return fs.FilesReadManyAnswer(items=tuple(items), more=not whole)


def _result(outcome: str, *, isolation: str, error: str = "none", errno: str = "", op: str = "", answer=None, ms: int = 0) -> fs.FilesResult:
    return fs.FilesResult(provider="local", isolation=isolation, environment="", software_identity="", duration_ms=ms, record=None,
                          outcome=outcome, error=error, errno=errno, op=op, answer=answer)


def run_files(root: str, op: fs.FilesOperation, *, timeout: float = 60.0, isolation: str = "kernel") -> fs.FilesResult:
    """One file call over the folder ``root``, carried out by the real helper, read as the daemon
    reads it: an answered error is ``completed`` with its error, an exit 2 (the daemon's own check
    refuses what the helper would call malformed, before anything starts) the daemon's refusal,
    and an answer that cannot be read ``protocol_error``."""
    name = _OPS[type(op)]
    words, rest = _words(op)
    stdin = str(len(words)).encode() + b":" + b"".join(w + b"\0" for w in words) + rest
    began = time.monotonic()
    try:
        code, out, err = _start(root, op.scope, stdin, timeout)
    except subprocess.TimeoutExpired:
        return _result("timed_out", isolation=isolation)
    ms = int((time.monotonic() - began) * 1000)
    if code == 2:
        raise v.invalid(f"the file call is malformed: {err.decode('utf-8', 'replace').strip()}")
    if code == 92:
        return _result("runner_failed", isolation=isolation, ms=ms)
    if code == 1:
        first = err.split(b":", 1)[0].decode("ascii", "replace")
        return _result("completed", isolation=isolation, error="other", errno=first if first.isupper() else "", ms=ms)
    if code in EXITS:
        error, eno = EXITS[code]
        return _result("completed", isolation=isolation, error=error, errno=eno, ms=ms)
    if code != 0:
        return _result("runner_failed", isolation=isolation, ms=ms)
    try:
        answer = _answer(name, op, out)
    except (ValueError, IndexError, KeyError):
        return _result("protocol_error", isolation=isolation, ms=ms)
    return _result("completed", isolation=isolation, op=name, answer=answer, ms=ms)
