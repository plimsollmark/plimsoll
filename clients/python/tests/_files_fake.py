"""An in-memory stand-in for a session's file calls (``Session.run_files``), for the unit
tests of code built on :class:`~plimsoll_client.Workspace`: a tree of files, folders and
links answered as plimsoll's helper answers (docs/session-files.md), with no daemon. What the
real helper does is the docker checks'; this fake's glob is checked against the helper's own
vectors (sandbox/internal/nativehelper/testdata/glob-vectors.json) in test_workspace.py.

Paths are kept as absolute bytes. The work scope resolves from ``root``; a link at any part
of a work path is followed while it stays inside the root and refused (``symlink``) when it
leaves, as version 3 of the helper's contract does; the sandbox scope follows every link."""

from __future__ import annotations

import re
import posixpath
from typing import Callable, Dict, List, Optional, Set, Tuple

from plimsoll_client import _validate as v
from plimsoll_client import files as fs

ERRNO = {"not_found": "ENOENT", "is_dir": "EISDIR", "not_dir": "ENOTDIR", "exists": "EEXIST", "symlink": "ELOOP",
         "permission_denied": "EACCES", "too_large": "EFBIG", "no_space": "ENOSPC", "read_only": "EROFS",
         "not_empty": "ENOTEMPTY", "not_regular": "", "scan_limit": "", "other": "EIO"}


class _Error(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


def result(op: str = "", answer=None, *, outcome: str = "completed", error: str = "none", errno: str = "") -> fs.FilesResult:
    """A file call's result as the client maps one, with no record."""
    return fs.FilesResult(provider="fake", isolation="container", environment="", software_identity="", duration_ms=1, record=None,
                          outcome=outcome, error=error, errno=errno, op=op, answer=answer)


def _part_regex(pat: bytes) -> "re.Pattern[str]":
    """One part of a glob as a regular expression over latin-1 text (one character a byte):
    ``*``, ``?``, ``[...]`` (``!`` or ``^`` first negates, ``]`` first is plain) and ``\\``."""
    p, out, i = pat.decode("latin-1"), [], 0
    while i < len(p):
        c = p[i]
        if c == "\\":
            out.append(re.escape(p[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        elif c == "[":
            j = i + 1
            neg = j < len(p) and p[j] in "!^"
            if neg:
                j += 1
            body = ""
            if j < len(p) and p[j] == "]":
                body, j = "\\]", j + 1
            while p[j] != "]":
                if p[j] == "\\":
                    j += 1  # the next byte is plain, `]` included
                    body += re.escape(p[j])
                else:
                    body += "\\" + p[j] if p[j] in "^[" else p[j]
                j += 1
            out.append("[" + ("^" if neg else "") + body + "]")
            i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out), re.DOTALL)


def _part_match(pat: bytes, name: bytes) -> bool:
    return _part_regex(pat).fullmatch(name.decode("latin-1")) is not None


def glob_match(pattern: bytes, path: bytes) -> bool:
    """The helper's glob rule: part by part, ``**`` as a whole part zero or more parts, a
    leading dot not special."""
    pp, sp = pattern.split(b"/"), path.split(b"/")

    def go(i: int, j: int) -> bool:
        if i == len(pp):
            return j == len(sp)
        if pp[i] == b"**":
            return any(go(i + 1, k) for k in range(j, len(sp) + 1))
        return j < len(sp) and _part_match(pp[i], sp[j]) and go(i + 1, j + 1)

    return go(0, 0)


def glob_refused(pattern: bytes) -> bool:
    if pattern == b"" or pattern.endswith(b"\\"):
        return True
    for part in pattern.split(b"/"):
        if part == b"" or (b"**" in part and part != b"**"):
            return True
        if part.count(b"[") > part.count(b"]"):
            return True
    return False


class MemoryFiles:
    """A tree in memory and the file calls over it. ``page`` is how many entries a list or
    read_many page holds before ``more`` (the real helper pages by bytes). ``fail`` maps an
    operation name to results answered in turn before the tree is touched; ``hook`` is
    called with each operation first. ``calls`` holds every operation handed in."""

    def __init__(self, root: str = "/work") -> None:
        self.root = root.encode()
        self.files: Dict[bytes, bytes] = {}
        self.dirs: Set[bytes] = {b"/", self.root}
        self.links: Dict[bytes, bytes] = {}
        self.unreadable: Set[bytes] = set()
        self.page = 1000
        self.fail: Dict[str, List[fs.FilesResult]] = {}
        self.hook: Optional[Callable[[fs.FilesOperation], None]] = None
        self.calls: List[fs.FilesOperation] = []
        p = self.root
        while p not in (b"/", b""):
            self.dirs.add(p)
            p = posixpath.dirname(p)

    # ---- setting the tree up ----

    def abs(self, rel: str) -> bytes:
        b = rel.encode("utf-8", "surrogateescape")
        return b if b.startswith(b"/") else self.root + b"/" + b

    def put(self, rel: str, content: bytes = b"x") -> None:
        p = self.abs(rel)
        d = posixpath.dirname(p)
        while d not in self.dirs:
            self.dirs.add(d)
            d = posixpath.dirname(d)
        self.files[p] = content

    def link(self, rel: str, target: str) -> None:
        self.links[self.abs(rel)] = target.encode()

    def get(self, rel: str) -> Optional[bytes]:
        return self.files.get(self.abs(rel))

    # ---- resolution ----

    def _kind(self, p: bytes) -> str:
        if p in self.links:
            return "link"
        if p in self.dirs:
            return "dir"
        if p in self.files:
            return "file"
        return ""

    def _resolve(self, path: bytes, scope: str, *, follow_last: bool, parents: bool = False) -> bytes:
        if scope == "work":
            if path.startswith(b"/") or path == b"":
                raise _Error("other")
            start = self.root if path == b"." else self.root + b"/" + path
        else:
            if not path.startswith(b"/"):
                raise _Error("other")
            start = path
        parts = [x for x in start.split(b"/") if x]
        cur = b""
        hops = 0
        i = 0
        while i < len(parts):
            nxt = cur + b"/" + parts[i]
            last = i == len(parts) - 1
            if nxt in self.links and (not last or follow_last):
                hops += 1
                if hops > 40:
                    raise _Error("symlink")
                target = self.links[nxt]
                joined = target if target.startswith(b"/") else posixpath.normpath(cur + b"/" + target)
                if scope == "work" and not (joined == self.root or joined.startswith(self.root + b"/")):
                    raise _Error("symlink")
                parts = [x for x in joined.split(b"/") if x] + parts[i + 1 :]
                cur, i = b"", 0
                continue
            if not last:
                k = self._kind(nxt)
                if k == "":
                    if not parents:
                        raise _Error("not_found")
                if k == "file":
                    raise _Error("not_dir")
            cur = nxt
            i += 1
        return cur or b"/"

    # ---- the call ----

    def run_files(self, op: fs.FilesOperation, **kw) -> fs.FilesResult:
        self.calls.append(op)
        if self.hook is not None:
            self.hook(op)
        name = type(op).__name__
        if self.fail.get(name):
            return self.fail[name].pop(0)
        try:
            return self._do(op)
        except _Error as e:
            return result(error=e.code, errno=ERRNO[e.code])

    def _do(self, op) -> fs.FilesResult:
        scope = op.scope
        if isinstance(op, fs.FilesStat):
            p = self._resolve(fs.path_bytes(op.path), scope, follow_last=False)
            k = self._kind(p)
            if not k:
                raise _Error("not_found")
            return result("stat", fs.FilesStatAnswer(type=k, size=len(self.files.get(p, b"")), mode=0o644 if k == "file" else 0o755))
        if isinstance(op, fs.FilesRead):
            p = self._read_target(fs.path_bytes(op.path), scope)
            b = self.files[p]
            return result("read", fs.FilesReadAnswer(content=b[op.offset : op.offset + op.max_bytes], size_at_open=len(b)))
        if isinstance(op, fs.FilesWrite):
            return self._write(op)
        if isinstance(op, fs.FilesList):
            return self._list(op)
        if isinstance(op, fs.FilesReadMany):
            items = []
            for q in op.paths[: self.page]:
                try:
                    p = self._read_target(fs.path_bytes(q), scope)
                    b = self.files[p]
                    if len(b) > op.max_bytes_each:
                        raise _Error("too_large")
                    items.append(fs.FilesItem(error="none", errno="", content=b, size_at_open=len(b)))
                except _Error as e:
                    items.append(fs.FilesItem(error=e.code, errno=ERRNO[e.code], content=b"", size_at_open=0))
            return result("read_many", fs.FilesReadManyAnswer(items=tuple(items), more=len(op.paths) > self.page))
        if isinstance(op, fs.FilesMakeDir):
            p = self._resolve(fs.path_bytes(op.path), scope, follow_last=True, parents=op.parents)
            if self._kind(p) == "dir":
                if not op.parents:
                    raise _Error("exists")
                return result("make_dir")
            if self._kind(p):
                raise _Error("exists")
            parent = posixpath.dirname(p)
            if self._kind(parent) != "dir":
                if not op.parents:
                    raise _Error("not_found")
                d = parent
                while self._kind(d) != "dir":
                    self.dirs.add(d)
                    d = posixpath.dirname(d)
            self.dirs.add(p)
            return result("make_dir")
        if isinstance(op, fs.FilesRemove):
            p = self._resolve(fs.path_bytes(op.path), scope, follow_last=False)
            k = self._kind(p)
            if not k:
                raise _Error("not_found")
            if op.dir:
                if k != "dir":
                    raise _Error("not_dir")
                if any(q.startswith(p + b"/") for q in list(self.files) + list(self.dirs) + list(self.links)):
                    raise _Error("not_empty")
                self.dirs.discard(p)
            elif k == "dir":
                raise _Error("is_dir")
            else:
                self.files.pop(p, None)
                self.links.pop(p, None)
            return result("remove")
        if isinstance(op, fs.FilesRename):
            a = self._resolve(fs.path_bytes(op.from_path), scope, follow_last=False)
            b = self._resolve(fs.path_bytes(op.to_path), scope, follow_last=False)
            if not self._kind(a):
                raise _Error("not_found")
            if self._kind(b) and not op.replace:
                raise _Error("exists")
            for store in (self.files, self.links):
                if a in store:
                    store[b] = store.pop(a)
            if a in self.dirs:
                moved = [d for d in self.dirs if d == a or d.startswith(a + b"/")]
                for d in moved:
                    self.dirs.discard(d)
                    self.dirs.add(b + d[len(a) :])
                for store in (self.files, self.links):
                    for q in [q for q in store if q.startswith(a + b"/")]:
                        store[b + q[len(a) :]] = store.pop(q)
            return result("rename")
        raise AssertionError(f"no such operation {op!r}")

    def _read_target(self, path: bytes, scope: str) -> bytes:
        p = self._resolve(path, scope, follow_last=True)
        k = self._kind(p)
        if not k:
            raise _Error("not_found")
        if k == "dir":
            raise _Error("is_dir")
        if p in self.unreadable:
            raise _Error("permission_denied")
        return p

    def _write(self, op: fs.FilesWrite) -> fs.FilesResult:
        path = fs.path_bytes(op.path)
        p = self._resolve(path, op.scope, follow_last=op.mode == "append", parents=op.make_parents)
        parent = posixpath.dirname(p)
        if self._kind(parent) != "dir":
            if self._kind(parent) == "file":
                raise _Error("not_dir")
            if not op.make_parents:
                raise _Error("not_found")
            d = parent
            while self._kind(d) == "":
                self.dirs.add(d)
                d = posixpath.dirname(d)
            if self._kind(d) != "dir":
                raise _Error("not_dir")
        k = self._kind(p)
        if k == "dir":
            raise _Error("is_dir")
        if p in self.unreadable:
            raise _Error("permission_denied")
        if op.mode == "create_only" and k:
            raise _Error("exists")
        if op.mode == "append":
            if k != "file":
                raise _Error("not_found")
            self.files[p] += bytes(op.content)
        else:
            self.links.pop(p, None)
            self.files[p] = bytes(op.content)
        return result("write", fs.FilesWriteAnswer(written=len(op.content)))

    def _list(self, op: fs.FilesList) -> fs.FilesResult:
        d = self._resolve(fs.path_bytes(op.path), op.scope, follow_last=True)
        k = self._kind(d)
        if not k:
            raise _Error("not_found")
        if k != "dir":
            raise _Error("not_dir")
        match = fs.path_bytes(op.match)
        if match and glob_refused(match):
            raise v.invalid("the file call's match is not a glob")  # as the daemon refuses one, before the call
        out: List[Tuple[bytes, str, int]] = []

        def walk(folder: bytes, rel: bytes) -> None:
            names = sorted({q[len(folder) + 1 :].split(b"/")[0] for q in list(self.files) + list(self.dirs) + list(self.links)
                            if q.startswith(folder + b"/") and q != folder})
            for n in names:
                q = folder + b"/" + n
                r = rel + n
                kind = self._kind(q)
                out.append((r, kind, len(self.files.get(q, b"")) if kind == "file" else 0))
                if op.recursive and kind == "dir":
                    walk(q, r + b"/")

        walk(d if d != b"/" else b"", b"")
        after = fs.path_bytes(op.after)
        if after:
            idx = [r for r, _, _ in out].index(after) + 1
            out = out[idx:]
        if match:
            out = [e for e in out if glob_match(match, e[0])]
        page = out[: self.page]
        entries = tuple(fs.FilesEntry(path=r, type=t, size=s) for r, t, s in page)
        return result("list", fs.FilesListAnswer(entries=entries, more=len(out) > self.page))
