"""A session's file calls (``Session.run_files``): one operation on the files inside the
session's sandbox, carried out by plimsoll's own helper as the guest's own user
(docs/session-files.md), a session call like any other, in the chain, with its record
checked against the request sent.

Every path is bytes, end to end. A name in a sandbox may hold any byte but ``/`` and NUL,
which is not always UTF-8, so a name a listing returns is ``bytes`` and is named back by
the same bytes: this client never decodes, normalizes (no Unicode normalization) or
cleans a path (no ``..`` or ``//`` folding; the daemon refuses a path out of its scope).
A path may be given as ``str`` for convenience: it is encoded as Linux's ``os.fsencode``
encodes it (UTF-8, with ``surrogateescape``), so a name that ``os.fsdecode`` turned into
text comes back as the same bytes. A ``*_text`` property is a display form only, lossy
(an invalid byte shows as an escape), and always beside the bytes it shows.

The operations (``scope`` is ``"work"``, a relative path from the session's work folder,
resolved beneath it with a link followed only while it stays inside (one that leaves is
refused, ``symlink``), or ``"sandbox"``, an absolute path resolved as the guest would
resolve it, links followed; docs/session-files.md, "Links, per operation"):

- :class:`FilesStat`, :class:`FilesRead`, :class:`FilesWrite`, :class:`FilesList`,
  :class:`FilesReadMany`, :class:`FilesMakeDir`, :class:`FilesRemove`, :class:`FilesRename`.

The result is a :class:`FilesResult`: ``outcome`` (``completed`` when the helper answered,
else ``timed_out``, ``protocol_error`` or ``runner_failed``), ``error`` (``none``, or the
reason the operation failed: ``not_found``, ``is_dir`` ...), and ``answer``, the
operation's answer when there is one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence, Tuple, Union

from .types import RunEvidence

__all__ = [
    "FilesPath",
    "FilesStat",
    "FilesRead",
    "FilesWrite",
    "FilesList",
    "FilesReadMany",
    "FilesMakeDir",
    "FilesRemove",
    "FilesRename",
    "FilesOperation",
    "FilesEntry",
    "FilesItem",
    "FilesStatAnswer",
    "FilesReadAnswer",
    "FilesWriteAnswer",
    "FilesListAnswer",
    "FilesReadManyAnswer",
    "FilesResult",
    "path_bytes",
    "path_text",
]

FilesPath = Union[bytes, str]
"""A path: bytes as they are, or text encoded as ``os.fsencode`` encodes it on Linux."""

MAX_READ = 8 << 20
"""The most one read, and one read_many item, may return: 8 MiB."""
MAX_WRITE = 4 << 20
"""The most one write may carry: 4 MiB."""


def path_bytes(p: FilesPath) -> bytes:
    """``p`` as the bytes sent: bytes unchanged, text encoded as UTF-8 with
    ``surrogateescape`` (``os.fsencode`` on Linux), with no normalization."""
    if isinstance(p, (bytes, bytearray, memoryview)):
        return bytes(p)
    if isinstance(p, str):
        return p.encode("utf-8", "surrogateescape")
    raise TypeError(f"a path is bytes or str, not {type(p).__name__}")


def path_text(p: bytes) -> str:
    """A display form of a path, lossy: a byte that is not UTF-8 shows as ``\\xNN``.
    Never send it back as a path: name a file by its bytes."""
    return p.decode("utf-8", "backslashreplace")


@dataclass(frozen=True)
class FilesStat:
    """A path's type, size and permission bits. In the sandbox scope a link at the last
    part is reported as a link."""

    path: FilesPath
    scope: str = "work"


@dataclass(frozen=True)
class FilesRead:
    """At most ``max_bytes`` (1 to 8 MiB) of a file, from ``offset``."""

    path: FilesPath
    offset: int = 0
    max_bytes: int = MAX_READ
    scope: str = "work"


@dataclass(frozen=True)
class FilesWrite:
    """One file of at most 4 MiB. ``mode`` is ``replace`` (the file becomes ``content``,
    atomically), ``create_only`` (refused with ``exists`` when the path is there) or
    ``append`` (not atomic: after a call that may have run, the file may have grown, so a
    blind retry is unsafe). ``make_parents`` makes the folders on the way."""

    path: FilesPath
    content: bytes
    mode: str = "replace"
    make_parents: bool = False
    scope: str = "work"


@dataclass(frozen=True)
class FilesList:
    """One page of a folder's entries, sorted by their bytes, folders depth first with
    ``recursive``. ``match`` is a glob matched part by part (docs/session-files.md, "Glob");
    empty lists every entry. ``after`` is the last path of the page before, empty for the
    first page; ``budget_bytes`` (8 KiB to 8 MiB) ends a page, and the answer's ``more``
    says one did."""

    path: FilesPath = b"."
    recursive: bool = False
    match: FilesPath = b""
    after: FilesPath = b""
    budget_bytes: int = 1 << 20
    scope: str = "work"


@dataclass(frozen=True)
class FilesReadMany:
    """At most 16,384 files in order, each up to ``max_bytes_each``, until ``budget_bytes``
    ends the answer (its ``more``). One file's error does not fail the call."""

    paths: Sequence[FilesPath]
    max_bytes_each: int = 1 << 20
    budget_bytes: int = MAX_READ
    scope: str = "work"


@dataclass(frozen=True)
class FilesMakeDir:
    """A folder; with ``parents``, the folders above it too, and one already there is done."""

    path: FilesPath
    parents: bool = False
    scope: str = "work"


@dataclass(frozen=True)
class FilesRemove:
    """One file, or with ``dir`` one empty folder. There is no recursive remove."""

    path: FilesPath
    dir: bool = False
    scope: str = "work"


@dataclass(frozen=True)
class FilesRename:
    """``from_path`` renamed to ``to_path``, replacing a file there only with ``replace``."""

    from_path: FilesPath
    to_path: FilesPath
    replace: bool = False
    scope: str = "work"


FilesOperation = Union[FilesStat, FilesRead, FilesWrite, FilesList, FilesReadMany, FilesMakeDir, FilesRemove, FilesRename]


@dataclass(frozen=True)
class FilesEntry:
    """One entry of a listing: its path from the listed folder (bytes), its type
    (``file``, ``dir``, ``link``, ``other``, and in a recursive listing ``unreadable``: a
    folder the walk could not enter, which it names and goes on past) and a regular file's
    size (0 for the rest)."""

    path: bytes
    type: str
    size: int

    @property
    def path_text(self) -> str:
        """A lossy display form of ``path``; name the entry by ``path``."""
        return path_text(self.path)


@dataclass(frozen=True)
class FilesItem:
    """One path's answer in a read_many, in the order asked: its bytes and the file's size
    as its open saw it, or its ``error`` (``none`` when it was read) and ``errno``."""

    error: str
    errno: str
    content: bytes
    size_at_open: int


@dataclass(frozen=True)
class FilesStatAnswer:
    type: str
    size: int
    mode: int
    """The permission bits."""


@dataclass(frozen=True)
class FilesReadAnswer:
    content: bytes
    size_at_open: int
    """The file's size as the read's open saw it: no promise about any later moment."""


@dataclass(frozen=True)
class FilesWriteAnswer:
    written: int


@dataclass(frozen=True)
class FilesListAnswer:
    entries: Tuple[FilesEntry, ...]
    more: bool
    """The budget ended the page: ask again with ``after`` set to the last entry's path."""


@dataclass(frozen=True)
class FilesReadManyAnswer:
    items: Tuple[FilesItem, ...]
    more: bool
    """The next path's answer did not fit the budget: ask again for the rest."""


FilesAnswer = Union[FilesStatAnswer, FilesReadAnswer, FilesWriteAnswer, FilesListAnswer, FilesReadManyAnswer]


@dataclass(frozen=True, kw_only=True)
class FilesResult(RunEvidence):
    """A file call's result. ``outcome`` is ``completed`` when the helper answered (then
    ``error`` says whether the operation succeeded: ``none``, or ``not_found``, ``is_dir``,
    ``not_dir``, ``exists``, ``symlink``, ``not_regular``, ``permission_denied``,
    ``too_large``, ``no_space``, ``read_only``, ``not_empty``, ``scan_limit``, ``other``),
    ``timed_out`` when the call's deadline passed, ``protocol_error`` when the helper's
    answer could not be read, ``runner_failed`` when it ended without one. A file that is
    not there is an answered ``not_found``, as a nonzero exit is, not an exception.

    ``op`` is the operation the answer names (``stat``, ``read``, ``write``, ``list``,
    ``read_many``, ``make_dir``, ``remove``, ``rename``), "" when there is no answer;
    ``answer`` is its answer, None for make_dir, remove and rename, which answer nothing,
    and whenever ``op`` is ""."""

    outcome: str
    error: str
    errno: str
    """The errno name the error came from (``ENOENT`` ...), "" with none."""
    op: str
    answer: Optional[FilesAnswer]

    @property
    def ok(self) -> bool:
        """The operation was carried out: completed with no error."""
        return self.outcome == "completed" and self.error == "none"
