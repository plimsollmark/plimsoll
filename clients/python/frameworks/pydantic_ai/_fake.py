"""An in-memory plimsoll session for the PydanticAI suite, and the check that keeps it the shape of the real one.

:class:`FakeSession` answers what a real :class:`plimsoll_client.workspace.Workspace` sends a session (its own
fixed steps: the work directory, reads, a shell command) and the backend's fixed scripts, recognized by their
text, against a small POSIX tree in memory. It keeps a session's state as the real :class:`plimsoll_client.Session`
does: ``ended`` once an answer or a refusal said the session ended, ``stopped`` once a call raised an error without
plimsoll's not-dispatched mark. A test makes the next calls fail or answer otherwise through :attr:`FakeSession.plan`.

:func:`shape_differences` compares a fake with the real class attribute by attribute (a property stays a property,
a method a method with the real one's parameters): the public OpenAI adapter shipped broken for five weeks because
a fake modeled a property as a method."""

from __future__ import annotations

import base64
import inspect
import posixpath
import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

import plimsoll_client.pydantic_ai as pa
import plimsoll_client.workspace as pw
from plimsoll_client import Client, PlimsollError, RecoveringError, Session, SessionEndedError
from plimsoll_client._tables import RECOVERING_TEXT
from plimsoll_client._wire import Msg
from plimsoll_client.types import Artifact, LostCall, ProjectResult, RunRecord, SessionEnded, SessionSummary, StepResult

ROOT = "/work"
STATE = ROOT + "/" + pw.STATE_DIR


def record(sequence: int, previous: str, *, isolation: str = "kernel") -> RunRecord:
    digest = f"{sequence:064x}"
    return RunRecord(version=5, request_sha256="1" * 64, result_sha256="2" * 64, provider="fake", isolation=isolation,
                     environment="", policy="", software_identity="", software_rule_id="", started_unix_ms=1,
                     ended_unix_ms=2, session="f" * 64, sequence=sequence, previous_sha256=previous, sha256=digest)


@dataclass
class Tree:
    """A POSIX tree in memory: directories, files, and the paths the sandbox user may not read or write."""

    dirs: Set[str] = field(default_factory=lambda: {"/", ROOT, STATE, "/tmp"})
    files: Dict[str, bytes] = field(default_factory=dict)
    unreadable: Set[str] = field(default_factory=set)
    unwritable: Set[str] = field(default_factory=set)

    def exists(self, p: str) -> bool:
        return p in self.dirs or p in self.files

    def ancestors_code(self, p: str, write: bool) -> Optional[int]:
        """The fixed scripts' _ANCESTORS: _ENOTDIR for an ancestor that is a file, _EACCES for an unwritable nearest
        directory when writing."""
        a = posixpath.dirname(p) or "/"
        while True:
            if a in self.files:
                return pa._ENOTDIR
            if a in self.dirs:
                return pa._EACCES if write and a in self.unwritable else None
            if a == "/":
                return None
            a = posixpath.dirname(a) or "/"

    def mkdirs(self, p: str) -> None:
        while p not in self.dirs:
            self.dirs.add(p)
            p = posixpath.dirname(p) or "/"

    def children(self, p: str) -> List[Tuple[str, bool]]:
        prefix = p.rstrip("/") + "/"
        out = []
        for d in self.dirs:
            if d != p and d.startswith(prefix) and "/" not in d[len(prefix):]:
                out.append((d[len(prefix):], True))
        for f in self.files:
            if f.startswith(prefix) and "/" not in f[len(prefix):]:
                out.append((f[len(prefix):], False))
        return out

    def remove(self, p: str) -> None:
        self.files.pop(p, None)
        prefix = p.rstrip("/") + "/"
        self.dirs = {d for d in self.dirs if d != p and not d.startswith(prefix)}
        self.files = {f: c for f, c in self.files.items() if not f.startswith(prefix)}


# One scripted answer: an exception to raise, or a function of the call returning a ProjectResult.
Planned = Any


class FakeSession:
    """What a backend's Workspace asks of a plimsoll Session (``run_project`` and ``close``), and the state the
    backend reads (``ended``, ``stopped``), over a :class:`Tree`. ``plan`` holds what the next calls do instead of
    answering: an exception, raised (unmarked ones stop the session, as Session does), or a function of the call's
    files and steps returning a ProjectResult. ``commands`` are the shell commands the shell tool sent.

    A session taken over across a lost call carries it in ``lost_call`` (a :class:`LostCall`), as the real one does,
    and is recovering: every call is refused with nothing sent (``RecoveringError``) until ``resolve_lost_call()``,
    which ``resolves`` counts."""

    def __init__(self, *, isolation: str = "kernel", tree: Optional[Tree] = None) -> None:
        self.fingerprint = "f" * 64
        self.provider = "fake"
        self.isolation = isolation
        self.isolation_qualification = ""
        self.software_identity = ""
        self.tree = tree if tree is not None else Tree()
        self.plan: List[Planned] = []
        self.commands: List[str] = []
        self.scripts: List[str] = []
        self.budgets: List[float] = []
        self.closes = 0
        self.lost_call: Optional[LostCall] = None
        self.resolves = 0
        self.refused_recovering = 0  # the calls refused while recovering
        self._ended: Optional[SessionEnded] = None
        self._stopped: Optional[str] = None
        self._calls = 0
        self._last = ""

    @property
    def ended(self) -> Optional[SessionEnded]:
        return self._ended

    @property
    def stopped(self) -> Optional[str]:
        return self._stopped

    @property
    def calls(self) -> int:
        return self._calls

    @property
    def last_record_sha256(self) -> str:
        return self._last

    def resolve_lost_call(self) -> None:
        self.resolves += 1
        self.lost_call = None

    def end(self, reason: str = "expired") -> None:
        self._ended = SessionEnded(reason=reason, detail="")

    def close(self) -> SessionSummary:
        self.closes += 1
        if self._ended is None:
            self._ended = SessionEnded(reason="closed", detail="")
        return SessionSummary(session=self.fingerprint, calls=self._calls, last_record_sha256=self._last, end="closed")

    def run_project(self, files: Any, steps: Sequence[str], artifacts: Sequence[str] = (), *, timeout: Optional[float] = None,
                    minimum_isolation: Optional[str] = None, software: Any = None, grant_profile: Optional[str] = None,
                    trace_id: Optional[str] = None, cancel: Any = None) -> ProjectResult:
        if self._ended is not None:
            raise SessionEndedError(f"plimsoll: the session has ended ({self._ended.reason})", reason=self._ended.reason,
                                    not_dispatched="request")
        if self._stopped is not None:
            raise PlimsollError("plimsoll: an earlier call ... sends nothing more", code="failed_precondition", not_dispatched="request")
        files = dict(files)
        if self.lost_call is not None:
            self.refused_recovering += 1
            raise RecoveringError(f"plimsoll: {RECOVERING_TEXT}; nothing was sent", not_dispatched="request")
        self.budgets.append(timeout or 0.0)
        if self.plan:
            planned = self.plan.pop(0)
            if isinstance(planned, BaseException):
                if isinstance(planned, SessionEndedError):
                    self._ended = SessionEnded(reason=planned.reason, detail="")
                if isinstance(planned, PlimsollError) and planned.not_dispatched is None:
                    if planned.record is not None:
                        self._calls, self._last = planned.record.sequence, planned.record.sha256
                    else:
                        self._stopped = planned.message
                raise planned
            return planned(self, files, list(steps))
        return self.answer(files, list(steps))

    # ---- answering as a sandbox would ----

    def result(self, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0, *, outcome: str = "completed",
               timed_out: bool = False, stdout_truncated: bool = False, steps: bool = True,
               artifacts: Tuple[Artifact, ...] = (), ended: Optional[str] = None) -> ProjectResult:
        self._calls += 1
        rec = record(self._calls, self._last, isolation=self.isolation)
        self._last = rec.sha256
        if ended is not None:
            self._ended = SessionEnded(reason=ended, detail="")
        step = StepResult(command="", stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=timed_out, duration_ms=1,
                          stdout_truncated=stdout_truncated, stderr_truncated=False)
        return ProjectResult(provider="fake", isolation=self.isolation, environment="", software_identity="", duration_ms=1,
                             record=rec, outcome=outcome, detail="", steps=(step,) if steps else (),
                             artifacts=(Artifact(pw._ROOT, (ROOT + "\n").encode()),) + artifacts, artifacts_truncated=False,
                             advice=())

    def answer(self, files: Dict[str, str], steps: List[str]) -> ProjectResult:
        step = steps[0]
        if step == pw._ROOT_STEP:
            return self.result()
        if step == pw._EXEC_STEP:
            command = files[pw._CMD]
            self.commands.append(command)
            return self.result(f"ran {command}\n".encode(), artifacts=(Artifact(pw._CWD, (ROOT + "\n").encode()),))
        if step in (pw._READ_STEP, pw._READ_AT_STEP):
            rel, n = files[pw._A1], int(files[pw._A2])
            start = int(files.get(pw._A3, "1")) - 1
            path = rel if rel.startswith("/") else posixpath.join(ROOT, rel)
            if path not in self.tree.files:
                return self.result(b"", b"cannot read", 1)
            return self.result(artifacts=(Artifact(pw._OUT, self.tree.files[path][start : start + n]),))
        if step == pw._RUN_STEP:
            argv = shlex.split(files[pw._RUN].strip().splitlines()[-1])[1:]
            stdin = base64.b64decode(files[pw._IN_B64])
            assert argv[:2] == ["sh", "-c"] and argv[3] == "sh", argv
            script, args = argv[2], argv[4:]
            self.scripts.append(script)
            code, out = self.script(script, args, stdin)
            return self.result(out, b"", code)
        raise AssertionError(f"a step the backend never sends: {step!r}")

    def script(self, script: str, args: List[str], stdin: bytes) -> Tuple[int, bytes]:
        t = self.tree
        p = args[0] if args else ""
        if script == pa._EXISTS:
            return (0 if t.exists(p) else 1), b""
        if script == pa._STAT:
            if p in t.dirs:
                return 0, b"d\n"
            if p in t.files:
                return 0, f"f{len(t.files[p])}\n".encode()  # stat reads no file, so an unreadable one has a size
            return t.ancestors_code(p, False) or pa._ENOENT, b""
        if script == pa._READ_CHECK:
            if p in t.dirs:
                return pa._EISDIR, b""
            if p not in t.files:
                return t.ancestors_code(p, False) or pa._ENOENT, b""
            if p in t.unreadable:
                return pa._EACCES, b""
            return 0, f"{len(t.files[p])}\n".encode()
        if script == pa._LIST:
            if p not in t.dirs:
                return (pa._ENOTDIR if p in t.files else (t.ancestors_code(p, False) or pa._ENOENT)), b""
            return 0, b"".join((b"d" if d else b"-") + name.encode() + b"\0" for name, d in t.children(p))
        if script == pa._WRITE_BEGIN:
            stage = args[2]
            if p in t.dirs:
                return pa._EISDIR, b""
            if p in t.unwritable:
                return pa._EACCES, b""
            code = t.ancestors_code(p, True)
            if code:
                return code, b""
            t.mkdirs(posixpath.dirname(p))
            t.files[stage or p] = stdin
            return 0, b""
        if script == pa._WRITE_APPEND:
            t.files[p] = t.files.get(p, b"") + stdin
            return 0, b""
        if script == pa._WRITE_COMMIT:
            stage = args[1]
            t.files[p] = t.files.pop(stage, b"") + stdin
            return 0, b""
        if script == pa._WRITE_ABORT:
            t.files.pop(p, None)
            return 0, b""
        if script == pa._MAKE_DIR:
            if p in t.dirs:
                return 0, b""
            if p in t.files:
                return pa._EEXIST, b""
            code = t.ancestors_code(p, True)
            if code:
                return code, b""
            t.mkdirs(p)
            return 0, b""
        if script == pa._REMOVE:
            if not t.exists(p):
                return t.ancestors_code(p, False) or pa._ENOENT, b""
            if (posixpath.dirname(p) or "/") in t.unwritable:
                return pa._EACCES, b""
            t.remove(p)
            return 0, b""
        if script == pa._REALPATH:
            return 0, posixpath.normpath(p).encode()
        raise AssertionError(f"a script the backend does not have: {script[:60]!r}")


class FakeClient(Client):
    """A Client whose open_session answers a FakeSession, with no daemon; ``opened`` keeps each open's options."""

    def __init__(self, *, isolation: str = "kernel", tree: Optional[Tree] = None) -> None:
        super().__init__("http://127.0.0.1:9")
        self.isolation = isolation
        self.tree = tree
        self.opened: List[Dict[str, Any]] = []
        self.sessions: List[FakeSession] = []
        self.refuse: List[BaseException] = []  # raised by the next opens, in order
        self.attached: List[Any] = []  # each attach's key and store
        self.attach_answer: Any = None  # what an attach answers (a FakeSession, or an error it raises); None raises as an empty store does

    def open_session(self, *, minimum_isolation: Optional[str] = None, software: Any = None, lifetime: Optional[float] = None,
                     idle_timeout: Optional[float] = None, trace_id: Optional[str] = None, languages: Optional[Sequence[str]] = None,
                     owner: Optional[str] = None, warm_only: bool = False, keep_no_answer: bool = False, checkpoint_store: Any = None,
                     checkpoint_key: Optional[str] = None) -> Any:
        opened: Dict[str, Any] = {"minimum_isolation": minimum_isolation, "lifetime": lifetime, "languages": languages, "owner": owner}
        if checkpoint_store is not None or checkpoint_key is not None:
            opened.update(checkpoint_store=checkpoint_store, checkpoint_key=checkpoint_key)
        self.opened.append(opened)
        if self.refuse:
            raise self.refuse.pop(0)
        s = FakeSession(isolation=self.isolation, tree=self.tree)
        self.sessions.append(s)
        return s

    def attach_session(self, key: str, *, store: Any, fingerprint: Optional[str] = None, trace_id: Optional[str] = None,
                       cancel: Any = None) -> Any:
        """Reads the store as the real attach does, then records the attach and answers ``attach_answer``, or, with
        none, as an attach whose store holds nothing under the key does. With ``fingerprint``, a stored record naming
        another session is refused before anything is sent (recorded), as the real client refuses it."""
        loaded = store.load(key)
        if fingerprint is not None and loaded is not None and loaded.checkpoint.session != fingerprint:
            raise LookupError("plimsoll: the checkpoint store holds another session under this key than the one named; nothing was sent")
        self.attached.append((key, store))
        if self.attach_answer is None:
            raise LookupError("plimsoll: the checkpoint store holds no session under this key")
        if isinstance(self.attach_answer, BaseException):
            raise self.attach_answer
        return self.attach_answer

    @property
    def session(self) -> FakeSession:
        assert len(self.sessions) == 1, f"{len(self.sessions)} sessions opened"
        return self.sessions[0]


# ---- the shape check ----

_MISSING = object()


def _kind(value: Any) -> str:
    if isinstance(value, (staticmethod, classmethod)) or inspect.isfunction(value) or inspect.ismethod(value):
        return "method"
    return "value"  # a property, or a plain attribute: both are read, never called


def real_session() -> Session:
    """A real Session, made as the client makes one from an open's answer, to read its instance attributes."""
    return Session(None, "fake-session-id", Msg({}, "OpenSessionResponse"), None)  # type: ignore[arg-type]


def shape_differences(fake: Any, real: Any, *, only: Optional[Sequence[str]] = None) -> List[str]:
    """Each public attribute of ``fake`` (or the names in ``only``) that ``real`` lacks, that is a method on one
    and a value (a property or an attribute) on the other, or a method whose parameters do not accept what the
    real one's do: names, kinds and which have defaults."""
    out = []
    names = only if only is not None else [n for n in dir(fake) if not n.startswith("_")]
    for name in names:
        f = inspect.getattr_static(fake, name, _MISSING)
        r = inspect.getattr_static(real, name, _MISSING)
        if r is _MISSING:
            out.append(f"{name}: the real {type(real).__name__} has none")
            continue
        if f is _MISSING:
            out.append(f"{name}: the fake has none")
            continue
        if _kind(f) != _kind(r):
            out.append(f"{name}: a {_kind(f)} on the fake, a {_kind(r)} on the real {type(real).__name__}")
            continue
        if _kind(f) == "method":
            out.extend(f"{name}: {d}" for d in _signature_differences(getattr(fake, name), getattr(real, name)))
    return out


def _signature_differences(fake: Callable[..., Any], real: Callable[..., Any]) -> List[str]:
    fs, rs = inspect.signature(fake).parameters, inspect.signature(real).parameters
    out = []
    for name, p in rs.items():
        q = fs.get(name)
        if q is None:
            out.append(f"the fake lacks the parameter {name!r}")
        elif q.kind != p.kind:
            out.append(f"{name!r} is {q.kind.description} on the fake, {p.kind.description} on the real one")
        elif p.default is not inspect.Parameter.empty and q.default is inspect.Parameter.empty:
            out.append(f"{name!r} has a default on the real one and none on the fake")
    for name, q in fs.items():
        if name not in rs:
            out.append(f"the fake has a parameter {name!r} the real one does not")
    return out
