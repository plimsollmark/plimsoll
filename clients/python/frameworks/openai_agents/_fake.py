"""A plimsoll workspace kept in memory for the OpenAI Agents SDK suites: it counts every
call it is handed (a refused one too), answers each command with a checked-looking
result (a tier, a run record with a digest of its own), and can hold a call until its
cancel handle is cancelled. The real daemon-backed paths are in test_openai_sandbox's
DaemonTests and in docker_openai_check."""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Any, Dict, List, Optional, Sequence

from plimsoll_client import AtCapacityError, InsufficientIsolationError, PlimsollError
from plimsoll_client.types import ProjectResult, RunRecord, StepResult
from plimsoll_client.files import FilesReadAnswer
from plimsoll_client.workspace import ExecOutcome, Workspace, WorkspaceCallError

CANARY = "GUEST-CANARY-7f3a"
"""Text a guest controls (its output, its file names): no label may ever carry it."""


def record(n: int, isolation: str = "container", qualification: str = "", sha256: Optional[str] = None) -> RunRecord:
    digest = sha256 if sha256 is not None else hashlib.sha256(f"record {n}".encode()).hexdigest()
    return RunRecord(
        version=5, request_sha256="0" * 64, result_sha256="1" * 64, provider="fake", isolation=isolation, environment="",
        policy="", software_identity="", software_rule_id="", started_unix_ms=0, ended_unix_ms=1, session="fp-fake",
        sequence=n, previous_sha256="", sha256=digest, isolation_qualification=qualification,
    )


def project(n: int, *, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0, timed_out: bool = False, outcome: str = "completed",
            steps: bool = True, isolation: str = "container", qualification: str = "", detail: str = "", sha256: Optional[str] = None) -> ProjectResult:
    step = StepResult(command="exec", stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=timed_out, duration_ms=1,
                      stdout_truncated=False, stderr_truncated=False)
    return ProjectResult(
        provider="fake", isolation=isolation, isolation_qualification=qualification, environment="", software_identity="",
        duration_ms=1, record=record(n, isolation, qualification, sha256), outcome=outcome, detail=detail,
        steps=(step,) if steps else (), artifacts=(), artifacts_truncated=False, advice=(),
    )


class FakeSession:
    fingerprint = "fp-fake"
    isolation = "container"

    def __init__(self) -> None:
        self.closed = False
        self.stopped: Optional[str] = None

    @property
    def ended(self) -> Optional[str]:
        # A property, as plimsoll_client.Session's is.
        return "closed" if self.closed else None

    def close(self) -> None:
        self.closed = True


class FakeWorkspace:
    """Commands it knows, by their text: ``echo X``; ``false`` (exit 1); ``sleep ...`` (past
    its budget); ``refuse capacity`` / ``refuse isolation`` (refused, nothing ran);
    ``lost`` (an unmarked error, with an unanswered record); ``setup`` and ``incomplete``
    (answered, without a usable result); ``canary`` (the guest prints the canary);
    ``qualified`` (a tier with the provider's sentence); ``bad-labels`` (a result whose
    tier, sentence and digest are outside their closed sets). Any other command exits 0.
    ``hold`` makes every call wait until its cancel handle is cancelled (only the command
    ``hold_only`` names, when it names one)."""

    root = "/work"

    def __init__(self) -> None:
        self.session = FakeSession()
        self.files: Dict[str, bytes] = {}
        self.commands: List[str] = []
        self.budgets: List[Optional[float]] = []
        self.cancels: List[Any] = []
        self.calls = 0  # every call handed to the workspace, a refused one included
        self.hydrated: List[bytes] = []
        self.reads: List[Any] = []  # (path, offset) of every read, in order
        self.hold: Optional[threading.Event] = None
        self.hold_only: Optional[str] = None  # hold only this command, when set
        self.held = threading.Event()  # set once a held call is waiting
        self.ended_hold = threading.Event()  # set once a held call has returned

    def _enter(self, cancel: Any, command: Optional[str] = None) -> None:
        self.calls += 1
        self.cancels.append(cancel)
        if self.hold is not None and (self.hold_only is None or command == self.hold_only):
            self.held.set()
            # A cancel that never comes fails the test at its deadline; it must not hold
            # the worker thread, which the interpreter waits for at exit, for ever.
            deadline = time.monotonic() + 3
            while not (cancel is not None and cancel.cancelled):
                if time.monotonic() > deadline:
                    raise PlimsollError("plimsoll: the fake's hold was never cancelled")
                self.hold.wait(0.01)
            self.ended_hold.set()
            raise PlimsollError("plimsoll: the request was cancelled")

    def exec(self, command: str, *, timeout: Optional[float] = None, cancel: Any = None) -> ExecOutcome:
        self.commands.append(command)
        self.budgets.append(timeout)
        self._enter(cancel, command)
        n = self.calls
        if command == "refuse capacity":
            raise AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        if command == "refuse isolation":
            raise InsufficientIsolationError("plimsoll: below the floor", not_dispatched="isolation")
        if command == "lost":
            e = PlimsollError("plimsoll: the connection broke after the call was sent")
            e.record = record(n)
            raise e
        if command == "setup":
            raise WorkspaceCallError("plimsoll: the call did not run: setup_failed: x", project(n, outcome="setup_failed", steps=False, detail=CANARY))
        if command == "incomplete":
            raise WorkspaceCallError("plimsoll: incomplete", project(n, outcome="runner_failed", steps=False, detail=CANARY))
        if command.startswith("echo "):
            r = project(n, stdout=(command[5:] + "\n").encode())
        elif command == "false":
            r = project(n, stderr=b"no\n", exit_code=1)
        elif command.startswith("sleep"):
            r = project(n, exit_code=124, timed_out=True, outcome="timed_out")
        elif command == "canary":
            r = project(n, stdout=f"{CANARY}\n".encode(), stderr=f"{CANARY}/file.txt\n".encode())
        elif command == "qualified":
            r = project(n, isolation="vm", qualification="The vendor states this is not a security boundary.")
        elif command == "bad-labels":
            r = project(n, isolation=CANARY, qualification=f"{CANARY}\n", sha256=CANARY)
        else:
            r = project(n)
        step = r.steps[0]
        return ExecOutcome(stdout=step.stdout, stderr=step.stderr, exit_code=step.exit_code, timed_out=step.timed_out or r.outcome == "timed_out",
                           stdout_truncated=False, stderr_truncated=False, cwd="/work", result=r)

    def run(self, argv: Sequence[str], *, cancel: Any = None) -> Any:
        self._enter(cancel)
        assert list(argv[:3]) == ["wc", "-c", "--"], argv
        path = argv[3]
        size = len(self.files[path]) if path in self.files else 0
        return ExecOutcome(stdout=f"{size} {path}\n".encode(), stderr=b"", exit_code=0 if path in self.files else 1, timed_out=False,
                           stdout_truncated=False, stderr_truncated=False, cwd="/work", result=project(self.calls))

    # The whole-file reads are the real Workspace's, over this fake's read, so the
    # adapter's reads past one call's budget run the code they run on a real session.
    read_whole = Workspace.read_whole
    read_pieces = Workspace.read_pieces
    read_head = Workspace.read_head
    _pieces = Workspace._pieces

    def _path(self, path: str, *, folder: bool) -> str:
        return path

    def _read(self, rel: str, shown: Any, offset: int, max_bytes: int, cancel: Any) -> FilesReadAnswer:
        # A read states the file's size as its open saw it, as a file call's does.
        content = self.read(rel, max_bytes=max_bytes, offset=offset, cancel=cancel)
        return FilesReadAnswer(content=content, size_at_open=len(self.files.get(rel, b"")))

    def read(self, path: str, *, max_bytes: int = 1 << 20, offset: int = 0, cancel: Any = None) -> bytes:
        self._enter(cancel)
        self.reads.append((path, offset))
        if path == "refused":
            raise AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        if path == "slow":  # Workspace._call's own error for a call past its budget
            raise TimeoutError("plimsoll: the call ran past its budget of 120.0 s")
        if path not in self.files:
            raise FileNotFoundError(path)
        if path == "shrinking" and offset > 0:
            return b""  # cut short between the pieces of one read
        return self.files[path][offset : offset + max_bytes]

    def write(self, path: str, content: Any, *, cancel: Any = None) -> None:
        self._enter(cancel)
        if path == "refused":
            raise AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        if path == "slow":
            raise TimeoutError("plimsoll: the call ran past its budget of 120.0 s")
        self.files[path] = content.encode() if isinstance(content, str) else bytes(content)

    def persist(self, *, cancel: Any = None) -> bytes:
        self._enter(cancel)
        return b"TAR:" + ",".join(sorted(self.files)).encode()

    def hydrate(self, data: bytes, *, cancel: Any = None) -> None:
        self._enter(cancel)
        self.hydrated.append(data)

    def close(self) -> None:
        self.session.close()
