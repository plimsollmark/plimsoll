"""verifiers v1, runtime plugin: a plimsoll session as the sandbox of a verifiers rollout.

verifiers (Prime Intellect's environment library, read at 0.4.1.dev97 on 2026-10-27) runs a
task's commands and files through a *runtime*, and since 2026-10-19 takes a runtime from
outside its own tree as a plugin (``type = "custom"`` and an import path). This module is
that plugin over plimsoll: every command, read and write is one call of one plimsoll
session through :class:`plimsoll_client.workspace.Workspace` (a fixed step, the command as a
file), so a verifiers task gets what every plimsoll call gets: the isolation floor the
session was opened at, no network, and a run record per call that this client recomputes
before answering. The records also go to a JSON-lines log that :func:`check_record_log`
rechecks offline; the session's fingerprint on the trace (``trace.agent.runtime.id``) joins
the two.

    [env.agent.runtime]
    type = "custom"
    import_path = "plimsoll_client.verifiers_runtime.PlimsollBackend"
    url = "https://plimsoll.internal"
    minimum_isolation = "kernel"
    record_log = "runs/plimsoll-records.jsonl"

The bearer token comes from the environment variable ``token_env`` names
(``PLIMSOLL_TOKEN`` by default), never from the config, because verifiers saves configs
into its traces.

What differs from verifiers' docker and prime runtimes, stated here because a plugin that
fails part of the upstream conformance suite must say so:

- **No network, in any phase.** verifiers lets setup download packages before a task's
  policy closes the network; a plimsoll sandbox never has one. The config's allow list is
  empty and cannot be widened, so a task that asks for no egress is accepted and one that
  asks for a host is refused before anything runs. A setup that downloads fails with its
  own exit code.
- **The shipped harnesses do not run inside it.** Each starts its agent program inside the
  runtime, installs it with uv from the network, and calls the model over HTTP (the
  ``bash`` harness fails in its setup: ``wget: bad address 'astral.sh'``). What runs here
  unchanged: task setup, ``vf-validate`` and grading (shared or isolated). A model attempt
  runs through ``plimsoll-bash`` (:mod:`plimsoll_client.verifiers_harness`), the shipped
  ``bash`` harness's own loop on the evaluator.
- **One image, one work directory.** The sandbox runs the image its operator configured
  and works in the daemon's work directory (``/work`` on docker). ``SUPPORTS_TASK_IMAGES``
  is declared, because verifiers uses it as its test for a container runtime (tasks that
  run model-written code, isolated grading); a task naming another image is refused at
  start, naming both, before any of its code runs. A task's work directory is accepted
  when, inside the sandbox, it resolves to the session's (the same path, or a link the
  image carries, checked by one call at start); any other is refused the same way. The
  root file system is read-only, so ``/tests``, ``/logs`` or ``/app`` exist only if the
  image provides them.
- **No process outlives its call**: a session's sweep ends what a call leaves running, so
  ``run_background`` is refused (and with it tool servers, compose and setup daemons).
  ``exec`` is buffered: the command runs when its output or exit status is first asked
  for, and what was written to its stdin by then is its whole input.
- **Size**: one read returns at most :data:`~plimsoll_client.workspace.MAX_READ_BYTES`
  (8 MiB, the runner's artifact budget); the docker provider's ``/tmp``, where verifiers
  stages artifacts, holds 16 MiB by default.
- **A cut call ends the session's use**: cancelling an await (a phase timeout) cuts the
  request in flight, and this client then sends nothing more on that session, since the
  call may have run. Later operations fail with the client's message, so an attempt whose
  agent phase timed out mid-call is not graded (verifiers' finalize cannot read the
  sandbox), where verifiers' docker runtime would grade it; the daemon stops the command
  and the close reports a call this client has no record of, which
  :func:`check_record_log` lists as ``incomplete``.
- **Calls cost more than a docker exec**: about 290 ms a command under runc and 400 ms
  under gVisor against about 36 ms on verifiers' docker runtime (medians, one development
  machine, 2026-10-27), nearly all of it the daemon's project call. The daemon's default
  rate limit (``SANDBOX_RATE_PER_MIN``, 30 a minute per caller) admits about two attempts
  a minute; evaluation traffic needs it raised.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import re
import threading
import time
from typing import Any, AsyncIterator, ClassVar, Dict, List, Mapping, Optional, Sequence

try:
    import verifiers.v1.runtimes  # noqa: F401  (the extra this module needs; named if it is missing)
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "plimsoll_client.verifiers_runtime needs verifiers v1 with runtime plugins (0.4.1.dev97 or later): "
        "pip install 'plimsoll-client[verifiers]'"
    ) from e
from pydantic import Field, model_validator
from verifiers.v1.configs.runtime import NetworkPolicyConfig
from verifiers.v1.errors import SandboxError
from verifiers.v1.runtimes import (
    CustomRuntimeConfig,
    CustomRuntimeInfo,
    ProgramResult,
    Runtime,
    RuntimeBackend,
    RuntimeProcess,
)

from ._record import record_digest
from ._transport import in_thread
from .client import Client
from .errors import PlimsollError
from .types import RunRecord, meets
from .workspace import MAX_READ_BYTES, STEP_KINDS, ExecOutcome, Workspace, WorkspacePathError, WorkspaceTooLargeError

__all__ = [
    "PlimsollBackend",
    "PlimsollConfig",
    "PlimsollProcess",
    "PlimsollRuntimeInfo",
    "RecordLogError",
    "check_record_log",
]

logger = logging.getLogger(__name__)

IMPORT_PATH = __name__ + ".PlimsollBackend"

# plimsoll's correlation id: the backend's name goes to the daemon's audit line only when
# it already fits, never trimmed (a trimmed id joins to nothing).
_TRACE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")

# Exit codes a shell reports for a process ended by SIGKILL and SIGTERM, for a buffered
# process killed before it ran.
_KILLED = 137
_TERMINATED = 143

# Serializes record log appends across every backend in the process.
_LOG_LOCK = threading.Lock()

# Both directories as the sandbox resolves them, links followed: a task's work directory
# is accepted when it is the session's.
_SAME_DIRECTORY = 'cd -P -- "$1" && pwd -P && cd -P -- "$2" && pwd -P'


class PlimsollConfig(CustomRuntimeConfig, NetworkPolicyConfig):
    """The runtime's settings, validated when verifiers loads the config. ``url`` is the
    daemon (http only to loopback unless ``insecure_http``); ``token_env`` names the
    environment variable holding its bearer token. ``image`` and ``workdir``, when set,
    must be the daemon's own (None: whatever it runs). ``command_timeout`` is each call's
    budget in seconds, capped by the daemon's. ``record_log`` is a JSON-lines file on the
    evaluator that receives every call's checked record."""

    url: str
    token_env: str = "PLIMSOLL_TOKEN"
    insecure_http: bool = False
    minimum_isolation: str = "kernel"
    image: Optional[str] = None
    workdir: Optional[str] = None
    command_timeout: float = 600.0
    lifetime: Optional[float] = None
    idle_timeout: Optional[float] = None
    record_log: Optional[str] = None
    allow: List[str] = Field(default_factory=list)
    """Always empty: a plimsoll sandbox has no network, so no destination can be allowed."""

    @model_validator(mode="after")
    def _no_network(self) -> "PlimsollConfig":
        if self.allow:
            raise ValueError(
                f"the plimsoll runtime has no network, so it cannot allow {self.allow!r}; "
                "a task that needs egress runs elsewhere"
            )
        if self.minimum_isolation not in ("container", "kernel", "vm"):
            raise ValueError("minimum_isolation must be container, kernel or vm (a session never runs at process tier)")
        if self.command_timeout <= 0:
            raise ValueError("command_timeout must be a positive number of seconds")
        return self


class PlimsollRuntimeInfo(CustomRuntimeInfo):
    """What a rollout's trace keeps of the runtime (``trace.agent.runtime``): ``id`` is the
    session's fingerprint, the SHA-256 of its ID, which every record of the session names;
    the rest is what the daemon stated when the session opened."""

    url: str = ""
    provider: str = ""
    isolation: str = ""
    environment: str = ""
    software_identity: str = ""


class _RecordingSession:
    """The session a Workspace drives, passing every checked record to the backend."""

    def __init__(self, session: Any, backend: "PlimsollBackend") -> None:
        self._session = session
        self._backend = backend

    def run_project(self, files: Any, steps: Sequence[str], artifacts: Sequence[str] = (), **kwargs: Any) -> Any:
        op = STEP_KINDS.get(steps[0], "other") if steps else "other"
        try:
            result = self._session.run_project(files, steps, artifacts, **kwargs)
        except PlimsollError as e:
            record = getattr(e, "record", None)
            if isinstance(record, RunRecord):
                self._backend._note_record(op, record)
            raise
        if result.record is not None:
            self._backend._note_record(op, result.record)
        return result

    def close(self) -> Any:
        return self._session.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)


class PlimsollBackend(RuntimeBackend):
    """A verifiers runtime backend over one plimsoll session (see the module docstring)."""

    config_class = PlimsollConfig
    SUPPORTS_TASK_IMAGES: ClassVar[bool] = True
    # Nothing inside the sandbox can reach a URL, so a public tunnel to verifiers'
    # interception server (what a non-local runtime gets) would only publish it.
    is_local = True

    def __init__(self, config: PlimsollConfig, name: Optional[str] = None) -> None:
        super().__init__(name)
        self.config = config
        self.info = PlimsollRuntimeInfo(import_path=config.import_path, url=config.url)
        self.records: List[RunRecord] = []
        self._workspace: Optional[Workspace] = None
        self._lock = threading.Lock()
        self._max_timeout: Optional[float] = None
        self._environment = ""

    # ---- provisioning ----

    def _client(self) -> Client:
        token = os.environ.get(self.config.token_env) or None
        return Client(self.config.url, token, insecure_http=self.config.insecure_http)

    def _open_session(self) -> Any:
        """Opens the session; refuses, before it opens, a daemon without sessions and an
        image the daemon does not run. Tests replace it."""
        client = self._client()
        info = client.describe()
        if not info.supports_sessions:
            raise SandboxError(f"the plimsoll daemon at {self.config.url} offers no sessions (SANDBOX_MAX_SESSIONS is unset or its provider has none)")
        env = info.session_environment
        if self.config.image is not None and self.config.image not in (env.identity, env.software_identity):
            raise SandboxError(
                f"the plimsoll runtime runs only the daemon's image {env.identity or '(unstated)'}; "
                f"the task asks for {self.config.image!r}"
            )
        self._max_timeout = env.max_timeout_ms / 1000 if env.max_timeout_ms else None
        self._environment = env.identity
        trace_id = self.name if _TRACE_ID.match(self.name) else None
        return client.open_session(
            minimum_isolation=self.config.minimum_isolation,
            lifetime=self.config.lifetime,
            idle_timeout=self.config.idle_timeout,
            trace_id=trace_id,
        )

    def _provision(self) -> Workspace:
        session = self._open_session()
        workspace = Workspace(
            _RecordingSession(session, self),
            timeout=self.config.command_timeout,
            max_timeout=self._max_timeout,
            confined=False,
        )
        with self._lock:
            self._workspace = workspace
        self._log(
            {
                "kind": "open",
                "session": session.fingerprint,
                "isolation": session.isolation,
                "provider": session.provider,
                "runtime": self.name,
            }
        )
        root = workspace.root
        workdir = root
        asked = self.config.workdir
        if asked is not None and asked.rstrip("/") != root:
            if not self._same_directory(workspace, asked, root):
                self.cleanup()
                raise SandboxError(
                    f"the plimsoll runtime works in the daemon's directory {root}; the task asks for {asked!r}, "
                    f"which the daemon's image does not make that directory (a link to {root} would)"
                )
            workdir = asked
        self.config = self.config.model_copy(update={"workdir": workdir, "image": self.config.image or self._environment or None})
        self.info.id = session.fingerprint
        self.info.provider = session.provider
        self.info.isolation = session.isolation
        self.info.environment = self._environment
        self.info.software_identity = session.software_identity
        return workspace

    @staticmethod
    def _same_directory(workspace: Workspace, asked: str, root: str) -> bool:
        """Whether ``asked`` is the work directory inside the sandbox, by path or by a
        link the image carries: one call, both resolved by the sandbox's own shell."""
        out = workspace.run(["sh", "-c", _SAME_DIRECTORY, "same-directory", asked, root])
        lines = out.stdout_text.splitlines()
        return out.exit_code == 0 and len(lines) == 2 and lines[0] == lines[1]

    async def start(self) -> None:
        # Opening runs to its answer even when the await is cancelled: a session the
        # daemon opened is one this process must close, so a late open is closed here.
        task = asyncio.ensure_future(asyncio.to_thread(self._provision))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            # Off the event loop: closing is a request to the daemon.
            task.add_done_callback(lambda _t: threading.Thread(target=self.cleanup, daemon=True).start())
            raise
        except PlimsollError as e:
            raise SandboxError(str(e)) from e

    def cleanup(self) -> None:
        """Closes the session (its sandbox and files are gone) and logs the daemon's count
        of calls and last record. Idempotent; also run at interpreter exit."""
        with self._lock:
            workspace, self._workspace = self._workspace, None
        if workspace is None:
            return
        try:
            summary = workspace.close()
        except Exception as e:  # best effort, like every runtime's cleanup
            logger.warning("plimsoll runtime %s: closing the session failed: %s", self.name, e)
            self._log({"kind": "close", "session": self.info.id or "", "error": str(e)})
            return
        self._log(
            {
                "kind": "close",
                "session": summary.session,
                "calls": summary.calls,
                "last_record_sha256": summary.last_record_sha256,
                "end": summary.end,
            }
        )

    # ---- the record log ----

    def _note_record(self, op: str, record: RunRecord) -> None:
        with self._lock:
            self.records.append(record)
        self._log({"kind": "record", "op": op, "record": dataclasses.asdict(record)})

    def _log(self, entry: Dict[str, Any]) -> None:
        path = self.config.record_log
        if not path:
            return
        entry = {"time_unix_ms": int(time.time() * 1000), **entry}
        data = (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        # verifiers runs many rollouts at once, each with a backend of its own, often
        # into one log: one lock for the process and one append per line, so lines of
        # different sessions never interleave.
        with _LOG_LOCK:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view) :]
            finally:
                os.close(fd)

    # ---- operations ----

    def _require(self) -> Workspace:
        workspace = self._workspace
        if workspace is None:
            raise SandboxError(f"the plimsoll runtime {self.name} is not started, or was closed")
        return workspace

    async def _ws(self, method: str, *args: Any, **kwargs: Any) -> Any:
        workspace = self._require()
        try:
            return await in_thread(getattr(workspace, method), *args, **kwargs)
        except PlimsollError as e:
            raise SandboxError(str(e)) from e
        except (WorkspacePathError, WorkspaceTooLargeError) as e:
            raise SandboxError(f"plimsoll runtime: {e}") from e

    async def _run_argv(self, argv: Sequence[str], env: Mapping[str, str], stdin: bytes) -> ExecOutcome:
        return await self._ws("run", list(argv), env=dict(env), stdin=stdin)

    @staticmethod
    def _program_result(out: ExecOutcome) -> ProgramResult:
        stderr = out.stderr_text
        notes = []
        if out.timed_out:
            notes.append("plimsoll: the command ran past its budget and was ended")
        if out.stdout_truncated:
            notes.append("plimsoll: stdout was cut at the daemon's output limit")
        if out.stderr_truncated:
            notes.append("plimsoll: stderr was cut at the daemon's output limit")
        if notes:
            stderr = stderr + ("" if not stderr or stderr.endswith("\n") else "\n") + "\n".join(notes) + "\n"
        return ProgramResult(out.exit_code, out.stdout_text, stderr)

    async def run(self, runtime: Runtime, argv: list[str], env: dict[str, str]) -> ProgramResult:
        """Runs ``argv`` to completion in the work directory, stdin closed: one call."""
        out = await self._run_argv(argv, runtime.process_env(env), b"")
        return self._program_result(out)

    async def exec(self, runtime: Runtime, argv: list[str], env: dict[str, str]) -> RuntimeProcess:
        return PlimsollProcess(self, list(argv), runtime.process_env(env))

    async def run_background(self, runtime: Runtime, argv: list[str], env: dict[str, str], log: str) -> None:
        raise SandboxError(
            "the plimsoll runtime cannot keep a process running after its call: a session's sweep ends "
            "what a call leaves behind; run the command to completion with run, or use another runtime"
        )

    async def read(self, runtime: Runtime, path: str, max_bytes: Optional[int] = None) -> bytes:
        if max_bytes is not None and max_bytes <= 0:
            return b""
        cap = MAX_READ_BYTES if max_bytes is None else min(max_bytes, MAX_READ_BYTES)
        try:
            data = await self._ws("read", path, max_bytes=cap)
        except FileNotFoundError as e:
            raise SandboxError(f"read {path!r}: {e}") from e
        if len(data) >= MAX_READ_BYTES and (max_bytes is None or max_bytes > MAX_READ_BYTES):
            raise SandboxError(f"read {path!r}: at least {MAX_READ_BYTES} bytes, the most the plimsoll runtime reads at once")
        return data

    async def write(self, runtime: Runtime, path: str, data: bytes) -> None:
        try:
            await self._ws("write", path, bytes(data))
        except OSError as e:
            raise SandboxError(f"write {path!r}: {e}") from e

    async def expose(self, port: int) -> str:
        raise SandboxError("the plimsoll runtime publishes no ports: nothing inside its sandbox is reachable from outside")

    async def prepare_execution(self, routes: Optional[List[str]], network: Optional[NetworkPolicyConfig] = None) -> None:
        """Nothing to do: the sandbox has no network before, during or after the agent."""


class PlimsollProcess(RuntimeProcess):
    """A buffered process: the command runs, as one call, when its output or exit status
    is first asked for, with what was written to its stdin by then as its whole input.
    ``poll`` never starts it. Killing it before it starts means it never runs; killing it
    while it runs cuts the call, which ends the session's use (the call may have run)."""

    def __init__(self, backend: PlimsollBackend, argv: List[str], env: Dict[str, str]) -> None:
        self._backend = backend
        self._argv = argv
        self._env = env
        self._stdin = bytearray()
        self._task: Optional["asyncio.Future[ExecOutcome]"] = None
        self._code: Optional[int] = None
        self._out = b""
        self._err = b""
        self.stdout = self._stream(True)
        self.stderr = self._stream(False)

    async def _finish(self) -> None:
        if self._code is not None:
            return
        if self._task is None:
            self._task = asyncio.ensure_future(self._backend._run_argv(self._argv, self._env, bytes(self._stdin)))
        try:
            out = await self._task
        except asyncio.CancelledError:
            if self._code is not None:  # killed while running
                return
            raise
        result = PlimsollBackend._program_result(out)
        self._out, self._err = out.stdout, result.stderr.encode("utf-8", errors="replace")
        self._code = result.exit_code

    async def _stream(self, stdout: bool) -> AsyncIterator[bytes]:
        await self._finish()
        data = self._out if stdout else self._err
        if data:
            yield data

    async def write(self, data: bytes) -> None:
        if self._task is not None or self._code is not None:
            raise BrokenPipeError("plimsoll runtime: the command has started; its stdin is what was written before")
        self._stdin += data

    async def wait(self) -> int:
        await self._finish()
        assert self._code is not None
        return self._code

    async def poll(self) -> Optional[int]:
        return self._code

    async def _end(self, code: int) -> None:
        if self._code is not None:
            return
        self._code = code
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(BaseException):
                await self._task

    async def terminate(self) -> None:
        await self._end(_TERMINATED)

    async def kill(self) -> None:
        await self._end(_KILLED)


class RecordLogError(ValueError):
    """A record log that does not check: the message names the line."""


def check_record_log(path: str, *, minimum_isolation: Optional[str] = None) -> Dict[str, Any]:
    """Rechecks a record log the runtime wrote, with nothing but the file: every record's
    digest recomputed from its fields, every session's chain unbroken (calls 1, 2, 3,
    each naming the one before), each closed session's call count and last record equal
    to its chain's, and every tier at or above ``minimum_isolation``. Returns the number
    of sessions, records and closed sessions, the tiers seen, and ``incomplete``: each
    session the log cannot show whole, with why (a call cut in flight leaves the daemon
    counting a call whose record this client never received, and the close says so; a
    session with no close in the log may still be open). Every record in the log checks
    either way. Raises :class:`RecordLogError` naming the first line that fails."""
    chains: Dict[str, List[RunRecord]] = {}
    closed = 0
    closed_sessions: set = set()
    close_errors: Dict[str, str] = {}
    tiers: Dict[str, int] = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError as e:
                raise RecordLogError(f"{path}:{n}: not JSON: {e}") from None
            kind = entry.get("kind")
            if kind == "record":
                try:
                    r = RunRecord(**entry["record"])
                except (KeyError, TypeError) as e:
                    raise RecordLogError(f"{path}:{n}: not a run record: {e}") from None
                if record_digest(r) != r.sha256:
                    raise RecordLogError(f"{path}:{n}: the record's digest does not match its fields")
                chain = chains.setdefault(r.session, [])
                previous = chain[-1].sha256 if chain else ""
                if r.sequence != len(chain) + 1 or r.previous_sha256 != previous:
                    raise RecordLogError(
                        f"{path}:{n}: session {r.session[:12]} call {r.sequence} follows {r.previous_sha256[:12] or 'nothing'}, "
                        f"the log's last was call {len(chain)}"
                    )
                if minimum_isolation and not meets(r.isolation, minimum_isolation):
                    raise RecordLogError(f"{path}:{n}: tier {r.isolation or 'unknown'} is below {minimum_isolation}")
                chain.append(r)
                tiers[r.isolation] = tiers.get(r.isolation, 0) + 1
            elif kind == "close" and "calls" in entry:
                chain = chains.get(entry["session"], [])
                last = chain[-1].sha256 if chain else ""
                if entry["calls"] != len(chain) or entry["last_record_sha256"] != last:
                    raise RecordLogError(
                        f"{path}:{n}: the daemon closed session {entry['session'][:12]} after {entry['calls']} calls, the log holds {len(chain)}"
                    )
                closed += 1
                closed_sessions.add(entry["session"])
            elif kind == "close":
                close_errors[entry.get("session", "")] = str(entry.get("error", "the close failed"))
            elif kind == "open":
                chains.setdefault(entry["session"], [])
    incomplete = [
        {"session": session[:12], "records": len(chain), "reason": close_errors.get(session, "no close in the log")}
        for session, chain in chains.items()
        if session not in closed_sessions
    ]
    return {
        "sessions": len(chains),
        "records": sum(len(c) for c in chains.values()),
        "closed": closed,
        "tiers": tiers,
        "incomplete": incomplete,
    }
