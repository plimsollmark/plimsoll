"""OpenAI Agents SDK, sandbox provider: a plimsoll session as a `SandboxAgent`'s sandbox.

The Agents SDK (``openai-agents`` 0.23.1, read on 2026-10-13) runs a ``SandboxAgent``'s
commands and files in a sandbox session it gets from a provider: a ``BaseSandboxClient``
that creates, resumes and deletes sessions, and a ``BaseSandboxSession`` that runs a
command, reads and writes a file, and saves and restores the workspace. This module is that
provider over plimsoll: every command is a call of one plimsoll session through
:class:`plimsoll_client.workspace.Workspace` (a fixed step, the command as a file), so the
daemon's guarantees hold for the agent's whole run: the isolation floor the session was
opened at, a run record on every call, no network. The SDK's maintainers keep third-party
providers out of the SDK, so this one lives here.

    from agents.sandbox import SandboxAgent, SandboxRunConfig
    from plimsoll_client import Client
    from plimsoll_client.openai_sandbox import PlimsollSandboxClient, PlimsollSandboxClientOptions

    client = PlimsollSandboxClient(Client("https://plimsoll.internal", token=...))
    run_config = SandboxRunConfig(client=client, options=PlimsollSandboxClientOptions(minimum_isolation="kernel"))

What differs from a provider that owns a machine, stated here and in the docstrings: the
work directory is the daemon's (``/work`` on docker), learned from the sandbox at create
unless the manifest names it; ``resume`` opens a new session and lets the SDK restore the
snapshot into it, since this client cannot re-attach to a session another process opened
(the state carries the session's public fingerprint, never its ID); no PTY; no exposed
ports; no manifest users or groups (a plimsoll sandbox runs as one user); a background
process does not survive a command (the session's sweep). ``stop`` and ``delete`` close
the session: the sandbox is gone, the snapshot keeps the files.
"""

from __future__ import annotations

import asyncio
import io
import shlex
import uuid
from pathlib import Path
from typing import Any, Callable, List, Literal, Optional, Sequence

try:
    import agents.sandbox  # noqa: F401  (the extra this module needs; named if it is missing)
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.openai_sandbox needs the OpenAI Agents SDK: pip install 'plimsoll-client[openai-agents]'") from e
from agents.sandbox.errors import ExecTimeoutError
from agents.sandbox.manifest import Manifest
from agents.sandbox.materialization import MaterializationResult
from agents.sandbox.session import SandboxSession, SandboxSessionState
from agents.sandbox.session.base_sandbox_session import BaseSandboxSession
from agents.sandbox.session.dependencies import Dependencies
from agents.sandbox.session.manager import Instrumentation
from agents.sandbox.session.sandbox_client import BaseSandboxClient, BaseSandboxClientOptions
from agents.sandbox.snapshot import SnapshotBase, SnapshotSpec, resolve_snapshot
from agents.sandbox.types import ExecResult

from .client import Client
from .errors import PlimsollError
from .workspace import MAX_READ_BYTES, Workspace

__all__ = ["PlimsollSandboxClient", "PlimsollSandboxClientOptions", "PlimsollSandboxSession", "PlimsollSandboxSessionState"]

BACKEND_ID = "plimsoll"
_DEFAULT_MANIFEST_ROOT = str(Manifest.model_fields["root"].default)

WorkspaceFactory = Callable[["PlimsollSandboxClientOptions"], Workspace]


class PlimsollSandboxClientOptions(BaseSandboxClientOptions):
    """How a session is opened: the isolation floor (``kernel`` by default: a docker
    daemon without gVisor is refused), the languages hint for a daemon's warm pool, and
    the budget of a command the SDK gives no timeout."""

    type: Literal["plimsoll"] = "plimsoll"
    minimum_isolation: str = "kernel"
    languages: tuple[str, ...] = ("python",)
    timeout: float = 120.0

    def __init__(
        self,
        minimum_isolation: str = "kernel",
        languages: tuple[str, ...] = ("python",),
        timeout: float = 120.0,
        *,
        type: Literal["plimsoll"] = "plimsoll",
    ) -> None:
        super().__init__(type=type, minimum_isolation=minimum_isolation, languages=tuple(languages), timeout=timeout)


class PlimsollSandboxSessionState(SandboxSessionState):
    """What a persisted session keeps: the daemon, how the session was opened (so a resume
    opens its replacement the same way), the session's public fingerprint and the tier it
    opened at. Never the session ID: a resume cannot use it, and the state is written
    wherever the app keeps run state."""

    type: Literal["plimsoll"] = "plimsoll"
    base_url: str = ""
    minimum_isolation: str = "kernel"
    languages: tuple[str, ...] = ("python",)
    timeout: float = 120.0
    fingerprint: str = ""
    isolation: str = ""


class PlimsollSandboxSession(BaseSandboxSession):
    """One plimsoll session as an Agents SDK sandbox session."""

    state: PlimsollSandboxSessionState

    def __init__(self, *, state: PlimsollSandboxSessionState, workspace: Workspace) -> None:
        self.state = state
        self._workspace = workspace
        self._running = False

    @property
    def workspace(self) -> Workspace:
        return self._workspace

    # ---- lifecycle hooks the base class drives ----

    async def _validate_manifest_application(
        self,
        *,
        only_ephemeral: bool = False,
        manifest: Manifest | None = None,
        session_running: bool | None = None,
    ) -> None:
        _ = (only_ephemeral, session_running)
        from agents.sandbox._mount_security import validate_manifest_mount_credential_boundaries

        validate_manifest_mount_credential_boundaries(manifest or self.state.manifest, provider_backend_id=BACKEND_ID)

    async def _prepare_backend_workspace(self) -> None:
        # The work directory exists before any call: the daemon made it with the session.
        return None

    async def _after_start(self) -> None:
        self._running = True

    async def _after_start_failed(self) -> None:
        self._running = False

    async def _apply_manifest(self, *, only_ephemeral: bool = False, provision_accounts: bool = True) -> MaterializationResult:
        if self.state.manifest.users or self.state.manifest.groups:
            raise ValueError("a plimsoll sandbox runs as one user: manifest users and groups are not supported")
        return await super()._apply_manifest(only_ephemeral=only_ephemeral, provision_accounts=provision_accounts)

    async def provision_manifest_accounts(self) -> None:
        if self.state.manifest.users or self.state.manifest.groups:
            raise ValueError("a plimsoll sandbox runs as one user: manifest users and groups are not supported")

    async def _shutdown_backend(self) -> None:
        await asyncio.to_thread(self._close_quietly)

    async def _after_shutdown(self) -> None:
        self._running = False

    async def _after_stop(self) -> None:
        # A stopped session is closed on the daemon: the snapshot the base class persisted
        # before this hook is what a resume restores.
        await asyncio.to_thread(self._close_quietly)
        self._running = False

    def _close_quietly(self) -> None:
        try:
            self._workspace.close()
        except PlimsollError:
            pass  # ended already; the daemon has it either way

    def supports_pty(self) -> bool:
        return False

    # ---- what the SDK requires of a session ----

    async def _exec_internal(self, *command: str | Path, timeout: float | None = None) -> ExecResult:
        parts = [str(c) for c in command]
        if len(parts) == 3 and parts[0] == "sh" and parts[1] == "-lc":
            text = parts[2]  # the base class's own prefix: the shell is the sandbox's already
        else:
            text = shlex.join(parts)
        try:
            out = await asyncio.to_thread(self._workspace.exec, text, timeout=timeout)
        except TimeoutError as e:
            raise ExecTimeoutError(command=command, timeout_s=timeout, cause=e) from e
        if out.timed_out:
            raise ExecTimeoutError(command=command, timeout_s=timeout)
        return ExecResult(stdout=out.stdout, stderr=out.stderr, exit_code=out.exit_code)

    async def read(self, path: Path, *, user: Any = None) -> io.IOBase:
        _ = user
        data = await asyncio.to_thread(self._workspace.read, str(path), max_bytes=MAX_READ_BYTES)
        return io.BytesIO(data)

    async def write(self, path: Path, data: io.IOBase, *, user: Any = None) -> None:
        _ = user
        payload = data.read()
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        await asyncio.to_thread(self._workspace.write, str(path), bytes(payload))

    async def running(self) -> bool:
        if not self._running:
            return False
        ended = self._workspace.session.ended()
        return ended is None

    async def persist_workspace(self) -> io.IOBase:
        return io.BytesIO(await asyncio.to_thread(self._workspace.persist))

    async def hydrate_workspace(self, data: io.IOBase) -> None:
        payload = data.read()
        await asyncio.to_thread(self._workspace.hydrate, bytes(payload))


class PlimsollSandboxClient(BaseSandboxClient[PlimsollSandboxClientOptions]):
    """Creates, resumes and deletes plimsoll sessions for the Agents SDK.

    ``client`` is the plimsoll client the sessions are opened with. ``workspace_factory``
    replaces how a session's :class:`Workspace` is made, for tests.
    """

    backend_id = BACKEND_ID
    supports_default_options = True

    def __init__(
        self,
        client: Optional[Client],
        *,
        instrumentation: Instrumentation | None = None,
        dependencies: Dependencies | None = None,
        workspace_factory: Optional[WorkspaceFactory] = None,
    ) -> None:
        if client is None and workspace_factory is None:
            raise ValueError("a plimsoll Client is required (a workspace_factory stands in for it in tests)")
        self._client = client
        self._factory = workspace_factory
        self._instrumentation = instrumentation if instrumentation is not None else Instrumentation()
        self._dependencies = dependencies

    def _open(self, options: PlimsollSandboxClientOptions) -> Workspace:
        if self._factory is not None:
            return self._factory(options)
        assert self._client is not None
        session = self._client.open_session(minimum_isolation=options.minimum_isolation, languages=list(options.languages))
        return Workspace(session, timeout=options.timeout)

    async def create(
        self,
        *,
        snapshot: SnapshotSpec | SnapshotBase | None = None,
        manifest: Manifest | None = None,
        options: PlimsollSandboxClientOptions | None = None,
    ) -> SandboxSession:
        resolved = options if options is not None else PlimsollSandboxClientOptions()
        manifest = manifest if manifest is not None else Manifest()
        self._validate_manifest_for_create(manifest)
        workspace = await asyncio.to_thread(self._open, resolved)
        try:
            if manifest.root == _DEFAULT_MANIFEST_ROOT:
                # The daemon decides the work directory; the SDK's default names another.
                root = await asyncio.to_thread(lambda: workspace.root)
                manifest = manifest.model_copy(update={"root": root}, deep=True)
            session_id = uuid.uuid4()
            state = PlimsollSandboxSessionState(
                session_id=session_id,
                manifest=manifest,
                snapshot=resolve_snapshot(snapshot, str(session_id)),
                base_url=self._client.base_url if self._client is not None else "",
                minimum_isolation=resolved.minimum_isolation,
                languages=tuple(resolved.languages),
                timeout=resolved.timeout,
                fingerprint=getattr(workspace.session, "fingerprint", "") or "",
                isolation=getattr(workspace.session, "isolation", "") or "",
            )
        except BaseException:
            await asyncio.to_thread(lambda: _close_quietly(workspace))
            raise
        inner = PlimsollSandboxSession(state=state, workspace=workspace)
        return self._wrap_session(inner, instrumentation=self._instrumentation)

    async def resume(self, state: SandboxSessionState) -> SandboxSession:
        """A new session opened as the old one was; the base class's ``start`` restores
        the snapshot into it. The old session, if it still exists on the daemon, ends by
        its own lifetime: this client cannot reach it from here."""
        if not isinstance(state, PlimsollSandboxSessionState):
            raise TypeError("PlimsollSandboxClient.resume expects a PlimsollSandboxSessionState")
        options = PlimsollSandboxClientOptions(
            minimum_isolation=state.minimum_isolation, languages=tuple(state.languages), timeout=state.timeout
        )
        workspace = await asyncio.to_thread(self._open, options)
        try:
            root = await asyncio.to_thread(lambda: workspace.root) if state.manifest.root == _DEFAULT_MANIFEST_ROOT else state.manifest.root
            new_state = state.model_copy(
                update={
                    "manifest": state.manifest.model_copy(update={"root": root}, deep=True),
                    "fingerprint": getattr(workspace.session, "fingerprint", "") or "",
                    "isolation": getattr(workspace.session, "isolation", "") or "",
                    "workspace_root_ready": False,
                },
                deep=True,
            )
        except BaseException:
            await asyncio.to_thread(lambda: _close_quietly(workspace))
            raise
        inner = PlimsollSandboxSession(state=new_state, workspace=workspace)
        return self._wrap_session(inner, instrumentation=self._instrumentation)

    async def delete(self, session: SandboxSession) -> SandboxSession:
        inner = session._inner
        if not isinstance(inner, PlimsollSandboxSession):
            raise TypeError("PlimsollSandboxClient.delete expects a PlimsollSandboxSession")
        await asyncio.to_thread(inner._close_quietly)
        inner._running = False
        return session

    def deserialize_session_state(self, payload: dict[str, object]) -> SandboxSessionState:
        return self._deserialize_session_state_payload(payload, PlimsollSandboxSessionState)


def _close_quietly(workspace: Workspace) -> None:
    try:
        workspace.close()
    except PlimsollError:
        pass
