"""An asyncio face on the client, for async agent frameworks.

Each call runs the blocking client in a worker thread (``asyncio.to_thread``), so
the checks, the errors and the results are exactly the synchronous client's.
Cancelling an awaiting task stops the wait, not the request: the HTTP exchange
runs on in its thread until it finishes or reaches the client's
``request_timeout``, and a run it carried may execute. A session that
``open_session`` opens after its await was cancelled is closed, not left
holding a slot on the daemon until it expires.
"""

from __future__ import annotations

import asyncio
import ssl
import threading
from typing import Any, List, Optional, Sequence

from . import _validate as v
from .client import DEFAULT_REQUEST_TIMEOUT, Client, Session
from .types import (
    CellResult,
    Info,
    JavaScriptResult,
    ModuleResult,
    ProjectResult,
    SessionEnded,
    SessionSummary,
    SoftwareRule,
)

__all__ = ["AsyncClient", "AsyncSession"]


class AsyncClient:
    """The asynchronous counterpart of :class:`Client`, with the same arguments."""

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        *,
        insecure_http: bool = False,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.sync = Client(
            base_url, token, insecure_http=insecure_http, request_timeout=request_timeout, ssl_context=ssl_context
        )
        """The synchronous client every call goes through."""

    def __repr__(self) -> str:
        return f"AsyncClient({self.sync.base_url!r})"

    async def describe(self) -> Info:
        return await asyncio.to_thread(self.sync.describe)

    async def run_javascript(
        self,
        code: str,
        *,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        grant_profile: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> JavaScriptResult:
        return await asyncio.to_thread(
            self.sync.run_javascript,
            code,
            timeout=timeout,
            minimum_isolation=minimum_isolation,
            software=software,
            grant_profile=grant_profile,
            trace_id=trace_id,
        )

    async def run_project(
        self,
        files: v.FilesArg,
        steps: Sequence[str],
        artifacts: Sequence[str] = (),
        *,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        grant_profile: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> ProjectResult:
        return await asyncio.to_thread(
            self.sync.run_project,
            files,
            steps,
            artifacts,
            timeout=timeout,
            minimum_isolation=minimum_isolation,
            software=software,
            grant_profile=grant_profile,
            trace_id=trace_id,
        )

    async def run_module(
        self,
        model: str,
        rows: Sequence[Sequence[float]],
        *,
        end_time: float,
        step: float,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        trace_id: Optional[str] = None,
    ) -> ModuleResult:
        return await asyncio.to_thread(
            self.sync.run_module,
            model,
            rows,
            end_time=end_time,
            step=step,
            timeout=timeout,
            minimum_isolation=minimum_isolation,
            software=software,
            trace_id=trace_id,
        )

    async def open_session(
        self,
        *,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        lifetime: Optional[float] = None,
        idle_timeout: Optional[float] = None,
        trace_id: Optional[str] = None,
    ) -> "AsyncSession":
        # Cancelling the await does not stop the open in its thread, and a session
        # the daemon opens after the cancel would reach nobody and hold its slot
        # until it expired. So the thread closes a session nobody waits for any
        # more, and one it handed over just as the cancel came is closed here.
        lock = threading.Lock()
        handed: List[Session] = []
        abandoned = False

        def open_in_thread() -> Optional[Session]:
            s = self.sync.open_session(
                minimum_isolation=minimum_isolation,
                software=software,
                lifetime=lifetime,
                idle_timeout=idle_timeout,
                trace_id=trace_id,
            )
            with lock:
                if not abandoned:
                    handed.append(s)
                    return s
            s._close_quietly()
            return None

        try:
            s = await asyncio.to_thread(open_in_thread)
        except asyncio.CancelledError:
            with lock:
                abandoned = True
                orphans = list(handed)
            for o in orphans:
                threading.Thread(target=o._close_quietly, name="plimsoll-close-abandoned-session").start()
            raise
        if s is None:  # unreachable: only a cancel abandons the open
            raise asyncio.CancelledError()
        return AsyncSession(s)


class AsyncSession:
    """The asynchronous counterpart of :class:`Session`; ``async with`` closes it."""

    def __init__(self, session: Session) -> None:
        self.sync = session
        """The synchronous session every call goes through."""

    def __repr__(self) -> str:
        return f"Async{self.sync!r}"

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    @property
    def fingerprint(self) -> str:
        return self.sync.fingerprint

    @property
    def isolation(self) -> str:
        return self.sync.isolation

    @property
    def ended(self) -> Optional[SessionEnded]:
        return self.sync.ended

    @property
    def calls(self) -> int:
        return self.sync.calls

    async def run_javascript(
        self,
        code: str,
        *,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        grant_profile: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> JavaScriptResult:
        return await asyncio.to_thread(
            self.sync.run_javascript,
            code,
            timeout=timeout,
            minimum_isolation=minimum_isolation,
            software=software,
            grant_profile=grant_profile,
            trace_id=trace_id,
        )

    async def run_project(
        self,
        files: v.FilesArg,
        steps: Sequence[str],
        artifacts: Sequence[str] = (),
        *,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        grant_profile: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> ProjectResult:
        return await asyncio.to_thread(
            self.sync.run_project,
            files,
            steps,
            artifacts,
            timeout=timeout,
            minimum_isolation=minimum_isolation,
            software=software,
            grant_profile=grant_profile,
            trace_id=trace_id,
        )

    async def run_cell(
        self,
        code: str,
        language: str = "python",
        *,
        files: v.FilesArg = None,
        timeout: Optional[float] = None,
        minimum_isolation: Optional[str] = None,
        software: Optional[SoftwareRule] = None,
        trace_id: Optional[str] = None,
    ) -> CellResult:
        return await asyncio.to_thread(
            self.sync.run_cell,
            code,
            language,
            files=files,
            timeout=timeout,
            minimum_isolation=minimum_isolation,
            software=software,
            trace_id=trace_id,
        )

    async def close(self) -> SessionSummary:
        return await asyncio.to_thread(self.sync.close)
