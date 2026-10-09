"""Framework-neutral, fresh Python/JavaScript execution over the checked client.

Dependencies are supplied by the daemon's project image. This helper never opens
a persistent session, installs packages, runs code on the client host or retries
a request. Guest failures are ProjectResult values. Describe errors before Run
keep their refusal reason, with environment added only when none was supplied
(request for a cancelled Describe). Errors from Run retain their original
dispatch mark. One cancel handle covers both requests of a call.
"""

from __future__ import annotations

import math
from typing import Optional, Sequence

from . import _validate as v
from ._transport import CancelHandle
from .client import Client
from .errors import InsufficientIsolationError, PlimsollError, RequestCanceledError, UnsupportedError
from .types import ProjectResult, SoftwareRule, meets

__all__ = ["CodeExecutor"]

# Fixed commands, never assembled from model-provided code or file names. runpy
# keeps the work directory on Python's import path so caller files can be modules.
# JavaScript runs as a native ES-module script (.mjs), with imports and top-level
# await, unlike the TypeScript tool's notebook-style runner. It has no implicit
# require global: CommonJS loading can use import {createRequire} from 'node:module'
# and createRequire(process.cwd() + '/') explicitly in the caller's module.
_RUNNERS = {
    "python": (
        ".plimsoll/code.py",
        'python3 -c \'import runpy; runpy.run_path(".plimsoll/code.py", run_name="__main__")\'',
    ),
    "javascript": (".plimsoll/code.mjs", "node .plimsoll/code.mjs"),
}


class CodeExecutor:
    """One fresh project per call, with a required isolation floor.

    The default 30-second daemon budget bounds interactive calculations well below
    the daemon's five-minute ceiling. Operators can choose a different positive
    budget up to that ceiling. Ordinary Docker needs an explicit container floor
    for controlled development; hostile code requires verified kernel or VM tier.
    """

    def __init__(
        self,
        client: Client,
        *,
        minimum_isolation: str = "kernel",
        timeout: float = 30.0,
        software: Optional[SoftwareRule] = None,
    ) -> None:
        if not v.floor(minimum_isolation):
            raise v.invalid("CodeExecutor requires an explicit minimum isolation tier")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise v.invalid("CodeExecutor timeout must be positive finite seconds, at most 300")
        self.client = client
        self.minimum_isolation = minimum_isolation
        self.timeout = timeout
        self.software = v.software_rule(software)

    def execute_code(
        self,
        code: str,
        *,
        language: str = "python",
        files: v.FilesArg = None,
        artifacts: Sequence[str] = (),
        cancel: Optional[CancelHandle] = None,
    ) -> ProjectResult:
        """Run code and text files in a fresh sandbox and capture named artifacts.

        Files may be a mapping or path/content pairs. The existing client validates
        paths, duplicates and size limits. Its byte-valued outputs and checked run
        record are returned unchanged, including truncation and timeout flags.

        ``cancel`` (a :class:`~plimsoll_client.CancelHandle`) stops the call from
        another thread. Cancelled before Run is sent, during Describe included, the
        call raises RequestCanceledError marked not dispatched, reason ``request``,
        and no Run is ever sent. Cancelled once Run may have been sent, it cuts Run's
        connection and raises an unmarked RequestCanceledError: the code may have run.
        """
        v.code(code)
        if not isinstance(language, str) or language not in _RUNNERS:
            raise UnsupportedError("CodeExecutor supports python or javascript", not_dispatched="unsupported")
        supplied = v._file_list(files)
        for file in supplied:
            path = file["path"]
            if path == ".plimsoll" or path.startswith(".plimsoll/"):
                raise v.invalid(".plimsoll/ is reserved for CodeExecutor's script")
        script, command = _RUNNERS[language]
        project_files = [(f["path"], f["content"]) for f in supplied] + [(script, code)]
        # Validate the complete payload before any HTTP exchange, including the
        # reserved script's contribution to file count and total content size.
        payload = v.project(project_files, [command], artifacts)
        try:
            info = self.client.describe(cancel=cancel)
        except PlimsollError as exc:
            # Describe cannot run code, and no Run has been sent by this call.
            # Preserve the original error and any daemon-supplied refusal reason.
            if exc.not_dispatched is None:
                exc.not_dispatched = "request" if isinstance(exc, RequestCanceledError) else "environment"
            raise
        if not info.supports_project:
            raise UnsupportedError("the daemon does not support projects", not_dispatched="unsupported")
        if not meets(info.isolation, self.minimum_isolation):
            raise InsufficientIsolationError("the daemon is below CodeExecutor's isolation floor", not_dispatched="isolation")
        languages = info.project_environment.languages
        if languages and language not in languages:
            raise UnsupportedError(f"the project image does not state support for {language}", not_dispatched="unsupported")
        return self.client.run_project(
            project_files, [command], payload.get("artifacts", []),
            timeout=self.timeout, minimum_isolation=self.minimum_isolation, software=self.software, cancel=cancel,
        )
