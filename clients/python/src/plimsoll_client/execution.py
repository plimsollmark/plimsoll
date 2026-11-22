"""Framework-neutral, fresh Python/JavaScript execution over the checked client.

Dependencies are supplied by the daemon's project image. This helper never opens
a persistent session, installs packages, runs code on the client host or retries
a request. Guest failures are ProjectResult values. Describe errors before Run
keep their refusal reason, with environment added only when none was supplied
(request for a cancelled Describe). Errors from Run retain their original
dispatch mark. One cancel handle covers both requests of a call.

An executor built with a grant profile (``CodeExecutor(..., grant_profile=...,
api_description=...)``, chosen by the application, never by a model) sends every run
with that profile, so the code can call the routes of the one web API the operator's
profile allows, through plimsoll's broker outside the sandbox, which holds and adds the
API's credential. It reads the daemon's Describe when it is built and states, in
:attr:`CodeExecutor.grant`, which languages' code can reach the API there: JavaScript
wherever the provider gives a project run a grant (the host client is preloaded into
every Node step), and Python too where every step gets the broker's socket (docker and
openshell, ``_granted.PYTHON_GRANT_PROVIDERS``), through the module ``plimsoll_host``
this executor writes into the run. A call in a language that cannot reach the API is
refused before anything is sent.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

from . import _granted
from . import _validate as v
from ._transport import CancelHandle
from .client import Client
from .errors import InsufficientIsolationError, PlimsollError, RequestCanceledError, UnsupportedError
from .types import Info, ProjectResult, SoftwareRule, meets

__all__ = ["CodeExecutor", "Grant"]

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
# A granted Python call runs the same script with plimsoll_host's directory on the import
# path after the work directory, and carries the module there. A granted JavaScript call
# runs as any other: the provider preloads the host client into every Node step.
_GRANTED_PYTHON = (
    ".plimsoll/code.py",
    "python3 -c 'import runpy, sys; sys.path.insert(1, \"" + _granted.HOST_MODULE_DIR
    + "\"); runpy.run_path(\".plimsoll/code.py\", run_name=\"__main__\")'",
)

#: The most characters of an API description an executor takes: the text goes into a
#: tool's description, which every model request carries. 32,000 is about 8,000 tokens,
#: room for a few hundred routes of plimsoll-specgen's description.
MAX_API_DESCRIPTION_CHARS = 32_000

_LANGUAGE_NAMES = {"python": "Python", "javascript": "JavaScript"}


@dataclass(frozen=True)
class Grant:
    """The grant an executor's runs carry: the profile and the API's description as the
    application chose them, and what the daemon's Describe stated when the executor was
    built. ``languages`` are those whose code can call the API on that daemon;
    ``provider`` is the provider the daemon named."""

    profile: str
    description: str
    provider: str
    languages: Tuple[str, ...]

    def refusal(self, language: str) -> str:
        """Why code in ``language`` cannot call the API here, and what to do instead."""
        name = _LANGUAGE_NAMES.get(language, language)
        others = [_LANGUAGE_NAMES[lang] for lang in self.languages]
        instead = f" Write the program in {' or '.join(others)}." if others else ""
        if language == "python":
            why = f"its provider ({self.provider}) gives a Python step no way to reach plimsoll's broker"
        else:
            why = f"the daemon's project image (provider {self.provider}) states no {name} interpreter"
        return f"plimsoll: {name} code cannot call the API on this sandbox: {why}; nothing ran.{instead}"


def _grant_languages(info: Info) -> Tuple[str, ...]:
    """The languages whose granted project steps reach the broker on the daemon ``info``
    describes: the image's, less Python on a provider that hands Python steps no socket."""
    langs = info.project_environment.languages
    return tuple(lang for lang in ("javascript", "python") if lang in langs
                 and (lang != "python" or info.provider in _granted.PYTHON_GRANT_PROVIDERS))


def _grant_unsupported(info: Info, profile: str) -> Optional[UnsupportedError]:
    """The refusal for a daemon that cannot carry a grant on a project run, or None."""
    if not info.supports_project:
        return UnsupportedError(f"plimsoll: the daemon (provider {info.provider}) runs no projects, so no run of this tool "
                                f"can carry grant profile {profile!r}; nothing ran", not_dispatched="unsupported")
    if not info.supports_project_grants:
        return UnsupportedError(f"plimsoll: the daemon's provider ({info.provider}) cannot give a project run a grant, so this "
                                f"tool's code cannot call the API of grant profile {profile!r}; nothing ran. The operator "
                                "serves the tool from a provider with grants, or builds it without one", not_dispatched="unsupported")
    return None


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
        grant_profile: Optional[str] = None,
        api_description: Optional[str] = None,
    ) -> None:
        """``grant_profile`` and ``api_description``, both or neither, are the
        application's: the name of a grant profile the operator configured on the daemon
        (``PLIMSOLL_GRANTS_FILE``), which every run then carries, and the description of
        its API that ``plimsoll-specgen -emit description`` wrote for that profile, which
        a code tool shows its model. With them the executor reads the daemon's Describe
        once, here, and raises ``UnsupportedError`` (marked not dispatched) when the
        daemon cannot carry a grant on a project run; :attr:`grant` then states which
        languages can reach the API. Whether the daemon knows the profile, and lets this
        caller use it, only a run can tell: an unknown profile and one this caller is not
        on are both refused, reason ``permission``, before anything runs."""
        if not v.floor(minimum_isolation):
            raise v.invalid("CodeExecutor requires an explicit minimum isolation tier")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise v.invalid("CodeExecutor timeout must be positive finite seconds, at most 300")
        self.client = client
        self.minimum_isolation = minimum_isolation
        self.timeout = timeout
        self.software = v.software_rule(software)
        #: The grant every run carries, or None (the default: no network at all).
        self.grant: Optional[Grant] = None
        if grant_profile is not None or api_description is not None:
            self.grant = self._grant(grant_profile, api_description)

    def _grant(self, profile: Optional[str], description: Optional[str]) -> Grant:
        if not isinstance(profile, str) or not profile:
            raise v.invalid("CodeExecutor's grant_profile is the name of a grant profile, set with its api_description")
        v.grant_profile(profile)
        if not isinstance(description, str) or not description.strip():
            raise v.invalid("CodeExecutor's api_description is the API's description (plimsoll-specgen -emit description), set with its grant_profile")
        if len(description) > MAX_API_DESCRIPTION_CHARS:
            raise v.invalid(f"CodeExecutor's api_description holds {len(description)} characters, more than {MAX_API_DESCRIPTION_CHARS}")
        try:
            info = self.client.describe()
        except PlimsollError as exc:
            if exc.not_dispatched is None:
                exc.not_dispatched = "environment"
            raise
        refused = _grant_unsupported(info, profile)
        if refused is not None:
            raise refused
        grant = Grant(profile=profile, description=description, provider=info.provider, languages=_grant_languages(info))
        if not grant.languages:
            raise UnsupportedError(f"plimsoll: no language of the daemon's project image (provider {info.provider}) can call "
                                   "the API from a granted run", not_dispatched="unsupported")
        return grant

    def execute_code(
        self,
        code: str,
        *,
        language: str = "python",
        files: v.FilesArg = None,
        artifacts: Sequence[str] = (),
        cancel: Optional[CancelHandle] = None,
        trace_id: Optional[str] = None,
    ) -> ProjectResult:
        """Run code and text files in a fresh sandbox and capture named artifacts.

        Files may be a mapping or path/content pairs. The existing client validates
        paths, duplicates and size limits. Its byte-valued outputs and checked run
        record are returned unchanged, including truncation and timeout flags.

        ``trace_id`` is the run's opaque correlation ID, the one :meth:`Client.run_project`
        takes: the daemon puts it on the run's audit line and does nothing else with it.

        ``cancel`` (a :class:`~plimsoll_client.CancelHandle`) stops the call from
        another thread. Cancelled before Run is sent, during Describe included, the
        call raises RequestCanceledError marked not dispatched, reason ``request``,
        and no Run is ever sent. Cancelled once Run may have been sent, it cuts Run's
        connection and raises an unmarked RequestCanceledError: the code may have run.

        With a :attr:`grant`, the run carries its profile; code in a language that cannot
        reach the API on this daemon is refused, marked not dispatched, reason
        ``unsupported``, before Describe, and so is any call once Describe says the
        daemon can no longer carry the grant.
        """
        v.code(code)
        v.trace_id(trace_id)
        if not isinstance(language, str) or language not in _RUNNERS:
            raise UnsupportedError("CodeExecutor supports python or javascript", not_dispatched="unsupported")
        grant = self.grant
        if grant is not None and language not in grant.languages:
            raise UnsupportedError(grant.refusal(language), not_dispatched="unsupported")
        supplied = v._file_list(files)
        for file in supplied:
            path = file["path"]
            if path == ".plimsoll" or path.startswith(".plimsoll/"):
                raise v.invalid(".plimsoll/ is reserved for CodeExecutor's script")
        granted_python = grant is not None and language == "python"
        script, command = _GRANTED_PYTHON if granted_python else _RUNNERS[language]
        project_files = [(f["path"], f["content"]) for f in supplied] + [(script, code)]
        if granted_python:
            project_files.append((_granted.HOST_MODULE_PATH, _granted.HOST_MODULE_SOURCE))
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
        # Every daemon states its languages (protocol 4): one that states none proved
        # none, and is refused rather than let try (review B9, 2026-10-23).
        if language not in languages:
            raise UnsupportedError(f"the project image does not state support for {language}", not_dispatched="unsupported")
        if grant is not None:
            # A daemon can change under a long-lived executor (restarted on another
            # provider): what it states now decides, before anything is sent.
            refused = _grant_unsupported(info, grant.profile)
            now = _grant_languages(info)
            if refused is None and language not in now:
                refused = UnsupportedError(Grant(grant.profile, grant.description, info.provider, now).refusal(language),
                                           not_dispatched="unsupported")
            if refused is not None:
                raise refused
        return self.client.run_project(
            project_files, [command], payload.get("artifacts", []),
            timeout=self.timeout, minimum_isolation=self.minimum_isolation, software=self.software, cancel=cancel,
            grant_profile=grant.profile if grant is not None else None, trace_id=trace_id,
        )
