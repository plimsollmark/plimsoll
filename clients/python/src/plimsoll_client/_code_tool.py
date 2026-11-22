"""The model-facing half of the framework code tools (``plimsoll_client.agno`` and
``plimsoll_client.crewai``): one description, one input check and one result shape,
so every framework's tool says the same thing in the same words. Execution is
:class:`~plimsoll_client.execution.CodeExecutor`'s; nothing here runs code.

A tool answers the model with a dict, never an exception, because a framework shows
a tool's exception to the model as text anyway and drops the structure. The dict
says whether the code ran: ``ran`` is ``True`` (the result is the guest's, a
non-zero exit included), ``False`` (plimsoll refused before anything ran; ``refused``
says why) or ``"unknown"`` (an error after which the code may have run, or a run that
ended without its step's report; it was not retried, and retrying is the caller's
decision). ``outcome`` is plimsoll's own word for how a run ended, where there was one.

:func:`arun` is the frameworks' async path: the call runs in a worker thread with a
:class:`~plimsoll_client.CancelHandle` that is cancelled when the await is, so a
cancelled call never sends a Run it had not sent yet and cuts one in flight.

A tool whose executor carries a grant (``CodeExecutor(grant_profile=..., api_description=...)``)
offers only the languages that can call the API on its daemon (:func:`offered`), says in
its description what the code can call and how (:func:`api_text`), and refuses a call in
another language as ``unsupported`` with what to write instead. The tool's arguments
never name a profile: the application chose it when it built the executor.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import _validate as v
from ._transport import CancelHandle, in_thread
from .errors import PlimsollError
from .execution import CodeExecutor, Grant
from .types import ProjectResult

# The tool's name in every framework. Not "run_code": Agno's own DaytonaTools has a
# run_code, and Agno keeps the first toolkit's tool of a name and skips the next with only
# a log warning, so plimsoll could be silently absent; and a
# crew that opts into CrewAI's cache keys it by tool name.
TOOL_NAME = "plimsoll_run_code"

LANGUAGES: Tuple[str, ...] = ("python", "javascript")
NAMES = {"python": "Python 3", "javascript": "JavaScript (Node.js, run as an ES module: use import, not require)"}
# Characters of stdout and of stderr a tool returns to the model. 16,000 is about
# 4,000 tokens per stream: enough for a traceback and a printed table, short enough
# that one runaway print cannot fill the model's context.
MAX_OUTPUT_CHARS = 16_000
# The client's project limit, less the script CodeExecutor adds and the module a granted
# Python call carries, so a call the tool accepts is never refused for its file count.
# The client's other limits (size, paths) still apply.
MAX_INPUT_FILES = v.MAX_PROJECT_FILES - 2

UNKNOWN_NOTE = "The code may have run. It was not retried; running it again could repeat what it did."
# A granted tool's note says what else may have happened.
GRANTED_UNKNOWN_NOTE = ("The code may have run, and may have called the API too, as many times as the run's call budget "
                        "allows. It was not retried; running it again could repeat what it did.")
# Said after a granted run's permission refusal: the daemon's words name the profile; these
# say whose it is to fix and what to do meanwhile.
PERMISSION_NOTE = ("The API this tool is set up to call is not available to it, so nothing ran: the grant profile is "
                   "unknown to the daemon, or this caller is not on it. That is the operator's to fix; do not retry, "
                   "and tell the user the API could not be reached.")

# The reasons a refusal is the model's to fix (its code, language or files). Any other
# refusal (the daemon's isolation, image, capacity, a permission) is the operator's,
# and is also logged.
MODEL_FIXABLE = frozenset({"request", "unsupported"})

log = logging.getLogger("plimsoll_client")


def check_languages(languages: Iterable[str]) -> Tuple[str, ...]:
    langs = tuple(languages)
    if not langs or len(set(langs)) != len(langs) or any(lang not in LANGUAGES for lang in langs):
        raise ValueError(f"plimsoll: languages must be a non-empty list of distinct names from {LANGUAGES}, not {langs!r}")
    return langs


def check_max_output(n: int) -> int:
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("plimsoll: max_output_chars must be a positive int")
    return n


def offered(executor: CodeExecutor, languages: Iterable[str]) -> Tuple[str, ...]:
    """The languages a tool offers: the application's (check_languages), and with a
    grant only those whose code can call the API on the daemon the executor described
    when it was built, so the model is never offered a language that would be refused.
    None of them is the application's mistake, said at once."""
    langs = check_languages(languages)
    grant = executor.grant
    if grant is None:
        return langs
    kept = tuple(lang for lang in langs if lang in grant.languages)
    if not kept:
        raise ValueError(f"plimsoll: this tool's code is to call the API of grant profile {grant.profile!r}, and on this "
                         f"daemon none of {list(langs)} can: {grant.refusal(langs[0])}")
    return kept


def description(languages: Sequence[str], grant: Optional[Grant] = None) -> str:
    """The tool's description for the languages it offers, and with a grant what the
    code can call and how: plimsoll's words, then the API's description as the
    application gave it (plimsoll-specgen's, for the profile). No credential is in
    either: the application never holds one."""
    names = " or ".join(NAMES[lang] for lang in languages)
    network = "no network access" if grant is None else "no network access except the one web API described below"
    text = (
        f"Run {names} in a fresh, isolated sandbox with {network} and return its exit code, stdout and stderr. "
        "Every call starts from nothing: no variable, import or file from an earlier call exists, so each call must "
        "contain all the code it needs. Print what you want to see; the value of a last expression is not shown. "
        "Only the libraries installed in the sandbox image are available, and nothing can be installed. "
        "To give the code data, such as another tool's output, pass it in input_files rather than pasting it into the "
        "code; the code reads each file by its relative path. "
        "The result's ran field says whether the code ran (true), was refused before anything ran (false, with the "
        "reason), or may have run without an answer to show for it (\"unknown\"; it was not retried). It also reports the isolation "
        "tier the code ran behind and the SHA-256 of the run record the client checked."
    )
    return text if grant is None else text + "\n\n" + api_text(languages, grant)


def api_text(languages: Sequence[str], grant: Grant) -> str:
    """What a granted tool tells its model about the API, in every kit the same words:
    the routes are the only requests sent, the credential is added outside, the budget,
    what a call that changes data means, and how each offered language calls it."""
    lines = [
        "This tool's code can call one web API, described below, from inside the sandbox. Only its routes listed below "
        "(each a method and a path) are sent to it: any other request is refused before it leaves, and so is a call "
        "past the run's call budget (status 429). plimsoll adds the API's key outside the sandbox; the code never needs "
        "one. A call that changes data takes effect even if the program fails afterwards, and a run is never retried.",
    ]
    if "javascript" in languages:
        lines.append("In JavaScript, call it through the global client the description names, as it shows; each call "
                     "returns a promise, so await it.")
    if "python" in languages:
        lines.append("In Python, import plimsoll_host and call plimsoll_host.get(path), post(path, body), put(path, body), "
                     "patch(path, body), delete(path) or call(method, path, body) with a route's method and path from the "
                     "list below; each returns the answer's parsed JSON and raises plimsoll_host.HostAPIError, which has "
                     ".status and .body, for any other status.")
    elif "python" not in grant.languages:
        lines.append(f"Python code cannot call the API on this sandbox (its provider, {grant.provider}, gives a Python "
                     "step no way to reach it).")
    lines.append("The API:\n" + grant.description)
    return "\n".join(lines)


CODE_HELP = "The complete source to run. Print what you need to see."
LANGUAGE_HELP = "The language of code."
FILES_HELP = "Text files written into the working directory before the code runs, for data the code should read."
PATH_HELP = "A relative path, such as data/orders.csv."
CONTENT_HELP = "The file's text."


def _files(input_files: Optional[Sequence[Any]]) -> List[Tuple[str, str]]:
    # Each entry arrives as the framework decoded it: a dict, or a pydantic model of
    # the same two fields.
    out: List[Tuple[str, str]] = []
    for f in input_files or ():
        if isinstance(f, Mapping):
            path, content = f.get("path"), f.get("content")
        else:
            path, content = getattr(f, "path", None), getattr(f, "content", None)
        if not isinstance(path, str) or not isinstance(content, str):
            raise TypeError("each input file needs a string path and a string content")
        out.append((path, content))
    return out


def run(
    executor: CodeExecutor,
    languages: Sequence[str],
    max_output_chars: int,
    code: str,
    language: Optional[str],
    input_files: Optional[Sequence[Any]],
    cancel: Optional[CancelHandle] = None,
    trace_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Runs one tool call and returns what the model is shown. ``trace_id`` goes on
    the run as its correlation ID; one the client would refuse is the caller's to drop
    before it gets here."""
    lang = language or languages[0]
    grant = executor.grant
    if lang not in languages:
        if grant is not None and lang in LANGUAGES and lang not in grant.languages:
            return _refusal("unsupported", grant.refusal(lang))
        return _refusal("request", f"this tool runs {' or '.join(languages)}, not {lang!r}")
    if not isinstance(code, str) or not code.strip():
        return _refusal("request", "code is empty")
    if input_files is not None and len(input_files) > MAX_INPUT_FILES:
        return _refusal("request", f"at most {MAX_INPUT_FILES} input files")
    try:
        files = _files(input_files)
    except TypeError as e:
        return _refusal("request", str(e))
    try:
        result = executor.execute_code(code, language=lang, files=files, cancel=cancel, trace_id=trace_id)
    except PlimsollError as e:
        if e.not_dispatched is not None:
            if e.not_dispatched not in MODEL_FIXABLE:
                log.warning("plimsoll: a code tool call was refused (%s): %s", e.not_dispatched, e.message)
            if grant is not None and e.not_dispatched == "permission":
                return _refusal(e.not_dispatched, e.message + " " + PERMISSION_NOTE)
            return _refusal(e.not_dispatched, e.message)
        log.warning("plimsoll: a code tool call ended in an error after which the code may have run: %s", e.message)
        return {"ran": "unknown", "error": e.message, "note": unknown_note(grant)}
    return _result(lang, result, max_output_chars, grant)


async def arun(
    executor: CodeExecutor,
    languages: Sequence[str],
    max_output_chars: int,
    code: str,
    language: Optional[str],
    input_files: Optional[Sequence[Any]],
    trace_id: Optional[str] = None,
) -> Dict[str, Any]:
    """:func:`run` in a worker thread. Cancelling the await cancels the call: a Run not
    yet sent is never sent, and the connection of one in flight is cut, so the thread
    returns at once instead of waiting out the executor's deadline."""
    return await in_thread(run, executor, languages, max_output_chars, code, language, input_files, trace_id=trace_id)


def _refusal(reason: str, message: str) -> Dict[str, Any]:
    return {"ran": False, "refused": reason, "error": message}


def unknown_note(grant: Optional[Grant]) -> str:
    return UNKNOWN_NOTE if grant is None else GRANTED_UNKNOWN_NOTE


def _qualification(r: ProjectResult) -> Dict[str, Any]:
    """The sentence the provider states beside the tier, under the tier, when it states
    one (only WSL runs so far), so no result names the tier without it."""
    return {"isolation_qualification": r.isolation_qualification} if r.isolation_qualification else {}


def _result(language: str, r: ProjectResult, max_chars: int, grant: Optional[Grant] = None) -> Dict[str, Any]:
    # Only a step's own report says the code ran, and only setup_failed says it did not:
    # it means no step began. Without a step's report, timed_out, protocol_error and
    # runner_failed leave it unknown. Reading the detail text to tell them apart would be
    # guessing.
    record = r.record.sha256 if r.record is not None else ""
    if not r.steps and r.outcome == "setup_failed":
        return {
            "ran": False,
            "outcome": r.outcome,
            "error": "plimsoll: the run ended setup_failed before any step began" + (f": {r.detail}" if r.detail else ""),
            "isolation": r.isolation,
            **_qualification(r),
            "record_sha256": record,
        }
    if not r.steps:
        return {
            "ran": "unknown",
            "outcome": r.outcome,
            "error": f"plimsoll: the run ended {r.outcome} without a step's report" + (f": {r.detail}" if r.detail else ""),
            "note": unknown_note(grant),
            "isolation": r.isolation,
            **_qualification(r),
            "record_sha256": record,
        }
    step = r.steps[0]
    stdout, stderr = step.stdout_text, step.stderr_text
    return {
        "ran": True,
        "outcome": r.outcome,
        "language": language,
        "exit_code": step.exit_code,
        "timed_out": step.timed_out or r.outcome == "timed_out",
        "stdout": stdout[:max_chars],
        "stderr": stderr[:max_chars],
        "truncated": step.stdout_truncated or step.stderr_truncated or len(stdout) > max_chars or len(stderr) > max_chars,
        "isolation": r.isolation,
        **_qualification(r),
        "record_sha256": record,
    }
