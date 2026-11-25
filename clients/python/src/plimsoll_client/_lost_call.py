"""What a framework adapter tells a model about a call whose answer was lost before a takeover.

A session taken over across a lost call is recovering (``Session.lost_call``): the client refuses every call until
the application resolves it. The PydanticAI and Deep Agents adapters resolve it on the model's next tool call: that
tool call is not run, and the model is told, in this module's words, what plimsoll's record of the lost call says,
and the lost call's output when the daemon kept its answer, cut to the adapter's output limit. The words come from
values the client checked only: whether the record states a result digest (the daemon answered the call, which does
not show that the command ran to its end) or an unanswered code (the call ended without an answer, which does not
show that the command started), and its two times. Never the code itself, the command (only its digest is known
here), or an identifier. The record says whether the daemon answered the call; nothing here claims more.
"""

from __future__ import annotations

import re
from typing import Any, Optional, Tuple

from ._tables import UNANSWERED_CODES
from .types import LostCall, ProjectResult, RunRecord

__all__ = ["lost_call_message"]

# How a call whose record states an unanswered code ended, for the codes plimsoll can say something plain about;
# every other code of the closed set gets _ENDED_OTHER.
_ENDED_HOW = {
    "canceled": "the request for it was called off",
    "deadline_exceeded": "the request for it ran out of time",
}
_ENDED_OTHER = "the sandbox service reported an error for it"
_UNANSWERED = frozenset(UNANSWERED_CODES)
_HEX64 = re.compile("[0-9a-f]{64}")

_HEAD = (
    "plimsoll: this tool call was not run. Before it, plimsoll found that the last call sent to this sandbox (sent "
    "before this agent's process took the sandbox over) never got its answer back to the agent."
)
_TAIL = (
    "Anything that call wrote to files is still in the sandbox: look there before you repeat it. Then send this tool "
    "call again if you still want it; it will be run."
)


def _took(r: RunRecord) -> Optional[str]:
    if isinstance(r.started_unix_ms, int) and isinstance(r.ended_unix_ms, int):
        return f"{max(0, r.ended_unix_ms - r.started_unix_ms) / 1000:.1f} s"
    return None


def _streams(answer: Any) -> Optional[Tuple[int, bool, str, str, bool]]:
    """(exit code, timed out, stdout, stderr, cut by the daemon) of a lost call's answer: a project's first step, or a
    snippet's or cell's own streams; None for an answer with no step."""
    if isinstance(answer, ProjectResult):
        if not answer.steps:
            return None
        s = answer.steps[0]
        return s.exit_code, s.timed_out or answer.outcome == "timed_out", s.stdout_text, s.stderr_text, s.stdout_truncated or s.stderr_truncated
    stdout, stderr = getattr(answer, "stdout_text", None), getattr(answer, "stderr_text", None)
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        return None
    cut = bool(getattr(answer, "stdout_truncated", False) or getattr(answer, "stderr_truncated", False))
    return int(getattr(answer, "exit_code", 0)), bool(getattr(answer, "timed_out", False)), stdout, stderr, cut


def _output(answer: Any, max_chars: int) -> str:
    """The lost call's output as the adapters show a command's: its exit code, stdout and stderr each cut at
    ``max_chars``, and a mark when either was cut (here or by the daemon)."""
    streams = _streams(answer)
    if streams is None:
        outcome = getattr(answer, "outcome", "")
        return f"(no step reported: {outcome})" if outcome else "(no output)"
    code, timed_out, stdout, stderr, cut = streams
    cut = cut or len(stdout) > max_chars or len(stderr) > max_chars
    head = f"exit code: {code}"
    if timed_out:
        head += " (it ran past its time budget and was stopped)"
    parts = [head]
    if stdout:
        parts.append(stdout[:max_chars].rstrip("\n"))
    if stderr:
        parts.append("stderr:\n" + stderr[:max_chars].rstrip("\n"))
    if cut:
        parts.append("[output truncated]")
    return "\n".join(parts)


def lost_call_message(lost: LostCall, max_chars: int) -> str:
    """The text a model is told, in place of its next tool call's result, about the lost call ``lost`` (the
    session's ``lost_call``, which the client checked): one for a record that states a result digest (with the
    answer's output when the daemon kept it, each stream cut at ``max_chars``), one for a record that states an
    unanswered code, and one for no record at hand (a session taken over from a checkpoint that carried the lost
    call's digest without its record). A record stating both, or neither, or a code outside the closed set, is read
    as no record."""
    r = lost.record
    took = _took(r) if r is not None else None
    if r is not None and took is not None:
        if r.unanswered == "" and isinstance(r.result_sha256, str) and _HEX64.fullmatch(r.result_sha256):
            if lost.answer is not None:
                return (
                    f"{_HEAD} The sandbox answered that call after {took}, and kept its answer, which follows; whether "
                    f"it did what was meant is for you to judge from it. {_TAIL}\n\n"
                    f"The lost call's answer:\n{_output(lost.answer, max_chars)}"
                )
            return (
                f"{_HEAD} The sandbox answered that call after {took}, but the answer is lost, so whether it ran to its "
                f"end, and whether it succeeded, is not known. {_TAIL}"
            )
        if r.result_sha256 == "" and r.unanswered in _UNANSWERED:
            return (
                f"{_HEAD} That call ended without an answer after {took}: {_ENDED_HOW.get(r.unanswered, _ENDED_OTHER)}. "
                f"Whether it began, and how much of its work it did, is not known, and any output it gave is lost. {_TAIL}"
            )
    return f"{_HEAD} Whether the sandbox answered that call is not known here. {_TAIL}"
