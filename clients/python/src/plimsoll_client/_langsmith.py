"""What the LangChain tool states on the tool call's LangSmith run: trusted labels, as
metadata, and nothing else.

When an agent is traced in LangSmith, each tool call is a run there. After a call the
tool adds to that run's metadata what plimsoll's answer states about the run, and
nothing the guest wrote: the SHA-256 of the run record the client checked, the
isolation tier and the sentence the provider states beside it, whether the run was
dispatched (handed to the provider) with the refusal's reason when it was not, and the
outcome. Each value is checked against its closed set (a tier, an outcome, a refusal
reason, a hex digest, a qualification a run record accepts) and left out when it does
not pass, so no stdout, stderr, code, path or detail text reaches the trace through it.

The tool also sends the LangChain run ID of the tool call as plimsoll's ``trace_id``, so
the daemon's audit line for the run joins to the trace. An ID outside the daemon's
charset, ``[A-Za-z0-9._:-]{1,64}``, is dropped whole, as the daemon drops one: never cut,
since a cut ID looks joinable and joins to nothing. LangChain's run IDs are UUIDs, 36
characters of hex digits and hyphens; a caller may pass any value as ``run_id``.

Nothing here imports LangSmith: with no ``langsmith`` module loaded no LangSmith run can
be active. With no active run, or an active run that is not the tool call's own, nothing
is added. Nothing here raises, and nothing here changes the tool's answer.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any, Dict, Mapping, Optional

from . import _validate as v
from ._record import valid_qualification
from ._tables import OUTCOME_NAMES, REFUSAL_NAMES, TIERS

# Every key the tool may add, and the only ones.
KEYS = (
    "plimsoll_dispatched",
    "plimsoll_refused",
    "plimsoll_outcome",
    "plimsoll_isolation",
    "plimsoll_isolation_qualification",
    "plimsoll_record_sha256",
)

_SHA256 = re.compile(r"[0-9a-f]{64}")

log = logging.getLogger("plimsoll_client")


def trace_id(run_id: Any) -> Optional[str]:
    """``run_id`` as plimsoll's trace ID, or None when there is none or it does not
    conform to the daemon's charset and length (dropped whole, never cut)."""
    if run_id is None:
        return None
    try:
        tid = str(run_id)
    except Exception:
        return None
    return tid if v._TRACE_ID.fullmatch(tid) else None


def labels(answer: Mapping[str, Any]) -> Dict[str, str]:
    """The metadata for one answer of the tool (``plimsoll_client._code_tool``'s dict),
    read from its trusted fields only, each kept only if it is in its closed set."""
    out: Dict[str, str] = {}
    refused = answer.get("refused")
    if refused is not None:
        out["plimsoll_dispatched"] = "no"
        out["plimsoll_refused"] = refused if isinstance(refused, str) and refused in REFUSAL_NAMES else "unknown"
    elif "outcome" in answer:
        out["plimsoll_dispatched"] = "yes"
    else:
        # An error after which the code may have run: no result, no mark.
        out["plimsoll_dispatched"] = "unknown"
    outcome = answer.get("outcome")
    if isinstance(outcome, str) and outcome in OUTCOME_NAMES:
        out["plimsoll_outcome"] = outcome
    isolation = answer.get("isolation")
    if isinstance(isolation, str) and isolation in TIERS:
        out["plimsoll_isolation"] = isolation
    qualification = answer.get("isolation_qualification")
    if isinstance(qualification, str) and qualification and valid_qualification(qualification):
        out["plimsoll_isolation_qualification"] = qualification
    digest = answer.get("record_sha256")
    if isinstance(digest, str) and _SHA256.fullmatch(digest):
        out["plimsoll_record_sha256"] = digest
    return out


def _active_run() -> Any:
    """LangSmith's active run, the one its ``get_current_run_tree`` names. A test fakes
    this, not LangSmith's function, which LangSmith also reads to decide whether to
    trace at all."""
    from langsmith.run_helpers import get_current_run_tree

    return get_current_run_tree()


def label_run(answer: Mapping[str, Any], run_id: Any) -> None:
    """Adds :func:`labels` to the active LangSmith run if it is the tool call's own run
    (its ID is ``run_id``). Does nothing without LangSmith, without an active run, or
    when the active run is another (a caller's traced function, say); never raises."""
    if run_id is None or sys.modules.get("langsmith") is None:
        return
    try:
        run = _active_run()
        if run is None or str(getattr(run, "id", None)) != str(run_id):
            return
        run.add_metadata(labels(answer))
    except Exception as e:
        # A label is never worth the tool's answer: the call already ran or was refused.
        log.debug("plimsoll: the LangSmith run was not labeled (%s)", type(e).__name__)
