"""Verdicts on the shared test cases every client must pass (internal/clientcases).

A test that runs a shared case asserts the client's answer here, as it always has, and
also writes it down with ``verdict``: one JSON line per case and path in the file
PLIMSOLL_CASE_VERDICTS names. Under ``go test ./clients/python`` that file is read after
the suite by the judge, which fails a case this suite skipped or answered otherwise than
the case's file states. Unset, as when the suite runs alone, nothing is written.
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import Any, Optional

from plimsoll_client import (
    ChainError,
    IsolationEvidenceMismatchError,
    NoRecordError,
    PlimsollError,
    RecordMismatchError,
    RecordVersionError,
)
from plimsoll_client.errors import MalformedResponseError, ResultKindMismatchError, SoftwareEvidenceMismatchError

ROOT = pathlib.Path(__file__).resolve().parents[3]
_FILE = os.environ.get("PLIMSOLL_CASE_VERDICTS", "")


def verdict(case_id: str, path: str, says: Any) -> None:
    """Writes down what this client said about one case on one path."""
    if _FILE:
        with open(_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps({"id": case_id, "path": path, "says": says}) + "\n")


# The kind of rule an error names, in the Go record package's kinds; the order matters
# only for a class that is two kinds at once, which none is.
_CHECKS = (
    (ChainError, "chain"),
    (RecordVersionError, "version"),
    (NoRecordError, "no_record"),
    (IsolationEvidenceMismatchError, "floor"),
    (MalformedResponseError, "malformed"),
    (RecordMismatchError, "mismatch"),
    (SoftwareEvidenceMismatchError, "mismatch"),
    (ResultKindMismatchError, "mismatch"),
)


def says_of(e: Optional[BaseException]) -> str:
    """The verdict on an error: "accept" for none, else the outcome a caller acts on
    (not_dispatched:<reason>, or may_have_run) and the kind of rule that failed."""
    if e is None:
        return "accept"
    nd = e.not_dispatched if isinstance(e, PlimsollError) else None
    outcome = f"not_dispatched:{nd}" if nd else "may_have_run"
    check = next((name for cls, name in _CHECKS if isinstance(e, cls)), "other:" + type(e).__name__)
    return f"{outcome}/{check}"
