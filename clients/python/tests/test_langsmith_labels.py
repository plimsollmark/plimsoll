"""The LangChain tool's LangSmith labels and trace ID (plimsoll_client._langsmith), with
no LangSmith installed: what the labels may hold, that a guest-written string never
reaches them, that a non-conforming ID is dropped whole, and that without LangSmith
nothing is imported and nothing happens. The tool's own path, with LangSmith and a
real LangChain tracer, is frameworks/langchain/test_langsmith.py."""

from __future__ import annotations

import builtins
import json
import sys
import types
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from plimsoll_client import _langsmith as ls

DIGEST = "ab" * 32
GUEST = "GUEST-WROTE-THIS /work/secret.txt"

# The tool's answers (plimsoll_client._code_tool), one per shape, with guest-written text
# wherever the guest can put some.
RAN = {"ran": True, "outcome": "completed", "language": "python", "exit_code": 0, "timed_out": False,
       "stdout": GUEST, "stderr": GUEST, "truncated": False, "isolation": "kernel", "record_sha256": DIGEST}
REFUSED = {"ran": False, "refused": "capacity", "error": "plimsoll: at capacity " + GUEST}
SETUP = {"ran": False, "outcome": "setup_failed", "error": "plimsoll: setup_failed: " + GUEST, "isolation": "vm",
         "record_sha256": DIGEST}
LOST = {"ran": "unknown", "error": "plimsoll: Run: " + GUEST, "note": "The code may have run."}


class TraceID(unittest.TestCase):
    def test_a_uuid_is_sent_as_it_is(self) -> None:
        u = uuid.uuid4()
        self.assertEqual(ls.trace_id(u), str(u))
        self.assertEqual(len(str(u)), 36)

    def test_a_non_conforming_id_is_dropped_whole(self) -> None:
        self.assertEqual(ls.trace_id("x" * 64), "x" * 64)
        for bad in ("x" * 65, "has space", "a/b", chr(0xE9), "", "line\nbreak", None):
            with self.subTest(bad=bad):
                self.assertIsNone(ls.trace_id(bad))

    def test_an_id_that_cannot_be_read_is_dropped(self) -> None:
        class Unreadable:
            def __str__(self) -> str:
                raise RuntimeError("no")

        self.assertIsNone(ls.trace_id(Unreadable()))


class Labels(unittest.TestCase):
    def test_each_answer_gives_exactly_its_labels(self) -> None:
        cases = [
            (RAN, {"plimsoll_dispatched": "yes", "plimsoll_outcome": "completed", "plimsoll_isolation": "kernel",
                   "plimsoll_record_sha256": DIGEST}),
            (REFUSED, {"plimsoll_dispatched": "no", "plimsoll_refused": "capacity"}),
            (SETUP, {"plimsoll_dispatched": "yes", "plimsoll_outcome": "setup_failed", "plimsoll_isolation": "vm",
                     "plimsoll_record_sha256": DIGEST}),
            (LOST, {"plimsoll_dispatched": "unknown"}),
        ]
        for answer, want in cases:
            with self.subTest(answer=answer.get("outcome") or answer.get("refused") or answer["ran"]):
                got = ls.labels(answer)
                self.assertEqual(got, want)
                self.assertTrue(set(got) <= set(ls.KEYS))
                self.assertNotIn("GUEST", json.dumps(got))

    def test_the_qualification_is_kept_when_a_record_could_hold_it(self) -> None:
        said = "Microsoft states that WSL is not a security sandbox for running untrusted code."
        self.assertEqual(ls.labels({**RAN, "isolation_qualification": said})["plimsoll_isolation_qualification"], said)
        for bad in ("x" * 1025, "bell\x07", "bidi" + chr(0x202E), ""):
            with self.subTest(bad=bad[:8]):
                self.assertNotIn("plimsoll_isolation_qualification", ls.labels({**RAN, "isolation_qualification": bad}))

    def test_a_value_outside_its_set_is_left_out(self) -> None:
        odd = {"ran": True, "outcome": GUEST, "isolation": GUEST, "record_sha256": GUEST, "stdout": GUEST}
        self.assertEqual(ls.labels(odd), {"plimsoll_dispatched": "yes"})
        self.assertEqual(ls.labels({"ran": False, "refused": GUEST}), {"plimsoll_dispatched": "no", "plimsoll_refused": "unknown"})
        self.assertEqual(ls.labels({**RAN, "record_sha256": DIGEST.upper()}).get("plimsoll_record_sha256"), None)


class FakeRun:
    def __init__(self, run_id: Any, fail: bool = False) -> None:
        self.id = run_id
        self.fail = fail
        self.added: List[Dict[str, Any]] = []

    def add_metadata(self, metadata: Dict[str, Any]) -> None:
        if self.fail:
            raise RuntimeError("the tracer broke")
        self.added.append(dict(metadata))


def fake_langsmith(run: Optional[FakeRun]) -> Dict[str, types.ModuleType]:
    """A stand-in for the langsmith package: only what label_run reaches for."""
    top = types.ModuleType("langsmith")
    helpers = types.ModuleType("langsmith.run_helpers")
    helpers.get_current_run_tree = lambda: run  # type: ignore[attr-defined]
    top.run_helpers = helpers  # type: ignore[attr-defined]
    return {"langsmith": top, "langsmith.run_helpers": helpers}


class LabelRun(unittest.TestCase):
    def test_without_langsmith_nothing_is_imported(self) -> None:
        imported: List[str] = []
        real = builtins.__import__

        def spy(name: str, *args: Any, **kwargs: Any) -> Any:
            imported.append(name)
            return real(name, *args, **kwargs)

        absent = {k: v for k, v in sys.modules.items() if not k.startswith("langsmith")}
        with patch.dict(sys.modules, absent, clear=True), patch("builtins.__import__", spy):
            ls.label_run(RAN, uuid.uuid4())
            self.assertFalse([k for k in sys.modules if k.startswith("langsmith")])
        self.assertFalse([n for n in imported if n.startswith("langsmith")])
        with patch.dict(sys.modules, {"langsmith": None}):  # installed but blocked
            ls.label_run(RAN, uuid.uuid4())

    def test_the_tool_calls_own_run_gets_the_labels(self) -> None:
        rid = uuid.uuid4()
        run = FakeRun(rid)
        with patch.dict(sys.modules, fake_langsmith(run)):
            ls.label_run(RAN, rid)
        self.assertEqual(run.added, [ls.labels(RAN)])

    def test_no_active_run_or_another_run_gets_nothing(self) -> None:
        with patch.dict(sys.modules, fake_langsmith(None)):
            ls.label_run(RAN, uuid.uuid4())
        caller = FakeRun(uuid.uuid4())
        with patch.dict(sys.modules, fake_langsmith(caller)):
            ls.label_run(RAN, uuid.uuid4())
            ls.label_run(RAN, None)
        self.assertEqual(caller.added, [])

    def test_a_failing_tracer_never_reaches_the_tool(self) -> None:
        rid = uuid.uuid4()
        with patch.dict(sys.modules, fake_langsmith(FakeRun(rid, fail=True))):
            ls.label_run(RAN, rid)  # no exception
        broken = fake_langsmith(None)
        broken["langsmith.run_helpers"].get_current_run_tree = lambda: 1 / 0  # type: ignore[attr-defined]
        with patch.dict(sys.modules, broken):
            ls.label_run(RAN, rid)


if __name__ == "__main__":
    unittest.main()
