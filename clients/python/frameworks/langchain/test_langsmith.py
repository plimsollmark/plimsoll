"""PlimsollCodeTool's trace ID and LangSmith labels through LangChain's own tool path,
against the echo daemon: the tool call's run ID reaches the daemon as the run's
trace_id; on a traced call the labels land on the tool call's own run (a LangChain
tracer whose LangSmith uploads are kept in memory, and a fake run tree), are exactly
the allowed set, and hold nothing the guest wrote; a failing tracer, no active run or
a non-conforming ID changes nothing in the tool's answer. Nothing is sent to LangSmith."""

from __future__ import annotations

import asyncio
import json
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from langchain_core.messages import ToolCall
from langchain_core.runnables import RunnableLambda
from langchain_core.tracers.langchain import LangChainTracer

from plimsoll_client import _langsmith as ls
from plimsoll_client.langchain import PlimsollCodeTool

from .._shared import echo, echo_trace_id

CANARY = "PLIMSOLL-GUEST-CANARY-7f3a"


class KeptTracer(LangChainTracer):
    """LangChain's LangSmith tracer, with each run kept in memory where it would be
    uploaded: ``posted`` at its start, ``ended`` at its end, as LangSmith receives them."""

    def __init__(self) -> None:
        super().__init__(client=object())  # never reached: the two methods below replace the uploads
        self.posted: List[Any] = []
        self.ended: List[Any] = []

    def _persist_run_single(self, run: Any) -> None:
        self.posted.append(run)

    def _update_run_single(self, run: Any) -> None:  # type: ignore[override]
        self.ended.append(run)

    def run_named(self, name: str) -> Any:
        return next(r for r in self.ended if r.name == name)


def plimsoll_keys(run: Any) -> Dict[str, Any]:
    meta = (run.extra or {}).get("metadata", {})
    return {k: v for k, v in meta.items() if k.startswith("plimsoll_")}


class FakeRun:
    def __init__(self, run_id: Any, fail: bool = False) -> None:
        self.id = run_id
        self.fail = fail
        self.added: List[Dict[str, Any]] = []

    def add_metadata(self, metadata: Dict[str, Any]) -> None:
        if self.fail:
            raise RuntimeError("the tracer broke")
        self.added.append(dict(metadata))


def active(run: Optional[FakeRun]) -> Any:
    # The tool's view of the active run only: faking LangSmith's own get_current_run_tree
    # would also tell LangChain that tracing is on, and it would start uploading.
    return patch.object(ls, "_active_run", lambda: run)


class TraceIdAndLabels(unittest.TestCase):
    def tool(self, **opts: Any) -> PlimsollCodeTool:
        return PlimsollCodeTool(echo(**opts))

    def test_the_tool_calls_run_id_is_the_runs_trace_id_and_its_run_is_labeled(self) -> None:
        tracer = KeptTracer()
        out = json.loads(self.tool().invoke({"code": f"print('{CANARY}')"}, config={"callbacks": [tracer]}))
        run = tracer.run_named("plimsoll_run_code")
        self.assertEqual(echo_trace_id(), str(run.id))
        self.assertEqual(plimsoll_keys(run), {
            "plimsoll_dispatched": "yes", "plimsoll_outcome": "completed", "plimsoll_isolation": "container",
            "plimsoll_record_sha256": out["record_sha256"],
        })
        # The guest's output was in the answer, and so in the run's outputs (LangChain's
        # own tracing, which LangSmith's hide_outputs turns off), never in the labels.
        self.assertIn(CANARY, out["stdout"])
        self.assertNotIn(CANARY, json.dumps(plimsoll_keys(run)))

    def test_only_the_tool_calls_run_is_labeled(self) -> None:
        tracer = KeptTracer()
        tool = self.tool()
        RunnableLambda(lambda code: tool.invoke({"code": code}), name="caller").invoke("print(1)", config={"callbacks": [tracer]})
        self.assertEqual(plimsoll_keys(tracer.run_named("caller")), {})
        self.assertEqual(plimsoll_keys(tracer.run_named("plimsoll_run_code"))["plimsoll_dispatched"], "yes")

    def test_the_async_path_does_the_same(self) -> None:
        tracer = KeptTracer()
        out = json.loads(asyncio.run(self.tool().ainvoke({"code": "ECHO:EXIT"}, config={"callbacks": [tracer]})))
        run = tracer.run_named("plimsoll_run_code")
        self.assertEqual(echo_trace_id(), str(run.id))
        self.assertEqual(plimsoll_keys(run)["plimsoll_record_sha256"], out["record_sha256"])

    def test_with_a_fake_run_tree_the_labels_are_exactly_the_allowed_set(self) -> None:
        rid = uuid.uuid4()
        run = FakeRun(rid)
        with active(run):
            out = json.loads(self.tool().invoke(
                ToolCall(name="plimsoll_run_code", type="tool_call", id="call-1",
                         args={"code": f"print('{CANARY}')", "input_files": [{"path": f"{CANARY}/a.txt", "content": CANARY}]}),
                config={"run_id": rid},
            ).content)
        self.assertEqual(len(run.added), 1)
        labels = run.added[0]
        self.assertEqual(set(labels), {"plimsoll_dispatched", "plimsoll_outcome", "plimsoll_isolation", "plimsoll_record_sha256"})
        self.assertTrue(set(labels) <= set(ls.KEYS))
        self.assertEqual(labels["plimsoll_record_sha256"], out["record_sha256"])
        self.assertIn(CANARY, out["stdout"])
        self.assertNotIn(CANARY, json.dumps(labels))
        self.assertEqual(echo_trace_id(), str(rid))

    def test_each_outcome_is_labeled_from_the_answer(self) -> None:
        cases = [
            ("ECHO:LOST", {}, {"plimsoll_dispatched": "unknown"}),
            ("ECHO:SETUP", {}, {"plimsoll_dispatched": "yes", "plimsoll_outcome": "setup_failed"}),
            ("ECHO:PROTOCOL", {}, {"plimsoll_dispatched": "yes", "plimsoll_outcome": "protocol_error"}),
            ("print(1)", {"minimum_isolation": "kernel"}, {"plimsoll_dispatched": "no", "plimsoll_refused": "isolation"}),
        ]
        for code, opts, want in cases:
            with self.subTest(code=code, **opts):
                rid = uuid.uuid4()
                run = FakeRun(rid)
                with active(run):
                    self.tool(**opts).invoke({"code": code}, config={"run_id": rid})
                got = run.added[0]
                self.assertEqual({k: got[k] for k in want}, want)
                if want["plimsoll_dispatched"] != "yes":
                    self.assertNotIn("plimsoll_record_sha256", got)

    def test_a_refusal_the_tool_makes_itself_is_labeled(self) -> None:
        rid = uuid.uuid4()
        run = FakeRun(rid)
        with active(run):
            out = json.loads(self.tool().invoke({"code": "   "}, config={"run_id": rid}))
        self.assertEqual(out["refused"], "request")
        self.assertEqual(run.added, [{"plimsoll_dispatched": "no", "plimsoll_refused": "request"}])

    def test_no_active_run_labels_nothing_and_the_id_still_joins(self) -> None:
        rid = uuid.uuid4()
        with active(None):
            out = json.loads(self.tool().invoke({"code": "print(1)"}, config={"run_id": rid}))
        self.assertIs(out["ran"], True)
        self.assertEqual(echo_trace_id(), str(rid))

    def test_another_active_run_is_not_labeled(self) -> None:
        caller = FakeRun(uuid.uuid4())
        with active(caller):
            self.tool().invoke({"code": "print(1)"}, config={"run_id": uuid.uuid4()})
        self.assertEqual(caller.added, [])

    def test_a_failing_tracer_changes_nothing_in_the_answer(self) -> None:
        rid = uuid.uuid4()
        with active(FakeRun(rid, fail=True)):
            out = json.loads(self.tool().invoke({"code": "ECHO:WARN"}, config={"run_id": rid}))
        self.assertEqual((out["ran"], out["stdout"]), (True, "RESULT 42\n"))

    def test_a_non_conforming_run_id_is_not_sent(self) -> None:
        # A run ID the caller set: LangChain hands it over as it is.
        for bad in ("x" * 65, "has space"):
            with self.subTest(bad=bad[:8]):
                self.tool().invoke({"code": "print(0)"})  # a conforming ID first, so the check below is not stale
                self.assertNotEqual(echo_trace_id(), "")
                out = json.loads(self.tool().invoke({"code": "print(1)"}, config={"run_id": bad}))
                self.assertIs(out["ran"], True)
                self.assertEqual(echo_trace_id(), "")


class StandInShapeTests(unittest.TestCase):
    def test_fake_run_has_the_shape_of_langsmiths_run_tree(self) -> None:
        # The labels are put on the stand-in as on LangSmith's RunTree (tests/_framework_shapes.py); its id, set in
        # __init__, is a field of RunTree.
        from langsmith.run_trees import RunTree

        from tests._framework_shapes import fake_problems

        self.assertEqual(fake_problems(FakeRun, RunTree), [])
        self.assertIn("id", RunTree.model_fields)


if __name__ == "__main__":
    unittest.main()
