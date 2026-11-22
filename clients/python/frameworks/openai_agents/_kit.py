"""What the OpenAI Agents SDK suites share: the SDK's own Runner driven by its ScriptedModel
(agents/testing/model.py, no model is called), an event sink and a tracing processor that
keep what the SDK hands them in memory, and the checks on plimsoll's labels.

Importing this replaces the SDK's trace processors with the in-memory one, so no suite
exports a trace to OpenAI (the SDK's default processor uploads to api.openai.com whenever
OPENAI_API_KEY is set; TestPythonFrameworks also drops OPENAI_ variables)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

from agents import RunConfig, Runner, set_trace_processors
from agents.sandbox import SandboxAgent, SandboxRunConfig
from agents.sandbox.session import CallbackSink, Instrumentation
from agents.testing import ScriptedModel, assistant_message, function_call
from agents.tracing import TracingProcessor
from openai.types.responses import ResponseCustomToolCall

from plimsoll_client.openai_sandbox import LABEL_KEYS

SHA256 = re.compile(r"^[0-9a-f]{64}$")


class Spans(TracingProcessor):
    """Every ended span's export, kept here and sent nowhere."""

    def __init__(self) -> None:
        self.ended: List[Dict[str, Any]] = []

    def on_trace_start(self, trace: Any) -> None:
        pass

    def on_trace_end(self, trace: Any) -> None:
        pass

    def on_span_start(self, span: Any) -> None:
        pass

    def on_span_end(self, span: Any) -> None:
        exported = span.export()
        if exported is not None:
            self.ended.append(exported)

    def shutdown(self) -> None:
        pass

    def force_flush(self) -> None:
        pass

    def named(self, name: str) -> List[Dict[str, Any]]:
        return [s["span_data"]["data"] for s in self.ended if (s.get("span_data") or {}).get("name") == name]


SPANS = Spans()
set_trace_processors([SPANS])


class Events:
    """The SDK's sandbox audit events, as an app's CallbackSink receives them."""

    def __init__(self) -> None:
        self.seen: List[Any] = []
        self.instrumentation = Instrumentation(sinks=[CallbackSink(lambda event, _session: self.seen.append(event))])

    def finished(self, op: str = "exec") -> List[Any]:
        return [e for e in self.seen if e.op == op and e.phase == "finish"]


def plimsoll_labels(data: Dict[str, Any]) -> Dict[str, Any]:
    """The labels in an event's or a span's data: every plimsoll_ key but the record."""
    return {k: v for k, v in data.items() if k.startswith("plimsoll_") and k != "plimsoll_record"}


def call(name: str, arguments: Dict[str, Any], n: int) -> Any:
    return function_call(name, arguments, call_id=f"call-{n}")


def patch(text: str, n: int) -> Any:
    """A call of the SDK's apply_patch tool, a custom tool whose input is the patch text
    (agents/sandbox/capabilities/tools/apply_patch_tool.py)."""
    return ResponseCustomToolCall(type="custom_tool_call", name="apply_patch", input=text, call_id=f"call-{n}", id=f"call-{n}")


def script(*calls: Sequence[Any], final: str = "done") -> ScriptedModel:
    """A model that makes each turn's calls in order, then answers ``final``."""
    return ScriptedModel([list(c) for c in calls] + [[assistant_message(final)]])


def run_agent(client: Any, model: ScriptedModel, options: Any, *, session: Any = None, max_turns: int = 10) -> Any:
    """``Runner.run`` of a SandboxAgent on ``model`` with ``client`` as its sandbox
    provider (or the live ``session``), as an app runs one."""
    agent = SandboxAgent(name="plimsoll-check", model=model, instructions="Work in the sandbox.")
    sandbox = SandboxRunConfig(session=session) if session is not None else SandboxRunConfig(client=client, options=options)
    return Runner.run(agent, "go", run_config=RunConfig(sandbox=sandbox, tracing_disabled=False), max_turns=max_turns)


def tool_outputs(result: Any) -> List[str]:
    return [str(item.output) for item in result.new_items if type(item).__name__ == "ToolCallOutputItem"]


def check_labels(tc: Any, labels: Dict[str, Any], *, dispatched: str, isolation: Optional[str] = None, outcome: Optional[str] = None,
                 refused: Optional[str] = None, record: bool = False) -> None:
    """Every label is one of plimsoll's keys with a value from its closed set."""
    tc.assertLessEqual(set(labels), set(LABEL_KEYS))
    tc.assertEqual(labels.get("plimsoll_dispatched"), dispatched)
    tc.assertEqual(labels.get("plimsoll_refused"), refused)
    tc.assertEqual(labels.get("plimsoll_outcome"), outcome)
    tc.assertEqual(labels.get("plimsoll_isolation"), isolation)
    if record:
        tc.assertRegex(labels.get("plimsoll_record_sha256", ""), SHA256)
    else:
        tc.assertNotIn("plimsoll_record_sha256", labels)
