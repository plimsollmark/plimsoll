"""PlimsollCodeTool through LangChain's own tool-call path (BaseTool.invoke and ainvoke,
as LangGraph's ToolNode calls them), with no model: the cases every framework's tool
passes, then LangChain's standard tool tests (langchain-tests), against the echo daemon.

This environment has langchain-core and no deepagents: the tool must not need it."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import unittest
from typing import Any, Dict, Type

from langchain_core.messages import ToolCall, ToolMessage
from langchain_core.tools import BaseTool
from langchain_tests.integration_tests import ToolsIntegrationTests
from langchain_tests.unit_tests import ToolsUnitTests

from plimsoll_client.execution import CodeExecutor
from plimsoll_client.langchain import PlimsollCodeTool

from .._shared import ToolCases, echo, echo_runs

EXAMPLE: Dict[str, Any] = {"code": "print(6 * 7)", "language": "python", "input_files": [{"path": "data/a.txt", "content": "x"}]}


class LangChainTests(ToolCases, unittest.TestCase):
    def make(self, executor: CodeExecutor, **opts: Any) -> PlimsollCodeTool:
        return PlimsollCodeTool(executor, **opts)

    def call(self, tool: PlimsollCodeTool, **args: Any) -> str:
        # A ToolCall, as an agent's ToolNode hands it over, answered with a ToolMessage.
        msg = tool.invoke(ToolCall(name=tool.name, args=args, id="call-1", type="tool_call"))
        self.assertIsInstance(msg, ToolMessage)
        self.assertEqual((msg.tool_call_id, msg.status), ("call-1", "success"))
        return msg.content

    async def acall(self, tool: PlimsollCodeTool, **args: Any) -> str:
        msg = await tool.ainvoke(ToolCall(name=tool.name, args=args, id="call-1", type="tool_call"))
        return msg.content

    def model_view(self, tool: PlimsollCodeTool) -> Any:
        # What a chat model is sent, through LangChain's own conversion.
        from langchain_core.utils.function_calling import convert_to_openai_tool

        fn = convert_to_openai_tool(tool)["function"]
        return fn["description"], set(fn["parameters"]["properties"])

    def test_is_a_langchain_tool_with_a_schema_of_the_offered_languages(self) -> None:
        tool = self.make(echo(), languages=("python",))
        self.assertIsInstance(tool, BaseTool)
        self.assertEqual(tool.name, "plimsoll_run_code")
        schema = tool.get_input_schema().model_json_schema()
        self.assertEqual(set(schema["properties"]), {"code", "language", "input_files"})
        self.assertEqual(schema["required"], ["code"])
        self.assertEqual(schema["properties"]["language"].get("const", schema["properties"]["language"].get("enum")), "python")
        self.assertIn("fresh", tool.description)
        self.assertNotIn("JavaScript", tool.description)
        both = self.make(echo()).get_input_schema().model_json_schema()["properties"]["language"]["enum"]
        self.assertEqual(both, ["python", "javascript"])
        # What a chat model is sent: the same schema, through LangChain's own conversion.
        from langchain_core.utils.function_calling import convert_to_openai_tool

        fn = convert_to_openai_tool(tool)["function"]
        self.assertEqual((fn["name"], fn["parameters"]["required"]), ("plimsoll_run_code", ["code"]))

    def test_the_async_path_answers_the_same(self) -> None:
        r = json.loads(asyncio.run(self.make(echo()).ainvoke({"code": "ECHO:EXIT"})))
        self.assertEqual((r["ran"], r["exit_code"]), (True, 3))

    def test_a_language_outside_the_schema_never_reaches_the_daemon(self) -> None:
        before = echo_runs()
        with self.assertRaises(ValueError):
            self.make(echo(), languages=("python",)).invoke({"code": "1", "language": "javascript"})
        self.assertEqual(echo_runs(), before)

    def test_construction_refuses_what_it_cannot_keep(self) -> None:
        with self.assertRaises(TypeError):
            PlimsollCodeTool(object())  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            PlimsollCodeTool(echo(), response_format="content_and_artifact")
        tool = PlimsollCodeTool(echo(), name="run_python", tags=["sandbox"])
        self.assertEqual((tool.name, tool.tags), ("run_python", ["sandbox"]))

    def test_needs_no_deepagents(self) -> None:
        self.assertIsNone(importlib.util.find_spec("deepagents"), "this environment is the tool without Deep Agents")


class LangChainPlimsollPackageTests(unittest.TestCase):
    """langchain-plimsoll (clients/python/langchain-plimsoll) re-exports plimsoll-client's own classes, at its version."""

    def test_names_are_plimsoll_clients_own(self) -> None:
        import langchain_plimsoll
        from plimsoll_client import Client, retry_on

        self.assertIs(langchain_plimsoll.PlimsollCodeTool, PlimsollCodeTool)
        self.assertIs(langchain_plimsoll.CodeExecutor, CodeExecutor)
        self.assertIs(langchain_plimsoll.Client, Client)
        self.assertIs(langchain_plimsoll.retry_on, retry_on)
        self.assertEqual(sorted(langchain_plimsoll.__all__), ["Client", "CodeExecutor", "PlimsollCodeTool", "PlimsollSandbox", "retry_on"])

    def test_version_is_plimsoll_clients(self) -> None:
        import langchain_plimsoll
        import plimsoll_client

        self.assertEqual(langchain_plimsoll.__version__, plimsoll_client.__version__)

    def test_the_sandbox_backend_names_its_extra_when_deep_agents_is_missing(self) -> None:
        import langchain_plimsoll

        with self.assertRaises(ImportError) as cm:
            langchain_plimsoll.PlimsollSandbox  # noqa: B018
        self.assertIn("langchain-plimsoll[deepagents]", str(cm.exception))


# LangChain's standard tool tests (langchain-tests), the suite its integration listing asks
# for. They are pytest classes; the framework runner runs this directory with pytest.


class TestPlimsollCodeToolStandardUnit(ToolsUnitTests):
    @property
    def tool_constructor(self) -> Type[PlimsollCodeTool]:
        return PlimsollCodeTool

    @property
    def tool_constructor_params(self) -> Dict[str, Any]:
        return {"executor": echo()}

    @property
    def tool_invoke_params_example(self) -> Dict[str, Any]:
        return EXAMPLE


class TestPlimsollCodeToolStandardIntegration(ToolsIntegrationTests):
    @property
    def tool_constructor(self) -> Type[PlimsollCodeTool]:
        return PlimsollCodeTool

    @property
    def tool_constructor_params(self) -> Dict[str, Any]:
        return {"executor": echo()}

    @property
    def tool_invoke_params_example(self) -> Dict[str, Any]:
        return EXAMPLE


class FrameworkShapeTests(unittest.TestCase):
    """Each member the adapter defines over the framework's own (inherited, or declared by a protocol it is used
    as) against the framework at the version this suite installs: kind, coroutine, the calls it takes
    (tests/_framework_shapes.py)."""

    def test_the_adapter_takes_the_calls_the_framework_makes(self) -> None:
        import importlib

        from tests._framework_shapes import problems

        self.assertEqual(problems(importlib.import_module('plimsoll_client.langchain')), [])


if __name__ == "__main__":
    unittest.main()
