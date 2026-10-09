"""PlimsollTools through Agno's own tool-call path (FunctionCall, as an agent's run
loop drives it), with no model."""

from __future__ import annotations

import asyncio
import json
import unittest
from typing import Any

from agno.tools.function import FunctionCall

from plimsoll_client.agno import PlimsollTools
from plimsoll_client.execution import CodeExecutor

from .._shared import ToolCases, echo


def _function(tool: PlimsollTools, *, asynchronous: bool = False) -> Any:
    f = (tool.async_functions if asynchronous else tool.functions)["plimsoll_run_code"]
    f.process_entrypoint()
    return f


class AgnoTests(ToolCases, unittest.TestCase):
    def make(self, executor: CodeExecutor, **opts: Any) -> PlimsollTools:
        return PlimsollTools(executor, **opts)

    def call(self, tool: PlimsollTools, **args: Any) -> str:
        fc = FunctionCall(function=_function(tool), arguments=args)
        out = fc.execute()
        self.assertEqual(out.status, "success", fc.error)
        return fc.result

    async def acall(self, tool: PlimsollTools, **args: Any) -> str:
        fc = FunctionCall(function=_function(tool, asynchronous=True), arguments=args)
        out = await fc.aexecute()
        self.assertEqual(out.status, "success", fc.error)
        return fc.result

    def test_schema_names_the_offered_languages_and_input_files(self) -> None:
        schema = _function(self.make(echo(), languages=("python",))).to_dict()
        props = schema["parameters"]["properties"]
        self.assertEqual(set(props), {"code", "language", "input_files"})
        self.assertEqual(schema["parameters"]["required"], ["code"])
        self.assertEqual(props["language"]["enum"], ["python"])
        self.assertEqual(set(props["input_files"]["items"]["required"]), {"path", "content"})
        self.assertIn("fresh", schema["description"])
        self.assertNotIn("JavaScript", schema["description"])

    def test_the_async_path_answers_the_same(self) -> None:
        tool = self.make(echo())
        fc = FunctionCall(function=_function(tool, asynchronous=True), arguments={"code": "ECHO:EXIT"})
        out = asyncio.run(fc.aexecute())
        self.assertEqual(out.status, "success", fc.error)
        r = json.loads(fc.result)
        self.assertEqual((r["ran"], r["exit_code"]), (True, 3))
        # The async variant offers the model the same arguments as the sync one (Agno may
        # add additionalProperties: false to one of them, which forbids nothing they take).
        a, s = (_function(tool, asynchronous=x).to_dict()["parameters"] for x in (True, False))
        self.assertEqual((a["properties"], a["required"]), (s["properties"], s["required"]))

    def test_a_language_outside_the_schema_never_reaches_the_daemon(self) -> None:
        fc = FunctionCall(function=_function(self.make(echo(), languages=("python",))), arguments={"code": "1", "language": "javascript"})
        self.assertEqual(fc.execute().status, "failure")

    def test_result_caching_is_refused(self) -> None:
        # A cached answer would be a run that did not happen.
        with self.assertRaises(ValueError):
            PlimsollTools(echo(), cache_results=True)
        self.assertFalse(_function(PlimsollTools(echo())).cache_results)

    def test_toolkit_options_pass_through(self) -> None:
        tool = PlimsollTools(echo(), requires_confirmation_tools=["plimsoll_run_code"])
        self.assertEqual(tool.name, "plimsoll_tools")
        self.assertTrue(_function(tool).requires_confirmation)
        with self.assertRaises(TypeError):
            PlimsollTools(object())  # type: ignore[arg-type]
        # Agno's own timeout would be kept and bound nothing; the budget is the executor's.
        with self.assertRaises(ValueError):
            PlimsollTools(echo(), timeout=5)


if __name__ == "__main__":
    unittest.main()
