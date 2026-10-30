"""The plimsoll-bash harness: verifiers' own chat loop run on the evaluator, its tool calls sent
to a runtime. The runtime here runs each command on this machine in a fresh temporary
directory (every command is the test's own), and the model is the scripted server, so the
loop, its tool definitions, the edit tool's shipped source and the results the model sees
are all real. No model is called and no sandbox is involved; the docker attempt
(attempt/run_attempt.py) runs the same harness on plimsoll sessions."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from typing import Any, Dict, List, Optional

import verifiers.v1 as vf
from verifiers.v1.clients import EvalClientConfig, ModelContext
from verifiers.v1.errors import HarnessError
from verifiers.v1.harnesses.bash.harness import BASH_SYSTEM_PROMPT, EDIT_SYSTEM_PROMPT, BashHarnessConfig
from verifiers.v1.harnesses.utils import core
from verifiers.v1.runtimes import ProgramResult
from verifiers.v1.utils.loaders import harness_class

from frameworks.verifiers.scripted_model import ScriptedModel, assistant, last_tool_result, tool_call
from plimsoll_client import verifiers_harness as vh


class HostRuntime:
    """A stand-in for ``vf.Runtime``: runs each argv in its own directory on this machine
    and keeps what it was asked. Only ``run`` is used by the harness."""

    def __init__(self, test: unittest.TestCase, missing: Optional[List[str]] = None) -> None:
        self.dir = tempfile.mkdtemp(prefix="plimsoll-bash-test-")
        test.addCleanup(shutil.rmtree, self.dir, True)
        self.calls: List[List[str]] = []
        self.envs: List[Dict[str, str]] = []
        self.missing = missing

    async def run(self, argv: List[str], env: Dict[str, str]) -> ProgramResult:
        self.calls.append(list(argv))
        self.envs.append(dict(env))
        if self.missing is not None and argv[:3] == ["sh", "-c", vh._PROBE]:
            return ProgramResult(0, " " + " ".join(self.missing) if self.missing else "", "")
        proc = await asyncio.to_thread(
            subprocess.run, argv, cwd=self.dir, capture_output=True, text=True, timeout=60, env={"PATH": os.environ["PATH"], **env}
        )
        return ProgramResult(proc.returncode, proc.stdout, proc.stderr)

    def host_url(self, url: str) -> str:
        return url

    def file(self, name: str) -> str:
        with open(os.path.join(self.dir, name), encoding="utf-8") as f:
            return f.read()


def harness(**config: Any) -> vh.PlimsollBashHarness:
    return vh.PlimsollBashHarness(BashHarnessConfig(id=vh.HARNESS_ID, **config))


def launch(h: vh.PlimsollBashHarness, runtime: HostRuntime, model: ScriptedModel, prompt: Any = "do the task", **kw: Any) -> ProgramResult:
    ctx = ModelContext(model="scripted", client=EvalClientConfig(base_url=model.base_url, api_key_var="UNSET_SCRIPTED_KEY"))
    data = vf.TaskData(prompt=prompt, **kw)
    return asyncio.run(h.launch(ctx, None, runtime, model.base_url, "test-secret", {}, data))


class Policy:
    """Answers turn by turn from a list of answers, keeping what each turn saw."""

    def __init__(self, *turns: Any) -> None:
        self.turns = list(turns)
        self.seen: List[List[Dict[str, Any]]] = []

    def __call__(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.seen.append(messages)
        turn = self.turns[len(self.seen) - 1]
        return turn(messages) if callable(turn) else turn


class PlimsollBashHarnessTest(unittest.TestCase):
    def test_verifiers_resolves_the_harness_id(self) -> None:
        self.assertIs(harness_class("plimsoll-bash"), vh.PlimsollBashHarness)

    def test_tool_calls_run_in_the_runtime_and_their_results_reach_the_model(self) -> None:
        policy = Policy(
            assistant(None, tool_call("bash", command="printf 'a\\nb\\n' > f.txt; cat f.txt")),
            assistant(None, tool_call("edit", path="f.txt", old_str="b", new_str="c")),
            assistant("checking", tool_call("bash", command="cat f.txt; echo oops >&2; exit 3")),
            assistant("done"),
        )
        runtime = HostRuntime(self)
        with ScriptedModel(policy) as model:
            result = launch(harness(), runtime, model)
        self.assertEqual((result.exit_code, result.stderr), (0, ""))
        self.assertEqual(runtime.file("f.txt"), "a\nc\n")
        # Each tool call was one runtime call: bash -c, then the shipped edit by its source.
        self.assertEqual(runtime.calls[0], ["bash", "-c", "printf 'a\\nb\\n' > f.txt; cat f.txt"])
        self.assertEqual(runtime.calls[1][:3], ["python3", "-c", vh._EDIT_SCRIPT])
        self.assertEqual(json.loads(runtime.calls[1][3]), {"path": "f.txt", "old_str": "b", "new_str": "c"})
        self.assertEqual(len(runtime.calls), 3)
        # What the model saw after each call, as the shipped program reports it (stdout then stderr).
        self.assertEqual([last_tool_result(m) for m in policy.seen[1:]], ["a\nb\n", "Edited f.txt", "a\nc\noops\n"])
        # The shipped harness's system prompt and tool definitions, and the user's prompt.
        first = model.requests[0]
        self.assertEqual(first["messages"][0], {"role": "system", "content": f"{BASH_SYSTEM_PROMPT} {EDIT_SYSTEM_PROMPT}"})
        self.assertEqual(first["messages"][1], {"role": "user", "content": "do the task"})
        self.assertEqual(first["tools"], [core.BASH_TOOL, core.EDIT_TOOL])
        self.assertTrue(first["stream"])

    def test_edit_errors_are_the_shipped_function_s(self) -> None:
        cases = [
            {"path": "nope.txt", "old_str": "x", "new_str": "y"},
            {"path": "f.txt", "old_str": "a", "new_str": "y"},
            {"path": "f.txt", "old_str": 1, "new_str": "y"},
            {"path": "f.txt", "old_str": "", "new_str": "y"},
            {"path": "", "old_str": "a", "new_str": "y"},
            {"path": ".", "old_str": "a", "new_str": "y"},
        ]
        policy = Policy(
            assistant(None, tool_call("bash", command="printf 'a a\\n' > f.txt")),
            *[assistant(None, tool_call("edit", **case)) for case in cases],
            assistant("done"),
        )
        runtime = HostRuntime(self)
        with ScriptedModel(policy) as model:
            self.assertEqual(launch(harness(), runtime, model).exit_code, 0)
        got = [last_tool_result(m) for m in policy.seen[2:]]
        # The same calls through the shipped function, in a copy of the same directory.
        reference = HostRuntime(self)
        with open(os.path.join(reference.dir, "f.txt"), "w", encoding="utf-8") as f:
            f.write("a a\n")
        here = os.getcwd()
        os.chdir(reference.dir)
        try:
            want = [core.run_edit(c.get("path"), c.get("old_str"), c.get("new_str")) for c in cases]
        finally:
            os.chdir(here)
        # A directory's error names the directory, each side its own.
        self.assertEqual([g.replace(runtime.dir, "DIR") for g in got], [w.replace(reference.dir, "DIR") for w in want])
        self.assertIn("found 2", got[1])

    def test_edit_off_offers_bash_alone_and_probes_only_bash(self) -> None:
        runtime = HostRuntime(self, missing=[])
        h = harness(edit=False)
        asyncio.run(h.setup(runtime))
        self.assertEqual(runtime.calls[0][4:], ["bash"])
        with ScriptedModel(Policy(assistant("nothing to do"))) as model:
            launch(h, runtime, model)
            self.assertEqual(model.requests[0]["tools"], [core.BASH_TOOL])
            self.assertEqual(model.requests[0]["messages"][0]["content"], BASH_SYSTEM_PROMPT)

    def test_setup_names_what_the_image_lacks(self) -> None:
        with self.assertRaisesRegex(HarnessError, r"lacks python3 \(or set --env.agent.harness.edit false\)"):
            asyncio.run(harness().setup(HostRuntime(self, missing=["python3"])))
        with self.assertRaisesRegex(HarnessError, r"lacks bash and python3"):
            asyncio.run(harness().setup(HostRuntime(self, missing=["bash", "python3"])))
        asyncio.run(harness().setup(HostRuntime(self, missing=[])))

    def test_setup_probe_runs_in_the_runtime(self) -> None:
        runtime = HostRuntime(self)
        asyncio.run(harness().setup(runtime))  # this machine has bash and python3
        self.assertEqual(runtime.calls[0], ["sh", "-c", vh._PROBE, "probe", "bash", "python3"])

    def test_search_and_task_tool_servers_are_refused(self) -> None:
        with self.assertRaisesRegex(HarnessError, "does not offer the search tool"):
            asyncio.run(harness(search=True).setup(HostRuntime(self, missing=[])))
        h = harness()
        ctx = ModelContext(model="m", client=EvalClientConfig(base_url="http://127.0.0.1:9/v1", api_key_var="UNSET_SCRIPTED_KEY"))
        with self.assertRaisesRegex(HarnessError, "takes no task tool servers"):
            asyncio.run(h.launch(ctx, None, HostRuntime(self), "http://127.0.0.1:9/v1", "s", {"tools": "http://x"}, vf.TaskData(prompt="p")))
        self.assertFalse(vh.PlimsollBashHarness.SUPPORTS_MCP)

    def test_a_runtime_that_rewrites_the_endpoint_is_refused(self) -> None:
        runtime = HostRuntime(self)
        runtime.host_url = lambda url: url.replace("127.0.0.1", "host.docker.internal")  # type: ignore[method-assign]
        with ScriptedModel(Policy(assistant("never asked"))) as model:
            with self.assertRaisesRegex(HarnessError, "rewritten model endpoint the evaluator cannot use"):
                launch(harness(), runtime, model)
            self.assertEqual(model.requests, [])
        self.assertEqual(runtime.calls, [])

    def test_a_model_endpoint_error_is_the_program_s_exit_status(self) -> None:
        def broken(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
            raise ValueError("no more turns")

        runtime = HostRuntime(self)
        with ScriptedModel(Policy(broken, broken, broken)) as model:
            result = launch(harness(), runtime, model)
        # The shipped program would exit 1 with the traceback; the harness then decides.
        self.assertEqual(result.exit_code, 1)
        self.assertIn("scripted policy failed", result.stderr)
        self.assertEqual(runtime.calls, [])

    def test_a_messages_prompt_and_a_task_system_prompt(self) -> None:
        prompt = [vf.UserMessage(content="first"), vf.AssistantMessage(content="ok"), vf.UserMessage(content="second")]
        with ScriptedModel(Policy(assistant("fine"))) as model:
            launch(harness(), HostRuntime(self), model, prompt=prompt, system_prompt="Be brief.")
        messages = model.requests[0]["messages"]
        self.assertEqual(messages[0]["content"], f"{BASH_SYSTEM_PROMPT} {EDIT_SYSTEM_PROMPT}\n\nBe brief.")
        self.assertEqual([m["content"] for m in messages[1:]], ["first", "ok", "second"])

    def test_the_chat_program_is_verifiers_own_and_loaded_once(self) -> None:
        program = vh.chat_program()
        self.assertIs(program, vh.chat_program())
        self.assertNotEqual(program.__name__, "__main__")
        self.assertEqual(program.BASH_TOOL, core.BASH_TOOL)


if __name__ == "__main__":
    unittest.main()
