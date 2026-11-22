"""The check OpenAI's provider guide asks of an outside sandbox provider: "Exercise the
public `Runner` path with `ScriptedModel`", "covering success, tool errors, timeouts,
cancellation, and partial startup" (openai.github.io/openai-agents-python/sandbox/
custom-providers/, read 2026-11-17). The SDK's own Runner, SandboxAgent, shell tool and
ScriptedModel (agents/testing/model.py: no model is called, no key is needed), with
plimsoll's provider over a workspace that counts every call (frameworks/openai_agents/
_fake.py). The same Runner path on a real docker session is docker_openai_check.py."""

from __future__ import annotations

import asyncio
import threading
import unittest
from typing import Any, List

from frameworks.openai_agents._fake import FakeWorkspace
from frameworks.openai_agents._kit import SPANS, Events, call, check_labels, plimsoll_labels, run_agent, script, tool_outputs
from agents import RunConfig, Runner
from agents.exceptions import UserError
from agents.sandbox import SandboxAgent, SandboxRunConfig

from plimsoll_client import InsufficientIsolationError
from plimsoll_client.openai_sandbox import PlimsollExecError, PlimsollSandboxClient, PlimsollSandboxClientOptions

OPTIONS = PlimsollSandboxClientOptions(minimum_isolation="container")


def _cause_of_type(e: BaseException, kind: type) -> Any:
    seen = 0
    while e is not None and seen < 10:
        if isinstance(e, kind):
            return e
        e = e.__cause__ or e.__context__  # type: ignore[assignment]
        seen += 1
    return None


class Kit:
    def __init__(self, *, refuse_open: bool = False) -> None:
        self.events = Events()
        self.made: List[FakeWorkspace] = []
        self.hold = False

        def factory(_options: Any) -> FakeWorkspace:
            if refuse_open:
                raise InsufficientIsolationError("plimsoll: the daemon states container, below vm", not_dispatched="isolation")
            ws = FakeWorkspace()
            if self.hold:
                ws.hold, ws.hold_only = threading.Event(), "sleep 60"
            self.made.append(ws)
            return ws

        self.client = PlimsollSandboxClient(None, workspace_factory=factory, instrumentation=self.events.instrumentation)

    @property
    def ws(self) -> FakeWorkspace:
        return self.made[-1]

    def run(self, *calls: Any) -> Any:
        return asyncio.run(run_agent(self.client, script(*calls), OPTIONS))

    def agent_commands(self) -> List[str]:
        # The base class's own setup command at start is not the agent's.
        return [c for c in self.ws.commands if c != "mkdir -p /work"]


class RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        SPANS.ended.clear()

    def test_success_the_agents_command_runs_and_the_app_sees_its_record(self) -> None:
        kit = Kit()
        result = kit.run([call("exec_command", {"cmd": "echo hello"}, 1)])
        self.assertEqual(result.final_output, "done")
        out = tool_outputs(result)
        self.assertEqual(len(out), 1)
        self.assertIn("Process exited with code 0", out[0])
        self.assertIn("hello", out[0])
        self.assertEqual(kit.agent_commands(), ["echo hello"])
        self.assertEqual(kit.ws.budgets[kit.ws.commands.index("echo hello")], 10.0, "the shell tool's default budget, yield_time_ms 10000")
        (event,) = kit.events.finished("exec")
        check_labels(self, plimsoll_labels(event.data), dispatched="yes", isolation="container", outcome="completed", record=True)
        (span,) = SPANS.named("sandbox.exec")
        self.assertEqual(plimsoll_labels(span), plimsoll_labels(event.data))
        self.assertTrue(kit.ws.session.closed, "the run's end closed the session")

    def test_a_streamed_run_delivers_the_commands_output_when_it_ends(self) -> None:
        # Runner.run_streamed works through the provider; the command's output arrives
        # whole when the call ends (no PTY, so no output while it runs).
        kit = Kit()

        async def main() -> List[Any]:
            agent = SandboxAgent(name="plimsoll-stream", model=script([call("exec_command", {"cmd": "echo streamed"}, 1)]), instructions="x")
            streamed = Runner.run_streamed(agent, "go", run_config=RunConfig(sandbox=SandboxRunConfig(client=kit.client, options=OPTIONS)))
            seen = [e async for e in streamed.stream_events() if getattr(e, "name", None) == "tool_output"]
            self.assertEqual(streamed.final_output, "done")
            return seen

        outputs = asyncio.run(main())
        self.assertEqual(len(outputs), 1)
        self.assertIn("streamed", str(outputs[0].item.output))
        (event,) = kit.events.finished("exec")
        check_labels(self, plimsoll_labels(event.data), dispatched="yes", isolation="container", outcome="completed", record=True)

    def test_tool_error_the_run_stops_with_it_and_the_kit_does_not_send_the_command_again(self) -> None:
        # The shell tool's errors are not answered to the model: the Runner ends the run
        # with UserError("Error running tool exec_command: ..."), the plimsoll error as its
        # cause (agents/run_internal/tool_execution.py:1847-1861). The kit retries model
        # calls only when asked (ModelSettings.retry, "Opt-in runner-managed retry
        # settings for model calls"), never a tool call.
        kit = Kit()
        with self.assertRaises(UserError) as caught:
            kit.run([call("exec_command", {"cmd": "lost"}, 1)], [call("exec_command", {"cmd": "echo after"}, 2)])
        cause = caught.exception.__cause__
        self.assertIsInstance(cause, PlimsollExecError)
        self.assertIsNone(cause.not_dispatched)
        self.assertIs(cause.retryable, False)
        self.assertEqual(kit.agent_commands(), ["lost"], "the command that may have run was sent once, and nothing after it")
        (lost,) = kit.events.finished("exec")
        check_labels(self, plimsoll_labels(lost.data), dispatched="unknown", isolation="container", record=True)
        self.assertIs(lost.error_retryable, False)
        self.assertTrue(kit.ws.session.closed, "the failed run's cleanup closed the session")

    def test_a_refusal_stops_the_run_marked_with_its_reason(self) -> None:
        kit = Kit()
        with self.assertRaises(UserError) as caught:
            kit.run([call("exec_command", {"cmd": "refuse capacity"}, 1)])
        cause = caught.exception.__cause__
        self.assertIsInstance(cause, PlimsollExecError)
        self.assertEqual(cause.not_dispatched, "capacity")
        self.assertIs(cause.retryable, True)
        (event,) = kit.events.finished("exec")
        check_labels(self, plimsoll_labels(event.data), dispatched="no", refused="capacity")
        self.assertIs(event.error_retryable, True)
        self.assertEqual(kit.agent_commands(), ["refuse capacity"])

    def test_timeouts_the_models_budget_is_the_calls_and_zero_sends_nothing(self) -> None:
        kit = Kit()
        result = kit.run([call("exec_command", {"cmd": "sleep 30", "yield_time_ms": 250}, 1)],
                         [call("exec_command", {"cmd": "echo never", "yield_time_ms": 0}, 2)])
        out = tool_outputs(result)
        self.assertIn("Command timed out after 0.250 seconds.", out[0])
        self.assertIn("Command timed out after 0.000 seconds.", out[1])
        self.assertEqual(kit.agent_commands(), ["sleep 30"], "a zero budget sent nothing")
        self.assertEqual(kit.ws.budgets[kit.ws.commands.index("sleep 30")], 0.25)
        timed, zero = kit.events.finished("exec")
        check_labels(self, plimsoll_labels(timed.data), dispatched="yes", isolation="container", outcome="timed_out", record=True)
        check_labels(self, plimsoll_labels(zero.data), dispatched="no", refused="request")

    def test_cancellation_cancelling_the_run_cancels_the_command_and_closes_the_session(self) -> None:
        kit = Kit()
        kit.hold = True

        async def main() -> None:
            task = asyncio.ensure_future(run_agent(kit.client, script([call("exec_command", {"cmd": "sleep 60", "yield_time_ms": 60000}, 1)]), OPTIONS))
            while not (kit.made and kit.ws.held.is_set()):
                await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(main())
        ws = kit.ws
        self.assertTrue(ws.ended_hold.wait(2), "the held call returned")
        held = [c for c in ws.cancels if c is not None and c.cancelled]
        self.assertTrue(held, "the command's cancel handle was cancelled")
        self.assertTrue(ws.session.closed, "the cancelled run's cleanup closed the session")

    def test_partial_startup_a_refused_open_raises_its_refusal(self) -> None:
        kit = Kit(refuse_open=True)
        with self.assertRaises(InsufficientIsolationError) as caught:
            kit.run([call("exec_command", {"cmd": "echo hello"}, 1)])
        self.assertEqual(caught.exception.not_dispatched, "isolation")
        self.assertEqual(kit.made, [])

    def test_partial_startup_a_failed_start_closes_the_session(self) -> None:
        kit = Kit()
        original = FakeWorkspace.exec

        def refuse_setup(ws: FakeWorkspace, command: str, **kw: Any) -> Any:
            return original(ws, "refuse capacity" if command == "mkdir -p /work" else command, **kw)

        FakeWorkspace.exec = refuse_setup  # type: ignore[method-assign]
        try:
            with self.assertRaises(Exception) as caught:
                kit.run([call("exec_command", {"cmd": "echo hello"}, 1)])
        finally:
            FakeWorkspace.exec = original  # type: ignore[method-assign]
        self.assertIsInstance(_cause_of_type(caught.exception, PlimsollExecError), PlimsollExecError)
        self.assertEqual(kit.ws.commands, ["refuse capacity"], "the start failed at its first call; no command of the agent's was sent")
        self.assertTrue(kit.ws.session.closed, "the session whose start failed was closed")


if __name__ == "__main__":
    unittest.main()
