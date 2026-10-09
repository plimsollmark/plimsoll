"""Actual ADK executor/Runner interfaces, with local RPC and no model service."""

from __future__ import annotations

import asyncio
import base64
import json
import time
import unittest
from dataclasses import replace
from typing import Any
from unittest.mock import patch

from google.adk.agents import Agent
from google.adk.agents.run_config import RunConfig
from google.adk.agents.live_request_queue import LiveRequestQueue
from google.adk.artifacts import InMemoryArtifactService
from google.adk.code_executors.code_execution_utils import CodeExecutionInput, File
from google.adk.events import Event, EventActions
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.agent_tool import AgentTool
from google.genai import types
from pydantic import Field, ValidationError

from plimsoll_client import Client
from plimsoll_client.adk import CODE_EXECUTION_INSTRUCTION, PlimsollCodeExecutor, PlimsollCodeExecutionError, PlimsollCodeExecutorGuard
from plimsoll_client.errors import AtCapacityError, InsufficientIsolationError, InvalidRequestError, PlimsollError, UnsupportedError
from plimsoll_client.execution import CodeExecutor
from plimsoll_client.types import Artifact
from tests._env import setting

from .._shared import PROMPT, echo_hold_describe, echo_holds, echo_release, echo_runs


class ScriptedModel(BaseLlm):
    model: str = "offline-scripted-model"
    requests: list[Any] = Field(default_factory=list, exclude=True)
    codes: tuple[str, ...] = ("print(6 * 7)",)

    async def generate_content_async(self, llm_request: Any, stream: bool = False):
        self.requests.append(llm_request.model_copy(deep=True))
        index = len(self.requests) - 1
        # A "TEXT:" entry is a plain answer, which ends the turn.
        code = self.codes[index] if index < len(self.codes) else "TEXT:Finished using the execution result."
        text = code[5:] if code.startswith("TEXT:") else "```python\n" + code + "\n```"
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))


class ADKTests(unittest.TestCase):
    def executor(self, **kwargs: Any) -> PlimsollCodeExecutor:
        return PlimsollCodeExecutor(client=Client(setting("PLIMSOLL_ECHO_URL")),
                                    minimum_isolation="container", **kwargs)

    def test_base_contract_and_decoding_match_adk(self) -> None:
        executor = self.executor()
        out = executor.execute_code(None, CodeExecutionInput(code="print('files')", input_files=[
            File(name="encoded.csv", content=base64.b64encode(b"n\n42\n").decode(), mime_type="text/csv"),
            File(name="raw.txt", content=b"plain", mime_type="text/plain")], execution_id="ignored-fresh"))
        plan = json.loads(out.stdout)
        self.assertEqual(plan["files"]["encoded.csv"], "n\n42\n")
        self.assertEqual(plan["files"]["raw.txt"], "plain")
        self.assertEqual(plan["timeout_s"], 30)
        self.assertEqual((out.exit_code, out.stderr, executor.stateful, executor.error_retry_attempts), (0, "", False, 2))
        self.assertRegex(out.execution.record.sha256, r"^[0-9a-f]{64}$")

    def refused(self, out: Any, reason: str, error: type) -> None:
        # A refusal is ADK's kind of failure, a result whose stderr the model
        # sees, never an exception out of the Runner.
        self.assertTrue(out.stderr.startswith(f"Nothing ran ({reason}): "), out.stderr)
        self.assertIsInstance(out.refusal, error)
        self.assertEqual(out.refusal.not_dispatched, reason)
        self.assertEqual((out.stdout, out.exit_code, out.output_files, out.execution), ("", None, [], None))

    def test_bad_files_refused_before_http(self) -> None:
        bad = [File(name="a.txt", content="not base64!"), File(name="a.txt", content=b"\xff"),
               File(name="a.png", content=b"text", mime_type="image/png"),
               File(name="../a.txt", content=b"x"), File(name=".plimsoll/code.py", content=b"x")]
        with patch.object(Client, "describe", side_effect=AssertionError("HTTP must not start")):
            for file in bad:
                with self.subTest(file=file.name):
                    self.refused(self.executor().execute_code(None, CodeExecutionInput(code="print(1)", input_files=[file])),
                                 "request", InvalidRequestError)
            self.refused(self.executor().execute_code(None, CodeExecutionInput(code="1", input_files=[bad[-1], bad[-1]])),
                         "request", InvalidRequestError)

    def test_stateful_retry_and_budget_configuration_refused(self) -> None:
        for options in ({"stateful": True}, {"error_retry_attempts": 0}, {"error_retry_attempts": -1},
                        {"error_retry_attempts": True}, {"error_retry_attempts": 1.5}, {"error_retry_attempts": "2"},
                        {"timeout_seconds": 0}, {"timeout_seconds": True}):
            with self.subTest(options=options), self.assertRaises(ValidationError):
                self.executor(**options)
        with self.assertRaises(ValidationError):
            self.executor().stateful = True

    def test_positive_retry_limits_are_configurable(self) -> None:
        for attempts in (1, 2, 3, 100):
            with self.subTest(attempts=attempts):
                self.assertEqual(self.executor(error_retry_attempts=attempts).error_retry_attempts, attempts)

    def test_csv_optimization_is_refused_before_http(self) -> None:
        with patch.object(Client, "describe", side_effect=AssertionError("HTTP must not start")):
            with self.assertRaisesRegex(ValidationError, "optimize_data_file"):
                self.executor(optimize_data_file=True)
        self.assertFalse(self.executor().optimize_data_file)
        with self.assertRaises(ValidationError):
            self.executor().optimize_data_file = True

    def test_isolation_and_unsupported_project_errors_keep_marks(self) -> None:
        for executor, error, reason in (
            (PlimsollCodeExecutor(client=Client(setting("PLIMSOLL_ECHO_URL"))), InsufficientIsolationError, "isolation"),
            (PlimsollCodeExecutor(client=Client(setting("PLIMSOLL_WASM_URL")), minimum_isolation="process"), UnsupportedError, "unsupported")):
            self.refused(executor.execute_code(None, CodeExecutionInput(code="print(1)")), reason, error)

    def test_infrastructure_error_is_propagated_without_replay(self) -> None:
        with self.assertRaises(PlimsollError) as caught:
            self.executor().execute_code(None, CodeExecutionInput(code="ECHO:LOST"))
        self.assertIsNone(caught.exception.not_dispatched)
        unknown = RuntimeError("may already have run")
        with patch.object(CodeExecutor, "execute_code", side_effect=unknown) as call:
            with self.assertRaises(RuntimeError) as propagated:
                self.executor().execute_code(None, CodeExecutionInput(code="print(1)"))
            self.assertIs(propagated.exception, unknown)
            self.assertEqual(call.call_count, 1)

    def test_guest_failure_and_timeout_are_adk_results(self) -> None:
        failed = self.executor().execute_code(None, CodeExecutionInput(code="ECHO:EXIT"))
        self.assertEqual((failed.exit_code, failed.stderr), (3, "boom"))
        timeout = self.executor().execute_code(None, CodeExecutionInput(code="ECHO:TIMEOUT"))
        self.assertEqual(timeout.exit_code, 124)
        self.assertIn("timed_out", timeout.stderr)

    def test_missing_step_report_stops_the_actual_runner_without_replay(self) -> None:
        for code, outcome in (("ECHO:SETUP", "setup_failed"), ("ECHO:PROTOCOL", "protocol_error")):
            with self.subTest(outcome=outcome):
                async def run():
                    model = ScriptedModel(codes=(code, code))
                    agent = Agent(name="offline_uncertain", model=model, code_executor=self.executor())
                    sessions = InMemorySessionService()
                    session = await sessions.create_session(app_name="adk-uncertain-test", user_id="user")
                    runner = Runner(agent=agent, app_name="adk-uncertain-test", session_service=sessions,
                                    artifact_service=InMemoryArtifactService(), plugins=[PlimsollCodeExecutorGuard()])
                    original = CodeExecutor.execute_code
                    with patch.object(CodeExecutor, "execute_code", autospec=True, side_effect=original) as dispatch:
                        with self.assertRaises(PlimsollCodeExecutionError) as caught:
                            async for _ in runner.run_async(user_id="user", session_id=session.id,
                                    new_message=types.Content(role="user", parts=[types.Part(text="Use Python.")])):
                                pass
                        self.assertEqual(dispatch.call_count, 1)
                        self.assertEqual(len(model.requests), 1)
                        error = caught.exception
                        self.assertIsNone(error.not_dispatched)
                        self.assertEqual(error.code, "unknown")
                        self.assertIn("may have run", str(error))
                        self.assertEqual(error.execution.outcome, outcome)
                        self.assertEqual(error.execution.steps, ())
                        self.assertRegex(error.execution.record.sha256, r"^[0-9a-f]{64}$")
                asyncio.run(run())

    def test_exit_without_stderr_and_raw_artifact_shaping(self) -> None:
        result = self.executor().execute_code(None, CodeExecutionInput(code="print(1)")).execution
        result = replace(result, steps=(replace(result.steps[0], exit_code=3, stderr=b""),),
                         artifacts=(Artifact(path="a.bin", content=b"\x00\xff"),))
        with patch.object(CodeExecutor, "execute_code", return_value=result):
            out = self.executor().execute_code(None, CodeExecutionInput(code="exit(3)"))
        self.assertIn("status 3", out.stderr)  # ADK's event builder ignores exit_code.
        self.assertEqual(out.output_files[0].content, b"\x00\xff")
        self.assertIs(out.execution, result)

    def test_actual_adk_runner_reads_the_execution_result(self) -> None:
        async def run():
            model = ScriptedModel()
            agent = Agent(name="offline", model=model, code_executor=self.executor())
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-test", user_id="user")
            runner = Runner(agent=agent, app_name="adk-test", session_service=sessions,
                            artifact_service=InMemoryArtifactService(),
                            plugins=[PlimsollCodeExecutorGuard()])
            events = [event async for event in runner.run_async(user_id="user", session_id=session.id,
                new_message=types.Content(role="user", parts=[types.Part(text="Calculate using Python.")]))]
            return model, events
        model, events = asyncio.run(run())
        self.assertEqual(len(model.requests), 2)
        results = [part.code_execution_result for event in events if event.content
                   for part in event.content.parts if part.code_execution_result]
        self.assertEqual(len(results), 1)
        payload = results[-1].output.removeprefix("Code execution result:\n").strip()
        self.assertEqual(json.loads(payload)["files"][".plimsoll/code.py"], "print(6 * 7)")
        self.assertIn(".plimsoll/code.py", str(model.requests[-1].contents))

    def test_guarded_runner_refuses_cfc_before_any_model_or_code_call(self) -> None:
        async def run():
            # ADK accepts CFC only for a Gemini 2 model name. This remains the
            # scripted model: neither generate nor live connect may be reached.
            model = ScriptedModel(model="gemini-2.5-pro")
            agent = Agent(name="offline_cfc", model=model, code_executor=self.executor())
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-cfc-test", user_id="user")
            runner = Runner(agent=agent, app_name="adk-cfc-test", session_service=sessions,
                            plugins=[PlimsollCodeExecutorGuard()])
            with patch.object(ScriptedModel, "connect", side_effect=AssertionError("vendor transport reached")) as connect, \
                    patch.object(CodeExecutor, "execute_code", side_effect=AssertionError("code dispatched")) as dispatch:
                with self.assertRaisesRegex(RuntimeError, "support_cfc=True") as caught:
                    async for _ in runner.run_async(user_id="user", session_id=session.id,
                            run_config=RunConfig(support_cfc=True),
                            new_message=types.Content(role="user", parts=[types.Part(text="Use Python.")])):
                        pass
                # ADK wraps plugin exceptions, preserving their cause.
                self.assertIsInstance(caught.exception.__cause__, UnsupportedError)
                self.assertEqual(caught.exception.__cause__.not_dispatched, "unsupported")
                connect.assert_not_called()
                dispatch.assert_not_called()
                self.assertEqual(model.requests, [])
        asyncio.run(run())

    def test_guard_checks_the_live_flow_agent_hook(self) -> None:
        async def run():
            model = ScriptedModel(model="gemini-2.5-pro")
            agent = Agent(name="offline_live", model=model, code_executor=self.executor())
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-live-test", user_id="user")
            runner = Runner(agent=agent, app_name="adk-live-test", session_service=sessions,
                            plugins=[PlimsollCodeExecutorGuard()])
            with patch.object(ScriptedModel, "connect", side_effect=AssertionError("vendor transport reached")) as connect, \
                    patch.object(CodeExecutor, "execute_code", side_effect=AssertionError("code dispatched")) as dispatch:
                with self.assertRaisesRegex(RuntimeError, "support_cfc=True") as caught:
                    async for _ in runner.run_live(user_id="user", session_id=session.id,
                            live_request_queue=LiveRequestQueue(), run_config=RunConfig(support_cfc=True)):
                        pass
                self.assertIsInstance(caught.exception.__cause__, UnsupportedError)
                self.assertEqual(caught.exception.__cause__.not_dispatched, "unsupported")
                connect.assert_not_called()
                dispatch.assert_not_called()
                self.assertEqual(model.requests, [])
        asyncio.run(run())

    def test_truncation_flags_do_not_turn_success_into_adk_failure(self) -> None:
        result = self.executor().execute_code(None, CodeExecutionInput(code="print(1)")).execution
        for flag in ("stdout_truncated", "stderr_truncated", "artifacts_truncated"):
            with self.subTest(flag=flag):
                truncated = (replace(result, artifacts_truncated=True) if flag == "artifacts_truncated"
                             else replace(result, steps=(replace(result.steps[0], **{flag: True}),)))
                with patch.object(CodeExecutor, "execute_code", return_value=truncated):
                    out = self.executor().execute_code(None, CodeExecutionInput(code="print(1)"))
                self.assertEqual((out.exit_code, out.stderr), (0, ""))
                self.assertIs(out.execution, truncated)

    def test_actual_adk_runner_executes_the_models_correction_after_failure(self) -> None:
        async def run():
            model = ScriptedModel(codes=("ECHO:EXIT", "print(6 * 7)"))
            agent = Agent(name="offline", model=model, code_executor=self.executor())
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-retry-test", user_id="user")
            runner = Runner(agent=agent, app_name="adk-retry-test", session_service=sessions,
                            artifact_service=InMemoryArtifactService())
            events = [event async for event in runner.run_async(user_id="user", session_id=session.id,
                new_message=types.Content(role="user", parts=[types.Part(text="Calculate using Python.")]))]
            return model, events
        model, events = asyncio.run(run())
        self.assertEqual(len(model.requests), 3)
        results = [part.code_execution_result for event in events if event.content
                   for part in event.content.parts if part.code_execution_result]
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].outcome, types.Outcome.OUTCOME_FAILED)
        self.assertIn("boom", results[0].output)
        self.assertIn("boom", str(model.requests[1].contents))
        self.assertEqual(results[1].outcome, types.Outcome.OUTCOME_OK)
        payload = results[1].output.removeprefix("Code execution result:\n").strip()
        self.assertEqual(json.loads(payload)["files"][".plimsoll/code.py"], "print(6 * 7)")

    def run_turns(self, executor: PlimsollCodeExecutor, codes: tuple[str, ...], turns: int,
                  between: Any = None, state: Any = None) -> tuple[ScriptedModel, list[list[Any]]]:
        """Drives turns of one session through ADK's real Runner, raising whatever it raises."""
        async def run():
            model = ScriptedModel(codes=codes)
            agent = Agent(name="offline_turns", model=model, code_executor=executor)
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-turns", user_id="user", state=state)
            runner = Runner(agent=agent, app_name="adk-turns", session_service=sessions,
                            artifact_service=InMemoryArtifactService(), plugins=[PlimsollCodeExecutorGuard()])
            results = []
            for turn in range(turns):
                if turn and between:
                    await between(sessions, await sessions.get_session(app_name="adk-turns", user_id="user", session_id=session.id))
                events = [e async for e in runner.run_async(user_id="user", session_id=session.id,
                          new_message=types.Content(role="user", parts=[types.Part(text=f"Turn {turn}: use Python.")]))]
                results.append([p.code_execution_result for e in events if e.content
                                for p in e.content.parts if p.code_execution_result])
            return model, results
        return asyncio.run(run())

    def test_a_refusal_reaches_the_model_and_a_later_turn_runs(self) -> None:
        # The daemon refuses the first block (capacity: nothing ran); the model sees it,
        # ADK lets it try again, and the session's next turn runs code as usual.
        original = CodeExecutor.execute_code
        calls = []

        def once_full(self_: Any, *args: Any, **kwargs: Any) -> Any:
            calls.append(1)
            if len(calls) == 1:
                raise AtCapacityError("plimsoll: the daemon is at capacity", not_dispatched="capacity")
            return original(self_, *args, **kwargs)

        with patch.object(CodeExecutor, "execute_code", autospec=True, side_effect=once_full):
            model, results = self.run_turns(self.executor(), ("print(1)", "print(2)", "TEXT:Done.", "print(3)"), 2)
        first, second = results
        self.assertEqual(first[0].outcome, types.Outcome.OUTCOME_FAILED)
        self.assertTrue(first[0].output.startswith("Nothing ran (capacity): "), first[0].output)
        self.assertIn("Nothing ran (capacity)", str(model.requests[1].contents))
        self.assertEqual(first[1].outcome, types.Outcome.OUTCOME_OK, "ADK's retry ran the model's next block")
        self.assertEqual([r.outcome for r in second], [types.Outcome.OUTCOME_OK])
        self.assertEqual(len(calls), 3)

    def test_a_windows_1252_csv_is_refused_without_ending_the_session(self) -> None:
        # An Excel export in Windows-1252, supplied by the application as one
        # of the session's input files. Every block is refused (nothing ran) while it is
        # there, each turn still ends normally, and once the application replaces it with
        # UTF-8 the same session runs code with it.
        # ADK keeps a session's input files under this top-level state key
        # (code_executors/code_executor_context.py, _INPUT_FILE_KEY).
        key = "_code_executor_input_files"
        cp1252 = base64.b64encode("region,units\nZürich,3\n".encode("cp1252")).decode()
        utf8 = base64.b64encode("region,units\nZürich,3\n".encode("utf-8")).decode()
        state = {key: [{"name": "sales.csv", "content": cp1252, "mime_type": "text/csv"}]}

        async def replace_file(sessions: Any, session: Any) -> None:
            files = [{"name": "sales.csv", "content": utf8, "mime_type": "text/csv"}]
            await sessions.append_event(session, Event(author="user", actions=EventActions(state_delta={key: files})))

        before = echo_runs()
        model, results = self.run_turns(self.executor(), ("print(1)", "print(2)", "print(3)", "print(open('sales.csv').read())"),
                                        2, between=replace_file, state=state)
        first, second = results
        self.assertEqual(len(first), 2, "ADK's two attempts, both refused; its retry gate skipped the third block")
        for r in first:
            self.assertEqual(r.outcome, types.Outcome.OUTCOME_FAILED)
            self.assertTrue(r.output.startswith("Nothing ran (request): "), r.output)
            self.assertIn("'sales.csv' is not UTF-8 text", r.output)
        self.assertEqual(echo_runs(), before + 1, "only the second turn's block reached the daemon")
        self.assertEqual(second[0].outcome, types.Outcome.OUTCOME_OK)
        payload = json.loads(second[0].output.removeprefix("Code execution result:\n").strip())
        self.assertEqual(payload["files"]["sales.csv"], "region,units\nZürich,3\n")

    def test_stderr_of_a_successful_run_reaches_the_model_and_execution_goes_on(self) -> None:
        # A warning on stderr from a program that exited 0. ADK would show the
        # model only the warning, count a failure, and stop executing after two.
        direct = self.executor().execute_code(None, CodeExecutionInput(code="ECHO:WARN"))
        self.assertEqual((direct.exit_code, direct.stderr), (0, ""))
        self.assertEqual(direct.stdout, "RESULT 42\nstderr (the program exited 0):\nDeprecationWarning: this call is old\n")
        self.assertEqual(direct.execution.steps[0].stderr, b"DeprecationWarning: this call is old\n", "the bytes are kept")
        model, (results,) = self.run_turns(self.executor(), ("ECHO:WARN", "ECHO:WARN", "ECHO:WARN"), 1)
        self.assertEqual([r.outcome for r in results], [types.Outcome.OUTCOME_OK] * 3, "all three blocks ran")
        for r in results:
            self.assertIn("RESULT 42", r.output)
            self.assertIn("DeprecationWarning", r.output)
        self.assertIn("RESULT 42", str(model.requests[1].contents))
        failing = self.executor().execute_code(None, CodeExecutionInput(code="ECHO:EXIT"))
        self.assertEqual((failing.exit_code, failing.stderr), (3, "boom"), "a failing run keeps its stderr")

    def test_a_runner_without_an_artifact_service_is_refused_before_anything_runs(self) -> None:
        # ADK needs the artifact service for every execution, not only when
        # files come back. Without the guard, the block runs and then ADK raises.
        async def run(plugins: list[Any]) -> tuple[ScriptedModel, Any, Exception]:
            model = ScriptedModel(codes=("print(1)",))
            child = Agent(name="offline_child", model=model, code_executor=self.executor())
            root = Agent(name="offline_root", model=model, sub_agents=[child])
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-artifacts", user_id="user")
            runner = Runner(agent=child if not plugins else root, app_name="adk-artifacts",
                            session_service=sessions, plugins=plugins)
            original = CodeExecutor.execute_code
            with patch.object(CodeExecutor, "execute_code", autospec=True, side_effect=original) as dispatch:
                with self.assertRaises(Exception) as caught:
                    async for _ in runner.run_async(user_id="user", session_id=session.id,
                            new_message=types.Content(role="user", parts=[types.Part(text="Use Python.")])):
                        pass
                return model, dispatch, caught.exception
        model, dispatch, error = asyncio.run(run([PlimsollCodeExecutorGuard()]))
        self.assertIsInstance(error.__cause__, UnsupportedError, error)
        self.assertIn("artifact service", str(error.__cause__))
        self.assertEqual(error.__cause__.not_dispatched, "unsupported")
        self.assertEqual((model.requests, dispatch.call_count), ([], 0), "refused before the model or the daemon")
        model, dispatch, error = asyncio.run(run([]))
        self.assertIn("Artifact service is not initialized", str(error))
        self.assertEqual(dispatch.call_count, 1, "unguarded, the block ran before ADK raised")

    def test_the_guard_gives_the_model_the_fenced_code_instruction(self) -> None:
        # ADK gives its fence instruction only under optimize_data_file, which
        # this executor refuses, so the guard supplies an equivalent one.
        model, (results,) = self.run_turns(self.executor(), ("print(1)",), 1)
        self.assertEqual(len(results), 1)
        for request in model.requests:
            system = str(request.config.system_instruction)
            self.assertEqual(system.count("# Code execution"), 1, "once per request, not once per hook")
            start, end = self.executor().code_block_delimiters[0]  # ADK's default, ```tool_code
            self.assertIn(start + 'print("hello")' + end + "\n", system)
            self.assertIn("Each block runs in a new sandbox", system)
        async def unguarded() -> ScriptedModel:
            model = ScriptedModel(codes=("TEXT:no code",))
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-plain", user_id="user")
            runner = Runner(agent=Agent(name="plain", model=model, code_executor=self.executor()), app_name="adk-plain",
                            session_service=sessions, artifact_service=InMemoryArtifactService())
            async for _ in runner.run_async(user_id="user", session_id=session.id,
                    new_message=types.Content(role="user", parts=[types.Part(text="hi")])):
                pass
            return model
        self.assertNotIn("# Code execution", str(asyncio.run(unguarded()).requests[0].config.system_instruction),
                         "ADK itself adds none: the guard is what supplies it")
        self.assertIn("{start}", CODE_EXECUTION_INSTRUCTION)

    def cancel_turn(self, code: str, held: str) -> tuple[float, dict[str, int], dict[str, int]]:
        """Starts one guarded turn whose block is held at the daemon, cancels the task
        awaiting the Runner once the hold is reached, and returns how long the cancel
        took to land with the daemon's holds before and after."""
        before = echo_holds()

        async def main() -> float:
            model = ScriptedModel(codes=(code,))
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-cancel", user_id="user")
            runner = Runner(agent=Agent(name="offline_cancel", model=model, code_executor=self.executor()),
                            app_name="adk-cancel", session_service=sessions,
                            artifact_service=InMemoryArtifactService(), plugins=[PlimsollCodeExecutorGuard()])

            async def turn() -> None:
                async for _ in runner.run_async(user_id="user", session_id=session.id,
                        new_message=types.Content(role="user", parts=[types.Part(text="Use Python.")])):
                    pass
            task = asyncio.ensure_future(turn())
            try:
                while echo_holds()[held] == before[held]:
                    await asyncio.sleep(0.01)
                start = time.monotonic()
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                # The daemon's handler sees the cut connection, while it still holds.
                deadline = time.monotonic() + PROMPT
                key = "describe_canceled" if held == "describe_waiting" else "run_canceled"
                while echo_holds().get(key, 0) == before.get(key, 0) and time.monotonic() < deadline:
                    await asyncio.sleep(0.01)
                return time.monotonic() - start
            finally:
                echo_release()
        elapsed = asyncio.run(main())
        time.sleep(0.2)  # a thread the cancel missed would send its Run once released
        return elapsed, before, echo_holds()

    def test_cancelling_a_turn_cuts_the_run_it_was_waiting_for(self) -> None:
        elapsed, before, after = self.cancel_turn("ECHO:HOLD", "run_waiting")
        self.assertLess(elapsed, PROMPT, "the request was cut, not left to the deadline")
        self.assertEqual(after["run_requests"], before["run_requests"] + 1)
        self.assertEqual(after["run_canceled"], before["run_canceled"] + 1, "the daemon saw the connection close")

    def test_cancelling_a_turn_during_describe_sends_no_run(self) -> None:
        echo_hold_describe()
        elapsed, before, after = self.cancel_turn("print(1)", "describe_waiting")
        self.assertLess(elapsed, PROMPT)
        self.assertEqual(after["run_requests"], before["run_requests"], "a Run reached the daemon after the cancel")

    def test_an_agent_wrapped_as_a_tool_is_covered_by_the_artifact_check(self) -> None:
        # An inner agent behind AgentTool runs in a nested Runner
        # whose artifact service forwards to the outer one, so the outer Runner's check
        # must see it; and the live flow, which skips before_run_callback, is checked too.
        async def run(live: bool) -> tuple[ScriptedModel, Any, Exception]:
            model = ScriptedModel(model="gemini-2.5-pro", codes=("print(1)",))
            inner = Agent(name="inner_coder", model=model, code_executor=self.executor(), description="Runs Python.")
            root = Agent(name="root_no_code", model=model, tools=[AgentTool(agent=inner)])
            sessions = InMemorySessionService()
            session = await sessions.create_session(app_name="adk-agenttool", user_id="user")
            runner = Runner(agent=root, app_name="adk-agenttool", session_service=sessions, plugins=[PlimsollCodeExecutorGuard()])
            with patch.object(ScriptedModel, "connect", side_effect=AssertionError("vendor transport reached")), \
                    patch.object(CodeExecutor, "execute_code", side_effect=AssertionError("code dispatched")) as dispatch:
                with self.assertRaises(Exception) as caught:
                    if live:
                        async for _ in runner.run_live(user_id="user", session_id=session.id, live_request_queue=LiveRequestQueue()):
                            pass
                    else:
                        async for _ in runner.run_async(user_id="user", session_id=session.id,
                                new_message=types.Content(role="user", parts=[types.Part(text="Use Python.")])):
                            pass
                return model, dispatch, caught.exception
        for live in (False, True):
            with self.subTest(live=live):
                model, dispatch, error = asyncio.run(run(live))
                self.assertIsInstance(error.__cause__, UnsupportedError, error)
                self.assertIn("artifact service", str(error.__cause__))
                self.assertEqual((model.requests, dispatch.call_count), ([], 0))

    def test_an_executor_without_delimiters_still_gets_the_instruction(self) -> None:
        model, (results,) = self.run_turns(self.executor(code_block_delimiters=[]), ("TEXT:no code",), 1)
        self.assertIn("```tool_code\nprint(\"hello\")\n```", str(model.requests[0].config.system_instruction))

