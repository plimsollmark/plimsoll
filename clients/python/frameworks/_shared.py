"""What the Agno and CrewAI suites both check: one tool result shape, read from the
JSON each framework's tool hands its model."""

from __future__ import annotations

import asyncio
import json
import re
import threading
import time
import unittest
import urllib.request
from typing import Any, Awaitable, Callable, Dict, Optional

from plimsoll_client import Client, PlimsollError, RequestCanceledError
from plimsoll_client.execution import CodeExecutor
from tests._env import setting

# Seconds a cancelled call may take to end. A cut is a socket shutdown and a thread
# waking, milliseconds; a call left waiting waits for the test's release instead.
PROMPT = 1.0


def echo(**kwargs: Any) -> CodeExecutor:
    """An executor on the echo daemon, which is container tier: a test that is not about
    the floor asks for container."""
    kwargs.setdefault("minimum_isolation", "container")
    return CodeExecutor(Client(setting("PLIMSOLL_TOOL_ECHO_URL")), **kwargs)


def echo_runs() -> int:
    """How many projects the echo daemon has been handed so far."""
    with urllib.request.urlopen(setting("PLIMSOLL_TOOL_ECHO_URL").rstrip("/") + "/test/project-runs", timeout=10) as r:
        return int(r.read())


def _echo(method: str, path: str) -> bytes:
    req = urllib.request.Request(setting("PLIMSOLL_TOOL_ECHO_URL").rstrip("/") + path, method=method)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read()


def echo_holds() -> Dict[str, int]:
    """What the echo daemon's holds stand at: Describes and Runs waiting, waits that
    ended because the call's context did (the client hung up), Run requests received."""
    return json.loads(_echo("GET", "/test/holds"))


def echo_hold_describe() -> None:
    """Every Describe the echo daemon receives from now on waits for echo_release."""
    _echo("POST", "/test/hold-describe")


def echo_release() -> None:
    _echo("POST", "/test/release")


def echo_trace_id() -> str:
    """The trace ID of the last Run request the echo daemon received, "" for none."""
    return _echo("GET", "/test/last-trace-id").decode()


class Recording(CodeExecutor):
    """An executor that keeps how its last call ended, in the worker thread a
    framework's async path runs it in: the awaiting side of a cancelled call never
    sees that."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.done = threading.Event()
        self.error: Optional[BaseException] = None

    def execute_code(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return super().execute_code(*args, **kwargs)
        except BaseException as e:
            self.error = e
            raise
        finally:
            self.done.set()


def recording() -> Recording:
    return Recording(Client(setting("PLIMSOLL_TOOL_ECHO_URL")), minimum_isolation="container")


def wasm() -> CodeExecutor:
    return CodeExecutor(Client(setting("PLIMSOLL_WASM_URL")), minimum_isolation="process")


def dead() -> CodeExecutor:
    """A daemon nothing listens on."""
    return CodeExecutor(Client("http://127.0.0.1:9"), minimum_isolation="container")


# An API description in plimsoll-specgen's shape, for the grant-echo daemons' one profile.
API_DESCRIPTION = (
    "Echo lights (v1).\nAgent code reaches it through the brokered `host.*` client; only the operations\n"
    "below are permitted.\n\n  host.getLight(id)  ->  GET /v1/lights/*\n  host.lightOn(id, body)  ->  POST /v1/lights/*/on\n"
)
ECHO_ROUTES = ["GET /v1/lights/*", "POST /v1/lights/*/on"]


def grant_client(*, guard: bool = False) -> Client:
    """A client of a grant-echo daemon: its provider named docker (Python steps reach the
    broker), or e2b with guard (they do not)."""
    if guard:
        return Client(setting("PLIMSOLL_GRANT_ECHO_GUARD_URL"), token=setting("PLIMSOLL_GRANT_ECHO_GUARD_TOKEN"))
    return Client(setting("PLIMSOLL_GRANT_ECHO_URL"), token=setting("PLIMSOLL_GRANT_ECHO_TOKEN"))


def granted(*, guard: bool = False, profile: str = "echo-api", **kwargs: Any) -> CodeExecutor:
    """An executor whose runs carry a grant profile the application chose: the daemon's
    one (echo-api) by default."""
    kwargs.setdefault("minimum_isolation", "container")
    return CodeExecutor(grant_client(guard=guard), grant_profile=profile, api_description=API_DESCRIPTION, **kwargs)


class ToolCases:
    """Mixed into each framework's TestCase. ``call(tool, **args)`` returns the text the
    framework's own call path produced; ``make(executor, **opts)`` builds the tool."""

    make: Callable[..., Any]
    call: Callable[..., str]
    acall: Callable[..., Awaitable[str]]
    """The framework's own async tool path, as an agent's async run takes it."""

    def result(self, tool: Any, **args: Any) -> Dict[str, Any]:
        text = self.call(tool, **args)
        self.assertIsInstance(text, str)  # type: ignore[attr-defined]
        return json.loads(text)

    def test_runs_code_and_files_through_the_executor(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        # A budget other than the default, so the check is that the executor's budget
        # reaches the daemon, not what the default happens to be.
        r = self.result(self.make(echo(timeout=17)), code="print(open('data/a.csv').read())",
                        input_files=[{"path": "data/a.csv", "content": "a,b\n1,2\n"}])
        tc.assertIs(r["ran"], True)
        tc.assertEqual(r["outcome"], "completed")
        tc.assertEqual((r["exit_code"], r["timed_out"], r["truncated"]), (0, False, False))
        tc.assertEqual(r["language"], "python")
        tc.assertEqual(r["isolation"], "container")
        tc.assertRegex(r["record_sha256"], re.compile(r"^[0-9a-f]{64}$"))
        plan = json.loads(r["stdout"])
        # The model's file arrived as a file, its code as the executor's script, and the
        # step is the executor's fixed command, not built from either.
        tc.assertEqual(plan["files"]["data/a.csv"], "a,b\n1,2\n")
        tc.assertEqual(plan["files"][".plimsoll/code.py"], "print(open('data/a.csv').read())")
        self.assert_fixed_step("python", ".plimsoll/code.py", plan)
        tc.assertEqual(plan["timeout_s"], 17)

    def test_javascript_is_offered_and_runs_as_javascript(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(echo()), code="console.log(6 * 7)", language="javascript")
        tc.assertIs(r["ran"], True)
        plan = json.loads(r["stdout"])
        tc.assertEqual(plan["files"][".plimsoll/code.mjs"], "console.log(6 * 7)")
        self.assert_fixed_step("javascript", ".plimsoll/code.mjs", plan)

    def assert_fixed_step(self, language: str, script: str, plan: Dict[str, Any]) -> None:
        """The contract, not the command's spelling: one step, which runs the executor's
        script and is the same whatever code and files the model sends, so no part of
        the command is built from them. What the step does in a real sandbox is checked
        by the live runs, not by this echo daemon."""
        tc: unittest.TestCase = self  # type: ignore[assignment]
        tc.assertEqual(len(plan["steps"]), 1)
        tc.assertIn(script, plan["steps"][0])
        other = self.result(self.make(echo()), code="print('$(id) `id` ; rm -rf /') // x", language=language,
                            input_files=[{"path": "data/b.txt", "content": "y"}])
        tc.assertEqual(json.loads(other["stdout"])["steps"], plan["steps"], "the step does not depend on the code or files")

    def test_a_failing_guest_is_a_result(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(echo()), code="ECHO:EXIT")
        tc.assertEqual((r["ran"], r["exit_code"], r["stderr"]), (True, 3, "boom"))

    def test_a_timeout_says_so(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(echo()), code="ECHO:TIMEOUT")
        tc.assertEqual((r["ran"], r["timed_out"], r["exit_code"], r["outcome"]), (True, True, 124, "timed_out"))

    def test_a_run_without_a_step_report_is_unknown_not_a_result(self) -> None:
        # protocol_error is unknown by definition, so neither ran: true nor ran: false is
        # known. No exit code is invented.
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(echo()), code="ECHO:PROTOCOL")
        tc.assertEqual((r["ran"], r["outcome"]), ("unknown", "protocol_error"))
        tc.assertNotIn("exit_code", r)
        tc.assertIn("the runner's report was cut", r["error"])
        tc.assertIn("not retried", r["note"])
        tc.assertRegex(r["record_sha256"], re.compile(r"^[0-9a-f]{64}$"))

    def test_a_setup_failure_did_not_run(self) -> None:
        # setup_failed means no step began, so the code did not run.
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(echo()), code="ECHO:SETUP")
        tc.assertEqual((r["ran"], r["outcome"]), (False, "setup_failed"))
        tc.assertNotIn("exit_code", r)
        tc.assertIn("a file could not be written", r["error"])
        tc.assertRegex(r["record_sha256"], re.compile(r"^[0-9a-f]{64}$"))

    def test_output_is_cut_and_marked(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(echo(), max_output_chars=100), code="ECHO:LOUD")
        tc.assertEqual((len(r["stdout"]), r["truncated"]), (100, True))

    def test_the_default_floor_refuses_a_container_daemon_before_anything_runs(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(CodeExecutor(Client(setting("PLIMSOLL_TOOL_ECHO_URL")))), code="print(1)")
        tc.assertEqual((r["ran"], r["refused"]), (False, "isolation"))

    def test_a_daemon_without_projects_refuses_before_anything_runs(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(wasm()), code="print(1)")
        tc.assertEqual((r["ran"], r["refused"]), (False, "unsupported"))

    def test_a_reserved_path_is_refused_before_anything_runs(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(echo()), code="print(1)", input_files=[{"path": ".plimsoll/code.py", "content": "x"}])
        tc.assertEqual((r["ran"], r["refused"]), (False, "request"))

    def test_an_error_after_dispatch_is_unknown_and_not_retried(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        before = echo_runs()
        r = self.result(self.make(echo()), code="ECHO:LOST")
        tc.assertEqual(r["ran"], "unknown")
        tc.assertIn("not retried", r["note"])
        # Exactly one dispatch: neither the tool nor the framework ran it again.
        tc.assertEqual(echo_runs() - before, 1)

    def test_a_full_allowance_of_input_files_is_accepted(self) -> None:
        # The executor adds its own script, so the tool's limit is one under the client's.
        tc: unittest.TestCase = self  # type: ignore[assignment]
        from plimsoll_client import _code_tool as ct

        files = [{"path": f"in/{i}.txt", "content": "x"} for i in range(ct.MAX_INPUT_FILES)]
        tc.assertIs(self.result(self.make(echo()), code="print(1)", input_files=files)["ran"], True)
        r = tool_direct(self.make(echo()), code="print(1)", input_files=files + [{"path": "in/extra.txt", "content": "x"}])
        tc.assertEqual((r["ran"], r["refused"]), (False, "request"))

    def test_a_dead_daemon_is_an_environment_refusal_before_anything_runs(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(dead()), code="print(1)")
        tc.assertEqual((r["ran"], r["refused"]), (False, "environment"))

    def test_tool_runs_only_the_languages_it_offers(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        tool = self.make(echo(), languages=("python",))
        r = tool_direct(tool, code="1", language="javascript")
        tc.assertEqual((r["ran"], r["refused"]), (False, "request"))
        with tc.assertRaises(ValueError):
            self.make(echo(), languages=("ruby",))
        with tc.assertRaises(ValueError):
            self.make(echo(), languages=())


    # ---- a granted tool (CodeExecutor(grant_profile=..., api_description=...)) ----

    model_view: Callable[[Any], "tuple[str, set]"]
    """The tool's description and its argument names, as the framework hands them to a model."""

    def test_a_granted_tool_tells_the_model_what_its_code_can_call(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        text, args = self.model_view(self.make(granted()))
        tc.assertIn(API_DESCRIPTION.strip(), text)
        tc.assertIn("no network access except the one web API described below", text)
        tc.assertIn("plimsoll_host", text)  # Python is offered: the daemon's provider is docker
        tc.assertIn("adds the API's key outside the sandbox", text)
        # The model's arguments name no profile, no route and no credential: the
        # application chose the profile when it built the executor.
        tc.assertEqual(args, {"code", "language", "input_files"})
        plain, _ = self.model_view(self.make(echo()))
        tc.assertNotIn("web API", plain)
        tc.assertNotIn("plimsoll_host", plain)

    def test_a_granted_call_carries_the_applications_profile_and_nothing_else_does(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        from plimsoll_client import _granted

        r = self.result(self.make(granted()), code="console.log(1)", language="javascript")
        tc.assertIs(r["ran"], True)
        plan = json.loads(r["stdout"])
        tc.assertEqual(plan["grant"]["allow"], ECHO_ROUTES)
        tc.assertNotIn(_granted.HOST_MODULE_PATH, plan["files"])
        r = self.result(self.make(granted()), code="import plimsoll_host", language="python")
        plan = json.loads(r["stdout"])
        tc.assertEqual(plan["grant"]["allow"], ECHO_ROUTES)
        tc.assertEqual(plan["files"][_granted.HOST_MODULE_PATH], _granted.HOST_MODULE_SOURCE)
        tc.assertIn(_granted.HOST_MODULE_DIR, plan["steps"][0])
        # The same daemon, a tool without a grant: no grant reaches the provider.
        r = self.result(self.make(CodeExecutor(grant_client(), minimum_isolation="container")), code="print(1)")
        tc.assertNotIn("grant", json.loads(r["stdout"]))

    def test_python_where_it_cannot_reach_the_api_is_not_offered_and_is_refused(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        tool = self.make(granted(guard=True))
        tc.assertEqual(tuple(tool.languages), ("javascript",))
        text, _ = self.model_view(tool)
        tc.assertIn("Python code cannot call the API on this sandbox", text)
        tc.assertNotIn("import plimsoll_host", text)
        r = tool_direct(tool, code="print(1)", language="python")
        tc.assertEqual((r["ran"], r["refused"]), (False, "unsupported"))
        tc.assertIn("Write the program in JavaScript", r["error"])
        # A tool that would offer none is the application's mistake, said when it is built.
        with tc.assertRaises(ValueError):
            self.make(granted(guard=True), languages=("python",))

    def test_an_unknown_profile_is_refused_as_the_operators_to_fix(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        from plimsoll_client import _code_tool as ct

        r = self.result(self.make(granted(profile="no-such-api")), code="console.log(1)", language="javascript")
        tc.assertEqual((r["ran"], r["refused"]), (False, "permission"))
        tc.assertIn(ct.PERMISSION_NOTE, r["error"])

    def test_a_granted_call_that_may_have_run_says_the_api_may_have_been_called(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        r = self.result(self.make(granted()), code="ECHO:LOST", language="javascript")
        tc.assertEqual(r["ran"], "unknown")
        tc.assertIn("may have called the API too", r["note"])

    def test_cancel_while_describe_is_held_sends_no_run(self) -> None:
        # The call is cancelled
        # while the daemon's Describe answers, before Run is sent.
        tc: unittest.TestCase = self  # type: ignore[assignment]
        executor = recording()
        tool = self.make(executor)
        before = echo_holds()

        async def main() -> float:
            echo_hold_describe()
            task = asyncio.ensure_future(self.acall(tool, code="print(1)"))
            try:
                while echo_holds()["describe_waiting"] == 0:
                    await asyncio.sleep(0.01)
                start = time.monotonic()
                task.cancel()
                with tc.assertRaises(asyncio.CancelledError):
                    await task
                return time.monotonic() - start
            finally:
                echo_release()

        tc.assertLess(asyncio.run(main()), PROMPT)
        # asyncio.run has waited for the worker thread, so a Run it was going to send
        # once Describe answered has been sent and answered by now.
        tc.assertTrue(executor.done.is_set())
        tc.assertEqual(echo_holds()["run_requests"], before["run_requests"], "a Run reached the daemon after the cancel")
        tc.assertIsInstance(executor.error, RequestCanceledError)
        assert isinstance(executor.error, PlimsollError)
        tc.assertEqual(executor.error.not_dispatched, "request")

    def test_cancel_during_a_held_run_cuts_it(self) -> None:
        tc: unittest.TestCase = self  # type: ignore[assignment]
        executor = recording()
        tool = self.make(executor)
        before = echo_holds()

        async def main() -> float:
            task = asyncio.ensure_future(self.acall(tool, code="ECHO:HOLD"))
            try:
                while echo_holds()["run_waiting"] == 0:
                    await asyncio.sleep(0.01)
                start = time.monotonic()
                task.cancel()
                with tc.assertRaises(asyncio.CancelledError):
                    await task
                elapsed = time.monotonic() - start
                # The worker thread ends now, while the daemon still holds the run.
                tc.assertTrue(await asyncio.to_thread(executor.done.wait, PROMPT), "the worker thread kept waiting for the run")
                return elapsed
            finally:
                echo_release()

        tc.assertLess(asyncio.run(main()), PROMPT)
        tc.assertEqual(echo_holds()["run_requests"], before["run_requests"] + 1)
        tc.assertIsInstance(executor.error, RequestCanceledError)
        assert isinstance(executor.error, PlimsollError)
        # Run had been sent: the code may have run, so the error is not marked.
        tc.assertIsNone(executor.error.not_dispatched)
        # The daemon's handler saw the connection close: the context it gave the
        # provider ended before the release.
        deadline = time.monotonic() + PROMPT
        while echo_holds()["run_canceled"] == before["run_canceled"] and time.monotonic() < deadline:
            time.sleep(0.01)
        tc.assertEqual(echo_holds()["run_canceled"], before["run_canceled"] + 1)


def tool_direct(tool: Any, **args: Any) -> Dict[str, Any]:
    """The dict a tool's model answer is made of, past the framework's own validation
    (which refuses a language the schema does not offer before the tool sees it)."""
    from plimsoll_client import _code_tool as ct

    return ct.run(tool.executor, tool.languages, ct.MAX_OUTPUT_CHARS, args["code"], args.get("language"), args.get("input_files"))
