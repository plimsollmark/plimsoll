"""PlimsollShellTool and plimsoll_code_tool through Agent Framework's own paths: the harness
(create_harness_agent, its shell assembly and its ShellEnvironmentProvider), the function
invocation loop driven by a scripted chat client, and FunctionTool.invoke. A real Workspace
runs over a session faked in memory; no model and no network are used. What the shell does on
a real session is the docker check's."""

from __future__ import annotations

import asyncio
import threading
import time
import unittest
import warnings
from typing import Any, Dict, List, Optional, Sequence, Tuple

import contextlib
from unittest import mock

from agent_framework import (
    BaseChatClient,
    ChatResponse,
    Content,
    FunctionInvocationLayer,
    FunctionTool,
    Message,
    MiddlewareFailure,
    SupportsChatGetResponse,
    SupportsShellTool,
    create_harness_agent,
    function_middleware,
)
from agent_framework._harness._agent import _assemble_shell
from agent_framework.observability import OBSERVABILITY_SETTINGS
from agent_framework_tools.shell import ShellEnvironmentProvider, ShellExecutor, ShellResult
from opentelemetry import trace as otel

import plimsoll_client.agent_framework as paf
from plimsoll_client import (
    AsyncClient,
    AtCapacityError,
    Client,
    InsufficientIsolationError,
    InvalidRequestError,
    PlimsollError,
    RequestCanceledError,
    SessionEndedError,
    retry_on,
)
from plimsoll_client.agent_framework import LABEL_KEYS, PlimsollShellResult, PlimsollShellTool, call_labels, plimsoll_code_tool
from plimsoll_client.execution import CodeExecutor
from plimsoll_client.types import Artifact, ProjectResult, RunRecord, SessionSummary, StepResult
from plimsoll_client.workspace import STATE_DIR, WorkspaceCallError

CMD = STATE_DIR + "/cmd"
# Seconds a canceled call may take to end: a cut is a thread waking, milliseconds.
PROMPT = 1.0


def result(
    stdout: bytes = b"",
    stderr: bytes = b"",
    exit_code: int = 0,
    *,
    timed_out: bool = False,
    outcome: str = "completed",
    stdout_truncated: bool = False,
    steps: bool = True,
    isolation: str = "kernel",
    qualification: str = "",
    record: Optional[RunRecord] = None,
) -> ProjectResult:
    step = StepResult(command="", stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=timed_out, duration_ms=1,
                      stdout_truncated=stdout_truncated, stderr_truncated=False)
    return ProjectResult(provider="fake", isolation=isolation, environment="", software_identity="", duration_ms=1, record=record,
                         isolation_qualification=qualification,
                         outcome=outcome, detail="", steps=(step,) if steps else (),
                         artifacts=(Artifact(STATE_DIR + "/root", b"/work\n"), Artifact(STATE_DIR + "/cwd", b"/work\n")),
                         artifacts_truncated=False, advice=())


#: A digest that is a record's, and a sentence a provider states beside its tier.
DIGEST = "ab" * 32
SENTENCE = "The provider states that this tier is not a security boundary for hostile code."


def record(isolation: str = "vm", qualification: str = SENTENCE, digest: str = DIGEST) -> RunRecord:
    return RunRecord(version=5, request_sha256="1" * 64, result_sha256="2" * 64, provider="fake", isolation=isolation,
                     environment="", policy="", software_identity="", software_rule_id="", started_unix_ms=1, ended_unix_ms=2,
                     session="s", sequence=1, previous_sha256="", sha256=digest, isolation_qualification=qualification)


def stated(stdout: bytes = b"hello\n", **kw: Any) -> ProjectResult:
    """A completed command whose answer states a tier, the provider's sentence and a record."""
    return result(stdout, isolation="vm", qualification=SENTENCE, record=record(), **kw)


class RecordingSpan(otel.Span):
    """A span that keeps its name and attributes, for checking what reached a trace."""

    def __init__(self, name: str, attributes: Optional[Dict[str, Any]]) -> None:
        self.name = name
        self.attributes: Dict[str, Any] = dict(attributes or {})

    def end(self, end_time: Optional[int] = None) -> None:
        pass

    def get_span_context(self) -> otel.SpanContext:
        return otel.SpanContext(trace_id=1, span_id=id(self) & 0xFFFFFFFF or 1, is_remote=False, trace_flags=otel.TraceFlags(1))

    def set_attributes(self, attributes: Any) -> None:
        self.attributes.update(attributes)

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def add_event(self, name: str, attributes: Any = None, timestamp: Any = None) -> None:
        pass

    def update_name(self, name: str) -> None:
        self.name = name

    def is_recording(self) -> bool:
        return True

    def set_status(self, status: Any, description: Optional[str] = None) -> None:
        pass

    def record_exception(self, exception: BaseException, attributes: Any = None, timestamp: Any = None, escaped: bool = False) -> None:
        pass


class OpaqueSpan(RecordingSpan):
    """A recording span that keeps its attributes but does not show them, as a span of an
    OpenTelemetry implementation other than the SDK may not."""

    def __init__(self) -> None:
        self.name = "opaque"
        self.kept: Dict[str, Any] = {}

    @property
    def attributes(self) -> Dict[str, Any]:  # type: ignore[override]
        raise AttributeError("attributes")

    def set_attributes(self, attributes: Any) -> None:
        self.kept.update(attributes)

    def set_attribute(self, key: str, value: Any) -> None:
        self.kept[key] = value


class RecordingTracer(otel.Tracer):
    """Stands in for an OpenTelemetry SDK's tracer (the lock holds only the API): every span the
    framework starts is kept."""

    def __init__(self) -> None:
        self.spans: List[RecordingSpan] = []

    def start_span(self, name: str, context: Any = None, kind: Any = None, attributes: Any = None, *args: Any, **kw: Any) -> RecordingSpan:
        span = RecordingSpan(name, attributes)
        self.spans.append(span)
        return span

    @contextlib.contextmanager
    def start_as_current_span(self, name: str, context: Any = None, kind: Any = None, attributes: Any = None, *args: Any,
                              end_on_exit: bool = True, **kw: Any) -> Any:
        span = self.start_span(name, attributes=attributes)
        with otel.use_span(span, end_on_exit=end_on_exit, record_exception=False, set_status_on_exception=False):
            yield span

    def tool_spans(self, name: str) -> List[RecordingSpan]:
        return [s for s in self.spans if s.name == "execute_tool " + name]


@contextlib.contextmanager
def traced() -> Any:
    """The framework's tracer replaced by a recording one, for the block."""
    tracer = RecordingTracer()
    with mock.patch("agent_framework.observability.get_tracer", lambda *a, **k: tracer):
        yield tracer


def plimsoll_attributes(span: RecordingSpan) -> Dict[str, Any]:
    return {k: v for k, v in span.attributes.items() if k.startswith("plimsoll.")}


class FakeSession:
    """What a Workspace asks of a Session, in memory. ``replies`` maps a command to what it
    gives (a ProjectResult, or an exception to raise); any other command answers
    ``ran <command>``. After close, a call raises SessionEndedError, as Session does."""

    fingerprint = "fp-fake"

    def __init__(self, isolation: str) -> None:
        self.isolation = isolation
        self.closes = 0
        self.commands: List[str] = []
        self.budgets: List[float] = []
        self.cancels: List[Any] = []
        self.replies: Dict[str, Any] = {}
        self.hold: Optional[threading.Event] = None
        self.done = threading.Event()
        self.error: Optional[BaseException] = None

    def run_project(self, files: Dict[str, str], steps: Sequence[str], artifacts: Sequence[str], *, timeout: float, cancel: Any = None) -> ProjectResult:
        if self.closes:
            raise SessionEndedError("plimsoll: this session was closed; nothing was sent", reason="closed", not_dispatched="request")
        command = files[CMD]
        self.commands.append(command)
        self.budgets.append(timeout)
        self.cancels.append(cancel)
        try:
            if self.hold is not None:
                while not (cancel is not None and cancel.cancelled):
                    self.hold.wait(0.01)
                raise RequestCanceledError("plimsoll: the call was canceled in flight")
            reply = self.replies.get(command, result(f"ran {command}\n".encode()))
            if isinstance(reply, BaseException):
                raise reply
            return reply
        except BaseException as e:
            self.error = e
            raise
        finally:
            self.done.set()

    def close(self) -> SessionSummary:
        self.closes += 1
        return SessionSummary(session=self.fingerprint, calls=len(self.commands), last_record_sha256="", end="closed")


class FakeClient(Client):
    """A Client whose open_session answers a FakeSession at the given tier, with no daemon."""

    def __init__(self, isolation: str = "kernel") -> None:
        super().__init__("http://127.0.0.1:9")
        self.isolation = isolation
        self.opened: List[Dict[str, Any]] = []
        self.sessions: List[FakeSession] = []
        self.hold: Optional[threading.Event] = None  # set: an open waits for it
        self.opening = threading.Event()

    def open_session(self, **kw: Any) -> Any:  # type: ignore[override]
        self.opened.append(kw)
        self.opening.set()
        if self.hold is not None:
            self.hold.wait(PROMPT)
        s = FakeSession(self.isolation)
        self.sessions.append(s)
        return s

    @property
    def session(self) -> FakeSession:
        """The one session opened."""
        assert len(self.sessions) == 1, f"{len(self.sessions)} sessions opened"
        return self.sessions[0]


def run(coro: Any) -> Any:
    return asyncio.run(coro)


class Scripted(FunctionInvocationLayer, BaseChatClient):
    """A chat client that answers with the given tool calls in order, then "done", and takes
    any tools; it states shell support, whose tool is the function itself."""

    def __init__(self, *calls: Tuple[str, Dict[str, Any]]) -> None:
        super().__init__()
        self.calls = list(calls)
        self.requests: List[List[Message]] = []

    @staticmethod
    def get_shell_tool(**kwargs: Any) -> Any:
        return kwargs["func"]

    def _inner_get_response(self, *, messages: Sequence[Message], stream: bool, options: Any, **kwargs: Any) -> Any:
        self.requests.append(list(messages))

        async def answer() -> ChatResponse:
            if self.calls:
                name, args = self.calls.pop(0)
                content = Content.from_function_call(f"call-{len(self.requests)}", name, arguments=args)
                return ChatResponse(messages=[Message(role="assistant", contents=[content])], response_id="r")
            return ChatResponse(messages=[Message(role="assistant", contents=["done"])], response_id="r")

        return answer()

    def results(self) -> List[Content]:
        """The function results the model was sent, in order."""
        return [c for m in self.requests[-1] for c in m.contents if c.type == "function_result"]


def harness(client: Scripted, shell: PlimsollShellTool, middleware: Optional[List[Any]] = None) -> Any:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # the framework marks its shell tooling as pre-release
        # No file memory: it would write under the working directory.
        return create_harness_agent(client, shell_executor=shell, disable_file_memory=True, disable_web_search=True, middleware=middleware)


async def converse_with(client: Scripted, shell: PlimsollShellTool, middleware: Optional[List[Any]] = None) -> Scripted:
    agent = harness(client, shell, middleware)
    await agent.run("go", session=agent.create_session())
    return client


async def converse(shell: PlimsollShellTool, *calls: Tuple[str, Dict[str, Any]]) -> Scripted:
    return await converse_with(Scripted(*calls), shell)


def shell_calls(session: FakeSession) -> List[str]:
    """The commands an agent sent, past the environment provider's probes."""
    return [c for c in session.commands if not (c.startswith('echo "VERSION=') or c.endswith(" --version"))]


class ShellToolTests(unittest.TestCase):
    def test_is_a_shell_executor(self) -> None:
        # ShellExecutor is a runtime-checkable protocol: this is the check the framework can make.
        self.assertIsInstance(PlimsollShellTool(FakeClient(), minimum_isolation="kernel"), ShellExecutor)

    def test_the_harness_takes_it_as_the_shell_and_probes_through_it(self) -> None:
        tool = PlimsollShellTool(FakeClient(), minimum_isolation="kernel")
        client = Scripted()
        self.assertIsInstance(client, SupportsChatGetResponse)
        self.assertIsInstance(client, SupportsShellTool)
        shell, provider = _assemble_shell(client, tool, None)
        self.assertIsInstance(shell, FunctionTool)
        assert isinstance(shell, FunctionTool)
        self.assertEqual((shell.name, shell.kind, shell.approval_mode), ("run_shell", "shell", "never_require"))
        self.assertIsInstance(provider, ShellEnvironmentProvider)
        agent = harness(client, tool)
        self.assertIn("run_shell", [t.name for t in agent.default_options["tools"]])
        self.assertTrue(any(isinstance(p, ShellEnvironmentProvider) for p in agent.context_providers))

    def test_a_scripted_command_answers_with_its_output(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel")
        client = run(converse(tool, ("run_shell", {"command": "echo hi"})))
        self.assertEqual(shell_calls(c.session), ["echo hi"])
        # The environment provider started the tool and probed the shell through it first.
        self.assertTrue(c.session.commands[0].startswith('echo "VERSION='))
        (r,) = client.results()
        self.assertIsNone(r.exception)
        self.assertEqual(r.result, "exit code: 0\nran echo hi")
        self.assertEqual(len(c.opened), 1, "one session for the probes and the command")
        self.assertEqual(c.opened[0], {"minimum_isolation": "kernel", "lifetime": 3600.0, "languages": None, "owner": None})

    def test_a_non_zero_exit_is_a_result(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel")
        run(tool.start())
        c.session.replies["make"] = result(b"partial\n", b"error: no rule\n", 2)
        r = run(tool.run("make"))
        self.assertEqual((r.stdout, r.stderr, r.exit_code, r.timed_out, r.truncated), ("partial\n", "error: no rule\n", 2, False, False))
        self.assertGreaterEqual(r.duration_ms, 0)
        text = run(tool.as_function().invoke(arguments={"command": "make"}))[0].text
        self.assertEqual(text, "exit code: 2\npartial\nstderr:\nerror: no rule")

    def test_a_timeout_sets_timed_out_and_is_a_result(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel", timeout=30)
        run(tool.start())
        c.session.replies["sleep 99"] = result(b"started\n", exit_code=124, timed_out=True, outcome="timed_out")
        r = run(tool.run("sleep 99", timeout=7))
        self.assertEqual((r.exit_code, r.timed_out, r.stdout), (124, True, "started\n"))
        self.assertEqual(c.session.budgets, [7.0])
        self.assertIn("past its time budget", run(tool.as_function().invoke(arguments={"command": "sleep 99"}))[0].text)

    def test_budgets(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel", timeout=30, max_timeout=300)
        for t in (None, 0, 45, 900):
            run(tool.run("true", timeout=t))
        # None or 0: the default; past max_timeout: capped.
        self.assertEqual(c.session.budgets, [30.0, 30.0, 45.0, 300.0])
        for bad in (-1, float("nan"), float("inf"), True, "5"):
            with self.assertRaises(ValueError):
                run(tool.run("true", timeout=bad))  # type: ignore[arg-type]
        self.assertEqual(len(c.session.commands), 4, "a bad budget sends nothing")

    def test_a_tier_below_the_floor_raises_at_start_and_sends_no_command(self) -> None:
        c = FakeClient("container")
        tool = PlimsollShellTool(c, minimum_isolation="kernel")
        with self.assertRaises(InsufficientIsolationError) as cm:
            run(tool.start())
        self.assertEqual(cm.exception.not_dispatched, "isolation")
        self.assertEqual(c.sessions[0].commands, [])
        self.assertEqual(c.sessions[0].closes, 1, "no session stays open")
        with self.assertRaises(RuntimeError):
            tool.session  # noqa: B018
        # The same through the harness: its environment provider starts the tool, and the
        # run stops there, before the model is asked anything.
        client = Scripted(("run_shell", {"command": "echo hi"}))
        with self.assertRaises(InsufficientIsolationError):
            run(converse_with(client, PlimsollShellTool(c, minimum_isolation="kernel")))
        self.assertTrue(all(s.commands == [] and s.closes == 1 for s in c.sessions))
        self.assertEqual(client.requests, [])

    def test_a_refusal_raises_and_is_never_returned_as_text(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel")
        run(tool.start())
        c.session.replies["ls"] = AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        with self.assertRaises(AtCapacityError):
            run(tool.run("ls"))
        with self.assertRaises(AtCapacityError):
            run(tool.as_function().invoke(arguments={"command": "ls"}))
        # Through the agent the framework turns the exception into an error result; the
        # refusal's text is never the command's output.
        client = run(converse(tool, ("run_shell", {"command": "ls"})))
        (r,) = client.results()
        self.assertIn("at capacity", r.exception or "")
        self.assertNotIn("exit code", str(r.result))

    def test_a_refusal_during_the_environment_probe_stops_the_run(self) -> None:
        # The framework's ShellEnvironmentProvider reads a probe that raises its own shell errors
        # (ShellExecutionError, ShellTimeoutError, ShellCommandError) or TimeoutError as "not
        # installed" (agent_framework_tools/shell/_environment.py:238). plimsoll's refusals are
        # none of those, so a refused probe stops the run before the model is asked anything,
        # rather than telling the model a CLI is missing.
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel")
        run(tool.start())
        c.session.replies["python --version"] = AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        client = Scripted(("run_shell", {"command": "echo hi"}))
        with self.assertRaises(AtCapacityError):
            run(converse_with(client, tool))
        self.assertEqual(client.requests, [])
        self.assertNotIn("echo hi", c.session.commands)

    def test_an_error_after_which_the_command_may_have_run_raises(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel")
        run(tool.start())
        lost = PlimsollError("plimsoll: the answer was lost", code="unavailable")
        self.assertIsNone(lost.not_dispatched)
        c.session.replies["rm -rf build"] = lost
        with self.assertRaises(PlimsollError) as cm:
            run(tool.run("rm -rf build"))
        self.assertIs(cm.exception, lost)
        # A run with no step's report: the workspace's may-have-run error.
        c.session.replies["make"] = result(outcome="protocol_error", steps=False)
        with self.assertRaises(RuntimeError) as rcm:
            run(tool.run("make"))
        self.assertIn("may have run", str(rcm.exception))
        self.assertEqual(shell_calls(c.session), ["rm -rf build", "make"], "neither was retried")

    def test_an_ended_session_raises_and_is_never_replaced(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel")
        run(tool.start())
        run(tool.close())
        run(tool.start())  # does nothing: the tool never opens a second session
        with self.assertRaises(SessionEndedError) as cm:
            run(tool.run("cat notes.md"))
        self.assertEqual(cm.exception.reason, "closed")
        self.assertEqual(len(c.opened), 1)

    def test_close_twice_and_before_start_is_safe(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel")
        run(tool.close())
        self.assertEqual(c.opened, [])

        async def twice() -> None:
            async with tool as t:
                self.assertIs(t, tool)
                self.assertEqual(t.isolation, "kernel")
            await tool.close()

        run(twice())
        self.assertGreaterEqual(c.session.closes, 1)

    def test_a_close_that_races_the_open_closes_what_it_opened(self) -> None:
        # A start whose await was canceled goes on opening in its thread; a close meanwhile
        # waits for it and closes the session, so none outlives close().
        c = FakeClient()
        c.hold = threading.Event()
        tool = PlimsollShellTool(c, minimum_isolation="kernel")

        async def main() -> None:
            start = asyncio.ensure_future(tool.start())
            await asyncio.to_thread(c.opening.wait, PROMPT)
            start.cancel()
            closing = asyncio.ensure_future(tool.close())
            await asyncio.sleep(0.05)
            c.hold.set()
            await closing

        run(main())
        self.assertEqual(c.session.closes, 1)

    def test_start_twice_opens_one_session_and_run_opens_it_if_needed(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel")
        with self.assertRaises(RuntimeError):
            tool.session  # noqa: B018

        async def concurrently() -> None:
            await asyncio.gather(tool.start(), tool.start(), tool.run("pwd"))

        run(concurrently())
        self.assertEqual(len(c.opened), 1)
        self.assertIs(tool.session, c.session)
        self.assertEqual(c.session.commands, ["pwd"])

    def test_canceling_the_task_cancels_the_call(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel")
        run(tool.start())
        c.session.hold = threading.Event()

        async def main() -> float:
            task = asyncio.ensure_future(tool.run("sleep 60"))
            while not c.session.cancels:
                await asyncio.sleep(0.01)
            start = time.monotonic()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(await asyncio.to_thread(c.session.done.wait, PROMPT), "the worker thread kept waiting")
            return time.monotonic() - start

        self.assertLess(run(main()), PROMPT)
        self.assertTrue(c.session.cancels[0].cancelled, "the call's cancel handle was canceled")
        self.assertIsInstance(c.session.error, RequestCanceledError)

    def test_output_is_cut_and_marked(self) -> None:
        c = FakeClient()
        tool = PlimsollShellTool(c, minimum_isolation="kernel", max_output_chars=10)
        run(tool.start())
        c.session.replies["yes"] = result(b"y\n" * 50)
        c.session.replies["short"] = result(b"ok\n", stdout_truncated=True)
        r = run(tool.run("yes"))
        self.assertEqual((r.stdout, r.truncated), ("y\n" * 5, True))
        # The daemon's own cut is reported too.
        self.assertTrue(run(tool.run("short")).truncated)
        self.assertTrue(run(tool.as_function().invoke(arguments={"command": "yes"}))[0].text.endswith("[output truncated]"))

    def test_the_description_states_the_tier_the_shell_and_the_network(self) -> None:
        tool = PlimsollShellTool(FakeClient(), minimum_isolation="kernel", approval_mode="always_require")
        before = tool.as_function(name="sandbox_shell")
        self.assertEqual((before.name, before.approval_mode), ("sandbox_shell", "always_require"))
        self.assertIn("kernel isolation tier or stronger", before.description)
        for words in ("plimsoll sandbox", "the sandbox image's sh (BusyBox sh on plimsoll's docker images)",
                      "no network access unless the operator", "persist"):
            self.assertIn(words, before.description)
        run(tool.start())
        self.assertIn("isolated at the kernel isolation tier,", tool.as_function().description)
        self.assertEqual(tool.as_function(description="mine").description, "mine")

    def test_construction_refuses_what_it_cannot_keep(self) -> None:
        with self.assertRaises(TypeError):
            PlimsollShellTool(FakeClient())  # type: ignore[call-arg]  # the floor has no default
        for bad in ("", None):
            with self.assertRaises(ValueError):
                PlimsollShellTool(FakeClient(), minimum_isolation=bad)  # type: ignore[arg-type]
        with self.assertRaises(PlimsollError):
            PlimsollShellTool(FakeClient(), minimum_isolation="kernl")
        for kw in ({"timeout": 0}, {"lifetime": -1}, {"max_timeout": 0}, {"max_output_chars": 0}, {"approval_mode": "sometimes"}):
            with self.assertRaises(ValueError, msg=kw):
                PlimsollShellTool(FakeClient(), minimum_isolation="kernel", **kw)  # type: ignore[arg-type]
        with self.assertRaises(PlimsollError):
            PlimsollShellTool(FakeClient(), minimum_isolation="kernel", languages=["ruby"])
        with self.assertRaises(TypeError):
            PlimsollShellTool(AsyncClient("http://127.0.0.1:9"), minimum_isolation="kernel")  # type: ignore[arg-type]

    def test_open_carries_the_session_options(self) -> None:
        c = FakeClient("vm")
        run(PlimsollShellTool(c, minimum_isolation="vm", lifetime=60, languages=("python",), owner="user-7").start())
        self.assertEqual(c.opened, [{"minimum_isolation": "vm", "lifetime": 60.0, "languages": ["python"], "owner": "user-7"}])

    def test_the_private_shell_kind_exists_at_the_pinned_version(self) -> None:
        # The one private name this module imports; agent-framework-plimsoll pins the version.
        from agent_framework._tools import SHELL_TOOL_KIND_VALUE

        self.assertEqual(SHELL_TOOL_KIND_VALUE, "shell")
        self.assertIs(paf.SHELL_TOOL_KIND_VALUE, SHELL_TOOL_KIND_VALUE)
        self.assertIs(paf.ShellResult, ShellResult)


class WhatReachesTheApplicationTests(unittest.TestCase):
    """For each command, the application can get what plimsoll states about it: the checked run
    record (and its SHA-256), the tier with the provider's sentence, the outcome, and whether
    anything was dispatched with the refusal's reason, through the framework's own channels
    (the ShellResult, the function result's additional_properties, a function middleware, the
    tool span), and nothing the guest wrote is ever one of plimsoll's labels."""

    def tool(self) -> Tuple[FakeClient, PlimsollShellTool]:
        c = FakeClient("vm")
        tool = PlimsollShellTool(c, minimum_isolation="vm")
        run(tool.start())
        return c, tool

    def test_run_returns_the_tier_the_sentence_the_outcome_and_the_record(self) -> None:
        c, tool = self.tool()
        c.session.replies["date"] = stated()
        r = run(tool.run("date"))
        self.assertIsInstance(r, PlimsollShellResult)
        self.assertIsInstance(r, ShellResult, "the framework's own type, as its environment provider reads it")
        self.assertEqual((r.isolation, r.isolation_qualification, r.outcome, r.record_sha256), ("vm", SENTENCE, "completed", DIGEST))
        assert r.record is not None and r.result is not None
        self.assertEqual(r.record.sha256, DIGEST)
        self.assertIs(r.result, c.session.replies["date"])
        # A timed-out command states its outcome too.
        c.session.replies["sleep 9"] = result(exit_code=124, timed_out=True, outcome="timed_out", isolation="vm", record=record())
        self.assertEqual(run(tool.run("sleep 9")).outcome, "timed_out")

    def test_through_the_agent_each_result_carries_the_labels_beside_the_models_text(self) -> None:
        c, tool = self.tool()
        c.session.replies["date"] = stated()
        client = run(converse(tool, ("run_shell", {"command": "date"})))
        (r,) = client.results()
        self.assertEqual(r.result, "exit code: 0\nhello", "the model's text is unchanged")
        (item,) = r.items or []
        props = item.additional_properties
        # Microsoft's own shell tool's five fields, then plimsoll's labels.
        self.assertEqual({k: props[k] for k in ("stdout", "stderr", "exit_code", "truncated", "timed_out")},
                         {"stdout": "hello\n", "stderr": "", "exit_code": 0, "truncated": False, "timed_out": False})
        self.assertEqual({k: v for k, v in props.items() if k.startswith("plimsoll_")}, {
            "plimsoll_dispatched": "yes",
            "plimsoll_outcome": "completed",
            "plimsoll_isolation": "vm",
            "plimsoll_isolation_qualification": SENTENCE,
            "plimsoll_record_sha256": DIGEST,
        })
        self.assertTrue(set(k for k in props if k.startswith("plimsoll_")) <= set(LABEL_KEYS))

    def test_nothing_the_guest_wrote_becomes_a_label(self) -> None:
        # Output shaped like a digest, a tier and an outcome stays output; values outside their
        # closed sets are left out.
        forged = result(("plimsoll_record_sha256=" + "cd" * 32 + " kernel completed\n").encode(), isolation="hyperkernel", outcome="pwned",
                        record=record(digest="not a digest"))
        labels = call_labels(PlimsollShellResult(stdout="x", stderr="", exit_code=0, duration_ms=1, isolation="hyperkernel",
                                                  outcome="pwned", record_sha256="not a digest", result=forged))
        self.assertEqual(labels, {"plimsoll_dispatched": "yes"})
        self.assertEqual(call_labels(AtCapacityError("x", not_dispatched="a reason no daemon gives")),
                         {"plimsoll_dispatched": "no", "plimsoll_refused": "unknown"})

    def test_a_refusal_reaches_a_function_middleware_as_the_exception(self) -> None:
        c, tool = self.tool()
        c.session.replies["ls"] = AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        c.session.replies["date"] = stated()
        seen: List[Any] = []

        @function_middleware
        async def watch(context: Any, call_next: Any) -> None:
            try:
                await call_next()
            except PlimsollError as e:
                seen.append(e)
                raise
            seen.append(context.result)

        client = run(converse_with(Scripted(("run_shell", {"command": "ls"}), ("run_shell", {"command": "date"})), tool, [watch]))
        refusal, answered = seen
        self.assertIsInstance(refusal, AtCapacityError)
        self.assertEqual(refusal.not_dispatched, "capacity")
        self.assertEqual(call_labels(refusal), {"plimsoll_dispatched": "no", "plimsoll_refused": "capacity"})
        self.assertEqual(answered[0].additional_properties["plimsoll_record_sha256"], DIGEST)
        # The model got the framework's error result for the refusal, then the command's output.
        first, second = [x for m in client.requests[-1] for x in m.contents if x.type == "function_result"]
        self.assertIn("at capacity", first.exception or "")
        self.assertEqual(second.result, "exit code: 0\nhello")

    def test_an_answered_call_with_no_step_report_keeps_its_result(self) -> None:
        # setup_failed: no step began, so the command did not run; protocol_error: it may have.
        # Either way the daemon answered, and its result (outcome, tier, record) comes with the
        # error rather than being dropped.
        c, tool = self.tool()
        for command, outcome, said in (("make", "setup_failed", "did not run"), ("make all", "protocol_error", "may have run")):
            c.session.replies[command] = result(outcome=outcome, steps=False, isolation="vm", qualification=SENTENCE, record=record())
            with self.assertRaises(WorkspaceCallError) as cm:
                run(tool.run(command))
            self.assertIn(said, str(cm.exception))
            self.assertIsInstance(cm.exception, RuntimeError)
            self.assertEqual(cm.exception.result.outcome, outcome)
            self.assertEqual(call_labels(cm.exception), {
                "plimsoll_dispatched": "yes", "plimsoll_outcome": outcome, "plimsoll_isolation": "vm",
                "plimsoll_isolation_qualification": SENTENCE, "plimsoll_record_sha256": DIGEST,
            })
            self.assertFalse(retry_on(cm.exception))

    def test_a_may_have_run_error_with_the_sessions_record_keeps_the_record(self) -> None:
        lost = PlimsollError("plimsoll: the answer was lost", code="unavailable")
        lost.record = record()
        self.assertEqual(call_labels(lost), {
            "plimsoll_dispatched": "unknown", "plimsoll_isolation": "vm",
            "plimsoll_isolation_qualification": SENTENCE, "plimsoll_record_sha256": DIGEST,
        })
        self.assertEqual(call_labels(PlimsollError("plimsoll: the answer was lost")), {"plimsoll_dispatched": "unknown"})
        self.assertEqual(call_labels(ValueError("anything else")), {"plimsoll_dispatched": "unknown"})

    def test_the_tool_span_gets_the_labels_and_nothing_else_of_plimsolls(self) -> None:
        self.assertTrue(OBSERVABILITY_SETTINGS.ENABLED, "the framework's instrumentation is on by default")
        c, tool = self.tool()
        c.session.replies["date"] = stated(b"secret output " + DIGEST.encode() + b"\n")
        c.session.replies["ls"] = AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        with traced() as tracer:
            run(converse(tool, ("run_shell", {"command": "date"}), ("run_shell", {"command": "ls"})))
        answered, refused = tracer.tool_spans("run_shell")
        self.assertEqual(plimsoll_attributes(answered), {
            "plimsoll.dispatched": "yes", "plimsoll.outcome": "completed", "plimsoll.isolation": "vm",
            "plimsoll.isolation_qualification": SENTENCE, "plimsoll.record_sha256": DIGEST,
        })
        self.assertEqual(plimsoll_attributes(refused), {"plimsoll.dispatched": "no", "plimsoll.refused": "capacity"})
        for span in tracer.spans:
            for value in span.attributes.values():
                self.assertNotIn("secret output", str(value), f"{span.name} carries the guest's output")

    def test_only_the_tools_own_span_is_labeled(self) -> None:
        c, tool = self.tool()
        c.session.replies["date"] = stated()
        tracer = RecordingTracer()
        # An application's own span around a direct call: not the framework's tool span.
        with tracer.start_as_current_span("my app", attributes={"gen_ai.operation.name": "chat"}) as mine:
            paf._label_span("run_shell", {"plimsoll_dispatched": "yes"})
            run(tool.run("date"))
        self.assertEqual(plimsoll_attributes(mine), {})
        # Another tool's span is left alone too.
        with tracer.start_as_current_span("execute_tool other", attributes={"gen_ai.operation.name": "execute_tool",
                                                                             "gen_ai.tool.name": "other"}) as other:
            paf._label_span("run_shell", {"plimsoll_dispatched": "yes"})
        self.assertEqual(plimsoll_attributes(other), {})
        # With the instrumentation on, a recording span that does not show its attributes may be an
        # application's own, so it is left alone too.
        self.assertTrue(OBSERVABILITY_SETTINGS.ENABLED)
        shy = OpaqueSpan()
        with otel.use_span(shy, end_on_exit=False):
            paf._label_span("run_shell", {"plimsoll_dispatched": "yes"})
        self.assertEqual(shy.kept, {})
        # With the instrumentation off, even a span that says it is this tool's is not the
        # framework's, which opens none then.
        named = RecordingSpan("execute_tool run_shell", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "run_shell"})
        with mock.patch.object(type(OBSERVABILITY_SETTINGS), "ENABLED", new_callable=mock.PropertyMock, return_value=False):
            with otel.use_span(named, end_on_exit=False):
                paf._label_span("run_shell", {"plimsoll_dispatched": "yes"})
        self.assertEqual(plimsoll_attributes(named), {})
        # With the framework's instrumentation off it opens no tool span, so the current span
        # during the call is the application's; one that does not show its attributes is left
        # alone too.
        opaque = OpaqueSpan()
        with mock.patch.object(type(OBSERVABILITY_SETTINGS), "ENABLED", new_callable=mock.PropertyMock, return_value=False), traced() as off:
            with otel.use_span(opaque, end_on_exit=False):
                run(converse(tool, ("run_shell", {"command": "date"})))
        self.assertEqual(off.tool_spans("run_shell"), [])
        self.assertEqual({k: v for k, v in opaque.kept.items() if k.startswith("plimsoll.")}, {})

    def test_the_framework_does_not_run_a_refused_call_again(self) -> None:
        # The framework turns a tool's exception into one error result for the model and never
        # invokes the tool again by itself (agent-framework-core 1.26.0, _tools.py).
        c, tool = self.tool()
        c.session.replies["ls"] = AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        client = run(converse(tool, ("run_shell", {"command": "ls"})))
        self.assertEqual(shell_calls(c.session), ["ls"])
        (r,) = client.results()
        self.assertIsNotNone(r.exception)

    def test_a_command_that_may_have_run_stops_the_run(self) -> None:
        # The answer was lost, or the run ended without the command's report: the command may
        # have run, so the run ends (the framework's MiddlewareFailure, plimsoll's error as its
        # cause) instead of the model getting an error result it could answer by running it again.
        for reply in (PlimsollError("plimsoll: the answer was lost", code="unavailable"),
                      result(outcome="protocol_error", steps=False, isolation="vm", record=record())):
            c, tool = self.tool()
            c.session.replies["rm -rf build"] = reply
            client = Scripted(("run_shell", {"command": "rm -rf build"}), ("run_shell", {"command": "rm -rf build"}))
            with self.assertRaises(MiddlewareFailure) as cm:
                run(converse_with(client, tool))
            self.assertEqual(shell_calls(c.session), ["rm -rf build"], "it ran at most once")
            self.assertEqual(len(client.requests), 1, "the model was not asked again")
            cause = cm.exception.__cause__
            self.assertIsInstance(cause, (PlimsollError, WorkspaceCallError))
            self.assertTrue(paf.may_have_run(cause))
            self.assertFalse(retry_on(cause))
            self.assertEqual(call_labels(cm.exception)["plimsoll_dispatched"], call_labels(cause)["plimsoll_dispatched"])
        # The unanswered call's record reaches the application through the cause.
        self.assertEqual(call_labels(cm.exception)["plimsoll_record_sha256"], DIGEST)

    def test_what_ran_nothing_goes_to_the_model_and_the_run_goes_on(self) -> None:
        # A marked refusal, an ended session, setup_failed (no step began) and the tool's own
        # input checks ran nothing: the model gets an error result and the run continues.
        c, tool = self.tool()
        c.session.replies["make"] = result(outcome="setup_failed", steps=False, isolation="vm", record=record())
        client = run(converse(tool, ("run_shell", {"command": "make"}), ("run_shell", {"command": "echo\x00x"}),
                              ("run_shell", {"command": "date"})))
        first, second, third = [x for m in client.requests[-1] for x in m.contents if x.type == "function_result"]
        self.assertIn("did not run", first.exception or "")
        self.assertIsNotNone(second.exception)
        self.assertIsNone(third.exception)
        for e in (AtCapacityError("x", not_dispatched="capacity"), SessionEndedError("x", reason="closed", not_dispatched="request"),
                  WorkspaceCallError("x", result(outcome="setup_failed", steps=False)),
                  InvalidRequestError("x", not_dispatched="request")):
            self.assertFalse(paf.may_have_run(e), e)
        # The command check is made before the call and raised as a marked refusal: nothing sent.
        sent = len(c.session.commands)
        with self.assertRaises(InvalidRequestError) as cm:
            run(tool.run("echo\x00x"))
        self.assertEqual(cm.exception.not_dispatched, "request")
        self.assertEqual(len(c.session.commands), sent)

    def test_any_other_exception_may_have_run_and_stops_the_run(self) -> None:
        # Only a marked refusal, setup_failed and the tool's own check say nothing ran. Any other
        # exception from the call, plimsoll's or not, may have followed the command running, as the
        # client's Session takes it: the run stops after one dispatch.
        for e in (KeyError("boom"), RuntimeError("a bug"), WorkspaceCallError("x", result(outcome="runner_failed", steps=False))):
            self.assertTrue(paf.may_have_run(e), e)
        c, tool = self.tool()
        c.session.replies["make install"] = KeyError("boom")
        client = Scripted(("run_shell", {"command": "make install"}), ("run_shell", {"command": "make install"}))
        with self.assertRaises(MiddlewareFailure) as cm:
            run(converse_with(client, tool))
        self.assertIsInstance(cm.exception.__cause__, KeyError)
        self.assertEqual(shell_calls(c.session), ["make install"], "handed over once")
        self.assertEqual(len(client.requests), 1, "the model was not asked again")
        self.assertEqual(call_labels(cm.exception), {"plimsoll_dispatched": "unknown"})

    def test_the_code_tool_carries_the_labels_too(self) -> None:
        refused = plimsoll_code_tool(Refusing(AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")))
        (item,) = run(refused.invoke(arguments={"code": "print(1)"}))
        self.assertIn('"refused": "capacity"', item.text, "the model's JSON text is the framework's own")
        self.assertEqual(item.additional_properties, {"plimsoll_dispatched": "no", "plimsoll_refused": "capacity"})
        with traced() as tracer:
            run(refused.invoke(arguments={"code": "print(1)"}))
        (span,) = tracer.tool_spans("plimsoll_run_code")
        self.assertEqual(plimsoll_attributes(span), {"plimsoll.dispatched": "no", "plimsoll.refused": "capacity"})


class Refusing(CodeExecutor):
    """An executor whose every call ends in the given error."""

    def __init__(self, error: BaseException) -> None:
        super().__init__(Client("http://127.0.0.1:9"), minimum_isolation="kernel")
        self.error = error
        self.calls = 0

    def execute_code(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        raise self.error


class CodeToolTests(unittest.TestCase):
    def test_a_refusal_is_a_dict_and_never_raises(self) -> None:
        refused = Refusing(AtCapacityError("plimsoll: at capacity", not_dispatched="capacity"))
        r = run(plimsoll_code_tool(refused).invoke(arguments={"code": "print(1)"}, skip_parsing=True))
        self.assertEqual(r, {"ran": False, "refused": "capacity", "error": "plimsoll: at capacity"})
        lost = Refusing(PlimsollError("plimsoll: the answer was lost"))
        r = run(plimsoll_code_tool(lost).invoke(arguments={"code": "print(1)"}, skip_parsing=True))
        self.assertEqual(r["ran"], "unknown")
        self.assertEqual(lost.calls, 1, "not retried")

    def test_a_dead_daemon_is_refused_through_the_agent_as_a_result(self) -> None:
        # A daemon nothing listens on: refused before anything ran, as the model sees it.
        tool = plimsoll_code_tool(CodeExecutor(Client("http://127.0.0.1:9"), minimum_isolation="container"))
        client = Scripted(("plimsoll_run_code", {"code": "print(1)"}))
        agent = create_harness_agent(client, tools=[tool], disable_file_memory=True, disable_web_search=True)
        run(agent.run("go", session=agent.create_session()))
        (r,) = client.results()
        self.assertIsNone(r.exception)
        self.assertIn('"ran": false', str(r.result))
        self.assertIn('"refused": "environment"', str(r.result))

    def test_schema_offers_the_languages_given(self) -> None:
        executor = Refusing(RuntimeError("unused"))
        tool = plimsoll_code_tool(executor)
        self.assertEqual(tool.name, "plimsoll_run_code")
        params = tool.parameters()
        self.assertEqual(params["required"], ["code"])
        language = params["properties"]["language"]
        self.assertEqual(language.get("const", language.get("enum")), "python")
        self.assertNotIn("JavaScript", tool.description)
        both = plimsoll_code_tool(executor, languages=("python", "javascript"), name="run_code").parameters()
        self.assertEqual(both["properties"]["language"]["enum"], ["python", "javascript"])
        with self.assertRaises(TypeError):
            plimsoll_code_tool(object())  # type: ignore[arg-type]
        for bad in ((), ("ruby",)):
            with self.assertRaises(ValueError):
                plimsoll_code_tool(executor, languages=bad)

    def test_a_language_outside_the_schema_is_refused_before_the_call(self) -> None:
        executor = Refusing(RuntimeError("unused"))
        with self.assertRaises(Exception):
            run(plimsoll_code_tool(executor).invoke(arguments={"code": "1", "language": "javascript"}))
        self.assertEqual(executor.calls, 0)

    def test_a_granted_tool_tells_the_model_the_api_and_carries_the_applications_profile(self) -> None:
        import json

        from .._shared import API_DESCRIPTION, ECHO_ROUTES, granted

        tool = plimsoll_code_tool(granted(), languages=("javascript", "python"))
        self.assertIn(API_DESCRIPTION.strip(), tool.description)
        self.assertIn("plimsoll_host", tool.description)
        self.assertEqual(set(tool.parameters()["properties"]), {"code", "language", "input_files"})
        r = run(tool.invoke(arguments={"code": "console.log(1)", "language": "javascript"}, skip_parsing=True))
        self.assertEqual(json.loads(r["stdout"])["grant"]["allow"], ECHO_ROUTES)
        # On a daemon whose Python steps cannot reach the broker, the default (Python) is
        # the application's mistake, and JavaScript is what is offered.
        with self.assertRaises(ValueError):
            plimsoll_code_tool(granted(guard=True))
        js = plimsoll_code_tool(granted(guard=True), languages=("python", "javascript"))
        self.assertEqual(js.parameters()["properties"]["language"].get("const", js.parameters()["properties"]["language"].get("enum")),
                         "javascript")
        self.assertIn("Python code cannot call the API on this sandbox", js.description)



class AgentFrameworkPlimsollPackageTests(unittest.TestCase):
    """agent-framework-plimsoll (clients/python/agent-framework-plimsoll) re-exports plimsoll-client's own names, at
    its version, and pins the Agent Framework versions this suite runs against."""

    def test_names_are_plimsoll_clients_own(self) -> None:
        import agent_framework_plimsoll

        self.assertIs(agent_framework_plimsoll.PlimsollShellTool, PlimsollShellTool)
        self.assertIs(agent_framework_plimsoll.plimsoll_code_tool, plimsoll_code_tool)
        self.assertIs(agent_framework_plimsoll.CodeExecutor, CodeExecutor)
        self.assertIs(agent_framework_plimsoll.Client, Client)
        self.assertIs(agent_framework_plimsoll.PlimsollShellResult, PlimsollShellResult)
        self.assertIs(agent_framework_plimsoll.call_labels, call_labels)
        self.assertEqual(sorted(agent_framework_plimsoll.__all__),
                         ["Client", "CodeExecutor", "PlimsollShellResult", "PlimsollShellTool", "call_labels", "plimsoll_code_tool"])

    def test_version_is_plimsoll_clients(self) -> None:
        import agent_framework_plimsoll
        import plimsoll_client

        self.assertEqual(agent_framework_plimsoll.__version__, plimsoll_client.__version__)

    def _text(self, *parts: str) -> str:
        import pathlib

        return pathlib.Path(__file__).resolve().parents[2].joinpath(*parts).read_text()

    def test_the_readme_states_the_approval_default_and_how_to_turn_it_on(self) -> None:
        # Review finding release-30: Microsoft's own shell tools ask a person by default and this
        # one does not, so the PyPI page says so; the default it names is the tool's real one.
        import inspect

        default = inspect.signature(PlimsollShellTool.__init__).parameters["approval_mode"].default
        readme = self._text("agent-framework-plimsoll", "README.md")
        self.assertIn(f"`approval_mode` is `{default}`", readme)
        self.assertIn('approval_mode="always_require"', readme)
        self.assertIn("LocalShellTool", readme)

    def test_the_readme_and_the_example_agree_on_whether_the_package_is_released(self) -> None:
        # Review finding release-34: the PyPI page's install line carries the until-the-next-release
        # note the example's header carries, and the release takes both away together.
        note = "ships with plimsoll's next release"
        self.assertEqual(note in self._text("agent-framework-plimsoll", "README.md"),
                         note in self._text("examples", "agent_framework_shell.py"))

    def test_the_pins_are_the_versions_this_suite_runs_against(self) -> None:
        # Both packages are pinned exactly, at the versions this suite runs against
        # (TestAdaptersPinTheVersionTheirLockInstalls, in Go, holds every adapter's pins to
        # its lock file; this holds them to what is installed here).
        import importlib.metadata
        import pathlib
        import tomllib

        pyproject = pathlib.Path(__file__).resolve().parents[2] / "agent-framework-plimsoll" / "pyproject.toml"
        dependencies = tomllib.loads(pyproject.read_text())["project"]["dependencies"]
        self.assertIn("agent-framework-tools==" + importlib.metadata.version("agent-framework-tools"), dependencies)
        self.assertIn("agent-framework-core==" + importlib.metadata.version("agent-framework-core"), dependencies)


class FrameworkShapeTests(unittest.TestCase):
    """Each member the adapter defines over the framework's own (inherited, or declared by a protocol it is used
    as) against the framework at the version this suite installs: kind, coroutine, the calls it takes
    (tests/_framework_shapes.py)."""

    def test_the_adapter_takes_the_calls_the_framework_makes(self) -> None:
        import plimsoll_client.agent_framework
        from tests._framework_shapes import problems

        from agent_framework_tools.shell._executor_base import ShellExecutor

        self.assertEqual(problems(plimsoll_client.agent_framework, [(plimsoll_client.agent_framework.PlimsollShellTool, ShellExecutor)]), [])


if __name__ == "__main__":
    unittest.main()
