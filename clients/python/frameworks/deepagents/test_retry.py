"""plimsoll_client.retry_on on LangGraph's and LangChain's own retry paths: a graph node's
RetryPolicy and an agent's ToolRetryMiddleware, each around a fake plimsoll call that
counts how often the code ran; then a Deep Agents agent's execute tool over the backend;
then a node calling the echo daemon. Each path is also run with the framework's own
default predicate, which reruns an error after which the code may have run: if a release
changes that, these controls fail and the docs' warning is reviewed.

LangGraph and LangChain come with Deep Agents in this environment (requirements.in names
the versions)."""

from __future__ import annotations

import asyncio
import unittest
from typing import Any, List, TypedDict

from langchain.agents import create_agent
from langchain.agents.middleware import ToolRetryMiddleware
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from langgraph.types import RetryPolicy

from deepagents import create_deep_agent
from plimsoll_client import AtCapacityError, InvalidRequestError, PlimsollError, TransportError, retry_on

from .._shared import echo, echo_runs
from .test_deepagents import Backend, Scripted, call, outcome

RAN = "ran"


def capacity() -> AtCapacityError:
    return AtCapacityError("plimsoll: resource_exhausted: at capacity", not_dispatched="capacity")


def lost() -> TransportError:
    # Unmarked: the request was sent and the answer never came, so the code may have run.
    return TransportError("plimsoll: Run: connection reset after the request was sent")


def request() -> InvalidRequestError:
    return InvalidRequestError("plimsoll: invalid request: at most 63 input files", not_dispatched="request")


class Calls:
    """One plimsoll call, faked. Each attempt takes the next step: ``RAN`` (the code
    runs and answers), an exception (a refusal: raised before the code runs), or
    ``(RAN, exception)`` (the code runs, then the answer is lost). With no steps left it
    runs. ``attempts`` counts calls, ``runs`` how often the code ran."""

    def __init__(self, *steps: Any) -> None:
        self.steps: List[Any] = list(steps)
        self.attempts = 0
        self.runs = 0

    def __call__(self) -> str:
        self.attempts += 1
        step = self.steps.pop(0) if self.steps else RAN
        if isinstance(step, tuple):
            self.runs += 1
            raise step[1]
        if isinstance(step, BaseException):
            raise step
        self.runs += 1
        return RAN


class State(TypedDict, total=False):
    out: str


def node_graph(fn: Any, predicate: Any = retry_on) -> Any:
    """A one-node graph whose node calls ``fn``, with a RetryPolicy of ``predicate``
    (three attempts, LangGraph's default, and no wait between them)."""
    b = StateGraph(State)
    b.add_node("run", lambda s: {"out": fn()}, retry_policy=RetryPolicy(retry_on=predicate, initial_interval=0.0, jitter=False))
    b.add_edge(START, "run")
    b.add_edge("run", END)
    return b.compile()


class RetryPolicyPath(unittest.TestCase):
    """LangGraph: RetryPolicy(retry_on=retry_on) on the node that calls plimsoll."""

    def test_a_capacity_refusal_is_retried_and_the_code_runs_once(self) -> None:
        calls = Calls(capacity(), capacity())
        self.assertEqual(node_graph(calls).invoke({}), {"out": RAN})
        self.assertEqual((calls.attempts, calls.runs), (3, 1))

    def test_an_unmarked_error_is_not_retried(self) -> None:
        calls = Calls((RAN, lost()))
        with self.assertRaises(TransportError):
            node_graph(calls).invoke({})
        self.assertEqual((calls.attempts, calls.runs), (1, 1))

    def test_a_request_refusal_is_not_retried(self) -> None:
        calls = Calls(request())
        with self.assertRaises(InvalidRequestError):
            node_graph(calls).invoke({})
        self.assertEqual((calls.attempts, calls.runs), (1, 0))

    def test_the_async_path_retries_the_same(self) -> None:
        calls = Calls(capacity())
        self.assertEqual(asyncio.run(node_graph(calls).ainvoke({})), {"out": RAN})
        self.assertEqual((calls.attempts, calls.runs), (2, 1))
        calls = Calls((RAN, lost()))
        with self.assertRaises(TransportError):
            asyncio.run(node_graph(calls).ainvoke({}))
        self.assertEqual((calls.attempts, calls.runs), (1, 1))

    def test_control_langgraphs_default_reruns_code_that_may_have_run(self) -> None:
        from langgraph._internal._retry import default_retry_on

        self.assertIs(RetryPolicy().retry_on, default_retry_on)
        calls = Calls((RAN, lost()), (RAN, lost()), (RAN, lost()))
        with self.assertRaises(TransportError):
            node_graph(calls, default_retry_on).invoke({})
        self.assertEqual((calls.attempts, calls.runs), (3, 3))


def tool_agent(calls: Calls, predicate: Any = retry_on, on_failure: str = "continue") -> Any:
    """create_agent with one tool that makes the plimsoll call, a scripted model that
    calls it once, and ToolRetryMiddleware (two retries, no wait)."""

    @tool
    def run_code(code: str) -> str:
        """Runs code."""
        return calls()

    model = Scripted(messages=iter([call("run_code", {"code": "print(1)"}), AIMessage(content="done")]))
    retry = ToolRetryMiddleware(retry_on=predicate, max_retries=2, initial_delay=0.0, jitter=False, on_failure=on_failure)  # type: ignore[arg-type]
    return create_agent(model, tools=[run_code], middleware=[retry])


def tool_message(out: Any, name: str) -> ToolMessage:
    return next(m for m in out["messages"] if isinstance(m, ToolMessage) and m.name == name)


GO = {"messages": [{"role": "user", "content": "go"}]}


class ToolRetryMiddlewarePath(unittest.TestCase):
    """LangChain: ToolRetryMiddleware(retry_on=retry_on) around the tool that calls plimsoll."""

    def test_a_capacity_refusal_is_retried_and_the_code_runs_once(self) -> None:
        calls = Calls(capacity(), capacity())
        msg = tool_message(tool_agent(calls).invoke(GO), "run_code")
        self.assertEqual((msg.content, msg.status), (RAN, "success"))
        self.assertEqual((calls.attempts, calls.runs), (3, 1))

    def test_an_unmarked_error_is_not_retried(self) -> None:
        calls = Calls((RAN, lost()))
        with self.assertRaises(TransportError):
            tool_agent(calls).invoke(GO)
        self.assertEqual((calls.attempts, calls.runs), (1, 1))

    def test_a_request_refusal_is_not_retried(self) -> None:
        calls = Calls(request())
        with self.assertRaises(InvalidRequestError):
            tool_agent(calls).invoke(GO)
        self.assertEqual((calls.attempts, calls.runs), (1, 0))

    def test_the_async_path_retries_the_same(self) -> None:
        calls = Calls(capacity())
        msg = tool_message(asyncio.run(tool_agent(calls).ainvoke(GO)), "run_code")
        self.assertEqual(msg.content, RAN)
        self.assertEqual((calls.attempts, calls.runs), (2, 1))
        calls = Calls((RAN, lost()))
        with self.assertRaises(TransportError):
            asyncio.run(tool_agent(calls).ainvoke(GO))
        self.assertEqual((calls.attempts, calls.runs), (1, 1))

    def test_control_the_middlewares_default_reruns_code_that_may_have_run(self) -> None:
        from langchain.agents.middleware._retry import default_retry_on

        self.assertIs(ToolRetryMiddleware().retry_on, default_retry_on)
        calls = Calls((RAN, lost()), (RAN, lost()), (RAN, lost()))
        msg = tool_message(tool_agent(calls, default_retry_on).invoke(GO), "run_code")
        self.assertEqual(msg.status, "error")
        self.assertEqual((calls.attempts, calls.runs), (3, 3))


class DeepAgentsExecute(unittest.TestCase):
    """A Deep Agents agent whose execute tool, over PlimsollSandbox, has ToolRetryMiddleware:
    the backend raises on a refusal, so this is where a retry policy meets a session."""

    def agent(self, b: Backend, predicate: Any = retry_on) -> Any:
        model = Scripted(messages=iter([call("execute", {"command": "echo hello"}), AIMessage(content="done")]))
        retry = ToolRetryMiddleware(retry_on=predicate, tools=["execute"], max_retries=2, initial_delay=0.0, jitter=False)
        return create_deep_agent(model=model, backend=b.backend, middleware=[retry])

    def test_a_capacity_refusal_is_sent_again_and_answers(self) -> None:
        b = Backend()
        b.ws.answers += [capacity(), outcome(stdout=b"hello\n")]
        msg = tool_message(self.agent(b).invoke(GO), "execute")
        self.assertIn("hello", msg.content)
        self.assertEqual(b.ws.commands, ["echo hello", "echo hello"])

    def test_an_unmarked_error_is_sent_once(self) -> None:
        b = Backend()
        b.ws.answers += [lost()]
        with self.assertRaises(TransportError):
            self.agent(b).invoke(GO)
        self.assertEqual(b.ws.commands, ["echo hello"])

    def test_a_session_that_ended_is_not_retried(self) -> None:
        from plimsoll_client import SessionEndedError

        b = Backend()
        b.ws.answers += [SessionEndedError("plimsoll: the session has ended", reason="expired", not_dispatched="request")]
        with self.assertRaises(SessionEndedError):
            self.agent(b).invoke(GO)
        self.assertEqual(b.ws.commands, ["echo hello"])


class EchoDaemon(unittest.TestCase):
    """A node that calls the echo daemon through CodeExecutor: the daemon's unmarked error
    (ECHO:LOST, the code may have run) comes back over the wire and is not run again."""

    def run_lost(self, predicate: Any) -> int:
        executor = echo()
        before = echo_runs()
        with self.assertRaises(PlimsollError) as cm:
            node_graph(lambda: executor.execute_code("ECHO:LOST"), predicate).invoke({})
        self.assertIsNone(cm.exception.not_dispatched)
        return echo_runs() - before

    def test_the_daemons_unmarked_error_is_run_once(self) -> None:
        self.assertEqual(self.run_lost(retry_on), 1)

    def test_control_langgraphs_default_runs_it_three_times(self) -> None:
        from langgraph._internal._retry import default_retry_on

        self.assertEqual(self.run_lost(default_retry_on), 3)


if __name__ == "__main__":
    unittest.main()
