"""PlimsollExecutor and code_agent through smolagents' own paths: CodeAgent's run loop driven by
a scripted model, its send_tools and send_variables, and the executor's own calls. Each cell
runs in a session faked in memory that runs it as the session's Python interpreter does
(sandbox/internal/sessionkit/interp/kernel.py: one global namespace, a final expression's value
printed with repr), so the helper the executor defines in the interpreter is exercised. That
interpreter cannot import Pillow (plimsoll/sandbox-python has none), NumPy or pickle (which the
executor's own definitions must not need). No model and no network are used. What a real
session does is the docker check's."""

from __future__ import annotations

import ast
import base64
import builtins
import contextlib
import dataclasses
import datetime
import decimal
import hashlib
import inspect
import io
import json
import pathlib
import pickle
import sys
import traceback
import unittest
from typing import Any, Dict, List, Optional
from unittest import mock

import smolagents
from rich.console import Console
from smolagents import CodeAgent, tool
from smolagents.default_tools import FinalAnswerTool
from smolagents.local_python_executor import CodeOutput
from smolagents.memory import FinalAnswerStep
from smolagents.models import ChatMessage, MessageRole, Model
from smolagents.monitoring import AgentLogger, LogLevel
from smolagents.remote_executors import RemotePythonExecutor
from smolagents.serialization import SafeSerializer, SerializationError
from smolagents.utils import AgentError

from plimsoll_client import AtCapacityError, Client, InsufficientIsolationError, PlimsollError, SessionEndedError
from plimsoll_client.smolagents import _CARRIED_MARKS, MARKER, PlimsollCellRecord, PlimsollExecutor, code_agent
from plimsoll_client.types import CellResult, RunRecord, SessionSummary

LOG = AgentLogger(level=LogLevel.OFF)


#: What the fake interpreter cannot import.
ABSENT = {"PIL", "numpy", "pickle"}


def _import(name: str, globals: Any = None, locals: Any = None, fromlist: Any = (), level: int = 0) -> Any:
    if level == 0 and name.split(".")[0] in ABSENT:
        raise ModuleNotFoundError(f"No module named {name.split('.')[0]!r}", name=name)
    return builtins.__import__(name, globals, locals, fromlist, level)


def fresh() -> Dict[str, Any]:
    return {"__name__": "__main__", "__builtins__": {**vars(builtins), "__import__": _import}}


class FakeSession:
    """What PlimsollExecutor asks of a Session, in memory. A cell runs as the session's
    interpreter runs it. ``fail`` maps a text to an exception a cell containing it raises
    instead of running; ``restart`` and ``timeout`` hold texts whose cell finds a fresh
    interpreter, or runs past its budget and ends the interpreter. After close, a cell
    raises SessionEndedError, as Session does. Each answered cell carries a run record chained
    to the one before, and ``calls`` and ``last_record_sha256`` follow the chain, as Session's
    do; a cell that raises moves nothing."""

    fingerprint = "fp-fake"

    def __init__(self, isolation: str) -> None:
        self.isolation = isolation
        self.namespace = fresh()
        self.started = False
        self.cells: List[str] = []
        self.budgets: List[Optional[float]] = []
        self.closes = 0
        self.fail: Dict[str, BaseException] = {}
        self.restart: List[str] = []
        self.timeout: List[str] = []
        self.calls = 0
        self.last_record_sha256 = ""

    def run_cell(self, code: str, language: str = "python", **kw: Any) -> CellResult:
        result = self._run_cell(code, language, **kw)
        self.calls += 1
        sha = hashlib.sha256(f"{self.last_record_sha256}|{self.calls}|{code}".encode()).hexdigest()
        record = RunRecord(version=5, request_sha256="", result_sha256="", provider="fake", isolation=self.isolation, environment="",
                           policy="", software_identity="", software_rule_id="", started_unix_ms=0, ended_unix_ms=0,
                           session=self.fingerprint, sequence=self.calls, previous_sha256=self.last_record_sha256, sha256=sha)
        self.last_record_sha256 = sha
        return dataclasses.replace(result, record=record, isolation=self.isolation)

    def _run_cell(self, code: str, language: str = "python", *, timeout: Optional[float] = None, **kw: Any) -> CellResult:
        assert language == "python" and not kw, (language, kw)
        if self.closes:
            raise SessionEndedError("plimsoll: this session was closed; nothing was sent", reason="closed", not_dispatched="request")
        self.cells.append(code)
        self.budgets.append(timeout)
        for text, error in self.fail.items():
            if text in code:
                raise error
        if any(t in code for t in self.restart):
            self.namespace, self.started = fresh(), False
        started = not self.started
        self.started = True
        if any(t in code for t in self.timeout):
            # The deadline ends the cell and the interpreter: no record, and the next cell
            # starts a fresh interpreter.
            self.namespace, self.started = fresh(), False
            return cell(b"partial", b"", 124, started=started, timed_out=True, ended=True)
        out, err = io.StringIO(), io.StringIO()
        exit_code = 0
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                tree = ast.parse(code, "<cell>", "exec")
                last = None
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    last = ast.Expression(tree.body.pop().value)
                exec(compile(tree, "<cell>", "exec"), self.namespace)
                if last is not None:
                    value = eval(compile(last, "<cell>", "eval"), self.namespace)
                    if value is not None:
                        self.namespace["_"] = value
                        print(repr(value))
            except BaseException as e:  # noqa: BLE001 - the kernel's own rule
                exit_code = 1
                traceback.print_exception(type(e), e, e.__traceback__, file=sys.stderr)
        return cell(out.getvalue().encode(), err.getvalue().encode(), exit_code, started=started)

    def close(self) -> SessionSummary:
        self.closes += 1
        return SessionSummary(session=self.fingerprint, calls=self.calls, last_record_sha256=self.last_record_sha256, end="closed")


def cell(stdout: bytes, stderr: bytes, exit_code: int, *, started: bool, timed_out: bool = False, ended: bool = False) -> CellResult:
    return CellResult(provider="fake", isolation="kernel", environment="", software_identity="", duration_ms=1, record=None,
                      stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=timed_out, stdout_truncated=False,
                      stderr_truncated=False, interpreter_started=started, interpreter_ended=ended)


class FakeClient(Client):
    """A Client whose open_session answers a FakeSession at the given tier, with no daemon."""

    def __init__(self, isolation: str = "kernel") -> None:
        super().__init__("http://127.0.0.1:9")
        self.isolation = isolation
        self.opened: List[Dict[str, Any]] = []
        self.sessions: List[FakeSession] = []

    def open_session(self, **kw: Any) -> Any:  # type: ignore[override]
        self.opened.append(kw)
        s = FakeSession(self.isolation)
        self.sessions.append(s)
        return s

    @property
    def session(self) -> FakeSession:
        assert len(self.sessions) == 1, f"{len(self.sessions)} sessions opened"
        return self.sessions[0]


class Scripted(Model):
    """A model that answers each step with the next of its code blocks, and anything after
    them (the final answer smolagents asks for at max_steps included) with "made up"."""

    def __init__(self, *codes: str) -> None:
        super().__init__(model_id="scripted")
        self.codes = list(codes)
        self.calls = 0

    def generate(self, messages: Any, stop_sequences: Any = None, response_format: Any = None, tools_to_call_from: Any = None, **kw: Any) -> ChatMessage:
        self.calls += 1
        if self.codes:
            return ChatMessage(role=MessageRole.ASSISTANT, content=f"Thought: go\n<code>\n{self.codes.pop(0)}\n</code>")
        return ChatMessage(role=MessageRole.ASSISTANT, content="made up")


def executor(client: Optional[FakeClient] = None, **kw: Any) -> PlimsollExecutor:
    return PlimsollExecutor([], LOG, client=client or FakeClient(), minimum_isolation="kernel", **kw)


def steps(session: FakeSession) -> List[str]:
    """The cells sent after the setup cell."""
    return session.cells[1:]


def record_line(nonce: str, record: Dict[str, Any]) -> str:
    return MARKER + nonce + ">>" + base64.b64encode(json.dumps(record).encode()).decode()


@tool
def add(a: int, b: int) -> int:
    """Adds two numbers.

    Args:
        a: The first number.
        b: The second number.
    """
    return a + b


class ExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FakeClient()
        self.ex = executor(self.client)
        self.session = self.client.session

    def test_opens_a_python_session_and_defines_the_helper(self) -> None:
        self.assertEqual(self.client.opened, [{"minimum_isolation": "kernel", "lifetime": 3600.0, "languages": ["python"], "owner": None}])
        self.assertEqual(len(self.session.cells), 1)
        self.assertIn("__plimsoll_step", self.session.namespace)
        self.assertIs(self.ex.session, self.session)
        self.assertIsNone(self.ex.fatal_error)

    def test_each_step_is_one_cell_with_a_fresh_nonce(self) -> None:
        self.ex("1")
        self.ex("1")
        self.assertEqual(len(steps(self.session)), 2)
        nonces = [ast.literal_eval(ast.parse(c, mode="eval").body.args[1]) for c in steps(self.session)]  # type: ignore[attr-defined]
        self.assertEqual([len(n) for n in nonces], [32, 32])
        self.assertNotEqual(nonces[0], nonces[1])
        self.assertEqual(self.session.budgets, [120.0, 120.0, 120.0])

    def test_variables_persist_across_steps(self) -> None:
        self.ex("x = 41\ndef inc(n):\n    return n + 1")
        self.assertEqual(self.ex("inc(x)").output, 42)

    def test_the_last_expression_comes_back(self) -> None:
        out = self.ex("print('hi')\n[1, {'a': 2}]")
        self.assertEqual((out.output, out.logs, out.is_final_answer), ([1, {"a": 2}], "hi\n", False))
        self.assertIsNone(self.ex("y = 3").output)
        self.assertIsNone(self.ex("None").output)
        # A value JSON cannot carry comes back as its repr.
        self.assertTrue(self.ex("object()").output.startswith("<object object at "))

    def test_logs_are_exactly_what_the_step_printed(self) -> None:
        self.assertEqual(self.ex("print('abc', end='')").logs, "abc")
        self.assertEqual(self.ex("pass").logs, "")

    def test_rebinding_the_helpers_names_breaks_nothing(self) -> None:
        self.ex("json = None\nbase64 = None\nsys = 3\nast = 4\ntraceback = 5")
        self.assertEqual(self.ex("1 + 1").output, 2)

    def test_a_raised_error_is_an_agent_error_with_the_traceback(self) -> None:
        self.ex("def boom():\n    return 1 / 0")
        with self.assertRaises(AgentError) as cm:
            self.ex("print('before')\nboom()")
        message = str(cm.exception)
        self.assertTrue(message.startswith("before\n\nExecuting code yielded an error:\nZeroDivisionError\ndivision by zero\n"), message)
        self.assertIn("Traceback (most recent call last)", message)
        self.assertIn('File "<step 2>", line 2', message)  # the step, not the helper
        self.assertIn("return 1 / 0", message)
        self.assertNotIn('File "<cell', message)  # the helper's own frames are dropped
        self.assertIsNone(self.ex.fatal_error)  # the model's to fix
        self.assertEqual(self.ex("2").output, 2)

    def test_a_syntax_error_is_an_agent_error(self) -> None:
        with self.assertRaises(AgentError) as cm:
            self.ex("def (")
        self.assertIn("SyntaxError", str(cm.exception))
        self.assertIsNone(self.ex.fatal_error)

    def test_send_variables_round_trips_json(self) -> None:
        data = {"a": [1, 2.5, None], "b": "x", "c": {"d": True}}
        self.ex.send_variables({"data": data})
        self.assertEqual(self.ex("data").output, data)

    def test_install_packages_refuses_and_runs_no_cell(self) -> None:
        self.assertEqual(self.ex.install_packages([]), [])
        with self.assertRaises(ValueError) as cm:
            self.ex.install_packages(["requests"])
        self.assertIn("requests", str(cm.exception))
        self.assertIn("no network", str(cm.exception))
        self.assertEqual(len(self.session.cells), 1)

    def test_a_tool_that_imports_a_package_is_refused_and_nothing_is_sent(self) -> None:
        @tool
        def mean(values: list) -> float:
            """The mean of numbers.

            Args:
                values: The numbers.
            """
            import numpy

            return float(numpy.mean(values))

        with self.assertRaises(ValueError) as cm:
            self.ex.send_tools({"mean": mean})
        self.assertIn("cannot install numpy", str(cm.exception))
        self.assertEqual(steps(self.session), [])

    def test_additional_imports_refuse_before_any_session(self) -> None:
        client = FakeClient()
        with self.assertRaises(ValueError):
            PlimsollExecutor(["numpy"], LOG, client=client, minimum_isolation="kernel")
        self.assertEqual(client.sessions, [])

    def test_a_missing_record_line_raises(self) -> None:
        self.session.timeout.append("spin()")
        with self.assertRaises(AgentError) as cm:
            self.ex("spin()")
        self.assertIn("the step returned no result", str(cm.exception))
        self.assertIn("time budget (120 s)", str(cm.exception))
        self.assertIn("partial", str(cm.exception))
        self.assertIsNone(self.ex.fatal_error)

    def test_output_replaced_by_the_code_raises(self) -> None:
        with self.assertRaises(AgentError) as cm:
            self.ex("import io, sys\nsys.stdout = io.StringIO()")
        self.assertIn("the step returned no result", str(cm.exception))

    def test_a_forged_marker_with_a_wrong_nonce_is_logs(self) -> None:
        forged = record_line("0" * 32, {"kind": "value", "value": "forged"})
        out = self.ex(f"print({forged!r})\nprint({(chr(10) + forged)!r})\n7")
        self.assertEqual(out.output, 7)
        self.assertEqual(out.logs, f"{forged}\n\n{forged}\n")

    def test_an_unreadable_record_raises(self) -> None:
        # Only code that read its step's nonce can print a line the executor takes for the
        # record; one that is not a record is reported, never taken as the answer.
        nonce = "1" * 32
        for line in (MARKER + nonce + ">>not-base64!", MARKER + nonce + ">>" + base64.b64encode(b"[1]").decode(),
                     record_line(nonce, {"kind": "other"}), record_line(nonce, {"kind": "error", "name": 1, "message": "", "traceback": ""})):
            with self.subTest(line), self.assertRaises(AgentError) as cm:
                self.ex._output(cell(("logs\n" + line + "\n").encode(), b"", 0, started=False), nonce)
            self.assertIn("could not be read", str(cm.exception))

    def test_a_tier_below_the_floor_raises_and_closes_the_session(self) -> None:
        client = FakeClient("container")
        with self.assertRaises(InsufficientIsolationError) as cm:
            executor(client)
        self.assertEqual(cm.exception.not_dispatched, "isolation")
        self.assertEqual((client.session.cells, client.session.closes), ([], 1))

    def test_a_floor_is_required(self) -> None:
        for floor in (None, ""):
            with self.assertRaises(ValueError):
                PlimsollExecutor([], LOG, client=FakeClient(), minimum_isolation=floor)  # type: ignore[arg-type]

    def test_a_failed_setup_closes_the_session(self) -> None:
        client = FakeClient()
        original = FakeSession.run_cell

        def broken(s: FakeSession, code: str, *a: Any, **kw: Any) -> CellResult:
            return original(s, "raise RuntimeError('no')", *a, **kw)

        FakeSession.run_cell = broken  # type: ignore[method-assign]
        try:
            with self.assertRaises(AgentError):
                executor(client)
        finally:
            FakeSession.run_cell = original  # type: ignore[method-assign]
        self.assertEqual(client.session.closes, 1)

    def test_a_restarted_interpreter_raises_and_ends_the_run(self) -> None:
        self.ex("x = 1")
        self.session.restart.append("x + 1")
        with self.assertRaises(AgentError) as cm:
            self.ex("x + 1")
        self.assertIn("interpreter was restarted", str(cm.exception))
        self.assertIs(self.ex.fatal_error, cm.exception)
        self.assertRefusesWithoutSending(cm.exception)

    def test_a_not_dispatched_refusal_is_raised_unchanged(self) -> None:
        refusal = AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        self.session.fail["STEP"] = refusal
        with self.assertRaises(AtCapacityError) as cm:
            self.ex("STEP = 1")
        self.assertIs(cm.exception, refusal)
        self.assertNotIsInstance(cm.exception, AgentError)
        self.assertIs(self.ex.fatal_error, refusal)
        self.assertRefusesWithoutSending(refusal)

    def test_a_may_have_run_error_is_raised_unchanged(self) -> None:
        lost = PlimsollError("plimsoll: the answer was lost")
        self.session.fail["STEP"] = lost
        with self.assertRaises(PlimsollError) as cm:
            self.ex("STEP = 1")
        self.assertIs(cm.exception, lost)
        self.assertIs(self.ex.fatal_error, lost)
        self.assertRefusesWithoutSending(lost)

    def test_any_other_error_of_the_call_ends_the_run(self) -> None:
        # An exception that is not plimsoll's (one the transport did not wrap, a bug, an
        # interrupt) may have followed the cell running, so it ends the run like a lost
        # answer, rather than reaching the model as a code error it would answer with
        # another cell.
        for error in (KeyError("lost"), OSError("connection reset"), KeyboardInterrupt()):
            with self.subTest(type(error).__name__):
                client = FakeClient()
                ex = executor(client)
                self.session = client.session
                self.ex = ex
                self.session.fail["STEP"] = error
                with self.assertRaises(type(error)) as cm:
                    ex("STEP = 1")
                self.assertIs(cm.exception, error)
                self.assertIs(ex.fatal_error, error)
                self.assertRefusesWithoutSending(error)

    def test_the_first_fatal_error_is_kept(self) -> None:
        first = AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        self.session.fail["STEP"] = first
        with self.assertRaises(AtCapacityError):
            self.ex("STEP")
        with self.assertRaises(PlimsollError):
            self.ex("STEP")
        self.assertIs(self.ex.fatal_error, first)

    def assertRefusesWithoutSending(self, fatal: BaseException) -> None:
        sent = len(self.session.cells)
        for call in (lambda: self.ex("1"), lambda: self.ex.send_variables({"a": 1}), lambda: self.ex.send_tools({"add": add})):
            with self.assertRaises(PlimsollError) as cm:
                call()
            self.assertEqual(cm.exception.not_dispatched, "request")
            self.assertIs(cm.exception.__cause__, fatal)
        self.assertEqual(len(self.session.cells), sent)

    def test_cleanup_twice_is_safe(self) -> None:
        self.ex.cleanup()
        self.ex.cleanup()
        self.assertEqual(self.session.closes, 1)
        with self.assertRaises(SessionEndedError):
            self.ex("1")
        self.assertIsInstance(self.ex.fatal_error, SessionEndedError)


#: The parts of smolagents 1.26.0 the final-answer protocol lives in, by SHA-256 of their
#: source. The executor copies that protocol (plimsoll_client/smolagents.py,
#: _final_answer_forward and PlimsollExecutor._final_answer), so a smolagents that changes
#: any of them fails here instead of breaking quietly.
PINNED = {
    "RemotePythonExecutor.send_tools": "2c5597f32af836ac6760a0d776605f544c86954193e6959b1c091532f5826384",
    "RemotePythonExecutor._patch_final_answer_with_exception": "46a78307e6a9fae167bdd1ee92b93d2d08a434e62c5e953ed582ee5a4ee3f587",
    "RemotePythonExecutor._deserialize_final_answer": "e8b46f4fdb7cf6bd5f5c18c4ec9b58d88793586bb6f9ff9d949d6d9a858006b6",
    "SafeSerializer.from_json_safe": "4695cfc3207b181bed8d354a1122f15c2dc1ac53f3a68e7fade96ec2534fbeae",
    "FinalAnswerTool": "488bda181b92e3af641b59afa9278d261a6de183d7081cc29feaa58cdf2d54e4",
}


class Recorder(RemotePythonExecutor):
    """smolagents' own remote executor with nothing behind it: what it would send and install."""

    def __init__(self) -> None:
        super().__init__([], LOG)
        self.sent: List[str] = []
        self.installs: List[List[str]] = []

    def install_packages(self, additional_imports: List[str]) -> List[str]:
        self.installs.append(sorted(additional_imports))
        return list(additional_imports)

    def run_code_raise_errors(self, code: str) -> CodeOutput:
        self.sent.append(code)
        return CodeOutput(output=None, logs="", is_final_answer=False)


def own_definition() -> str:
    r = Recorder()
    r.send_tools({"final_answer": FinalAnswerTool()})
    assert r.installs == [["numpy", "pillow"]], r.installs
    (code,) = r.sent
    return code


def sent_definition() -> str:
    client = FakeClient()
    ex = executor(client)
    ex.send_tools({"final_answer": FinalAnswerTool()})
    (call,) = steps(client.session)
    return ast.literal_eval(ast.parse(call, mode="eval").body.args[0])  # type: ignore[attr-defined]


def split(code: str) -> Any:
    """A tool definition's top-level imported modules, its other statements but the tool's
    class, and the class's methods by name."""
    imports, rest, methods = set(), [], {}
    for node in ast.parse(code).body:
        if isinstance(node, ast.Import):
            imports |= {a.name for a in node.names}
        elif isinstance(node, ast.ClassDef) and node.name == "_FinalAnswerTool":
            methods = {m.name: m for m in node.body if isinstance(m, ast.FunctionDef)}
            rest.append(("class", node.name, [ast.dump(b) for b in node.bases], [m for m in methods]))
        else:
            rest.append(ast.dump(node))
    return imports, rest, methods


def marks(function: ast.FunctionDef) -> set:
    """The ``__type__`` marks a final answer's forward can write."""
    found = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "__type__" and isinstance(value, ast.Constant):
                    found.add(value.value)
    return found


def marks_in(data: Any) -> set:
    """The ``__type__`` marks in a final answer's JSON form."""
    found, stack = set(), [data]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if "__type__" in item:
                found.add(item["__type__"])
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return found


def reader_marks() -> set:
    """The ``__type__`` marks smolagents' own reader knows: each text its source compares
    obj_type with (SafeSerializer.from_json_safe)."""
    import textwrap

    found = set()
    for node in ast.walk(ast.parse(textwrap.dedent(inspect.getsource(SafeSerializer.from_json_safe)))):
        if (isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "obj_type"
                and len(node.comparators) == 1 and isinstance(node.comparators[0], ast.Constant)):
            found.add(node.comparators[0].value)
    return found


def answer_of(final_answer: Any, value: Any) -> str:
    """The text the final answer travels as: the FinalAnswerException's (or the error's)."""
    try:
        final_answer.forward(value)
    except BaseException as e:  # noqa: BLE001 - FinalAnswerException is a BaseException
        return f"{type(e).__name__}: {e}"
    raise AssertionError("final_answer returned")


@dataclasses.dataclass
class Point:
    x: int
    tags: list


class StandInArray:
    """A NumPy array as the final answer's code sees one: the fake interpreter has no NumPy."""


StandInArray.__module__ = "numpy"


class StandInImage:
    pass


StandInImage.__module__ = "PIL.PngImagePlugin"

#: Every kind of value smolagents' own final answer carries, but images and arrays.
CARRIED = [
    "text", "", 3, -2**70, 2.5, float("inf"), True, None, [1, "a", None], {"a": {"b": [1, 2]}},
    {1: "one", (2, 3): "pair"}, (1, (2, 3)), {3}, frozenset({4}), b"\x00\xff", 1 + 2j,
    datetime.datetime(2026, 11, 15, 12, 30, 5), datetime.date(2026, 11, 15), datetime.time(7, 8, 9),
    datetime.timedelta(seconds=90.5), decimal.Decimal("1.10"), pathlib.Path("/work/a.txt"), Point(1, ["x"]),
    {"when": datetime.date(2026, 1, 2), "items": (b"x", decimal.Decimal("2"))}, object(),
]


class FinalAnswerTests(unittest.TestCase):
    """The final_answer definition the executor sends, against smolagents' own (1.26.0)."""

    def test_smolagents_final_answer_protocol_is_the_pinned_one(self) -> None:
        self.assertEqual(RemotePythonExecutor.FINAL_ANSWER_EXCEPTION, "FinalAnswerException")
        objects = {"RemotePythonExecutor.send_tools": RemotePythonExecutor.send_tools,
                   "RemotePythonExecutor._patch_final_answer_with_exception": RemotePythonExecutor._patch_final_answer_with_exception,
                   "RemotePythonExecutor._deserialize_final_answer": RemotePythonExecutor._deserialize_final_answer,
                   "SafeSerializer.from_json_safe": SafeSerializer.from_json_safe,
                   "FinalAnswerTool": FinalAnswerTool}
        for name, obj in objects.items():
            with self.subTest(name):
                self.assertEqual(
                    hashlib.sha256(inspect.getsource(obj).encode()).hexdigest(), PINNED[name],
                    f"smolagents {smolagents.__version__} changed {name}, part of the final-answer protocol the executor copies "
                    "(pinned at 1.26.0): compare plimsoll_client/smolagents.py with it, then update PINNED")

    def test_the_sent_definition_imports_no_numpy_pillow_or_pickle(self) -> None:
        names = set()
        for node in ast.walk(ast.parse(sent_definition())):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
        self.assertFalse(names & ABSENT, names)
        self.assertTrue(names <= set(sys.stdlib_module_names) | {"typing"}, names - set(sys.stdlib_module_names))

    def test_the_sent_definition_is_smolagents_own_but_its_forward(self) -> None:
        own_imports, own_rest, own_methods = split(own_definition())
        imports, rest, methods = split(sent_definition())
        self.assertEqual(own_imports - imports, {"PIL", "numpy", "pickle", "io"})
        self.assertEqual(imports - own_imports, set())
        self.assertEqual(rest, own_rest)  # the preamble, the class line, the instance
        self.assertEqual(set(methods), set(own_methods))
        self.assertEqual(set(methods), {"__init__", "forward", "_forward"})
        for name in ("__init__", "_forward"):
            self.assertEqual(ast.dump(methods[name]), ast.dump(own_methods[name]), name)
        self.assertEqual(ast.dump(methods["forward"].args), ast.dump(own_methods["forward"].args))
        # Type for type, but the two it refuses.
        self.assertEqual(marks(methods["forward"]), marks(own_methods["forward"]) - {"PIL.Image", "ndarray"})
        # The reader's allow list is the writer's marks, neither more nor fewer.
        self.assertEqual(marks(methods["forward"]), set(_CARRIED_MARKS))

    def test_the_sent_definition_carries_what_smolagents_own_carries(self) -> None:
        own = FinalAnswerTool()
        Recorder()._patch_final_answer_with_exception(own)
        namespace = fresh()
        exec(compile(sent_definition(), "<definition>", "exec"), namespace)
        ex = executor()
        written = set()
        for value in CARRIED:
            with self.subTest(value=value):
                text = answer_of(namespace["final_answer"], value)
                self.assertEqual(text, answer_of(own, value))
                if text.startswith("FinalAnswerException: "):
                    message = text[len("FinalAnswerException: "):]
                    self.assertEqual(ex._final_answer(message, ""), RemotePythonExecutor._deserialize_final_answer(message))
                    written |= marks_in(json.loads(message[len("safe:"):]))
        # Every kind the writer writes went through the reader above and was accepted.
        self.assertEqual(written, set(_CARRIED_MARKS))

    def test_an_image_or_array_is_refused_in_the_sandbox(self) -> None:
        import PIL.Image  # the host has Pillow, as smolagents needs it

        namespace = fresh()
        exec(compile(sent_definition(), "<definition>", "exec"), namespace)
        own = FinalAnswerTool()
        Recorder()._patch_final_answer_with_exception(own)
        image = PIL.Image.new("RGB", (1, 1))
        self.assertTrue(answer_of(own, image).startswith('FinalAnswerException: safe:{"__type__": "PIL.Image"'))
        for value, what in ((image, "an image (PIL.Image.Image)"), (StandInImage(), "an image (PIL.PngImagePlugin.StandInImage)"),
                            (StandInArray(), "a NumPy array or number (numpy.StandInArray)"), ([1, {"a": StandInArray()}], "NumPy")):
            with self.subTest(what):
                text = answer_of(namespace["final_answer"], value)
                self.assertTrue(text.startswith("SerializationError: final_answer cannot carry "), text)
                self.assertIn(what, text)

    def test_a_step_answering_an_array_is_shown_the_error(self) -> None:
        model = Scripted("class ndarray:\n    pass\nndarray.__module__ = 'numpy'\nfinal_answer(ndarray())", "final_answer('plain')")
        agent = agent_for(model)
        self.assertEqual(agent.run("go"), "plain")
        error = str(agent.memory.steps[1].error)
        self.assertIn("SerializationError", error)
        self.assertIn("final_answer cannot carry a NumPy array or number (numpy.ndarray)", error)
        self.assertIsNone(agent.python_executor.fatal_error)

    def test_a_forged_image_or_array_mark_is_refused_on_the_host(self) -> None:
        ex = executor()
        png = base64.b64encode(b"\x89PNG\r\n\x1a\n").decode()
        for data, what in (({"__type__": "PIL.Image", "data": png}, "an image"),
                           ([1, {"k": {"__type__": "ndarray", "data": [1], "dtype": "int64"}}], "a NumPy array")):
            with self.subTest(what):
                code = f"class FinalAnswerException(BaseException):\n    pass\nraise FinalAnswerException({('safe:' + json.dumps(data))!r})"
                with self.assertRaises(AgentError) as cm:
                    ex(code)
                self.assertIn(f"plimsoll: the final answer could not be read: it is {what}", str(cm.exception))

    def test_a_kind_the_writer_does_not_write_is_refused_on_the_host(self) -> None:
        """The reader takes exactly the kinds the executor's own writer writes. Any other
        mark is refused before smolagents' reader sees the answer: a made-up one (a kind a
        later smolagents release teaches its reader), each kind smolagents' reader knows
        today beyond the writer's, and a mark that is not text (finding hunt-quality-50)."""
        ex = executor()
        reads = reader_marks()
        self.assertTrue(set(_CARRIED_MARKS) <= reads, set(_CARRIED_MARKS) - reads)
        self.assertEqual(reads - set(_CARRIED_MARKS), {"PIL.Image", "ndarray"})
        refused = [
            ({"__type__": "a_mark_a_later_release_adds", "data": "x"}, "a value of the kind 'a_mark_a_later_release_adds'"),
            ([1, {"k": [{"__type__": "torch.Tensor", "data": [1]}]}], "a value of the kind 'torch.Tensor'"),
            ({"__type__": "tuple", "data": [{"__type__": "class_by_name", "module": "os", "name": "system"}]}, "a value of the kind 'class_by_name'"),
            ({"__type__": 3}, "a value of the kind 3"),
            ({"__type__": None}, "a value of the kind None"),
            ({"__type__": ["tuple"]}, "a value of the kind ['tuple']"),
            ({"__type__": "Tuple", "data": []}, "a value of the kind 'Tuple'"),
            ({"__type__": "\x1b]0;title\x07"}, "a value of the kind '\\x1b]0;title\\x07'"),
            ({"__type__": "m" * 500}, "a value of the kind 'mmmm"),
        ] + [({"__type__": mark, "data": "x"}, what) for mark, what in (("PIL.Image", "an image"), ("ndarray", "a NumPy array"))]
        for data, what in refused:
            with self.subTest(what), mock.patch.object(PlimsollExecutor, "_deserialize_final_answer") as reader:
                with self.assertRaises(AgentError) as cm:
                    ex._final_answer("safe:" + json.dumps(data), "")
                self.assertIn(f"plimsoll: the final answer could not be read: it is {what}", str(cm.exception))
                self.assertIn("which a plimsoll executor does not carry", str(cm.exception))
                self.assertLess(len(str(cm.exception)), 400)
                reader.assert_not_called()
        # A plain dictionary without the key is no marked value, whatever else it holds.
        self.assertEqual(ex._final_answer('safe:{"type": "x", "__types__": 1}', ""), {"type": "x", "__types__": 1})

    def test_an_unreadable_final_answer_is_an_agent_error(self) -> None:
        ex = executor()
        for text in ("plain", "safe:{", 'safe:{"__type__": "Decimal", "data": "x"}', 'safe:{"__type__": "bytes"}'):
            with self.subTest(text), self.assertRaises(AgentError) as cm:
                ex._final_answer(text, "logs")
            self.assertIn("the final answer could not be read", str(cm.exception))

    def test_a_second_run_gets_its_final_answer(self) -> None:
        client = FakeClient()
        agent = agent_for(Scripted("final_answer(1)", "final_answer(2)"), client=client)
        self.assertEqual(agent.run("go"), 1)
        self.assertEqual(agent.run("again"), 2)
        # The tool is patched once: the second run sends the same definition.
        definitions = [c for c in steps(client.session) if "_FinalAnswerTool" in c]
        self.assertEqual(len(definitions), 2)
        strip = lambda c: ast.literal_eval(ast.parse(c, mode="eval").body.args[0])  # type: ignore[attr-defined]  # noqa: E731
        self.assertEqual(strip(definitions[0]), strip(definitions[1]))


UNPICKLED: List[str] = []


def _unpickled(what: str) -> str:
    UNPICKLED.append(what)
    return what


class Live:
    """Unpickling one calls _unpickled: the code a pickle runs where it is loaded."""

    def __reduce__(self) -> Any:
        return (_unpickled, ("ran",))


class PickleTests(unittest.TestCase):
    def setUp(self) -> None:
        UNPICKLED.clear()

    def test_allow_pickle_is_refused(self) -> None:
        client = FakeClient()
        with self.assertRaises(ValueError) as cm:
            PlimsollExecutor([], LOG, client=client, minimum_isolation="kernel", allow_pickle=True)
        self.assertIn("allow_pickle is refused", str(cm.exception))
        self.assertEqual(client.sessions, [])
        ex = executor(client)
        self.assertIs(ex.allow_pickle, False)
        with self.assertRaises(ValueError):
            ex.allow_pickle = True
        self.assertIs(ex.allow_pickle, False)

    def test_a_pickled_final_answer_is_never_unpickled(self) -> None:
        payload = "pickle:" + base64.b64encode(pickle.dumps(Live())).decode()
        pickle.loads(base64.b64decode(payload[len("pickle:"):]))  # the payload is live: loading it runs code
        self.assertEqual(UNPICKLED, ["ran"])
        UNPICKLED.clear()
        ex = executor()
        code = f"class FinalAnswerException(BaseException):\n    pass\nraise FinalAnswerException({payload!r})"
        with self.assertRaises(AgentError) as cm:
            ex(code)
        self.assertIn("it is a pickle, which this executor never unpickles", str(cm.exception))
        self.assertEqual(UNPICKLED, [])
        # Through the agent too: the model is shown the error, and nothing is unpickled.
        agent = agent_for(Scripted(code, "final_answer('done')"))
        self.assertEqual(agent.run("go"), "done")
        self.assertEqual(UNPICKLED, [])

    def test_variables_are_never_pickled(self) -> None:
        client = FakeClient()
        ex = executor(client)
        with self.assertRaises(SerializationError):
            ex.send_variables({"thing": Live()})
        self.assertEqual(steps(client.session), [])
        ex.send_variables({"n": 1})
        sent = ast.literal_eval(ast.parse(steps(client.session)[0], mode="eval").body.args[0])  # type: ignore[attr-defined]
        imported = {a.name for n in ast.walk(ast.parse(sent)) if isinstance(n, ast.Import) for a in n.names}
        self.assertNotIn("pickle", imported)
        self.assertEqual(ex("n").output, 1)


#: A backslash, for the escapes the executor writes (built from chr so that no reader of this
#: file takes the expected text for the control character itself).
BS = chr(92)
ESC, CSI_C1 = chr(0x1B), chr(0x9B)
#: What a step prints and answers to drive a terminal: a new window title (OSC 0, ended by
#: BEL), the clipboard (OSC 52, ended by ESC backslash), a cleared screen (CSI 2J), and the
#: one-character C1 form of CSI. The step's own source spells them as Python escapes.
DRIVE = "a\\x1b]0;PWNED\\x07b\\x1b]52;c;aGk=\\x1b\\\\c\\x1b[2Jd\\x9b2Je\\tf\\rg"
DRIVEN = f"a{BS}x1b]0;PWNED{BS}x07b{BS}x1b]52;c;aGk={BS}x1b{BS}c{BS}x1b[2Jd{BS}x9b2Je\tf\rg"
#: What must never reach a terminal from the sandbox.
RAW = (ESC + "]0;PWNED", ESC + "]52;", ESC + "[2J", CSI_C1, chr(7))


class PrintableTests(unittest.TestCase):
    """smolagents prints a step's output, its value and the final answer on the terminal as they
    are (its own sanitize_for_rich covers only error messages), so every text from the sandbox
    the executor hands smolagents arrives with each terminal control character but tab, newline
    and carriage return written as a visible escape."""

    def setUp(self) -> None:
        self.ex = executor()
        self.ex.send_tools({"final_answer": FinalAnswerTool()})

    def assertNoRaw(self, text: str) -> None:
        for raw in RAW:
            self.assertNotIn(raw, text)

    def test_a_steps_output_arrives_escaped(self) -> None:
        self.assertEqual(self.ex(f"print('{DRIVE}')").logs, DRIVEN + "\n")

    def test_a_steps_error_arrives_escaped(self) -> None:
        with self.assertRaises(AgentError) as cm:
            self.ex(f"print('{DRIVE}')\nraise ValueError('{DRIVE}')")
        self.assertNoRaw(str(cm.exception))
        self.assertTrue(str(cm.exception).startswith(DRIVEN + "\n\nExecuting code yielded an error:\nValueError\n" + DRIVEN + "\n"), str(cm.exception))

    def test_a_step_with_no_record_arrives_escaped(self) -> None:
        with self.assertRaises(AgentError) as cm:
            self.ex(f"import sys\nprint('{DRIVE}')\nsys.stderr.write('{DRIVE}')\nsys.stdout = None")
        self.assertIn("the step returned no result", str(cm.exception))
        self.assertNoRaw(str(cm.exception))
        self.assertEqual(str(cm.exception).count(DRIVEN), 2)  # what it printed, and its stderr

    def test_a_text_value_arrives_escaped_and_a_container_as_it_came(self) -> None:
        self.assertEqual(self.ex(f"'{DRIVE}'").output, DRIVEN)
        # smolagents prints a container as its repr, which escapes the text in it already.
        self.assertEqual(self.ex("{'k': ['\\x1b']}").output, {"k": [ESC]})
        self.assertEqual(self.ex("'tab\\tnewline\\ncr\\r'").output, "tab\tnewline\ncr\r")

    def test_a_final_answer_that_is_text_or_a_path_arrives_escaped(self) -> None:
        out = self.ex(f"final_answer('{DRIVE}')")
        self.assertTrue(out.is_final_answer)
        self.assertEqual(out.output, DRIVEN)
        self.assertEqual(self.ex(f"import pathlib\nfinal_answer(pathlib.Path('/work/{DRIVE}'))").output, pathlib.Path(f"/work/{DRIVEN}"))
        self.assertEqual(self.ex("final_answer(['\\x1b', b'\\x1b'])").output, [ESC, b"\x1b"])

    def test_an_unreadable_final_answer_arrives_escaped(self) -> None:
        # smolagents 1.26.0's reader names no text of the answer's in its errors (its date and
        # time errors quote a repr), so a reader that does stands in for a later release.
        reader = mock.Mock(side_effect=ValueError(f"cannot read {ESC}]0;PWNED{chr(7)}"))
        with mock.patch.object(PlimsollExecutor, "_deserialize_final_answer", reader), self.assertRaises(AgentError) as cm:
            self.ex._final_answer('safe:"x"', "")
        self.assertIn(f"could not be read: ValueError: cannot read {BS}x1b]0;PWNED{BS}x07", str(cm.exception))
        self.assertNoRaw(str(cm.exception))

    def test_nothing_from_the_sandbox_drives_the_terminal_through_smolagents_logger(self) -> None:
        # smolagents' own console logging at its default level (INFO) into a terminal, through
        # a CodeAgent run: what the steps printed, a step's value, an error and the final
        # answer are all on the console, and no control sequence of the sandbox's is.
        console = io.StringIO()
        logger = AgentLogger(level=LogLevel.INFO, console=Console(file=console, force_terminal=True, width=200))
        model = Scripted(f"print('{DRIVE}')\n'{DRIVE}'", f"raise ValueError('{DRIVE}')", f"final_answer('{DRIVE}')")
        agent = code_agent(executor(), tools=[], model=model, max_steps=3, logger=logger)
        self.assertEqual(agent.run("go"), DRIVEN)
        self.assertEqual(model.calls, 3)
        printed = console.getvalue()
        # The step's value and the final answer as smolagents printed them (rich drops the
        # carriage return and turns the tab into spaces), beside the code it showed.
        shown = f"a{BS}x1b]0;PWNED{BS}x07b"
        self.assertIn("Out: " + shown, printed)
        self.assertIn("Final answer: " + shown, printed)
        self.assertNoRaw(printed)


def agent_for(model: Scripted, *, tools: Any = (), helper: bool = True, max_steps: int = 3, client: Optional[FakeClient] = None) -> Any:
    ex = executor(client)
    if helper:
        return code_agent(ex, tools=list(tools), model=model, max_steps=max_steps, verbosity_level=LogLevel.OFF)
    return CodeAgent(tools=list(tools), model=model, executor=ex, max_steps=max_steps, verbosity_level=LogLevel.OFF)


class AgentTests(unittest.TestCase):
    def test_the_final_answer_ends_the_run_with_its_value(self) -> None:
        model = Scripted("x = 6", "final_answer(x * 7)")
        agent = agent_for(model)
        self.assertEqual(agent.run("go"), 42)
        self.assertEqual(model.calls, 2)

    def test_a_sent_tool_is_called_by_the_next_step(self) -> None:
        model = Scripted("final_answer(add(2, 3))")
        self.assertEqual(agent_for(model, tools=[add]).run("go"), 5)

    def test_a_code_error_is_shown_to_the_model_and_the_run_goes_on(self) -> None:
        model = Scripted("1 / 0", "final_answer('fixed')")
        agent = agent_for(model)
        self.assertEqual(agent.run("go"), "fixed")
        self.assertIn("ZeroDivisionError", str(agent.memory.steps[1].error))

    def test_additional_args_reach_the_code(self) -> None:
        model = Scripted("final_answer(numbers['a'] + 1)")
        self.assertEqual(agent_for(model).run("go", additional_args={"numbers": {"a": 1}}), 2)

    def test_the_agent_closes_the_session(self) -> None:
        client = FakeClient()
        with agent_for(Scripted("final_answer(1)"), client=client) as agent:
            agent.run("go")
        self.assertEqual(client.session.closes, 1)

    def test_the_records_are_the_sessions_chain(self) -> None:
        # What plimsoll states about each cell reaches the application (the gap Carroll had
        # filled in the other kits on 2026-11-17): after a three-step run, one record per cell
        # the client checked, in order, ending where the session's chain ends.
        client = FakeClient("vm")  # above the kernel floor: the tier is the cell's, not the floor
        agent = agent_for(Scripted("x = 6", "print(x)", "final_answer(x * 7)"), client=client)
        self.assertEqual(agent.run("go"), 42)
        session, records = client.session, agent.python_executor.records
        self.assertIsInstance(records, tuple)
        # The executor's setup cell, the tools' definitions, then the three steps.
        self.assertEqual(len(records), 5)
        self.assertEqual(len(records), session.calls)
        self.assertTrue(all(isinstance(r, PlimsollCellRecord) for r in records))
        self.assertEqual([r.record.sequence for r in records], [1, 2, 3, 4, 5])
        self.assertEqual([r.record.previous_sha256 for r in records], [""] + [r.record_sha256 for r in records[:-1]])
        self.assertEqual(records[-1].record_sha256, session.last_record_sha256)
        self.assertTrue(records[0].result.interpreter_started)  # the setup cell started the interpreter
        self.assertEqual({(r.isolation, r.isolation_qualification, r.outcome) for r in records}, {("vm", "", "completed")})
        self.assertTrue(all(r.record is r.result.record for r in records))
        self.assertIn(b"6\n", records[3].result.stdout)  # the second step's cell printed x

    def test_a_cell_is_kept_whatever_its_code_did(self) -> None:
        client = FakeClient()
        ex = executor(client)
        session = client.session
        with self.assertRaises(AgentError):
            ex("1 / 0")
        session.timeout.append("spin()")
        with self.assertRaises(AgentError):
            ex("spin()")
        self.assertEqual([r.outcome for r in ex.records], ["completed", "completed", "timed_out"])
        with self.assertRaises(AgentError):
            ex("2")  # finds the interpreter restarted: the run's fatal error, its cell kept
        self.assertIsNotNone(ex.fatal_error)
        self.assertEqual(len(ex.records), 4)
        self.assertTrue(ex.records[-1].result.interpreter_started)
        self.assertEqual((len(ex.records), ex.records[-1].record_sha256), (session.calls, session.last_record_sha256))

    def test_a_call_that_raised_adds_no_record(self) -> None:
        for error in (AtCapacityError("plimsoll: at capacity", not_dispatched="capacity"), PlimsollError("plimsoll: the answer was lost"),
                      KeyError("lost")):
            with self.subTest(type(error).__name__):
                client = FakeClient()
                ex = executor(client)
                ex("1")
                before = ex.records
                client.session.fail["STEP"] = error
                with self.assertRaises(type(error)):
                    ex("STEP")
                with self.assertRaises(PlimsollError):
                    ex("1")  # refused before anything is sent: adds none either
                self.assertIs(ex.fatal_error, error)
                self.assertEqual(ex.records, before)
                self.assertEqual(len(ex.records), 2)
                self.assertEqual((len(ex.records), ex.records[-1].record_sha256), (client.session.calls, client.session.last_record_sha256))

    def test_code_agent_needs_a_plimsoll_executor(self) -> None:
        with self.assertRaises(TypeError):
            code_agent(object(), tools=[], model=Scripted())  # type: ignore[arg-type]


def fatal_cases() -> Dict[str, Any]:
    """Each way the sandbox ends a run, applied to the cell that carries STEP_ONE: a function
    that arms the session and returns the error the run must raise (None: the executor's own)."""

    def raising(error: BaseException) -> Any:
        def arm(session: FakeSession) -> BaseException:
            session.fail["STEP_ONE"] = error
            return error

        return arm

    def restart(session: FakeSession) -> None:
        session.restart.append("STEP_ONE")
        return None

    return {
        "refusal": raising(AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")),
        "may-have-run": raising(PlimsollError("plimsoll: the answer was lost")),
        # Not plimsoll's: the real Session would refuse the next cell itself, but the run
        # must not rest on that (review finding 3 of the Agent Framework branch, the same shape).
        "other error": raising(KeyError("lost")),
        "ended session": raising(SessionEndedError("plimsoll: the session has ended", reason="expired", not_dispatched="request")),
        "restarted interpreter": restart,
    }


class FatalTests(unittest.TestCase):
    """The sandbox's failure ends the run with plimsoll's error, after one cell and one model call."""

    def run_fatal(self, arm: Any, *, max_steps: int = 3, helper: bool = True) -> Any:
        client = FakeClient()
        model = Scripted("STEP_ONE = 1", "STEP_TWO = 2", "final_answer(3)")
        agent = agent_for(model, client=client, helper=helper, max_steps=max_steps)
        expected = arm(client.session)
        return agent, model, client.session, expected

    def assertOneStepSent(self, session: FakeSession) -> None:
        # The tool definitions, then the failing step, then nothing.
        sent = steps(session)
        self.assertEqual(len(sent), 2, sent)
        self.assertIn("FinalAnswerTool", sent[0])
        self.assertIn("STEP_ONE", sent[1])

    def test_each_fatal_error_is_raised_by_run_after_one_cell(self) -> None:
        for name, arm in fatal_cases().items():
            with self.subTest(name):
                agent, model, session, expected = self.run_fatal(arm)
                with self.assertRaises(BaseException) as cm:
                    agent.run("go")
                fatal = agent.python_executor.fatal_error
                self.assertIsNotNone(fatal)
                self.assertIs(cm.exception, fatal)
                if expected is not None:
                    self.assertIs(cm.exception, expected)
                else:
                    self.assertIsInstance(cm.exception, AgentError)
                    self.assertIn("interpreter was restarted", str(cm.exception))
                self.assertEqual(model.calls, 1)
                self.assertOneStepSent(session)

    def test_the_fatal_error_keeps_its_own_context(self) -> None:
        def arm(session: FakeSession) -> BaseException:
            try:
                raise OSError("connection reset")
            except OSError as e:
                error = PlimsollError("plimsoll: the answer was lost")
                error.__context__ = e
            session.fail["STEP_ONE"] = error
            return error

        agent, _, _, expected = self.run_fatal(arm)
        with self.assertRaises(PlimsollError) as cm:
            agent.run("go")
        self.assertIs(cm.exception, expected)
        self.assertIsInstance(cm.exception.__context__, OSError)

    def test_a_run_ended_at_max_steps_still_raises(self) -> None:
        # With one step, smolagents asks the model for a final answer instead of stopping.
        agent, model, session, expected = self.run_fatal(fatal_cases()["refusal"], max_steps=1)
        with self.assertRaises(AtCapacityError) as cm:
            agent.run("go")
        self.assertIs(cm.exception, expected)
        self.assertOneStepSent(session)

    def test_a_streamed_run_raises_in_place_of_the_final_answer(self) -> None:
        for max_steps in (3, 1):
            with self.subTest(max_steps=max_steps):
                agent, model, session, expected = self.run_fatal(fatal_cases()["may-have-run"], max_steps=max_steps)
                seen: List[Any] = []
                with self.assertRaises(PlimsollError) as cm:
                    for item in agent.run("go", stream=True):
                        seen.append(item)
                self.assertIs(cm.exception, expected)
                self.assertFalse(any(isinstance(i, FinalAnswerStep) for i in seen))
                self.assertEqual(model.calls, 1 if max_steps == 3 else 2)
                self.assertOneStepSent(session)

    def test_a_run_after_the_failure_raises_at_once(self) -> None:
        agent, model, session, expected = self.run_fatal(fatal_cases()["refusal"])
        with self.assertRaises(AtCapacityError):
            agent.run("go")
        calls, sent, memory = model.calls, len(session.cells), len(agent.memory.steps)
        with self.assertRaises(AtCapacityError) as cm:
            agent.run("again", reset=False)
        self.assertIs(cm.exception, expected)
        # Nothing of the new run happens: no model call, no cell, not even its task in memory.
        self.assertEqual((model.calls, len(session.cells), len(agent.memory.steps)), (calls, sent, memory))

    def test_a_failure_sending_the_tools_is_raised(self) -> None:
        client = FakeClient()
        model = Scripted("final_answer(1)")
        agent = agent_for(model, client=client)
        error = AtCapacityError("plimsoll: at capacity", not_dispatched="capacity")
        client.session.fail["FinalAnswerTool"] = error
        with self.assertRaises(AtCapacityError) as cm:
            agent.run("go")
        self.assertIs(cm.exception, error)
        self.assertEqual(model.calls, 0)

    def test_the_bare_executor_never_sends_a_second_cell(self) -> None:
        # Without code_agent smolagents goes on to the next step and asks the model again
        # (3 steps, then a final answer), but the executor sends nothing more and keeps the
        # error; the run returns the model's own answer, which is why code_agent exists.
        agent, model, session, expected = self.run_fatal(fatal_cases()["refusal"], helper=False)
        self.assertEqual(agent.run("go"), "made up")
        self.assertEqual(model.calls, 4)
        self.assertOneStepSent(session)
        self.assertIs(agent.python_executor.fatal_error, expected)
        later = [s.error for s in agent.memory.steps[2:4]]  # steps 2 and 3
        self.assertEqual(len(later), 2)
        self.assertTrue(all("nothing more is sent to the sandbox" in str(e) for e in later), later)



class SmolagentsPlimsollPackageTests(unittest.TestCase):
    """smolagents-plimsoll (clients/python/smolagents-plimsoll) re-exports plimsoll-client's own names, at its
    version, and requires at least the smolagents version this suite runs against."""

    def test_names_are_plimsoll_clients_own(self) -> None:
        import smolagents_plimsoll

        self.assertIs(smolagents_plimsoll.PlimsollExecutor, PlimsollExecutor)
        self.assertIs(smolagents_plimsoll.PlimsollCellRecord, PlimsollCellRecord)
        self.assertIs(smolagents_plimsoll.code_agent, code_agent)
        self.assertIs(smolagents_plimsoll.Client, Client)
        self.assertEqual(sorted(smolagents_plimsoll.__all__), ["Client", "PlimsollCellRecord", "PlimsollExecutor", "code_agent"])

    def test_version_is_plimsoll_clients(self) -> None:
        import plimsoll_client
        import smolagents_plimsoll

        self.assertEqual(smolagents_plimsoll.__version__, plimsoll_client.__version__)

    def test_the_pin_is_the_version_this_suite_runs_against(self) -> None:
        # The package installs with exactly the smolagents this suite runs against
        # (TestAdaptersPinTheVersionTheirLockInstalls, in Go, holds every adapter's pin to
        # its lock file; this holds the pin to what is installed here).
        import importlib.metadata
        import tomllib

        pyproject = pathlib.Path(__file__).resolve().parents[2] / "smolagents-plimsoll" / "pyproject.toml"
        dependencies = tomllib.loads(pyproject.read_text())["project"]["dependencies"]
        self.assertIn("smolagents==" + importlib.metadata.version("smolagents"), dependencies)

    def _text(self, *parts: str) -> str:
        return pathlib.Path(__file__).resolve().parents[2].joinpath(*parts).read_text()

    def test_the_readme_states_the_executors_own_defaults_and_pin(self) -> None:
        # The PyPI page's numbers are the code's: the step budget, the session lifetime asked
        # for, and the version range and the one version tested.
        import importlib.metadata

        readme = self._text("smolagents-plimsoll", "README.md")
        parameters = inspect.signature(PlimsollExecutor.__init__).parameters
        self.assertIn(f"`timeout`, {parameters['timeout'].default:g} seconds unless you set it", readme)
        self.assertIn(f"`lifetime` (seconds, {parameters['lifetime'].default:g} unless you set it)", readme)
        self.assertIs(parameters["allow_pickle"].default, False)
        self.assertNotIn("smolagents>=", readme)
        self.assertIn(f"tested with, and installs with, exactly smolagents {importlib.metadata.version('smolagents')} (released 2026-05-29)", " ".join(readme.split()))

    def test_the_readme_names_what_each_cell_record_carries(self) -> None:
        # The fields the PyPI page names for executor.records are the type's own.
        readme = self._text("smolagents-plimsoll", "README.md")
        self.assertIn("`executor.records`", readme)
        names = {n for n, v in vars(PlimsollCellRecord).items() if isinstance(v, property)} | {f.name for f in dataclasses.fields(PlimsollCellRecord)}
        self.assertEqual(names, {"result", "record", "record_sha256", "isolation", "isolation_qualification", "outcome"})
        for name in names:
            self.assertIn(f"(`{name}`", readme)
        for outcome in ("completed", "timed_out"):
            self.assertIn(f"`{outcome}`", readme)

    def test_the_readme_and_the_example_agree_on_whether_the_package_is_released(self) -> None:
        # Finding release-34 (a PyPI name is not reserved until its first upload): the PyPI page's
        # install line carries the until-the-next-release note the example's header carries, and
        # the release takes both away together.
        note = "ships with plimsoll's next release"
        self.assertEqual(note in self._text("smolagents-plimsoll", "README.md"), note in self._text("examples", "smolagents_executor.py"))


class FrameworkShapeTests(unittest.TestCase):
    """Each member the adapter defines over the framework's own (inherited, or declared by a protocol it is used
    as) against the framework at the version this suite installs: kind, coroutine, the calls it takes
    (tests/_framework_shapes.py)."""

    def test_the_adapter_takes_the_calls_the_framework_makes(self) -> None:
        import importlib

        from tests._framework_shapes import problems

        self.assertEqual(problems(importlib.import_module('plimsoll_client.smolagents')), [])


if __name__ == "__main__":
    unittest.main()
