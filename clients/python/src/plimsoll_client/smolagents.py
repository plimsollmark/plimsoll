"""smolagents: a plimsoll session as a ``CodeAgent``'s Python executor.

smolagents (``smolagents`` 1.26.0, read on 2026-11-15) runs the code a ``CodeAgent``'s model
writes through a **Python executor**; its remote executors (E2B, Docker, Modal, Blaxel)
subclass ``RemotePythonExecutor`` and implement ``run_code_raise_errors``.
:class:`PlimsollExecutor` is that executor over one plimsoll session: every step of the agent
is one cell in the session's Python interpreter, so what one step defines (variables,
functions, the agent's tools) is there in the next, and the daemon's guarantees hold for the
whole run: the isolation floor, a run record on every cell, and no network (a cell carries
no grant).

    from smolagents import AgentLogger, LogLevel
    from plimsoll_client import Client
    from plimsoll_client.smolagents import PlimsollExecutor, code_agent

    executor = PlimsollExecutor([], AgentLogger(LogLevel.INFO),
                                client=Client("https://plimsoll.internal:8746", token=TOKEN),
                                minimum_isolation="kernel")
    with code_agent(executor, tools=[], model=model) as agent:   # closes the session after
        print(agent.run("..."))

What the executor needs and does, stated here and in the docstrings:

- **The floor is yours to set.** ``minimum_isolation`` has no default. The executor opens its
  session when it is built and checks the tier the session states before any of the agent's
  code is sent; below the floor it closes the session and raises.
- **A failure of the sandbox ends the run, with plimsoll's error.** A cell plimsoll refused
  before anything ran, one that may have run without an answer to show for it (any error of
  the session's call that is not a refusal, plimsoll's or not), a cell on an ended session,
  and a step that finds the interpreter restarted (the earlier steps'
  variables gone) all mean the run cannot go on. smolagents turns every error an executor
  raises into an error the model is shown, and goes on to the next step; so the executor
  keeps the first such error as :attr:`PlimsollExecutor.fatal_error` and refuses every later
  cell without sending it, and :func:`code_agent` builds a ``CodeAgent`` that stops at the end
  of that step and whose ``run`` raises that same error. **Build the agent with**
  :func:`code_agent`. A ``CodeAgent`` given the executor directly still sends nothing more to
  the sandbox, but goes on asking its model until ``max_steps`` and then returns the model's
  own answer, made up after the sandbox failed; check ``executor.fatal_error`` after such a
  run.
- **The code's own errors are the model's to fix.** An exception the agent's code raises
  comes back to the model as smolagents' ``AgentError``, with the code's output and the
  traceback, as smolagents' own remote executors report it.
- **Nothing is installed.** :meth:`~PlimsollExecutor.install_packages` refuses any package:
  a plimsoll sandbox has no network by default, so packages belong in the image the operator
  runs (``plimsoll/sandbox-python`` has NumPy and SciPy). smolagents asks its executor to
  install every package a tool's code imports from outside the standard library, so such a
  tool is refused when the run starts, even when the image has the package; the agent's
  steps can import what the image has.
- **Tools run in the sandbox.** The agent's tools are sent into the interpreter and run there,
  in the step's cell. A cell carries no grant (docs/sessions.md, "No API access"), so a tool
  that needs the network cannot reach it from a step.
- **The final answer is plain data.** The executor sends its own definition of the
  ``final_answer`` tool, with no NumPy or Pillow import (``plimsoll/sandbox-python`` has no
  Pillow); it carries what smolagents' own carries (JSON values, tuples, sets, bytes, dates,
  dataclasses and the rest), but an image or a NumPy array or number is refused with an
  error the model is shown, so it can answer with a plain value instead. A NumPy number
  that is also a Python ``float`` (``numpy.float64``) is carried as that float; a
  ``numpy.int64`` is refused, where smolagents' own carries it as a plain int
  (measured with NumPy 2.5.5, 2026-11-21).
- **No pickle, ever.** smolagents' ``allow_pickle`` would let a final answer from the
  sandbox be unpickled in this process, which runs code the sandbox chose here: the
  executor refuses it, and a final answer that arrives as a pickle is refused unread.
- **Text from the sandbox arrives printable.** smolagents prints a step's output, its value
  and the final answer on the terminal as they are; the executor writes each terminal
  control character in them (but tab, newline and carriage return) as a visible escape,
  ``\\x1b``, so code in the sandbox cannot drive the terminal through them
  (:class:`PlimsollExecutor` says which texts).
- **What plimsoll states about each cell reaches the application.** smolagents asks an
  executor only for a step's output, value or error; :attr:`PlimsollExecutor.records` keeps,
  for every cell the executor sent and the client checked, a :class:`PlimsollCellRecord`: the
  tier, the provider's sentence beside it, how the cell ended, its run record and the
  checked result. They are the session's chain of records, in order.

Needs smolagents (``pip install smolagents-plimsoll``).
"""

from __future__ import annotations

import base64
import binascii
import inspect
import json
import math
import re
import secrets
import threading
import types
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any, Generator, Iterator, List, Optional, Sequence, Tuple

try:
    from smolagents.agents import CodeAgent
    from smolagents.local_python_executor import CodeOutput
    from smolagents.memory import ActionStep, FinalAnswerStep
    from smolagents.models import Model
    from smolagents.monitoring import LogLevel
    from smolagents.remote_executors import RemotePythonExecutor
    from smolagents.tools import Tool
    from smolagents.utils import AgentError
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.smolagents needs smolagents: pip install smolagents-plimsoll (or smolagents==1.26.0, the version it is tested with)") from e

from . import _validate as v
from .aio import AsyncClient
from .client import Client, Session
from .errors import InsufficientIsolationError, PlimsollError
from .types import CellResult, RunRecord, meets
from .workspace import close_quietly as _close_quietly

__all__ = ["PlimsollCellRecord", "PlimsollExecutor", "code_agent"]


@dataclass(frozen=True)
class PlimsollCellRecord:
    """What plimsoll states about one cell :class:`PlimsollExecutor` sent and the client
    checked, as :class:`plimsoll_client.agent_framework.PlimsollShellResult` states it about a
    command: the tier the cell ran at (``isolation``), the sentence the provider states beside
    the tier (``isolation_qualification``, "" when it states none), how the cell ended
    (``outcome``: ``completed``, or ``timed_out`` when its time budget ended it and the
    interpreter with it), the SHA-256 of its run record (``record_sha256``), the record
    (``record``, its place in the session's chain included) and the checked result itself
    (``result``). Nothing here comes from what the cell's code printed."""

    result: CellResult

    @property
    def record(self) -> Optional[RunRecord]:
        return self.result.record

    @property
    def record_sha256(self) -> str:
        return self.result.record.sha256 if self.result.record is not None else ""

    @property
    def isolation(self) -> str:
        return self.result.isolation

    @property
    def isolation_qualification(self) -> str:
        return self.result.isolation_qualification

    @property
    def outcome(self) -> str:
        return "timed_out" if self.result.timed_out else "completed"

#: The start of the line a step's record is on: then the step's nonce, ``>>`` and the record,
#: base64 of its JSON.
MARKER = "<<plimsoll-smolagents:"

# The setup cell. It defines one name in the interpreter's global namespace,
# __plimsoll_step(source, nonce), which runs one step of the agent's code there and prints
# the step's record as the last line of standard output. Everything the helper uses is held
# in its closure, so a step that rebinds json, sys or base64 in the namespace breaks nothing
# of the helper's. It catches BaseException, the FinalAnswerException smolagents' patched
# final_answer tool raises included, and returns None, so the interpreter prints nothing
# after the record.
_SETUP = '''\
def __plimsoll_define():
    import ast, base64, json, linecache, sys, traceback

    namespace = globals()
    count = [0]

    def text(value):
        try:
            return str(value)
        except BaseException:
            return "<unprintable %s>" % type(value).__name__

    def run(source):
        count[0] += 1
        filename = "<step %d>" % count[0]
        linecache.cache[filename] = (len(source), None, source.splitlines(True), filename)
        try:
            tree = ast.parse(source, filename, "exec")
            last = None
            if tree.body and isinstance(tree.body[-1], ast.Expr):
                last = ast.Expression(tree.body.pop().value)
            exec(compile(tree, filename, "exec"), namespace)
            if last is None:
                return json.dumps({"kind": "none"})
            value = eval(compile(last, filename, "eval"), namespace)
            if value is None:
                return json.dumps({"kind": "none"})
            try:
                return json.dumps({"kind": "value", "value": value})
            except Exception:
                return json.dumps({"kind": "value", "value": repr(value)})
        except BaseException as error:
            tb = error.__traceback__
            while tb is not None and tb.tb_frame.f_code.co_filename != filename:
                tb = tb.tb_next  # drop the helper's own frames: the traceback starts at the step
            try:
                formatted = "".join(traceback.format_exception(type(error), error, tb))
            except BaseException:
                formatted = ""
            return json.dumps({"kind": "error", "name": type(error).__name__, "message": text(error), "traceback": formatted})

    def step(source, nonce):
        data = run(source)
        line = "<<plimsoll-smolagents:" + nonce + ">>" + base64.b64encode(data.encode()).decode()
        sys.stdout.flush()
        # The leading newline puts the record at the start of a line whatever the step printed last.
        sys.stdout.write("\\n" + line + "\\n")
        sys.stdout.flush()

    return step


__plimsoll_step = __plimsoll_define()
del __plimsoll_define
'''


# The final_answer tool's forward as the sandbox runs it, sent in place of smolagents' own
# (RemotePythonExecutor._patch_final_answer_with_exception, smolagents 1.26.0). The protocol
# is smolagents': the answer travels as an exception named FinalAnswerException whose text is
# "safe:" and the JSON form smolagents' SafeSerializer reads back. The JSON form is built as
# smolagents' own builds it, type for type, except that it imports neither Pillow nor NumPy
# and has no pickle fallback: an image or a NumPy value is refused with an error the model
# is shown. Its source is sent as written, so it imports what it needs itself, and the def
# line is renamed to forward when it is sent. test_smolagents.py compares it with
# smolagents' own.
def _final_answer_forward(self, *args, **kwargs):
    import base64
    import json

    class SerializationError(Exception):
        pass

    def _from(obj, package):
        return any(str(getattr(c, "__module__", "")).split(".")[0] == package for c in type(obj).__mro__)

    def _name(obj):
        return str(type(obj).__module__) + "." + type(obj).__qualname__

    def _to_json_safe(obj):
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, dict):
            if all(isinstance(k, str) for k in obj.keys()):
                return {k: _to_json_safe(v) for k, v in obj.items()}
            else:
                return {
                    "__type__": "dict_with_complex_keys",
                    "data": [[_to_json_safe(k), _to_json_safe(v)] for k, v in obj.items()],
                }
        elif isinstance(obj, list):
            return [_to_json_safe(item) for item in obj]
        elif isinstance(obj, tuple):
            return {"__type__": "tuple", "data": [_to_json_safe(item) for item in obj]}
        elif isinstance(obj, set):
            return {"__type__": "set", "data": [_to_json_safe(item) for item in obj]}
        elif isinstance(obj, bytes):
            return {"__type__": "bytes", "data": base64.b64encode(obj).decode()}
        elif isinstance(obj, complex):
            return {"__type__": "complex", "real": obj.real, "imag": obj.imag}
        elif isinstance(obj, frozenset):
            return {"__type__": "frozenset", "data": [_to_json_safe(item) for item in obj]}

        if _from(obj, "PIL"):
            raise SerializationError(
                "final_answer cannot carry an image (" + _name(obj) + ") in a plimsoll sandbox: answer with plain "
                "data, for example a description, a file path in the sandbox, or the image's bytes"
            )

        from datetime import date, datetime, time, timedelta
        from decimal import Decimal
        from pathlib import Path

        if isinstance(obj, datetime):
            return {"__type__": "datetime", "data": obj.isoformat()}
        elif isinstance(obj, date):
            return {"__type__": "date", "data": obj.isoformat()}
        elif isinstance(obj, time):
            return {"__type__": "time", "data": obj.isoformat()}
        elif isinstance(obj, timedelta):
            return {"__type__": "timedelta", "total_seconds": obj.total_seconds()}
        elif isinstance(obj, Decimal):
            return {"__type__": "Decimal", "data": str(obj)}
        elif isinstance(obj, Path):
            return {"__type__": "Path", "data": str(obj)}

        if _from(obj, "numpy"):
            raise SerializationError(
                "final_answer cannot carry a NumPy array or number (" + _name(obj) + ") in a plimsoll sandbox: "
                "answer with a plain Python value, for example value.tolist() or value.item()"
            )

        import dataclasses

        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return {
                "__type__": "dataclass",
                "class_name": type(obj).__name__,
                "module": type(obj).__module__,
                "data": {f.name: _to_json_safe(getattr(obj, f.name)) for f in dataclasses.fields(obj)},
            }

        raise SerializationError(f"Cannot safely serialize object of type {type(obj).__name__}")

    class FinalAnswerException(BaseException):
        def __init__(self, value):
            self.value = value

    raise FinalAnswerException("safe:" + json.dumps(_to_json_safe(self._forward(*args, **kwargs))))


def _forward_source(function: Any, name: str) -> str:
    """The source smolagents sends for ``function``, its def line renamed to ``name`` (read
    as smolagents' own ``get_source`` reads it: a ``__source__`` first)."""
    source = getattr(function, "__source__", None) or inspect.getsource(function)
    return source.replace(f"def {function.__name__}(", f"def {name}(", 1)


#: The ``__type__`` marks of smolagents' final-answer JSON this executor decodes: exactly
#: the kinds its own writer writes (:func:`_final_answer_forward`; test_smolagents.py holds
#: this set to the marks in that function's source, and to what smolagents' reader reads).
#: Every other mark is refused before smolagents' reader sees the answer, because that
#: reader runs in this process, on bytes the sandbox chose, and learns new kinds with new
#: smolagents releases: it opens an image with Pillow and builds a NumPy array today. Until
#: 2026-11-20 this was a list of those two to refuse, which a later smolagents' new kind
#: would have passed (finding hunt-quality-50).
_CARRIED_MARKS = frozenset({
    "dict_with_complex_keys", "tuple", "set", "bytes", "complex", "frozenset",
    "datetime", "date", "time", "timedelta", "Decimal", "Path", "dataclass",
})

#: Plain words for the two kinds smolagents' own executors carry and this one refuses.
_KNOWN_REFUSED = {"PIL.Image": "an image", "ndarray": "a NumPy array"}


def _refused_mark(data: Any) -> Optional[str]:
    """What to call the first value in ``data`` whose kind this executor does not carry,
    or None when every marked value is one of :data:`_CARRIED_MARKS`. A dict with a
    ``__type__`` key is a marked value whatever the key holds: smolagents' reader looks at
    the key before anything else."""
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if "__type__" in item:
                mark = item["__type__"]
                if not isinstance(mark, str) or mark not in _CARRIED_MARKS:
                    known = _KNOWN_REFUSED.get(mark) if isinstance(mark, str) else None
                    return known or "a value of the kind " + _printable(repr(mark))[:80]
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return None


# The control characters a terminal acts on: C0 but tab, newline and carriage return, DEL, and
# C1. smolagents' console logger (AgentLogger, at its default level) prints what a step printed,
# a step's value and the final answer to the developer's terminal as they are (only its error
# messages pass through its own sanitize_for_rich, which leaves C1 alone), so code in the sandbox
# could send the terminal escape sequences: a new window title, a cleared screen, the clipboard on
# a terminal that allows OSC 52. Measured with smolagents 1.26.0 and rich on 2026-11-18.
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _printable(text: str) -> str:
    """``text`` with each terminal control character written as a visible escape (``\\x1b``)."""
    return _CONTROL.sub(lambda m: "\\x%02x" % ord(m.group()), text)


def _printable_answer(value: Any) -> Any:
    """A value from the sandbox as smolagents prints it raw: text, or a path (whose ``str`` is
    its text). Anything else prints as its ``repr``, which escapes control characters itself,
    and is handed over as it came."""
    if isinstance(value, str):
        return _printable(value)
    if isinstance(value, PurePath):
        return type(value)(_printable(str(value)))
    return value


def _seconds(what: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"plimsoll: {what} must be a positive number of seconds, not {value!r}")
    return float(value)


class PlimsollExecutor(RemotePythonExecutor):
    """A smolagents remote Python executor over one plimsoll session.

    ``additional_imports`` must be empty: nothing is installed (:meth:`install_packages`).
    ``logger`` is a smolagents ``AgentLogger``. ``client`` is a
    :class:`plimsoll_client.Client`. ``minimum_isolation`` (``process``, ``container``,
    ``kernel`` or ``vm``) is the tier the session must state; it has no default.
    ``lifetime`` (seconds) may only shorten the daemon's own session lifetime. ``timeout``
    is each step's time budget: the daemon stops a step at it and ends the interpreter, so
    the step after it finds the interpreter restarted and the run ends. ``owner`` names the
    end user, for a daemon's per-owner cap (:meth:`plimsoll_client.Client.open_session`).

    **allow_pickle is refused.** In smolagents it lets a final answer from the sandbox
    travel as a pickle, and unpickling it runs code the sandbox chose, in this process: code
    in the sandbox could then run code outside it, which is what a sandbox is there to
    prevent. Anything but ``False`` raises ``ValueError`` before a session is opened, and so
    does setting the attribute later; a final answer that arrives as a pickle anyway is
    refused unread.

    The tools are sent into the sandbox and run there, in the step's cell. A cell carries no
    grant (docs/sessions.md), so no tool can reach the network from a step. The
    ``final_answer`` tool is sent as this executor's own definition (the module's
    docstring says how it differs from smolagents' own).

    Building the executor opens the session (language ``python``), checks its tier, and runs
    one setup cell that defines the helper ``__plimsoll_step`` in the interpreter. Each step
    of the agent is then one cell, ``__plimsoll_step(<the code>, "<nonce>")``, with a fresh
    random nonce: the helper runs the code in the interpreter's global namespace (so
    variables persist), evaluates a final expression, and prints the step's record (the
    value, nothing, or the error) as the last line of standard output, marked with the
    nonce. Everything the step printed before that line is its logs.

    **A limit, stated plainly:** the agent's own code runs in the same interpreter as the
    helper and can read the nonce, so it can forge the record of its own step: it can forge
    nothing but its own answer. The record is the model's code reporting on itself; the
    run record of each cell is plimsoll's.

    **The first error after which the run cannot go on** is kept as :attr:`fatal_error`:
    a refusal before anything ran, an error after which the cell may have run, a cell on an
    ended session (all raised as the client's own exceptions, unchanged: they are not
    ``AgentError``), any other exception the session's call raised (it may have followed
    the cell running, so it is raised unchanged too), and a step that finds the interpreter
    restarted (raised as an ``AgentError``, since the agent's variables and tools are gone).
    Every later cell is refused before anything is sent. :func:`code_agent` stops the agent
    at that step and raises :attr:`fatal_error` from ``run``.

    **Text from the sandbox arrives printable.** smolagents' console logger prints a step's
    output, its value and the final answer to the terminal as they are, so in each text this
    executor hands smolagents (the step's output, its error, a value or final answer that is
    text, a final answer that is a path) a terminal control character other than tab,
    newline and carriage return is written as a visible escape, ``\\x1b`` for the escape
    character. Text inside a list, a dictionary or another container is handed over as it
    came: smolagents prints such a value as its ``repr``, which escapes it already.

    **What plimsoll states about each cell** is kept in :attr:`records`, one
    :class:`PlimsollCellRecord` per cell the client checked, in the order they ran: first
    the executor's own setup cell, then one per call smolagents made (the variables and the
    tools' definitions at the start of each run, then each step), so the records are the
    session's chain and the last one's ``record_sha256`` is
    ``session.last_record_sha256``. A cell that returned a checked result is kept whatever
    its code did (an error, no result line, a timeout, a restarted interpreter). A call
    that raised adds none: when its error carries the checked record of a call that may
    have run, that record is ``fatal_error.record``.
    """

    def __init__(
        self,
        additional_imports: List[str],
        logger: Any,
        *,
        client: Client,
        minimum_isolation: str,
        lifetime: float = 3600.0,
        timeout: float = 120.0,
        allow_pickle: bool = False,
        owner: Optional[str] = None,
    ) -> None:
        if isinstance(client, AsyncClient):
            raise TypeError("plimsoll: PlimsollExecutor needs a plimsoll_client.Client (smolagents calls its executor synchronously)")
        if not v.floor(minimum_isolation):
            raise ValueError("plimsoll: an executor needs a floor: minimum_isolation process, container, kernel or vm")
        self._floor = minimum_isolation
        self._lifetime = _seconds("lifetime", lifetime)
        self._timeout = _seconds("timeout", timeout)
        # smolagents' __init__ sets allow_pickle, whose setter refuses anything but False.
        super().__init__(list(additional_imports), logger, allow_pickle)
        #: The first error after which the run cannot go on; ``None`` until there is one.
        self.fatal_error: Optional[BaseException] = None
        self._lock = threading.Lock()
        self._closed = False
        self._records: List[PlimsollCellRecord] = []
        # Refuses any package before a session is opened.
        self.installed_packages = self.install_packages(list(additional_imports))
        session = client.open_session(minimum_isolation=self._floor, lifetime=self._lifetime, languages=["python"], owner=owner)
        try:
            # The client checks the tier against the floor it sent; this is the executor's
            # own check, so the floor holds whatever the client is.
            if not meets(getattr(session, "isolation", "") or "", self._floor):
                raise InsufficientIsolationError(
                    f"plimsoll: the session states {getattr(session, 'isolation', '') or 'no tier'}, below the required "
                    f"{self._floor}; nothing of the agent's ran (the session was closed)",
                    not_dispatched="isolation",
                )
            setup = session.run_cell(_SETUP, "python", timeout=self._timeout)
            self._records.append(PlimsollCellRecord(setup))
            if setup.exit_code != 0 or setup.timed_out:
                raise AgentError(
                    f"plimsoll: the sandbox's Python interpreter could not define the executor's helper (exit code "
                    f"{setup.exit_code}); the session was closed\n{_printable(setup.stderr_text)}",
                    self.logger,
                )
        except BaseException:
            _close_quietly(session)
            raise
        self._session = session
        self.logger.log(f"plimsoll session open, isolation {session.isolation}", level=LogLevel.INFO)

    @property
    def session(self) -> Session:
        """The plimsoll session."""
        return self._session

    @property
    def records(self) -> Tuple[PlimsollCellRecord, ...]:
        """What plimsoll stated about each cell the client checked, in the order they ran:
        the setup cell first, then one per call smolagents made (the class docstring says
        which). A copy: the executor's own list keeps growing as the agent runs."""
        with self._lock:
            return tuple(self._records)

    @property  # type: ignore[override]
    def allow_pickle(self) -> bool:
        """Always ``False``: no pickle travels either way (the class docstring says why)."""
        return False

    @allow_pickle.setter
    def allow_pickle(self, value: Any) -> None:
        if value is not False:
            raise ValueError(
                "plimsoll: allow_pickle is refused: unpickling a value from the sandbox runs code the sandbox chose in "
                "this process; the executor carries only JSON-safe values"
            )

    def _patch_final_answer_with_exception(self, final_answer_tool: Tool) -> None:
        """smolagents' hook, called by ``send_tools`` before the tools are sent: the
        ``final_answer`` tool's forward becomes this executor's own (the module's
        ``_final_answer_forward``), and its original forward becomes ``_forward``, as
        smolagents' own hook does. A tool patched by an earlier run is left as it is."""
        cls = type(final_answer_tool)
        if cls.__dict__.get("forward") is _final_answer_forward:
            return
        original = final_answer_tool.forward.__func__  # type: ignore[attr-defined]
        if not hasattr(_final_answer_forward, "__source__"):
            _final_answer_forward.__source__ = _forward_source(_final_answer_forward, "forward")  # type: ignore[attr-defined]
        # A copy of the original, so the source smolagents reads for it (renamed _forward)
        # is set on the copy and the tool's own class keeps its forward's source.
        inner = types.FunctionType(original.__code__, original.__globals__, "_forward", original.__defaults__, original.__closure__)
        inner.__kwdefaults__ = original.__kwdefaults__
        inner.__annotations__ = dict(getattr(original, "__annotations__", {}))
        inner.__source__ = _forward_source(original, "_forward")  # type: ignore[attr-defined]

        class _FinalAnswerTool(cls):  # type: ignore[valid-type, misc]
            pass

        _FinalAnswerTool.forward = _final_answer_forward  # type: ignore[method-assign]
        _FinalAnswerTool._forward = inner  # type: ignore[attr-defined]
        final_answer_tool.__class__ = _FinalAnswerTool

    def install_packages(self, additional_imports: List[str]) -> List[str]:
        """Installs nothing: an empty list returns ``[]``, and any package raises
        ``ValueError``. A plimsoll sandbox has no network by default, so packages belong in
        the image the operator runs. It never runs ``pip``."""
        if not additional_imports:
            return []
        raise ValueError(
            f"plimsoll: cannot install {', '.join(map(str, additional_imports))}: a plimsoll sandbox has no network by "
            "default, and packages belong in the image its operator runs; nothing was run"
        )

    def _fail(self, error: BaseException) -> None:
        with self._lock:
            if self.fatal_error is None:
                self.fatal_error = error

    def run_code_raise_errors(self, code: str) -> CodeOutput:
        """Runs one step of the agent's code as one cell of the session and returns its
        ``CodeOutput``; the code's own exception raises ``AgentError``, as does a step that
        returned no record (it ran past its time budget, ended the interpreter, or its
        output was cut). The errors after which the run cannot go on raise as the class
        docstring says, and are kept as :attr:`fatal_error`; once there is one, every call
        raises :class:`~plimsoll_client.PlimsollError`, marked not dispatched, and sends
        nothing."""
        fatal = self.fatal_error
        if fatal is not None:
            raise PlimsollError(
                f"plimsoll: an earlier step ended this run ({type(fatal).__name__}: {fatal}); nothing more is sent to the sandbox",
                code="failed_precondition",
                not_dispatched="request",
            ) from fatal
        nonce = secrets.token_hex(16)
        try:
            cell = self._session.run_cell(f"__plimsoll_step({code!r}, {nonce!r})", "python", timeout=self._timeout)
        except BaseException as e:
            # Whatever ended the call, plimsoll's or not (an error the transport did not wrap,
            # a bug, an interrupt), the cell may have run: smolagents would show anything but
            # this to the model as a code error and send the next step, so every exception
            # here ends the run, as a marked refusal does.
            self._fail(e)
            raise
        # Kept before anything is read from the cell's output: an answered, checked cell is
        # in the session's chain whatever its code did.
        with self._lock:
            self._records.append(PlimsollCellRecord(cell))
        if cell.interpreter_started:
            error = AgentError(
                "plimsoll: the sandbox's Python interpreter was restarted, so the variables and tools of earlier steps are gone; "
                "the run cannot continue",
                self.logger,
            )
            self._fail(error)
            raise error
        return self._output(cell, nonce)

    def _output(self, cell: CellResult, nonce: str) -> CodeOutput:
        text = cell.stdout_text
        prefix = "\n" + MARKER + nonce + ">>"
        at = text.rfind(prefix)
        if at < 0:
            raise AgentError(self._no_record(cell, _printable(text)), self.logger)
        # Every text from the sandbox that smolagents prints is handed over printable
        # (_printable): the logs, a value that is text, the error, the final answer.
        logs = _printable(text[:at])
        payload = text[at + len(prefix) :].split("\n", 1)[0]
        try:
            record = json.loads(base64.b64decode(payload, validate=True))
            kind = record["kind"]
            if kind == "none":
                return CodeOutput(output=None, logs=logs, is_final_answer=False)
            if kind == "value":
                return CodeOutput(output=_printable_answer(record["value"]), logs=logs, is_final_answer=False)
            if kind != "error":
                raise ValueError(kind)
            name, message, tb = record["name"], record["message"], record["traceback"]
            if not (isinstance(name, str) and isinstance(message, str) and isinstance(tb, str)):
                raise ValueError("error fields")
        except (ValueError, KeyError, TypeError, RecursionError, binascii.Error):
            raise AgentError(f"{logs}\nExecuting code yielded an error:\nplimsoll: the step's result record could not be read", self.logger) from None
        if name == self.FINAL_ANSWER_EXCEPTION:
            return CodeOutput(output=self._final_answer(message, logs), logs=logs, is_final_answer=True)
        # The layout smolagents' own E2B executor uses.
        raise AgentError(f"{logs}\nExecuting code yielded an error:\n{_printable(name)}\n{_printable(message)}\n{_printable(tb)}", self.logger)

    def _final_answer(self, message: str, logs: str) -> Any:
        """The final answer from its text, read as smolagents reads it, but never from a
        pickle, and never a value of a kind the executor's own writer does not write
        (:data:`_CARRIED_MARKS`): an image, a NumPy array and any kind a later smolagents
        teaches its reader are refused here, since a step's code can raise an exception of
        that name with any text. A final answer that is text or a path comes back printable
        (:func:`_printable_answer`)."""
        if not message.startswith("safe:"):
            why = "it is a pickle, which this executor never unpickles" if message.startswith("pickle:") else "it is not in smolagents' safe form"
        else:
            try:
                refused = _refused_mark(json.loads(message[len("safe:") :]))
                if refused is None:
                    # False: smolagents' reader then refuses a pickle itself as well.
                    return _printable_answer(self._deserialize_final_answer(message, False))
                why = f"it is {refused}, which a plimsoll executor does not carry; answer with a plain value"
            except Exception as e:  # noqa: BLE001 - any text the sandbox sent that cannot be read is the step's error
                why = _printable(f"{type(e).__name__}: {e}")
        raise AgentError(f"{logs}\nExecuting code yielded an error:\nplimsoll: the final answer could not be read: {why}", self.logger)

    def _no_record(self, cell: CellResult, logs: str) -> str:
        """The error text for a step that returned no record; ``logs`` is already printable."""
        if cell.timed_out:
            what = f"it ran past its time budget ({self._timeout:g} s) and was stopped, and the sandbox ended its interpreter"
        elif cell.stdout_truncated:
            what = "its output passed the sandbox's limit and was cut, so the result at its end was lost"
        elif cell.interpreter_ended:
            what = "its code ended the sandbox's Python interpreter (an exit, a kill or a crash)"
        else:
            what = "its code replaced or closed standard output, or removed the executor's helper from the interpreter"
        stderr = _printable(cell.stderr_text)
        return f"{logs}\nExecuting code yielded an error:\nplimsoll: the step returned no result: {what}" + (f"\n{stderr}" if stderr else "")

    def cleanup(self) -> None:
        """Closes the session: the sandbox and its files are gone. Safe to call twice."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        _close_quietly(self._session)


class _PlimsollCodeAgent(CodeAgent):
    """A CodeAgent whose run raises its PlimsollExecutor's fatal error (code_agent)."""

    def __init__(self, tools: List[Tool], model: Model, *, executor: PlimsollExecutor, **kwargs: Any) -> None:
        self._plimsoll = executor
        super().__init__(tools, model, executor=executor, **kwargs)

    def run(self, task: str, stream: bool = False, *args: Any, **kwargs: Any) -> Any:
        fatal = self._plimsoll.fatal_error
        if fatal is not None:
            raise fatal  # a run after the sandbox failed calls no model and sends nothing
        if stream:
            try:
                steps = super().run(task, True, *args, **kwargs)
            except Exception:
                if self._plimsoll.fatal_error is None:
                    raise
            else:
                return self._stream(steps)
        else:
            try:
                out = super().run(task, False, *args, **kwargs)
            except Exception:
                if self._plimsoll.fatal_error is None:
                    raise
            else:
                if self._plimsoll.fatal_error is None:
                    return out
        # Raised here, outside the except clause, so the error keeps its own context.
        raise self._plimsoll.fatal_error

    def _stream(self, steps: Iterator[Any]) -> Generator[Any, None, None]:
        try:
            for item in steps:
                if isinstance(item, FinalAnswerStep) and self._plimsoll.fatal_error is not None:
                    break  # the model's own answer, after the sandbox failed: never handed on
                yield item
        except Exception:
            if self._plimsoll.fatal_error is None:
                raise
        if self._plimsoll.fatal_error is not None:
            raise self._plimsoll.fatal_error


def _stop(step: Any, agent: Any) -> None:
    executor = getattr(agent, "_plimsoll", None)
    if executor is not None and executor.fatal_error is not None:
        agent.interrupt()


def code_agent(executor: PlimsollExecutor, *, tools: Sequence[Tool], model: Model, **kwargs: Any) -> CodeAgent:
    """A smolagents ``CodeAgent`` that runs its code through ``executor`` and stops at the
    sandbox's first failure. ``tools``, ``model`` and every other keyword are
    ``CodeAgent``'s own (``step_callbacks`` included).

    The agent carries one more step callback: at the end of the step in which ``executor``
    kept a :attr:`~PlimsollExecutor.fatal_error`, it calls ``agent.interrupt()`` (smolagents'
    public way to stop a run), so the model is not asked again. Its ``run`` then raises that
    error, the original exception, rather than smolagents' "Agent interrupted.", and also
    when the run ended at ``max_steps`` with the model's own answer instead; with
    ``stream=True`` the steps are handed on as they come and the error is raised in place of
    the final answer. A run on an agent whose executor already failed raises at once.
    ``with agent:`` closes the session at the end, as ``agent.cleanup()`` does."""
    if not isinstance(executor, PlimsollExecutor):
        raise TypeError("plimsoll: code_agent needs a plimsoll_client.smolagents.PlimsollExecutor")
    agent = _PlimsollCodeAgent(list(tools), model, executor=executor, **kwargs)
    agent.step_callbacks.register(ActionStep, _stop)
    return agent
