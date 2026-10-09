"""A CrewAI tool that runs model-written code in plimsoll.

    from crewai import Agent
    from plimsoll_client import Client
    from plimsoll_client.crewai import PlimsollCodeTool
    from plimsoll_client.execution import CodeExecutor

    executor = CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN))
    agent = Agent(role=..., goal=..., backstory=..., tools=[PlimsollCodeTool(executor)])

CrewAI no longer ships a code interpreter of its own (since April 2026 an agent's
``allow_code_execution`` only warns and points to hosted sandboxes), so this tool is how a
crew runs code on infrastructure you choose.

A crew or agent that opts into CrewAI's tool cache (``Crew(cache=True)``, an agent with
``cache=True`` set or a ``cache_handler``; both off by default in CrewAI 1.15.23) looks a
call up in that cache by tool name and arguments before calling the tool, whatever the
tool's ``cache_function`` says, so another tool of the same name could
answer for this one with nothing run and no run record checked. The tool never writes
to the cache, and constructing one makes every read of CrewAI's ``CacheHandler`` miss
for its name, so CrewAI always calls it. A cache handler of your own that overrides
``read`` is not covered: keep caching off for such a crew (``cache=False``).

The tool, ``plimsoll_run_code`` (code, language, input_files), answers with the dict
``plimsoll_client._code_tool`` describes, as JSON. Every call runs in a fresh
sandbox through :class:`~plimsoll_client.execution.CodeExecutor`, which sets the
isolation floor, the time budget and the software rule; nothing persists between
calls and nothing is installed. Needs ``crewai`` (``pip install
'plimsoll-client[crewai]'``).
"""

from __future__ import annotations

import inspect
import json
import threading
import warnings
from importlib.metadata import version as _version
from typing import Any, List, Literal, Optional, Sequence, Set, Type

try:
    from crewai.agents.cache.cache_handler import CacheHandler
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.crewai needs CrewAI: pip install 'plimsoll-client[crewai]'") from e
from crewai.tools import BaseTool
from crewai.utilities.string_utils import sanitize_tool_name
from pydantic import BaseModel, Field, PrivateAttr, create_model

from . import _code_tool as ct
from .execution import CodeExecutor

__all__ = ["PlimsollCodeTool", "InputFile"]


class InputFile(BaseModel):
    """One text file written into the sandbox before the code runs."""

    path: str = Field(description=ct.PATH_HELP)
    content: str = Field(description=ct.CONTENT_HELP)


def _never_cache(_args: Any = None, _result: Any = None) -> bool:
    """A crew with caching on would answer a repeated call from its cache: a run that
    did not happen, with the last call's result (a capacity refusal included)."""
    return False


def _args_schema(languages: Sequence[str]) -> Type[BaseModel]:
    # The language enum names exactly the languages this tool offers.
    return create_model(
        "PlimsollCodeInput",
        code=(str, Field(description=ct.CODE_HELP)),
        language=(Literal[tuple(languages)], Field(default=languages[0], description=f'{ct.LANGUAGE_HELP} Default "{languages[0]}".')),  # type: ignore[valid-type]
        input_files=(Optional[List[InputFile]], Field(default=None, description=ct.FILES_HELP)),
    )


# The names of the plimsoll tools constructed in this process, as CrewAI sanitizes them.
_uncached: Set[str] = set()
_uncached_lock = threading.Lock()


# The CrewAI release whose cache reads were checked, all through CacheHandler.read (the
# framework suite's test_every_cache_read_goes_through_the_handler fails when a locked
# CrewAI reads elsewhere). Another release gets a warning, not a refusal.
_CHECKED_CREWAI = "1.15."


def _never_read_from_cache(name: str) -> None:
    """Makes every CacheHandler read miss for the tool name. CrewAI 1.15.23 reads its
    cache before calling a tool in five places (tools/tool_usage.py twice,
    agents/crew_agent_executor.py, utilities/agent_utils.py, experimental/
    agent_executor.py), all through CacheHandler.read and none asking the tool, so the
    read is wrapped once, process wide; it changes nothing for any other tool's name.
    A CacheHandler.read of another shape is refused, since the guard could not hold."""
    with _uncached_lock:
        _uncached.add(sanitize_tool_name(name))
        if getattr(CacheHandler.read, "_plimsoll_guard", False):
            return
        original = CacheHandler.read
        if list(inspect.signature(original).parameters)[:3] != ["self", "tool", "input"]:
            raise TypeError(
                "plimsoll: this CrewAI's CacheHandler.read does not take (tool, input), so the "
                "guard that keeps a cached answer from standing in for a plimsoll run cannot apply"
            )
        crewai_version = _version("crewai")
        if not crewai_version.startswith(_CHECKED_CREWAI):
            warnings.warn(
                f"plimsoll: the CrewAI cache guard was checked on CrewAI {_CHECKED_CREWAI}x, not "
                f"{crewai_version}; keep tool caching off (cache=False) for crews with plimsoll "
                "tools until it is", stacklevel=3)

        def read(self: CacheHandler, tool: str, input: str) -> Any:
            if sanitize_tool_name(tool) in _uncached:
                return None
            return original(self, tool, input)

        read._plimsoll_guard = True  # type: ignore[attr-defined]
        CacheHandler.read = read  # type: ignore[method-assign]


class PlimsollCodeTool(BaseTool):
    """CrewAI tool ``plimsoll_run_code``.

    ``languages`` are the languages the tool offers, the first being the default;
    offer only what the daemon's project image runs. ``max_output_chars`` cuts stdout
    and stderr before the model sees them (the result says ``truncated``). Other
    keyword arguments are CrewAI's tool fields (``max_usage_count``,
    ``result_as_answer``, ...).

    The async path (``arun``) calls the tool in a worker thread. Cancelling it cancels
    the call: if Run has not been sent (the daemon's Describe is still answering, say)
    it never is, and a Run in flight has its connection cut, so the worker thread ends
    at once rather than at the executor's deadline. Whether the daemon then stops the
    code depends on its provider (see the README).
    """

    # The cache is closed to it by _never_read_from_cache, not by the name.
    name: str = ct.TOOL_NAME
    description: str = ct.description(ct.LANGUAGES)
    args_schema: Type[BaseModel] = _args_schema(ct.LANGUAGES)

    _executor: CodeExecutor = PrivateAttr()
    _languages: tuple = PrivateAttr()
    _max_output_chars: int = PrivateAttr()

    def __init__(
        self,
        executor: CodeExecutor,
        *,
        languages: Sequence[str] = ct.LANGUAGES,
        max_output_chars: int = ct.MAX_OUTPUT_CHARS,
        **kwargs: Any,
    ) -> None:
        if not isinstance(executor, CodeExecutor):
            raise TypeError("plimsoll: PlimsollCodeTool needs a plimsoll_client.execution.CodeExecutor")
        if "cache_function" in kwargs:
            raise ValueError("plimsoll: PlimsollCodeTool runs every call; its answers are never cached")
        kwargs["cache_function"] = _never_cache
        langs = ct.check_languages(languages)
        kwargs.setdefault("description", ct.description(langs))
        kwargs.setdefault("args_schema", _args_schema(langs))
        super().__init__(**kwargs)
        _never_read_from_cache(self.name)
        self._executor = executor
        self._languages = langs
        self._max_output_chars = ct.check_max_output(max_output_chars)

    @property
    def executor(self) -> CodeExecutor:
        return self._executor

    @property
    def languages(self) -> tuple:
        """The languages the tool offers, the first being the default."""
        return self._languages

    def _run(self, code: str, language: Optional[str] = None, input_files: Optional[List[Any]] = None) -> str:
        return json.dumps(ct.run(self._executor, self._languages, self._max_output_chars, code, language, input_files))

    async def _arun(self, code: str, language: Optional[str] = None, input_files: Optional[List[Any]] = None) -> str:
        return json.dumps(await ct.arun(self._executor, self._languages, self._max_output_chars, code, language, input_files))
