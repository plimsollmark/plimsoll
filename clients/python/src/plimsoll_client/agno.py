"""An Agno toolkit that runs model-written code in plimsoll.

    from agno.agent import Agent
    from plimsoll_client import Client
    from plimsoll_client.agno import PlimsollTools
    from plimsoll_client.execution import CodeExecutor

    executor = CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN))
    agent = Agent(model=..., tools=[PlimsollTools(executor)])

The toolkit has one tool, ``plimsoll_run_code`` (code, language, input_files), and answers
with the dict ``plimsoll_client._code_tool`` describes, as JSON. Every call runs in a fresh
sandbox through :class:`~plimsoll_client.execution.CodeExecutor`, which sets the
isolation floor, the time budget and the software rule; nothing persists between
calls. Needs ``agno`` (``pip install 'plimsoll-client[agno]'``).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Literal, Optional, Sequence

try:
    from agno.tools import Toolkit
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.agno needs Agno: pip install 'plimsoll-client[agno]'") from e
from pydantic import BaseModel, Field

from . import _code_tool as ct
from .execution import CodeExecutor

__all__ = ["PlimsollTools", "InputFile"]


class InputFile(BaseModel):
    """One text file written into the sandbox before the code runs."""

    path: str = Field(description=ct.PATH_HELP)
    content: str = Field(description=ct.CONTENT_HELP)


class PlimsollTools(Toolkit):
    """Agno toolkit with one tool, ``plimsoll_run_code``.

    ``languages`` are the languages the tool offers, the first being the default;
    offer only what the daemon's project image runs. ``max_output_chars`` cuts stdout
    and stderr before the model sees them (the result says ``truncated``). Other
    keyword arguments go to Agno's :class:`Toolkit` (``requires_confirmation_tools``,
    ``instructions``, ...).

    Agno's async runs (``agent.arun``) call the tool in a worker thread. Cancelling
    the run cancels the call: if Run has not been sent (the daemon's Describe is
    still answering, say) it never is, and a Run in flight has its connection cut, so
    the worker thread ends at once rather than at the executor's deadline. Whether
    the daemon then stops the code depends on its provider (see the README).
    """

    def __init__(
        self,
        executor: CodeExecutor,
        *,
        languages: Sequence[str] = ct.LANGUAGES,
        max_output_chars: int = ct.MAX_OUTPUT_CHARS,
        **kwargs: Any,
    ) -> None:
        if not isinstance(executor, CodeExecutor):
            raise TypeError("plimsoll: PlimsollTools needs a plimsoll_client.execution.CodeExecutor")
        # A cached answer is a run that did not happen: the same code would get the last
        # call's result (a capacity refusal included) without the executor being asked.
        # Agno's Toolkit takes a timeout too, and would keep it without bounding anything
        # here: the run's budget is the executor's.
        if "timeout" in kwargs:
            raise ValueError("plimsoll: set the run's time budget on the CodeExecutor (CodeExecutor(..., timeout=seconds))")
        if kwargs.get("cache_results"):
            raise ValueError("plimsoll: PlimsollTools runs every call; Agno's cache_results would answer repeats without running them")
        self.executor = executor
        self.languages = ct.check_languages(languages)
        self.max_output_chars = ct.check_max_output(max_output_chars)
        kwargs.setdefault("name", "plimsoll_tools")
        super().__init__(tools=[self._tool(sync=True)], async_tools=[(self._tool(sync=False), ct.TOOL_NAME)], **kwargs)

    def run_code(self, code: str, language: Optional[str] = None, input_files: Optional[Sequence[Any]] = None) -> Dict[str, Any]:
        """Runs one call as the model would make it, for use outside an agent."""
        return ct.run(self.executor, self.languages, self.max_output_chars, code, language, input_files)

    # Agno shows the model str() of a tool's return value, so the tool returns the dict
    # as JSON. Agno builds a tool's schema from its function's annotations and docstring, so each
    # toolkit gets its own function: the language enum and the description name exactly
    # the languages this toolkit offers. The parameter is input_files because Agno
    # reserves `files` for the media it injects and leaves it out of the schema.
    def _tool(self, *, sync: bool) -> Any:
        doc = (
            ct.description(self.languages)
            + "\n\nArgs:\n"
            + f"    code: {ct.CODE_HELP}\n"
            + f"    language: {ct.LANGUAGE_HELP} Default \"{self.languages[0]}\".\n"
            + f"    input_files: {ct.FILES_HELP}\n"
        )
        if sync:

            def run_code(code: str, language: Optional[str] = None, input_files: Optional[List[InputFile]] = None) -> str:
                return json.dumps(self.run_code(code, language, input_files))

        else:

            async def run_code(code: str, language: Optional[str] = None, input_files: Optional[List[InputFile]] = None) -> str:  # type: ignore[misc]
                return json.dumps(await ct.arun(self.executor, self.languages, self.max_output_chars, code, language, input_files))

        run_code.__doc__ = doc
        run_code.__annotations__["language"] = Optional[Literal[self.languages]]  # type: ignore[valid-type]
        # Agno names a tool by its function.
        run_code.__name__ = run_code.__qualname__ = ct.TOOL_NAME
        return run_code
