"""A LangChain tool that runs model-written code in plimsoll.

    from langchain.agents import create_agent
    from plimsoll_client import Client
    from plimsoll_client.execution import CodeExecutor
    from plimsoll_client.langchain import PlimsollCodeTool

    executor = CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN))
    agent = create_agent(model, tools=[PlimsollCodeTool(executor)])

A LangChain tool is also a LangGraph tool: ``ToolNode``, ``create_agent`` and a graph of
your own call it the same way, synchronously or with ``ainvoke``.

The tool, ``plimsoll_run_code`` (code, language, input_files), answers with the dict
``plimsoll_client._code_tool`` describes, as JSON. Every call runs in a fresh sandbox
through :class:`~plimsoll_client.execution.CodeExecutor`, which sets the isolation floor
(the kernel tier by default), the time budget and the software rule; nothing persists
between calls and nothing is installed. For an agent that keeps files and a shell
between commands, use a plimsoll session as a Deep Agents backend
(:mod:`plimsoll_client.deepagents`). Needs ``langchain-core`` (``pip install
'plimsoll-client[langchain]'``).

Each call sends the LangChain run ID of the tool call as the run's ``trace_id``, so the
daemon's audit line joins to the trace, and, when the call is traced in LangSmith, adds
trusted labels to the tool call's run as metadata (the record's digest, the tier, whether
the run was dispatched, the outcome; never the code or its output):
:mod:`plimsoll_client._langsmith` says which, and how each is checked.
"""

from __future__ import annotations

import json
from typing import Any, List, Literal, Optional, Sequence, Type

try:
    from langchain_core.callbacks import AsyncCallbackManagerForToolRun, CallbackManagerForToolRun
    from langchain_core.tools import BaseTool
except ImportError as e:  # pragma: no cover
    raise ImportError("plimsoll_client.langchain needs LangChain: pip install 'plimsoll-client[langchain]'") from e
from pydantic import BaseModel, Field, PrivateAttr, create_model

from . import _code_tool as ct
from . import _langsmith as ls
from .execution import CodeExecutor

__all__ = ["PlimsollCodeTool", "InputFile"]


class InputFile(BaseModel):
    """One text file written into the sandbox before the code runs."""

    path: str = Field(description=ct.PATH_HELP)
    content: str = Field(description=ct.CONTENT_HELP)


def _args_schema(languages: Sequence[str]) -> Type[BaseModel]:
    # The language enum names exactly the languages this tool offers.
    return create_model(
        "PlimsollCodeInput",
        code=(str, Field(description=ct.CODE_HELP)),
        language=(Literal[tuple(languages)], Field(default=languages[0], description=f'{ct.LANGUAGE_HELP} Default "{languages[0]}".')),  # type: ignore[valid-type]
        input_files=(Optional[List[InputFile]], Field(default=None, description=ct.FILES_HELP)),
    )


class PlimsollCodeTool(BaseTool):
    """LangChain tool ``plimsoll_run_code``.

    ``languages`` are the languages the tool offers, the first being the default;
    offer only what the daemon's project image runs. ``max_output_chars`` cuts stdout
    and stderr before the model sees them (the result says ``truncated``). Other
    keyword arguments are LangChain's tool fields (``name``, ``tags``, ``metadata``,
    ``return_direct``, ...). ``response_format`` stays ``"content"``: the answer is the
    JSON text, which already carries the run record's digest.

    The async path (``ainvoke``) calls the tool in a worker thread. Cancelling it cancels
    the call: if Run has not been sent (the daemon's Describe is still answering, say)
    it never is, and a Run in flight has its connection cut, so the worker thread ends
    at once rather than at the executor's deadline. Whether the daemon then stops the
    code depends on its provider (see the README).
    """

    name: str = ct.TOOL_NAME
    description: str = ct.description(ct.LANGUAGES)
    args_schema: Type[BaseModel] = _args_schema(ct.LANGUAGES)  # type: ignore[assignment]

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
        if kwargs.get("response_format", "content") != "content":
            raise ValueError("plimsoll: PlimsollCodeTool answers with its JSON text (response_format='content')")
        langs = ct.offered(executor, languages)
        if executor.grant is not None and "description" in kwargs:
            raise ValueError("plimsoll: a granted tool's description is plimsoll's, with the API's own; it tells the model what the code can call")
        kwargs.setdefault("description", ct.description(langs, executor.grant))
        kwargs.setdefault("args_schema", _args_schema(langs))
        super().__init__(**kwargs)
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

    def _run(
        self,
        code: str,
        language: Optional[str] = None,
        input_files: Optional[List[Any]] = None,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        run_id = run_manager.run_id if run_manager is not None else None
        answer = ct.run(self._executor, self._languages, self._max_output_chars, code, language, input_files,
                        trace_id=ls.trace_id(run_id))
        ls.label_run(answer, run_id)
        return json.dumps(answer)

    async def _arun(
        self,
        code: str,
        language: Optional[str] = None,
        input_files: Optional[List[Any]] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> str:
        run_id = run_manager.run_id if run_manager is not None else None
        answer = await ct.arun(self._executor, self._languages, self._max_output_chars, code, language, input_files,
                               trace_id=ls.trace_id(run_id))
        # Here, not in the worker thread: this coroutine runs in the tool call's context,
        # where the tool call's LangSmith run is the active one.
        ls.label_run(answer, run_id)
        return json.dumps(answer)
