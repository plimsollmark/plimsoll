"""A scripted PydanticAI model for the suites: FunctionModel answering with the given tool calls in order, then
"done", streamed or not (PydanticAI's Coder streams its requests). No model provider is called."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator, Dict, List, Sequence, Tuple, Union

from pydantic_ai.messages import ModelMessage, ModelRequest, ModelResponse, RetryPromptPart, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, DeltaToolCall, DeltaToolCalls, FunctionModel


class Scripted:
    """``model`` answers each request with the next of ``calls`` (a tool name and its arguments), then "done".
    ``offered`` keeps the tool names the agent offered on each request; ``returns`` the tool returns and retry
    prompts the model was sent, by tool name."""

    def __init__(self, *calls: Tuple[str, Dict[str, Any]]) -> None:
        self.calls: List[Tuple[str, Dict[str, Any]]] = list(calls)
        self.offered: List[List[str]] = []
        self.returns: List[Tuple[str, Any]] = []
        self.model = FunctionModel(self._answer, stream_function=self._stream)

    def _next(self, messages: Sequence[ModelMessage], info: AgentInfo) -> Union[Tuple[str, Dict[str, Any]], None]:
        self.offered.append(sorted(t.name for t in info.function_tools))
        last = messages[-1]
        if isinstance(last, ModelRequest):
            for part in last.parts:
                if isinstance(part, (ToolReturnPart, RetryPromptPart)) and part.tool_name is not None:
                    self.returns.append((part.tool_name, part.content))
        return self.calls.pop(0) if self.calls else None

    def _answer(self, messages: Sequence[ModelMessage], info: AgentInfo) -> ModelResponse:
        call = self._next(messages, info)
        if call is not None:
            return ModelResponse(parts=[ToolCallPart(call[0], call[1], tool_call_id=f"call-{len(self.offered)}")])
        return ModelResponse(parts=[TextPart("done")])

    async def _stream(self, messages: Sequence[ModelMessage], info: AgentInfo) -> AsyncIterator[Union[str, DeltaToolCalls]]:
        call = self._next(messages, info)
        if call is not None:
            yield {0: DeltaToolCall(name=call[0], json_args=json.dumps(call[1]), tool_call_id=f"call-{len(self.offered)}")}
        else:
            yield "done"

    def returned(self, tool: str) -> List[Any]:
        return [content for name, content in self.returns if name == tool]
