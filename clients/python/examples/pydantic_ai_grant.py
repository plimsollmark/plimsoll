"""PydanticAI + plimsoll, with a grant: the code tool's programs can call one web API.

As crewai_grant.py, through a PydanticAI agent whose model is FunctionModel with a scripted
function (it asks for the two programs in turn, then answers), so nothing calls a model
service. The tool return's metadata, which the model is not sent, carries plimsoll's labels
for the application. Install: pip install pydantic-ai-plimsoll. Checked:
clients/python/examples_docker_test.go runs this file against a real docker daemon and a
stand-in for the API.
"""

import asyncio

from pydantic_ai import Agent
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from plimsoll_client.pydantic_ai import plimsoll_code_tool

from _granted import JS, PY, executor

CALLS = [{"code": JS, "language": "javascript"}, {"code": PY, "language": "python"}]


def scripted(messages, info):
    turn = sum(isinstance(m, ModelResponse) for m in messages)
    if turn < len(CALLS):
        return ModelResponse(parts=[ToolCallPart("plimsoll_run_code", CALLS[turn], tool_call_id=f"call_{turn}")])
    return ModelResponse(parts=[TextPart("done")])


async def main() -> None:
    tool = plimsoll_code_tool(executor(), languages=("javascript", "python"))
    print("the model is told of:", tool.description.split("The API:\n", 1)[1].splitlines()[0])
    result = await Agent(FunctionModel(scripted), tools=[tool]).run("Turn the kitchen light on.")
    for message in result.all_messages():
        for part in getattr(message, "parts", []):
            if isinstance(part, ToolReturnPart):
                print(part.content["language"] if "language" in part.content else "?", "->", part.content)
                print("labels", part.metadata)


if __name__ == "__main__":
    asyncio.run(main())
