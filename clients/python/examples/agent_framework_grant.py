"""Microsoft Agent Framework + plimsoll, with a grant: the code tool's programs can call one
web API.

As crewai_grant.py, through the framework's own tool invocation (FunctionTool.invoke), so
nothing calls a model service. What reaches the application beside the model's text is
plimsoll's labels (whether the call ran, the tier, the record's digest): route templates,
paths, arguments and results are never among them. Install: pip install
agent-framework-plimsoll. Checked: clients/python/examples_docker_test.go runs this file
against a real docker daemon and a stand-in for the API.
"""

import asyncio

from plimsoll_client.agent_framework import plimsoll_code_tool

from _granted import JS, PY, executor


async def main() -> None:
    tool = plimsoll_code_tool(executor(), languages=("javascript", "python"))
    print("the model is told of:", tool.description.split("The API:\n", 1)[1].splitlines()[0])
    for code, language in ((JS, "javascript"), (PY, "python")):
        (item,) = await tool.invoke(arguments={"code": code, "language": language})
        print(language, "->", item.text)
        print(language, "labels", item.additional_properties)


if __name__ == "__main__":
    asyncio.run(main())
