"""LangChain + plimsoll, with a grant: the code tool's programs can call one web API.

As crewai_grant.py, through LangChain's own tool-call path (a ToolCall answered with a
ToolMessage, as ToolNode and create_agent drive it), so nothing calls a model service.
Install: pip install langchain-plimsoll. Checked: clients/python/examples_docker_test.go runs
this file against a real docker daemon and a stand-in for the API.
"""

from langchain_core.messages import ToolCall

from plimsoll_client.langchain import PlimsollCodeTool

from _granted import JS, PY, executor


def main() -> None:
    tool = PlimsollCodeTool(executor())
    print("the model is told of:", tool.description.split("The API:\n", 1)[1].splitlines()[0])
    for i, (code, language) in enumerate(((JS, "javascript"), (PY, "python"))):
        message = tool.invoke(ToolCall(name=tool.name, args={"code": code, "language": language}, id=f"call-{i}", type="tool_call"))
        print(language, "->", message.content)


if __name__ == "__main__":
    main()
