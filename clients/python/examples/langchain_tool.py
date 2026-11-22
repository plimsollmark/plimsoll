"""LangChain + plimsoll: a LangChain agent whose code runs in a plimsoll sandbox.

The smallest program that hands a LangChain agent plimsoll's code tool and has it run one
piece of code. The model is LangChain's own fake chat model, scripted to ask for one run and
then answer, so nothing here calls a model service. To use a real model, replace `model`
below with any LangChain chat model.

Install:  pip install 'plimsoll-client[langchain]' langchain   (0.28.0 and later)
          Or from a checkout of the repository: pip install './clients/python[langchain]' langchain
Daemon:   a plimsolld that runs projects and has python3 in its project image. From a
          checkout, after `make docker-images` (docs/getting-started.md has every step):
              export PLIMSOLL_TOKEN=$(openssl rand -hex 16)   # 32 characters, the daemon's minimum
              SANDBOX_PROVIDER=docker SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python \\
              PLIMSOLL_ADDR=127.0.0.1:8746 go run ./cmd/plimsolld
Run:      in a shell with the same PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python langchain_tool.py
          The tool refuses anything weaker than the kernel tier (Docker under gVisor). Plain
          Docker is the container tier: for your own code on your own machine only, add
          PLIMSOLL_MIN_ISOLATION=container.
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon.
"""

import os

from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from plimsoll_client import Client
from plimsoll_client.execution import CodeExecutor
from plimsoll_client.langchain import PlimsollCodeTool

CODE = "import platform\nprint('6 x 7 =', 6 * 7, 'on Python', platform.python_version())"


class ScriptedModel(GenericFakeChatModel):
    """LangChain's fake chat model answers with the messages it is given, in order.
    create_agent also asks it to bind the tools, which a script does not need."""

    def bind_tools(self, tools, **kwargs):
        return self


def main() -> None:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    executor = CodeExecutor(client, minimum_isolation=os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel"))
    model = ScriptedModel(messages=iter([
        AIMessage(content="", tool_calls=[{"name": "plimsoll_run_code", "args": {"code": CODE}, "id": "call_1", "type": "tool_call"}]),
        AIMessage(content="The tool's answer is above."),
    ]))
    agent = create_agent(model, tools=[PlimsollCodeTool(executor)])
    result = agent.invoke({"messages": [{"role": "user", "content": "What is 6 x 7? Check it by running code."}]})
    for message in result["messages"]:
        if message.type == "tool":
            # JSON: ran (true, false or "unknown"), stdout, exit_code, isolation, record_sha256, ...
            print("plimsoll answered:", message.content)
    print("the agent said:", result["messages"][-1].content)


if __name__ == "__main__":
    main()
