"""Microsoft Agent Framework + plimsoll: an agent whose shell is one plimsoll session.

The smallest program that hands an Agent Framework agent plimsoll's shell tool and has it run
two commands, the second reading the file the first wrote. Agent Framework ships no fake chat
client, so the model is a scripted stand-in written to the framework's chat client interface
(BaseChatClient, whose subclasses implement _inner_get_response): it asks for the two commands,
then answers, so nothing here calls a model service. To use a real model, replace `model` below
with any Agent Framework chat client.

Install:  pip install agent-framework-plimsoll
          Or from a checkout of the repository:
          pip install ./clients/python ./clients/python/agent-framework-plimsoll
Daemon:   a plimsolld with sessions on. From a checkout, after `make docker-images`
          (docs/getting-started.md has every step):
              export PLIMSOLL_TOKEN=$(openssl rand -hex 16)   # 32 characters, the daemon's minimum
              SANDBOX_PROVIDER=docker SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox \\
              SANDBOX_MAX_SESSIONS=4 PLIMSOLL_ADDR=127.0.0.1:8746 go run ./cmd/plimsolld
Run:      in a shell with the same PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python agent_framework_shell.py
          The shell refuses anything weaker than the kernel tier (Docker under gVisor). Plain
          Docker is the container tier: for your own code on your own machine only, add
          PLIMSOLL_MIN_ISOLATION=container.
Network:  Agent Framework exports no traces unless you configure an OpenTelemetry exporter, so
          the program reaches nothing but the daemon.
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon.
"""

import asyncio
import os

from agent_framework import Agent, BaseChatClient, ChatResponse, Content, FunctionInvocationLayer, Message
from plimsoll_client import Client
from plimsoll_client.agent_framework import PlimsollShellTool

COMMANDS = ['echo "6 x 7 = $((6 * 7))" > answer.txt', "cat answer.txt"]


class ScriptedModel(FunctionInvocationLayer, BaseChatClient):
    """Asks for each command in turn, then answers. FunctionInvocationLayer is the framework's
    own tool loop: it runs each tool call and hands the result back on the next request."""

    def __init__(self) -> None:
        super().__init__()
        self.turn = 0

    def _inner_get_response(self, *, messages, stream, options, **kwargs):
        async def answer():
            self.turn += 1
            if self.turn <= len(COMMANDS):
                call = Content.from_function_call(f"call_{self.turn}", "run_shell", arguments={"command": COMMANDS[self.turn - 1]})
                return ChatResponse(messages=[Message(role="assistant", contents=[call])])
            return ChatResponse(messages=[Message(role="assistant", contents=["The shell's answers are above."])])

        return answer()


async def main() -> None:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    async with PlimsollShellTool(client, minimum_isolation=os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel")) as shell:
        model = ScriptedModel()
        agent = Agent(client=model, tools=[shell.as_function()])
        response = await agent.run("What is 6 x 7? Work it out in the shell and keep the answer in a file.")
        for message in response.messages:
            for content in message.contents:
                if content.type == "function_result":
                    (item,) = content.items
                    print("the model saw:", repr(item.text))
                    # What plimsoll stated about the command, for the application: whether it ran,
                    # how it ended, the tier, and the SHA-256 of the run record the client checked.
                    print("plimsoll stated:", {k: v for k, v in item.additional_properties.items() if k.startswith("plimsoll_")})
        print("the agent said:", response.text)


if __name__ == "__main__":
    asyncio.run(main())
