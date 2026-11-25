"""PydanticAI + plimsoll: an agent whose workspace is one plimsoll session.

The smallest program that gives a PydanticAI agent a plimsoll session as its workspace: PydanticAI's own FileSystem
tool writes a file, and plimsoll's shell tool runs a command over it in the same sandbox. The model is PydanticAI's
FunctionModel with a scripted function (it asks for the two tools in turn, then answers), so nothing here calls a
model service. To use a real model, replace `FunctionModel(scripted)` below with a model name such as
"anthropic:claude-opus-5-5".

Install:  pip install pydantic-ai-plimsoll pydantic-ai-harness
Daemon:   a plimsolld with sessions on. From a checkout, after `make docker-images`
          (docs/getting-started.md has every step):
              export PLIMSOLL_TOKEN=$(openssl rand -hex 16)   # 32 characters, the daemon's minimum
              SANDBOX_PROVIDER=docker SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox \\
              SANDBOX_MAX_SESSIONS=4 PLIMSOLL_ADDR=127.0.0.1:8746 go run ./cmd/plimsolld
Run:      in a shell with the same PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python pydantic_ai_workspace.py
          The workspace refuses anything weaker than the kernel tier (Docker under gVisor). Plain
          Docker is the container tier: for your own code on your own machine only, add
          PLIMSOLL_MIN_ISOLATION=container.
Network:  PydanticAI sends no traces unless you configure Logfire or another OpenTelemetry exporter, so
          the program reaches nothing but the daemon.
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon.
"""

import asyncio
import os

from pydantic_ai import Agent
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai_harness import FileSystem
from plimsoll_client import Client
from plimsoll_client.pydantic_ai import PlimsollWorkspace

CALLS = [
    ("write_file", {"path": "answer.sh", "content": 'echo "6 x 7 = $((6 * 7))"\n'}),
    ("plimsoll_shell", {"command": "sh answer.sh"}),
]


def scripted(messages, info):
    """Asks for each tool call in turn, then answers."""
    turn = sum(isinstance(m, ModelResponse) for m in messages)
    if turn < len(CALLS):
        name, args = CALLS[turn]
        return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id=f"call_{turn}")])
    return ModelResponse(parts=[TextPart("The shell's answer is above.")])


async def main() -> None:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    workspace = PlimsollWorkspace(client=client, minimum_isolation=os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel"))
    agent = Agent(FunctionModel(scripted), capabilities=[workspace, FileSystem()])
    result = await agent.run("What is 6 x 7? Write a script that works it out, then run it in the shell.")
    for message in result.all_messages():
        for part in getattr(message, "parts", []):
            if isinstance(part, ToolReturnPart) and part.tool_name == "plimsoll_shell":
                print("the model saw:", repr(part.content))
                # What plimsoll stated about the command, for the application: whether it ran, how it ended, the
                # tier, and the SHA-256 of the run record the client checked.
                print("plimsoll stated:", {k: v for k, v in part.metadata.items() if k.startswith("plimsoll_")})
    print("the agent said:", result.output)
    # The run leaves the session open for the conversation's next run; this program has none, so it closes it.
    if result.workspace.ref is not None:
        workspace.destroy(result.workspace.ref)


if __name__ == "__main__":
    asyncio.run(main())
