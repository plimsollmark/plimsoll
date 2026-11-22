"""OpenAI Agents SDK + plimsoll: a SandboxAgent whose workspace is one plimsoll session.

The smallest program that hands the Agents SDK plimsoll as its sandbox provider and has the
agent run one command there. The model is a scripted stand-in written to the SDK's model
interface: it asks for one shell command, then answers with what the command printed, so
nothing here calls a model service. The SDK also ships a test model,
`agents.testing.ScriptedModel`, which plimsoll's own tests of the provider use
(clients/python/frameworks/openai_agents/). To use a real model,
drop `model=ScriptedModel()` from the agent (the SDK then uses its default model and your
OPENAI_API_KEY) or pass any model the SDK supports.

Install:  pip install 'plimsoll-client[openai-agents]'
          Releases up to 0.27.2 fail as the SDK starts the sandbox (TypeError in running());
          use 0.28.0 or later, or from a checkout of the repository:
          pip install './clients/python[openai-agents]'
Daemon:   a plimsolld with sessions on and python3 in its project image. From a checkout,
          after `make docker-images` (docs/getting-started.md has every step):
              export PLIMSOLL_TOKEN=$(openssl rand -hex 16)   # 32 characters, the daemon's minimum
              SANDBOX_PROVIDER=docker SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python \\
              SANDBOX_MAX_SESSIONS=4 PLIMSOLL_ADDR=127.0.0.1:8746 go run ./cmd/plimsolld
Run:      in a shell with the same PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python openai_agents_sandbox.py
          The session refuses anything weaker than the kernel tier (Docker under gVisor).
          Plain Docker is the container tier: for your own code on your own machine only,
          add PLIMSOLL_MIN_ISOLATION=container.
Network:  tracing is off for this run (the SDK otherwise sends traces to OpenAI), so the
          program reaches nothing but the daemon.
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon.
"""

import asyncio
import json
import os

from agents import Runner, RunConfig
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.sandbox import SandboxAgent
from agents.run_config import SandboxRunConfig
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText
from plimsoll_client import Client
from plimsoll_client.openai_sandbox import PlimsollSandboxClient, PlimsollSandboxClientOptions

COMMAND = "python3 -c \"import platform; print('6 x 7 =', 6 * 7, 'on Python', platform.python_version())\""


class ScriptedModel(Model):
    """Asks for one exec_command call, then, once its output is in the conversation,
    answers with that output."""

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs,
                           tracing, *, previous_response_id=None, conversation_id=None, prompt=None):
        outputs = [item.get("output") for item in input if isinstance(item, dict) and item.get("type") == "function_call_output"]
        if outputs:
            text = ResponseOutputText(type="output_text", text=f"The sandbox answered: {outputs[-1]}", annotations=[])
            item = ResponseOutputMessage(id="msg_1", type="message", role="assistant", status="completed", content=[text])
        else:
            item = ResponseFunctionToolCall(type="function_call", call_id="call_1", name="exec_command",
                                            arguments=json.dumps({"cmd": COMMAND}))
        return ModelResponse(output=[item], usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):
        raise NotImplementedError("this scripted model answers Runner.run, not Runner.run_streamed")


async def main() -> None:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    options = PlimsollSandboxClientOptions(minimum_isolation=os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel"))
    agent = SandboxAgent(name="calculator", instructions="Check answers by running commands.", model=ScriptedModel())
    run_config = RunConfig(sandbox=SandboxRunConfig(client=PlimsollSandboxClient(client), options=options),
                           tracing_disabled=True)
    result = await Runner.run(agent, "What is 6 x 7? Check it by running a command.", run_config=run_config)
    print("the agent said:", result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
