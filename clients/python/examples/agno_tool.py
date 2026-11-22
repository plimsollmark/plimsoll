"""Agno + plimsoll: an Agno agent whose code runs in a plimsoll sandbox.

The smallest program that hands an Agno agent plimsoll's toolkit and has it run one piece
of code. Agno ships no fake model, so the model is a scripted stand-in written to Agno's
model interface: it asks for one run, then answers, so nothing here calls a model service.
To use a real model, pass it in place of `ScriptedModel()` (Agent(model=...), as usual).

Install:  pip install 'plimsoll-client[agno]'
Daemon:   a plimsolld that runs projects and has python3 in its project image. From a
          checkout, after `make docker-images` (docs/getting-started.md has every step):
              export PLIMSOLL_TOKEN=$(openssl rand -hex 16)   # 32 characters, the daemon's minimum
              SANDBOX_PROVIDER=docker SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python \\
              PLIMSOLL_ADDR=127.0.0.1:8746 go run ./cmd/plimsolld
Run:      in a shell with the same PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python agno_tool.py
          The tool refuses anything weaker than the kernel tier (Docker under gVisor). Plain
          Docker is the container tier: for your own code on your own machine only, add
          PLIMSOLL_MIN_ISOLATION=container.
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon.
"""

import json
import os

from agno.agent import Agent
from agno.models.base import Model
from agno.models.response import ModelResponse
from plimsoll_client import Client
from plimsoll_client.agno import PlimsollTools
from plimsoll_client.execution import CodeExecutor

CODE = "import platform\nprint('6 x 7 =', 6 * 7, 'on Python', platform.python_version())"


class ScriptedModel(Model):
    """Asks for one plimsoll_run_code call, then, once the tool's answer is in the
    conversation, answers with a sentence."""

    def __init__(self) -> None:
        super().__init__(id="scripted", name="scripted", provider="none")

    def invoke(self, messages, **kwargs) -> ModelResponse:
        if any(m.role == "tool" for m in messages):
            return ModelResponse(role="assistant", content="The tool's answer is above.")
        call = {"id": "call_1", "type": "function", "function": {"name": "plimsoll_run_code", "arguments": json.dumps({"code": CODE})}}
        return ModelResponse(role="assistant", tool_calls=[call])

    async def ainvoke(self, messages, **kwargs) -> ModelResponse:
        return self.invoke(messages, **kwargs)

    def invoke_stream(self, messages, **kwargs):
        yield self.invoke(messages, **kwargs)

    async def ainvoke_stream(self, messages, **kwargs):
        yield self.invoke(messages, **kwargs)

    def _parse_provider_response(self, response, **kwargs) -> ModelResponse:
        return response

    def _parse_provider_response_delta(self, response) -> ModelResponse:
        return response


def main() -> None:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    executor = CodeExecutor(client, minimum_isolation=os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel"))
    # telemetry=False: Agno otherwise reports each run to its own service.
    agent = Agent(model=ScriptedModel(), tools=[PlimsollTools(executor)], telemetry=False)
    run = agent.run("What is 6 x 7? Check it by running code.")
    for message in run.messages or []:
        if message.role == "tool":
            # JSON: ran (true, false or "unknown"), stdout, exit_code, isolation, record_sha256, ...
            print("plimsoll answered:", message.content)
    print("the agent said:", run.content)


if __name__ == "__main__":
    main()
