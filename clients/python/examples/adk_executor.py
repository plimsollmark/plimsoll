"""Google ADK + plimsoll: an ADK agent whose code blocks run in a plimsoll sandbox.

The smallest program that hands an ADK agent plimsoll's code executor and has it run one
Python block. The model is a scripted stand-in written to ADK's custom-model interface
(BaseLlm): it answers with one block, then with a sentence, so nothing here calls a model
service. To use a real model, pass your model in place of `ScriptedModel()`, as for any
ADK agent.

Install:  pip install 'plimsoll-client[adk]'
Daemon:   a plimsolld that runs projects and has python3 in its project image. From a
          checkout, after `make docker-images` (docs/getting-started.md has every step):
              export PLIMSOLL_TOKEN=$(openssl rand -hex 16)   # 32 characters, the daemon's minimum
              SANDBOX_PROVIDER=docker SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python \\
              PLIMSOLL_ADDR=127.0.0.1:8746 go run ./cmd/plimsolld
Run:      in a shell with the same PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python adk_executor.py
          The executor refuses anything weaker than the kernel tier (Docker under gVisor).
          Plain Docker is the container tier: for your own code on your own machine only,
          add PLIMSOLL_MIN_ISOLATION=container.
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon.
          examples/adk_smoke.py is the stricter check of files, artifacts and the kernel floor.
"""

import asyncio
import os

from google.adk.agents import Agent
from google.adk.artifacts import InMemoryArtifactService
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from plimsoll_client import Client
from plimsoll_client.adk import PlimsollCodeExecutor, PlimsollCodeExecutorGuard


class ScriptedModel(BaseLlm):
    """Answers with one Python block, then, once the block's output is in the
    conversation, with a sentence."""

    model: str = "scripted"

    async def generate_content_async(self, llm_request, stream=False):
        ran = "```tool_output" in str(llm_request.contents)
        text = "The block's result is above." if ran else "```python\nprint('6 x 7 =', 6 * 7)\n```"
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))


async def main() -> None:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    executor = PlimsollCodeExecutor(client=client, minimum_isolation=os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel"))
    agent = Agent(name="calculator", model=ScriptedModel(), code_executor=executor)
    sessions = InMemorySessionService()
    session = await sessions.create_session(app_name="example", user_id="me")
    # The guard goes first: it refuses ADK settings that would bypass plimsoll, and tells
    # the model how to write a block. ADK saves every result through the artifact service.
    runner = Runner(agent=agent, app_name="example", session_service=sessions,
                    artifact_service=InMemoryArtifactService(), plugins=[PlimsollCodeExecutorGuard()])
    question = types.Content(role="user", parts=[types.Part(text="What is 6 x 7? Check it by running code.")])
    async for event in runner.run_async(user_id="me", session_id=session.id, new_message=question):
        for part in (event.content.parts if event.content else []):
            if part.code_execution_result:
                print("plimsoll ran the block:", part.code_execution_result.outcome, repr(part.code_execution_result.output))
            elif part.text and event.author == "calculator" and not part.text.startswith("```"):
                print("the agent said:", part.text)


if __name__ == "__main__":
    asyncio.run(main())
