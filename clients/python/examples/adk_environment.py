"""Google ADK + plimsoll: an ADK agent with a kept sandbox, its shell and files in one plimsoll session.

The smallest program that gives an ADK agent ADK's own environment tools (Execute, ReadFile,
EditFile, WriteFile, from EnvironmentToolset) over plimsoll's environment: the agent writes a
script, runs it, edits it and runs it again, and the file is still there between the calls.
The model is a scripted stand-in written to ADK's custom-model interface (BaseLlm), so nothing
here calls a model service. To use a real model, pass your model in place of `ScriptedModel()`,
as for any ADK agent.

Install:  pip install 'plimsoll-client[adk]'
Daemon:   a plimsolld with sessions on and python3 in its project image. From a checkout,
          after `make docker-images` (docs/getting-started.md has every step):
              export PLIMSOLL_TOKEN=$(openssl rand -hex 16)   # 32 characters, the daemon's minimum
              SANDBOX_PROVIDER=docker SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python \\
              SANDBOX_MAX_SESSIONS=4 PLIMSOLL_ADDR=127.0.0.1:8746 go run ./cmd/plimsolld
Run:      in a shell with the same PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python adk_environment.py
          The environment refuses anything weaker than the kernel tier (Docker under gVisor).
          Plain Docker is the container tier: for your own code on your own machine only,
          add PLIMSOLL_MIN_ISOLATION=container.
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon.
"""

import asyncio
import os

from google.adk.agents import Agent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.environment import EnvironmentToolset
from google.genai import types
from plimsoll_client import Client
from plimsoll_client.adk import PlimsollEnvironment, PlimsollEnvironmentGuard

# What the stand-in model asks for, one answer per turn: write a script, run it, edit it, run it again.
TURNS = [
    ("WriteFile", {"path": "answer.py", "content": "print('6 x 7 =', 6 * 7)\n"}),
    ("Execute", {"command": "python3 answer.py"}),
    ("EditFile", {"path": "answer.py", "old_string": "'6 x 7 =', 6 * 7", "new_string": "'7 x 6 =', 7 * 6"}),
    ("Execute", {"command": "python3 answer.py"}),
]


class ScriptedModel(BaseLlm):
    """Makes the calls in TURNS, one a turn, then answers with a sentence."""

    model: str = "scripted"

    async def generate_content_async(self, llm_request, stream=False):
        turn = sum(1 for c in llm_request.contents if c.role == "model")
        if turn < len(TURNS):
            name, args = TURNS[turn]
            part = types.Part(function_call=types.FunctionCall(name=name, args=args))
        else:
            part = types.Part(text="The script ran twice, and the file was there both times.")
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


async def main() -> None:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    # The session opens when the agent first runs, at this floor, and closes with the Runner.
    environment = PlimsollEnvironment(client, minimum_isolation=os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel"))
    agent = Agent(name="scripter", model=ScriptedModel(), tools=[EnvironmentToolset(environment=environment)])
    sessions = InMemorySessionService()
    session = await sessions.create_session(app_name="example", user_id="me")
    # The guard goes first: it ties each plimsoll call to its tool call, labels ADK's trace,
    # and stops the agent after a call that may have run without an answer.
    async with Runner(agent=agent, app_name="example", session_service=sessions,
                      plugins=[PlimsollEnvironmentGuard()]) as runner:
        question = types.Content(role="user", parts=[types.Part(text="Work out 6 x 7 with a script.")])
        async for event in runner.run_async(user_id="me", session_id=session.id, new_message=question):
            for part in (event.content.parts if event.content else []):
                if part.function_response:
                    print(f"{part.function_response.name}:", part.function_response.response)
                elif part.text and event.author == "scripter":
                    print("the agent said:", part.text)
        # What plimsoll stated about every call it made, the work directory's first one included.
        for call in environment.calls:
            print(f"plimsoll: {call.method} ran behind {call.isolation}, record {call.record_sha256}")


if __name__ == "__main__":
    asyncio.run(main())
