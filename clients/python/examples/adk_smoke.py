"""No model API: real ADK executor, local Docker/gVisor, files and checked records."""

import asyncio
import base64
import json
import os
from urllib.parse import urlsplit

from google.adk.agents import Agent
from google.adk.artifacts import InMemoryArtifactService
from google.adk.code_executors.code_execution_utils import CodeExecutionInput, File
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from plimsoll_client import Client
from plimsoll_client.adk import PlimsollCodeExecutor


class ScriptedModel(BaseLlm):
    model: str = "offline-scripted-model"

    async def generate_content_async(self, llm_request, stream=False):
        has_result = "```tool_output" in str(llm_request.contents)
        text = "Done." if has_result else "```python\nprint(40 + 2)\n```"
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))


async def framework_roundtrip(executor):
    sessions = InMemorySessionService()
    session = await sessions.create_session(app_name="local-smoke", user_id="offline")
    runner = Runner(agent=Agent(name="calculator", model=ScriptedModel(), code_executor=executor),
                    app_name="local-smoke", session_service=sessions, artifact_service=InMemoryArtifactService())
    outputs = []
    async for event in runner.run_async(user_id="offline", session_id=session.id,
                                       new_message=types.Content(role="user", parts=[types.Part(text="Calculate 40 + 2.")])):
        if event.content:
            outputs.extend(part.code_execution_result.output for part in event.content.parts if part.code_execution_result)
    assert len(outputs) == 1 and "42" in outputs[0], outputs
    return outputs[0]


def main():
    url = os.environ["PLIMSOLL_URL"]
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise RuntimeError("This no-spend example requires a loopback HTTP daemon")
    client = Client(url, token=os.environ.get("PLIMSOLL_TOKEN"))
    if client.describe().provider != "docker":
        raise RuntimeError("This no-spend example requires the local Docker provider")
    executor = PlimsollCodeExecutor(client=client, artifact_paths=("answer.bin",))
    result = executor.execute_code(None, CodeExecutionInput(
        code="import csv\nprint(sum(int(r['value']) for r in csv.DictReader(open('data.csv'))))\n"
             "open('answer.bin', 'wb').write(bytes([0, 255]))",
        input_files=[File(name="data.csv", content=base64.b64encode(b"value\n20\n22\n").decode(), mime_type="text/csv")]))
    assert result.stdout.strip() == "42", result
    assert result.exit_code == 0 and not result.stderr, result
    assert result.output_files[0].content == bytes([0, 255]), result.output_files
    assert result.execution.isolation == "kernel", result.execution.isolation
    assert result.execution.record is not None
    native_output = asyncio.run(framework_roundtrip(executor))
    print(json.dumps({"framework": "Google ADK", "model": "scripted; no inference service",
        "stdout": result.stdout, "exit_code": result.exit_code, "isolation": result.execution.isolation,
        "artifact_hex": result.output_files[0].content.hex(), "fresh": True,
        "record_sha256": result.execution.record.sha256, "runner_output": native_output}, indent=2))


if __name__ == "__main__":
    main()
