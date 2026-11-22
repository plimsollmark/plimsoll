"""CrewAI + plimsoll: a CrewAI agent whose code runs in a plimsoll sandbox.

The smallest program that hands a CrewAI agent plimsoll's code tool and has it run one piece
of code. CrewAI ships no fake model, so the model is a scripted stand-in written to CrewAI's
custom-model interface (BaseLLM): it asks for one run in CrewAI's text format, then answers
with what the tool returned, so nothing here calls a model service. To use a real model,
pass it as llm= in place of `ScriptedLLM()`, as for any CrewAI agent.

Install:  pip install crewai-plimsoll
Daemon:   a plimsolld that runs projects and has python3 in its project image. From a
          checkout, after `make docker-images` (docs/getting-started.md has every step):
              export PLIMSOLL_TOKEN=$(openssl rand -hex 16)   # 32 characters, the daemon's minimum
              SANDBOX_PROVIDER=docker SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python \\
              PLIMSOLL_ADDR=127.0.0.1:8746 go run ./cmd/plimsolld
Run:      in a shell with the same PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python crewai_tool.py
          The tool refuses anything weaker than the kernel tier (Docker under gVisor). Plain
          Docker is the container tier: for your own code on your own machine only, add
          PLIMSOLL_MIN_ISOLATION=container.
Network:  the program turns off CrewAI's telemetry and its trace collection (the three
          variables set below, unless you set them first), so it reaches nothing but the daemon.
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon.
"""

import json
import os

for name, value in (("CREWAI_DISABLE_TELEMETRY", "true"), ("OTEL_SDK_DISABLED", "true"), ("CREWAI_TRACING_ENABLED", "false")):
    os.environ.setdefault(name, value)

from crewai import Agent  # noqa: E402  (after the telemetry switches, which CrewAI reads at import)
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai_plimsoll import Client, CodeExecutor, PlimsollCodeTool  # noqa: E402

CODE = "import platform\nprint('6 x 7 =', 6 * 7, 'on Python', platform.python_version())"


class ScriptedLLM(BaseLLM):
    """Asks for one plimsoll_run_code call, then, once the tool's answer is in the
    conversation, gives it as the final answer."""

    def __init__(self) -> None:
        super().__init__(model="scripted")

    def call(self, messages, tools=None, callbacks=None, available_functions=None, **kwargs):
        text = messages if isinstance(messages, str) else "\n".join(str(m.get("content", "")) for m in messages)
        if '"ran":' in text:  # the tool's JSON answer, which CrewAI adds after "Observation:"
            observation = text.rsplit("Observation:", 1)[1].strip().splitlines()[0]
            return f"Thought: The sandbox answered.\nFinal Answer: plimsoll answered: {observation}"
        return "Thought: I should check by running code.\nAction: plimsoll_run_code\nAction Input: " + json.dumps({"code": CODE})

    def supports_function_calling(self) -> bool:
        return False  # the text format above, rather than native tool calls


def main() -> None:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    executor = CodeExecutor(client, minimum_isolation=os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel"))
    agent = Agent(role="Calculator", goal="Answer arithmetic questions, checked by running code.",
                  backstory="You check every answer in a sandbox.", tools=[PlimsollCodeTool(executor)],
                  llm=ScriptedLLM(), verbose=False)
    result = agent.kickoff("What is 6 x 7? Check it by running code.")
    # JSON from the tool: ran (true, false or "unknown"), stdout, exit_code, isolation, record_sha256, ...
    print("the agent said:", result.raw)


if __name__ == "__main__":
    main()
