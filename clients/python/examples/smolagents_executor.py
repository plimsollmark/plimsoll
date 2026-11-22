"""smolagents + plimsoll: a CodeAgent whose Python runs in one plimsoll session.

The smallest program that gives a smolagents CodeAgent plimsoll's executor and has it run two
steps, the second using a variable the first set. smolagents' CodeAgent acts by writing Python;
here the model is a scripted stand-in written to smolagents' model interface (Model, whose
subclasses implement generate): it answers each step with a block of Python, so nothing here
calls a model service. To use a real model, replace `ScriptedModel()` below with any smolagents
model, such as InferenceClientModel or LiteLLMModel.

Install:  pip install smolagents-plimsoll
          Or from a checkout of the repository:
          pip install ./clients/python ./clients/python/smolagents-plimsoll
Daemon:   a plimsolld with sessions on and Python in its project image. From a checkout, after
          `make docker-images` (docs/getting-started.md has every step):
              export PLIMSOLL_TOKEN=$(openssl rand -hex 16)   # 32 characters, the daemon's minimum
              SANDBOX_PROVIDER=docker SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python \\
              SANDBOX_MAX_SESSIONS=4 PLIMSOLL_ADDR=127.0.0.1:8746 go run ./cmd/plimsolld
Run:      in a shell with the same PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python smolagents_executor.py
          The executor refuses anything weaker than the kernel tier (Docker under gVisor). Plain
          Docker is the container tier: for your own code on your own machine only, add
          PLIMSOLL_MIN_ISOLATION=container.
Network:  smolagents' own network calls are in its web tools and its other executors, which this
          program does not use, so it reaches nothing but the daemon.
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon.
"""

import os

from smolagents import AgentLogger, LogLevel
from smolagents.memory import ActionStep
from smolagents.models import ChatMessage, MessageRole, Model

from plimsoll_client import Client
from plimsoll_client.smolagents import PlimsollExecutor, code_agent

STEPS = [
    "import sys\nanswer = 6 * 7\nprint('6 x 7 =', answer, 'in Python', sys.version.split()[0])",
    "final_answer(answer)",
]


class ScriptedModel(Model):
    """Answers each step with the next block of Python, in the form smolagents reads a model's
    code from (between <code> tags)."""

    def __init__(self) -> None:
        super().__init__(model_id="scripted")
        self.turn = 0

    def generate(self, messages, stop_sequences=None, response_format=None, tools_to_call_from=None, **kwargs):
        code = STEPS[min(self.turn, len(STEPS) - 1)]
        self.turn += 1
        return ChatMessage(role=MessageRole.ASSISTANT, content=f"Thought: work it out in Python.\n<code>\n{code}\n</code>")


def main() -> None:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    # The floor has no default: below it, the session is closed and nothing of the agent's runs.
    executor = PlimsollExecutor([], AgentLogger(LogLevel.OFF), client=client,
                                minimum_isolation=os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel"))
    # code_agent stops the run at the sandbox's first failure and raises plimsoll's error; the
    # with block closes the session.
    with code_agent(executor, tools=[], model=ScriptedModel(), max_steps=4, verbosity_level=LogLevel.OFF) as agent:
        answer = agent.run("What is 6 x 7? Work it out in Python.")
    for step in agent.memory.steps:
        if isinstance(step, ActionStep):
            print(f"the model saw, after step {step.step_number}:", repr(step.observations))
    print("the agent said:", answer)
    # What plimsoll stated about each cell the client checked, in order: the executor's own setup
    # cell, the tools' definitions, then each step. Nothing of it comes from what the code printed.
    for i, cell in enumerate(executor.records):
        print(f"plimsoll stated, cell {i + 1}: isolation {cell.isolation}, {cell.outcome}, record sha256 {cell.record_sha256}")
    # The records are the session's chain: the last one is where the chain the client checked ends.
    print("the last record ends the session's chain:", executor.records[-1].record_sha256 == executor.session.last_record_sha256)


if __name__ == "__main__":
    main()
