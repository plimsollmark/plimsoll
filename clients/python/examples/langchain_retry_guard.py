"""LangGraph's retries and LangSmith's labels with plimsoll: which failures may run again, and
what a traced tool call says about its run.

Part 1, the retry guard. LangGraph retries a node only when you give it a RetryPolicy, and its
default rule then retries a PlimsollError even when nothing says the code did not run.
plimsoll_client.retry_on is the rule to give it instead: true only for a refusal marked
not dispatched with the reason capacity or environment, where nothing ran and another try may
pass. A graph with one node that runs code on the daemon is driven three times: once after a
capacity refusal (a stand-in, raised by the node on its first try: a real one needs a daemon
at its limit), which retry_on retries and the second try runs; once after an answer lost once
the request was sent (a stand-in too: the code may have run), which retry_on never retries
and LangGraph's default rule would; and once with a floor above the daemon's tier, a real refusal
before anything is sent to a sandbox (marked isolation: a stronger backend is a placement
decision, not a retry).

Part 2, the LangSmith labels. When a tool call is traced in LangSmith, PlimsollCodeTool adds
metadata to the call's own run: whether it was dispatched, the outcome, the isolation tier,
the record's SHA-256. The call is traced here by LangChain's own LangSmith tracer with its two
upload methods replaced by lists in memory, so the labels are printed as LangSmith would
receive them and nothing is sent to LangSmith.

Nothing calls a model service or anything but the local daemon.

Install:  pip install 'plimsoll-client[langchain]' langgraph
          From a checkout of the repository: pip install './clients/python[langchain]' langgraph
Daemon:   a plimsolld that runs projects and has python3 in its project image, as
          langchain_tool.py says (docs/getting-started.md has every step).
Run:      in a shell with the daemon's PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python langchain_retry_guard.py
          The runs refuse anything weaker than the kernel tier (Docker under gVisor). Plain
          Docker is the container tier: for your own code on your own machine only, add
          PLIMSOLL_MIN_ISOLATION=container.
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon.
"""

import json
import os
from typing import Optional, TypedDict

from langchain_core.messages import ToolCall
from langchain_core.tracers.langchain import LangChainTracer
from langgraph.graph import END, START, StateGraph
from langgraph.types import RetryPolicy

from plimsoll_client import AtCapacityError, Client, PlimsollError, TransportError, retry_on
from plimsoll_client.execution import CodeExecutor
from plimsoll_client.langchain import PlimsollCodeTool

CODE = "print('6 x 7 =', 6 * 7)"
TIERS = ("process", "container", "kernel", "vm")


class State(TypedDict, total=False):
    out: str


def graph_with(client: Client, floor: str, first_try_raises: Optional[PlimsollError], tries: list):
    """One node that runs CODE as a project; on its first try it raises first_try_raises, if
    given, as the client would. tries counts the node's runs."""

    def run(state: State) -> State:
        tries.append(1)
        if first_try_raises is not None and len(tries) == 1:
            raise first_try_raises
        result = client.run_project({"main.py": CODE}, ["python3 main.py"], minimum_isolation=floor)
        return {"out": result.steps[-1].stdout_text.strip()}

    builder = StateGraph(State)
    builder.add_node("run", run, retry_policy=RetryPolicy(retry_on=retry_on, initial_interval=0.01, jitter=False))
    builder.add_edge(START, "run")
    builder.add_edge("run", END)
    return builder.compile()


def drive(name: str, client: Client, floor: str, first_try_raises: Optional[PlimsollError] = None) -> None:
    tries: list = []
    try:
        out = graph_with(client, floor, first_try_raises, tries).invoke({})["out"]
    except PlimsollError as e:
        out = f"raised {type(e).__name__} (not_dispatched={e.not_dispatched})"
        error = e
    else:
        error = first_try_raises
    if error is not None:
        print(f"{name}: retry_on says {retry_on(error)}, LangGraph's default rule says {RetryPolicy().retry_on(error)}")
    print(f"{name}: the node ran {len(tries)} time(s): {out}")


class KeptTracer(LangChainTracer):
    """LangChain's LangSmith tracer, each run kept in memory where it would be uploaded."""

    def __init__(self) -> None:
        super().__init__(client=object())  # never used: the two methods below replace the uploads
        self.ended: list = []

    def _persist_run_single(self, run) -> None:
        pass

    def _update_run_single(self, run) -> None:  # type: ignore[override]
        self.ended.append(run)


def main() -> None:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    floor = os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel")

    print("Part 1: the retry guard")
    drive("capacity refusal (stand-in)", client, floor, AtCapacityError("shed by admission", not_dispatched="capacity"))
    drive("answer lost after sending (stand-in)", client, floor, TransportError("the connection closed before the answer"))
    tier = client.describe().isolation
    if tier in TIERS[:-1]:
        drive(f"floor above the daemon's {tier} tier (real)", client, TIERS[TIERS.index(tier) + 1])
    else:
        print(f"the daemon is at the {tier} tier, the strongest: no real refusal to show")

    print("Part 2: the LangSmith labels")
    tool = PlimsollCodeTool(CodeExecutor(client, minimum_isolation=floor))
    tracer = KeptTracer()
    message = tool.invoke(ToolCall(name=tool.name, args={"code": CODE, "language": "python"}, id="call_1", type="tool_call"),
                          config={"callbacks": [tracer]})
    print("the tool answered the model:", json.loads(message.content)["stdout"].strip())
    run = next(r for r in tracer.ended if r.name == tool.name)
    labels = {k: v for k, v in (run.extra or {}).get("metadata", {}).items() if k.startswith("plimsoll_")}
    print("the labels on the tool call's LangSmith run:", json.dumps(labels, sort_keys=True))


if __name__ == "__main__":
    main()
