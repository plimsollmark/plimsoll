"""Run a smolagents CodeAgent's code in plimsoll.

    from smolagents import AgentLogger, LogLevel
    from smolagents_plimsoll import Client, PlimsollExecutor, code_agent

    executor = PlimsollExecutor([], AgentLogger(LogLevel.INFO),
                                client=Client("https://plimsoll.internal:8746", token=TOKEN),
                                minimum_isolation="kernel")
    with code_agent(executor, tools=[], model=model) as agent:   # closes the session after
        print(agent.run("..."))

The names are plimsoll-client's own, gathered here so an agent imports from one place:
PlimsollExecutor is plimsoll_client.smolagents.PlimsollExecutor (one plimsoll session as the
agent's Python executor), code_agent is plimsoll_client.smolagents.code_agent (a CodeAgent that
stops at the sandbox's first failure and raises plimsoll's error), PlimsollCellRecord is
plimsoll_client.smolagents.PlimsollCellRecord (what plimsoll states about each cell, in
executor.records), and Client is plimsoll_client.Client. The executor's floor,
minimum_isolation, has no default: it is set in your code and checked before any of the
agent's code is sent.
"""

from plimsoll_client import Client
from plimsoll_client.smolagents import PlimsollCellRecord, PlimsollExecutor, code_agent

__all__ = ["Client", "PlimsollCellRecord", "PlimsollExecutor", "code_agent"]
__version__ = "0.30.0"
