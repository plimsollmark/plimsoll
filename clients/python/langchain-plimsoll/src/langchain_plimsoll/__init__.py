"""Run a LangChain, LangGraph or Deep Agents agent's code in plimsoll.

    from langchain_plimsoll import Client, CodeExecutor, PlimsollCodeTool

    executor = CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN))
    tools = [PlimsollCodeTool(executor)]          # create_agent, ToolNode, any LangGraph graph

    from langchain_plimsoll import PlimsollSandbox  # pip install 'langchain-plimsoll[deepagents]'

    with PlimsollSandbox.open(Client("https://plimsoll.internal:8746", token=TOKEN)) as backend:
        agent = create_deep_agent(model=..., backend=backend, system_prompt=f"Work in {backend.root}.")

    from langchain_plimsoll import retry_on       # LangGraph's RetryPolicy, LangChain's ToolRetryMiddleware

    builder.add_node("run", node, retry_policy=RetryPolicy(retry_on=retry_on))

The names are plimsoll-client's own, gathered here so an agent imports from one place:
PlimsollCodeTool is plimsoll_client.langchain.PlimsollCodeTool (a fresh sandbox per call),
PlimsollSandbox is plimsoll_client.deepagents.PlimsollSandbox (one plimsoll session as a Deep
Agents backend), Client is plimsoll_client.Client, CodeExecutor is
plimsoll_client.execution.CodeExecutor and retry_on is plimsoll_client.retry_on (retry only a
refusal that ran nothing and may pass on another try). Both require the kernel isolation tier
by default and refuse, before any code is sent, a daemon that states less.
"""

from typing import Any

from plimsoll_client import Client, retry_on
from plimsoll_client.execution import CodeExecutor
from plimsoll_client.langchain import PlimsollCodeTool

__all__ = ["Client", "CodeExecutor", "PlimsollCodeTool", "PlimsollSandbox", "retry_on"]
__version__ = "0.28.0"


def __getattr__(name: str) -> Any:
    # The backend needs deepagents, an extra: imported on first use, so the tool alone
    # needs only langchain-core.
    if name == "PlimsollSandbox":
        try:
            from plimsoll_client.deepagents import PlimsollSandbox
        except ImportError as e:
            raise ImportError("langchain_plimsoll.PlimsollSandbox needs Deep Agents: pip install 'langchain-plimsoll[deepagents]'") from e
        return PlimsollSandbox
    raise AttributeError(f"module 'langchain_plimsoll' has no attribute {name!r}")
