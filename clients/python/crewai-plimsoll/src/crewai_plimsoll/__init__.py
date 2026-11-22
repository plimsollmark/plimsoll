"""Run a CrewAI agent's code in plimsoll.

    from crewai import Agent
    from crewai_plimsoll import Client, CodeExecutor, PlimsollCodeTool

    executor = CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN))
    agent = Agent(role=..., goal=..., backstory=..., tools=[PlimsollCodeTool(executor)])

The names are plimsoll-client's own, gathered here so a crew imports from one place:
PlimsollCodeTool is plimsoll_client.crewai.PlimsollCodeTool, Client is plimsoll_client.Client,
and CodeExecutor is plimsoll_client.execution.CodeExecutor. CodeExecutor requires the kernel
isolation tier by default and refuses, before any code is sent, a daemon that states less.
"""

from plimsoll_client import Client
from plimsoll_client.crewai import PlimsollCodeTool
from plimsoll_client.execution import CodeExecutor

__all__ = ["Client", "CodeExecutor", "PlimsollCodeTool"]
__version__ = "0.28.0"
