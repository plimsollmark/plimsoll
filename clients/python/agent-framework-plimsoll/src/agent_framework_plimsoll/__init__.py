"""Run a Microsoft Agent Framework agent's shell commands and code in plimsoll.

    from agent_framework import create_harness_agent
    from agent_framework_plimsoll import Client, PlimsollShellTool

    async with PlimsollShellTool(Client("https://plimsoll.internal:8746", token=TOKEN),
                                 minimum_isolation="kernel") as shell:
        agent = create_harness_agent(chat_client, shell_executor=shell)

    from agent_framework_plimsoll import CodeExecutor, plimsoll_code_tool

    tools = [plimsoll_code_tool(CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN)))]

The names are plimsoll-client's own, gathered here so an agent imports from one place:
PlimsollShellTool is plimsoll_client.agent_framework.PlimsollShellTool (one plimsoll session as
the agent's shell), plimsoll_code_tool is plimsoll_client.agent_framework.plimsoll_code_tool (a
fresh sandbox per call), Client is plimsoll_client.Client and CodeExecutor is
plimsoll_client.execution.CodeExecutor. PlimsollShellResult is what the shell tool's run returns
(the framework's ShellResult with the tier, the provider's sentence, the outcome and the checked
run record), and call_labels gives plimsoll's closed-set labels for a result or a raised refusal,
as each function result carries them in additional_properties. The shell tool's floor, minimum_isolation, has no
default: it is set in your code and checked before any command is sent. CodeExecutor requires
the kernel isolation tier by default and refuses, before any code is sent, a daemon that states
less.
"""

from plimsoll_client import Client
from plimsoll_client.agent_framework import PlimsollShellResult, PlimsollShellTool, call_labels, plimsoll_code_tool
from plimsoll_client.execution import CodeExecutor

__all__ = ["Client", "CodeExecutor", "PlimsollShellResult", "PlimsollShellTool", "call_labels", "plimsoll_code_tool"]
__version__ = "0.29.0"
