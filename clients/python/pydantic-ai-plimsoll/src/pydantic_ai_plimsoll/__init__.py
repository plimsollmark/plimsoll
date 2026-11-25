"""Give a PydanticAI agent run one plimsoll session as its workspace.

    from pydantic_ai import Agent
    from pydantic_ai_harness import FileSystem
    from pydantic_ai_plimsoll import Client, PlimsollWorkspace

    workspace = PlimsollWorkspace(client=Client("https://plimsoll.internal:8746", token=TOKEN),
                                  minimum_isolation="kernel")
    agent = Agent(model, capabilities=[workspace, FileSystem()])

    from pydantic_ai_plimsoll import CodeExecutor, plimsoll_code_tool

    tools = [plimsoll_code_tool(CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN)))]

The names are plimsoll-client's own, gathered here so an agent imports from one place: PlimsollWorkspace is
plimsoll_client.pydantic_ai.PlimsollWorkspace (the capability: one session as the run's workspace, files only, and
plimsoll's shell tool over it), PlimsollWorkspaceBackend its workspace backend, plimsoll_code_tool the code tool (a
fresh sandbox per call), the errors plimsoll_client.pydantic_ai's (a call that may have run, and its subclass for a
refused repeat of a call lost before a takeover; a session gone; a refusal another try may pass), JsonLinesRecordSink the file sink for checked records, Client plimsoll_client.Client
and CodeExecutor plimsoll_client.execution.CodeExecutor. The workspace's floor, minimum_isolation, has no default:
it is set in your code and checked before anything runs. CodeExecutor requires the kernel isolation tier by default.
"""

from plimsoll_client import Client
from plimsoll_client.execution import CodeExecutor
from plimsoll_client.pydantic_ai import (
    JsonLinesRecordSink,
    PlimsollLostCallError,
    PlimsollOutcomeUnknownError,
    PlimsollRetryableError,
    PlimsollWorkspace,
    PlimsollWorkspaceBackend,
    PlimsollWorkspaceGoneError,
    plimsoll_code_tool,
)

__all__ = [
    "Client",
    "CodeExecutor",
    "JsonLinesRecordSink",
    "PlimsollLostCallError",
    "PlimsollOutcomeUnknownError",
    "PlimsollRetryableError",
    "PlimsollWorkspace",
    "PlimsollWorkspaceBackend",
    "PlimsollWorkspaceGoneError",
    "plimsoll_code_tool",
]
__version__ = "0.29.0"
