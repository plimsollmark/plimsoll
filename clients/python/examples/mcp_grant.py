"""plimsoll's MCP server, installed with a grant: run_code's programs can call one web API.

Whoever installs the server sets PLIMSOLL_GRANT_PROFILE (a profile the operator configured
on the daemon) and PLIMSOLL_GRANT_DESCRIPTION_FILE (the description plimsoll-specgen wrote
for it); no tool argument names a profile. This program starts the server over stdio, as
an MCP host does, with the MCP Python SDK's client, and calls run_code twice without a
sandbox (those calls carry the grant) and once in a sandbox from open_sandbox (which never
does), so nothing calls a model service.

Install:  pip install mcp, and the plimsoll-mcp binary (npm install -g @plimsollmark/mcp,
          or go build ./cmd/plimsoll-mcp in clients/mcp); PLIMSOLL_MCP names it.
Run:      PLIMSOLL_URL=... PLIMSOLL_TOKEN=... PLIMSOLL_GRANT_PROFILE=lights \\
          PLIMSOLL_GRANT_DESCRIPTION_FILE=description.txt PLIMSOLL_MCP=plimsoll-mcp python mcp_grant.py
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon
          and a stand-in for the API.
"""

import asyncio
import json
import os

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from _granted import JS


async def main() -> None:
    names = ("PLIMSOLL_URL", "PLIMSOLL_TOKEN", "PLIMSOLL_MIN_ISOLATION", "PLIMSOLL_GRANT_PROFILE", "PLIMSOLL_GRANT_DESCRIPTION_FILE",
             "PLIMSOLL_INSECURE_HTTP", "PATH", "HOME")
    server = StdioServerParameters(command=os.environ.get("PLIMSOLL_MCP", "plimsoll-mcp"),
                                   env={n: os.environ[n] for n in names if n in os.environ})
    async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = {t.name: t for t in (await session.list_tools()).tools}
        print("the model is told of:", tools["run_code"].description.split("The API:\n", 1)[1].splitlines()[0])
        for code, language in ((JS, "javascript"), ('import plimsoll_host\nplimsoll_host.get("/v1/lights/hall")', "python")):
            result = await session.call_tool("run_code", {"code": code, "language": language})
            print(language, "->", result.content[0].text)
        handle = json.loads((await session.call_tool("open_sandbox", {})).content[0].text)["sandbox"]
        kept = await session.call_tool("run_code", {"code": "typeof host", "language": "javascript", "sandbox": handle})
        print("in a kept sandbox ->", json.loads(kept.content[0].text)["stdout"].strip())
        await session.call_tool("close_sandbox", {"sandbox": handle})
        print("server_info:", json.loads((await session.call_tool("server_info", {})).content[0].text)["summary"])


if __name__ == "__main__":
    asyncio.run(main())
