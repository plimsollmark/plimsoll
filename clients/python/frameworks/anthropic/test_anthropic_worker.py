"""The Managed Agents worker tools over a plimsoll workspace: the real Anthropic SDK's tool
classes, schemas and call path, a workspace faked in memory, and no call to
api.anthropic.com anywhere. The one daemon-backed case uses the in-memory session daemon
client_test.go serves."""

from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from typing import Any, Dict, List, Optional

from anthropic.lib.tools import BetaAsyncFunctionTool, ToolError
from anthropic.lib.tools._tool_dispatch import tool_registry  # the runner's own index: a change there fails here, which is the point
from anthropic.lib.tools.agent_toolset import AgentToolContext, beta_agent_toolset_20260401
from anthropic.types.beta import (
    BetaManagedAgentsAgentToolset20260401BashInput,
    BetaManagedAgentsAgentToolset20260401EditInput,
    BetaManagedAgentsAgentToolset20260401GlobInput,
    BetaManagedAgentsAgentToolset20260401GrepInput,
    BetaManagedAgentsAgentToolset20260401ReadInput,
    BetaManagedAgentsAgentToolset20260401WriteInput,
)

from plimsoll_client import Client, SessionEndedError
from plimsoll_client.anthropic_worker import TOOL_NAMES, PlimsollTools, session_key
from plimsoll_client.workspace import ExecOutcome, WorkspacePathError
from tests._env import setting

INPUTS = (
    BetaManagedAgentsAgentToolset20260401BashInput,
    BetaManagedAgentsAgentToolset20260401ReadInput,
    BetaManagedAgentsAgentToolset20260401WriteInput,
    BetaManagedAgentsAgentToolset20260401EditInput,
    BetaManagedAgentsAgentToolset20260401GlobInput,
    BetaManagedAgentsAgentToolset20260401GrepInput,
)


def outcome(stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0, timed_out: bool = False, cwd: str = "/work") -> ExecOutcome:
    return ExecOutcome(stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=timed_out, stdout_truncated=False, stderr_truncated=False, cwd=cwd, result=None)  # type: ignore[arg-type]


class FakeWorkspace:
    """The spec's Workspace interface in memory: files in a dict, commands recorded and
    answered by a few rules."""

    root = "/work"

    def __init__(self) -> None:
        self.files: Dict[str, bytes] = {}
        self.commands: List[str] = []
        self.closed = False

    def resolve(self, path: str) -> str:
        if path.startswith("/"):
            if path == self.root:
                return "."
            if not path.startswith(self.root + "/"):
                raise WorkspacePathError(f"{path!r} is outside the work directory {self.root}")
            path = path[len(self.root) + 1 :]
        if path in ("", ".") or path.startswith("../") or path == "..":
            return "." if path in ("", ".") else (_ for _ in ()).throw(WorkspacePathError(path))
        return path

    def exec(self, command: str, *, timeout: Optional[float] = None) -> ExecOutcome:
        self.commands.append(command)
        if command.startswith("echo "):
            return outcome(stdout=(command[5:] + "\n").encode())
        if command == "false":
            return outcome(stderr=b"it failed\n", exit_code=1)
        if command.startswith("sleep"):
            return outcome(exit_code=124, timed_out=True)
        return outcome()

    def read(self, path: str, *, max_bytes: int = 1 << 20) -> bytes:
        rel = self.resolve(path)
        if rel not in self.files:
            raise FileNotFoundError(f"{path}: no such file")
        return self.files[rel][:max_bytes]

    def write(self, path: str, content: Any) -> None:
        rel = self.resolve(path)
        self.files[rel] = content.encode("utf-8") if isinstance(content, str) else bytes(content)

    def edit(self, path: str, old: str, new: str, *, replace_all: bool = False) -> int:
        text = self.read(path).decode("utf-8")
        count = text.count(old)
        if count == 0:
            raise ValueError(f"{path}: old string not found")
        if count > 1 and not replace_all:
            raise ValueError(f"{path}: old string occurs {count} times; pass replace_all=True to replace every one")
        self.write(path, text.replace(old, new) if replace_all else text.replace(old, new, 1))
        return count if replace_all else 1

    def glob(self, pattern: str, path: Optional[str] = None) -> List[str]:
        import re

        if pattern.startswith("/"):
            raise WorkspacePathError("an absolute pattern is not permitted")
        # A shell glob: `*` and `?` stop at `/`; `**/` is any run of directories.
        rx = "".join(
            "(?:.*/)?" if part == "**/" else ".*" if part == "**" else "[^/]*" if part == "*" else "[^/]" if part == "?" else re.escape(part)
            for part in re.findall(r"\*\*/|\*\*|\*|\?|[^*?]+", pattern)
        )
        base = self.resolve(path) if path else "."
        out = []
        for name in sorted(self.files):
            rel = name if base == "." else (name[len(base) + 1 :] if name.startswith(base + "/") else None)
            if rel is not None and re.fullmatch(rx, rel):
                out.append(rel)
        return out

    def grep(self, pattern: str, path: Optional[str] = None) -> str:
        import re

        rx = re.compile(pattern)
        lines = []
        for name in sorted(self.files):
            for i, line in enumerate(self.files[name].decode("utf-8", "replace").split("\n"), 1):
                if rx.search(line):
                    lines.append(f"{name}:{i}:{line}")
        return "\n".join(lines)

    def persist(self) -> bytes:
        return b"TAR"

    def hydrate(self, data: bytes) -> None:
        pass

    def close(self) -> None:
        self.closed = True


_LOOPS: List[asyncio.AbstractEventLoop] = []


def tearDownModule() -> None:
    for loop in _LOOPS:
        if not loop.is_closed():
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()


class Harness:
    """A PlimsollTools over fake workspaces, one per session key, and a tool context.

    Every call runs on one event loop, as the worker's calls do: the SDK's bash tool is an
    async context manager whose generator belongs to the loop that entered it, and
    ``asyncio.run`` would finalize it (and so close the session) at the end of each call."""

    def __init__(self, workdir: Optional[str] = None, session_id: str = "sess_1", **kw: Any) -> None:
        self.made: List[FakeWorkspace] = []

        def factory(key: str) -> FakeWorkspace:
            ws = FakeWorkspace()
            self.made.append(ws)
            return ws

        self.tools = PlimsollTools(None, workspace_factory=factory, **kw)
        self.ctx = AgentToolContext(workdir=workdir or tempfile.mkdtemp(), session_id=session_id)
        self.by_name = tool_registry(self.tools.tools(self.ctx))
        self.loop = asyncio.new_event_loop()
        _LOOPS.append(self.loop)

    def call(self, name: str, **input: Any) -> Any:
        return self.loop.run_until_complete(self.by_name[name].call(input))

    def run(self, coro: Any) -> Any:
        return self.loop.run_until_complete(coro)

    def shutdown(self) -> None:
        """What asyncio.run does at the end of a worker: finalizes the loop's async
        generators, which exits the bash tool's context manager."""
        self.loop.run_until_complete(self.loop.shutdown_asyncgens())
        self.loop.close()

    @property
    def ws(self) -> FakeWorkspace:
        return self.made[-1]


class ShapeTests(unittest.TestCase):
    def test_names_and_schemas_match_the_sdk_toolset(self) -> None:
        h = Harness()
        ours = h.tools.tools(h.ctx)
        theirs = beta_agent_toolset_20260401(h.ctx)
        self.assertEqual([t.name for t in ours], [t.name for t in theirs])
        self.assertEqual([t.name for t in ours], list(TOOL_NAMES))
        for mine, built_in, cls in zip(ours, theirs, INPUTS):
            self.assertIsInstance(mine, BetaAsyncFunctionTool)
            self.assertEqual(mine.input_schema, built_in.input_schema, mine.name)
            self.assertEqual(mine.input_schema, cls.model_json_schema(), mine.name)
        self.assertEqual(set(tool_registry(ours)), set(TOOL_NAMES))

    def test_session_key(self) -> None:
        self.assertEqual(session_key(AgentToolContext(workdir=".", session_id="sess_9")), "sess_9")

        class Session:
            id = "sess_from_object"

        class Ctx:
            session = Session()
            session_id = "ignored"

        self.assertEqual(session_key(Ctx()), "sess_from_object")
        self.assertTrue(session_key(object()).startswith("context-"))

    def test_constructor_refusals(self) -> None:
        with self.assertRaises(ValueError):
            PlimsollTools(None)
        with self.assertRaises(ValueError):
            PlimsollTools(None, workspace_factory=lambda k: FakeWorkspace(), timeout=0)
        with self.assertRaises(ValueError):
            PlimsollTools(None, workspace_factory=lambda k: FakeWorkspace(), max_file_bytes=0)


class BashTests(unittest.TestCase):
    def test_output_errors_and_restart(self) -> None:
        h = Harness()
        self.assertEqual(h.call("bash", command="echo hi"), "hi\n")
        self.assertEqual(len(h.made), 1)
        self.assertEqual(h.ws.commands, ["echo hi"])
        with self.assertRaises(ToolError) as cm:
            h.call("bash", command="false")
        self.assertEqual(str(cm.exception), "it failed\n")
        with self.assertRaises(ToolError) as cm:
            h.call("bash", command="sleep 99", timeout_ms=500)
        self.assertIn("timed out after 0.5s", str(cm.exception))
        with self.assertRaises(ToolError):
            h.call("bash")
        self.assertEqual(h.call("bash", restart=True), "bash session restarted")
        self.assertEqual(len(h.made), 2)
        self.assertTrue(h.made[0].closed)
        self.assertFalse(h.made[1].closed)
        self.assertEqual(h.tools.open_sessions, ["sess_1"])

    def test_the_runner_cleanup_closes_the_session(self) -> None:
        h = Harness()
        h.call("bash", command="echo hi")
        tool = h.by_name["bash"]
        # The SDK sets _context_manager once the tool was entered and drives its __aexit__
        # on the tool runner's cleanup path (_beta_functions.py, the asynccontextmanager
        # branch of beta_async_tool); this is that path.
        cm = getattr(tool, "_context_manager", None)
        self.assertIsNotNone(cm)
        h.run(cm.__aexit__(None, None, None))
        self.assertTrue(h.ws.closed)
        self.assertEqual(h.tools.open_sessions, [])

    def test_the_loop_ending_closes_the_session_too(self) -> None:
        h = Harness()
        h.call("bash", command="echo hi")
        self.assertFalse(h.ws.closed)
        h.shutdown()
        self.assertTrue(h.ws.closed)
        self.assertEqual(h.tools.open_sessions, [])

    def test_a_session_is_shared_by_the_six_tools_and_closed_by_close(self) -> None:
        h = Harness()
        h.call("write", file_path="a.txt", content="x")
        h.call("bash", command="echo hi")
        self.assertEqual(len(h.made), 1)
        h.tools.close(h.ctx)
        self.assertTrue(h.ws.closed)
        h.call("bash", command="echo again")
        self.assertEqual(len(h.made), 2)
        h.tools.close_all()
        self.assertTrue(h.made[1].closed)


class FileToolTests(unittest.TestCase):
    def test_read_write_edit(self) -> None:
        h = Harness()
        self.assertEqual(h.call("write", file_path="src/app.py", content="one\ntwo\nthree\n"), "wrote 14 bytes to src/app.py")
        self.assertEqual(h.call("read", file_path="src/app.py"), "one\ntwo\nthree\n")
        self.assertEqual(h.call("read", file_path="/work/src/app.py", view_range=[2, 3]), "two\nthree")
        self.assertEqual(h.call("read", file_path="src/app.py", view_range=[3, -1]), "three\n")
        with self.assertRaises(ToolError):
            h.call("read", file_path="src/app.py", view_range=[1])
        with self.assertRaises(ToolError):
            h.call("read", file_path="missing.txt")
        with self.assertRaises(ToolError):
            h.call("read", file_path="/etc/passwd")
        h.ws.files["blob"] = b"\xff\xfe"
        with self.assertRaises(ToolError) as cm:
            h.call("read", file_path="blob")
        self.assertIn("not valid UTF-8", str(cm.exception))
        self.assertEqual(h.call("edit", file_path="src/app.py", old_string="two", new_string="2"), "edited src/app.py (1 replacement(s))")
        self.assertEqual(h.call("read", file_path="src/app.py"), "one\n2\nthree\n")
        with self.assertRaises(ToolError):
            h.call("edit", file_path="src/app.py", old_string="zzz", new_string="2")
        h.ws.files["dup"] = b"a a"
        with self.assertRaises(ToolError):
            h.call("edit", file_path="dup", old_string="a", new_string="b")
        self.assertEqual(h.call("edit", file_path="dup", old_string="a", new_string="b", replace_all=True), "edited dup (2 replacement(s))")

    def test_large_reads_need_a_view_range(self) -> None:
        h = Harness(max_file_bytes=16)
        h.ws_big = None
        h.call("write", file_path="big.txt", content="x" * 40)
        with self.assertRaises(ToolError) as cm:
            h.call("read", file_path="big.txt")
        self.assertIn("view_range", str(cm.exception))
        self.assertEqual(h.call("read", file_path="big.txt", view_range=[1, 1]), "x" * 40)

    def test_glob_and_grep(self) -> None:
        h = Harness()
        h.call("write", file_path="src/a.py", content="import os\n")
        h.call("write", file_path="src/lib/b.py", content="import sys\n")
        h.call("write", file_path="README.md", content="# hi\n")
        self.assertEqual(h.call("glob", pattern="*.py", path="src"), "src/a.py")
        self.assertEqual(h.call("glob", pattern="**/*.py"), "src/a.py\nsrc/lib/b.py")
        self.assertEqual(h.call("glob", pattern="*.nothing"), "no matches")
        with self.assertRaises(ToolError):
            h.call("glob", pattern="/etc/*")
        self.assertEqual(h.call("grep", pattern="^import"), "src/a.py:1:import os\nsrc/lib/b.py:1:import sys")
        self.assertEqual(h.call("grep", pattern="absent"), "no matches")

    def test_the_sdk_validates_the_input(self) -> None:
        h = Harness()
        with self.assertRaises(ValueError):
            h.call("read")  # file_path is required by the SDK's schema
        with self.assertRaises(TypeError):
            h.run(h.by_name["read"].call("not a dict"))


class SkillsTests(unittest.TestCase):
    def test_downloaded_skills_are_staged_with_their_executable_bits(self) -> None:
        workdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(workdir, "skills", "demo", "scripts"))
        with open(os.path.join(workdir, "skills", "demo", "SKILL.md"), "w") as f:
            f.write("# demo\n")
        script = os.path.join(workdir, "skills", "demo", "scripts", "run.sh")
        with open(script, "w") as f:
            f.write("#!/bin/sh\necho demo\n")
        os.chmod(script, 0o755)
        with open(os.path.join(workdir, "skills", "demo", "data.bin"), "wb") as f:
            f.write(b"\x00\x01")
        h = Harness(workdir=workdir)
        h.call("bash", command="echo hi")
        self.assertEqual(h.ws.files["skills/demo/SKILL.md"], b"# demo\n")
        self.assertEqual(h.ws.files["skills/demo/data.bin"], b"\x00\x01")
        self.assertEqual(h.ws.commands[0], "chmod +x skills/demo/scripts/run.sh")
        self.assertEqual(h.ws.commands[1], "echo hi")

    def test_staging_can_be_off(self) -> None:
        workdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(workdir, "skills", "demo"))
        with open(os.path.join(workdir, "skills", "demo", "SKILL.md"), "w") as f:
            f.write("# demo\n")
        h = Harness(workdir=workdir, stage_skills=False)
        h.call("bash", command="echo hi")
        self.assertEqual(h.ws.files, {})


class DaemonTests(unittest.TestCase):
    """Through the in-memory session daemon: the session is opened with the floor and
    the owner, and closed by close(); its calls run nothing there, so no tool is called."""

    def test_open_and_close_through_the_daemon(self) -> None:
        client = Client(setting("PLIMSOLL_SESSIONS_URL"))
        tools = PlimsollTools(client, minimum_isolation="container", languages=["python"])
        ctx = AgentToolContext(workdir=tempfile.mkdtemp(), session_id="sess_daemon")
        ws = tools.open(ctx)
        self.assertEqual(ws.session.isolation, "container")
        self.assertIs(tools.open(ctx), ws)
        self.assertEqual(tools.open_sessions, ["sess_daemon"])
        tools.close(ctx)
        self.assertEqual(tools.open_sessions, [])
        with self.assertRaises(SessionEndedError):
            ws.session.run_project({}, ["true"])
        tools.close(ctx)  # a second close is nothing


if __name__ == "__main__":
    unittest.main()
