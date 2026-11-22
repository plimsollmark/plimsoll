"""PlimsollShellTool on a real docker session under the docker provider, run by
TestAgentFrameworkDocker in make docker-suite once for each of plimsoll's project images
(plimsoll/sandbox and plimsoll/sandbox-python): the harness's ShellEnvironmentProvider (agent_framework_tools/shell/_environment.py)
runs its probe commands through the tool in BusyBox sh and builds its snapshot, and a harness
agent driven by a scripted chat client (no model is called) writes a file with one command and
reads it with the next.

What each probe printed is written to standard output, which the Go test logs. A CLI the image
does not have is reported as the provider reports it (a None version, then "Not installed" in
the block the model is shown), not hidden.

Not a test_*.py, so the framework suite (TestPythonFrameworks, an in-memory daemon) never
collects it."""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from typing import Any, List, Optional, Sequence, Tuple

from agent_framework import Message
from agent_framework_tools.shell import (
    ShellEnvironmentProvider,
    ShellEnvironmentProviderOptions,
    ShellEnvironmentSnapshot,
    ShellFamily,
    ShellResult,
    default_instructions_formatter,
)

from frameworks.agent_framework.test_agent_framework import Scripted, harness
from plimsoll_client import Client
from plimsoll_client.agent_framework import PlimsollShellResult, PlimsollShellTool
from plimsoll_client.types import meets

URL = os.environ.get("PLIMSOLL_DOCKER_SESSIONS_URL", "")
# The tier the daemon's docker runtime gives: container under runc, kernel under runsc.
FLOOR = os.environ.get("PLIMSOLL_DOCKER_FLOOR", "container")

if not URL:
    sys.exit("PLIMSOLL_DOCKER_SESSIONS_URL is not set: run through TestAgentFrameworkDocker (make docker-suite)")

#: The provider's first probe, as _environment.py sends it on a POSIX shell.
SHELL_PROBE = 'echo "VERSION=${BASH_VERSION:-${ZSH_VERSION:-unknown}}"; echo "CWD=$(pwd)"'
#: The CLIs the harness's provider probes: it is built with no options, so the defaults.
PROBE_TOOLS = tuple(ShellEnvironmentProviderOptions().probe_tools)


class Recording(PlimsollShellTool):
    """PlimsollShellTool that keeps every command it ran and what came back."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ran: List[Tuple[str, Optional[float], ShellResult]] = []

    async def run(self, command: str, *, timeout: Optional[float] = None) -> ShellResult:  # noqa: ASYNC109
        result = await super().run(command, timeout=timeout)
        self.ran.append((command, timeout, result))
        return result


class Instructed(Scripted):
    """The scripted chat client, keeping the instructions each request carried."""

    def __init__(self, *calls: Any) -> None:
        super().__init__(*calls)
        self.instructions: List[str] = []

    def _inner_get_response(self, *, messages: Sequence[Message], stream: bool, options: Any, **kwargs: Any) -> Any:
        self.instructions.append(str((options or {}).get("instructions") or ""))
        return super()._inner_get_response(messages=messages, stream=stream, options=options, **kwargs)


def tool() -> Recording:
    return Recording(Client(URL), minimum_isolation=FLOOR)


def provider_of(agent: Any) -> ShellEnvironmentProvider:
    (provider,) = [p for p in agent.context_providers if isinstance(p, ShellEnvironmentProvider)]
    return provider


async def converse(shell: Recording, client: Instructed) -> Tuple[Any, ShellEnvironmentProvider]:
    agent = harness(client, shell)
    await agent.run("go", session=agent.create_session())
    return agent, provider_of(agent)


def show(command: str, timeout: Optional[float], r: ShellResult) -> str:
    return (
        f"  $ {command}   (budget {timeout} s)\n"
        f"    exit code {r.exit_code}, timed out {r.timed_out}, truncated {r.truncated}, {r.duration_ms} ms\n"
        f"    stdout {r.stdout!r}\n"
        f"    stderr {r.stderr!r}"
    )


def first_line(text: str) -> Optional[str]:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return None


class EnvironmentProviderUnderBusyBox(unittest.TestCase):
    def test_the_harness_provider_builds_its_snapshot_through_the_tool(self) -> None:
        shell = tool()
        client = Instructed()  # no tool calls: the run is the provider's probes, then "done"

        async def main() -> Tuple[ShellEnvironmentProvider, str, ShellResult]:
            async with shell:
                _, provider = await converse(shell, client)
                # Not one of the provider's probes: what sh is in this image, so the record
                # below is known to be BusyBox's, as the tool's description says.
                which = await PlimsollShellTool.run(shell, "readlink /proc/$$/exe")
                return provider, shell.isolation, which

        provider, isolation, which = asyncio.run(main())
        self.assertTrue(meets(isolation, FLOOR), isolation)
        snapshot = provider.current_snapshot
        self.assertIsInstance(snapshot, ShellEnvironmentSnapshot, "the provider built no snapshot")
        assert snapshot is not None

        probes = shell.ran
        print("\nShellEnvironmentProvider probes through PlimsollShellTool, isolation " + isolation + ":")
        for command, timeout, r in probes:
            print(show(command, timeout, r))
        print("  sh is " + which.stdout.strip() + " (readlink /proc/$$/exe, exit code " + str(which.exit_code) + ")")
        print("snapshot: " + repr(snapshot))
        block = default_instructions_formatter(snapshot)
        print("the block the model is shown:\n" + block)

        self.assertEqual((which.exit_code, which.stdout.strip()), (0, "/bin/busybox"), "the image's sh is not BusyBox")
        # The provider's commands, in its order, each with its probe budget.
        self.assertEqual([c for c, _, _ in probes], [SHELL_PROBE] + [f"{t} --version" for t in PROBE_TOOLS])
        self.assertTrue(all(t == ShellEnvironmentProviderOptions().probe_timeout for _, t, _ in probes))
        self.assertTrue(all(not r.timed_out for _, _, r in probes), "a probe ran past its budget")

        # BusyBox sh sets neither BASH_VERSION nor ZSH_VERSION, so the provider names no version.
        self.assertEqual(probes[0][2].exit_code, 0)
        self.assertEqual(probes[0][2].stdout, "VERSION=unknown\nCWD=/work\n")
        self.assertEqual(snapshot.family, ShellFamily.POSIX)
        self.assertIsNone(snapshot.shell_version)
        self.assertEqual(snapshot.working_directory, "/work")

        # Each CLI as the provider read it from its probe: present with its first line of
        # output, or None, never dropped.
        self.assertEqual(list(snapshot.tool_versions), list(PROBE_TOOLS))
        for (command, _, r), name in zip(probes[1:], PROBE_TOOLS):
            expected = (first_line(r.stdout) or first_line(r.stderr)) if r.exit_code == 0 else None
            self.assertEqual(snapshot.tool_versions[name], expected, command)
        absent = [n for n, v in snapshot.tool_versions.items() if v is None]
        present = [n for n, v in snapshot.tool_versions.items() if v is not None]
        print("absent in the image: " + (", ".join(absent) or "none") + "; present: " + (", ".join(present) or "none"))
        if absent:
            self.assertIn("Not installed: " + ", ".join(absent), block)
        for name in present:
            self.assertIn(f"{name} ({snapshot.tool_versions[name]})", block)

        # The block reached the model with the request.
        self.assertEqual(len(client.instructions), 1)
        self.assertIn(block, client.instructions[0])


class FilesPersist(unittest.TestCase):
    def test_a_file_written_by_one_command_is_read_by_the_next(self) -> None:
        shell = tool()
        client = Instructed(("run_shell", {"command": "echo hi > f"}), ("run_shell", {"command": "cat f"}))

        async def main() -> None:
            async with shell:
                await converse(shell, client)

        asyncio.run(main())
        conversation = [(c, r) for c, _, r in shell.ran if c != SHELL_PROBE and not c.endswith(" --version")]
        self.assertEqual([c for c, _ in conversation], ["echo hi > f", "cat f"])
        first, second = client.results()
        self.assertIsNone(first.exception, first.exception)
        self.assertIsNone(second.exception, second.exception)
        self.assertEqual(first.result, "exit code: 0")
        self.assertEqual(second.result, "exit code: 0\nhi")
        print("\nrun_shell answered: " + repr(first.result) + ", then " + repr(second.result))

        # What plimsoll stated about each command reached the application: the checked record,
        # the tier, the outcome, on the result and in the function result's labels; and the
        # second command's record follows the first's in the session's chain.
        records = []
        for (command, r), content in zip(conversation, (first, second)):
            self.assertIsInstance(r, PlimsollShellResult)
            assert isinstance(r, PlimsollShellResult) and r.record is not None
            self.assertRegex(r.record_sha256, "^[0-9a-f]{64}$")
            self.assertEqual(r.record.sha256, r.record_sha256)
            self.assertEqual((r.isolation, r.record.isolation, r.outcome), (shell.isolation, shell.isolation, "completed"))
            (item,) = content.items or []
            self.assertEqual({k: v for k, v in item.additional_properties.items() if k.startswith("plimsoll_")},
                             {"plimsoll_dispatched": "yes", "plimsoll_outcome": "completed", "plimsoll_isolation": shell.isolation,
                              "plimsoll_record_sha256": r.record_sha256})
            records.append(r.record)
            print(f"  {command!r}: record {r.record_sha256}, tier {r.isolation}, outcome {r.outcome}, sequence {r.record.sequence}")
        self.assertEqual(records[1].previous_sha256, records[0].sha256)
        self.assertEqual(records[1].session, records[0].session)


if __name__ == "__main__":
    unittest.main()
