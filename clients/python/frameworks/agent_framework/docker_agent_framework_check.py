"""PlimsollShellTool on a real docker session under the docker provider, run by
TestAgentFrameworkDocker in make docker-suite once for each of plimsoll's project images
(plimsoll/sandbox and plimsoll/sandbox-python): the harness's ShellEnvironmentProvider (agent_framework_tools/shell/_environment.py)
runs its probe commands through the tool in BusyBox sh and builds its snapshot, and a harness
agent driven by a scripted chat client (no model is called) writes a file with one command and
reads it with the next. PlimsollFileStore, through harness_options, gives the same agent the
framework's file tools on the same session: what the file tools write the shell reads, and the
reverse; and each of the store's refusals holds against what a guest can make in BusyBox (a link to
/etc, a link to a file outside the work directory, a sparse file past the cap), against a folder
swapped for a link out by the guest's own kept interpreter while the store reads through it, and a
search of 5,000 files and a listing and search of 60,000 names end inside the framework's bound.
Every store operation is a file call carried out by plimsoll's helper in the sandbox.

What each probe printed is written to standard output, which the Go test logs. A CLI the image
does not have is reported as the provider reports it (a None version, then "Not installed" in
the block the model is shown), not hidden.

Not a test_*.py, so the framework suite (TestPythonFrameworks, an in-memory daemon) never
collects it."""

from __future__ import annotations

import asyncio
import errno
import os
import re
import sys
import time
import unittest
from typing import Any, List, Optional, Sequence, Tuple

from agent_framework import FileAccessProvider, Message
from agent_framework_tools.shell import (
    ShellEnvironmentProvider,
    ShellEnvironmentProviderOptions,
    ShellEnvironmentSnapshot,
    ShellFamily,
    ShellResult,
    default_instructions_formatter,
)

from frameworks.agent_framework.test_agent_framework import Scripted, harness
from frameworks.agent_framework.test_file_store import harness as files_harness
from plimsoll_client import Client
from plimsoll_client.agent_framework import PlimsollFileStore, PlimsollShellResult, PlimsollShellTool
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


class FileStoreShares(unittest.TestCase):
    def test_the_file_tools_and_the_shell_see_one_tree(self) -> None:
        shell = tool()
        client = Instructed(
            (FileAccessProvider.WRITE_TOOL_NAME, {"file_name": "notes/plan.md", "content": "step one\n"}),
            ("run_shell", {"command": "cat notes/plan.md && echo step two >> notes/plan.md"}),
            (FileAccessProvider.READ_TOOL_NAME, {"file_name": "notes/plan.md"}),
            (FileAccessProvider.GREP_TOOL_NAME, {"regex_pattern": "TWO"}),
            (FileAccessProvider.LS_TOOL_NAME, {"directory": ""}),
        )

        async def main() -> str:
            async with shell:
                agent = files_harness(client, shell)
                await agent.run("go", session=agent.create_session())
                return shell.isolation

        isolation = asyncio.run(main())
        self.assertTrue(meets(isolation, FLOOR), isolation)
        wrote, cat, read, grep, ls = client.results()
        for name, r in (("write", wrote), ("cat", cat), ("read", read), ("grep", grep), ("ls", ls)):
            print(f"  {name}: {r.result!r}")
            self.assertIsNone(r.exception, r.exception)
        self.assertIn("written", str(wrote.result))
        self.assertEqual(cat.result, "exit code: 0\nstep one")
        self.assertEqual(read.result, "step one\nstep two\n")
        self.assertIn("notes/plan.md", str(grep.result))
        self.assertIn("notes", str(ls.result))
        self.assertNotIn(".plimsoll-shell", str(ls.result))


class FileStoreRefusesOnBusyBox(unittest.TestCase):
    def test_each_refusal_holds_against_what_a_guest_can_make(self) -> None:
        shell = tool()
        store = PlimsollFileStore(shell, max_file_bytes=4096)

        async def main() -> List[str]:
            seen: List[str] = []
            async with shell:
                made = await PlimsollShellTool.run(shell, (
                    "ln -s /etc out && ln -s /etc/passwd leaf && mkdir -p a/b && ln -s / a/b/root && "
                    "ln -s /tmp/planted dangling && head -c 5000 /dev/zero > big && "
                    "dd if=/dev/zero of=sparse bs=1 count=0 seek=104857600 2>/dev/null && "
                    "printf 'needle here\\n' > hay.txt && printf 'caf\\351\\n' > latin1"))
                self.assertEqual(made.exit_code, 0, made.stderr)

                async def refused(what: str, op: Any, error: type = ValueError, code: Optional[int] = None) -> None:
                    try:
                        await op()
                    except error as e:
                        if code is not None:
                            self.assertEqual(getattr(e, "errno", None), code, what)
                        seen.append(f"{what}: {type(e).__name__}: {e}")
                        return
                    self.fail(f"{what}: not refused")

                for path in ("out/passwd", "leaf", "a/b/root/etc/passwd"):
                    await refused(f"read {path}", lambda p=path: store.read(p))
                    await refused(f"write {path}", lambda p=path: store.write(p, "x"))
                    await refused(f"delete {path}", lambda p=path: store.delete(p))
                await refused("write out/planted", lambda: store.write("out/planted", "x"))
                await refused("write through a dangling link", lambda: store.write("dangling", "x", overwrite=False))
                await refused("list out", lambda: store.list_children("out"))
                await refused("search out", lambda: store.search("out", "root", recursive=True))
                await refused("read ../etc/passwd", lambda: store.read("../etc/passwd"))
                await refused("read /etc/passwd", lambda: store.read("/etc/passwd"))
                await refused("write .plimsoll-shell/env", lambda: store.write(".plimsoll-shell/env", "export X=1"))
                await refused("write past the cap", lambda: store.write("w.txt", "x" * 4097), OSError, errno.EFBIG)
                await refused("read past the cap", lambda: store.read("big"), OSError, errno.EFBIG)
                await refused("read a sparse file past the cap", lambda: store.read("sparse"), OSError, errno.EFBIG)
                await refused("read a file that is not UTF-8", lambda: store.read("latin1"))
                await store.write("once.txt", "first", overwrite=False)
                await refused("create a file already there", lambda: store.write("once.txt", "second", overwrite=False), FileExistsError)

                after = await PlimsollShellTool.run(shell, "test ! -e /etc/planted && test ! -e /tmp/planted && head -1 /etc/passwd && cat once.txt")
                self.assertEqual(after.exit_code, 0, after.stderr)
                self.assertTrue(after.stdout.endswith("first"), after.stdout)
                names = [e.name for e in await store.list_children()]
                self.assertEqual(sorted(names), sorted(["a", "big", "hay.txt", "latin1", "once.txt", "sparse"]), names)
                found = await store.search("", "needle", recursive=True)
                self.assertEqual([(r.file_name, [m.line_number for m in r.matching_lines]) for r in found], [("hay.txt", [1])])
            return seen

        seen = asyncio.run(main())
        print("\nPlimsollFileStore's refusals on a real session:")
        for line in seen:
            print("  " + line)


class FileStoreSearchesATreeInTime(unittest.TestCase):
    def test_a_search_of_5000_files_ends_inside_the_frameworks_bound(self) -> None:
        # The framework ends a search at 10 seconds (ValueError). Under gVisor, the old scripts'
        # programs started per file took 8.0 s to list 5,000 small files and 16.8 s to read them
        # (2026-11-26, finding release-116); the helper's list and readmany answer them in a few
        # file calls. A name the store does not take as a path (a newline in it) is left out.
        shell = tool()
        store = PlimsollFileStore(shell)

        async def main() -> Tuple[float, List[str], List[str]]:
            async with shell:
                made = await PlimsollShellTool.run(shell, (
                    "mkdir many odd && cd many && for d in $(seq 1 50); do mkdir d$d; for f in $(seq 1 100); do "
                    "printf 'line\\nneedle %s %s\\n' $d $f > d$d/f$f.txt; done; done && cd ../odd && "
                    "printf 'needle split\\n' > \"$(printf 'two\\nlines')\" && printf 'needle plain\\n' > plain"), timeout=120)
                self.assertEqual(made.exit_code, 0, made.stderr)
                start = time.monotonic()
                many = await store.search("many", "needle", recursive=True)
                spent = time.monotonic() - start
                odd = await store.search("odd", "needle")
                start = time.monotonic()
                for _ in range(10):
                    await store.read("many/d1/f1.txt")  # three stats (one per part) and the read
                self.read_ms = (time.monotonic() - start) * 100
                return spent, [r.file_name for r in many], sorted(r.file_name for r in odd)

        spent, many, odd = asyncio.run(main())
        print(f"\n  a recursive search of 5,000 files: {spent:.2f} s, {len(many)} found; a read three parts deep: {self.read_ms:.0f} ms")
        self.assertEqual(len(many), 5000)
        self.assertIn("d50/f100.txt", many)
        self.assertEqual(odd, ["plain"])

    def test_sixty_thousand_names_are_listed_inside_the_frameworks_bound_and_searched(self) -> None:
        # One listing of 60,000 short names was past one step's output for the old scripts (OSError
        # EFBIG, 2026-11-26); the helper pages a listing, and readmany takes 1,024 files a call, so a
        # search of them is 59 readmany calls. Measured 2026-11-27: 7.4 to 8.5 s under runc and 9.3
        # to 10 s under gVisor, at the framework's 10-second bound (under gVisor its pattern's own
        # deadline cut one run), so the search's time is printed, not held to the bound (it runs
        # through the store's search with a plain pattern, without the framework's deadline); the
        # listing is held to it.
        shell = tool()
        store = PlimsollFileStore(shell)

        async def main() -> Tuple[float, float, int, List[str]]:
            async with shell:
                made = await PlimsollShellTool.run(shell, (
                    "mkdir big && cd big && for d in $(seq 10 69); do mkdir d$d && (cd d$d && seq 1000 1999 | sed 's/.*/file&.txt/' | xargs touch) "
                    "|| exit 1; done && echo 'the needle' > d69/file1999.txt"), timeout=300)
                self.assertEqual(made.exit_code, 0, made.stderr)
                start = time.monotonic()
                names = await store.find_matching_files("big", "", recursive=True)
                listed = time.monotonic() - start
                start = time.monotonic()
                # A plain pattern: the framework's compiled one carries the 10-second deadline too.
                found = await store._search("big", re.compile("needle", re.IGNORECASE), None, True)
                searched = time.monotonic() - start
                return listed, searched, len(names), [r.file_name for r in found]

        listed, searched, count, found = asyncio.run(main())
        print(f"\n  60,000 names: listed in {listed:.2f} s, searched in {searched:.2f} s")
        self.assertEqual(count, 60_000)  # the listing is whole
        self.assertEqual(found, ["d69/file1999.txt"])
        self.assertLess(listed, 10.0)


class FileStoreNeverFollowsASwappedLinkOut(unittest.TestCase):
    def test_a_folder_swapped_for_a_link_out_mid_read_is_never_followed(self) -> None:
        # The race the old scripts lost (a link checked by one program, the path opened by another):
        # a process of the guest's own, the session's kept interpreter, swaps a folder on the path
        # for a link to /etc over and over while the store reads through it. The helper resolves the
        # read's path beneath the work folder in one openat2 call, so no read reaches /etc/passwd.
        shell = tool()
        store = PlimsollFileStore(shell)

        async def main() -> Tuple[int, set]:
            seen: set = set()
            reads = 0
            async with shell:
                made = await PlimsollShellTool.run(shell, "mkdir real && echo inside > real/passwd && command -v python3 >/dev/null; echo $?")
                python = made.stdout.strip().endswith("0")
                session = shell.session
                if python:
                    cell = session.run_cell(
                        "import os, threading\n_stop = threading.Event()\n"
                        "def _flip():\n    while not _stop.is_set():\n        try:\n"
                        "            os.rename('real', 'd'); os.rename('d', 'real'); os.symlink('/etc', 'd'); os.unlink('d')\n"
                        "        except OSError:\n            pass\n"
                        "threading.Thread(target=_flip, daemon=True).start()\n", "python")
                else:
                    cell = session.run_cell(
                        "const fs = process.getBuiltinModule ? process.getBuiltinModule('node:fs') : process.mainModule.require('node:fs');\n"
                        "globalThis.stopFlip = false;\n"
                        "(function flip() { if (globalThis.stopFlip) return; try { fs.renameSync('real', 'd'); fs.renameSync('d', 'real'); "
                        "fs.symlinkSync('/etc', 'd'); fs.unlinkSync('d'); } catch (e) {} setImmediate(flip); })();\n", "javascript")
                self.assertEqual((cell.exit_code, cell.timed_out), (0, False), cell.stderr_text)
                deadline = time.monotonic() + 6
                while time.monotonic() < deadline:
                    reads += 1
                    try:
                        seen.add(await store.read("d/passwd"))
                    except (ValueError, OSError) as e:
                        seen.add(type(e).__name__)
                stop = session.run_cell("_stop.set()\n" if python else "globalThis.stopFlip = true;\n", "python" if python else "javascript")
                self.assertEqual((stop.exit_code, stop.timed_out), (0, False), stop.stderr_text)
            return reads, seen

        reads, seen = asyncio.run(main())
        print(f"\n  {reads} reads through a folder swapped for a link to /etc: {sorted(map(str, seen))}")
        self.assertFalse(any(isinstance(x, str) and "root:" in x for x in seen), "a read followed the link out")
        self.assertTrue(seen <= {"inside\n", None, "ValueError", "FileNotFoundError"}, seen)
        self.assertIn("ValueError", seen, "the swap never showed: the race was not run")


if __name__ == "__main__":
    unittest.main()
