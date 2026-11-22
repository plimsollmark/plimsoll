"""PlimsollEnvironment on a real docker session, with ADK 2.14.1's real tools, toolset and
Runner and a scripted model: what the framework suite's fake session cannot show, that the
workspace's fixed steps do in a real sandbox what ADK's contract says, and that ADK's own
LocalEnvironment answers the same command script the same way.

Not a test_*.py, so the framework suite's `unittest discover` never sees it: it needs docker.
adk_docker_test.go's TestADKEnvironmentDocker serves a docker daemon with sessions on, sets
PLIMSOLL_DOCKER_SESSIONS_URL and PLIMSOLL_DOCKER_FLOOR, and runs this module by name in the
ADK framework environment. Without the setting every case skips, unless
PLIMSOLL_DOCKER_REQUIRED=1.

The LocalEnvironment comparison runs a fixed list of harmless commands (echo, printf,
mkdir, basename, export, true, false, sleep) on this host in a temporary directory under the
repository's tmp/: ADK's own environment, never a command a model wrote."""

from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, List, Tuple

from google.adk.environment import LocalEnvironment
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from plimsoll_client import Client
from plimsoll_client.adk import PlimsollEnvironment, PlimsollEnvironmentGuard

from .test_adk_environment import responses_of, run_agent, scripted

SPANS = InMemorySpanExporter()

# The same commands, in order, on both environments. Each runs in a new shell in the work
# directory, so the directory change and the export do not reach the commands after them.
SCRIPT: List[str] = [
    "echo out; echo err >&2; exit 3",
    "printf 'a\\nb\\n'",
    "mkdir -p sub && cd sub && basename \"$PWD\"",
    "basename \"$PWD\" | grep -qx sub && echo kept || echo fresh",
    "export PLIMSOLL_CHECK_X=1",
    "echo \"${PLIMSOLL_CHECK_X:-unset}\"",
    "true",
    "false",
]


def setUpModule() -> None:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(SPANS))
    trace.set_tracer_provider(provider)


def _setting(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        if os.environ.get("PLIMSOLL_DOCKER_REQUIRED") == "1":
            raise RuntimeError(f"{name} is not set, and PLIMSOLL_DOCKER_REQUIRED=1")
        raise unittest.SkipTest(f"{name} is not set; run through go test ./clients/python -run TestADKEnvironmentDocker")
    return value


def environment(**kwargs: Any) -> PlimsollEnvironment:
    return PlimsollEnvironment(Client(_setting("PLIMSOLL_DOCKER_SESSIONS_URL")),
                               minimum_isolation=_setting("PLIMSOLL_DOCKER_FLOOR"), timeout=60, **kwargs)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


class EnvironmentOnDocker(unittest.TestCase):
    def test_the_contract_on_a_real_session(self) -> None:
        async def go() -> None:
            env = environment(env_vars={"GREETING": "hello there"})
            await env.initialize()
            try:
                self.assertEqual(env.working_dir, Path("/work"))
                floor = _setting("PLIMSOLL_DOCKER_FLOOR")
                await env.write_file("notes/a.txt", "one\ntwo\n")
                self.assertEqual(await env.read_file("notes/a.txt"), b"one\ntwo\n")
                self.assertEqual(await env.read_file("/work/notes/a.txt"), b"one\ntwo\n")
                out = await env.execute("cat notes/a.txt && wc -l < notes/a.txt")
                self.assertEqual((out.exit_code, out.stdout.split()), (0, ["one", "two", "2"]))
                await env.write_file("bin/data.bin", b"\x00\xff\x00 end")
                self.assertEqual(await env.read_file("bin/data.bin"), b"\x00\xff\x00 end")
                await env.write_file("nul.txt", "a\x00b")
                self.assertEqual(await env.read_file("nul.txt"), b"a\x00b")
                await env.write_file("/tmp/outside.txt", "outside\n")
                self.assertEqual(await env.read_file("/tmp/outside.txt"), b"outside\n")
                self.assertEqual((await env.execute('echo "$GREETING"')).stdout, "hello there\n")
                with self.assertRaises(FileNotFoundError):
                    await env.read_file("missing.txt")
                with self.assertRaises(IsADirectoryError):
                    await env.read_file("notes")
                timed = await env.execute("sleep 20", timeout=2)
                self.assertTrue(timed.timed_out)
                # A file past one call's artifact budget comes back whole, in pieces.
                big = os.urandom(9 << 20)
                await env.write_file("big.bin", big)
                self.assertEqual(await env.read_file("big.bin"), big)
                pieces = [p async for p in env.read_file_stream("big.bin")]
                self.assertEqual(b"".join(pieces), big)
                self.assertEqual(len(pieces), 2)
                # Every call stated its tier and came with a checked record.
                for c in env.calls:
                    self.assertEqual((c.dispatched, c.isolation), ("yes", floor), c)
                    self.assertRegex(c.record_sha256, r"^[0-9a-f]{64}$")
                    self.assertEqual(c.record.session, env.session.fingerprint)
            finally:
                await env.close()
            self.assertEqual(env.close_summary.calls, len(env.calls))
        run(go())

    def test_commands_answer_as_on_adks_local_environment(self) -> None:
        async def play(env: Any) -> List[Tuple[int, str, str]]:
            out = []
            for command in SCRIPT:
                r = await env.execute(command, timeout=30)
                out.append((r.exit_code, r.stdout, r.stderr))
            return out

        async def go() -> None:
            scratch = Path(__file__).resolve().parents[4] / "tmp"
            scratch.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(dir=scratch) as d:
                local = LocalEnvironment(working_dir=Path(d))
                await local.initialize()
                expected = await play(local)
                local_timeout = await local.execute("sleep 20", timeout=2)
            env = environment()
            await env.initialize()
            try:
                got = await play(env)
                timeout = await env.execute("sleep 20", timeout=2)
            finally:
                await env.close()
            for command, want, have in zip(SCRIPT, expected, got):
                with self.subTest(command=command):
                    self.assertEqual(have, want)
            self.assertEqual(got[3][1], "fresh\n")
            self.assertEqual(got[5][1], "unset\n")
            # Both say the command timed out; the exit codes differ (LocalEnvironment gives the
            # signal's negative, plimsoll the step's own code), and ADK's tool reads timed_out.
            self.assertEqual((timeout.timed_out, local_timeout.timed_out), (True, True))
        run(go())

    def test_a_scripted_agent_through_adks_runner(self) -> None:
        async def go() -> None:
            SPANS.clear()
            env = environment()
            model = scripted(
                [("WriteFile", {"path": "greet.sh", "content": "echo hello from $(basename \"$PWD\")\n"})],
                [("Execute", {"command": "sh greet.sh"})],
                [("EditFile", {"path": "greet.sh", "old_string": "hello", "new_string": "goodbye"})],
                [("ReadFile", {"path": "greet.sh"})],
                [("Execute", {"command": "sh greet.sh"})],
                "finished",
            )
            try:
                events = await run_agent(env, model, [PlimsollEnvironmentGuard()])
            finally:
                await env.close()
            answers = [r.response for r in responses_of(events)]
            self.assertEqual([a["status"] for a in answers], ["ok"] * 5)
            self.assertEqual(answers[1]["stdout"], "hello from work\n")
            self.assertIn("goodbye from $(basename", answers[3]["content"])
            self.assertEqual(answers[4]["stdout"], "goodbye from work\n")
            ids = {r.id for r in responses_of(events)}
            calls = [c for c in env.calls if c.function_call_id is not None]
            self.assertEqual({c.function_call_id for c in calls}, ids)
            spans = [sp for sp in SPANS.get_finished_spans() if sp.name == "execute_tool Execute"]
            self.assertEqual(len(spans), 2)
            for sp in spans:
                mine = [c.record_sha256 for c in calls if c.function_call_id == sp.attributes["gen_ai.tool.call.id"]]
                self.assertEqual(list(sp.attributes["plimsoll_record_sha256"]), mine)
                self.assertEqual(list(sp.attributes["plimsoll_isolation"]), [_setting("PLIMSOLL_DOCKER_FLOOR")])
        run(go())


if __name__ == "__main__":
    unittest.main()
