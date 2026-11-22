"""The OpenAI Agents SDK sandbox provider on a real docker session, run by
TestPythonExamplesDocker (its openai_agents_check subtest) in make docker-suite: the SDK's Runner, driven by its
ScriptedModel (no model is called), through plimsoll's provider; then the isolation,
filesystem, network and process checks OpenAI's provider guide asks for on a real
sandbox ("Run real isolation, filesystem, network, and process tests on each supported
runtime/platform combination. Mock tests cannot establish those properties.",
openai.github.io/openai-agents-python/sandbox/custom-providers/, read 2026-11-17).

Not a test_*.py, so the framework suite in make clients-suite, which has no docker,
never collects it."""

from __future__ import annotations

import asyncio
import io
import os
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, List

from agents.sandbox import LocalSnapshotSpec

from frameworks.openai_agents._kit import SPANS, Events, call, check_labels, patch, plimsoll_labels, run_agent, script, tool_outputs
from plimsoll_client import Client
from plimsoll_client.openai_sandbox import PlimsollExecError, PlimsollExecResult, PlimsollSandboxClient, PlimsollSandboxClientOptions

URL = os.environ.get("PLIMSOLL_DOCKER_SESSIONS_URL", "")
# The tier the daemon's docker runtime gives: container under runc, kernel under runsc.
FLOOR = os.environ.get("PLIMSOLL_DOCKER_FLOOR", "container")

# Scratch files stay inside the repository (its gitignored tmp/), never the system /tmp.
SCRATCH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "tmp")
os.makedirs(SCRATCH, exist_ok=True)

if not URL:
    raise RuntimeError("PLIMSOLL_DOCKER_SESSIONS_URL is not set: run through TestPythonExamplesDocker (make docker-suite)")


# A one-pixel PNG, for the SDK's view_image tool.
DOT_PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="


def options(timeout: float = 60.0) -> PlimsollSandboxClientOptions:
    return PlimsollSandboxClientOptions(minimum_isolation=FLOOR, timeout=timeout)


class RunnerOnDocker(unittest.TestCase):
    """The SDK's own agent loop on a real session."""

    def setUp(self) -> None:
        self.events = Events()
        self.client = PlimsollSandboxClient(Client(URL), instrumentation=self.events.instrumentation)
        SPANS.ended.clear()

    def test_a_scripted_agent_runs_commands_and_files_and_the_app_sees_each_record(self) -> None:
        model = script(
            [call("exec_command", {"cmd": "mkdir -p sub && cd sub && echo hello > a.txt && pwd"}, 1)],
            [call("exec_command", {"cmd": "pwd; cat a.txt; export GREETING=hi"}, 2)],
            [call("exec_command", {"cmd": "echo \"$GREETING\"; exit 3"}, 3)],
            [patch("*** Begin Patch\n*** Add File: notes.md\n+line one\n+line two\n*** End Patch\n", 4)],
            [call("exec_command", {"cmd": "cat /work/notes.md && printf '%s' '" + DOT_PNG + "' | base64 -d > /work/dot.png"}, 5)],
            [call("view_image", {"path": "dot.png"}, 6)],
        )
        result = asyncio.run(run_agent(self.client, model, options()))
        out = tool_outputs(result)
        self.assertEqual(result.final_output, "done")
        self.assertIn("/work/sub", out[0])
        self.assertIn("Process exited with code 0", out[0])
        self.assertIn("/work/sub", out[1])  # the directory persists from one command to the next
        self.assertIn("hello", out[1])
        self.assertIn("hi", out[2])  # and so do the exports
        self.assertIn("Process exited with code 3", out[2])
        self.assertIn("line two", out[4], out)
        self.assertIn("data:image/png;base64,", out[5], "the SDK's view_image read the file through the provider")
        exec_events = self.events.finished("exec")
        self.assertEqual(len(exec_events), 4, [e.data for e in exec_events])
        digests = set()
        for event in exec_events:
            labels = plimsoll_labels(event.data)
            check_labels(self, labels, dispatched="yes", isolation=FLOOR, outcome="completed", record=True)
            self.assertEqual(event.data["plimsoll_record"]["sha256"], labels["plimsoll_record_sha256"])
            self.assertEqual(event.data["plimsoll_record"]["isolation"], FLOOR)
            digests.add(labels["plimsoll_record_sha256"])
        self.assertEqual(len(digests), 4, "each command has its own record")
        span_labels = [plimsoll_labels(d) for d in SPANS.named("sandbox.exec")]
        self.assertEqual([s["plimsoll_record_sha256"] for s in span_labels], [plimsoll_labels(e.data)["plimsoll_record_sha256"] for e in exec_events])

    def test_a_command_past_its_budget_times_out_and_the_session_goes_on(self) -> None:
        model = script(
            [call("exec_command", {"cmd": "sleep 30", "yield_time_ms": 1500}, 1)],
            [call("exec_command", {"cmd": "echo after"}, 2)],
        )
        t0 = time.monotonic()
        result = asyncio.run(run_agent(self.client, model, options()))
        elapsed = time.monotonic() - t0
        out = tool_outputs(result)
        self.assertIn("Command timed out after 1.500 seconds.", out[0])
        self.assertIn("after", out[1])
        self.assertLess(elapsed, 25, "the sleep was ended at its budget, not run out")
        timed_out = self.events.finished("exec")[0]
        check_labels(self, plimsoll_labels(timed_out.data), dispatched="yes", isolation=FLOOR, outcome="timed_out", record=True)


class SessionOnDocker(unittest.TestCase):
    """The provider's session, as an app drives it."""

    def setUp(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)  # after every session's cleanup (cleanups run last first)
        self.client = PlimsollSandboxClient(Client(URL))

    def run_(self, coro: Any) -> Any:
        return self.loop.run_until_complete(coro)

    def open(self) -> Any:
        session = self.run_(self.client.create(options=options()))
        self.run_(session.start())
        self.addCleanup(lambda: self.run_(session.aclose()))
        return session

    def test_exec_returns_the_checked_record(self) -> None:
        session = self.open()
        r = self.run_(session.exec("echo hi"))
        self.assertIsInstance(r, PlimsollExecResult)
        self.assertEqual((r.stdout, r.exit_code), (b"hi\n", 0))
        self.assertEqual(r.isolation, FLOOR)
        self.assertEqual(r.outcome, "completed")
        self.assertIsNotNone(r.record)
        self.assertEqual(r.record.sha256, r.record_sha256)
        self.assertEqual(r.record.isolation, FLOOR)

    def test_no_network_read_only_system_and_no_background_process(self) -> None:
        session = self.open()
        net = self.run_(session.exec("wget -q -T 3 -O - http://1.1.1.1/ || echo NO-NETWORK"))
        self.assertIn(b"NO-NETWORK", net.stdout)
        ro = self.run_(session.exec("touch /etc/plimsoll-probe 2>&1; echo rc=$?"))
        self.assertNotIn(b"rc=0", ro.stdout)
        self.run_(session.exec("sleep 300 >/dev/null 2>&1 &"))
        ps = self.run_(session.exec("ps -o args 2>/dev/null || ps"))
        self.assertNotIn(b"sleep 300", ps.stdout)

    def test_files_through_the_sdk_helpers(self) -> None:
        session = self.open()
        self.run_(session.write(Path("data/in.bin"), io.BytesIO(bytes(range(256)) * 4)))
        self.assertEqual(self.run_(session.read(Path("data/in.bin"))).read(), bytes(range(256)) * 4)
        self.assertEqual(self.run_(session.read_bounded(Path("data/in.bin"), max_bytes=10)), bytes(range(10)))
        with self.assertRaises(FileNotFoundError):
            self.run_(session.read(Path("data/missing")))
        listing = self.run_(session.ls(Path("data")))
        self.assertIn("in.bin", [Path(str(e.path)).name for e in listing])
        self.run_(session.mkdir(Path("data/sub/deeper"), parents=True))
        self.run_(session.mv(Path("data/in.bin"), Path("data/sub/moved.bin")))
        self.assertEqual(self.run_(session.read(Path("data/sub/moved.bin"))).read(), bytes(range(256)) * 4)
        self.run_(session.rm(Path("data/sub"), recursive=True))
        with self.assertRaises(FileNotFoundError):
            self.run_(session.read(Path("data/sub/moved.bin")))

    def test_cancelling_a_command_in_flight_cuts_it(self) -> None:
        session = self.open()

        async def main() -> float:
            task = asyncio.ensure_future(session.exec("sleep 40", timeout=60))
            await asyncio.sleep(2.0)
            t0 = time.monotonic()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            return time.monotonic() - t0

        self.assertLess(self.run_(main()), 2.0, "the await ended at once")
        # The cut call may have run and has no answer this client could check, so the
        # client sends nothing more on the session (once the cut call's thread has
        # returned, milliseconds), and says so before sending.
        deadline = time.monotonic() + 5
        while self.run_(session.running()) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(self.run_(session.running()))
        with self.assertRaises(PlimsollExecError) as caught:
            self.run_(session.exec("echo next"))
        self.assertEqual(caught.exception.not_dispatched, "request")
        self.assertIs(caught.exception.retryable, False)

    def test_stop_and_resume_restore_the_files(self) -> None:
        snapshots = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(snapshots.cleanup)
        session = self.run_(self.client.create(snapshot=LocalSnapshotSpec(base_path=Path(snapshots.name)), options=options()))
        self.run_(session.start())
        self.run_(session.exec("echo kept > kept.txt"))
        state = session.state
        self.run_(session.stop())
        self.run_(session.shutdown())
        payload = self.client.serialize_session_state(state)
        resumed = self.run_(self.client.resume(self.client.deserialize_session_state(payload)))
        self.run_(resumed.start())
        self.addCleanup(lambda: self.run_(resumed.aclose()))
        r = self.run_(resumed.exec("cat kept.txt"))
        self.assertEqual(r.stdout, b"kept\n")


if __name__ == "__main__":
    unittest.main()

