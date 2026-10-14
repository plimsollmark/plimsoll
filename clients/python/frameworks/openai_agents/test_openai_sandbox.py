"""The Agents SDK sandbox provider over a plimsoll workspace: the real SDK's base classes,
state and exec path, a workspace faked in memory, and no model call anywhere. The
daemon-backed cases use the in-memory session daemon client_test.go serves, which runs
nothing, so they create and delete without starting."""

from __future__ import annotations

import asyncio
import io
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.sandbox.errors import ExecTimeoutError
from agents.sandbox.manifest import Manifest
from agents.sandbox.session import SandboxSession, SandboxSessionState
from agents.sandbox.types import ExecResult

from plimsoll_client import Client, SessionEndedError
from plimsoll_client.openai_sandbox import (
    PlimsollSandboxClient,
    PlimsollSandboxClientOptions,
    PlimsollSandboxSession,
    PlimsollSandboxSessionState,
)
from plimsoll_client.workspace import ExecOutcome
from tests._env import setting


def outcome(stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0, timed_out: bool = False) -> ExecOutcome:
    return ExecOutcome(stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=timed_out, stdout_truncated=False, stderr_truncated=False, cwd="/work", result=None)  # type: ignore[arg-type]


class FakeSession:
    fingerprint = "fp-fake"
    isolation = "container"

    def __init__(self) -> None:
        self.closed = False

    def ended(self) -> Optional[str]:
        return "closed" if self.closed else None

    def close(self) -> None:
        self.closed = True


class FakeWorkspace:
    root = "/work"

    def __init__(self) -> None:
        self.session = FakeSession()
        self.files: Dict[str, bytes] = {}
        self.commands: List[str] = []
        self.hydrated: List[bytes] = []

    def exec(self, command: str, *, timeout: Optional[float] = None) -> ExecOutcome:
        self.commands.append(command)
        if command.startswith("echo "):
            return outcome(stdout=(command[5:] + "\n").encode())
        if command == "false":
            return outcome(stderr=b"no\n", exit_code=1)
        if command.startswith("sleep"):
            return outcome(exit_code=124, timed_out=True)
        return outcome()

    def read(self, path: str, *, max_bytes: int = 1 << 20) -> bytes:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path][:max_bytes]

    def write(self, path: str, content: Any) -> None:
        self.files[path] = content.encode() if isinstance(content, str) else bytes(content)

    def persist(self) -> bytes:
        return b"TAR:" + ",".join(sorted(self.files)).encode()

    def hydrate(self, data: bytes) -> None:
        self.hydrated.append(data)

    def close(self) -> None:
        self.session.close()


_LOOPS: List[asyncio.AbstractEventLoop] = []


def tearDownModule() -> None:
    for loop in _LOOPS:
        if not loop.is_closed():
            loop.close()


class Harness:
    def __init__(self) -> None:
        self.made: List[FakeWorkspace] = []
        self.options_seen: List[PlimsollSandboxClientOptions] = []

        def factory(options: PlimsollSandboxClientOptions) -> FakeWorkspace:
            self.options_seen.append(options)
            ws = FakeWorkspace()
            self.made.append(ws)
            return ws

        self.client = PlimsollSandboxClient(None, workspace_factory=factory)
        self.loop = asyncio.new_event_loop()
        _LOOPS.append(self.loop)

    def run(self, coro: Any) -> Any:
        return self.loop.run_until_complete(coro)

    def create(self, **kw: Any) -> SandboxSession:
        return self.run(self.client.create(**kw))


class ProviderTests(unittest.TestCase):
    def test_backend_and_options(self) -> None:
        self.assertEqual(PlimsollSandboxClient.backend_id, "plimsoll")
        self.assertTrue(PlimsollSandboxClient.supports_default_options)
        o = PlimsollSandboxClientOptions()
        self.assertEqual((o.type, o.minimum_isolation, o.languages, o.timeout), ("plimsoll", "kernel", ("python",), 120.0))
        o = PlimsollSandboxClientOptions("container", ("python", "javascript"), 30)
        self.assertEqual((o.minimum_isolation, o.languages, o.timeout), ("container", ("python", "javascript"), 30))
        with self.assertRaises(ValueError):
            PlimsollSandboxClient(None)

    def test_create_learns_the_root_and_the_state_carries_no_session_id(self) -> None:
        h = Harness()
        session = h.create(options=PlimsollSandboxClientOptions(minimum_isolation="container"))
        inner = session._inner
        self.assertIsInstance(inner, PlimsollSandboxSession)
        self.assertEqual(h.options_seen[0].minimum_isolation, "container")
        self.assertEqual(inner.state.type, "plimsoll")
        self.assertEqual(inner.state.manifest.root, "/work")
        self.assertEqual(inner.state.fingerprint, "fp-fake")
        self.assertEqual(inner.state.isolation, "container")
        self.assertEqual(inner.state.minimum_isolation, "container")
        payload = h.client.serialize_session_state(inner.state)
        self.assertNotIn("session", {k for k in payload if k != "session_id"} - {"session_id"})
        self.assertEqual(payload["type"], "plimsoll")
        back = h.client.deserialize_session_state(payload)
        self.assertIsInstance(back, PlimsollSandboxSessionState)
        self.assertEqual((back.session_id, back.manifest.root, back.fingerprint, back.minimum_isolation), (inner.state.session_id, "/work", "fp-fake", "container"))
        self.assertIsInstance(SandboxSessionState.parse(payload), PlimsollSandboxSessionState)

    def test_a_manifest_root_given_is_kept(self) -> None:
        h = Harness()
        session = h.create(manifest=Manifest(root="/tmp/work"))
        self.assertEqual(session._inner.state.manifest.root, "/tmp/work")

    def test_exec_through_the_sdk(self) -> None:
        h = Harness()
        session = h.create()
        ws = h.made[0]
        r = h.run(session.exec("echo hi"))
        self.assertIsInstance(r, ExecResult)
        self.assertEqual((r.stdout, r.stderr, r.exit_code), (b"hi\n", b"", 0))
        self.assertEqual(ws.commands[-1], "echo hi")  # the SDK's `sh -lc` prefix stripped
        r = h.run(session.exec("echo", "a b"))
        self.assertEqual(ws.commands[-1], "echo 'a b'")
        r = h.run(session.exec("false"))
        self.assertEqual((r.exit_code, r.stderr), (1, b"no\n"))
        with self.assertRaises(ExecTimeoutError):
            h.run(session.exec("sleep 9", timeout=0.5))
        r = h.run(session.exec("ls", "-l", shell=False))
        self.assertEqual(ws.commands[-1], "ls -l")

    def test_files_persist_and_hydrate(self) -> None:
        h = Harness()
        session = h.create()
        inner = session._inner
        ws = h.made[0]
        h.run(inner.write(Path("src/a.txt"), io.BytesIO(b"hello")))
        self.assertEqual(ws.files, {"src/a.txt": b"hello"})
        self.assertEqual(h.run(inner.read(Path("src/a.txt"))).read(), b"hello")
        with self.assertRaises(FileNotFoundError):
            h.run(inner.read(Path("missing")))
        tar = h.run(inner.persist_workspace()).read()
        self.assertEqual(tar, b"TAR:src/a.txt")
        h.run(inner.hydrate_workspace(io.BytesIO(tar)))
        self.assertEqual(ws.hydrated, [tar])
        self.assertFalse(inner.supports_pty())

    def test_running_stop_and_delete(self) -> None:
        h = Harness()
        session = h.create()
        inner = session._inner
        ws = h.made[0]
        self.assertFalse(h.run(inner.running()))
        h.run(inner._after_start())
        self.assertTrue(h.run(inner.running()))
        h.run(h.client.delete(session))
        self.assertTrue(ws.session.closed)
        self.assertFalse(h.run(inner.running()))

    def test_resume_opens_a_new_session_for_the_same_state(self) -> None:
        h = Harness()
        session = h.create(options=PlimsollSandboxClientOptions(minimum_isolation="container", languages=("javascript",)))
        state = session._inner.state
        payload = h.client.serialize_session_state(state)
        resumed = h.run(h.client.resume(h.client.deserialize_session_state(payload)))
        self.assertEqual(len(h.made), 2)
        self.assertEqual(h.options_seen[1].minimum_isolation, "container")
        self.assertEqual(h.options_seen[1].languages, ("javascript",))
        self.assertEqual(resumed._inner.state.session_id, state.session_id)
        self.assertEqual(resumed._inner.state.manifest.root, "/work")
        self.assertFalse(resumed._inner.state.workspace_root_ready)
        with self.assertRaises(TypeError):
            h.run(h.client.resume(SandboxSessionState(type="other", snapshot=state.snapshot, manifest=state.manifest)))

    def test_manifest_users_are_refused(self) -> None:
        h = Harness()
        session = h.create()
        inner = session._inner
        inner.state.manifest = inner.state.manifest.model_copy(update={"users": {"bob": {}}}, deep=True) if "users" in Manifest.model_fields else inner.state.manifest
        if "users" in Manifest.model_fields:
            with self.assertRaises(ValueError):
                h.run(inner.provision_manifest_accounts())


class DaemonTests(unittest.TestCase):
    """Through the in-memory session daemon (its sessions run nothing): a session is
    opened at the floor the options name and closed by delete."""

    def test_create_and_delete(self) -> None:
        client = PlimsollSandboxClient(Client(setting("PLIMSOLL_SESSIONS_URL")))
        loop = asyncio.new_event_loop()
        _LOOPS.append(loop)
        session = loop.run_until_complete(
            client.create(manifest=Manifest(root="/work"), options=PlimsollSandboxClientOptions(minimum_isolation="container"))
        )
        inner = session._inner
        self.assertEqual(inner.state.isolation, "container")
        self.assertEqual(inner.state.base_url, client._client.base_url)
        self.assertTrue(inner.state.fingerprint)
        self.assertNotIn(inner.workspace.session._id, str(client.serialize_session_state(inner.state)))
        loop.run_until_complete(client.delete(session))
        with self.assertRaises(SessionEndedError):
            inner.workspace.session.run_project({}, ["true"])


if __name__ == "__main__":
    unittest.main()
