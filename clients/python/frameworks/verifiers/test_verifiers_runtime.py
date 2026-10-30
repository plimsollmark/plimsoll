"""The verifiers runtime plugin: verifiers' own machinery (config validation, provisioning,
runtime views, the network policy rules) driving the backend over a session faked in
memory, which interprets the workspace's fixed steps and keeps a real record chain. No
model is called. The daemon-backed cases use the in-memory sessions daemon client_test.go
serves, which runs nothing, so they cover only what is refused before anything runs. A
real docker session runs the same backend in docker_check.py."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shlex
import tempfile
import unittest
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

import verifiers.v1 as vf
from pydantic import TypeAdapter, ValidationError
from verifiers.v1.configs.runtime import NetworkPolicyConfig
from verifiers.v1.errors import SandboxError
from verifiers.v1.runtimes import RuntimeConfig, backend_cls, provision_runtime
from verifiers.v1.utils.compile import resolve_runtime_config

from plimsoll_client import workspace as ws
from plimsoll_client._record import VERSION, record_digest
from plimsoll_client.errors import IsolationEvidenceMismatchError
from plimsoll_client.types import Artifact, PayloadEnvironment, ProjectResult, RunRecord, SessionSummary, StepResult, meets
from plimsoll_client.verifiers_runtime import (
    IMPORT_PATH,
    PlimsollBackend,
    PlimsollConfig,
    PlimsollProcess,
    RecordLogError,
    check_record_log,
)
from tests._env import setting

ROOT = "/work"
STATE = ROOT + "/" + ws.STATE_DIR
ENVIRONMENT = "fake-image:sha256:0001"

Program = Callable[["FakeSandbox", List[str], Dict[str, str], bytes], Tuple[int, bytes, bytes]]


def parse_script(text: str) -> Tuple[Dict[str, str], List[str]]:
    """The environment and argv a run script sets, read back the way sh reads it."""
    words = shlex.split(text, posix=True)
    env: Dict[str, str] = {}
    i = 0
    while words[i] == "export":
        name, _, value = words[i + 1].partition("=")
        env[name] = value
        i += 2
    assert words[i] == "exec", text
    return env, words[i + 1 :]


def echo_program(sb: "FakeSandbox", argv: List[str], env: Dict[str, str], stdin: bytes) -> Tuple[int, bytes, bytes]:
    """cat echoes its stdin; anything else prints its arguments."""
    if argv == ["cat"]:
        return 0, stdin, b""
    return 0, (" ".join(argv) + "\n").encode(), b""


class FakeSandbox:
    """One session faked in memory: files by absolute path, the fixed steps interpreted, a
    run's program answered by ``program``, and a record chain the client's checks accept."""

    provider = "fake"
    software_identity = "fake-software"

    def __init__(self, program: Program = echo_program, isolation: str = "kernel") -> None:
        self.fingerprint = os.urandom(32).hex()
        self.isolation = isolation
        self.program = program
        self.files: Dict[str, bytes] = {}
        self.steps: List[str] = []
        self.runs: List[Tuple[List[str], Dict[str, str], bytes]] = []
        self.cancels: List[Any] = []
        self.flags: Dict[str, Any] = {}
        self.calls = 0
        self.last = ""
        self.closed = False

    @staticmethod
    def _path(p: str) -> str:
        return p if p.startswith("/") else ROOT + "/" + p

    def _text(self, p: str) -> str:
        return self.files[self._path(p)].decode()

    def run_project(self, files: Any, steps: List[str], artifacts: Any = (), *, timeout: Optional[float] = None, cancel: Any = None, **kw: Any) -> ProjectResult:
        assert not self.closed
        self.cancels.append(cancel)
        for name, content in (files or {}).items():
            self.files[self._path(name)] = content.encode()
        step = steps[0]
        self.steps.append(step)
        code, out, err = 0, b"", b""
        self.files[STATE + "/root"] = (ROOT + "\n").encode()
        if step == ws._RUN_STEP:
            stdin = base64.b64decode(self.files[STATE + "/in.b64"])
            env, argv = parse_script(self._text(STATE + "/run"))
            self.runs.append((argv, env, stdin))
            code, out, err = self.program(self, argv, env, stdin)
        elif step == ws._READ_STEP:
            path = self._path(self._text(STATE + "/a1"))
            if path in self.files:
                self.files[STATE + "/out"] = self.files[path][: int(self._text(STATE + "/a2"))]
            else:
                code, err = 1, b"head: no such file\n"
        elif step in (ws._WRITE_B64_STEP, ws._APPEND_B64_STEP):
            path = self._path(self._text(STATE + "/a1"))
            before = self.files.get(path, b"") if step == ws._APPEND_B64_STEP else b""
            self.files[path] = before + base64.b64decode(self.files[STATE + "/in.b64"])
        elif step not in (ws._ROOT_STEP, ws._TRUE_STEP):
            raise AssertionError(f"a step this fake does not know: {step[:60]}")
        self.calls += 1
        record = RunRecord(
            version=VERSION,
            request_sha256="a" * 64,
            result_sha256="b" * 64,
            provider=self.provider,
            isolation=self.isolation,
            environment=ENVIRONMENT,
            policy="",
            software_identity=self.software_identity,
            software_rule_id="",
            started_unix_ms=1,
            ended_unix_ms=2,
            session=self.fingerprint,
            sequence=self.calls,
            previous_sha256=self.last,
            sha256="",
        )
        record = replace(record, sha256=record_digest(record))
        self.last = record.sha256
        rels = {a: self.files[ROOT + "/" + a] for a in artifacts if ROOT + "/" + a in self.files}
        return ProjectResult(
            provider=self.provider,
            isolation=self.isolation,
            environment=ENVIRONMENT,
            software_identity=self.software_identity,
            duration_ms=1,
            record=record,
            outcome="timed_out" if self.flags.get("timed_out") else "completed",
            detail="",
            steps=(
                StepResult(
                    command="",
                    stdout=out,
                    stderr=err,
                    exit_code=124 if self.flags.get("timed_out") else code,
                    timed_out=bool(self.flags.get("timed_out")),
                    duration_ms=1,
                    stdout_truncated=bool(self.flags.get("stdout_truncated")),
                    stderr_truncated=False,
                ),
            ),
            artifacts=tuple(Artifact(p, c) for p, c in rels.items()),
            artifacts_truncated=False,
            advice=(),
        )

    def close(self) -> SessionSummary:
        self.closed = True
        return SessionSummary(session=self.fingerprint, calls=self.calls, last_record_sha256=self.last, end="closed")


class FakeClient:
    """Describe and open as a daemon with sessions answers them; the opened sandboxes are
    kept on the class for the test to inspect."""

    opened: List[Tuple[FakeSandbox, Dict[str, Any]]] = []
    next: List[FakeSandbox] = []
    sessions = True

    def describe(self) -> Any:
        return SimpleNamespace(
            supports_sessions=self.sessions,
            session_environment=PayloadEnvironment(identity=ENVIRONMENT, software_identity="fake-software", max_timeout_ms=300_000),
        )

    def open_session(self, **kwargs: Any) -> FakeSandbox:
        sb = FakeClient.next.pop(0) if FakeClient.next else FakeSandbox()
        floor = kwargs.get("minimum_isolation") or ""
        if floor and not meets(sb.isolation, floor):
            raise IsolationEvidenceMismatchError(f"plimsoll: the session opened at {sb.isolation}, below the requested minimum {floor}; the session was closed")
        FakeClient.opened.append((sb, kwargs))
        return sb


class FakeBackend(PlimsollBackend):
    def _client(self) -> Any:
        return FakeClient()


def plugin(**fields: Any) -> PlimsollConfig:
    data = {"type": "custom", "import_path": f"{__name__}.FakeBackend", "url": "http://127.0.0.1:1", **fields}
    config = TypeAdapter(RuntimeConfig).validate_python(data)
    assert isinstance(config, PlimsollConfig)
    return config


def task(**data: Any) -> vf.Task:
    return vf.Task(data=vf.TaskData(idx=0, prompt=None, **data))


class Reset(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        FakeClient.opened = []
        FakeClient.next = []
        FakeClient.sessions = True


class ConfigTests(unittest.TestCase):
    def test_the_config_loads_as_the_plugins_own(self) -> None:
        config = TypeAdapter(RuntimeConfig).validate_python({"type": "custom", "import_path": IMPORT_PATH, "url": "http://127.0.0.1:8080"})
        self.assertIsInstance(config, PlimsollConfig)
        self.assertIs(backend_cls(config), PlimsollBackend)
        self.assertIsInstance(config, NetworkPolicyConfig)
        self.assertEqual(config.allow, [])
        self.assertTrue(config.network_restricted)
        self.assertEqual(config.minimum_isolation, "kernel")
        self.assertEqual(config.token_env, "PLIMSOLL_TOKEN")
        self.assertNotIn("token", config.model_dump())

    def test_no_destination_can_be_allowed(self) -> None:
        for allow in (["pypi.org"], ["*"]):
            with self.assertRaises(ValidationError, msg=allow):
                plugin(allow=allow)
        for floor in ("process", "none", ""):
            with self.assertRaises(ValidationError, msg=floor):
                plugin(minimum_isolation=floor)

    def test_the_features_it_declares(self) -> None:
        self.assertTrue(PlimsollBackend.SUPPORTS_TASK_IMAGES)
        self.assertFalse(PlimsollBackend.SUPPORTS_USER_SWITCHING)
        self.assertFalse(PlimsollBackend.SUPPORTS_PORT_EXPOSURE)
        self.assertFalse(PlimsollBackend.SUPPORTS_COMPOSE)
        self.assertTrue(PlimsollBackend.is_local)

    def test_task_network_policies(self) -> None:
        config = plugin()
        # A task that asks for no egress gets it: there is none.
        resolved = resolve_runtime_config(config, task(network=NetworkPolicyConfig(allow=[])))
        self.assertEqual(resolved.allow, [])
        # A task that asks for a host is refused before anything is provisioned.
        with self.assertRaises((ValueError, ValidationError)):
            resolve_runtime_config(config, task(network=NetworkPolicyConfig(allow=["pypi.org"])))
        with self.assertRaises(ValueError):
            resolve_runtime_config(config, task(agent_user="agent"))


class LifecycleTests(Reset):
    async def test_start_opens_one_session_at_the_floor_and_close_ends_it(self) -> None:
        async with provision_runtime(plugin(minimum_isolation="kernel", lifetime=60)) as view:
            self.assertEqual(len(FakeClient.opened), 1)
            sb, kwargs = FakeClient.opened[0]
            self.assertEqual(kwargs["minimum_isolation"], "kernel")
            self.assertEqual(kwargs["lifetime"], 60)
            self.assertEqual(kwargs["trace_id"], view.name)
            self.assertEqual(view.info.id, sb.fingerprint)
            self.assertEqual(view.info.isolation, "kernel")
            self.assertEqual(view.info.environment, ENVIRONMENT)
            self.assertEqual(view.config.workdir, ROOT)
            self.assertEqual(view.config.image, ENVIRONMENT)
            self.assertEqual(sb.steps, [ws._ROOT_STEP])
        self.assertTrue(sb.closed)

    async def test_a_floor_the_daemon_does_not_meet_is_refused(self) -> None:
        FakeClient.next = [FakeSandbox(isolation="container")]
        with self.assertRaisesRegex(SandboxError, "below the requested minimum kernel"):
            async with provision_runtime(plugin()):
                pass
        self.assertEqual(FakeClient.opened, [])

    async def test_another_image_is_refused_before_a_session_opens(self) -> None:
        with self.assertRaisesRegex(SandboxError, "runs only the daemon's image fake-image.*python:3.12-alpine"):
            async with provision_runtime(plugin(image="python:3.12-alpine")):
                pass
        self.assertEqual(FakeClient.opened, [])
        async with provision_runtime(plugin(image=ENVIRONMENT)) as view:
            self.assertEqual(view.config.image, ENVIRONMENT)

    async def test_another_work_directory_is_refused_and_the_session_closed(self) -> None:
        # The echo program prints its arguments, so the sandbox reports no such directory.
        with self.assertRaisesRegex(SandboxError, "daemon's directory /work; the task asks for '/app', which the daemon's image does not make"):
            async with provision_runtime(plugin(workdir="/app")):
                pass
        self.assertTrue(FakeClient.opened[0][0].closed)
        async with provision_runtime(plugin(workdir="/work/")) as view:
            self.assertEqual(view.config.workdir, ROOT)
        # The same directory needs no call to say so.
        self.assertEqual(FakeClient.opened[-1][0].steps, [ws._ROOT_STEP])

    async def test_a_work_directory_the_image_links_to_the_session_s_is_accepted(self) -> None:
        asked: List[List[str]] = []

        def resolve(links: Dict[str, str]) -> Program:
            def program(sb: "FakeSandbox", argv: List[str], env: Dict[str, str], stdin: bytes) -> Tuple[int, bytes, bytes]:
                asked.append(argv)
                if argv[:2] != ["sh", "-c"] or argv[3] != "same-directory":
                    return echo_program(sb, argv, env, stdin)
                out = []
                for path in argv[4:]:
                    if path not in links:
                        return 1, b"", f"cd: {path}: No such file or directory\n".encode()
                    out.append(links[path])
                return 0, ("\n".join(out) + "\n").encode(), b""

            return program

        FakeClient.next = [FakeSandbox(program=resolve({"/workspace": ROOT, ROOT: ROOT}))]
        async with provision_runtime(plugin(workdir="/workspace")) as view:
            self.assertEqual(view.config.workdir, "/workspace")
        self.assertEqual(asked[0][4:], ["/workspace", ROOT])
        # A directory of its own, or none at all, is refused, and the session closed.
        for links in ({"/workspace": "/workspace", ROOT: ROOT}, {ROOT: ROOT}):
            FakeClient.next = [FakeSandbox(program=resolve(links))]
            with self.assertRaisesRegex(SandboxError, "asks for '/workspace', which the daemon's image does not make that directory"):
                async with provision_runtime(plugin(workdir="/workspace")):
                    pass
            self.assertTrue(FakeClient.opened[-1][0].closed)

    async def test_a_daemon_without_sessions_is_refused(self) -> None:
        FakeClient.sessions = False
        with self.assertRaisesRegex(SandboxError, "offers no sessions"):
            async with provision_runtime(plugin()):
                pass


class OperationTests(Reset):
    async def test_run_passes_argv_and_env_as_given_and_closes_stdin(self) -> None:
        argv = ["printf", "%s\n", "a b", "it's", "$(id)", "`id`", "line\nbreak", "ünï", "*", "-"]
        async with provision_runtime(plugin()) as view:
            sb = FakeClient.opened[0][0]
            result = await view.with_env({"FROM_VIEW": "v"}).run(argv, {"GREETING": "hi 'there'\n"})
            self.assertEqual(result.exit_code, 0)
            got_argv, got_env, stdin = sb.runs[-1]
            self.assertEqual(got_argv, argv)
            self.assertEqual(got_env, {"FROM_VIEW": "v", "GREETING": "hi 'there'\n"})
            self.assertEqual(stdin, b"")
            self.assertEqual(sb.steps[-1], ws._RUN_STEP)
            with self.assertRaises(ValueError):
                await view.run(["true"], {"NOT A NAME": "x"})
            with self.assertRaises(ValueError):
                await view.run([], {})

    async def test_exit_codes_timeouts_and_cuts_come_back_as_results(self) -> None:
        sb = FakeSandbox(program=lambda sb, argv, env, stdin: (3, b"out\n", b"err\n"))
        FakeClient.next = [sb]
        async with provision_runtime(plugin()) as view:
            result = await view.run(["sh", "-c", "exit 3"], {})
            self.assertEqual((result.exit_code, result.stdout, result.stderr), (3, "out\n", "err\n"))
            sb.flags = {"timed_out": True, "stdout_truncated": True}
            result = await view.run(["sleep", "999"], {})
            self.assertEqual(result.exit_code, 124)
            self.assertIn("ran past its budget", result.stderr)
            self.assertIn("stdout was cut", result.stderr)

    async def test_exec_is_buffered(self) -> None:
        async with provision_runtime(plugin()) as view:
            sb = FakeClient.opened[0][0]
            process = await view.exec(["cat"], {})
            self.assertIsInstance(process, PlimsollProcess)
            await process.write(b"ping\n")
            self.assertIsNone(await process.poll())
            self.assertEqual(sb.runs, [])
            stdout = b"".join([chunk async for chunk in process.stdout])
            stderr = b"".join([chunk async for chunk in process.stderr])
            self.assertEqual((stdout, stderr), (b"ping\n", b""))
            self.assertEqual(await process.wait(), 0)
            self.assertEqual(await process.poll(), 0)
            self.assertEqual(sb.runs[-1][2], b"ping\n")
            with self.assertRaises(BrokenPipeError):
                await process.write(b"more")
            # Killed before it was asked for anything: it never runs.
            sleeper = await view.exec(["sleep", "600"], {})
            self.assertIsNone(await sleeper.poll())
            await sleeper.kill()
            self.assertEqual(await sleeper.wait(), 137)
            self.assertEqual(len(sb.runs), 1)

    async def test_files_inside_and_outside_the_work_directory(self) -> None:
        async with provision_runtime(plugin()) as view:
            sb = FakeClient.opened[0][0]
            data = bytes(range(256)) * 64
            await view.write("vf-check/nested/data.bin", data)
            self.assertEqual(sb.files[ROOT + "/vf-check/nested/data.bin"], data)
            self.assertEqual(await view.read("vf-check/nested/data.bin"), data)
            self.assertEqual(await view.read("vf-check/nested/data.bin", max_bytes=len(data)), data)
            with self.assertRaises(SandboxError):
                await view.read("vf-check/nested/data.bin", max_bytes=10)
            await view.write("/tmp/vf-artifact-1.tar", b"tar")
            self.assertEqual(sb.files["/tmp/vf-artifact-1.tar"], b"tar")
            self.assertEqual(await view.read("/tmp/vf-artifact-1.tar"), b"tar")
            await view.write(ROOT + "/abs.txt", b"x")
            self.assertEqual(sb.files[ROOT + "/abs.txt"], b"x")
            with self.assertRaisesRegex(SandboxError, "missing"):
                await view.read("missing")
            for bad in (ws.STATE_DIR + "/run", ROOT + "/" + ws.STATE_DIR + "/in.b64", "/", "../escape", "a\nb"):
                with self.assertRaises(SandboxError, msg=bad):
                    await view.write(bad, b"x")

    async def test_what_it_refuses(self) -> None:
        async with provision_runtime(plugin()) as view:
            with self.assertRaisesRegex(SandboxError, "cannot keep a process running"):
                await view.run_background(["sh", "-c", "sleep 600"], {}, "bg.log")
            with self.assertRaisesRegex(SandboxError, "publishes no ports"):
                await view.expose(8000)
            with self.assertRaises(ValueError):
                view.with_user("agent")

    async def test_every_step_sent_is_a_fixed_script(self) -> None:
        async with provision_runtime(plugin()) as view:
            sb = FakeClient.opened[0][0]
            await view.run(["sh", "-c", "rm -rf /; echo $(id)"], {"X": "$(id)"})
            await view.write("/tmp/x", b"rm -rf /")
            await view.read("/tmp/x")
            process = await view.exec(["sh", "-c", "rm -rf /"], {})
            await process.wait()
            for step in sb.steps:
                self.assertIn(step, ws.FIXED_STEPS)
                self.assertNotIn("rm -rf", step)
                self.assertNotIn("$(id)", step)
            # Every call carried a cancel handle, so a cancelled await cuts its request.
            self.assertTrue(all(c is not None for c in sb.cancels[1:]))


class RecordLogTests(Reset):
    async def asyncSetUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "records", "log.jsonl")

    async def asyncTearDown(self) -> None:
        self.dir.cleanup()

    async def _one_rollout(self) -> FakeSandbox:
        async with provision_runtime(plugin(record_log=self.log)) as view:
            await view.run(["true"], {})
            await view.write("answer.txt", b"6\n")
            self.assertEqual(await view.read("answer.txt"), b"6\n")
            self.assertEqual(len(view.backend.records), 4)
        return FakeClient.opened[-1][0]

    def _entries(self) -> List[Dict[str, Any]]:
        with open(self.log, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def _rewrite(self, entries: List[Dict[str, Any]]) -> None:
        with open(self.log, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(e) + "\n" for e in entries)

    async def test_every_call_is_logged_and_the_log_checks(self) -> None:
        sb = await self._one_rollout()
        entries = self._entries()
        self.assertEqual([e["kind"] for e in entries], ["open", "record", "record", "record", "record", "close"])
        self.assertEqual([e["op"] for e in entries if e["kind"] == "record"], ["root", "run", "write", "read"])
        self.assertEqual(entries[0]["session"], sb.fingerprint)
        self.assertEqual(entries[-1]["calls"], 4)
        # No command text, argument or file content reaches the log: digests only.
        self.assertNotIn("answer.txt", json.dumps(entries))
        summary = check_record_log(self.log, minimum_isolation="kernel")
        self.assertEqual(summary, {"sessions": 1, "records": 4, "closed": 1, "tiers": {"kernel": 4}, "incomplete": []})
        await self._one_rollout()
        self.assertEqual(check_record_log(self.log)["sessions"], 2)

    async def test_concurrent_rollouts_share_one_log(self) -> None:
        # verifiers runs rollouts at once, each with its own backend, into one log.
        async def rollout() -> None:
            async with provision_runtime(plugin(record_log=self.log)) as view:
                for i in range(3):
                    await view.write(f"f{i}.txt", b"x")
                    await view.run(["true"], {})

        await asyncio.gather(*(rollout() for _ in range(8)))
        # Each: the root call, three writes and three runs.
        summary = check_record_log(self.log, minimum_isolation="kernel")
        self.assertEqual(summary, {"sessions": 8, "records": 56, "closed": 8, "tiers": {"kernel": 56}, "incomplete": []})
        kinds = [e["kind"] for e in self._entries()]
        self.assertEqual((kinds.count("open"), kinds.count("close")), (8, 8))

    async def test_a_changed_record_fails(self) -> None:
        await self._one_rollout()
        entries = self._entries()
        entries[2]["record"]["isolation"] = "vm"
        self._rewrite(entries)
        with self.assertRaisesRegex(RecordLogError, ":3: the record's digest does not match"):
            check_record_log(self.log)

    async def test_a_dropped_record_fails(self) -> None:
        await self._one_rollout()
        original = self._entries()
        self._rewrite(original[:2] + original[3:])  # the second record gone
        with self.assertRaisesRegex(RecordLogError, ":3: session .* call 3 follows"):
            check_record_log(self.log)
        self._rewrite(original[:3] + original[5:])  # the last two gone, the close still counting four
        with self.assertRaisesRegex(RecordLogError, "closed session .* after 4 calls, the log holds"):
            check_record_log(self.log)

    async def test_a_session_the_log_cannot_show_whole_is_named(self) -> None:
        await self._one_rollout()
        original = self._entries()
        session = original[0]["session"]
        # A call cut in flight: the client's close reports the daemon's larger count.
        cut = dict(original[-1])
        for key in ("calls", "last_record_sha256", "end"):
            cut.pop(key)
        cut["error"] = "plimsoll: the daemon counts 5 calls ending 'ab', this client saw 4 ending 'cd'"
        self._rewrite(original[:-1] + [cut])
        summary = check_record_log(self.log)
        self.assertEqual((summary["records"], summary["closed"]), (4, 0))
        self.assertEqual(summary["incomplete"], [{"session": session[:12], "records": 4, "reason": cut["error"]}])
        # No close at all: the session may still be open.
        self._rewrite(original[:-1])
        self.assertEqual(check_record_log(self.log)["incomplete"][0]["reason"], "no close in the log")

    async def test_a_tier_below_the_floor_fails(self) -> None:
        await self._one_rollout()
        with self.assertRaisesRegex(RecordLogError, "tier kernel is below vm"):
            check_record_log(self.log, minimum_isolation="vm")


class DaemonTests(unittest.IsolatedAsyncioTestCase):
    """Against the in-memory sessions daemon (container tier, runs nothing)."""

    def config(self, **fields: Any) -> PlimsollConfig:
        data = {"type": "custom", "import_path": IMPORT_PATH, "url": setting("PLIMSOLL_SESSIONS_URL"), **fields}
        return TypeAdapter(RuntimeConfig).validate_python(data)

    async def test_a_floor_above_the_daemon_is_refused_at_start(self) -> None:
        with self.assertRaisesRegex(SandboxError, "kernel"):
            async with provision_runtime(self.config(minimum_isolation="kernel")):
                pass

    async def test_an_image_the_daemon_does_not_run_is_refused(self) -> None:
        with self.assertRaisesRegex(SandboxError, "runs only the daemon's image"):
            async with provision_runtime(self.config(minimum_isolation="container", image="python:3.12-alpine")):
                pass


if __name__ == "__main__":
    unittest.main()
