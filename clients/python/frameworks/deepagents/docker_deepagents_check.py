"""The Deep Agents backend on a real docker session (plimsoll/sandbox-python under the
docker provider), run by TestDeepAgentsDocker in make docker-suite: LangChain's standard
sandbox tests (langchain-tests' SandboxIntegrationTests: deepagents' own python3 scripts for
ls, read, edit, grep and glob, through plimsoll's BusyBox shell), then a Deep Agents agent
driven by a scripted model (no model is called) through every file tool and execute.

Not a test_*.py, so the framework suite in make clients-suite, which has no docker, never
collects it."""

from __future__ import annotations

import os
from typing import Any, Dict, Iterator, List

import pytest
from deepagents import create_deep_agent
from deepagents.backends.protocol import SandboxBackendProtocol
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_tests.integration_tests import SandboxIntegrationTests

from plimsoll_client import CheckpointConflictError, Client, MemoryCheckpointStore
from plimsoll_client.deepagents import PlimsollSandbox

URL = os.environ.get("PLIMSOLL_DOCKER_SESSIONS_URL", "")
TOKEN = os.environ.get("PLIMSOLL_DOCKER_TOKEN") or None
# The tier the daemon's docker runtime gives: container under runc, kernel under runsc.
FLOOR = os.environ.get("PLIMSOLL_DOCKER_FLOOR", "container")

if not URL:
    pytest.fail("PLIMSOLL_DOCKER_SESSIONS_URL is not set: run through TestDeepAgentsDocker (make docker-suite)", pytrace=False)


# Cases where langchain-tests and deepagents 0.7.38 disagree with each other: they fail
# the same way for a plain local-shell BaseSandbox that has nothing of plimsoll's (checked
# 2026-11-14 at langchain-tests 1.1.9, private/langchain-plimsoll-plan-2026-11-14.md; the
# same seven, and only they, at 1.2.0 on 2026-11-25). deepagents' glob
# answers absolute paths of regular files only ("glob's tool contract is absolute paths";
# "Regular files only"), where the suite expects names relative to the search root and
# directories; deepagents' write overwrites (its preflight only makes the parent
# directories), where the suite expects "already exists". Each must still fail on its
# assertion (strict): when the two packages agree again the case passes and this fails.
_GLOB = "the suite expects root-relative names and directories; deepagents 0.7.38 answers absolute paths of files only"
UPSTREAM_DISAGREEMENTS = {
    "test_glob": _GLOB,
    "test_glob_basic_pattern": _GLOB,
    "test_glob_with_question_mark": _GLOB,
    "test_glob_with_character_class": _GLOB,
    "test_glob_hidden_files_explicitly": _GLOB,
    "test_glob_with_directories": _GLOB,
    "test_write_existing_file_fails": "the suite expects an existing file to be refused; deepagents 0.7.38's write overwrites it",
}


def _expected_to_fail(name: str, why: str) -> Any:
    base = getattr(SandboxIntegrationTests, name)

    def case(self: Any, sandbox_backend: SandboxBackendProtocol, sandbox_test_root: str) -> None:
        base(self, sandbox_backend, sandbox_test_root)

    case.__name__ = name
    return pytest.mark.xfail(strict=True, raises=AssertionError, reason=why)(case)


def client() -> Client:
    return Client(URL, TOKEN, daemon_name="docker-check")


def open_backend() -> PlimsollSandbox:
    return PlimsollSandbox.open(client(), minimum_isolation=FLOOR)


class TestPlimsollSandboxStandard(SandboxIntegrationTests):
    @property
    def sandbox_root_dir(self) -> str:
        # The work directory, not the suite's /tmp default: on docker /tmp is a 16 MiB
        # tmpfs (the provider's TmpDiskMB default) and the suite's large-file cases fill it; the work
        # directory is where an agent's files go, under the run's own disk limit.
        return "/work/test_sandbox_ops/"

    @pytest.fixture(scope="class")
    def sandbox(self) -> Iterator[SandboxBackendProtocol]:
        backend = open_backend()
        try:
            yield backend
        finally:
            backend.close()


for _name, _why in UPSTREAM_DISAGREEMENTS.items():
    setattr(TestPlimsollSandboxStandard, _name, _expected_to_fail(_name, _why))


class Scripted(GenericFakeChatModel):
    def bind_tools(self, tools: Any, **kwargs: Any) -> "Scripted":
        return self


def calls(*steps: Dict[str, Any]) -> List[AIMessage]:
    return [AIMessage(content="", tool_calls=[{"name": s["tool"], "args": s["args"], "id": f"c{i}", "type": "tool_call"}])
            for i, s in enumerate(steps)] + [AIMessage(content="done")]


def test_a_deep_agent_works_in_the_session() -> None:
    with open_backend() as backend:
        root = backend.root
        app = f"{root}/app"
        script = calls(
            {"tool": "write_file", "args": {"file_path": f"{app}/main.py", "content": "import sys\nprint('total', sum(range(5)))\n"}},
            {"tool": "execute", "args": {"command": f"cd {app} && python3 main.py && echo warn >&2"}},
            {"tool": "edit_file", "args": {"file_path": f"{app}/main.py", "old_string": "range(5)", "new_string": "range(10)"}},
            {"tool": "execute", "args": {"command": "python3 main.py"}},  # the shell is still in app/
            {"tool": "read_file", "args": {"file_path": f"{app}/main.py"}},
            {"tool": "ls", "args": {"path": app}},
            {"tool": "grep", "args": {"pattern": "total", "path": root}},
            {"tool": "glob", "args": {"pattern": "**/*.py", "path": root}},
            {"tool": "execute", "args": {"command": "exit 7"}},
        )
        agent = create_deep_agent(model=Scripted(messages=iter(script)), backend=backend, system_prompt=f"Work in {root}.")
        out = agent.invoke({"messages": [{"role": "user", "content": "go"}]})
        got = [m for m in out["messages"] if isinstance(m, ToolMessage)]
        assert [m.name for m in got] == ["write_file", "execute", "edit_file", "execute", "read_file", "ls", "grep", "glob", "execute"]
        assert all(m.status != "error" for m in got), [(m.name, m.content) for m in got if m.status == "error"]
        text = [str(m.content) for m in got]
        assert "total 10" in text[1] and "[stderr] warn" in text[1] and "exit code 0" in text[1], text[1]
        assert "total 45" in text[3], text[3]
        assert "range(10)" in text[4], text[4]
        assert "main.py" in text[5], text[5]
        assert "main.py" in text[6], text[6]
        assert "main.py" in text[7], text[7]
        assert "exit code 7" in text[8], text[8]


def test_files_outside_the_work_directory_and_a_timeout() -> None:
    with open_backend() as backend:
        (up,) = backend.upload_files([("/tmp/plimsoll-check/a.bin", bytes(range(256)))])
        assert up.error is None, up.error
        (down,) = backend.download_files(["/tmp/plimsoll-check/a.bin"])
        assert down.content == bytes(range(256)), down.error
        r = backend.execute("echo started; sleep 30", timeout=2)
        assert r.exit_code == 124 and "timed out after 2 seconds" in r.output and "started" in r.output, r


def test_a_thread_resumed_on_another_worker_gets_the_same_sandbox() -> None:
    # Two backends standing for two workers: the second takes the session over by its key,
    # finds the first one's file, and the first is refused from then on.
    store = MemoryCheckpointStore()
    first = PlimsollSandbox.open(client(), minimum_isolation=FLOOR, checkpoint_store=store, checkpoint_key="user-1/thread-1")
    (up,) = first.upload_files([("/work/notes.txt", b"from the first worker")])
    assert up.error is None, up.error
    second = PlimsollSandbox.attach(client(), "user-1/thread-1", store=store, minimum_isolation=FLOOR)
    try:
        assert second.id == first.id
        (down,) = second.download_files(["/work/notes.txt"])
        assert down.content == b"from the first worker", down.error
        with pytest.raises(CheckpointConflictError):
            first.execute("echo the stale worker")
        assert second.execute("cat /work/notes.txt").output == "from the first worker"
    finally:
        second.close()
