"""The PydanticAI workspace on a real docker session, run by TestPydanticAIDocker in make docker-suite: PydanticAI's
own conformance suite (``pydantic_ai.workspaces.conformance.WorkspaceBackendSuite``) with the fixtures a backend of
files only supplies (``backend``, ``fresh_backend``, ``destructive_backend``, ``destroy_environment``, and
``attach_backend``: a backend of another capability, standing for another process, that takes the session over from a
shared checkpoint store),
run with ``-rs`` so every skipped rule is listed and the Go test compares the list with what the package promises;
then agents of the
real, installed PydanticAI with plimsoll's capability, driven by a scripted FunctionModel (no model is called):
PydanticAI's FileSystem tools reach the session (the integration test upstream asks for), its searches work on a
backend with no commands, plimsoll's shell tool sees the files they wrote, PydanticAI's Coder offers no shell, and
an agent in a second process that repeats a command canceled in the first is told what the daemon's record of it
says, its run going on.

Not a test_*.py, so the framework suite in make clients-suite, which has no docker, never collects it."""

from __future__ import annotations

import asyncio
import os
import threading
import uuid
from typing import Any, Callable, Iterator, List, Tuple

import pytest
from pydantic_ai import Agent
from pydantic_ai.workspaces import Workspace, WorkspaceBackend, WorkspaceRef
from pydantic_ai.workspaces.conformance import WorkspaceBackendSuite
from pydantic_ai_harness import Coder, FileSystem, Shell

from frameworks.pydantic_ai._scripted import Scripted
from plimsoll_client import CancelHandle, Client, MemoryCheckpointStore
from plimsoll_client.pydantic_ai import (
    PlimsollLostCallError,
    PlimsollOutcomeUnknownError,
    PlimsollWorkspace,
    PlimsollWorkspaceBackend,
    PlimsollWorkspaceGoneError,
)

URL = os.environ.get("PLIMSOLL_DOCKER_SESSIONS_URL", "")
TOKEN = os.environ.get("PLIMSOLL_DOCKER_TOKEN") or None
# The tier the daemon's docker runtime gives: container under runc, kernel under runsc.
FLOOR = os.environ.get("PLIMSOLL_DOCKER_FLOOR", "container")

if not URL:
    pytest.fail("PLIMSOLL_DOCKER_SESSIONS_URL is not set: run through TestPydanticAIDocker (make docker-suite)", pytrace=False)


def capability(**kw: Any) -> PlimsollWorkspace:
    return PlimsollWorkspace(client=Client(URL, TOKEN, daemon_name="plimsoll"), minimum_isolation=FLOOR, lifetime=600, **kw)


def stored(store: MemoryCheckpointStore) -> PlimsollWorkspace:
    """A capability whose sessions pass through ``store``; each one made stands for another process (its own
    registry of open sessions). Outside a run the key a run would derive from its verified user and conversation is
    passed to ``backend`` instead."""
    return capability(checkpoint_store=store, checkpoint_key=lambda ctx: "unused-outside-a-run")


def close_everywhere(caps: List[PlimsollWorkspace]) -> None:
    for cap in caps:
        for env in list(cap._open.values()):
            try:
                cap.destroy(env.ref)
            except Exception:
                pass  # another capability holds it now; it ends with its lifetime


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class TestPlimsollWorkspaceConformance(WorkspaceBackendSuite):
    """PydanticAI's rules for a workspace backend, on one fresh session per rule, every session's calls through one
    checkpoint store. The command rules skip (the backend claims no SupportsCommands), and so do the rules that set
    up a case with a command; an attached backend is another capability's, standing for another process."""

    @pytest.fixture
    def store(self) -> MemoryCheckpointStore:
        return MemoryCheckpointStore()

    @pytest.fixture
    def caps(self, store: MemoryCheckpointStore) -> Iterator[List[PlimsollWorkspace]]:
        made: List[PlimsollWorkspace] = [stored(store)]
        yield made
        close_everywhere(made)

    @pytest.fixture
    def made(self) -> List[Tuple[PlimsollWorkspaceBackend, str]]:
        return []  # every backend of the rule, with its store key

    @pytest.fixture
    def cap(self, caps: List[PlimsollWorkspace]) -> PlimsollWorkspace:
        return caps[0]

    @staticmethod
    def _make(cap: PlimsollWorkspace, made: List[Tuple[PlimsollWorkspaceBackend, str]]) -> PlimsollWorkspaceBackend:
        key = f"conformance/{uuid.uuid4().hex}"
        b = cap.backend(key=key)
        made.append((b, key))
        return b

    @pytest.fixture
    def backend(self, cap: PlimsollWorkspace, made: List[Tuple[PlimsollWorkspaceBackend, str]]) -> Iterator[WorkspaceBackend]:
        # A plain generator, not an async one: the cancellation rule skips from inside a task group, and an async
        # generator fixture's teardown then fails in anyio's runner (ClosedResourceError, pydantic-ai-slim 2.70.0
        # with anyio 4.16.0). The caps fixture closes the sessions.
        yield self._make(cap, made)

    @pytest.fixture
    def fresh_backend(self, cap: PlimsollWorkspace, made: List[Tuple[PlimsollWorkspaceBackend, str]]) -> Iterator[Callable[[], WorkspaceBackend]]:
        yield lambda: self._make(cap, made)

    @pytest.fixture
    def attach_backend(
        self, caps: List[PlimsollWorkspace], store: MemoryCheckpointStore, made: List[Tuple[PlimsollWorkspaceBackend, str]]
    ) -> Callable[[WorkspaceRef], WorkspaceBackend]:
        def attach(ref: WorkspaceRef) -> WorkspaceBackend:
            key = next(k for b, k in made if b.ref == ref)
            other = stored(store)
            caps.append(other)
            return other.backend(ref, key=key)

        return attach

    @pytest.fixture
    def destroy_environment(self, cap: PlimsollWorkspace) -> Callable[[WorkspaceBackend], Any]:
        async def destroy(backend: WorkspaceBackend) -> None:
            assert backend.ref is not None
            await asyncio.to_thread(cap.destroy, backend.ref)

        return destroy


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_filesystem_tools_reach_the_session_and_the_shell_tool_sees_their_files() -> None:
    """The integration test upstream asks of a workspace (pydantic-ai issue 13728): an Agent with a model that calls
    no provider, PydanticAI's FileSystem, and plimsoll's capability; the file tools reach the backend's session."""
    cap = capability()
    script = Scripted(
        ("create_directory", {"path": "notes"}),
        ("write_file", {"path": "notes/a.txt", "content": "alpha\nbeta\n"}),
        ("read_file", {"path": "notes/a.txt"}),
        ("edit_file", {"path": "notes/a.txt", "old_text": "beta", "new_text": "gamma"}),
        ("list_directory", {"path": "notes"}),
        ("file_info", {"path": "notes/a.txt"}),
        ("plimsoll_shell", {"command": "cat notes/a.txt; pwd"}),
    )
    agent = Agent(script.model, capabilities=[cap, FileSystem(content_hashes=False)])
    run(agent.run("go"))
    try:
        assert "read_file" in script.offered[0] and "plimsoll_shell" in script.offered[0]
        assert "alpha" in str(script.returned("read_file")[0])
        assert "a.txt" in str(script.returned("list_directory")[0])
        shell = str(script.returned("plimsoll_shell")[0])
        assert "exit code: 0" in shell and "alpha\ngamma" in shell, shell
        opened = [env for env in cap._open.values()]
        assert len(opened) == 1, "the run's tools used one session"
        assert opened[0].records, "every call's record was kept"
    finally:
        for env in list(cap._open.values()):
            cap.destroy(env.ref)


def test_filesystem_searches_walk_files_on_a_backend_with_no_commands() -> None:
    """Stage 0's third measurement: FileSystem's search_files and find_files on a backend that has no commands walk
    the files through the filesystem operations instead of running rg."""
    cap = capability()
    script = Scripted(
        ("create_directory", {"path": "src"}),
        ("write_file", {"path": "src/one.py", "content": "def needle():\n    return 1\n"}),
        ("write_file", {"path": "src/two.txt", "content": "no match here\n"}),
        ("search_files", {"pattern": "needle", "path": "."}),
        ("find_files", {"pattern": "**/*.py", "path": "."}),
    )
    agent = Agent(script.model, capabilities=[cap, FileSystem(content_hashes=False)])
    try:
        run(agent.run("go"))
        found = str(script.returned("search_files")[0])
        assert "one.py" in found and "two.txt" not in found, found
        listed = str(script.returned("find_files")[0])
        assert "src/one.py" in listed and "two.txt" not in listed, listed
    finally:
        for env in list(cap._open.values()):
            cap.destroy(env.ref)


def test_coder_and_shell_offer_no_shell_on_this_backend() -> None:
    """Stage 0's fourth measurement, what the README tells users: PydanticAI's Coder, and its Shell, on a backend
    with no commands neither refuse at the run's start nor at a first command, and raise nothing: their shell tools
    are left out of the model's tools (harness 0.70.0's ShellToolset offers none without SupportsCommands), so only
    plimsoll's shell tool is there."""
    for kit in (Coder, Shell):
        cap = capability()
        script = Scripted(("plimsoll_shell", {"command": "echo still here"}))
        agent = Agent(script.model, capabilities=[cap, kit()])
        try:
            run(agent.run("go"))
            print(f"tools {kit.__name__}'s agent offered:", script.offered[0])
            assert "shell" not in script.offered[0] and "run_command" not in script.offered[0], (kit, script.offered[0])
            assert "plimsoll_shell" in script.offered[0]
            assert "still here" in str(script.returned("plimsoll_shell")[0])
        finally:
            for env in list(cap._open.values()):
                cap.destroy(env.ref)


def test_a_later_run_reaches_the_same_session_by_its_ref_in_this_process() -> None:
    cap = capability()
    first = Scripted(("write_file", {"path": "kept.txt", "content": "from the first run\n"}))
    agent = Agent(first.model, capabilities=[cap, FileSystem(content_hashes=False)])
    result = run(agent.run("go"))
    try:
        second = Scripted(("read_file", {"path": "kept.txt"}))
        again = Agent(second.model, capabilities=[cap, FileSystem(content_hashes=False)])
        run(again.run("again", message_history=result.all_messages()))
        assert "from the first run" in str(second.returned("read_file")[0])
        assert len(cap._open) == 1, "the second run opened no session of its own"
    finally:
        for env in list(cap._open.values()):
            cap.destroy(env.ref)


def test_realpath_and_entries_follow_symlinks_made_by_the_shell_tool() -> None:
    """The conformance rule test_realpath_and_entries_follow_symlinks needs commands to make its links, so it skips
    on this backend; the same links, made through plimsoll's shell tool in the same session, and the rule's own
    expectations of the backend's realpath, stat and list_dir. BusyBox's realpath cannot answer these (it
    fails on a missing component and on a loop): the backend resolves them with its own script."""
    cap = capability()

    async def go() -> None:
        b = cap.backend()
        ws = Workspace(b)
        root = await ws.working_dir()
        base = root + "/links"
        out = await asyncio.to_thread(
            b._shell,
            "mkdir -p links/target links/a/b && cd links && ln -s $PWD/target link && "
            "ln -s b a/rel && ln -s ../out a/up && ln -s loop2 a/loop1 && ln -s loop1 a/loop2",
            30.0, CancelHandle(),
        )
        assert out.exit_code == 0, out.stderr_text
        join = ws.paths.join
        target, link, a = join(base, "target"), join(base, "link"), join(base, "a")
        assert await ws.realpath(join(link, "missing")) == join(target, "missing")
        assert await ws.realpath(join(a, "rel", "missing")) == join(a, "b", "missing")
        assert await ws.realpath(join(a, "up", "missing")) == join(base, "out", "missing")
        assert await ws.realpath(join(a, "rel", "..")) == a
        assert await ws.realpath(join(a, "up", "..")) == base
        loop = await ws.realpath(join(a, "loop1", "q"))
        assert loop.startswith(join(a, "")), loop
        assert (await ws.stat(link)).is_dir
        assert {e.name: e.is_dir for e in await ws.list_dir(base)} == {"a": True, "link": True, "target": True}
        assert {e.name: e.is_dir for e in await ws.list_dir(a)} == {"b": True, "rel": True, "up": False, "loop1": False, "loop2": False}
        # A write through a link reaches its target.
        out = await asyncio.to_thread(b._shell, f"printf old > {target}/file && ln -s {target}/file {base}/flink", 30.0, CancelHandle())
        assert out.exit_code == 0, out.stderr_text
        await ws.write_bytes(join(base, "flink"), b"new")
        assert await ws.read_bytes(join(target, "file")) == b"new"
        assert await ws.realpath(join(base, "flink")) == join(target, "file")
        # Removing a link removes the link, not its target.
        await ws.remove(link)
        assert not await ws.exists(link) and await ws.exists(target)

    try:
        run(go())
    finally:
        for env in list(cap._open.values()):
            cap.destroy(env.ref)


def test_fifo_and_permission_rules_with_cases_made_by_the_shell_tool() -> None:
    """The conformance rules test_fifo_read_does_not_wait_for_writer and test_permission_denied_uses_builtin_error make
    their cases with commands, so they skip on this backend; the same cases, made through plimsoll's shell tool, and
    the rules' own expectations. The sandbox user is not root on plimsoll's images (uid 61000)."""
    cap = capability()

    async def go() -> None:
        b = cap.backend()
        ws = Workspace(b)
        root = await ws.working_dir()
        out = await asyncio.to_thread(b._shell, f"mkfifo {root}/fifo && printf data > {root}/locked && chmod 000 {root}/locked && id -u",
                                      30.0, CancelHandle())
        assert out.exit_code == 0, out.stderr_text
        assert out.stdout_text.strip() != "0", "root bypasses file permissions"
        with pytest.raises(OSError):
            await asyncio.wait_for(ws.read_bytes("fifo"), 30)
        with pytest.raises(PermissionError):
            await ws.read_bytes("locked")
        with pytest.raises(PermissionError):
            await ws.write_bytes("locked", b"changed")

    try:
        run(go())
    finally:
        for env in list(cap._open.values()):
            cap.destroy(env.ref)


def test_a_destroyed_session_is_never_replaced() -> None:
    cap = capability()

    async def go() -> None:
        b = cap.backend()
        await Workspace(b).write_text("x.txt", "x")
        ref = b.ref
        assert isinstance(ref, WorkspaceRef)
        await asyncio.to_thread(cap.destroy, ref)
        for backend in (b, cap.backend(ref)):
            with pytest.raises(PlimsollWorkspaceGoneError):
                await Workspace(backend).read_text("x.txt")
        assert not cap._open

    run(go())


def test_another_process_takes_the_session_over_and_the_first_takes_it_back() -> None:
    # Two capabilities stand for two processes sharing one store. The second reaches the first's session by its ref
    # and key and finds its file; the first's next operation finds the session taken, takes it back from the store
    # once and goes on.
    store = MemoryCheckpointStore()
    caps = [stored(store), stored(store)]

    async def go() -> None:
        first = caps[0].backend(key="user-1/conv-1")
        await Workspace(first).write_text("carried.txt", "from the first process")
        ref = first.ref
        assert ref is not None
        second = caps[1].backend(ref, key="user-1/conv-1")
        assert await Workspace(second).read_text("carried.txt") == "from the first process"
        held = first.session
        await Workspace(first).write_text("carried.txt", "back in the first process")
        assert first.session is not held, "the first process took the session back with a new attach"
        assert await Workspace(second).read_text("carried.txt") == "back in the first process"
        assert first.ref == second.ref == ref

    try:
        run(go())
    finally:
        close_everywhere(caps)


def test_a_lost_command_is_not_run_again_by_the_next_process() -> None:
    # A command whose answer is cut leaves the store pending with its call. The next process takes the session over
    # across that call (the explained gap) and is recovering: its first operation is not sent, whatever it is, and says
    # what the lost call's record says; the session is then resolved, and the next command runs.
    store = MemoryCheckpointStore()
    caps = [stored(store), stored(store)]
    command = "sleep 2; echo ran >> lost.log"
    try:
        first = caps[0].backend(key="user-1/conv-2")
        run(Workspace(first).write_text("start.txt", "x"))
        ref = first.ref
        assert ref is not None
        handle = CancelHandle()
        threading.Timer(0.7, handle.cancel).start()
        with pytest.raises(PlimsollOutcomeUnknownError):
            first._shell(command, 30.0, handle)
        record = store.load("user-1/conv-2")
        assert record is not None and record.state == "pending" and record.request_sha256
        second = caps[1].backend(ref, key="user-1/conv-2")
        with pytest.raises(PlimsollLostCallError, match="this tool call was not run"):
            second._shell(command, 30.0, CancelHandle())
        assert second.session is not None and second.session.lost_call is None, "the first operation resolved it"
        assert second.resolved_lost_call is not None and second.resolved_lost_call.record is not None
        out = second._shell("cat lost.log 2>/dev/null; echo next", 30.0, CancelHandle())
        assert out.stdout_text.count("ran") <= 1 and out.stdout_text.endswith("next\n"), out.stdout_text
    finally:
        close_everywhere(caps)


def test_the_next_processs_agent_is_told_a_canceled_lost_command_may_have_done_part_of_its_work() -> None:
    # The crash question on a real sandbox: the first process's command is cut 0.7 s into its 3 s, so the daemon's
    # record of it states an unanswered code and no result. An agent in the next process repeats the command as its
    # first call (as PydanticAI's resume of a pending tool call does): nothing is sent, the model is told the call
    # ended without an answer and that whether it began is not known, and the run goes on. Each process keeps the records it saw, the lost one
    # the second's first, and the two logs form one chain that the daemon's close statement ends.
    store = MemoryCheckpointStore()
    logs: Tuple[List[Any], List[Any]] = ([], [])
    caps = [capability(checkpoint_store=store, checkpoint_key=lambda ctx: "user-1/conv-3", record_sink=log.append) for log in logs]
    command = "echo start >> starts.log; sleep 3; echo end >> ends.log"
    try:
        first = caps[0].backend(key="user-1/conv-3")
        run(Workspace(first).write_text("start.txt", "x"))
        ref = first.ref
        assert ref is not None
        handle = CancelHandle()
        threading.Timer(0.7, handle.cancel).start()
        with pytest.raises(PlimsollOutcomeUnknownError):
            # The tool's own budget, so the request is the one the agent's tool sends: the same request digest.
            first._shell(command, caps[0].timeout, handle)
        second = caps[1].backend(ref, key="user-1/conv-3")
        script = Scripted(("plimsoll_shell", {"command": command}),
                          ("plimsoll_shell", {"command": "cat starts.log; test -e ends.log && echo ended || echo not ended"}))
        result = run(Agent(script.model, capabilities=[caps[1]]).run("go", workspace=second))
        told, files = (str(a) for a in script.returned("plimsoll_shell"))
        print("the model was told:", told)
        print("the sandbox's files:", files)
        resolved = second.resolved_lost_call
        lost = resolved.record if resolved is not None else None
        assert lost is not None and lost.result_sha256 == "" and lost.unanswered == "canceled", lost
        assert "That call ended without an answer after" in told, told
        assert "Whether it began, and how much of its work it did, is not known" in told, told
        assert "started" not in told and "finished" not in told, told
        assert result.output == "done", "the run did not go on to its answer"
        assert files.count("start") == 1, f"the lost command started again: {files}"
        assert "not ended" in files, f"the canceled command ran to its end: {files}"
        # One chain across the two logs, with no hole at the lost call, and the daemon's close statement at its end.
        chain = logs[0] + logs[1]
        assert logs[1][0].sha256 == lost.sha256, "the second process's log does not start with the lost call's record"
        assert [r.sequence for r in chain] == list(range(1, len(chain) + 1)), [r.sequence for r in chain]
        assert all(after.previous_sha256 == before.sha256 for before, after in zip(chain, chain[1:]))
        summary = caps[1].destroy(ref)
        assert summary is not None and (summary.calls, summary.last_record_sha256) == (len(chain), chain[-1].sha256), summary
    finally:
        close_everywhere(caps)
