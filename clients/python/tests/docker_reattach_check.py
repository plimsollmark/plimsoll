"""Session reattach on a real docker session, across processes (step R6 of the sessions
builds plan). reattach_docker_test.go serves the docker provider behind a callers file,
writes the daemon's audit log to a file, and runs this check; it is not a test_*.py, so
the client's own suite never sees it.

Every worker is a process of its own (``python -m tests.docker_reattach_check <role>``),
sharing only what an application would: the token, the daemon's name and a checkpoint
store kept in a JSON file. The roles:

- ``open``: opens a session with the store, writes a file in it, and exits without
  closing.
- ``attach``: takes the session over by its key, reads the file, runs a cell.
- ``attach-old``: takes it over from a copy of the record the opener left, now stale.
- ``hold``: opens a session with no store, writes its checkpoint to a file, waits for a line
  on standard input, then tries a call: by then another process holds the session.
"""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import unittest
from typing import Any, Dict, List, Optional

from plimsoll_client import (
    Client,
    MemoryCheckpointStore,
    PlimsollError,
    SessionCheckpoint,
    StaleOwnerError,
    StoredCheckpoint,
)

DAEMON = "docker-check"


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        if os.environ.get("PLIMSOLL_DOCKER_REQUIRED") == "1":
            raise RuntimeError(f"{name} is not set")
        raise unittest.SkipTest(f"{name} is not set; run through reattach_docker_test.go")
    return value


class FakeFileCheckpointStore:
    """A checkpoint store in one JSON file, for this check only: compare-and-set under an
    exclusive lock on a file beside it, the record replaced with os.replace, so processes
    sharing the file never see half a write. Not a store for production use."""

    def __init__(self, path: str) -> None:
        self.path = path

    def _read(self) -> Dict[str, Any]:
        try:
            with open(self.path, encoding="utf-8") as f:
                return dict(json.load(f))
        except FileNotFoundError:
            return {}

    @staticmethod
    def _to(s: StoredCheckpoint) -> Dict[str, Any]:
        return {"revision": s.revision, "state": s.state, "operation": s.operation,
                "request_sha256": s.request_sha256, "checkpoint": s.checkpoint.to_json()}

    @staticmethod
    def _from(d: Dict[str, Any]) -> StoredCheckpoint:
        return StoredCheckpoint(revision=d["revision"], state=d["state"], operation=d["operation"],
                                request_sha256=d["request_sha256"], checkpoint=SessionCheckpoint.from_json(d["checkpoint"]))

    def load(self, key: str) -> Optional[StoredCheckpoint]:
        d = self._read().get(key)
        return None if d is None else self._from(d)

    def compare_and_set(self, key: str, expected: Optional[StoredCheckpoint], replacement: StoredCheckpoint) -> bool:
        with open(self.path + ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            records = self._read()
            current = records.get(key)
            if (current is None) != (expected is None) or (expected is not None and self._from(current) != expected):
                return False
            records[key] = self._to(replacement)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(records, f)
            os.replace(tmp, self.path)
            return True


def _client(url: Optional[str] = None, token: Optional[str] = None) -> Client:
    return Client(url or _env("PLIMSOLL_DOCKER_REATTACH_URL"), token or _env("PLIMSOLL_DOCKER_REATTACH_TOKEN"), daemon_name=DAEMON)


def _role(role: str, store_path: str, key: str) -> None:
    """One worker process's part; it prints one JSON line with what it saw."""
    store = FakeFileCheckpointStore(store_path)
    out: Dict[str, Any] = {}
    if role == "open":
        s = _client().open_session(checkpoint_store=store, checkpoint_key=key)
        s.run_cell("open('note.txt', 'w').write('written by the opener')")
        out = {"session": s.fingerprint}
        # Exit without closing: the session stays open on the daemon.
    elif role == "attach":
        s = _client().attach_session(key, store=store)
        read = s.run_cell("open('note.txt').read()")
        more = s.run_cell("x = 41\nx + 1")
        assert more.record is not None
        out = {"session": s.fingerprint, "read": read.stdout_text, "more": more.stdout_text, "sequence": more.record.sequence}
    elif role == "attach-old":
        try:
            _client().attach_session(key, store=store)
            out = {"error": None}
        except PlimsollError as e:
            out = {"error": type(e).__name__, "not_dispatched": e.not_dispatched}
    elif role == "hold":
        s = _client().open_session()
        s.run_cell("y = 1")
        with open(key, "w", encoding="utf-8") as f:  # here the "key" is where the checkpoint goes
            f.write(s.checkpoint().to_json())
        print(json.dumps({"session": s.fingerprint}), flush=True)
        sys.stdin.readline()
        try:
            s.run_cell("y = 2")
            out = {"error": None}
        except PlimsollError as e:
            out = {"error": type(e).__name__, "not_dispatched": e.not_dispatched}
    print(json.dumps(out), flush=True)


def _run(role: str, store: str, key: str) -> Dict[str, Any]:
    p = subprocess.run([sys.executable, "-B", "-m", "tests.docker_reattach_check", role, store, key],
                       capture_output=True, text=True, timeout=300, env=os.environ.copy())
    if p.returncode != 0:
        raise AssertionError(f"{role} failed: {p.stderr}")
    return dict(json.loads(p.stdout.strip().splitlines()[-1]))


def _audit_calls(session: str) -> List[int]:
    """The session call numbers the daemon's audit log shows it ran ("code run" lines)."""
    calls = []
    with open(_env("PLIMSOLL_DOCKER_AUDIT_LOG"), encoding="utf-8") as f:
        for line in f:
            entry = json.loads(line)
            if entry.get("msg") == "code run" and entry.get("session") == session:
                calls.append(int(entry["session_call"]))
    return calls


def _close_stored(store: str, key: str) -> None:
    """Closes the session a store holds, by taking it over: the workers left it open."""
    _client().attach_session(key, store=FakeFileCheckpointStore(store)).close()


class DockerReattach(unittest.TestCase):
    """Every session a case opens is closed when the case ends, pass or fail: one left open on the daemon goes idle,
    the daemon suspends (pauses) its container, and a paused container outlives the test that started it, with the
    docker exec attached to it (2026-11-20: the docker Python suite left one on every run, from the first case here).
    reattach_docker_test.go drains the daemon's sandbox as well, for a case that cannot run its cleanups."""

    def setUp(self) -> None:
        self.dir = _env("PLIMSOLL_DOCKER_REATTACH_DIR")

    def test_another_process_carries_the_session_on_and_the_old_one_is_refused(self) -> None:
        store = os.path.join(self.dir, "store.json")
        opened = _run("open", store, "user-1/thread-1")
        self.addCleanup(_close_stored, store, "user-1/thread-1")
        old = os.path.join(self.dir, "old-store.json")
        with open(store, encoding="utf-8") as src, open(old, "w", encoding="utf-8") as dst:
            dst.write(src.read())
        got = _run("attach", store, "user-1/thread-1")
        self.assertEqual(got["session"], opened["session"])
        self.assertEqual(got["read"], "'written by the opener'\n", "the file the opener wrote (a cell prints its last value's repr)")
        self.assertEqual((got["more"], got["sequence"]), ("42\n", 3))
        stale = _run("attach-old", old, "user-1/thread-1")
        self.assertEqual((stale["error"], stale["not_dispatched"]), ("StaleOwnerError", "permission"))
        self.assertEqual(sorted(_audit_calls(opened["session"])), [1, 2, 3], "only the three calls the owners sent ran")

    def test_a_stale_worker_is_refused_before_anything_runs(self) -> None:
        checkpoint = os.path.join(self.dir, "held-checkpoint.json")
        p = subprocess.Popen([sys.executable, "-B", "-m", "tests.docker_reattach_check", "hold", "", checkpoint],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=os.environ.copy())
        try:
            assert p.stdout is not None and p.stdin is not None
            held = json.loads(p.stdout.readline())
            store = MemoryCheckpointStore()
            with open(checkpoint, encoding="utf-8") as f:
                cp = SessionCheckpoint.from_json(f.read())
            store.compare_and_set("held", None, StoredCheckpoint(revision=1, state="ready", operation="", checkpoint=cp))
            taker = _client().attach_session("held", store=store)
            self.addCleanup(taker.close)
            taker.run_cell("z = 3")
            p.stdin.write("go\n")
            p.stdin.flush()
            out, err = p.communicate(timeout=300)
            self.assertEqual(p.returncode, 0, err)
            result = json.loads(out.strip().splitlines()[-1])
            self.assertEqual((result["error"], result["not_dispatched"]), ("StaleOwnerError", "permission"))
            self.assertEqual(sorted(_audit_calls(held["session"])), [1, 2], "the stale worker's call ran")
        finally:
            if p.poll() is None:
                p.kill()

    def test_open_development_mode_refuses_the_takeover(self) -> None:
        url = _env("PLIMSOLL_DOCKER_DEVMODE_URL")
        store = MemoryCheckpointStore()
        s = Client(url, daemon_name=DAEMON).open_session(checkpoint_store=store, checkpoint_key="dev")
        self.addCleanup(s.close)
        with self.assertRaises(PlimsollError) as cm:
            Client(url, daemon_name=DAEMON).attach_session("dev", store=store)
        self.assertEqual((cm.exception.code, cm.exception.not_dispatched), ("unauthenticated", "permission"))


if __name__ == "__main__":
    if len(sys.argv) == 4:
        _role(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        unittest.main()
