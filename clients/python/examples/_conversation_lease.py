"""The part of pydantic_ai_crash.py an application supplies: a checkpoint store that serves only the worker holding
the conversation's lease.

A checkpoint store (plimsoll_client.checkpoint.CheckpointStore) is where the application keeps each session's
checkpoint: its ownership generation, its call count and the digest of its last run record. The plimsoll client
passes every call through it (before a call the stored record is marked pending with the call's request digest,
after it ready), and a worker in another process takes the session over from it. A lease is the application's note
of which worker may use a conversation; in a real application it is a job queue's visibility timeout or a lease
with an expiry. Here it is one small file per conversation that the supervisor rewrites.

This store does two things for a worker the lease does not name, and both are needed:

- load returns None, so that worker never starts a takeover: the client's attach sends AttachSession before its own
  compare_and_set, so a refusal that came only there would come after the daemon had moved the session.
- compare_and_set raises, so a worker that already holds the session (it was frozen while the lease moved) is
  refused before it sends anything: the client marks the record pending before each call, and that write fails.

Files: <key>.json holds the stored checkpoint, <key>.lease the worker's name, and LOCK the lock every write and every
lease change takes (fcntl.flock), so a lease never moves halfway through a compare_and_set. A write goes to a
temporary file that is then renamed over the old one, so a reader never sees half a record. POSIX only. The
directory must be one only the application can write: whoever can write it decides which worker gets the sandbox.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
from typing import Iterator, Optional

from plimsoll_client.checkpoint import SessionCheckpoint, StoredCheckpoint


class LeaseRefused(RuntimeError):
    """A write by a worker the conversation's lease does not name."""


def _name(key: str) -> str:
    # Keys are the application's own (user/ticket), never model or user text; "/" cannot be in a file name.
    return key.replace("/", "__")


@contextlib.contextmanager
def _locked(directory: str) -> Iterator[None]:
    with open(os.path.join(directory, "LOCK"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _replace(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, path)


def claim(directory: str, key: str, worker: str) -> None:
    """Gives the conversation ``key`` to ``worker`` (the supervisor's move)."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    with _locked(directory):
        _replace(os.path.join(directory, _name(key) + ".lease"), worker)


def holder(directory: str, key: str) -> str:
    """The worker the lease of ``key`` names, or "" before any claim."""
    try:
        with open(os.path.join(directory, _name(key) + ".lease"), encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


class LeaseCheckpointStore:
    """A checkpoint store in ``directory`` that serves ``worker`` only while the lease of a key names it."""

    def __init__(self, directory: str, worker: str) -> None:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        self.directory = directory
        self.worker = worker

    def _path(self, key: str) -> str:
        return os.path.join(self.directory, _name(key) + ".json")

    def _read(self, key: str) -> Optional[StoredCheckpoint]:
        try:
            with open(self._path(key), encoding="utf-8") as f:
                d = json.load(f)
        except FileNotFoundError:
            return None
        return StoredCheckpoint(revision=d["revision"], state=d["state"], operation=d["operation"],
                                checkpoint=SessionCheckpoint.from_json(d["checkpoint"]), request_sha256=d["request_sha256"])

    def load(self, key: str) -> Optional[StoredCheckpoint]:
        if holder(self.directory, key) != self.worker:
            return None
        return self._read(key)

    def compare_and_set(self, key: str, expected: Optional[StoredCheckpoint], replacement: StoredCheckpoint) -> bool:
        with _locked(self.directory):
            owner = holder(self.directory, key)
            if owner != self.worker:
                raise LeaseRefused(f"the conversation belongs to worker {owner or 'nobody'}, not {self.worker}")
            if self._read(key) != expected:
                return False
            _replace(self._path(key), json.dumps({
                "revision": replacement.revision, "state": replacement.state, "operation": replacement.operation,
                "checkpoint": replacement.checkpoint.to_json(), "request_sha256": replacement.request_sha256,
            }))
            return True
