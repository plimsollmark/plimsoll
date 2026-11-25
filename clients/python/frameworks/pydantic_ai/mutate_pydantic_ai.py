"""Mutation check for the PydanticAI workspace's hard requirements: each mutation breaks one of them in a scratch
copy of plimsoll-client's source (under tmp/), and the PydanticAI suite (frameworks/pydantic_ai) must fail on it.
The unmutated suite must pass first. Needs the PydanticAI environment (make py-frameworks PY_FRAMEWORKS=pydantic_ai);
from the repository root:

    python3 clients/python/frameworks/pydantic_ai/mutate_pydantic_ai.py

The suite's daemon cases skip here (no daemon is served); every requirement below is held by a case that needs
none.
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), *[os.pardir] * 4))  # the repository
PY = os.path.join(ROOT, "tmp", "py-frameworks", "pydantic_ai", "bin", "python")
CLIENTS = os.path.join(ROOT, "clients", "python")

PA = "plimsoll_client/pydantic_ai.py"

MUTATIONS = [
    # It claims no command support.
    ("the backend gains SupportsCommands.run", PA, "    # ---- SupportsRealpath ----\n",
     "    async def run(self, command, *, shell=False, env=None, timeout=None):\n        raise NotImplementedError\n\n    # ---- SupportsRealpath ----\n"),
    # It refuses durable execution, saying why.
    ("get_workspace lets a durable run through", PA, "            raise UserError(_DURABLE_REFUSAL.format(what=what))\n", "            pass\n"),
    ("a durable unit is not seen", PA, "    return bool(in_durable_unit())\n", "    return False\n"),
    ("the refusal does not say why", PA, '"Under Temporal, DBOS or Prefect a workspace call may run again after its answer was lost, and every call rebuilds "',
     '"Under Temporal, DBOS or Prefect a workspace call rebuilds "'),
    # Every row of the error mapping; a call that may have run is never reported as one that did not.
    ("an unmarked error is reported as retryable", PA,
     '        return PlimsollOutcomeUnknownError(\n            f"plimsoll: the call may have run without an answer ({e.message}); it was not retried, and this run sends nothing "',
     '        return PlimsollRetryableError(e.message, reason="environment")\n        return PlimsollOutcomeUnknownError(\n            f"plimsoll: the call may have run without an answer ({e.message}); it was not retried, and this run sends nothing "'),
    ("evidence that does not check is reported as an argument error", PA,
     "        if isinstance(e, DataLossError):\n", "        if isinstance(e, DataLossError):\n            return ValueError(e.message)\n"),
    ("an unanswered call's record is dropped", PA, "                record=e.record,\n            )\n        return PlimsollOutcomeUnknownError(",
     "            )\n        return PlimsollOutcomeUnknownError("),
    ("an incomplete answer counts as one that did not run", PA,
     '        return PlimsollOutcomeUnknownError(\n            f"plimsoll: the call may have run and its answer is incomplete',
     '        return WorkspaceError("did not run")\n        return PlimsollOutcomeUnknownError(\n            f"plimsoll: the call may have run and its answer is incomplete'),
    ("an ended session is an argument error", PA, "    if isinstance(e, SessionEndedError):\n", "    if False:\n"),
    ("capacity and environment are gone, not retryable", PA, "    if reason in _RETRYABLE:\n", "    if False:\n"),
    ("a refused request is retryable", PA, '    if reason == "request":\n        return ValueError(',
     '    if reason == "request":\n        return PlimsollRetryableError(e.message, reason="request")\n        return ValueError('),
    ("a refusal for good is retryable", PA,
     '    return PlimsollWorkspaceGoneError(f"plimsoll: refused before anything ran ({reason}): {e.message}", reason=reason)\n\n\n',
     '    return PlimsollRetryableError(e.message, reason=reason)\n\n\n'),
    ("capacity is not retried by the backend", PA, '            if e.not_dispatched != "capacity" or pause is None', '            if True or pause is None'),
    ("capacity is retried past 30 seconds", PA, "_CAPACITY_BACKOFF = (0.5, 1.0, 2.0, 4.0, 8.0, 8.0)", "_CAPACITY_BACKOFF = (0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 16.0)"),
    ("a stopped or ended session is called again", PA, "        ended = self.session.ended\n        if ended is not None:", "        ended = None\n        if ended is not None:"),
    ("a stopped session is called again", PA, "        if self.session.stopped is not None:\n", "        if False:\n"),
    ("a file operation past its budget returns", PA, "        if out.timed_out:\n            raise WorkspaceTimeoutError(", "        if False:\n            raise WorkspaceTimeoutError("),
    ("a cut answer is returned short", PA, "        if out.stdout_truncated or out.stderr_truncated:\n", "        if False:\n"),
    ("path errors are plain workspace errors", PA, "    cls = _ERRNO.get(code)\n", "    cls = None\n"),
    ("a record the sink could not keep is ignored", PA, "            self._sink(record)\n        except Exception as e:", "            self._sink(record)\n        except ZeroDivisionError as e:"),
    # The session and the registry.
    ("another owner reaches a session by its ref", PA, "        if env is None or env.owner != owner:", "        if env is None:"),
    ("a ref not open here opens a fresh session", PA, "            if self._attach:\n",
     "            if self._attach and self._capability._lookup(self._ref, self._owner) is not None:\n"),
    # asyncio's own cancel waits for the operation's thread, so a run canceled while it opens records its ref.
    ("asyncio's cancel ends the await before the thread does", PA,
     "        return await _to_its_end(partial(self._in_thread, op))\n",
     "        return await anyio.to_thread.run_sync(self._in_thread, op)\n"),
    ("the floor is not checked", PA, "            if not meets(getattr(session, \"isolation\", \"\") or \"\", cap.minimum_isolation):", "            if False:"),
    ("plimsoll's state directory is reachable", PA, '            if path == state or path.startswith(state + "/"):\n', "            if False:\n"),
    ("plimsoll's state directory is listed", PA, "            if child in env.state_dirs:\n", "            if False:\n"),
    ("remove takes the working directory", PA, '        if target == "/" or target == root or root.startswith(target.rstrip("/") + "/"):', "        if False:"),
    # The shell tool.
    ("the shell tool's description drops the sweep", PA, "a process left running in the background is stopped \"\n            \"when its command returns",
     "processes \"\n            \"may run"),
    ("the shell tool turns a call that may have run into a retry prompt", PA,
     "            out = await anyio.to_thread.run_sync(partial(backend._shell, command, budget, handle), abandon_on_cancel=True)\n",
     "            try:\n                out = await anyio.to_thread.run_sync(partial(backend._shell, command, budget, handle), abandon_on_cancel=True)\n"
     "            except PlimsollOutcomeUnknownError as e:\n                raise ModelRetry(str(e)) from e\n"),
    # A call lost before a takeover (findings release-73, -75 and -76; lost call option 3, findings release-61,
    # -74, -83 and -84).
    ("the first operation after a takeover is sent instead of told", PA,
     "            env.recover(cap.max_output_chars)\n            return op(env)\n        except PlimsollWorkspaceGoneError as e:\n",
     "            return op(env)\n        except PlimsollWorkspaceGoneError as e:\n"),
    ("the lost call is told but the session is never resolved", PA,
     "            self.session.resolve_lost_call()\n            self.resolved_lost = lost\n",
     "            self.resolved_lost = lost\n"),
    ("the session is resolved before the sink takes the lost record", PA,
     "            if self.pending_lost is not None:\n                self.recording.keep_lost(self.pending_lost)\n                self.pending_lost = None\n            self.session.resolve_lost_call()\n",
     "            self.session.resolve_lost_call()\n            if self.pending_lost is not None:\n                self.recording.keep_lost(self.pending_lost)\n                self.pending_lost = None\n"),
    ("a lost record the sink could not keep is not offered again", PA,
     "                self.recording.keep_lost(self.pending_lost)\n                self.pending_lost = None\n",
     "                pending, self.pending_lost = self.pending_lost, None\n                self.recording.keep_lost(pending)\n"),
    ("the floor refusal forgets the lost record", PA,
     "            if env.pending_lost is not None:\n                env.recording.keep_lost(env.pending_lost)\n                env.pending_lost = None\n            raise map_error(InsufficientIsolationError(\n",
     "            raise map_error(InsufficientIsolationError(\n"),
    ("the told operation ends the run", PA, "class PlimsollLostCallError(ToolFailed, WorkspaceError):\n",
     "class PlimsollLostCallError(WorkspaceUnavailableError):\n"),
    ("the model is told the lost call's output past the output limit", "plimsoll_client/_lost_call.py",
     "        parts.append(stdout[:max_chars].rstrip(\"\\n\"))\n", "        parts.append(stdout.rstrip(\"\\n\"))\n"),
    ("every lost call is told the sandbox answered it", "plimsoll_client/_lost_call.py",
     '        if r.unanswered == "" and isinstance(r.result_sha256, str) and _HEX64.fullmatch(r.result_sha256):\n',
     "        if True:\n"),
    ("the unanswered code is echoed to the model", "plimsoll_client/_lost_call.py",
     "{_ENDED_HOW.get(r.unanswered, _ENDED_OTHER)}", "{r.unanswered}"),
    ("a record stating both is read as unanswered", "plimsoll_client/_lost_call.py",
     '        if r.result_sha256 == "" and r.unanswered in _UNANSWERED:\n', "        if r.unanswered:\n"),
    ("an operation refused part way is sent again from its start", PA,
     "        if env.mutations != mutations:\n", "        if False:\n"),
]


def suite(src: str) -> bool:
    """Whether the PydanticAI suite passes against the source tree src."""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([src, os.path.join(CLIENTS, "pydantic-ai-plimsoll", "src")]),
               PYTHONDONTWRITEBYTECODE="1")
    env.pop("PLIMSOLL_INTEGRATION_REQUIRED", None)
    p = subprocess.run([PY, "-B", "-m", "unittest", "discover", "-s", "frameworks/pydantic_ai", "-t", "."], cwd=CLIENTS,
                       env=env, capture_output=True, text=True)
    return p.returncode == 0


def main() -> int:
    if not suite(os.path.join(CLIENTS, "src")):
        print("the unmutated suite fails: fix that first")
        return 1
    survived = 0
    for label, rel, old, new in MUTATIONS:
        os.makedirs(os.path.join(ROOT, "tmp"), exist_ok=True)
        scratch = tempfile.mkdtemp(dir=os.path.join(ROOT, "tmp"), prefix="mut-pyai-")
        try:
            src = os.path.join(scratch, "src")
            shutil.copytree(os.path.join(CLIENTS, "src"), src)
            path = os.path.join(src, rel)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if text.count(old) != 1:
                print(f"BAD MUTATION ({text.count(old)} matches): {label}")
                survived += 1
                continue
            with open(path, "w", encoding="utf-8") as f:
                f.write(text.replace(old, new))
            killed = not suite(src)
            survived += not killed
            print(("killed  " if killed else "SURVIVED") + "  " + label)
        finally:
            shutil.rmtree(scratch)
    print(f"{len(MUTATIONS) - survived} of {len(MUTATIONS)} killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
