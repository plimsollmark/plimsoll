"""Mutation check for the ADK environment and the workspace's whole-file read: each mutation
breaks one behavior in a scratch copy of the package (tmp/mut/src), and the environment suite
and the workspace's unit tests must fail on it (a suite that hangs past 180 s counts as failing).
The unmutated suite must pass first. Needs the ADK framework environment
(make py-frameworks PY_FRAMEWORKS=adk); from the repository root:

    python3 clients/python/frameworks/adk/mutate_environment.py
"""

import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), *[os.pardir] * 4))  # the repository
SRC = os.path.join(ROOT, "clients", "python", "src")
MUT = os.path.join(ROOT, "tmp", "mut", "src")
PY = os.path.join(ROOT, "tmp", "py-frameworks", "adk", "bin", "python")
MODULE = sys.argv[1] if len(sys.argv) > 1 else "frameworks.adk.test_adk_environment"

M = [
    ("execute keeps no shell state (new sh each time)",
     'out = live.workspace.run(["sh", "-c", command], env=self._env_vars, timeout=budget, cancel=cancel)',
     'out = live.workspace.exec(command, timeout=budget, cancel=cancel)'),
    ("env_vars reach the command",
     'out = live.workspace.run(["sh", "-c", command], env=self._env_vars, timeout=budget, cancel=cancel)',
     'out = live.workspace.run(["sh", "-c", command], timeout=budget, cancel=cancel)'),
    ("timeout None gets the daemon's ceiling",
     "budget = live.ceiling if live.ceiling is not None else self._timeout",
     "budget = self._timeout"),
    ("a cut stream is said in stderr",
     "        if notes:\n            stderr +=",
     "        if False:\n            stderr +="),
    ("env_vars names are checked when the environment is made",
     "            if not _ENV_NAME.match(name):", "            if False:"),
    ("the guard untags after the tool call",
     "        finally:\n            _TOOL_CALL.set(None)  # nothing after the tool call is tagged with it",
     "        finally:\n            pass"),
    ("the guard untags after a tool error",
     "            self._settle(tool_context)\n        finally:\n            _TOOL_CALL.set(None)\n        return None",
     "            self._settle(tool_context)\n        finally:\n            pass\n        return None"),
    ("a write carries the content's bytes",
     "        live.workspace.write(rel, data, cancel=cancel)", "        live.workspace.write(rel, data[:1], cancel=cancel)"),
    ("setup_failed is not uncertain",
     'uncertain=r.outcome in _INCOMPLETE or (not r.steps and r.outcome != "setup_failed"),',
     'uncertain=r.outcome in _INCOMPLETE or not r.steps,'),
    ("runner_failed is uncertain",
     '_INCOMPLETE = frozenset({"protocol_error", "runner_failed", "unspecified"})',
     '_INCOMPLETE = frozenset({"protocol_error", "unspecified"})'),
    ("a refusal is noted as not dispatched",
     '        return PlimsollCall(method=method, function_call_id=call_id, dispatched="no", refused=reason)',
     '        return PlimsollCall(method=method, function_call_id=call_id, dispatched="unknown", uncertain=True)'),
    ("labels keep only their closed sets",
     "        return _langsmith.labels(answer)",
     "        return {k: str(x) for k, x in answer.items()}"),
    ("the call's ID goes as its trace ID",
     "cancel=cancel,\n                                          trace_id=_langsmith.trace_id(call_id))",
     "cancel=cancel,\n                                          trace_id=None)"),
    ("a file call's ID goes as its trace ID",
     "r = self._session.run_files(op, timeout=timeout, cancel=cancel, trace_id=_langsmith.trace_id(call_id))",
     "r = self._session.run_files(op, timeout=timeout, cancel=cancel, trace_id=None)"),
    ("a later ADK's ctx names the call",
     '        call_id = getattr(ctx, "function_call_id", None) if ctx is not None else None',
     '        call_id = None'),
    ("the guard tags the tool call",
     "        _TOOL_CALL.set(_ToolCall(call_id if isinstance(call_id, str) else None, (str(app), str(user))))",
     "        pass"),
    ("the guard labels ADK's span",
     '        span.set_attribute("plimsoll_calls", len(calls))', "        return"),
    ("the guard stops after an uncertain call",
     "            if call.uncertain:\n                # From None", "            if False:\n                # From None"),
    ("the guard's stop drops the tool's error chain",
     "                ) from None\n\n\ndef _label_span", "                )\n\n\ndef _label_span"),
    ("one sandbox, one user",
     "            elif self._owner != owner:", "            elif False:"),
    ("close() lets the owner go",
     "                self._session, self._live, self._root, self._owner = None, None, None, None",
     "                self._session, self._live, self._root = None, None, None"),
    ("a session below the floor is closed",
     "        except BaseException:\n            if attach is None:\n                _close_quietly(session)\n            raise",
     "        except BaseException:\n            raise"),
    ("close() closes the session",
     "            return _close_session(session)", "            return None"),
    ("close waits for an open on its way and closes what it opened (release-94)",
     "        with self._open_lock:\n            with self._state_lock:\n                session = self._session",
     "        if True:\n            with self._state_lock:\n                session = self._session"),
    ("a daemon without sessions is refused before any open",
     "        if not info.supports_sessions:", "        if False:"),
    ("an invocation is refused once the session it used is closed",
     "            if held is not None and (live is None or live.identity != held):",
     "            if False:"),
    ("an invocation is refused in a session that replaced its own",
     "            if held is not None and (live is None or live.identity != held):",
     "            if held is not None and live is None:"),
    ("the invocation that ran an AgentTool is held to its session",
     "            for key in (own, parent):", "            for key in (own,):"),
    ("a call after a close says the invocation's session was closed",
     "            self._hold(invocation, None)  # an invocation whose session was closed is told so\n",
     ""),
    ("initialize refuses before it opens",
     "        self._hold(invocation, self._live)  # refused here, before anything is sent\n",
     ""),
    ("initialize opens once",
     "        if self._live is not None:\n            return\n        await in_thread(self._open, self._tag(ctx))",
     "        self._live = None\n        await in_thread(self._open, self._tag(ctx))"),
    ("session scope: a sandbox per ADK session, not one for all",
     "            await self._initialize_slot(ctx)\n            return\n",
     ""),
    ("session scope: close() lets the sandboxes go",
     "        if self._scope is EnvironmentScope.SESSION:\n            self._is_initialized = False\n            return\n"
     "        summary = await in_thread(self._close)",
     "        if self._scope is EnvironmentScope.SESSION:\n            await in_thread(self._end_slots)\n"
     "            return\n        summary = await in_thread(self._close)"),
    ("session scope: a conversation's state names its sandbox",
     "        _write_mark(ctx, key, live)\n", ""),
    ("session scope: the state's mark picks the sandbox",
     "            mark = (named, fingerprint)\n            sid = named\n", "            mark = (named, fingerprint)\n"),
    ("session scope: a sandbox it no longer holds is refused, not replaced",
     "        not_held = mark is not None and self._store is None and not self._reopen",
     "        not_held = False"),
    ("session scope: with a store, the sandbox is attached again",
     "                session, live, root = self._start(tag, cancel, attach=(store_key, mark[1]))",
     "                session, live, root = self._start_making_room(slot, tag, cancel, owner=key[1] or None,"),
    ("session scope: an open checks for a sandbox another call opened",
     "                if slot.live is not None:\n                    return slot, slot.live",
     "                if False:\n                    return slot, slot.live"),
    ("session scope: a mark naming another sandbox is refused",
     "    if mark is not None and mark[1] != live.fingerprint:",
     "    if False:"),
    ("session scope: a mark must match the sandbox's fingerprint, an empty one included",
     "    if mark is not None and mark[1] != live.fingerprint:",
     "    if mark is not None and mark[1] and live.fingerprint and mark[1] != live.fingerprint:"),
    ("session scope: a mark without a fingerprint is refused",
     "            if not isinstance(fingerprint, str) or not fingerprint:",
     "            if not isinstance(fingerprint, str):"),
    ("session scope: a sandbox without a fingerprint writes no mark",
     "    if not live.fingerprint:\n        return  # a mark", "    if False:\n        return  # a mark"),
    ("session scope: an end racing an open closes what it opened",
     "                gone = self._slots.get(key) is not slot", "                gone = False"),
    ("session scope: past the limit a sandbox between turns is let go",
     "                    victim = self._take(for_limit=True)\n", "                    victim = None\n"),
    ("session scope: past the limit an open is refused when no sandbox can go (D86 B, defect 3)",
     "                        if victim is None:\n                            raise AtCapacityError(_FULL, not_dispatched=\"capacity\")\n",
     ""),
    ("session scope: a refused reopen lets nothing go for the limit",
     "                if slot is None and not_held:", "                if False:"),
    ("session scope: a failed open takes its slot out, so it holds no place among the 256",
     "                        if self._slots.get(key) is slot:\n                            del self._slots[key]\n",
     ""),
    ("session scope: a call waiting on a failed open starts again with a new slot",
     "                if slot.failed:\n                    continue", "                if False:\n                    continue"),
    ("session scope: with a store, an invocation is held to its plimsoll session, attached again or not",
     "        return self.fingerprint or self.generation", "        return self.generation"),
    ("session scope: with a store, a turn whose sandbox was let go is not refused before it attaches it again",
     "        if live is not None or self._store is None:\n", "        if True:\n"),
    ("session scope: at capacity one open closes one sandbox at most",
     "                if closed or e.limit not in _ROOM_LIMITS:", "                if e.limit not in _ROOM_LIMITS:"),
    ("session scope: past the limit, opens in flight count",
     "                if len(self._slots) >= _MAX_SANDBOXES:  # opens in flight",
     "                if sum(s.live is not None for s in self._slots.values()) >= _MAX_SANDBOXES:  # opens in flight"),
    ("session scope: a let-go sandbox without a store is closed",
     "        if session is not None and self._store is None:\n            _close_quietly(session)",
     "        if False:\n            _close_quietly(session)"),
    ("session scope: end() closes every sandbox",
     "        try:\n            summary = _close_session(session)", "        try:\n            summary = None"),
    ("session scope: the ADK user is the session's owner",
     "                session, live, root = self._start_making_room(slot, tag, cancel, owner=key[1] or None,",
     "                session, live, root = self._start_making_room(slot, tag, cancel, owner=None,"),
    ("session scope: the checkpoint goes to the store under the derived key",
     "                options.update(checkpoint_store=self._store, checkpoint_key=store_key)", "                pass"),
    ("session scope: the finalizer closes what is held at collection and exit",
     "if self._scope is EnvironmentScope.SESSION and self._store is None else None)", "if False else None)"),
    ("session scope: with a store the finalizer leaves the sandboxes for another process",
     "if self._scope is EnvironmentScope.SESSION and self._store is None else None)",
     "if self._scope is EnvironmentScope.SESSION else None)"),
    ("session scope: at capacity a finished sandbox is closed and the open retried",
     "            self._close_for_room(victim)\n",
     "            self._close_for_room(victim)\n            raise AtCapacityError('mutated', not_dispatched='capacity')\n"),
    ("session scope: at capacity the least recently used finished sandbox goes",
     "        for key, slot in self._slots.items():  # least recently used first",
     "        for key, slot in reversed(list(self._slots.items())):"),
    ("session scope: a sandbox with a call in flight is never taken (D86 B, defect 3)",
     "            if slot is opening or slot.busy:\n", "            if slot is opening:\n"),
    ("session scope: a cancelled call counts in flight until its thread ends",
     "                if not ticket.started:  # the thread may never run: count the call out here\n", "                if True:\n"),
    ("session scope: a call cancelled before its thread starts is counted out (D86 B, defect 4)",
     "                    ticket.abandoned = True\n                    slot.busy -= 1\n",
     "                    ticket.abandoned = True\n"),
    ("session scope: a turn in progress keeps its sandbox (D86 B, defect 1)",
     "        return not any(_TURNS.in_turn(k) for k in (slot.key, *slot.turns))", "        return True"),
    ("session scope: a sandbox reached from an invocation no guard saw is never taken for room",
     "            if chain is None:\n                slot.unseen = True\n", "            if chain is None:\n"),
    ("session scope: the guard ends an invocation after its run",
     "    async def after_run_callback(self, *, invocation_context: Any) -> None:\n        _TURNS.end(invocation_context)",
     "    async def after_run_callback(self, *, invocation_context: Any) -> None:\n        pass"),
    ("session scope: a run that ends in an error ends its invocation",
     "        _TURNS.end(invocation_context)  # the run ends with this error", "        pass  # the run ends with this error"),
    ("session scope: the guard notes an invocation's beginning",
     "        if not isinstance(invocation, str) or not invocation or not all(isinstance(x, str) for x in key):",
     "        if True:"),
    ("session scope: an AgentTool's caller is in the chain of its agent's sessions",
     "                turn = parent\n                keys.append(turn.key)\n", "                turn = parent\n"),
    ("session scope: an invocation collected without an end ends",
     "            if not turn.objects:\n                del self._by_invocation[invocation]", "            if False:\n                del self._by_invocation[invocation]"),
    ("session scope: an AgentTool's agent and its caller opening together share one sandbox (D86 B, defect 2)",
     "                        key = joined\n                        break\n", "                        break\n"),
    ("session scope: a conversation split across two sandboxes is refused (D86 B, defect 2)",
     "                    raise SessionEndedError(_SPLIT, reason=\"replaced\", not_dispatched=\"request\")",
     "                    pass"),
    ("session scope: reopen_after_close gives a closed conversation an empty sandbox",
     "        not_held = mark is not None and self._store is None and not self._reopen",
     "        not_held = mark is not None and self._store is None"),
    ("session scope: a call is refused when its sandbox was taken for room before it counted",
     "            if self._slots.get(slot.key) is not slot or slot.live is not live:", "            if False:"),
    ("session scope: a call without an ADK session is refused",
     "    if session is None:\n        # As ADK's toolsets", "    if False:\n        # As ADK's toolsets"),
    ("session scope: a capacity refusal no close cures (the rate) closes nothing (release-115)",
     "                if closed or e.limit not in _ROOM_LIMITS:", "                if closed:"),
    ("session scope: a collected invocation's finalizer takes no lock",
     "        self._gone.put((invocation, object_id))",
     "        with self._lock:\n            self._gone.put((invocation, object_id))"),
    ("session scope: what was collected is forgotten before a turn is read",
     "            self._drain()\n            return self._by_session.get(key, 0) > 0",
     "            return self._by_session.get(key, 0) > 0"),
]


# Mutations of the shared whole-file read in workspace.py, held by tests/test_workspace.py
# and by the environment suite.
W = [
    ("workspace: a file past one piece is read to the size its first read states",
     "        target = size if stop is None else min(size, stop)", "        target = len(first.content)"),
    ("workspace: a file that changed size is an error",
     "        if changed or got != target:\n            raise WorkspaceChangedError(",
     "        if False:\n            raise WorkspaceChangedError("),
    ("workspace: each piece's stated size is held to the first's",
     "            if piece.size_at_open != size:", "            if False:"),
    ("workspace: a removed file mid-read is a change, not a missing file",
     "            except FileNotFoundError:\n                break  # removed after its first piece",
     "            except ZeroDivisionError:\n                break  # removed after its first piece"),
    ("workspace: a longer file is read past its first piece",
     "        while not changed and got < target:", "        while False:"),
    ("workspace: the root is the open's work_dir, with no call",
     '        root = getattr(self._session, "work_dir", "") or ""', '        root = ""'),
    ("workspace: an answered error names its own class and errno",
     '    cls, code, words = _ERRORS.get(error, (OSError, named', '    cls, code, words = {}.get(error, (OSError, named'),
    ("workspace: an errno is read by name only when the name is a number's",
     'named if type(named) is int else errno.EIO', 'named if named is not None else errno.EIO'),
    ("workspace: a write past 4 MiB appends its later pieces",
     'mode=first_mode if i == 0 else "append"', 'mode=first_mode'),
]

A = [
    ("an incomplete answer becomes PlimsollEnvironmentError",
     "            raise _environment_error(method, call or _from_result(method, tag.function_call_id, e.result), e.result) from None",
     "            raise"),
    ("the environment error drops the workspace's chain",
     "            raise _environment_error(method, call or _from_result(method, tag.function_call_id, e.result), e.result) from None",
     "            raise _environment_error(method, call or _from_result(method, tag.function_call_id, e.result), e.result) from e"),
    ("a cancelled stream cuts the read in flight",
     "            handle.cancel()  # the worker thread is still in the read: cut it there",
     "            pass"),
    ("a cancelled stream leaves the running read to end with the cut",
     "            if not in_flight:\n                pieces.close()", "            if True:\n                pieces.close()"),
    ("a cancelled open closes its session",
     "            if cancel is not None and cancel.cancelled:\n                # The await was cancelled while the open (or the pwd)",
     "            if False:\n                # The await was cancelled while the open (or the pwd)"),
    ("no time at all is a timed-out result with nothing sent",
     "        if budget <= 0:\n            # ADK's LocalEnvironment", "        if False:\n            # ADK's LocalEnvironment"),
]

# A sandbox whose session can take no more calls is let go and named on every later call
# (hunt-quality-109): each guard, removed, fails CutCallTests or LostSandboxTests.
L = [
    ("a lost sandbox is looked for after each call",
     "        finally:\n            self._let_go_if_lost(live, slot)", "        finally:\n            pass"),
    ("the loss names the daemon's reason",
     'reason = ended.reason if ended.reason in SESSION_END_NAMES else "unknown"', 'reason = "unknown"'),
    ("the loss names only a reason of the client's closed set",
     'reason = ended.reason if ended.reason in SESSION_END_NAMES else "unknown"', "reason = ended.reason"),
    ("a stopped session is a loss",
     "    if session.stopped is not None:\n        return _Lost(", "    if False:\n        return _Lost("),
    ("shared: the loss is recorded", "                    self._lost = lost\n", ""),
    ("shared: a lost sandbox is closed",
     "                if session is not None:\n                    _close_quietly(session)\n            return",
     "                pass\n            return"),
    ("shared: a late loss leaves the next sandbox alone",
     "                    if self._live is not live:\n                        return", "                    if False:\n                        return"),
    ("shared: every call after a loss is refused",
     "        if lost is not None:\n            raise _lost_error(lost, scoped=False)",
     "        if False:\n            raise _lost_error(lost, scoped=False)"),
    ("shared: initialize names the loss before the invocation's hold",
     "        invocation = _invocation(ctx)\n        self._refuse_if_lost()\n        self._hold(invocation, self._live)",
     "        invocation = _invocation(ctx)\n        self._hold(invocation, self._live)"),
    ("shared: a call names the loss",
     "        invocation = _invocation(ctx)\n        self._refuse_if_lost()\n        live = self._live",
     "        invocation = _invocation(ctx)\n        live = self._live"),
    ("shared: an open that begins after a loss is refused",
     "            self._refuse_if_lost()  # a loss let go", "            pass  # a loss let go"),
    ("shared: close() ends the lost state", "                self._lost = None\n", ""),
    ("session scope: the loss is recorded on the conversation's slot",
     "            session, slot.lost = slot.session, lost", "            session = slot.session"),
    ("session scope: a lost sandbox is closed",
     "            slot.session, slot.live = None, None\n        if session is not None:\n            _close_quietly(session)",
     "            slot.session, slot.live = None, None\n        if False:\n            _close_quietly(session)"),
    ("session scope: initialize names the loss before the invocation's hold",
     "        if slot is not None and slot.lost is not None:\n            raise _lost_error(slot.lost, scoped=True)\n"
     "        live = slot.live if slot is not None else None\n        if live is not None or self._store is None:",
     "        live = slot.live if slot is not None else None\n        if live is not None or self._store is None:"),
    ("session scope: a call of a lost conversation is refused",
     "        if slot is not None and slot.lost is not None:\n            raise _lost_error(slot.lost, scoped=True)\n"
     "        live = slot.live if slot is not None else None\n        self._hold(invocation, live)  # an invocation",
     "        live = slot.live if slot is not None else None\n        self._hold(invocation, live)  # an invocation"),
    ("session scope: an open that begins after a loss is refused",
     "                if slot.lost is not None:\n                    raise _lost_error(slot.lost, scoped=True)  # lost since",
     "                if False:\n                    raise _lost_error(slot.lost, scoped=True)  # lost since"),
]


# Room at capacity and a lost sandbox together under the SESSION scope: each guard, removed,
# fails RoomAndLossTests.
R = [
    ("session scope: a lost sandbox, which holds none, is never taken for room",
     "                if not (for_limit and slot.lost is not None):\n                    continue",
     "                if not (slot.lost is not None):\n                    continue"),
    ("session scope: a call whose sandbox a parallel call lost is told of the loss, not not_found",
     "                lost = slot.lost\n                if lost is not None:\n                    raise _lost_error(lost, scoped=True)\n",
     ""),
    ("session scope: a call is counted in flight until its lost sandbox is let go",
     "            try:\n                return self._run_call(live, slot, method, tag, fn, *a, cancel=cancel)\n"
     "            finally:\n                with self._state_lock:\n                    slot.busy -= 1\n",
     "            try:\n                return live.recorder.run(method, tag, fn, *a, cancel=cancel)\n"
     "            finally:\n                with self._state_lock:\n                    slot.busy -= 1\n"
     "                self._let_go_if_lost(live, slot)\n"),
    ("session scope: end() and the finalizer skip a lost sandbox, already closed",
     "        if session is None:\n            continue\n        try:\n            summary = _close_session(session)",
     "        try:\n            summary = _close_session(session)"),
]


def run_suite() -> int:
    env = dict(os.environ, PYTHONPATH=MUT + os.pathsep + ".", PYTHONDONTWRITEBYTECODE="1")
    env.pop("PLIMSOLL_INTEGRATION_REQUIRED", None)
    try:
        p = subprocess.run([PY, "-B", "-m", "unittest", MODULE, "tests.test_workspace"], cwd=os.path.join(ROOT, "clients", "python"),
                           env=env, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return -1  # a mutation that makes the suite hang fails it too
    return p.returncode


def main() -> int:
    survived = 0
    every = [(n, o, x, "adk.py") for n, o, x in M + A + L + R] + [(n, o, x, "workspace.py") for n, o, x in W]
    baseline = None
    shutil.rmtree(os.path.dirname(MUT), ignore_errors=True)
    shutil.copytree(SRC, MUT)
    baseline = run_suite()
    print(f"unmutated suite: exit {baseline}")
    if baseline != 0:
        return 2
    for name, old, new, module in every:
        shutil.rmtree(os.path.dirname(MUT), ignore_errors=True)
        shutil.copytree(SRC, MUT)
        path = os.path.join(MUT, "plimsoll_client", module)
        text = open(path).read()
        if text.count(old) != 1:
            print(f"BAD MUTATION (found {text.count(old)} times): {name}")
            survived += 1
            continue
        open(path, "w").write(text.replace(old, new))
        code = run_suite()
        verdict = "killed" if code != 0 else "SURVIVED"
        if code == 0:
            survived += 1
        print(f"{verdict}: {name}")
    shutil.rmtree(os.path.dirname(MUT), ignore_errors=True)
    print(f"{len(every) - survived} of {len(every)} mutations killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
