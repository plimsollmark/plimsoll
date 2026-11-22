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
     "budget = self._ceiling if self._ceiling is not None else self._timeout",
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
    ("a directory is IsADirectoryError",
     'if word == "is_directory":', 'if word == "never":'),
    ("an unreadable file is PermissionError",
     'if word == "permission_denied":', 'if word == "never":'),
    ("a write error carries no sandbox text",
     "            raise _write_error(rel, str(e)) from None", "            raise"),
    ("text with a NUL goes as bytes",
     'as_text = isinstance(content, str) and "\\x00" not in content and len(data) <= v.MAX_PROJECT_BYTES - 1024',
     'as_text = isinstance(content, str) and len(data) <= v.MAX_PROJECT_BYTES - 1024'),
    ("large text goes as bytes",
     'as_text = isinstance(content, str) and "\\x00" not in content and len(data) <= v.MAX_PROJECT_BYTES - 1024',
     'as_text = isinstance(content, str) and "\\x00" not in content'),
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
     "trace_id=_langsmith.trace_id(call_id))", "trace_id=None)"),
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
     "            self._session, self._live, self._root, self._ceiling, self._owner = None, None, None, None, None",
     "            self._session, self._live, self._root, self._ceiling = None, None, None, None"),
    ("a session below the floor is closed",
     "            except BaseException:\n                _close_quietly(session)\n                raise",
     "            except BaseException:\n                raise"),
    ("close() closes the session",
     "            return _close_session(session)", "            return None"),
    ("close waits for an open on its way and closes what it opened (release-94)",
     "        with self._open_lock:\n            with self._state_lock:\n                session = self._session",
     "        if True:\n            with self._state_lock:\n                session = self._session"),
    ("a daemon without sessions is refused before any open",
     "            if not info.supports_sessions:", "            if False:"),
    ("initialize opens once",
     "        if self._live is not None:\n            return\n        await in_thread(self._open, self._tag(ctx))",
     "        self._live = None\n        await in_thread(self._open, self._tag(ctx))"),
]


# Mutations of the shared whole-file read in workspace.py, held by tests/test_workspace.py
# and by the environment suite.
W = [
    ("workspace: a file past one piece is measured",
     "        size = self._size(self._file_path(path), cancel)", "        size = None if False else len(first)"),
    ("workspace: a file that changed size is an error",
     "        if size is None or got != size:\n            raise WorkspaceChangedError(",
     "        if False:\n            raise WorkspaceChangedError("),
    ("workspace: a removed file mid-read is a change, not a missing file",
     "            except FileNotFoundError:\n                break  # removed after its first piece",
     "            except ZeroDivisionError:\n                break  # removed after its first piece"),
    ("workspace: a longer file is read past its first piece",
     "        while size is not None and got < size:", "        while False:"),
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
     "                if cancel is not None and cancel.cancelled:\n                    # The await was cancelled",
     "                if False:\n                    # The await was cancelled"),
    ("no time at all is a timed-out result with nothing sent",
     "        if budget <= 0:\n            # ADK's LocalEnvironment", "        if False:\n            # ADK's LocalEnvironment"),
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
    every = [(n, o, x, "adk.py") for n, o, x in M + A] + [(n, o, x, "workspace.py") for n, o, x in W]
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
